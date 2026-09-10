-- Nade quota and plan derivation.

-- ---------------------------------------------------------------- quota
-- A team on a plan with nade_limit N holds at most N nades. We count stored
-- nades, not uploads, so deleting one frees a slot and nothing ever resets.
-- The check runs before the insert, so a blocked upload costs no bandwidth:
-- the client inserts the row first and only then uploads the video.
create or replace function nades_enforce_quota() returns trigger
language plpgsql as $$
declare
  lim integer;
  cnt integer;
begin
  -- Serialize per team: two uploads racing for the last slot cannot both pass.
  perform pg_advisory_xact_lock(hashtext(new.team_id::text));

  select p.nade_limit into lim
    from teams t
    join plans p on p.id = t.plan_id
   where t.id = new.team_id;
  if not found then
    raise exception 'team_not_found';
  end if;

  if lim is null then
    return new;                                -- unlimited plan
  end if;

  select count(*) into cnt from nades where team_id = new.team_id;
  if cnt >= lim then
    -- Clients match on the message and open checkout; hint carries the limit.
    raise exception 'nade_quota_exceeded'
      using detail = format('team %s holds %s of %s nades', new.team_id, cnt, lim),
            hint   = lim::text;
  end if;

  return new;
end $$;

create trigger nades_quota
  before insert on nades
  for each row execute function nades_enforce_quota();

-- What the UI meter reads. security_invoker makes RLS on teams apply to the view.
create view team_nade_usage with (security_invoker = true) as
select t.id      as team_id,
       t.plan_id,
       p.nade_limit,
       (select count(*) from nades n where n.team_id = t.id)::integer as nade_count
  from teams t
  join plans p on p.id = t.plan_id;

-- ---------------------------------------------------------------- plan derivation
-- The webhook only upserts subscriptions. These functions decide the plan.
-- Access continues while the provider says: on_trial, active, past_due (card is
-- being retried), or cancelled but paid through ends_at. Everything else is free.
create or replace function subscription_grants_access(p_status text, p_ends_at timestamptz)
returns boolean language sql stable as $$
  select p_status in ('on_trial', 'active', 'past_due')
      or (p_status = 'cancelled' and coalesce(p_ends_at, 'infinity'::timestamptz) > now());
$$;

create or replace function team_effective_plan(p_team uuid) returns text
language sql stable as $$
  select coalesce(
    (select s.plan_id
       from subscriptions s
      where s.team_id = p_team
        and subscription_grants_access(s.status, s.ends_at)
      order by s.provider_updated_at desc nulls last, s.updated_at desc
      limit 1),
    'free');
$$;

create or replace function apply_team_plan(p_team uuid) returns text
language plpgsql as $$
declare
  new_plan text := team_effective_plan(p_team);
begin
  update teams set plan_id = new_plan where id = p_team and plan_id <> new_plan;
  return new_plan;
end $$;

-- Ignore a webhook that is older than what we already stored (out-of-order delivery).
create or replace function subs_skip_stale() returns trigger
language plpgsql as $$
begin
  if new.provider_updated_at is not null
     and old.provider_updated_at is not null
     and new.provider_updated_at < old.provider_updated_at then
    return null;
  end if;
  return new;
end $$;

-- Flag a second live subscription on the same team (double purchase). Refund
-- one in the provider dashboard and clear the flag by hand.
create or replace function subs_flag_duplicates() returns trigger
language plpgsql as $$
begin
  if subscription_grants_access(new.status, new.ends_at) and exists (
       select 1 from subscriptions s
        where s.team_id = new.team_id
          and s.id <> new.id
          and subscription_grants_access(s.status, s.ends_at)) then
    new.needs_review := true;
  end if;
  return new;
end $$;

create or replace function subs_apply_plan() returns trigger
language plpgsql as $$
begin
  if tg_op = 'DELETE' then
    perform apply_team_plan(old.team_id);
    return old;
  end if;
  perform apply_team_plan(new.team_id);
  if tg_op = 'UPDATE' and new.team_id <> old.team_id then
    perform apply_team_plan(old.team_id);
  end if;
  return new;
end $$;

-- Numbered so they fire in this order.
create trigger subs_10_skip_stale      before update           on subscriptions for each row execute function subs_skip_stale();
create trigger subs_20_flag_duplicates before insert or update on subscriptions for each row execute function subs_flag_duplicates();
create trigger subs_30_set_updated_at  before update           on subscriptions for each row execute function set_updated_at();
create trigger subs_90_apply_plan      after insert or update or delete on subscriptions for each row execute function subs_apply_plan();

-- Safety net for time passing without a webhook (a cancelled subscription
-- reaching ends_at). Run daily: select reconcile_team_plans();
create or replace function reconcile_team_plans() returns integer
language plpgsql as $$
declare
  changed integer := 0;
  r record;
begin
  for r in
    select t.id, t.plan_id
      from teams t
     where t.plan_id <> 'free'
        or exists (select 1 from subscriptions s where s.team_id = t.id)
  loop
    if r.plan_id <> team_effective_plan(r.id) then
      perform apply_team_plan(r.id);
      changed := changed + 1;
    end if;
  end loop;
  return changed;
end $$;
