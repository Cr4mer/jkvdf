-- Row-level security and the RPCs that need to cross it.
-- Requires Supabase's auth.uid(); test/helpers.ts installs a stand-in.

alter table plans          enable row level security;
alter table profiles       enable row level security;
alter table teams          enable row level security;
alter table team_members   enable row level security;
alter table team_invites   enable row level security;
alter table nades          enable row level security;
alter table sessions       enable row level security;
alter table session_rsvps  enable row level security;
alter table subscriptions  enable row level security;
alter table billing_events enable row level security;

-- Helpers are security definer so they can read team_members regardless of
-- the caller's own policies.
create or replace function is_team_member(p_team uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from team_members m
     where m.team_id = p_team and m.user_id = auth.uid());
$$;

create or replace function is_team_owner(p_team uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from team_members m
     where m.team_id = p_team and m.user_id = auth.uid() and m.role = 'owner');
$$;

create or replace function shares_team_with(p_user uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from team_members a
      join team_members b on b.team_id = a.team_id
     where a.user_id = auth.uid() and b.user_id = p_user);
$$;

-- plans: readable by everyone signed in
create policy plans_read on plans for select using (true);

-- profiles: see yourself and your teammates, edit yourself
create policy profiles_read   on profiles for select using (id = auth.uid() or shares_team_with(id));
create policy profiles_insert on profiles for insert with check (id = auth.uid());
create policy profiles_update on profiles for update using (id = auth.uid()) with check (id = auth.uid());

-- teams: members read, owners change; creation goes through create_team()
create policy teams_read   on teams for select using (is_team_member(id));
create policy teams_update on teams for update using (is_team_owner(id)) with check (is_team_owner(id));
create policy teams_delete on teams for delete using (is_team_owner(id));

-- team_members: members read; owners change roles and remove; anyone may leave;
-- joining goes through accept_invite()
create policy members_read   on team_members for select using (is_team_member(team_id));
create policy members_update on team_members for update using (is_team_owner(team_id)) with check (is_team_owner(team_id));
create policy members_delete on team_members for delete using (user_id = auth.uid() or is_team_owner(team_id));

-- invites: owners manage; redemption goes through accept_invite()
create policy invites_read   on team_invites for select using (is_team_owner(team_id));
create policy invites_insert on team_invites for insert with check (is_team_owner(team_id) and created_by = auth.uid());
create policy invites_delete on team_invites for delete using (is_team_owner(team_id));

-- nades: private to the team; there is no public library
create policy nades_read   on nades for select using (is_team_member(team_id));
create policy nades_insert on nades for insert with check (is_team_member(team_id) and created_by = auth.uid());
create policy nades_update on nades for update using (is_team_member(team_id)) with check (is_team_member(team_id));
create policy nades_delete on nades for delete using (created_by = auth.uid() or is_team_owner(team_id));

-- sessions
create policy sessions_read   on sessions for select using (is_team_member(team_id));
create policy sessions_insert on sessions for insert with check (is_team_member(team_id) and created_by = auth.uid());
create policy sessions_update on sessions for update using (is_team_member(team_id)) with check (is_team_member(team_id));
create policy sessions_delete on sessions for delete using (created_by = auth.uid() or is_team_owner(team_id));

-- rsvps: members read, you write your own
create policy rsvps_read on session_rsvps for select
  using (exists (select 1 from sessions s where s.id = session_id and is_team_member(s.team_id)));
create policy rsvps_insert on session_rsvps for insert
  with check (user_id = auth.uid()
              and exists (select 1 from sessions s where s.id = session_id and is_team_member(s.team_id)));
create policy rsvps_update on session_rsvps for update using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy rsvps_delete on session_rsvps for delete using (user_id = auth.uid());

-- subscriptions: members see their team's billing state; only the service role writes.
create policy subscriptions_read on subscriptions for select using (is_team_member(team_id));
-- billing_events: no user access at all (the service role bypasses RLS).

-- ---------------------------------------------------------------- RPCs
-- create_team: the team and its first owner in one transaction.
create or replace function create_team(p_name text, p_slug text) returns teams
language plpgsql security definer set search_path = public as $$
declare
  t teams;
begin
  if auth.uid() is null then
    raise exception 'not_authenticated';
  end if;
  insert into teams (name, slug, created_by)
       values (p_name, p_slug, auth.uid())
    returning * into t;
  insert into team_members (team_id, user_id, role) values (t.id, auth.uid(), 'owner');
  return t;
end $$;

-- accept_invite: join the team behind a valid token. Idempotent for existing members.
create or replace function accept_invite(p_token text) returns uuid
language plpgsql security definer set search_path = public as $$
declare
  inv team_invites;
begin
  if auth.uid() is null then
    raise exception 'not_authenticated';
  end if;
  select * into inv from team_invites where token = p_token for update;
  if not found or inv.expires_at < now() or inv.uses >= inv.max_uses then
    raise exception 'invite_invalid';
  end if;
  insert into team_members (team_id, user_id, role)
       values (inv.team_id, auth.uid(), 'member')
  on conflict (team_id, user_id) do nothing;
  update team_invites set uses = uses + 1 where token = p_token;
  return inv.team_id;
end $$;

-- transfer_billing: an owner, or the current payer, hands billing to another member.
create or replace function transfer_billing(p_team uuid, p_to_user uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not (is_team_owner(p_team)
          or exists (select 1 from teams where id = p_team and billing_user_id = auth.uid())) then
    raise exception 'not_allowed';
  end if;
  if not exists (select 1 from team_members where team_id = p_team and user_id = p_to_user) then
    raise exception 'not_a_member';
  end if;
  update teams set billing_user_id = p_to_user where id = p_team;
end $$;

grant execute on function create_team(text, text), accept_invite(text), transfer_billing(uuid, uuid)
  to authenticated;
