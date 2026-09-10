-- Ladder A schema: teams, nade book, scheduling, billing.
-- Target: Postgres 15+ (Supabase). No demo or stats tables on purpose.

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------- plans
-- One row per plan. Limits and feature flags live here, so adding a Pro tier
-- later is a new row plus a price in the billing provider, not a migration.
create table plans (
  id                text primary key,                         -- 'free' | 'team'
  name              text not null,
  nade_limit        integer,                                  -- null = unlimited
  max_video_bytes   bigint  not null default 52428800,        -- 50 MB per nade video
  max_video_seconds integer not null default 30,
  features          jsonb   not null default '{}'::jsonb,
  price_month_eur   numeric(8,2) not null default 0,
  price_year_eur    numeric(8,2) not null default 0,
  sort_order        integer not null default 0
);

insert into plans (id, name, nade_limit, features, price_month_eur, price_year_eur, sort_order) values
  ('free', 'Free', 30,   '{"scheduling": true}', 0,    0,     0),
  ('team', 'Team', null, '{"scheduling": true}', 9.99, 89.00, 1);

-- ---------------------------------------------------------------- users
-- id equals auth.users.id on Supabase; rows are created by 0004_supabase_auth.sql.
create table profiles (
  id           uuid primary key,
  display_name text not null default '',
  avatar_url   text,
  created_at   timestamptz not null default now()
);

-- ---------------------------------------------------------------- teams
create type team_role as enum ('owner', 'member');

create table teams (
  id              uuid primary key default gen_random_uuid(),
  name            text not null check (char_length(name) between 2 and 40),
  slug            text not null unique check (slug ~ '^[a-z0-9][a-z0-9-]{0,38}[a-z0-9]$'),
  plan_id         text not null default 'free' references plans(id),
  billing_user_id uuid references profiles(id) on delete set null,   -- who pays; transferable
  created_by      uuid not null references profiles(id),
  created_at      timestamptz not null default now()
);

create table team_members (
  team_id   uuid not null references teams(id) on delete cascade,
  user_id   uuid not null references profiles(id) on delete cascade,
  role      team_role not null default 'member',
  joined_at timestamptz not null default now(),
  primary key (team_id, user_id)
);
create index team_members_user_idx on team_members (user_id);

create table team_invites (
  token      text primary key default encode(gen_random_bytes(16), 'hex'),
  team_id    uuid not null references teams(id) on delete cascade,
  created_by uuid not null references profiles(id),
  expires_at timestamptz not null default now() + interval '7 days',
  max_uses   integer not null default 10 check (max_uses > 0),
  uses       integer not null default 0,
  created_at timestamptz not null default now()
);

-- ---------------------------------------------------------------- nades
create type nade_type       as enum ('smoke', 'flash', 'molotov', 'he', 'decoy');
create type nade_side       as enum ('t', 'ct', 'both');
create type nade_throw      as enum ('stand', 'crouch', 'jump', 'walk_jump', 'run_jump', 'other');
create type nade_visibility as enum ('team', 'public');

create table nades (
  id            uuid primary key default gen_random_uuid(),
  team_id       uuid not null references teams(id) on delete cascade,
  created_by    uuid not null references profiles(id),
  map           text not null check (map ~ '^[a-z0-9_]{3,40}$'),      -- de_mirage, de_inferno ...
  title         text not null check (char_length(title) between 1 and 80),
  description   text check (char_length(description) <= 2000),
  type          nade_type not null,
  side          nade_side not null default 'both',
  throw         nade_throw not null default 'stand',
  from_pos      jsonb,      -- {"x": .., "y": ..} radar-image coordinates of the throw spot
  to_pos        jsonb,      -- {"x": .., "y": ..} where it lands
  setpos        text check (char_length(setpos) <= 200),  -- "setpos ...; setang ..." for practice
  visibility    nade_visibility not null default 'team',
  video_key     text,       -- object key in R2; null until the upload completes
  video_bytes   bigint  check (video_bytes is null or video_bytes > 0),
  video_seconds numeric(6,2) check (video_seconds is null or video_seconds > 0),
  thumb_key     text,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);
create index nades_team_map_idx   on nades (team_id, map);
create index nades_public_map_idx on nades (map) where visibility = 'public';

-- ---------------------------------------------------------------- scheduling
create type session_type as enum ('prac', 'scrim', 'nade_practice', 'vod_review', 'other');
create type rsvp_status  as enum ('yes', 'no', 'maybe');

create table sessions (
  id         uuid primary key default gen_random_uuid(),
  team_id    uuid not null references teams(id) on delete cascade,
  created_by uuid not null references profiles(id),
  type       session_type not null default 'prac',
  title      text not null check (char_length(title) between 1 and 80),
  starts_at  timestamptz not null,
  ends_at    timestamptz not null,
  notes      text check (char_length(notes) <= 4000),
  created_at timestamptz not null default now(),
  check (ends_at > starts_at)
);
create index sessions_team_time_idx on sessions (team_id, starts_at);

create table session_rsvps (
  session_id uuid not null references sessions(id) on delete cascade,
  user_id    uuid not null references profiles(id) on delete cascade,
  status     rsvp_status not null,
  updated_at timestamptz not null default now(),
  primary key (session_id, user_id)
);

-- ---------------------------------------------------------------- billing
-- One row per provider subscription. Written only by the webhook (service role).
-- The team's plan is derived from these rows in 0002, never set by hand.
create table subscriptions (
  id                  text primary key,                     -- provider subscription id
  provider            text not null default 'lemonsqueezy',
  team_id             uuid not null references teams(id) on delete cascade,
  plan_id             text not null references plans(id),
  status              text not null,                        -- provider status string, see 0002
  customer_id         text,
  variant_id          text,
  renews_at           timestamptz,
  ends_at             timestamptz,
  provider_updated_at timestamptz,
  customer_portal_url text,
  update_payment_url  text,
  needs_review        boolean not null default false,       -- a second live subscription on one team
  created_at          timestamptz not null default now(),
  updated_at          timestamptz not null default now()
);
create index subscriptions_team_idx on subscriptions (team_id);

-- Every accepted webhook delivery, for idempotency and audit.
create table billing_events (
  id          text primary key,           -- sha256 of the raw request body
  provider    text not null,
  event_name  text not null,
  received_at timestamptz not null default now(),
  payload     jsonb not null
);

-- ---------------------------------------------------------------- updated_at
create or replace function set_updated_at() returns trigger
language plpgsql as $$
begin
  new.updated_at := now();
  return new;
end $$;

create trigger nades_set_updated_at
  before update on nades
  for each row execute function set_updated_at();
