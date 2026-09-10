// Boots the SQL migrations in PGlite (Postgres in WASM) with stand-ins for the
// two Supabase things the migrations depend on: auth.uid() and the
// `authenticated` role.
import { PGlite } from '@electric-sql/pglite';
import { pgcrypto } from '@electric-sql/pglite/contrib/pgcrypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const MIGRATIONS = ['0001_schema.sql', '0002_quota_billing.sql', '0003_rls.sql'];

export const USER_A = '00000000-0000-4000-8000-00000000000a';
export const USER_B = '00000000-0000-4000-8000-00000000000b';
export const USER_C = '00000000-0000-4000-8000-00000000000c';

export async function freshDb(): Promise<PGlite> {
  const db = new PGlite({ extensions: { pgcrypto } });
  await db.exec(`
    create schema auth;
    create function auth.uid() returns uuid language sql stable as $$
      select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid
    $$;
    create role authenticated nologin;
    grant usage on schema auth to authenticated;   -- Supabase grants this by default
  `);
  for (const file of MIGRATIONS) {
    await db.exec(readFileSync(join(here, '..', 'db', file), 'utf8'));
  }
  await db.exec(`
    grant usage on schema public to authenticated;
    grant select, insert, update, delete on all tables in schema public to authenticated;
    insert into profiles (id, display_name) values
      ('${USER_A}', 'a'), ('${USER_B}', 'b'), ('${USER_C}', 'c');
  `);
  return db;
}

/** Run fn as a signed-in user: RLS applies and auth.uid() returns userId. */
export async function asUser<T>(db: PGlite, userId: string, fn: () => Promise<T>): Promise<T> {
  await db.exec(`set role authenticated; select set_config('request.jwt.claim.sub', '${userId}', false);`);
  try {
    return await fn();
  } finally {
    await db.exec(`reset role; select set_config('request.jwt.claim.sub', '', false);`);
  }
}

export async function createTeam(db: PGlite, userId: string, slug: string): Promise<string> {
  return asUser(db, userId, async () => {
    const r = await db.query<{ id: string }>(`select (create_team($1, $2)).id as id`, [slug.toUpperCase(), slug]);
    return r.rows[0].id;
  });
}

export function addNade(db: PGlite, teamId: string, title: string) {
  return db.query<{ id: string }>(
    `insert into nades (team_id, created_by, map, title, type)
     values ($1, auth.uid(), 'de_mirage', $2, 'smoke') returning id`,
    [teamId, title]);
}

export async function teamPlan(db: PGlite, teamId: string): Promise<string> {
  const r = await db.query<{ plan_id: string }>(`select plan_id from teams where id = $1`, [teamId]);
  return r.rows[0].plan_id;
}

export async function nadeCount(db: PGlite, teamId: string): Promise<number> {
  const r = await db.query<{ n: number }>(`select count(*)::int as n from nades where team_id = $1`, [teamId]);
  return r.rows[0].n;
}
