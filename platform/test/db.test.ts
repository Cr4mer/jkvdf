import test from 'node:test';
import assert from 'node:assert/strict';
import { addNade, asUser, createTeam, freshDb, nadeCount, teamPlan, USER_A, USER_B, USER_C } from './helpers.ts';

test('quota: 30 free, blocked at 31, unlimited on Team, read-only after downgrade', async () => {
  const db = await freshDb();
  const team = await createTeam(db, USER_A, 'jkvdf');

  await asUser(db, USER_A, async () => {
    for (let i = 1; i <= 30; i++) await addNade(db, team, `nade ${i}`);
    await assert.rejects(addNade(db, team, 'nade 31'), /nade_quota_exceeded/);
    const usage = await db.query<{ nade_count: number; nade_limit: number }>(
      `select nade_count, nade_limit from team_nade_usage where team_id = $1`, [team]);
    assert.deepEqual(usage.rows[0], { nade_count: 30, nade_limit: 30 });
  });

  // Webhook (service role) records an active subscription: plan flips to team.
  await db.query(
    `insert into subscriptions (id, team_id, plan_id, status, provider_updated_at)
     values ('sub_1', $1, 'team', 'active', now())`, [team]);
  assert.equal(await teamPlan(db, team), 'team');
  await asUser(db, USER_A, () => addNade(db, team, 'nade 31'));
  assert.equal(await nadeCount(db, team), 31);

  // Cancelled but paid through ends_at: still team.
  await db.query(
    `update subscriptions set status = 'cancelled', ends_at = now() + interval '1 day',
            provider_updated_at = now() where id = 'sub_1'`);
  assert.equal(await teamPlan(db, team), 'team');

  // Period over: back to free. Nothing is deleted, uploads are blocked.
  await db.query(
    `update subscriptions set ends_at = now() - interval '1 day',
            provider_updated_at = now() where id = 'sub_1'`);
  assert.equal(await teamPlan(db, team), 'free');
  await asUser(db, USER_A, async () => {
    await assert.rejects(addNade(db, team, 'nade 32'), /nade_quota_exceeded/);
    assert.equal(await nadeCount(db, team), 31);
    // Deleting below the limit frees slots again.
    await db.query(`delete from nades where id in (select id from nades where team_id = $1 limit 2)`, [team]);
    await addNade(db, team, 'nade 32');
    assert.equal(await nadeCount(db, team), 30);
  });
});

test('membership: invites work, members can upload, outsiders see only public nades', async () => {
  const db = await freshDb();
  const team = await createTeam(db, USER_A, 'jkvdf');

  const token = await asUser(db, USER_A, async () => {
    const r = await db.query<{ token: string }>(
      `insert into team_invites (team_id, created_by) values ($1, auth.uid()) returning token`, [team]);
    return r.rows[0].token;
  });

  await asUser(db, USER_B, async () => {
    const r = await db.query<{ accept_invite: string }>(`select accept_invite($1)`, [token]);
    assert.equal(r.rows[0].accept_invite, team);
    await addNade(db, team, 'member nade');          // non-owner passes the quota trigger under RLS
  });

  await asUser(db, USER_C, async () => {
    assert.equal(await nadeCount(db, team), 0);      // RLS hides the team's book
    await assert.rejects(addNade(db, team, 'intruder'), /team_not_found|row-level security/);
  });

  await asUser(db, USER_A, () =>
    db.query(`update nades set visibility = 'public' where team_id = $1`, [team]));
  await asUser(db, USER_C, async () => {
    assert.equal(await nadeCount(db, team), 1);      // public nade is visible to anyone signed in
  });

  // Owner can hand billing to a member; a stranger cannot.
  await asUser(db, USER_A, () => db.query(`select transfer_billing($1, $2)`, [team, USER_B]));
  await assert.rejects(
    asUser(db, USER_C, () => db.query(`select transfer_billing($1, $2)`, [team, USER_C])),
    /not_allowed/);
});

test('billing rows: stale events are ignored, double purchase is flagged, reconcile catches expiry', async () => {
  const db = await freshDb();
  const t1 = await createTeam(db, USER_A, 'team-one');
  const t2 = await createTeam(db, USER_A, 'team-two');

  await db.query(
    `insert into subscriptions (id, team_id, plan_id, status, provider_updated_at)
     values ('sub_a', $1, 'team', 'active', '2026-01-02T00:00:00Z')`, [t1]);
  // An older event arriving late must not downgrade the team.
  await db.query(
    `update subscriptions set status = 'expired', provider_updated_at = '2026-01-01T00:00:00Z' where id = 'sub_a'`);
  assert.equal(await teamPlan(db, t1), 'team');
  // A newer one does.
  await db.query(
    `update subscriptions set status = 'expired', provider_updated_at = '2026-01-03T00:00:00Z' where id = 'sub_a'`);
  assert.equal(await teamPlan(db, t1), 'free');

  // Two live subscriptions on one team: the second is flagged for review, access is unaffected.
  await db.query(
    `insert into subscriptions (id, team_id, plan_id, status, provider_updated_at)
     values ('sub_b', $1, 'team', 'active', now()), ('sub_c', $1, 'team', 'active', now())`, [t2]);
  const flags = await db.query<{ id: string; needs_review: boolean }>(
    `select id, needs_review from subscriptions where team_id = $1 order by id`, [t2]);
  assert.deepEqual(flags.rows, [{ id: 'sub_b', needs_review: false }, { id: 'sub_c', needs_review: true }]);
  assert.equal(await teamPlan(db, t2), 'team');

  // Time passes without a webhook: reconcile_team_plans() downgrades the lapsed team.
  await db.query(
    `update subscriptions set status = 'cancelled', ends_at = now() + interval '300 milliseconds',
            provider_updated_at = now() where team_id = $1`, [t2]);
  assert.equal(await teamPlan(db, t2), 'team');
  await new Promise((r) => setTimeout(r, 400));
  const changed = await db.query<{ n: number }>(`select reconcile_team_plans() as n`);
  assert.equal(changed.rows[0].n, 1);
  assert.equal(await teamPlan(db, t2), 'free');
});
