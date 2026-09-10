# Platform draft: Ladder A

A team nade book with a per-team quota, session scheduling, and a paid Team
plan. This directory is a starting point for the multi-team version of the
site. It contains the database schema, the quota enforcement, row-level
security, and the billing integration, with tests. It does not contain UI.

Deliberately out of scope for now: demo parsing, match stats, FACEIT and
Leetify ingestion. Everything in the rest of this repository belongs to that
part and is untouched.

## Tiers

| Tier | Price | Nades per team | Scheduling | Seats |
|---|---|---|---|---|
| Free | €0 | 30 | yes | unlimited |
| Team | €9.99 per month or €89 per year | unlimited | yes | unlimited |

Rules the code enforces:

- The cap counts **stored** nades per team. Deleting one frees a slot. Nothing resets monthly.
- At the cap the insert fails with `nade_quota_exceeded`; the client opens checkout. Existing nades stay editable.
- Anyone on the team can buy the plan. The subscription belongs to the team; the payer is only the billing contact and can hand it over.
- One live subscription per team. Checkout refuses a second one; if two slip through, the second is flagged for review.
- Losing the plan sets the limit back to 30 and blocks new uploads. Nothing is deleted.

## Stack

- **Supabase**: Postgres, row-level security, Auth with Discord and email login.
- **Cloudflare R2** for nade videos and thumbnails, uploaded straight from the browser with presigned URLs.
- **Lemon Squeezy** as merchant of record: VAT, invoices, card retries, customer portal.
- Web app on Cloudflare Pages or the existing Firebase Hosting. Not part of this draft.

## Files

```
db/0001_schema.sql          plans, profiles, teams, members, invites, nades, sessions, rsvps, subscriptions, billing_events
db/0002_quota_billing.sql   nade quota trigger, usage view, plan derivation from subscriptions, reconcile job
db/0003_rls.sql             row-level security policies and the RPCs create_team, accept_invite, transfer_billing
db/0004_supabase_auth.sql   Supabase only: profile row for every new auth user
billing/store.ts            BillingStore interface, access rule, in-memory implementation for tests
billing/supabase-store.ts   BillingStore on Supabase with the service-role key
billing/lemonsqueezy.ts     webhook handler (signature check, idempotency, mapping) and checkout creation
test/                       PGlite runs the real migrations; billing tests use the memory store
```

## How the pieces fit

1. **Sign up.** Supabase Auth creates the user; `0004` inserts the `profiles` row.
2. **Create a team.** The app calls the `create_team(name, slug)` RPC, which inserts the team and makes the caller owner in one transaction.
3. **Invite.** An owner inserts a `team_invites` row and shares `/join/<token>`. The joiner calls `accept_invite(token)`.
4. **Add a nade.** The client inserts the `nades` row first. The `nades_quota` trigger runs before the row exists, so a blocked upload costs no bandwidth. On success the client asks the server for a presigned R2 URL, uploads the video, then updates `video_key`, `video_bytes`, and `video_seconds`. The presign endpoint enforces `plans.max_video_bytes` and `max_video_seconds`.
5. **Meter.** The UI reads `team_nade_usage` for `nade_count` and `nade_limit`. Show a banner at 20 of 30.
6. **Checkout.** Any member clicks upgrade; the server calls `createTeamCheckout()` and redirects to the returned URL. The team id and user id travel as custom data.
7. **Webhook.** Lemon Squeezy posts `subscription_*` events to `handleLemonWebhook()`, which verifies the signature, records the delivery for idempotency, and upserts `subscriptions`. Database triggers then derive `teams.plan_id`. Nothing else writes that column.
8. **Lapse.** A cancelled subscription keeps access until `ends_at`, then the trigger sets the plan to free. A daily `select reconcile_team_plans()` covers the case where no webhook arrives at that moment.
9. **Transfer billing.** `transfer_billing(team, user)` is allowed for an owner or the current payer.

Handling the cap in the client:

```ts
const { error } = await supabase.from('nades').insert(nade);
if (error?.message.includes('nade_quota_exceeded')) {
  openUpgradeDialog();          // error.hint is the limit as text
}
```

## Environment

See `.env.example`. The service-role key and the Lemon Squeezy API key are server-side only.

## Applying the migrations

With the Supabase CLI, copy the files into `supabase/migrations/` and run `supabase db push`. With plain `psql`, run them in order against the project database. `0004` requires Supabase's `auth.users` table.

Supabase grants table access to the `anon` role by default. The policies here use `auth.uid()`, so anonymous requests see nothing. If you want the public nade library to be browsable without an account, add one policy: `create policy nades_anon_read on nades for select to anon using (visibility = 'public');`

## Wiring the webhook and checkout

Cloudflare Worker:

```ts
import { handleLemonWebhook, createTeamCheckout } from './billing/lemonsqueezy.ts';
import { createSupabaseStore } from './billing/supabase-store.ts';

export default {
  async fetch(req: Request, env: Record<string, string>) {
    const store = createSupabaseStore(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY);
    const variantPlans = {
      [env.LEMONSQUEEZY_VARIANT_TEAM_MONTHLY]: 'team',
      [env.LEMONSQUEEZY_VARIANT_TEAM_YEARLY]: 'team',
    };
    const url = new URL(req.url);
    if (url.pathname === '/webhooks/lemonsqueezy') {
      return handleLemonWebhook(req, { signingSecret: env.LEMONSQUEEZY_WEBHOOK_SECRET, store, variantPlans });
    }
    // POST /billing/checkout: authenticate the caller, check team membership, then:
    // const checkoutUrl = await createTeamCheckout({ apiKey, storeId, store }, { teamId, userId, variantId, email, redirectUrl });
    return new Response('not found', { status: 404 });
  },
};
```

Supabase Edge Function: the same call inside `Deno.serve((req) => handleLemonWebhook(req, deps))`.

In the Lemon Squeezy dashboard, create the webhook with the events `subscription_created`, `subscription_updated`, `subscription_cancelled`, `subscription_resumed`, `subscription_expired`, `subscription_paused`, `subscription_unpaused`, and `subscription_plan_changed`. Payment events are accepted and ignored.

## Tests

```
npm install
npm test          # PGlite boots the migrations; no Postgres server needed
npm run typecheck
```

`test/db.test.ts` covers the quota lifecycle, membership and RLS, stale and duplicate billing events, and the reconcile job. `test/billing.test.ts` covers signature verification, idempotency, mapping, and checkout.

## Adding a Pro tier later

1. Insert a row in `plans`, for example `('pro', 'Team Pro', null, ...)` with its feature flags.
2. Create the product and prices in Lemon Squeezy and map the new variant ids to `'pro'` in `variantPlans`.
3. Read the flag from the plan row where the feature is gated.

No schema change and no change to the trigger.

## Not in this draft

- The presign endpoint for R2 uploads and the video size and duration check.
- UI: meter, upgrade dialog, team settings, calendar.
- Emails for "cap reached" and "payment failed". Lemon Squeezy sends receipts and dunning emails itself.
- Terms of service and privacy policy.
