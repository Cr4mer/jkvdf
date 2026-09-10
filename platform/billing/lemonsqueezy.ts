// Lemon Squeezy integration: webhook handler and checkout creation.
// Runs anywhere with fetch + Web Crypto: Cloudflare Workers, Supabase Edge
// Functions (Deno), Node 22.
//
// Flow: createTeamCheckout() -> customer pays -> Lemon Squeezy POSTs
// subscription_* events -> handleLemonWebhook() upserts the subscription row ->
// the database derives teams.plan_id (db/0002_quota_billing.sql).

import type { BillingStore, SubscriptionRecord } from './store.ts';

const enc = new TextEncoder();
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const LEMON_API = 'https://api.lemonsqueezy.com/v1';

// ---------------------------------------------------------------- crypto

function toHex(bytes: ArrayBuffer): string {
  return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function sha256Hex(text: string): Promise<string> {
  return toHex(await crypto.subtle.digest('SHA-256', enc.encode(text)));
}

export async function hmacSha256Hex(secret: string, text: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return toHex(await crypto.subtle.sign('HMAC', key, enc.encode(text)));
}

function equalConstantTime(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** Lemon Squeezy signs the raw body with HMAC-SHA256 and sends the hex in X-Signature. */
export async function verifyLemonSignature(
  rawBody: string, signature: string | null, secret: string): Promise<boolean> {
  if (!signature || !secret) return false;
  const expected = await hmacSha256Hex(secret, rawBody);
  return equalConstantTime(expected, signature.trim().toLowerCase());
}

// ---------------------------------------------------------------- payload mapping

export interface LemonWebhookPayload {
  meta?: {
    event_name?: string;
    custom_data?: Record<string, unknown> | null;
  };
  data?: {
    type?: string;
    id?: string | number;
    attributes?: Record<string, unknown>;
  };
}

/** variant id (as a string) -> plan id in the plans table */
export type VariantPlanMap = Readonly<Record<string, string>>;

export type MapResult =
  | { ok: true; subscription: SubscriptionRecord; payerUserId: string | null }
  | { ok: false; status: number; error: string };

const str = (v: unknown): string | null =>
  v === null || v === undefined || v === '' ? null : String(v);

/**
 * Turns a subscription_* payload into our record. `fallbackTeamId` covers the
 * rare event that arrives without custom_data for a subscription we already know.
 */
export function mapLemonSubscription(
  payload: LemonWebhookPayload,
  variantPlans: VariantPlanMap,
  fallbackTeamId: string | null = null,
): MapResult {
  const data = payload.data;
  if (!data || data.type !== 'subscriptions' || data.id === undefined || data.id === null) {
    return { ok: false, status: 422, error: 'not a subscription object' };
  }
  const a = data.attributes ?? {};
  const custom = payload.meta?.custom_data ?? {};

  const teamId = str(custom.team_id) ?? fallbackTeamId;
  if (!teamId || !UUID_RE.test(teamId)) {
    return { ok: false, status: 422, error: 'missing or invalid team_id in custom_data' };
  }

  const variantId = str(a.variant_id);
  const planId = variantId ? variantPlans[variantId] : undefined;
  if (!planId) {
    return { ok: false, status: 422, error: `unknown variant ${variantId ?? '(none)'}` };
  }

  const urls = (a.urls ?? {}) as Record<string, unknown>;
  const payerUserId = str(custom.user_id);

  return {
    ok: true,
    payerUserId: payerUserId && UUID_RE.test(payerUserId) ? payerUserId : null,
    subscription: {
      id: String(data.id),
      provider: 'lemonsqueezy',
      teamId,
      planId,
      status: str(a.status) ?? 'unknown',
      customerId: str(a.customer_id),
      variantId,
      renewsAt: str(a.renews_at),
      endsAt: str(a.ends_at),
      providerUpdatedAt: str(a.updated_at),
      customerPortalUrl: str(urls.customer_portal),
      updatePaymentUrl: str(urls.update_payment_method),
    },
  };
}

// ---------------------------------------------------------------- webhook

export interface LemonWebhookDeps {
  signingSecret: string;
  store: BillingStore;
  variantPlans: VariantPlanMap;
  log?: (message: string, extra?: unknown) => void;
}

/**
 * HTTP handler for the Lemon Squeezy webhook URL.
 * 200 for handled, duplicate, and ignored events (so the provider stops retrying);
 * 401 for a bad signature; 422 for a payload we cannot map (fix config, then resend
 * from the dashboard).
 */
export async function handleLemonWebhook(req: Request, deps: LemonWebhookDeps): Promise<Response> {
  const log = deps.log ?? (() => {});
  if (req.method !== 'POST') return new Response('method not allowed', { status: 405 });

  const raw = await req.text();
  if (!(await verifyLemonSignature(raw, req.headers.get('x-signature'), deps.signingSecret))) {
    return new Response('invalid signature', { status: 401 });
  }

  let payload: LemonWebhookPayload;
  try {
    payload = JSON.parse(raw) as LemonWebhookPayload;
  } catch {
    return new Response('invalid json', { status: 400 });
  }

  const eventName = payload.meta?.event_name ?? req.headers.get('x-event-name') ?? 'unknown';
  const eventId = await sha256Hex(raw);
  const fresh = await deps.store.recordEvent(eventId, 'lemonsqueezy', eventName, payload);
  if (!fresh) return new Response('duplicate', { status: 200 });

  // Invoice and order events never change entitlement; subscription_updated follows them.
  if (payload.data?.type !== 'subscriptions') {
    return new Response('ignored', { status: 200 });
  }

  const known = payload.data.id !== undefined
    ? await deps.store.findSubscription(String(payload.data.id))
    : null;
  const mapped = mapLemonSubscription(payload, deps.variantPlans, known?.teamId ?? null);
  if (!mapped.ok) {
    log(`lemonsqueezy webhook ${eventName} rejected: ${mapped.error}`, { eventId });
    return new Response(mapped.error, { status: mapped.status });
  }

  await deps.store.upsertSubscription(mapped.subscription);
  if (mapped.payerUserId && eventName === 'subscription_created') {
    await deps.store.setBillingContact(mapped.subscription.teamId, mapped.payerUserId);
  }

  log(`lemonsqueezy ${eventName}: subscription ${mapped.subscription.id} -> team ${mapped.subscription.teamId} ${mapped.subscription.status}`);
  return new Response('ok', { status: 200 });
}

// ---------------------------------------------------------------- checkout

export class AlreadySubscribedError extends Error {
  constructor(teamId: string) {
    super(`team ${teamId} already has a live subscription`);
    this.name = 'AlreadySubscribedError';
  }
}

export interface CheckoutDeps {
  apiKey: string;
  storeId: string;
  store: BillingStore;
  fetchImpl?: typeof fetch;
  apiBase?: string;
}

export interface CheckoutInput {
  teamId: string;
  userId: string;        // the member who clicked "upgrade"; becomes billing contact
  variantId: string;     // monthly or yearly Team variant
  email?: string;
  redirectUrl?: string;
}

/**
 * Creates a hosted checkout for a team and returns its URL. Any team member may
 * call this. Refuses when the team already has a live subscription, which is
 * the only way to make "one subscription per team" hold with anyone-can-pay.
 */
export async function createTeamCheckout(deps: CheckoutDeps, input: CheckoutInput): Promise<string> {
  if (!UUID_RE.test(input.teamId) || !UUID_RE.test(input.userId)) {
    throw new Error('teamId and userId must be UUIDs');
  }
  if ((await deps.store.liveSubscriptions(input.teamId)).length > 0) {
    throw new AlreadySubscribedError(input.teamId);
  }

  const body = {
    data: {
      type: 'checkouts',
      attributes: {
        checkout_data: {
          ...(input.email ? { email: input.email } : {}),
          custom: { team_id: input.teamId, user_id: input.userId },   // values must be strings
        },
        ...(input.redirectUrl ? { product_options: { redirect_url: input.redirectUrl } } : {}),
      },
      relationships: {
        store: { data: { type: 'stores', id: deps.storeId } },
        variant: { data: { type: 'variants', id: input.variantId } },
      },
    },
  };

  const doFetch = deps.fetchImpl ?? fetch;
  const res = await doFetch(`${deps.apiBase ?? LEMON_API}/checkouts`, {
    method: 'POST',
    headers: {
      Accept: 'application/vnd.api+json',
      'Content-Type': 'application/vnd.api+json',
      Authorization: `Bearer ${deps.apiKey}`,
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    throw new Error(`lemonsqueezy checkout failed: ${res.status} ${await res.text()}`);
  }
  const json = (await res.json()) as { data?: { attributes?: { url?: string } } };
  const url = json.data?.attributes?.url;
  if (!url) throw new Error('lemonsqueezy checkout response had no url');
  return url;
}
