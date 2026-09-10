import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import {
  AlreadySubscribedError, createTeamCheckout, handleLemonWebhook, mapLemonSubscription,
} from '../billing/lemonsqueezy.ts';
import { MemoryBillingStore } from '../billing/store.ts';

const SECRET = 'whsec_test';
const TEAM = '00000000-0000-4000-8000-0000000000aa';
const USER = '00000000-0000-4000-8000-0000000000bb';
const VARIANTS = { '111': 'team', '222': 'team' };

function subscriptionEvent(eventName: string, attrs: Record<string, unknown>, custom: Record<string, unknown> | null = { team_id: TEAM, user_id: USER }) {
  return {
    meta: { event_name: eventName, custom_data: custom },
    data: {
      type: 'subscriptions',
      id: '9001',
      attributes: {
        customer_id: 42,
        variant_id: 111,
        status: 'active',
        renews_at: '2026-10-10T00:00:00.000000Z',
        ends_at: null,
        updated_at: '2026-09-10T10:00:00.000000Z',
        urls: { update_payment_method: 'https://ls.test/pay', customer_portal: 'https://ls.test/portal' },
        ...attrs,
      },
    },
  };
}

function signedRequest(body: unknown, secret = SECRET): Request {
  const raw = JSON.stringify(body);
  const sig = createHmac('sha256', secret).update(raw).digest('hex');
  return new Request('https://app.test/webhooks/lemonsqueezy', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-signature': sig },
    body: raw,
  });
}

test('webhook: created event stores the subscription and the billing contact', async () => {
  const store = new MemoryBillingStore();
  const res = await handleLemonWebhook(signedRequest(subscriptionEvent('subscription_created', {})), {
    signingSecret: SECRET, store, variantPlans: VARIANTS,
  });
  assert.equal(res.status, 200);
  const sub = await store.findSubscription('9001');
  assert.ok(sub);
  assert.equal(sub.teamId, TEAM);
  assert.equal(sub.planId, 'team');
  assert.equal(sub.status, 'active');
  assert.equal(sub.variantId, '111');
  assert.equal(sub.customerPortalUrl, 'https://ls.test/portal');
  assert.equal(store.billingContacts.get(TEAM), USER);
});

test('webhook: exact redelivery is a no-op, bad signature is rejected', async () => {
  const store = new MemoryBillingStore();
  const deps = { signingSecret: SECRET, store, variantPlans: VARIANTS };
  const body = subscriptionEvent('subscription_created', {});
  assert.equal((await handleLemonWebhook(signedRequest(body), deps)).status, 200);
  const dup = await handleLemonWebhook(signedRequest(body), deps);
  assert.equal(dup.status, 200);
  assert.equal(await dup.text(), 'duplicate');
  assert.equal(store.events.size, 1);

  const bad = await handleLemonWebhook(signedRequest(body, 'wrong'), deps);
  assert.equal(bad.status, 401);
});

test('webhook: later update without custom_data still maps to the known team; stale one is dropped', async () => {
  const store = new MemoryBillingStore();
  const deps = { signingSecret: SECRET, store, variantPlans: VARIANTS };
  await handleLemonWebhook(signedRequest(subscriptionEvent('subscription_created', {})), deps);

  const cancelled = subscriptionEvent('subscription_cancelled',
    { status: 'cancelled', ends_at: '2026-10-10T00:00:00.000000Z', updated_at: '2026-09-11T10:00:00.000000Z' }, null);
  assert.equal((await handleLemonWebhook(signedRequest(cancelled), deps)).status, 200);
  assert.equal((await store.findSubscription('9001'))?.status, 'cancelled');

  const stale = subscriptionEvent('subscription_updated',
    { status: 'active', updated_at: '2026-09-10T12:00:00.000000Z' }, null);
  assert.equal((await handleLemonWebhook(signedRequest(stale), deps)).status, 200);
  assert.equal((await store.findSubscription('9001'))?.status, 'cancelled');
});

test('webhook: unknown variant is 422, invoice events are ignored', async () => {
  const store = new MemoryBillingStore();
  const deps = { signingSecret: SECRET, store, variantPlans: VARIANTS };
  const unknown = await handleLemonWebhook(
    signedRequest(subscriptionEvent('subscription_created', { variant_id: 999 })), deps);
  assert.equal(unknown.status, 422);
  assert.equal(await store.findSubscription('9001'), null);

  const invoice = await handleLemonWebhook(signedRequest({
    meta: { event_name: 'subscription_payment_success', custom_data: { team_id: TEAM } },
    data: { type: 'subscription-invoices', id: '77', attributes: { subscription_id: 9001, status: 'paid' } },
  }), deps);
  assert.equal(invoice.status, 200);
  assert.equal(await invoice.text(), 'ignored');
});

test('mapLemonSubscription rejects a missing team', () => {
  const r = mapLemonSubscription(subscriptionEvent('subscription_created', {}, null), VARIANTS);
  assert.equal(r.ok, false);
});

test('checkout: sends team and user as custom data, refuses a second live subscription', async () => {
  const store = new MemoryBillingStore();
  const captured: { url?: string; init?: RequestInit } = {};
  const fetchImpl: typeof fetch = async (url, init) => {
    captured.url = String(url);
    captured.init = init ?? {};
    return new Response(JSON.stringify({ data: { attributes: { url: 'https://checkout.test/abc' } } }), { status: 201 });
  };
  const deps = { apiKey: 'k', storeId: '5', store, fetchImpl };

  const url = await createTeamCheckout(deps, { teamId: TEAM, userId: USER, variantId: '111', email: 'a@b.c' });
  assert.equal(url, 'https://checkout.test/abc');
  assert.equal(captured.url, 'https://api.lemonsqueezy.com/v1/checkouts');
  const sent = JSON.parse(String(captured.init?.body));
  assert.deepEqual(sent.data.attributes.checkout_data.custom, { team_id: TEAM, user_id: USER });
  assert.equal(sent.data.relationships.variant.data.id, '111');
  assert.equal(sent.data.relationships.store.data.id, '5');

  await store.upsertSubscription({
    id: 's1', provider: 'lemonsqueezy', teamId: TEAM, planId: 'team', status: 'active',
    customerId: null, variantId: '111', renewsAt: null, endsAt: null, providerUpdatedAt: null,
    customerPortalUrl: null, updatePaymentUrl: null,
  });
  await assert.rejects(
    createTeamCheckout(deps, { teamId: TEAM, userId: USER, variantId: '111' }),
    AlreadySubscribedError);
});
