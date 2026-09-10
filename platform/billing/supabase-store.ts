// BillingStore backed by Supabase with the service-role key. Server-side only.
import { createClient } from '@supabase/supabase-js';
import { grantsAccess, type BillingStore, type Provider, type SubscriptionRecord } from './store.ts';

interface Row {
  id: string;
  provider: Provider;
  team_id: string;
  plan_id: string;
  status: string;
  customer_id: string | null;
  variant_id: string | null;
  renews_at: string | null;
  ends_at: string | null;
  provider_updated_at: string | null;
  customer_portal_url: string | null;
  update_payment_url: string | null;
}

const toRow = (s: SubscriptionRecord): Row => ({
  id: s.id,
  provider: s.provider,
  team_id: s.teamId,
  plan_id: s.planId,
  status: s.status,
  customer_id: s.customerId,
  variant_id: s.variantId,
  renews_at: s.renewsAt,
  ends_at: s.endsAt,
  provider_updated_at: s.providerUpdatedAt,
  customer_portal_url: s.customerPortalUrl,
  update_payment_url: s.updatePaymentUrl,
});

const fromRow = (r: Row): SubscriptionRecord => ({
  id: r.id,
  provider: r.provider,
  teamId: r.team_id,
  planId: r.plan_id,
  status: r.status,
  customerId: r.customer_id,
  variantId: r.variant_id,
  renewsAt: r.renews_at,
  endsAt: r.ends_at,
  providerUpdatedAt: r.provider_updated_at,
  customerPortalUrl: r.customer_portal_url,
  updatePaymentUrl: r.update_payment_url,
});

export function createSupabaseStore(url: string, serviceRoleKey: string): BillingStore {
  const db = createClient(url, serviceRoleKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  return {
    async recordEvent(id, provider, eventName, payload) {
      const { error } = await db
        .from('billing_events')
        .insert({ id, provider, event_name: eventName, payload });
      if (!error) return true;
      if (error.code === '23505') return false;          // unique_violation: duplicate delivery
      throw new Error(`billing_events insert failed: ${error.message}`);
    },

    async findSubscription(id) {
      const { data, error } = await db.from('subscriptions').select('*').eq('id', id).maybeSingle();
      if (error) throw new Error(`subscriptions select failed: ${error.message}`);
      return data ? fromRow(data as Row) : null;
    },

    async upsertSubscription(sub) {
      const { error } = await db.from('subscriptions').upsert(toRow(sub), { onConflict: 'id' });
      if (error) throw new Error(`subscriptions upsert failed: ${error.message}`);
    },

    async setBillingContact(teamId, userId) {
      const { error } = await db.from('teams').update({ billing_user_id: userId }).eq('id', teamId);
      if (error) throw new Error(`teams update failed: ${error.message}`);
    },

    async liveSubscriptions(teamId) {
      const { data, error } = await db.from('subscriptions').select('*').eq('team_id', teamId);
      if (error) throw new Error(`subscriptions select failed: ${error.message}`);
      return ((data ?? []) as Row[]).map(fromRow).filter((s) => grantsAccess(s.status, s.endsAt));
    },
  };
}
