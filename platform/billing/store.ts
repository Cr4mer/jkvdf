// Storage boundary for billing. The webhook and checkout code only talk to this
// interface: tests use MemoryBillingStore, production uses supabase-store.ts.

export type Provider = 'lemonsqueezy';

export interface SubscriptionRecord {
  id: string;                    // provider subscription id
  provider: Provider;
  teamId: string;
  planId: string;                // 'team' today; a Pro tier is another variant -> plan mapping
  status: string;                // provider status string, e.g. active, past_due, cancelled, expired
  customerId: string | null;
  variantId: string | null;
  renewsAt: string | null;       // ISO timestamps as sent by the provider
  endsAt: string | null;
  providerUpdatedAt: string | null;
  customerPortalUrl: string | null;
  updatePaymentUrl: string | null;
}

/** Statuses that keep the team on its paid plan. Mirrors subscription_grants_access() in SQL. */
export const LIVE_STATUSES: ReadonlySet<string> = new Set(['on_trial', 'active', 'past_due']);

export function grantsAccess(status: string, endsAt: string | null, now: Date = new Date()): boolean {
  if (LIVE_STATUSES.has(status)) return true;
  if (status === 'cancelled') return endsAt === null || new Date(endsAt) > now;
  return false;
}

export interface BillingStore {
  /** Stores the delivery; returns false if this exact delivery was seen before. */
  recordEvent(id: string, provider: Provider, eventName: string, payload: unknown): Promise<boolean>;
  findSubscription(id: string): Promise<SubscriptionRecord | null>;
  /** Insert or update by subscription id. Stale updates are dropped by the database trigger. */
  upsertSubscription(sub: SubscriptionRecord): Promise<void>;
  /** Records who pays for the team (teams.billing_user_id). */
  setBillingContact(teamId: string, userId: string): Promise<void>;
  /** Subscriptions that currently grant access; checkout refuses a second one. */
  liveSubscriptions(teamId: string): Promise<SubscriptionRecord[]>;
}

export class MemoryBillingStore implements BillingStore {
  events = new Map<string, { provider: Provider; eventName: string; payload: unknown }>();
  subscriptions = new Map<string, SubscriptionRecord>();
  billingContacts = new Map<string, string>();

  async recordEvent(id: string, provider: Provider, eventName: string, payload: unknown): Promise<boolean> {
    if (this.events.has(id)) return false;
    this.events.set(id, { provider, eventName, payload });
    return true;
  }

  async findSubscription(id: string): Promise<SubscriptionRecord | null> {
    return this.subscriptions.get(id) ?? null;
  }

  async upsertSubscription(sub: SubscriptionRecord): Promise<void> {
    const prev = this.subscriptions.get(sub.id);
    // Same rule as the subs_10_skip_stale trigger.
    if (prev?.providerUpdatedAt && sub.providerUpdatedAt
        && new Date(sub.providerUpdatedAt) < new Date(prev.providerUpdatedAt)) {
      return;
    }
    this.subscriptions.set(sub.id, sub);
  }

  async setBillingContact(teamId: string, userId: string): Promise<void> {
    this.billingContacts.set(teamId, userId);
  }

  async liveSubscriptions(teamId: string): Promise<SubscriptionRecord[]> {
    return [...this.subscriptions.values()]
      .filter((s) => s.teamId === teamId && grantsAccess(s.status, s.endsAt));
  }
}
