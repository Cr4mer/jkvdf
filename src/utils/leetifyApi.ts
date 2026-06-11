/**
 * Leetify API integration for Premier (CS2) stats.
 * Uses Firebase Callable leetifyProxy so the API key stays on the server.
 * Data only returned for players registered on Leetify. See https://leetify.com
 */

import { getFunctions, httpsCallable, type HttpsCallable } from 'firebase/functions';
import { app } from '@/firebase';
import { legacyToSteamId64 } from '@/utils/steamAuth';
import type { LeetifyStats } from '@/types';

type LeetifyProxyRequest = { path: string; steamId64?: string };
type LeetifyProxyCallable = HttpsCallable<LeetifyProxyRequest, unknown>;

let leetifyProxyCallable: LeetifyProxyCallable | null = null;

function getLeetifyProxy(): LeetifyProxyCallable {
  if (!leetifyProxyCallable) {
    const functions = getFunctions(app);
    leetifyProxyCallable = httpsCallable<LeetifyProxyRequest, unknown>(functions, 'leetifyProxy');
  }
  return leetifyProxyCallable;
}

/** Leetify Public CS API profile response (see api-public-docs.cs-prod.leetify.com) */
interface LeetifyProfileResponse {
  name?: string;
  steam64_id?: string;
  winrate?: number;
  total_matches?: number;
  ranks?: {
    leetify?: number;
    premier?: number;
    faceit?: number;
    competitive?: Array<{ map_name?: string; rank?: number }>;
    [k: string]: unknown;
  };
  rating?: {
    aim?: number;
    utility?: number;
    positioning?: number;
    [k: string]: unknown;
  };
  stats?: Record<string, unknown>;
  recent_matches?: Array<{
    id?: string;
    finished_at?: string;
    outcome?: string;
    leetify_rating?: number;
    [k: string]: unknown;
  }>;
  [k: string]: unknown;
}

function mapProfileToLeetifyStats(
  steamIdLegacy: string,
  displayName: string,
  data: LeetifyProfileResponse | null
): LeetifyStats {
  if (!data || typeof data !== 'object') {
    return { steamId: steamIdLegacy, displayName, noData: true };
  }

  const rating = data.rating && typeof data.rating === 'object' ? data.rating : undefined;
  const ranks = data.ranks && typeof data.ranks === 'object' ? data.ranks : undefined;
  const stats = data.stats && typeof data.stats === 'object' ? data.stats : undefined;

  // Leetify API: ranks.leetify = overall rating, ranks.premier = premier rank, rating.aim, rating.utility
  const premierRank = ranks?.premier;
  const leetifyRating = ranks?.leetify;

  const recentMatches = Array.isArray(data.recent_matches)
    ? data.recent_matches.slice(0, 10).map((m) => ({
        matchId: (m?.id ?? '') as string,
        finishedAt: m?.finished_at as string | undefined,
        result: (m?.outcome === 'win' ? 'win' : m?.outcome === 'loss' ? 'loss' : undefined) as 'win' | 'loss' | undefined,
      }))
    : undefined;

  const headshotPct = stats && typeof stats.accuracy_head === 'number' ? stats.accuracy_head : undefined;

  return {
    steamId: steamIdLegacy,
    displayName: (data.name as string) ?? displayName,
    leetifyRating: typeof leetifyRating === 'number' ? leetifyRating : undefined,
    aim: rating?.aim,
    utility: rating?.utility,
    gamesPlayed: typeof data.total_matches === 'number' ? data.total_matches : undefined,
    winRate: typeof data.winrate === 'number' ? data.winrate : undefined,
    hsRate: headshotPct,
    premierRank: premierRank !== undefined && premierRank !== null ? premierRank : undefined,
    recentMatches,
    noData: false,
  };
}

/**
 * Fetch Leetify profile for a player by Steam ID (legacy format). Returns stats for Premier section.
 * If the player is not on Leetify or profile is private, noData will be true.
 */
export async function getLeetifyProfile(
  steamIdLegacy: string,
  displayName: string
): Promise<LeetifyStats> {
  const steamId64 = legacyToSteamId64(steamIdLegacy);
  // Leetify Public CS API: GET /v3/profile?steam64_id=<Steam64 ID>
  const path = `/v3/profile?steam64_id=${encodeURIComponent(steamId64)}`;

  try {
    const callable = getLeetifyProxy();
    const result = await callable({ path, steamId64 });
    let data = result.data as LeetifyProfileResponse | null;
    if (import.meta.env.DEV && displayName) {
      const raw = data == null ? 'null' : JSON.stringify(data).slice(0, 600);
      console.log(`[Leetify] ${displayName} (${steamId64}):`, raw + (raw.length >= 600 ? '...' : ''));
    }
    // API can return 200 with { error: "..." } - treat as no data
    if (data && typeof data === 'object' && 'error' in data && typeof (data as Record<string, unknown>).error === 'string') {
      data = null;
    }
    // Unwrap if API returns { data: profile } or { profile: profile } or { player: profile }
    if (data && typeof data === 'object' && !Array.isArray(data)) {
      const wrapped = (data as Record<string, unknown>).data ?? (data as Record<string, unknown>).profile ?? (data as Record<string, unknown>).player;
      if (wrapped && typeof wrapped === 'object') {
        data = wrapped as LeetifyProfileResponse;
      }
    }
    return mapProfileToLeetifyStats(steamIdLegacy, displayName, data);
  } catch (err) {
    if (import.meta.env.DEV) {
      console.warn(`Leetify profile for ${displayName}:`, err);
    }
    return { steamId: steamIdLegacy, displayName, noData: true };
  }
}

/** JKVDF Leetify club dashboard URL for highlights (provided by Allstar). */
export const LEETIFY_CLUB_URL = 'https://leetify.com/app/club/53fc120c-b63f-4e52-92a2-b14c2f6eef86/dashboard';
