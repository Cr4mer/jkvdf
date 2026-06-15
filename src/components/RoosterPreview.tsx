import { useState, useEffect, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { collection } from 'firebase/firestore';
import { FaceitStats } from '@/types';
import { TEAM_MEMBERS } from '@/utils/steamWhitelist';
import { db } from '@/firebase';
import { useFirestoreCollection } from '@/hooks/useFirestoreCollection';

const members = TEAM_MEMBERS;

// A single recent match from either source, normalised for the activity feed.
type ActivityMatch = {
  source: 'FACEIT' | 'Premier';
  finishedAt: string; // ISO timestamp
  result?: 'win' | 'loss';
  kills?: number;
  deaths?: number;
  assists?: number;
};

// premierMatches/{faceitNickname-lowercased} — written by the Premier GitHub Action.
type PremierMatch = {
  matchId?: string;
  finishedAt?: string | null;
  result?: 'win' | 'loss' | null;
  kills?: number | null;
  deaths?: number | null;
  assists?: number | null;
  map?: string | null;
};
type PremierDoc = {
  id: string;
  faceitNickname?: string;
  matches?: PremierMatch[];
  profile?: { gamesInLast30Days?: number } | null;
};

export default function RoosterPreview() {
  const [stats, setStats] = useState<FaceitStats[]>([]);
  const [loading, setLoading] = useState(true);
  const [currentTime, setCurrentTime] = useState(new Date());

  // Premier matches come from Firestore (populated by the Premier GitHub Action), so this
  // works on the Spark plan with no Cloud Function. Public read; empty until the Action runs.
  const premierRef = useMemo(() => collection(db, 'premierMatches'), []);
  const { data: premierDocs } = useFirestoreCollection<PremierDoc>(premierRef);

  useEffect(() => {
    let cancelled = false;

    // FACEIT stats drive the loading / error state of the card.
    const loadFaceit = async () => {
      setLoading(true);
      try {
        // Fetch quick stats (50 matches per player for fast display), in batches of 2.
        const { getPlayerFullStats } = await import('@/utils/faceitApi');
        const loadedStats: FaceitStats[] = [];
        const batchSize = 2;

        for (let i = 0; i < members.length; i += batchSize) {
          const batch = members.slice(i, i + batchSize);
          const batchResults = await Promise.allSettled(
            batch.map((member) => getPlayerFullStats(member.faceitNickname, 50))
          );
          batchResults.forEach((result, index) => {
            if (result.status === 'fulfilled') {
              loadedStats.push(result.value);
            } else {
              console.error(`Failed to load FACEIT stats for ${batch[index].faceitNickname}:`, result.reason);
            }
          });

          if (i + batchSize < members.length) {
            await new Promise((resolve) => setTimeout(resolve, 150));
          }
        }

        if (!cancelled) setStats(loadedStats);
      } catch (err) {
        console.error('Failed to load preview stats:', err);
        if (!cancelled) setStats([]);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    loadFaceit();

    return () => {
      cancelled = true;
    };
  }, []);

  // Update current time every minute for the "time ago" counter
  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentTime(new Date());
    }, 60000);
    return () => clearInterval(interval);
  }, []);

  // Calculate most active player(s) - MUST be before any returns
  // Premier games in the last 30 days, by FACEIT nickname (from the ingest's profile).
  const premierGames30ByNick = useMemo(() => {
    const map: Record<string, number> = {};
    for (const d of premierDocs ?? []) {
      const nick = (d.faceitNickname ?? d.id ?? '').toLowerCase();
      const g = d.profile?.gamesInLast30Days;
      if (nick && typeof g === 'number') map[nick] = g;
    }
    return map;
  }, [premierDocs]);

  // Total recent activity = FACEIT + Premier games in the last 30 days.
  const games30 = (p: FaceitStats): number =>
    (p.gamesInLast30Days || 0) + (premierGames30ByNick[p.faceitNickname.toLowerCase()] || 0);

  const mostActivePlayers = useMemo(() => {
    if (stats.length === 0) return [];
    const maxGames = Math.max(...stats.map(games30));
    return stats.filter((p) => games30(p) === maxGames);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [stats, premierGames30ByNick]);

  // FACEIT nickname (lowercased) -> that player's Premier matches from Firestore.
  const premierByNick = useMemo(() => {
    const map: Record<string, PremierMatch[]> = {};
    for (const d of premierDocs ?? []) {
      const nick = (d.faceitNickname ?? d.id ?? '').toLowerCase();
      if (nick) map[nick] = Array.isArray(d.matches) ? d.matches : [];
    }
    return map;
  }, [premierDocs]);

  // Merge a player's FACEIT + Premier matches into one feed and show the most recent
  // ones — no per-source quota, so recent Premier isn't padded out with stale FACEIT.
  const RECENT_MATCH_LIMIT = 5;
  const getCombinedMatches = (player: FaceitStats): ActivityMatch[] => {
    const faceitMatches: ActivityMatch[] = (player.last3Games ?? []).map((g) => ({
      source: 'FACEIT',
      finishedAt: g.finishedAt,
      result: g.result,
      kills: g.kills,
      deaths: g.deaths,
      assists: g.assists,
    }));

    const premierMatches: ActivityMatch[] = (premierByNick[player.faceitNickname.toLowerCase()] ?? [])
      .filter((m): m is PremierMatch & { finishedAt: string } => typeof m.finishedAt === 'string' && m.finishedAt.length > 0)
      .map((m) => ({
        source: 'Premier',
        finishedAt: m.finishedAt,
        result: m.result ?? undefined,
        kills: m.kills ?? undefined,
        deaths: m.deaths ?? undefined,
        assists: m.assists ?? undefined,
      }));

    return [...faceitMatches, ...premierMatches]
      .filter((m) => !Number.isNaN(new Date(m.finishedAt).getTime()))
      .sort((a, b) => new Date(b.finishedAt).getTime() - new Date(a.finishedAt).getTime())
      .slice(0, RECENT_MATCH_LIMIT);
  };

  const formatMatchDate = (date: Date) =>
    date.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });

  const formatTimeAgo = (date: Date): string => {
    const diffInMins = Math.max(0, Math.floor((currentTime.getTime() - date.getTime()) / (1000 * 60)));
    const diffInHours = Math.floor(diffInMins / 60);
    const diffInDays = Math.floor(diffInHours / 24);
    if (diffInMins < 60) return `${diffInMins}m ago`;
    if (diffInHours < 24) return `${diffInHours}h ago`;
    return `${diffInDays}d ago`;
  };

  if (loading) {
    return (
      <div className="mt-12">
        <div className="border border-white/10 rounded-lg p-6 bg-neutral-900/50 backdrop-blur-sm">
          <div className="text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500 mx-auto mb-4"></div>
            <p className="text-gray-400">Loading team stats...</p>
          </div>
        </div>
      </div>
    );
  }

  if (stats.length === 0) {
    return (
      <div className="mt-12">
        <div className="border border-white/10 rounded-lg p-6 bg-neutral-900/50 backdrop-blur-sm">
          <div className="text-center">
            <div className="text-red-400 mb-4">⚠️</div>
            <h3 className="text-lg font-semibold text-red-400 mb-2">Failed to Load Stats</h3>
            <p className="text-gray-400 mb-4">
              Unable to fetch team stats from Faceit API. Please check:
            </p>
            <div className="text-left text-sm text-gray-400 space-y-1">
              <p>• API key is configured in .env file</p>
              <p>• Faceit API is accessible</p>
              <p>• Player nicknames are correct</p>
            </div>
            <button
              onClick={() => window.location.reload()}
              className="mt-4 px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded text-sm transition-colors"
            >
              Retry
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="mt-12">
      <div className="border border-white/10 rounded-lg p-6 bg-neutral-900/50 backdrop-blur-sm">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-semibold flex items-center gap-2">
            <span className="text-2xl">👥</span>
            Recent Activity
          </h2>
          <Link
            to="/rooster"
            className="text-sm text-blue-400 hover:text-blue-300 transition-colors"
          >
            Go to JKVDF Performance Center →
          </Link>
        </div>

        <div className="grid grid-cols-1 gap-6 mb-6">
          {/* Most Active Player */}
          {mostActivePlayers.length > 0 && (
            <div className="bg-gradient-to-r from-green-900/30 to-emerald-900/30 border border-green-500/30 rounded-lg p-4">
              <h3 className="text-sm font-semibold text-green-400 uppercase tracking-wide mb-3">
                Most Active Player
              </h3>
              <div className="space-y-2">
                {mostActivePlayers.map((player) => (
                  <div key={player.playerId} className="flex items-center justify-between">
                    <span className="font-semibold text-green-300">{player.faceitNickname}</span>
                    <span className="text-sm text-gray-300">
                      {games30(player)} games in last 30 days
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
          {/* Recent Matches (FACEIT + CS2 Premier) */}
          <div className="bg-neutral-800/50 rounded-lg p-4">
            <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
              <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wide">Recent Matches</h3>
              <div className="flex items-center gap-2 text-[10px] uppercase tracking-wide">
                <span className="px-1.5 py-0.5 rounded bg-orange-900/50 text-orange-300">FACEIT</span>
                <span className="px-1.5 py-0.5 rounded bg-purple-900/50 text-purple-300">Premier</span>
              </div>
            </div>
            <div className="space-y-3">
              {stats.map((player) => {
                const matches = getCombinedMatches(player);
                return (
                  <div key={player.playerId} className="space-y-2">
                    <div className="text-sm font-medium text-blue-400">{player.faceitNickname}</div>
                    <div className="space-y-1">
                      {matches.length === 0 ? (
                        <div className="text-xs text-gray-500">No recent games</div>
                      ) : (
                        matches.map((game, index) => {
                          const gameDate = new Date(game.finishedAt);
                          return (
                            <div
                              key={`${player.playerId}-${game.source}-${index}`}
                              className="flex items-center justify-between text-xs bg-neutral-700/30 rounded px-2 py-1"
                            >
                              <div className="flex items-center gap-2 flex-wrap">
                                <span
                                  className={`px-1 rounded text-[10px] uppercase tracking-wide ${
                                    game.source === 'FACEIT'
                                      ? 'bg-orange-900/50 text-orange-300'
                                      : 'bg-purple-900/50 text-purple-300'
                                  }`}
                                >
                                  {game.source}
                                </span>
                                <span className="text-gray-400">{formatMatchDate(gameDate)}</span>
                                <span className="text-gray-500">({formatTimeAgo(gameDate)})</span>
                                {game.result && (
                                  <span
                                    className={`px-1 rounded text-xs ${
                                      game.result === 'win' ? 'bg-green-900/50 text-green-300' : 'bg-red-900/50 text-red-300'
                                    }`}
                                  >
                                    {game.result === 'win' ? 'W' : 'L'}
                                  </span>
                                )}
                                {game.kills != null && game.deaths != null && (
                                  <span className="text-gray-300">
                                    {game.kills}/{game.deaths}/{game.assists ?? 0}
                                  </span>
                                )}
                              </div>
                            </div>
                          );
                        })
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
