import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { FaceitStats, LeetifyStats } from '@/types';
import { TEAM_MEMBERS } from '@/utils/steamWhitelist';
import { LEETIFY_CLUB_URL } from '@/utils/leetifyApi';
import { db } from '@/firebase';
import { collection, getDocs } from 'firebase/firestore';

const members = TEAM_MEMBERS;

type PremierProfile = {
  gamesPlayed?: number;
  winRate?: number;
  kd?: number;
  avgKills?: number;
  hsRate?: number;
  leetifyRating?: number | null;
  mvps?: number;
};
type PremierDocData = {
  faceitNickname?: string;
  displayName?: string;
  matches?: unknown[];
  profile?: PremierProfile | null;
};

export default function RoosterPage() {
  const [stats, setStats] = useState<FaceitStats[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [weekRange, setWeekRange] = useState<'2W' | '10W' | '52W' | 'all-time'>('10W'); // Default to 10 weeks
  const [activeSection, setActiveSection] = useState<'simple-stats' | 'recent-activity' | 'premier' | 'highlights'>('simple-stats');
  const [leetifyStats, setLeetifyStats] = useState<LeetifyStats[]>([]);
  const [leetifyLoading, setLeetifyLoading] = useState(false);
  const [leetifyError, setLeetifyError] = useState<string | null>(null);

  const loadStats = async (isManualRefresh = false) => {
    if (isManualRefresh) {
      setIsRefreshing(true);
    } else {
      setLoading(true);
    }
    
    try {
      // FIRST PASS: Fetch quick stats (50 matches per player for fast display)
      // Process in batches of 3 to avoid rate limiting while still being reasonably fast
      const { getPlayerFullStats, updatePlayerStatsWithMoreMatches } = await import('@/utils/faceitApi');
      
      const loadedStats: FaceitStats[] = [];
      const batchSize = 3;
      
      for (let i = 0; i < members.length; i += batchSize) {
        const batch = members.slice(i, i + batchSize);
        const batchPromises = batch.map(async (member) => {
          try {
            // Fetch only 50 matches for quick display
            return await getPlayerFullStats(member.faceitNickname, 50);
          } catch (err) {
            console.error(`Failed to load stats for ${member.faceitNickname}:`, err);
            // Re-throw the error to let the main catch block handle it
            throw err;
          }
        });
        
        const batchResults = await Promise.all(batchPromises);
        loadedStats.push(...batchResults);
        
        // Reduced delay between batches
        if (i + batchSize < members.length) {
          await new Promise(resolve => setTimeout(resolve, 150));
        }
      }
      
      // Show initial stats immediately
      setStats(loadedStats);
      setLoading(false);
      setIsRefreshing(false);
      
      // SECOND PASS: Fetch full matches in background for accurate weekly averages
      for (let i = 0; i < loadedStats.length; i++) {
        const currentStats = loadedStats[i];
        try {
          // Try cs2 first, fallback to csgo
          let updated;
          try {
            updated = await updatePlayerStatsWithMoreMatches(currentStats, 'cs2');
          } catch (error) {
            updated = await updatePlayerStatsWithMoreMatches(currentStats, 'csgo');
          }
          
          // Update UI progressively
          const updatedStats = [...loadedStats];
          updatedStats[i] = updated;
          setStats([...updatedStats]);
          
        } catch (err) {
          console.error(`Failed to update stats for ${currentStats.faceitNickname}:`, err);
        }
        
        // Small delay between updates
        if (i < loadedStats.length - 1) {
          await new Promise(resolve => setTimeout(resolve, 200));
        }
      }
      
    } catch (err) {
      console.error('Failed to load stats:', err);
      setError('Failed to load stats.');
      setStats([]);
      setLoading(false);
      setIsRefreshing(false);
    }
  };

  // Premier stats come from the premierMatches Firestore collection (populated by the
  // Premier GitHub Action). No Cloud Function, so this works on the Spark plan.
  const loadLeetifyStats = async () => {
    setLeetifyLoading(true);
    setLeetifyError(null);
    try {
      const snap = await getDocs(collection(db, 'premierMatches'));
      const byNick: Record<string, PremierDocData> = {};
      snap.forEach((d) => {
        const data = d.data() as PremierDocData;
        byNick[String(data.faceitNickname ?? d.id).toLowerCase()] = data;
      });

      const results: LeetifyStats[] = members.map((m) => {
        const doc = byNick[m.faceitNickname.toLowerCase()];
        const p = doc?.profile;
        const hasData = !!p && (doc?.matches?.length ?? 0) > 0;
        if (!hasData) {
          return { steamId: m.steamId, displayName: m.name, noData: true };
        }
        return {
          steamId: m.steamId,
          displayName: m.name,
          noData: false,
          leetifyRating: p?.leetifyRating ?? undefined,
          gamesPlayed: p?.gamesPlayed,
          winRate: p?.winRate,
          kd: p?.kd,
          avgKills: p?.avgKills,
          hsRate: p?.hsRate,
        };
      });
      setLeetifyStats(results);
    } catch (err: unknown) {
      console.error('Failed to load Premier stats from Firestore:', err);
      setLeetifyError('Failed to load Premier stats. Try again later.');
      setLeetifyStats(members.map((m) => ({ steamId: m.steamId, displayName: m.name, noData: true })));
    } finally {
      setLeetifyLoading(false);
    }
  };

  useEffect(() => {
    if (stats.length === 0) {
      loadStats();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (leetifyStats.length === 0 && activeSection === 'premier') {
      loadLeetifyStats();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeSection]);

  const handleRefresh = () => {
    loadStats(true);
    loadLeetifyStats();
  };

  const handleRefreshPremier = () => {
    loadLeetifyStats();
  };

  // Find Gamer of the Last 30 Games (sorted by MVPs)
  const playersWithLast30Games = stats.filter(player => (player.last30Games || 0) > 0);
  const sortedByLast30Mvps = [...playersWithLast30Games].sort((a, b) => (b.last30Mvps || 0) - (a.last30Mvps || 0));
  const gamerOfTheLast30 = sortedByLast30Mvps[0];
  
  // Find Gamer of the Last 5 Games (sorted by MVPs)
  const playersWithLast5Games = stats.filter(player => (player.last5Games || 0) > 0);
  const sortedByLast5Mvps = [...playersWithLast5Games].sort((a, b) => (b.last5Mvps || 0) - (a.last5Mvps || 0));
  const gamerOfTheLast5 = sortedByLast5Mvps[0];

  return (
    <div className="flex flex-col md:flex-row gap-6 max-w-7xl mx-auto px-4 md:px-0">
      {/* Top Navigation for Mobile, Left Sidebar for Desktop */}
      <div className="order-2 md:order-1 hidden md:block w-64 flex-shrink-0">
        <div className="sticky top-4">
          <div className="bg-neutral-900/50 backdrop-blur-sm border border-white/10 rounded-lg p-4">
            <h2 className="text-lg font-bold mb-4 text-gray-300">Navigation</h2>
            <nav className="space-y-2">
              <button
                onClick={() => setActiveSection('simple-stats')}
                className={`w-full text-left px-4 py-2 rounded-lg transition-colors ${
                  activeSection === 'simple-stats'
                    ? 'bg-blue-600 text-white'
                    : 'text-gray-400 hover:text-white hover:bg-neutral-800'
                }`}
              >
                FACEIT – Simple Stats
              </button>
              <button
                onClick={() => setActiveSection('recent-activity')}
                className={`w-full text-left px-4 py-2 rounded-lg transition-colors ${
                  activeSection === 'recent-activity'
                    ? 'bg-blue-600 text-white'
                    : 'text-gray-400 hover:text-white hover:bg-neutral-800'
                }`}
              >
                FACEIT – Activity
              </button>
              <button
                onClick={() => setActiveSection('premier')}
                className={`w-full text-left px-4 py-2 rounded-lg transition-colors ${
                  activeSection === 'premier'
                    ? 'bg-blue-600 text-white'
                    : 'text-gray-400 hover:text-white hover:bg-neutral-800'
                }`}
              >
                Premier stats
              </button>
              <button
                onClick={() => setActiveSection('highlights')}
                className={`w-full text-left px-4 py-2 rounded-lg transition-colors ${
                  activeSection === 'highlights'
                    ? 'bg-blue-600 text-white'
                    : 'text-gray-400 hover:text-white hover:bg-neutral-800'
                }`}
              >
                Highlights
              </button>
            </nav>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 order-1 md:order-2">
        {/* Header with Mobile Navigation */}
        <div className="mb-6 space-y-4">
          <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-4">
            <h1 className="text-2xl sm:text-3xl font-bold">JKVDF Performance Center</h1>

            <button
              onClick={handleRefresh}
              disabled={isRefreshing || loading}
              className="w-full sm:w-auto px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg font-medium transition-colors flex items-center justify-center gap-2"
            >
              {isRefreshing ? (
                <>
                  <svg className="animate-spin h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Refreshing...
                </>
              ) : (
                <>
                  <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                  </svg>
                  Refresh Stats
                </>
              )}
            </button>
          </div>
          
          {/* Mobile Navigation */}
          <div className="md:hidden bg-neutral-900/50 backdrop-blur-sm border border-white/10 rounded-lg p-2">
            <div className="flex flex-wrap gap-2">
              <button
                onClick={() => setActiveSection('simple-stats')}
                className={`flex-1 min-w-[100px] px-4 py-2 rounded-lg transition-colors text-sm font-medium ${
                  activeSection === 'simple-stats'
                    ? 'bg-blue-600 text-white'
                    : 'text-gray-400 hover:text-white hover:bg-neutral-800'
                }`}
              >
                FACEIT Stats
              </button>
              <button
                onClick={() => setActiveSection('recent-activity')}
                className={`flex-1 min-w-[100px] px-4 py-2 rounded-lg transition-colors text-sm font-medium ${
                  activeSection === 'recent-activity'
                    ? 'bg-blue-600 text-white'
                    : 'text-gray-400 hover:text-white hover:bg-neutral-800'
                }`}
              >
                Activity
              </button>
              <button
                onClick={() => setActiveSection('premier')}
                className={`flex-1 min-w-[100px] px-4 py-2 rounded-lg transition-colors text-sm font-medium ${
                  activeSection === 'premier'
                    ? 'bg-blue-600 text-white'
                    : 'text-gray-400 hover:text-white hover:bg-neutral-800'
                }`}
              >
                Premier
              </button>
              <button
                onClick={() => setActiveSection('highlights')}
                className={`flex-1 min-w-[100px] px-4 py-2 rounded-lg transition-colors text-sm font-medium ${
                  activeSection === 'highlights'
                    ? 'bg-blue-600 text-white'
                    : 'text-gray-400 hover:text-white hover:bg-neutral-800'
                }`}
              >
                Highlights
              </button>
            </div>
          </div>
        </div>

      {/* Conditional Content Based on Active Section */}
      {activeSection === 'simple-stats' && (
        <>
          {/* Awards Section */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
        {/* Gamer of the Last 30 Games */}
        {gamerOfTheLast30 ? (
          <div className="bg-gradient-to-r from-blue-900/30 to-cyan-900/30 border border-blue-500/30 rounded-lg p-4 sm:p-6">
            <div className="flex items-center justify-between gap-4">
              <div className="flex-1">
                <p className="text-blue-400 text-xs sm:text-sm font-semibold uppercase tracking-wide mb-1">
                  MVP of the Last 30 Games
                </p>
                <h2 className="text-xl sm:text-2xl font-bold text-blue-300 truncate">{gamerOfTheLast30.faceitNickname}</h2>
                <p className="text-gray-300 mt-2">
                  <span className="text-blue-400 font-semibold">MVPs:</span> {gamerOfTheLast30.last30Mvps || 0}
                </p>
              </div>
              <div className="text-3xl sm:text-4xl flex-shrink-0">⭐</div>
            </div>
          </div>
        ) : (
          <div className="bg-neutral-800/50 border border-neutral-700/50 rounded-lg p-6 text-center">
            <p className="text-gray-400 text-sm">No recent games played</p>
          </div>
        )}

        {/* Gamer of the Last 5 Games */}
        {gamerOfTheLast5 ? (
          <div className="bg-gradient-to-r from-yellow-900/30 to-orange-900/30 border border-yellow-500/30 rounded-lg p-4 sm:p-6">
            <div className="flex items-center justify-between gap-4">
              <div className="flex-1">
                <p className="text-yellow-400 text-xs sm:text-sm font-semibold uppercase tracking-wide mb-1">
                  MVP of the Last 5 Games
                </p>
                <h2 className="text-xl sm:text-2xl font-bold text-yellow-300 truncate">{gamerOfTheLast5.faceitNickname}</h2>
                <p className="text-gray-300 mt-2">
                  <span className="text-yellow-400 font-semibold">MVPs:</span> {gamerOfTheLast5.last5Mvps || 0}
                </p>
              </div>
              <div className="text-3xl sm:text-4xl flex-shrink-0">🏆</div>
            </div>
          </div>
        ) : (
          <div className="bg-neutral-800/50 border border-neutral-700/50 rounded-lg p-6 text-center">
            <p className="text-gray-400 text-sm">No recent games played</p>
          </div>
        )}
          </div>

          <p className="text-gray-400 mb-6 text-center">JKVDF Team - Faceit Stats (Last 30 Games)</p>

          {loading && <div className="text-center py-12">Loading stats...</div>}
          {error && <div className="text-center text-red-400 py-12">{error}</div>}

          {/* Player Stats Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {stats.map((playerStats) => (
          <div
            key={playerStats.playerId}
            className="border border-white/10 rounded-lg p-6 bg-neutral-900/50 backdrop-blur-sm hover:border-white/20 transition-colors"
          >
            <h3 className="text-xl font-bold mb-4">{playerStats.faceitNickname}</h3>
            
            <div className="space-y-3">
              {/* Win Rate */}
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-gray-400">Win Rate</span>
                  <span className="font-semibold">{playerStats.winRate.toFixed(1)}%</span>
                </div>
                <div className="h-2 bg-neutral-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-blue-500"
                    style={{ width: `${playerStats.winRate}%` }}
                  />
                </div>
              </div>

              {/* K/D */}
              <div className="flex justify-between">
                <span className="text-gray-400">K/D</span>
                <span className="font-semibold">{playerStats.kd.toFixed(2)}</span>
              </div>

              {/* Average Kills */}
              <div className="flex justify-between">
                <span className="text-gray-400">Avg Kills</span>
                <span className="font-semibold">{playerStats.avgKills.toFixed(1)}</span>
              </div>

              {/* Average Deaths */}
              <div className="flex justify-between">
                <span className="text-gray-400">Avg Deaths</span>
                <span className="font-semibold">{playerStats.avgDeaths.toFixed(1)}</span>
              </div>

              {/* Headshot Rate */}
              <div className="flex justify-between">
                <span className="text-gray-400">Headshot %</span>
                <span className="font-semibold">{playerStats.hsRate.toFixed(1)}%</span>
              </div>

              {/* MVP Count */}
              <div className="flex justify-between">
                <span className="text-gray-400">MVPs</span>
                <span className="font-semibold">{playerStats.last30Mvps || 0}</span>
              </div>

              {/* Games Last 30 Days */}
              <div className="flex justify-between">
                <span className="text-gray-400">Games (30 Days)</span>
                <span className="font-semibold">{playerStats.gamesInLast30Days || 0}</span>
              </div>

              {/* Go to Profile Button */}
              <div className="pt-3 border-t border-white/10 flex justify-center">
                <a
                  href={`https://www.faceit.com/en/players/${playerStats.faceitNickname}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-block hover:opacity-80 transition-opacity"
                  title="View Faceit Profile"
                >
                  <img 
                    src="/faceit.png" 
                    alt="Faceit Logo" 
                    className="h-8 w-auto"
                  />
                </a>
              </div>
            </div>
          </div>
        ))}
          </div>

          {/* MVP Visualization Chart */}
          {stats.length > 0 && (
            <div className="mt-12 border border-white/10 rounded-lg p-6 bg-neutral-900/50 backdrop-blur-sm">
          <h3 className="text-xl font-bold mb-6 text-center">MVP Distribution</h3>
          <div className="space-y-3">
            {stats
              .sort((a, b) => (b.last30Mvps || 0) - (a.last30Mvps || 0))
              .map((player) => {
                const maxMvps = Math.max(...stats.map(p => p.last30Mvps || 0), 1);
                const percentage = ((player.last30Mvps || 0) / maxMvps) * 100;
                
                return (
                  <div key={player.playerId} className="flex items-center gap-4">
                    <div className="w-32 text-sm font-semibold truncate">
                      {player.faceitNickname}
                    </div>
                    <div className="flex-1 h-6 bg-neutral-800 rounded-full overflow-hidden relative">
                      <div
                        className="h-full bg-gradient-to-r from-yellow-500 to-orange-500 transition-all duration-500"
                        style={{ width: `${percentage}%` }}
                      />
                      <div className="absolute inset-0 flex items-center justify-center text-xs font-bold text-white">
                        {player.last30Mvps || 0}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
        </>
      )}

      {activeSection === 'recent-activity' && (
        <div>
          <h2 className="text-xl sm:text-2xl font-bold mb-6">Activity</h2>

          {/* Last 3 Games Section */}
          {stats.length > 0 && (
            <div className="mb-8 border border-white/10 rounded-lg p-6 bg-neutral-900/50 backdrop-blur-sm">
              <h3 className="text-xl font-bold mb-4 text-center">Last 3 Games</h3>
              <div className="bg-neutral-800/50 rounded-lg p-4">
                <div className="space-y-4">
                  {stats.map((player) => (
                    <div key={player.playerId} className="space-y-2">
                      <div className="text-sm font-medium text-blue-400">{player.faceitNickname}</div>
                      <div className="space-y-1">
                        {player.last3Games && player.last3Games.length > 0 ? (
                          player.last3Games.map((game, index) => {
                            const gameDate = new Date(game.finishedAt);
                            const formattedDate = gameDate.toLocaleDateString('en-US', { 
                              year: 'numeric',
                              month: 'short', 
                              day: 'numeric',
                              hour: '2-digit',
                              minute: '2-digit'
                            });
                            
                            // Calculate time ago
                            const now = new Date();
                            const diffInMs = now.getTime() - gameDate.getTime();
                            const diffInMins = Math.floor(diffInMs / (1000 * 60));
                            const diffInHours = Math.floor(diffInMins / 60);
                            const diffInDays = Math.floor(diffInHours / 24);
                            
                            let timeAgo;
                            if (diffInMins < 60) {
                              timeAgo = `${diffInMins}m ago`;
                            } else if (diffInHours < 24) {
                              timeAgo = `${diffInHours}h ago`;
                            } else {
                              timeAgo = `${diffInDays}d ago`;
                            }
                            
                            return (
                              <div key={`${player.playerId}-game-${index}`} className="flex items-center justify-between text-xs bg-neutral-700/30 rounded px-2 py-1">
                                <div className="flex items-center gap-2">
                                  <span className="text-gray-400">{formattedDate}</span>
                                  <span className="text-gray-500">({timeAgo})</span>
                                  <span className={`px-1 rounded text-xs ${game.result === 'win' ? 'bg-green-900/50 text-green-300' : 'bg-red-900/50 text-red-300'}`}>
                                    {game.result === 'win' ? 'W' : 'L'}
                                  </span>
                                  <span className="text-gray-300">
                                    {game.kills}/{game.deaths}/{game.assists}
                                  </span>
                                </div>
                              </div>
                            );
                          })
                        ) : (
                          <div className="text-xs text-gray-500">No recent games</div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Average Games Per Week Section - Moved to bottom */}
          {stats.length > 0 && (
            <div className="border border-white/10 rounded-lg p-6 bg-neutral-900/50 backdrop-blur-sm">
              <div className="mb-6">
                <h3 className="text-xl font-bold mb-4 text-center">Average Games Per Week</h3>
                
                {/* Week Range Selector */}
                <div className="flex justify-center">
                  <div className="inline-flex bg-neutral-800 rounded-lg p-1 gap-1 flex-wrap">
                    <button
                      onClick={() => setWeekRange('2W')}
                      className={`px-2 sm:px-4 py-2 rounded-md text-xs sm:text-sm font-medium transition-colors ${
                        weekRange === '2W'
                          ? 'bg-neutral-700 text-white'
                          : 'text-gray-400 hover:text-white'
                      }`}
                    >
                      2W
                    </button>
                    <button
                      onClick={() => setWeekRange('10W')}
                      className={`px-2 sm:px-4 py-2 rounded-md text-xs sm:text-sm font-medium transition-colors ${
                        weekRange === '10W'
                          ? 'bg-neutral-700 text-white'
                          : 'text-gray-400 hover:text-white'
                      }`}
                    >
                      10W
                    </button>
                    <button
                      onClick={() => setWeekRange('52W')}
                      className={`px-2 sm:px-4 py-2 rounded-md text-xs sm:text-sm font-medium transition-colors ${
                        weekRange === '52W'
                          ? 'bg-neutral-700 text-white'
                          : 'text-gray-400 hover:text-white'
                      }`}
                    >
                      1Y
                    </button>
                    <button
                      onClick={() => setWeekRange('all-time')}
                      className={`px-2 sm:px-4 py-2 rounded-md text-xs sm:text-sm font-medium transition-colors ${
                        weekRange === 'all-time'
                          ? 'bg-neutral-700 text-white'
                          : 'text-gray-400 hover:text-white'
                      }`}
                    >
                      All
                    </button>
                  </div>
                </div>
              </div>

              {/* Stats Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {stats.map((player) => {
                  const avgGames = weekRange === '2W' 
                    ? (player.avgGamesPerWeek2W || 0)
                    : weekRange === '10W'
                    ? (player.avgGamesPerWeek10W || 0)
                    : weekRange === '52W'
                    ? (player.avgGamesPerWeek52W || 0)
                    : weekRange === 'all-time'
                    ? (player.avgGamesPerWeekAllTime || 0)
                    : 0;
                  
                  return (
                    <div 
                      key={player.playerId} 
                      className="bg-neutral-800/50 rounded-lg p-4 border border-white/5"
                    >
                      <div className="flex justify-between items-center">
                        <span className="text-gray-300 font-medium">{player.faceitNickname}</span>
                        <span className="text-white font-bold text-lg">{avgGames.toFixed(1)}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}

      {activeSection === 'premier' && (
        <div>
          <h2 className="text-xl sm:text-2xl font-bold mb-2">Premier stats</h2>
          <p className="text-gray-400 text-sm mb-6">CS2 Premier stats from Leetify (same metrics as FACEIT plus Leetify Rating, Aim, Utility).</p>
          <div className="flex flex-wrap items-center gap-3 mb-4">
            <button
              type="button"
              onClick={handleRefreshPremier}
              disabled={leetifyLoading}
              className="px-4 py-2 rounded-lg bg-white/10 hover:bg-white/20 text-sm font-medium disabled:opacity-50"
            >
              {leetifyLoading ? 'Loading…' : 'Refresh Premier stats'}
            </button>
          </div>
          {leetifyError && (
            <div className="mb-4 p-4 rounded-lg bg-amber-500/20 border border-amber-500/40 text-amber-200 text-sm">
              {leetifyError}
            </div>
          )}
          {leetifyLoading ? (
            <div className="text-center py-12 text-gray-400">Loading Premier stats...</div>
          ) : (
            <>
              {!leetifyError && leetifyStats.length > 0 && leetifyStats.every((p) => p.noData) && (
                <div className="mb-6 p-5 rounded-xl bg-blue-500/10 border border-blue-500/30 text-blue-100">
                  <p className="font-medium mb-1">No Premier stats yet — setup required</p>
                  <p className="text-sm text-blue-200/90">
                    Stats here come from Leetify. Each player must{' '}
                    <a href="https://leetify.com" target="_blank" rel="noopener noreferrer" className="text-pink-300 hover:underline">sign up at leetify.com</a>
                    , then in Leetify <strong>link their Steam account</strong> (same Steam ID as in the team list). 
                    After that, their Premier stats will show up when you refresh.
                  </p>
                </div>
              )}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {leetifyStats.map((player) => (
                  <div
                    key={player.steamId}
                    className="border border-white/10 rounded-lg p-6 bg-neutral-900/50 backdrop-blur-sm"
                  >
                    <h3 className="text-xl font-bold mb-4">{player.displayName}</h3>
                    {player.noData ? (
                      <p className="text-gray-500 text-sm">No Leetify data (sign up at leetify.com to appear here)</p>
                    ) : (
                      <div className="space-y-3">
                        {player.leetifyRating != null && (
                          <div className="flex justify-between">
                            <span className="text-gray-400">Leetify Rating</span>
                            <span className="font-semibold">{Number(player.leetifyRating).toFixed(2)}</span>
                          </div>
                        )}
                        {player.aim != null && (
                          <div className="flex justify-between">
                            <span className="text-gray-400">Aim</span>
                            <span className="font-semibold">{Number(player.aim).toFixed(2)}</span>
                          </div>
                        )}
                        {player.utility != null && (
                          <div className="flex justify-between">
                            <span className="text-gray-400">Utility</span>
                            <span className="font-semibold">{Number(player.utility).toFixed(2)}</span>
                          </div>
                        )}
                        {player.premierRank != null && (
                          <div className="flex justify-between">
                            <span className="text-gray-400">Premier rank</span>
                            <span className="font-semibold">{String(player.premierRank)}</span>
                          </div>
                        )}
                        {player.gamesPlayed != null && (
                          <div className="flex justify-between">
                            <span className="text-gray-400">Games</span>
                            <span className="font-semibold">{player.gamesPlayed}</span>
                          </div>
                        )}
                        {player.winRate != null && (
                          <div className="flex justify-between">
                            <span className="text-gray-400">Win rate</span>
                            <span className="font-semibold">{(Number(player.winRate) * 100).toFixed(1)}%</span>
                          </div>
                        )}
                        {player.kd != null && (
                          <div className="flex justify-between">
                            <span className="text-gray-400">K/D</span>
                            <span className="font-semibold">{Number(player.kd).toFixed(2)}</span>
                          </div>
                        )}
                        {player.hsRate != null && (
                          <div className="flex justify-between">
                            <span className="text-gray-400">Headshot %</span>
                            <span className="font-semibold">{Number(player.hsRate).toFixed(1)}%</span>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
              <div className="mt-6 text-center">
                <a
                  href="https://leetify.com"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-sm text-gray-400 hover:text-pink-400 transition-colors"
                >
                  Data provided by Leetify
                </a>
              </div>
            </>
          )}
        </div>
      )}

      {activeSection === 'highlights' && (
        <div>
          <h2 className="text-xl sm:text-2xl font-bold mb-2">Highlights</h2>
          <p className="text-gray-400 text-sm mb-6">Team highlights from the Leetify club (provided by Allstar).</p>
          <div className="border border-white/10 rounded-lg p-6 bg-neutral-900/50 backdrop-blur-sm">
            <a
              href={LEETIFY_CLUB_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 px-4 py-3 bg-neutral-800 hover:bg-neutral-700 rounded-lg font-medium transition-colors"
            >
              Open JKVDF Leetify Club Dashboard
            </a>
            <p className="mt-4 text-sm text-gray-500">
              View group stats and highlights on Leetify. Data provided by Leetify; highlights by Allstar.
            </p>
          </div>
        </div>
      )}
        </div>
      {/* End Main Content */}
    </div>
  );
}
