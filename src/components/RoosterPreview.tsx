import { useState, useEffect, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { FaceitStats } from '@/types';

type MemberData = {
  name: string;
  faceitNickname: string;
};

const members: MemberData[] = [
  { name: 'Cr4mer', faceitNickname: 'Cr4mer' },
  { name: 'Faqin', faceitNickname: 'faqin' },
  { name: 'Pharty', faceitNickname: 'pharty' },
  { name: 'Psykenn', faceitNickname: 'psYKENN' },
  { name: 'TIS_Black_Panther', faceitNickname: 'Black_panth' },
  { name: 'KQligChris', faceitNickname: 'KQligchris' },
  { name: 'Kattepeter', faceitNickname: 'kattepeter' },
];

// Helper function to format time ago
function getTimeAgo(date: Date): string {
  const now = new Date();
  const diffInMs = now.getTime() - date.getTime();
  const diffInHours = Math.floor(diffInMs / (1000 * 60 * 60));
  const diffInDays = Math.floor(diffInHours / 24);
  
  if (diffInHours < 1) {
    return 'Just now';
  } else if (diffInHours < 24) {
    return `${diffInHours}h ago`;
  } else if (diffInDays < 7) {
    return `${diffInDays}d ago`;
  } else {
    return date.toLocaleDateString();
  }
}

export default function RoosterPreview() {
  const [stats, setStats] = useState<FaceitStats[]>([]);
  const [loading, setLoading] = useState(true);
  const [currentTime, setCurrentTime] = useState(new Date());

  useEffect(() => {
    const loadPreviewStats = async () => {
      setLoading(true);
      try {
      // Fetch quick stats (50 matches per player for fast display)
      // Process in batches of 2 to avoid rate limiting while still being reasonably fast
      const { getPlayerFullStats } = await import('@/utils/faceitApi');
      
      const loadedStats: FaceitStats[] = [];
      const batchSize = 2;
        
        for (let i = 0; i < members.length; i += batchSize) {
          const batch = members.slice(i, i + batchSize);
          const batchPromises = batch.map(async (member) => {
            // Fetch only 50 matches for quick display
            return await getPlayerFullStats(member.faceitNickname, 50);
          });
          
          const batchResults = await Promise.allSettled(batchPromises);
          const successfulResults = batchResults
            .filter((result): result is PromiseFulfilledResult<any> => result.status === 'fulfilled')
            .map(result => result.value);
          
          // Log failed requests
          batchResults.forEach((result, index) => {
            if (result.status === 'rejected') {
              console.error(`Failed to load stats for ${batch[index].faceitNickname}:`, result.reason);
            }
          });
          
          loadedStats.push(...successfulResults);
          
          // Reduced delay between batches
          if (i + batchSize < members.length) {
            await new Promise(resolve => setTimeout(resolve, 150));
          }
        }
        
        setStats(loadedStats);
      } catch (err) {
        console.error('Failed to load preview stats:', err);
        // Show error state instead of mock data
        setStats([]);
      } finally {
        setLoading(false);
      }
    };

    loadPreviewStats();
  }, []);

  // Update current time every minute for the time ago counter
  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentTime(new Date());
    }, 60000); // Update every minute

    return () => clearInterval(interval);
  }, []);

  // Calculate most active player(s) - MUST be before any returns
  const mostActivePlayers = useMemo(() => {
    if (stats.length === 0) return [];
    
    // Find the max number of games in last 30 days
    const maxGames = Math.max(...stats.map(p => p.gamesInLast30Days || 0));
    
    // Find all players with the max games (handles ties)
    return stats.filter(p => (p.gamesInLast30Days || 0) === maxGames);
  }, [stats]);

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
                      {player.gamesInLast30Days || 0} games in last 30 days
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
          {/* Last 3 Games */}
          <div className="bg-neutral-800/50 rounded-lg p-4">
            <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-3">Last 3 Games</h3>
            <div className="space-y-3">
              {stats.map((player) => (
                <div key={player.playerId} className="space-y-2">
                  <div className="text-sm font-medium text-blue-400">{player.faceitNickname}</div>
                  <div className="space-y-1">
                    {player.last3Games?.map((game, index) => {
                      const gameDate = new Date(game.finishedAt);
                      const formattedDate = gameDate.toLocaleDateString('en-US', { 
                        year: 'numeric',
                        month: 'short', 
                        day: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit'
                      });
                      
                      // Calculate time ago
                      const diffInMs = currentTime.getTime() - gameDate.getTime();
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
                    }) || []}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
