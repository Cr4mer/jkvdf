/**
 * Faceit API Integration
 *
 * When VITE_FACEIT_API_KEY is set (at build time): use direct FACEIT API (no Cloud Function, no CORS).
 * When not set: use Firebase Callable `faceitProxy` (key on server).
 *
 * API Documentation: https://developers.faceit.com/
 */

import { getFunctions, httpsCallable, HttpsCallable } from 'firebase/functions';
import { app } from '@/firebase';

const FACEIT_API_BASE = 'https://open.faceit.com/data/v4';
const FACEIT_API_KEY = import.meta.env.VITE_FACEIT_API_KEY as string | undefined;

let faceitProxyCallable: HttpsCallable<{ endpoint: string }, unknown> | null = null;

function getFaceitProxy(): HttpsCallable<{ endpoint: string }, unknown> {
  if (!faceitProxyCallable) {
    const functions = getFunctions(app);
    faceitProxyCallable = httpsCallable<{ endpoint: string }, unknown>(functions, 'faceitProxy');
  }
  return faceitProxyCallable;
}

async function faceitRequestDirect<T>(endpoint: string): Promise<T> {
  if (!FACEIT_API_KEY) {
    throw new Error('Faceit API key not configured. Add VITE_FACEIT_API_KEY to .env or deploy the faceitProxy function.');
  }
  const response = await fetch(`${FACEIT_API_BASE}${endpoint}`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${FACEIT_API_KEY}`,
      'Content-Type': 'application/json',
    },
  });
  if (!response.ok) {
    if (response.status === 429) {
      await delay(2000);
      return faceitRequestDirect<T>(endpoint);
    }
    throw new Error(`Faceit API error: ${response.status} ${response.statusText}`);
  }
  return response.json();
}

interface FaceitPlayerResponse {
  player_id: string;
  nickname: string;
}

interface FaceitStatsResponse {
  lifetime: {
    Matches: string;
    'Average K/D Ratio': string;
    'Average Headshots %': string;
    'Win Rate %': string;
    'Average K/R Ratio': string;
    'Average Penta Kills': string;
    'Average Quadro Kills': string;
    'Average Triple Kills': string;
  };
  segments: Array<{
    type: string;
    mode: string;
    label: string;
    img_small: string;
    img_regular: string;
    stats: {
      Matches: string;
      'Average K/D Ratio': string;
      'Average Headshots %': string;
      'Win Rate %': string;
      'Average K/R Ratio': string;
      'Average Penta Kills': string;
      'Average Quadro Kills': string;
      'Average Triple Kills': string;
      'Average Assists': string;
    };
  }>;
}

interface FaceitMatchesResponse {
  items: Array<{
    match_id: string;
    game_id: string;
    region: string;
    match_type: string;
    game_mode: string;
    max_players: number;
    teams_size: number;
    teams_faction1: {
      team_id: string;
      nickname: string;
      avatar: string;
      type: string;
      players: Array<{
        player_id: string;
        nickname: string;
        avatar: string;
        skill_level: number;
        game_player_id: string;
        game_player_name: string;
        faceit_url: string;
      }>;
    };
    teams_faction2: {
      team_id: string;
      nickname: string;
      avatar: string;
      type: string;
      players: Array<{
        player_id: string;
        nickname: string;
        avatar: string;
        skill_level: number;
        game_player_id: string;
        game_player_name: string;
        faceit_url: string;
      }>;
    };
    started_at: number;
    finished_at: number;
    results: {
      winner: string;
      score: Record<string, number>;
    };
  }>;
  start: number;
  end: number;
  from: number;
  to: number;
}

interface FaceitPlayerMatchStatsResponse {
  items: Array<{
    match_id: string;
    player_id: string;
    game_id: string;
    stats: {
      Kills: string;
      Deaths: string;
      Assists: string;
      'Headshots %': string;
      MVPs: string;
      'K/D Ratio': string;
      'K/R Ratio': string;
      'Quadro Kills': string;
      'Penta Kills': string;
      'Headshots': string;
      'Triple Kills': string;
      'Match Result': string;
      'Match Finished At': string;
    };
  }>;
  start: number;
  end: number;
  from: number;
  to: number;
}

// Helper function to add delay between requests
const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

// Request queue to avoid rate limits by throttling requests
let lastRequestTime = 0;
const MIN_REQUEST_INTERVAL = 250; // 250ms between requests to stay under rate limit

// Use direct API when key is set (avoids CORS); otherwise use callable.
async function faceitRequest<T>(endpoint: string): Promise<T> {
  const now = Date.now();
  const timeSinceLastRequest = now - lastRequestTime;
  if (timeSinceLastRequest < MIN_REQUEST_INTERVAL) {
    await delay(MIN_REQUEST_INTERVAL - timeSinceLastRequest);
  }
  lastRequestTime = Date.now();

  if (FACEIT_API_KEY) {
    return faceitRequestDirect<T>(endpoint);
  }

  try {
    const callable = getFaceitProxy();
    const result = await callable({ endpoint });
    return result.data as T;
  } catch (err: unknown) {
    const msg = err && typeof err === 'object' && 'message' in err ? String((err as { message: string }).message) : '';
    if (msg.includes('429') || msg.includes('rate')) {
      await delay(2000);
      return faceitRequest<T>(endpoint);
    }
    throw err;
  }
}

// Get player ID by nickname
export async function getPlayerId(nickname: string): Promise<string> {
  try {
    const data = await faceitRequest<FaceitPlayerResponse>(`/players?nickname=${encodeURIComponent(nickname)}`);
    return data.player_id;
  } catch (error) {
    console.error(`Failed to get player ID for ${nickname}:`, error);
    throw error;
  }
}

// Get player stats
export async function getPlayerStats(playerId: string, gameId: string = 'csgo'): Promise<any> {
  try {
    const stats = await faceitRequest<FaceitStatsResponse>(`/players/${playerId}/stats/${gameId}`);
    return stats;
  } catch (error) {
    console.error(`Failed to get stats for player ${playerId}:`, error);
    throw error;
  }
}

// Get recent matches
export async function getPlayerMatches(playerId: string, limit: number = 20): Promise<any> {
  try {
    const matches = await faceitRequest<FaceitMatchesResponse>(`/players/${playerId}/history?game=csgo&offset=0&limit=${limit}`);
    return matches;
  } catch (error) {
    console.error(`Failed to get matches for player ${playerId}:`, error);
    throw error;
  }
}

// Get detailed match statistics for a player
export async function getPlayerMatchStats(playerId: string, gameId: string = 'csgo', limit: number = 30): Promise<any> {
  try {
    console.log(`Fetching matches for player ${playerId} with gameId: ${gameId}`);
    const matchStats = await faceitRequest<FaceitPlayerMatchStatsResponse>(`/players/${playerId}/games/${gameId}/stats?offset=0&limit=${limit}`);
    console.log(`Received ${matchStats.items?.length || 0} matches`);
    return matchStats;
  } catch (error) {
    console.error(`Failed to get match stats for player ${playerId}:`, error);
    throw error;
  }
}

// Get all match statistics for a player (with pagination)
export async function getAllPlayerMatchStats(playerId: string, gameId: string = 'csgo', maxMatches: number = 1000): Promise<any> {
  try {
    const allMatches: any[] = [];
    let offset = 0;
    const limit = 100; // FaceIt API max per request
    
    while (allMatches.length < maxMatches) {
      console.log(`Fetching matches for player ${playerId} (offset: ${offset}, already have: ${allMatches.length})`);
      try {
        const matchStats = await faceitRequest<FaceitPlayerMatchStatsResponse>(`/players/${playerId}/games/${gameId}/stats?offset=${offset}&limit=${limit}`);
        
        if (!matchStats.items || matchStats.items.length === 0) {
          // No more matches
          break;
        }
        
        allMatches.push(...matchStats.items);
        
        // Check if we got all available matches
        if (matchStats.items.length < limit) {
          break;
        }
        
        offset += limit;
      } catch (error: any) {
        // If we get a 400 error, it likely means we've reached the end of available matches
        // Return what we've collected so far
        if (error.message && error.message.includes('400')) {
          console.log(`Received 400 error at offset ${offset}, likely no more matches available`);
          break;
        }
        // For other errors, re-throw
        throw error;
      }
      
      // Add a small delay to avoid rate limiting
      await delay(200);
    }
    
    console.log(`Total matches fetched for player ${playerId}: ${allMatches.length}`);
    return { items: allMatches };
  } catch (error) {
    console.error(`Failed to get match stats for player ${playerId}:`, error);
    throw error;
  }
}

// Get comprehensive player stats for our app
export async function getPlayerFullStats(nickname: string, matchLimit: number = 1000) {
  try {
    // Get player ID
    const playerId = await getPlayerId(nickname);
    
    // Fetch stats and match data in parallel for faster loading
    // Try cs2 first, fallback to csgo
    // Use getAllPlayerMatchStats to get matches for activity tracking
    let matchStats;
    try {
      matchStats = await getAllPlayerMatchStats(playerId, 'cs2', matchLimit);
    } catch (cs2Error) {
      console.log(`cs2 matches not found, trying csgo for ${nickname}`);
      matchStats = await getAllPlayerMatchStats(playerId, 'csgo', matchLimit);
    }
    
    // Try cs2 first for stats, fallback to csgo
    let stats;
    try {
      stats = await getPlayerStats(playerId, 'cs2');
    } catch (cs2Error) {
      console.log(`cs2 stats not found, trying csgo for ${nickname}`);
      stats = await getPlayerStats(playerId, 'csgo');
    }
    
    // Calculate averages from detailed match stats
    const matchStatsItems = matchStats.items || [];
    
    // Debug: Log the structure
    console.log('Match stats response structure:', {
      hasItems: !!matchStats.items,
      itemsLength: matchStatsItems.length,
      firstItem: matchStatsItems[0]
    });
    let totalKills = 0;
    let totalDeaths = 0;
    let totalAssists = 0;
    let wins = 0;
    let totalRounds = 0;
    let validGames = 0;
    
    // Track both "last 30 games" and "last 5 games" stats separately
    let last30Kills = 0;
    let last30Deaths = 0;
    let last30Assists = 0;
    let last30Wins = 0;
    let last30Games = 0;
    let last30Headshots = 0;
    let last30KillsForHs = 0;
    let last30RwsSum = 0;
    let last30RwsCount = 0;
    let last30Mvps = 0;
    
    let last5Kills = 0;
    let last5Deaths = 0;
    let last5Assists = 0;
    let last5Wins = 0;
    let last5Games = 0;
    let last5RwsSum = 0;
    let last5RwsCount = 0;
    let last5Mvps = 0;
    
    // Count games within last 30 days (separate from "last 30 games")
    let gamesInLast30Days = 0;
    
    // Count games for different week ranges for average games per week calculation
    let gamesInLast2Weeks = 0;
    let gamesInLast10Weeks = 0;
    let gamesInLast52Weeks = 0;
    
    // Track the oldest match date for "all time" calculation
    let oldestMatchDate: Date | undefined = undefined;
    
    // Get the current date and calculate various time ranges
    const now = new Date();
    const thirtyDaysAgo = new Date(now.getTime() - (30 * 24 * 60 * 60 * 1000));
    
    // Calculate dates for different week ranges
    const twoWeeksAgo = new Date(now.getTime() - (14 * 24 * 60 * 60 * 1000));
    const tenWeeksAgo = new Date(now.getTime() - (70 * 24 * 60 * 60 * 1000));
    const fiftyTwoWeeksAgo = new Date(now.getTime() - (364 * 24 * 60 * 60 * 1000));
    
    matchStatsItems.forEach((match: any, index: number) => {
      const kills = parseInt(match.stats.Kills || '0');
      const deaths = parseInt(match.stats.Deaths || '0');
      const assists = parseInt(match.stats.Assists || '0');
      const headshots = parseInt(match.stats.Headshots || '0');
      const mvps = parseInt(match.stats.MVPs || '0');
      const result = match.stats['Result'] || match.stats['Match Result'] || '0';
      
      // Get match date - try multiple field names
      const matchFinishedAt = match.stats['Match Finished At'] || 
                              match.stats['Created At'] ||
                              match.finished_at ||
                              match.fullMatch?.finished_at ||
                              '';
      
      let matchDate = new Date();
      if (matchFinishedAt) {
        // Try parsing as ISO string first
        matchDate = new Date(matchFinishedAt);
        // If that fails (invalid date), try as unix timestamp
        if (isNaN(matchDate.getTime())) {
          matchDate = new Date(parseInt(matchFinishedAt) * 1000);
        }
      }
      
      // Track the oldest match date for all-time calculation
      if (matchDate && !isNaN(matchDate.getTime())) {
        if (oldestMatchDate === undefined || matchDate < oldestMatchDate) {
          oldestMatchDate = matchDate;
        }
      }
      
      // Check if match is within various time ranges
      const isWithinLast30Days = matchDate >= thirtyDaysAgo;
      const isWithinLast2Weeks = matchDate >= twoWeeksAgo;
      const isWithinLast10Weeks = matchDate >= tenWeeksAgo;
      const isWithinLast52Weeks = matchDate >= fiftyTwoWeeksAgo;
      
      if (index < 3) {
        console.log(`Match ${index + 1} Raw date:`, matchFinishedAt, 'Parsed:', matchDate.toISOString(), 'Within 30 days:', isWithinLast30Days);
      }
      
      if (isNaN(kills) || isNaN(deaths)) {
        return;
      }
      
      // Normalize match result - handle various formats
      const normalizedResult = String(result || '').toLowerCase().trim();
      const isWin = normalizedResult === 'win' || normalizedResult === '1' || normalizedResult === 'won' || normalizedResult === 'true';
      
      // Calculate RWS for this match
      const kd = deaths > 0 ? kills / deaths : kills;
      const roundWinShare = (isWin ? 50 : 0) + (kd - 1) * 10;
      const matchRws = Math.max(0, Math.min(100, roundWinShare));
      
      validGames++;
      
      totalKills += kills;
      totalDeaths += deaths;
      totalAssists += assists;
      
      if (isWin) {
        wins++;
      }
      
      // Count games within last 30 days
      if (isWithinLast30Days) {
        gamesInLast30Days++;
      }
      
      // Count games within different week ranges
      if (isWithinLast2Weeks) {
        gamesInLast2Weeks++;
      }
      if (isWithinLast10Weeks) {
        gamesInLast10Weeks++;
      }
      if (isWithinLast52Weeks) {
        gamesInLast52Weeks++;
      }
      
      // Track last 30 games stats (most recent 30 matches, regardless of date)
      if (last30Games < 30) {
        last30Games++;
        last30Kills += kills;
        last30Deaths += deaths;
        last30Assists += assists;
        last30Headshots += headshots;
        last30KillsForHs += kills;
        last30Mvps += mvps;
        if (isWin) {
          last30Wins++;
        }
        
        if (matchRws > 0) {
          last30RwsSum += matchRws;
          last30RwsCount++;
        }
      }
      
      // Track last 5 games stats
      if (last5Games < 5) {
        last5Games++;
        last5Kills += kills;
        last5Deaths += deaths;
        last5Assists += assists;
        last5Mvps += mvps;
        if (isWin) {
          last5Wins++;
        }
        
        if (matchRws > 0) {
          last5RwsSum += matchRws;
          last5RwsCount++;
        }
      }
      
      totalRounds += 24;
    });

    const gamesPlayed = validGames || 1;
    
    const avgKills = totalKills / gamesPlayed;
    const avgDeaths = totalDeaths / gamesPlayed;
    const avgAssists = totalAssists / gamesPlayed;
    const winRate = (wins / gamesPlayed) * 100;
    
    const kd = avgDeaths > 0 ? avgKills / avgDeaths : avgKills;
    
    const last30AvgKills = last30Games > 0 ? last30Kills / last30Games : 0;
    const last30AvgDeaths = last30Games > 0 ? last30Deaths / last30Games : 0;
    const last30Kd = last30AvgDeaths > 0 ? last30AvgKills / last30AvgDeaths : (last30AvgKills || 0);
    const last30WinRate = last30Games > 0 ? (last30Wins / last30Games) * 100 : 0;
    const last30Rws = last30RwsCount > 0 ? last30RwsSum / last30RwsCount : 0;
    
    const last5AvgKills = last5Games > 0 ? last5Kills / last5Games : 0;
    const last5AvgDeaths = last5Games > 0 ? last5Deaths / last5Games : 0;
    const last5Kd = last5AvgDeaths > 0 ? last5AvgKills / last5AvgDeaths : (last5AvgKills || 0);
    const last5WinRate = last5Games > 0 ? (last5Wins / last5Games) * 100 : 0;
    const last5Rws = last5RwsCount > 0 ? last5RwsSum / last5RwsCount : 0;
    
    const last3Games = matchStatsItems.slice(0, 3).map((match: any, index: number) => {
      const kills = parseInt(match.stats.Kills || '0');
      const deaths = parseInt(match.stats.Deaths || '0');
      const assists = parseInt(match.stats.Assists || '0');
      const result = match.stats['Result'] || match.stats['Match Result'] || '0';
      
      const normalizedResult = String(result || '').toLowerCase().trim();
      const isWin = normalizedResult === 'win' || normalizedResult === '1' || normalizedResult === 'won' || normalizedResult === 'true';
      
      // Extract date from 'Match Finished At' field
      let finishedAt = match.stats['Match Finished At'] || 
                      match.stats['Created At'] ||
                      new Date().toISOString();
      
      // Convert to ISO timestamp
      let finalTimestamp = finishedAt;
      try {
        // If it's a date string, parse it
        if (typeof finishedAt === 'string') {
          finalTimestamp = new Date(finishedAt).toISOString();
        } else if (typeof finishedAt === 'number' || /^\d+$/.test(finishedAt)) {
          finalTimestamp = new Date(parseInt(finishedAt)).toISOString();
        }
      } catch (e) {
        finalTimestamp = new Date().toISOString();
      }
      
      const kd = deaths > 0 ? kills / deaths : kills;
      const roundWinShare = (isWin ? 50 : 0) + (kd - 1) * 10;
      const matchRws = Math.max(0, Math.min(100, roundWinShare));
      
      return {
        matchId: match.stats['Match Id'] || 'unknown',
        finishedAt: finalTimestamp,
        kills,
        deaths,
        assists,
        result: isWin ? 'win' as const : 'loss' as const,
        rws: matchRws,
      };
    });
    
    const lifetime = stats.lifetime || {};
    const totalGamesPlayed = parseInt(lifetime.Matches || '0', 10) || gamesPlayed;
    
    let hsRate = 0;
    if (last30KillsForHs > 0) {
      hsRate = (last30Headshots / last30KillsForHs) * 100;
    } else {
      hsRate = parseFloat(lifetime['Average Headshots %']?.replace('%', '') || '0');
    }
    
    const rws = winRate + (kd - 1) * 20;
    const impact = (avgKills * 0.5) + (avgAssists * 0.25) + (winRate * 0.5);

    const lifetimeWinRate = parseFloat(lifetime['Win Rate %']?.replace('%', '') || '0');
    const displayGames = last30Games > 0 ? last30Games : gamesPlayed;
    const displayWinRate = last30WinRate > 0 ? last30WinRate : (lifetimeWinRate > 0 ? lifetimeWinRate : winRate);
    const displayKd = last30Kd > 0 ? last30Kd : kd;
    const displayAvgKills = last30Games > 0 ? last30Kills / last30Games : avgKills;
    const displayAvgDeaths = last30Games > 0 ? last30Deaths / last30Games : avgDeaths;
    const displayAvgAssists = last30Games > 0 ? last30Assists / last30Games : avgAssists;

    // Calculate average games per week for different time ranges
    const avgGamesPerWeek2W = gamesInLast2Weeks / 2;
    const avgGamesPerWeek10W = gamesInLast10Weeks / 10;
    const avgGamesPerWeek52W = gamesInLast52Weeks / 52;
    
    // Calculate all-time average games per week since first game
    let avgGamesPerWeekAllTime = 0;
    if (oldestMatchDate !== undefined && validGames > 0) {
      const oldestDate = oldestMatchDate as Date;
      const weeksSinceFirstGame = (now.getTime() - oldestDate.getTime()) / (7 * 24 * 60 * 60 * 1000);
      avgGamesPerWeekAllTime = weeksSinceFirstGame > 0 ? validGames / weeksSinceFirstGame : 0;
    }

    return {
      playerId,
      faceitNickname: nickname,
      gamesPlayed: displayGames,
      winRate: displayWinRate,
      kd: displayKd,
      avgKills: displayAvgKills,
      avgDeaths: displayAvgDeaths,
      avgAssists: displayAvgAssists,
      hsRate,
      rws: Math.max(0, Math.min(100, last30Rws)),
      impact: Math.max(0, Math.min(100, impact)),
      last30Games,
      last30Rws: Math.max(0, Math.min(100, last30Rws)),
      last30Mvps,
      gamesInLast30Days,
      last5Games,
      last5Rws: Math.max(0, Math.min(100, last5Rws)),
      last5Mvps,
      avgGamesPerWeek2W: Math.round(avgGamesPerWeek2W * 10) / 10, // Round to 1 decimal place
      avgGamesPerWeek10W: Math.round(avgGamesPerWeek10W * 10) / 10,
      avgGamesPerWeek52W: Math.round(avgGamesPerWeek52W * 10) / 10,
      avgGamesPerWeekAllTime: Math.round(avgGamesPerWeekAllTime * 10) / 10, // Round to 1 decimal place
      last3Games,
    };
  } catch (error) {
    console.error(`Failed to get full stats for ${nickname}:`, error);
    throw error;
  }
}

// Team Stats Interfaces
interface FaceitTeamResponse {
  team_id: string;
  name: string;
  avatar: string;
}

interface FaceitTeamStatsResponse {
  lifetime: {
    Matches: string;
    'Average K/D Ratio': string;
    'Average Headshots %': string;
    'Win Rate %': string;
    'Average K/R Ratio': string;
  };
  segments: Array<{
    type: string;
    mode: string;
    label: string;
    img_small: string;
    img_regular: string;
    stats: {
      Matches: string;
      'Average K/D Ratio': string;
      'Average Headshots %': string;
      'Win Rate %': string;
      'Average K/R Ratio': string;
    };
  }>;
}

export interface TeamStats {
  teamId: string;
  teamName: string;
  avatar: string;
  gamesPlayed: number;
  winRate: number;
  avgKd: number;
  avgHsRate: number;
  avgKr: number;
}

// Get team by ID
export async function getTeamById(teamId: string): Promise<FaceitTeamResponse> {
  try {
    const data = await faceitRequest<FaceitTeamResponse>(`/teams/${teamId}`);
    return data;
  } catch (error) {
    console.error(`Failed to get team ${teamId}:`, error);
    throw error;
  }
}

// Fetch additional matches for a player and update weekly activity stats
export async function updatePlayerStatsWithMoreMatches(
  existingStats: any,
  gameId: string = 'cs2'
): Promise<any> {
  try {
    const matchStats = await getAllPlayerMatchStats(existingStats.playerId, gameId, 1000);
    const matchStatsItems = matchStats.items || [];
    
    // Recalculate activity-based stats with full dataset
    let gamesInLast2Weeks = 0;
    let gamesInLast10Weeks = 0;
    let gamesInLast52Weeks = 0;
    let oldestMatchDate: Date | undefined = undefined;
    
    const now = new Date();
    const twoWeeksAgo = new Date(now.getTime() - (14 * 24 * 60 * 60 * 1000));
    const tenWeeksAgo = new Date(now.getTime() - (70 * 24 * 60 * 60 * 1000));
    const fiftyTwoWeeksAgo = new Date(now.getTime() - (364 * 24 * 60 * 60 * 1000));
    
    matchStatsItems.forEach((match: any) => {
      const matchFinishedAt = match.stats['Match Finished At'] || 
                              match.stats['Created At'] ||
                              match.finished_at ||
                              match.fullMatch?.finished_at ||
                              '';
      
      let matchDate = new Date();
      if (matchFinishedAt) {
        matchDate = new Date(matchFinishedAt);
        if (isNaN(matchDate.getTime())) {
          matchDate = new Date(parseInt(matchFinishedAt) * 1000);
        }
      }
      
      if (matchDate && !isNaN(matchDate.getTime())) {
        if (oldestMatchDate === undefined || matchDate < oldestMatchDate) {
          oldestMatchDate = matchDate;
        }
      }
      
      const isWithinLast2Weeks = matchDate >= twoWeeksAgo;
      const isWithinLast10Weeks = matchDate >= tenWeeksAgo;
      const isWithinLast52Weeks = matchDate >= fiftyTwoWeeksAgo;
      
      if (isWithinLast2Weeks) gamesInLast2Weeks++;
      if (isWithinLast10Weeks) gamesInLast10Weeks++;
      if (isWithinLast52Weeks) gamesInLast52Weeks++;
    });
    
    const totalGames = matchStatsItems.length;
    const avgGamesPerWeek2W = gamesInLast2Weeks / 2;
    const avgGamesPerWeek10W = gamesInLast10Weeks / 10;
    const avgGamesPerWeek52W = gamesInLast52Weeks / 52;
    
    let avgGamesPerWeekAllTime = 0;
    if (oldestMatchDate !== undefined && totalGames > 0) {
      const oldestDate = oldestMatchDate as Date;
      const weeksSinceFirstGame = (now.getTime() - oldestDate.getTime()) / (7 * 24 * 60 * 60 * 1000);
      avgGamesPerWeekAllTime = weeksSinceFirstGame > 0 ? totalGames / weeksSinceFirstGame : 0;
    }
    
    // Return updated stats with new weekly averages
    return {
      ...existingStats,
      avgGamesPerWeek2W: Math.round(avgGamesPerWeek2W * 10) / 10,
      avgGamesPerWeek10W: Math.round(avgGamesPerWeek10W * 10) / 10,
      avgGamesPerWeek52W: Math.round(avgGamesPerWeek52W * 10) / 10,
      avgGamesPerWeekAllTime: Math.round(avgGamesPerWeekAllTime * 10) / 10,
    };
  } catch (error) {
    console.error(`Failed to update stats for player ${existingStats.playerId}:`, error);
    // Return existing stats if update fails
    return existingStats;
  }
}

// Get team stats
export async function getTeamStats(teamId: string, gameId: string = 'csgo'): Promise<TeamStats> {
  try {
    const [team, stats] = await Promise.all([
      getTeamById(teamId),
      faceitRequest<FaceitTeamStatsResponse>(`/teams/${teamId}/stats/${gameId}`)
    ]);

    const lifetime = stats.lifetime || {};
    
    const gamesPlayed = parseInt(lifetime.Matches || '0', 10) || 0;
    const winRate = parseFloat(lifetime['Win Rate %']?.replace('%', '') || '0');
    const avgKd = parseFloat(lifetime['Average K/D Ratio'] || '0');
    const avgHsRate = parseFloat(lifetime['Average Headshots %']?.replace('%', '') || '0');
    const avgKr = parseFloat(lifetime['Average K/R Ratio'] || '0');

    return {
      teamId: team.team_id,
      teamName: team.name,
      avatar: team.avatar,
      gamesPlayed,
      winRate,
      avgKd,
      avgHsRate,
      avgKr,
    };
  } catch (error) {
    console.error(`Failed to get team stats for ${teamId}:`, error);
    throw error;
  }
}
