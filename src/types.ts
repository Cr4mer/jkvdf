export type Cs2Map = {
  id: string;
  name: string;
  slug: string;
  thumbnailUrl: string;
};

export type Nade = {
  id: string;
  name: string;
  type: 'smoke' | 'instant_smoke' | 'flash' | 'molotov' | 'he' | 'decoy' | string;
  side: 'ct' | 't' | 'both';
  thumbnailUrl: string;
  youtubeVideoId: string;
  startSeconds: number;
  endSeconds?: number;
  throwMethod?: string[];
  /** Optional tags for categorizing nades (e.g. "execute", "retake", "one-way") */
  tags?: string[];
};

export type Member = {
  id: string;
  name: string;
  faceitNickname?: string;
  steamId?: string;
  position?: string;
};

export type FaceitStats = {
  playerId: string;
  faceitNickname: string;
  gamesPlayed: number;
  winRate: number;
  kd: number;
  avgKills: number;
  avgDeaths: number;
  avgAssists: number;
  hsRate: number;
  rws: number;
  impact: number;
  last30Games?: number;
  last30Rws?: number;
  last30Mvps?: number;
  gamesInLast30Days?: number;
  last5Games?: number;
  last5Rws?: number;
  last5Mvps?: number;
  avgGamesPerWeek2W?: number; // Average games per week in last 2 weeks
  avgGamesPerWeek10W?: number; // Average games per week in last 10 weeks
  avgGamesPerWeek52W?: number; // Average games per week in last 52 weeks (1 year)
  avgGamesPerWeekAllTime?: number; // Average games per week since first match
  // Last 3 games with individual match details
  last3Games?: Array<{
    matchId: string;
    finishedAt: string;
    kills: number;
    deaths: number;
    assists: number;
    result: 'win' | 'loss';
    rws: number;
  }>;
};

/** Premier (CS2) stats from Leetify. Same kind of metrics as FACEIT plus Leetify-specific. */
export type LeetifyStats = {
  steamId: string;
  displayName: string;
  /** Leetify Rating (their overall metric) */
  leetifyRating?: number;
  /** Aim rating (Leetify) */
  aim?: number;
  /** Utility rating (Leetify) */
  utility?: number;
  gamesPlayed?: number;
  winRate?: number;
  kd?: number;
  avgKills?: number;
  avgDeaths?: number;
  avgAssists?: number;
  hsRate?: number;
  /** Premier / competitive rank if available */
  premierRank?: number | string;
  /** Recent matches from Leetify */
  recentMatches?: Array<{
    matchId: string;
    finishedAt?: string;
    kills?: number;
    deaths?: number;
    assists?: number;
    result?: 'win' | 'loss';
  }>;
  /** No data (player not on Leetify or profile private) */
  noData?: boolean;
};

export type TrainingSessionResponse = {
  id: string;
  userId: string;
  steamId: string;
  displayName: string;
  status: 'can_go_online' | 'can_go_hall' | 'can_go_both' | 'cannot_go';
  createdAt: string;
};

export type TrainingSession = {
  id: string;
  date: string; // ISO date string
  createdBy: string; // Steam ID of creator
  createdByName: string; // Display name of creator
  createdAt: string; // ISO timestamp
  responses: TrainingSessionResponse[];
  agenda?: string; // Training session agenda (max 20,000 characters)
};


