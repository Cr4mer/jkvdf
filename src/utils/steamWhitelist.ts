// JKVDF Team Steam IDs (in both formats for compatibility)
export const ADMIN_STEAM_IDS = [
  'STEAM_0:1:125547',      // Cr4mer
  'STEAM_0:0:43407091',    // faqin
  'STEAM_0:1:21839777',    // Black_panth
  'STEAM_0:1:10761131',    // psYKENN
  'STEAM_0:1:46139323',    // KQligchris
  'STEAM_0:0:2997904',     // kattepeter
  'STEAM_0:0:3814864',     // pharty
];

// Steam ID to FaceIT username mapping
export const STEAM_ID_TO_FACEIT_NAME: Record<string, string> = {
  'STEAM_0:1:125547': 'Cr4mer',
  'STEAM_0:0:43407091': 'faqin',
  'STEAM_0:1:21839777': 'Black_panth',
  'STEAM_0:1:10761131': 'psYKENN',
  'STEAM_0:1:46139323': 'KQligchris',
  'STEAM_0:0:2997904': 'kattepeter',
  'STEAM_0:0:3814864': 'pharty',
};

/** Team members for Performance Center (FACEIT + Leetify/Premier). One source of truth. */
export const TEAM_MEMBERS: { name: string; faceitNickname: string; steamId: string }[] = [
  { name: 'Cr4mer', faceitNickname: 'Cr4mer', steamId: 'STEAM_0:1:125547' },
  { name: 'Faqin', faceitNickname: 'faqin', steamId: 'STEAM_0:0:43407091' },
  { name: 'Pharty', faceitNickname: 'pharty', steamId: 'STEAM_0:0:3814864' },
  { name: 'Psykenn', faceitNickname: 'psYKENN', steamId: 'STEAM_0:1:10761131' },
  { name: 'TIS_Black_Panther', faceitNickname: 'Black_panth', steamId: 'STEAM_0:1:21839777' },
  { name: 'KQligChris', faceitNickname: 'KQligchris', steamId: 'STEAM_0:1:46139323' },
  { name: 'Kattepeter', faceitNickname: 'kattepeter', steamId: 'STEAM_0:0:2997904' },
];

// Get FaceIT username from Steam ID
export function getFaceitName(steamId: string | undefined): string {
  if (!steamId) return 'Unknown';
  const normalized = normalizeSteamId(steamId);
  return STEAM_ID_TO_FACEIT_NAME[normalized] || steamId;
}

// Convert Steam ID format if needed
export function normalizeSteamId(steamId: string): string {
  // Convert to uppercase for consistency
  return steamId.toUpperCase();
}

// Check if a Steam ID is whitelisted
export function isWhitelisted(steamId: string | undefined): boolean {
  if (!steamId) return false;
  const normalized = normalizeSteamId(steamId);
  return ADMIN_STEAM_IDS.some(id => normalizeSteamId(id) === normalized);
}
