// Steam OpenID authentication utility
// Steam uses OpenID 2.0 for authentication.
// We only redirect to Steam's official URL (steamcommunity.com); the user enters
// their password only on Steam's site. We never receive their password or any
// token that could be used to access their Steam account—only their public Steam ID.

const STEAM_ID64_BASE = BigInt('76561197960265728');

// Convert Steam ID64 to legacy STEAM_0:0:xxxxxx format
export function steamId64ToLegacy(steamId64: string): string {
  const baseId = BigInt(steamId64);
  const accountNumber = Number(baseId - STEAM_ID64_BASE);
  const Y = accountNumber % 2;
  const Z = (accountNumber - Y) / 2;
  return `STEAM_0:${Y}:${Z}`;
}

// Convert legacy STEAM_0:Y:Z to Steam ID64 (for Leetify/APIs that use 64-bit ID)
export function legacyToSteamId64(legacy: string): string {
  const match = legacy.match(/STEAM_0:(\d):(\d+)/);
  if (!match) return legacy; // already 64-bit or invalid
  const Y = parseInt(match[1], 10);
  const Z = parseInt(match[2], 10);
  const accountNumber = Z * 2 + Y;
  return String(STEAM_ID64_BASE + BigInt(accountNumber));
}

// Start Steam OpenID authentication
export function initiateSteamLogin(): void {
  // Steam OpenID endpoint
  const realm = window.location.origin;
  const returnTo = `${realm}/steam-callback`;
  const steamOpenIdUrl = `https://steamcommunity.com/openid/login?openid.ns=http://specs.openid.net/auth/2.0&openid.mode=checkid_setup&openid.return_to=${encodeURIComponent(returnTo)}&openid.realm=${encodeURIComponent(realm)}&openid.identity=http://specs.openid.net/auth/2.0/identifier_select&openid.claimed_id=http://specs.openid.net/auth/2.0/identifier_select`;
  
  // Redirect to Steam
  window.location.href = steamOpenIdUrl;
}

// Parse Steam ID from OpenID response
export function parseSteamIdFromCallback(): { steamId: string; isValid: boolean } {
  const urlParams = new URLSearchParams(window.location.search);
  
  // Check if this is a Steam callback
  if (!urlParams.has('openid.mode') || urlParams.get('openid.mode') !== 'id_res') {
    return { steamId: '', isValid: false };
  }
  
  // Check for required parameters
  const requiredParams = ['openid.identity', 'openid.claimed_id', 'openid.return_to', 'openid.response_nonce', 'openid.assoc_handle'];
  const hasAllParams = requiredParams.every(param => urlParams.has(param));
  
  if (!hasAllParams) {
    return { steamId: '', isValid: false };
  }
  
  // Steam returns the identity in the format: https://steamcommunity.com/openid/id/{STEAM_ID64}
  const identity = urlParams.get('openid.identity');
  if (!identity || !identity.includes('steamcommunity.com/openid/id/')) {
    return { steamId: '', isValid: false };
  }
  
  // Extract Steam ID64
  const steamId64Match = identity.match(/\/openid\/id\/(\d+)/);
  if (!steamId64Match || !steamId64Match[1]) {
    return { steamId: '', isValid: false };
  }
  
  const steamId64 = steamId64Match[1];
  
  // Convert to legacy format
  return { steamId: steamId64ToLegacy(steamId64), isValid: true };
}
