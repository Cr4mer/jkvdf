import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

const FACEIT_API_KEY = process.env.FACEIT_API_KEY;
if (!FACEIT_API_KEY) {
  console.error('FACEIT_API_KEY missing');
  process.exit(1);
}

const FACEIT_BASE = 'https://open.faceit.com/data/v4';

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 15000) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(timeout);
    return res;
  } catch (err) {
    clearTimeout(timeout);
    throw err;
  }
}

async function faceit(endpoint, opts = {}) {
  const headers = {
    Authorization: `Bearer ${FACEIT_API_KEY}`,
    'Content-Type': 'application/json',
  };

  const url = `${FACEIT_BASE}${endpoint}`;
  console.log(`[faceit] GET ${url}`);
  try {
    const res = await fetchWithTimeout(url, { headers, ...opts }, 15000);

    if (res.status === 429) {
      console.warn('[faceit] Rate limited; waiting 2s and retrying');
      await sleep(2000);
      return faceit(endpoint, opts);
    }

    if (!res.ok) {
      const body = await res.text().catch(() => '');
      throw new Error(`[faceit] ${res.status} ${res.statusText}: ${body}`);
    }

    return res.json();
  } catch (err) {
    console.error(`[faceit] ${endpoint} failed: ${err.message || err}`);
    throw err;
  }
}

const repoRoot = process.cwd();
const dataDir = join(repoRoot, 'data');
if (!existsSync(dataDir)) mkdirSync(dataDir, { recursive: true });

const playersPath = join(repoRoot, 'players.json');
const statePath = join(dataDir, 'state.json');
const matchesPath = join(dataDir, 'matches.json');

const players = JSON.parse(readFileSync(playersPath, 'utf8'));
const state = existsSync(statePath) ? JSON.parse(readFileSync(statePath, 'utf8')) : {};
const matchesIndex = existsSync(matchesPath) ? JSON.parse(readFileSync(matchesPath, 'utf8')) : { matches: [] };

const byKey = (m) => `${m.playerId}:${m.matchId}`;
const seen = new Set(matchesIndex.matches.map(byKey));

async function getPlayerId(nickname) {
  const data = await faceit(`/players?nickname=${encodeURIComponent(nickname)}`);
  return data.player_id;
}

async function getRecentMatches(playerId, limit = 5) {
  try {
    const data = await faceit(`/players/${playerId}/history?game=cs2&offset=0&limit=${limit}`);
    return data.items ?? [];
  } catch (err) {
    console.warn(`[history] cs2 failed for ${playerId}, retrying csgo: ${err.message || err}`);
    const data = await faceit(`/players/${playerId}/history?game=csgo&offset=0&limit=${limit}`);
    return data.items ?? [];
  }
}

async function getMatchDetails(matchId) {
  try {
    return await faceit(`/matches/${matchId}`);
  } catch (err) {
    console.warn(`[match-details] ${matchId} failed: ${err.message || err}`);
    return null;
  }
}

const newEntries = [];

for (const p of players) {
  const nickname = p.faceitNickname;
  if (!nickname) continue;

  console.log(`\n== Processing player ${nickname} ==`);
  let playerId;
  try {
    playerId = await getPlayerId(nickname);
    console.log(`Resolved ${nickname} → ${playerId}`);
  } catch (e) {
    console.warn(`Failed to resolve playerId for ${nickname}: ${e.message}`);
    continue;
  }

  let recent;
  try {
    recent = await getRecentMatches(playerId, 10);
  } catch (err) {
    console.error(`Failed to fetch matches for ${nickname}: ${err.message || err}`);
    continue;
  }
  console.log(`Fetched ${recent.length} matches for ${nickname}`);

  const lastProcessed = state[playerId]?.lastProcessedMatchId;
  let newestForState = lastProcessed || null;

  for (const m of recent) {
    const item = {
      playerId,
      faceitNickname: nickname,
      matchId: m.match_id,
      gameMode: m.game_mode,
      region: m.region,
      startedAt: m.started_at,
      finishedAt: m.finished_at,
      teamsSize: m.teams_size,
      urlRoom: `https://www.faceit.com/en/cs2/room/${m.match_id}`,
    };

    if (!newestForState || (m.finished_at && Number(m.finished_at) > Number(newestForState))) {
      newestForState = m.match_id;
    }

    const key = byKey(item);
    if (seen.has(key)) continue;

    const details = await getMatchDetails(m.match_id);
    if (details) {
      item.map = details?.voting?.map?.pick?.[0] || details?.map || null;
      item.score = details?.results?.score || null;
    }

    newEntries.push(item);
    seen.add(key);

    // Throttle to avoid hammering the API
    await sleep(250);
  }

  state[playerId] = {
    faceitNickname: nickname,
    lastProcessedMatchId: newestForState || lastProcessed || null,
    updatedAt: new Date().toISOString(),
  };

  await sleep(250);
}

const merged = [...matchesIndex.matches, ...newEntries]
  .sort((a, b) => Number(b.finishedAt || 0) - Number(a.finishedAt || 0))
  .slice(0, 1000);

writeFileSync(matchesPath, JSON.stringify({ matches: merged }, null, 2));
writeFileSync(statePath, JSON.stringify(state, null, 2));

console.log(`\nIngest complete. Added ${newEntries.length} new entries. Saved to data/matches.json`);
