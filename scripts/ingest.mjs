import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

const FACEIT_API_KEY = process.env.FACEIT_API_KEY;
if (!FACEIT_API_KEY) {
  console.error('FACEIT_API_KEY missing');
  process.exit(1);
}

const FACEIT_BASE = 'https://open.faceit.com/data/v4';

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function faceit(endpoint) {
  const res = await fetch(`${FACEIT_BASE}${endpoint}`, {
    headers: {
      'Authorization': `Bearer ${FACEIT_API_KEY}`,
      'Content-Type': 'application/json'
    }
  });
  if (res.status === 429) {
    await sleep(2000);
    return faceit(endpoint);
  }
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`Faceit error ${res.status} ${res.statusText}: ${body}`);
  }
  return res.json();
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
  // CS2 first; fallback to csgo
  try {
    const data = await faceit(`/players/${playerId}/history?game=cs2&offset=0&limit=${limit}`);
    return data.items ?? [];
  } catch (e) {
    const data = await faceit(`/players/${playerId}/history?game=csgo&offset=0&limit=${limit}`);
    return data.items ?? [];
  }
}

async function getMatchDetails(matchId) {
  // Not all fields are guaranteed; this endpoint may change. Best-effort.
  try {
    const data = await faceit(`/matches/${matchId}`);
    return data;
  } catch {
    return null;
  }
}

const newEntries = [];

for (const p of players) {
  const nickname = p.faceitNickname;
  if (!nickname) continue;

  let playerId;
  try {
    playerId = await getPlayerId(nickname);
  } catch (e) {
    console.warn(`Failed to resolve playerId for ${nickname}: ${e.message}`);
    continue;
  }

  const recent = await getRecentMatches(playerId, 10);

  // Track last processed per player to reduce churn
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

    // Track newest
    if (!newestForState || (m.finished_at && Number(m.finished_at) > Number(newestForState))) {
      newestForState = m.match_id;
    }

    const key = byKey(item);
    if (seen.has(key)) continue;

    // Try match details (optional)
    const details = await getMatchDetails(m.match_id).catch(() => null);
    if (details) {
      // Placeholders for future use; demo resource is not always exposed here
      item.map = details?.voting?.map?.pick?.[0] || details?.map || null;
      item.score = details?.results?.score || null;
    }

    newEntries.push(item);
    seen.add(key);

    // Be gentle with API
    await sleep(250);
  }

  state[playerId] = {
    faceitNickname: nickname,
    lastProcessedMatchId: newestForState || lastProcessed || null,
    updatedAt: new Date().toISOString()
  };

  await sleep(250);
}

// Merge and keep recent N (optional: 1000)
const merged = [...matchesIndex.matches, ...newEntries]
  .sort((a, b) => Number(b.finishedAt || 0) - Number(a.finishedAt || 0))
  .slice(0, 1000);

writeFileSync(matchesPath, JSON.stringify({ matches: merged }, null, 2));
writeFileSync(statePath, JSON.stringify(state, null, 2));

console.log(`Ingest complete. Added ${newEntries.length} new entries. Saved to data/matches.json`);
