/**
 * Premier (CS2) match ingest — runs in GitHub Actions, writes to Firestore.
 *
 * Why this exists: the web app is on the Firebase Spark plan, which can't deploy
 * Cloud Functions, so the browser can't reach a server-side Leetify proxy. Instead
 * this script runs server-side in CI (where the Leetify key is safe in a GitHub
 * Secret and there's no CORS), fetches each player's recent Premier matches, and
 * writes them to the `premierMatches` Firestore collection. The site reads that
 * collection directly (public read), so Premier matches show up with no functions
 * and no billing.
 *
 * Env (set as GitHub Secrets):
 *   LEETIFY_API_KEY          - Leetify developer API key (https://leetify.com/app/developer)
 *   FIREBASE_SERVICE_ACCOUNT - JSON of a Firebase service account with Firestore write access
 *   FIREBASE_PROJECT_ID      - optional, defaults to jkvdf-d185b
 */
import admin from 'firebase-admin';

const LEETIFY_BASE = 'https://api-public.cs-prod.leetify.com';
const API_KEY = process.env.LEETIFY_API_KEY;
const SERVICE_ACCOUNT = process.env.FIREBASE_SERVICE_ACCOUNT;
const PROJECT_ID = process.env.FIREBASE_PROJECT_ID || 'jkvdf-d185b';

if (!API_KEY) {
  console.error('LEETIFY_API_KEY is not set');
  process.exit(1);
}
if (!SERVICE_ACCOUNT) {
  console.error('FIREBASE_SERVICE_ACCOUNT is not set');
  process.exit(1);
}

// Keep in sync with src/utils/steamWhitelist.ts (TEAM_MEMBERS).
const TEAM = [
  { name: 'Cr4mer', faceitNickname: 'Cr4mer', steamId: 'STEAM_0:1:125547' },
  { name: 'Faqin', faceitNickname: 'faqin', steamId: 'STEAM_0:0:43407091' },
  { name: 'Pharty', faceitNickname: 'pharty', steamId: 'STEAM_0:0:3814864' },
  { name: 'Psykenn', faceitNickname: 'psYKENN', steamId: 'STEAM_0:1:10761131' },
  { name: 'TIS_Black_Panther', faceitNickname: 'Black_panth', steamId: 'STEAM_0:1:21839777' },
  { name: 'KQligChris', faceitNickname: 'KQligchris', steamId: 'STEAM_0:1:46139323' },
  { name: 'Kattepeter', faceitNickname: 'kattepeter', steamId: 'STEAM_0:0:2997904' },
];

const STEAM_ID64_BASE = 76561197960265728n;
function legacyToSteamId64(legacy) {
  const m = String(legacy).match(/STEAM_0:(\d):(\d+)/);
  if (!m) return String(legacy);
  return String(STEAM_ID64_BASE + BigInt(m[2]) * 2n + BigInt(m[1]));
}

function num(v) {
  if (typeof v === 'number' && !Number.isNaN(v)) return v;
  if (typeof v === 'string' && v.trim() !== '' && !Number.isNaN(Number(v))) return Number(v);
  return null;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function leetifyGet(path) {
  const res = await fetch(`${LEETIFY_BASE}${path}`, {
    headers: { Authorization: `Bearer ${API_KEY}`, 'Content-Type': 'application/json' },
  });
  if (res.status === 404) return null;
  if (res.status === 429) {
    console.warn('  rate limited, waiting 2s');
    await sleep(2000);
    return leetifyGet(path);
  }
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`Leetify ${res.status} for ${path}: ${body.slice(0, 200)}`);
  }
  return res.json();
}

// The public API's identifier param name has varied across versions; try a few.
function extractMatchesArray(data) {
  if (Array.isArray(data)) return data;
  if (data && typeof data === 'object') {
    for (const key of ['matches', 'data', 'items', 'recent_matches', 'results']) {
      if (Array.isArray(data[key])) return data[key];
    }
  }
  return null;
}

async function fetchMatches(steamId64) {
  const candidates = [
    `/v3/profile/matches?steam64_id=${steamId64}`,
    `/v3/profile/matches?steam_id=${steamId64}`,
    `/v3/profile/matches?steamId64=${steamId64}`,
    `/v3/profile/matches/${steamId64}`,
    // Fallback: some versions embed recent matches on the profile itself.
    `/v3/profile?steam64_id=${steamId64}`,
  ];
  for (const path of candidates) {
    try {
      const data = await leetifyGet(path);
      if (data == null) continue;
      const arr = extractMatchesArray(data);
      if (arr) return { path, arr };
    } catch (err) {
      console.warn(`  attempt failed (${path}): ${err.message}`);
    }
  }
  return null;
}

function mapMatch(m, steamId64) {
  const rec = m && typeof m === 'object' ? m : {};

  const finishedAtRaw = rec.finished_at ?? rec.finishedAt ?? rec.date ?? rec.match_finished_at ?? rec.created_at;
  let finishedAt = null;
  if (typeof finishedAtRaw === 'string' && finishedAtRaw.trim() !== '') {
    finishedAt = finishedAtRaw;
  } else if (typeof finishedAtRaw === 'number') {
    finishedAt = new Date(finishedAtRaw < 1e12 ? finishedAtRaw * 1000 : finishedAtRaw).toISOString();
  }

  // Per-player K/D/A live in the match's `stats` array — find this player's entry.
  const statsArr = Array.isArray(rec.stats) ? rec.stats : [];
  const idStr = String(steamId64);
  const mine =
    statsArr.find(
      (s) =>
        s &&
        typeof s === 'object' &&
        [s.steam64_id, s.steam_id, s.steamId64, s.steam_id_64, s.steamId, s.steamid].some(
          (v) => v != null && String(v) === idStr,
        ),
    ) || {};

  const kills = num(mine.kills ?? mine.total_kills);
  const deaths = num(mine.deaths ?? mine.total_deaths);
  const assists = num(mine.assists ?? mine.total_assists);

  // W/L: compare this player's team score vs the opponent in `team_scores`.
  const myTeam = num(mine.team_number ?? mine.initial_team_number ?? mine.starting_team_number ?? mine.team);
  let result = null;
  const scores = Array.isArray(rec.team_scores) ? rec.team_scores : [];
  if (myTeam != null && scores.length >= 2) {
    const myScore = num(scores.find((t) => num(t?.team_number) === myTeam)?.score);
    const oppScore = num(scores.find((t) => num(t?.team_number) !== myTeam)?.score);
    if (myScore != null && oppScore != null) {
      result = myScore > oppScore ? 'win' : myScore < oppScore ? 'loss' : null;
    }
  }
  if (result == null) {
    // Fallback: the player's own round tally (rounds_won/rounds_lost exist per Leetify stats).
    const rw = num(mine.rounds_won);
    const rl = num(mine.rounds_lost);
    if (rw != null && rl != null && rw !== rl) result = rw > rl ? 'win' : 'loss';
  }
  if (result == null) {
    const outcome = String(rec.outcome ?? rec.result ?? rec.match_result ?? mine.match_result ?? '').toLowerCase();
    if (['win', 'won', '1'].includes(outcome)) result = 'win';
    else if (['loss', 'lost', '0'].includes(outcome)) result = 'loss';
  }

  return {
    matchId: String(rec.id ?? rec.match_id ?? rec.matchId ?? ''),
    finishedAt,
    result,
    kills,
    deaths,
    assists,
    map: rec.map_name ?? rec.map ?? rec.mapName ?? null,
    shareCode: rec.data_source_match_id ?? null,
    demoUrl: rec.replay_url ?? null,
  };
}

async function main() {
  const serviceAccount = JSON.parse(SERVICE_ACCOUNT);
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount), projectId: PROJECT_ID });
  const db = admin.firestore();
  db.settings({ ignoreUndefinedProperties: true });

  let totalWritten = 0;
  for (const member of TEAM) {
    const steamId64 = legacyToSteamId64(member.steamId);
    console.log(`\n== ${member.name} (${member.faceitNickname}) steam64=${steamId64} ==`);

    let matches = [];
    try {
      const found = await fetchMatches(steamId64);
      if (!found) {
        console.warn('  no matches returned (player may not be on Leetify / not linked)');
      } else {
        console.log(`  matches via ${found.path}: ${found.arr.length} raw`);
        if (found.arr[0] && typeof found.arr[0] === 'object') {
          console.log('  sample match keys:', Object.keys(found.arr[0]).join(', '));
          const ps = Array.isArray(found.arr[0].stats) ? found.arr[0].stats[0] : null;
          if (ps && typeof ps === 'object') {
            console.log('  sample player-stats keys:', Object.keys(ps).join(', '));
          }
        }
        matches = found.arr
          .map((m) => mapMatch(m, steamId64))
          .filter((m) => m.finishedAt)
          .sort((a, b) => new Date(b.finishedAt).getTime() - new Date(a.finishedAt).getTime())
          .slice(0, 10);
      }
    } catch (err) {
      console.error(`  failed: ${err.message}`);
    }

    const docId = member.faceitNickname.toLowerCase();
    await db.collection('premierMatches').doc(docId).set(
      {
        faceitNickname: member.faceitNickname,
        displayName: member.name,
        steamId: member.steamId,
        steamId64,
        matches,
        updatedAt: new Date().toISOString(),
      },
      { merge: true },
    );
    totalWritten += matches.length;
    console.log(`  wrote ${matches.length} match(es) to premierMatches/${docId}`);

    await sleep(300);
  }

  console.log(`\nPremier ingest complete. ${totalWritten} matches across ${TEAM.length} players.`);
}

main().catch((err) => {
  console.error('Premier ingest failed:', err);
  process.exit(1);
});
