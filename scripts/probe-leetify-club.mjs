/**
 * TEMPORARY discovery probe — does Leetify's PUBLIC developer API expose CLUB data?
 *
 * The webapp's club features (leaderboards, dashboard highlights, badge winners)
 * need club-level endpoints. We only know the per-player ones (/v3/profile,
 * /v3/profile/matches). This script tries a list of candidate club endpoints with
 * the developer key and logs which exist + their shape, so we can build against
 * whatever is actually available. Delete this script + its workflow once we know.
 *
 * Env: LEETIFY_API_KEY (required), LEETIFY_CLUB_ID (defaults to the JKVDF club).
 */
const BASE = 'https://api-public.cs-prod.leetify.com';
const KEY = process.env.LEETIFY_API_KEY;
const CLUB = process.env.LEETIFY_CLUB_ID || '53fc120c-b63f-4e52-92a2-b14c2f6eef86';

if (!KEY) {
  console.error('LEETIFY_API_KEY is not set');
  process.exit(1);
}

const paths = [
  `/v3/club/${CLUB}`,
  `/v3/clubs/${CLUB}`,
  `/v3/club/${CLUB}/leaderboards`,
  `/v3/club/${CLUB}/leaderboard`,
  `/v3/club/${CLUB}/members`,
  `/v3/club/${CLUB}/highlights`,
  `/v3/club/${CLUB}/clips`,
  `/v3/club/${CLUB}/badges`,
  `/v3/club/${CLUB}/awards`,
  `/v3/club/${CLUB}/dashboard`,
  `/v3/clubs/${CLUB}/leaderboards`,
  `/v3/clubs/${CLUB}/highlights`,
  `/v3/clubs/${CLUB}/badges`,
  `/v3/group/${CLUB}`,
  `/v3/groups/${CLUB}`,
  `/v3/group/${CLUB}/leaderboards`,
  `/v2/club/${CLUB}`,
  `/club/${CLUB}`,
];

const summarize = (data) => {
  if (data == null) return 'null/non-JSON';
  if (Array.isArray(data)) {
    const first = data[0] && typeof data[0] === 'object' ? ` first-keys: ${Object.keys(data[0]).join(',')}` : '';
    return `array[${data.length}]${first}`;
  }
  if (typeof data === 'object') return `object keys: ${Object.keys(data).join(', ')}`;
  return String(data).slice(0, 120);
};

console.log(`Probing Leetify club API for club ${CLUB}\n`);
for (const p of paths) {
  try {
    const res = await fetch(`${BASE}${p}`, {
      headers: { Authorization: `Bearer ${KEY}`, 'Content-Type': 'application/json' },
    });
    let text = '';
    let body = null;
    try {
      text = await res.text();
      body = JSON.parse(text);
    } catch {
      /* non-JSON */
    }
    if (res.ok) {
      console.log(`OK  ${res.status}  ${p}`);
      console.log(`    -> ${summarize(body)}`);
      console.log(`    ${text.slice(0, 400)}`);
    } else {
      console.log(`--  ${res.status}  ${p}   ${text.slice(0, 80)}`);
    }
  } catch (err) {
    console.log(`ERR       ${p}: ${err.message}`);
  }
  await new Promise((r) => setTimeout(r, 200));
}
console.log('\nProbe complete. Paste the OK lines (and their shapes) back to continue.');
