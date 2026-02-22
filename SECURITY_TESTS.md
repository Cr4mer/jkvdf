# Security Test Guide

Use this checklist to verify that access control, validation, and headers behave correctly.

---

## 1. Firestore rules (authz)

**Goal:** Only admins can write maps/nades; training session delete is callable-only.

| Test | How | Expected |
|------|-----|----------|
| **1.1 Non-admin cannot create map** | In browser console (on hosted app, not logged in or logged in as non-admin): try `firebase.firestore().collection('maps').add({ name: 'x', slug: 'x', thumbnailUrl: 'https://x', _adminSteamId: 'FAKE_ID' })`. Or use [Firestore Rules Playground](https://console.firebase.google.com/project/jkvdf-d185b/firestore/rules/playground) with a non-admin uid / no auth. | Permission denied. |
| **1.2 Admin can create map** | Log in as admin, add a map via Admin → Maps. | Success. |
| **1.3 Non-admin cannot delete map** | As non-admin (or unauthenticated), call `deleteDoc(doc(db, 'maps', '<some-map-id>'))` from console. | Permission denied. |
| **1.4 Client cannot delete training session** | From console: `deleteDoc(doc(db, 'trainingSessions', '<some-session-id>'))`. | Permission denied (rules have `allow delete: if false`). |
| **1.5 Invalid map shape rejected** | In Rules Playground, simulate create on `maps` with missing `name` or `slug`, or `name` > 100 chars. | Denied. |

**Optional (emulator):**  
`firebase emulators:start --only firestore` then run the same operations against the emulator and check that rules deny/allow as above.

---

## 2. Cloud Functions

**Goal:** deleteTrainingSession only allows creator or admin; faceitProxy only forwards valid FACEIT paths.

| Test | How | Expected |
|------|-----|----------|
| **2.1 Only creator or admin can delete session** | Call `deleteTrainingSession({ sessionId: '<id>', steamId: '<random-steam-id>' })` via Firebase SDK (e.g. from browser console) for a session created by someone else. | permission-denied (or not-found). |
| **2.2 Creator can delete own session** | As the Steam user who created the session, use the app’s delete button. | Success. |
| **2.3 faceitProxy invalid endpoint** | Call faceitProxy with `{ endpoint: '' }` or `{ endpoint: 'https://evil.com' }`. | invalid-argument. |

---

## 3. Security headers (hosted site)

**Goal:** Headers are present and CSP allows only intended origins.

| Test | How | Expected |
|------|-----|----------|
| **3.1 Headers present** | Open https://jkvdf-d185b.web.app → DevTools → Network → select the document request → Headers. | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Strict-Transport-Security`, `Content-Security-Policy` present. |
| **3.2 CSP blocks inline scripts from unknown source** | In Console, try loading a script from a non-whitelisted URL (e.g. `document.createElement('script'); ... src = 'https://evil.com/x.js'` and append). | CSP blocks it (console error). |
| **3.3 FACEIT requests allowed** | Open Rooster page; FACEIT stats load. | No CSP errors; requests to `open.faceit.com` succeed. |

---

## 4. Auth / admin flow

**Goal:** Only whitelisted admins can “log in”; admin UI is gated.

| Test | How | Expected |
|------|-----|----------|
| **4.1 Non-whitelisted Steam cannot log in** | Use Steam OpenID with an account that is not in Firestore `admins` and not in client whitelist. | Callback fails with “Steam ID not whitelisted for admin access.” |
| **4.2 Admin UI only for admins** | Log out; try to open `/admin` or map/nade admin routes directly. | No admin forms / redirect or message that you’re not admin. |
| **4.3 Admin from Firestore** | Add a new doc in `admins/<steamId>` in Firebase Console (no client whitelist change). Log in with that Steam ID. | Treated as admin (single source of truth). |

---

## 5. Input validation and sanitization

**Goal:** No raw API keys in errors; lengths and types enforced.

| Test | How | Expected |
|------|-----|----------|
| **5.1 Map/nade length limits** | Try saving map with name length > 100 or slug > 50 (via UI or direct Firestore attempt). | Client truncation and/or Firestore rule rejection. |
| **5.2 Error messages** | Trigger a Firestore or API error (e.g. wrong credentials). | No raw API key in alert/UI (keys redacted if present in message). |

---

## Quick manual run (no emulator)

1. **Hosted site:** Open https://jkvdf-d185b.web.app.
2. **Headers:** Network tab → first document → check CSP and other security headers.
3. **Read-only:** Don’t log in; browse maps, nades, training. Everything readable; no write/delete.
4. **Non-admin login:** Use a non-whitelisted Steam account; expect login to be rejected.
5. **Admin login:** Use a whitelisted Steam ID; expect success and access to admin UI.
6. **Delete session:** As admin, delete another user’s session (if UI allows) or only your own; confirm behavior matches rules and callable (only creator or admin can delete).

After running these, you’ll have a good baseline that Firestore rules, Functions, headers, and auth are aligned with your security goals.
