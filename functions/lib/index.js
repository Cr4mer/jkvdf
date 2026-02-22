"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.deleteTrainingSession = exports.leetifyProxy = exports.faceitProxy = void 0;
const functions = __importStar(require("firebase-functions"));
const admin = __importStar(require("firebase-admin"));
admin.initializeApp();
const FACEIT_BASE = 'https://open.faceit.com/data/v4';
/** Single source of truth: admin check via Firestore admins collection. */
async function isAdminSteamId(db, steamId) {
    if (!steamId || typeof steamId !== 'string')
        return false;
    const id = String(steamId).toUpperCase();
    const snap = await db.collection('admins').doc(id).get();
    return snap.exists;
}
/**
 * FACEIT API proxy. Callable from client with { endpoint: string }.
 * Keeps FACEIT API key on the server (set via firebase functions:config:set faceit.api_key "YOUR_KEY").
 * Wrapped in try/catch so all errors return HttpsError and get proper CORS headers.
 */
// Allowed FACEIT API path prefixes (no path traversal, no protocol-relative or absolute URLs)
const FACEIT_ALLOWED_PREFIXES = ['/players', '/matches', '/games', '/games/csgo', '/organizers', '/championships', '/leaderboards', '/search'];
function isAllowedFaceitEndpoint(endpoint) {
    if (typeof endpoint !== 'string' || !endpoint.startsWith('/'))
        return false;
    if (endpoint.includes('..') || endpoint.includes('//'))
        return false;
    return FACEIT_ALLOWED_PREFIXES.some((p) => endpoint === p || endpoint.startsWith(p + '/') || endpoint.startsWith(p + '?'));
}
exports.faceitProxy = functions.https.onCall(async (data, context) => {
    try {
        const endpoint = data?.endpoint;
        if (!isAllowedFaceitEndpoint(endpoint)) {
            throw new functions.https.HttpsError('invalid-argument', 'Invalid endpoint');
        }
        const apiKey = process.env.FACEIT_API_KEY ?? functions.config().faceit?.api_key;
        if (!apiKey) {
            throw new functions.https.HttpsError('failed-precondition', 'FACEIT API key not configured');
        }
        const url = `${FACEIT_BASE}${endpoint}`;
        const res = await fetch(url, {
            method: 'GET',
            headers: {
                Authorization: `Bearer ${apiKey}`,
                'Content-Type': 'application/json',
            },
        });
        if (!res.ok) {
            const text = await res.text();
            throw new functions.https.HttpsError('internal', `FACEIT API error: ${res.status}`, { details: text.slice(0, 200) });
        }
        return res.json();
    }
    catch (err) {
        if (err instanceof functions.https.HttpsError)
            throw err;
        const message = err instanceof Error ? err.message : String(err);
        throw new functions.https.HttpsError('internal', message);
    }
});
const LEETIFY_BASE = 'https://api-public.cs-prod.leetify.com';
/**
 * Leetify API proxy. Callable with { path: string } (e.g. "/v3/profile", "/v3/profile/matches").
 * Query params (e.g. steam_id) must be included in path. Keeps API key on server.
 * Set key via: firebase functions:config:set leetify.api_key "YOUR_KEY"
 * or env LEETIFY_API_KEY. Get key at https://leetify.com/app/developer
 */
exports.leetifyProxy = functions.https.onCall(async (data, context) => {
    try {
        const path = data?.path;
        const steamId64 = typeof data?.steamId64 === 'string' ? data.steamId64.replace(/\D/g, '') : null;
        if (typeof path !== 'string' || !path.startsWith('/')) {
            throw new functions.https.HttpsError('invalid-argument', 'Invalid path');
        }
        if (path.includes('..') || path.includes('//')) {
            throw new functions.https.HttpsError('invalid-argument', 'Invalid path');
        }
        const allowedPaths = ['/v3/profile', '/v3/profile/matches'];
        const allowed = allowedPaths.some((p) => path === p || path.startsWith(p + '?') || path.startsWith(p + '/'));
        if (!allowed) {
            throw new functions.https.HttpsError('invalid-argument', 'Invalid path');
        }
        const apiKey = process.env.LEETIFY_API_KEY ?? functions.config().leetify?.api_key;
        if (!apiKey) {
            throw new functions.https.HttpsError('failed-precondition', 'Leetify API key not configured');
        }
        const headers = {
            Authorization: `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
        };
        const basePath = path.split('?')[0];
        const tryPath = (param, value) => `${basePath}?${param}=${encodeURIComponent(value)}`;
        let url = `${LEETIFY_BASE}${path}`;
        let res = await fetch(url, { method: 'GET', headers });
        let body = null;
        if (res.ok) {
            body = await res.json();
            const errMsg = body && typeof body === 'object' && 'error' in body && typeof body.error === 'string' ? body.error : '';
            if (errMsg && errMsg.toLowerCase().includes('identifier') && steamId64) {
                const toTry = [
                    ...['steam_id_64', 'steamId64', 'steam_id', 'identifier'].map((param) => ({
                        url: `${LEETIFY_BASE}${tryPath(param, steamId64)}`,
                    })),
                    { url: `${LEETIFY_BASE}${basePath}/${steamId64}` },
                ];
                for (const { url: tryUrl } of toTry) {
                    res = await fetch(tryUrl, { method: 'GET', headers });
                    if (!res.ok)
                        continue;
                    body = await res.json();
                    if (body && typeof body === 'object' && !('error' in body))
                        break;
                }
            }
        }
        if (!res.ok) {
            if (res.status === 404)
                return null;
            const text = await res.text();
            throw new functions.https.HttpsError('internal', `Leetify API error: ${res.status}`, { details: text.slice(0, 200) });
        }
        return body;
    }
    catch (err) {
        if (err instanceof functions.https.HttpsError)
            throw err;
        const message = err instanceof Error ? err.message : String(err);
        throw new functions.https.HttpsError('internal', message);
    }
});
/**
 * Delete a training session. Callable with { sessionId: string, steamId: string }.
 * Allowed only if steamId is the session creator or an admin.
 * Wrapped in try/catch so all errors return HttpsError and get proper CORS headers.
 */
exports.deleteTrainingSession = functions.https.onCall(async (data, context) => {
    try {
        const sessionId = data?.sessionId;
        const steamId = data?.steamId;
        if (typeof sessionId !== 'string' || sessionId.length === 0) {
            throw new functions.https.HttpsError('invalid-argument', 'sessionId is required');
        }
        if (typeof steamId !== 'string' || steamId.length === 0) {
            throw new functions.https.HttpsError('invalid-argument', 'steamId is required');
        }
        const db = admin.firestore();
        const sessionRef = db.collection('trainingSessions').doc(sessionId);
        const sessionSnap = await sessionRef.get();
        if (!sessionSnap.exists) {
            throw new functions.https.HttpsError('not-found', 'Session not found');
        }
        const createdBy = sessionSnap.data()?.createdBy;
        const normalizedSteamId = String(steamId).toUpperCase();
        const normalizedCreatedBy = createdBy ? String(createdBy).toUpperCase() : '';
        const isCreator = normalizedCreatedBy === normalizedSteamId;
        const isAdmin = await isAdminSteamId(db, steamId);
        if (!isCreator && !isAdmin) {
            throw new functions.https.HttpsError('permission-denied', 'Only the session creator or an admin can delete this session');
        }
        await sessionRef.delete();
        return { success: true };
    }
    catch (err) {
        if (err instanceof functions.https.HttpsError)
            throw err;
        const message = err instanceof Error ? err.message : String(err);
        throw new functions.https.HttpsError('internal', message);
    }
});
//# sourceMappingURL=index.js.map