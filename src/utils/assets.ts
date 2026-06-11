// Cache-busting for locally-served images (e.g. /nuke.jpg).
//
// Firebase previously served any *.jpg/png with a 1-year `immutable` cache, and
// before those map images were deployed the SPA rewrite returned index.html for
// their URLs — so some browsers have a broken response pinned for a year.
// Appending a version makes a new cache key so every browser re-fetches once.
//
// Bump ASSET_VERSION whenever you replace a local image in place and need
// clients to pick it up. Remote URLs (YouTube thumbnails, etc.) are left as-is.
export const ASSET_VERSION = '2';

export function versionedAsset(url: string | undefined | null): string {
  if (!url || !url.startsWith('/')) return url ?? '';
  return url.includes('?') ? `${url}&v=${ASSET_VERSION}` : `${url}?v=${ASSET_VERSION}`;
}
