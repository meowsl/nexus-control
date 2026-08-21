import type { Asset } from "./types";

/** Short in-memory catalog cache so returning to a repo does not re-list Nexus. */
export const ASSET_CACHE_TTL_MS = 2 * 60 * 1000;

type Entry = { items: Asset[]; at: number };

const store = new Map<string, Entry>();

export function readAssetCache(repo: string): { items: Asset[]; fresh: boolean } | null {
  const entry = store.get(repo);
  if (!entry) return null;
  return {
    items: entry.items,
    fresh: Date.now() - entry.at < ASSET_CACHE_TTL_MS,
  };
}

export function writeAssetCache(repo: string, items: Asset[]): void {
  store.set(repo, { items, at: Date.now() });
}
