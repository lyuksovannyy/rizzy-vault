// The `storage.session` fallback (ADR 0013 §3 rule 2; ADR 0036 §2): "if the offscreen
// document/background page is torn down while the user expects to stay unlocked, the extension
// restores unlocked state from `storage.session`, cleared on lock and on browser close, never
// from `storage.local` or IndexedDB (INV-63)."
//
// This module moves opaque bytes only. It never interprets what it stores: the long-lived
// context decides what "unlocked state" means (today, nothing real — see `core/bindings.ts`;
// this module exists and is tested so the fallback plumbing is ready the day a real snapshot
// exists to put in it). `storage.session` is already memory-only and cleared by the browser on
// profile close, which is why INV-63 allows it as the one exception to "never outside the
// long-lived context's own memory."
const STORAGE_KEY = "rizzy.unlocked_snapshot.v1";

/** `chrome.storage.session`/`browser.storage.session` is undefined on a browser that predates
 * it, AND — measured empirically, not documented in Chrome's own API reference at the time of
 * writing — inside a `chrome.offscreen` document specifically, where `ext.storage` itself is
 * `undefined` (`types/webext.d.ts`'s own comment). Callers degrade to "no fallback, re-enter the
 * master password" in either case; every other function below is only ever called after this one
 * returns `true` (this module's own contract, relied on by the non-null assertions below). */
export function hasSessionStorage(ext: WebExtNamespace): boolean {
  return ext.storage?.session !== undefined;
}

/** Saves `bytes` (base64-encoded: `storage.session` carries structured-clone values, and a
 * plain string round-trips everywhere without a Uint8Array/ArrayBuffer clone quirk). Callers
 * must check {@link hasSessionStorage} first (this module's own contract, above). */
export async function saveUnlockedSnapshot(ext: WebExtNamespace, bytes: Uint8Array): Promise<void> {
  await ext.storage!.session.set({ [STORAGE_KEY]: bytesToBase64(bytes) });
}

/** Reads back a snapshot saved by {@link saveUnlockedSnapshot}, or `undefined` if none is
 * stored (first run, already locked, or the browser restarted and cleared it). Callers must
 * check {@link hasSessionStorage} first. */
export async function restoreUnlockedSnapshot(ext: WebExtNamespace): Promise<Uint8Array | undefined> {
  const got = await ext.storage!.session.get(STORAGE_KEY);
  const value = got[STORAGE_KEY];
  if (typeof value !== "string") {
    return undefined;
  }
  return base64ToBytes(value);
}

/** Clears the snapshot: called on lock (explicit or auto-lock) and before writing a new one.
 * Callers must check {@link hasSessionStorage} first. */
export async function clearUnlockedSnapshot(ext: WebExtNamespace): Promise<void> {
  await ext.storage!.session.remove(STORAGE_KEY);
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
