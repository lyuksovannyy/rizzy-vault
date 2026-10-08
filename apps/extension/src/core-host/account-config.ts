// Persists the one non-secret fact `unlockDevice` needs beyond the encrypted cache: which
// server this device enrolled against (ADR 0026 §3's `device_state`/cache rows hold no server
// URL).
//
// IndexedDB, not `chrome.storage.local`: measured empirically against a real Chromium build
// (the same finding `core-host/listener.ts`'s own doc comment records for `chrome.idle`), a
// `chrome.offscreen` document's `chrome` object has no `storage` namespace at all — and
// `handlePopupRequest` (enrol, status, unlock) runs inside exactly that context on Chromium
// (ADR 0036 §2). The previous version of this module used `ext.storage.local` and degraded to a
// no-op when it was missing, which on Chromium is *every* call: `saveAccountConfig` silently
// never persisted anything, so `get_status` read back `serverOrigin: undefined` forever, even
// immediately after a successful `enrol` (the popup's "Set up" form never left itself — no
// error, no `Lock` button, because `App.tsx`'s `refreshStatus` landed back on `view: "enrol"`).
//
// IndexedDB has no such gap: `cache/idb.ts`'s `ExtensionCache` already depends on it working
// inside the offscreen document, so this module uses the same browser API, in a database of its
// own — not the durable-device cache's database (`cacheStoreNames()` is owned by
// `@rizzy-vault/core`; this value has nothing to do with the core and must keep working even
// before `initCore()` has resolved, which `get_status` relies on per `core-context.ts`).
export class AccountConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AccountConfigError";
  }
}

const DATABASE_NAME = "rizzy-account-config";
const STORE_NAME = "config";
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const RECORD_KEY = encoder.encode("config");

interface StoredConfig {
  readonly serverOrigin: string;
  readonly loginName: string;
}

function toPromise<T>(req: IDBRequest<T>, label: string): Promise<T> {
  return new Promise((resolve, reject) => {
    req.addEventListener("success", () => resolve(req.result));
    req.addEventListener("error", () => reject(new AccountConfigError(`${label}: ${String(req.error)}`)));
  });
}

function openDatabase(factory: IDBFactory): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = factory.open(DATABASE_NAME, 1);
    req.addEventListener("upgradeneeded", () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    });
    req.addEventListener("success", () => resolve(req.result));
    req.addEventListener("error", () => reject(new AccountConfigError(`opening account config: ${String(req.error)}`)));
  });
}

function toBytes(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) {
    return value;
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
  }
  throw new AccountConfigError(`expected bytes from IndexedDB, got ${typeof value}`);
}

/** Saves the server origin and login name an enrolment just used, so a later `unlock` does not
 * need the user to retype them. `factory` defaults to `globalThis.indexedDB` and is overridden
 * only by tests (`test/support/fake-idb.ts`). */
export async function saveAccountConfig(serverOrigin: string, loginName: string, factory: IDBFactory = globalThis.indexedDB): Promise<void> {
  const db = await openDatabase(factory);
  try {
    const record: StoredConfig = { serverOrigin, loginName };
    const value = encoder.encode(JSON.stringify(record));
    const tx = db.transaction(STORE_NAME, "readwrite");
    await toPromise(tx.objectStore(STORE_NAME).put(value, RECORD_KEY as unknown as IDBValidKey), "saving account config");
  } finally {
    db.close();
  }
}

/** Reads back what {@link saveAccountConfig} last saved, or `undefined` fields if nothing was
 * ever saved (a fresh profile) or the stored record is unreadable (never thrown — a corrupt or
 * foreign-shaped record degrades to "not enrolled" rather than breaking `get_status`). */
export async function readAccountConfig(
  factory: IDBFactory = globalThis.indexedDB,
): Promise<{ readonly serverOrigin: string | undefined; readonly loginName: string | undefined }> {
  const db = await openDatabase(factory);
  try {
    const tx = db.transaction(STORE_NAME, "readonly");
    const stored = await toPromise(tx.objectStore(STORE_NAME).get(RECORD_KEY as unknown as IDBValidKey), "reading account config");
    if (stored === undefined) {
      return { serverOrigin: undefined, loginName: undefined };
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(decoder.decode(toBytes(stored)));
    } catch {
      return { serverOrigin: undefined, loginName: undefined };
    }
    if (typeof parsed !== "object" || parsed === null) {
      return { serverOrigin: undefined, loginName: undefined };
    }
    const record = parsed as Partial<StoredConfig>;
    return {
      serverOrigin: typeof record.serverOrigin === "string" ? record.serverOrigin : undefined,
      loginName: typeof record.loginName === "string" ? record.loginName : undefined,
    };
  } finally {
    db.close();
  }
}
