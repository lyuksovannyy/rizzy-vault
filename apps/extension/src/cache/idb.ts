// The IndexedDB adapter (ADR 0036 §3, §6): "a small TypeScript module... that implements the
// host-provided storage capability... calling `rizzy-wasm`'s `store` bindings with raw bytes it
// never interprets." Implements `@rizzy-vault/core`'s `CacheStore` contract exactly: one
// IndexedDB object store per name in `cacheStoreNames()`, each row keyed by the opaque
// `Uint8Array` key `rizzy-wasm` already encoded. No IndexedDB `keyPath`: a `keyPath` only makes
// sense when this module inspects the value to find its key, and `CacheStore`'s value is
// already-opaque bytes it never parses (ADR 0036 §6). `get`/`put`/`delete`/`list` each map onto
// exactly one browser-native IndexedDB call.
import type { CacheRow, CacheStore } from "@rizzy-vault/core";

import { CACHE_DATABASE_NAME } from "./stores.ts";

export class CacheError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CacheError";
  }
}

/** Every value this adapter reads back from IndexedDB is normalised to a fresh, independent
 * `Uint8Array`: a real browser round-trips a binary key/value through structured clone (so the
 * caller already gets its own copy there), but always copying here means a caller mutating a
 * value this module returned can never reach back into this adapter's own storage — true of the
 * real IndexedDB and, since it does not clone on read, deliberately enforced for the in-memory
 * test fake too (`test/support/fake-idb.ts`). */
function toBytes(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) {
    return new Uint8Array(value);
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
  }
  throw new CacheError(`expected bytes from IndexedDB, got ${typeof value}`);
}

/** A `Uint8Array` is a valid IndexedDB key at runtime (binary keys, part of the IndexedDB spec
 * and supported by every browser this extension targets): `IDBValidKey`'s `BufferSource` arm
 * covers it. The cast below exists only because this workspace's TypeScript/`@types/node`
 * combination narrows generic `Uint8Array<ArrayBufferLike>` in a way that trips up overload
 * resolution against `IDBValidKey | IDBKeyRange` (a types-package mismatch, not a runtime
 * concern) — see `cache/idb.ts`'s own test (`test/idb.test.ts`) for the behaviour this asserts. */
function toKey(key: Uint8Array): IDBValidKey {
  return key as unknown as IDBValidKey;
}

function toPromise<T>(req: IDBRequest<T>, label: string): Promise<T> {
  return new Promise((resolve, reject) => {
    req.addEventListener("success", () => resolve(req.result));
    req.addEventListener("error", () => reject(new CacheError(`${label}: ${String(req.error)}`)));
  });
}

function openDatabase(factory: IDBFactory, storeNames: readonly string[]): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = factory.open(CACHE_DATABASE_NAME, 1);
    req.addEventListener("upgradeneeded", () => {
      const db = req.result;
      for (const name of storeNames) {
        if (!db.objectStoreNames.contains(name)) {
          // Out-of-line keys (no `keyPath`, no `autoIncrement`): every row's key is the
          // `Uint8Array` `put`/`get`/`delete` already receive from `@rizzy-vault/core`.
          db.createObjectStore(name);
        }
      }
    });
    req.addEventListener("success", () => resolve(req.result));
    req.addEventListener("error", () => reject(new CacheError(`opening cache: ${String(req.error)}`)));
  });
}

/** The browser extension's `CacheStore` (ADR 0026 §3; ADR 0036 §6: "parses nothing"). Every
 * value in and out is raw bytes this module never interprets, decodes or validates — that is
 * `rizzy_client::store`'s job, run inside `@rizzy-vault/core`'s `DurableSession` before a byte
 * ever reaches here. */
export class ExtensionCache implements CacheStore {
  readonly #db: IDBDatabase;

  private constructor(db: IDBDatabase) {
    this.#db = db;
  }

  /** Opens (creating on first use) the one database this adapter manages, with one object
   * store per name in `storeNames`. `storeNames` must be `cacheStoreNames()`'s result, read by
   * the caller only after the core is initialised — `cacheStoreNames()` itself calls the core's
   * `ensureReady`, so this cannot run before `init()` resolves (ADR 0036 §2: the long-lived
   * context loads the wasm module once, before any cache or device call). `factory` is
   * `globalThis.indexedDB` by default and an injected fake in tests
   * (`test/support/fake-idb.ts`), never a new dependency (`fake-indexeddb` is not in this
   * workspace's `package.json`). */
  static async open(
    storeNames: readonly string[],
    factory: IDBFactory = globalThis.indexedDB,
  ): Promise<ExtensionCache> {
    return new ExtensionCache(await openDatabase(factory, storeNames));
  }

  close(): void {
    this.#db.close();
  }

  async get(store: string, key: Uint8Array): Promise<Uint8Array | undefined> {
    const tx = this.#db.transaction(store, "readonly");
    const value = await toPromise(tx.objectStore(store).get(toKey(key)), store);
    return value === undefined ? undefined : toBytes(value);
  }

  /** Writes one row whole (ADR 0026 §4's "one write of the whole record"): this adapter never
   * offers a partial-field update, only `put` of a complete value, keyed explicitly by `key`
   * rather than any `keyPath` derived from it. */
  async put(store: string, key: Uint8Array, value: Uint8Array): Promise<void> {
    const tx = this.#db.transaction(store, "readwrite");
    await toPromise(tx.objectStore(store).put(value, toKey(key)), store);
  }

  async delete(store: string, key: Uint8Array): Promise<void> {
    const tx = this.#db.transaction(store, "readwrite");
    await toPromise(tx.objectStore(store).delete(toKey(key)), store);
  }

  /** Every row of `store`, for `unlockDurableDevice`'s one-time full load (ADR 0026 §4 "load").
   * Walks a cursor, rather than pairing `getAllKeys()` with `getAll()`, so a key and its value
   * can never be read from two slightly different snapshots of the store. Small cache, read in
   * full; no pagination, matching `idb.ts`'s previous scale assumption. */
  async list(store: string): Promise<readonly CacheRow[]> {
    const tx = this.#db.transaction(store, "readonly");
    const rows: CacheRow[] = [];
    await new Promise<void>((resolve, reject) => {
      const cursorReq = tx.objectStore(store).openCursor();
      cursorReq.addEventListener("success", () => {
        const cursor = cursorReq.result;
        if (cursor === null) {
          resolve();
          return;
        }
        rows.push({ store, key: toBytes(cursor.key), value: toBytes(cursor.value) });
        cursor.continue();
      });
      cursorReq.addEventListener("error", () => reject(new CacheError(`${store}: ${String(cursorReq.error)}`)));
    });
    return rows;
  }
}

/** Deletes the whole durable-device cache (ADR 0026 §5 "removal"). Not wired to any caller yet
 * (`core-context.ts` has no reset/purge path today — checked while writing this change, since
 * its doc used to claim otherwise); when one is added, per the open question's recommendation in
 * ADR 0026 — itself unresolved — it should call this only after any unsent own rows have been
 * handled, since this function only removes and does not implement the "upload unsent own ops
 * first" step. **It must also clear `account-config.ts`'s own database** (a separate IndexedDB
 * database, not a store inside this one): leaving the saved server origin behind while this
 * cache is gone would make `get_status` report `enrolled: true` forever with nothing in the
 * cache to unlock — a wedge with no UI escape, since the enrol form only shows up when
 * `enrolled` is `false`. */
export function deleteCache(factory: IDBFactory = globalThis.indexedDB): Promise<void> {
  return new Promise((resolve, reject) => {
    const req = factory.deleteDatabase(CACHE_DATABASE_NAME);
    req.addEventListener("success", () => resolve());
    req.addEventListener("error", () => reject(new CacheError(`deleting cache: ${String(req.error)}`)));
  });
}
