// The IndexedDB adapter (ADR 0036 §3, §6): "a small TypeScript module... that implements the
// host-provided storage capability... calling `rizzy-wasm`'s `store` bindings with raw bytes it
// never interprets." This module opens the database, creates the object stores of
// `cache/stores.ts` on first use, and exposes `get`/`put`/`delete`/`listKeys` as byte-in,
// byte-out operations. It does not decode a `device_state` record, does not know what
// `account_objects.kind` means, and never runs `rizzy_client::store`'s invariant checks itself
// — that is `core/bindings.ts`'s `applyChangeset`'s job once it exists.
import { ALL_STORES, type StoreDef, databaseName } from "./stores.ts";

export class CacheError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CacheError";
  }
}

function openDatabase(accountIdHex: string): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(databaseName(accountIdHex), 1);
    request.addEventListener("upgradeneeded", () => {
      const db = request.result;
      for (const store of ALL_STORES) {
        if (!db.objectStoreNames.contains(store.name)) {
          db.createObjectStore(
            store.name,
            store.keyPath === undefined ? {} : { keyPath: [...store.keyPath] },
          );
        }
      }
    });
    request.addEventListener("success", () => resolve(request.result));
    request.addEventListener("error", () => reject(new CacheError(`opening cache: ${String(request.error)}`)));
  });
}

/** One account's encrypted local cache (ADR 0026 §3). Every value in and out is raw bytes; the
 * record a store's row holds is only ever `rizzy_client::store`'s own encoding of it. */
export class ExtensionCache {
  readonly #db: IDBDatabase;

  private constructor(db: IDBDatabase) {
    this.#db = db;
  }

  static async open(accountIdHex: string): Promise<ExtensionCache> {
    return new ExtensionCache(await openDatabase(accountIdHex));
  }

  close(): void {
    this.#db.close();
  }

  /** Reads one row's bytes, or `undefined` if the key has no row (this is not an error: a
   * missing `pending_commit`/`device_state` singleton, or a cache miss in `account_objects`,
   * is an ordinary "nothing written yet" the caller interprets, not a storage failure). */
  async get(store: StoreDef, key: unknown): Promise<unknown | undefined> {
    return this.#run(store.name, "readonly", (objectStore) => objectStore.get(key as never));
  }

  /** Writes one row whole, matching ADR 0026 §4's "one write of the whole record" rule: this
   * adapter never offers a partial-field update, only `put` of a complete value. */
  async put(store: StoreDef, value: unknown): Promise<void> {
    await this.#run(store.name, "readwrite", (objectStore) => objectStore.put(value as never));
  }

  async delete(store: StoreDef, key: unknown): Promise<void> {
    await this.#run(store.name, "readwrite", (objectStore) => objectStore.delete(key as never));
  }

  /** Every row of `store`, for a full reload (ADR 0026 §4 "load"). Small cache, read in full;
   * no pagination is implemented because none of the ADR 0026 stores are expected to need one
   * before a later milestone revisits this (same scale assumption `rv`'s SQLite file makes). */
  async getAll(store: StoreDef): Promise<unknown[]> {
    return this.#run(store.name, "readonly", (objectStore) => objectStore.getAll());
  }

  #run<T>(storeName: string, mode: IDBTransactionMode, body: (objectStore: IDBObjectStore) => IDBRequest<T>): Promise<T> {
    return new Promise((resolve, reject) => {
      const tx = this.#db.transaction(storeName, mode);
      const request = body(tx.objectStore(storeName));
      request.addEventListener("success", () => resolve(request.result));
      request.addEventListener("error", () => reject(new CacheError(`${storeName}: ${String(request.error)}`)));
    });
  }
}

/** Deletes the whole cache for one account (ADR 0026 §5 "removal"). `core-context.ts` calls
 * this only after any unsent own rows have been handled, per the open question's recommendation
 * in ADR 0026 — itself unresolved, so this function only removes; it does not yet implement
 * the "upload unsent own ops first" step (tracked alongside the other missing bindings). */
export function deleteCache(accountIdHex: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.deleteDatabase(databaseName(accountIdHex));
    request.addEventListener("success", () => resolve());
    request.addEventListener("error", () => reject(new CacheError(`deleting cache: ${String(request.error)}`)));
  });
}
