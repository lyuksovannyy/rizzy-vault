// The IndexedDB database the browser extension's durable-device cache lives in (ADR 0026 §3
// "IndexedDB (M2)"; ADR 0036 §6). `packages/core`'s `cacheStoreNames()` — not this file — is now
// the single source of truth for which object stores exist and what each is named: that is
// `@rizzy-vault/core`'s `CacheStore` contract ("get/put/delete of one row, and list of a whole
// store, keyed exactly as `cacheStoreNames` names them... every value here is already the
// opaque bytes a `put`/`get` needs"). This file used to mirror ADR 0026 §3's SQL `PRIMARY KEY`s
// as IndexedDB `keyPath`s, store by store; that mirroring does not match the actual contract
// (`get(store, key)` / `put(store, key, value)` over an already-encoded `Uint8Array` key,
// never a structured value this module would have to inspect) and has been removed along with
// its test (`cache-mapping.test.ts`) — see `cache/idb.ts` for what replaced it.
//
// This module itself never imports `@rizzy-vault/core`: `eslint.config.mjs` allows a *value*
// import of it only from `apps/extension/src/core-host/**` (ADR 0036 §2), and `cache/` is not
// under that directory. `core-host/bindings.ts` re-exports `cacheStoreNames()`;
// `core-host/core-context.ts` is the one caller that reads it and passes the result into
// `cache/idb.ts`'s `ExtensionCache.open(storeNames)`.

/** The single IndexedDB database the extension's durable-device cache lives in. One database,
 * not one per account: ADR 0036 enrols the extension as exactly one durable device per browser
 * profile for M2 (no multi-account switcher is in ROADMAP §4.4's scope), and naming the
 * database by account id would need to decrypt something before the database that holds the
 * still-encrypted `device_state` row can even be opened — backwards. Bumping this name (or
 * adding a real migration) is the path if a later milestone adds multi-account support. */
export const CACHE_DATABASE_NAME = "rizzy-vault.durable-device";

/** The current cache format, mirrored from ADR 0026 §5's "cache format 1". Bumping this is a
 * migration, exactly as it is for `rv`'s SQLite file; `cache/idb.ts` does not implement one yet
 * because the format has not changed since this adapter's first cut. */
export const CACHE_FORMAT_VERSION = 1;
