// `cache/idb.ts` against `@rizzy-vault/core`'s `CacheStore` contract: flat (store, key, value)
// records, one object store per name, opaque bytes in and out, no structured `keyPath`. Uses
// `test/support/fake-idb.ts` (vitest's `environment: "node"` has no real `indexedDB`), never
// `fake-indexeddb` — not a dependency of this workspace.
import { beforeEach, describe, expect, it } from "vitest";

import { CacheError, ExtensionCache, deleteCache } from "../src/cache/idb.ts";
import { FakeIndexedDBFactory } from "./support/fake-idb.ts";

const STORES = ["cache_meta", "device_state", "pending_commit", "account_objects", "vaults", "wraps", "ops", "snapshots"];

function bytes(...values: number[]): Uint8Array {
  return new Uint8Array(values);
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function fake(): any {
  return new FakeIndexedDBFactory();
}

describe("ExtensionCache (cache/idb.ts)", () => {
  let factory: ReturnType<typeof fake>;

  beforeEach(() => {
    factory = fake();
  });

  it("opens and creates one object store per name", async () => {
    const cache = await ExtensionCache.open(STORES, factory);
    for (const name of STORES) {
      await expect(cache.list(name)).resolves.toEqual([]);
    }
  });

  it("put then get round-trips opaque bytes exactly", async () => {
    const cache = await ExtensionCache.open(STORES, factory);
    const key = bytes(1, 2, 3);
    const value = bytes(9, 9, 9, 0);
    await cache.put("device_state", key, value);
    await expect(cache.get("device_state", key)).resolves.toEqual(value);
  });

  it("get on a missing key resolves undefined, not an error (an ordinary cache miss)", async () => {
    const cache = await ExtensionCache.open(STORES, factory);
    await expect(cache.get("account_objects", bytes(1))).resolves.toBeUndefined();
  });

  it("the same key bytes in two different stores do not collide", async () => {
    const cache = await ExtensionCache.open(STORES, factory);
    const key = bytes(7, 7);
    await cache.put("vaults", key, bytes(1));
    await cache.put("wraps", key, bytes(2));
    await expect(cache.get("vaults", key)).resolves.toEqual(bytes(1));
    await expect(cache.get("wraps", key)).resolves.toEqual(bytes(2));
  });

  it("delete removes the row; a later get is a miss again", async () => {
    const cache = await ExtensionCache.open(STORES, factory);
    const key = bytes(5);
    await cache.put("ops", key, bytes(42));
    await cache.delete("ops", key);
    await expect(cache.get("ops", key)).resolves.toBeUndefined();
  });

  it("delete of an already-missing key is a no-op, not an error", async () => {
    const cache = await ExtensionCache.open(STORES, factory);
    await expect(cache.delete("snapshots", bytes(1, 2))).resolves.toBeUndefined();
  });

  it("put overwrites an existing row at the same key (one write of the whole record)", async () => {
    const cache = await ExtensionCache.open(STORES, factory);
    const key = bytes(1);
    await cache.put("cache_meta", key, bytes(1));
    await cache.put("cache_meta", key, bytes(2));
    await expect(cache.get("cache_meta", key)).resolves.toEqual(bytes(2));
    await expect(cache.list("cache_meta")).resolves.toEqual([{ store: "cache_meta", key, value: bytes(2) }]);
  });

  it("list returns every row of a store as {store, key, value}, keys and values paired correctly", async () => {
    const cache = await ExtensionCache.open(STORES, factory);
    await cache.put("account_objects", bytes(1), bytes(10));
    await cache.put("account_objects", bytes(2), bytes(20));
    await cache.put("account_objects", bytes(3), bytes(30));
    const rows = await cache.list("account_objects");
    const sorted = [...rows].sort((a, b) => a.key[0]! - b.key[0]!);
    expect(sorted).toEqual([
      { store: "account_objects", key: bytes(1), value: bytes(10) },
      { store: "account_objects", key: bytes(2), value: bytes(20) },
      { store: "account_objects", key: bytes(3), value: bytes(30) },
    ]);
  });

  it("list of an untouched store is empty, never an error", async () => {
    const cache = await ExtensionCache.open(STORES, factory);
    await expect(cache.list("pending_commit")).resolves.toEqual([]);
  });

  it("mutating the input array after put does not change the stored value (defensive copy)", async () => {
    const cache = await ExtensionCache.open(STORES, factory);
    const key = bytes(1);
    const value = bytes(1, 2, 3);
    await cache.put("device_state", key, value);
    value[0] = 99;
    await expect(cache.get("device_state", key)).resolves.toEqual(bytes(1, 2, 3));
  });

  it("mutating a returned value does not change what is stored (defensive copy on read)", async () => {
    const cache = await ExtensionCache.open(STORES, factory);
    const key = bytes(1);
    await cache.put("device_state", key, bytes(1, 2, 3));
    const first = await cache.get("device_state", key);
    first![0] = 255;
    await expect(cache.get("device_state", key)).resolves.toEqual(bytes(1, 2, 3));
  });

  it("an empty key or value is a valid row, not refused", async () => {
    const cache = await ExtensionCache.open(STORES, factory);
    await cache.put("cache_meta", bytes(), bytes());
    await expect(cache.get("cache_meta", bytes())).resolves.toEqual(bytes());
  });

  it("reopening the same factory's database sees rows written by a previous open (persists across opens)", async () => {
    const first = await ExtensionCache.open(STORES, factory);
    await first.put("vaults", bytes(1), bytes(1));
    first.close();
    const second = await ExtensionCache.open(STORES, factory);
    await expect(second.get("vaults", bytes(1))).resolves.toEqual(bytes(1));
  });

  it("deleteCache removes every row; a later open starts from empty again", async () => {
    const cache = await ExtensionCache.open(STORES, factory);
    await cache.put("vaults", bytes(1), bytes(1));
    cache.close();
    await deleteCache(factory);
    const reopened = await ExtensionCache.open(STORES, factory);
    await expect(reopened.list("vaults")).resolves.toEqual([]);
  });

  it("CacheError names its error class so a caller can distinguish a storage failure from a miss", () => {
    expect(new CacheError("boom").name).toBe("CacheError");
  });
});
