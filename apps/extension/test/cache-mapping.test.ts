// Cache store mapping (ADR 0026 §3 "IndexedDB (M2)": "the same logical stores, keyed
// identically, with the same blobs"). This test is the one piece of machine-checkable evidence
// that `cache/stores.ts` matches the SQL `PRIMARY KEY`s the ADR defines — written so the
// integration step can trust the mapping without re-deriving it from the ADR text.
import { describe, expect, it } from "vitest";

import {
  ACCOUNT_OBJECTS,
  ALL_STORES,
  CACHE_META,
  DEVICE_STATE,
  OPS,
  PENDING_COMMIT,
  SNAPSHOTS,
  VAULTS,
  WRAPS,
  decodeU64BE,
  encodeU64BE,
} from "../src/cache/stores.ts";

// ADR 0026 §3's SQL, verbatim, as the reference this test checks `stores.ts` against:
//   cache_meta(k TEXT PRIMARY KEY, v BLOB NOT NULL)
//   device_state(id INTEGER PRIMARY KEY CHECK (id = 1), record BLOB NOT NULL)
//   pending_commit(id INTEGER PRIMARY KEY CHECK (id = 1), request BLOB NOT NULL)
//   account_objects(kind INTEGER, key BLOB, bytes BLOB NOT NULL, PRIMARY KEY (kind, key))
//   vaults(vault_id BLOB PRIMARY KEY, self_grant BLOB NOT NULL, ...)
//   wraps(vault_id BLOB, item_id BLOB, item_key_id BLOB, ..., PRIMARY KEY (vault_id, item_id, item_key_id))
//   ops(vault_id BLOB, device_id BLOB, device_seq BLOB, ..., PRIMARY KEY (vault_id, device_id, device_seq))
//   snapshots(vault_id BLOB, snapshot_id BLOB, ..., PRIMARY KEY (vault_id, snapshot_id))
describe("cache/stores.ts matches ADR 0026 §3's SQL primary keys", () => {
  it("cache_meta is keyed by k (the TEXT PRIMARY KEY)", () => {
    expect(CACHE_META).toEqual({ name: "cache_meta", keyPath: ["k"] });
  });

  it("device_state and pending_commit are singletons (SQL CHECK (id = 1), no IndexedDB key path)", () => {
    expect(DEVICE_STATE).toEqual({ name: "device_state", keyPath: undefined });
    expect(PENDING_COMMIT).toEqual({ name: "pending_commit", keyPath: undefined });
  });

  it("account_objects is keyed by (kind, key)", () => {
    expect(ACCOUNT_OBJECTS).toEqual({ name: "account_objects", keyPath: ["kind", "key"] });
  });

  it("vaults is keyed by vault_id", () => {
    expect(VAULTS).toEqual({ name: "vaults", keyPath: ["vault_id"] });
  });

  it("wraps is keyed by (vault_id, item_id, item_key_id)", () => {
    expect(WRAPS).toEqual({ name: "wraps", keyPath: ["vault_id", "item_id", "item_key_id"] });
  });

  it("ops is keyed by (vault_id, device_id, device_seq)", () => {
    expect(OPS).toEqual({ name: "ops", keyPath: ["vault_id", "device_id", "device_seq"] });
  });

  it("snapshots is keyed by (vault_id, snapshot_id)", () => {
    expect(SNAPSHOTS).toEqual({ name: "snapshots", keyPath: ["vault_id", "snapshot_id"] });
  });

  it("ALL_STORES holds exactly the eight tables above, once each", () => {
    const names = ALL_STORES.map((s) => s.name);
    expect(names).toEqual([
      "cache_meta",
      "device_state",
      "pending_commit",
      "account_objects",
      "vaults",
      "wraps",
      "ops",
      "snapshots",
    ]);
    expect(new Set(names).size).toBe(names.length);
  });
});

describe("encodeU64BE / decodeU64BE", () => {
  it("round-trips", () => {
    for (const n of [0n, 1n, 255n, 256n, 2n ** 32n, 2n ** 63n, 0xffffffffffffffffn]) {
      expect(decodeU64BE(encodeU64BE(n))).toBe(n);
    }
  });

  it("is always 8 bytes", () => {
    expect(encodeU64BE(0n)).toHaveLength(8);
    expect(encodeU64BE(0xffffffffffffffffn)).toHaveLength(8);
  });

  it("rejects out-of-range values", () => {
    expect(() => encodeU64BE(-1n)).toThrow(RangeError);
    expect(() => encodeU64BE(0x10000000000000000n)).toThrow(RangeError);
  });

  it("rejects a malformed byte length on decode", () => {
    expect(() => decodeU64BE(new Uint8Array(7))).toThrow(RangeError);
    expect(() => decodeU64BE(new Uint8Array(9))).toThrow(RangeError);
  });

  it("bytewise order equals numeric order (ADR 0026 §3's whole reason for this encoding)", () => {
    const values = [0n, 1n, 2n, 255n, 256n, 65535n, 65536n, 2n ** 40n, 2n ** 63n, 0xffffffffffffffffn];
    const sortedByValue = [...values].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const sortedByBytes = [...values]
      .map((n) => ({ n, bytes: encodeU64BE(n) }))
      .sort((a, b) => compareBytes(a.bytes, b.bytes))
      .map((e) => e.n);
    expect(sortedByBytes).toEqual(sortedByValue);
  });
});

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < a.length; i += 1) {
    const av = a[i] ?? 0;
    const bv = b[i] ?? 0;
    if (av !== bv) {
      return av - bv;
    }
  }
  return 0;
}
