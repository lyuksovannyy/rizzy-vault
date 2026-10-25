// SPDX-License-Identifier: AGPL-3.0-only

// The durable-device (ADR 0036) and matching (ADR 0037) wrappers, without a server: bad input,
// cache-corrupt refusals, and the matcher's pure decisions. The full cycle against a real
// server (enrol, authenticate, reopen) is e2e.test.ts's job.
import { beforeAll, describe, expect, it } from "vitest";

import {
  type CacheRow,
  type CacheStore,
  type Clock,
  CoreError,
  DurableSession,
  MatchMode,
  type Transport,
  cacheRemovalRefusal,
  cacheStoreNames,
  decideMatchCandidates,
  enrolDevice,
  normalizePageUrl,
  registrableDomainOf,
  unlockDurableDevice,
} from "../src/index.js";
import { loadCore } from "./load.js";

beforeAll(() => {
  loadCore();
});

/** A transport nothing should call in these tests (bad input is refused before any request). */
const unreachable: Transport = () => {
  throw new Error("no request should be sent");
};

/** Whether two byte arrays hold the same bytes. */
function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

/** An in-memory {@link CacheStore}, for tests that never touch real `IndexedDB` (ADR 0026 §3's
 * eight stores, as a plain array). */
function memoryCacheStore(seed: readonly CacheRow[] = []): CacheStore {
  const rows: CacheRow[] = [...seed];
  return {
    async get(store, key) {
      return rows.find((r) => r.store === store && sameBytes(r.key, key))?.value;
    },
    async put(store, key, value) {
      const i = rows.findIndex((r) => r.store === store && sameBytes(r.key, key));
      if (i >= 0) {
        rows[i] = { store, key, value };
      } else {
        rows.push({ store, key, value });
      }
    },
    async delete(store, key) {
      const i = rows.findIndex((r) => r.store === store && sameBytes(r.key, key));
      if (i >= 0) {
        rows.splice(i, 1);
      }
    },
    async list(store) {
      return rows.filter((r) => r.store === store);
    },
  };
}

describe("cacheStoreNames", () => {
  it("names ADR 0026 §3's eight stores", () => {
    expect(cacheStoreNames()).toEqual([
      "cache_meta",
      "device_state",
      "pending_commit",
      "account_objects",
      "vaults",
      "wraps",
      "ops",
      "snapshots",
    ]);
  });
});

describe("enrolDevice", () => {
  it("refuses a malformed origin before sending anything", async () => {
    await expect(
      enrolDevice(
        unreachable,
        {
          origin: "not an origin",
          loginName: "alice",
          secretKey: "RV1-not-a-key",
          password: "pw",
        },
        memoryCacheStore(),
      ),
    ).rejects.toMatchObject({ code: "invalid_input" });
  });
});

describe("unlockDurableDevice", () => {
  it("refuses an empty cache dump as cache_corrupt, never a panic", async () => {
    await expect(unlockDurableDevice(unreachable, memoryCacheStore(), "pw")).rejects.toMatchObject(
      { code: "cache_corrupt" },
    );
  });

  it("refuses a cache row from an unknown store", async () => {
    // A row whose own `store` field names no real store — whichever named list a corrupted
    // or malicious host answers it under, the decode step catches it (store.rs's module docs,
    // "a row whose store name is not one of STORE_NAMES").
    const bad: CacheStore = {
      ...memoryCacheStore(),
      list: async () => [{ store: "not_a_real_store", key: new Uint8Array(), value: new Uint8Array() }],
    };
    await expect(unlockDurableDevice(unreachable, bad, "pw")).rejects.toMatchObject({
      code: "cache_corrupt",
    });
  });
});

// `DurableSession`'s own class docs: "Every mutating call ... drains the core's cache writes
// ... and persists them ... before it resolves" (ADR 0026 §4's write order). `sync()`'s
// auto-purge step is the one place that promise was broken (rizzy-cli's matching
// `Device::auto_purge` fix, same commit): a failing `autoPurge` used to skip the drain that
// follows it, so whatever the pass had already journaled before failing stayed in the wasm
// instance instead of reaching the `CacheStore` — lost if the session does not survive to the
// next successful `sync()` (a lock, a reload, the offscreen document closing). The fake
// `WasmDeviceSession` below needs no real wasm module: `sync()`'s drain-before-propagate
// ordering is pure orchestration over whatever `#inner` returns, so a double-cast stub drives
// it exactly as a real failing auto-purge would, with no server and no cache mocking beyond
// `memoryCacheStore`.
describe("DurableSession.sync", () => {
  const clock: Clock = () => 1_000;

  /** A `CacheDelta`-shaped object `drainCacheWrites` can return: no rows, freed once. */
  function emptyDelta(): { puts: never[]; deletes: never[]; free: () => void } {
    return { puts: [], deletes: [], free: () => {} };
  }

  it("drains cache writes before rethrowing a failed auto-purge", async () => {
    let drains = 0;
    const inner = {
      syncStart: () => {},
      syncRequest: () => undefined,
      autoPurge: () => {
        throw new Error("auto-purge failed partway");
      },
      drainCacheWrites: () => {
        drains += 1;
        return emptyDelta();
      },
    } as unknown as ConstructorParameters<typeof DurableSession>[0];
    const session = new DurableSession(inner, unreachable, memoryCacheStore(), clock);

    await expect(session.sync()).rejects.toThrow("auto-purge failed partway");

    // One drain for the fetch/upload driver settling, a second for whatever auto-purge wrote
    // before it failed — the second drain must run even though the call goes on to reject.
    expect(drains).toBe(2);
  });

  it("still drains and resolves when auto-purge succeeds", async () => {
    let drains = 0;
    const inner = {
      syncStart: () => {},
      syncRequest: () => undefined,
      autoPurge: () => {},
      drainCacheWrites: () => {
        drains += 1;
        return emptyDelta();
      },
    } as unknown as ConstructorParameters<typeof DurableSession>[0];
    const session = new DurableSession(inner, unreachable, memoryCacheStore(), clock);

    await expect(session.sync()).resolves.toBeUndefined();
    expect(drains).toBe(2);
  });
});

/** A request-shaped object `takeRequest` can read and free, for the stubbed drivers below. */
function stubRequest(): object {
  return {
    client: "rizzy-test",
    authorization: undefined,
    contentType: undefined,
    requestCounter: undefined,
    requestSignature: undefined,
    method: "POST",
    path: "/api/v1/vault/fetch",
    body: new Uint8Array(),
    free: () => {},
  };
}

/** A transport that answers every request with an empty 200 and logs it. */
function loggingTransport(log: string[]): Transport {
  return async (request) => {
    log.push(`send ${request.path}`);
    return { status: 200, body: new Uint8Array() };
  };
}

// ADR 0026 §4 step 4: "an alarm is written in the transaction that detects it". An answer that
// raises one (a rollback, a fork, an older copy of this device's history) fails `syncRespond`,
// and the alarm row journaled with that answer must reach the `CacheStore` before the error
// propagates, or a restart would lift read-only mode.
describe("DurableSession.sync and alarms", () => {
  const clock: Clock = () => 1_000;

  it("drains the writes of an answer that raised an alarm before rethrowing", async () => {
    const log: string[] = [];
    let requests = 0;
    const inner = {
      syncStart: () => log.push("start"),
      syncRequest: () => (requests++ === 0 ? stubRequest() : undefined),
      syncRespond: () => {
        log.push("respond");
        throw new Error("device_state_outdated");
      },
      drainCacheWrites: () => {
        log.push("drain");
        return { puts: [], deletes: [], free: () => {} };
      },
    } as unknown as ConstructorParameters<typeof DurableSession>[0];
    const session = new DurableSession(inner, loggingTransport(log), memoryCacheStore(), clock);

    await expect(session.sync()).rejects.toThrow("device_state_outdated");
    expect(log).toEqual(["start", "send /api/v1/vault/fetch", "respond", "drain"]);
  });
});

// ADR 0026 §5 as ADR 0095 §D replaces it: the removal upload persists every step's rows (the
// rows it sends are recorded as sent) before the next request goes out, and an alarm a step
// raised before its error propagates; a transport failure ends it with nothing more tried.
describe("DurableSession.uploadUnsentForRemoval", () => {
  const clock: Clock = () => 1_000;

  function removalInner(log: string[], respond: () => void, requestsLeft: number) {
    let left = requestsLeft;
    return {
      removalUploadStart: () => log.push("start"),
      removalUploadRequest: () => (left-- > 0 ? stubRequest() : undefined),
      removalUploadRespond: () => {
        log.push("respond");
        respond();
      },
      removalUploadAbort: () => log.push("abort"),
      drainCacheWrites: () => {
        log.push("drain");
        return { puts: [], deletes: [], free: () => {} };
      },
    } as unknown as ConstructorParameters<typeof DurableSession>[0];
  }

  it("drains after the start and after every answer, before the next request", async () => {
    const log: string[] = [];
    const session = new DurableSession(removalInner(log, () => {}, 2), loggingTransport(log), memoryCacheStore(), clock);
    await session.uploadUnsentForRemoval();
    expect(log).toEqual([
      "start",
      "drain",
      "send /api/v1/vault/fetch",
      "respond",
      "drain",
      "send /api/v1/vault/fetch",
      "respond",
      "drain",
    ]);
  });

  it("drains before rethrowing a refused answer, and tries nothing more", async () => {
    const log: string[] = [];
    const inner = removalInner(
      log,
      () => {
        throw new Error("server_unauthorized");
      },
      3,
    );
    const session = new DurableSession(inner, loggingTransport(log), memoryCacheStore(), clock);
    await expect(session.uploadUnsentForRemoval()).rejects.toThrow("server_unauthorized");
    expect(log).toEqual(["start", "drain", "send /api/v1/vault/fetch", "respond", "drain"]);
  });

  it("ends the upload when the transport fails", async () => {
    const log: string[] = [];
    const failing: Transport = async () => {
      log.push("send");
      throw new CoreError("transport_failed");
    };
    const session = new DurableSession(removalInner(log, () => {}, 3), failing, memoryCacheStore(), clock);
    await expect(session.uploadUnsentForRemoval()).rejects.toThrow("transport_failed");
    expect(log).toEqual(["start", "drain", "send", "abort"]);
  });
});

// ADR 0095 §D: the alarm rows are cleartext (ADR 0026 §3), so a cache that does not unlock is
// refused removal by the same rule, read through the real core without any key.
describe("cacheRemovalRefusal", () => {
  /** An `account_objects` row of kind 7 (alarm) with key `key`, in the core's byte codec. */
  function alarmRow(key: readonly number[]): CacheRow {
    return { store: "account_objects", key: new Uint8Array([0, 0, 0, 0, 0, 0, 0, 7, ...key]), value: new Uint8Array() };
  }

  it("allows removal with no alarm or only alarm 4 (device state outdated)", async () => {
    await expect(cacheRemovalRefusal(memoryCacheStore())).resolves.toBeUndefined();
    await expect(cacheRemovalRefusal(memoryCacheStore([alarmRow([4])]))).resolves.toBeUndefined();
  });

  it("refuses removal under alarms 1 to 3 and names the alarm", async () => {
    await expect(cacheRemovalRefusal(memoryCacheStore([alarmRow([1])]))).resolves.toBe("rollback");
    await expect(cacheRemovalRefusal(memoryCacheStore([alarmRow([2]), alarmRow([4])]))).resolves.toBe("fork");
    await expect(cacheRemovalRefusal(memoryCacheStore([alarmRow([3])]))).resolves.toBe("identity_change_unconfirmed");
  });

  it("refuses removal under an alarm key this build does not know", async () => {
    await expect(cacheRemovalRefusal(memoryCacheStore([alarmRow([5])]))).resolves.toBe("alarm_unknown");
    await expect(cacheRemovalRefusal(memoryCacheStore([alarmRow([])]))).resolves.toBe("alarm_unknown");
  });
});

describe("normalizePageUrl", () => {
  it("normalises scheme, host case, and drops the query", () => {
    expect(normalizePageUrl("HTTPS://Example.com/Path?x=1")).toBe("https://example.com/Path");
  });

  it("refuses a non-URL", () => {
    expect(() => normalizePageUrl("not a url")).toThrowError(
      expect.objectContaining({ code: "invalid_input" }),
    );
  });
});

// The extension's save-prompt-by-location index (ADR 0037 §2 rule 7) keys state by this.
describe("registrableDomainOf", () => {
  it("is the eTLD+1 of a host with a registrable domain", () => {
    expect(registrableDomainOf("https://login.example.com/path")).toBe("example.com");
  });

  // `rizzy-match`'s own `normalize.rs` doc: an IP literal is its own "registrable domain" (never
  // passed to the PSL, which has no concept of one) so the save-prompt-location index still
  // keys correctly for a self-hosted/intranet login reached by IP literal.
  it("is the IP literal itself for an IP-literal host, never a PSL lookup", () => {
    expect(registrableDomainOf("http://127.0.0.1:8080/")).toBe("127.0.0.1");
  });

  it("is undefined only for a bare public suffix, which has no registrable domain beneath it", () => {
    expect(registrableDomainOf("https://co.uk/")).toBeUndefined();
  });

  it("refuses a non-URL", () => {
    expect(() => registrableDomainOf("not a url")).toThrowError(
      expect.objectContaining({ code: "invalid_input" }),
    );
  });
});

describe("decideMatchCandidates", () => {
  const topFrame = { isTopFrame: true, frameOrigin: "" };

  it("matches a saved URI on the same registrable domain", () => {
    const decision = decideMatchCandidates(
      "https://example.com/",
      topFrame,
      MatchMode.BaseDomain,
      [
        {
          itemId: "11111111111111111111111111111111",
          uriId: "22222222222222222222222222222222",
          value: "https://login.example.com/signin",
          mode: MatchMode.BaseDomain,
        },
      ],
    );
    expect(decision.candidates).toHaveLength(1);
    expect(decision.candidates[0]).toMatchObject({
      itemId: "11111111111111111111111111111111",
      uriId: "22222222222222222222222222222222",
      needsWarning: false,
    });
    expect(decision.warnings).toEqual([]);
  });

  it("offers nothing for a different registrable domain, with no warning", () => {
    const decision = decideMatchCandidates(
      "https://example.com/",
      topFrame,
      MatchMode.BaseDomain,
      [
        {
          itemId: "11111111111111111111111111111111",
          uriId: "22222222222222222222222222222222",
          value: "https://other.example/",
          mode: MatchMode.BaseDomain,
        },
      ],
    );
    expect(decision.candidates).toEqual([]);
    expect(decision.warnings).toEqual([]);
  });

  it("narrows a non-top frame on another domain to no candidates, with a warning", () => {
    const decision = decideMatchCandidates(
      "https://example.com/",
      { isTopFrame: false, frameOrigin: "https://attacker.example/" },
      MatchMode.BaseDomain,
      [
        {
          itemId: "11111111111111111111111111111111",
          uriId: "22222222222222222222222222222222",
          value: "https://example.com/",
          mode: MatchMode.BaseDomain,
        },
      ],
    );
    expect(decision.candidates).toEqual([]);
    expect(decision.warnings).toHaveLength(1);
  });

  it("refuses a page URL that does not normalise", () => {
    expect(() => decideMatchCandidates("not a url", topFrame, MatchMode.BaseDomain, [])).toThrow(
      CoreError,
    );
  });
});
