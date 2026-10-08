// The durable-device (ADR 0036) and matching (ADR 0037) wrappers, without a server: bad input,
// cache-corrupt refusals, and the matcher's pure decisions. The full cycle against a real
// server (enrol, authenticate, reopen) is e2e.test.ts's job.
import { beforeAll, describe, expect, it } from "vitest";

import {
  type CacheRow,
  type CacheStore,
  CoreError,
  MatchMode,
  type Transport,
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
