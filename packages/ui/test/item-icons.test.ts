// SPDX-License-Identifier: AGPL-3.0-only

// The item-icon loader (`src/itemIcons.ts`, ADR 0052 point 6): one fetch per host
// per session, at most two at once, a pause and retry after a rate limit, no retry after any
// other failure, and every URL revoked on clear.
import { describe, expect, it } from "vitest";

import { type IconFetcher, IconLoader, MAX_CONCURRENT, RATE_LIMIT_WAIT_MS, iconKey } from "../src/itemIcons.ts";

/** A fetcher whose calls the test settles by hand. */
function manual() {
  const calls: { host: string; resolve: (v: Uint8Array | null) => void; reject: (e: unknown) => void }[] = [];
  const fetch: IconFetcher = (host) =>
    new Promise((resolve, reject) => {
      calls.push({ host, resolve, reject });
    });
  return { fetch, calls };
}

function urls() {
  const made: string[] = [];
  const revoked: string[] = [];
  return {
    made,
    revoked,
    factory: {
      create: (png: Uint8Array) => {
        const url = `blob:test/${made.length}-${png.length}`;
        made.push(url);
        return url;
      },
      revoke: (url: string) => {
        revoked.push(url);
      },
    },
  };
}

function timers() {
  const pending: { f: () => void; ms: number }[] = [];
  return {
    pending,
    timers: {
      set: (f: () => void, ms: number) => {
        pending.push({ f, ms });
        return pending.length - 1;
      },
      clear: () => undefined,
    },
  };
}

const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47]);
const settle = () => new Promise((r) => setTimeout(r, 0));

describe("iconKey", () => {
  it("lowercases, trims and drops trailing dots", () => {
    expect(iconKey(" WWW.Example.COM. ")).toBe("www.example.com");
    expect(iconKey("example.com..")).toBe("example.com");
  });
});

describe("IconLoader", () => {
  it("fetches each host once and shows a blob URL", async () => {
    const { fetch, calls } = manual();
    const u = urls();
    const loader = new IconLoader(fetch, u.factory, timers().timers);
    let changes = 0;
    loader.subscribe(() => (changes += 1));
    loader.request("example.com");
    loader.request("EXAMPLE.com");
    loader.request("example.com.");
    expect(calls.map((c) => c.host)).toEqual(["example.com"]);
    expect(loader.peek("example.com")).toBeNull();
    calls[0]!.resolve(PNG);
    await settle();
    expect(loader.peek("Example.com")).toBe("blob:test/0-4");
    expect(changes).toBe(1);
    loader.request("example.com");
    expect(calls).toHaveLength(1);
  });

  it("runs at most two fetches at once", async () => {
    const { fetch, calls } = manual();
    const loader = new IconLoader(fetch, urls().factory, timers().timers);
    for (const host of ["a.example", "b.example", "c.example", "d.example"]) {
      loader.request(host);
    }
    expect(calls).toHaveLength(MAX_CONCURRENT);
    calls[0]!.resolve(null);
    await settle();
    expect(calls.map((c) => c.host)).toEqual(["a.example", "b.example", "c.example"]);
    expect(loader.peek("a.example")).toBeNull();
  });

  it("pauses after a rate limit and retries the same host", async () => {
    const { fetch, calls } = manual();
    const t = timers();
    const loader = new IconLoader(fetch, urls().factory, t.timers);
    loader.request("a.example");
    loader.request("b.example");
    loader.request("c.example");
    calls[0]!.reject({ code: "server_rate_limited" });
    await settle();
    expect(t.pending).toHaveLength(1);
    expect(t.pending[0]!.ms).toBe(RATE_LIMIT_WAIT_MS);
    calls[1]!.resolve(PNG);
    await settle();
    expect(calls).toHaveLength(2);
    t.pending[0]!.f();
    expect(calls.map((c) => c.host)).toEqual(["a.example", "b.example", "a.example", "c.example"]);
  });

  it("does not retry other failures", async () => {
    const { fetch, calls } = manual();
    const loader = new IconLoader(fetch, urls().factory, timers().timers);
    loader.request("a.example");
    calls[0]!.reject({ code: "transport_failed" });
    await settle();
    loader.request("a.example");
    expect(calls).toHaveLength(1);
    expect(loader.peek("a.example")).toBeNull();
  });

  it("revokes every URL on clear and fetches nothing after", async () => {
    const { fetch, calls } = manual();
    const u = urls();
    const loader = new IconLoader(fetch, u.factory, timers().timers);
    loader.request("a.example");
    loader.request("b.example");
    calls[0]!.resolve(PNG);
    await settle();
    loader.clear();
    expect(u.revoked).toEqual(["blob:test/0-4"]);
    expect(loader.peek("a.example")).toBeNull();
    // A fetch that finishes after the clear makes no URL.
    calls[1]!.resolve(PNG);
    await settle();
    expect(u.made).toHaveLength(1);
    expect(u.revoked).toEqual(["blob:test/0-4"]);
    loader.request("c.example");
    expect(calls).toHaveLength(2);
  });

  it("ignores an empty host", () => {
    const { fetch, calls } = manual();
    const loader = new IconLoader(fetch, urls().factory, timers().timers);
    loader.request("  ");
    expect(calls).toHaveLength(0);
  });
});
