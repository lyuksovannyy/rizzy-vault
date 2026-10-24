// SPDX-License-Identifier: AGPL-3.0-only

// The ADR 0043 iframe instance-token store (`core-host/iframe-instance.ts`): pure and
// synchronous, with an injected clock, same pattern as `passkey-ceremony.test.ts`. What it must
// enforce: a token is honoured only for the exact tab that registered it, only until it expires
// or is revoked, a revoke never aborts a request already admitted (ADR 0043 Open question 4)
// but refuses every later one, and the store stays bounded.
import { describe, expect, it } from "vitest";

import { createIframeInstanceStore, IFRAME_INSTANCE_TTL_MS } from "../src/core-host/iframe-instance.ts";

const TTL = 30 * 60 * 1000;
const ORIGIN = "https://example.com";
const T1 = "3b241101-e2bb-4255-8caf-4136c566a962";
const T2 = "9d3f0a5e-1c2b-4f6e-a7d8-0b1c2d3e4f50";

describe("IframeInstanceStore", () => {
  it("the default TTL is ADR 0043 Open question 1's recommendation, 30 minutes", () => {
    expect(IFRAME_INSTANCE_TTL_MS).toBe(TTL);
  });

  it("admits a registered token for the exact tab it was registered for", () => {
    const store = createIframeInstanceStore(TTL);
    expect(store.register(T1, 7, ORIGIN, 1000)).toBe(true);
    expect(store.acquire(T1, 7, 1500)).toBe(true);
  });

  it("is reusable while live: one menu instance may send several requests (a generate, then a fill)", () => {
    const store = createIframeInstanceStore(TTL);
    store.register(T1, 7, ORIGIN, 1000);
    expect(store.acquire(T1, 7, 1500)).toBe(true);
    store.release(T1);
    expect(store.acquire(T1, 7, 1600)).toBe(true);
  });

  it("an unknown token always finds nothing", () => {
    const store = createIframeInstanceStore(TTL);
    expect(store.acquire(T1, 7, 1500)).toBe(false);
  });

  it("refuses a token registered for a different tab id (cross-instance)", () => {
    const store = createIframeInstanceStore(TTL);
    store.register(T1, 7, ORIGIN, 1000);
    expect(store.acquire(T1, 8, 1500)).toBe(false);
    // ...and that refusal does not consume or damage the real tab's registration.
    expect(store.acquire(T1, 7, 1500)).toBe(true);
  });

  it("expires after the TTL, checked on read even without a timer", () => {
    const store = createIframeInstanceStore(TTL);
    store.register(T1, 7, ORIGIN, 1000);
    expect(store.acquire(T1, 7, 1000 + TTL)).toBe(true);
    store.release(T1);
    expect(store.acquire(T1, 7, 1000 + TTL + 1)).toBe(false);
    expect(store.size()).toBe(0);
  });

  it("refuses a revoked token (a destroyed instance's replay)", () => {
    const store = createIframeInstanceStore(TTL);
    store.register(T1, 7, ORIGIN, 1000);
    store.revoke(T1, 7);
    expect(store.acquire(T1, 7, 1500)).toBe(false);
    expect(store.size()).toBe(0);
  });

  it("ignores a revoke from a different tab than the registering one", () => {
    const store = createIframeInstanceStore(TTL);
    store.register(T1, 7, ORIGIN, 1000);
    store.revoke(T1, 8);
    expect(store.acquire(T1, 7, 1500)).toBe(true);
  });

  // ADR 0043 point 5 / Open question 4: a blur or rebuild revoking the token while a real click's
  // request is already being handled must not pull it out from under that request, but nothing
  // arriving after the revoke may use it.
  it("a revoke during an admitted request refuses later requests at once, and deletes the entry only once it settles", () => {
    const store = createIframeInstanceStore(TTL);
    store.register(T1, 7, ORIGIN, 1000);
    expect(store.acquire(T1, 7, 1100)).toBe(true);
    store.revoke(T1, 7);
    expect(store.acquire(T1, 7, 1200)).toBe(false);
    expect(store.size()).toBe(1);
    store.release(T1);
    expect(store.size()).toBe(0);
    expect(store.acquire(T1, 7, 1300)).toBe(false);
  });

  it("with two requests in flight, the entry survives until the last one settles", () => {
    const store = createIframeInstanceStore(TTL);
    store.register(T1, 7, ORIGIN, 1000);
    store.acquire(T1, 7, 1100);
    store.acquire(T1, 7, 1100);
    store.revoke(T1, 7);
    store.release(T1);
    expect(store.size()).toBe(1);
    store.release(T1);
    expect(store.size()).toBe(0);
  });

  it("an unpaired release is a no-op, never a negative in-flight count", () => {
    const store = createIframeInstanceStore(TTL);
    store.register(T1, 7, ORIGIN, 1000);
    store.release(T1);
    store.release("no-such-token");
    store.revoke(T1, 7);
    expect(store.size()).toBe(0);
  });

  it("refuses to register a token it already holds, never rebinding it to another tab or refreshing its TTL", () => {
    const store = createIframeInstanceStore(TTL);
    expect(store.register(T1, 7, ORIGIN, 1000)).toBe(true);
    expect(store.register(T1, 8, "https://attacker.example", 2000)).toBe(false);
    expect(store.acquire(T1, 8, 2500)).toBe(false);
    expect(store.acquire(T1, 7, 1000 + TTL + 1)).toBe(false);
  });

  it("keeps each tab's tokens independent", () => {
    const store = createIframeInstanceStore(TTL);
    store.register(T1, 7, ORIGIN, 1000);
    store.register(T2, 8, ORIGIN, 1000);
    store.revoke(T1, 7);
    expect(store.acquire(T2, 8, 1500)).toBe(true);
  });

  it("clear drops every registration (lock)", () => {
    const store = createIframeInstanceStore(TTL);
    store.register(T1, 7, ORIGIN, 1000);
    store.register(T2, 8, ORIGIN, 1000);
    store.clear();
    expect(store.acquire(T1, 7, 1500)).toBe(false);
    expect(store.acquire(T2, 8, 1500)).toBe(false);
    expect(store.size()).toBe(0);
  });

  it("is bounded per tab: the tab's own oldest registration is evicted, never another tab's", () => {
    const store = createIframeInstanceStore(TTL, 2, 100);
    store.register(T2, 8, ORIGIN, 1000);
    store.register("t-a", 7, ORIGIN, 1000);
    store.register("t-b", 7, ORIGIN, 1001);
    store.register("t-c", 7, ORIGIN, 1002);
    expect(store.acquire("t-a", 7, 1500)).toBe(false);
    expect(store.acquire("t-b", 7, 1500)).toBe(true);
    expect(store.acquire("t-c", 7, 1500)).toBe(true);
    expect(store.acquire(T2, 8, 1500)).toBe(true);
  });

  it("is bounded overall: past the global cap the soonest-expiring registration is evicted", () => {
    const store = createIframeInstanceStore(TTL, 8, 3);
    store.register("t-1", 1, ORIGIN, 1000);
    store.register("t-2", 2, ORIGIN, 1001);
    store.register("t-3", 3, ORIGIN, 1002);
    store.register("t-4", 4, ORIGIN, 1003);
    expect(store.size()).toBe(3);
    expect(store.acquire("t-1", 1, 1500)).toBe(false);
    expect(store.acquire("t-4", 4, 1500)).toBe(true);
  });

  it("prunes expired, idle registrations on the next register", () => {
    const store = createIframeInstanceStore(TTL);
    store.register(T1, 7, ORIGIN, 1000);
    store.register(T2, 7, ORIGIN, 1000 + TTL + 1);
    expect(store.size()).toBe(1);
  });
});
