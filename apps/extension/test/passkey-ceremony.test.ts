// The passkey consent ceremony store (`core-host/passkey-ceremony.ts`): pure and synchronous,
// with an injected clock, same pattern as `save-prompt-location.test.ts`. The one rule this
// store exists to enforce that `save-prompt-location.ts` deliberately does not: a navigation
// (a changed tab id or a changed bound origin) invalidates a pending ceremony, never survives it.
import { describe, expect, it } from "vitest";

import {
  createPasskeyCeremonyStore,
  isOfferedCandidate,
  type PasskeyCreateCeremony,
  type PasskeyGetCeremony,
} from "../src/core-host/passkey-ceremony.ts";

const TTL = 2 * 60 * 1000;

const createRequest: PasskeyCreateCeremony = {
  kind: "create",
  origin: "https://example.com",
  rpId: "example.com",
  rpName: "Example",
  userIdB64: "dXNlci0x",
  userName: "alice",
  userDisplayName: "Alice",
  challengeB64: "Y2hhbGxlbmdl",
};

const getRequest: PasskeyGetCeremony = {
  kind: "get",
  origin: "https://example.com",
  rpId: "example.com",
  challengeB64: "Y2hhbGxlbmdl",
  candidates: [{ passkeyRef: "item-1:el-1", itemTitle: "Example", userName: "alice" }],
};

describe("PasskeyCeremonyStore", () => {
  it("finds a created ceremony with the exact binding it was created with", () => {
    const store = createPasskeyCeremonyStore(TTL);
    const token = store.create(createRequest, 7, "https://example.com", 1000);
    expect(store.take(token, 7, "https://example.com", 1500)).toEqual(createRequest);
  });

  it("is single-use: a second take for the same token finds nothing", () => {
    const store = createPasskeyCeremonyStore(TTL);
    const token = store.create(createRequest, 7, "https://example.com", 1000);
    expect(store.take(token, 7, "https://example.com", 1500)).toEqual(createRequest);
    expect(store.take(token, 7, "https://example.com", 1500)).toBeUndefined();
  });

  it("expires after the TTL, checked on read even without a timer", () => {
    const store = createPasskeyCeremonyStore(TTL);
    const token = store.create(createRequest, 7, "https://example.com", 1000);
    expect(store.take(token, 7, "https://example.com", 1000 + TTL + 1)).toBeUndefined();
  });

  it("an unknown token always finds nothing", () => {
    const store = createPasskeyCeremonyStore(TTL);
    expect(store.take("no-such-token", 7, "https://example.com", 1500)).toBeUndefined();
  });

  // The module's own reason to exist: a navigation (a different tab, or the same tab now at a
  // different origin) must invalidate the ceremony, unlike a save-prompt offer.
  it("refuses a take from a different tab id than the one the ceremony was bound to", () => {
    const store = createPasskeyCeremonyStore(TTL);
    const token = store.create(createRequest, 7, "https://example.com", 1000);
    expect(store.take(token, 8, "https://example.com", 1500)).toBeUndefined();
  });

  it("refuses a take from a different live origin than the one the ceremony was bound to", () => {
    const store = createPasskeyCeremonyStore(TTL);
    const token = store.create(createRequest, 7, "https://example.com", 1000);
    expect(store.take(token, 7, "https://attacker.example", 1500)).toBeUndefined();
  });

  it("a binding mismatch still consumes the token (single-use regardless of outcome)", () => {
    const store = createPasskeyCeremonyStore(TTL);
    const token = store.create(createRequest, 7, "https://example.com", 1000);
    expect(store.take(token, 8, "https://example.com", 1500)).toBeUndefined();
    // Even the correct binding now finds nothing: `take` always deletes the entry first.
    expect(store.take(token, 7, "https://example.com", 1500)).toBeUndefined();
  });

  it("clear drops every pending ceremony (the lock path)", () => {
    const store = createPasskeyCeremonyStore(TTL);
    const token1 = store.create(createRequest, 7, "https://example.com", 1000);
    const token2 = store.create(getRequest, 8, "https://example.org", 1000);
    store.clear();
    expect(store.take(token1, 7, "https://example.com", 1500)).toBeUndefined();
    expect(store.take(token2, 8, "https://example.org", 1500)).toBeUndefined();
  });

  it("stores a get ceremony with its candidates intact", () => {
    const store = createPasskeyCeremonyStore(TTL);
    const token = store.create(getRequest, 7, "https://example.com", 1000);
    expect(store.take(token, 7, "https://example.com", 1500)).toEqual(getRequest);
  });
});

describe("isOfferedCandidate", () => {
  it("accepts a passkeyRef that is one of the ceremony's own candidates", () => {
    expect(isOfferedCandidate(getRequest, "item-1:el-1")).toBe(true);
  });

  it("refuses a passkeyRef that was never offered", () => {
    expect(isOfferedCandidate(getRequest, "item-2:el-2")).toBe(false);
  });
});
