// The save-prompt-by-location index (`core-host/save-prompt-location.ts`): the fix for the
// save-prompt race (`apps/extension/README.md`'s residual note). Pure and synchronous, with an
// injected clock, so every TTL and single-use edge is exercised directly, no fake timers or a
// real `DurableSession` needed.
import { describe, expect, it } from "vitest";

import { createSavePromptLocationIndex } from "../src/core-host/save-prompt-location.ts";

const TTL = 2 * 60 * 1000;

describe("SavePromptLocationIndex", () => {
  it("finds a remembered token for the same tab and registrable domain", () => {
    const index = createSavePromptLocationIndex(TTL);
    index.remember(7, "example.com", "tok-1", 1000);
    expect(index.take(7, "example.com", 1500)).toBe("tok-1");
  });

  it("is single-use: a second take for the same tab and domain finds nothing", () => {
    const index = createSavePromptLocationIndex(TTL);
    index.remember(7, "example.com", "tok-1", 1000);
    expect(index.take(7, "example.com", 1500)).toBe("tok-1");
    expect(index.take(7, "example.com", 1500)).toBeUndefined();
  });

  it("expires after the TTL, checked on read even without a timer", () => {
    const index = createSavePromptLocationIndex(TTL);
    index.remember(7, "example.com", "tok-1", 1000);
    expect(index.take(7, "example.com", 1000 + TTL + 1)).toBeUndefined();
  });

  it("does not find a token remembered for a different tab", () => {
    const index = createSavePromptLocationIndex(TTL);
    index.remember(7, "example.com", "tok-1", 1000);
    expect(index.take(8, "example.com", 1500)).toBeUndefined();
    // The entry for tab 7 is still there — a lookup for the wrong tab must not consume it.
    expect(index.take(7, "example.com", 1500)).toBe("tok-1");
  });

  it("does not find a token remembered for a different registrable domain", () => {
    const index = createSavePromptLocationIndex(TTL);
    index.remember(7, "example.com", "tok-1", 1000);
    expect(index.take(7, "evil.example", 1500)).toBeUndefined();
  });

  it("a later remember for the same tab and domain replaces the earlier one", () => {
    const index = createSavePromptLocationIndex(TTL);
    index.remember(7, "example.com", "tok-1", 1000);
    index.remember(7, "example.com", "tok-2", 1200);
    expect(index.take(7, "example.com", 1500)).toBe("tok-2");
  });

  it("is a no-op when the tab id is undefined (some senders carry none)", () => {
    const index = createSavePromptLocationIndex(TTL);
    index.remember(undefined, "example.com", "tok-1", 1000);
    expect(index.take(7, "example.com", 1500)).toBeUndefined();
    expect(index.take(undefined, "example.com", 1500)).toBeUndefined();
  });

  it("is a no-op when the registrable domain is undefined (an IP literal or bare suffix)", () => {
    const index = createSavePromptLocationIndex(TTL);
    index.remember(7, undefined, "tok-1", 1000);
    expect(index.take(7, "example.com", 1500)).toBeUndefined();
    expect(index.take(7, undefined, 1500)).toBeUndefined();
  });

  it("clear drops every entry (the lock path)", () => {
    const index = createSavePromptLocationIndex(TTL);
    index.remember(7, "example.com", "tok-1", 1000);
    index.remember(8, "example.org", "tok-2", 1000);
    index.clear();
    expect(index.take(7, "example.com", 1500)).toBeUndefined();
    expect(index.take(8, "example.org", 1500)).toBeUndefined();
  });
});
