// SPDX-License-Identifier: AGPL-3.0-only

// The content-script <-> inline-menu-iframe `postMessage` protocol's own shape validation
// (`inline-menu/protocol.ts`): pure logic, no DOM needed. `window.postMessage` delivers to any
// listener regardless of claimed source, so both message shapes are checked defensively even
// though only one direction is actually forgeable (see `protocol.ts`'s own comment).
import { describe, expect, it } from "vitest";

import { MAX_CANDIDATES, MAX_HOST_LEN } from "../src/messaging/contract.ts";
import {
  INLINE_MENU_PICK,
  INLINE_MENU_SHOW,
  isInlineMenuPickMessage,
  isInlineMenuShowMessage,
} from "../src/inline-menu/protocol.ts";

/** An ADR 0043 instance token: a canonical v4 UUID. */
const TOKEN = "3b241101-e2bb-4255-8caf-4136c566a962";

describe("isInlineMenuShowMessage", () => {
  it("accepts a well-formed show message with candidates", () => {
    const message = {
      type: INLINE_MENU_SHOW,
      pageOrigin: "https://example.com",
      instanceToken: TOKEN,
      pageHost: "example.com",
      candidates: [
        { itemId: "item-1", title: "Example", username: "alice", needsWarning: false, savedHost: "example.com" },
      ],
    };
    expect(isInlineMenuShowMessage(message)).toBe(true);
  });

  // Multi-step login pages (ROADMAP §4.4 M3): the step's one field, passed on to the fill request.
  it("accepts only: username or password, and refuses any other value", () => {
    const base = { type: INLINE_MENU_SHOW, pageOrigin: "https://example.com", instanceToken: TOKEN, pageHost: "example.com", candidates: [] };
    expect(isInlineMenuShowMessage({ ...base, only: "username" })).toBe(true);
    expect(isInlineMenuShowMessage({ ...base, only: "password" })).toBe(true);
    expect(isInlineMenuShowMessage({ ...base, only: "email" })).toBe(false);
    expect(isInlineMenuShowMessage({ ...base, only: 1 })).toBe(false);
  });

  // ADR 0043 point 3: the show message is the one channel the instance token travels.
  it("refuses a missing or malformed instanceToken", () => {
    const base = { type: INLINE_MENU_SHOW, pageOrigin: "https://example.com", pageHost: "example.com", candidates: [] };
    expect(isInlineMenuShowMessage(base)).toBe(false);
    expect(isInlineMenuShowMessage({ ...base, instanceToken: "tok-1" })).toBe(false);
    expect(isInlineMenuShowMessage({ ...base, instanceToken: TOKEN.toUpperCase() })).toBe(false);
  });

  it("refuses a candidate missing needsWarning", () => {
    const message = {
      type: INLINE_MENU_SHOW,
      pageOrigin: "https://example.com",
      instanceToken: TOKEN,
      pageHost: "example.com",
      candidates: [{ itemId: "item-1", title: "Example", username: "alice", savedHost: "example.com" }],
    };
    expect(isInlineMenuShowMessage(message)).toBe(false);
  });

  it("refuses a candidate missing savedHost (gap 31 in the M2 gap audit)", () => {
    const message = {
      type: INLINE_MENU_SHOW,
      pageOrigin: "https://example.com",
      instanceToken: TOKEN,
      pageHost: "example.com",
      candidates: [{ itemId: "item-1", title: "Example", username: "alice", needsWarning: false }],
    };
    expect(isInlineMenuShowMessage(message)).toBe(false);
  });

  it("refuses an oversized savedHost", () => {
    const message = {
      type: INLINE_MENU_SHOW,
      pageOrigin: "https://example.com",
      instanceToken: TOKEN,
      pageHost: "example.com",
      candidates: [
        {
          itemId: "item-1",
          title: "Example",
          username: "alice",
          needsWarning: false,
          savedHost: "a".repeat(MAX_HOST_LEN + 1),
        },
      ],
    };
    expect(isInlineMenuShowMessage(message)).toBe(false);
  });

  it("accepts zero candidates", () => {
    expect(
      isInlineMenuShowMessage({
        type: INLINE_MENU_SHOW,
        pageOrigin: "https://example.com",
        instanceToken: TOKEN,
        pageHost: "example.com",
        candidates: [],
      }),
    ).toBe(true);
  });

  it("refuses more than MAX_CANDIDATES", () => {
    const candidates = Array.from({ length: MAX_CANDIDATES + 1 }, (_, i) => ({
      itemId: `item-${i}`,
      title: "t",
      username: "u",
      needsWarning: false,
      savedHost: "example.com",
    }));
    expect(
      isInlineMenuShowMessage({
        type: INLINE_MENU_SHOW,
        pageOrigin: "https://example.com",
        instanceToken: TOKEN,
        pageHost: "example.com",
        candidates,
      }),
    ).toBe(false);
  });

  it("refuses a malformed candidate", () => {
    const message = {
      type: INLINE_MENU_SHOW,
      pageOrigin: "https://example.com",
      instanceToken: TOKEN,
      pageHost: "example.com",
      candidates: [{ itemId: "x" }],
    };
    expect(isInlineMenuShowMessage(message)).toBe(false);
  });

  it("refuses the wrong type tag", () => {
    expect(
      isInlineMenuShowMessage({
        type: "something_else",
        pageOrigin: "https://example.com",
        pageHost: "example.com",
        candidates: [],
      }),
    ).toBe(false);
  });

  it("refuses a missing pageOrigin", () => {
    expect(isInlineMenuShowMessage({ type: INLINE_MENU_SHOW, pageHost: "example.com", candidates: [] })).toBe(false);
  });

  it("refuses a missing pageHost", () => {
    expect(isInlineMenuShowMessage({ type: INLINE_MENU_SHOW, pageOrigin: "https://example.com", candidates: [] })).toBe(
      false,
    );
  });

  it("refuses non-object input", () => {
    expect(isInlineMenuShowMessage(null)).toBe(false);
    expect(isInlineMenuShowMessage("show")).toBe(false);
  });
});

describe("isInlineMenuPickMessage", () => {
  it("accepts a well-formed pick message", () => {
    expect(isInlineMenuPickMessage({ type: INLINE_MENU_PICK, itemId: "item-1" })).toBe(true);
  });

  it("refuses a missing itemId", () => {
    expect(isInlineMenuPickMessage({ type: INLINE_MENU_PICK })).toBe(false);
  });

  it("refuses the wrong type tag", () => {
    expect(isInlineMenuPickMessage({ type: INLINE_MENU_SHOW, itemId: "item-1" })).toBe(false);
  });

  it("refuses non-object input", () => {
    expect(isInlineMenuPickMessage(undefined)).toBe(false);
  });
});
