// The content-script <-> inline-menu-iframe `postMessage` protocol's own shape validation
// (`inline-menu/protocol.ts`): pure logic, no DOM needed. `window.postMessage` delivers to any
// listener regardless of claimed source, so both message shapes are checked defensively even
// though only one direction is actually forgeable (see `protocol.ts`'s own comment).
import { describe, expect, it } from "vitest";

import { MAX_CANDIDATES } from "../src/messaging/contract.ts";
import {
  INLINE_MENU_PICK,
  INLINE_MENU_SHOW,
  isInlineMenuPickMessage,
  isInlineMenuShowMessage,
} from "../src/inline-menu/protocol.ts";

describe("isInlineMenuShowMessage", () => {
  it("accepts a well-formed show message with candidates", () => {
    const message = {
      type: INLINE_MENU_SHOW,
      pageOrigin: "https://example.com",
      candidates: [{ itemId: "item-1", title: "Example", username: "alice", needsWarning: false }],
    };
    expect(isInlineMenuShowMessage(message)).toBe(true);
  });

  it("refuses a candidate missing needsWarning", () => {
    const message = {
      type: INLINE_MENU_SHOW,
      pageOrigin: "https://example.com",
      candidates: [{ itemId: "item-1", title: "Example", username: "alice" }],
    };
    expect(isInlineMenuShowMessage(message)).toBe(false);
  });

  it("accepts zero candidates", () => {
    expect(isInlineMenuShowMessage({ type: INLINE_MENU_SHOW, pageOrigin: "https://example.com", candidates: [] })).toBe(
      true,
    );
  });

  it("refuses more than MAX_CANDIDATES", () => {
    const candidates = Array.from({ length: MAX_CANDIDATES + 1 }, (_, i) => ({
      itemId: `item-${i}`,
      title: "t",
      username: "u",
    }));
    expect(isInlineMenuShowMessage({ type: INLINE_MENU_SHOW, pageOrigin: "https://example.com", candidates })).toBe(
      false,
    );
  });

  it("refuses a malformed candidate", () => {
    const message = { type: INLINE_MENU_SHOW, pageOrigin: "https://example.com", candidates: [{ itemId: "x" }] };
    expect(isInlineMenuShowMessage(message)).toBe(false);
  });

  it("refuses the wrong type tag", () => {
    expect(isInlineMenuShowMessage({ type: "something_else", pageOrigin: "https://example.com", candidates: [] })).toBe(
      false,
    );
  });

  it("refuses a missing pageOrigin", () => {
    expect(isInlineMenuShowMessage({ type: INLINE_MENU_SHOW, candidates: [] })).toBe(false);
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
