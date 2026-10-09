// Messaging validation (ADR 0036 §4, INV-40): `parseFromContentScript` must accept every
// well-formed message this contract defines and refuse anything oversized or malshaped, before
// any shape-specific logic runs.
import { describe, expect, it } from "vitest";

import {
  MAX_FIELDS_PER_REPORT,
  MAX_MESSAGE_BYTES,
  MAX_URL_LEN,
  isApplyFillMessage,
  isInlineMenuFillRequestMessage,
  isInlineMenuGeneratePasswordRequestMessage,
  isRelayApplyFillMessage,
} from "../src/messaging/contract.ts";
import { MessageRejected, parseFromContentScript } from "../src/messaging/validate.ts";

describe("parseFromContentScript: accepts well-formed messages", () => {
  it("fields_detected with a password and a username field", () => {
    const message = {
      type: "fields_detected",
      pageUrl: "https://example.com/login",
      isTopFrame: true,
      fields: [
        { fieldId: "f1", kind: "username", visible: true, currentValue: "alice" },
        { fieldId: "f2", kind: "password", visible: true },
      ],
    };
    expect(parseFromContentScript(message)).toEqual(message);
  });

  it("save_prompt_resolved", () => {
    const message = { type: "save_prompt_resolved", token: "abc", action: "save" };
    expect(parseFromContentScript(message)).toEqual(message);
  });

  it("credentials_submitted with only a password value", () => {
    const message = {
      type: "credentials_submitted",
      pageUrl: "https://example.com/login",
      passwordValue: "s3cret",
    };
    expect(parseFromContentScript(message)).toEqual(message);
  });

  it("check_save_prompt", () => {
    const message = { type: "check_save_prompt", pageUrl: "https://example.com/dashboard" };
    expect(parseFromContentScript(message)).toEqual(message);
  });
});

describe("parseFromContentScript: refuses bad input", () => {
  it("an unknown type", () => {
    expect(() => parseFromContentScript({ type: "steal_vault" })).toThrow(MessageRejected);
  });

  it("not a plain object", () => {
    expect(() => parseFromContentScript("fields_detected")).toThrow(MessageRejected);
    expect(() => parseFromContentScript(null)).toThrow(MessageRejected);
    expect(() => parseFromContentScript(["fields_detected"])).toThrow(MessageRejected);
  });

  it("a cyclic object (not JSON-safe)", () => {
    const cyclic: Record<string, unknown> = { type: "fields_detected" };
    cyclic["self"] = cyclic;
    expect(() => parseFromContentScript(cyclic)).toThrow(MessageRejected);
  });

  it("a pageUrl over MAX_URL_LEN", () => {
    const message = {
      type: "fields_detected",
      pageUrl: `https://example.com/${"a".repeat(MAX_URL_LEN)}`,
      isTopFrame: true,
      fields: [],
    };
    expect(() => parseFromContentScript(message)).toThrow(MessageRejected);
  });

  it("more fields than MAX_FIELDS_PER_REPORT", () => {
    const fields = Array.from({ length: MAX_FIELDS_PER_REPORT + 1 }, (_, i) => ({
      fieldId: `f${i}`,
      kind: "other",
      visible: true,
    }));
    const message = { type: "fields_detected", pageUrl: "https://example.com", isTopFrame: true, fields };
    expect(() => parseFromContentScript(message)).toThrow(MessageRejected);
  });

  it("a password field reporting a currentValue (never allowed)", () => {
    const message = {
      type: "fields_detected",
      pageUrl: "https://example.com",
      isTopFrame: true,
      fields: [{ fieldId: "f1", kind: "password", visible: true, currentValue: "leaked" }],
    };
    expect(() => parseFromContentScript(message)).toThrow(MessageRejected);
  });

  it("a message over MAX_MESSAGE_BYTES overall", () => {
    const message = {
      type: "credentials_submitted",
      pageUrl: "https://example.com",
      usernameValue: "a".repeat(MAX_MESSAGE_BYTES),
    };
    expect(() => parseFromContentScript(message)).toThrow(MessageRejected);
  });

  it("save_prompt_resolved with an invalid action", () => {
    expect(() => parseFromContentScript({ type: "save_prompt_resolved", token: "abc", action: "nope" })).toThrow(
      MessageRejected,
    );
  });

  it("missing required fields", () => {
    expect(() => parseFromContentScript({ type: "fields_detected" })).toThrow(MessageRejected);
  });

  it("check_save_prompt missing pageUrl", () => {
    expect(() => parseFromContentScript({ type: "check_save_prompt" })).toThrow(MessageRejected);
  });

  it("check_save_prompt with a pageUrl over MAX_URL_LEN", () => {
    const message = { type: "check_save_prompt", pageUrl: `https://example.com/${"a".repeat(MAX_URL_LEN)}` };
    expect(() => parseFromContentScript(message)).toThrow(MessageRejected);
  });

  // ADR 0040, defence in depth: `inline_menu_fill_chosen` is not one of
  // `FromContentScript`'s own variants at all (deliberately — see `contract.ts`'s doc on it), so
  // even a content script that sends this type's exact shape gets the same "unknown type"
  // refusal as any other impersonation attempt. The privileged path
  // (`isInlineMenuFillRequestMessage`, exercised in `content-handler.test.ts`) is a completely
  // separate validator this function never calls.
  it("inline_menu_fill_chosen is not a content-script message at all", () => {
    const message = { type: "inline_menu_fill_chosen", itemId: "item-1", confirmedEquivalence: true };
    expect(() => parseFromContentScript(message)).toThrow(MessageRejected);
  });

  // Same ADR 0040 defence-in-depth rule, for the generator's privileged request (gap 32 in the
  // M2 gap audit): it must never be reachable through the content-script path either.
  it("inline_menu_generate_password_chosen is not a content-script message at all", () => {
    const message = { type: "inline_menu_generate_password_chosen" };
    expect(() => parseFromContentScript(message)).toThrow(MessageRejected);
  });
});

describe("isInlineMenuFillRequestMessage", () => {
  it("accepts a well-formed request", () => {
    expect(isInlineMenuFillRequestMessage({ type: "inline_menu_fill_chosen", itemId: "item-1", confirmedEquivalence: false })).toBe(
      true,
    );
  });

  it("rejects a missing confirmedEquivalence", () => {
    expect(isInlineMenuFillRequestMessage({ type: "inline_menu_fill_chosen", itemId: "item-1" })).toBe(false);
  });

  it("rejects an itemId over its own length budget", () => {
    expect(
      isInlineMenuFillRequestMessage({ type: "inline_menu_fill_chosen", itemId: "a".repeat(257), confirmedEquivalence: true }),
    ).toBe(false);
  });

  it("rejects a non-object", () => {
    expect(isInlineMenuFillRequestMessage(null)).toBe(false);
    expect(isInlineMenuFillRequestMessage("inline_menu_fill_chosen")).toBe(false);
  });
});

// Gap 32 in the M2 gap audit: the generator's own privileged request, same validator pattern as
// `isInlineMenuFillRequestMessage` above, but with no fields beyond `type` to bound.
describe("isInlineMenuGeneratePasswordRequestMessage", () => {
  it("accepts a well-formed request", () => {
    expect(isInlineMenuGeneratePasswordRequestMessage({ type: "inline_menu_generate_password_chosen" })).toBe(true);
  });

  it("rejects the wrong type tag", () => {
    expect(isInlineMenuGeneratePasswordRequestMessage({ type: "inline_menu_fill_chosen" })).toBe(false);
  });

  it("rejects a non-object", () => {
    expect(isInlineMenuGeneratePasswordRequestMessage(null)).toBe(false);
    expect(isInlineMenuGeneratePasswordRequestMessage("inline_menu_generate_password_chosen")).toBe(false);
  });
});

describe("isApplyFillMessage", () => {
  it("accepts a password-only fill", () => {
    expect(isApplyFillMessage({ type: "apply_fill", values: { password: "s3cret" } })).toBe(true);
  });

  it("accepts a username+password fill", () => {
    expect(isApplyFillMessage({ type: "apply_fill", values: { username: "alice", password: "s3cret" } })).toBe(true);
  });

  it("rejects a missing password", () => {
    expect(isApplyFillMessage({ type: "apply_fill", values: { username: "alice" } })).toBe(false);
  });

  it("rejects a missing values object", () => {
    expect(isApplyFillMessage({ type: "apply_fill" })).toBe(false);
  });
});

// `relay_apply_fill` (ADR 0040): the Chromium-only internal relay
// `core-host/content-handler.ts`'s `pushApplyFill` sends when `ext.tabs` is unavailable inside
// the offscreen document (a real, previously-shipping `TypeError` otherwise — see
// `README.md`'s "bugs found" list). `background/service-worker.ts` is the only thing that
// accepts it, and only from this extension's own non-tab sender; this validator only bounds the
// shape, same as every other message boundary.
describe("isRelayApplyFillMessage", () => {
  it("accepts a well-formed relay", () => {
    expect(isRelayApplyFillMessage({ type: "relay_apply_fill", tabId: 7, values: { password: "s3cret" } })).toBe(true);
  });

  it("accepts a username+password relay", () => {
    expect(
      isRelayApplyFillMessage({ type: "relay_apply_fill", tabId: 7, values: { username: "alice", password: "s3cret" } }),
    ).toBe(true);
  });

  it("rejects a non-numeric tabId", () => {
    expect(isRelayApplyFillMessage({ type: "relay_apply_fill", tabId: "7", values: { password: "s3cret" } })).toBe(false);
  });

  it("rejects a missing password", () => {
    expect(isRelayApplyFillMessage({ type: "relay_apply_fill", tabId: 7, values: { username: "alice" } })).toBe(false);
  });

  it("rejects a different message type (e.g. the public apply_fill shape)", () => {
    expect(isRelayApplyFillMessage({ type: "apply_fill", tabId: 7, values: { password: "s3cret" } })).toBe(false);
  });
});
