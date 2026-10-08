// Messaging validation (ADR 0036 §4, INV-40): `parseFromContentScript` must accept every
// well-formed message this contract defines and refuse anything oversized or malshaped, before
// any shape-specific logic runs.
import { describe, expect, it } from "vitest";

import { MAX_FIELDS_PER_REPORT, MAX_MESSAGE_BYTES, MAX_URL_LEN } from "../src/messaging/contract.ts";
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

  it("fill_chosen", () => {
    const message = {
      type: "fill_chosen",
      pageUrl: "https://example.com/login",
      isTopFrame: true,
      itemId: "item-1",
      fieldIds: ["f1", "f2"],
    };
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

  it("fill_chosen with an empty fieldIds array", () => {
    const message = {
      type: "fill_chosen",
      pageUrl: "https://example.com",
      isTopFrame: true,
      itemId: "item-1",
      fieldIds: [],
    };
    expect(() => parseFromContentScript(message)).toThrow(MessageRejected);
  });

  it("missing required fields", () => {
    expect(() => parseFromContentScript({ type: "fill_chosen" })).toThrow(MessageRejected);
  });
});
