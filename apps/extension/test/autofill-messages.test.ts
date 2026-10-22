// SPDX-License-Identifier: AGPL-3.0-only

// ADR 0076 §4.1–§4.4 and §5.1–§5.3 at the message boundaries (INV-40): the scope, offer,
// fill-request, fill-values, captured-field and save-dialog validators refuse oversize input,
// bad and reserved tokens, duplicate tokens, a bad `totp`, unknown members and a bad `offerId`;
// the offer store's lifetime, single use, tab and URL binding and per-tab cap; the inline menu's
// disclosure text; and the save dialog's row wording.
import { describe, expect, it } from "vitest";

import { MAX_OFFERS_PER_TAB, OFFER_TTL_MS, createOfferStore } from "../src/core-host/offer-store.ts";
import { disclosureText } from "../src/inline-menu/disclosure.ts";
import {
  isFillScope,
  isFillValues,
  isInlineMenuFillRequestMessage,
  isInlineMenuOfferMessage,
  isInlineMenuOfferRequestMessage,
  isSaveDialogRequestMessage,
  isSaveDialogResolveMessage,
} from "../src/messaging/contract.ts";
import { MessageRejected, parseFromContentScript } from "../src/messaging/validate.ts";
import { dialogTitle, isSaveDialogShowMessage, rowText } from "../src/save-dialog/protocol.ts";

const TOKEN = "123e4567-e89b-42d3-a456-426614174000";
const OFFER = "0123456789abcdef0123456789abcdef";

describe("isFillScope", () => {
  it("accepts the ADR's shapes", () => {
    expect(isFillScope({})).toBe(true);
    expect(isFillScope({ only: "totp" })).toBe(true);
    expect(isFillScope({ only: "password", totp: true, custom: ["a", "b"], passwordToken: "a" })).toBe(true);
  });
  it.each([
    ["unknown member", { evil: 1 }],
    ["bad only", { only: "custom" }],
    ["totp with only totp", { only: "totp", totp: true }],
    ["totp not true", { totp: false }],
    ["empty custom", { custom: [] }],
    ["reserved token", { custom: ["username"] }],
    ["bad token", { custom: ["Member"] }],
    ["section token", { custom: ["section-a"] }],
    ["duplicate tokens", { custom: ["a", "a"] }],
    ["17 tokens", { custom: Array.from({ length: 17 }, (_, i) => "t" + String(i)) }],
    ["role token not in custom", { custom: ["a"], usernameToken: "b" }],
    ["array", []],
    ["null", null],
  ])("refuses %s", (_, scope) => {
    expect(isFillScope(scope)).toBe(false);
  });
});

describe("isInlineMenuOfferRequestMessage / isInlineMenuOfferMessage", () => {
  it("bounds the request", () => {
    expect(isInlineMenuOfferRequestMessage({ type: "inline_menu_offer_request", instanceToken: TOKEN, scope: {} })).toBe(true);
    expect(isInlineMenuOfferRequestMessage({ type: "inline_menu_offer_request", instanceToken: "x", scope: {} })).toBe(false);
    expect(isInlineMenuOfferRequestMessage({ type: "inline_menu_offer_request", instanceToken: TOKEN, scope: { custom: ["totp"] } })).toBe(false);
    expect(isInlineMenuOfferRequestMessage({ type: "inline_menu_offer_request", instanceToken: TOKEN, scope: {}, extra: 1 })).toBe(false);
  });
  it("bounds the offer", () => {
    const ok = { type: "inline_menu_offer", offerId: OFFER, pageHost: "example.com", candidates: [{ itemId: "i", fillsTotp: true, customFill: [{ label: "PIN", concealed: true }] }] };
    expect(isInlineMenuOfferMessage(ok)).toBe(true);
    expect(isInlineMenuOfferMessage({ ...ok, offerId: OFFER.toUpperCase() })).toBe(false);
    expect(isInlineMenuOfferMessage({ ...ok, offerId: OFFER.slice(1) })).toBe(false);
    expect(
      isInlineMenuOfferMessage({ ...ok, candidates: [{ itemId: "i", fillsTotp: false, customFill: [{ label: "x".repeat(257), concealed: false }] }] }),
    ).toBe(false);
    expect(
      isInlineMenuOfferMessage({
        ...ok,
        candidates: [{ itemId: "i", fillsTotp: false, customFill: Array.from({ length: 17 }, () => ({ label: "a", concealed: false })) }],
      }),
    ).toBe(false);
  });
});

describe("isInlineMenuFillRequestMessage (ADR 0076 §4.2)", () => {
  const base = { type: "inline_menu_fill_chosen", instanceToken: TOKEN, itemId: "i", confirmedEquivalence: false };
  it("takes an offerId and only: totp with it", () => {
    expect(isInlineMenuFillRequestMessage({ ...base, offerId: OFFER, only: "totp" })).toBe(true);
    expect(isInlineMenuFillRequestMessage({ ...base, only: "password" })).toBe(true);
  });
  it("refuses a TOTP-only fill without an offer, a bad offerId and unknown members", () => {
    expect(isInlineMenuFillRequestMessage({ ...base, only: "totp" })).toBe(false);
    expect(isInlineMenuFillRequestMessage({ ...base, offerId: "nothex" })).toBe(false);
    expect(isInlineMenuFillRequestMessage({ ...base, custom: [{ token: "a", value: "b" }] })).toBe(false);
  });
});

describe("isFillValues (INV-40, ADR 0076 §4.4)", () => {
  it("accepts each member alone and together", () => {
    expect(isFillValues({ username: "u" })).toBe(true);
    expect(isFillValues({ totp: "123456" })).toBe(true);
    expect(isFillValues({ totp: "12345678" })).toBe(true);
    expect(isFillValues({ custom: [{ token: "member", value: "M-1" }] })).toBe(true);
    expect(isFillValues({ username: "u", password: "p", totp: "1234567", custom: [{ token: "a", value: "" }] })).toBe(true);
  });
  it.each([
    ["nothing", {}],
    ["a 5-digit code", { totp: "12345" }],
    ["a 9-digit code", { totp: "123456789" }],
    ["a non-digit code", { totp: "12345a" }],
    ["unknown member", { password: "p", fieldId: "f1" }],
    ["empty custom", { custom: [] }],
    ["reserved custom token", { custom: [{ token: "password", value: "x" }] }],
    ["bad custom token", { custom: [{ token: "A B", value: "x" }] }],
    ["duplicate custom tokens", { custom: [{ token: "a", value: "x" }, { token: "a", value: "y" }] }],
    ["a custom entry with more", { custom: [{ token: "a", value: "x", element: "e" }] }],
    ["17 custom entries", { custom: Array.from({ length: 17 }, (_, i) => ({ token: "t" + String(i), value: "v" })) }],
    ["oversize custom value", { custom: [{ token: "a", value: "x".repeat(4097) }] }],
    ["oversize password", { password: "x".repeat(4097) }],
    ["oversize message", { custom: Array.from({ length: 16 }, (_, i) => ({ token: "t" + String(i), value: "x".repeat(4096) })) }],
  ])("refuses %s", (_, values) => {
    expect(isFillValues(values)).toBe(false);
  });
});

describe("captured custom fields (ADR 0076 §5.1)", () => {
  const submit = (customFields: unknown) =>
    parseFromContentScript({ type: "credentials_submitted", pageUrl: "https://example.com/login", passwordValue: "p", customFields });
  it("accepts up to 8 valid entries", () => {
    const fields = Array.from({ length: 8 }, (_, i) => ({ token: "t" + String(i), value: "v", masked: i % 2 === 0 }));
    expect(submit(fields)).toMatchObject({ customFields: fields });
  });
  it.each([
    ["9 entries", Array.from({ length: 9 }, (_, i) => ({ token: "t" + String(i), value: "v", masked: false }))],
    ["a reserved token", [{ token: "one-time-code", value: "1", masked: false }]],
    ["an empty value", [{ token: "a", value: "", masked: false }]],
    ["an oversize value", [{ token: "a", value: "x".repeat(4097), masked: false }]],
    ["a duplicate token", [{ token: "a", value: "1", masked: false }, { token: "a", value: "2", masked: false }]],
    ["an extra member", [{ token: "a", value: "1", masked: false, type: "hidden" }]],
    ["no masked flag", [{ token: "a", value: "1" }]],
  ])("refuses %s", (_, fields) => {
    expect(() => submit(fields)).toThrow(MessageRejected);
  });
});

describe("save dialog messages (ADR 0076 §5.2–§5.3)", () => {
  it("bounds the request and the answer", () => {
    expect(isSaveDialogRequestMessage({ type: "save_dialog_request", instanceToken: TOKEN, token: "t" })).toBe(true);
    expect(isSaveDialogRequestMessage({ type: "save_dialog_request", instanceToken: "x", token: "t" })).toBe(false);
    const resolve = { type: "save_dialog_resolve", instanceToken: TOKEN, token: "t", action: "save", rows: [{ index: 0, label: "Member" }] };
    expect(isSaveDialogResolveMessage(resolve)).toBe(true);
    expect(isSaveDialogResolveMessage({ ...resolve, action: "steal" })).toBe(false);
    expect(isSaveDialogResolveMessage({ ...resolve, rows: [{ index: 8, label: "a" }] })).toBe(false);
    expect(isSaveDialogResolveMessage({ ...resolve, rows: [{ index: 0, label: "a" }, { index: 0, label: "b" }] })).toBe(false);
    expect(isSaveDialogResolveMessage({ ...resolve, rows: [{ index: 0, label: "x".repeat(257) }] })).toBe(false);
    expect(isSaveDialogResolveMessage({ ...resolve, rows: [{ index: 0, label: "a", value: "planted" }] })).toBe(false);
    expect(isSaveDialogShowMessage({ type: "rizzy-save-dialog-show", pageOrigin: "https://a", instanceToken: TOKEN, token: "t" })).toBe(true);
    expect(isSaveDialogShowMessage({ type: "rizzy-save-dialog-show", pageOrigin: "https://a", instanceToken: "x", token: "t" })).toBe(false);
  });
  it("words the rows as the ADR does", () => {
    expect(rowText("add", "member", false)).toBe("Add custom field");
    expect(rowText("add", "pin", true)).toBe("Add custom field (hidden)");
    expect(rowText("update", "Member no.", false)).toBe("Update Member no.");
    expect(dialogTitle("save", undefined)).toBe("Save this login to rizzy-vault?");
    expect(dialogTitle("update", "Example")).toBe("Update “Example” in rizzy-vault?");
  });
});

describe("the inline menu's disclosure (ADR 0076 §4.1 step 4)", () => {
  it("lists the code and every Display Name, with (hidden)", () => {
    expect(disclosureText(undefined)).toBe("");
    expect(disclosureText({ itemId: "i", fillsTotp: false, customFill: [] })).toBe("");
    expect(
      disclosureText({ itemId: "i", fillsTotp: true, customFill: [{ label: "Member no.", concealed: false }, { label: "PIN", concealed: true }] }),
    ).toBe("Also fills: one-time code · Member no. · PIN (hidden)");
  });
});

describe("the offer store (ADR 0076 §4.1–§4.2)", () => {
  const make = () => {
    let t = 1_000;
    let n = 0;
    const store = createOfferStore(
      (out) => {
        out.fill(0);
        out[15] = n;
        n += 1;
      },
      () => t,
    );
    const items = new Map([["item", { fillsTotp: true, custom: [] }]]);
    return { store, items, advance: (ms: number) => (t += ms) };
  };
  it("mints 32-hex ids and is used once", () => {
    const { store, items } = make();
    const id = store.create({ tabId: 1, pageUrl: "https://a/", scope: { only: "totp" }, items });
    expect(id).toMatch(/^[0-9a-f]{32}$/);
    expect(typeof store.take(id, 1, "https://a/", "item", "totp")).toBe("object");
    expect(store.take(id, 1, "https://a/", "item", "totp")).toBe("missing");
  });
  it("refuses an expired, other-tab, navigated, unoffered or only-mismatched offer, and uses it up", () => {
    const { store, items, advance } = make();
    const old = store.create({ tabId: 1, pageUrl: "https://a/", scope: {}, items });
    advance(OFFER_TTL_MS + 1);
    expect(store.take(old, 1, "https://a/", "item", undefined)).toBe("expired");
    expect(store.take(old, 1, "https://a/", "item", undefined)).toBe("missing");
    const fresh = () => store.create({ tabId: 1, pageUrl: "https://a/", scope: { only: "password" }, items });
    expect(store.take(fresh(), 2, "https://a/", "item", "password")).toBe("other_tab");
    expect(store.take(fresh(), 1, "https://a/next", "item", "password")).toBe("navigated");
    expect(store.take(fresh(), 1, "https://a/", "other", "password")).toBe("not_offered");
    expect(store.take(fresh(), 1, "https://a/", "item", undefined)).toBe("only_mismatch");
    const used = fresh();
    store.take(used, 2, "https://a/", "item", "password");
    expect(store.take(used, 1, "https://a/", "item", "password")).toBe("missing");
  });
  it("holds at most 4 offers per tab and drops everything on clear", () => {
    const { store, items } = make();
    const ids = Array.from({ length: MAX_OFFERS_PER_TAB + 1 }, () => store.create({ tabId: 7, pageUrl: "https://a/", scope: {}, items }));
    store.create({ tabId: 8, pageUrl: "https://a/", scope: {}, items });
    expect(store.size()).toBe(MAX_OFFERS_PER_TAB + 1);
    expect(store.take(ids[0] ?? "", 7, "https://a/", "item", undefined)).toBe("missing");
    store.clear();
    expect(store.size()).toBe(0);
  });
});
