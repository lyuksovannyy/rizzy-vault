// SPDX-License-Identifier: AGPL-3.0-only

// ADR 0076 §1 in Node: the `autocomplete` parser (§1.1), the role table (§1.2), the strict TOTP
// heuristic (§1.3) against an HTML fixture for every negative case of §1.4
// (`test/fixtures/totp/`), the step's fill scope (§4.1), hostile renaming (THREAT_MODEL A7:
// a page that relabels its inputs to harvest custom fields gets nothing but exact, valid,
// unreserved tokens into the scope), and the reserved set's parity with `rizzy-core`.
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { RESERVED_AUTOCOMPLETE_IDS, isCustomToken, parseAutocomplete } from "../src/messaging/autocomplete.ts";
import {
  NO_FORM,
  detectLoginStep,
  identifierSignal,
  isPasswordTarget,
  menuAllowed,
  stepScope,
  type InputFacts,
} from "../src/content/login-step.ts";
import { factsFromHtml } from "./support/html-facts.ts";

const FIXTURES = fileURLToPath(new URL("./fixtures/totp/", import.meta.url));

function rustReserved(): string[] {
  const source = readFileSync(new URL("../../../crates/rizzy-core/src/item/autocomplete.rs", import.meta.url), "utf8");
  const start = source.indexOf("pub const RESERVED_AUTOCOMPLETE_IDS");
  const end = source.indexOf("];", start);
  return [...source.slice(start, end).matchAll(/"([^"]+)"/g)].map((m) => m[1] ?? "");
}

function facts(more: Partial<InputFacts>): InputFacts {
  return { type: "text", autocomplete: "", hints: "", visible: true, editable: true, form: 0, ...more };
}

describe("the reserved set", () => {
  it("is rizzy-core's, in order", () => {
    expect(rustReserved()).toHaveLength(70);
    expect(RESERVED_AUTOCOMPLETE_IDS).toEqual(rustReserved());
  });
});

describe("parseAutocomplete (ADR 0076 §1.1)", () => {
  it.each([
    [null, { kind: "none", webauthn: false }],
    ["", { kind: "none", webauthn: false }],
    ["   ", { kind: "none", webauthn: false }],
    ["on", { kind: "none", webauthn: false }],
    ["ON", { kind: "none", webauthn: false }],
    ["off", { kind: "off", webauthn: false }],
    ["Off", { kind: "off", webauthn: false }],
    ["username", { kind: "standard", field: "username", webauthn: false }],
    ["username webauthn", { kind: "standard", field: "username", webauthn: true }],
    ["current-password webauthn", { kind: "standard", field: "current-password", webauthn: true }],
    ["webauthn", { kind: "none", webauthn: true }],
    ["section-login username", { kind: "standard", field: "username", webauthn: false }],
    ["section-a shipping postal-code", { kind: "standard", field: "postal-code", webauthn: false }],
    ["billing cc-number", { kind: "standard", field: "cc-number", webauthn: false }],
    ["shipping work email", { kind: "standard", field: "email", webauthn: false }],
    ["home tel", { kind: "standard", field: "tel", webauthn: false }],
    ["mobile tel-national", { kind: "standard", field: "tel-national", webauthn: false }],
    ["work username", { kind: "none", webauthn: false }],
    ["one-time-code", { kind: "standard", field: "one-time-code", webauthn: false }],
    ["ONE-TIME-CODE", { kind: "standard", field: "one-time-code", webauthn: false }],
    ["custominput", { kind: "custom", token: "custominput", webauthn: false }],
    ["Member-No", { kind: "custom", token: "member-no", webauthn: false }],
    ["nope", { kind: "custom", token: "nope", webauthn: false }],
    ["false", { kind: "custom", token: "false", webauthn: false }],
    ["custominput webauthn", { kind: "none", webauthn: true }],
    ["custom input", { kind: "none", webauthn: false }],
    ["totp", { kind: "none", webauthn: false }],
    ["password", { kind: "none", webauthn: false }],
    ["section-x", { kind: "none", webauthn: false }],
    ["home", { kind: "none", webauthn: false }],
    ["shipping", { kind: "none", webauthn: false }],
    ["caf\u00e9", { kind: "none", webauthn: false }],
    ["a/b", { kind: "none", webauthn: false }],
    ["a b c d e f g h i", { kind: "none", webauthn: false }],
    ["x".repeat(65), { kind: "none", webauthn: false }],
    ["x".repeat(257), { kind: "none", webauthn: false }],
  ])("%j", (attribute, expected) => {
    expect(parseAutocomplete(attribute)).toEqual(expected);
  });

  it("only valid, unreserved tokens are custom", () => {
    for (const reserved of RESERVED_AUTOCOMPLETE_IDS) {
      expect(isCustomToken(reserved)).toBe(false);
      expect(parseAutocomplete(reserved).kind).not.toBe("custom");
    }
    expect(isCustomToken("a".repeat(64))).toBe(true);
    expect(isCustomToken("a".repeat(65))).toBe(false);
    expect(isCustomToken("Member")).toBe(false);
    expect(isCustomToken("")).toBe(false);
    expect(isCustomToken(7)).toBe(false);
  });
});

describe("roles (ADR 0076 §1.2)", () => {
  it("username or webauthn is a strong identifier; email and tel stay weak; other names have no role", () => {
    expect(identifierSignal(facts({ autocomplete: "username" }))).toBe(2);
    expect(identifierSignal(facts({ autocomplete: "webauthn" }))).toBe(2);
    expect(identifierSignal(facts({ autocomplete: "section-a username" }))).toBe(2);
    expect(identifierSignal(facts({ autocomplete: "email", type: "email" }))).toBe(1);
    expect(identifierSignal(facts({ autocomplete: "given-name", hints: "user" }))).toBeUndefined();
    expect(identifierSignal(facts({ autocomplete: "cc-name", hints: "login" }))).toBeUndefined();
    expect(identifierSignal(facts({ autocomplete: "one-time-code" }))).toBeUndefined();
    // Absent, off and custom keep the heuristics.
    expect(identifierSignal(facts({ autocomplete: "off", hints: "username" }))).toBe(1);
    expect(identifierSignal(facts({ autocomplete: "nope", hints: "login" }))).toBe(1);
  });

  it("only current-password or no declared name makes a password target", () => {
    const pw = (autocomplete: string) => isPasswordTarget(facts({ type: "password", autocomplete }));
    expect(pw("")).toBe(true);
    expect(pw("off")).toBe(true);
    expect(pw("current-password")).toBe(true);
    expect(pw("nope")).toBe(true);
    expect(pw("new-password")).toBe(false);
    expect(pw("one-time-code")).toBe(false);
    expect(pw("cc-csc")).toBe(false);
  });

  it("a new-password field alone is a generator-only step, never a saved-password target", () => {
    const step = detectLoginStep([facts({ type: "password", autocomplete: "new-password" })], () => "");
    expect(step).toEqual({ kind: "new_password", password: 0 });
    expect(stepScope([facts({ type: "password", autocomplete: "new-password" })], step!)).toEqual({ only: "password" });
  });
});

/** The TOTP target of a fixture (its element id) and the step kind. */
function totpOf(name: string): { kind: string | undefined; totp: string | undefined } {
  const { inputs, ids, formHint } = factsFromHtml(readFileSync(FIXTURES + name, "utf8"));
  const step = detectLoginStep(inputs, formHint);
  return { kind: step?.kind, totp: step !== undefined && "totp" in step && step.totp !== undefined ? ids[step.totp] : undefined };
}

const EXPECTED: Readonly<Record<string, { kind: string | undefined; totp: string | undefined }>> = {
  "p-one-time-code.html": { kind: "totp", totp: "code" },
  "p-heuristic.html": { kind: "totp", totp: "otp" },
  "p-heuristic-off.html": { kind: "totp", totp: "totp" },
  "p-password-and-totp.html": { kind: "username_and_password", totp: "totp" },
  "p-one-time-code-password.html": { kind: "totp", totp: "code" },
  "n01-card-csc.html": { kind: undefined, totp: undefined },
  "n02-card-number.html": { kind: undefined, totp: undefined },
  "n03-sms.html": { kind: undefined, totp: undefined },
  "n04-email-code.html": { kind: undefined, totp: undefined },
  // The password-type PIN is a password step's field (as before); no TOTP is offered.
  "n05-pin.html": { kind: "password", totp: undefined },
  "n06-postal.html": { kind: undefined, totp: undefined },
  "n07-phone.html": { kind: undefined, totp: undefined },
  "n08-codes.html": { kind: undefined, totp: undefined },
  "n09-backup.html": { kind: undefined, totp: undefined },
  "n10-split-digits.html": { kind: undefined, totp: undefined },
  "n11-code-only.html": { kind: undefined, totp: undefined },
  "n12-signup-checkout-contact.html": { kind: "new_password", totp: undefined },
  "n13-hidden.html": { kind: undefined, totp: undefined },
  "n15-custom-token.html": { kind: undefined, totp: undefined },
};

describe("the TOTP heuristic (ADR 0076 §1.3) over the §1.4 fixtures", () => {
  it("has an expectation for every fixture", () => {
    expect(readdirSync(FIXTURES).sort()).toEqual(Object.keys(EXPECTED).sort());
  });
  it.each(Object.entries(EXPECTED))("%s", (name, expected) => {
    expect(totpOf(name)).toEqual(expected);
  });

  it("rule (d): a maxlength outside 6–8 rules a field out; a minlength or inputmode can say numeric", () => {
    const one = (more: Partial<InputFacts>) => detectLoginStep([facts({ hints: "otp", ...more })], () => "")?.kind;
    expect(one({ inputMode: "numeric" })).toBe("totp");
    expect(one({ minLength: 6 })).toBe("totp");
    expect(one({ maxLength: 8 })).toBe("totp");
    expect(one({ maxLength: 9, inputMode: "numeric" })).toBeUndefined();
    expect(one({ maxLength: 5, type: "tel" })).toBeUndefined();
    expect(one({})).toBeUndefined();
    expect(one({ type: "number" })).toBe("totp");
    expect(one({ type: "email", inputMode: "numeric" })).toBeUndefined();
  });

  it("rule (e): two qualifying fields in one form, or among the form-less, offer nothing", () => {
    const two = [facts({ hints: "otp", inputMode: "numeric", form: NO_FORM }), facts({ hints: "totp", inputMode: "numeric", form: NO_FORM })];
    expect(detectLoginStep(two, () => "")).toBeUndefined();
  });

  it("negative case 14: no candidate with a time-based secret, no TOTP-only menu (rule (g))", () => {
    expect(menuAllowed("totp", [{ hasTotp: false }, { hasTotp: false }])).toBe(false);
    expect(menuAllowed("totp", [])).toBe(false);
    expect(menuAllowed("totp", [{ hasTotp: false }, { hasTotp: true }])).toBe(true);
    // Other steps are unaffected (the generator needs no candidate).
    expect(menuAllowed("password", [])).toBe(true);
  });
});

describe("the fill scope (ADR 0076 §4.1)", () => {
  const page = (html: string) => {
    const { inputs, formHint } = factsFromHtml(html);
    const step = detectLoginStep(inputs, formHint);
    return step === undefined ? undefined : stepScope(inputs, step);
  };

  it("carries distinct custom tokens of the step's form in document order, and the role targets' tokens", () => {
    expect(
      page(`<form action="/login">
        <input id="u" name="user" autocomplete="member-id" />
        <input id="p" type="password" name="password" />
        <input id="b" name="branch" autocomplete="Branch" />
        <input id="b2" name="branch2" autocomplete="branch" />
        <input id="h" name="hidden" autocomplete="secret-x" style="display:none" />
        <input id="r" name="ro" autocomplete="ro-x" readonly />
      </form>
      <form action="/other"><input id="o" autocomplete="other-form" /></form>`),
    ).toEqual({ custom: ["member-id", "branch"], usernameToken: "member-id" });
  });

  it("caps the tokens at 16 and adds the TOTP flag to a password step with a code field", () => {
    const fields = Array.from({ length: 20 }, (_, i) => `<input name="f${i}" autocomplete="tok${i}" />`).join("");
    const scope = page(`<form action="/login"><input type="password" name="password" />${fields}<input name="otp" inputmode="numeric" maxlength="6" /></form>`);
    expect(scope?.only).toBe("password");
    expect(scope?.custom).toHaveLength(16);
    expect(scope?.totp).toBe(true);
  });

  it("hostile renaming (A7): reserved names, standard names, junk with spaces and uppercase-only variants never become other tokens", () => {
    const scope = page(`<form action="/login">
      <input type="password" name="password" autocomplete="nope" />
      <input name="a" autocomplete="username" />
      <input name="b" autocomplete="cc-number" />
      <input name="c" autocomplete="section-x member" />
      <input name="d" autocomplete="member webauthn" />
      <input name="e" autocomplete="Totp" />
      <input name="f" autocomplete="MEMBER" />
      <input name="g" autocomplete="member*" />
      <input type="hidden" name="h" autocomplete="api-key" />
    </form>`);
    // Only exact, valid, unreserved tokens: "nope" (the password target's own) and "member"
    // (uppercase on the page, ASCII-lowercased like the WHATWG attribute).
    expect(scope).toEqual({ only: "password", custom: ["nope", "member"], passwordToken: "nope" });
  });
});
