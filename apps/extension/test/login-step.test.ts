// SPDX-License-Identifier: AGPL-3.0-only

// `login-step.ts`'s heuristic against the HTML fixtures in `test/fixtures/login-steps/`
// (ROADMAP §4.4 M3 "Heuristic multi-step login form support"): which step each page is on, and
// which field(s) that step may fill. Hostile fixtures (hidden, off-screen and covered username
// decoys; a password in a cross-origin iframe; stray text fields outside a form) check that the
// heuristic never chooses a field the visibility and topmost gates (THREAT_MODEL A7, INV-37) or
// the top-frame-only rule (ADR 0037 §5) rule out. The same fixtures run in real Chromium in
// `e2e/multistep.spec.ts`.
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { NO_FORM, detectLoginStep, identifierSignal, stepFillScope, type InputFacts, type LoginStep } from "../src/content/login-step.ts";
import { factsFromHtml } from "./support/html-facts.ts";

const FIXTURES = fileURLToPath(new URL("./fixtures/login-steps/", import.meta.url));

/** The step a fixture is on, with field indexes mapped back to the fixture's own element ids. */
function stepOf(name: string): { kind: LoginStep["kind"]; username?: string; password?: string } | undefined {
  const { inputs, ids, formHint } = factsFromHtml(readFileSync(FIXTURES + name, "utf8"));
  const step = detectLoginStep(inputs, formHint);
  if (step === undefined) {
    return undefined;
  }
  return {
    kind: step.kind,
    ...("username" in step ? { username: ids[step.username] } : {}),
    ...("password" in step ? { password: ids[step.password] } : {}),
  };
}

const EXPECTED: Readonly<Record<string, ReturnType<typeof stepOf>>> = {
  "one-page.html": { kind: "username_and_password", username: "user", password: "pass" },
  "identifier-first.html": { kind: "username", username: "user" },
  "identifier-weak.html": { kind: "username", username: "user" },
  "password-step.html": { kind: "password", password: "pass" },
  "password-step-readonly-user.html": { kind: "password", password: "pass" },
  "same-page-reveal.html": { kind: "username", username: "user" },
  "hidden-username-decoys.html": { kind: "username", username: "user" },
  "password-with-hidden-username-decoy.html": { kind: "password", password: "pass" },
  "covered-username.html": { kind: "password", password: "pass" },
  "cross-origin-iframe-password.html": { kind: "username", username: "user" },
  "iframe-password.html": { kind: "password", password: "pass" },
  "password-no-form.html": { kind: "password", password: "pass" },
  "search-box.html": undefined,
  "newsletter.html": undefined,
  "signup-email.html": undefined,
  "contact-form.html": undefined,
  // ADR 0076 §1.2: a `one-time-code` field is the TOTP target of a TOTP-only step.
  "one-time-code.html": { kind: "totp" },
  "webauthn-identifier.html": { kind: "username", username: "user" },
  "disabled-password.html": { kind: "username", username: "user" },
};

describe("detectLoginStep over the HTML fixtures", () => {
  it("has an expectation for every fixture file, and a file for every expectation", () => {
    const files = readdirSync(FIXTURES).filter((f) => f.endsWith(".html")).sort();
    expect(files).toEqual(Object.keys(EXPECTED).sort());
  });

  for (const [name, expected] of Object.entries(EXPECTED)) {
    it(`${name} → ${expected === undefined ? "no step" : expected.kind}`, () => {
      expect(stepOf(name)).toEqual(expected);
    });
  }

  it("is deterministic: the same facts always give the same step", () => {
    for (const name of Object.keys(EXPECTED)) {
      expect(stepOf(name)).toEqual(stepOf(name));
    }
  });
});

describe("the fixture reader sees what the content script would", () => {
  it("never reads a field inside an iframe (top frame only)", () => {
    const { ids } = factsFromHtml(readFileSync(FIXTURES + "cross-origin-iframe-password.html", "utf8"));
    expect(ids).toEqual(["user"]);
  });

  it("marks hidden, off-screen, zero-size, transparent and covered fields invisible", () => {
    const invisible: Readonly<Record<string, readonly string[]>> = {
      "hidden-username-decoys.html": ["offscreen-decoy", "hidden-decoy"],
      "password-with-hidden-username-decoy.html": ["opacity-decoy", "zero-decoy"],
      "covered-username.html": ["user"],
      "password-step.html": ["hidden-user"],
      "same-page-reveal.html": ["pass"],
    };
    for (const [name, hidden] of Object.entries(invisible)) {
      const { inputs, ids } = factsFromHtml(readFileSync(FIXTURES + name, "utf8"));
      const notVisible = ids.filter((_, i) => inputs[i]?.visible === false);
      expect(notVisible, name).toEqual(hidden);
    }
  });
});

function facts(overrides: Partial<InputFacts>): InputFacts {
  return { type: "text", autocomplete: "", hints: "", visible: true, editable: true, form: 0, ...overrides };
}

describe("detectLoginStep rules", () => {
  const signIn = () => "next";

  it("pairs the closest preceding signalled identifier of the same form, not the first text field", () => {
    const inputs = [
      facts({ hints: "nickname", form: 0 }),
      facts({ autocomplete: "username", form: 0 }),
      facts({ type: "password", form: 0 }),
    ];
    expect(detectLoginStep(inputs, signIn)).toEqual({ kind: "username_and_password", username: 1, password: 2 });
  });

  it("never pairs a username from a different form with the password", () => {
    const inputs = [facts({ autocomplete: "username", form: 0 }), facts({ type: "password", form: 1 })];
    expect(detectLoginStep(inputs, signIn)).toEqual({ kind: "password", password: 1 });
  });

  it("never pairs a field that comes after the password", () => {
    const inputs = [facts({ type: "password", form: 0 }), facts({ autocomplete: "username", form: 0 })];
    expect(detectLoginStep(inputs, signIn)).toEqual({ kind: "password", password: 0 });
  });

  it("inside a form, falls back to the plain text field just before the password", () => {
    const inputs = [facts({ form: 0 }), facts({ type: "password", form: 0 })];
    expect(detectLoginStep(inputs, signIn)).toEqual({ kind: "username_and_password", username: 0, password: 1 });
  });

  it("outside any form, never pairs an unsignalled text field", () => {
    const inputs = [facts({ form: NO_FORM }), facts({ type: "password", form: NO_FORM })];
    expect(detectLoginStep(inputs, signIn)).toEqual({ kind: "password", password: 1 });
  });

  it("a hidden or read-only password field is not a password step", () => {
    for (const pw of [facts({ type: "password", visible: false }), facts({ type: "password", editable: false })]) {
      expect(detectLoginStep([pw], signIn)).toBeUndefined();
    }
  });

  it("a weak identifier needs a sign-in form; a strong one does not", () => {
    expect(detectLoginStep([facts({ type: "email" })], () => "")).toBeUndefined();
    expect(detectLoginStep([facts({ type: "email" })], () => "continue")).toEqual({ kind: "username", username: 0 });
    expect(detectLoginStep([facts({ autocomplete: "username" })], () => "")).toEqual({ kind: "username", username: 0 });
  });

  it("a concealed password in the same form is sign-in context for a weak identifier", () => {
    const inputs = [facts({ hints: "email" }), facts({ type: "password", visible: false })];
    expect(detectLoginStep(inputs, () => "")).toEqual({ kind: "username", username: 0 });
  });

  it("a sign-up or newsletter hint outweighs a sign-in hint for a weak identifier", () => {
    expect(detectLoginStep([facts({ type: "email" })], () => "continue sign up")).toBeUndefined();
    expect(detectLoginStep([facts({ type: "email" })], () => "next subscribe")).toBeUndefined();
  });

  it("prefers a strong identifier over an earlier weak one", () => {
    const inputs = [facts({ type: "email", form: 0 }), facts({ autocomplete: "username", form: 1 })];
    expect(detectLoginStep(inputs, signIn)).toEqual({ kind: "username", username: 1 });
  });

  it("ignores invisible and non-editable identifiers, whatever their signal", () => {
    expect(detectLoginStep([facts({ autocomplete: "username", visible: false })], signIn)).toBeUndefined();
    expect(detectLoginStep([facts({ autocomplete: "username", editable: false })], signIn)).toBeUndefined();
  });
});

describe("identifierSignal", () => {
  it("is strong for autocomplete username or webauthn", () => {
    expect(identifierSignal(facts({ autocomplete: "username" }))).toBe(2);
    expect(identifierSignal(facts({ autocomplete: "section-a username webauthn" }))).toBe(2);
    expect(identifierSignal(facts({ type: "tel", autocomplete: "username" }))).toBe(2);
  });

  it("is weak for email-shaped or identifier-named fields", () => {
    expect(identifierSignal(facts({ autocomplete: "email" }))).toBe(1);
    expect(identifierSignal(facts({ type: "email" }))).toBe(1);
    expect(identifierSignal(facts({ hints: "loginfmt" }))).toBe(1);
  });

  it("rules out codes, searches, password-named text fields and non-text types", () => {
    expect(identifierSignal(facts({ autocomplete: "one-time-code" }))).toBeUndefined();
    expect(identifierSignal(facts({ hints: "q search" }))).toBeUndefined();
    expect(identifierSignal(facts({ hints: "password" }))).toBeUndefined();
    expect(identifierSignal(facts({ autocomplete: "current-password" }))).toBeUndefined();
    expect(identifierSignal(facts({ type: "search" }))).toBeUndefined();
    expect(identifierSignal(facts({ type: "checkbox" }))).toBeUndefined();
    expect(identifierSignal(facts({ type: "tel", hints: "phone" }))).toBeUndefined();
  });
});

describe("stepFillScope", () => {
  it("fills both on a one-page form and only the step's own field otherwise", () => {
    expect(stepFillScope({ kind: "username_and_password", username: 0, password: 1 })).toBeUndefined();
    expect(stepFillScope({ kind: "username", username: 0 })).toBe("username");
    expect(stepFillScope({ kind: "password", password: 0 })).toBe("password");
  });
});
