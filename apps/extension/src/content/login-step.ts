// SPDX-License-Identifier: AGPL-3.0-only

// Login-step detection for the content script (ROADMAP §4.4 M3 row "Heuristic multi-step login
// form support"; ADR 0014 §2: the content script "detects login fields"). Decides, for one
// document snapshot, which login step the page is on and which of its fields that step fills:
//
// - `username_and_password`: the classic one-page form. The inline menu fills both.
// - `username`: an identifier-first step (a username or email field with no visible password
//   field yet: the password is on the next page, or the page reveals it later). The inline menu
//   fills the username only.
// - `password`: a password-only step (the username was asked for on an earlier page). The
//   inline menu fills the password only.
//
// Every step is a separate offer and a separate fill, each on its own trusted click in the
// extension-origin inline menu (INV-36; ADR 0037 §5 "gesture-only fill"; ADR 0040). Nothing here
// remembers anything between snapshots or across navigations: a pick on the username step never
// fills a later password step, which waits for a new click of its own.
//
// Pure and deterministic: no DOM access, no clock, no randomness. `content-script.ts` collects
// one {@link InputFacts} per `<input>` of the top-frame document, in document order, and one
// hint string per form; this module only reads those facts, so it is unit tested in Node against
// HTML fixtures (`test/login-step.test.ts`). It is a heuristic for what to *offer*; it never
// widens what may be *filled*. The visibility and topmost gates (THREAT_MODEL A7, INV-37) are
// applied by the caller before a field reaches this module (`visible`), and again by
// `content-script.ts`'s `applyFill` at fill time, for every field of every step. Fields in
// cross-origin iframes never reach it at all: the content script runs in the top frame only and
// reads only that frame's own document (ADR 0037 §5 "no cross-origin iframe fill by default").

/** What the content script observed about one `<input>`, all strings lowercased. */
export interface InputFacts {
  /** `input.type` as the browser normalises it (`"text"` for a missing or unknown type). */
  readonly type: string;
  /** The `autocomplete` attribute, whitespace-separated tokens, as written. */
  readonly autocomplete: string;
  /** `name`, `id`, `placeholder`, `aria-label` and the associated label texts, space-joined. */
  readonly hints: string;
  /** Passed the content script's visibility and topmost gate (A7) for this snapshot. */
  readonly visible: boolean;
  /** Neither `readOnly` nor `disabled`: a field the user (and so a fill) can change. */
  readonly editable: boolean;
  /** Index of the owning `<form>` in document order, or {@link NO_FORM}. */
  readonly form: number;
}

/** {@link InputFacts.form} for an input outside every `<form>`. */
export const NO_FORM = -1;

/** One detected login step. Indexes point into the `inputs` array passed to
 * {@link detectLoginStep}. */
export type LoginStep =
  | { readonly kind: "username_and_password"; readonly username: number; readonly password: number }
  | { readonly kind: "username"; readonly username: number }
  | { readonly kind: "password"; readonly password: number };

/** Hint words that make a text field look like a login identifier. */
const IDENTIFIER_HINT = /user|login|log-in|signin|sign-in|e-?mail|identifier|account|benutzer|usuario|correo|courriel/;

/** Hint words that rule a text field out as a login identifier, whatever else it says. */
const NOT_IDENTIFIER_HINT =
  /search|query|coupon|promo|voucher|captcha|otp|one-time|onetime|verification|passcode|\bcode\b|totp|2fa|mfa|zip|postal|password|passwd|subject|message|comment/;

/** Form-level hints (form `id`/`name`/`action`/`aria-label`, submit-button text) that say
 * "this form starts a sign-in". */
const LOGIN_FORM_HINT = /log ?in|login|sign ?in|signin|auth|next|continue|weiter|suivant|anmelden/;

/** Form-level hints that say "this form is something else", which outweigh {@link LOGIN_FORM_HINT}
 * for an identifier field with only a weak signal. */
const NOT_LOGIN_FORM_HINT = /search|subscribe|newsletter|sign ?up|signup|register|create (an )?account|checkout|contact|feedback/;

function tokens(autocomplete: string): readonly string[] {
  return autocomplete.split(/\s+/).filter((t) => t !== "");
}

function isTextLike(f: InputFacts): boolean {
  return f.type === "text" || f.type === "email" || f.type === "tel";
}

function isFillable(f: InputFacts): boolean {
  return f.visible && f.editable;
}

/**
 * How strongly one field says "I am the login identifier":
 * - 2 (strong): `autocomplete` names it (`username`, or `webauthn` for a conditional-mediation
 *   passkey field, which is always the identifier field);
 * - 1 (weak): `autocomplete="email"`, `type="email"` or an identifier name/id/label hint;
 * - 0: a plain text field with no signal;
 * - undefined: never an identifier (wrong type, a one-time code, a search box, a password
 *   field shown as text, …).
 */
export function identifierSignal(f: InputFacts): 0 | 1 | 2 | undefined {
  if (!isTextLike(f)) {
    return undefined;
  }
  const toks = tokens(f.autocomplete);
  if (toks.includes("one-time-code") || toks.includes("new-password") || toks.includes("current-password")) {
    return undefined;
  }
  if (toks.includes("username") || toks.includes("webauthn")) {
    return 2;
  }
  if (NOT_IDENTIFIER_HINT.test(f.hints)) {
    return undefined;
  }
  if (f.type === "tel") {
    // A phone number is only an identifier when the page says so in `autocomplete` (above).
    return undefined;
  }
  if (toks.includes("email") || f.type === "email" || IDENTIFIER_HINT.test(f.hints)) {
    return 1;
  }
  return 0;
}

/** The identifier paired with the password at `passwordIndex`: the closest preceding fillable
 * field of the same form with an identifier signal, else (inside a real `<form>` only) the
 * closest preceding plain text field, the classic "field before the password". Outside any
 * form, an unsignalled text field is never paired: on a form-less page the field before the
 * password can be anything (a header search box, say), and a password-only fill is the safe
 * answer there. */
function pairedIdentifier(inputs: readonly InputFacts[], passwordIndex: number): number | undefined {
  const form = inputs[passwordIndex]?.form ?? NO_FORM;
  let fallback: number | undefined;
  for (let i = passwordIndex - 1; i >= 0; i -= 1) {
    const f = inputs[i];
    if (f === undefined || f.form !== form || !isFillable(f)) {
      continue;
    }
    const signal = identifierSignal(f);
    if (signal === undefined) {
      continue;
    }
    if (signal > 0) {
      return i;
    }
    if (fallback === undefined && form !== NO_FORM && f.type !== "tel") {
      fallback = i;
    }
  }
  return fallback;
}

/** Whether `form` (an index, or {@link NO_FORM}) holds a password input the user cannot see
 * yet: the "revealed later in the same page" shape of an identifier-first step. */
function hasConcealedPassword(inputs: readonly InputFacts[], form: number): boolean {
  return inputs.some((f) => f.form === form && f.type === "password" && !f.visible);
}

/**
 * The identifier-first step's username field, if the page has one. A strong signal is enough on
 * its own. A weak one needs the field to be the only fillable text field of its form (an
 * identifier-first form asks for one thing) and the form to look like a sign-in: either it
 * already holds a not-yet-visible password field, or its hints say so and nothing says it is a
 * search, newsletter or sign-up form instead. Highest signal wins; ties go to document order.
 */
function identifierOnly(inputs: readonly InputFacts[], formHint: (form: number) => string): number | undefined {
  let best: number | undefined;
  let bestSignal = 0;
  for (let i = 0; i < inputs.length; i += 1) {
    const f = inputs[i];
    if (f === undefined || !isFillable(f)) {
      continue;
    }
    const signal = identifierSignal(f);
    if (signal === undefined || signal === 0 || signal <= bestSignal) {
      continue;
    }
    if (signal === 1) {
      const textFields = inputs.filter((g) => g.form === f.form && isFillable(g) && isTextLike(g)).length;
      if (textFields !== 1) {
        continue;
      }
      const hint = formHint(f.form);
      const looksLikeLogin = hasConcealedPassword(inputs, f.form) || (LOGIN_FORM_HINT.test(hint) && !NOT_LOGIN_FORM_HINT.test(hint));
      if (!looksLikeLogin) {
        continue;
      }
    }
    best = i;
    bestSignal = signal;
  }
  return best;
}

/**
 * The login step this snapshot shows, or `undefined` for none. `inputs` is every `<input>` of
 * the document in document order; `formHint(i)` is form `i`'s lowercased hint text
 * ({@link LOGIN_FORM_HINT}), and for {@link NO_FORM} the hint text of submit controls outside
 * any form.
 *
 * A visible, editable password field makes it a password step: the first such field in
 * document order (as before this change), paired with its form's identifier when there is one.
 * Otherwise it is an identifier-first step when {@link identifierOnly} finds a field, and no
 * step at all when it does not. Hidden, covered, off-screen, read-only and disabled fields are
 * never chosen, so a hidden username decoy next to a visible password yields a password-only
 * step, never a fill into the decoy.
 */
export function detectLoginStep(inputs: readonly InputFacts[], formHint: (form: number) => string): LoginStep | undefined {
  const password = inputs.findIndex((f) => f.type === "password" && isFillable(f));
  if (password !== -1) {
    const username = pairedIdentifier(inputs, password);
    return username === undefined ? { kind: "password", password } : { kind: "username_and_password", username, password };
  }
  const username = identifierOnly(inputs, formHint);
  return username === undefined ? undefined : { kind: "username", username };
}

/** What a step lets the inline menu fill: `undefined` for both fields (the one-page form, the
 * same request shape as before this change), otherwise the one field kind the step has. */
export function stepFillScope(step: LoginStep): "username" | "password" | undefined {
  switch (step.kind) {
    case "username_and_password":
      return undefined;
    case "username":
      return "username";
    case "password":
      return "password";
  }
}
