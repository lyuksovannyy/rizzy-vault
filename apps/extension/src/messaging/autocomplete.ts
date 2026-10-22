// SPDX-License-Identifier: AGPL-3.0-only

// The page's `autocomplete` attribute and custom-field autocomplete ids (ADR 0076 §1.1, §1.3,
// §2.2, §3). Pure and deterministic, shared by the content script (detection), the message
// validators (`contract.ts`) and the long-lived context; unit tested in Node
// (`test/autocomplete.test.ts`, which also checks the reserved set against `rizzy-core`'s list,
// the authority for what a custom field may hold).
//
// Detection only decides what to *offer*: nothing here widens what may be filled. Every fill
// still needs a trusted click in the extension-origin inline menu (INV-36, ADR 0040), and the
// long-lived context decides what crosses (ADR 0076 §4).

/** The longest custom token, in bytes (`ac_id = 1*64(...)`, ADR 0076 §2.2). */
export const MAX_AUTOCOMPLETE_ID_LEN = 64;

/** The reserved set R of ADR 0076 §3, without the `section-` prefix rule; frozen by the ADR. */
export const RESERVED_AUTOCOMPLETE_IDS: readonly string[] = [
  "on", "off", "webauthn", "shipping", "billing", "home", "work", "mobile", "fax", "pager",
  "username", "current-password", "new-password", "one-time-code",
  "name", "honorific-prefix", "given-name", "additional-name", "family-name", "honorific-suffix",
  "nickname", "organization-title", "organization", "street-address", "address-line1",
  "address-line2", "address-line3", "address-level4", "address-level3", "address-level2",
  "address-level1", "country", "country-name", "postal-code", "cc-name", "cc-given-name",
  "cc-additional-name", "cc-family-name", "cc-number", "cc-exp", "cc-exp-month", "cc-exp-year",
  "cc-csc", "cc-type", "transaction-currency", "transaction-amount", "language", "bday",
  "bday-day", "bday-month", "bday-year", "sex", "url", "photo",
  "tel", "tel-country-code", "tel-national", "tel-area-code", "tel-local", "tel-local-prefix",
  "tel-local-suffix", "tel-extension", "email", "impp",
  "password", "totp", "otp", "2fa", "mfa", "passkey",
];

const RESERVED = new Set(RESERVED_AUTOCOMPLETE_IDS);

/** `true` for a token a custom field may hold and the page may be matched on: the §2.2 grammar
 * (1–64 bytes of `a-z`, `0-9`, `-`, `_`, `.`), not in R, not `section-…`. */
export function isCustomToken(token: unknown): token is string {
  return (
    typeof token === "string" &&
    token.length >= 1 &&
    token.length <= MAX_AUTOCOMPLETE_ID_LEN &&
    /^[a-z0-9._-]+$/.test(token) &&
    !token.startsWith("section-") &&
    !RESERVED.has(token)
  );
}

/** WHATWG autofill field names that take no contact prefix (§3 rows 2–3). */
const NON_CONTACT_FIELDS = new Set([
  "name", "honorific-prefix", "given-name", "additional-name", "family-name", "honorific-suffix",
  "nickname", "username", "new-password", "current-password", "one-time-code",
  "organization-title", "organization", "street-address", "address-line1", "address-line2",
  "address-line3", "address-level4", "address-level3", "address-level2", "address-level1",
  "country", "country-name", "postal-code", "cc-name", "cc-given-name", "cc-additional-name",
  "cc-family-name", "cc-number", "cc-exp", "cc-exp-month", "cc-exp-year", "cc-csc", "cc-type",
  "transaction-currency", "transaction-amount", "language", "bday", "bday-day", "bday-month",
  "bday-year", "sex", "url", "photo",
]);

/** WHATWG contact field names (§3 row 4), which may follow a contact keyword. */
const CONTACT_FIELDS = new Set([
  "tel", "tel-country-code", "tel-national", "tel-area-code", "tel-local", "tel-local-prefix",
  "tel-local-suffix", "tel-extension", "email", "impp",
]);

const CONTACT_KEYWORDS = new Set(["home", "work", "mobile", "fax", "pager"]);

/** The parsed attribute (ADR 0076 §1.1). `webauthn` is the trailing-token flag. */
export type ParsedAutocomplete =
  | { readonly kind: "none"; readonly webauthn: boolean }
  | { readonly kind: "off"; readonly webauthn: false }
  | { readonly kind: "standard"; readonly field: string; readonly webauthn: boolean }
  | { readonly kind: "custom"; readonly token: string; readonly webauthn: false };

/** Longest attribute parsed, in UTF-16 code units (§1.1 rule 1). */
export const MAX_AUTOCOMPLETE_ATTR_LEN = 256;
/** Most tokens parsed (§1.1 rule 1). */
export const MAX_AUTOCOMPLETE_TOKENS = 8;

const NONE: ParsedAutocomplete = { kind: "none", webauthn: false };

/** Whether `tokens` are WHATWG autofill detail tokens; returns the field name if so. */
function whatwgField(tokens: readonly string[]): string | undefined {
  let i = 0;
  if (tokens[i]?.startsWith("section-") === true) {
    i += 1;
  }
  if (tokens[i] === "shipping" || tokens[i] === "billing") {
    i += 1;
  }
  const rest = tokens.slice(i);
  if (rest.length === 1) {
    const field = rest[0] ?? "";
    return NON_CONTACT_FIELDS.has(field) || CONTACT_FIELDS.has(field) ? field : undefined;
  }
  if (rest.length === 2 && CONTACT_KEYWORDS.has(rest[0] ?? "") && CONTACT_FIELDS.has(rest[1] ?? "")) {
    return rest[1];
  }
  return undefined;
}

/**
 * Parses an `autocomplete` attribute (ADR 0076 §1.1):
 * 1. missing, empty, over 256 characters or over 8 tokens: none;
 * 2. ASCII-lowercased and split on ASCII whitespace; a lone `on` is none, a lone `off` is off;
 * 3. a trailing `webauthn` sets the flag and is dropped;
 * 4. WHATWG detail tokens give standard(F);
 * 5. else one remaining token, without the flag, that is a custom token (grammar, not in R) is
 *    custom(t);
 * 6. else none.
 */
export function parseAutocomplete(attribute: string | null | undefined): ParsedAutocomplete {
  if (attribute === null || attribute === undefined || attribute.length > MAX_AUTOCOMPLETE_ATTR_LEN) {
    return NONE;
  }
  const lowered = attribute.replace(/[A-Z]/g, (c) => c.toLowerCase());
  const tokens = lowered.split(/[\t\n\f\r ]+/).filter((t) => t !== "");
  if (tokens.length === 0 || tokens.length > MAX_AUTOCOMPLETE_TOKENS) {
    return NONE;
  }
  if (tokens.length === 1 && tokens[0] === "on") {
    return NONE;
  }
  if (tokens.length === 1 && tokens[0] === "off") {
    return { kind: "off", webauthn: false };
  }
  let webauthn = false;
  if (tokens[tokens.length - 1] === "webauthn") {
    webauthn = true;
    tokens.pop();
  }
  const field = whatwgField(tokens);
  if (field !== undefined) {
    return { kind: "standard", field, webauthn };
  }
  if (tokens.length === 1 && !webauthn && isCustomToken(tokens[0])) {
    return { kind: "custom", token: tokens[0] ?? "", webauthn: false };
  }
  return { kind: "none", webauthn };
}

/** §1.3 rule (b): hints that say "authenticator code". The word `code` alone is not enough. */
export const TOTP_HINT =
  /totp|2fa|two-?factor|2-?step|two-?step|mfa|tfa|otp|one-?time|authenticator|auth(entication)?[-_ ]?code|verification[-_ ]?code|verify[-_ ]?code/;

/** §1.3 rule (c): hints that rule a field out as a TOTP target, whatever else it says. */
export const TOTP_NEGATIVE_HINT =
  /sms|text ?message|texted|phone|mobile|e-?mail|sent to|cvc|cvv|csc|card|security ?code|\bpin\b|zip|postal|post ?code|captcha|coupon|promo|voucher|gift|referral|invite|backup|recovery|search/;

/** §1.2: the delivery words that keep a `one-time-code` field from being the TOTP target
 * (the field's own hints say the code comes by SMS, phone or e-mail). */
export const DELIVERY_HINT = /sms|text ?message|texted|phone|mobile|e-?mail|sent to/;
