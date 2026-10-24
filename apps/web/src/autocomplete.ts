// SPDX-License-Identifier: AGPL-3.0-only

// Custom-field autocomplete ids in the web editor (ADR 0076 §2.2–§2.5, §3). The editor checks
// an id as the user types, so the errors appear inline next to the field: the grammar (W1),
// the reserved set (W2), another field of the form with the same id (W3), a boolean field
// (W4) and a missing Display Name (W5). `rizzy-client` runs the same checks on every write
// path and stays the authority: these are only the early, per-field copies of its answers
// (this UI thread loads no wasm, ADR 0013 §4). `test/autocomplete.test.ts` checks that the
// reserved set here equals `rizzy-core`'s list byte for byte.

/** The longest id, in bytes (`ac_id = 1*64(...)`). */
export const MAX_AUTOCOMPLETE_ID_LEN = 64;

/** The reserved prefix (§3 row 1). */
export const RESERVED_AUTOCOMPLETE_PREFIX = "section-";

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

/** Why an id is refused by the grammar or the reserved set, or `undefined` if it is fine. */
export function autocompleteIdError(id: string): "invalid" | "reserved" | undefined {
  if (id.length === 0 || id.length > MAX_AUTOCOMPLETE_ID_LEN || !/^[a-z0-9._-]+$/.test(id)) {
    return "invalid";
  }
  if (id.startsWith(RESERVED_AUTOCOMPLETE_PREFIX) || RESERVED.has(id)) {
    return "reserved";
  }
  return undefined;
}

/** ASCII-lowercases what the user typed (§2.2: "The web and CLI editors lowercase ASCII input
 * before writing"). Nothing else is changed: whitespace or a non-ASCII letter stays, and the
 * grammar check reports it. */
export function lowercaseAscii(text: string): string {
  return text.replace(/[A-Z]/g, (c) => c.toLowerCase());
}

/** One custom field of the form, as the checks see it. */
export interface AutocompleteRow {
  /** A stable key of the row (element id). */
  readonly key: string;
  /** The Display Name as the form holds it. */
  readonly label: string;
  readonly kind: "text" | "hidden" | "boolean";
  /** The id as the form holds it (already lowercased); empty for none. */
  readonly id: string;
  /** The id the field displays now (saved), empty for none or a new row. */
  readonly savedId: string;
  /** The user changed something in this row, or it is new: W5 applies (§2.3). */
  readonly edited: boolean;
}

/** The inline message of one row's id, or of its Display Name. */
export interface RowProblems {
  readonly id?: "invalid" | "reserved" | "duplicate" | "kind";
  readonly label?: "required";
}

/**
 * The W1–W5 problems of every row of the form (ADR 0076 §2.3), by row key. W3 applies only
 * to an id the user is setting (one that differs from the saved one): two saved fields that a
 * merge left with the same id are a warning (§2.5), not an error, so an unrelated edit is never
 * blocked.
 */
export function autocompleteProblems(rows: readonly AutocompleteRow[]): Map<string, RowProblems> {
  const out = new Map<string, RowProblems>();
  for (const row of rows) {
    let id: RowProblems["id"];
    if (row.id !== "") {
      id = autocompleteIdError(row.id);
      if (id === undefined && row.id !== row.savedId && rows.some((o) => o.key !== row.key && o.id === row.id)) {
        id = "duplicate";
      }
      if (id === undefined && row.kind === "boolean") {
        id = "kind";
      }
    }
    const label = row.edited && row.label.trim() === "" ? "required" : undefined;
    if (id !== undefined || label !== undefined) {
      out.set(row.key, { ...(id !== undefined ? { id } : {}), ...(label !== undefined ? { label } : {}) });
    }
  }
  return out;
}

/** The text of a row's id problem. */
export function idProblemText(problem: NonNullable<RowProblems["id"]>): string {
  switch (problem) {
    case "invalid":
      return "Use 1–64 lowercase letters, digits, “-”, “_” or “.”, with no spaces.";
    case "reserved":
      return "This autocomplete id is reserved for the manager (username, password, one-time code and the standard browser names).";
    case "duplicate":
      return "Another custom field of this item already uses this autocomplete id.";
    case "kind":
      return "Only text and hidden fields can have an autocomplete id. Clear it, or change the field's kind.";
  }
}

/** The §2.5 warning of a shadowed field. */
export function shadowedText(id: string, winnerLabel: string): string {
  return `Autocomplete id “${id}” is also used by “${winnerLabel}”; only that field is filled. Change or clear one.`;
}
