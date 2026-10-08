// The messaging contract between the content script, the background (MV3 service worker /
// Firefox event page), and the long-lived core-holding context (ADR 0036 §4). Every shape here
// is a plain, serializable object (structured-clone safe, no class instances, no functions),
// so it survives `chrome.runtime.sendMessage` unchanged. ADR 0036 §4 rules this file encodes:
//
// - the content script sends only: detected-field reports, a chosen fill request (after the
//   user picks a candidate), and submitted-credential reports for save/update prompts;
// - it never asks for or receives the master password, the Secret Key, or any decrypted item
//   field beyond the one value it was told to fill;
// - the core replies to a fill with only the chosen candidate's values, never a candidate list
//   with secrets (list views carry title/username/icon only, ADR 0013 §3 rule 3);
// - popup/options messages are coarse, one call per action ("unlock", "lock", "list items",
//   "save item", "generate password"): no primitive crypto call crosses a message boundary.
//
// Every message has a byte budget (`validate.ts`), checked before the shape is interpreted, so
// an oversized or malformed message from an untrusted content script is refused before it is
// parsed as JSON-shaped data (INV-40). The limits below are this implementation's own choice,
// generous enough for real pages and forms; they are not independently verified against a
// standard (U) and may be revisited once real-world pages are measured.

/** Bytes, as `JSON.stringify(message).length` approximates (ASCII-biased, intentionally loose:
 * it only has to reject pathological input, not measure exactly). */
export const MAX_MESSAGE_BYTES = 64 * 1024;
export const MAX_URL_LEN = 2048;
export const MAX_FIELD_VALUE_LEN = 4096;
export const MAX_FIELDS_PER_REPORT = 64;
export const MAX_CANDIDATES = 32;
export const MAX_TITLE_LEN = 256;

/** A field the content script found on the page (never includes the field's current value for
 * a password field; only for username-shaped fields, and only up to {@link MAX_FIELD_VALUE_LEN}). */
export interface FieldDescriptor {
  readonly fieldId: string;
  readonly kind: "username" | "password" | "other";
  readonly visible: boolean;
  /** Present only for `kind: "username"`, and only if the user already typed something. */
  readonly currentValue?: string;
}

export interface FieldsDetectedMessage {
  readonly type: "fields_detected";
  readonly pageUrl: string;
  readonly isTopFrame: boolean;
  readonly fields: readonly FieldDescriptor[];
}

/** The user picked a candidate in the inline menu or popup, on a trusted gesture (INV-36). The
 * content script never decides this on its own; it only reports the user's click. */
export interface FillChosenMessage {
  readonly type: "fill_chosen";
  readonly pageUrl: string;
  readonly isTopFrame: boolean;
  readonly itemId: string;
  readonly fieldIds: readonly string[];
}

/** A form the page submitted, offered for a save/update prompt. These are the user's own
 * freshly typed values, not vault secrets, but still sensitive: the background forwards this to
 * the long-lived context only, zeroizes it once the prompt is answered or dismissed, and it is
 * never written to `storage.local`/IndexedDB in cleartext. */
export interface CredentialsSubmittedMessage {
  readonly type: "credentials_submitted";
  readonly pageUrl: string;
  readonly usernameValue?: string;
  readonly passwordValue?: string;
}

export type FromContentScript = FieldsDetectedMessage | FillChosenMessage | CredentialsSubmittedMessage;

/** The long-lived context's answer to {@link FillChosenMessage}: only the chosen fields' values,
 * at fill time, never a list (ADR 0036 §4). */
export interface FillValuesMessage {
  readonly type: "fill_values";
  readonly values: Readonly<Record<string, string>>;
}

/** A match candidate as shown to the content script/inline menu: title/username/icon only,
 * never the password (ADR 0013 §3 rule 3). `matchedVia` carries ADR 0037 §5's equivalence-only
 * warning flag. */
export interface MatchCandidateSummary {
  readonly itemId: string;
  readonly title: string;
  readonly username: string;
  readonly matchedVia: "exact" | "registrable_domain" | "host" | { readonly equivalence: string };
}

export interface CandidatesMessage {
  readonly type: "candidates";
  readonly candidates: readonly MatchCandidateSummary[];
  readonly warnings: readonly string[];
}

/** An explicit failure answer to the content script (e.g. the device is locked, or the save
 * prompt is not implemented yet): distinct from {@link FillValuesMessage} so "nothing to fill"
 * is never confused with "here are zero values to fill." */
export interface ContentErrorMessage {
  readonly type: "content_error";
  readonly code: string;
}

export type ToContentScript = FillValuesMessage | CandidatesMessage | ContentErrorMessage;

/** The service worker's internal forward of a validated content-script message to the
 * long-lived context (ADR 0036 §2, §4): never sent by a content script itself (it has no way
 * to produce a `trustedOrigin` the long-lived context would accept — that field is set only by
 * the background, from `sender.ts`, after its own checks). */
export interface ContentScriptForward {
  readonly type: "cs_request";
  readonly message: FromContentScript;
  readonly trustedOrigin: string;
}

/** Popup/options → long-lived context: coarse, one call per action (ADR 0036 §4). */
export type PopupRequest =
  | { readonly type: "unlock"; readonly masterPassword: string }
  | { readonly type: "lock" }
  | { readonly type: "list_items" }
  | { readonly type: "reveal_field"; readonly itemId: string; readonly fieldId: string }
  | { readonly type: "generate_password"; readonly options: GeneratorOptions }
  | { readonly type: "get_status" };

export interface GeneratorOptions {
  readonly kind: "password" | "passphrase";
  readonly length: number;
}

export interface ItemSummary {
  readonly itemId: string;
  readonly title: string;
  readonly username: string;
}

export type PopupResponse =
  | { readonly type: "status"; readonly locked: boolean }
  | { readonly type: "unlocked" }
  | { readonly type: "locked" }
  | { readonly type: "items"; readonly items: readonly ItemSummary[] }
  | { readonly type: "revealed"; readonly value: string }
  | { readonly type: "generated"; readonly value: string }
  | { readonly type: "error"; readonly code: string };

/** Every message type this contract defines, used by `validate.ts` to size-check before shape
 * dispatch and by tests to assert the vocabulary stays in sync with this file. */
export const MESSAGE_TYPES = [
  "fields_detected",
  "fill_chosen",
  "credentials_submitted",
  "fill_values",
  "candidates",
  "unlock",
  "lock",
  "list_items",
  "reveal_field",
  "generate_password",
  "get_status",
  "status",
  "unlocked",
  "locked",
  "items",
  "revealed",
  "generated",
  "error",
] as const;
