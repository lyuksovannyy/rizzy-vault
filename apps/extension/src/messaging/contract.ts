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

/** The content script's answer to a {@link SavePromptOfferedMessage} it showed the user: the
 * `token` ties it back to the exact submission the long-lived context still holds in memory
 * (ADR 0036 §4's "credentials_submitted... zeroizes it once the prompt is answered or
 * dismissed"). Never carries the credential values themselves — those never leave the
 * long-lived context a second time. */
export interface SavePromptResolvedMessage {
  readonly type: "save_prompt_resolved";
  readonly token: string;
  readonly action: "save" | "update" | "dismiss";
}

/**
 * Sent once, unconditionally, on every content-script load (`content-script.ts`'s
 * `installContentScript`) — never gated on whether this page has any detected login fields,
 * because the page a form's submit navigates *to* (a dashboard, say) often has none. Asks the
 * long-lived context whether a save/update offer from a form submitted on an earlier page of
 * this same tab and registrable domain is still pending: the fix for the save-prompt race
 * (`apps/extension/README.md`'s residual note) where a page that navigates away right after
 * submit tears down the document before the immediate {@link CredentialsSubmittedMessage}
 * response's `.then` callback ever runs, losing the offer with it. `pageUrl` is this (new)
 * page's own URL; the background derives the tab id from `sender.tab.id`, never the message
 * body (ADR 0036 §4, INV-40), and the registrable domain from this `pageUrl` only once it has
 * passed the same `pageUrlMatchesSender` check every other content-script message does.
 */
export interface CheckSavePromptMessage {
  readonly type: "check_save_prompt";
  readonly pageUrl: string;
}

export type FromContentScript =
  | FieldsDetectedMessage
  | CredentialsSubmittedMessage
  | SavePromptResolvedMessage
  | CheckSavePromptMessage;

/**
 * The user picked a candidate in the extension-origin inline menu, on a trusted gesture
 * (INV-36). Sent by `src/inline-menu/main.ts` **directly** to the long-lived context — never by
 * the content script, and never part of {@link FromContentScript} (ADR 0040 on
 * this): a compromised content script can echo back whatever a real pick produced, but it
 * cannot itself produce `sender.origin` equal to this extension's own origin inside an
 * http(s)-hosted tab — only a genuine extension-origin document, loaded from this extension's
 * own bundle, running inside that tab, can (`sender.ts`'s `isInlineMenuSender`). `itemId` is
 * re-checked against a freshly recomputed candidate list for the sender's own tab (never
 * trusted outright): this message carries no `pageUrl` at all, precisely so there is nothing
 * for it to claim that the sender's own `sender.tab.url` does not already settle.
 * `confirmedEquivalence` must be `true` whenever the recomputed candidate's own `needsWarning`
 * is `true` (ADR 0037 §5's second explicit confirmation) — checked again here, server-side,
 * not only in `main.ts`'s own UI, in case that UI is ever bypassed.
 */
export interface InlineMenuFillRequestMessage {
  readonly type: "inline_menu_fill_chosen";
  readonly itemId: string;
  readonly confirmedEquivalence: boolean;
}

/** Acknowledges a successful {@link InlineMenuFillRequestMessage}: never carries the revealed
 * values themselves (ADR 0040) — those go straight to the content script's own
 * tab as {@link ApplyFillMessage}, never back through the iframe that asked for them. */
export interface InlineMenuFillDispatchedMessage {
  readonly type: "inline_menu_fill_dispatched";
}

/**
 * The long-lived context pushes this to the one content script tab that hosted the inline-menu
 * iframe whose {@link InlineMenuFillRequestMessage} it just approved (`ext.tabs.sendMessage`,
 * never a reply to anything the content script itself sent) — only the chosen item's own
 * values, never a list, matching ADR 0036 §4. The content script maps `username`/`password` by
 * kind onto whichever fields it currently has tagged that way (`content-script.ts`'s own
 * tracked targets from the same detection pass the inline menu was shown for), re-checking
 * visibility at fill time (THREAT_MODEL.md row T, "re-check ... at fill time").
 */
export interface ApplyFillMessage {
  readonly type: "apply_fill";
  readonly values: { readonly username?: string; readonly password: string };
}

/**
 * Chromium-only internal relay (ADR 0036 §2, ADR 0040): a `chrome.offscreen` document has
 * no `chrome.tabs` access at all (Chrome's own "Offscreen documents" guide lists it among the
 * APIs withheld there; confirmed empirically fixing this change — a `TypeError` the instant
 * `content-handler.ts` first tried `ext.tabs.sendMessage`). `pushApplyFill` sends this to the MV3
 * service worker instead, which does have `tabs` like every other extension page, and which
 * performs the real {@link ApplyFillMessage} push on the long-lived context's behalf.
 * `background/service-worker.ts` is the only thing that ever accepts it, and only from this
 * extension's own non-tab sender (the offscreen document itself) — never from a content script
 * or the inline-menu iframe, neither of which this type is ever exposed to. Firefox's
 * `background-page.ts` has `tabs` directly and never sends this at all.
 */
export interface RelayApplyFillMessage {
  readonly type: "relay_apply_fill";
  readonly tabId: number;
  readonly values: { readonly username?: string; readonly password: string };
}

/** A match candidate as shown to the content script/inline menu: title/username/icon only,
 * never the password (ADR 0013 §3 rule 3). `needsWarning` is exactly
 * `@rizzy-vault/core`'s `MatchCandidate.needsWarning` (ADR 0037 §5's equivalence-only warning
 * flag) — the core gives no richer "matched via" tag than that boolean, so this contract never
 * invents one. */
export interface MatchCandidateSummary {
  readonly itemId: string;
  readonly title: string;
  readonly username: string;
  readonly needsWarning: boolean;
}

export interface CandidatesMessage {
  readonly type: "candidates";
  readonly candidates: readonly MatchCandidateSummary[];
  readonly warnings: readonly string[];
}

/** Offered after a {@link CredentialsSubmittedMessage}: the long-lived context decided (by
 * matching the submitted page against the user's saved items, the same way candidates are
 * decided) whether this looks like a new login to save or an existing one to update. The content
 * script shows this as a small save/update/dismiss prompt; it is never auto-applied (ROADMAP
 * §4.4: "save/update on submit" means *offering*, not writing without the user's choice). */
export interface SavePromptOfferedMessage {
  readonly type: "save_prompt";
  readonly token: string;
  readonly suggestion: "save" | "update";
  /** The matching item's title, only set when `suggestion` is `"update"`. */
  readonly itemTitle?: string;
}

/** An explicit failure answer (e.g. the device is locked, or — for
 * {@link InlineMenuFillRequestMessage} — the claimed `itemId` is not a current candidate, or an
 * equivalence-only candidate without `confirmedEquivalence`): distinct from a success message so
 * "nothing to fill" is never confused with "here are zero values to fill." Reused for both the
 * content script's and the inline-menu iframe's error answers — the shape is identical and
 * neither ever carries a secret, so one type serves both. */
export interface ContentErrorMessage {
  readonly type: "content_error";
  readonly code: string;
}

/** Acknowledges a {@link SavePromptResolvedMessage} whose action actually wrote or dismissed
 * something (as opposed to failing outright, which still answers with {@link ContentErrorMessage}
 * so the content script can tell "saved" apart from "the device is locked"). */
export interface SavePromptDoneMessage {
  readonly type: "save_prompt_done";
}

/** The answer to a {@link CheckSavePromptMessage} when nothing is pending for this tab and
 * registrable domain — distinct from {@link ContentErrorMessage} (this is the ordinary,
 * expected case on most page loads, never a failure) and distinct from `undefined` (so a test,
 * or a future caller, can tell "answered: nothing pending" apart from "no listener answered at
 * all"). */
export interface NoPendingSavePromptMessage {
  readonly type: "no_pending_save_prompt";
}

export type ToContentScript =
  | CandidatesMessage
  | SavePromptOfferedMessage
  | SavePromptDoneMessage
  | NoPendingSavePromptMessage
  | ContentErrorMessage;

/** `core-host/listener.ts`'s answer to an {@link InlineMenuFillRequestMessage} — never a
 * success-plus-values shape; see {@link InlineMenuFillDispatchedMessage}'s own doc for why. */
export type InlineMenuFillResponse = InlineMenuFillDispatchedMessage | ContentErrorMessage;

function isBoundedString(value: unknown, maxLen: number): value is string {
  return typeof value === "string" && value.length <= maxLen;
}

/** Validates a raw message claimed to be an {@link InlineMenuFillRequestMessage}. Only
 * `core-host/listener.ts` calls this, and only once `sender.ts`'s `isInlineMenuSender` has
 * already vouched for the sender — this still bounds the shape before it is interpreted
 * (CLAUDE.md "untrusted input is size-limited and parsed without panics" applies to every
 * message boundary, even a privileged sender's). */
export function isInlineMenuFillRequestMessage(value: unknown): value is InlineMenuFillRequestMessage {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  return v["type"] === "inline_menu_fill_chosen" && isBoundedString(v["itemId"], 256) && typeof v["confirmedEquivalence"] === "boolean";
}

/** Shared by {@link isApplyFillMessage} and {@link isRelayApplyFillMessage}: both carry the
 * exact same `values` shape (username/password by kind, never by field id). */
function isFillValues(value: unknown): value is { readonly username?: string; readonly password: string } {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  if (!isBoundedString(v["password"], MAX_FIELD_VALUE_LEN)) {
    return false;
  }
  return v["username"] === undefined || isBoundedString(v["username"], MAX_FIELD_VALUE_LEN);
}

/** Validates a raw message claimed to be an {@link ApplyFillMessage} — checked by
 * `content-script.ts` before use, even though only this extension's own background ever sends
 * it (the content script's `onMessage` listener cannot otherwise tell that apart from a bug). */
export function isApplyFillMessage(value: unknown): value is ApplyFillMessage {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  return v["type"] === "apply_fill" && isFillValues(v["values"]);
}

/** Validates a raw message claimed to be a {@link RelayApplyFillMessage} — checked by
 * `background/service-worker.ts` before use, alongside its own sender check (this type is never
 * exposed to a content script or the inline-menu iframe, but the shape is still bounded here,
 * same as every other message boundary). */
export function isRelayApplyFillMessage(value: unknown): value is RelayApplyFillMessage {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  return v["type"] === "relay_apply_fill" && typeof v["tabId"] === "number" && isFillValues(v["values"]);
}

/** The service worker's internal forward of a validated content-script message to the
 * long-lived context (ADR 0036 §2, §4): never sent by a content script itself (it has no way
 * to produce a `trustedOrigin` the long-lived context would accept — that field is set only by
 * the background, from `sender.ts`, after its own checks). */
export interface ContentScriptForward {
  readonly type: "cs_request";
  readonly message: FromContentScript;
  readonly trustedOrigin: string;
  /** `sender.tab.id` (`background/service-worker.ts`'s own `sender`, never the message body):
   * the save-prompt-by-location lookup's tab half (`core-host/content-handler.ts`'s
   * `check_save_prompt`/`credentials_submitted` handling). `undefined` on the rare sender that
   * validated as a content script but carries no tab id; callers that need it degrade to "no
   * location-keyed offer" rather than failing the whole request. */
  readonly trustedTabId: number | undefined;
}

/** Popup/options → long-lived context: coarse, one call per action (ADR 0036 §4). `enrol`
 * carries the Secret Key and master password (CRYPTO.md §11.2; ADR 0036 §3) — it crosses this
 * one message boundary and no other, exactly like `unlock`'s master password already does. */
export type PopupRequest =
  | {
      readonly type: "enrol";
      readonly serverOrigin: string;
      readonly loginName: string;
      readonly secretKey: string;
      readonly masterPassword: string;
      readonly totp?: string;
    }
  | { readonly type: "unlock"; readonly masterPassword: string }
  | { readonly type: "lock" }
  | { readonly type: "sync" }
  | { readonly type: "list_items" }
  | { readonly type: "item_fields"; readonly itemId: string }
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

/** One displayed field of an item, popup-facing (`item_fields`): a trimmed `FieldView` — never
 * carries a concealed value (`reveal_field` is the only way to get one, on the user's own
 * request, ADR 0013 §3 rule 3). */
export interface ItemFieldSummary {
  readonly key: string;
  readonly kind: "text" | "bool" | "number" | "enum" | "bytes" | "sort_key" | "unknown";
  readonly concealed: boolean;
  readonly value: string | undefined;
}

export type PopupResponse =
  | {
      readonly type: "status";
      readonly locked: boolean;
      readonly enrolled: boolean;
      /** The saved server origin (not secret), only once enrolled — so the popup can offer
       * "open web vault" without a separate round trip. */
      readonly serverOrigin?: string;
    }
  | { readonly type: "enrolled" }
  | { readonly type: "unlocked" }
  | { readonly type: "locked" }
  | { readonly type: "synced" }
  | { readonly type: "items"; readonly items: readonly ItemSummary[] }
  | { readonly type: "fields"; readonly fields: readonly ItemFieldSummary[] }
  | { readonly type: "revealed"; readonly value: string }
  | { readonly type: "generated"; readonly value: string }
  | { readonly type: "error"; readonly code: string };

/** Every message type this contract defines, used by `validate.ts` to size-check before shape
 * dispatch and by tests to assert the vocabulary stays in sync with this file. */
export const MESSAGE_TYPES = [
  "fields_detected",
  "credentials_submitted",
  "save_prompt_resolved",
  "check_save_prompt",
  "inline_menu_fill_chosen",
  "inline_menu_fill_dispatched",
  "apply_fill",
  "relay_apply_fill",
  "candidates",
  "save_prompt",
  "save_prompt_done",
  "no_pending_save_prompt",
  "enrol",
  "unlock",
  "lock",
  "sync",
  "list_items",
  "item_fields",
  "reveal_field",
  "generate_password",
  "get_status",
  "status",
  "enrolled",
  "unlocked",
  "locked",
  "synced",
  "items",
  "fields",
  "revealed",
  "generated",
  "error",
] as const;
