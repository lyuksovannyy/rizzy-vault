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
/** A DNS name is at most 253 characters (RFC 1035 §3.1's 255-byte wire form, minus the root
 * label and the length-prefix byte it elides in presentation form). Bounds `pageHost`/
 * `savedHost` (ADR 0037 §5 "Exact host shown"; gap 31 in the M2 gap audit): `rizzy-match`
 * already enforces this on every host it normalises, so this is a defence-in-depth bound on an
 * untrusted-boundary string, not the authority for host validity. */
export const MAX_HOST_LEN = 253;

// --- Passkeys (ADR 0039 §2, ADR 0040's pattern applied to a passkey ceremony instead of a
// fill) -------------------------------------------------------------------------------------
/** Generous bound for a base64-encoded byte string crossing this boundary (challenge, user id,
 * credential id): large enough for anything a real `WebAuthn` ceremony uses (a credential id is
 * typically well under 1 KiB; this project's own are 32 bytes), small enough that a hostile page
 * cannot use this field to smuggle an oversized payload through the one message type it can
 * reach (`passkey_create_request`/`passkey_get_request`) before `validate.ts`'s own per-field
 * check rejects it. Not independently verified against the `WebAuthn` spec's own limits ("U");
 * this implementation's own, deliberately generous choice. */
export const MAX_PASSKEY_BYTES_B64 = 2730; // base64 of 2048 raw bytes, rounded up to a multiple of 4
export const MAX_RP_NAME_LEN = 256;
export const MAX_USER_NAME_LEN = 256;
export const MAX_RP_ID_LEN = 256;
export const MAX_ALGS = 16;
export const MAX_ALLOW_CREDENTIALS = 16;

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

/**
 * The page's own `navigator.credentials.create({publicKey})` call, relayed by
 * `content/passkey-relay.ts` (ADR 0039 §2) — never trusted for `origin`/`rpId` (those come only
 * from `sender.tab.url` at the background, INV-64), but every *other* field here is legitimately
 * page/RP-supplied data the ceremony needs regardless (the relying party's own `rp.name`,
 * `user.id`/`user.name`/`user.displayName`, and its random `challenge`): there is nothing to
 * "trust" about them beyond passing them through unmodified, the same way `fieldId`s or a saved
 * URI's path are page data this project already forwards without needing a second source of
 * truth for them. `rpIdHint` is the page's own optional `rp.id`; `core-host/content-handler.ts`
 * defaults it to the verified origin's host when absent, exactly as a real browser's WebAuthn
 * implementation does, before anything is handed to `createPasskey` (which itself enforces
 * INV-64 in Rust). `algs` are the COSE algorithm ids out of `pubKeyCredParams`; a request with no
 * `-7` (ES256) is never forwarded here at all — `passkey-relay.ts` resolves straight to the
 * native fallback itself (this project supports no other algorithm yet, ADR 0039 §3).
 */
export interface PasskeyCreateRequestMessage {
  readonly type: "passkey_create_request";
  readonly pageUrl: string;
  readonly rpIdHint?: string;
  readonly rpName: string;
  readonly userIdB64: string;
  readonly userName: string;
  readonly userDisplayName: string;
  readonly challengeB64: string;
  readonly algs: readonly number[];
}

/** The page's own `navigator.credentials.get({publicKey})` call, relayed the same way
 * (`PasskeyCreateRequestMessage`'s own doc). `allowCredentialIdsB64` is the page's optional
 * `allowCredentials` list (base64 credential ids); empty means "any discoverable credential for
 * this `rpId`," which is how this project's own always-discoverable credentials (ADR 0039 §1,
 * `discoverable` always `true`) are meant to be requested in the first place. */
export interface PasskeyGetRequestMessage {
  readonly type: "passkey_get_request";
  readonly pageUrl: string;
  readonly rpIdHint?: string;
  readonly challengeB64: string;
  readonly allowCredentialIdsB64: readonly string[];
}

export type FromContentScript =
  | FieldsDetectedMessage
  | CredentialsSubmittedMessage
  | SavePromptResolvedMessage
  | CheckSavePromptMessage
  | PasskeyCreateRequestMessage
  | PasskeyGetRequestMessage;

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
 * The user clicked "Generate password" in the extension-origin inline-menu iframe, on a trusted
 * gesture (gap 32 in the M2 gap audit) — sent directly to the long-lived context, exactly
 * mirroring {@link InlineMenuFillRequestMessage}'s own rationale (ADR 0040): a compromised
 * content script cannot produce `sender.origin` equal to this extension's own, so
 * `isInlineMenuSender` is what the background trusts, never a claim this message could make.
 * Carries no options (length/kind) at all — there is nothing here for a compromised sender to
 * lie about, and the one generator call behind it (`core-host/core-context.ts`'s
 * `generatePasswordForFill`) takes none either.
 */
export interface InlineMenuGeneratePasswordRequestMessage {
  readonly type: "inline_menu_generate_password_chosen";
}

/** Acknowledges a successful {@link InlineMenuGeneratePasswordRequestMessage}: never carries the
 * generated value itself (same ADR 0040 rule as {@link InlineMenuFillDispatchedMessage}) — the
 * value goes straight to the content script's own tab as an {@link ApplyFillMessage} (`values: {
 * password }`, reusing that exact shape rather than inventing a second one — `content-script.ts`
 * already maps `values.password` onto whichever field it has tagged `"password"`, which for this
 * request is always the one the inline menu is anchored to). */
export interface InlineMenuGeneratePasswordDispatchedMessage {
  readonly type: "inline_menu_generate_password_dispatched";
}

/**
 * The user approved a pending passkey ceremony in the extension-origin consent UI
 * (`passkey-consent/main.ts`), on a trusted gesture (INV-36) — sent **directly** to the
 * long-lived context, never relayed by the content script, exactly mirroring
 * {@link InlineMenuFillRequestMessage}'s own rationale (ADR 0040): a compromised content script
 * cannot produce `sender.origin` equal to this extension's own, so `messaging/sender.ts`'s
 * `isInlineMenuSender` check — reused as-is for this message too, since the sender class it
 * tests for ("an extension-origin document embedded in a real http(s) tab") is identical for
 * the inline-menu iframe and the passkey consent iframe — is what the background trusts, never
 * this message's own claims. `ceremonyToken` is the one the background itself minted and handed
 * back in the earlier `passkey_offer` answer (`core-host/passkey-ceremony.ts`'s own store);
 * `chosenPasskeyRef` selects which offered candidate for a `get` ceremony (ignored, and
 * irrelevant, for a `create`) — re-checked against that ceremony's own candidate list
 * server-side (`isOfferedCandidate`), never trusted outright from this UI.
 */
export interface PasskeyCeremonyApprovedMessage {
  readonly type: "passkey_ceremony_approved";
  readonly ceremonyToken: string;
  readonly chosenPasskeyRef?: string;
}

/** The user declined, in the same consent UI, on the same trusted-gesture requirement. */
export interface PasskeyCeremonyDeclinedMessage {
  readonly type: "passkey_ceremony_declined";
  readonly ceremonyToken: string;
}

export type PasskeyCeremonyMessage = PasskeyCeremonyApprovedMessage | PasskeyCeremonyDeclinedMessage;

/** Acknowledges a {@link PasskeyCeremonyMessage}: never carries the credential itself (same
 * rule as {@link InlineMenuFillDispatchedMessage}) — the real result, or the fallback signal,
 * goes straight to the content script's tab as {@link ApplyPasskeyResultMessage}. */
export interface PasskeyCeremonyDispatchedMessage {
  readonly type: "passkey_ceremony_dispatched";
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
 * Everything one WebAuthn ceremony's successful result hands back to the page (ADR 0039 §2),
 * every byte field base64-encoded for this message boundary (`messaging/bytes.ts`'s own doc on
 * why). `attestationObjectB64` is set only for a `create`; `authenticatorDataB64`/`signatureB64`/
 * `userHandleB64` only for a `get` — mirroring `rizzy-wasm`'s own `CreatedPasskey`/
 * `PasskeyAssertion` split, never merged into one looser shape that could carry the wrong half.
 */
export interface PasskeyResultPayload {
  readonly credentialIdB64: string;
  readonly clientDataJsonB64: string;
  readonly attestationObjectB64?: string;
  readonly authenticatorDataB64?: string;
  readonly signatureB64?: string;
  readonly userHandleB64?: string;
}

/**
 * Pushed to the one tab that hosted the consent UI for `ceremonyToken` (`core-host/
 * content-handler.ts`'s `handlePasskeyCeremonyApproval`/decline/expiry paths — never a reply to
 * anything the content script itself sent, same shape as {@link ApplyFillMessage}): `"ok"` with
 * `result` for an approved ceremony; `"fallback"` with no `result` for a decline, a timeout, an
 * expired/unknown/mismatched-binding token, or any failure along the way. `passkey-relay.ts`
 * maps `ceremonyToken` back to the page-world shim's own pending promise and either resolves it
 * with `result` or calls the browser's native `navigator.credentials` method with the original
 * options (ADR 0039 §2's "Decline, timeout or no match" rule) — never anything in between.
 */
export interface ApplyPasskeyResultMessage {
  readonly type: "apply_passkey_result";
  readonly ceremonyToken: string;
  readonly outcome: "ok" | "fallback";
  readonly result?: PasskeyResultPayload;
}

/** Chromium-only internal relay for {@link ApplyPasskeyResultMessage}, exactly mirroring
 * {@link RelayApplyFillMessage}'s own doc (a `chrome.offscreen` document has no `chrome.tabs`). */
export interface RelayPasskeyResultMessage {
  readonly type: "relay_passkey_result";
  readonly tabId: number;
  readonly ceremonyToken: string;
  readonly outcome: "ok" | "fallback";
  readonly result?: PasskeyResultPayload;
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
  /** The saved URI's exact normalised host, A-label form — exactly
   * `@rizzy-vault/core`'s `MatchCandidate.savedHost` (ADR 0037 §5 "Exact host shown"; gap 31
   * in the M2 gap audit): "the saved site" in the inline menu's equivalence-only warning. */
  readonly savedHost: string;
}

export interface CandidatesMessage {
  readonly type: "candidates";
  /** The page's own exact normalised host, A-label form — exactly
   * `@rizzy-vault/core`'s `MatchDecisionResult.pageHost` (ADR 0037 §5 "Exact host shown"; gap
   * 31 in the M2 gap audit). */
  readonly pageHost: string;
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

/** One stored passkey offered as a `get`-ceremony candidate: title/username only, never a
 * credential id or any other secret-adjacent byte string (ADR 0013 §3 rule 3's "list views
 * never carry more than title/username," applied to passkeys). `passkeyRef` is opaque
 * (`core-host/passkey-ceremony.ts`'s own doc); the consent UI never does anything with it but
 * echo it back in {@link PasskeyCeremonyApprovedMessage}. */
export interface PasskeyCandidateSummary {
  readonly passkeyRef: string;
  readonly itemTitle: string;
  readonly userName: string;
}

/**
 * Answers a {@link PasskeyCreateRequestMessage}/{@link PasskeyGetRequestMessage} that passed
 * every check content-handler.ts runs before a consent prompt is even shown (HTTPS origin, top
 * frame, ES256 requested, device unlocked, and — for `get` — at least one candidate). Carries no
 * secret: just enough to render "Save a passkey for `rpName` as `userName`?" or "Sign in to
 * `rpId` — pick an account" (ADR 0039 §2's consent requirement). The content script relays this
 * to the consent iframe (`passkey-consent/protocol.ts`), never acts on it itself — there is
 * nothing in here for it to act on besides display.
 */
export interface PasskeyOfferMessage {
  readonly type: "passkey_offer";
  readonly ceremonyToken: string;
  readonly kind: "create" | "get";
  readonly rpId: string;
  /** Set for `create` only. */
  readonly rpName?: string;
  /** Set for `create` only. */
  readonly userName?: string;
  /** Set for `get` only; always at least one entry (content-handler.ts refuses the request with
   * {@link ContentErrorMessage} rather than ever offering an empty list). */
  readonly candidates?: readonly PasskeyCandidateSummary[];
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
  | PasskeyOfferMessage
  | ContentErrorMessage;

/** `core-host/listener.ts`'s answer to an {@link InlineMenuFillRequestMessage} — never a
 * success-plus-values shape; see {@link InlineMenuFillDispatchedMessage}'s own doc for why. */
export type InlineMenuFillResponse = InlineMenuFillDispatchedMessage | ContentErrorMessage;

/** `core-host/listener.ts`'s answer to an {@link InlineMenuGeneratePasswordRequestMessage} —
 * same never-the-secret-itself rule, see {@link InlineMenuGeneratePasswordDispatchedMessage}'s
 * own doc. */
export type InlineMenuGeneratePasswordResponse = InlineMenuGeneratePasswordDispatchedMessage | ContentErrorMessage;

/** `core-host/listener.ts`'s answer to a {@link PasskeyCeremonyMessage} — same
 * never-the-secret-itself rule, see {@link PasskeyCeremonyDispatchedMessage}'s own doc. */
export type PasskeyCeremonyResponse = PasskeyCeremonyDispatchedMessage | ContentErrorMessage;

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

/** Validates a raw message claimed to be an {@link InlineMenuGeneratePasswordRequestMessage} —
 * same gate as {@link isInlineMenuFillRequestMessage}'s own doc explains. The message carries no
 * fields beyond `type`, so there is nothing else to bound. */
export function isInlineMenuGeneratePasswordRequestMessage(value: unknown): value is InlineMenuGeneratePasswordRequestMessage {
  return typeof value === "object" && value !== null && (value as Record<string, unknown>)["type"] === "inline_menu_generate_password_chosen";
}

/** Validates a raw message claimed to be a {@link PasskeyCeremonyMessage} — only
 * `core-host/listener.ts` calls this, and only once `isInlineMenuSender` has already vouched for
 * the sender (same gate as {@link isInlineMenuFillRequestMessage}'s own doc explains). */
export function isPasskeyCeremonyMessage(value: unknown): value is PasskeyCeremonyMessage {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  if (!isBoundedString(v["ceremonyToken"], 256)) {
    return false;
  }
  if (v["type"] === "passkey_ceremony_declined") {
    return true;
  }
  return v["type"] === "passkey_ceremony_approved" && (v["chosenPasskeyRef"] === undefined || isBoundedString(v["chosenPasskeyRef"], 256));
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

function isPasskeyResultPayload(value: unknown): value is PasskeyResultPayload {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  if (!isBoundedString(v["credentialIdB64"], MAX_PASSKEY_BYTES_B64) || !isBoundedString(v["clientDataJsonB64"], MAX_PASSKEY_BYTES_B64)) {
    return false;
  }
  for (const key of ["attestationObjectB64", "authenticatorDataB64", "signatureB64", "userHandleB64"] as const) {
    if (v[key] !== undefined && !isBoundedString(v[key], MAX_PASSKEY_BYTES_B64)) {
      return false;
    }
  }
  return true;
}

function isPasskeyOutcomeShape(v: Record<string, unknown>): boolean {
  if (!isBoundedString(v["ceremonyToken"], 256)) {
    return false;
  }
  if (v["outcome"] === "fallback") {
    return v["result"] === undefined;
  }
  return v["outcome"] === "ok" && isPasskeyResultPayload(v["result"]);
}

/** Validates a raw message claimed to be an {@link ApplyPasskeyResultMessage} — checked by
 * `passkey-relay.ts` before use, same reasoning as {@link isApplyFillMessage}'s own doc. */
export function isApplyPasskeyResultMessage(value: unknown): value is ApplyPasskeyResultMessage {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  return v["type"] === "apply_passkey_result" && isPasskeyOutcomeShape(v);
}

/** Validates a raw message claimed to be a {@link RelayPasskeyResultMessage} — checked by
 * `background/service-worker.ts`, mirroring {@link isRelayApplyFillMessage}. */
export function isRelayPasskeyResultMessage(value: unknown): value is RelayPasskeyResultMessage {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  return v["type"] === "relay_passkey_result" && typeof v["tabId"] === "number" && isPasskeyOutcomeShape(v);
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
  "passkey_create_request",
  "passkey_get_request",
  "passkey_offer",
  "passkey_ceremony_approved",
  "passkey_ceremony_declined",
  "passkey_ceremony_dispatched",
  "apply_passkey_result",
  "relay_passkey_result",
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
