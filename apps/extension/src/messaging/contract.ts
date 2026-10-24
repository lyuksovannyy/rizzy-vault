// SPDX-License-Identifier: AGPL-3.0-only

// The messaging contract between the content script, the background (MV3 service worker /
// Firefox event page), and the long-lived core-holding context (ADR 0036 §4). Every shape here
// is a plain, serializable object (structured-clone safe, no class instances, no functions),
// so it survives `chrome.runtime.sendMessage` unchanged. ADR 0036 §4 rules this file encodes:
//
// - the content script sends only: detected-field reports, submitted-credential reports for
//   save/update prompts, and a per-instance registration/revocation message for an inline-menu
//   or passkey-consent iframe it is about to build or tear down (ADR 0043); the chosen fill
//   request comes from the inline-menu iframe itself (ADR 0040);
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
import { isCustomToken } from "./autocomplete.ts";

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
  /** ADR 0076 §5.1: visible, editable custom-token inputs of the submitted form, ≤ 8. */
  readonly customFields?: readonly CapturedCustomField[];
}

/** One captured custom field (ADR 0076 §5.1). */
export interface CapturedCustomField {
  readonly token: string;
  readonly value: string;
  /** `type=password`. */
  readonly masked: boolean;
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

/**
 * The content script is about to build an inline-menu or passkey-consent iframe (ADR 0043 points
 * 1-2): `instanceToken` is the one it just minted (`crypto.randomUUID()`) for that one iframe
 * instance, before setting its `src`. Sent over the ordinary content-script channel, so the
 * background binds it to the browser-vouched `sender.tab.id` and origin (`isContentScriptSender`/
 * `trustedOriginOf`), never to anything this message claims; it carries no URL at all. The token
 * then reaches the iframe only in the targeted show `postMessage` (`InlineMenuShowMessage`/
 * `PasskeyConsentShowMessage`), and every privileged message from that iframe must carry it back
 * ({@link InlineMenuFillRequestMessage}, {@link InlineMenuGeneratePasswordRequestMessage},
 * {@link PasskeyCeremonyMessage}).
 */
export interface RegisterIframeInstanceMessage {
  readonly type: "register_iframe_instance";
  readonly instanceToken: string;
}

/** The content script tore that iframe down (ADR 0043 point 5: a pick, a blur, a rebuild, a
 * settled passkey ceremony). Only the registering tab's own revoke is honoured
 * (`core-host/iframe-instance.ts`). */
export interface RevokeIframeInstanceMessage {
  readonly type: "revoke_iframe_instance";
  readonly instanceToken: string;
}

export type FromContentScript =
  | FieldsDetectedMessage
  | CredentialsSubmittedMessage
  | SavePromptResolvedMessage
  | CheckSavePromptMessage
  | PasskeyCreateRequestMessage
  | PasskeyGetRequestMessage
  | RegisterIframeInstanceMessage
  | RevokeIframeInstanceMessage;

/** The exact string length of a v4 UUID in its canonical form (`crypto.randomUUID()`). */
export const INSTANCE_TOKEN_LEN = 36;

const INSTANCE_TOKEN_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/** Whether `value` has the exact shape of an `instanceToken` (ADR 0043 point 3: "shape-validated
 * first"): a lowercase canonical v4 UUID, the only form `crypto.randomUUID()` produces. Length
 * is checked before the pattern runs, so an oversized string never reaches the regex. */
export function isInstanceToken(value: unknown): value is string {
  return typeof value === "string" && value.length === INSTANCE_TOKEN_LEN && INSTANCE_TOKEN_PATTERN.test(value);
}

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
 *
 * `only` narrows the fill to one field on a multi-step login page (`content/login-step.ts`):
 * `"username"` on an identifier-first step, `"password"` on a password-only step; absent, both
 * (the one-page form). It only ever narrows: the long-lived context sends the content script no
 * value beyond the one kind named (ADR 0036 §4: nothing "beyond what the user is filling"), and
 * a forged or missing `only` can at most give the content script the same both-values push it
 * gets for a one-page form, still written only into the visible fields of the step the user
 * clicked on. It is not remembered: every step is its own click and its own request (INV-36).
 */
export interface InlineMenuFillRequestMessage {
  readonly type: "inline_menu_fill_chosen";
  /** ADR 0043 point 3: the token the content script registered for this exact iframe instance
   * and delivered to it only in its own {@link InlineMenuShowMessage}-shaped `postMessage`. A
   * clone of the inline-menu resource elsewhere in the tab never has one. */
  readonly instanceToken: string;
  readonly itemId: string;
  readonly confirmedEquivalence: boolean;
  readonly only?: FillOnly;
  /** ADR 0076 §4.2: the offer this click answers. With it, the scope comes from the long-lived
   * context's own offer record, never from this message. */
  readonly offerId?: string;
}

/** The one field kind a multi-step login step fills ({@link InlineMenuFillRequestMessage.only}). */
export type FillOnly = "username" | "password" | "totp";

/** One detected step's fill scope (ADR 0076 §4.1), as the content script hands it to the
 * inline-menu iframe and the iframe to the long-lived context in an offer request. Every member
 * is a claim of the (untrusted) content script; the long-lived context only ever uses it to
 * narrow what crosses, never to widen it. */
export interface FillScope {
  /** Today's narrowing; `"totp"` is a TOTP-only step. */
  readonly only?: FillOnly;
  /** The step also has a TOTP target (`only` absent, `"username"` or `"password"`). */
  readonly totp?: true;
  /** Distinct custom tokens on the step's visible, editable fields, document order, ≤ 16. */
  readonly custom?: readonly string[];
  /** The custom token the step's username target carries (also in `custom`). */
  readonly usernameToken?: string;
  /** Likewise for the password target. */
  readonly passwordToken?: string;
}

/** ADR 0076 §4.1: at most 16 custom tokens per scope, 16 disclosures per candidate. */
export const MAX_SCOPE_TOKENS = 16;
/** ADR 0076 §5.1: at most 8 captured custom fields per submitted form. */
export const MAX_CAPTURED_FIELDS = 8;
/** ADR 0076 §4.1: a Display Name in an offer is at most 256 characters. */
export const MAX_OFFER_LABEL_LEN = 256;

/** ADR 0076 §4.3 / §4.4: an offer id is 16 random bytes, lowercase hex. */
export function isOfferId(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{32}$/.test(value);
}

/** The values one fill pushes to the content script, by kind (never by field id): at least one
 * of the two. A one-page form gets both (or the password alone when the item has no username);
 * an identifier-first step only `username`; a password-only step, and the generator, only
 * `password`. */
export interface FillValues {
  readonly username?: string;
  readonly password?: string;
  /** The current TOTP code (ADR 0076 §4.4): 6–8 digits, never the secret. */
  readonly totp?: string;
  /** Custom values by page token (ADR 0076 §4.4): 1–16 entries, distinct tokens. */
  readonly custom?: readonly { readonly token: string; readonly value: string }[];
}

/** The iframe → long-lived context offer request (ADR 0076 §4.1 step 2), validated as an
 * inline-menu sender (ADR 0040 point 1) whose ADR 0043 instance token the background admits. */
export interface InlineMenuOfferRequestMessage {
  readonly type: "inline_menu_offer_request";
  readonly instanceToken: string;
  readonly scope: FillScope;
}

/** One candidate of an {@link InlineMenuOfferMessage}: what a click on its row would fill
 * besides username and password. Display Names only, never a value. */
export interface OfferCandidate {
  readonly itemId: string;
  readonly fillsTotp: boolean;
  readonly customFill: readonly { readonly label: string; readonly concealed: boolean }[];
}

/** The long-lived context's answer to the iframe, never the content script (ADR 0076 §4.1
 * step 3). The offer record behind `offerId` stays in the long-lived context's memory. */
export interface InlineMenuOfferMessage {
  readonly type: "inline_menu_offer";
  readonly offerId: string;
  readonly pageHost: string;
  readonly candidates: readonly OfferCandidate[];
}

export type InlineMenuOfferResponse = InlineMenuOfferMessage | ContentErrorMessage;

/** The save dialog → long-lived context request for its rows (ADR 0076 §5.2), by save-prompt
 * token, from the extension-origin dialog iframe (an inline-menu-class sender whose ADR 0043
 * instance token the background admits). */
export interface SaveDialogRequestMessage {
  readonly type: "save_dialog_request";
  readonly instanceToken: string;
  readonly token: string;
}

/** One row the save dialog shows (ADR 0076 §5.3). Never a value. */
export interface SaveDialogRowView {
  readonly index: number;
  readonly kind: "add" | "update";
  readonly label: string;
  readonly concealed: boolean;
  readonly checked: boolean;
}

/** One vault a new login may be saved to (ADR 0081 §A8): its id and its label ("Personal",
 * a name, or "Untitled vault"). Shown only in the extension-origin dialog, never in the page. */
export interface SaveDialogVaultView {
  readonly id: string;
  readonly label: string;
}

/** ADR 0081 §A8: at most this many vaults are offered in a save prompt's picker
 * (`MAX_DIRECTORY_ENTRIES`). */
export const MAX_PICKER_VAULTS = 128;
/** The longest vault label a picker shows, in UTF-16 code units (64 scalar values, each at most
 * two units). */
export const MAX_VAULT_LABEL_LEN = 128;

/** A vault id: 16 bytes, lowercase hex. */
export function isVaultId(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{32}$/.test(value);
}

/** The answer to a {@link SaveDialogRequestMessage}. */
export interface SaveDialogChoicesMessage {
  readonly type: "save_dialog_choices";
  readonly suggestion: "save" | "update";
  readonly itemTitle?: string;
  readonly pageHost: string;
  readonly rows: readonly SaveDialogRowView[];
  /** ADR 0081 §A8: for a new login, the vaults it may be saved to (only when there are two or
   * more), with {@link SaveDialogChoicesMessage.defaultVaultId}, the Personal vault,
   * preselected every time. */
  readonly vaults?: readonly SaveDialogVaultView[];
  readonly defaultVaultId?: string;
}

export type SaveDialogChoicesResponse = SaveDialogChoicesMessage | ContentErrorMessage;

/** The user's answer in the save dialog, on a trusted click (ADR 0076 §5.3): the action, and the
 * rows they ticked with the Display Name left in each (used for "add" rows only). */
export interface SaveDialogResolveMessage {
  readonly type: "save_dialog_resolve";
  readonly instanceToken: string;
  readonly token: string;
  readonly action: "save" | "update" | "dismiss";
  readonly rows: readonly { readonly index: number; readonly label: string }[];
  /** ADR 0081 §A8: the vault the user picked for a new login; the Personal vault when absent.
   * The long-lived context accepts only a vault it offered. */
  readonly vaultId?: string;
}

export type SaveDialogResolveResponse = SavePromptDoneMessage | ContentErrorMessage;

/** Validates a raw {@link SaveDialogRequestMessage}. */
export function isSaveDialogRequestMessage(value: unknown): value is SaveDialogRequestMessage {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  return (
    v["type"] === "save_dialog_request" &&
    isInstanceToken(v["instanceToken"]) &&
    isBoundedString(v["token"], 256) &&
    hasOnlyKeys(v, ["type", "instanceToken", "token"])
  );
}

/** Validates a raw {@link SaveDialogResolveMessage}: at most 8 rows (one per captured field),
 * distinct indexes 0–7, Display Names of at most 256 characters. */
export function isSaveDialogResolveMessage(value: unknown): value is SaveDialogResolveMessage {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  if (
    v["type"] !== "save_dialog_resolve" ||
    !isInstanceToken(v["instanceToken"]) ||
    !isBoundedString(v["token"], 256) ||
    (v["action"] !== "save" && v["action"] !== "update" && v["action"] !== "dismiss") ||
    !hasOnlyKeys(v, ["type", "instanceToken", "token", "action", "rows", "vaultId"]) ||
    (v["vaultId"] !== undefined && !isVaultId(v["vaultId"]))
  ) {
    return false;
  }
  const rows = v["rows"];
  if (!Array.isArray(rows) || rows.length > MAX_CAPTURED_FIELDS) {
    return false;
  }
  const seen = new Set<number>();
  for (const row of rows as unknown[]) {
    if (typeof row !== "object" || row === null || Array.isArray(row)) {
      return false;
    }
    const r = row as Record<string, unknown>;
    const index = r["index"];
    if (
      !hasOnlyKeys(r, ["index", "label"]) ||
      typeof index !== "number" ||
      !Number.isInteger(index) ||
      index < 0 ||
      index >= MAX_CAPTURED_FIELDS ||
      seen.has(index) ||
      !isBoundedString(r["label"], MAX_OFFER_LABEL_LEN)
    ) {
      return false;
    }
    seen.add(index);
  }
  return true;
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
  /** ADR 0043 point 3, exactly as {@link InlineMenuFillRequestMessage.instanceToken}. */
  readonly instanceToken: string;
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
  /** ADR 0043 point 3: the consent iframe instance's own token, delivered in its
   * `PasskeyConsentShowMessage`. An independent layer beside `ceremonyToken`, never in place
   * of it (ADR 0043 point 6). */
  readonly instanceToken: string;
  readonly ceremonyToken: string;
  readonly chosenPasskeyRef?: string;
  /** ADR 0081 §A8: the vault a `create` that saves a new login goes to, picked in the consent
   * UI (the Personal vault preselected); accepted only if it is a vault the session may write. */
  readonly vaultId?: string;
}

/** The user declined, in the same consent UI, on the same trusted-gesture requirement. */
export interface PasskeyCeremonyDeclinedMessage {
  readonly type: "passkey_ceremony_declined";
  readonly instanceToken: string;
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
  readonly values: FillValues;
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
  readonly values: FillValues;
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
  /** ADR 0076 §4.1: the item holds a valid time-based `login.totp` (a non-secret flag, like
   * `needsWarning`); the content script opens a menu at a TOTP-only step only if one has it. */
  readonly hasTotp: boolean;
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
  /** ADR 0076 §5.2: captured custom fields give rows, so the content script shows the
   * extension-origin save dialog instead of the page-DOM banner. */
  readonly dialog?: true;
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
  /** ADR 0081 §A8, `create` of a new login with two or more vaults to save to: the picker's
   * vaults, the Personal vault preselected every time. Display only, for the consent iframe. */
  readonly vaults?: readonly SaveDialogVaultView[];
  readonly defaultVaultId?: string;
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
/** Acknowledges a {@link RegisterIframeInstanceMessage} or {@link RevokeIframeInstanceMessage}.
 * A registration the background refused (a token it already holds) is answered with a
 * {@link ContentErrorMessage} instead, and the content script then never shows that iframe its
 * candidates or offer. */
export interface IframeInstanceDoneMessage {
  readonly type: "iframe_instance_done";
}

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
  | IframeInstanceDoneMessage
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
  return (
    v["type"] === "inline_menu_fill_chosen" &&
    isInstanceToken(v["instanceToken"]) &&
    isBoundedString(v["itemId"], 256) &&
    typeof v["confirmedEquivalence"] === "boolean" &&
    (v["only"] === undefined || isFillOnly(v["only"])) &&
    (v["offerId"] === undefined || isOfferId(v["offerId"])) &&
    // ADR 0076 §4.2: a TOTP-only fill exists only as the answer to an offer.
    !(v["only"] === "totp" && v["offerId"] === undefined) &&
    hasOnlyKeys(v, ["type", "instanceToken", "itemId", "confirmedEquivalence", "only", "offerId"])
  );
}

export function isFillOnly(value: unknown): value is FillOnly {
  return value === "username" || value === "password" || value === "totp";
}

function hasOnlyKeys(v: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(v).every((k) => keys.includes(k));
}

/** A list of distinct custom tokens (grammar, not reserved), 1–16 long (ADR 0076 §4.4). */
function isTokenList(value: unknown): value is readonly string[] {
  return (
    Array.isArray(value) &&
    value.length >= 1 &&
    value.length <= MAX_SCOPE_TOKENS &&
    value.every((t) => isCustomToken(t)) &&
    new Set(value).size === value.length
  );
}

/** Validates a {@link FillScope} (ADR 0076 §4.4 "the scope and offer messages get the same
 * treatment"): known members only, `totp` only with a non-TOTP `only`, tokens valid, distinct
 * and at most 16, the role tokens among them. */
export function isFillScope(value: unknown): value is FillScope {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const v = value as Record<string, unknown>;
  if (!hasOnlyKeys(v, ["only", "totp", "custom", "usernameToken", "passwordToken"])) {
    return false;
  }
  if (v["only"] !== undefined && !isFillOnly(v["only"])) {
    return false;
  }
  if (v["totp"] !== undefined && (v["totp"] !== true || v["only"] === "totp")) {
    return false;
  }
  if (v["custom"] !== undefined && !isTokenList(v["custom"])) {
    return false;
  }
  const custom = (v["custom"] as readonly string[] | undefined) ?? [];
  for (const key of ["usernameToken", "passwordToken"] as const) {
    if (v[key] !== undefined && (!isCustomToken(v[key]) || !custom.includes(v[key]))) {
      return false;
    }
  }
  return true;
}

/** Validates a raw {@link InlineMenuOfferRequestMessage}; same gate as
 * {@link isInlineMenuFillRequestMessage}. */
export function isInlineMenuOfferRequestMessage(value: unknown): value is InlineMenuOfferRequestMessage {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  return (
    v["type"] === "inline_menu_offer_request" &&
    isInstanceToken(v["instanceToken"]) &&
    isFillScope(v["scope"]) &&
    hasOnlyKeys(v, ["type", "instanceToken", "scope"]) &&
    approximateSize(v) <= MAX_MESSAGE_BYTES
  );
}

/** Validates an {@link InlineMenuOfferMessage} — the iframe checks the long-lived context's
 * answer before rendering it, as every boundary bounds what it reads. */
export function isInlineMenuOfferMessage(value: unknown): value is InlineMenuOfferMessage {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  if (v["type"] !== "inline_menu_offer" || !isOfferId(v["offerId"]) || !isBoundedString(v["pageHost"], MAX_HOST_LEN)) {
    return false;
  }
  const candidates = v["candidates"];
  if (!Array.isArray(candidates) || candidates.length > MAX_CANDIDATES) {
    return false;
  }
  return candidates.every((c: unknown) => {
    if (typeof c !== "object" || c === null) {
      return false;
    }
    const cc = c as Record<string, unknown>;
    const fills = cc["customFill"];
    return (
      isBoundedString(cc["itemId"], 256) &&
      typeof cc["fillsTotp"] === "boolean" &&
      Array.isArray(fills) &&
      fills.length <= MAX_SCOPE_TOKENS &&
      fills.every(
        (f: unknown) =>
          typeof f === "object" &&
          f !== null &&
          isBoundedString((f as Record<string, unknown>)["label"], MAX_OFFER_LABEL_LEN) &&
          typeof (f as Record<string, unknown>)["concealed"] === "boolean",
      )
    );
  });
}

function approximateSize(value: unknown): number {
  try {
    return JSON.stringify(value).length;
  } catch {
    return Number.POSITIVE_INFINITY;
  }
}

/** Validates a raw message claimed to be an {@link InlineMenuGeneratePasswordRequestMessage} —
 * same gate as {@link isInlineMenuFillRequestMessage}'s own doc explains. The message carries no
 * fields beyond `type` and its `instanceToken` (ADR 0043), so there is nothing else to bound. */
export function isInlineMenuGeneratePasswordRequestMessage(value: unknown): value is InlineMenuGeneratePasswordRequestMessage {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  return v["type"] === "inline_menu_generate_password_chosen" && isInstanceToken(v["instanceToken"]);
}

/** Validates a raw message claimed to be a {@link PasskeyCeremonyMessage} — only
 * `core-host/listener.ts` calls this, and only once `isInlineMenuSender` has already vouched for
 * the sender (same gate as {@link isInlineMenuFillRequestMessage}'s own doc explains). */
export function isPasskeyCeremonyMessage(value: unknown): value is PasskeyCeremonyMessage {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  if (!isInstanceToken(v["instanceToken"]) || !isBoundedString(v["ceremonyToken"], 256)) {
    return false;
  }
  if (v["type"] === "passkey_ceremony_declined") {
    return true;
  }
  return (
    v["type"] === "passkey_ceremony_approved" &&
    (v["chosenPasskeyRef"] === undefined || isBoundedString(v["chosenPasskeyRef"], 256)) &&
    (v["vaultId"] === undefined || isVaultId(v["vaultId"]))
  );
}

/** Shared by {@link isApplyFillMessage} and {@link isRelayApplyFillMessage}: both carry the
 * exact same `values` shape (username/password by kind, never by field id), at least one of the
 * two present. */
export function isFillValues(value: unknown): value is FillValues {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const v = value as Record<string, unknown>;
  // INV-40 / ADR 0076 §4.4: at least one member, known members only, each bounded, the code
  // 6–8 digits, custom values keyed by valid, distinct, unreserved tokens, the whole under the
  // message cap. Keyed by kind and token, never by DOM field id.
  if (!hasOnlyKeys(v, ["username", "password", "totp", "custom"])) {
    return false;
  }
  if (v["username"] === undefined && v["password"] === undefined && v["totp"] === undefined && v["custom"] === undefined) {
    return false;
  }
  if (v["totp"] !== undefined && !(typeof v["totp"] === "string" && /^[0-9]{6,8}$/.test(v["totp"]))) {
    return false;
  }
  if (v["custom"] !== undefined) {
    const custom = v["custom"];
    if (!Array.isArray(custom) || custom.length < 1 || custom.length > MAX_SCOPE_TOKENS) {
      return false;
    }
    const tokens: unknown[] = [];
    for (const entry of custom as unknown[]) {
      if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
        return false;
      }
      const e = entry as Record<string, unknown>;
      if (!hasOnlyKeys(e, ["token", "value"]) || !isCustomToken(e["token"]) || !isBoundedString(e["value"], MAX_FIELD_VALUE_LEN)) {
        return false;
      }
      tokens.push(e["token"]);
    }
    if (new Set(tokens).size !== tokens.length) {
      return false;
    }
  }
  return (
    (v["password"] === undefined || isBoundedString(v["password"], MAX_FIELD_VALUE_LEN)) &&
    (v["username"] === undefined || isBoundedString(v["username"], MAX_FIELD_VALUE_LEN)) &&
    approximateSize(v) <= MAX_MESSAGE_BYTES
  );
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
  | { readonly type: "get_status" }
  /** The icon of an item's website host (ADR 0052 point 6), fetched by the core from the
   * account's server; only the hostname leaves the browser. */
  | { readonly type: "item_icon"; readonly websiteHost: string };

export interface GeneratorOptions {
  readonly kind: "password" | "passphrase";
  readonly length: number;
}

export interface ItemSummary {
  /** The item reference, `<vault hex>:<item hex>` (ADR 0081 §A7, INV-103). */
  readonly itemId: string;
  readonly title: string;
  readonly username: string;
  /** The label of the item's vault (ADR 0081 §A7: every row shows its vault). */
  readonly vault?: string;
  /** The host of the item's first website, never the full URI (for its icon). */
  readonly websiteHost?: string;
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
  /** `item_icon`'s answer: the PNG as base64 (`messaging/bytes.ts`), or `null` for none. */
  | { readonly type: "icon"; readonly png: string | null }
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
  "register_iframe_instance",
  "revoke_iframe_instance",
  "iframe_instance_done",
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
  "item_icon",
  "status",
  "enrolled",
  "unlocked",
  "locked",
  "synced",
  "items",
  "fields",
  "revealed",
  "generated",
  "icon",
  "error",
] as const;
