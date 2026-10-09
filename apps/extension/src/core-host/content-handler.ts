// Handles a content-script request forwarded by the service worker (ADR 0036 §4, ADR 0037 §1:
// "matching... runs in the background/long-lived context"), and — separately —
// {@link handleInlineMenuFillRequest}'s own privileged request from the inline-menu iframe
// (ADR 0040; `core-host/listener.ts` routes to it, never through
// `handleContentScriptRequest`). This module runs inside the offscreen document / background
// page, alongside `core-context.ts`, and is the one place that calls `@rizzy-vault/core`'s
// `decideMatchCandidates` (via `core-context.ts`'s `matchCandidatesFor`) — never the content
// script itself, and never the service worker (ADR 0037 §1 puts matching in `rizzy-match`,
// reached only from here).
import {
  approvePasskeyCeremony,
  checkPendingSavePromptByLocation,
  declinePasskeyCeremony,
  itemSummaryFor,
  matchCandidatesFor,
  offerPasskeyCreate,
  offerPasskeyGet,
  offerSavePrompt,
  resolveSavePrompt,
  revealCredentialsForFill,
} from "./core-context.ts";
import type {
  ApplyFillMessage,
  ApplyPasskeyResultMessage,
  ContentErrorMessage,
  FromContentScript,
  InlineMenuFillRequestMessage,
  InlineMenuFillResponse,
  PasskeyCeremonyMessage,
  PasskeyCeremonyResponse,
  RelayApplyFillMessage,
  RelayPasskeyResultMessage,
  ToContentScript,
} from "../messaging/contract.ts";
import type { MatchCandidate } from "./bindings.ts";

/** The one COSE algorithm id this project can create a credential for today (ADR 0039 §3: ES256
 * is approved — ADR 0041 — EdDSA is approved but `createPasskey` only ever produces ES256). A
 * `create` request whose `pubKeyCredParams` lists neither is refused here, a second check behind
 * `passkey-relay.ts`'s own pre-filter (module docs there): defence in depth, never the only
 * gate. */
const COSE_ALG_ES256 = -7;

/**
 * Whether `origin` satisfies INV-64's "the origin is HTTPS" (checked here too, not only inside
 * `createPasskey`/`DurableSession.passkeyAssertion`'s own Rust check at approval time — refusing
 * before a consent prompt is even shown is strictly more honest than showing one for a ceremony
 * that could never succeed). Literally `https:` only, matching `rizzy-client::passkey::
 * verify_rp_id`'s own gate exactly (`origin.scheme() != Scheme::Https` → `RpIdRejected`, no
 * exception for `localhost`/loopback there) — this layer must never be more permissive than the
 * Rust layer it is a cheap pre-check for, or a user could be shown a consent prompt whose
 * approval always fails downstream. The E2E test suite (`e2e/passkey.spec.ts`) serves its test
 * page over real (self-signed) HTTPS for exactly this reason, rather than this project adding a
 * localhost exception neither ADR 0039 nor the already-committed Rust layer makes.
 */
function isSecureOrigin(origin: string): boolean {
  return origin.startsWith("https://");
}

/**
 * Pushes {@link ApplyFillMessage} to `tabId`'s own content script. Not always a direct
 * `ext.tabs.sendMessage`: a `chrome.offscreen` document (Chromium's long-lived context) has no
 * `chrome.tabs` access at all — a real `TypeError`, found empirically fixing this change, not
 * merely inferred — so there, this relays through the MV3 service worker instead
 * ({@link RelayApplyFillMessage}; `background/service-worker.ts`'s own handler for it), which
 * does have `tabs` like every other extension page. Firefox's `background-page.ts` has `tabs`
 * directly and takes the first branch, same as any other context that has it.
 */
async function pushApplyFill(ext: WebExtNamespace, tabId: number, values: { readonly username?: string; readonly password: string }): Promise<void> {
  if (ext.tabs !== undefined) {
    await ext.tabs.sendMessage(tabId, { type: "apply_fill", values } satisfies ApplyFillMessage);
    return;
  }
  await ext.runtime.sendMessage({ type: "relay_apply_fill", tabId, values } satisfies RelayApplyFillMessage);
}

/** {@link pushApplyFill}'s exact pattern, for a passkey ceremony's result (ADR 0039 §2;
 * `messaging/contract.ts`'s `ApplyPasskeyResultMessage`/`RelayPasskeyResultMessage`). */
async function pushApplyPasskeyResult(ext: WebExtNamespace, tabId: number, msg: Omit<ApplyPasskeyResultMessage, "type">): Promise<void> {
  if (ext.tabs !== undefined) {
    await ext.tabs.sendMessage(tabId, { type: "apply_passkey_result", ...msg } satisfies ApplyPasskeyResultMessage);
    return;
  }
  await ext.runtime.sendMessage({ type: "relay_passkey_result", tabId, ...msg } satisfies RelayPasskeyResultMessage);
}

/**
 * Whether `pageUrl` (the content script's own, untrusted claim) is consistent with
 * `trustedOrigin` (derived by the caller from `sender.tab.url`/`sender.origin`, never from the
 * message body). A compromised or buggy content script is exactly the threat `validate.ts`'s
 * own comment names for this field: it must never be trusted for the sender's actual origin.
 */
function pageUrlMatchesSender(pageUrl: string, trustedOrigin: string): boolean {
  try {
    return new URL(pageUrl).origin === trustedOrigin;
  } catch {
    return false;
  }
}

/**
 * `trustedOrigin` is the page origin the service worker (Chromium) or this listener (Firefox)
 * derived from `sender.tab.url`/`sender.origin` (`sender.ts`), never from `message.pageUrl`.
 * Every branch that would otherwise hand `message.pageUrl` onward first checks it against
 * `trustedOrigin` and refuses the request outright on a mismatch (`pageUrlMatchesSender`), so a
 * compromised content script can never claim an origin the sender-validation step did not
 * itself vouch for (THREAT_MODEL.md row 2, "a compromised/malicious content script"). The full
 * `pageUrl` — not just the origin — is still what reaches matching once it passes that check,
 * because ADR 0037 §4's *Starts with* and *Regex* match modes need the path, not only the host.
 */
export async function handleContentScriptRequest(
  message: FromContentScript,
  trustedOrigin: string,
  trustedTabId?: number,
): Promise<ToContentScript> {
  switch (message.type) {
    case "fields_detected": {
      if (!pageUrlMatchesSender(message.pageUrl, trustedOrigin)) {
        return { type: "content_error", code: "fields_detected: pageUrl does not match the sender's own origin" };
      }
      const result = matchCandidatesFor(message.pageUrl, { isTopFrame: message.isTopFrame, frameOrigin: trustedOrigin });
      if (result === undefined) {
        return refused("fields_detected: the device is locked");
      }
      // The match decision itself only ever carries `itemId`/`uriId`/`needsWarning` (never a
      // secret, ADR 0013 §3 rule 3); title/username for display come from one `item()` lookup
      // per candidate here. A candidate whose item vanished between the match and this lookup
      // (e.g. deleted mid-request) is dropped rather than shown blank.
      const candidates = result.candidates.flatMap((c) => {
        const summary = itemSummaryFor(c.itemId);
        return summary === undefined ? [] : [{ itemId: c.itemId, ...summary, needsWarning: c.needsWarning }];
      });
      return { type: "candidates", candidates, warnings: result.warnings };
    }
    case "credentials_submitted": {
      if (!pageUrlMatchesSender(message.pageUrl, trustedOrigin)) {
        return { type: "content_error", code: "credentials_submitted: pageUrl does not match the sender's own origin" };
      }
      const offer = offerSavePrompt(message.pageUrl, message.usernameValue, message.passwordValue, trustedTabId);
      if (offer === undefined) {
        return refused("credentials_submitted: the device is locked, or nothing worth saving was captured");
      }
      return { type: "save_prompt", ...offer };
    }
    case "save_prompt_resolved": {
      const resolved = await resolveSavePrompt(message.token, message.action);
      if (!resolved) {
        return { type: "content_error", code: "save_prompt_resolved: unknown or already-resolved token" };
      }
      return { type: "save_prompt_done" };
    }
    case "check_save_prompt": {
      // No `pageUrlMatchesSender` check here, deliberately: this message's only input is the
      // page to check, and `checkPendingSavePromptByLocation` itself derives the registrable
      // domain from exactly this `pageUrl` — there is no *other*, trusted value to compare it
      // against the way `trustedOrigin` lets every other handler catch a lying content script.
      // The worst a compromised content script gains by claiming a different `pageUrl` here is
      // asking for a pending offer keyed to a domain it is not actually on, which the location
      // index (keyed by the browser-vouched `trustedTabId` too) would not have put there for
      // this tab in the first place unless a real submit on a page of that same domain, in this
      // same tab, already happened.
      const offer = checkPendingSavePromptByLocation(trustedTabId, message.pageUrl);
      return offer === undefined ? { type: "no_pending_save_prompt" } : { type: "save_prompt", ...offer };
    }
    case "passkey_create_request": {
      if (!pageUrlMatchesSender(message.pageUrl, trustedOrigin) || trustedTabId === undefined) {
        return refused("passkey_create_request: pageUrl does not match the sender's own origin");
      }
      if (!isSecureOrigin(trustedOrigin)) {
        return refused("passkey_create_request: origin is not https");
      }
      if (!message.algs.includes(COSE_ALG_ES256)) {
        return refused("passkey_create_request: no ES256 in pubKeyCredParams");
      }
      const offer = offerPasskeyCreate(
        trustedOrigin,
        trustedTabId,
        message.rpIdHint,
        message.rpName,
        message.userIdB64,
        message.userName,
        message.userDisplayName,
        message.challengeB64,
      );
      if (offer === undefined) {
        return refused("passkey_create_request: the device is locked");
      }
      return { type: "passkey_offer", ceremonyToken: offer.ceremonyToken, kind: "create", rpId: offer.rpId, rpName: offer.rpName, userName: offer.userName };
    }
    case "passkey_get_request": {
      if (!pageUrlMatchesSender(message.pageUrl, trustedOrigin) || trustedTabId === undefined) {
        return refused("passkey_get_request: pageUrl does not match the sender's own origin");
      }
      if (!isSecureOrigin(trustedOrigin)) {
        return refused("passkey_get_request: origin is not https");
      }
      const offer = offerPasskeyGet(trustedOrigin, trustedTabId, message.rpIdHint, message.challengeB64);
      if (offer === undefined) {
        return refused("passkey_get_request: the device is locked, or no stored passkey matches this rpId");
      }
      return { type: "passkey_offer", ceremonyToken: offer.ceremonyToken, kind: "get", rpId: offer.rpId, candidates: offer.candidates };
    }
  }
}

/**
 * Handles a {@link PasskeyCeremonyMessage} from the passkey consent iframe
 * (`core-host/listener.ts` routes to this only once `sender.ts`'s `isInlineMenuSender` has
 * vouched for the sender — the same gate {@link handleInlineMenuFillRequest} uses, module docs
 * on why it is reused as-is). Always pushes an {@link ApplyPasskeyResultMessage} to the tab that
 * hosted the consent UI, `"ok"` or `"fallback"` (never nothing: `passkey-relay.ts`'s own pending
 * shim promise would otherwise hang until its own timeout, ADR 0039 §2's "Decline, timeout or no
 * match" rule), and answers the iframe itself with only an acknowledgement — never the result
 * (ADR 0040's "never back to the iframe," applied here too).
 */
export async function handlePasskeyCeremonyApproval(
  ext: WebExtNamespace,
  tabId: number,
  tabUrl: string,
  message: PasskeyCeremonyMessage,
): Promise<PasskeyCeremonyResponse> {
  let origin: string;
  try {
    origin = new URL(tabUrl).origin;
  } catch {
    return refused("passkey_ceremony: the sender's tab URL does not parse");
  }
  if (message.type === "passkey_ceremony_declined") {
    declinePasskeyCeremony(message.ceremonyToken, tabId, origin);
    await pushApplyPasskeyResult(ext, tabId, { ceremonyToken: message.ceremonyToken, outcome: "fallback" });
    return { type: "passkey_ceremony_dispatched" };
  }
  const result = await approvePasskeyCeremony(message.ceremonyToken, tabId, origin, message.chosenPasskeyRef);
  await pushApplyPasskeyResult(
    ext,
    tabId,
    result === undefined
      ? { ceremonyToken: message.ceremonyToken, outcome: "fallback" }
      : { ceremonyToken: message.ceremonyToken, outcome: "ok", result },
  );
  return { type: "passkey_ceremony_dispatched" };
}

function refused(reason: string): ContentErrorMessage {
  return { type: "content_error", code: reason };
}

/**
 * The candidate-membership and equivalence-confirmation decision for an
 * {@link InlineMenuFillRequestMessage} (the fix for a real vulnerability: the previous code
 * revealed any item's credentials for any claimed `itemId`, with no check at all that it was
 * even a match for the sender's own page). Pure and synchronous — no session, no I/O — so it is
 * unit-testable with a plain fabricated `candidates` array, independent of whether a real
 * `DurableSession` is unlocked. `candidates` must already be freshly recomputed against the
 * sender's own, browser-vouched `sender.tab.url` ({@link handleInlineMenuFillRequest}); this
 * function never itself re-derives or re-checks the origin, only membership within whatever
 * list it is given.
 */
export function selectFillCandidate(
  candidates: readonly MatchCandidate[],
  itemId: string,
  confirmedEquivalence: boolean,
): { readonly ok: true } | { readonly ok: false; readonly code: string } {
  const candidate = candidates.find((c) => c.itemId === itemId);
  if (candidate === undefined) {
    return { ok: false, code: "inline_menu_fill_chosen: itemId is not a current candidate for this tab" };
  }
  if (candidate.needsWarning && !confirmedEquivalence) {
    // ADR 0037 §5: re-checked here, not only trusted from `src/inline-menu/main.ts`'s own UI
    // (which already requires a second click before it ever sends `confirmedEquivalence: true`)
    // — defence in depth in case that UI is ever bypassed or this message is ever reachable
    // some other way.
    return { ok: false, code: "inline_menu_fill_chosen: equivalence-only candidate needs confirmedEquivalence" };
  }
  return { ok: true };
}

/**
 * Handles an {@link InlineMenuFillRequestMessage} from the inline-menu iframe
 * (`core-host/listener.ts` routes to this only once `sender.ts`'s `isInlineMenuSender` has
 * vouched for the sender, and only ever with that sender's own real `tabId`/`tabUrl` — never
 * anything the message itself claims, since this message carries no URL at all). Re-derives the
 * candidate list fresh from `tabUrl` ({@link selectFillCandidate} never trusts a cached one),
 * and on success pushes the revealed values straight to that tab's content script
 * ({@link ApplyFillMessage} via {@link pushApplyFill}) — never back to the iframe that asked
 * (ADR 0040: "only the chosen fill's values cross... the content script
 * performs the actual DOM write").
 */
export async function handleInlineMenuFillRequest(
  ext: WebExtNamespace,
  tabId: number,
  tabUrl: string,
  message: InlineMenuFillRequestMessage,
): Promise<InlineMenuFillResponse> {
  let origin: string;
  try {
    origin = new URL(tabUrl).origin;
  } catch {
    return refused("inline_menu_fill_chosen: the sender's tab URL does not parse");
  }
  const result = matchCandidatesFor(tabUrl, { isTopFrame: true, frameOrigin: origin });
  if (result === undefined) {
    return refused("inline_menu_fill_chosen: the device is locked");
  }
  const selection = selectFillCandidate(result.candidates, message.itemId, message.confirmedEquivalence);
  if (!selection.ok) {
    return refused(selection.code);
  }
  const values = revealCredentialsForFill(message.itemId);
  if (values === undefined) {
    return refused("inline_menu_fill_chosen: the device is locked");
  }
  await pushApplyFill(ext, tabId, values);
  return { type: "inline_menu_fill_dispatched" };
}
