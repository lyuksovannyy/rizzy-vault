// The one `onMessage` listener both the offscreen document and the Firefox background page
// register (ADR 0036 §2, §4). On Chromium, a real content-script message (`sender.tab` set) is
// ignored here: the service worker is the only Chromium context that accepts those
// (`background/service-worker.ts`), validates them, and forwards a {@link ContentScriptForward}
// to this listener with `sender.tab` unset (the forward is itself sent by the service worker, an
// extension page). On Firefox there is no separate service worker — `background-page.ts` *is*
// the long-lived context — so this listener must validate and handle a raw content-script
// message itself there; `acceptContentScripts` tells it which mode it is running in, set by each
// browser-specific bootstrap (`offscreen.ts`: `false`; `background-page.ts`: `true`). Giving
// Chromium's offscreen document `acceptContentScripts: true` too would double-handle every
// content-script message (this listener directly, and again via the service worker's forward),
// racing two independent `handleContentScriptRequest` calls against one `sendResponse` — never
// do that.
//
// Popup/options messages (`sender.tab` undefined, `sender.id` equal to this extension's own id,
// `isOwnExtensionPage`) are answered the same way on both browsers.
//
// The inline-menu iframe (`src/inline-menu/main.ts`) is a fourth, separate sender (ADR 0040):
// `sender.tab` IS set (it is embedded inside a real page), but `sender.origin` is
// this extension's own, not that page's — `isInlineMenuSender` (`messaging/sender.ts`) is what
// tells it apart from a real content script, which a compromised content script cannot ever
// satisfy (the browser sets `sender.origin`, not any script). This is the one sender allowed to
// request a decrypted item's credentials directly, and the one place that check runs.
import {
  extensionOriginOf,
  isContentScriptSender,
  isInlineMenuSender,
  isOwnExtensionPage,
  SenderRejected,
  trustedOriginOf,
} from "../messaging/sender.ts";
import { MessageRejected, parseFromContentScript } from "../messaging/validate.ts";
import { isInlineMenuFillRequestMessage, isInlineMenuGeneratePasswordRequestMessage, isPasskeyCeremonyMessage } from "../messaging/contract.ts";
import type { ContentScriptForward, PopupRequest, PopupResponse, ToContentScript } from "../messaging/contract.ts";
import {
  handleContentScriptRequest,
  handleInlineMenuFillRequest,
  handleInlineMenuGeneratePasswordRequest,
  handlePasskeyCeremonyApproval,
} from "./content-handler.ts";
import { handlePopupRequest, lockFromIdleState, startCoreContext } from "./core-context.ts";
import { DEFAULT_AUTO_LOCK_MS } from "./lifecycle.ts";

function isPopupRequest(value: unknown): value is PopupRequest {
  if (typeof value !== "object" || value === null || !("type" in value)) {
    return false;
  }
  const type = (value as { type: unknown }).type;
  return (
    type === "enrol" ||
    type === "unlock" ||
    type === "lock" ||
    type === "sync" ||
    type === "list_items" ||
    type === "item_fields" ||
    type === "reveal_field" ||
    type === "generate_password" ||
    type === "get_status"
  );
}

function isContentScriptForward(value: unknown): value is ContentScriptForward {
  return typeof value === "object" && value !== null && (value as { type?: unknown }).type === "cs_request";
}

export interface InstallCoreContextListenerOptions {
  /** `true` only on the one browser build where this listener is the sole context that ever
   * sees a raw content-script message (Firefox: no service worker exists to validate and
   * forward one). `false` on Chromium, where `background/service-worker.ts` already does that
   * job and forwards the result as a {@link ContentScriptForward} — accepting raw content-script
   * senders here too would process every one of them twice. */
  readonly acceptContentScripts: boolean;
}

/** Registers the listener and starts the core context. Called once by `offscreen.ts` and
 * `background-page.ts`, the only difference between them (besides `acceptContentScripts`) being
 * how each browser creates this context (`chrome.offscreen` vs. a plain `background.scripts`
 * entry, ADR 0036 §2).
 *
 * The `ext.runtime.onMessage.addListener` call below is the FIRST statement this function runs,
 * deliberately, and nothing before it can throw: measured empirically against a real Chromium
 * build (not documented in Chrome's own API reference at the time of writing), a
 * `chrome.offscreen` document's `chrome` object has no `idle` or `storage` namespace at all —
 * both are `undefined`, unlike every other extension page. The previous ordering called
 * `ext.idle.setDetectionInterval` *before* registering this listener, so that `TypeError` (`"Cannot
 * read properties of undefined (reading 'setDetectionInterval')"`) aborted this function before
 * the listener was ever installed — every popup/options/content-script message landed in a
 * context with nothing listening, and `ext.runtime.sendMessage` resolved to `undefined` forever
 * (finding (4)/(5)'s underlying cause, deeper than the offscreen-document-creation race
 * `background/service-worker.ts`'s `ensureOffscreenDocument` already guards: the document existed
 * the whole time, but its own message handling never came up). Most conservative reading, per
 * CLAUDE.md: feature-detect `ext.idle`/`ext.storage` and degrade (no idle-triggered lock; no
 * `storage.session` fallback; the options page's auto-lock minutes read as the default) rather
 * than assume either exists, while the core messaging contract above never depends on either. */
export function installCoreContextListener(ext: WebExtNamespace, options: InstallCoreContextListenerOptions): void {
  const extensionOrigin = extensionOriginOf(ext);
  ext.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (isContentScriptSender(sender, ext.runtime.id)) {
      // A real content script (ADR 0036 §4, INV-40: never trusted by shape alone) — not merely
      // "`sender.tab` is set," which one of our own pages can also show when opened directly in
      // a tab (`isContentScriptSender`'s own comment). On Chromium this listener must not touch
      // a real content-script message at all — `background/service-worker.ts` owns validation
      // there and forwards the result as a `cs_request` (handled below, where `sender.tab` is
      // unset again because the forward comes from an extension page).
      if (!options.acceptContentScripts) {
        return undefined;
      }
      try {
        const trustedOrigin = trustedOriginOf(sender, ext.runtime.id);
        const validated = parseFromContentScript(message);
        void handleContentScriptRequest(validated, trustedOrigin, sender.tab?.id).then(sendResponse);
      } catch (e) {
        const code = e instanceof SenderRejected || e instanceof MessageRejected ? e.message : "rejected";
        sendResponse({ type: "content_error", code } satisfies ToContentScript);
      }
      return true; // keeps the channel open for the async `sendResponse` above.
    }
    if (isInlineMenuSender(sender, ext.runtime.id, extensionOrigin)) {
      // ADR 0040: the inline-menu iframe, not the content script, asks for a
      // fill directly — the one sender this grants a decrypted credential to. `sender.tab.id`/
      // `.url` are the browser's own, for the real tab hosting the iframe; never anything the
      // message itself could claim (it carries no URL at all — see
      // `InlineMenuFillRequestMessage`'s own doc for why). The passkey consent iframe
      // (`passkey-consent/main.ts`) is a second, separate extension-origin iframe that reaches
      // this exact same sender class — `messaging/contract.ts`'s `PasskeyCeremonyApprovedMessage`
      // doc explains why `isInlineMenuSender` is reused as-is rather than duplicated.
      const tabId = sender.tab?.id;
      const tabUrl = sender.tab?.url;
      if (tabId === undefined || tabUrl === undefined) {
        sendResponse({ type: "content_error", code: "inline_menu_sender: no tab" } satisfies ToContentScript);
        return true;
      }
      if (isPasskeyCeremonyMessage(message)) {
        void handlePasskeyCeremonyApproval(ext, tabId, tabUrl, message)
          .then(sendResponse)
          .catch(() => sendResponse({ type: "content_error", code: "passkey_ceremony: failed" } satisfies ToContentScript));
        return true;
      }
      if (isInlineMenuGeneratePasswordRequestMessage(message)) {
        // Gap 32 in the M2 gap audit: the same trusted-click/never-back-to-the-iframe pattern
        // as the fill request just above, for the generator instead of a saved item's
        // credentials — see `handleInlineMenuGeneratePasswordRequest`'s own doc.
        void handleInlineMenuGeneratePasswordRequest(ext, tabId, tabUrl)
          .then(sendResponse)
          .catch(() => sendResponse({ type: "content_error", code: "inline_menu_generate_password_chosen: failed" } satisfies ToContentScript));
        return true;
      }
      if (!isInlineMenuFillRequestMessage(message)) {
        sendResponse({ type: "content_error", code: "inline_menu_fill_chosen: malformed request" } satisfies ToContentScript);
        return true;
      }
      // `.catch` here, not left to an unhandled rejection: unlike the content-script branch
      // above, `handleInlineMenuFillRequest` has no internal `try`/`catch` of its own around
      // `pushApplyFill`'s tab push, which can reject (e.g. the tab navigated away or closed
      // between the click and this response). Without this, `sendResponse` would simply never
      // be called on that path, and the iframe's own `sendMessage` call would hang forever
      // rather than settle with a refusal — found exactly this way fixing this change, when an
      // earlier, unrelated bug (ADR 0040: `chrome.tabs` is unavailable inside a
      // `chrome.offscreen` document, see `types/webext.d.ts`) produced the identical symptom.
      void handleInlineMenuFillRequest(ext, tabId, tabUrl, message)
        .then(sendResponse)
        .catch(() => sendResponse({ type: "content_error", code: "inline_menu_fill_chosen: failed" } satisfies ToContentScript));
      return true; // keeps the channel open for the async `sendResponse` above.
    }
    if (!isOwnExtensionPage(sender, ext.runtime.id)) {
      return undefined;
    }
    if (isContentScriptForward(message)) {
      void handleContentScriptRequest(message.message, message.trustedOrigin, message.trustedTabId).then(
        (response: ToContentScript) => sendResponse(response),
      );
      return true;
    }
    if (isPopupRequest(message)) {
      void handlePopupRequest(ext, message).then((response: PopupResponse) => sendResponse(response));
      return true; // keeps the message channel open for the async `sendResponse` above.
    }
    return undefined;
  });

  // ADR 0036 §3: "lock on `chrome.idle`/`browser.idle` reaching `locked` or `idle`" — the
  // system-idle/screen-lock half of auto-lock, alongside `AutoLockTimer`'s own
  // message-activity-based timeout (`core-context.ts`). The detection interval is the same
  // threshold as the timeout, in seconds (the API's minimum unit; most platforms floor this at
  // 15s regardless of what is requested). Feature-detected, not assumed (see this function's own
  // doc comment): skipped entirely where `ext.idle` does not exist, a real, reported residual —
  // the timeout-based `AutoLockTimer` alone still locks on inactivity either way.
  if (ext.idle !== undefined) {
    ext.idle.setDetectionInterval(Math.max(15, Math.round(DEFAULT_AUTO_LOCK_MS / 1000)));
    ext.idle.onStateChanged.addListener((state) => {
      if (state === "idle" || state === "locked") {
        void lockFromIdleState(ext);
      }
    });
  }
  void startCoreContext(ext);
}
