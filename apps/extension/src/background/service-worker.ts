// The MV3 service worker (ADR 0036 §2, §4): message-routing only. It never imports
// `@rizzy-vault/core` and holds no key material — it is only ever woken to relay a
// content-script message to the long-lived context (an offscreen document on Chromium) and
// relay the answer back. Popup/options messages skip this file entirely: `core-host/listener.ts`
// answers those directly, because both browsers keep the long-lived context reachable by
// `chrome.runtime.sendMessage` the whole time a popup can be open.
//
// On Firefox there is no separate service worker (its manifest's `background.scripts` points at
// `background-page.ts` instead, ADR 0036 §2); this file is Chromium-only.
import { webext } from "../types/runtime-api.ts";
import { MessageRejected, parseFromContentScript } from "../messaging/validate.ts";
import { SenderRejected, isContentScriptSender, trustedOriginOf } from "../messaging/sender.ts";
import type { ContentScriptForward, ToContentScript } from "../messaging/contract.ts";
import { isEnsureCoreMessage } from "./ensure-core.ts";

// Relative to the extension root (`dist/<target>/`), matching `vite.config.ts`'s output
// layout (Vite's default: an HTML entry is emitted at its path relative to the project root)
// and the path `manifest.chromium.json` loads this same document from directly.
const OFFSCREEN_URL = "src/core-host/offscreen.html";
/** The exact justification string recorded with the M2 code (ADR 0036 "Owner answers at
 * acceptance"): `WORKERS` is the closest fit the `chrome.offscreen` reason enum offers for
 * "hold a wasm instance and answer messages for the life of the browser session." */
const OFFSCREEN_JUSTIFICATION =
  "Hosts the rizzy-vault wasm core (a WebAssembly module performing cryptographic work) for " +
  "the life of the browsing session, since the MV3 service worker is torn down too often to " +
  "hold key material. Closest fit of the fixed reason enum: WORKERS.";

/** Serializes every concurrent caller behind the one in-flight creation attempt, so two callers
 * racing (e.g. a content-script message and the popup/options transport's `ensure_core` priming
 * call arriving together, or `onStartup` firing alongside either) never both see
 * `hasDocument() === false` and both call `chrome.offscreen.createDocument` — the second such
 * call throws ("Only a single offscreen document may be created"). Reset in `finally` once the
 * attempt settles (success or failure) so a later call re-checks `hasDocument()` fresh rather
 * than being permanently stuck on one outcome — idempotent on every call, not only the first. */
let offscreenCreation: Promise<void> | undefined;

export async function ensureOffscreenDocument(ext: WebExtNamespace): Promise<void> {
  const offscreen = ext.offscreen;
  if (offscreen === undefined) {
    return; // Firefox: no offscreen API, nothing to create (background page is already up).
  }
  if (offscreenCreation !== undefined) {
    return offscreenCreation;
  }
  offscreenCreation = (async () => {
    try {
      if (await offscreen.hasDocument()) {
        return;
      }
      await offscreen.createDocument({
        url: OFFSCREEN_URL,
        reasons: ["WORKERS"],
        justification: OFFSCREEN_JUSTIFICATION,
      });
    } finally {
      offscreenCreation = undefined;
    }
  })();
  return offscreenCreation;
}

const ext = webext();

// Belt-and-suspenders with `createRuntimeTransport`'s `ensure_core` priming call
// (`core/client.ts`): the offscreen document is created as soon as the extension is installed
// or the browser starts, not only on first use, so even a popup opened before either of those
// signals had a chance to matter already has a live receiver.
ext.runtime.onInstalled.addListener(() => void ensureOffscreenDocument(ext));
ext.runtime.onStartup.addListener(() => void ensureOffscreenDocument(ext));

ext.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!isContentScriptSender(sender, ext.runtime.id)) {
    // Not a genuine content script — `sender.tab` being set is not enough on its own; see
    // `isContentScriptSender`'s own comment (it is also what this extension's own pages look
    // like when a test opens one directly in a tab, e.g. the popup, instead of through
    // `chrome.action`). It's our own popup/options/offscreen talking to each other directly.
    if (isEnsureCoreMessage(message)) {
      // The popup/options transport's priming call (`core/client.ts`): make sure the offscreen
      // document exists, then answer, so the caller's very next `sendMessage` has somewhere to
      // land even on a profile where neither `onInstalled` nor `onStartup` fired yet in this
      // browser session (e.g. the extension was already running when Playwright attached).
      void ensureOffscreenDocument(ext).then(() => sendResponse({ type: "core_ready" }));
      return true;
    }
    // Not `ensure_core` either: nothing for the router to do.
    return undefined;
  }
  void (async () => {
    let trustedOrigin: string;
    let validated;
    try {
      trustedOrigin = trustedOriginOf(sender, ext.runtime.id);
      validated = parseFromContentScript(message);
    } catch (e) {
      const code = e instanceof SenderRejected || e instanceof MessageRejected ? e.message : "rejected";
      sendResponse({ type: "content_error", code } satisfies ToContentScript);
      return;
    }
    await ensureOffscreenDocument(ext);
    const forward: ContentScriptForward = { type: "cs_request", message: validated, trustedOrigin };
    const response = await ext.runtime.sendMessage(forward);
    sendResponse(response);
  })();
  return true; // async sendResponse above.
});
