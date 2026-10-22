// SPDX-License-Identifier: AGPL-3.0-only

// The passkey relay content script (ADR 0039 §2; THREAT_MODEL A7's "Passkey provider" section):
// a SEPARATE content-script entry from `content-script.ts` (not folded into it), registered at
// `document_start` (`manifest.*.json`) rather than `document_idle` — a page can call
// `navigator.credentials.create/get` the instant its own first script runs, long before
// `content-script.ts`'s own `document_idle` fields-detection pass would ever install, so the
// page-world shim (`passkey-page-shim.ts`) must already be in place by then. Injected as a
// `<script src="...">` web-accessible resource, not a manifest `content_scripts.world: "MAIN"`
// entry: that key needs a newer engine version than this project's own Firefox floor
// (`manifest.firefox.json`'s `strict_min_version`) reliably supports, where the script-tag
// injection this file does instead works identically on both targets and has shipped in this
// project's inline-menu/content-script split since M2's first commit.
//
// This file never imports `@rizzy-vault/core` (same `eslint.config.mjs` restriction
// `content-script.ts` is under) and never fills, saves, or reveals anything itself: every
// security decision is the long-lived context's (`core-host/content-handler.ts`), reached only
// through `chrome.runtime.sendMessage`/`onMessage`, same as every other content-script message.
import {
  isApplyPasskeyResultMessage,
  type ApplyPasskeyResultMessage,
  type FromContentScript,
  type PasskeyCreateRequestMessage,
  type PasskeyGetRequestMessage,
  type ToContentScript,
} from "../messaging/contract.ts";
import {
  PASSKEY_PAGE_RESPONSE,
  isPasskeyRequestFromPage,
  type PasskeyRequestFromPage,
  type PasskeyResponseToPage,
} from "./passkey-protocol.ts";
import { mintInstanceToken } from "./instance-token.ts";
import { PASSKEY_CONSENT_SHOW, isPasskeyConsentDoneMessage, type PasskeyConsentShowMessage } from "../passkey-consent/protocol.ts";

if (window.top === window) {
  installPasskeyRelay();
}

function installPasskeyRelay(): void {
  injectPageShim();

  /** `ceremonyToken` (the background's own id for a pending consent prompt) -> the page-world
   * shim's own request `nonce`, so {@link onApplyPasskeyResult} can answer the right pending
   * page promise once the background pushes a final result — the two ids are deliberately kept
   * distinct (`messaging/contract.ts`'s `PasskeyOfferMessage` doc): the background mints and
   * owns `ceremonyToken`; the page-world shim mints and owns `nonce`; this map is the one place
   * that ties them together, and the only state this file keeps about an in-flight ceremony. */
  const nonceByCeremonyToken = new Map<string, string>();
  /** The one consent iframe currently shown, and the teardown that removes it AND revokes its
   * ADR 0043 instance token — every removal path goes through `teardown`, never a bare
   * `frame.remove()`, so no token outlives the iframe it was minted for. */
  let consent: { readonly frame: HTMLIFrameElement; readonly teardown: () => void } | undefined;

  window.addEventListener("message", (event) => {
    if (event.source !== window || !isPasskeyRequestFromPage(event.data)) {
      return;
    }
    void handlePageRequest(event.data);
  });

  async function handlePageRequest(request: PasskeyRequestFromPage): Promise<void> {
    const forward: PasskeyCreateRequestMessage | PasskeyGetRequestMessage =
      request.kind === "create"
        ? {
            type: "passkey_create_request",
            pageUrl: location.href,
            ...(request.rpIdHint !== undefined ? { rpIdHint: request.rpIdHint } : {}),
            rpName: request.rpName,
            userIdB64: request.userIdB64,
            userName: request.userName,
            userDisplayName: request.userDisplayName,
            challengeB64: request.challengeB64,
            algs: request.algs,
          }
        : {
            type: "passkey_get_request",
            pageUrl: location.href,
            ...(request.rpIdHint !== undefined ? { rpIdHint: request.rpIdHint } : {}),
            challengeB64: request.challengeB64,
            allowCredentialIdsB64: request.allowCredentialIdsB64,
          };
    const answer = await sendToBackground(forward);
    if (answer?.type !== "passkey_offer") {
      replyToPage({ type: PASSKEY_PAGE_RESPONSE, nonce: request.nonce, outcome: "fallback" });
      return;
    }
    nonceByCeremonyToken.set(answer.ceremonyToken, request.nonce);
    showConsent({
      type: PASSKEY_CONSENT_SHOW,
      pageOrigin: location.origin,
      ceremonyToken: answer.ceremonyToken,
      kind: answer.kind,
      rpId: answer.rpId,
      ...(answer.rpName !== undefined ? { rpName: answer.rpName } : {}),
      ...(answer.userName !== undefined ? { userName: answer.userName } : {}),
      ...(answer.candidates !== undefined ? { candidates: answer.candidates } : {}),
    });
  }

  function showConsent(offer: Omit<PasskeyConsentShowMessage, "instanceToken">): void {
    consent?.teardown();
    // ADR 0043 points 1-2: one token per consent-iframe instance, minted and registered before
    // `src` is set below. Delivered only in the targeted show `postMessage` (point 3), and only
    // once the background has confirmed the registration, so the iframe can never hold a token
    // the background does not yet vouch for. A refused registration shows nothing and falls the
    // page back to its own native ceremony, exactly like any other refusal here.
    const instanceToken = mintInstanceToken();
    const registered = sendToBackground({ type: "register_iframe_instance", instanceToken }).then(
      (answer) => answer?.type === "iframe_instance_done",
      () => false,
    );
    let tornDown = false;
    const frame = document.createElement("iframe");
    frame.setAttribute("data-rizzy-passkey-consent", "");
    frame.style.position = "fixed";
    frame.style.top = "16px";
    frame.style.right = "16px";
    frame.style.width = "320px";
    frame.style.height = "160px";
    frame.style.border = "0";
    frame.style.zIndex = "2147483647";
    const menuOrigin = extensionOrigin();
    frame.addEventListener(
      "load",
      () => {
        void registered.then((ok) => {
          if (ok && !tornDown) {
            frame.contentWindow?.postMessage({ ...offer, instanceToken } satisfies PasskeyConsentShowMessage, menuOrigin);
          }
        });
      },
      { once: true },
    );
    // ADR 0043 point 5: the consent iframe's teardown revokes its token. Sent only once the
    // registration itself has settled, so the revoke can never overtake it at the background.
    const teardown = (): void => {
      if (tornDown) {
        return;
      }
      tornDown = true;
      window.removeEventListener("message", onMessage);
      frame.remove();
      if (consent?.frame === frame) {
        consent = undefined;
      }
      void registered.then(() => sendToBackground({ type: "revoke_iframe_instance", instanceToken })).catch(() => undefined);
    };
    const onMessage = (event: MessageEvent) => {
      if (event.source !== frame.contentWindow || event.origin !== menuOrigin || !isPasskeyConsentDoneMessage(event.data)) {
        return;
      }
      teardown();
    };
    window.addEventListener("message", onMessage);
    void registered.then((ok) => {
      if (ok || tornDown) {
        return;
      }
      teardown();
      const nonce = nonceByCeremonyToken.get(offer.ceremonyToken);
      if (nonce !== undefined) {
        nonceByCeremonyToken.delete(offer.ceremonyToken);
        replyToPage({ type: PASSKEY_PAGE_RESPONSE, nonce, outcome: "fallback" });
      }
    });
    // `src` set before attaching, same documented ordering fix `content-script.ts`'s own
    // `InlineMenu` constructor uses, and for the identical reason (a detached iframe's first
    // `src` assignment queues exactly one navigation, avoiding the double-`load` race that
    // ordering fixed there).
    frame.src = consentUrl();
    document.body.appendChild(frame);
    consent = { frame, teardown };
  }

  const ext = typeof chrome !== "undefined" ? chrome : browser;
  ext?.runtime.onMessage.addListener((message) => {
    if (!isApplyPasskeyResultMessage(message)) {
      return undefined;
    }
    onApplyPasskeyResult(message);
    return undefined;
  });

  function onApplyPasskeyResult(message: ApplyPasskeyResultMessage): void {
    const nonce = nonceByCeremonyToken.get(message.ceremonyToken);
    if (nonce === undefined) {
      return;
    }
    nonceByCeremonyToken.delete(message.ceremonyToken);
    const response: PasskeyResponseToPage =
      message.outcome === "ok" && message.result !== undefined
        ? { type: PASSKEY_PAGE_RESPONSE, nonce, outcome: "ok", result: message.result }
        : { type: PASSKEY_PAGE_RESPONSE, nonce, outcome: "fallback" };
    replyToPage(response);
    // The consent iframe tears itself down on settling (its own `respond`'s teardown message),
    // but a result can arrive before that message's own round trip completes — removing it here
    // too is idempotent (`showConsent`'s `teardown` runs once per frame) and makes sure the
    // overlay, and its ADR 0043 instance token, never outlive the ceremony they were for.
    consent?.teardown();
  }

  function replyToPage(response: PasskeyResponseToPage): void {
    window.postMessage(response, window.location.origin);
  }
}

function sendToBackground(message: FromContentScript): Promise<ToContentScript | undefined> {
  const ext = typeof chrome !== "undefined" ? chrome : browser;
  if (ext === undefined) {
    return Promise.resolve(undefined);
  }
  return ext.runtime.sendMessage(message).then((r) => r as ToContentScript | undefined);
}

function injectPageShim(): void {
  const ext = typeof chrome !== "undefined" ? chrome : browser;
  if (ext === undefined) {
    return;
  }
  const script = document.createElement("script");
  script.src = ext.runtime.getURL("src/content/passkey-page-shim.js");
  // Removed once it has run its one job (installing the shim): the element itself carries no
  // further purpose, and leaving it in the DOM is only a cosmetic residue a page's own inspector
  // would otherwise show. The page-world code it loaded keeps running regardless — removing the
  // `<script>` element does not undo the global assignments it already made.
  script.addEventListener("load", () => script.remove());
  (document.head ?? document.documentElement).appendChild(script);
}

function extensionOrigin(): string {
  const ext = typeof chrome !== "undefined" ? chrome : browser;
  if (ext === undefined) {
    throw new Error("passkey-relay: no WebExtension runtime (chrome/browser) in this content script");
  }
  return new URL(ext.runtime.getURL("")).origin;
}

function consentUrl(): string {
  const ext = typeof chrome !== "undefined" ? chrome : browser;
  if (ext === undefined) {
    throw new Error("passkey-relay: no WebExtension runtime (chrome/browser) in this content script");
  }
  return ext.runtime.getURL("src/passkey-consent/index.html");
}
