// The content script (ADR 0036 §4, §5; ADR 0014 §2: "plain TypeScript, no wasm, no React").
// Top frame only for now (ADR 0037 §5 "no cross-origin iframe fill by default" — this file
// does not even try same-origin-iframe fill yet, a stricter default than the ADR requires,
// tracked in `not_done`). It never imports `@rizzy-vault/core` (enforced by
// `eslint.config.mjs`'s `no-restricted-imports` for this file) and never fills without a
// trusted user gesture (INV-36): detection and the inline-menu offer happen passively, but the
// fill request itself is only ever triggered by the extension-origin inline-menu iframe's own
// `click` handler (`inline-menu/main.ts`) — the menu the user opened, in a document the page's
// own JS cannot reach at all (not merely one it is asked nicely not to script). That iframe asks
// the background directly (ADR 0040; `messaging/sender.ts`'s
// `isInlineMenuSender`), which re-validates the request and pushes the values back to this
// script as `apply_fill` — this content script never relays `fill_chosen` itself and never
// receives any credential except through that one push, so it alone cannot pull one for an
// `itemId` it names of its own accord. The actual DOM write (`applyFill`, below) still runs
// here, since this is the only context with the real `HTMLInputElement`s.
import {
  MAX_FIELDS_PER_REPORT,
  isApplyFillMessage,
  type CandidatesMessage,
  type CredentialsSubmittedMessage,
  type FieldDescriptor,
  type FromContentScript,
  type SavePromptOfferedMessage,
  type SavePromptResolvedMessage,
  type ToContentScript,
} from "../messaging/contract.ts";
import { INLINE_MENU_SHOW, isInlineMenuPickMessage } from "../inline-menu/protocol.ts";
import { isOwnOverlayMutation } from "./own-overlay-mutation.ts";

if (window.top === window) {
  installContentScript();
}

function installContentScript(): void {
  let menu: InlineMenu | undefined;

  // The one pair of fields the inline menu currently showing (if any) is offering to fill —
  // set by `wireInlineMenu` from the same detection pass the menu itself is for, and read only
  // by the `apply_fill` listener below (ADR 0040: the background never names a
  // field, only `username`/`password` by kind — this is what maps that kind back onto a real
  // `HTMLInputElement` in *this* tab). Cleared whenever the menu is destroyed or replaced, so an
  // `apply_fill` arriving after the user closed or changed the menu (e.g. a stale, delayed
  // response racing a later report) lands on nothing rather than an unrelated field.
  let activeFillTargets: { readonly usernameField: HTMLInputElement | null; readonly passwordField: HTMLInputElement } | undefined;

  const report = () => {
    const fields = detectFields();
    if (fields.length === 0) {
      return;
    }
    void sendToBackground({
      type: "fields_detected",
      pageUrl: location.href,
      isTopFrame: true,
      fields,
    }).then((answer) => {
      if (answer?.type === "candidates") {
        wireInlineMenu(answer);
      }
    });
  };

  function wireInlineMenu(answer: CandidatesMessage): void {
    const usernameField = document.querySelector<HTMLInputElement>('input[data-rizzy-field="username"]');
    const passwordField = document.querySelector<HTMLInputElement>('input[data-rizzy-field="password"]');
    menu?.destroy();
    activeFillTargets = undefined;
    if (answer.candidates.length === 0 || passwordField === null) {
      menu = undefined;
      return;
    }
    activeFillTargets = { usernameField, passwordField };
    // `InlineMenu` no longer tells this script which candidate was picked (ADR 0036 §4's new
    // bullet): the iframe itself sends the fill request straight to the background
    // (`inline-menu/main.ts`), as the one sender the background grants a decrypted credential to
    // (`messaging/sender.ts`'s `isInlineMenuSender`). This script only ever hears about it
    // indirectly, as an `apply_fill` push the background sends back to *this* tab once it has
    // validated that request — never as anything the iframe tells this content script directly,
    // which a compromised content script could otherwise have spoofed by itself.
    menu = new InlineMenu(passwordField, answer.candidates);
  }

  let savePrompt: SavePromptBanner | undefined;

  // ROADMAP §4.4 "save/update on submit": a capturing listener so a page's own `stopPropagation`
  // on the bubbling phase cannot hide the submit from this script. Reads the current value of
  // whichever fields detection already tagged `username`/`password` (never a guess at the
  // field's identity at submit time) and only ever *offers* save/update — `offerSavePrompt`'s
  // own doc says this never auto-writes anything.
  document.addEventListener(
    "submit",
    () => {
      const usernameField = document.querySelector<HTMLInputElement>('input[data-rizzy-field="username"]');
      const passwordField = document.querySelector<HTMLInputElement>('input[data-rizzy-field="password"]');
      if (passwordField === null || passwordField.value === "") {
        return;
      }
      void sendToBackground({
        type: "credentials_submitted",
        pageUrl: location.href,
        ...(usernameField !== null && usernameField.value !== "" ? { usernameValue: usernameField.value } : {}),
        passwordValue: passwordField.value,
      } satisfies CredentialsSubmittedMessage).then((answer) => {
        if (answer?.type === "save_prompt") {
          savePrompt?.destroy();
          savePrompt = new SavePromptBanner(answer, () => {
            savePrompt = undefined;
          });
        }
      });
    },
    true,
  );

  // Detection reruns on load and on DOM mutation (dynamically rendered login forms), debounced
  // by `requestIdleCallback`-style batching via a simple timer so a busy page cannot cause a
  // flood of `fields_detected` messages (each is still independently size- and rate-limited by
  // the background's `MAX_MESSAGE_BYTES`/shape validation; this is a courtesy, not the gate).
  let pending: number | undefined;
  const schedule = () => {
    if (pending !== undefined) {
      return;
    }
    pending = window.setTimeout(() => {
      pending = undefined;
      report();
    }, 250);
  };
  // The one message this script ever receives rather than sends (ADR 0040): the
  // background pushes this only after it has (1) re-run the matcher for *this tab's own*,
  // browser-vouched URL and confirmed `itemId` was among the result, and (2) confirmed the
  // request came from the extension-origin inline-menu iframe, not this content script
  // (`core-host/listener.ts`, `core-host/content-handler.ts`). This listener does not and cannot
  // re-check either of those — it has no way to — so it trusts the push exactly as much as it
  // already trusts every other extension-internal message delivered to a content script, and
  // relies entirely on `activeFillTargets` plus a fresh visibility recheck for the rest.
  const ext = typeof chrome !== "undefined" ? chrome : browser;
  ext?.runtime.onMessage.addListener((message) => {
    if (!isApplyFillMessage(message) || activeFillTargets === undefined) {
      return undefined;
    }
    applyFill(message.values, activeFillTargets.usernameField, activeFillTargets.passwordField);
    return undefined;
  });

  new MutationObserver((records) => {
    // A real bug, found empirically running this change's E2E coverage against a real
    // Chromium build: `InlineMenu`'s own `appendChild`/`remove` of its iframe (and
    // `SavePromptBanner`'s of its banner) are themselves `childList` mutations under
    // `document.documentElement`, so without this filter every inline-menu show/hide
    // re-triggered `report()`, which could `wireInlineMenu` a *new* menu, mutating the DOM
    // again — an unbounded destroy/recreate loop that starved the page's own event loop and,
    // observed directly, could tear the menu out from under a click already in flight. Only
    // mutations that add or remove something other than our own marked elements count as "the
    // page changed" and deserve a re-detection.
    if (isOwnOverlayMutation(records)) {
      return;
    }
    schedule();
  }).observe(document.documentElement, { childList: true, subtree: true });
  schedule();
}

/** Finds visible username/password-shaped inputs, tags them with a `data-rizzy-field`
 * attribute so {@link wireInlineMenu}/fill can find them again by a stable marker instead of
 * re-running heuristics, and reports at most {@link MAX_FIELDS_PER_REPORT}. No hidden or
 * zero-size field is ever reported (ADR 0037 §5 "no hidden/invisible field fill"). */
function detectFields(): FieldDescriptor[] {
  const inputs = Array.from(document.querySelectorAll("input"));
  const out: FieldDescriptor[] = [];
  for (const input of inputs) {
    if (out.length >= MAX_FIELDS_PER_REPORT) {
      break;
    }
    if (!isVisible(input)) {
      continue;
    }
    const kind = classify(input);
    if (kind === undefined) {
      continue;
    }
    const fieldId = stableFieldId(input);
    input.dataset["rizzyField"] = kind;
    input.dataset["rizzyFieldId"] = fieldId;
    out.push({
      fieldId,
      kind,
      visible: true,
      ...(kind === "username" && input.value !== "" ? { currentValue: input.value.slice(0, 4096) } : {}),
    });
  }
  return out;
}

function isVisible(el: HTMLElement): boolean {
  const rect = el.getBoundingClientRect();
  if (rect.width === 0 || rect.height === 0) {
    return false;
  }
  const style = getComputedStyle(el);
  if (style.visibility === "hidden" || style.display === "none" || Number(style.opacity) === 0) {
    return false;
  }
  return isTopmost(el, rect);
}

/** ADR 0037 §5 ("No hidden/invisible field fill") assigns the content script "visibility and
 * topmost checks" — CSS visibility alone (above) does not catch a field an attacker-controlled
 * element visually covers while leaving it `display`/`visibility`/`opacity` "visible". Checked
 * at the field's own centre point, where a label or an inline icon that is part of the field's
 * own markup, not an overlay, would also land (`el.contains(topEl)` accepts that).
 *
 * `elementFromPoint` returns `null` for a point outside the viewport — a routine case for a
 * field below the fold, not evidence of an overlay — and (per spec) for a point with nothing
 * paintable there, e.g. inside an ancestor clipped by `overflow: hidden`. Neither is the attack
 * this check defends against, which needs a *different*, non-containing element actually
 * painted on top; conservative reading, documented here as the task asks: `null` passes. */
function isTopmost(el: HTMLElement, rect: DOMRect): boolean {
  const x = rect.left + rect.width / 2;
  const y = rect.top + rect.height / 2;
  const topEl = document.elementFromPoint(x, y);
  if (topEl === null) {
    return true;
  }
  return topEl === el || el.contains(topEl);
}

function classify(input: HTMLInputElement): "username" | "password" | undefined {
  if (input.type === "password") {
    return "password";
  }
  const auto = input.autocomplete.toLowerCase();
  const type = input.type.toLowerCase();
  if (auto.includes("username") || auto === "email" || type === "email" || type === "text") {
    // A heuristic, not matching: it decides what to *report*, never what to *fill* — filling is
    // always the one field the user picked in the inline menu (ADR 0036 §4).
    return "username";
  }
  return undefined;
}

let counter = 0;
const idsByElement = new WeakMap<HTMLInputElement, string>();
function stableFieldId(el: HTMLInputElement): string {
  const existing = idsByElement.get(el);
  if (existing !== undefined) {
    return existing;
  }
  counter += 1;
  const id = `f${counter}`;
  idsByElement.set(el, id);
  return id;
}

function applyFill(
  values: { readonly username?: string; readonly password: string },
  usernameField: HTMLInputElement | null,
  passwordField: HTMLInputElement,
): void {
  // Mapped by kind, not by `fieldId` (ADR 0040: the background never sees or
  // names a `fieldId`, only `username`/`password`) — `usernameField`/`passwordField` are exactly
  // the two fields `wireInlineMenu` tagged when the inline menu was shown for them, so there is
  // nothing left to look up by id.
  const targets: ReadonlyArray<readonly [HTMLInputElement | null, string | undefined]> = [
    [usernameField, values.username],
    [passwordField, values.password],
  ];
  for (const [target, value] of targets) {
    if (target === null || value === undefined) {
      continue;
    }
    // THREAT_MODEL.md row "T" (page scripts rearrange forms between click and fill): "re-check
    // origin, frame and visibility at fill time," not only when the field was first detected.
    // The inline menu is destroyed well before this runs (the user's click tears it down
    // immediately, and the round trip through the background takes longer still), so it is
    // never the thing covering `target` here.
    if (!isVisible(target)) {
      continue;
    }
    target.value = value;
    target.dispatchEvent(new Event("input", { bubbles: true }));
    target.dispatchEvent(new Event("change", { bubbles: true }));
  }
}

function sendToBackground(message: FromContentScript): Promise<ToContentScript | undefined> {
  const ext = typeof chrome !== "undefined" ? chrome : browser;
  if (ext === undefined) {
    return Promise.resolve(undefined);
  }
  return ext.runtime.sendMessage(message).then((r) => r as ToContentScript | undefined);
}

/** The extension-origin inline menu (ADR 0036 §4/§5, ADR 0036 §75 "the inline-menu iframe app";
 * INV-36, INV-40): an `<iframe>` loaded from this extension's own `chrome-extension://` origin
 * (`inline-menu/index.html`/`main.ts`), positioned under the password field, one entry per
 * candidate (title + username only, ADR 0013 §3 rule 3). The page's own JS has no same-origin
 * access to this iframe's document at all — not merely a weaker "please don't script this"
 * convention the prior same-DOM-element version relied on — so it cannot call `.click()` on a
 * candidate itself; `protocol.ts` documents exactly what the `postMessage` channel to and from
 * it does and does not let a hostile page do. Destroyed on blur or a new report, and by itself
 * the instant it reports a pick — by then the iframe has already sent the actual fill request
 * straight to the background on its own (ADR 0040), so nothing of this menu's
 * own is ever what a later visibility recheck sees covering the field. */
class InlineMenu {
  readonly #frame: HTMLIFrameElement;
  readonly #onMessage: (event: MessageEvent) => void;
  readonly #onBlur: () => void;

  constructor(anchor: HTMLInputElement, candidates: CandidatesMessage["candidates"]) {
    const frame = document.createElement("iframe");
    frame.setAttribute("data-rizzy-inline-menu", "");
    const rect = anchor.getBoundingClientRect();
    frame.style.position = "fixed";
    frame.style.left = `${rect.left}px`;
    frame.style.top = `${rect.bottom}px`;
    frame.style.width = `${Math.max(rect.width, 220)}px`;
    frame.style.height = `${candidates.length * 36 + 8}px`;
    frame.style.border = "0";
    frame.style.zIndex = "2147483647";

    const pageOrigin = location.origin;
    const menuOrigin = inlineMenuOrigin();
    frame.addEventListener(
      "load",
      () => {
        frame.contentWindow?.postMessage(
          {
            type: INLINE_MENU_SHOW,
            pageOrigin,
            candidates: candidates.map((c) => ({
              itemId: c.itemId,
              title: c.title,
              username: c.username,
              needsWarning: c.needsWarning,
            })),
          },
          menuOrigin,
        );
      },
      { once: true },
    );

    this.#onMessage = (event) => {
      // Unforgeable (`protocol.ts`): both `event.source` (this exact iframe's window, a
      // distinct object no page script can impersonate) and `event.origin` (this extension's
      // own origin, set by the browser from the document that actually called `postMessage`)
      // are outside any script running in the page's shared `window`'s reach.
      if (event.source !== frame.contentWindow || event.origin !== menuOrigin) {
        return;
      }
      if (!isInlineMenuPickMessage(event.data)) {
        return;
      }
      // Teardown only (ADR 0040): the iframe already sent the actual fill
      // request straight to the background itself, on the same trusted click, before it ever
      // posted this message (`inline-menu/main.ts`). This script never learns `itemId` and never
      // acts on it — it only tears the menu down, exactly as it would on blur.
      this.destroy();
    };
    window.addEventListener("message", this.#onMessage);

    // `src` set *before* the element is attached to the document — the opposite of this file's
    // other DOM-insertion comment, and deliberately so: a real bug, found empirically running
    // this change's E2E coverage against a real Chromium build. Appending an `src`-less iframe
    // first (the previous order here) queues a navigation to `about:blank` immediately; setting
    // `src` afterwards queues a *second* navigation, so `"load"` fires twice — once for the
    // blank document (same-origin as this page, `window.location.origin`), once for the real
    // one. The `{ once: true }` listener below caught only the first, so it tried to
    // `postMessage` the candidate list to `menuOrigin` while the iframe's actual window still
    // had this page's own origin — exactly the "target origin ... does not match the recipient
    // window's origin" warning Chromium logs for that mismatch, and the inline menu never
    // received its candidates. Setting `src` on a still-detached iframe queues no navigation at
    // all (there is nothing to navigate yet); appending it then starts exactly one navigation,
    // straight to `inlineMenuUrl()`, so `"load"` fires exactly once, for the right origin.
    frame.src = inlineMenuUrl();
    document.body.appendChild(frame);

    this.#frame = frame;
    this.#onBlur = () => this.destroy();
    anchor.addEventListener("blur", this.#onBlur);
  }

  destroy(): void {
    window.removeEventListener("message", this.#onMessage);
    this.#frame.remove();
  }
}

/**
 * The save/update/dismiss prompt after a form submission (ROADMAP §4.4). Unlike {@link
 * InlineMenu}, this renders directly in the page's own DOM rather than a cross-origin iframe:
 * a known, documented residual (`apps/extension/README.md`'s "Known gaps") — the page's own
 * script could technically call `.click()` on one of these buttons, where it cannot on the
 * fill menu's. The impact is bounded either way: the values involved are the page's *own* form
 * values the page's script already had, "save" or "update" only ever writes what the user just
 * typed into that page's own form, and dismissing or forging a click here can never read or
 * exfiltrate an existing vault secret. `event.isTrusted` is still checked, as defence in depth.
 */
class SavePromptBanner {
  readonly #el: HTMLElement;

  constructor(offer: SavePromptOfferedMessage, onDone: () => void) {
    const el = document.createElement("div");
    el.setAttribute("data-rizzy-save-prompt", "");
    el.style.position = "fixed";
    el.style.right = "16px";
    el.style.bottom = "16px";
    el.style.zIndex = "2147483647";
    el.style.background = "#fff";
    el.style.color = "#000";
    el.style.border = "1px solid #888";
    el.style.padding = "8px";

    const label = document.createElement("span");
    label.textContent =
      offer.suggestion === "save" ? "Save this login in rizzy-vault?" : `Update "${offer.itemTitle ?? ""}" in rizzy-vault?`;
    el.appendChild(label);

    const resolve = (action: "save" | "update" | "dismiss") => (event: MouseEvent) => {
      if (!event.isTrusted) {
        return;
      }
      void sendToBackground({ type: "save_prompt_resolved", token: offer.token, action } satisfies SavePromptResolvedMessage);
      this.destroy();
      onDone();
    };

    const actionButton = document.createElement("button");
    actionButton.type = "button";
    actionButton.textContent = offer.suggestion === "save" ? "Save" : "Update";
    actionButton.addEventListener("click", resolve(offer.suggestion));
    el.appendChild(actionButton);

    const dismissButton = document.createElement("button");
    dismissButton.type = "button";
    dismissButton.textContent = "Dismiss";
    dismissButton.addEventListener("click", resolve("dismiss"));
    el.appendChild(dismissButton);

    document.body.appendChild(el);
    this.#el = el;
  }

  destroy(): void {
    this.#el.remove();
  }
}

function inlineMenuUrl(): string {
  const ext = typeof chrome !== "undefined" ? chrome : browser;
  if (ext === undefined) {
    throw new Error("inline-menu: no WebExtension runtime (chrome/browser) in this content script");
  }
  return ext.runtime.getURL("src/inline-menu/index.html");
}

function inlineMenuOrigin(): string {
  return new URL(inlineMenuUrl()).origin;
}
