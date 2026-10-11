// SPDX-License-Identifier: AGPL-3.0-only

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
  type CheckSavePromptMessage,
  type CredentialsSubmittedMessage,
  type FieldDescriptor,
  type FromContentScript,
  type SavePromptOfferedMessage,
  type SavePromptResolvedMessage,
  type ToContentScript,
} from "../messaging/contract.ts";
import { INLINE_MENU_SHOW, isInlineMenuPickMessage } from "../inline-menu/protocol.ts";
import { isOwnOverlayElement, isOwnOverlayMutation } from "./own-overlay-mutation.ts";
import {
  MAX_Z_INDEX,
  type ChainStyleSample,
  type MenuVisibilityState,
  type PointHitResult,
  type Rect,
  computeExpectedRect,
  initMenuVisibilityState,
  isFillAllowed,
  isPointHitOk,
  isTopLayerClear,
  isVisibilityChainOk,
  parseBoxShadowMarginPx,
  rectsMatch,
  recordSample,
} from "./menu-visibility.ts";

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
      // A real bug, found fixing the security review's iframe-geometry finding: with no visible
      // field left at all (e.g. a client-side route change replaced a login form with other
      // content, without the old field ever receiving a `blur` — single-page apps routinely
      // unmount a focused element without the browser running the usual focus-loss sequence),
      // this used to return without ever destroying a still-open `menu` from an earlier report,
      // leaving its iframe sitting on the page indefinitely. Harmless-looking while the iframe's
      // own height tracked `candidates.length` (often tiny), but the fixed outer height the
      // geometry fix now always uses made the leftover iframe large enough to cover unrelated
      // page content below where the vanished field used to be (an e2e regression this fix
      // surfaced against the web vault's own post-login view). Tear down exactly as
      // `wireInlineMenu` already does when it finds no password field.
      menu?.destroy();
      menu = undefined;
      activeFillTargets = undefined;
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
    if (passwordField === null) {
      menu = undefined;
      return;
    }
    // Gap 32 in the M2 gap audit: the menu is now shown for ANY detected password field, even
    // with zero saved candidates — it always offers "Generate password" (ROADMAP §4.4's
    // generator, not only in the popup), which needs no saved item at all. A blank signup form
    // (the generator's main use case) is exactly the `candidates.length === 0` case this used to
    // skip entirely. `activeFillTargets` is still needed either way: the generator's own
    // `apply_fill` push (`values: { password }`, no `username`) lands through the exact same
    // `activeFillTargets.passwordField` lookup a real fill does.
    activeFillTargets = { usernameField, passwordField };
    // `InlineMenu` no longer tells this script which candidate was picked (ADR 0036 §4's new
    // bullet): the iframe itself sends the fill request straight to the background
    // (`inline-menu/main.ts`), as the one sender the background grants a decrypted credential to
    // (`messaging/sender.ts`'s `isInlineMenuSender`). This script only ever hears about it
    // indirectly, as an `apply_fill` push the background sends back to *this* tab once it has
    // validated that request — never as anything the iframe tells this content script directly,
    // which a compromised content script could otherwise have spoofed by itself.
    menu = new InlineMenu(passwordField, answer.candidates, answer.pageHost);
  }

  let savePrompt: SavePromptBanner | undefined;

  // Shows `answer` as the save/update banner when the background actually offered one,
  // replacing whatever banner (if any) is already showing. Shared by the immediate response to
  // a submit, below, and by the save-prompt-race recovery path (`checkForPendingSavePrompt`):
  // both are "the background just told this page about an offer," the only difference being
  // which page load the offer was originally made on.
  const showSavePromptIfOffered = (answer: ToContentScript | undefined): void => {
    if (answer?.type !== "save_prompt") {
      return;
    }
    savePrompt?.destroy();
    savePrompt = new SavePromptBanner(answer, () => {
      savePrompt = undefined;
    });
  };

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
      } satisfies CredentialsSubmittedMessage).then(showSavePromptIfOffered);
    },
    true,
  );

  // The save-prompt race fix (module docs; `apps/extension/README.md`'s residual note,
  // `core-host/core-context.ts`'s `pendingOffersByLocation`): sent once, unconditionally, on
  // every content-script load — not only when this page itself has login fields, since the page
  // a submit navigates *to* (a dashboard, say) usually has none — so a save offer whose
  // originating page navigated away before it could show the immediate response above is still
  // delivered here, on whichever page of the same tab and registrable domain loads next. A plain
  // "no_pending_save_prompt" answer, or no answer at all (the device is locked, or this is a
  // fresh profile with no long-lived context to ask yet), is the ordinary, silent case.
  void sendToBackground({
    type: "check_save_prompt",
    pageUrl: location.href,
  } satisfies CheckSavePromptMessage).then(showSavePromptIfOffered);

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
  // relies entirely on `activeFillTargets`, a fresh visibility recheck on the target field, and
  // (A7/THREAT_MODEL gap, HANDOFF X6) Gate B below on the menu iframe itself, for the rest.
  const ext = typeof chrome !== "undefined" ? chrome : browser;
  ext?.runtime.onMessage.addListener((message) => {
    if (!isApplyFillMessage(message) || activeFillTargets === undefined) {
      return undefined;
    }
    // GATE B (`menu-visibility.ts`'s own module doc): the causally-after-click, authoritative
    // refusal. Checked here, at `apply_fill` arrival — after the real click → iframe →
    // background → decrypt → push round trip has already happened — never only at click time,
    // which a timed "flip visible for the click, flip back after" attack would already have
    // defeated by the time this message lands. `menu` is the same InlineMenu instance
    // `activeFillTargets` was set from (they only ever change together); it can already be torn
    // down by the time this arrives (the normal post-click teardown), in which case its gate
    // state is simply frozen at its last sample, which is exactly the informative state for this
    // check.
    if (menu === undefined || !menu.isFillAllowedNow(performance.now())) {
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

/** Fixed outer size of the inline-menu `<iframe>` (security review finding: a size derived from
 * `candidates.length` let the embedding page's own script read, via `getBoundingClientRect()`
 * on an element it can always see even though it cannot see *into* it, how many saved items
 * matched — 0 vs. N is exactly the "does this user have an account here" oracle THREAT_MODEL
 * INV-37 exists to deny a page by default). The iframe's outer element — size, position,
 * attributes, insertion and removal — is observable DOM, cross-origin or not; only its
 * *document* is protected. Every one of those properties must therefore be fixed or depend only
 * on the page's own already-known layout (the anchor field's position), never on candidate data
 * or count. `candidates.length` no longer reaches `frame.style` at all; a candidate list longer
 * than fits scrolls inside the iframe's own document instead (`inline-menu/index.html`'s own
 * `overflow-y: auto`) — this constant is deliberately tall enough for a few rows plus the
 * header and the generator button without scrolling in the common case, while every case,
 * including zero candidates, renders at this exact same outer height. */
const INLINE_MENU_WIDTH_PX = 240;
const INLINE_MENU_HEIGHT_PX = 220;

/** The extension-origin inline menu (ADR 0036 §4/§5, ADR 0036 §6 "the inline-menu iframe app";
 * INV-36, INV-40): an `<iframe>` loaded from this extension's own `chrome-extension://` origin
 * (`inline-menu/index.html`/`main.ts`), positioned under the password field, one entry per
 * candidate (title + username only, ADR 0013 §3 rule 3). The page's own JS has no same-origin
 * access to this iframe's document at all — not merely a weaker "please don't script this"
 * convention the prior same-DOM-element version relied on — so it cannot call `.click()` on a
 * candidate itself; `protocol.ts` documents exactly what the `postMessage` channel to and from
 * it does and does not let a hostile page do. Destroyed on blur or a new report, and by itself
 * the instant it reports a pick — by then the iframe has already sent the actual fill request
 * straight to the background on its own (ADR 0040), so nothing of this menu's
 * own is ever what a later visibility recheck sees covering the field.
 *
 * Outer geometry is fixed ({@link INLINE_MENU_WIDTH_PX}/{@link INLINE_MENU_HEIGHT_PX}) and
 * `left`/`top` depend only on the anchor field's own position — never on `candidates` — so a
 * page cannot distinguish 0 from N matches, or which host matched, by reading this element's
 * `getBoundingClientRect()`, `className`, or attributes (security review finding; see the
 * constants' own doc).
 *
 * A7/THREAT_MODEL.md gap (HANDOFF X6): the two checks above only ever covered the TARGET FIELD
 * (`isVisible`/`isTopmost`, above) — this iframe itself had no visibility/topmost check of its
 * own, so a page could hide it with CSS while it stayed the topmost hit-test target, and a
 * trusted click at a decoy's location would land on the real, invisible candidate button. This
 * class now also runs two additive gates (`menu-visibility.ts`'s own module doc has the full
 * reasoning): GATE A is a `requestAnimationFrame` loop, for the lifetime of this instance, that
 * samples the frame's real rendered/hit-test state every frame and toggles its own
 * `pointer-events` from the result — not `MutationObserver`, which the content script already
 * uses elsewhere but only for `childList`, so it would miss an attribute change, an injected
 * `<style>` tag, or a running CSS transition/animation with no DOM mutation at all. GATE B is
 * the authoritative refusal at `apply_fill` arrival (`installContentScript`'s `onMessage`
 * listener, via {@link isFillAllowedNow}), which is what actually closes a timed
 * "flip-visible-for-the-click, flip-back-after" race, because it runs after the click has
 * already happened. Gate A never calls {@link destroy} on a bad sample — this content script's
 * own `MutationObserver` callback already documents a real, previously-fixed unbounded
 * destroy/recreate loop from treating incidental DOM churn as "menu changed, rebuild it"; doing
 * that here against a page that simply leaves a permanent hiding rule in place would reproduce
 * exactly that failure mode. Toggling `pointer-events` is idempotent, reversible, and the one
 * new thing a page can observe about this element (`getComputedStyle(iframe).pointerEvents`) —
 * accepted, because it differs only by whether THIS page is currently tampering with the menu,
 * never by candidate count (INV-37 stays intact: outer geometry, attributes and this toggle are
 * all independent of `candidates`). */
class InlineMenu {
  readonly #frame: HTMLIFrameElement;
  readonly #onMessage: (event: MessageEvent) => void;
  readonly #onBlur: () => void;
  readonly #expectedRect: Rect;
  #visibilityState: MenuVisibilityState;
  #rafId: number | undefined;

  constructor(anchor: HTMLInputElement, candidates: CandidatesMessage["candidates"], pageHost: string) {
    const frame = document.createElement("iframe");
    frame.setAttribute("data-rizzy-inline-menu", "");
    const anchorRect = anchor.getBoundingClientRect();
    // Frozen once, here, never re-derived from `anchor` again (`menu-visibility.ts`'s own doc on
    // why `computeExpectedRect` clamps into the viewport): this is both the frame's real
    // position AND Gate A's geometry baseline for this instance's whole lifetime, so the two can
    // never disagree with each other.
    const expectedRect = computeExpectedRect(anchorRect, { width: window.innerWidth, height: window.innerHeight }, { width: INLINE_MENU_WIDTH_PX, height: INLINE_MENU_HEIGHT_PX });
    this.#expectedRect = expectedRect;
    frame.style.position = "fixed";
    frame.style.left = `${expectedRect.left}px`;
    frame.style.top = `${expectedRect.top}px`;
    frame.style.width = `${expectedRect.width}px`;
    frame.style.height = `${expectedRect.height}px`;
    frame.style.border = "0";
    frame.style.zIndex = String(MAX_Z_INDEX);
    // Set *before* `frame.src` is assigned below, closing the gap between iframe creation and
    // the first animation frame: inline `!important` outranks any author-stylesheet rule in the
    // same bucket by specificity, including one that is itself `!important` — this is what
    // defeats the fixme reproducer's one-line `iframe[data-rizzy-inline-menu]{opacity:0}` (no
    // `!important` needed on the attacker's side at all, since there was nothing competing with
    // it before this change).
    //
    // Deviation from the spec, stated per CLAUDE.md ("deviate only with a stated reason"): the
    // spec also calls for `frame.style.setProperty("visibility", "visible", "important")` here,
    // as "cheap insurance against a plain visibility:hidden page rule." `visibility` INHERITS,
    // so forcing the frame's own computed value to `visible` does not only defeat an attacker's
    // rule — it defeats every OTHER reason an ancestor might legitimately be
    // `visibility:hidden` at some point (a loading/transition state on a page this extension
    // runs on for reasons that have nothing to do with it, including the web vault's own pages,
    // which get an inline menu too whenever they have a password field). A real, OS-level click
    // never reaches an element whose OWN computed `visibility` is `hidden` — that is the
    // browser's ordinary hit-testing rule, with no code of ours involved — so while this
    // override is in place, our frame can intercept a click at a moment when, left to ordinary
    // CSS inheritance, it would not have been clickable at all, exactly like the un-tampered
    // iframe this change is supposed to leave no more clickable than before. `isVisibilityChainOk`
    // already catches an ancestor's OWN `visibility: hidden` directly (`menu-visibility.ts`'s own
    // doc) — the one case this override exists for — so Gate A still refuses it; it just does so
    // through the chain check instead of through inheritance, with no need to touch hit-testing
    // itself. Confirmed empirically: this line was the discriminator in a flake found running
    // this change's own E2E suite against a real Chromium build (`passkey.spec.ts`'s "a passkey
    // the extension created shows up in the web vault" test — this extension's content script
    // shows its OWN inline menu on the web vault's own login page too, for the real "Master
    // password" field; removing this one line stopped the flake across repeated runs).
    frame.style.setProperty("pointer-events", "none", "important");

    this.#visibilityState = initMenuVisibilityState();
    const tick = () => {
      const ok = this.#sampleOk();
      frame.style.setProperty("pointer-events", ok ? "auto" : "none", "important");
      this.#visibilityState = recordSample(this.#visibilityState, performance.now(), ok);
      this.#rafId = requestAnimationFrame(tick);
    };
    this.#rafId = requestAnimationFrame(tick);

    const pageOrigin = location.origin;
    const menuOrigin = inlineMenuOrigin();
    frame.addEventListener(
      "load",
      () => {
        frame.contentWindow?.postMessage(
          {
            type: INLINE_MENU_SHOW,
            pageOrigin,
            pageHost,
            candidates: candidates.map((c) => ({
              itemId: c.itemId,
              title: c.title,
              username: c.username,
              needsWarning: c.needsWarning,
              savedHost: c.savedHost,
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
    if (this.#rafId !== undefined) {
      cancelAnimationFrame(this.#rafId);
    }
    window.removeEventListener("message", this.#onMessage);
    this.#frame.remove();
  }

  /** GATE B (`menu-visibility.ts`'s own module doc): the authoritative, causally-after-click
   * check `installContentScript`'s `apply_fill` listener runs before ever writing a value into
   * the page. Reads whatever Gate A's rAF loop last recorded — frozen at its last sample once
   * {@link destroy} has cancelled that loop, which is exactly the informative state for a push
   * that arrives shortly after the normal post-click teardown. */
  isFillAllowedNow(now: number): boolean {
    return isFillAllowed(this.#visibilityState, now);
  }

  /** One Gate-A tick's full sample: geometry, the `{frame, body, documentElement}` style chain,
   * the browser's top layer, and a single-point hit test — any `false` is a bad sample
   * (`menu-visibility.ts`'s own fail-closed doc). */
  #sampleOk(): boolean {
    if (!rectsMatch(toRect(this.#frame.getBoundingClientRect()), this.#expectedRect)) {
      return false;
    }
    if (!isVisibilityChainOk(this.#chainSamples())) {
      return false;
    }
    // Two independent occlusion sources fed into the same rect-intersection check
    // (`isTopLayerClear`'s own doc): the browser's top layer, and (A7 bypass-2 fix) any
    // body-level sibling tying the frame's own maximum z-index that comes after it in document
    // order — the only other route ordinary DOM stacking has to paint above a
    // `zIndex: MAX_Z_INDEX` element, and one `elementFromPoint`-based hit-testing can never catch
    // on its own when the sibling is `pointer-events: none` (this method's own point-hit check,
    // below, is blind to exactly this).
    if (!isTopLayerClear(this.#expectedRect, [...this.#topLayerRects(), ...this.#occludingSiblingRects()])) {
      return false;
    }
    return isPointHitOk(this.#pointHitResult());
  }

  /** Walks `parentElement` generically from the frame up to (and including) `documentElement` —
   * today, with the frame appended directly to `document.body`, that is exactly
   * `{frame, body, documentElement}`, confirmed by reading this constructor, but a generic walk
   * stays correct if the insertion point ever changes. */
  #chainSamples(): ChainStyleSample[] {
    const samples: ChainStyleSample[] = [];
    let node: Element | null = this.#frame;
    while (node !== null) {
      const style = getComputedStyle(node);
      samples.push({
        opacity: Number(style.opacity),
        visibility: style.visibility,
        display: style.display,
        filter: style.filter,
        clipPath: style.clipPath,
        mask: style.getPropertyValue("mask") || style.getPropertyValue("-webkit-mask") || "none",
        mixBlendMode: style.mixBlendMode,
        contentVisibility: style.getPropertyValue("content-visibility") || "visible",
      });
      node = node.parentElement;
    }
    return samples;
  }

  /** The rects of every element the browser's top layer can render above all z-index (spec):
   * `document.fullscreenElement`, every open `<dialog>`, and every open popover. The `:popover-
   * open` selector throws in a browser/version without the Popover API — caught and treated as
   * "no open popovers," which matches reality (nothing can be a popover there either).
   *
   * A7 bypass-1/3 fix: each element's own `getBoundingClientRect()` is widened by
   * {@link pushOcclusionRect} before being used here — box-shadow (confirmed by direct probe: a
   * 1×1 top-layer popover with a 3000px box-shadow blankets the viewport while its own rect
   * stays 1×1, and box-shadow never participates in hit-testing) and non-`none` `filter` can both
   * paint a top-layer element's visible extent far outside its own border box, so taking the raw
   * rect at face value here was the exact gap those reports used. */
  #topLayerRects(): Rect[] {
    const rects: Rect[] = [];
    if (document.fullscreenElement !== null) {
      pushOcclusionRect(rects, document.fullscreenElement);
    }
    for (const dialog of document.querySelectorAll("dialog[open]")) {
      pushOcclusionRect(rects, dialog);
    }
    try {
      for (const popover of document.querySelectorAll(":popover-open")) {
        pushOcclusionRect(rects, popover);
      }
    } catch {
      // No Popover API support: nothing can be `:popover-open` either.
    }
    return rects;
  }

  /** A7 bypass-2 fix: siblings of the frame, under its own parent, that come AFTER it in
   * document order and whose own computed `z-index` ties {@link MAX_Z_INDEX} — the structural
   * precondition an opaque, `pointer-events: none` decoy needs to visually cover the frame while
   * staying invisible to `elementFromPoint`/`elementsFromPoint` (both exclude `pointer-events:
   * none` targets from hit-testing by spec — confirmed by direct probe, matching
   * THREAT_MODEL.md's own residual-risk note on exactly this). Detected from the DOM structure
   * itself, not from paint or hit-testing, so it closes the gap regardless of `pointer-events`,
   * regardless of whether the content script's own rebuild-on-mutation has had a chance to run
   * yet, and regardless of a concurrent main-thread stall (a reported bypass combined a decoy
   * with a synchronous busy-loop specifically to deny that rebuild a chance to re-win the
   * DOM-order tie before the next real sample; this check does not depend on the rebuild at all).
   * `isOwnOverlayElement` excludes this frame's own later overlays (there are none today, but a
   * generic walk stays correct if that changes) from counting against itself. */
  #occludingSiblingRects(): Rect[] {
    const parent = this.#frame.parentElement;
    if (parent === null) {
      return [];
    }
    const rects: Rect[] = [];
    let passedFrame = false;
    for (const child of parent.children) {
      if (child === this.#frame) {
        passedFrame = true;
        continue;
      }
      if (!passedFrame || isOwnOverlayElement(child)) {
        continue;
      }
      const zIndex = Number(getComputedStyle(child).zIndex);
      if (!Number.isFinite(zIndex) || zIndex < MAX_Z_INDEX) {
        continue;
      }
      rects.push(toRect(child.getBoundingClientRect()));
    }
    return rects;
  }

  /** `document.elementFromPoint` excludes a `pointer-events: none` target from hit-testing by
   * spec — exactly the value this instance's own Gate-A toggle may currently have set on the
   * frame. Measuring with that value still in place would make the check watch its own
   * defensive posture and conclude "occluded" forever, a permanent false-refusal bug, not a
   * security property. So this measures with `pointer-events` momentarily forced to `auto`,
   * then restores whatever value was there before — entirely within this one synchronous call,
   * with no `await` or task boundary in between, so no real pointer event can ever be routed
   * using the intermediate value (the browser only dispatches input events between tasks, never
   * mid-script). `tick()` (the constructor's rAF loop) applies the real, authoritative value
   * right after this returns, from the full sample including this result. */
  #pointHitResult(): PointHitResult {
    const cx = this.#expectedRect.left + this.#expectedRect.width / 2;
    const cy = this.#expectedRect.top + this.#expectedRect.height / 2;
    const previous = this.#frame.style.getPropertyValue("pointer-events");
    this.#frame.style.setProperty("pointer-events", "auto", "important");
    const el = document.elementFromPoint(cx, cy);
    this.#frame.style.setProperty("pointer-events", previous === "" ? "none" : previous, "important");
    if (el === null) {
      return "none";
    }
    return el === this.#frame ? "frame" : "other";
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

/** A plain, already-read `Rect` from a live `DOMRect` — `menu-visibility.ts`'s pure functions
 * never take a DOM type directly. */
function toRect(rect: DOMRect): Rect {
  return { left: rect.left, top: rect.top, width: rect.width, height: rect.height };
}

/** Pushes `el`'s occlusion rect onto `rects`, widened for any paint that can escape its own
 * border box (A7 bypass-1/3 fix, `InlineMenu#topLayerRects`'s own doc). A non-`none` `filter`
 * (e.g. `drop-shadow`) is rare on a top-layer element and not reliably boundable from computed
 * style alone, so it conservatively substitutes the full viewport rect rather than attempting to
 * parse `filter`'s own shorthand; `parseBoxShadowMarginPx` returning `undefined` (a computed
 * `box-shadow` shape this parser does not recognise) does the same — "only ever refuse more"
 * means a value this cannot confidently bound must widen the fallback, never narrow it. */
function pushOcclusionRect(rects: Rect[], el: Element): void {
  const rect = toRect(el.getBoundingClientRect());
  const style = getComputedStyle(el);
  if (style.filter !== "none") {
    rects.push({ left: 0, top: 0, width: window.innerWidth, height: window.innerHeight });
    return;
  }
  const margin = parseBoxShadowMarginPx(style.boxShadow);
  if (margin === undefined) {
    rects.push({ left: 0, top: 0, width: window.innerWidth, height: window.innerHeight });
    return;
  }
  rects.push({ left: rect.left - margin, top: rect.top - margin, width: rect.width + margin * 2, height: rect.height + margin * 2 });
}
