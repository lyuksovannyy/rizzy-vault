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
  MAX_FIELD_VALUE_LEN,
  isApplyFillMessage,
  type CandidatesMessage,
  type CheckSavePromptMessage,
  type CredentialsSubmittedMessage,
  type FieldDescriptor,
  type FillScope,
  type FillValues,
  type FromContentScript,
  type SavePromptOfferedMessage,
  type SavePromptResolvedMessage,
  type ToContentScript,
} from "../messaging/contract.ts";
import { INLINE_MENU_SHOW, isInlineMenuPickMessage, type InlineMenuShowMessage } from "../inline-menu/protocol.ts";
import { NO_FORM, detectLoginStep, stepFillScope, type InputFacts } from "./login-step.ts";
import { isOwnOverlayElement, pageMutations } from "./own-overlay-mutation.ts";
import {
  MAX_Z_INDEX,
  type ChainStyleSample,
  type MenuVisibilityState,
  type PointHitResult,
  type Rect,
  computeExpectedRect,
  initMenuVisibilityState,
  isAllZeroLengths,
  isBackdropOccluding,
  isFillAllowed,
  isPointHitOk,
  isTopLayerClear,
  isVisibilityChainOk,
  parseBoxShadowMarginPx,
  parseOutlineMarginPx,
  pseudoElementPaintsFixedOverlay,
  pseudoElementTiesMaxZIndex,
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
  //
  // Multi-step login pages (ROADMAP §4.4 M3; `login-step.ts`): on an identifier-first step only
  // `usernameField` is set, on a password-only step only `passwordField`. Each step's menu is
  // its own offer and each fill its own trusted click (INV-36): nothing is carried from one
  // step's pick to the next step's fields, and nothing survives a navigation (this whole closure
  // is per document).
  let activeFillTargets: FillTargets | undefined;

  // The step the latest detection pass found, compared on attribute-only mutations so a page
  // that merely restyles itself (animations, focus classes) does not re-ask the background and
  // re-create the menu on every change; a step that appears, changes or goes away (a password
  // field revealed by "Next", say) does.
  let currentStep: DetectedStep | undefined;
  // Bumped per report: only the answer to the latest report wires a menu, so a slow answer for
  // a step the page has already left never anchors a menu to that old step's fields.
  let reportSeq = 0;

  const report = (force: boolean) => {
    const step = detectStep();
    if (!force && sameStep(step, currentStep)) {
      return;
    }
    currentStep = step;
    reportSeq += 1;
    const seq = reportSeq;
    if (step === undefined) {
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
      fields: step.fields,
    }).then((answer) => {
      if (answer?.type === "candidates" && seq === reportSeq) {
        wireInlineMenu(answer, step);
      }
    });
  };

  function wireInlineMenu(answer: CandidatesMessage, step: DetectedStep): void {
    const { usernameField, passwordField, only } = step;
    menu?.destroy();
    activeFillTargets = undefined;
    // The menu anchors on the password field when the step has one (the one-page form, as
    // before, and the password-only step), else on the identifier-first step's username field.
    const anchor = passwordField ?? usernameField;
    if (anchor === null || !anchor.isConnected) {
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
    menu = new InlineMenu(anchor, answer.candidates, answer.pageHost, only);
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
  //
  // `force`: re-report even if the detected step did not change (the first pass, and any batch
  // with a `childList` change — the behaviour before multi-step support, kept as it was). An
  // attribute-only batch (`style`, `class`, `hidden`, …: how a same-page identifier-first form
  // usually reveals its password field) re-reports only when the step itself changed.
  let pending: number | undefined;
  let pendingForce = false;
  const schedule = (force: boolean) => {
    pendingForce ||= force;
    if (pending !== undefined) {
      return;
    }
    pending = window.setTimeout(() => {
      pending = undefined;
      const f = pendingForce;
      pendingForce = false;
      report(f);
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
    applyFill(message.values, activeFillTargets);
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
    //
    // Attribute changes are observed too (multi-step login pages, ROADMAP §4.4 M3: a password
    // field revealed in place by toggling `hidden`/`style`/`class`), filtered the same way: the
    // inline menu restyles its own iframe on every animation frame (`pointer-events`), which
    // must never count as the page changing. `data-rizzy-*` attributes this script writes are
    // not in the filter at all.
    const relevant = pageMutations(records);
    if (relevant === "none") {
      return;
    }
    schedule(relevant === "structure");
  }).observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ["style", "class", "hidden", "disabled", "readonly"],
  });
  schedule(true);
}

/** The fields one login step fills (`login-step.ts`): both on a one-page form, one of them on
 * an identifier-first or password-only step. */
interface FillTargets {
  readonly usernameField: HTMLInputElement | null;
  readonly passwordField: HTMLInputElement | null;
}

/** One detection pass's result: the step's own fields, the `only` scope its menu carries, and
 * the field report the background gets (ADR 0036 §4 "detected-field reports"). */
interface DetectedStep extends FillTargets {
  readonly only: FillScope | undefined;
  readonly fields: readonly FieldDescriptor[];
}

function sameStep(a: DetectedStep | undefined, b: DetectedStep | undefined): boolean {
  if (a === undefined || b === undefined) {
    return a === b;
  }
  return a.usernameField === b.usernameField && a.passwordField === b.passwordField;
}

/** Upper bound on `<input>` elements one detection pass reads, so a page with a pathological
 * number of inputs costs a bounded amount of layout work per pass. A login form is at the top of
 * any realistic page's inputs; past this bound the page gets no offer (fail closed: no menu, no
 * fill), never a wrong one. */
const MAX_INPUTS_SCANNED = 1000;
/** Upper bound on each hint string (`login-step.ts`'s `InputFacts.hints`, a form's hint text). */
const MAX_HINT_LEN = 512;

function hintOf(parts: readonly (string | null | undefined)[]): string {
  return parts
    .filter((p): p is string => typeof p === "string" && p !== "")
    .join(" ")
    .slice(0, MAX_HINT_LEN)
    .toLowerCase();
}

const SUBMIT_CONTROLS = 'button:not([type]), button[type="submit"], input[type="submit"]';

function submitControlText(el: Element): string {
  return el instanceof HTMLInputElement ? el.value : (el.textContent ?? "");
}

/**
 * Runs `login-step.ts`'s heuristic over this document and tags the chosen field(s) with
 * `data-rizzy-field` (`username`/`password`; the submit listener and the e2e suite read the
 * tag), clearing the tag from every other input. Only inputs that pass the visibility and
 * topmost gate (THREAT_MODEL A7, INV-37) are ever chosen — the gate runs here, before the
 * heuristic, and again at fill time in {@link applyFill}. Reads this frame's own document only:
 * fields inside any iframe, cross-origin or not, are never seen (ADR 0037 §5).
 */
function detectStep(): DetectedStep | undefined {
  const elements = Array.from(document.querySelectorAll("input")).slice(0, MAX_INPUTS_SCANNED);
  const forms = new Map<HTMLFormElement, number>();
  Array.from(document.forms).forEach((form, i) => forms.set(form, i));
  const facts: InputFacts[] = elements.map((el) => {
    const type = el.type.toLowerCase();
    // Layout reads (`isVisible`) only for the types the heuristic can ever choose.
    const relevant = type === "password" || type === "text" || type === "email" || type === "tel";
    const labels = el.labels === null ? [] : Array.from(el.labels, (l) => (l.textContent ?? "").slice(0, MAX_HINT_LEN));
    return {
      type,
      autocomplete: (el.getAttribute("autocomplete") ?? "").toLowerCase(),
      hints: hintOf([el.getAttribute("name"), el.getAttribute("id"), el.getAttribute("placeholder"), el.getAttribute("aria-label"), ...labels]),
      visible: relevant && isVisible(el),
      editable: !el.readOnly && !el.disabled,
      form: el.form === null ? NO_FORM : (forms.get(el.form) ?? NO_FORM),
    };
  });
  const formHint = (form: number): string => {
    if (form === NO_FORM) {
      const outside = Array.from(document.querySelectorAll(SUBMIT_CONTROLS)).filter(
        (el) => (el as HTMLButtonElement | HTMLInputElement).form === null,
      );
      return hintOf(outside.map(submitControlText));
    }
    const el = document.forms[form];
    if (el === undefined) {
      return "";
    }
    return hintOf([
      el.getAttribute("id"),
      el.getAttribute("name"),
      el.getAttribute("action"),
      el.getAttribute("aria-label"),
      ...Array.from(el.querySelectorAll(SUBMIT_CONTROLS), submitControlText),
    ]);
  };
  const step = detectLoginStep(facts, formHint);
  const usernameField = step !== undefined && "username" in step ? (elements[step.username] ?? null) : null;
  const passwordField = step !== undefined && "password" in step ? (elements[step.password] ?? null) : null;
  for (const el of document.querySelectorAll<HTMLInputElement>("input[data-rizzy-field]")) {
    if (el !== usernameField && el !== passwordField) {
      delete el.dataset["rizzyField"];
    }
  }
  if (step === undefined) {
    return undefined;
  }
  const fields: FieldDescriptor[] = [];
  for (const [el, kind] of [
    [usernameField, "username"],
    [passwordField, "password"],
  ] as const) {
    if (el === null) {
      continue;
    }
    const fieldId = stableFieldId(el);
    el.dataset["rizzyField"] = kind;
    el.dataset["rizzyFieldId"] = fieldId;
    fields.push({
      fieldId,
      kind,
      visible: true,
      ...(kind === "username" && el.value !== "" ? { currentValue: el.value.slice(0, MAX_FIELD_VALUE_LEN) } : {}),
    });
  }
  return { usernameField, passwordField, only: stepFillScope(step), fields };
}

function isVisible(el: HTMLElement): boolean {
  const rect = el.getBoundingClientRect();
  if (rect.width === 0 || rect.height === 0) {
    return false;
  }
  // Off-screen (THREAT_MODEL A7: "fields positioned off-screen"): entirely left of or above the
  // document's own origin, where no scrolling can ever bring it into view. A field merely below
  // the fold or right of the viewport is still reachable and stays visible here.
  if (rect.right + window.scrollX <= 0 || rect.bottom + window.scrollY <= 0) {
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

function applyFill(values: FillValues, { usernameField, passwordField }: FillTargets): void {
  // Mapped by kind, not by `fieldId` (ADR 0040: the background never sees or
  // names a `fieldId`, only `username`/`password`) — `usernameField`/`passwordField` are exactly
  // the field(s) `wireInlineMenu` tagged when the inline menu was shown for them, so there is
  // nothing left to look up by id. On a multi-step login page (`login-step.ts`) one of them is
  // `null`: a value for a field this step does not have is dropped here, never written anywhere
  // else (and the long-lived context does not send it in the first place, `only`).
  const targets: ReadonlyArray<readonly [HTMLInputElement | null, string | undefined]> = [
    [usernameField, values.username],
    [passwordField, values.password],
  ];
  for (const [target, value] of targets) {
    if (target === null || value === undefined) {
      continue;
    }
    // A page can detach, disable or lock a field between detection and fill; none of those is
    // a field the user can see being filled.
    if (!target.isConnected || target.readOnly || target.disabled) {
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
  // A7 nested-decoy fix: measured directly, 20 warmed-up iterations of one full
  // `#scanElementForDeepOccluders` walk on a synthetic page (5000 plain "chrome" elements, 3
  // nodes deep each, BEFORE the frame; the frame; 5 trailing elements AFTER it plus one genuine
  // occluder nested inside an open Shadow DOM) — avg 103ms, max 114ms (not re-measured with a
  // per-call breakdown, so this does not attribute the cost to any one step;
  // `getBoundingClientRect()` itself is called exactly once in this scenario, on the single
  // matching occluder, which the probe source confirms): too expensive to re-run on every Gate-A
  // `requestAnimationFrame` tick (a real jank risk, confirming the performance objection the
  // second adversarial round raised, unbenchmarked, was correct). Re-run only when something could
  // plausibly have changed, tracked by this dedicated observer (separate from
  // `installContentScript`'s own, narrower `childList`-only one, so this does not also widen THAT
  // observer's debounced field-redetection to fire on every attribute change on the page): any
  // `childList` mutation anywhere in the subtree (an inserted decoy), any ATTRIBUTE change
  // anywhere (deliberately unfiltered, not just `style`/`class` — a decoy's z-index can equally be
  // keyed by an `id` or a `data-*` attribute a stylesheet rule selects on; a z-index raised by a
  // LATER, non-insertion attribute write is the exact gap a one-shot, insertion-only scan missed
  // in an earlier version of this fix, confirmed by review and by
  // `adversarial-fill-requests.spec.ts`'s own regression test), or any character-data change (a
  // `<style>` tag's `textContent` rewritten in place) — EXCLUDING this content script's own
  // overlay elements (`isOwnOverlayElement`, reused from `own-overlay-mutation.ts`): without this
  // exclusion, Gate A's own per-tick `frame.style.setProperty("pointer-events", ...)` write
  // (`tick()`, `#pointHitResult()`) would itself be an attribute mutation on `#frame`, self-
  // triggering a dirty flag that never clears while the frame's own pointer-events keeps toggling
  // — a review finding, not empirically confirmed to reproduce today (Chromium appears to suppress
  // a mutation record when the serialized attribute value does not actually change, which is most
  // ticks), but excluding our own marked elements costs nothing, filters no attacker-relevant
  // signal (a decoy is never one of our own marked elements), and removes the possibility
  // entirely rather than relying on an unspecified browser optimisation. Residual, named rather
  // than silently unclosed: `CSSStyleSheet.insertRule`/`deleteRule`/`replace()` changes a rule's
  // effective z-index with NO corresponding DOM mutation of any kind, observable by nothing a
  // `MutationObserver` can report. A page with heavy, unrelated attribute/class churn elsewhere
  // (common on a highly interactive page) re-triggers the full rebuild often, so this check's own
  // cost is bounded by page ACTIVITY, not fixed — accepted, since it is still event-driven rather
  // than the unconditional per-frame cost the second round rejected.
  #deepOccludersDirty = true;
  #deepOccluderCandidates: Element[] = [];
  readonly #deepOccluderObserver: MutationObserver;

  constructor(anchor: HTMLInputElement, candidates: CandidatesMessage["candidates"], pageHost: string, only: FillScope | undefined) {
    const frame = document.createElement("iframe");
    this.#frame = frame;
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
            ...(only === undefined ? {} : { only }),
          } satisfies InlineMenuShowMessage,
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

    // A7 nested-decoy fix: dedicated to this instance, disconnected in `destroy()` — separate from
    // `installContentScript`'s own `childList`-only observer so widening what THIS one watches
    // (attributes, character data) never also widens that one's debounced field-redetection to
    // fire on every attribute change a page makes (`#deepOccludersDirty`'s own doc has the full
    // reasoning for why this is dirty-flagged rather than re-scanned unconditionally every tick,
    // and for why every record whose `target` is one of this script's own overlay elements is
    // skipped — Gate A's own per-tick `pointer-events` write on `#frame` is exactly such a
    // record). `isOwnOverlayElement` duck-types `hasAttribute`, so a `characterData` mutation's
    // `target` (a `Text` node, which has no `hasAttribute`) is correctly never treated as "our
    // own" and never filtered.
    this.#deepOccluderObserver = new MutationObserver((records) => {
      for (const record of records) {
        if (!isOwnOverlayElement(record.target)) {
          this.#deepOccludersDirty = true;
          return;
        }
      }
    });
    this.#deepOccluderObserver.observe(document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
      characterData: true,
    });

    this.#onBlur = () => this.destroy();
    anchor.addEventListener("blur", this.#onBlur);
  }

  /**
   * A7 nested-decoy fix: {@link #deepOccluderRects} rebuilds {@link #deepOccluderCandidates} from
   * scratch whenever {@link #deepOccludersDirty}, never unconditionally on every Gate-A tick —
   * measured directly (see {@link #deepOccludersDirty}'s own doc) to cost ~103ms on average on a
   * synthetic 5000-element page, far too slow for a 16ms tick budget. A deliberate change from an
   * earlier version of this fix, which cached a decoy's own `Element` the first time a
   * `MutationObserver` callback saw it INSERTED and never re-examined it again — a bypassable gap
   * of its own (a review finding, not a report): a page can insert a decoy at a LOW `z-index` (no
   * reason to be flagged at insertion time) and raise it to {@link MAX_Z_INDEX} later via a plain
   * style write, which the dirty-flag observer (unlike a `childList`-only one) DOES see and react
   * to. `#deepOccludersDirty` starts `true` unconditionally, so the FIRST tick after construction
   * always does a full scan — covering a decoy already on the page before this menu was even
   * built, which a purely insertion-triggered design would never see at all.
   *
   * Recursively checks `el` itself, then every light-DOM descendant and — critically, the exact
   * gap the narrower, direct-siblings-only `#occludingSiblingRects` this replaces could not see —
   * every descendant reachable through an open (`mode: "open"`) Shadow DOM root at any depth,
   * collecting the rect of each one whose own computed `z-index` ties {@link MAX_Z_INDEX} when it
   * also comes AFTER this instance's own `#frame` in tree order.
   *
   * `afterFrame`, once resolved for a node, is reused UNCHANGED for every descendant rather than
   * re-derived (`undefined` means "not yet known — derive it now"): if a node follows `#frame` in
   * tree order, so does every one of its descendants, and if it precedes `#frame`, so does every
   * one of its descendants — tree order is transitive this way, so one `compareDocumentPosition`
   * call per LIGHT-DOM boundary crossing is both correct and all this needs, never one per node.
   * This is also what makes crossing a Shadow DOM boundary safe despite `compareDocumentPosition`
   * itself being unreliable across one (two nodes rooted in different trees compare as
   * disconnected, per spec): a shadow root's entire rendered content paints exactly at its own
   * HOST element's position in the composed tree, so once the host's own `afterFrame` is known
   * (computed while the host was still being visited as a plain light-DOM element), every node
   * inside that host's shadow tree — and any shadow root nested further within it — inherits that
   * SAME value, with no further cross-boundary comparison ever attempted.
   *
   * CORRECTNESS REQUIREMENT, found in review (an earlier version of this fix called this with
   * `document.documentElement` itself as the first `el`, which is silently wrong): `el` must never
   * be a node on `#frame`'s own ANCESTOR PATH (`html`, `body`, or anything else between them and
   * `#frame`) — `compareDocumentPosition` reports an ancestor as PRECEDING its descendant (the
   * same flag a genuinely-earlier SIBLING gets), so resolving one of them this way yields `false`
   * for the wrong reason, and that `false` then propagates to EVERY descendant, including real
   * siblings that come after `#frame`. {@link #deepOccluderRects} avoids this by walking the
   * ancestor path one level at a time and calling this only on each level's SIBLINGS (fifth
   * adversarial round: originally scanned only `#frame.parentElement`'s children — i.e. only
   * `document.body`'s own children — which is the scan-SCOPE gap a decoy appended directly to
   * `document.documentElement`, a sibling of `<body>` rather than a descendant of it, exploited;
   * walking every ancestor level up to and including `documentElement` closes that without ever
   * passing an ancestor of `#frame` itself as `el`).
   *
   * `getComputedStyle` (the one real cost here) is only ever called for a node already known to
   * follow `#frame` — in practice almost always a small minority of the page, since ordinary page
   * chrome (headers, nav, footers) is already in the DOM, and therefore precedes a freshly
   * constructed `#frame` the content script always appends LAST, before this scan ever runs.
   *
   * `mode: "closed"` Shadow DOM is a named, left-open gap, not a silent one: `element.shadowRoot`
   * returns `null` for it by spec, with no API anywhere, in any browser, for an extension content
   * script (or any other same-process, non-devtools code) to read a closed shadow tree's content
   * — there is nothing here to close without a capability the web platform does not expose.
   */
  #scanElementForDeepOccluders(el: Element, afterFrame: boolean | undefined, candidates: Element[]): void {
    if (isOwnOverlayElement(el)) {
      return;
    }
    const resolved = afterFrame ?? (this.#frame.compareDocumentPosition(el) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0;
    if (resolved && this.#deepOccluderQualification(el) !== false) {
      candidates.push(el);
    }
    for (const child of el.children) {
      this.#scanElementForDeepOccluders(child, resolved, candidates);
    }
    if (el.shadowRoot !== null) {
      for (const child of el.shadowRoot.children) {
        this.#scanElementForDeepOccluders(child, resolved, candidates);
      }
    }
  }

  /** Whether `el` itself, or a `::before`/`::after` pseudo-element it generates, independently
   * ties the frame's own maximum z-index — and if so, which: `"own"` when `el`'s OWN computed
   * z-index already ties it (the pre-existing check), `"pseudo"` only when a generated-content
   * pseudo-element does while `el` itself does not (A7 pseudo-element deep-occluder fix, fourth
   * adversarial round: a host whose own `z-index` stays `"auto"` can still win the document-order
   * tie if its generated content declares its own `position`/`z-index` —
   * {@link pseudoElementTiesMaxZIndex}'s own doc has the full reasoning). Returning which one
   * qualified, not just whether, is what lets {@link #deepOccluderRects} pick the right occlusion
   * rect for each (tight, widened `getBoundingClientRect()` for `"own"`; conservative full
   * viewport for `"pseudo"`, which has no `Element`/`Node` of its own to read a rect from at all)
   * from the SAME style reads, rather than reading `el`'s own z-index a second time.
   *
   * The two extra `getComputedStyle` pseudo-element reads only ever run for an element the caller
   * already knows follows `#frame` in tree order — the same bound
   * {@link #scanElementForDeepOccluders}'s own doc already relies on to keep that walk affordable
   * (an already-small minority of the page in the common case), and the same bound
   * {@link #deepOccluderRects}'s own per-tick re-check relies on (the candidate SET, not the page,
   * bounds that cost). */
  #deepOccluderQualification(el: Element): "own" | "pseudo" | false {
    const zIndex = Number(getComputedStyle(el).zIndex);
    if (Number.isFinite(zIndex) && zIndex >= MAX_Z_INDEX) {
      return "own";
    }
    const before = getComputedStyle(el, "::before");
    if (pseudoElementTiesMaxZIndex(before.content, before.position, before.zIndex)) {
      return "pseudo";
    }
    const after = getComputedStyle(el, "::after");
    return pseudoElementTiesMaxZIndex(after.content, after.position, after.zIndex) ? "pseudo" : false;
  }

  /** Rebuilds {@link #deepOccluderCandidates} from scratch, walking `#frame`'s own siblings
   * (never `#frame`'s ancestors — see {@link #scanElementForDeepOccluders}'s own correctness
   * requirement) under its parent, only when {@link #deepOccludersDirty}; otherwise re-reads the
   * live rect — and re-checks {@link #deepOccluderQualification} still holds, so an element that
   * stops qualifying self-heals even between two dirty-triggered rebuilds, e.g. the
   * `CSSStyleSheet.insertRule` residual this class's own doc names — for each candidate already
   * found, which stays cheap regardless of page size because this SET, not the page, bounds it.
   *
   * A7 box-shadow/outline-escape fix (fourth adversarial round): an element that qualifies through
   * its OWN z-index (`"own"`) gets its occlusion rect from {@link pushOcclusionRect} — the same
   * box-shadow/outline/filter widening the top-layer path already uses — rather than its raw
   * `getBoundingClientRect()`, closing the identical "paints outside the border box, never
   * hit-tested" gap this path had and the top-layer path did not (confirmed by direct probe: a
   * 1×1, far-away decoy tying the frame's z-index with a 3000px box-shadow or outline blanketed
   * the viewport while its own rect never intersected the menu's). A qualification that comes ONLY
   * from a `::before`/`::after` pseudo-element (`"pseudo"`, A7 pseudo-element deep-occluder fix,
   * same round) has no `Element`/`Node` and no `getBoundingClientRect()` to widen in the first
   * place — the same structural gap {@link pushBackdropOcclusionRect} already closes for
   * `::backdrop` — so that case conservatively occludes the full viewport instead, never
   * narrower.
   *
   * A7 own-z-index-qualifying-element's-own-pseudo-element fix (fifth adversarial round): the
   * `"own"` branch below now ALSO checks `el`'s own `::before`/`::after` via
   * {@link pushPseudoOcclusionRect}, unconditionally, exactly as {@link #topLayerRects} already
   * does for every top-layer element — closing a gap `#deepOccluderQualification` itself left open
   * by returning only `"own"` (never also `"pseudo"`) the instant an element's OWN z-index already
   * ties the maximum: an element that qualifies that way got ONLY {@link pushOcclusionRect}'s
   * widening of its OWN rect, so a `::before`/`::after` that independently declares
   * `position: fixed; inset: 0` on that SAME element — a real, Node-less overlay, structurally
   * identical to the case {@link pushPseudoOcclusionRect} already exists to close for a
   * `"pseudo"`-only qualification — was never looked at. Two extra pseudo-element reads per
   * candidate, same cost shape already accepted for the top-layer path. */
  #deepOccluderRects(): Rect[] {
    if (this.#deepOccludersDirty) {
      this.#deepOccludersDirty = false;
      const candidates: Element[] = [];
      // Fifth adversarial round (scan-scope fix): walks `#frame`'s ANCESTOR PATH one level at a
      // time — `#frame`'s own parent (today, `document.body`), then THAT element's parent, and so
      // on up to and including `document.documentElement` — scanning each level's SIBLINGS (every
      // child of that level except the one continuing the chain toward `#frame`, which is itself
      // an ancestor of `#frame` and must never be passed to `#scanElementForDeepOccluders` as `el`
      // — see that method's own correctness requirement). The previous version only ever scanned
      // `#frame.parentElement.children` (`document.body`'s own children), which missed a decoy
      // appended directly to `document.documentElement` — a SIBLING of `<body>`, not a descendant
      // of it, so never reachable from inside `body`'s subtree at all, regardless of how deep or
      // how the walk inside `body` was extended. Terminates when `parentElement` is `null` (the
      // node IS `documentElement`, which has no element parent). Each level's own subtree, besides
      // the one child that continues the chain, is covered exactly once, by the iteration at THAT
      // level — never re-walked by a later, higher iteration. The one-time extra cost over the
      // previous version is `<head>`'s own subtree plus any other `documentElement`-level sibling
      // of `<body>` — negligible next to the existing bound (this SET, built once per dirty flag,
      // not the whole page re-walked every tick) and not re-benchmarked, since it adds at most one
      // more sibling subtree, of ordinary page-chrome size, to a walk whose own cost already scales
      // with page size regardless.
      let node: Element = this.#frame;
      while (node.parentElement !== null) {
        const parent: Element = node.parentElement;
        for (const sibling of parent.children) {
          if (sibling !== node) {
            this.#scanElementForDeepOccluders(sibling, undefined, candidates);
          }
        }
        node = parent;
      }
      this.#deepOccluderCandidates = candidates;
    }
    const rects: Rect[] = [];
    for (const el of this.#deepOccluderCandidates) {
      if (!el.isConnected) {
        continue;
      }
      const qualification = this.#deepOccluderQualification(el);
      if (qualification === "own") {
        pushOcclusionRect(rects, el);
        pushPseudoOcclusionRect(rects, el, "::before");
        pushPseudoOcclusionRect(rects, el, "::after");
      } else if (qualification === "pseudo") {
        rects.push(fullViewportRect());
      }
    }
    return rects;
  }

  destroy(): void {
    this.#deepOccluderObserver.disconnect();
    if (this.#rafId !== undefined) {
      cancelAnimationFrame(this.#rafId);
    }
    window.removeEventListener("message", this.#onMessage);
    this.#frame.remove();
  }

  /** GATE B (`menu-visibility.ts`'s own module doc): the authoritative, causally-after-click
   * check `installContentScript`'s `apply_fill` listener runs before ever writing a value into
   * the page.
   *
   * Takes one more LIVE sample, HERE, when `#frame` is still attached — closing a gap found by
   * direct measurement (A7, HANDOFF X6 bypass triage), reproducing a reported bypass's own
   * underlying idea with a different, reliable trigger. The reported trigger itself (`focus` on
   * the parent's `<iframe>` element) does not reliably fire for a real trusted click in this
   * architecture — measured directly across repeated real-click runs, it fires in roughly 2 of
   * 10, not 10 of 10 or 0 of 10 — so the original report's own mechanism is correctly rejected
   * (kept as a non-flaky test, `adversarial-fill-requests.spec.ts`). But `window`'s own `blur`
   * event, firing for the same underlying reason (focus moving into the cross-origin iframe),
   * fired in every run measured, within ~1-2ms of the click landing. A page with a
   * `window.blur` listener that hides the frame (`opacity: 0 !important`) and reveals it again
   * ~50ms later got a real fill through the OLD code in roughly half of repeated live-click
   * runs — not because Gate A's `requestAnimationFrame` loop was ever fooled by a well-timed
   * flip (that race is already closed, see the trailing-window doc below), but because this
   * method read ONLY the rolling history that loop had last written, up to one whole tick
   * (~16ms) stale, while `#frame` is routinely STILL attached when `apply_fill` arrives
   * (instrumented directly: ~15-120ms after the click in this harness, varying with machine
   * load) — `pick`'s own teardown (`destroy`, triggered by the iframe's `postMessage`) is a
   * later, independent task that in direct measurement usually lands AFTER this method already
   * ran, not before, so the "frozen since teardown" framing this method's own history assumed
   * was simply wrong for the common case. A hide landing in the gap between Gate A's last
   * periodic tick and this call had, until now, zero chance of ever being recorded. Querying
   * `#frame.isConnected` rather than sampling unconditionally is what keeps this safe for the
   * OTHER case — `destroy` already ran, `#frame` is detached, `getBoundingClientRect()` on it
   * would read an all-zero rect, always a bad sample, which would spuriously refuse a fill
   * arriving after an ordinary, already-completed teardown; skipping the live sample there
   * leaves that case exactly as before, reading only the frozen history.
   *
   * Residual, named rather than silently unclosed (THREAT_MODEL.md A7 has the full text): in
   * that SAME "already detached" case, the decision is back to resting purely on history up to
   * one tick stale — a page that could reliably win the ordering race the other way (make its
   * own hide land, and `destroy` finish, inside the SAME gap before this call) would not be
   * caught by the live sample above, because there would be no live sample to take. Not
   * reproduced as a working trigger here — the page has no way to control exactly when
   * `destroy`'s own async `postMessage` resolves relative to `apply_fill` — but not proven
   * impossible either. */
  isFillAllowedNow(now: number): boolean {
    if (this.#frame.isConnected) {
      this.#visibilityState = recordSample(this.#visibilityState, now, this.#sampleOk());
    }
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
    // Three independent occlusion sources fed into the same rect-intersection check
    // (`isTopLayerClear`'s own doc): the browser's top layer (including each top-layer element's
    // own `::backdrop`, A7 bypass fix), any element anywhere in the document — light DOM at any
    // depth, or an open Shadow DOM root — tying the frame's own maximum z-index that comes after
    // it in tree order (A7 bypass-2/nested-decoy fix, `#deepOccluderRects`), and (sixth
    // adversarial round) each ANCESTOR's own `::before`/`::after` tying the frame's maximum
    // z-index (`#ancestorPseudoOcclusionRects` — deliberately separate from `#deepOccluderRects`,
    // which by its own correctness requirement never visits an ancestor itself) — together the
    // only routes ordinary DOM stacking has to paint above a `zIndex: MAX_Z_INDEX` element, and
    // one `elementFromPoint`-based hit-testing can never catch on its own when the occluder is
    // `pointer-events: none` (this method's own point-hit check, below, is blind to exactly this).
    if (!isTopLayerClear(this.#expectedRect, [...this.#topLayerRects(), ...this.#deepOccluderRects(), ...this.#ancestorPseudoOcclusionRects()])) {
      return false;
    }
    return isPointHitOk(this.#pointHitResult());
  }

  /**
   * Sixth adversarial round. Reported bypass: `body::after { position: fixed; inset: 0; z-index:
   * 2147483647; ... }` — one CSS rule, no JavaScript. `body` is the frame's own ANCESTOR
   * (`document.body.appendChild(frame)` in this constructor), never a sibling
   * `#scanElementForDeepOccluders` would visit — that method's own correctness requirement is
   * that `el` must never be a node on the frame's ancestor path, so `#deepOccluderRects`
   * deliberately never passes `body`/`documentElement` themselves to the pseudo-element check it
   * already runs on every SIBLING candidate (`pushPseudoOcclusionRect`/`pseudoElementTiesMaxZIndex`).
   * That correctness requirement does not apply here: this checks each ancestor's OWN generated
   * content, never a sibling, and needs no `compareDocumentPosition` tree-order reasoning at all
   * — per CSS2.1 Appendix E, `::after` is generated as the LAST box in its own host's paint
   * order, UNCONDITIONALLY, regardless of when real children were inserted, so an ancestor's own
   * `::after` always follows the frame (one of that ancestor's real descendants) in paint order;
   * only a TIE at the frame's own maximum z-index (never a strictly lower one) lets it win, which
   * {@link pseudoElementTiesMaxZIndex} already encodes. Walks `parentElement` from the frame's
   * immediate parent up to and including `documentElement` (today, `{body, documentElement}`),
   * mirroring `#chainSamples`'s own walk one level narrower (never the frame itself — pseudo-
   * elements of the frame's own iframe box are not a thing this needs to reason about).
   */
  #ancestorPseudoOcclusionRects(): Rect[] {
    const rects: Rect[] = [];
    let node = this.#frame.parentElement;
    while (node !== null) {
      const before = getComputedStyle(node, "::before");
      if (pseudoElementTiesMaxZIndex(before.content, before.position, before.zIndex)) {
        rects.push(fullViewportRect());
      }
      const after = getComputedStyle(node, "::after");
      if (pseudoElementTiesMaxZIndex(after.content, after.position, after.zIndex)) {
        rects.push(fullViewportRect());
      }
      node = node.parentElement;
    }
    return rects;
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
        isolation: style.getPropertyValue("isolation") || "auto",
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
   * stays 1×1, and box-shadow never participates in hit-testing), `outline` (same paint-outside-
   * the-box, never-hit-tested shape, fourth adversarial round), and non-`none` `filter` can all
   * paint a top-layer element's visible extent far outside its own border box, so taking the raw
   * rect at face value here was the exact gap those reports used.
   *
   * A7 `::backdrop` bypass fix: {@link pushBackdropOcclusionRect} additionally checks each
   * element's own `::backdrop` pseudo-element — a browser-painted box with no corresponding
   * `Element`/`Node` at all, so `pushOcclusionRect` above, which only ever reads an ELEMENT's own
   * rect/filter/box-shadow/outline, cannot see it regardless of how it is widened. A top-layer
   * backdrop is always sized to the full viewport by the browser itself (never shrunk by author
   * CSS, only made transparent or not), so there is nothing to bound more precisely than "does it
   * paint something, yes or no."
   *
   * A7 pseudo-element bypass fix (fourth adversarial round): {@link pushPseudoOcclusionRect}
   * additionally checks each element's `::before`/`::after` — also a browser-painted box with no
   * `Element`/`Node` of its own, closing the same structural gap for generated content that
   * independently declares `position: fixed` and paints (its own doc has the full reasoning and
   * the stated, narrower-than-`position:absolute` scope). */
  #topLayerRects(): Rect[] {
    const rects: Rect[] = [];
    if (document.fullscreenElement !== null) {
      pushOcclusionRect(rects, document.fullscreenElement);
      pushBackdropOcclusionRect(rects, document.fullscreenElement);
      pushPseudoOcclusionRect(rects, document.fullscreenElement, "::before");
      pushPseudoOcclusionRect(rects, document.fullscreenElement, "::after");
    }
    for (const dialog of document.querySelectorAll("dialog[open]")) {
      pushOcclusionRect(rects, dialog);
      pushBackdropOcclusionRect(rects, dialog);
      pushPseudoOcclusionRect(rects, dialog, "::before");
      pushPseudoOcclusionRect(rects, dialog, "::after");
    }
    try {
      for (const popover of document.querySelectorAll(":popover-open")) {
        pushOcclusionRect(rects, popover);
        pushBackdropOcclusionRect(rects, popover);
        pushPseudoOcclusionRect(rects, popover, "::before");
        pushPseudoOcclusionRect(rects, popover, "::after");
      }
    } catch {
      // No Popover API support: nothing can be `:popover-open` either.
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

/** A full-viewport occlusion rect — the conservative substitute every "cannot confidently bound
 * this" path below uses, never a narrower guess ("only ever refuse more"). */
function fullViewportRect(): Rect {
  return { left: 0, top: 0, width: window.innerWidth, height: window.innerHeight };
}

/** Bound on how many descendant nodes {@link collectUnclippedDescendantRects} will ever visit for
 * one `pushOcclusionRect` call (fifth adversarial round). Chosen to sit comfortably below the
 * third adversarial round's own measured-too-slow figure (~103ms average walking 5000 plain
 * elements with a `getComputedStyle` read per node, `#deepOccludersDirty`'s own doc) while staying
 * generous enough that an ordinary, legitimately content-rich `<dialog>` (a form with a few dozen
 * fields, say) does not trip the full-viewport fallback — not independently re-benchmarked for
 * this narrower, `getBoundingClientRect()`-only walk (cheaper per node than `getComputedStyle`,
 * and always confined to one element's own subtree, never the whole page), so this is a
 * conservative starting point, not a measured ceiling. */
const MAX_UNCLIPPED_DESCENDANTS = 256;

/** Collects every descendant's own `getBoundingClientRect()` under `el`, following light-DOM
 * children AND every open (`mode: "open"`) Shadow DOM root at any depth — the same traversal
 * shape {@link InlineMenu}'s own `#scanElementForDeepOccluders` already uses for the deep-occluder
 * candidate set, reused here so an escaping descendant nested inside an open shadow root is
 * covered the same way a light-DOM one is (`pushOcclusionRect`'s own doc has the full reasoning
 * for why this exists and why it is bounded). Returns `undefined`, never a partial list, once more
 * than {@link MAX_UNCLIPPED_DESCENDANTS} nodes have been visited — the caller must then widen its
 * own fallback to the full viewport rather than settle for an under-counted, narrower union
 * ("only ever refuse more," the same contract {@link parseBoxShadowMarginPx} and every other
 * unboundable-shape fallback in this file already follow). `mode: "closed"` Shadow DOM is the
 * same already-named, structurally unreachable residual `#scanElementForDeepOccluders` names —
 * not a new gap this function reopens. */
function collectUnclippedDescendantRects(el: Element): DOMRect[] | undefined {
  const rects: DOMRect[] = [];
  const stack: Element[] = [el];
  let visited = 0;
  let node: Element | undefined;
  while ((node = stack.pop()) !== undefined) {
    for (const child of node.children) {
      visited += 1;
      if (visited > MAX_UNCLIPPED_DESCENDANTS) {
        return undefined;
      }
      rects.push(child.getBoundingClientRect());
      stack.push(child);
    }
    if (node.shadowRoot !== null) {
      for (const shadowChild of node.shadowRoot.children) {
        visited += 1;
        if (visited > MAX_UNCLIPPED_DESCENDANTS) {
          return undefined;
        }
        rects.push(shadowChild.getBoundingClientRect());
        stack.push(shadowChild);
      }
    }
  }
  return rects;
}

/** Pushes `el`'s occlusion rect onto `rects`, widened for any paint that can escape its own
 * border box (A7 bypass-1/3 fix, `InlineMenu#topLayerRects`'s own doc; A7 outline-escape fix,
 * fourth adversarial round; A7 text-shadow/border-image/unclipped-descendant fixes, fifth
 * adversarial round). A non-`none` `filter` (e.g. `drop-shadow`) is rare on a top-layer
 * element and not reliably boundable from computed style alone, so it conservatively substitutes
 * the full viewport rect rather than attempting to parse `filter`'s own shorthand;
 * `parseBoxShadowMarginPx`/`parseOutlineMarginPx` returning `undefined` (a computed shape either
 * parser does not recognise) does the same — "only ever refuse more" means a value this cannot
 * confidently bound must widen the fallback, never narrow it. `outline` paints a uniform ring
 * around the border box exactly like `box-shadow` (never changes `getBoundingClientRect()`, never
 * participates in hit-testing) — the two margins are independent properties of the same element,
 * so the wider of the two bounds the combined painted extent (a uniform single margin is already
 * this function's own, pre-existing simplification; see `parseBoxShadowMarginPx`'s own doc on
 * why a single margin, not a per-side one, is deliberate).
 *
 * `text-shadow` (fifth adversarial round): unlike `box-shadow`/`outline`, this function does not
 * attempt to derive a margin from `el`'s own rect at all — confirmed by direct probe, a 1×1,
 * `overflow: visible` element with an oversized `font-size` and `color: transparent` already
 * renders its own (invisible) glyph far outside its border box BEFORE any `text-shadow` offset is
 * even applied, so a margin computed from `el.getBoundingClientRect()` would under-estimate the
 * painted extent regardless of how the shadow offset itself were parsed — the one shape in this
 * function where "only ever refuse more" rules out attempting a margin at all. Any non-`"none"`
 * `text-shadow` therefore substitutes the full viewport rect directly, the same conservative
 * answer `filter` already gets.
 *
 * `border-image` (fifth adversarial round): a `border-image-source` other than `"none"` paints
 * the border-image area, which `border-image-outset` can extend beyond the border box by an
 * author-controlled amount with no corresponding change to `getBoundingClientRect()` and no
 * participation in hit-testing — the identical shape `box-shadow`/`outline` already have a margin
 * carve-out for, except `border-image-outset`'s two possible value shapes (an outset `<number>`
 * multiplies the corresponding `border-width`, which this function has no reliable access to)
 * make a precise margin unsound to compute here ({@link isAllZeroLengths}'s own doc); gated on
 * `border-image-outset` rather than on `border-image-source` alone, so an ordinary decorative
 * border-image with no outset (overwhelmingly the common case) is never falsely widened.
 *
 * Unclipped-descendant escape (fifth adversarial round): `el.getBoundingClientRect()` only ever
 * reflects `el`'s OWN layout box — an `overflow: visible` element (the default for most elements,
 * and for the outermost `<svg>` specifically, confirmed by direct probe: the UA stylesheet only
 * forces `overflow: hidden` on a NESTED `svg`/`symbol`/`image`/`marker`/`pattern`/`foreignObject`/
 * `clipPath`/`mask`, never on the document's outermost one) whose descendant is positioned, or an
 * SVG descendant drawn, outside that box paints there regardless — confirmed by direct probe for
 * both an `<svg>` host with an out-of-viewBox `<rect>`/`<foreignObject>` child and the identical
 * HTML analogue (a plain `position: absolute` descendant placed outside its unclipped ancestor).
 * Scoped to an element that does NOT clip on BOTH axes (`overflow-x`/`overflow-y` both `hidden`/
 * `clip`): a genuinely clipping container cannot let a descendant paint outside it, so this union
 * is skipped entirely for the common case of an ordinary clipped widget, and for a childless
 * element (the union of zero rects changes nothing). Widens by UNIONING every descendant's own raw
 * rect into the result, not by substituting the full viewport: an ordinary top-layer
 * `<dialog>`/popover's own content almost always renders INSIDE its own visual box regardless of
 * its `overflow` value, so the union equals the already-widened rect in that common case (no added
 * false-refusal cost), while a descendant genuinely painted outside the host's box — the attack
 * this closes — still widens the result exactly as far as that descendant's own rect requires. A
 * descendant hidden behind a nested clipping container of its own is still unioned in (its rect is
 * read directly, not checked against further ancestors between it and `el`) — strictly wider than
 * necessary in that case, never narrower, the same "only ever refuse more" direction as every
 * other fallback in this function.
 *
 * {@link collectUnclippedDescendantRects} does the actual walk, bounded by
 * {@link MAX_UNCLIPPED_DESCENDANTS} and crossing into every open (`mode: "open"`) Shadow DOM root
 * it finds, the same traversal shape {@link InlineMenu}'s own `#scanElementForDeepOccluders`
 * already uses — reused here so an escaping descendant nested inside an open shadow root is
 * covered the same way a light-DOM one is, rather than reopening that exact gap one boundary over.
 * UNLIKE {@link InlineMenu}'s deep-occluder candidate set, this walk cannot be deferred behind a
 * dirty flag: this function runs for a handful of top-layer/deep-occluder elements, not the whole
 * page, but it still runs on every Gate-A tick for each one, and a widened rect has to reflect the
 * CURRENT render, which no mutation needs to have changed at all (a descendant's position can move
 * via an ongoing CSS animation with no corresponding `MutationObserver` record). Bounding the
 * traversal by node count, rather than leaving it unconditional, is what keeps this affordable: the
 * third adversarial round measured an unconditional, unbounded walk at ~103ms average on a
 * 5000-element page (`#deepOccludersDirty`'s own doc), far too slow for a 16ms tick budget — this
 * walk is always confined to one element's own subtree, not the whole page, but an ordinary
 * `<dialog>`'s content could still be arbitrarily large, so it is capped the same "only ever refuse
 * more" way as every other unboundable shape here: past the cap, {@link
 * collectUnclippedDescendantRects} returns `undefined` and this substitutes the full viewport
 * rather than return an under-counted, narrower union. */
function pushOcclusionRect(rects: Rect[], el: Element): void {
  const style = getComputedStyle(el);
  if (style.filter !== "none") {
    rects.push(fullViewportRect());
    return;
  }
  if (style.textShadow !== "none") {
    rects.push(fullViewportRect());
    return;
  }
  if (style.borderImageSource !== "none" && !isAllZeroLengths(style.borderImageOutset)) {
    rects.push(fullViewportRect());
    return;
  }
  const shadowMargin = parseBoxShadowMarginPx(style.boxShadow);
  if (shadowMargin === undefined) {
    rects.push(fullViewportRect());
    return;
  }
  const outlineMargin = parseOutlineMarginPx(style.outlineStyle, style.outlineWidth, style.outlineOffset);
  if (outlineMargin === undefined) {
    rects.push(fullViewportRect());
    return;
  }
  const margin = Math.max(shadowMargin, outlineMargin);
  const rect = toRect(el.getBoundingClientRect());
  let left = rect.left - margin;
  let top = rect.top - margin;
  let right = rect.left + rect.width + margin;
  let bottom = rect.top + rect.height + margin;

  const clipsX = style.overflowX === "hidden" || style.overflowX === "clip";
  const clipsY = style.overflowY === "hidden" || style.overflowY === "clip";
  if (!clipsX || !clipsY) {
    const descendantRects = collectUnclippedDescendantRects(el);
    if (descendantRects === undefined) {
      rects.push(fullViewportRect());
      return;
    }
    for (const dRect of descendantRects) {
      if (dRect.width === 0 && dRect.height === 0) {
        continue;
      }
      left = Math.min(left, dRect.left);
      top = Math.min(top, dRect.top);
      right = Math.max(right, dRect.left + dRect.width);
      bottom = Math.max(bottom, dRect.top + dRect.height);
    }
  }
  rects.push({ left, top, width: right - left, height: bottom - top });
}

/** Pushes a full-viewport occlusion rect when `el`'s `::before` or `::after` pseudo-element is
 * independently painting a `position: fixed` overlay (A7 pseudo-element top-layer fix, fourth
 * adversarial round; {@link pseudoElementPaintsFixedOverlay}'s own doc has the full reasoning and
 * the stated, narrower-than-`position:absolute` scope). Guarded in a `try`, same "only ever refuse
 * more" contract as {@link pushBackdropOcclusionRect}: an older browser can throw on the
 * two-argument pseudo-element form rather than returning initial values, and that failure must
 * widen this to the full viewport too, never silently skip it. */
function pushPseudoOcclusionRect(rects: Rect[], el: Element, pseudo: "::before" | "::after"): void {
  try {
    const style = getComputedStyle(el, pseudo);
    if (pseudoElementPaintsFixedOverlay(style.content, style.position, style.backgroundColor, style.backgroundImage, style.boxShadow)) {
      rects.push(fullViewportRect());
    }
  } catch {
    rects.push(fullViewportRect());
  }
}

/** Pushes a full-viewport occlusion rect when `el`'s own `::backdrop` pseudo-element is occluding
 * (A7 bypass fix, `InlineMenu#topLayerRects`'s own doc): a `popover`/`dialog`/fullscreen
 * element's rendered backdrop has no corresponding `Element`/`Node` for {@link pushOcclusionRect}
 * above to find — `getComputedStyle(el, "::backdrop")`, the two-argument pseudo-element form, is
 * the only way to read it. Guarded in a `try`: an older browser can throw on an unsupported
 * pseudo-element argument rather than returning initial values, and "only ever refuse more" means
 * that failure must widen this to the full viewport too, never silently skip it — the one
 * behaviour this function must NEVER have is "an exception here quietly drops a real occluder." */
function pushBackdropOcclusionRect(rects: Rect[], el: Element): void {
  try {
    const style = getComputedStyle(el, "::backdrop");
    if (isBackdropOccluding(style.backgroundColor, style.backgroundImage)) {
      rects.push(fullViewportRect());
    }
  } catch {
    rects.push(fullViewportRect());
  }
}
