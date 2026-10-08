// The content script (ADR 0036 §4, §5; ADR 0014 §2: "plain TypeScript, no wasm, no React").
// Top frame only for now (ADR 0037 §5 "no cross-origin iframe fill by default" — this file
// does not even try same-origin-iframe fill yet, a stricter default than the ADR requires,
// tracked in `not_done`). It never imports `@rizzy-vault/core` (enforced by
// `eslint.config.mjs`'s `no-restricted-imports` for this file) and never fills without a
// trusted user gesture (INV-36): detection and the inline-menu offer happen passively, but the
// actual DOM write only ever runs inside the extension-origin inline-menu iframe's own `click`
// handler (`InlineMenu`, `inline-menu/main.ts`) — the menu the user opened, in a document the
// page's own JS cannot reach at all (not merely one it is asked nicely not to script).
import {
  MAX_FIELDS_PER_REPORT,
  type CandidatesMessage,
  type FieldDescriptor,
  type FillChosenMessage,
  type FillValuesMessage,
  type FromContentScript,
  type ToContentScript,
} from "../messaging/contract.ts";
import { INLINE_MENU_SHOW, isInlineMenuPickMessage } from "../inline-menu/protocol.ts";

if (window.top === window) {
  installContentScript();
}

function installContentScript(): void {
  let menu: InlineMenu | undefined;

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
        wireInlineMenu(answer, fields);
      }
    });
  };

  function wireInlineMenu(answer: CandidatesMessage, fields: readonly FieldDescriptor[]): void {
    const usernameField = document.querySelector<HTMLInputElement>('input[data-rizzy-field="username"]');
    const passwordField = document.querySelector<HTMLInputElement>('input[data-rizzy-field="password"]');
    menu?.destroy();
    if (answer.candidates.length === 0 || passwordField === null) {
      menu = undefined;
      return;
    }
    menu = new InlineMenu(passwordField, answer.candidates, (itemId) => {
      // The gesture: `InlineMenu` only calls this once its own iframe reports a trusted click.
      // `menu` is already destroyed by this point (`InlineMenu`'s own message handler destroys
      // itself before calling `onPick`), so nothing of ours covers `target` when `applyFill`'s
      // own visibility recheck runs.
      const fieldIds = fields.filter((f) => f.kind === "username" || f.kind === "password").map((f) => f.fieldId);
      void sendToBackground({
        type: "fill_chosen",
        pageUrl: location.href,
        isTopFrame: true,
        itemId,
        fieldIds,
      } satisfies FillChosenMessage).then((result) => {
        if (result?.type === "fill_values") {
          applyFill(result, usernameField, passwordField);
        }
      });
    });
  }

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
  new MutationObserver(schedule).observe(document.documentElement, { childList: true, subtree: true });
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
  values: FillValuesMessage,
  usernameField: HTMLInputElement | null,
  passwordField: HTMLInputElement,
): void {
  for (const [fieldId, value] of Object.entries(values.values)) {
    const target =
      usernameField?.dataset["rizzyFieldId"] === fieldId
        ? usernameField
        : passwordField.dataset["rizzyFieldId"] === fieldId
          ? passwordField
          : undefined;
    if (target === undefined) {
      continue;
    }
    // THREAT_MODEL.md row "T" (page scripts rearrange forms between click and fill): "re-check
    // origin, frame and visibility at fill time," not only when the field was first detected.
    // The inline menu is destroyed before this runs (`wireInlineMenu`'s `onPick`), so it is
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
 * the instant it reports a pick (before telling `onPick`, so nothing of this menu's own is ever
 * what a later visibility recheck sees covering the field). */
class InlineMenu {
  readonly #frame: HTMLIFrameElement;
  readonly #onMessage: (event: MessageEvent) => void;
  readonly #onBlur: () => void;

  constructor(anchor: HTMLInputElement, candidates: CandidatesMessage["candidates"], onPick: (itemId: string) => void) {
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
            candidates: candidates.map((c) => ({ itemId: c.itemId, title: c.title, username: c.username })),
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
      const itemId = event.data.itemId;
      this.destroy();
      onPick(itemId);
    };
    window.addEventListener("message", this.#onMessage);

    // Appended before `src` is set, as elsewhere in this file's DOM handling: assigning `src`
    // on a not-yet-attached iframe does not reliably start the load in every engine.
    document.body.appendChild(frame);
    frame.src = inlineMenuUrl();

    this.#frame = frame;
    this.#onBlur = () => this.destroy();
    anchor.addEventListener("blur", this.#onBlur);
  }

  destroy(): void {
    window.removeEventListener("message", this.#onMessage);
    this.#frame.remove();
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
