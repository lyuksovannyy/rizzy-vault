// The inline-menu iframe's own script (ADR 0036 §4/§5; ADR 0014 §2-style — framework-free,
// like the content script, since this is a few buttons with no state worth a framework). Runs
// at the extension's own origin, inside an iframe `content-script.ts` injects into an untrusted
// page: see `protocol.ts` for exactly what that origin boundary does and does not guarantee.
import { INLINE_MENU_PICK, isInlineMenuShowMessage, type InlineMenuCandidate } from "./protocol.ts";
import { decideClick } from "./decide-click.ts";
import type { InlineMenuFillRequestMessage } from "../messaging/contract.ts";

const list = document.getElementById("list");
if (list === null) {
  throw new Error("inline-menu: #list is missing from index.html");
}

let replyOrigin: string | undefined;

window.addEventListener("message", (event) => {
  // `event.source`/`event.origin` are set by the browser from the real sending window and
  // document, never from the message body — but the sender here is `window.parent`, which the
  // embedding page's own script shares with the content script that is supposed to be the only
  // one sending this (`protocol.ts`'s documented residual: this direction cannot tell them
  // apart). Checking it anyway costs nothing and rejects any OTHER window's attempt.
  if (event.source !== window.parent) {
    return;
  }
  if (!isInlineMenuShowMessage(event.data)) {
    return;
  }
  replyOrigin = event.data.pageOrigin;
  render(event.data.candidates);
});

/** Candidates the user has already seen the equivalence warning for and confirmed once
 * (`itemId` set). A second click on the same candidate fills; the warning re-shows for a
 * different candidate or after a fresh `render()` (new page, new report). */
const confirmed = new Set<string>();

function render(candidates: readonly InlineMenuCandidate[]): void {
  if (list === null) {
    return;
  }
  confirmed.clear();
  list.replaceChildren();
  for (const candidate of candidates) {
    list.appendChild(renderCandidate(candidate));
  }
}

function renderCandidate(candidate: InlineMenuCandidate): HTMLElement {
  const wrapper = document.createElement("div");
  const item = document.createElement("button");
  item.type = "button";
  item.style.display = "block";
  item.style.width = "100%";
  item.style.textAlign = "left";
  const label = () =>
    candidate.needsWarning && !confirmed.has(candidate.itemId)
      ? `${candidate.title} (${candidate.username}) — different, equivalent domain. Click again to fill.`
      : `${candidate.title} (${candidate.username})`;
  item.textContent = label();
  item.addEventListener("click", (event) => {
    // Defence in depth, not the primary guarantee (INV-36): the primary guarantee is that this
    // document's DOM is unreachable from the page's own JS at all (cross-origin iframe), so the
    // page cannot call `.click()` on this button in the first place. This check only guards
    // against some future change accidentally making that call reachable.
    if (!event.isTrusted) {
      return;
    }
    // Captured now, not read again inside the `.finally` below: `replyOrigin` is a `let`
    // (reassigned if a fresh `InlineMenuShowMessage` arrives), so TypeScript cannot narrow it as
    // still-defined across that later, asynchronous callback — and semantically it should stay
    // whatever it was for *this* candidate's own render pass regardless of what arrives later.
    const origin = replyOrigin;
    if (origin === undefined) {
      return;
    }
    // ADR 0037 §5: a candidate that only matched via the equivalence list (a different
    // registrable domain treated as equivalent) needs its own explicit confirmation beyond the
    // one trusted click every fill already requires — the first click on such a candidate only
    // shows the warning text above; a second trusted click on the same button fills.
    // `decideClick` (`decide-click.ts`, unit-tested in `test/decide-click.test.ts`) is the
    // decision of whether to warn-and-return or to fill, and if filling, what
    // `confirmedEquivalence` to send — see that module's own doc for why it is pulled out.
    const decision = decideClick(candidate, confirmed);
    if (decision.action === "warn") {
      confirmed.add(candidate.itemId);
      item.textContent = label();
      return;
    }
    // The actual fill request (ADR 0040): sent directly to the background from
    // this extension-origin document, on the same trusted click `event.isTrusted` just checked
    // above — never relayed through the content script, which has no way to produce a
    // `sender.origin` equal to this extension's own (`messaging/sender.ts`'s
    // `isInlineMenuSender`; `core-host/listener.ts` is the only thing that accepts this message
    // type, and only from a sender that passes that check). The background re-derives the
    // candidate list itself from this tab's own real URL rather than trusting anything here —
    // this message carries no `pageUrl`/`itemId`-origin claim for it to even make.
    //
    // The `INLINE_MENU_PICK` teardown message — which makes the content script `remove()` this
    // very iframe — is sent only once `requestFill` *settles*, not right after starting it: a
    // real bug, found empirically running this change's E2E coverage against a real Chromium
    // build. Removing an iframe from the DOM tears down its JS execution context immediately,
    // including any `chrome.runtime.sendMessage` call still awaiting a response; sending both
    // messages back-to-back destroyed this document before the extension's own message channel
    // had a chance to complete the round trip, so the fill request was silently abandoned
    // mid-flight (no response, no thrown error to catch — the context simply ceased to exist).
    // Waiting for `requestFill` to settle first costs nothing visible to the user (the menu was
    // never shown again regardless, and this is a background `postMessage`, not a repaint), and
    // it is why `requestFill` itself must settle on every code path, including when `ext` is
    // `undefined` or the call throws.
    void requestFill(candidate.itemId, decision.confirmedEquivalence).finally(() => {
      // Unforgeable in the other direction (`protocol.ts`): `window.parent`'s listener checks
      // `event.source`/`event.origin` against this iframe's own, real identity, which no script
      // running in the page's window can fake.
      window.parent.postMessage({ type: INLINE_MENU_PICK, itemId: candidate.itemId }, origin);
    });
  });
  wrapper.appendChild(item);
  return wrapper;
}

/** Sends the one privileged message this document ever sends (ADR 0040), and
 * always settles (resolves, never rejects) once the round trip is over — its caller holds the
 * `INLINE_MENU_PICK` teardown message until this settles, precisely so the content script never
 * `remove()`s this document while the message is still in flight (see the caller's own comment
 * on why that ordering matters). The response itself is deliberately not inspected further: a
 * failure (device locked, candidate no longer valid) is not something this one-shot menu has any
 * UI left to show once it tears down right after — the content script's own next detection pass,
 * or the user trying again, is what recovers from it. */
async function requestFill(itemId: string, confirmedEquivalence: boolean): Promise<void> {
  const ext = typeof chrome !== "undefined" ? chrome : browser;
  if (ext === undefined) {
    return;
  }
  try {
    await ext.runtime.sendMessage({
      type: "inline_menu_fill_chosen",
      itemId,
      confirmedEquivalence,
    } satisfies InlineMenuFillRequestMessage);
  } catch {
    // The background/offscreen document was unreachable (e.g. mid-restart): nothing to do.
  }
}
