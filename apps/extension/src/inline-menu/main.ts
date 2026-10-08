// The inline-menu iframe's own script (ADR 0036 §4/§5; ADR 0014 §2-style — framework-free,
// like the content script, since this is a few buttons with no state worth a framework). Runs
// at the extension's own origin, inside an iframe `content-script.ts` injects into an untrusted
// page: see `protocol.ts` for exactly what that origin boundary does and does not guarantee.
import { INLINE_MENU_PICK, isInlineMenuShowMessage, type InlineMenuCandidate } from "./protocol.ts";

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

function render(candidates: readonly InlineMenuCandidate[]): void {
  if (list === null) {
    return;
  }
  list.replaceChildren();
  for (const candidate of candidates) {
    const item = document.createElement("button");
    item.type = "button";
    item.textContent = `${candidate.title} (${candidate.username})`;
    item.style.display = "block";
    item.style.width = "100%";
    item.style.textAlign = "left";
    item.addEventListener("click", (event) => {
      // Defence in depth, not the primary guarantee (INV-36): the primary guarantee is that
      // this document's DOM is unreachable from the page's own JS at all (cross-origin iframe),
      // so the page cannot call `.click()` on this button in the first place. This check only
      // guards against some future change accidentally making that call reachable.
      if (!event.isTrusted) {
        return;
      }
      if (replyOrigin === undefined) {
        return;
      }
      // Unforgeable in the other direction (`protocol.ts`): `window.parent`'s listener checks
      // `event.source`/`event.origin` against this iframe's own, real identity, which no script
      // running in the page's window can fake.
      window.parent.postMessage({ type: INLINE_MENU_PICK, itemId: candidate.itemId }, replyOrigin);
    });
    list.appendChild(item);
  }
}
