// The `window.postMessage` protocol between the content script (running in the untrusted
// page's own window — isolated-world JS, but a shared DOM/BOM, including `window` itself) and
// the extension-origin inline-menu iframe it creates (ADR 0036 §4/§5, ADR 0036 §75 "the
// inline-menu iframe app"; INV-36, INV-40). Carries no secrets, only title/username summaries
// (ADR 0013 §3 rule 3) in, and the user's chosen `itemId` out — never crosses
// `messaging/contract.ts`'s background-messaging boundary, and is validated on both ends all
// the same, because `postMessage` delivers to any listener regardless of claimed source.
//
// Security note, documented per CLAUDE.md "where a spec is ambiguous, pick the most
// conservative reading": the two directions are NOT equally trustworthy, because the content
// script's `window` is the same object as the page's own `window` (isolated worlds share the
// DOM/BOM) —
//   - content script -> iframe ({@link InlineMenuShowMessage}): forgeable. A hostile page's own
//     script can call `frame.contentWindow.postMessage(...)` just as validly as the content
//     script can; the iframe cannot tell which script in the shared window actually made the
//     call. A forged show message can therefore only ever carry *fabricated* `itemId`s the
//     attacker invented, since real ones are never otherwise observable from the page (never
//     written into the DOM, never echoed to a `window`-level listener — a message targeted at
//     `frame.contentWindow` is delivered there, not back to the sender's own listeners).
//   - iframe -> content script ({@link InlineMenuPickMessage}): NOT forgeable. The receiving
//     side checks `event.source === frame.contentWindow && event.origin === <this extension's
//     origin>`, both of which the browser sets from the true sending window/document and which
//     no page script can fake without actually executing code as that other origin.
// So the one thing that matters for INV-36 — a fill only ever follows a real click inside the
// iframe, never an automated one the page scripted — holds regardless. The one thing a forged
// show message can do is make the menu *display* fabricated entries; picking one leads nowhere,
// because `fill_chosen` still resolves `itemId` against the user's real vault items in the long
// -lived context, which a page-invented id never matches. This is a real, accepted residual
// (reported, not hidden): a hostile page can still make the dropdown show bogus-looking
// options, though it cannot make anything fill without the user's own trusted click, and cannot
// make a real item's title/username appear mislabelled, since it cannot observe real ones to
// relabel in the first place.
import { MAX_CANDIDATES, MAX_FIELD_VALUE_LEN, MAX_TITLE_LEN } from "../messaging/contract.ts";

export const INLINE_MENU_SHOW = "rizzy-inline-menu-show";
export const INLINE_MENU_PICK = "rizzy-inline-menu-pick";

export interface InlineMenuCandidate {
  readonly itemId: string;
  readonly title: string;
  readonly username: string;
}

export interface InlineMenuShowMessage {
  readonly type: typeof INLINE_MENU_SHOW;
  /** The embedding page's origin, used only as this message's own `postMessage` target when
   * the iframe later replies — never trusted as an identity claim beyond that. */
  readonly pageOrigin: string;
  readonly candidates: readonly InlineMenuCandidate[];
}

export interface InlineMenuPickMessage {
  readonly type: typeof INLINE_MENU_PICK;
  readonly itemId: string;
}

function isBoundedString(value: unknown, maxLen: number): value is string {
  return typeof value === "string" && value.length <= maxLen;
}

function isCandidate(value: unknown): value is InlineMenuCandidate {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  return isBoundedString(v["itemId"], 256) && isBoundedString(v["title"], MAX_TITLE_LEN) && isBoundedString(v["username"], MAX_FIELD_VALUE_LEN);
}

export function isInlineMenuShowMessage(value: unknown): value is InlineMenuShowMessage {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  if (v["type"] !== INLINE_MENU_SHOW || !isBoundedString(v["pageOrigin"], MAX_FIELD_VALUE_LEN)) {
    return false;
  }
  return Array.isArray(v["candidates"]) && v["candidates"].length <= MAX_CANDIDATES && v["candidates"].every(isCandidate);
}

export function isInlineMenuPickMessage(value: unknown): value is InlineMenuPickMessage {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  return v["type"] === INLINE_MENU_PICK && isBoundedString(v["itemId"], 256);
}
