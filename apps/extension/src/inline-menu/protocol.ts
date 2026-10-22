// SPDX-License-Identifier: AGPL-3.0-only

// The `window.postMessage` protocol between the content script (running in the untrusted
// page's own window — isolated-world JS, but a shared DOM/BOM, including `window` itself) and
// the extension-origin inline-menu iframe it creates (ADR 0036 §4/§5, ADR 0036 §6 "the
// inline-menu iframe app"; INV-36, INV-40). Carries no secrets, only title/username summaries
// (ADR 0013 §3 rule 3) in, and the user's chosen `itemId` out — never crosses
// `messaging/contract.ts`'s background-messaging boundary, and is validated on both ends all
// the same, because `postMessage` delivers to any listener regardless of claimed source.
//
// {@link InlineMenuPickMessage} is UI teardown only: it tells the content script "destroy the
// overlay, a pick happened" (only the content script, having created the `<iframe>` element in
// the page's own DOM, can remove it). It is NOT what triggers the actual fill — that is a
// second, independent message, `inline_menu_fill_chosen`, which `src/inline-menu/main.ts` sends
// straight to the long-lived context over the real extension-messaging boundary
// (`chrome.runtime.sendMessage`), never through this `postMessage` channel and never relayed by
// the content script at all (ADR 0040; `messaging/contract.ts`'s
// `InlineMenuFillRequestMessage` doc, `messaging/sender.ts`'s `isInlineMenuSender`). That split
// is deliberate, found while fixing a real vulnerability: a compromised content script can
// forge or skip this `postMessage` pick entirely (it already runs in the page's shared
// `window`), so if the content script itself were the one asking the background to reveal a
// credential, "some claimed itemId came from a pick" would mean nothing — the background would
// have no way to tell a real trusted click from the content script simply deciding to ask. The
// background only grants that request to the sender it can verify is the inline-menu document
// itself (`sender.origin`, browser-set, unforgeable), never to whatever the content script
// claims happened.
//
// Security note, documented per CLAUDE.md "where a spec is ambiguous, pick the most
// conservative reading": the two `postMessage` directions are NOT equally trustworthy, because
// the content script's `window` is the same object as the page's own `window` (isolated worlds
// share the DOM/BOM) —
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
//     no page script can fake without actually executing code as that other origin. It no
//     longer matters for INV-36 either way, now that this message only tears down UI: picking a
//     fabricated `itemId` from a forged show message fills nothing, because the *separate*
//     `inline_menu_fill_chosen` message that would have to follow only ever carries the real
//     `itemId` the real iframe's own click handler holds — a forged show message cannot make
//     the iframe send that for an id it never really rendered a trusted click for.
import { MAX_CANDIDATES, MAX_FIELD_VALUE_LEN, MAX_HOST_LEN, MAX_TITLE_LEN, isFillOnly, isFillScope, isInstanceToken, type FillOnly, type FillScope } from "../messaging/contract.ts";

export const INLINE_MENU_SHOW = "rizzy-inline-menu-show";
export const INLINE_MENU_PICK = "rizzy-inline-menu-pick";

export interface InlineMenuCandidate {
  readonly itemId: string;
  readonly title: string;
  readonly username: string;
  /** ADR 0037 §5: this candidate matched only through the equivalence list, a different
   * registrable domain treated as the same site (`rizzy-match`'s own decision, never this
   * module's) — the menu must show a warning and ask for a second, explicit confirmation before
   * filling it. */
  readonly needsWarning: boolean;
  /** The saved URI's exact normalised host, A-label form (ADR 0037 §5 "Exact host shown";
   * gap 31 in the M2 gap audit) — "the saved site" in the equivalence-only warning. Computed by
   * `rizzy-match`, never by this module: render it verbatim, never decoded to Unicode, so a
   * mixed-script host keeps showing its punycode `xn--` form. */
  readonly savedHost: string;
  /** ADR 0076 §4.1: the item can produce a TOTP code. */
  readonly hasTotp?: boolean;
}

export interface InlineMenuShowMessage {
  readonly type: typeof INLINE_MENU_SHOW;
  /** The embedding page's origin, used only as this message's own `postMessage` target when
   * the iframe later replies — never trusted as an identity claim beyond that. */
  readonly pageOrigin: string;
  /** ADR 0043 point 3: the token the content script minted for, and registered with the
   * background for, this one iframe instance. This targeted message is the only place it ever
   * travels — never `src`, an attribute, or anything else a page sharing the tab's frame tree
   * can read — and the iframe sends it back with every privileged request
   * (`messaging/contract.ts`'s `InlineMenuFillRequestMessage`). A page that forges this message
   * (the forgeable direction, module docs) can only invent a token, which the background refuses;
   * a clone of this resource is never sent one at all. */
  readonly instanceToken: string;
  /** The page's own exact normalised host, A-label form (ADR 0037 §5 "Exact host shown"; gap
   * 31 in the M2 gap audit): the menu always shows this, matching or not, so the user can
   * notice an unexpected match. Computed by `rizzy-match`, never by this module. */
  readonly pageHost: string;
  readonly candidates: readonly InlineMenuCandidate[];
  /** The one field this login step fills (`content/login-step.ts`; ROADMAP §4.4 M3 multi-step
   * login forms): `"username"` on an identifier-first step, `"password"` on a password-only
   * step, absent for a one-page form (both). The iframe passes it on unchanged in its own fill
   * request (`messaging/contract.ts`'s `InlineMenuFillRequestMessage.only`), where it can only
   * ever narrow what the long-lived context sends; a page script that forges this message can
   * at most widen it back to the one-page form's both-values push, which the content script
   * still writes only into the visible fields of the step it detected. */
  readonly only?: FillOnly;
  /** The step's whole fill scope (ADR 0076 §4.1): `only`, a TOTP target, the custom tokens.
   * The iframe sends it in its offer request; the long-lived context only ever narrows with it,
   * and discloses in the menu, before the click, everything a click on a row would fill. */
  readonly scope?: FillScope;
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
  return (
    isBoundedString(v["itemId"], 256) &&
    isBoundedString(v["title"], MAX_TITLE_LEN) &&
    isBoundedString(v["username"], MAX_FIELD_VALUE_LEN) &&
    typeof v["needsWarning"] === "boolean" &&
    isBoundedString(v["savedHost"], MAX_HOST_LEN) &&
    (v["hasTotp"] === undefined || typeof v["hasTotp"] === "boolean")
  );
}

export function isInlineMenuShowMessage(value: unknown): value is InlineMenuShowMessage {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  if (
    v["type"] !== INLINE_MENU_SHOW ||
    !isBoundedString(v["pageOrigin"], MAX_FIELD_VALUE_LEN) ||
    !isInstanceToken(v["instanceToken"]) ||
    !isBoundedString(v["pageHost"], MAX_HOST_LEN) ||
    !(v["only"] === undefined || isFillOnly(v["only"])) ||
    !(v["scope"] === undefined || isFillScope(v["scope"]))
  ) {
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
