// Sender identity checks (ADR 0036 §4, §4 last bullet; INV-40). The background takes the
// sender's origin from the browser's own sender information, never from the message body, and
// accepts a message only from the extension's own pages and content scripts — never from
// `externally_connectable`, which this extension's manifests do not declare at all (ADR 0036 §4
// last bullet: "not even the configured server's own origin").
export class SenderRejected extends Error {
  constructor(reason: string) {
    super(`sender rejected: ${reason}`);
    this.name = "SenderRejected";
  }
}

/** Only `http`/`https` pages are matchable or fillable (ADR 0037 §2 rule 2); a content-script
 * message from any other scheme (a `chrome-extension:`/`about:`/`file:` page) is refused before
 * its claimed `pageUrl` is ever compared to anything. */
function isHttpOrHttps(url: string): boolean {
  return url.startsWith("http://") || url.startsWith("https://");
}

/** This extension's own origin (`chrome-extension://<id>` on Chromium, `moz-extension://<id>`
 * on Firefox) — every one of its own pages, including the inline-menu iframe, shares it. Used
 * to tell "an extension-origin document" apart from "the http(s) page that document happens to
 * be embedded in," which `sender.tab.url` alone cannot (a sub-frame's `sender.tab` is the TAB's,
 * i.e. the top-level page's, not the sending frame's own). */
export function extensionOriginOf(ext: WebExtNamespace): string {
  // Built from `protocol`/`host`, not `.origin`: `chrome-extension:`/`moz-extension:` are not on
  // the WHATWG URL spec's "special scheme" list, so Node's own `URL` (unlike a real Chromium or
  // Firefox, which both special-case extension URLs) gives `.origin` as the literal string
  // `"null"` for one — confirmed empirically running this file's own tests under Vitest's node
  // environment. `protocol`/`host` parse the same either way, and a real `sender.origin` is
  // always exactly `${protocol}//${host}`, no trailing slash — so this produces an identical
  // value to what the browser hands `isInlineMenuSender`/`isContentScriptSender` at runtime.
  const url = new URL(ext.runtime.getURL(""));
  return `${url.protocol}//${url.host}`;
}

/** The real, browser-vouched-for URL of the tab hosting `sender` — the top-level page's own
 * current URL, never anything a message body could claim. Throws {@link SenderRejected} unless
 * `sender` is this extension's own and that tab is genuinely http(s) (a content script's own
 * manifest-declared `matches`, or the real page an embedded extension-origin frame, such as the
 * inline-menu iframe, sits inside). */
export function trustedTabUrlOf(sender: WebExtMessageSender, extensionId: string): string {
  if (sender.id !== extensionId) {
    throw new SenderRejected("sender.id is not this extension");
  }
  const tabUrl = sender.tab?.url;
  if (tabUrl === undefined || !isHttpOrHttps(tabUrl)) {
    throw new SenderRejected("sender.tab.url is missing or not http(s)");
  }
  return tabUrl;
}

/**
 * The trustworthy page origin of a content-script message, taken only from `sender`, never from
 * the message body. Throws {@link SenderRejected} if the sender is not this extension's own
 * content script running on an http(s) page.
 */
export function trustedOriginOf(sender: WebExtMessageSender, extensionId: string): string {
  return new URL(trustedTabUrlOf(sender, extensionId)).origin;
}

/**
 * Whether `sender` is a genuine content script running on an http(s) page — the only kind of
 * sender {@link trustedOriginOf} can derive a trusted origin from. `sender.tab` being set is
 * not enough on its own, for two different reasons:
 *
 * 1. One of this extension's own pages (popup, options) can end up hosted inside an ordinary tab
 *    too — opened directly in a tab, as a test does, rather than through
 *    `chrome.action`/`options_ui` — and such a sender still carries `sender.tab`, but
 *    `sender.tab.url` is then this extension's own `chrome-extension://`/`moz-extension://`
 *    origin, never an http(s) page the manifest's `content_scripts.matches` could ever have run
 *    a content script on. Checking the tab's own URL scheme, not merely whether a tab exists, is
 *    what tells the two apart.
 * 2. The inline-menu iframe (`src/inline-menu/main.ts`), embedded inside a real http(s) page's
 *    tab, satisfies (1)'s check too — `sender.tab.url` genuinely is that http(s) page. What
 *    tells it apart from the content script actually running in that page is `sender.origin`:
 *    the browser sets it from the document that actually called `sendMessage`, and for the
 *    iframe that is this extension's own origin, never the embedding page's. A real content
 *    script's `sender.origin` is the page's own origin, matching `sender.tab.url` — found while
 *    fixing a real vulnerability (a compromised content script could request a decrypted item's
 *    credentials for any `itemId`, with no proof a trusted click ever happened — see
 *    `isInlineMenuSender`): without this check, that embedded extension-origin sender would have
 *    been misclassified as "a content script" one layer up, in `background/service-worker.ts`'s
 *    own router, and forwarded down the untrusted content-script path instead of the privileged
 *    one `core-host/listener.ts` now gives only the inline-menu iframe. `sender.origin` is
 *    treated as absent-but-trustworthy (not Chrome's documented behaviour in every version) only
 *    when it is genuinely `undefined` — never when it is present and mismatched.
 */
export function isContentScriptSender(sender: WebExtMessageSender, extensionId: string): boolean {
  const tabUrl = sender.tab?.url;
  if (sender.id !== extensionId || tabUrl === undefined || !isHttpOrHttps(tabUrl)) {
    return false;
  }
  if (sender.origin === undefined) {
    return true;
  }
  try {
    return sender.origin === new URL(tabUrl).origin;
  } catch {
    return false;
  }
}

/**
 * Whether `sender` is the extension-origin inline-menu iframe (`src/inline-menu/main.ts`),
 * embedded inside a real http(s) page's tab — the one sender this extension lets request a
 * decrypted item's credentials directly (ADR 0040 on this; `core-host/
 * listener.ts`). Both conditions matter: `sender.tab.url` being http(s) means a real page
 * actually hosts it (never one of this extension's own pages opened directly in a tab, where
 * `sender.tab.url` would be this extension's own origin instead); `sender.origin` equalling
 * `extensionOrigin` means the document that actually called `sendMessage` is this extension's
 * own, not the embedding page's own script running in the content script's shared `window`
 * (which could never produce that origin — the browser sets it, not any script). Unlike
 * {@link isContentScriptSender}, a missing `sender.origin` is never trusted here: this check
 * grants a privileged capability (revealing a credential), so it fails closed rather than
 * falling back to "assume content script" on an old browser that does not populate `origin`.
 */
export function isInlineMenuSender(sender: WebExtMessageSender, extensionId: string, extensionOrigin: string): boolean {
  const tabUrl = sender.tab?.url;
  return sender.id === extensionId && tabUrl !== undefined && isHttpOrHttps(tabUrl) && sender.origin === extensionOrigin;
}

/**
 * Whether `sender` is one of this extension's own trusted pages (popup, options, offscreen
 * document / background page) rather than a content script or the inline-menu iframe. Used to
 * accept popup/options messages on the same `onMessage` listener the content script uses,
 * without accepting a page-injected message on that same channel (a page has no way to set
 * `sender.id`; the browser sets it) — and without misclassifying one of our own pages as a
 * content script merely because it happens to be open in a tab ({@link isContentScriptSender}).
 */
export function isOwnExtensionPage(sender: WebExtMessageSender, extensionId: string): boolean {
  return sender.id === extensionId && !isContentScriptSender(sender, extensionId);
}
