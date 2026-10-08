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

/**
 * The trustworthy page origin of a content-script message, taken only from `sender`, never from
 * the message body. Throws {@link SenderRejected} if the sender is not this extension's own
 * content script running on an http(s) page.
 */
export function trustedOriginOf(sender: WebExtMessageSender, extensionId: string): string {
  if (sender.id !== extensionId) {
    throw new SenderRejected("sender.id is not this extension");
  }
  const tabUrl = sender.tab?.url;
  if (tabUrl === undefined || !isHttpOrHttps(tabUrl)) {
    throw new SenderRejected("sender.tab.url is missing or not http(s)");
  }
  return new URL(tabUrl).origin;
}

/**
 * Whether `sender` is a genuine content script running on an http(s) page — the only kind of
 * sender {@link trustedOriginOf} can derive a trusted origin from. `sender.tab` being set is
 * not enough on its own: one of this extension's own pages (popup, options, the inline-menu
 * iframe) can end up hosted inside an ordinary tab too — opened directly in a tab, as a test
 * does, rather than through `chrome.action`/`options_ui` — and such a sender still carries
 * `sender.tab`, but `sender.tab.url` is then this extension's own
 * `chrome-extension://`/`moz-extension://` origin, never an http(s) page the manifest's
 * `content_scripts.matches` could ever have run a content script on. Checking the tab's own URL
 * scheme, not merely whether a tab exists, is what tells the two apart.
 */
export function isContentScriptSender(sender: WebExtMessageSender, extensionId: string): boolean {
  const tabUrl = sender.tab?.url;
  return sender.id === extensionId && tabUrl !== undefined && isHttpOrHttps(tabUrl);
}

/**
 * Whether `sender` is one of this extension's own trusted pages (popup, options, offscreen
 * document / background page, or the inline-menu iframe) rather than a content script. Used to
 * accept popup/options messages on the same `onMessage` listener the content script uses,
 * without accepting a page-injected message on that same channel (a page has no way to set
 * `sender.id`; the browser sets it) — and without misclassifying one of our own pages as a
 * content script merely because it happens to be open in a tab ({@link isContentScriptSender}).
 */
export function isOwnExtensionPage(sender: WebExtMessageSender, extensionId: string): boolean {
  return sender.id === extensionId && !isContentScriptSender(sender, extensionId);
}
