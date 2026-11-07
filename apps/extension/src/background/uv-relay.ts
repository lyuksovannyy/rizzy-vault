// SPDX-License-Identifier: AGPL-3.0-only

// The service worker's half of ADR 0110 §7's two Chromium relays: the offscreen document has
// neither `chrome.action` nor `chrome.tabs`, so it asks here to set the toolbar badge of a tab
// whose passkey ceremony waits for verification, and to read a tab's live URL before a verified
// ceremony signs. Both are accepted from the offscreen document only
// (`isOffscreenDocumentSender`): a content script, the inline menu, the consent iframe and the
// popup cannot set a badge or read another tab's URL through here.
import { type RelayTabUrlMessage, isRelayTabUrlMessage, isRelayUvBadgeMessage } from "../messaging/contract.ts";
import { OFFSCREEN_PATH, isOffscreenDocumentSender } from "../messaging/sender.ts";
import { applyUvBadge, toolbarActionOf } from "../core-host/uv-badge.ts";

/** The answer to a {@link RelayTabUrlMessage}. */
export interface RelayTabUrlAnswer {
  readonly url?: string;
}

/**
 * Handles `message` if it is one of the two relays and `sender` is the offscreen document:
 * returns `true` (an answer follows through `sendResponse`). Returns `false` for anything
 * else, a relay from any other sender included, which is then ignored like a malformed message.
 */
export function handleUvRelay(
  ext: WebExtNamespace,
  message: unknown,
  sender: WebExtMessageSender,
  sendResponse: (response?: unknown) => void,
): boolean {
  if (!isRelayUvBadgeMessage(message) && !isRelayTabUrlMessage(message)) {
    return false;
  }
  if (!isOffscreenDocumentSender(sender, ext.runtime.id, ext.runtime.getURL(OFFSCREEN_PATH))) {
    return false;
  }
  if (isRelayUvBadgeMessage(message)) {
    const action = toolbarActionOf(ext);
    if (action === undefined) {
      sendResponse({ ok: false });
      return true;
    }
    void applyUvBadge(action, message.tabId, message.on, message.openPopup).then(() => sendResponse({ ok: true }));
    return true;
  }
  void tabUrl(ext, message).then((answer) => sendResponse(answer));
  return true;
}

async function tabUrl(ext: WebExtNamespace, message: RelayTabUrlMessage): Promise<RelayTabUrlAnswer> {
  const get = ext.tabs?.get;
  if (get === undefined) {
    return {};
  }
  try {
    const tab = await get.call(ext.tabs, message.tabId);
    return typeof tab.url === "string" ? { url: tab.url } : {};
  } catch {
    return {};
  }
}
