// SPDX-License-Identifier: AGPL-3.0-only

// The toolbar badge of a passkey ceremony that waits for a master-password verification (ADR 0110
// §7 point 2): `"!"` on that tab while it waits, cleared when it settles. Where the long-lived
// context has a toolbar action API (Firefox's background page: `browser.browserAction`) it sets
// the badge itself; the Chromium offscreen document has none, so it asks the service worker
// (`background/uv-relay.ts`, which accepts the request from the offscreen document only). The
// badge carries nothing secret; it only tells the user to click the button.
import type { RelayUvBadgeMessage } from "../messaging/contract.ts";

/** The badge text of a tab whose passkey ceremony waits for verification. */
export const UV_BADGE_TEXT = "!";

/** `chrome.action` (Chromium MV3) or `browser.browserAction` (Firefox MV2), feature-detected. */
export function toolbarActionOf(ext: WebExtNamespace): WebExtAction | undefined {
  return ext.action ?? ext.browserAction;
}

/** Sets (`on`) or clears the badge of `tabId` on `action`; with `openPopup`, also tries
 * `openPopup()` where the browser offers it. Never throws: a missing or failing call leaves the
 * consent iframe's own text to tell the user to click the button (§7 point 2). */
export async function applyUvBadge(action: WebExtAction, tabId: number, on: boolean, openPopup: boolean): Promise<void> {
  try {
    await action.setBadgeText({ tabId, text: on ? UV_BADGE_TEXT : "" });
  } catch {
    // The tab may be gone; nothing to show it on.
  }
  if (on && openPopup && typeof action.openPopup === "function") {
    try {
      await action.openPopup();
    } catch {
      // Not offered without a user gesture on this browser or version (ADR 0110 §7 point 2, U).
    }
  }
}

/** Sets or clears the badge of `tabId` from the long-lived context, directly or through the
 * service worker. Never throws. */
export async function setUvBadge(ext: WebExtNamespace, tabId: number, on: boolean, openPopup = false): Promise<void> {
  const action = toolbarActionOf(ext);
  if (action !== undefined) {
    await applyUvBadge(action, tabId, on, openPopup);
    return;
  }
  try {
    await ext.runtime.sendMessage({ type: "relay_uv_badge", tabId, on, openPopup } satisfies RelayUvBadgeMessage);
  } catch {
    // The service worker is unreachable; the badge stays as it was.
  }
}
