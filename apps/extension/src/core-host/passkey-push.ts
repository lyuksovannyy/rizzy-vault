// SPDX-License-Identifier: AGPL-3.0-only

// Delivers a passkey ceremony's result (or the fallback) to its tab (ADR 0039 §2;
// `messaging/contract.ts`'s `ApplyPasskeyResultMessage`/`RelayPasskeyResultMessage`): directly
// where this context has `tabs` (Firefox's background page), through the service worker from
// the Chromium offscreen document, which has none. Shared by the approval path
// (`content-handler.ts`) and the popup's verification (`core-context.ts`, ADR 0110 §7 point 4.5:
// "deliver the result to the tab exactly as an approval does today").
import type { ApplyPasskeyResultMessage, PasskeyResultPayload, RelayPasskeyResultMessage } from "../messaging/contract.ts";

export async function pushApplyPasskeyResult(
  ext: WebExtNamespace,
  tabId: number,
  msg: Omit<ApplyPasskeyResultMessage, "type">,
): Promise<void> {
  if (ext.tabs !== undefined) {
    await ext.tabs.sendMessage(tabId, { type: "apply_passkey_result", ...msg } satisfies ApplyPasskeyResultMessage);
    return;
  }
  await ext.runtime.sendMessage({ type: "relay_passkey_result", tabId, ...msg } satisfies RelayPasskeyResultMessage);
}

/** {@link pushApplyPasskeyResult} of `result`, or of the fallback for `undefined`. Never throws:
 * a tab that is gone has nobody to answer. */
export async function deliverPasskeyResult(
  ext: WebExtNamespace,
  tabId: number,
  ceremonyToken: string,
  result: PasskeyResultPayload | undefined,
): Promise<void> {
  try {
    await pushApplyPasskeyResult(
      ext,
      tabId,
      result === undefined ? { ceremonyToken, outcome: "fallback" } : { ceremonyToken, outcome: "ok", result },
    );
  } catch {
    // The tab closed or navigated; its page has nothing left to resolve.
  }
}
