// Handles a content-script request forwarded by the service worker (ADR 0036 §4, ADR 0037 §1:
// "matching... runs in the background/long-lived context"). This module runs inside the
// offscreen document / background page, alongside `core-context.ts`, and is the one place that
// calls `match/stub.decide()` — never the content script itself, and never the service worker
// (ADR 0037 §1 puts matching in `rizzy-match`, reached only from here).
import { decide } from "../match/stub.ts";
import type { ContentErrorMessage, FromContentScript, ToContentScript } from "../messaging/contract.ts";

/**
 * Whether `pageUrl` (the content script's own, untrusted claim) is consistent with
 * `trustedOrigin` (derived by the caller from `sender.tab.url`/`sender.origin`, never from the
 * message body). A compromised or buggy content script is exactly the threat `validate.ts`'s
 * own comment names for this field: it must never be trusted for the sender's actual origin.
 */
function pageUrlMatchesSender(pageUrl: string, trustedOrigin: string): boolean {
  try {
    return new URL(pageUrl).origin === trustedOrigin;
  } catch {
    return false;
  }
}

/**
 * `trustedOrigin` is the page origin the service worker (Chromium) or this listener (Firefox)
 * derived from `sender.tab.url`/`sender.origin` (`sender.ts`), never from `message.pageUrl`.
 * Every branch that would otherwise hand `message.pageUrl` to `decide()` first checks it against
 * `trustedOrigin` and refuses the request outright on a mismatch (`pageUrlMatchesSender`), so a
 * compromised content script can never claim an origin the sender-validation step did not
 * itself vouch for (THREAT_MODEL.md row 2, "a compromised/malicious content script"). The full
 * `pageUrl` — not just the origin — is still what reaches `decide()` once it passes that check,
 * because ADR 0037 §4's *Starts with* and *Regex* match modes need the path, not only the host.
 */
export function handleContentScriptRequest(message: FromContentScript, trustedOrigin: string): ToContentScript {
  switch (message.type) {
    case "fields_detected": {
      if (!pageUrlMatchesSender(message.pageUrl, trustedOrigin)) {
        return { type: "content_error", code: "fields_detected: pageUrl does not match the sender's own origin" };
      }
      const result = decide(
        message.pageUrl,
        { isTopFrame: message.isTopFrame, frameOrigin: trustedOrigin },
        // No item URIs are available: `core/bindings.ts` has no `list_items` to call while
        // locked, and the device can never unlock today (same gap). An honest empty list, not
        // a placeholder one.
        [],
      );
      return { type: "candidates", candidates: result.candidates, warnings: result.warnings };
    }
    case "fill_chosen":
      return locked("fill_chosen: the device is locked (core/bindings.ts has no unlock yet)");
    case "credentials_submitted":
      return locked("credentials_submitted: save/update prompts are not implemented in this change (not_done)");
  }
}

function locked(reason: string): ContentErrorMessage {
  return { type: "content_error", code: reason };
}
