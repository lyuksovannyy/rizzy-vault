// The `window.postMessage` protocol between the relay content script (`content/passkey-relay.ts`,
// running in the untrusted page's own window) and the extension-origin passkey-consent iframe it
// creates (ADR 0039 §2; the same asymmetric-trust pattern `inline-menu/protocol.ts` documents in
// full, applied here to a consent prompt instead of a fill menu — read that file's module docs
// first). Carries no secret, only display data the content script already received from the
// background (`messaging/contract.ts`'s `PasskeyOfferMessage`): the relying party's name/id, the
// user's display name, and — for a `get` ceremony — the candidate list (title/username only, ADR
// 0013 §3 rule 3). The one thing that actually authorizes anything, `ceremonyToken`, crosses
// here too, but possessing it is not itself the authorization: `core-host/listener.ts`/
// `content-handler.ts` only ever accept an approval for it from a sender whose `sender.origin`
// is this extension's own (`isInlineMenuSender`, reused as-is) — a page that intercepted or
// forged this `postMessage` (the "content script -> iframe" direction is forgeable, exactly as
// `inline-menu/protocol.ts` already explains) still cannot produce that sender identity itself.
//
// {@link PasskeyConsentDoneMessage} is UI teardown only, the direct analogue of
// `inline-menu/protocol.ts`'s `InlineMenuPickMessage` — it tells the content script "destroy the
// overlay, the ceremony settled one way or another." The actual approval/decline is a second,
// independent message (`passkey_ceremony_approved`/`passkey_ceremony_declined`,
// `messaging/contract.ts`) the consent iframe sends straight to the long-lived context, never
// through this `postMessage` channel and never relayed by the content script.
import { MAX_FIELD_VALUE_LEN, MAX_RP_ID_LEN, MAX_RP_NAME_LEN, MAX_TITLE_LEN, MAX_USER_NAME_LEN } from "../messaging/contract.ts";

export const PASSKEY_CONSENT_SHOW = "rizzy-passkey-consent-show";
export const PASSKEY_CONSENT_DONE = "rizzy-passkey-consent-done";

export interface PasskeyConsentCandidate {
  readonly passkeyRef: string;
  readonly itemTitle: string;
  readonly userName: string;
}

export interface PasskeyConsentShowMessage {
  readonly type: typeof PASSKEY_CONSENT_SHOW;
  /** The embedding page's origin, used only as this message's own reply-time `postMessage`
   * target (`inline-menu/protocol.ts`'s identical field, same reasoning). */
  readonly pageOrigin: string;
  readonly ceremonyToken: string;
  readonly kind: "create" | "get";
  readonly rpId: string;
  readonly rpName?: string;
  readonly userName?: string;
  readonly candidates?: readonly PasskeyConsentCandidate[];
}

export interface PasskeyConsentDoneMessage {
  readonly type: typeof PASSKEY_CONSENT_DONE;
}

function isBoundedString(value: unknown, maxLen: number): value is string {
  return typeof value === "string" && value.length <= maxLen;
}

function isCandidate(value: unknown): value is PasskeyConsentCandidate {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  return isBoundedString(v["passkeyRef"], 512) && isBoundedString(v["itemTitle"], MAX_TITLE_LEN) && isBoundedString(v["userName"], MAX_FIELD_VALUE_LEN);
}

export function isPasskeyConsentShowMessage(value: unknown): value is PasskeyConsentShowMessage {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  if (v["type"] !== PASSKEY_CONSENT_SHOW || !isBoundedString(v["pageOrigin"], MAX_FIELD_VALUE_LEN) || !isBoundedString(v["ceremonyToken"], 256)) {
    return false;
  }
  if (v["kind"] !== "create" && v["kind"] !== "get") {
    return false;
  }
  if (!isBoundedString(v["rpId"], MAX_RP_ID_LEN)) {
    return false;
  }
  if (v["rpName"] !== undefined && !isBoundedString(v["rpName"], MAX_RP_NAME_LEN)) {
    return false;
  }
  if (v["userName"] !== undefined && !isBoundedString(v["userName"], MAX_USER_NAME_LEN)) {
    return false;
  }
  if (v["candidates"] !== undefined && (!Array.isArray(v["candidates"]) || !v["candidates"].every(isCandidate))) {
    return false;
  }
  return true;
}

export function isPasskeyConsentDoneMessage(value: unknown): value is PasskeyConsentDoneMessage {
  return typeof value === "object" && value !== null && (value as { type?: unknown }).type === PASSKEY_CONSENT_DONE;
}
