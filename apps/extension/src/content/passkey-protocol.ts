// The `window.postMessage` protocol between the page-world shim (`passkey-page-shim.ts`, running
// in the untrusted page's own main-world JS realm) and the isolated-world relay content script
// (`passkey-relay.ts`) that shares its `window`/DOM with that page (ADR 0039 §2). Unlike
// `inline-menu/protocol.ts`'s channel, this one is NOT, and does not need to be, unforgeable in
// either direction: a hostile page could call `window.postMessage` with exactly this shape
// itself, skipping the real shim entirely, but that buys it nothing it could not already do by
// calling `navigator.credentials.create/get` directly — every field here is either the page's own
// legitimate RP/ceremony data (`rpName`, `user.*`, `challenge`, `algs`, `allowCredentials`) or,
// on the way back, data the background has already decided to release (never the private key,
// never anything not already part of a normal `PublicKeyCredential` response). The actual
// security boundary is downstream of this channel entirely: the background derives `origin` only
// from the browser's own sender information, never from this message
// (`core-host/content-handler.ts`), and `rizzy-wasm`'s `createPasskey`/`passkeyAssertion` enforce
// INV-64's `rpId` check in Rust regardless of what this channel claims. `nonce` exists purely to
// pair a response with its own request when a page makes more than one concurrent call — a
// correlation id, not an authentication token.
import {
  MAX_ALGS,
  MAX_ALLOW_CREDENTIALS,
  MAX_PASSKEY_BYTES_B64,
  MAX_RP_ID_LEN,
  MAX_RP_NAME_LEN,
  MAX_USER_NAME_LEN,
} from "../messaging/contract.ts";

export const PASSKEY_PAGE_REQUEST = "rizzy-passkey-request";
export const PASSKEY_PAGE_RESPONSE = "rizzy-passkey-response";

export interface PasskeyCreateRequestFromPage {
  readonly type: typeof PASSKEY_PAGE_REQUEST;
  readonly nonce: string;
  readonly kind: "create";
  readonly rpIdHint?: string;
  readonly rpName: string;
  readonly userIdB64: string;
  readonly userName: string;
  readonly userDisplayName: string;
  readonly challengeB64: string;
  readonly algs: readonly number[];
}

export interface PasskeyGetRequestFromPage {
  readonly type: typeof PASSKEY_PAGE_REQUEST;
  readonly nonce: string;
  readonly kind: "get";
  readonly rpIdHint?: string;
  readonly challengeB64: string;
  readonly allowCredentialIdsB64: readonly string[];
}

export type PasskeyRequestFromPage = PasskeyCreateRequestFromPage | PasskeyGetRequestFromPage;

/** The byte fields of one ceremony's successful result, base64-encoded (same reasoning as
 * `messaging/bytes.ts`/`messaging/contract.ts`'s `PasskeyResultPayload` — duplicated here rather
 * than imported, deliberately: this file is bundled into the page-world shim too, which must
 * stay decoupled from the extension-messaging contract it never itself talks over). */
export interface PasskeyPageResultPayload {
  readonly credentialIdB64: string;
  readonly clientDataJsonB64: string;
  readonly attestationObjectB64?: string;
  readonly authenticatorDataB64?: string;
  readonly signatureB64?: string;
  readonly userHandleB64?: string;
}

export interface PasskeyResponseToPage {
  readonly type: typeof PASSKEY_PAGE_RESPONSE;
  readonly nonce: string;
  readonly outcome: "ok" | "fallback";
  readonly result?: PasskeyPageResultPayload;
}

function isBoundedString(value: unknown, maxLen: number): value is string {
  return typeof value === "string" && value.length <= maxLen;
}

function isBoundedStringArray(value: unknown, maxItems: number, maxLen: number): value is readonly string[] {
  return Array.isArray(value) && value.length <= maxItems && value.every((v) => isBoundedString(v, maxLen));
}

export function isPasskeyRequestFromPage(value: unknown): value is PasskeyRequestFromPage {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  if (v["type"] !== PASSKEY_PAGE_REQUEST || !isBoundedString(v["nonce"], 256)) {
    return false;
  }
  if (v["rpIdHint"] !== undefined && !isBoundedString(v["rpIdHint"], MAX_RP_ID_LEN)) {
    return false;
  }
  if (v["kind"] === "create") {
    return (
      isBoundedString(v["rpName"], MAX_RP_NAME_LEN) &&
      isBoundedString(v["userIdB64"], MAX_PASSKEY_BYTES_B64) &&
      isBoundedString(v["userName"], MAX_USER_NAME_LEN) &&
      isBoundedString(v["userDisplayName"], MAX_USER_NAME_LEN) &&
      isBoundedString(v["challengeB64"], MAX_PASSKEY_BYTES_B64) &&
      Array.isArray(v["algs"]) &&
      v["algs"].length <= MAX_ALGS &&
      v["algs"].every((a) => typeof a === "number" && Number.isInteger(a))
    );
  }
  if (v["kind"] === "get") {
    return (
      isBoundedString(v["challengeB64"], MAX_PASSKEY_BYTES_B64) &&
      isBoundedStringArray(v["allowCredentialIdsB64"], MAX_ALLOW_CREDENTIALS, MAX_PASSKEY_BYTES_B64)
    );
  }
  return false;
}

export function isPasskeyResponseToPage(value: unknown): value is PasskeyResponseToPage {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  if (v["type"] !== PASSKEY_PAGE_RESPONSE || !isBoundedString(v["nonce"], 256)) {
    return false;
  }
  if (v["outcome"] === "fallback") {
    return true;
  }
  if (v["outcome"] !== "ok" || typeof v["result"] !== "object" || v["result"] === null) {
    return false;
  }
  const r = v["result"] as Record<string, unknown>;
  return isBoundedString(r["credentialIdB64"], MAX_PASSKEY_BYTES_B64) && isBoundedString(r["clientDataJsonB64"], MAX_PASSKEY_BYTES_B64);
}
