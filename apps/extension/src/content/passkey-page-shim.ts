// The page-world WebAuthn interception point (ADR 0039 §2; THREAT_MODEL A7's "Passkey provider"
// section): overrides `navigator.credentials.create`/`.get` in the page's own main-world JS
// realm — the only place that can see the real `options` object before any site script reads
// it, and the only place a feature-detection check (`PublicKeyCredential` existing at all) needs
// to keep reporting the truth about this browser's native WebAuthn support, not a fake. Injected
// by `passkey-relay.ts` (the isolated-world content script) as a `<script src="...">` tag — not
// `MAIN`-world `content_scripts` (not supported by every target browser version this project
// still runs on; `passkey-relay.ts`'s own doc), and not inline, since this extension's own CSP
// never permits inline script.
//
// This file and `passkey-relay.ts` share nothing but `window.postMessage` and the plain-data
// protocol `passkey-protocol.ts` defines (module docs there on why that channel needs no
// authentication of its own): every security-relevant decision — the real origin, the `rpId`
// check, whether the device is unlocked, whether the user actually consented — happens on the
// other side of that extension-messaging boundary, in `core-host/content-handler.ts` and
// `rizzy-wasm`. This file's one job is to look, to the page, like a native WebAuthn
// implementation that happens to be backed by rizzy-vault instead of the OS.
import { base64ToBytes, bytesToBase64 } from "../messaging/bytes.ts";
import {
  PASSKEY_PAGE_REQUEST,
  isPasskeyResponseToPage,
  type PasskeyPageResultPayload,
  type PasskeyRequestFromPage,
} from "./passkey-protocol.ts";

/** The WebAuthn spec's own default ceremony timeout (60 s for `get`, 120 s is sometimes quoted
 * for `create`; this project uses one conservative value for both, "U", not independently
 * re-verified against every browser's own default) — the page may ask for a shorter one via
 * `options.publicKey.timeout`, which this shim honors as an upper bound, never a longer one: a
 * ceremony that outlives what the page itself asked for is never useful to it regardless of
 * whether the extension is still working on it. */
const DEFAULT_TIMEOUT_MS = 60_000;
const COSE_ALG_ES256 = -7;

type PublicKeyCredentialLike = {
  readonly id: string;
  readonly rawId: ArrayBuffer;
  readonly type: "public-key";
  readonly response: Record<string, unknown>;
  getClientExtensionResults(): Record<string, never>;
};

/** `send`'s own internal result: either a credential to resolve with, or "nothing usable came
 * back in time" — the caller always reacts to the latter by calling the real native method with
 * the original, untouched options (ADR 0039 §2's fallback rule), never by rejecting the page's
 * own promise with an error it did not ask for. */
type SendOutcome = { readonly ok: true; readonly credential: PublicKeyCredentialLike } | { readonly ok: false };

interface Pending {
  readonly settle: (outcome: SendOutcome) => void;
  readonly timer: ReturnType<typeof setTimeout>;
}

export function installPasskeyPageShim(): void {
  const nav = navigator as Navigator & { credentials?: CredentialsContainer };
  if (typeof window === "undefined" || window.top !== window || nav.credentials === undefined || window.PublicKeyCredential === undefined) {
    // Not a top frame, or this browser has no WebAuthn to shim in the first place (module docs:
    // feature-detection must keep telling the truth where there is nothing to intercept).
    return;
  }

  const originalCreate = nav.credentials.create.bind(nav.credentials);
  const originalGet = nav.credentials.get.bind(nav.credentials);
  const pending = new Map<string, Pending>();

  window.addEventListener("message", (event) => {
    // Same-window delivery only (module docs: this channel needs no sender authentication, but
    // it still has no reason to listen to a message some other window posted into this one).
    if (event.source !== window || !isPasskeyResponseToPage(event.data)) {
      return;
    }
    const waiting = pending.get(event.data.nonce);
    if (waiting === undefined) {
      return;
    }
    pending.delete(event.data.nonce);
    clearTimeout(waiting.timer);
    if (event.data.outcome === "fallback" || event.data.result === undefined) {
      waiting.settle({ ok: false });
      return;
    }
    try {
      waiting.settle({ ok: true, credential: toCredential(event.data.result) });
    } catch {
      // A malformed result (should not happen: `core-host/content-handler.ts` only ever sends
      // a shape `toCredential` can decode) — treated the same as "nothing usable," never thrown
      // into the page as an unexpected rejection.
      waiting.settle({ ok: false });
    }
  });

  function send(request: PasskeyRequestFromPage, timeoutMs: number): Promise<SendOutcome> {
    return new Promise<SendOutcome>((resolve) => {
      const timer = setTimeout(() => {
        pending.delete(request.nonce);
        resolve({ ok: false });
      }, timeoutMs);
      pending.set(request.nonce, { settle: resolve, timer });
      window.postMessage(request, window.location.origin);
    });
  }

  nav.credentials.create = (async (options?: CredentialCreationOptions) => {
    const publicKey = options?.publicKey;
    if (publicKey === undefined) {
      return originalCreate(options);
    }
    const algs = publicKey.pubKeyCredParams.map((p) => p.alg);
    if (!algs.includes(COSE_ALG_ES256)) {
      // ADR 0039 §3: this project creates ES256 credentials only. Resolved straight to the
      // native authenticator, never even offered to the background — `content-handler.ts` has
      // its own, second check of the same rule, but there is no reason to round-trip a request
      // this shim already knows it cannot serve.
      return originalCreate(options);
    }
    const timeoutMs = typeof publicKey.timeout === "number" ? Math.min(publicKey.timeout, DEFAULT_TIMEOUT_MS) : DEFAULT_TIMEOUT_MS;
    const request: PasskeyRequestFromPage = {
      type: PASSKEY_PAGE_REQUEST,
      nonce: crypto.randomUUID(),
      kind: "create",
      ...(publicKey.rp.id !== undefined ? { rpIdHint: publicKey.rp.id } : {}),
      rpName: publicKey.rp.name,
      userIdB64: bytesToBase64(toBytes(publicKey.user.id)),
      userName: publicKey.user.name,
      userDisplayName: publicKey.user.displayName,
      challengeB64: bytesToBase64(toBytes(publicKey.challenge)),
      algs,
    };
    const outcome = await send(request, timeoutMs);
    // "Fall back to the browser's own authenticator" (ADR 0039 §2) means actually calling it and
    // returning *its* result — a decline, a timeout, or no match all resolve the page's own
    // promise exactly as if this shim had never been installed, never with a rizzy-vault-specific
    // error the page did not ask for.
    return outcome.ok ? outcome.credential : originalCreate(options);
  }) as typeof nav.credentials.create;

  nav.credentials.get = (async (options?: CredentialRequestOptions) => {
    const publicKey = options?.publicKey;
    if (publicKey === undefined) {
      return originalGet(options);
    }
    const timeoutMs = typeof publicKey.timeout === "number" ? Math.min(publicKey.timeout, DEFAULT_TIMEOUT_MS) : DEFAULT_TIMEOUT_MS;
    const request: PasskeyRequestFromPage = {
      type: PASSKEY_PAGE_REQUEST,
      nonce: crypto.randomUUID(),
      kind: "get",
      ...(publicKey.rpId !== undefined ? { rpIdHint: publicKey.rpId } : {}),
      challengeB64: bytesToBase64(toBytes(publicKey.challenge)),
      allowCredentialIdsB64: (publicKey.allowCredentials ?? []).map((c) => bytesToBase64(toBytes(c.id))),
    };
    const outcome = await send(request, timeoutMs);
    return outcome.ok ? outcome.credential : originalGet(options);
  }) as typeof nav.credentials.get;

  // A non-enumerable readiness marker, for the E2E suite only (`e2e/passkey.spec.ts` polls it
  // with `page.waitForFunction`): `<script src>` injection (module docs) is asynchronous, so a
  // test calling `navigator.credentials.create` immediately after `page.goto()` could otherwise
  // race the shim's own installation and reach the *real* native implementation instead. Kept
  // non-enumerable and off `window` itself (on `navigator.credentials`, where a page has no
  // existing reason to look) to keep this project's own detectability no worse than any other
  // property a page could already probe for; still trivially detectable by a page that looks for
  // it by name, same residual every other property added to a shimmed object has.
  Object.defineProperty(nav.credentials, "__rizzyVaultPasskeyShimReady", { value: true, enumerable: false, configurable: true });
}

function toBytes(source: BufferSource): Uint8Array {
  return source instanceof ArrayBuffer ? new Uint8Array(source) : new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
}

/** `Uint8Array.buffer`'s own type is `ArrayBufferLike` (it admits a `SharedArrayBuffer`), but
 * `base64ToBytes` always allocates a fresh, non-shared buffer of its own — true at runtime, not
 * expressible to `tsc` without this one cast, kept in one place rather than repeated at every
 * call site below. */
function toArrayBuffer(b64: string): ArrayBuffer {
  return base64ToBytes(b64).buffer as ArrayBuffer;
}

function toCredential(result: PasskeyPageResultPayload): PublicKeyCredentialLike {
  const rawId = toArrayBuffer(result.credentialIdB64);
  const response: Record<string, unknown> = { clientDataJSON: toArrayBuffer(result.clientDataJsonB64) };
  if (result.attestationObjectB64 !== undefined) {
    response["attestationObject"] = toArrayBuffer(result.attestationObjectB64);
  }
  if (result.authenticatorDataB64 !== undefined) {
    response["authenticatorData"] = toArrayBuffer(result.authenticatorDataB64);
  }
  if (result.signatureB64 !== undefined) {
    response["signature"] = toArrayBuffer(result.signatureB64);
  }
  // Nullable per spec even for a discoverable credential's response (`core-context.ts`'s own
  // `not_done` doc on why this project never has a real value to put here today).
  response["userHandle"] = result.userHandleB64 !== undefined ? toArrayBuffer(result.userHandleB64) : null;
  return {
    id: base64urlOf(result.credentialIdB64),
    rawId,
    type: "public-key",
    response,
    getClientExtensionResults: () => ({}),
  };
}

/** The spec's `PublicKeyCredential.id` is base64url, not the plain base64 this extension's own
 * messaging boundary uses (`messaging/bytes.ts`'s own doc) — converted only here, at the one
 * point a real page-facing value needs the spec's exact alphabet. */
function base64urlOf(standardB64: string): string {
  return standardB64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

installPasskeyPageShim();
