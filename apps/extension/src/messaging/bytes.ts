// Base64 (standard alphabet, no URL-safe substitution — this extension's own messaging
// boundary only, never a wire format any other client reads) encode/decode for the one new
// class of message payload that is not already a plain string/number/boolean: WebAuthn byte
// buffers (challenge, credential id, signature, …). `core-host/session-store.ts` already has an
// equivalent private pair for its own, unrelated purpose (the `storage.session` snapshot); this
// module is the shared one for every passkey message (`messaging/contract.ts`,
// `content/passkey-protocol.ts`, `passkey-consent/protocol.ts`) and core-host code, so the two
// never drift apart (SSOT) and a third copy is never written.
//
// Why base64 strings cross this boundary at all, rather than the `Uint8Array`/`ArrayBuffer` the
// WebAuthn API itself uses: `chrome.runtime.sendMessage`/`browser.runtime.sendMessage` are
// documented as JSON-based message passing on both browsers' extension APIs (unlike
// `window.postMessage`, which is structured-clone and would preserve a `Uint8Array` as-is). A
// `Uint8Array` sent that way silently degrades to `{"0":1,"1":2,...}` on the other end — a real,
// easy-to-miss bug class this module exists to avoid entirely, by never putting a typed array on
// that wire in the first place. `content/passkey-page-shim.ts` and `passkey-relay.ts` convert
// to/from `ArrayBuffer` only at the two edges that actually need one: the page's own WebAuthn
// call arguments and its `PublicKeyCredential` response.
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

export function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/** Bounded `base64ToBytes`: throws rather than returning an oversized buffer. Every caller on
 * the untrusted (content-script-to-background) side of the boundary uses this, never the plain
 * decoder above, so a malformed or hostile length cannot allocate an unbounded buffer before
 * `validate.ts`'s own byte-budget check on the whole message would otherwise have caught it —
 * defence in depth, since `atob` itself happily decodes a very long string. */
export function boundedBase64ToBytes(base64: string, maxBytes: number): Uint8Array {
  // Every 4 base64 characters decode to at most 3 bytes; checking the encoded length first is
  // cheap and total, before `atob` ever runs on a string that could not possibly fit anyway.
  if (base64.length > Math.ceil((maxBytes * 4) / 3) + 4) {
    throw new RangeError("boundedBase64ToBytes: input too long");
  }
  const bytes = base64ToBytes(base64);
  if (bytes.length > maxBytes) {
    throw new RangeError("boundedBase64ToBytes: decoded too long");
  }
  return bytes;
}
