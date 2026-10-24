// SPDX-License-Identifier: AGPL-3.0-only

// Mints the per-instance token (ADR 0043 point 1) both minting content scripts use:
// `content-script.ts`'s `InlineMenu` constructor and `passkey-relay.ts`'s consent-iframe
// builder. `crypto.randomUUID()` (122 random bits, a canonical lowercase v4 UUID) whenever it
// exists. It does not exist everywhere this script runs: `randomUUID` is a [SecureContext]
// member of `Crypto`, and a content script's world shares its page's secure-context status, so on
// a plain `http://` page (which the inline menu does serve: an HTTP-saved item is offered on its
// own HTTP page, ADR 0037 §2) it is `undefined`, while `getRandomValues` is exposed in every
// context. There the same v4 layout is built from 16 `getRandomValues` bytes, the version and
// variant bits set exactly as RFC 4122 §4.4 fixes them: the same 122 CSPRNG bits and the same
// string shape `randomUUID` produces, which `messaging/contract.ts`'s `isInstanceToken` is the
// one check of. No new construction: a token is an unguessable random identifier, nothing more.

/** The subset of `Crypto` this module needs; injectable for tests. */
export type InstanceTokenRandom = Pick<Crypto, "getRandomValues"> & { readonly randomUUID?: () => string };

export function mintInstanceToken(random: InstanceTokenRandom = crypto): string {
  if (typeof random.randomUUID === "function") {
    return random.randomUUID();
  }
  const b = random.getRandomValues(new Uint8Array(16));
  b[6] = ((b[6] ?? 0) & 0x0f) | 0x40;
  b[8] = ((b[8] ?? 0) & 0x3f) | 0x80;
  const hex = Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20)].join("-");
}
