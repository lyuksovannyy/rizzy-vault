// Test-only WebAuthn wire-format verification (ADR 0039 §4's hand-written CBOR, verified from
// the *other* side): a minimal CBOR decoder — only the handful of major types `attestationObject`
// and a COSE EC2 key ever use (unsigned int, negative int, byte string, text string, map) — and
// an ES256 signature check over Node's own `node:crypto`, independent of anything `rizzy-core`
// or `rizzy-client` does. This is test infrastructure, never shipped: it exists so this suite can
// prove the extension's registration and assertion responses are genuinely verifiable by an
// independent relying party, not merely "well-formed by the same code that produced them."
import { createHash, createPublicKey, createVerify } from "node:crypto";

interface CborReader {
  readonly buf: Buffer;
  pos: number;
}

function readByte(r: CborReader): number {
  const b = r.buf[r.pos];
  if (b === undefined) {
    throw new Error("webauthn-verify: unexpected end of CBOR input");
  }
  r.pos += 1;
  return b;
}

function readUint(r: CborReader, additional: number): number {
  if (additional < 24) {
    return additional;
  }
  if (additional === 24) {
    return readByte(r);
  }
  if (additional === 25) {
    const hi = readByte(r);
    const lo = readByte(r);
    return (hi << 8) | lo;
  }
  if (additional === 26) {
    let v = 0;
    for (let i = 0; i < 4; i += 1) {
      v = (v << 8) | readByte(r);
    }
    return v >>> 0;
  }
  throw new Error(`webauthn-verify: unsupported CBOR length encoding ${additional}`);
}

/** Decodes exactly one CBOR value at `r.pos`, advancing it past the value. Maps decode to a
 * plain `Map<number | string, unknown>` (key type varies: COSE keys use small integers, the
 * top-level `attestationObject` map uses text strings) — never a plain object, so a numeric key
 * like `-1` (COSE `crv`) is never confused with the string `"-1"`. */
function decodeCbor(r: CborReader): unknown {
  const head = readByte(r);
  const majorType = head >> 5;
  const additional = head & 0x1f;
  switch (majorType) {
    case 0: // unsigned integer
      return readUint(r, additional);
    case 1: // negative integer: CBOR encodes -(n+1)
      return -1 - readUint(r, additional);
    case 2: {
      // byte string
      const len = readUint(r, additional);
      const bytes = r.buf.subarray(r.pos, r.pos + len);
      r.pos += len;
      return Buffer.from(bytes);
    }
    case 3: {
      // text string
      const len = readUint(r, additional);
      const text = r.buf.toString("utf8", r.pos, r.pos + len);
      r.pos += len;
      return text;
    }
    case 4: {
      // array
      const len = readUint(r, additional);
      const out: unknown[] = [];
      for (let i = 0; i < len; i += 1) {
        out.push(decodeCbor(r));
      }
      return out;
    }
    case 5: {
      // map
      const len = readUint(r, additional);
      const out = new Map<number | string, unknown>();
      for (let i = 0; i < len; i += 1) {
        const key = decodeCbor(r) as number | string;
        const value = decodeCbor(r);
        out.set(key, value);
      }
      return out;
    }
    default:
      throw new Error(`webauthn-verify: unsupported CBOR major type ${majorType}`);
  }
}

function decodeOneCbor(buf: Buffer): unknown {
  const r: CborReader = { buf, pos: 0 };
  return decodeCbor(r);
}

/** The COSE EC2 public key's `x`/`y` coordinates (32 bytes each for P-256/ES256), extracted from
 * a `"none"`-attestation `attestationObject` (ADR 0039 §4). */
export interface Es256PublicKeyPoint {
  readonly x: Buffer;
  readonly y: Buffer;
}

export function extractEs256PublicKeyFromAttestationObject(attestationObject: Buffer): Es256PublicKeyPoint {
  const top = decodeOneCbor(attestationObject);
  if (!(top instanceof Map)) {
    throw new Error("webauthn-verify: attestationObject is not a CBOR map");
  }
  const authData = top.get("authData");
  if (!Buffer.isBuffer(authData)) {
    throw new Error("webauthn-verify: attestationObject has no authData byte string");
  }
  // authenticatorData layout (WebAuthn §6.1): rpIdHash(32) | flags(1) | signCount(4) |
  // [attestedCredentialData: aaguid(16) | credentialIdLength(2) | credentialId(L) | credentialPublicKey(CBOR)].
  let pos = 32 + 1 + 4 + 16;
  const credIdLen = (authData[pos] ?? 0) * 256 + (authData[pos + 1] ?? 0);
  pos += 2 + credIdLen;
  const coseKey = decodeOneCbor(authData.subarray(pos));
  if (!(coseKey instanceof Map)) {
    throw new Error("webauthn-verify: credentialPublicKey is not a CBOR map");
  }
  const x = coseKey.get(-2);
  const y = coseKey.get(-3);
  if (!Buffer.isBuffer(x) || !Buffer.isBuffer(y)) {
    throw new Error("webauthn-verify: COSE key is missing x/y");
  }
  return { x, y };
}

/** Verifies one `get()` assertion's ES256 signature against the public key extracted at
 * registration (ADR 0039 §2): `signature` is DER-encoded (the WebAuthn spec's own format for
 * `AuthenticatorAssertionResponse.signature`, which `node:crypto`'s `verify` consumes directly —
 * no raw-`r`‖`s` conversion needed on this side, unlike `SubtleCrypto.verify`, which this test
 * deliberately does not use for exactly that reason). The signed data is `authenticatorData ‖
 * sha256(clientDataJSON)`, per spec. */
export function verifyEs256Assertion(
  point: Es256PublicKeyPoint,
  authenticatorData: Buffer,
  clientDataJSON: Buffer,
  signatureDer: Buffer,
): boolean {
  const publicKey = createPublicKey({
    key: { kty: "EC", crv: "P-256", x: point.x.toString("base64url"), y: point.y.toString("base64url") },
    format: "jwk",
  });
  const verifier = createVerify("sha256");
  verifier.update(authenticatorData);
  verifier.update(hashSha256(clientDataJSON));
  return verifier.verify(publicKey, signatureDer);
}

function hashSha256(data: Buffer): Buffer {
  return createHash("sha256").update(data).digest();
}
