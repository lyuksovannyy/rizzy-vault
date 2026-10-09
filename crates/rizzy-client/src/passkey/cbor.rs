//! The fixed, small set of CBOR structures `WebAuthn` needs: a COSE `EC2` key map for ES256,
//! and the three-entry `"none"`-attestation `attestationObject` map (ADR 0039 §4, §5).
//!
//! **Why hand-written, not a crate.** [ADR 0018]'s item-record encoding already rejected a
//! general-purpose CBOR crate for our own records (determinism and audit-surface grounds), and
//! ADR 0039 §4 makes the same call here: this is new, interoperability-mandated wire format,
//! not a place to reach for a dependency that could silently round-trip something the
//! `WebAuthn` spec never defined. Everything below is major types 0 (uint), 1 (negative int),
//! 2 (byte string) and 5 (map) — never 3 (text), 4 (array), 6 (tag) or indefinite length: the
//! three structures this module builds need none of those.
//!
//! **Not a decoder.** Nothing here parses CBOR; this project is never the `WebAuthn` relying
//! party, so it never needs to read someone else's `attestationObject` or COSE key, only write
//! its own ([ADR 0039] §2, "we are not a hardware authenticator").
//!
//! [ADR 0018]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0018-item-record-encoding.md
//! [ADR 0039]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0039-passkeys-vault-and-extension.md

/// Appends a CBOR map header for exactly `len` key/value pairs that follow (major type 5).
///
/// Every map this module writes has a fixed, small, compile-time-known entry count (0, 3 or
/// 5), always well under 24, so this never needs the one/two/four/eight-byte length extensions
/// a general encoder would carry. `debug_assert` catches a future caller that grows past that
/// without updating this comment, rather than silently writing a wrong header in a release
/// build (the one-byte direct form is wrong, not merely suboptimal, once `len >= 24`).
fn map_header(out: &mut Vec<u8>, len: u8) {
    debug_assert!(
        len < 24,
        "map_header: every map this module writes is small"
    );
    out.push(0xA0 | (len & 0x1F));
}

/// Appends a non-negative CBOR integer (major type 0), for the COSE small positive values this
/// module uses (`kty = 1` or `2`, `crv = 1` or `6`).
fn uint(out: &mut Vec<u8>, n: u8) {
    debug_assert!(n < 24, "uint: every value this module writes is small");
    out.push(n & 0x1F);
}

/// Appends a negative CBOR integer (major type 1), encoded as `-(n + 1)` per the CBOR spec, for
/// the COSE negative labels/values this module uses (`alg`, `crv`, `x`/`y`/`x`-coordinate
/// labels: `-1`, `-2`, `-3`, `-7`, `-8`). `n` is the *non-negative* argument already in that
/// `-(n + 1)` form, so `nint(out, 6)` writes `-7` and `nint(out, 0)` writes `-1`.
fn nint(out: &mut Vec<u8>, n: u8) {
    debug_assert!(n < 24, "nint: every value this module writes is small");
    out.push(0x20 | (n & 0x1F));
}

/// Appends a CBOR byte string (major type 2) holding exactly `bytes`.
///
/// Every byte string this module writes is already length-bounded by the item schema before it
/// gets here (`PASSKEY_CREDENTIAL_ID_MAX_LEN` ≤ 1024, `PASSKEY_PUBLIC_KEY_COSE_MAX_LEN` ≤ 256,
/// a P-256 coordinate fixed at 32, `rpIdHash` fixed at 32), so the three-range length encoding
/// below (direct, one-byte, two-byte) covers every input this crate ever builds; nothing here
/// needs the four/eight-byte forms. A length that still somehow exceeded `u16::MAX` is
/// saturated to `u16::MAX` rather than panicking — the resulting CBOR would already be a
/// structurally wrong (truncated-looking) attestation that no relying party accepts, which is a
/// safe failure mode for data this crate itself assembles and never trusts from elsewhere.
fn bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = bytes.len();
    if len < 24 {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "len < 24 fits in u8 by the branch condition"
        )]
        out.push(0x40 | (len as u8));
    } else if len <= 0xFF {
        out.push(0x58);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "len <= 0xFF fits in u8 by the branch condition"
        )]
        out.push(len as u8);
    } else {
        out.push(0x59);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "len is saturated to u16::MAX just below"
        )]
        let len16 = len.min(usize::from(u16::MAX)) as u16;
        out.extend_from_slice(&len16.to_be_bytes());
    }
    out.extend_from_slice(bytes);
}

/// Appends a short CBOR text string (major type 3), for `attestationObject`'s fixed keys and
/// its one value, `"none"`. Every string this module passes is a `'static` literal under 24
/// bytes (`debug_assert` catches a future literal that grows past that).
fn text(out: &mut Vec<u8>, s: &'static str) {
    debug_assert!(
        s.len() < 24,
        "text: every literal this module writes is short"
    );
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the debug_assert above bounds every literal this module actually passes"
    )]
    out.push(0x60 | (s.len() as u8));
    out.extend_from_slice(s.as_bytes());
}

/// Builds the COSE `EC2` key map for an ES256 (P-256) public key (RFC 9053 §7.1.1; `WebAuthn`
/// L3 §5.8.5):
///
/// ```text
/// { 1: 2,       // kty: EC2
///   3: -7,      // alg: ES256
///   -1: 1,      // crv: P-256
///   -2: x,      // 32-byte x coordinate
///   -3: y }     // 32-byte y coordinate
/// ```
#[must_use]
pub(super) fn cose_key_es256(x: &[u8; 32], y: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 2 + 2 + 2 + (2 + 32) + (2 + 32));
    map_header(&mut out, 5);
    uint(&mut out, 1);
    uint(&mut out, 2); // kty: EC2
    uint(&mut out, 3);
    nint(&mut out, 6); // alg: ES256 (-7)
    nint(&mut out, 0);
    uint(&mut out, 1); // crv: P-256
    nint(&mut out, 1);
    bytes(&mut out, x);
    nint(&mut out, 2);
    bytes(&mut out, y);
    out
}

/// The `"none"`-attestation `attestationObject` CBOR map (`WebAuthn` L3 §8.2):
///
/// ```text
/// { "fmt": "none",
///   "attStmt": {},
///   "authData": auth_data }
/// ```
///
/// `auth_data` is the full `authenticatorData` byte string ([`super::wire::authenticator_data`]
/// output), embedded as-is: this project claims no attestation statement or trust chain, only
/// that a credential with this public key now exists (ADR 0039 §4, "we are not a hardware
/// authenticator").
#[must_use]
pub(super) fn attestation_object_none(auth_data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + auth_data.len());
    map_header(&mut out, 3);
    text(&mut out, "fmt");
    text(&mut out, "none");
    text(&mut out, "attStmt");
    map_header(&mut out, 0);
    text(&mut out, "authData");
    bytes(&mut out, auth_data);
    out
}

#[cfg(test)]
mod tests {
    use super::{attestation_object_none, cose_key_es256};

    #[test]
    fn cose_key_es256_matches_a_hand_decoded_byte_layout() {
        let x = [0x11; 32];
        let y = [0x22; 32];
        let encoded = cose_key_es256(&x, &y);

        let mut expected = vec![0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
        expected.extend_from_slice(&x);
        expected.push(0x22);
        expected.push(0x58);
        expected.push(0x20);
        expected.extend_from_slice(&y);

        assert_eq!(encoded, expected);
    }

    #[test]
    fn cose_key_es256_output_length_is_exactly_the_fixed_layout_size() {
        // 1 (map header) + 2+2+2 (three small int label/value pairs) + 2*(1 label byte + 2-byte
        // length extension + 32 data bytes) for x and y: the hand-decoded byte test above
        // already pins every byte, this just names the arithmetic so a future change to the
        // layout fails loudly here too.
        let encoded = cose_key_es256(&[0xAB; 32], &[0xCD; 32]);
        assert_eq!(encoded.len(), 1 + 2 + 2 + 2 + (1 + 2 + 32) + (1 + 2 + 32));
    }

    #[test]
    fn attestation_object_none_wraps_auth_data_unchanged() {
        let auth_data = [0x01, 0x02, 0x03, 0x04, 0x05];
        let encoded = attestation_object_none(&auth_data);

        let mut expected = vec![
            0xA3, // map(3)
            0x63, b'f', b'm', b't', // "fmt"
            0x64, b'n', b'o', b'n', b'e', // "none"
            0x67, b'a', b't', b't', b'S', b't', b'm', b't', // "attStmt"
            0xA0, // {}
            0x68, b'a', b'u', b't', b'h', b'D', b'a', b't', b'a', // "authData"
            0x45, // byte string, length 5
        ];
        expected.extend_from_slice(&auth_data);

        assert_eq!(encoded, expected);
    }

    #[test]
    fn attestation_object_none_uses_a_two_byte_length_past_255_bytes() {
        let auth_data = vec![0x7Au8; 300];
        let encoded = attestation_object_none(&auth_data);
        // Everything up to `authData`'s own bytes is fixed and known; the three bytes right
        // before it are the two-byte length extension (0x59) and the big-endian length 300
        // (0x01, 0x2C) — checked with `strip_suffix` rather than a slice index.
        let prefix_len = encoded.len().saturating_sub(auth_data.len());
        let prefix = encoded.get(..prefix_len).unwrap_or_default();
        assert!(prefix.ends_with(&[0x59, 0x01, 0x2C]));
    }
}
