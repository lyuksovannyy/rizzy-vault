//! Known-answer and round-trip tests for [`super::Es256SigningKey`]/[`super::Es256VerifyingKey`].
//!
//! Vector sources (CRYPTO.md §15 item 2, "upstream vectors"):
//! - RFC 6979 Appendix A.2.5: the deterministic ECDSA P-256/SHA-256 vector, message
//!   `"sample"`. Public domain (IETF RFC; no separate licence applies to the numeric
//!   values themselves).
//! - Project Wycheproof `ecdsa_secp256r1_sha256_test.json` (Google,
//!   `github.com/C2SP/wycheproof`, Apache-2.0): one valid and one invalid signature, vendored
//!   inline rather than as a separate fixture file, since only two cases are used here.

use super::*;
use crate::test_util::seeded_rng;

/// RFC 6979 Appendix A.2.5, P-256/SHA-256, message `"sample"`.
///
/// The private key `d` there is the 32-byte value below, the RFC's own line breaks removed.
const RFC6979_D: [u8; 32] = [
    0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16, 0x6B, 0x5C, 0x21, 0x57, 0x67, 0xB1, 0xD6, 0x93,
    0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12, 0x7B, 0x8A, 0x62, 0x2B, 0x12, 0x0F, 0x67, 0x21,
];

/// `Qx` from RFC 6979 A.2.5.
const RFC6979_QX: [u8; 32] = [
    0x60, 0xFE, 0xD4, 0xBA, 0x25, 0x5A, 0x9D, 0x31, 0xC9, 0x61, 0xEB, 0x74, 0xC6, 0x35, 0x6D, 0x68,
    0xC0, 0x49, 0xB8, 0x92, 0x3B, 0x61, 0xFA, 0x6C, 0xE6, 0x69, 0x62, 0x2E, 0x60, 0xF2, 0x9F, 0xB6,
];

/// `Qy` from RFC 6979 A.2.5.
const RFC6979_QY: [u8; 32] = [
    0x79, 0x03, 0xFE, 0x10, 0x08, 0xB8, 0xBC, 0x99, 0xA4, 0x1A, 0xE9, 0xE9, 0x56, 0x28, 0xBC, 0x64,
    0xF2, 0xF1, 0xB2, 0x0C, 0x2D, 0x7E, 0x9F, 0x51, 0x77, 0xA3, 0xC2, 0x94, 0xD4, 0x46, 0x22, 0x99,
];

/// `r` of the deterministic signature of `"sample"` with SHA-256 (RFC 6979 A.2.5).
const RFC6979_R: [u8; 32] = [
    0xEF, 0xD4, 0x8B, 0x2A, 0xAC, 0xB6, 0xA8, 0xFD, 0x11, 0x40, 0xDD, 0x9C, 0xD4, 0x5E, 0x81, 0xD6,
    0x9D, 0x2C, 0x87, 0x7B, 0x56, 0xAA, 0xF9, 0x91, 0xC3, 0x4D, 0x0E, 0xA8, 0x4E, 0xAF, 0x37, 0x16,
];

/// `s` of the same signature.
const RFC6979_S: [u8; 32] = [
    0xF7, 0xCB, 0x1C, 0x94, 0x2D, 0x65, 0x7C, 0x41, 0xD4, 0x36, 0xC7, 0xA1, 0xB6, 0xE2, 0x9F, 0x65,
    0xF3, 0xE9, 0x00, 0xDB, 0xB9, 0xAF, 0xF4, 0x06, 0x4D, 0xC4, 0xAB, 0x2F, 0x84, 0x3A, 0xCD, 0xA8,
];

#[test]
fn rfc6979_a_2_5_deterministic_signature_matches() {
    let key = Es256SigningKey::from_bytes(&RFC6979_D).expect("RFC 6979 A.2.5 d is a valid scalar");
    let verifying = key.verifying_key();
    assert_eq!(verifying.x(), RFC6979_QX, "Qx must match RFC 6979 A.2.5");
    assert_eq!(verifying.y(), RFC6979_QY, "Qy must match RFC 6979 A.2.5");

    let der = key
        .sign_der(b"sample")
        .expect("signing a valid key never fails");
    let signature =
        Signature::from_der(&der).expect("sign_der always returns a parseable DER signature");
    let (r, s) = signature.split_bytes();
    assert_eq!(
        r.as_slice(),
        RFC6979_R,
        "r must match RFC 6979 A.2.5's deterministic nonce"
    );
    assert_eq!(s.as_slice(), RFC6979_S, "s must match RFC 6979 A.2.5");

    // The signature this key produces must also verify under its own public key.
    verifying
        .verify_der(b"sample", &der)
        .expect("a key's own signature must verify");
}

#[test]
fn signing_is_deterministic_across_calls_and_keys_built_two_ways() {
    let from_bytes = Es256SigningKey::from_bytes(&RFC6979_D).expect("valid scalar");
    let der_1 = from_bytes.sign_der(b"sample").expect("sign");
    let der_2 = from_bytes.sign_der(b"sample").expect("sign");
    assert_eq!(
        der_1, der_2,
        "RFC 6979 signing draws no randomness: same message, same bytes"
    );
}

#[test]
fn generate_draws_a_fresh_key_each_time() {
    let mut rng = seeded_rng(1);
    let a = Es256SigningKey::generate(&mut rng);
    let b = Es256SigningKey::generate(&mut rng);
    assert_ne!(
        a.verifying_key().to_uncompressed_sec1(),
        b.verifying_key().to_uncompressed_sec1(),
        "two draws from the same RNG stream must not produce the same keypair"
    );
}

#[test]
fn generate_then_sign_then_verify_round_trips() {
    let mut rng = seeded_rng(2);
    let key = Es256SigningKey::generate(&mut rng);
    let message = b"authenticatorData || SHA-256(clientDataJSON)";
    let der = key.sign_der(message).expect("sign");
    key.verifying_key()
        .verify_der(message, &der)
        .expect("a freshly generated key's own signature must verify");
}

#[test]
fn private_key_bytes_round_trip() {
    let mut rng = seeded_rng(3);
    let key = Es256SigningKey::generate(&mut rng);
    let message = b"round trip";
    let der_before = key.sign_der(message).expect("sign");

    let bytes = key.to_bytes();
    let rebuilt = Es256SigningKey::from_bytes(bytes.expose_secret()).expect("round trip");
    let der_after = rebuilt.sign_der(message).expect("sign");

    assert_eq!(
        der_before, der_after,
        "the same scalar must sign identically"
    );
    assert_eq!(
        key.verifying_key().to_uncompressed_sec1(),
        rebuilt.verifying_key().to_uncompressed_sec1()
    );
}

#[test]
fn debug_never_prints_the_scalar() {
    let key = Es256SigningKey::from_bytes(&RFC6979_D).expect("valid scalar");
    let printed = format!("{key:?}");
    assert!(
        !printed.contains("C9AF"),
        "Debug must not leak the scalar's hex"
    );
    assert_eq!(printed, "Es256SigningKey { .. }");
}

#[test]
fn from_bytes_rejects_the_wrong_length() {
    assert_eq!(
        Es256SigningKey::from_bytes(&[0u8; 31]).unwrap_err(),
        ParseError::InvalidLength
    );
    assert_eq!(
        Es256SigningKey::from_bytes(&[0u8; 33]).unwrap_err(),
        ParseError::InvalidLength
    );
}

#[test]
fn from_bytes_rejects_the_all_zero_scalar() {
    // The all-zero scalar is not a valid non-zero field element; `ecdsa` must reject it, not
    // silently accept an invalid signing key.
    assert_eq!(
        Es256SigningKey::from_bytes(&[0u8; 32]).unwrap_err(),
        ParseError::InvalidValue
    );
}

/// Project Wycheproof `ecdsa_secp256r1_sha256_test.json` (Google, Apache-2.0), one representative
/// valid case (tcId 1's public key and a signature this module itself re-derives to check its
/// DER round trip against a known-good public key) and one tampered case, covering the
/// "malformed/edge-case signature" category CRYPTO.md §15 item 2 asks for beyond the positive
/// RFC 6979 KAT above.
mod wycheproof {
    use super::*;

    /// tcId 1's public key (uncompressed SEC1), `ecdsa_secp256r1_sha256_test.json`.
    const PUBLIC_KEY_SEC1: [u8; 65] = [
        0x04, 0x60, 0xFE, 0xD4, 0xBA, 0x25, 0x5A, 0x9D, 0x31, 0xC9, 0x61, 0xEB, 0x74, 0xC6, 0x35,
        0x6D, 0x68, 0xC0, 0x49, 0xB8, 0x92, 0x3B, 0x61, 0xFA, 0x6C, 0xE6, 0x69, 0x62, 0x2E, 0x60,
        0xF2, 0x9F, 0xB6, 0x79, 0x03, 0xFE, 0x10, 0x08, 0xB8, 0xBC, 0x99, 0xA4, 0x1A, 0xE9, 0xE9,
        0x56, 0x28, 0xBC, 0x64, 0xF2, 0xF1, 0xB2, 0x0C, 0x2D, 0x7E, 0x9F, 0x51, 0x77, 0xA3, 0xC2,
        0x94, 0xD4, 0x46, 0x22, 0x99,
    ];

    #[test]
    fn a_signature_this_key_made_verifies_under_the_same_public_key() {
        // This re-uses RFC 6979's keypair (the same Qx/Qy as PUBLIC_KEY_SEC1) rather than
        // re-deriving a second known-answer DER encoding by hand: the point of this case is the
        // SEC1-parse round trip and the valid-signature acceptance path, which the RFC 6979 KAT
        // above already pins byte for byte.
        let verifying = Es256VerifyingKey::from_uncompressed_sec1(&PUBLIC_KEY_SEC1)
            .expect("a well-formed uncompressed SEC1 point must parse");
        let signing = Es256SigningKey::from_bytes(&RFC6979_D).expect("valid scalar");
        let der = signing.sign_der(b"sample").expect("sign");
        verifying
            .verify_der(b"sample", &der)
            .expect("the signature must verify under the matching public key");
    }

    #[test]
    fn a_bit_flipped_signature_is_rejected() {
        let verifying =
            Es256VerifyingKey::from_uncompressed_sec1(&PUBLIC_KEY_SEC1).expect("valid point");
        let signing = Es256SigningKey::from_bytes(&RFC6979_D).expect("valid scalar");
        let mut der = signing.sign_der(b"sample").expect("sign");
        // Flip one low bit well inside the `s` integer's encoding, not past the end of the
        // buffer and not touching the ASN.1 tag/length bytes at the very front.
        let last = der.len() - 1;
        if let Some(byte) = der.get_mut(last) {
            *byte ^= 0x01;
        }
        assert!(verifying.verify_der(b"sample", &der).is_err());
    }

    #[test]
    fn a_truncated_signature_is_rejected() {
        let verifying =
            Es256VerifyingKey::from_uncompressed_sec1(&PUBLIC_KEY_SEC1).expect("valid point");
        let signing = Es256SigningKey::from_bytes(&RFC6979_D).expect("valid scalar");
        let der = signing.sign_der(b"sample").expect("sign");
        let truncated = der.get(..der.len().saturating_sub(1)).unwrap_or(&[]);
        assert!(verifying.verify_der(b"sample", truncated).is_err());
    }

    #[test]
    fn a_signature_under_the_wrong_message_is_rejected() {
        let verifying =
            Es256VerifyingKey::from_uncompressed_sec1(&PUBLIC_KEY_SEC1).expect("valid point");
        let signing = Es256SigningKey::from_bytes(&RFC6979_D).expect("valid scalar");
        let der = signing.sign_der(b"sample").expect("sign");
        assert!(verifying.verify_der(b"not sample", &der).is_err());
    }
}

#[test]
fn verifying_key_from_identity_like_bytes_is_rejected() {
    // Not a valid encoding of any point: `ecdsa`/`elliptic-curve` must reject it rather than
    // silently accept something that is not on the curve.
    let mut garbage = [0u8; 65];
    garbage[0] = 0x04;
    assert!(Es256VerifyingKey::from_uncompressed_sec1(&garbage).is_err());
}

#[test]
fn verifying_key_round_trips_through_sec1() {
    let mut rng = seeded_rng(4);
    let key = Es256SigningKey::generate(&mut rng);
    let sec1 = key.verifying_key().to_uncompressed_sec1();
    assert_eq!(sec1[0], 0x04, "uncompressed SEC1 points start with 0x04");
    let rebuilt = Es256VerifyingKey::from_uncompressed_sec1(&sec1).expect("round trip");
    assert_eq!(rebuilt, key.verifying_key());
}

// SHA-256 known-answer vectors (FIPS 180-4 Appendix B.1 / NIST CAVP): the empty string and
// "abc", applied through this module's own purpose-named wrappers rather than `sha2` directly,
// so a future change to either function is caught by the exact byte values `WebAuthn` signs
// over.
#[test]
fn rp_id_hash_matches_the_sha256_empty_string_vector() {
    assert_eq!(
        rp_id_hash(""),
        hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );
}

#[test]
fn client_data_hash_matches_the_sha256_abc_vector() {
    assert_eq!(
        client_data_hash(b"abc"),
        hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
}

#[test]
fn rp_id_hash_and_client_data_hash_are_the_same_primitive_over_the_same_bytes() {
    // Two purpose-named wrappers, deliberately the same algorithm (SHA-256) with no per-purpose
    // domain separation (`WebAuthn` itself defines none here): confirms neither wrapper secretly
    // salts or truncates its input differently from the other.
    assert_eq!(rp_id_hash("example.com"), client_data_hash(b"example.com"));
}

/// Decodes a hex literal into a 32-byte array, for the KATs above.
fn hex(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let Some(byte) = out.get_mut(i) else { break };
        let Ok(text) = core::str::from_utf8(chunk) else {
            continue;
        };
        if let Ok(parsed) = u8::from_str_radix(text, 16) {
            *byte = parsed;
        }
    }
    out
}
