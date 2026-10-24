// SPDX-License-Identifier: AGPL-3.0-only

//! Known-answer, round-trip and hostile-input tests for [`super::parse`] and the writers.
//!
//! Vector provenance (CRYPTO.md §15; ADR 0074 §4: "OpenSSL- and browser-produced PKCS#8 files
//! for both algorithms"):
//! - **CXF Appendix A**: the `key` of the passkey credential in the example payload of the FIDO
//!   Alliance *Credential Exchange Format* 1.0, Proposed Standard with errata,
//!   `cxf-v1.0-ps-errata-20260309` (fetched 2026-10-22 from `fidoalliance.org/specs/cx/`). Its
//!   embedded public key was checked against its scalar with `openssl pkey -check`.
//! - **OpenSSL**: generated on 2026-10-22 with `OpenSSL 3.0.13`: `openssl genpkey -algorithm EC
//!   -pkeyopt ec_paramgen_curve:P-256 | openssl pkcs8 -topk8 -nocrypt -outform DER` and
//!   `openssl genpkey -algorithm ED25519 -outform DER`; public keys from `openssl pkey -pubout`.
//! - **RFC 8410 §10.3**: the Ed25519 private key examples, with and without attributes and
//!   public key; the public key the second one carries is the first one's.
//! - **Browser**: generated on 2026-10-22 in Playwright's Chromium (build 1223) with
//!   `crypto.subtle.generateKey` then `exportKey("pkcs8")` (ECDSA P-256 and Ed25519), public
//!   keys with `exportKey("raw")`.
//!
//! These are throwaway keys made for these tests; none protects anything.

use super::*;
use crate::passkey::{EdDsaSigningKey, Es256SigningKey};
use crate::test_util::hex;

/// CXF 1.0 PS errata, Appendix A, the passkey credential's `key`, base64url-decoded.
const CXF_APPENDIX_A_ES256: &str = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420011bbfd2c0addb4129815c5be0fbaadc66b95552e9b9363be6782f665caadd7ea14403420004a6764d712ec2b4a0e961c483e9d1dd59b92d2c4fd9dfe8166d49e961aaf2c15b47ce2f7de5fdb5e0b2bfd24d41e308b9fc97a81c449c1eece42f6d0b9b675758";
/// Its scalar.
const CXF_APPENDIX_A_SCALAR: &str =
    "011bbfd2c0addb4129815c5be0fbaadc66b95552e9b9363be6782f665caadd7e";
/// Its public key, uncompressed SEC1 (from `openssl ec -pubout`).
const CXF_APPENDIX_A_POINT: &str = "04a6764d712ec2b4a0e961c483e9d1dd59b92d2c4fd9dfe8166d49e961aaf2c15b47ce2f7de5fdb5e0b2bfd24d41e308b9fc97a81c449c1eece42f6d0b9b675758";

/// `OpenSSL 3.0.13` ES256 PKCS#8.
const OPENSSL_ES256: &str = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02010104201777a32526666ad1007afc679c3823f96d11657d05d74a3daf03e51b639b0ff9a14403420004a5d1e6a50a4bb29e345d9b16e0a24ec5b3f1a4096078f73e4b49320a2b891235a21fb927bf27b28a02e5583e23e573029bbde5473c7ed6efd2dd33cf14c85658";
/// Its scalar.
const OPENSSL_ES256_SCALAR: &str =
    "1777a32526666ad1007afc679c3823f96d11657d05d74a3daf03e51b639b0ff9";

/// `OpenSSL 3.0.13` Ed25519 PKCS#8.
const OPENSSL_ED25519: &str = "302e020100300506032b65700422042009da52d7dcc270c8b0ae3697d196a08fbecda8580c31e8352b69e4a61dcbf321";
/// Its seed.
const OPENSSL_ED25519_SEED: &str =
    "09da52d7dcc270c8b0ae3697d196a08fbecda8580c31e8352b69e4a61dcbf321";
/// Its public key (`openssl pkey -pubout`).
const OPENSSL_ED25519_PUBLIC: &str =
    "e06b4a8bfbf7695e71cb9778350cbd841c4942107975c21b2edf494e7aacc688";

/// RFC 8410 §10.3, first example (no public key).
const RFC8410_ED25519: &str = "302e020100300506032b657004220420d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842";
/// RFC 8410 §10.3, second example: version 1, an attribute and the public key.
const RFC8410_ED25519_V2: &str = "3072020101300506032b657004220420d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842a01f301d060a2a864886f70d01090914310f0c0d437572646c652043686169727381210019bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1";
/// The public key the second example carries.
const RFC8410_ED25519_PUBLIC: &str =
    "19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1";

/// Chromium 148 (Playwright build 1223) `WebCrypto` ES256 keys: PKCS#8 and the raw public key.
const BROWSER_ES256: [(&str, &str); 2] = [
    (
        "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420f42a00b2abd2d5e31c33641f8e28dfa802a5a6825a21bc5b24222fd3ddf8592ea14403420004e04ca91ae2a83460efb0e403b965886507a7d8ad8931dc033fa2f1e82507934a034841dc02ef512bfa082b2fa9442c6a8400e95fe5eb883c50f47450f7f42868",
        "04e04ca91ae2a83460efb0e403b965886507a7d8ad8931dc033fa2f1e82507934a034841dc02ef512bfa082b2fa9442c6a8400e95fe5eb883c50f47450f7f42868",
    ),
    (
        "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b020101042055e686017b6c1c390f5d0e3046987b8b320f6a93687503badd501fcf4175067ca144034200044af5667f008d55e6d1244ab898fa7a3c32b2a5db25ab6ebf3f27ff0f6a27a46513f7780190bd2b0f65c5996a3013ee00f43a9179fc58d8999c3ad4c9ad175e7c",
        "044af5667f008d55e6d1244ab898fa7a3c32b2a5db25ab6ebf3f27ff0f6a27a46513f7780190bd2b0f65c5996a3013ee00f43a9179fc58d8999c3ad4c9ad175e7c",
    ),
];

/// Chromium 148 `WebCrypto` Ed25519 keys: PKCS#8 and the raw public key.
const BROWSER_ED25519: [(&str, &str); 2] = [
    (
        "302e020100300506032b65700422042051e6a17374b06afd17bb0ad075061f911515c7a9085b7409c514506ea781af24",
        "33fa98edc8bd4f7cbc56f1e46d3e68c40d693ac3c6536bd606d35c71792c0e1e",
    ),
    (
        "302e020100300506032b657004220420730df122ccbf2693564078f1b327ae79003224965e4be990383bb9e858c957b4",
        "2c9cc0ef236b70cd0b8ab7b2e32a192da7c4fe4c5fe630bb8a152a4085810c8d",
    ),
];

/// Lowercase hex of `bytes`, to edit a vector as text.
fn to_hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// Parses `der`, which must succeed.
fn parsed(der: &[u8]) -> Pkcs8PrivateKey {
    parse(der).unwrap()
}

#[test]
fn cxf_appendix_a_key_parses_and_rewrites_byte_for_byte() {
    let der = hex(CXF_APPENDIX_A_ES256);
    let key = parsed(&der);
    assert_eq!(key.algorithm(), Pkcs8Algorithm::Es256);
    assert_eq!(
        key.secret().expose_secret().as_slice(),
        hex(CXF_APPENDIX_A_SCALAR)
    );
    let signing = Es256SigningKey::from_bytes(key.secret().expose_secret()).unwrap();
    assert_eq!(
        signing.verifying_key().to_uncompressed_sec1().as_slice(),
        hex(CXF_APPENDIX_A_POINT)
    );
    assert_eq!(encode_es256(&signing).expose_secret(), der.as_slice());
}

#[test]
fn openssl_keys_parse_and_rewrite_byte_for_byte() {
    let der = hex(OPENSSL_ES256);
    let key = parsed(&der);
    assert_eq!(key.algorithm(), Pkcs8Algorithm::Es256);
    assert_eq!(
        key.secret().expose_secret().as_slice(),
        hex(OPENSSL_ES256_SCALAR)
    );
    let signing = Es256SigningKey::from_bytes(key.secret().expose_secret()).unwrap();
    assert_eq!(encode_es256(&signing).expose_secret(), der.as_slice());

    let der = hex(OPENSSL_ED25519);
    let key = parsed(&der);
    assert_eq!(key.algorithm(), Pkcs8Algorithm::EdDsa);
    assert_eq!(
        key.secret().expose_secret().as_slice(),
        hex(OPENSSL_ED25519_SEED)
    );
    let signing = EdDsaSigningKey::from_seed(key.secret().expose_secret()).unwrap();
    assert_eq!(
        signing.verifying_key().to_bytes().as_slice(),
        hex(OPENSSL_ED25519_PUBLIC)
    );
    assert_eq!(encode_eddsa(&signing).expose_secret(), der.as_slice());
    assert_eq!(
        encode_eddsa_seed(key.secret().expose_secret())
            .unwrap()
            .expose_secret(),
        der.as_slice()
    );
}

#[test]
fn browser_keys_parse_and_rewrite_byte_for_byte() {
    for (der, public) in BROWSER_ES256 {
        let der = hex(der);
        let key = parsed(&der);
        assert_eq!(key.algorithm(), Pkcs8Algorithm::Es256);
        let signing = Es256SigningKey::from_bytes(key.secret().expose_secret()).unwrap();
        assert_eq!(
            signing.verifying_key().to_uncompressed_sec1().as_slice(),
            hex(public)
        );
        assert_eq!(encode_es256(&signing).expose_secret(), der.as_slice());
    }
    for (der, public) in BROWSER_ED25519 {
        let der = hex(der);
        let key = parsed(&der);
        assert_eq!(key.algorithm(), Pkcs8Algorithm::EdDsa);
        let signing = EdDsaSigningKey::from_seed(key.secret().expose_secret()).unwrap();
        assert_eq!(signing.verifying_key().to_bytes().as_slice(), hex(public));
        assert_eq!(encode_eddsa(&signing).expose_secret(), der.as_slice());
    }
}

#[test]
fn rfc8410_example_parses_and_derives_the_published_public_key() {
    let der = hex(RFC8410_ED25519);
    let key = parsed(&der);
    assert_eq!(key.algorithm(), Pkcs8Algorithm::EdDsa);
    let signing = EdDsaSigningKey::from_seed(key.secret().expose_secret()).unwrap();
    assert_eq!(
        signing.verifying_key().to_bytes().as_slice(),
        hex(RFC8410_ED25519_PUBLIC)
    );
    assert_eq!(encode_eddsa(&signing).expose_secret(), der.as_slice());
}

#[test]
fn rfc5958_v2_with_attributes_is_refused() {
    assert_eq!(
        parse(&hex(RFC8410_ED25519_V2)).unwrap_err(),
        Pkcs8Error::Invalid(ParseError::InvalidValue)
    );
}

/// The ES256 shape without the optional public key (RFC 5915 allows it; some encoders omit it).
fn es256_without_public_key(scalar: &[u8]) -> Vec<u8> {
    let mut out = hex("3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420");
    out.extend_from_slice(scalar);
    out
}

/// The ES256 shape with `[0] parameters` and the public key.
fn es256_with_parameters(scalar: &[u8], point: &[u8]) -> Vec<u8> {
    let mut out = hex("308193020100301306072a8648ce3d020106082a8648ce3d03010704793077020101 0420");
    out.extend_from_slice(scalar);
    out.extend_from_slice(&hex("a00a06082a8648ce3d030107a144034200"));
    out.extend_from_slice(point);
    out
}

#[test]
fn es256_optional_parts_are_accepted() {
    let scalar = hex(CXF_APPENDIX_A_SCALAR);
    let point = hex(CXF_APPENDIX_A_POINT);
    for der in [
        es256_without_public_key(&scalar),
        es256_with_parameters(&scalar, &point),
    ] {
        let key = parsed(&der);
        assert_eq!(key.algorithm(), Pkcs8Algorithm::Es256);
        assert_eq!(key.secret().expose_secret().as_slice(), scalar);
    }
}

#[test]
fn es256_public_key_must_be_the_scalars() {
    let mut der = hex(CXF_APPENDIX_A_ES256);
    // Flip a bit of the embedded point's x coordinate.
    let last = der.len() - 40;
    der[last] ^= 0x01;
    assert_eq!(
        parse(&der).unwrap_err(),
        Pkcs8Error::Invalid(ParseError::InvalidValue)
    );
    // Another valid key's point.
    let other = Es256SigningKey::from_bytes(&hex(OPENSSL_ES256_SCALAR)).unwrap();
    let mut der = hex(CXF_APPENDIX_A_ES256);
    let at = der.len() - 65;
    der[at..].copy_from_slice(&other.verifying_key().to_uncompressed_sec1());
    assert_eq!(
        parse(&der).unwrap_err(),
        Pkcs8Error::Invalid(ParseError::InvalidValue)
    );
    // Unused bits in the BIT STRING.
    let mut der = hex(CXF_APPENDIX_A_ES256);
    let at = der.len() - 66;
    der[at] = 0x01;
    assert_eq!(
        parse(&der).unwrap_err(),
        Pkcs8Error::Invalid(ParseError::InvalidValue)
    );
}

#[test]
fn invalid_scalars_are_refused() {
    // Zero, and the group order n itself (FIPS 186-4 D.1.2.3), which is not below n.
    for scalar in [
        [0u8; 32].to_vec(),
        hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
        [0xFF; 32].to_vec(),
    ] {
        assert_eq!(
            parse(&es256_without_public_key(&scalar)).unwrap_err(),
            Pkcs8Error::Invalid(ParseError::InvalidValue)
        );
    }
}

#[test]
fn every_truncation_is_refused_without_panicking() {
    for vector in [CXF_APPENDIX_A_ES256, OPENSSL_ED25519] {
        let der = hex(vector);
        for len in 0..der.len() {
            assert!(parse(&der[..len]).is_err(), "prefix of {len} bytes");
        }
    }
}

#[test]
fn trailing_bytes_are_refused_at_every_level() {
    let mut der = hex(OPENSSL_ED25519);
    der.push(0x00);
    assert_eq!(
        parse(&der).unwrap_err(),
        Pkcs8Error::Invalid(ParseError::TrailingBytes)
    );
    // Inside the PrivateKeyInfo: an extra NULL after the private key, lengths fixed up.
    let mut der = hex(
        "3030020100300506032b65700422042009da52d7dcc270c8b0ae3697d196a08fbecda8580c31e8352b69e4a61dcbf3210500",
    );
    assert_eq!(
        parse(&der).unwrap_err(),
        Pkcs8Error::Invalid(ParseError::TrailingBytes)
    );
    // Inside the CurvePrivateKey.
    der = hex(
        "3030020100300506032b657004240420 09da52d7dcc270c8b0ae3697d196a08fbecda8580c31e8352b69e4a61dcbf3210500",
    );
    assert_eq!(
        parse(&der).unwrap_err(),
        Pkcs8Error::Invalid(ParseError::TrailingBytes)
    );
    // Ed25519 with parameters (RFC 8410: MUST be absent).
    der = hex(
        "3030020100300706032b65700500042204 2009da52d7dcc270c8b0ae3697d196a08fbecda8580c31e8352b69e4a61dcbf321",
    );
    assert_eq!(
        parse(&der).unwrap_err(),
        Pkcs8Error::Invalid(ParseError::TrailingBytes)
    );
}

#[test]
fn other_algorithms_curves_and_versions_are_refused() {
    let base = hex(CXF_APPENDIX_A_ES256);
    let replace = |from: &str, to: &str| {
        let text = to_hex(&base).replacen(from, to, 1);
        parse(&hex(&text)).unwrap_err()
    };
    // Another curve OID of the same length (P-256's last arc changed): an unsupported curve.
    assert_eq!(
        replace("2a8648ce3d030107", "2a8648ce3d030106"),
        Pkcs8Error::UnsupportedAlgorithm
    );
    // id-ecPublicKey's last arc changed: an unsupported algorithm.
    assert_eq!(
        replace("2a8648ce3d0201", "2a8648ce3d0202"),
        Pkcs8Error::UnsupportedAlgorithm
    );
    // PrivateKeyInfo version 1.
    assert_eq!(
        replace("020100", "020101"),
        Pkcs8Error::Invalid(ParseError::InvalidValue)
    );
    // ECPrivateKey version 2.
    assert_eq!(
        replace("020101", "020102"),
        Pkcs8Error::Invalid(ParseError::InvalidValue)
    );
    // Ed448 (1.3.101.113) instead of Ed25519.
    let ed448 = OPENSSL_ED25519.replacen("2b6570", "2b6571", 1);
    assert_eq!(
        parse(&hex(&ed448)).unwrap_err(),
        Pkcs8Error::UnsupportedAlgorithm
    );
    // A seed of 31 or 33 bytes.
    let short = hex(
        "302d020100300506032b657004210420 09da52d7dcc270c8b0ae3697d196a08fbecda8580c31e8352b69e4a61dcbf3",
    );
    assert!(parse(&short).is_err());
}

#[test]
fn non_minimal_and_indefinite_lengths_are_refused() {
    // The outer length 46 written in the long form.
    let long_form = OPENSSL_ED25519.replacen("302e", "30812e", 1);
    assert_eq!(
        parse(&hex(&long_form)).unwrap_err(),
        Pkcs8Error::Invalid(ParseError::InvalidLength)
    );
    // BER's indefinite length.
    let indefinite = OPENSSL_ED25519.replacen("302e", "3080", 1);
    assert_eq!(
        parse(&hex(&indefinite)).unwrap_err(),
        Pkcs8Error::Invalid(ParseError::InvalidLength)
    );
    // A two-byte length.
    let two_bytes = OPENSSL_ED25519.replacen("302e", "3082002e", 1);
    assert_eq!(
        parse(&hex(&two_bytes)).unwrap_err(),
        Pkcs8Error::Invalid(ParseError::InvalidLength)
    );
}

#[test]
fn oversized_input_is_refused_before_reading() {
    let mut der = hex(OPENSSL_ED25519);
    der.resize(MAX_PKCS8_LEN + 1, 0);
    assert_eq!(
        parse(&der).unwrap_err(),
        Pkcs8Error::Invalid(ParseError::TooLong)
    );
}

#[test]
fn writers_round_trip_generated_keys() {
    let mut rng = crate::test_util::seeded_rng(0x7C5F);
    for _ in 0..32 {
        let key = Es256SigningKey::generate(&mut rng);
        let der = encode_es256(&key);
        assert_eq!(der.len(), ES256_PKCS8_LEN);
        let back = parsed(der.expose_secret());
        assert_eq!(back.algorithm(), Pkcs8Algorithm::Es256);
        assert_eq!(
            back.secret().expose_secret(),
            key.to_bytes().expose_secret()
        );

        let mut seed = [0u8; 32];
        rand_core::Rng::fill_bytes(&mut rng, &mut seed);
        let der = encode_eddsa_seed(&seed).unwrap();
        assert_eq!(der.len(), ED25519_PKCS8_LEN);
        let back = parsed(der.expose_secret());
        assert_eq!(back.algorithm(), Pkcs8Algorithm::EdDsa);
        assert_eq!(back.secret().expose_secret(), &seed);
    }
    assert_eq!(
        encode_eddsa_seed(&[0u8; 31]).unwrap_err(),
        ParseError::InvalidLength
    );
}

#[test]
fn debug_prints_no_key_material() {
    let key = parsed(&hex(OPENSSL_ED25519));
    let debug = format!("{key:?}");
    assert!(!debug.contains("09da") && !debug.to_lowercase().contains("09:da"));
    assert!(debug.contains("EdDsa"));
}
