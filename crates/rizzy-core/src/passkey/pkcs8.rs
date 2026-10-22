// SPDX-License-Identifier: AGPL-3.0-only

//! The PKCS#8 `PrivateKeyInfo` (RFC 5958) a CXF passkey's `key` holds ([ADR 0074] §4): a
//! hand-written reader and writer of exactly the two fixed shapes ES256 and `EdDSA` need, not a
//! general ASN.1/DER implementation (owner answer 2 at acceptance: no `pkcs8` feature of `p256`
//! or `ed25519-dalek`, no `der` crate).
//!
//! [ADR 0074]: ../../../../../docs/adr/0074-passkey-cxf-import-export.md
//!
//! **This is encoding, not cryptography** (ADR 0074 §4): it moves the 32 bytes a passkey
//! already stores (`passkey/<id>/private_key`, ADR 0039 §1) into and out of DER. No signature,
//! KDF or AEAD is involved; the only key operations are the ones [`super`] already has (the
//! ES256 scalar check and public-key derivation).
//!
//! # Accepted shapes
//!
//! Every length is DER's: definite and minimal (short form below 128, one `0x81` byte from 128
//! to 255). A key longer than [`MAX_PKCS8_LEN`] is refused before it is read, so no other
//! length form can occur.
//!
//! **ES256** (RFC 5958 `PrivateKeyInfo`, `id-ecPublicKey` with `prime256v1`, RFC 5480 §2.1.1,
//! wrapping an RFC 5915 `ECPrivateKey`):
//!
//! ```text
//! SEQUENCE {
//!   INTEGER 0
//!   SEQUENCE { OID 1.2.840.10045.2.1, OID 1.2.840.10045.3.1.7 }
//!   OCTET STRING { SEQUENCE {
//!     INTEGER 1
//!     OCTET STRING (32 bytes: the scalar)
//!     [0] { OID 1.2.840.10045.3.1.7 }         -- optional
//!     [1] { BIT STRING (0x00 0x04 x y) }      -- optional
//!   } }
//! }
//! ```
//!
//! The scalar must be a valid, non-zero P-256 scalar. When the optional public key is present
//! it must equal the key derived from the scalar: the public key is **never** taken from the
//! file (ADR 0074 §3, "a file cannot assert a public key that disagrees with its own private
//! key"), and a key whose embedded public key disagrees is refused rather than silently
//! corrected.
//!
//! **`EdDSA`** (RFC 8410 §7, `id-Ed25519`, parameters absent, `CurvePrivateKey` the 32-byte seed):
//!
//! ```text
//! SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING { OCTET STRING (32 bytes) } }
//! ```
//!
//! **Refused:** any other algorithm OID or curve, an `ECPrivateKey` version other than 1, a
//! `PrivateKeyInfo` version other than 0 (so RFC 5958's v2 `OneAsymmetricKey` with its optional
//! public key), attributes, trailing bytes at any level, and a non-minimal or indefinite length.
//!
//! # Written shapes
//!
//! [`encode_es256`] writes the ES256 shape with the optional public key and without `[0]`
//! (138 bytes), the form `WebCrypto`'s `exportKey("pkcs8")`, `OpenSSL` 3's `pkcs8 -topk8` and the
//! CXF specification's own Appendix A example use. [`encode_eddsa_seed`] writes the RFC 8410
//! shape (48 bytes). Both read back through [`parse`].
//!
//! # Secrets
//!
//! The private key is never logged and never copied outside a wiping buffer: the parsed key
//! is a [`SecretArray`], the written DER a [`SecretBytes`] allocated once at its final size.
//! Errors are [`Pkcs8Error`] kinds and carry no byte of the input.

use crate::error::ParseError;
use crate::secret::{SecretArray, SecretBytes};

use super::{COORDINATE_LEN, ED25519_KEY_LEN, EdDsaSigningKey, Es256SigningKey};

/// The longest PKCS#8 key [`parse`] reads, in bytes. The longest accepted shape (ES256 with
/// both optional parts) is 150 bytes; anything above this is refused before it is read.
pub const MAX_PKCS8_LEN: usize = 255;

/// DER tag of a SEQUENCE.
const TAG_SEQUENCE: u8 = 0x30;
/// DER tag of an INTEGER.
const TAG_INTEGER: u8 = 0x02;
/// DER tag of an OCTET STRING.
const TAG_OCTET_STRING: u8 = 0x04;
/// DER tag of an OBJECT IDENTIFIER.
const TAG_OID: u8 = 0x06;
/// DER tag of a BIT STRING.
const TAG_BIT_STRING: u8 = 0x03;
/// `ECPrivateKey`'s `[0] parameters`, constructed, explicit.
const TAG_EC_PARAMETERS: u8 = 0xA0;
/// `ECPrivateKey`'s `[1] publicKey`, constructed, explicit.
const TAG_EC_PUBLIC_KEY: u8 = 0xA1;

/// `id-ecPublicKey`, 1.2.840.10045.2.1 (RFC 5480 §2.1.1), content octets.
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
/// `secp256r1` / `prime256v1`, 1.2.840.10045.3.1.7 (RFC 5480 §2.1.1.1), content octets.
const OID_PRIME256V1: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
/// `id-Ed25519`, 1.3.101.112 (RFC 8410 §3), content octets.
const OID_ED25519: &[u8] = &[0x2B, 0x65, 0x70];

/// The DER of the ES256 `PrivateKeyInfo` up to the scalar: the outer SEQUENCE (135 bytes),
/// version 0, the algorithm identifier, the OCTET STRING (109) and the `ECPrivateKey` SEQUENCE
/// (107) with its version 1 and the scalar's OCTET STRING header.
const ES256_PREFIX: &[u8] = &[
    0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02,
    0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x04, 0x6D, 0x30, 0x6B, 0x02,
    0x01, 0x01, 0x04, 0x20,
];
/// The DER after the scalar: `[1]` (68 bytes) holding the BIT STRING (66) with no unused bits;
/// the uncompressed SEC1 point follows.
const ES256_PUBLIC_KEY_HEADER: &[u8] = &[0xA1, 0x44, 0x03, 0x42, 0x00];

/// Length of [`encode_es256`]'s output.
pub const ES256_PKCS8_LEN: usize =
    ES256_PREFIX.len() + COORDINATE_LEN + ES256_PUBLIC_KEY_HEADER.len() + 1 + 2 * COORDINATE_LEN;

/// The DER of the RFC 8410 Ed25519 `PrivateKeyInfo` up to the seed.
const ED25519_PREFIX: &[u8] = &[
    0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// Length of [`encode_eddsa_seed`]'s output.
pub const ED25519_PKCS8_LEN: usize = ED25519_PREFIX.len() + ED25519_KEY_LEN;

/// The signature algorithm a PKCS#8 key is for: the only two there are (ADR 0039 §1
/// `passkey/<id>/alg` values 1 and 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Pkcs8Algorithm {
    /// ES256: ECDSA P-256 with SHA-256 (COSE `-7`).
    Es256,
    /// `EdDSA` with Ed25519 (COSE `-8`).
    EdDsa,
}

/// Why a PKCS#8 key was refused. No variant carries a byte of the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Pkcs8Error {
    /// Well-formed up to its `AlgorithmIdentifier`, which names an algorithm or curve other than
    /// ES256 (P-256) and Ed25519: an importer skips such a key and counts it (ADR 0074 §3,
    /// "unknown OID: skip the credential, count it").
    UnsupportedAlgorithm,
    /// Anything else: over [`MAX_PKCS8_LEN`], broken or non-minimal DER, another version, an
    /// invalid P-256 scalar, or an embedded public key that is not the scalar's.
    Invalid(ParseError),
}

impl core::fmt::Display for Pkcs8Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedAlgorithm => f.write_str("unsupported private-key algorithm"),
            Self::Invalid(e) => write!(f, "invalid PKCS#8 private key: {e}"),
        }
    }
}

impl core::error::Error for Pkcs8Error {}

impl From<ParseError> for Pkcs8Error {
    fn from(e: ParseError) -> Self {
        Self::Invalid(e)
    }
}

/// A parsed PKCS#8 private key: the algorithm and the raw 32-byte private value (the P-256
/// scalar or the Ed25519 seed), exactly what `passkey/<id>/private_key` stores. No `Clone`;
/// `Debug` prints only the algorithm.
pub struct Pkcs8PrivateKey {
    /// The algorithm, from the `AlgorithmIdentifier`.
    algorithm: Pkcs8Algorithm,
    /// The scalar or the seed, wiped on drop.
    secret: SecretArray<32>,
}

impl Pkcs8PrivateKey {
    /// The algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> Pkcs8Algorithm {
        self.algorithm
    }

    /// The 32-byte private value, for the caller to encrypt at once.
    #[must_use]
    pub const fn secret(&self) -> &SecretArray<32> {
        &self.secret
    }
}

impl core::fmt::Debug for Pkcs8PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pkcs8PrivateKey")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// A bounded reader over DER bytes: one element at a time, minimal definite lengths only.
struct Der<'a> {
    /// What is left.
    rest: &'a [u8],
}

impl<'a> Der<'a> {
    /// A reader over `input`.
    const fn new(input: &'a [u8]) -> Self {
        Self { rest: input }
    }

    /// The tag of the next element, if any.
    fn peek(&self) -> Option<u8> {
        self.rest.first().copied()
    }

    /// Reads one element with tag `tag` and returns its content octets.
    fn read(&mut self, tag: u8) -> Result<&'a [u8], ParseError> {
        let (&found, rest) = self.rest.split_first().ok_or(ParseError::Truncated)?;
        if found != tag {
            return Err(ParseError::InvalidValue);
        }
        let (&first, rest) = rest.split_first().ok_or(ParseError::Truncated)?;
        let (len, rest) = match first {
            0x00..=0x7F => (usize::from(first), rest),
            0x81 => {
                let (&len, rest) = rest.split_first().ok_or(ParseError::Truncated)?;
                // DER: the long form only where the short form cannot say it.
                if len < 0x80 {
                    return Err(ParseError::InvalidLength);
                }
                (usize::from(len), rest)
            }
            // 0x80 is BER's indefinite length; 0x82 and up say at least 256, over the cap.
            _ => return Err(ParseError::InvalidLength),
        };
        if rest.len() < len {
            return Err(ParseError::Truncated);
        }
        let (content, rest) = rest.split_at(len);
        self.rest = rest;
        Ok(content)
    }

    /// Reads one element with tag `tag` whose content must be exactly `expected`.
    fn read_exact(&mut self, tag: u8, expected: &[u8]) -> Result<(), ParseError> {
        if self.read(tag)? == expected {
            Ok(())
        } else {
            Err(ParseError::InvalidValue)
        }
    }

    /// Checks that nothing is left.
    const fn finish(self) -> Result<(), ParseError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(ParseError::TrailingBytes)
        }
    }
}

/// Parses a PKCS#8 `PrivateKeyInfo` of one of the two accepted shapes (module docs).
///
/// # Errors
/// [`Pkcs8Error::UnsupportedAlgorithm`] for another algorithm OID or EC curve;
/// [`Pkcs8Error::Invalid`] with [`ParseError::TooLong`] above [`MAX_PKCS8_LEN`],
/// [`ParseError::InvalidValue`] for another version, an invalid P-256 scalar or an embedded
/// public key that is not the scalar's, and [`ParseError::Truncated`],
/// [`ParseError::TrailingBytes`] or [`ParseError::InvalidLength`] for broken DER.
pub fn parse(der: &[u8]) -> Result<Pkcs8PrivateKey, Pkcs8Error> {
    if der.len() > MAX_PKCS8_LEN {
        return Err(ParseError::TooLong.into());
    }
    let mut outer = Der::new(der);
    let mut info = Der::new(outer.read(TAG_SEQUENCE)?);
    outer.finish()?;
    info.read_exact(TAG_INTEGER, &[0x00])?;
    let mut algorithm = Der::new(info.read(TAG_SEQUENCE)?);
    let oid = algorithm.read(TAG_OID)?;
    let private_key = info.read(TAG_OCTET_STRING)?;
    // No `[0] attributes` (and version 0 already rules out v2's `[1] publicKey`).
    info.finish()?;
    if oid == OID_EC_PUBLIC_KEY {
        if algorithm.read(TAG_OID)? != OID_PRIME256V1 {
            return Err(Pkcs8Error::UnsupportedAlgorithm);
        }
        algorithm.finish()?;
        Ok(parse_ec_private_key(private_key)?)
    } else if oid == OID_ED25519 {
        // RFC 8410 §3: "the parameters MUST be absent".
        algorithm.finish()?;
        let mut curve_private_key = Der::new(private_key);
        let seed = curve_private_key.read(TAG_OCTET_STRING)?;
        curve_private_key.finish()?;
        if seed.len() != ED25519_KEY_LEN {
            return Err(ParseError::InvalidLength.into());
        }
        Ok(Pkcs8PrivateKey {
            algorithm: Pkcs8Algorithm::EdDsa,
            secret: SecretArray::from_slice(seed)?,
        })
    } else {
        Err(Pkcs8Error::UnsupportedAlgorithm)
    }
}

/// Parses the RFC 5915 `ECPrivateKey` inside an ES256 `PrivateKeyInfo` (module docs).
fn parse_ec_private_key(der: &[u8]) -> Result<Pkcs8PrivateKey, ParseError> {
    let mut outer = Der::new(der);
    let mut ec = Der::new(outer.read(TAG_SEQUENCE)?);
    outer.finish()?;
    ec.read_exact(TAG_INTEGER, &[0x01])?;
    let scalar = ec.read(TAG_OCTET_STRING)?;
    if scalar.len() != COORDINATE_LEN {
        return Err(ParseError::InvalidLength);
    }
    let key = Es256SigningKey::from_bytes(scalar)?;
    if ec.peek() == Some(TAG_EC_PARAMETERS) {
        let mut parameters = Der::new(ec.read(TAG_EC_PARAMETERS)?);
        parameters.read_exact(TAG_OID, OID_PRIME256V1)?;
        parameters.finish()?;
    }
    if ec.peek() == Some(TAG_EC_PUBLIC_KEY) {
        let mut public = Der::new(ec.read(TAG_EC_PUBLIC_KEY)?);
        let bits = public.read(TAG_BIT_STRING)?;
        public.finish()?;
        let (&unused_bits, point) = bits.split_first().ok_or(ParseError::Truncated)?;
        if unused_bits != 0 || point != key.verifying_key().to_uncompressed_sec1().as_slice() {
            return Err(ParseError::InvalidValue);
        }
    }
    ec.finish()?;
    Ok(Pkcs8PrivateKey {
        algorithm: Pkcs8Algorithm::Es256,
        secret: key.to_bytes(),
    })
}

/// Writes `key` as the 138-byte ES256 `PrivateKeyInfo`, its public key included (module docs,
/// "Written shapes").
#[must_use]
pub fn encode_es256(key: &Es256SigningKey) -> SecretBytes {
    let scalar = key.to_bytes();
    let point = key.verifying_key().to_uncompressed_sec1();
    let mut out = Vec::with_capacity(ES256_PKCS8_LEN);
    out.extend_from_slice(ES256_PREFIX);
    out.extend_from_slice(scalar.expose_secret());
    out.extend_from_slice(ES256_PUBLIC_KEY_HEADER);
    out.extend_from_slice(&point);
    SecretBytes::from_vec(out)
}

/// Writes a 32-byte Ed25519 seed as the 48-byte RFC 8410 `PrivateKeyInfo` (module docs,
/// "Written shapes"). The seed is wrapped as it is: no key is built from it (ADR 0074 §2,
/// "Building the item").
///
/// # Errors
/// [`ParseError::InvalidLength`] if `seed` is not 32 bytes.
pub fn encode_eddsa_seed(seed: &[u8]) -> Result<SecretBytes, ParseError> {
    if seed.len() != ED25519_KEY_LEN {
        return Err(ParseError::InvalidLength);
    }
    let mut out = Vec::with_capacity(ED25519_PKCS8_LEN);
    out.extend_from_slice(ED25519_PREFIX);
    out.extend_from_slice(seed);
    Ok(SecretBytes::from_vec(out))
}

/// Writes `key` as the RFC 8410 `PrivateKeyInfo`, as [`encode_eddsa_seed`] does for its seed.
#[must_use]
pub fn encode_eddsa(key: &EdDsaSigningKey) -> SecretBytes {
    let seed = key.to_bytes();
    let mut out = Vec::with_capacity(ED25519_PKCS8_LEN);
    out.extend_from_slice(ED25519_PREFIX);
    out.extend_from_slice(seed.expose_secret());
    SecretBytes::from_vec(out)
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code indexes fixtures at known offsets; a panic there fails the test, which CLAUDE.md allows"
)]
mod tests;
