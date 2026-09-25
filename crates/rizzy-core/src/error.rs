//! Error types.
//!
//! Rules (CRYPTO.md §9.5, §12.2, §12.3):
//! - Every decryption failure is the same [`DecryptError`]. It never says which check failed
//!   (length, version, algorithm, key id, commitment or tag), so there is no "which check
//!   failed" oracle.
//! - No error carries key material, plaintext or anything derived from a secret. The only
//!   values an error may carry are public protocol values, such as a `kdf_id` the server named.

use core::fmt;

/// The one error for every failed decryption.
///
/// Returned for a malformed envelope, a wrong format version, an algorithm outside the
/// purpose's allow-list, a key id that does not match the caller's key, a failed commitment,
/// a failed AEAD tag and a malformed plaintext frame alike (CRYPTO.md §8.3, §9.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DecryptError;

impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("decryption failed")
    }
}

impl core::error::Error for DecryptError {}

/// Malformed untrusted input.
///
/// Used by the purpose-agnostic parsers (the envelope layout parser, the frame reader, the
/// bounded [`Reader`](crate::encoding::Reader), base64url). The decryption path maps every one
/// of these to [`DecryptError`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ParseError {
    /// The input ended before a field was complete.
    Truncated,
    /// Bytes remained after the last field.
    TrailingBytes,
    /// A fixed-size value had the wrong length, or a length field disagrees with the input.
    InvalidLength,
    /// The input, or a length field, exceeds a limit.
    TooLong,
    /// A field holds a value outside its allowed set (version, algorithm id, enum value).
    InvalidValue,
    /// Text is not valid UTF-8.
    InvalidUtf8,
    /// Not canonical base64url without padding (RFC 4648 §5).
    InvalidEncoding,
    /// A padding byte is not zero.
    NonZeroPadding,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "input truncated",
            Self::TrailingBytes => "trailing bytes after the last field",
            Self::InvalidLength => "invalid length",
            Self::TooLong => "input exceeds its size limit",
            Self::InvalidValue => "field value not allowed",
            Self::InvalidUtf8 => "invalid UTF-8",
            Self::InvalidEncoding => "invalid base64url",
            Self::NonZeroPadding => "non-zero padding",
        })
    }
}

impl core::error::Error for ParseError {}

/// A value does not fit the canonical encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EncodeError {
    /// A value is longer than its length prefix can express (`u32` for `bytes(x)`), or than a
    /// format's size limit.
    TooLong,
    /// A field holds a value the format does not allow (for example a web-vault certificate
    /// without a 12 h expiry), so the structure would be rejected by every reader.
    InvalidField,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLong => "value too long to encode",
            Self::InvalidField => "field value not allowed by the format",
        })
    }
}

impl core::error::Error for EncodeError {}

/// Encryption failed. These are caller errors or unreachable internal failures; none depends on
/// a secret value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EncryptError {
    /// The (framed) plaintext exceeds the algorithm's limit (16 MiB for `0x01` in M1,
    /// CRYPTO.md §9.1).
    PlaintextTooLong,
    /// The purpose has a fixed plaintext size (a key wrap, CRYPTO.md §8.5) and the plaintext
    /// has a different length.
    InvalidPlaintextLength,
    /// The purpose's encrypt algorithm is not the one this function implements, or its
    /// plaintext layout is not specified yet.
    UnsupportedPurpose,
    /// The context disagrees with the keys or objects being wrapped (an epoch, id or key type
    /// that does not match), so the result could never be opened where it belongs.
    ContextMismatch,
    /// The recipient public key is unusable: the key exchange with it gives the all-zero
    /// shared secret (a small-order X25519 point, RFC 9180 §7.1.4).
    InvalidPublicKey,
    /// An internal primitive failed. Unreachable for the fixed sizes this crate uses.
    Internal,
}

impl fmt::Display for EncryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PlaintextTooLong => "plaintext too long",
            Self::InvalidPlaintextLength => "plaintext has the wrong length for this purpose",
            Self::UnsupportedPurpose => "purpose not supported by this algorithm",
            Self::ContextMismatch => "context does not match the wrapped object",
            Self::InvalidPublicKey => "unusable recipient public key",
            Self::Internal => "internal encryption error",
        })
    }
}

impl core::error::Error for EncryptError {}

/// A signed statement or signature container failed verification (CRYPTO.md §9.3, §10.2).
///
/// Signatures are public, so the kinds are distinguished for callers and logs; none carries key
/// material or statement contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum VerifyError {
    /// The statement, container or a field is malformed, or a field holds a value the format
    /// does not allow.
    Malformed(ParseError),
    /// The `statement_version`, `sig_format_version` or `sig_alg` is not one this build accepts
    /// (only version 1 and Ed25519 exist; `sig_alg` `0x02` is reserved).
    UnsupportedVersion,
    /// The container names a signer key id other than the key the verifier expected.
    WrongSigner,
    /// `verify_strict` rejected the signature.
    BadSignature,
    /// The statement verified but does not say what the verifier expected: another account,
    /// device, epoch, purpose or recipient.
    Mismatch,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(e) => write!(f, "malformed signed statement: {e}"),
            Self::UnsupportedVersion => f.write_str("unsupported statement or signature version"),
            Self::WrongSigner => f.write_str("statement signed by an unexpected key"),
            Self::BadSignature => f.write_str("invalid signature"),
            Self::Mismatch => f.write_str("signed statement does not match what was expected"),
        }
    }
}

impl core::error::Error for VerifyError {}

impl From<ParseError> for VerifyError {
    fn from(e: ParseError) -> Self {
        Self::Malformed(e)
    }
}

/// Signing a statement failed. None of these depends on a secret value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignError {
    /// The statement cannot be encoded: a field is too long or not allowed by the format.
    Encode(EncodeError),
    /// The signing key is not the key the statement names (a bundle's own identity key, a
    /// key grant's sender key), or the keys of a two-signature bundle are not distinct.
    WrongKey,
    /// The signature primitive failed. Unreachable for Ed25519 signing keys.
    Internal,
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encode(e) => write!(f, "cannot encode statement: {e}"),
            Self::WrongKey => f.write_str("signing key does not match the statement"),
            Self::Internal => f.write_str("internal signing error"),
        }
    }
}

impl core::error::Error for SignError {}

impl From<EncodeError> for SignError {
    fn from(e: EncodeError) -> Self {
        Self::Encode(e)
    }
}

/// Errors from the KDF layer: `kdf_id` checks, Argon2id and password normalisation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KdfError {
    /// The `kdf_id` is not on this client's compiled allow-list (CRYPTO.md §6.2). This is a
    /// hard error, never a fallback. The id is a public protocol value, usually named by the
    /// server.
    NotAllowed {
        /// The rejected `kdf_id`.
        kdf_id: u16,
    },
    /// The requested output length is not one CRYPTO.md §6.1 uses (32 or 64 bytes).
    InvalidOutputLength,
    /// Argon2 rejected its inputs (for example a password longer than `u32::MAX` bytes).
    InvalidInput,
    /// A new password contains a code point that is unassigned in the pinned Unicode tables
    /// (ADR 0004, owner decision 3).
    UnassignedCodePoint,
    /// An internal primitive failed. Unreachable for the fixed sizes this crate uses.
    Internal,
}

impl fmt::Display for KdfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAllowed { kdf_id } => write!(
                f,
                "KDF settings not allowed by this client (kdf_id {kdf_id})"
            ),
            Self::InvalidOutputLength => f.write_str("invalid KDF output length"),
            Self::InvalidInput => f.write_str("invalid KDF input"),
            Self::UnassignedCodePoint => {
                f.write_str("password contains a character unassigned in this Unicode version")
            }
            Self::Internal => f.write_str("internal KDF error"),
        }
    }
}

impl core::error::Error for KdfError {}

/// An HKDF output length outside `1..=8160` bytes was requested.
///
/// Unreachable for the fixed lengths this crate derives (16, 32 and 64 bytes); it exists
/// because the crate forbids panics in non-test code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DerivationError;

impl fmt::Display for DerivationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("key derivation failed")
    }
}

impl core::error::Error for DerivationError {}

impl From<DerivationError> for EncryptError {
    fn from(_: DerivationError) -> Self {
        Self::Internal
    }
}

impl From<DerivationError> for DecryptError {
    fn from(_: DerivationError) -> Self {
        Self
    }
}

impl From<ParseError> for DecryptError {
    fn from(_: ParseError) -> Self {
        Self
    }
}
