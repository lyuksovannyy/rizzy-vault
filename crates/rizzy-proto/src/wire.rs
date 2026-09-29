//! Bounded wire value types: every variable field of a request or response is one of these.
//!
//! JSON bodies are untrusted in both directions: the server parses client requests, and clients
//! parse responses from a server the threat model does not trust (threat model A2, §7.6 "D").
//! So every value that can grow carries its limit in its type, and deserialising checks the
//! limit **before** it allocates or decodes anything in proportion to the input:
//!
//! - [`Bytes`], [`Fixed`] and [`Id`]: binary values as base64url without padding (CRYPTO.md
//!   §9.6), decoded strictly (padding, characters outside the URL-safe alphabet, an impossible
//!   length and non-zero trailing bits are rejected), so each byte string has exactly one
//!   accepted text form. The text length is compared with the limit before decoding.
//! - [`Text`]: a string with a byte limit and a per-kind ASCII character set ([`TextRule`]).
//! - [`List`]: a sequence with an element-count limit; it reserves at most
//!   [`LIST_PREALLOC_MAX`] elements up front, whatever length the input announces.
//! - [`SessionToken`] and [`SecretText`]: secrets. They zeroize on drop, redact `Debug`, have no
//!   `PartialEq`, and never echo their input in an error.
//!
//! **Errors carry no input.** Every error this module produces names a limit or a rule, never
//! the rejected bytes or text. Note that `serde_json`'s own type errors (for example "invalid
//! type: string ..., expected u64") do quote the input: callers must map a deserialisation
//! failure to [`ErrorCode::InvalidRequest`](crate::error::ErrorCode::InvalidRequest) and never
//! log or return the `serde_json` message (threat model INV-48).
//!
//! **Debug output.** Binary values print their length only: they are OPAQUE messages,
//! envelopes, signatures and hashes, which INV-48 keeps out of logs. [`Id`] prints hex, as ids
//! are routing metadata the server already logs by design (ADR 0021 §4 "names the vault, item
//! and dot"). A [`Text`] kind that holds personal data (the login name) prints its length only.

use core::fmt;
use core::marker::PhantomData;

use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::de::{self, Deserializer, SeqAccess, Visitor};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// At most this many elements are reserved up front when a [`List`] is deserialised, whatever
/// size the input announces; the vector then grows only with elements actually parsed.
pub const LIST_PREALLOC_MAX: usize = 64;

/// Length of the base64url-without-padding text of `n` bytes (RFC 4648 §5, no `=`).
#[must_use]
pub const fn b64url_len(n: usize) -> usize {
    let rem = match n % 3 {
        0 => 0,
        1 => 2,
        _ => 3,
    };
    (n / 3).saturating_mul(4).saturating_add(rem)
}

/// Why a wire value was refused. Carries limits and rule names only, never the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WireError {
    /// A byte string or text is longer than its limit.
    TooLong {
        /// The limit, in bytes.
        max: usize,
    },
    /// A byte string or text is empty; no field of this API is empty.
    Empty,
    /// A fixed-size value has another length.
    WrongLength {
        /// The required length, in bytes.
        expected: usize,
    },
    /// A list has more elements than its limit.
    TooMany {
        /// The limit, in elements.
        max: usize,
    },
    /// Not strict base64url without padding.
    InvalidEncoding,
    /// A character outside the field's character set.
    InvalidCharacter,
    /// A list that must be canonical (strictly ascending, no zero entry) is not.
    NotCanonical,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { max } => write!(f, "value longer than {max} bytes"),
            Self::Empty => f.write_str("empty value"),
            Self::WrongLength { expected } => write!(f, "value is not {expected} bytes"),
            Self::TooMany { max } => write!(f, "more than {max} elements"),
            Self::InvalidEncoding => f.write_str("not base64url without padding"),
            Self::InvalidCharacter => f.write_str("character outside the allowed set"),
            Self::NotCanonical => f.write_str("list is not in canonical order"),
        }
    }
}

impl std::error::Error for WireError {}

/// Decodes strict base64url without padding into `out`, whose length is the exact expected
/// decoded length.
fn decode_exact(text: &str, out: &mut [u8]) -> Result<(), WireError> {
    if text.len() != b64url_len(out.len()) {
        return Err(WireError::WrongLength {
            expected: out.len(),
        });
    }
    let expected = out.len();
    let decoded = Base64UrlUnpadded::decode(text, out)
        .map_err(|_| WireError::InvalidEncoding)?
        .len();
    if decoded == expected {
        Ok(())
    } else {
        Err(WireError::WrongLength { expected })
    }
}

/// A variable-length binary value of 1 to `MAX` bytes, carried as base64url without padding.
///
/// The limit is checked on the text length before decoding, and again on the decoded length.
/// `Debug` prints the length only.
#[derive(Clone, PartialEq, Eq)]
pub struct Bytes<const MAX: usize>(Vec<u8>);

impl<const MAX: usize> Bytes<MAX> {
    /// The largest accepted length, in bytes.
    pub const MAX_LEN: usize = MAX;

    /// Wraps `bytes`.
    ///
    /// # Errors
    /// [`WireError::Empty`] or [`WireError::TooLong`].
    pub fn new(bytes: Vec<u8>) -> Result<Self, WireError> {
        if bytes.is_empty() {
            Err(WireError::Empty)
        } else if bytes.len() > MAX {
            Err(WireError::TooLong { max: MAX })
        } else {
            Ok(Self(bytes))
        }
    }

    /// Copies `bytes`.
    ///
    /// # Errors
    /// As [`Bytes::new`]. Nothing is copied on error.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.is_empty() {
            Err(WireError::Empty)
        } else if bytes.len() > MAX {
            Err(WireError::TooLong { max: MAX })
        } else {
            Ok(Self(bytes.to_vec()))
        }
    }

    /// Decodes base64url without padding, strictly.
    ///
    /// # Errors
    /// [`WireError::TooLong`] if the text could only decode to more than `MAX` bytes (checked
    /// before decoding), [`WireError::InvalidEncoding`], or [`WireError::Empty`].
    pub fn from_b64url(text: &str) -> Result<Self, WireError> {
        if text.len() > b64url_len(MAX) {
            return Err(WireError::TooLong { max: MAX });
        }
        let bytes = Base64UrlUnpadded::decode_vec(text).map_err(|_| WireError::InvalidEncoding)?;
        Self::new(bytes)
    }

    /// The base64url text, without padding.
    #[must_use]
    pub fn to_b64url(&self) -> String {
        Base64UrlUnpadded::encode_string(&self.0)
    }

    /// The bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// The bytes, by value.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }

    /// Length in bytes, at least 1.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Always `false`: an empty value is refused at construction. Present for clippy's
    /// `len_without_is_empty`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<const MAX: usize> fmt::Debug for Bytes<MAX> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bytes").field("len", &self.0.len()).finish()
    }
}

impl<const MAX: usize> Serialize for Bytes<MAX> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_b64url())
    }
}

impl<'de, const MAX: usize> Deserialize<'de> for Bytes<MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        /// Visitor for [`Bytes`].
        struct V<const MAX: usize>;
        impl<const MAX: usize> Visitor<'_> for V<MAX> {
            type Value = Bytes<MAX>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "base64url without padding of 1 to {MAX} bytes")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Bytes::from_b64url(v).map_err(E::custom)
            }
        }
        deserializer.deserialize_str(V::<MAX>)
    }
}

/// A binary value of exactly `N` bytes (hashes, challenges, the restore generation), carried
/// as base64url without padding. `Debug` prints the length only.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Fixed<const N: usize>([u8; N]);

impl<const N: usize> Fixed<N> {
    /// Length in bytes.
    pub const LEN: usize = N;

    /// Wraps `bytes`.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// The bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }

    /// The bytes, by value.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; N] {
        self.0
    }

    /// Decodes base64url without padding, strictly, as exactly `N` bytes.
    ///
    /// # Errors
    /// [`WireError::WrongLength`] or [`WireError::InvalidEncoding`].
    pub fn from_b64url(text: &str) -> Result<Self, WireError> {
        let mut out = [0u8; N];
        decode_exact(text, &mut out)?;
        Ok(Self(out))
    }

    /// The base64url text, without padding.
    #[must_use]
    pub fn to_b64url(&self) -> String {
        Base64UrlUnpadded::encode_string(&self.0)
    }
}

impl<const N: usize> fmt::Debug for Fixed<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Fixed").field("len", &N).finish()
    }
}

impl<const N: usize> Serialize for Fixed<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_b64url())
    }
}

impl<'de, const N: usize> Deserialize<'de> for Fixed<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        /// Visitor for [`Fixed`].
        struct V<const N: usize>;
        impl<const N: usize> Visitor<'_> for V<N> {
            type Value = Fixed<N>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "base64url without padding of exactly {N} bytes")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Fixed::from_b64url(v).map_err(E::custom)
            }
        }
        deserializer.deserialize_str(V::<N>)
    }
}

/// A 16-byte identifier (CRYPTO.md §2 "`id` values", and the 16-byte key ids of §4.4),
/// carried as base64url without padding. Ids are routing metadata, not secrets, so `Debug`
/// prints them in hex.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Id([u8; Id::LEN]);

impl Id {
    /// Length in bytes (CRYPTO.md §2).
    pub const LEN: usize = 16;

    /// Wraps `bytes`.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// The bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// The bytes, by value.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; Self::LEN] {
        self.0
    }

    /// Decodes base64url without padding, strictly, as exactly 16 bytes.
    ///
    /// # Errors
    /// [`WireError::WrongLength`] or [`WireError::InvalidEncoding`].
    pub fn from_b64url(text: &str) -> Result<Self, WireError> {
        let mut out = [0u8; Self::LEN];
        decode_exact(text, &mut out)?;
        Ok(Self(out))
    }

    /// The base64url text, without padding.
    #[must_use]
    pub fn to_b64url(&self) -> String {
        Base64UrlUnpadded::encode_string(&self.0)
    }
}

impl fmt::Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Id(")?;
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))?;
        f.write_str(")")
    }
}

impl Serialize for Id {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_b64url())
    }
}

impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        /// Visitor for [`Id`].
        struct V;
        impl Visitor<'_> for V {
            type Value = Id;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a 16-byte id as base64url without padding")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Id::from_b64url(v).map_err(E::custom)
            }
        }
        deserializer.deserialize_str(V)
    }
}

/// The limit and character set of one kind of [`Text`] or [`SecretText`].
pub trait TextRule {
    /// The largest accepted length, in bytes.
    const MAX: usize;
    /// `true` when `Debug` must print the length only (personal data or secrets).
    const REDACT: bool;
    /// Whether `byte` may appear. Every rule admits ASCII only, so byte length equals
    /// character count and no Unicode normalisation question arises.
    fn allowed(byte: u8) -> bool;
}

/// Checks `text` against rule `R`: not empty, at most `R::MAX` bytes, every byte allowed.
fn check_text<R: TextRule>(text: &str) -> Result<(), WireError> {
    if text.is_empty() {
        Err(WireError::Empty)
    } else if text.len() > R::MAX {
        Err(WireError::TooLong { max: R::MAX })
    } else if text.bytes().all(R::allowed) {
        Ok(())
    } else {
        Err(WireError::InvalidCharacter)
    }
}

/// A non-empty ASCII string of at most `R::MAX` bytes from `R`'s character set.
pub struct Text<R: TextRule>(String, PhantomData<R>);

impl<R: TextRule> Text<R> {
    /// Checks and wraps `text`.
    ///
    /// # Errors
    /// [`WireError::Empty`], [`WireError::TooLong`] or [`WireError::InvalidCharacter`].
    pub fn new(text: String) -> Result<Self, WireError> {
        check_text::<R>(&text)?;
        Ok(Self(text, PhantomData))
    }

    /// Checks and copies `text`.
    ///
    /// # Errors
    /// As [`Text::new`]. Nothing is copied on error.
    #[expect(
        clippy::should_implement_trait,
        reason = "fallible with a WireError; FromStr would add nothing but an alias"
    )]
    pub fn from_str(text: &str) -> Result<Self, WireError> {
        check_text::<R>(text)?;
        Ok(Self(text.to_owned(), PhantomData))
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The text, by value.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl<R: TextRule> Clone for Text<R> {
    fn clone(&self) -> Self {
        Self(self.0.clone(), PhantomData)
    }
}

impl<R: TextRule> PartialEq for Text<R> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<R: TextRule> Eq for Text<R> {}

impl<R: TextRule> fmt::Debug for Text<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if R::REDACT {
            f.debug_struct("Text").field("len", &self.0.len()).finish()
        } else {
            f.debug_tuple("Text").field(&self.0).finish()
        }
    }
}

impl<R: TextRule> Serialize for Text<R> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de, R: TextRule> Deserialize<'de> for Text<R> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        /// Visitor for [`Text`].
        struct V<R>(PhantomData<R>);
        impl<R: TextRule> Visitor<'_> for V<R> {
            type Value = Text<R>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "an ASCII string of 1 to {} bytes", R::MAX)
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Text::from_str(v).map_err(E::custom)
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                Text::new(v).map_err(E::custom)
            }
        }
        deserializer.deserialize_str(V::<R>(PhantomData))
    }
}

/// A secret ASCII string under rule `R` (an invite token, a TOTP code): zeroized on drop,
/// `Debug` redacted, no `PartialEq` (compare secrets in constant time, on the server, after
/// hashing where the spec says so).
pub struct SecretText<R: TextRule>(Zeroizing<String>, PhantomData<R>);

impl<R: TextRule> SecretText<R> {
    /// Checks and copies `text` into a zeroizing buffer.
    ///
    /// # Errors
    /// [`WireError::Empty`], [`WireError::TooLong`] or [`WireError::InvalidCharacter`].
    pub fn new(text: &str) -> Result<Self, WireError> {
        check_text::<R>(text)?;
        let mut owned = Zeroizing::new(String::with_capacity(text.len()));
        owned.push_str(text);
        Ok(Self(owned, PhantomData))
    }

    /// The secret. Keep the borrow short, and never log it.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl<R: TextRule> fmt::Debug for SecretText<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretText(<redacted>)")
    }
}

impl<R: TextRule> Serialize for SecretText<R> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de, R: TextRule> Deserialize<'de> for SecretText<R> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        /// Visitor for [`SecretText`].
        struct V<R>(PhantomData<R>);
        impl<R: TextRule> Visitor<'_> for V<R> {
            type Value = SecretText<R>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "an ASCII string of 1 to {} bytes", R::MAX)
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                SecretText::new(v).map_err(E::custom)
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                // Take ownership first, so the input is wiped on every path.
                let owned = Zeroizing::new(v);
                check_text::<R>(&owned).map_err(E::custom)?;
                Ok(SecretText(owned, PhantomData))
            }
        }
        deserializer.deserialize_str(V::<R>(PhantomData))
    }
}

/// A 32-byte bearer session token (CRYPTO.md §5.10): random, issued by the server, stored there
/// only as `SHA-256(token)` (§5.11). Zeroized on drop, `Debug` redacted, no `PartialEq`; it
/// never appears in a URL (threat model INV-52) or a log (INV-48).
pub struct SessionToken(Zeroizing<[u8; SessionToken::LEN]>);

impl SessionToken {
    /// Length in bytes (§5.10).
    pub const LEN: usize = 32;

    /// Wraps a token the caller drew from its CSPRNG.
    #[must_use]
    pub const fn new(bytes: Zeroizing<[u8; Self::LEN]>) -> Self {
        Self(bytes)
    }

    /// The token. Keep the borrow short: hash it (server) or put it in the `Authorization`
    /// header (client), and never log it.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// Decodes a token from base64url without padding into a zeroizing buffer.
    ///
    /// # Errors
    /// [`WireError::WrongLength`] or [`WireError::InvalidEncoding`].
    pub fn from_b64url(text: &str) -> Result<Self, WireError> {
        let mut out = Zeroizing::new([0u8; Self::LEN]);
        decode_exact(text, &mut *out)?;
        Ok(Self(out))
    }

    /// The token as base64url without padding, in a zeroizing buffer.
    #[must_use]
    pub fn to_b64url(&self) -> Zeroizing<String> {
        let mut buf = Zeroizing::new([0u8; b64url_len(Self::LEN)]);
        let mut out = Zeroizing::new(String::with_capacity(b64url_len(Self::LEN)));
        if let Ok(text) = Base64UrlUnpadded::encode(&*self.0, &mut *buf) {
            out.push_str(text);
        }
        out
    }
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionToken(<redacted>)")
    }
}

impl Serialize for SessionToken {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_b64url())
    }
}

impl<'de> Deserialize<'de> for SessionToken {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        /// Visitor for [`SessionToken`].
        struct V;
        impl Visitor<'_> for V {
            type Value = SessionToken;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a 32-byte token as base64url without padding")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                SessionToken::from_b64url(v).map_err(E::custom)
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                let owned = Zeroizing::new(v);
                SessionToken::from_b64url(&owned).map_err(E::custom)
            }
        }
        deserializer.deserialize_str(V)
    }
}

/// A secret binary value of exactly `N` bytes, carried as base64url without padding: the
/// recovery auth token (CRYPTO.md §4.3, §11.9) and the server's TOTP secret handed to the user
/// once (§11.15). Like [`SessionToken`]: zeroized on drop, `Debug` redacted, no `PartialEq`, and
/// errors never quote the input.
pub struct SecretFixed<const N: usize>(Zeroizing<[u8; N]>);

impl<const N: usize> SecretFixed<N> {
    /// Length in bytes.
    pub const LEN: usize = N;

    /// Wraps bytes the caller holds in a zeroizing buffer.
    #[must_use]
    pub const fn new(bytes: Zeroizing<[u8; N]>) -> Self {
        Self(bytes)
    }

    /// Copies `bytes` into a zeroizing buffer.
    ///
    /// # Errors
    /// [`WireError::WrongLength`]. Nothing is copied on error.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() != N {
            return Err(WireError::WrongLength { expected: N });
        }
        let mut out = Zeroizing::new([0u8; N]);
        out.copy_from_slice(bytes);
        Ok(Self(out))
    }

    /// The secret. Keep the borrow short, and never log it.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; N] {
        &self.0
    }

    /// Decodes base64url without padding, strictly, as exactly `N` bytes, into a zeroizing
    /// buffer.
    ///
    /// # Errors
    /// [`WireError::WrongLength`] or [`WireError::InvalidEncoding`].
    pub fn from_b64url(text: &str) -> Result<Self, WireError> {
        let mut out = Zeroizing::new([0u8; N]);
        decode_exact(text, &mut *out)?;
        Ok(Self(out))
    }

    /// The secret as base64url without padding, in a zeroizing buffer.
    #[must_use]
    pub fn to_b64url(&self) -> Zeroizing<String> {
        let mut buf = Zeroizing::new(vec![0u8; b64url_len(N)]);
        let mut out = Zeroizing::new(String::with_capacity(b64url_len(N)));
        if let Ok(text) = Base64UrlUnpadded::encode(&*self.0, &mut buf) {
            out.push_str(text);
        }
        out
    }
}

impl<const N: usize> fmt::Debug for SecretFixed<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretFixed(<redacted>)")
    }
}

impl<const N: usize> Serialize for SecretFixed<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_b64url())
    }
}

impl<'de, const N: usize> Deserialize<'de> for SecretFixed<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        /// Visitor for [`SecretFixed`].
        struct V<const N: usize>;
        impl<const N: usize> Visitor<'_> for V<N> {
            type Value = SecretFixed<N>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a {N}-byte secret as base64url without padding")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                SecretFixed::from_b64url(v).map_err(E::custom)
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                let owned = Zeroizing::new(v);
                SecretFixed::from_b64url(&owned).map_err(E::custom)
            }
        }
        deserializer.deserialize_str(V::<N>)
    }
}

/// A list of at most `MAX` elements.
///
/// Deserialising reserves at most [`LIST_PREALLOC_MAX`] elements up front and fails as soon as
/// the input holds element `MAX + 1`, so an announced or actual length never makes it allocate
/// past its limit. The elements' own limits bound each element.
#[derive(Clone, PartialEq, Eq)]
pub struct List<T, const MAX: usize>(Vec<T>);

impl<T, const MAX: usize> List<T, MAX> {
    /// The largest accepted number of elements.
    pub const MAX_LEN: usize = MAX;

    /// Wraps `items`.
    ///
    /// # Errors
    /// [`WireError::TooMany`].
    pub fn new(items: Vec<T>) -> Result<Self, WireError> {
        if items.len() > MAX {
            Err(WireError::TooMany { max: MAX })
        } else {
            Ok(Self(items))
        }
    }

    /// The empty list.
    #[must_use]
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    /// The elements.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    /// The elements, by value.
    #[must_use]
    pub fn into_vec(self) -> Vec<T> {
        self.0
    }

    /// Number of elements.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// `true` when there are no elements.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterates over the elements.
    pub fn iter(&self) -> core::slice::Iter<'_, T> {
        self.0.iter()
    }
}

impl<T, const MAX: usize> Default for List<T, MAX> {
    fn default() -> Self {
        Self::empty()
    }
}

impl<'a, T, const MAX: usize> IntoIterator for &'a List<T, MAX> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<T: fmt::Debug, const MAX: usize> fmt::Debug for List<T, MAX> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(&self.0).finish()
    }
}

impl<T: Serialize, const MAX: usize> Serialize for List<T, MAX> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(&self.0)
    }
}

impl<'de, T: Deserialize<'de>, const MAX: usize> Deserialize<'de> for List<T, MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        /// Visitor for [`List`].
        struct V<T, const MAX: usize>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>, const MAX: usize> Visitor<'de> for V<T, MAX> {
            type Value = List<T, MAX>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a list of at most {MAX} elements")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let reserve = seq.size_hint().unwrap_or(0).min(MAX).min(LIST_PREALLOC_MAX);
                let mut items = Vec::with_capacity(reserve);
                while let Some(item) = seq.next_element()? {
                    if items.len() == MAX {
                        return Err(de::Error::custom(WireError::TooMany { max: MAX }));
                    }
                    items.push(item);
                }
                Ok(List(items))
            }
        }
        deserializer.deserialize_seq(V::<T, MAX>(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    //! Limits, strictness and redaction of the wire value types.

    use super::*;
    use crate::limits::{LoginNameRule, TotpCodeRule};

    /// A small list type for the limit tests.
    type Three = List<u8, 3>;

    #[test]
    fn b64url_lengths() {
        assert_eq!(b64url_len(0), 0);
        assert_eq!(b64url_len(1), 2);
        assert_eq!(b64url_len(2), 3);
        assert_eq!(b64url_len(3), 4);
        assert_eq!(b64url_len(16), 22);
        assert_eq!(b64url_len(32), 43);
        for n in 0..200 {
            assert_eq!(
                b64url_len(n),
                Base64UrlUnpadded::encode_string(&vec![0; n]).len()
            );
        }
    }

    #[test]
    fn bytes_limits_and_strictness() {
        type B = Bytes<4>;
        assert_eq!(B::from_b64url("AQIDBA").unwrap().as_slice(), [1, 2, 3, 4]);
        // Five bytes: refused on the text length, before decoding.
        assert_eq!(
            B::from_b64url("AQIDBAU"),
            Err(WireError::TooLong { max: 4 })
        );
        assert_eq!(B::from_b64url(""), Err(WireError::Empty));
        for bad in ["AQ==", "AQ=", "A", "AR", "+/8", "AQ ID"] {
            assert!(B::from_b64url(bad).is_err(), "{bad:?}");
        }
        assert_eq!(B::new(vec![0; 5]), Err(WireError::TooLong { max: 4 }));
        assert_eq!(B::new(Vec::new()), Err(WireError::Empty));
        assert_eq!(
            format!("{:?}", B::new(vec![7; 3]).unwrap()),
            "Bytes { len: 3 }"
        );
    }

    #[test]
    fn fixed_and_id_need_exact_length() {
        assert!(Fixed::<2>::from_b64url("AQI").is_ok());
        assert_eq!(
            Fixed::<2>::from_b64url("AQ"),
            Err(WireError::WrongLength { expected: 2 })
        );
        assert_eq!(
            Fixed::<2>::from_b64url("AQID"),
            Err(WireError::WrongLength { expected: 2 })
        );
        // Non-zero trailing bits.
        assert!(Fixed::<2>::from_b64url("AQJ").is_err());
        let id = Id::from_bytes([0xab; 16]);
        assert_eq!(Id::from_b64url(&id.to_b64url()).unwrap(), id);
        assert_eq!(format!("{id:?}"), format!("Id({})", "ab".repeat(16)));
        assert_eq!(
            format!("{:?}", Fixed::from_bytes([1u8; 32])),
            "Fixed { len: 32 }"
        );
    }

    #[test]
    fn text_rules() {
        type Login = Text<LoginNameRule>;
        assert!(Login::from_str("Alice.B+x@example.org").is_ok());
        assert_eq!(Login::from_str(""), Err(WireError::Empty));
        assert_eq!(Login::from_str("a b"), Err(WireError::InvalidCharacter));
        assert_eq!(Login::from_str("ä"), Err(WireError::InvalidCharacter));
        assert_eq!(
            Login::from_str(&"a".repeat(255)),
            Err(WireError::TooLong { max: 254 })
        );
        assert!(Login::from_str(&"a".repeat(254)).is_ok());
        // The login name is personal data: Debug prints the length only.
        assert_eq!(
            format!("{:?}", Login::from_str("alice").unwrap()),
            "Text { len: 5 }"
        );
    }

    #[test]
    fn secrets_are_redacted() {
        let code = SecretText::<TotpCodeRule>::new("123456").unwrap();
        assert_eq!(format!("{code:?}"), "SecretText(<redacted>)");
        assert_eq!(code.expose_secret(), "123456");
        assert!(SecretText::<TotpCodeRule>::new("12a456").is_err());
        let token = SessionToken::new(Zeroizing::new([9; 32]));
        assert_eq!(format!("{token:?}"), "SessionToken(<redacted>)");
        let text = token.to_b64url();
        assert_eq!(text.len(), 43);
        assert_eq!(
            SessionToken::from_b64url(&text).unwrap().expose_secret(),
            &[9; 32]
        );
        let secret = SecretFixed::<20>::from_slice(&[7; 20]).unwrap();
        assert_eq!(format!("{secret:?}"), "SecretFixed(<redacted>)");
        let text = secret.to_b64url();
        assert_eq!(text.len(), 27);
        assert_eq!(
            SecretFixed::<20>::from_b64url(&text)
                .unwrap()
                .expose_secret(),
            &[7; 20]
        );
        assert_eq!(
            SecretFixed::<20>::from_slice(&[7; 19]).err(),
            Some(WireError::WrongLength { expected: 20 })
        );
    }

    #[test]
    fn list_limit() {
        assert!(Three::new(vec![1, 2, 3]).is_ok());
        assert_eq!(
            Three::new(vec![1, 2, 3, 4]),
            Err(WireError::TooMany { max: 3 })
        );
        assert_eq!(
            serde_json::from_str::<Three>("[1,2,3]").unwrap().as_slice(),
            [1, 2, 3]
        );
        assert!(serde_json::from_str::<Three>("[1,2,3,4]").is_err());
        assert!(serde_json::from_str::<Three>("[]").unwrap().is_empty());
    }

    #[test]
    fn errors_never_quote_the_input() {
        let secret = "s3cr3t-value-SHOULD-NOT-LEAK";
        let json = format!("\"{secret}!\"");
        let err = serde_json::from_str::<Text<LoginNameRule>>(&json).unwrap_err();
        assert!(!err.to_string().contains(secret), "{err}");
        let err = serde_json::from_str::<SecretText<TotpCodeRule>>(&json).unwrap_err();
        assert!(!err.to_string().contains(secret), "{err}");
        let err = serde_json::from_str::<Bytes<4>>(&json).unwrap_err();
        assert!(!err.to_string().contains(secret), "{err}");
        let err = serde_json::from_str::<SessionToken>(&json).unwrap_err();
        assert!(!err.to_string().contains(secret), "{err}");
        let err = serde_json::from_str::<SecretFixed<32>>(&json).unwrap_err();
        assert!(!err.to_string().contains(secret), "{err}");
    }
}
