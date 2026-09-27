//! Field values: the ADR 0018 §6 value encoding, its decoder and encoder (§10 per-value limit).
//!
//! A value is either empty (Cleared) or `u8 value_type ‖ payload`:
//!
//! | Type | Id | Payload | Well-formed when |
//! |---|---|---|---|
//! | Cleared | – | none: the value is 0 bytes | always |
//! | Text | `0x01` | UTF-8 as entered, not normalised | the payload is UTF-8 (it may be empty) |
//! | Bytes | `0x02` | raw | always (it may be empty) |
//! | Bool | `0x03` | one byte | the payload is exactly `0x00` or `0x01` |
//! | U64 | `0x04` | `u64`, big-endian | the payload is exactly 8 bytes |
//! | Enum | `0x05` | `u16`, big-endian | the payload is exactly 2 bytes |
//! | `SortKey` | `0x06` | 1–64 bytes, ordered bytewise | the payload is 1–64 bytes and its last byte is not `0x00` |
//! | Reserved | `0x00`, `0x07`–`0xFF` | – | never: an unknown type to this client |
//!
//! A value is at most [`MAX_VALUE_LEN`] = 65,536 bytes, type byte included (ADR 0018 §10).
//! Integers are big-endian at fixed width, as everywhere else (CRYPTO.md §2). Each well-formed
//! value has exactly one encoding, so decode then encode is the identity.
//!
//! **Empty and non-empty** (ADR 0018 §6). *Empty* is the zero-length Cleared value only. Every
//! value of one byte or more is non-empty: a Text with an empty payload, and every unsupported
//! or malformed value, too. Writers write Cleared, never an empty Text, when the user empties a
//! field ([`super::schema::check_write`]).
//!
//! **A decode error never rejects a record** (ADR 0018 §6, "Invalid values never reject an op").
//! [`ValueRef::decode`] returns [`ValueError`] for an unknown type, a malformed payload or an
//! oversize value, and the caller shows the field as "unsupported value". The record layer has
//! already kept, merged and snapshotted the bytes verbatim; it never calls this decoder, except
//! for the one-byte `@lifecycle` values it checks itself (ADR 0018 §5 rule 5). Rejecting here
//! would let replicas that run different schema versions diverge.
//!
//! **Secrets.** Values hold passwords, card numbers and TOTP secrets. An owned [`Value`] and a
//! [`SortKey`] live in zeroizing buffers allocated at their final size, and implement neither
//! `Clone` nor `Copy` (CRYPTO.md §12.2). [`ValueRef`] is a `Copy` view: its Text, Bytes and
//! `SortKey` variants borrow from the caller's buffer, but its Bool, U64 and Enum variants hold
//! copies of the decoded integers, which are plain stack values and are not wiped. None of the
//! three prints its content from `Debug` or implements `Display` or `PartialEq`, and errors are
//! kinds only (CRYPTO.md §12.2). Compare values with `subtle::ConstantTimeEq` on their encoded
//! bytes, as [`super::display`] does.
//!
//! The decoder is fuzzed (ADR 0018 §12, CRYPTO.md §15 item 7: "the value decoder").

use core::fmt;

use crate::secret::SecretBytes;

/// Longest value, in bytes, type byte included (ADR 0018 §10).
pub const MAX_VALUE_LEN: usize = 65_536;

/// Longest `SortKey` payload, in bytes (ADR 0018 §6).
pub const MAX_SORT_KEY_LEN: usize = 64;

/// The value types of ADR 0018 §6. Cleared has no type byte and is not one of them.
///
/// Type ids `0x00` and `0x07`–`0xFF` are reserved: a later ADR may assign one without a version
/// bump (ADR 0018 §11), and until then this client shows such a value as unsupported.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ValueType {
    /// `0x01`: UTF-8 text as entered.
    Text,
    /// `0x02`: raw bytes.
    Bytes,
    /// `0x03`: one byte, `0x00` or `0x01`.
    Bool,
    /// `0x04`: a big-endian `u64`, for example Unix milliseconds.
    U64,
    /// `0x05`: a big-endian `u16`.
    Enum,
    /// `0x06`: 1–64 bytes, last byte not `0x00`, ordered bytewise.
    SortKey,
}

impl ValueType {
    /// Every type, in id order.
    pub const ALL: [Self; 6] = [
        Self::Text,
        Self::Bytes,
        Self::Bool,
        Self::U64,
        Self::Enum,
        Self::SortKey,
    ];

    /// The type byte.
    #[must_use]
    pub const fn id(self) -> u8 {
        match self {
            Self::Text => 0x01,
            Self::Bytes => 0x02,
            Self::Bool => 0x03,
            Self::U64 => 0x04,
            Self::Enum => 0x05,
            Self::SortKey => 0x06,
        }
    }

    /// The type of a type byte; `None` for a reserved id.
    #[must_use]
    pub const fn from_id(id: u8) -> Option<Self> {
        match id {
            0x01 => Some(Self::Text),
            0x02 => Some(Self::Bytes),
            0x03 => Some(Self::Bool),
            0x04 => Some(Self::U64),
            0x05 => Some(Self::Enum),
            0x06 => Some(Self::SortKey),
            _ => None,
        }
    }
}

/// Why a value cannot be read. The field then shows as "unsupported value"; the record that
/// carries it is never rejected (ADR 0018 §6). Carries no part of the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ValueError {
    /// The value is longer than [`MAX_VALUE_LEN`] bytes. The record layer rejects such a
    /// record before any value is decoded (ADR 0018 §5 rule 2); an encoder refuses to build one.
    TooLong,
    /// The type byte is reserved (`0x00`, `0x07`–`0xFF`): a newer client's type, or garbage.
    UnknownType,
    /// The payload does not fit its type: bad UTF-8, a Bool other than `0x00`/`0x01`, a U64 or
    /// Enum of the wrong length, or a `SortKey` that is empty, longer than 64 bytes or ends in
    /// `0x00`.
    Malformed,
}

impl fmt::Display for ValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLong => "value is longer than 65536 bytes",
            Self::UnknownType => "value has an unsupported type",
            Self::Malformed => "value is malformed",
        })
    }
}

impl core::error::Error for ValueError {}

/// A decoded value, borrowed from its encoding.
///
/// `Copy`, because it is a view; the scalar variants (Bool, U64, Enum) hold copies of the
/// decoded integers, which are not wiped. `Debug` prints the type only. There is no
/// `PartialEq`: compare encoded bytes in constant time instead (CRYPTO.md §12.3).
#[derive(Clone, Copy)]
pub enum ValueRef<'a> {
    /// The empty value: the field has no value.
    Cleared,
    /// Text as entered.
    Text(&'a str),
    /// Raw bytes.
    Bytes(&'a [u8]),
    /// A boolean.
    Bool(bool),
    /// A `u64`.
    U64(u64),
    /// A `u16` enum value.
    Enum(u16),
    /// A sort key payload: 1–64 bytes, last byte not `0x00`.
    SortKey(&'a [u8]),
}

impl fmt::Debug for ValueRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Cleared => "Cleared",
            Self::Text(_) => "Text([REDACTED])",
            Self::Bytes(_) => "Bytes([REDACTED])",
            Self::Bool(_) => "Bool([REDACTED])",
            Self::U64(_) => "U64([REDACTED])",
            Self::Enum(_) => "Enum([REDACTED])",
            Self::SortKey(_) => "SortKey([REDACTED])",
        })
    }
}

impl<'a> ValueRef<'a> {
    /// Decodes a value (ADR 0018 §6).
    ///
    /// Never panics and never allocates. The length is checked first.
    ///
    /// # Errors
    /// [`ValueError`]: the field shows as "unsupported value". It never rejects the record.
    pub fn decode(encoded: &'a [u8]) -> Result<Self, ValueError> {
        if encoded.len() > MAX_VALUE_LEN {
            return Err(ValueError::TooLong);
        }
        let Some((&type_id, payload)) = encoded.split_first() else {
            return Ok(Self::Cleared);
        };
        let value_type = ValueType::from_id(type_id).ok_or(ValueError::UnknownType)?;
        match value_type {
            ValueType::Text => core::str::from_utf8(payload)
                .map(Self::Text)
                .map_err(|_| ValueError::Malformed),
            ValueType::Bytes => Ok(Self::Bytes(payload)),
            ValueType::Bool => match payload {
                [0x00] => Ok(Self::Bool(false)),
                [0x01] => Ok(Self::Bool(true)),
                _ => Err(ValueError::Malformed),
            },
            ValueType::U64 => <[u8; 8]>::try_from(payload)
                .map(|b| Self::U64(u64::from_be_bytes(b)))
                .map_err(|_| ValueError::Malformed),
            ValueType::Enum => <[u8; 2]>::try_from(payload)
                .map(|b| Self::Enum(u16::from_be_bytes(b)))
                .map_err(|_| ValueError::Malformed),
            ValueType::SortKey => {
                if is_sort_key(payload) {
                    Ok(Self::SortKey(payload))
                } else {
                    Err(ValueError::Malformed)
                }
            }
        }
    }

    /// The value's type; `None` for Cleared.
    #[must_use]
    pub const fn value_type(&self) -> Option<ValueType> {
        match self {
            Self::Cleared => None,
            Self::Text(_) => Some(ValueType::Text),
            Self::Bytes(_) => Some(ValueType::Bytes),
            Self::Bool(_) => Some(ValueType::Bool),
            Self::U64(_) => Some(ValueType::U64),
            Self::Enum(_) => Some(ValueType::Enum),
            Self::SortKey(_) => Some(ValueType::SortKey),
        }
    }

    /// `true` for the empty (Cleared) value only (ADR 0018 §6, "Empty and non-empty").
    #[must_use]
    pub const fn is_cleared(&self) -> bool {
        matches!(self, Self::Cleared)
    }

    /// Encodes the value again.
    ///
    /// # Errors
    /// [`ValueError::TooLong`] for a Text or Bytes payload longer than 65,535 bytes, and
    /// [`ValueError::Malformed`] for a `SortKey` payload that is not 1–64 bytes ending in a
    /// non-zero byte.
    pub fn encode(&self) -> Result<Value, ValueError> {
        match *self {
            Self::Cleared => Ok(Value::cleared()),
            Self::Text(text) => Value::text(text),
            Self::Bytes(bytes) => Value::bytes(bytes),
            Self::Bool(b) => Ok(Value::bool(b)),
            Self::U64(v) => Ok(Value::u64(v)),
            Self::Enum(v) => Ok(Value::enumeration(v)),
            Self::SortKey(payload) => {
                if is_sort_key(payload) {
                    Value::typed(ValueType::SortKey, payload)
                } else {
                    Err(ValueError::Malformed)
                }
            }
        }
    }
}

/// An encoded value, owned, in a zeroizing buffer allocated at its final size.
///
/// Built by the typed constructors, which write only well-formed values, or copied verbatim
/// from a record ([`Value::copy_from_encoded`]), which keeps any bytes, since an unsupported
/// value is carried unchanged (ADR 0018 §6, §11).
pub struct Value {
    /// `u8 value_type ‖ payload`, or empty for Cleared.
    bytes: SecretBytes,
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Value([REDACTED])")
    }
}

impl Value {
    /// The Cleared value: 0 bytes.
    #[must_use]
    pub fn cleared() -> Self {
        Self {
            bytes: SecretBytes::from_vec(Vec::new()),
        }
    }

    /// `0x01 ‖ UTF-8(text)`, as entered: no normalisation, so a stored site password
    /// round-trips (ADR 0018 §6).
    ///
    /// # Errors
    /// [`ValueError::TooLong`] if the value would exceed 65,536 bytes.
    pub fn text(text: &str) -> Result<Self, ValueError> {
        Self::typed(ValueType::Text, text.as_bytes())
    }

    /// `0x02 ‖ bytes`.
    ///
    /// # Errors
    /// [`ValueError::TooLong`] if the value would exceed 65,536 bytes.
    pub fn bytes(bytes: &[u8]) -> Result<Self, ValueError> {
        Self::typed(ValueType::Bytes, bytes)
    }

    /// `0x03 ‖ 0x00` or `0x03 ‖ 0x01`.
    #[must_use]
    pub fn bool(value: bool) -> Self {
        Self::fixed(ValueType::Bool, &[u8::from(value)])
    }

    /// `0x04 ‖ u64(value)`.
    #[must_use]
    pub fn u64(value: u64) -> Self {
        Self::fixed(ValueType::U64, &value.to_be_bytes())
    }

    /// `0x05 ‖ u16(value)`.
    #[must_use]
    pub fn enumeration(value: u16) -> Self {
        Self::fixed(ValueType::Enum, &value.to_be_bytes())
    }

    /// `0x06 ‖ key`.
    #[must_use]
    pub fn sort_key(key: &SortKey) -> Self {
        Self::fixed(ValueType::SortKey, key.as_bytes())
    }

    /// Copies an encoded value verbatim, whatever its type or payload, into a buffer of exactly
    /// its size. For carrying a value this client cannot read (ADR 0018 §11).
    ///
    /// # Errors
    /// [`ValueError::TooLong`] if `encoded` is longer than 65,536 bytes; nothing else is
    /// checked.
    pub fn copy_from_encoded(encoded: &[u8]) -> Result<Self, ValueError> {
        if encoded.len() > MAX_VALUE_LEN {
            return Err(ValueError::TooLong);
        }
        Ok(Self {
            bytes: SecretBytes::copy_from_slice(encoded),
        })
    }

    /// The encoded bytes, as the record layer writes them with `bytes()` (ADR 0018 §3).
    ///
    /// Do not copy them into a plain buffer, format or log them.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        self.bytes.expose_secret()
    }

    /// Decodes the value.
    ///
    /// # Errors
    /// As [`ValueRef::decode`]: only for a value copied verbatim.
    pub fn decode(&self) -> Result<ValueRef<'_>, ValueError> {
        ValueRef::decode(self.bytes.expose_secret())
    }

    /// `true` for the empty (Cleared) value.
    #[must_use]
    pub fn is_cleared(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The encoded length, type byte included. Lengths are not secret here: envelopes reveal
    /// padded sizes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// `true` for the empty (Cleared) value; the same as [`Value::is_cleared`].
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// `type ‖ payload` for a payload of any length, in one allocation of the final size.
    fn typed(value_type: ValueType, payload: &[u8]) -> Result<Self, ValueError> {
        let len = payload
            .len()
            .checked_add(1)
            .filter(|len| *len <= MAX_VALUE_LEN)
            .ok_or(ValueError::TooLong)?;
        let mut bytes = Vec::with_capacity(len);
        bytes.push(value_type.id());
        bytes.extend_from_slice(payload);
        Ok(Self {
            bytes: SecretBytes::from_vec(bytes),
        })
    }

    /// `type ‖ payload` for a payload of at most 64 bytes, which always fits the limit.
    fn fixed(value_type: ValueType, payload: &[u8]) -> Self {
        let mut bytes = Vec::with_capacity(payload.len() + 1);
        bytes.push(value_type.id());
        bytes.extend_from_slice(payload);
        Self {
            bytes: SecretBytes::from_vec(bytes),
        }
    }
}

/// A `SortKey` payload: 1–64 bytes whose last byte is not `0x00`, ordered bytewise
/// (ADR 0018 §6).
///
/// Why the last byte is never `0x00`: then bytewise order is the order of the base-256
/// fractions `0.k₁k₂…`, and between any two keys there is another (possibly longer) key,
/// which is what [`super::order::sort_key_between`] relies on. A trailing `0x00` would add a
/// second spelling of one fraction.
///
/// Held in a zeroizing buffer like any other value; `Debug` does not print it.
pub struct SortKey {
    /// The payload, wiped on drop.
    bytes: SecretBytes,
}

impl fmt::Debug for SortKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SortKey([REDACTED])")
    }
}

impl SortKey {
    /// Copies a `SortKey` payload.
    ///
    /// # Errors
    /// [`ValueError::Malformed`] unless `payload` is 1–64 bytes and its last byte is not
    /// `0x00`.
    pub fn from_slice(payload: &[u8]) -> Result<Self, ValueError> {
        if is_sort_key(payload) {
            Ok(Self {
                bytes: SecretBytes::copy_from_slice(payload),
            })
        } else {
            Err(ValueError::Malformed)
        }
    }

    /// The payload.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.expose_secret()
    }
}

/// `true` if `payload` is a well-formed `SortKey` payload: 1–64 bytes, last byte not `0x00`.
#[must_use]
pub fn is_sort_key(payload: &[u8]) -> bool {
    payload.len() <= MAX_SORT_KEY_LEN && payload.last().is_some_and(|last| *last != 0x00)
}
