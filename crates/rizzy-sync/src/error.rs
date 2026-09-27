//! Errors of the canonical encodings of this crate's core types: dots, HLC values and version
//! vectors (ADR 0012 §2–§3, ADR 0018 §3).
//!
//! | Type | Raised by |
//! |---|---|
//! | [`DecodeError`] | [`Dot::read`](crate::dot::Dot::read), [`Hlc::read`](crate::hlc::Hlc::read), [`VersionVector::read`](crate::vv::VersionVector::read) and [`VersionVector::parse`](crate::vv::VersionVector::parse) |
//! | [`EncodeError`] | [`VersionVector::encode`](crate::vv::VersionVector::encode) when the vector does not fit its `u16` count |
//! | [`HlcError`](crate::hlc::HlcError) | the clock update rules, in [`hlc`](crate::hlc) |
//!
//! These values are server-visible metadata (ADR 0012 §11, as replaced by ADR 0022 §2), never
//! field keys or values, so an error may name the byte offset and the kind of the failure. A
//! [`DecodeError`] carries only those two, the form ADR 0018 §2 gives parse errors.
//!
//! Normative vectors assert only that a byte string is rejected, never the kind or offset
//! (ADR 0018 §12). The kinds and offsets each decoder documents are local diagnostics: this
//! crate's unit tests pin them, and callers may rely on them, but the format does not freeze
//! them.

use core::fmt;

/// Why a canonical encoding was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DecodeErrorKind {
    /// The input ended before a field was complete, or a count claims more entries than the
    /// remaining input can hold (ADR 0018 §5 rule 2, "runs past the end").
    Truncated,
    /// Bytes remained after the last field of a structure parsed as a whole.
    TrailingBytes,
    /// A dot or a version-vector entry has `seq` 0 (ADR 0012 §3 "every `seq` ≥ 1", ADR 0018 §3
    /// `dot`, §5 rule 6).
    ZeroSeq,
    /// Version-vector entries are not strictly ascending by `device_id`: out of order, or a
    /// duplicate (ADR 0012 §3 "Canonical VV encoding").
    NotAscending,
}

impl fmt::Display for DecodeErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "input truncated",
            Self::TrailingBytes => "trailing bytes after the last field",
            Self::ZeroSeq => "sequence number 0",
            Self::NotAscending => "entries not strictly ascending by device id",
        })
    }
}

/// A rejected encoding: the kind of failure and the byte offset of the field that failed.
///
/// The offset counts from the first byte the failing call read: from the start of the input
/// for a `parse`, from the reader's position at the call for a `read`. A caller that parses a
/// larger structure adds the position at which it made the call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DecodeError {
    /// What was wrong.
    kind: DecodeErrorKind,
    /// Where the failing field starts, relative to the start of the call's input.
    offset: usize,
}

impl DecodeError {
    /// An error of `kind` at `offset`.
    pub(crate) const fn new(kind: DecodeErrorKind, offset: usize) -> Self {
        Self { kind, offset }
    }

    /// The same error, with `base` added to its offset: for an error raised by a nested read
    /// that started `base` bytes into the caller's input.
    pub(crate) const fn shifted(self, base: usize) -> Self {
        Self {
            kind: self.kind,
            offset: self.offset.saturating_add(base),
        }
    }

    /// What was wrong.
    #[must_use]
    pub const fn kind(&self) -> DecodeErrorKind {
        self.kind
    }

    /// The byte offset of the failing field, relative to the start of the call's input.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at byte {}", self.kind, self.offset)
    }
}

impl core::error::Error for DecodeError {}

/// A value does not fit its canonical encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EncodeError {
    /// A version vector has more than 65,535 non-zero entries, the most its `u16 n` count can
    /// express (ADR 0012 §3).
    TooManyEntries,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooManyEntries => "too many version-vector entries for a u16 count",
        })
    }
}

impl core::error::Error for EncodeError {}

#[cfg(test)]
mod tests {
    //! Accessors, offset shifting and the `Display` texts.

    use super::*;

    #[test]
    fn accessors_and_display() {
        let e = DecodeError::new(DecodeErrorKind::ZeroSeq, 18);
        assert_eq!(e.kind(), DecodeErrorKind::ZeroSeq);
        assert_eq!(e.offset(), 18);
        assert_eq!(e.to_string(), "sequence number 0 at byte 18");
        assert_eq!(e.shifted(2).offset(), 20);
        assert_eq!(e.shifted(usize::MAX).offset(), usize::MAX);
        assert_eq!(
            EncodeError::TooManyEntries.to_string(),
            "too many version-vector entries for a u16 count"
        );
        for kind in [
            DecodeErrorKind::Truncated,
            DecodeErrorKind::TrailingBytes,
            DecodeErrorKind::ZeroSeq,
            DecodeErrorKind::NotAscending,
        ] {
            assert!(!kind.to_string().is_empty());
        }
    }
}
