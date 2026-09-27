//! A bounded reader that knows its byte offset, shared by the header parser
//! ([`header`](crate::header)) and the record parser ([`record`](crate::record)).
//!
//! It wraps `rizzy-core`'s [`Reader`], which never panics, never copies and never allocates
//! (CRYPTO.md §9.5 rule 5), and adds the one thing both parsers need for their errors: the
//! offset, from the start of the parsed input, of the field that failed. Every failure is a
//! [`DecodeError`]; each parser maps it into its own error type, which carries only that kind
//! and offset (ADR 0018 §2).
//!
//! Like [`Reader`], a failed read leaves the cursor where it was.

use rizzy_core::encoding::Reader;

use crate::dot::Dot;
use crate::error::{DecodeError, DecodeErrorKind};
use crate::hlc::Hlc;
use crate::vv::VersionVector;

/// A [`Reader`] over one whole structure, with the structure's length for offsets.
#[derive(Clone, Debug)]
pub(crate) struct Cursor<'a> {
    /// The bytes not read yet.
    reader: Reader<'a>,
    /// Length of the whole input, so that `len − remaining` is the current offset.
    len: usize,
}

impl<'a> Cursor<'a> {
    /// Starts reading `input` from its first byte.
    pub(crate) const fn new(input: &'a [u8]) -> Self {
        Self {
            reader: Reader::new(input),
            len: input.len(),
        }
    }

    /// The offset of the next byte, from the start of the input.
    pub(crate) const fn offset(&self) -> usize {
        self.len.saturating_sub(self.reader.remaining())
    }

    /// Number of bytes not read yet.
    pub(crate) const fn remaining(&self) -> usize {
        self.reader.remaining()
    }

    /// A [`DecodeErrorKind::Truncated`] error at the current offset.
    const fn truncated(&self) -> DecodeError {
        DecodeError::new(DecodeErrorKind::Truncated, self.offset())
    }

    /// Reads a `u8`.
    pub(crate) fn u8(&mut self) -> Result<u8, DecodeError> {
        self.reader.u8().map_err(|_| self.truncated())
    }

    /// Reads a big-endian `u16`.
    pub(crate) fn u16(&mut self) -> Result<u16, DecodeError> {
        self.reader.u16().map_err(|_| self.truncated())
    }

    /// Reads a big-endian `u32`.
    pub(crate) fn u32(&mut self) -> Result<u32, DecodeError> {
        self.reader.u32().map_err(|_| self.truncated())
    }

    /// Reads a big-endian `u64`.
    pub(crate) fn u64(&mut self) -> Result<u64, DecodeError> {
        self.reader.u64().map_err(|_| self.truncated())
    }

    /// Reads the next `N` bytes, borrowed from the input.
    pub(crate) fn array<const N: usize>(&mut self) -> Result<&'a [u8; N], DecodeError> {
        self.reader.array::<N>().map_err(|_| self.truncated())
    }

    /// Reads the next `n` bytes, borrowed from the input. `n` has been read from the input, so
    /// nothing is allocated or copied for it.
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        self.reader.take(n).map_err(|_| self.truncated())
    }

    /// Reads a dot (`device_id ‖ u64 seq`, `seq` ≥ 1), with the error offset counted from the
    /// start of the input.
    pub(crate) fn dot(&mut self) -> Result<Dot, DecodeError> {
        let at = self.offset();
        Dot::read(&mut self.reader).map_err(|e| e.shifted(at))
    }

    /// Reads a `u64` HLC.
    pub(crate) fn hlc(&mut self) -> Result<Hlc, DecodeError> {
        let at = self.offset();
        Hlc::read(&mut self.reader).map_err(|e| e.shifted(at))
    }

    /// Reads a canonical version vector (ADR 0012 §3), with the error offset counted from the
    /// start of the input.
    pub(crate) fn vv(&mut self) -> Result<VersionVector, DecodeError> {
        let at = self.offset();
        VersionVector::read(&mut self.reader).map_err(|e| e.shifted(at))
    }

    /// Ends the structure: [`DecodeErrorKind::TrailingBytes`] at the first unread byte if any
    /// remains.
    pub(crate) fn finish(&self) -> Result<(), DecodeError> {
        if self.reader.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::new(
                DecodeErrorKind::TrailingBytes,
                self.offset(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    //! Offsets on success and on failure, and that a failed read does not move the cursor.

    use super::*;

    #[test]
    fn offsets_and_failed_reads() {
        let bytes = [0x01, 0x00, 0x02, 0xaa];
        let mut c = Cursor::new(&bytes);
        assert_eq!(c.u8(), Ok(0x01));
        assert_eq!(c.u16(), Ok(0x0002));
        assert_eq!(c.offset(), 3);
        let e = c.u32().unwrap_err();
        assert_eq!((e.kind(), e.offset()), (DecodeErrorKind::Truncated, 3));
        assert_eq!(c.remaining(), 1);
        let e = c.finish().unwrap_err();
        assert_eq!((e.kind(), e.offset()), (DecodeErrorKind::TrailingBytes, 3));
        assert_eq!(c.take(1), Ok([0xaa].as_slice()));
        assert_eq!(c.finish(), Ok(()));
        assert_eq!(c.u64().unwrap_err().offset(), 4);
        assert_eq!(c.array::<1>().unwrap_err().offset(), 4);
        assert_eq!(c.hlc().unwrap_err().offset(), 4);
    }

    #[test]
    fn nested_errors_count_from_the_input() {
        // Two bytes of padding, then a dot with seq 0: the error names byte 2 + 16.
        let mut bytes = vec![0xee, 0xee];
        bytes.extend_from_slice(&[7; 16]);
        bytes.extend_from_slice(&[0; 8]);
        let mut c = Cursor::new(&bytes);
        c.u16().unwrap();
        let e = c.dot().unwrap_err();
        assert_eq!((e.kind(), e.offset()), (DecodeErrorKind::ZeroSeq, 18));
        assert_eq!(c.offset(), 2);
        // A version vector whose count cannot fit: Truncated at the count.
        let mut c = Cursor::new(&[0xee, 0x00, 0x01]);
        c.u8().unwrap();
        let e = c.vv().unwrap_err();
        assert_eq!((e.kind(), e.offset()), (DecodeErrorKind::Truncated, 1));
    }
}
