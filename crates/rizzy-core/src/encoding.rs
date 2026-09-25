//! Canonical binary encoding (CRYPTO.md §2) and base64url transport encoding (§9.6).
//!
//! - `u8`, `u16`, `u32` and `u64` are unsigned, big-endian, fixed width.
//! - `bytes(x)` is `u32(len(x)) ‖ x`; `str(x)` is `bytes(UTF-8(x))`.
//! - Anything signed or used as AAD uses these fixed layouts, never a serde encoding.
//!
//! The writers append to a caller-owned `Vec<u8>`. Size the vector with its final capacity
//! when it will hold a secret, because a reallocation leaves the old copy behind (§12.2).
//!
//! [`Reader`] is the bounded reader for untrusted input: it never panics, never copies, and
//! never allocates, so a hostile length field cannot make it reserve memory.

use base64ct::{Base64UrlUnpadded, Encoding as _};

use crate::error::{EncodeError, ParseError};

/// Appends `u8(v)`.
pub fn put_u8(out: &mut Vec<u8>, v: u8) {
    out.push(v);
}

/// Appends `u16(v)`, big-endian.
pub fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Appends `u32(v)`, big-endian.
pub fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Appends `u64(v)`, big-endian.
pub fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Appends `bytes(x) = u32(len(x)) ‖ x`.
///
/// # Errors
/// [`EncodeError::TooLong`] if `x` is longer than `u32::MAX` bytes. Nothing is appended then.
pub fn put_bytes(out: &mut Vec<u8>, x: &[u8]) -> Result<(), EncodeError> {
    let len = u32::try_from(x.len()).map_err(|_| EncodeError::TooLong)?;
    put_u32(out, len);
    out.extend_from_slice(x);
    Ok(())
}

/// Appends `str(s) = bytes(UTF-8(s))`.
///
/// # Errors
/// [`EncodeError::TooLong`] if `s` is longer than `u32::MAX` bytes. Nothing is appended then.
pub fn put_str(out: &mut Vec<u8>, s: &str) -> Result<(), EncodeError> {
    put_bytes(out, s.as_bytes())
}

/// The encoded length of `bytes(x)` for an `x` of `len` bytes, for sizing buffers.
///
/// # Errors
/// [`EncodeError::TooLong`] if `len` does not fit the `u32` prefix or the sum overflows.
pub fn bytes_encoded_len(len: usize) -> Result<usize, EncodeError> {
    u32::try_from(len).map_err(|_| EncodeError::TooLong)?;
    len.checked_add(4).ok_or(EncodeError::TooLong)
}

/// A bounded reader over untrusted bytes.
///
/// Every method checks the remaining length before it reads and returns
/// [`ParseError::Truncated`] instead of panicking. Slices are borrowed from the input, so a
/// length field can never cause an allocation. Call [`Reader::finish`] at the end of a
/// structure to reject trailing bytes.
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    input: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Starts reading `input` from its first byte.
    #[must_use]
    pub const fn new(input: &'a [u8]) -> Self {
        Self { input }
    }

    /// Number of bytes not read yet.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.input.len()
    }

    /// `true` when every byte has been read.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.input.is_empty()
    }

    /// Reads the next `n` bytes.
    ///
    /// # Errors
    /// [`ParseError::Truncated`] if fewer than `n` bytes remain. The reader is unchanged then.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        let (head, tail) = self
            .input
            .split_at_checked(n)
            .ok_or(ParseError::Truncated)?;
        self.input = tail;
        Ok(head)
    }

    /// Reads the next `N` bytes as a fixed-size array reference.
    ///
    /// # Errors
    /// [`ParseError::Truncated`] if fewer than `N` bytes remain.
    pub fn array<const N: usize>(&mut self) -> Result<&'a [u8; N], ParseError> {
        let (head, tail) = self
            .input
            .split_first_chunk::<N>()
            .ok_or(ParseError::Truncated)?;
        self.input = tail;
        Ok(head)
    }

    /// Reads a `u8`.
    ///
    /// # Errors
    /// [`ParseError::Truncated`] if no byte remains.
    pub fn u8(&mut self) -> Result<u8, ParseError> {
        Ok(u8::from_be_bytes(*self.array::<1>()?))
    }

    /// Reads a big-endian `u16`.
    ///
    /// # Errors
    /// [`ParseError::Truncated`] if fewer than 2 bytes remain.
    pub fn u16(&mut self) -> Result<u16, ParseError> {
        Ok(u16::from_be_bytes(*self.array::<2>()?))
    }

    /// Reads a big-endian `u32`.
    ///
    /// # Errors
    /// [`ParseError::Truncated`] if fewer than 4 bytes remain.
    pub fn u32(&mut self) -> Result<u32, ParseError> {
        Ok(u32::from_be_bytes(*self.array::<4>()?))
    }

    /// Reads a big-endian `u64`.
    ///
    /// # Errors
    /// [`ParseError::Truncated`] if fewer than 8 bytes remain.
    pub fn u64(&mut self) -> Result<u64, ParseError> {
        Ok(u64::from_be_bytes(*self.array::<8>()?))
    }

    /// Reads `bytes(x)` and returns `x`, borrowed from the input.
    ///
    /// The length field is checked against the remaining input before anything else, so a
    /// hostile length costs nothing.
    ///
    /// # Errors
    /// [`ParseError::Truncated`] if the prefix or the value is incomplete. The reader is
    /// unchanged then.
    pub fn bytes(&mut self) -> Result<&'a [u8], ParseError> {
        self.bytes_max(usize::MAX)
    }

    /// Reads `bytes(x)` and rejects values longer than `max` bytes.
    ///
    /// # Errors
    /// [`ParseError::TooLong`] if the length field exceeds `max`, and
    /// [`ParseError::Truncated`] if the prefix or the value is incomplete. The reader is
    /// unchanged on error.
    pub fn bytes_max(&mut self, max: usize) -> Result<&'a [u8], ParseError> {
        let mut probe = self.clone();
        let len = usize::try_from(probe.u32()?).map_err(|_| ParseError::TooLong)?;
        if len > max {
            return Err(ParseError::TooLong);
        }
        let value = probe.take(len)?;
        *self = probe;
        Ok(value)
    }

    /// Reads `str(x)` and returns `x`, borrowed from the input.
    ///
    /// # Errors
    /// As [`Reader::bytes`], plus [`ParseError::InvalidUtf8`]. The reader is unchanged on error.
    pub fn str(&mut self) -> Result<&'a str, ParseError> {
        let mut probe = self.clone();
        let text = core::str::from_utf8(probe.bytes()?).map_err(|_| ParseError::InvalidUtf8)?;
        *self = probe;
        Ok(text)
    }

    /// Returns every remaining byte and leaves the reader empty.
    pub fn rest(&mut self) -> &'a [u8] {
        core::mem::take(&mut self.input)
    }

    /// Ends the structure.
    ///
    /// # Errors
    /// [`ParseError::TrailingBytes`] if any byte remains.
    pub fn finish(self) -> Result<(), ParseError> {
        if self.input.is_empty() {
            Ok(())
        } else {
            Err(ParseError::TrailingBytes)
        }
    }
}

/// Encodes `bytes` as base64url without padding (RFC 4648 §5), for JSON APIs and files
/// (CRYPTO.md §9.6). Constant-time in the data (`base64ct`).
#[must_use]
pub fn b64url_encode(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// Decodes base64url without padding.
///
/// Strict: padding characters, characters outside the URL-safe alphabet, an impossible length
/// and non-zero trailing bits are all rejected, so every byte string has exactly one accepted
/// encoding. The output is sized from the input length, never from anything inside it.
///
/// # Errors
/// [`ParseError::InvalidEncoding`].
pub fn b64url_decode(text: &str) -> Result<Vec<u8>, ParseError> {
    Base64UrlUnpadded::decode_vec(text).map_err(|_| ParseError::InvalidEncoding)
}

/// Decodes base64url without padding into `out`, which must be at least as long as the
/// decoded value, and returns the decoded prefix of `out`.
///
/// Use this for secrets: decode into a zeroizing buffer of the right size.
///
/// # Errors
/// [`ParseError::InvalidEncoding`] for malformed input, [`ParseError::TooLong`] if `out` is too
/// short.
pub fn b64url_decode_into<'o>(text: &str, out: &'o mut [u8]) -> Result<&'o [u8], ParseError> {
    Base64UrlUnpadded::decode(text, out).map_err(|e| match e {
        base64ct::Error::InvalidLength => ParseError::TooLong,
        base64ct::Error::InvalidEncoding => ParseError::InvalidEncoding,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_are_big_endian_fixed_width() {
        let mut out = Vec::new();
        put_u8(&mut out, 0x01);
        put_u16(&mut out, 0x0203);
        put_u32(&mut out, 0x0405_0607);
        put_u64(&mut out, 0x0809_0a0b_0c0d_0e0f);
        assert_eq!(out, (1u8..=15).collect::<Vec<_>>());

        let mut r = Reader::new(&out);
        assert_eq!(r.u8().unwrap(), 0x01);
        assert_eq!(r.u16().unwrap(), 0x0203);
        assert_eq!(r.u32().unwrap(), 0x0405_0607);
        assert_eq!(r.u64().unwrap(), 0x0809_0a0b_0c0d_0e0f);
        r.finish().unwrap();
    }

    #[test]
    fn bytes_and_str_are_length_prefixed() {
        let mut out = Vec::new();
        put_bytes(&mut out, b"ab").unwrap();
        put_str(&mut out, "é").unwrap();
        put_bytes(&mut out, b"").unwrap();
        assert_eq!(
            out,
            [0, 0, 0, 2, b'a', b'b', 0, 0, 0, 2, 0xc3, 0xa9, 0, 0, 0, 0]
        );
        assert_eq!(bytes_encoded_len(2).unwrap(), 6);

        let mut r = Reader::new(&out);
        assert_eq!(r.bytes().unwrap(), b"ab");
        assert_eq!(r.str().unwrap(), "é");
        assert_eq!(r.bytes().unwrap(), b"");
        assert!(r.is_empty());
    }

    #[test]
    fn reader_rejects_truncation_without_moving() {
        let input = [0u8, 0, 0, 5, 1, 2];
        let mut r = Reader::new(&input);
        assert_eq!(r.bytes(), Err(ParseError::Truncated));
        assert_eq!(r.remaining(), 6);
        assert_eq!(r.u64(), Err(ParseError::Truncated));
        assert_eq!(r.take(7), Err(ParseError::Truncated));
        assert_eq!(r.remaining(), 6);
        assert_eq!(r.clone().finish(), Err(ParseError::TrailingBytes));
        assert_eq!(r.rest(), &input);
        r.finish().unwrap();
    }

    #[test]
    fn reader_survives_hostile_length_fields() {
        // A 4 GiB length field over a 4-byte input: rejected, no allocation, no panic.
        let input = [0xff, 0xff, 0xff, 0xff];
        let mut r = Reader::new(&input);
        assert_eq!(r.bytes(), Err(ParseError::Truncated));
        let mut r = Reader::new(&[0, 0, 0, 3, b'a', b'b', b'c']);
        assert_eq!(r.bytes_max(2), Err(ParseError::TooLong));
        assert_eq!(r.bytes_max(3).unwrap(), b"abc");
    }

    #[test]
    fn reader_rejects_invalid_utf8() {
        let mut r = Reader::new(&[0, 0, 0, 1, 0xff]);
        assert_eq!(r.str(), Err(ParseError::InvalidUtf8));
        assert_eq!(r.remaining(), 5);
    }

    #[test]
    fn every_prefix_of_a_structure_is_rejected_without_panic() {
        let mut out = Vec::new();
        put_u16(&mut out, 7);
        put_bytes(&mut out, b"hello").unwrap();
        put_u64(&mut out, 9);
        for n in 0..out.len() {
            let mut r = Reader::new(&out[..n]);
            let parsed = (|| {
                r.u16()?;
                r.bytes()?;
                r.u64()?;
                Ok::<_, ParseError>(())
            })();
            assert_eq!(parsed, Err(ParseError::Truncated), "prefix {n}");
        }
    }

    #[test]
    fn base64url_round_trips_without_padding() {
        // RFC 4648 §10 test vectors, URL-safe alphabet, padding removed.
        let cases: [(&[u8], &str); 7] = [
            (b"", ""),
            (b"f", "Zg"),
            (b"fo", "Zm8"),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg"),
            (b"fooba", "Zm9vYmE"),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (raw, text) in cases {
            assert_eq!(b64url_encode(raw), text);
            assert_eq!(b64url_decode(text).unwrap(), raw);
        }
        // The URL-safe alphabet uses '-' and '_'.
        assert_eq!(b64url_encode(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn base64url_is_strict() {
        for bad in ["Zg==", "Zg=", "Z", "Zh", "+/8", "Zm9v YmFy", "Zm9v\n"] {
            assert_eq!(
                b64url_decode(bad),
                Err(ParseError::InvalidEncoding),
                "{bad:?}"
            );
        }
        let mut buf = [0u8; 2];
        assert_eq!(
            b64url_decode_into("Zm9v", &mut buf),
            Err(ParseError::TooLong)
        );
        let mut buf = [0u8; 3];
        assert_eq!(b64url_decode_into("Zm9v", &mut buf).unwrap(), b"foo");
    }
}
