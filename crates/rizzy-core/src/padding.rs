//! Plaintext framing and Padmé padding (CRYPTO.md §8.5).
//!
//! ```text
//! frame      = u32(data_len) ‖ data ‖ zero bytes up to padded_len
//! padded_len = max(256, Padmé(4 + data_len))
//! ```
//!
//! Used for the plaintexts of `ITEM_OP`, `ITEM_SNAPSHOT`, `SHARE_SNAPSHOT`, `RELAY_BATCH`,
//! `PAIRING_TRANSFER_SEALED`, `RESYNC_TRANSFER` and `MAIL_MESSAGE`. The envelope applies it
//! itself for those purposes ([`crate::envelope::PlaintextRule::Padded`]), so callers never
//! frame by hand.
//!
//! Padmé (Nikitin et al., PETS 2019) rounds a length `L` up so that only its top
//! `⌊log2 ⌊log2 L⌋⌋ + 1` bits may be non-zero. It leaks `O(log log L)` bits of the length for
//! at most about 12 % overhead.
//!
//! **Reader strictness.** CRYPTO.md §8.5 requires rejecting `data_len > len − 4` and any
//! non-zero padding byte. This reader also rejects a frame whose total length is not exactly
//! `padded_len(data_len)`: the layout above defines that length, so any other length is not a
//! frame a conforming writer produces. That makes the encoding canonical (one frame per `data`).

use crate::encoding::{Reader, put_u32};
use crate::error::{EncodeError, ParseError};
use crate::secret::SecretBytes;

/// Smallest padded frame, in bytes.
pub const MIN_PADDED_LEN: usize = 256;

/// Length of the `u32(data_len)` prefix.
pub const LEN_PREFIX: usize = 4;

/// Padmé(`len`): the padded length for a message of `len` bytes.
///
/// ```text
/// E = ⌊log2 L⌋,  S = ⌊log2 E⌋ + 1,  mask = 2^(E − S) − 1,  Padmé(L) = (L + mask) & !mask
/// ```
///
/// Lengths 0 and 1 are returned unchanged (the formula needs `L ≥ 2`; framing never asks for
/// less than 4). Returns `None` only if the result would overflow `u64`.
#[must_use]
pub const fn padme(len: u64) -> Option<u64> {
    if len < 2 {
        return Some(len);
    }
    let e = u64::BITS - 1 - len.leading_zeros(); // ⌊log2 L⌋ ≥ 1
    let s = u32::BITS - e.leading_zeros(); // ⌊log2 E⌋ + 1, and S ≤ E for E ≥ 1
    let last_bits = e - s;
    let mask = (1u64 << last_bits) - 1;
    match len.checked_add(mask) {
        Some(sum) => Some(sum & !mask),
        None => None,
    }
}

/// `padded_len = max(256, Padmé(4 + data_len))` for `data_len` bytes of data.
///
/// # Errors
/// [`EncodeError::TooLong`] if `data_len` does not fit the `u32` prefix or the padded length
/// does not fit `usize`.
pub fn padded_len(data_len: usize) -> Result<usize, EncodeError> {
    let data_len = u32::try_from(data_len).map_err(|_| EncodeError::TooLong)?;
    let framed = u64::from(data_len) + 4; // + LEN_PREFIX
    let padded = padme(framed).ok_or(EncodeError::TooLong)?;
    let padded = usize::try_from(padded).map_err(|_| EncodeError::TooLong)?;
    Ok(padded.max(MIN_PADDED_LEN))
}

/// Frames `data` into a new zeroizing buffer of exactly `padded_len(data.len())` bytes.
///
/// # Errors
/// As [`padded_len`].
pub fn frame(data: &[u8]) -> Result<SecretBytes, EncodeError> {
    let total = padded_len(data.len())?;
    let mut out = Vec::with_capacity(total);
    write_frame(&mut out, data, total)?;
    Ok(SecretBytes::from_vec(out))
}

/// Appends the frame of `data`, padded to `total` bytes, to `out`. `total` must be
/// [`padded_len`]`(data.len())`. Reserve the space first: `out` must not reallocate while it
/// holds plaintext.
pub(crate) fn write_frame(out: &mut Vec<u8>, data: &[u8], total: usize) -> Result<(), EncodeError> {
    if padded_len(data.len())? != total {
        return Err(EncodeError::TooLong);
    }
    let data_len = u32::try_from(data.len()).map_err(|_| EncodeError::TooLong)?;
    let end = out.len().checked_add(total).ok_or(EncodeError::TooLong)?;
    put_u32(out, data_len);
    out.extend_from_slice(data);
    out.resize(end, 0);
    Ok(())
}

/// Reads a frame strictly and returns `data`, borrowed from `frame`.
///
/// # Errors
/// - [`ParseError::Truncated`]: shorter than the prefix, or `data_len > len − 4`;
/// - [`ParseError::InvalidLength`]: the frame is not exactly `padded_len(data_len)` bytes;
/// - [`ParseError::NonZeroPadding`]: a padding byte is not zero.
///
/// Every padding byte is examined, with no early exit.
pub fn unframe(frame: &[u8]) -> Result<&[u8], ParseError> {
    let mut r = Reader::new(frame);
    let data_len = usize::try_from(r.u32()?).map_err(|_| ParseError::TooLong)?;
    let data = r.take(data_len)?;
    let padding = r.rest();
    if padded_len(data_len).map_err(|_| ParseError::TooLong)? != frame.len() {
        return Err(ParseError::InvalidLength);
    }
    if padding.iter().fold(0u8, |acc, b| acc | b) != 0 {
        return Err(ParseError::NonZeroPadding);
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Known values, worked by hand from the formula (E, S, mask in the comments).
    #[test]
    fn padme_known_values() {
        let cases: [(u64, u64); 15] = [
            (2, 2),                   // E=1 S=1 mask=0
            (3, 3),                   // E=1 S=1 mask=0
            (4, 4),                   // E=2 S=2 mask=0
            (9, 10),                  // E=3 S=2 mask=1
            (33, 36),                 // E=5 S=3 mask=3
            (129, 144),               // E=7 S=3 mask=15
            (256, 256),               // E=8 S=4 mask=15
            (257, 272),               // E=8 S=4 mask=15
            (260, 272),               // E=8 S=4 mask=15
            (1000, 1024),             // E=9 S=4 mask=31
            (1025, 1088),             // E=10 S=4 mask=63
            (10_000, 10_240),         // E=13 S=4 mask=511
            (65_537, 67_584),         // E=16 S=5 mask=2047
            (16_777_216, 16_777_216), // E=24 S=5 mask=524287
            (16_777_217, 17_301_504), // E=24 S=5 mask=524287
        ];
        for (len, padded) in cases {
            assert_eq!(padme(len), Some(padded), "Padmé({len})");
        }
        // E=63 S=6 mask=2^57-1: rounding up overflows u64.
        assert_eq!(padme(u64::MAX), None);
        assert_eq!(padme(0), Some(0));
        assert_eq!(padme(1), Some(1));
    }

    #[test]
    fn padded_len_known_values() {
        assert_eq!(padded_len(0).unwrap(), 256);
        assert_eq!(padded_len(252).unwrap(), 256);
        assert_eq!(padded_len(253).unwrap(), 272); // 4 + 253 = 257 → 272
        assert_eq!(padded_len(996).unwrap(), 1024);
        assert_eq!(padded_len(1021).unwrap(), 1088);
        assert_eq!(padded_len(16 * 1024 * 1024 - 4).unwrap(), 16 * 1024 * 1024);
    }

    #[test]
    fn frame_layout() {
        let f = frame(b"hello").unwrap();
        let bytes = f.expose_secret();
        assert_eq!(bytes.len(), 256);
        assert_eq!(&bytes[..9], b"\x00\x00\x00\x05hello");
        assert!(bytes[9..].iter().all(|b| *b == 0));
        assert_eq!(unframe(bytes).unwrap(), b"hello");
    }

    #[test]
    fn unframe_rejects_malformed_frames() {
        let good = frame(b"abc").unwrap();
        let good = good.expose_secret();

        // data_len > len - 4
        let mut long = good.to_vec();
        long[..4].copy_from_slice(&253u32.to_be_bytes());
        assert_eq!(unframe(&long), Err(ParseError::Truncated));
        // non-zero padding byte anywhere in the padding
        for i in 7..good.len() {
            let mut bad = good.to_vec();
            bad[i] = 1;
            assert_eq!(unframe(&bad), Err(ParseError::NonZeroPadding), "byte {i}");
        }
        // wrong total length (too short, too long)
        assert_eq!(unframe(&good[..255]), Err(ParseError::InvalidLength));
        let mut longer = good.to_vec();
        longer.push(0);
        assert_eq!(unframe(&longer), Err(ParseError::InvalidLength));
        // truncation at every length never panics
        for n in 0..good.len() {
            assert!(unframe(&good[..n]).is_err(), "prefix {n}");
        }
    }

    proptest! {
        #[test]
        fn frame_round_trips(data in proptest::collection::vec(any::<u8>(), 0..3000)) {
            let f = frame(&data).unwrap();
            prop_assert_eq!(f.len(), padded_len(data.len()).unwrap());
            prop_assert_eq!(unframe(f.expose_secret()).unwrap(), data.as_slice());
        }

        #[test]
        fn padme_properties(len in 2u64..(1u64 << 40)) {
            let p = padme(len).unwrap();
            prop_assert!(p >= len);
            // At most 12 % overhead (the bound is 2^-S ≤ 1/8 minus rounding; CRYPTO.md §8.5).
            prop_assert!((p - len) * 100 <= len * 12);
            // Idempotent and monotone.
            prop_assert_eq!(padme(p), Some(p));
            prop_assert!(padme(len + 1).unwrap() >= p);
        }

        #[test]
        fn unframe_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
            let _ = unframe(&bytes);
        }
    }
}
