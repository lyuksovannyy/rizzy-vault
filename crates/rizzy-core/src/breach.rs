// SPDX-License-Identifier: AGPL-3.0-only

//! The breach-check digest (CRYPTO.md §11.16; [ADR 0053] item 1).
//!
//! A lookup against an externally specified range API (Have I Been Pwned's k-anonymity
//! "range" search), not a construction of ours: SHA-1 appears here only because that API fixes
//! it (CRYPTO.md §3, the `sha1` row).
//!
//! ```text
//! digest = SHA-1(UTF-8(NFC(password)))           20 bytes
//! hex    = uppercase hex of digest                40 characters, 0-9 A-F
//! prefix = hex[0 .. 5]                            sent to the `icons` role (20 bits)
//! suffix = hex[5 .. 40]                           never leaves the client (35 characters)
//! ```
//!
//! The client compares every suffix of the returned range with its own suffix using
//! `ct_eq`, scanning the whole list without an early exit ([`BreachDigest::count_in`]).
//!
//! # Rules
//!
//! - **Only the prefix leaves the client.** [`BreachDigest::prefix`] is the one accessor that
//!   returns digest-derived bytes as plain data. The full hex digest stays in a wiped heap
//!   buffer ([`SecretArray`]); `Debug` prints `[REDACTED]`.
//! - **No secret-indexed lookup.** The hex encoding uses branch-free arithmetic (no table), as
//!   CRYPTO.md §12.3 requires of secret-derived encodings.
//! - **NFC, no further normalisation.** The password is NFC-normalised exactly as the master
//!   password is ([`crate::kdf`], CRYPTO.md §2), with no trimming or case folding. Unlike a
//!   new master password, a candidate with an unassigned code point is not refused: the check
//!   reads an existing item password, it does not set one.
//!
//! [ADR 0053]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0053-hibp-breach-check-egress.md

use core::fmt;

use sha1::{Digest as _, Sha1};
use subtle::{Choice, ConditionallySelectable as _, ConstantTimeEq as _};
use zeroize::{Zeroize as _, Zeroizing};

use crate::error::KdfError;
use crate::kdf;
use crate::secret::SecretArray;

/// Characters of the uppercase hex digest (SHA-1, 20 bytes).
pub const DIGEST_HEX_LEN: usize = 40;

/// Characters of the prefix the client sends (20 bits; ADR 0053 item 1).
pub const PREFIX_LEN: usize = 5;

/// Characters of the suffix the client keeps and compares (35).
pub const SUFFIX_LEN: usize = DIGEST_HEX_LEN - PREFIX_LEN;

/// The SHA-1 digest of a candidate password as 40 uppercase hex characters, wiped on drop.
pub struct BreachDigest {
    /// The uppercase hex digest, ASCII.
    hex: SecretArray<DIGEST_HEX_LEN>,
}

impl fmt::Debug for BreachDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BreachDigest([REDACTED])")
    }
}

impl BreachDigest {
    /// Computes `uppercase_hex(SHA-1(UTF-8(NFC(password))))`. The normalised bytes and the
    /// binary digest are wiped before this returns.
    ///
    /// # Errors
    /// [`KdfError::InvalidInput`] if the normalised length overflows `usize` (never for a
    /// string that fits in memory).
    pub fn of_password(password: &str) -> Result<Self, KdfError> {
        let normalized = Zeroizing::new(kdf::nfc_utf8(password)?);
        let mut hasher = Sha1::new();
        hasher.update(normalized.as_slice());
        let mut digest = hasher.finalize();
        let hex = SecretArray::try_init_with(|out: &mut [u8; DIGEST_HEX_LEN]| {
            if digest.len() * 2 != DIGEST_HEX_LEN {
                return Err(KdfError::Internal);
            }
            for (pair, byte) in out.chunks_exact_mut(2).zip(digest.iter()) {
                if let [high, low] = pair {
                    *high = upper_hex_digit(byte >> 4);
                    *low = upper_hex_digit(*byte);
                }
            }
            Ok(())
        });
        digest.as_mut_slice().zeroize();
        Ok(Self { hex: hex? })
    }

    /// The first [`PREFIX_LEN`] characters: the only part of the digest that leaves the
    /// client.
    #[must_use]
    pub fn prefix(&self) -> [u8; PREFIX_LEN] {
        let mut out = [0u8; PREFIX_LEN];
        for (o, h) in out.iter_mut().zip(self.hex.expose_secret().iter()) {
            *o = *h;
        }
        out
    }

    /// The whole hex digest. For known-answer vectors and tests; it is never sent, logged or
    /// formatted.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; DIGEST_HEX_LEN] {
        self.hex.expose_secret()
    }

    /// The last [`SUFFIX_LEN`] characters.
    fn suffix(&self) -> &[u8] {
        self.hex.expose_secret().get(PREFIX_LEN..).unwrap_or(&[])
    }

    /// Whether `candidate` equals this digest's suffix, in constant time over the 35 bytes. A
    /// candidate of another length never matches (its length is public).
    #[must_use]
    pub fn suffix_matches(&self, candidate: &[u8]) -> Choice {
        let suffix = self.suffix();
        if candidate.len() != SUFFIX_LEN || suffix.len() != SUFFIX_LEN {
            return Choice::from(0);
        }
        suffix.ct_eq(candidate)
    }

    /// The count of the entry whose suffix matches, scanning every entry with
    /// [`BreachDigest::suffix_matches`] and a constant-time select, without an early exit;
    /// `0` when no entry matches. A padded entry (count `0`, HIBP's `Add-Padding`) reads as
    /// no match either way. If several entries match (a malformed range), the last one wins.
    pub fn count_in<'a, I>(&self, entries: I) -> u64
    where
        I: IntoIterator<Item = (&'a [u8], u64)>,
    {
        let mut found = 0u64;
        for (candidate, count) in entries {
            found.conditional_assign(&count, self.suffix_matches(candidate));
        }
        found
    }
}

/// The uppercase hex digit of the low four bits of `nibble`, without a branch or table:
/// `'0' + n`, plus 7 (the distance from `'9' + 1` to `'A'`) when `n > 9`.
fn upper_hex_digit(nibble: u8) -> u8 {
    let n = i32::from(nibble & 0x0f);
    // `9 - n` is negative exactly when n > 9; the arithmetic shift turns that into all ones.
    let letter = (9 - n) >> 31;
    let [digit, ..] = (i32::from(b'0') + n + (letter & 0x07)).to_le_bytes();
    digit
}

#[cfg(test)]
mod tests {
    //! Unit checks; the normative known-answer vectors are `tests/vectors/breach.json`.

    use super::*;

    fn hex_of(password: &str) -> String {
        let digest = BreachDigest::of_password(password).unwrap();
        String::from_utf8(digest.expose_secret().to_vec()).unwrap()
    }

    #[test]
    fn upper_hex_digit_is_exact_for_every_nibble() {
        for n in 0u8..16 {
            assert_eq!(char::from(upper_hex_digit(n)).to_string(), format!("{n:X}"));
            // Only the low four bits count.
            assert_eq!(upper_hex_digit(n | 0xf0), upper_hex_digit(n));
        }
    }

    #[test]
    fn published_sha1_answers() {
        // FIPS 180 / RFC 3174 test strings, and HIBP's own documented example ("password").
        assert_eq!(hex_of(""), "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709");
        assert_eq!(hex_of("abc"), "A9993E364706816ABA3E25717850C26C9CD0D89D");
        assert_eq!(
            hex_of("password"),
            "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
        );
    }

    #[test]
    fn nfc_is_applied_and_nothing_else() {
        // U+00E9 and U+0065 U+0301 have one NFC form.
        assert_eq!(hex_of("caf\u{e9}"), hex_of("cafe\u{301}"));
        // No trimming, no case folding.
        assert_ne!(hex_of("password"), hex_of("password "));
        assert_ne!(hex_of("password"), hex_of("Password"));
    }

    #[test]
    fn prefix_and_suffix_split_the_digest() {
        let digest = BreachDigest::of_password("password").unwrap();
        assert_eq!(&digest.prefix(), b"5BAA6");
        assert_eq!(digest.suffix(), b"1E4C9B93F3F0682250B6CF8331B7EE68FD8");
        assert!(bool::from(
            digest.suffix_matches(b"1E4C9B93F3F0682250B6CF8331B7EE68FD8")
        ));
        assert!(!bool::from(
            digest.suffix_matches(b"1E4C9B93F3F0682250B6CF8331B7EE68FD9")
        ));
        // Lowercase is another string: ADR 0053 fixes uppercase.
        assert!(!bool::from(
            digest.suffix_matches(b"1e4c9b93f3f0682250b6cf8331b7ee68fd8")
        ));
        // Wrong lengths never match.
        assert!(!bool::from(digest.suffix_matches(b"")));
        assert!(!bool::from(
            digest.suffix_matches(b"1E4C9B93F3F0682250B6CF8331B7EE68FD")
        ));
        assert!(!bool::from(
            digest.suffix_matches(b"5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8")
        ));
    }

    #[test]
    fn count_in_scans_every_entry() {
        let digest = BreachDigest::of_password("password").unwrap();
        let entries: [(&[u8], u64); 3] = [
            (b"0018A45C4D1DEF81644B54AB7F969B88D65", 1),
            (b"1E4C9B93F3F0682250B6CF8331B7EE68FD8", 52_256_179),
            (b"1E4C9B93F3F0682250B6CF8331B7EE68FD9", 3),
        ];
        assert_eq!(digest.count_in(entries), 52_256_179);
        assert_eq!(digest.count_in(entries[..1].iter().copied()), 0);
        assert_eq!(digest.count_in(core::iter::empty()), 0);
        // A padded entry (count 0) is no match.
        assert_eq!(
            digest.count_in([(&b"1E4C9B93F3F0682250B6CF8331B7EE68FD8"[..], 0)]),
            0
        );
    }

    #[test]
    fn debug_is_redacted() {
        let digest = BreachDigest::of_password("password").unwrap();
        let text = format!("{digest:?}");
        assert_eq!(text, "BreachDigest([REDACTED])");
        assert!(!text.contains("5BAA6"));
    }
}
