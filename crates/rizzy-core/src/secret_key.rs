//! The Secret Key and the recovery code (CRYPTO.md §7, §11.9, §4.3 check labels, §12.3).
//!
//! Both are 16 bytes from the injected CSPRNG, generated on the client and never sent to the
//! server. Both use the same printable format, with different prefixes and check labels:
//!
//! ```text
//! Secret Key:     RV1-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
//! Recovery code: RVR1-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
//! ```
//!
//! - The 28 characters are Crockford Base32 (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`), grouped by
//!   fours.
//! - The first 26 characters encode the 128 secret bits, most significant bit first, followed by
//!   2 zero bits.
//! - The last 2 characters encode the check value: the top 10 bits of
//!   `SHA-256(LABEL("secret-key/check") ‖ 0x00 ‖ SK)` (or `LABEL("recovery-code/check")`). It is
//!   for typo detection only.
//! - Parsing is case-insensitive, maps `O`→`0` and `I`/`L`→`1`, and ignores dashes and spaces.
//!   The prefix is required, and the same mapping applies to it (`RVI-` reads as `RV1-`). A parse
//!   is rejected if the pad bits are non-zero or the check value does not match.
//!
//! **No secret-indexed lookups** (§12.3). The encoder and the decoder map between 5-bit values
//! and characters with branch-free arithmetic, never with a table indexed by secret bits, and the
//! check value is compared with `ct_eq`. What a parse reveals through its timing is only which
//! input positions are separators, which is formatting, not secret.
//!
//! # What the two codes are for
//!
//! - The **Secret Key** keys the OPAQUE password input `pw_in` (§5.2,
//!   [`crate::opaque::PasswordInput`]). Checking a master-password guess against server data
//!   therefore needs the Secret Key as well as the server's OPRF seed, so a leaked database
//!   plus secrets file gives nothing to brute-force (§5.5, threat model INV-2). It is mandatory
//!   for every account (ADR 0004 decision 6 and owner decision 1).
//! - The **recovery code** derives the recovery wrap key, which opens `E_rec`, and the
//!   recovery auth token, of which the server stores only `SHA-256(token)` (§4.3, §11.9).
//!
//! # Encoding, step by step
//!
//! 1. Read the 16 bytes as one 128-bit big-endian integer.
//! 2. Cut it into 25 five-bit symbols from the most significant end; the 26th symbol holds the
//!    last 3 bits followed by the 2 zero pad bits.
//! 3. Compute the 10-bit check value and split it into two symbols, high 5 bits first.
//! 4. Map each of the 28 symbols to its Crockford character by arithmetic, and write the prefix
//!    followed by the characters in dash-separated groups of four.
//!
//! Parsing reverses these steps. It first rejects input longer than [`MAX_INPUT_LEN`] bytes
//! without looking at it, skips separators, and checks the prefix. It then decodes every
//! remaining character, rejects an invalid character or a count other than 28, reassembles the
//! 128 bits, and rejects non-zero pad bits or a check value that does not match.
//!
//! # What the check value is not
//!
//! Ten bits catch typos: a single-character change or an adjacent transposition slips through
//! with probability at most about 2^-10. It is not an integrity or authenticity check. A
//! well-formed but wrong Secret Key surfaces as a failed login, and a wrong recovery code as a
//! failed recovery.
//!
//! This module only generates and encodes the codes. Where the Secret Key is kept (the
//! Emergency Kit, every enrolled device's state file, optionally the web vault's storage) and
//! what that costs are in §7 and §5.5; no client ever persists the recovery code (§11).

use core::fmt;

use rand_core::CryptoRng;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize as _, Zeroizing};

use crate::error::DerivationError;
use crate::keys::{RECOVERY_CODE_LEN, RecoveryAuthToken, RecoveryWrapKey};
use crate::labels::{self, Label};
use crate::secret::SecretArray;

/// Length of a Secret Key and of a recovery code, in bytes (CRYPTO.md §4.2).
pub const CODE_LEN: usize = 16;

/// Base32 characters after the prefix: 26 for the 130 data bits, 2 for the 10 check bits.
pub const SYMBOLS: usize = 28;

/// Longest input a parser looks at, in bytes. A formatted code is at most 39 bytes; this leaves
/// room for extra separators and spaces without letting a caller feed megabytes.
///
/// CRYPTO.md §7 fixes the limit: longer input is rejected without being parsed.
pub const MAX_INPUT_LEN: usize = 128;

/// Symbols that carry data: 25 whole symbols of secret bits, then one with the last 3 secret
/// bits and the 2 zero pad bits.
const DATA_SYMBOLS: usize = 26;
/// Characters per dash-separated group in the printable form.
const GROUP: usize = 4;

// Compile-time check: this module and `keys` agree on the recovery code's length.
const _: () = assert!(CODE_LEN == RECOVERY_CODE_LEN);

/// Why a typed Secret Key or recovery code was rejected. Carries no part of the input.
///
/// [`CodeParseError::NonZeroPadding`] and [`CodeParseError::CheckMismatch`] share one message,
/// "code is mistyped": both mean the characters are valid but the code is not.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CodeParseError {
    /// The input is longer than [`MAX_INPUT_LEN`] bytes.
    TooLong,
    /// The input does not start with the expected prefix (`RV1` or `RVR1`).
    WrongPrefix,
    /// A character is not Crockford Base32, a dash or a space.
    InvalidCharacter,
    /// The input does not have exactly 28 Base32 characters after the prefix.
    WrongLength,
    /// The 2 pad bits after the 128 secret bits are not zero.
    NonZeroPadding,
    /// The check characters do not match: most likely a typo.
    CheckMismatch,
}

impl fmt::Display for CodeParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLong => "input is too long",
            Self::WrongPrefix => "input does not start with the expected prefix",
            Self::InvalidCharacter => "input contains a character that cannot appear in a code",
            Self::WrongLength => "input has the wrong number of characters",
            Self::NonZeroPadding | Self::CheckMismatch => "code is mistyped",
        })
    }
}

impl core::error::Error for CodeParseError {}

/// The format parameters of one code kind.
#[derive(Clone, Copy)]
struct Kind {
    /// The prefix without its dash, as it reads after the O/I/L mapping.
    prefix: &'static str,
    /// The label of the check-value hash (CRYPTO.md §4.3). The two kinds use different
    /// labels, so the same 16 bytes get different check characters.
    check_label: Label,
}

/// The Secret Key format: prefix `RV1`, check label `secret-key/check` (CRYPTO.md §7).
const SECRET_KEY: Kind = Kind {
    prefix: "RV1",
    check_label: labels::SECRET_KEY_CHECK,
};

/// The recovery-code format: prefix `RVR1`, check label `recovery-code/check`
/// (CRYPTO.md §11.9).
const RECOVERY_CODE: Kind = Kind {
    prefix: "RVR1",
    check_label: labels::RECOVERY_CODE_CHECK,
};

/// The Secret Key (SK): 128 random bits mixed into the OPAQUE password input
/// ([`crate::opaque::PasswordInput`], CRYPTO.md §5.2) and printed on the Emergency Kit.
///
/// Generated on the client at signup, and again at an SK change or a recovery, and never sent
/// to the server (§7, §11.5, §11.9). A secret: wiped on drop, no `Clone`, `Debug` prints
/// `[REDACTED]`.
pub struct SecretKey {
    /// The 16 secret bytes, wiped on drop.
    bytes: SecretArray<CODE_LEN>,
}

/// The recovery code: 128 random bits from which the recovery wrap key and the recovery auth
/// token are derived (CRYPTO.md §4.3, §11.9). It exists only on the Emergency Kit.
///
/// Generated on the client and never persisted by a client (§11, "Secrets before commit");
/// the server sees only the auth token derived from it. A secret: wiped on drop, no `Clone`,
/// `Debug` prints `[REDACTED]`.
pub struct RecoveryCode {
    /// The 16 secret bytes, wiped on drop.
    bytes: SecretArray<CODE_LEN>,
}

/// Generates the shared API of [`SecretKey`] and [`RecoveryCode`] for one code kind:
/// generation, raw bytes, parsing, formatting, the last-group confirmation, `expose_secret`
/// and the redacted `Debug`. One definition keeps the two types identical except for their
/// [`Kind`] and their name.
macro_rules! code_type {
    ($name:ident, $kind:expr, $what:literal) => {
        impl $name {
            #[doc = concat!("Draws a new ", $what, " (16 bytes) from the injected CSPRNG.")]
            #[must_use]
            pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
                Self {
                    bytes: SecretArray::generate(rng),
                }
            }

            #[doc = concat!("Rebuilds a ", $what, " from its 16 raw bytes (device state).")]
            ///
            /// Only the Secret Key is kept in device state; no client persists a recovery code
            /// (CRYPTO.md §11). The bytes are copied; wiping `bytes` is the caller's job.
            ///
            /// # Errors
            /// [`crate::error::ParseError::InvalidLength`] unless `bytes` is 16 bytes long.
            pub fn from_slice(bytes: &[u8]) -> Result<Self, crate::error::ParseError> {
                Ok(Self {
                    bytes: SecretArray::from_slice(bytes)?,
                })
            }

            #[doc = concat!("Parses a typed ", $what, " (CRYPTO.md §7).")]
            ///
            /// Case-insensitive; `O` reads as `0` and `I` or `L` as `1`; ASCII dashes and
            /// spaces are ignored wherever they appear. The prefix is required. Input longer
            /// than [`MAX_INPUT_LEN`] bytes is rejected without being parsed. No error carries
            /// any part of the input.
            ///
            /// # Errors
            /// [`CodeParseError`].
            pub fn parse(input: &str) -> Result<Self, CodeParseError> {
                Ok(Self {
                    bytes: parse_code($kind, input)?,
                })
            }

            #[doc = concat!("The printable form of the ", $what, ", in a buffer wiped on drop.")]
            ///
            /// This is the Emergency Kit form, with its prefix and dash-separated groups of
            /// four. The types implement no `Display`, so this call is the only way to print
            /// the code.
            #[must_use]
            pub fn to_formatted(&self) -> Zeroizing<String> {
                format_code($kind, self.bytes.expose_secret())
            }

            /// Whether `typed` equals the last group of four characters of the printable form,
            /// compared in constant time after the same mapping as [`Self::parse`]. Signup asks
            /// the user to re-type it to confirm the Emergency Kit was saved (CRYPTO.md §7).
            #[must_use]
            pub fn matches_last_group(&self, typed: &str) -> bool {
                last_group_matches($kind, self.bytes.expose_secret(), typed)
            }

            /// The 16 raw bytes. Do not log, store or send them outside the uses §7 and §11.9
            /// describe.
            #[must_use]
            pub fn expose_secret(&self) -> &[u8; CODE_LEN] {
                self.bytes.expose_secret()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}

code_type!(SecretKey, SECRET_KEY, "Secret Key");
code_type!(RecoveryCode, RECOVERY_CODE, "recovery code");

impl RecoveryCode {
    /// The recovery wrap key, the key of `E_rec` (CRYPTO.md §4.3).
    ///
    /// # Errors
    /// [`DerivationError`] (unreachable).
    pub fn wrap_key(&self) -> Result<RecoveryWrapKey, DerivationError> {
        RecoveryWrapKey::derive(&self.bytes)
    }

    /// The recovery auth token the client sends to the server (CRYPTO.md §4.3, §11.9).
    ///
    /// The server stores only `SHA-256(token)` and compares in constant time. The token proves
    /// possession of the code but cannot open `E_rec`; only the wrap key can.
    ///
    /// # Errors
    /// [`DerivationError`] (unreachable).
    pub fn auth_token(&self) -> Result<RecoveryAuthToken, DerivationError> {
        RecoveryAuthToken::derive(&self.bytes)
    }
}

/// The 10-bit check value: the top 10 bits of `SHA-256(LABEL(check) ‖ 0x00 ‖ code)`.
///
/// Secret-derived, so callers compare it only with `ct_eq` (CRYPTO.md §12.3).
fn check_value(kind: Kind, code: &[u8; CODE_LEN]) -> u16 {
    let digest = Sha256::new()
        .chain_update(kind.check_label.as_bytes())
        .chain_update([0x00])
        .chain_update(code)
        .finalize();
    // All 8 bits of byte 0 and the top 2 bits of byte 1. A SHA-256 digest always has both
    // bytes, so the `unwrap_or` fallbacks are never taken.
    let (first, second) = (digest.first().copied(), digest.get(1).copied());
    (u16::from(first.unwrap_or(0)) << 2) | (u16::from(second.unwrap_or(0)) >> 6)
}

/// The 28 symbol values: 26 data symbols (128 bits, then 2 zero bits) and 2 check symbols.
/// Only public shift amounts are used.
///
/// The symbols are the code itself in another form, so they are returned in a buffer wiped on
/// drop, and the working copy of the 128 bits is wiped before returning.
fn symbols_of(kind: Kind, code: &[u8; CODE_LEN]) -> Zeroizing<[u8; SYMBOLS]> {
    let mut x = u128::from_be_bytes(*code);
    let mut out = Zeroizing::new([0u8; SYMBOLS]);
    let (data, check) = out.split_at_mut(DATA_SYMBOLS);
    for (i, symbol) in data.iter_mut().enumerate() {
        // Symbol i covers bits [5i, 5i + 5) of the 130-bit string; bits 128 and 129 are zero.
        let bits = if i + 1 < DATA_SYMBOLS {
            (x >> (123 - 5 * i)) & 0x1f
        } else {
            (x & 0b111) << 2
        };
        *symbol = u8::try_from(bits).unwrap_or(0);
    }
    // The 10-bit check value as two symbols, high 5 bits first. `check` always has exactly two
    // elements, and both values fit in 5 bits, so the fallbacks are never taken.
    let c = check_value(kind, code);
    if let [hi, lo] = check {
        *hi = u8::try_from(c >> 5).unwrap_or(0);
        *lo = u8::try_from(c & 0x1f).unwrap_or(0);
    }
    x.zeroize();
    out
}

/// The printable form of `code`: the prefix, then the 28 characters with a `-` before each
/// group of four (38 bytes for `RV1`, 39 for `RVR1`). Built in a wiped `String` allocated at
/// its final length, so it never reallocates.
fn format_code(kind: Kind, code: &[u8; CODE_LEN]) -> Zeroizing<String> {
    let symbols = symbols_of(kind, code);
    let len = kind.prefix.len() + SYMBOLS + SYMBOLS / GROUP;
    let mut out = Zeroizing::new(String::with_capacity(len));
    out.push_str(kind.prefix);
    for (i, value) in symbols.iter().enumerate() {
        if i % GROUP == 0 {
            out.push('-');
        }
        out.push(char::from(encode_symbol(*value)));
    }
    out
}

/// Whether `typed` is the last group of four characters of `code`'s printable form: two data
/// symbols and the two check symbols.
///
/// Separators are skipped and characters are decoded as in parsing (case, `O`, `I`, `L`).
/// Every character is decoded, with no early exit, and the four values are compared with
/// `ct_eq`. The result is `true` only if every character was valid, exactly four remained, the
/// input was at most [`MAX_INPUT_LEN`] bytes, and the values match.
fn last_group_matches(kind: Kind, code: &[u8; CODE_LEN], typed: &str) -> bool {
    let symbols = symbols_of(kind, code);
    let mut typed_values = Zeroizing::new([0u8; GROUP]);
    let mut count = 0usize;
    let mut valid = true;
    // At most `MAX_INPUT_LEN` bytes are read; a longer input fails the length test below.
    for b in typed.bytes().take(MAX_INPUT_LEN) {
        if is_separator(b) {
            continue;
        }
        let (value, ok) = decode_symbol(b);
        valid &= ok;
        // Only the first four values are kept; `count` keeps counting, so extra characters
        // make the count test fail.
        if let Some(slot) = typed_values.get_mut(count) {
            *slot = value;
        }
        count += 1;
    }
    // The last four of the 28 symbols; `SYMBOLS - GROUP` is in range, so the fallback (an
    // empty slice, which never matches) is never taken.
    let expected = symbols.get(SYMBOLS - GROUP..).unwrap_or_default();
    let equal: bool = typed_values.as_slice().ct_eq(expected).into();
    valid && count == GROUP && typed.len() <= MAX_INPUT_LEN && equal
}

/// Whether `b` is one of the two separators of CRYPTO.md §7: ASCII `-` (U+002D) or ASCII
/// space (U+0020). Unicode dashes, a no-break space, tabs and line breaks are not separators;
/// they are rejected as invalid characters.
fn is_separator(b: u8) -> bool {
    b == b'-' || b == b' '
}

/// Parses the printable form of one code kind into its 16 bytes (CRYPTO.md §7).
///
/// Steps: refuse over-long input unread; drop separators; match the prefix; decode every
/// remaining character without an early exit; check the character count; reassemble the 128
/// bits; compute the expected check value and compare it with `ct_eq`; only then report bad pad
/// bits or a check mismatch. The decoded symbols and the 128-bit working value are wiped.
///
/// # Errors
/// [`CodeParseError`], in this order of precedence: `TooLong`, `WrongPrefix`,
/// `InvalidCharacter`, `WrongLength`, `NonZeroPadding`, `CheckMismatch`.
fn parse_code(kind: Kind, input: &str) -> Result<SecretArray<CODE_LEN>, CodeParseError> {
    if input.len() > MAX_INPUT_LEN {
        return Err(CodeParseError::TooLong);
    }
    // Separators are formatting, not secret: skipping them branches only on their positions.
    let mut chars = input.bytes().filter(|b| !is_separator(*b));

    // The prefix, after the same case folding and O/I/L mapping as the payload. It is public.
    for expected in kind.prefix.bytes() {
        let got = chars.next().map(map_prefix_char);
        if got != Some(expected) {
            return Err(CodeParseError::WrongPrefix);
        }
    }

    // The payload: decode every character, keeping validity in a flag rather than returning
    // early, so the position of a bad character does not show in the timing. Only the first 28
    // values are stored; `count` keeps counting for the length check.
    let mut values = Zeroizing::new([0u8; SYMBOLS]);
    let mut count = 0usize;
    let mut all_valid = true;
    for b in chars {
        let (value, valid) = decode_symbol(b);
        all_valid &= valid;
        if let Some(slot) = values.get_mut(count) {
            *slot = value;
        }
        count += 1;
    }
    if !all_valid {
        return Err(CodeParseError::InvalidCharacter);
    }
    if count != SYMBOLS {
        return Err(CodeParseError::WrongLength);
    }

    // Reassemble the 128 bits from 25 whole symbols and the top 3 bits of the 26th.
    let mut x: u128 = 0;
    let (data, check) = values.split_at(DATA_SYMBOLS);
    for v in data.iter().take(DATA_SYMBOLS - 1) {
        x = (x << 5) | u128::from(*v);
    }
    let last = data.last().copied().unwrap_or(0);
    x = (x << 3) | u128::from(last >> 2);
    // The low 2 bits of the 26th symbol are the pad bits, which must be zero.
    let pad = last & 0b11;
    // `check` always has two elements (28 - 26), so the second arm is never taken.
    let typed_check = match check {
        [hi, lo] => (u16::from(*hi) << 5) | u16::from(*lo),
        _ => return Err(CodeParseError::WrongLength),
    };

    // Put the 16 bytes into their final wiped buffer, then wipe the working copy.
    let bytes = SecretArray::try_init_with(|out| {
        *out = x.to_be_bytes();
        Ok::<(), CodeParseError>(())
    })?;
    x.zeroize();
    // Both checks are computed before either result is acted on.
    let expected_check = check_value(kind, bytes.expose_secret());
    let check_ok: bool = typed_check.ct_eq(&expected_check).into();
    if pad != 0 {
        return Err(CodeParseError::NonZeroPadding);
    }
    if !check_ok {
        return Err(CodeParseError::CheckMismatch);
    }
    Ok(bytes)
}

/// The O/I/L mapping and case folding applied to the (public) prefix characters.
///
/// The prefix is not secret, so this uses an ordinary `match`; the payload goes through the
/// branch-free [`decode_symbol`] instead.
fn map_prefix_char(b: u8) -> u8 {
    match b.to_ascii_uppercase() {
        b'O' => b'0',
        b'I' | b'L' => b'1',
        other => other,
    }
}

/// `0xFF` if `lo <= x <= hi`, else `0x00`, without branches. Shared with the RFC 4648 Base32
/// code in [`crate::totp`].
pub(crate) fn in_range(x: u8, lo: u8, hi: u8) -> u8 {
    let x = i16::from(x);
    let below = i16::from(lo) - 1 - x; // negative iff x >= lo
    let above = x - i16::from(hi) - 1; // negative iff x <= hi
    // Both negative iff in range. Values are in -256..=255, so `>> 8` gives -1 or 0, whose low
    // byte is 0xFF or 0x00.
    let [mask, _] = ((below & above) >> 8).to_le_bytes();
    mask
}

/// Maps a 5-bit value to its Crockford Base32 character with arithmetic only:
/// `'0' + v`, shifted past `:`–`@` (7 characters) and past the skipped letters I, L, O and U.
fn encode_symbol(v: u8) -> u8 {
    let v = v & 0x1f;
    let mut c = b'0'.wrapping_add(v);
    c = c.wrapping_add(in_range(v, 10, 31) & 0x07); // skip ':' ..= '@'
    c = c.wrapping_add(in_range(v, 18, 31) & 1); // skip I
    c = c.wrapping_add(in_range(v, 20, 31) & 1); // skip L
    c = c.wrapping_add(in_range(v, 22, 31) & 1); // skip O
    c = c.wrapping_add(in_range(v, 27, 31) & 1); // skip U
    c
}

/// Maps a character to its 5-bit value with arithmetic only. Lowercase letters fold to
/// uppercase, `O` reads as `0`, `I` and `L` read as `1`. Returns `(value, valid)`; the value is
/// 0 for an invalid character.
fn decode_symbol(b: u8) -> (u8, bool) {
    // Fold lowercase to uppercase: clear bit 5 for 'a'..='z' only.
    let c = b ^ (in_range(b, b'a', b'z') & 0x20);
    let digit = in_range(c, b'0', b'9');
    let a_h = in_range(c, b'A', b'H');
    let j_k = in_range(c, b'J', b'K');
    let m_n = in_range(c, b'M', b'N');
    let p_t = in_range(c, b'P', b'T');
    let v_z = in_range(c, b'V', b'Z');
    let o = in_range(c, b'O', b'O');
    let i_l = in_range(c, b'I', b'I') | in_range(c, b'L', b'L');
    // Each mask is 0xFF for its range and 0x00 otherwise, and at most one is set, so OR-ing the
    // masked offsets selects the value without a branch. `O` adds nothing (value 0) and `I`/`L`
    // add 1; an invalid character leaves every mask clear and gives 0.
    let value = (digit & c.wrapping_sub(b'0'))
        | (a_h & c.wrapping_sub(b'A').wrapping_add(10))
        | (j_k & c.wrapping_sub(b'J').wrapping_add(18))
        | (m_n & c.wrapping_sub(b'M').wrapping_add(20))
        | (p_t & c.wrapping_sub(b'P').wrapping_add(22))
        | (v_z & c.wrapping_sub(b'V').wrapping_add(27))
        | (i_l & 1);
    let valid = digit | a_h | j_k | m_n | p_t | v_z | o | i_l;
    (value, valid != 0)
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code indexes fixtures at known offsets; a panic there fails the test, which CLAUDE.md allows"
)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::test_util::seeded_rng;

    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    #[test]
    fn arithmetic_mapping_matches_the_crockford_alphabet() {
        for (v, c) in ALPHABET.iter().enumerate() {
            let v = u8::try_from(v).unwrap();
            assert_eq!(encode_symbol(v), *c);
            assert_eq!(decode_symbol(*c), (v, true));
            assert_eq!(decode_symbol(c.to_ascii_lowercase()), (v, true));
        }
        for (alias, v) in [
            (b'O', 0),
            (b'o', 0),
            (b'I', 1),
            (b'i', 1),
            (b'L', 1),
            (b'l', 1),
        ] {
            assert_eq!(decode_symbol(alias), (v, true), "{}", char::from(alias));
        }
        for b in 0..=255u8 {
            let expected_valid = ALPHABET.contains(&b.to_ascii_uppercase())
                || b"OIL".contains(&b.to_ascii_uppercase());
            assert_eq!(decode_symbol(b).1, expected_valid, "{b:#04x}");
            if !expected_valid {
                assert_eq!(decode_symbol(b).0, 0);
            }
        }
        for (x, lo, hi, want) in [
            (5, 5, 5, 0xff),
            (4, 5, 9, 0),
            (10, 5, 9, 0),
            (0, 0, 255, 0xff),
        ] {
            assert_eq!(in_range(x, lo, hi), want);
        }
    }

    #[test]
    fn known_answer_format() {
        // Independent: a Python implementation written from CRYPTO.md §7 (bits as a 130-bit
        // string, the Crockford alphabet as a lookup table, hashlib SHA-256 for the check).
        let sk = SecretKey::from_slice(&(0u8..16).collect::<Vec<_>>()).unwrap();
        assert_eq!(
            sk.to_formatted().as_str(),
            "RV1-000G-40R4-0M30-E209-185G-R38E-1W28"
        );
        let rc = RecoveryCode::from_slice(&(16u8..32).collect::<Vec<_>>()).unwrap();
        assert_eq!(
            rc.to_formatted().as_str(),
            "RVR1-208H-44RM-2MB1-E60S-38DH-R78Y-3WQP"
        );
        // 128 one bits: 25 × 'Z', then '111' + the two zero pad bits = 0b11100 = 'W'.
        let ones = SecretKey::from_slice(&[0xff; 16]).unwrap();
        assert_eq!(
            ones.to_formatted().as_str(),
            "RV1-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZW8C"
        );
        for (text, bytes) in [
            ("RV1-000G-40R4-0M30-E209-185G-R38E-1W28", sk.expose_secret()),
            ("rv1 000g 40r4 om3o e2o9 l85g r38e iw28", sk.expose_secret()),
            (
                "RV1-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZW8C",
                ones.expose_secret(),
            ),
        ] {
            assert_eq!(SecretKey::parse(text).unwrap().expose_secret(), bytes);
        }
        assert_eq!(
            RecoveryCode::parse("RVR1-208H-44RM-2MB1-E60S-38DH-R78Y-3WQP")
                .unwrap()
                .expose_secret(),
            rc.expose_secret()
        );
        assert_eq!(ones.to_formatted().len(), 38);
        assert_eq!(rc.to_formatted().len(), 39);
    }

    #[test]
    fn bit_layout_is_msb_first() {
        // A single set bit at position k lands in symbol k / 5.
        for k in 0..128usize {
            let mut code = [0u8; 16];
            code[k / 8] = 0x80 >> (k % 8);
            let symbols = symbols_of(SECRET_KEY, &code);
            for (i, s) in symbols[..DATA_SYMBOLS].iter().enumerate() {
                let expected = if i == k / 5 { 0x10 >> (k % 5) } else { 0 };
                assert_eq!(*s, expected, "bit {k} symbol {i}");
            }
        }
    }

    #[test]
    fn round_trips() {
        let mut rng = seeded_rng(3);
        for _ in 0..200 {
            let sk = SecretKey::generate(&mut rng);
            let text = sk.to_formatted();
            let back = SecretKey::parse(&text).unwrap();
            assert_eq!(back.expose_secret(), sk.expose_secret());

            let rc = RecoveryCode::generate(&mut rng);
            let back = RecoveryCode::parse(&rc.to_formatted()).unwrap();
            assert_eq!(back.expose_secret(), rc.expose_secret());
        }
    }

    #[test]
    fn parsing_is_lenient_about_case_separators_and_look_alikes() {
        let sk = SecretKey::generate(&mut seeded_rng(9));
        let text = sk.to_formatted().to_string();
        let variants = [
            text.to_lowercase(),
            text.replace('-', ""),
            text.replace('-', " "),
            format!("  {}  ", text.replace('-', " - ")),
            text.replace('0', "O").replace('1', "I"),
            text.replace('0', "o").replace('1', "l"),
            text.replacen("RV1", "RVI", 1),
            text.replacen("RV1", "rvL", 1),
        ];
        for v in variants {
            let parsed = SecretKey::parse(&v);
            assert!(parsed.is_ok(), "{v}: {parsed:?}");
            assert_eq!(parsed.unwrap().expose_secret(), sk.expose_secret());
        }
    }

    #[test]
    fn rejections() {
        use CodeParseError as E;
        let sk = SecretKey::generate(&mut seeded_rng(11));
        let text = sk.to_formatted().to_string();
        let body = text.strip_prefix("RV1-").unwrap();
        assert_eq!(SecretKey::parse(body).map(|_| ()), Err(E::WrongPrefix));
        assert_eq!(
            SecretKey::parse(&format!("RVR1-{body}")).map(|_| ()),
            Err(E::WrongPrefix)
        );
        assert_eq!(RecoveryCode::parse(&text).map(|_| ()), Err(E::WrongPrefix));
        assert_eq!(SecretKey::parse("").map(|_| ()), Err(E::WrongPrefix));
        assert_eq!(
            SecretKey::parse(&format!("{text}0")).map(|_| ()),
            Err(E::WrongLength)
        );
        assert_eq!(
            SecretKey::parse(&text[..text.len() - 1]).map(|_| ()),
            Err(E::WrongLength)
        );
        for bad in ['U', 'u', '_', '*', 'é', '\t', '\n'] {
            let mut t = text.clone();
            t.replace_range(5..6, &bad.to_string());
            assert_eq!(
                SecretKey::parse(&t).map(|_| ()),
                Err(E::InvalidCharacter),
                "{bad:?}"
            );
        }
        assert_eq!(
            SecretKey::parse(&"-".repeat(MAX_INPUT_LEN + 1)).map(|_| ()),
            Err(E::TooLong)
        );
    }

    #[test]
    fn non_zero_pad_bits_are_rejected() {
        let sk = SecretKey::from_slice(&[0u8; 16]).unwrap();
        let text = sk.to_formatted().to_string();
        // The 26th Base32 character is the 2nd character of the last group ("…-0?XY"), whose
        // two low bits are the pad bits. Set them to 01, 10 and 11.
        let pos = text.len() - 4 + 1;
        for pad in ['1', '2', '3'] {
            let mut t = text.clone();
            t.replace_range(pos..=pos, &pad.to_string());
            assert_eq!(
                SecretKey::parse(&t).map(|_| ()),
                Err(CodeParseError::NonZeroPadding)
            );
        }
    }

    #[test]
    fn typos_are_detected() {
        let mut rng = seeded_rng(21);
        let mut accepted = 0usize;
        let mut tried = 0usize;
        for _ in 0..8 {
            let sk = SecretKey::generate(&mut rng);
            let text = sk.to_formatted().to_string();
            let positions: Vec<usize> = text
                .char_indices()
                .skip(4)
                .filter(|(_, c)| *c != '-')
                .map(|(i, _)| i)
                .collect();
            assert_eq!(positions.len(), SYMBOLS);
            for (n, &pos) in positions.iter().enumerate() {
                let original = text.as_bytes()[pos];
                for &replacement in ALPHABET {
                    if replacement == original {
                        continue;
                    }
                    let mut t = text.clone().into_bytes();
                    t[pos] = replacement;
                    let t = String::from_utf8(t).unwrap();
                    tried += 1;
                    match SecretKey::parse(&t) {
                        Ok(other) => {
                            // A check collision (probability 2^-10) can only hide a change in
                            // the data characters, and never yields the same key.
                            assert!(n < DATA_SYMBOLS);
                            assert_ne!(other.expose_secret(), sk.expose_secret());
                            accepted += 1;
                        }
                        Err(e) => assert!(
                            matches!(
                                e,
                                CodeParseError::CheckMismatch | CodeParseError::NonZeroPadding
                            ),
                            "{e:?}"
                        ),
                    }
                }
            }
            // Every adjacent transposition of two different characters is caught too, up to
            // the same collision rate.
            for w in positions.windows(2) {
                let (a, b) = (w[0], w[1]);
                let mut t = text.clone().into_bytes();
                if t[a] == t[b] {
                    continue;
                }
                t.swap(a, b);
                tried += 1;
                if SecretKey::parse(&String::from_utf8(t).unwrap()).is_ok() {
                    accepted += 1;
                }
            }
        }
        // Expected about tried / 1024 × (26/28) ≈ 6.5; far below this bound.
        assert!(tried > 7000, "{tried}");
        assert!(
            accepted <= 25,
            "{accepted} of {tried} mistyped codes accepted"
        );
    }

    #[test]
    fn check_labels_differ_between_kinds() {
        let bytes = [0x5a; 16];
        let sk = SecretKey::from_slice(&bytes).unwrap().to_formatted();
        let rc = RecoveryCode::from_slice(&bytes).unwrap().to_formatted();
        // Same data characters, different check characters (for this input).
        assert_eq!(sk[3..sk.len() - 2], rc[4..rc.len() - 2]);
        assert_ne!(sk[sk.len() - 2..], rc[rc.len() - 2..]);
    }

    #[test]
    fn last_group_confirmation() {
        let sk = SecretKey::generate(&mut seeded_rng(5));
        let text = sk.to_formatted().to_string();
        let last = &text[text.len() - 4..];
        assert!(sk.matches_last_group(last));
        assert!(sk.matches_last_group(&last.to_lowercase()));
        assert!(sk.matches_last_group(&format!(" {last}-")));
        assert!(!sk.matches_last_group(&text[text.len() - 5..text.len() - 1]));
        assert!(!sk.matches_last_group(&text[text.len() - 3..]));
        assert!(!sk.matches_last_group(""));
        assert!(!sk.matches_last_group(&format!("{last}0")));
        assert!(!sk.matches_last_group("UUUU"));
    }

    #[test]
    fn recovery_code_derivations_match_the_keys_module() {
        let code = RecoveryCode::from_slice(&[0xc3; 16]).unwrap();
        let raw = SecretArray::<RECOVERY_CODE_LEN>::from_slice(&[0xc3; 16]).unwrap();
        assert_eq!(
            code.auth_token().unwrap().server_hash(),
            RecoveryAuthToken::derive(&raw).unwrap().server_hash()
        );
        assert!(code.wrap_key().is_ok());
    }

    #[test]
    fn debug_is_redacted() {
        let sk = SecretKey::from_slice(&[0x41; 16]).unwrap();
        let rc = RecoveryCode::from_slice(&[0x41; 16]).unwrap();
        assert_eq!(format!("{sk:?}"), "SecretKey([REDACTED])");
        assert_eq!(format!("{rc:?}"), "RecoveryCode([REDACTED])");
    }

    proptest! {
        #[test]
        fn parsers_never_panic(input in "\\PC{0,60}") {
            let _ = SecretKey::parse(&input);
            let _ = RecoveryCode::parse(&input);
        }

        #[test]
        fn any_code_round_trips(bytes in proptest::array::uniform16(any::<u8>())) {
            let sk = SecretKey::from_slice(&bytes).unwrap();
            let back = SecretKey::parse(&sk.to_formatted()).unwrap();
            prop_assert_eq!(back.expose_secret(), &bytes);
            let rc = RecoveryCode::from_slice(&bytes).unwrap();
            let back = RecoveryCode::parse(&rc.to_formatted()).unwrap();
            prop_assert_eq!(back.expose_secret(), &bytes);
        }
    }
}
