//! Fuzzes the password generator's option parsing and checks (CRYPTO.md §12.1; ADR 0013 §3
//! rule 8): never panic, and every password or passphrase the generator accepts to make obeys
//! the options it was given.
//!
//! The first eight bytes are the length (two bytes), the four class rules (`rizzy-wasm`'s
//! numbering, so out-of-range rules are exercised), a flag byte (ambiguous exclusion, custom
//! symbol set, capitalisation, passphrase number) and the word count. The rest, read as UTF-8
//! and split at NUL, gives the exclusion text, the custom symbol text and the separator text.
//! For each input:
//!
//! - [`CharSet::parse`] on every string: an accepted set prints back to a string that parses
//!   to the same set.
//! - `password_options` (the wasm boundary's reader) and then the generator: when it accepts,
//!   `validate`, `entropy_bits` and generation agree; a generated password has the asked
//!   length, uses no excluded or ambiguous character, only the custom symbols, and every
//!   required class; its entropy is the options' entropy.
//! - `passphrase_options` and then the generator: when it accepts, the passphrase is ASCII,
//!   holds exactly one digit more than its separators account for when a number is asked, and
//!   reports the options' entropy.
//!
//! The RNG is a seeded SplitMix64, not a CSPRNG: nothing here depends on unpredictability,
//! and a crash must reproduce from its input alone. Options are not secrets; the generated
//! values here are not real secrets either.
#![no_main]

use std::convert::Infallible;

use libfuzzer_sys::fuzz_target;
use rand_core::{TryCryptoRng, TryRng};
use rizzy_core::generator::{
    AMBIGUOUS, CharSet, ClassRule, SYMBOLS, generate_passphrase, generate_password,
};
use rizzy_wasm::generator::{passphrase_options, password_options};

/// SplitMix64, seeded from the input.
struct SplitMix(u64);

impl TryRng for SplitMix {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let [a, b, c, d, ..] = self.try_next_u64()?.to_le_bytes();
        Ok(u32::from_le_bytes([a, b, c, d]))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        Ok(z ^ (z >> 31))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for chunk in dst.chunks_mut(8) {
            let bytes = self.try_next_u64()?.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

impl TryCryptoRng for SplitMix {}

fuzz_target!(|data: &[u8]| {
    let (head, rest) = data.split_at(data.len().min(8));
    let mut h = [0u8; 8];
    h[..head.len()].copy_from_slice(head);
    let [l0, l1, lower, upper, digits, symbols, flags, words] = h;
    let length = usize::from(u16::from_le_bytes([l0, l1]));
    let words = usize::from(words);
    let Ok(text) = core::str::from_utf8(rest) else {
        return;
    };
    let mut parts = text.split('\0');
    let mut next = || parts.next().unwrap_or("");
    let (exclude, symbol_text, separator) = (next(), next(), next());
    let seed = data
        .iter()
        .fold(0u64, |acc, &b| acc.rotate_left(5) ^ u64::from(b));

    for s in [exclude, symbol_text, separator] {
        if let Ok(set) = CharSet::parse(s) {
            assert_eq!(CharSet::parse(&set.to_ascii_string()), Ok(set));
        }
    }

    let custom = flags & 2 != 0;
    if let Ok(options) = password_options(
        length,
        lower,
        upper,
        digits,
        symbols,
        flags & 1 != 0,
        exclude,
        custom.then_some(symbol_text),
    ) {
        let entropy = options.entropy_bits();
        assert_eq!(options.validate(), entropy.map(|_| ()));
        match generate_password(&mut SplitMix(seed), &options) {
            Ok(pw) => {
                let entropy = entropy.expect("generation implies valid options");
                assert!((pw.entropy_bits() - entropy).abs() < 1e-9);
                assert!(entropy.is_finite() && entropy >= 0.0);
                let value = pw.expose_secret().as_bytes();
                assert_eq!(value.len(), options.length);
                let custom_set = options.symbol_set.unwrap_or(CharSet::from_ascii(SYMBOLS));
                for &c in value {
                    assert!(!options.exclude.contains(c));
                    assert!(!(options.exclude_ambiguous && AMBIGUOUS.contains(&c)));
                    if c.is_ascii_punctuation() {
                        assert!(custom_set.contains(c));
                        assert_ne!(options.symbols, ClassRule::Excluded);
                    }
                }
                for (rule, has) in [
                    (options.lowercase, value.iter().any(u8::is_ascii_lowercase)),
                    (options.uppercase, value.iter().any(u8::is_ascii_uppercase)),
                    (options.digits, value.iter().any(u8::is_ascii_digit)),
                    (options.symbols, value.iter().any(u8::is_ascii_punctuation)),
                ] {
                    assert!(rule != ClassRule::Required || has);
                    assert!(rule != ClassRule::Excluded || !has);
                }
            }
            Err(e) => {
                // Refused options, or (not expected with this RNG) a run of rejections.
                assert!(entropy.is_err() || e.to_string().contains("random"));
            }
        }
    }

    let number = flags & 8 != 0;
    if let Ok(options) = passphrase_options(words, separator, flags & 4 != 0, number) {
        let entropy = options.entropy_bits();
        assert_eq!(options.validate(), entropy.map(|_| ()));
        if let Ok(pp) = generate_passphrase(&mut SplitMix(seed), &options) {
            let entropy = entropy.expect("generation implies valid options");
            assert!((pp.entropy_bits() - entropy).abs() < 1e-9);
            let value = pp.expose_secret();
            assert!(value.is_ascii());
            let sep_is_digit = options.separator.is_ascii_digit();
            let digits = value.bytes().filter(u8::is_ascii_digit).count();
            let separators = if sep_is_digit { options.words - 1 } else { 0 };
            assert_eq!(digits, separators + usize::from(number));
        }
    }
});
