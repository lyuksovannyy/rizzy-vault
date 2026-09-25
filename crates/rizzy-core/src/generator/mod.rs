//! Password and passphrase generator (CRYPTO.md §12.1 "Password generator (M1)", §12.3).
//!
//! - **Uniform draws.** Every character and word is drawn uniformly from the injected CSPRNG by
//!   rejection sampling: a 32-bit draw is masked to the next power of two above the set size and
//!   redrawn when it falls outside. There is no `%` on raw random bytes.
//! - **Required classes.** A character class marked [`ClassRule::Required`] must appear at least
//!   once. This is met by rejecting the whole candidate and drawing a new one, never by patching
//!   positions, so the result is uniform over exactly the strings that satisfy the rules.
//! - **Passphrases** use one named, versioned wordlist embedded in the crate ([`wordlist`]: the
//!   EFF large wordlist, 7,776 words).
//! - **Entropy** is reported as `log2` of the size of the space actually sampled: for
//!   characters, the number of strings of that length over that alphabet that contain every
//!   required class (inclusion–exclusion); for passphrases, `words × log2(7776)`.
//! - **Secrets.** Results are wiped on drop and `Debug` is redacted. Characters and words are
//!   selected by scanning the whole alphabet or wordlist in constant time, not by indexing with
//!   the secret draw; class membership is computed the same way (§12.3). What timing reveals is
//!   how many candidates and draws were rejected, which says nothing about the accepted result,
//!   and, for passphrases, the output length, which the result's length reveals anyway.

pub mod wordlist;

use core::fmt;

use rand_core::CryptoRng;
use subtle::{Choice, ConditionallySelectable as _, ConstantTimeEq as _, ConstantTimeLess as _};
use zeroize::{Zeroize as _, Zeroizing};

/// Shortest generated password, in characters.
pub const MIN_LENGTH: usize = 4;
/// Longest generated password, in characters.
pub const MAX_LENGTH: usize = 256;
/// Fewest words in a passphrase.
pub const MIN_WORDS: usize = 3;
/// Most words in a passphrase.
pub const MAX_WORDS: usize = 20;

/// Candidates drawn before giving up. With at least one character per required class, the
/// least likely valid configuration (length 4, all four classes required, ambiguous characters
/// excluded) succeeds with probability about 0.06 per candidate, so reaching this limit has
/// probability below 2^-80: in practice it means the injected RNG is broken.
const MAX_CANDIDATES: usize = 1000;
/// Draws per uniform index before giving up. Each draw succeeds with probability above 1/2.
const MAX_DRAWS: usize = 128;

/// Lowercase letters.
const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
/// Uppercase letters.
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
/// Decimal digits.
const DIGITS: &[u8] = b"0123456789";
/// The 32 printable ASCII punctuation characters (no space).
const SYMBOLS: &[u8] = b"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
/// Characters left out when [`CharacterOptions::exclude_ambiguous`] is set: those commonly
/// confused with each other in print (`l`/`1`/`I`/`|`, `O`/`0`/`o`).
pub const AMBIGUOUS: &[u8] = b"lIo0O1|";

/// Why a generator request was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum GeneratorError {
    /// The length is outside [`MIN_LENGTH`]..=[`MAX_LENGTH`].
    InvalidLength,
    /// No character class is enabled.
    NoClasses,
    /// More classes are required than the password has characters.
    TooManyRequiredClasses,
    /// The word count is outside [`MIN_WORDS`]..=[`MAX_WORDS`].
    InvalidWordCount,
    /// The separator is not printable ASCII, is a letter, or is `-` (which occurs inside words
    /// of the list, so it would make different word sequences print the same passphrase).
    InvalidSeparator,
    /// The injected RNG produced an implausibly long run of rejected draws.
    RngExhausted,
}

impl fmt::Display for GeneratorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLength => "password length out of range",
            Self::NoClasses => "no character class selected",
            Self::TooManyRequiredClasses => "more required classes than characters",
            Self::InvalidWordCount => "passphrase word count out of range",
            Self::InvalidSeparator => "separator not allowed",
            Self::RngExhausted => "random number generator failure",
        })
    }
}

impl core::error::Error for GeneratorError {}

/// How a character class takes part in a generated password.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ClassRule {
    /// Never used.
    Excluded,
    /// In the alphabet, but not required.
    Included,
    /// In the alphabet, and at least one character of it must appear.
    Required,
}

/// Character-mode options.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CharacterOptions {
    /// Number of characters.
    pub length: usize,
    /// `a`–`z`.
    pub lowercase: ClassRule,
    /// `A`–`Z`.
    pub uppercase: ClassRule,
    /// `0`–`9`.
    pub digits: ClassRule,
    /// The 32 ASCII punctuation characters.
    pub symbols: ClassRule,
    /// Leave out [`AMBIGUOUS`] characters.
    pub exclude_ambiguous: bool,
}

impl Default for CharacterOptions {
    /// 20 characters, every class required, ambiguous characters allowed.
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: ClassRule::Required,
            uppercase: ClassRule::Required,
            digits: ClassRule::Required,
            symbols: ClassRule::Required,
            exclude_ambiguous: false,
        }
    }
}

/// Passphrase-mode options.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PassphraseOptions {
    /// Number of words.
    pub words: usize,
    /// Between words: printable ASCII, not a letter and not `-`
    /// ([`GeneratorError::InvalidSeparator`]).
    pub separator: char,
    /// Capitalise the first letter of every word. Adds no entropy.
    pub capitalize: bool,
}

impl Default for PassphraseOptions {
    /// Six words (about 77.5 bits) separated by `.`, not capitalised.
    fn default() -> Self {
        Self {
            words: 6,
            separator: '.',
            capitalize: false,
        }
    }
}

/// A generated password or passphrase, wiped on drop, with its entropy.
pub struct Generated {
    value: Zeroizing<String>,
    entropy_bits: f64,
}

impl Generated {
    /// The password or passphrase.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.value
    }

    /// `log2` of the size of the space it was drawn from, uniformly.
    #[must_use]
    pub const fn entropy_bits(&self) -> f64 {
        self.entropy_bits
    }
}

impl fmt::Debug for Generated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Generated")
            .field("value", &"[REDACTED]")
            .field("entropy_bits", &self.entropy_bits)
            .finish()
    }
}

/// The alphabet of one request: the enabled classes, concatenated in a fixed order, with each
/// class's index range. Public (it depends only on the options).
struct Alphabet {
    chars: [u8; 94],
    len: u32,
    /// `(start, end, required)` per enabled class, as indices into `chars`.
    classes: [(u32, u32, bool); 4],
    class_count: usize,
}

impl Alphabet {
    fn new(options: &CharacterOptions) -> Result<Self, GeneratorError> {
        let mut alphabet = Self {
            chars: [0; 94],
            len: 0,
            classes: [(0, 0, false); 4],
            class_count: 0,
        };
        for (set, rule) in [
            (LOWER, options.lowercase),
            (UPPER, options.uppercase),
            (DIGITS, options.digits),
            (SYMBOLS, options.symbols),
        ] {
            if rule == ClassRule::Excluded {
                continue;
            }
            let start = alphabet.len;
            for &c in set {
                if options.exclude_ambiguous && AMBIGUOUS.contains(&c) {
                    continue;
                }
                let slot = alphabet
                    .chars
                    .get_mut(usize::try_from(alphabet.len).map_err(|_| GeneratorError::NoClasses)?)
                    .ok_or(GeneratorError::NoClasses)?;
                *slot = c;
                alphabet.len += 1;
            }
            let class = alphabet
                .classes
                .get_mut(alphabet.class_count)
                .ok_or(GeneratorError::NoClasses)?;
            *class = (start, alphabet.len, rule == ClassRule::Required);
            alphabet.class_count += 1;
        }
        if alphabet.len == 0 {
            return Err(GeneratorError::NoClasses);
        }
        Ok(alphabet)
    }

    fn chars(&self) -> &[u8] {
        self.chars
            .get(..usize::try_from(self.len).unwrap_or(0))
            .unwrap_or_default()
    }

    fn classes(&self) -> &[(u32, u32, bool)] {
        self.classes.get(..self.class_count).unwrap_or_default()
    }

    fn required_count(&self) -> usize {
        self.classes().iter().filter(|c| c.2).count()
    }
}

impl CharacterOptions {
    fn checked_alphabet(&self) -> Result<Alphabet, GeneratorError> {
        if !(MIN_LENGTH..=MAX_LENGTH).contains(&self.length) {
            return Err(GeneratorError::InvalidLength);
        }
        let alphabet = Alphabet::new(self)?;
        if alphabet.required_count() > self.length {
            return Err(GeneratorError::TooManyRequiredClasses);
        }
        Ok(alphabet)
    }

    /// The entropy of a password generated with these options: `log2` of the number of strings
    /// of `length` characters over the alphabet that contain every required class.
    ///
    /// # Errors
    /// As [`generate_password`], for invalid options.
    pub fn entropy_bits(&self) -> Result<f64, GeneratorError> {
        let alphabet = self.checked_alphabet()?;
        Ok(character_entropy(&alphabet, self.length))
    }
}

/// `log2(count)` with, by inclusion–exclusion over the required classes `R`,
/// `count = Σ_{S ⊆ R} (−1)^{|S|} (N − Σ_{c ∈ S} n_c)^L`. Computed as
/// `L·log2(N) + log2(Σ (−1)^{|S|} (1 − Σ n_c / N)^L)`, which stays within `f64` range.
fn character_entropy(alphabet: &Alphabet, length: usize) -> f64 {
    let n = f64::from(alphabet.len);
    let l = i32::try_from(length).unwrap_or(i32::MAX);
    let required: Vec<f64> = alphabet
        .classes()
        .iter()
        .filter(|c| c.2)
        .map(|c| f64::from(c.1 - c.0))
        .collect();
    let mut fraction = 0.0f64;
    for subset in 0u32..(1 << required.len()) {
        let excluded: f64 = required
            .iter()
            .enumerate()
            .filter(|(i, _)| subset & (1 << i) != 0)
            .map(|(_, size)| size)
            .sum();
        let term = ((n - excluded) / n).powi(l);
        if subset.count_ones() % 2 == 0 {
            fraction += term;
        } else {
            fraction -= term;
        }
    }
    f64::from(l) * n.log2() + fraction.log2()
}

impl PassphraseOptions {
    fn check(&self) -> Result<u8, GeneratorError> {
        if !(MIN_WORDS..=MAX_WORDS).contains(&self.words) {
            return Err(GeneratorError::InvalidWordCount);
        }
        let sep = u8::try_from(self.separator).map_err(|_| GeneratorError::InvalidSeparator)?;
        if !(b' '..=b'~').contains(&sep) || sep.is_ascii_alphabetic() || sep == b'-' {
            return Err(GeneratorError::InvalidSeparator);
        }
        Ok(sep)
    }

    /// The entropy of a passphrase with these options: `words × log2(7776)`.
    ///
    /// # Errors
    /// As [`generate_passphrase`], for invalid options.
    pub fn entropy_bits(&self) -> Result<f64, GeneratorError> {
        self.check()?;
        Ok(passphrase_entropy(self.words))
    }
}

fn passphrase_entropy(words: usize) -> f64 {
    let words = u32::try_from(words).unwrap_or(0);
    let count = u32::try_from(wordlist::WORD_COUNT).unwrap_or(0);
    f64::from(words) * f64::from(count).log2()
}

/// Draws a uniform index in `0..n` by masked rejection sampling (no `%`).
fn uniform_index<R: CryptoRng + ?Sized>(rng: &mut R, n: u32) -> Result<u32, GeneratorError> {
    if n == 0 {
        return Err(GeneratorError::NoClasses);
    }
    let mask = n.checked_next_power_of_two().map_or(u32::MAX, |p| p - 1);
    for _ in 0..MAX_DRAWS {
        let x = rng.next_u32() & mask;
        if x < n {
            return Ok(x);
        }
    }
    Err(GeneratorError::RngExhausted)
}

/// `set[index]`, read by scanning every element and selecting in constant time.
fn ct_select(set: &[u8], index: u32) -> u8 {
    let mut out = 0u8;
    for (i, c) in (0u32..).zip(set) {
        out.conditional_assign(c, i.ct_eq(&index));
    }
    out
}

/// Generates a password in character mode.
///
/// # Errors
/// [`GeneratorError`] for invalid options, or [`GeneratorError::RngExhausted`] if the injected
/// RNG is broken.
pub fn generate_password<R: CryptoRng + ?Sized>(
    rng: &mut R,
    options: &CharacterOptions,
) -> Result<Generated, GeneratorError> {
    let alphabet = options.checked_alphabet()?;
    let chars = alphabet.chars();
    let mut buf = Zeroizing::new(vec![0u8; options.length]);
    for _ in 0..MAX_CANDIDATES {
        let mut present = [Choice::from(0); 4];
        for slot in buf.iter_mut() {
            let mut index = uniform_index(rng, alphabet.len)?;
            *slot = ct_select(chars, index);
            for (seen, (start, end, _)) in present.iter_mut().zip(alphabet.classes()) {
                *seen |= !index.ct_lt(start) & index.ct_lt(end);
            }
            index.zeroize();
        }
        let mut all_required = Choice::from(1);
        for (seen, (_, _, required)) in present.iter().zip(alphabet.classes()) {
            all_required &= *seen | Choice::from(u8::from(!*required));
        }
        // Only whether the candidate is accepted is revealed; a rejected one is discarded.
        if bool::from(all_required) {
            return Ok(Generated {
                value: ascii_string(buf),
                entropy_bits: character_entropy(&alphabet, options.length),
            });
        }
    }
    Err(GeneratorError::RngExhausted)
}

/// Generates a passphrase from the embedded wordlist.
///
/// # Errors
/// [`GeneratorError`] for invalid options, or [`GeneratorError::RngExhausted`] if the injected
/// RNG is broken.
pub fn generate_passphrase<R: CryptoRng + ?Sized>(
    rng: &mut R,
    options: &PassphraseOptions,
) -> Result<Generated, GeneratorError> {
    let separator = options.check()?;
    let count = u32::try_from(wordlist::WORD_COUNT).map_err(|_| GeneratorError::NoClasses)?;
    // Allocated once at the largest possible size.
    let capacity = options.words * (wordlist::MAX_WORD_LEN + 1);
    let mut out = Zeroizing::new(Vec::with_capacity(capacity));
    let mut slot = Zeroizing::new([0u8; wordlist::SLOT]);
    for n in 0..options.words {
        if n > 0 {
            out.push(separator);
        }
        let mut index = uniform_index(rng, count)?;
        wordlist::select_word(index, &mut slot);
        index.zeroize();
        let (len, letters) = slot.split_first().unwrap_or((&0, &[]));
        let word = letters.get(..usize::from(*len)).unwrap_or_default();
        let first = out.len();
        out.extend_from_slice(word);
        if options.capitalize {
            // Every word starts with a lowercase letter (checked by the wordlist tests).
            if let Some(b) = out.get_mut(first) {
                *b = b.to_ascii_uppercase();
            }
        }
    }
    Ok(Generated {
        value: ascii_string(out),
        entropy_bits: passphrase_entropy(options.words),
    })
}

/// Moves an ASCII buffer into a `String` without copying it.
fn ascii_string(mut bytes: Zeroizing<Vec<u8>>) -> Zeroizing<String> {
    match String::from_utf8(core::mem::take(&mut *bytes)) {
        Ok(text) => Zeroizing::new(text),
        Err(e) => {
            // Unreachable: every byte comes from an ASCII alphabet. Wipe and return nothing.
            e.into_bytes().zeroize();
            Zeroizing::new(String::new())
        }
    }
}

#[cfg(test)]
mod tests;
