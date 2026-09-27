//! Password and passphrase generator (CRYPTO.md §12.1 "Password generator (M1)", §12.3).
//!
//! Two modes. [`generate_password`] draws `length` characters from the alphabet that the
//! enabled character classes make up ([`CharacterOptions`]). [`generate_passphrase`] draws
//! `words` words from the embedded wordlist and joins them with a separator
//! ([`PassphraseOptions`]). Both take the caller's CSPRNG (§12.1: `rizzy-core` reaches no
//! randomness source itself) and return a [`Generated`] value with its entropy. The options'
//! `entropy_bits` methods give the same number before generating, for the UI.
//!
//! Character mode, step by step:
//! 1. Check the options and build the alphabet: the enabled classes in the fixed order
//!    lowercase, uppercase, digits, symbols, minus [`AMBIGUOUS`] if asked.
//! 2. Draw each position as a uniform index into the alphabet, read the character with a
//!    constant-time scan, and note in constant time which class the index falls in.
//! 3. If a required class is missing, discard the whole candidate and start again.
//!
//! Passphrase mode draws each word as a uniform index into the 7,776-word list, copies it
//! into a fixed-width slot with a constant-time scan, and assembles the result with the
//! two-pass layout described below.
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
//!   the secret draw; class membership is computed the same way (§12.3).
//! - **Passphrase layout.** Words have different lengths, so where a word lands in the output
//!   depends on the secret lengths of the words before it. A passphrase is therefore built in
//!   two passes whose memory accesses depend only on the word count: each word, its separator
//!   and its capitalisation go into a fixed-width region of their own, at offsets fixed by the
//!   word number, and a compaction pass then moves the bytes together with constant-time
//!   selects. Neither pass reads or writes at an offset derived from a word's length.
//! - **What timing reveals** is how many candidates and draws were rejected, which says nothing
//!   about the accepted result, and, for passphrases, the total output length, which the
//!   result's length reveals anyway.
//! - **Allocation.** Every secret buffer is allocated once at its final capacity and never
//!   grows (§12.2): a passphrase's at the fixed-width size, then truncated in place.
//!
//! # Attacker model
//!
//! What this module defends against:
//! - **Bias.** Masked rejection sampling and whole-candidate rejection keep the result uniform
//!   over the reported space, so the entropy figure is exact, not an estimate. Unit tests
//!   check the distributions with a chi-square bound.
//! - **Timing and cache side channels** on the chosen characters and words, as described
//!   above.
//! - **Leftover copies and logs.** Buffers are wiped on drop and never reallocated, and
//!   `Debug` on [`Generated`] prints `[REDACTED]`.
//! - **Ambiguous passphrases.** The separator may not be a letter or `-`, the only
//!   characters words contain, so every passphrase splits back into exactly one word
//!   sequence and the reported space is the real one.
//!
//! What it does not do:
//! - **Judge the RNG.** The output is only as unpredictable as the injected RNG. An RNG that
//!   rejects implausibly often is reported ([`GeneratorError::RngExhausted`]); a predictable
//!   one is not detected.
//! - **Protect the value after it leaves.** [`Generated::expose_secret`] returns a borrowed
//!   `&str`; a copy the caller makes (a UI string, the clipboard) is outside this crate's
//!   wiping (§12.2 Limits).
//! - **Add entropy from formatting.** The separator and capitalisation are fixed by the
//!   options, so they add nothing, and the entropy figure does not count them.

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
/// Bytes per word in a passphrase's fixed-width layout: the word, zero-filled to
/// [`wordlist::MAX_WORD_LEN`], then one more byte, so the separator always fits after it.
const WORD_WIDTH: usize = wordlist::MAX_WORD_LEN + 1;

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
///
/// A generated value is a secret (CRYPTO.md §12.1): the type has no `Clone` and no `Display`,
/// and `Debug` prints `[REDACTED]` for the value and shows only the entropy.
pub struct Generated {
    /// The password or passphrase, ASCII only, wiped on drop.
    value: Zeroizing<String>,
    /// `log2` of the number of values it was drawn from, uniformly. Public.
    entropy_bits: f64,
}

impl Generated {
    /// The password or passphrase.
    ///
    /// The explicit name marks every place the secret leaves its wrapper (§12.2). A copy the
    /// caller makes is not wiped by this crate.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.value
    }

    /// `log2` of the size of the space it was drawn from, uniformly.
    ///
    /// This is what the UI reports (§12.1). It assumes the injected RNG is a CSPRNG.
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
    /// The characters, in the first `len` bytes; room for all 94 (26 + 26 + 10 + 32).
    chars: [u8; 94],
    /// How many bytes of `chars` are in use.
    len: u32,
    /// `(start, end, required)` per enabled class, as indices into `chars`.
    classes: [(u32, u32, bool); 4],
    /// How many entries of `classes` are in use.
    class_count: usize,
}

impl Alphabet {
    /// Builds the alphabet for `options`: each class not [`ClassRule::Excluded`], in the fixed
    /// order lowercase, uppercase, digits, symbols, without [`AMBIGUOUS`] characters if
    /// requested. The class ranges are contiguous and do not overlap.
    ///
    /// # Errors
    /// [`GeneratorError::NoClasses`] if no character is left. The other `NoClasses` returns
    /// cannot happen: 94 characters and 4 classes always fit.
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
            // The options and the character sets are public, so this loop may branch freely.
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

    /// The characters in use, `chars[..len]`.
    fn chars(&self) -> &[u8] {
        self.chars
            .get(..usize::try_from(self.len).unwrap_or(0))
            .unwrap_or_default()
    }

    /// The enabled classes, `classes[..class_count]`.
    fn classes(&self) -> &[(u32, u32, bool)] {
        self.classes.get(..self.class_count).unwrap_or_default()
    }

    /// How many enabled classes are [`ClassRule::Required`].
    fn required_count(&self) -> usize {
        self.classes().iter().filter(|c| c.2).count()
    }
}

impl CharacterOptions {
    /// Validates the options and builds their alphabet: the length must be in
    /// [`MIN_LENGTH`]..=[`MAX_LENGTH`], at least one character must remain, and there must
    /// be no more required classes than characters (otherwise no candidate could pass).
    ///
    /// # Errors
    /// [`GeneratorError::InvalidLength`], [`GeneratorError::NoClasses`] or
    /// [`GeneratorError::TooManyRequiredClasses`].
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
    // `fraction` is the share of all `N^L` strings that contain every required class, a value
    // in (0, 1]; each subset `S` of the required classes adds or removes the strings that
    // avoid every class in `S`.
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
    /// Validates the options and returns the separator as its ASCII byte.
    ///
    /// The word count must be in [`MIN_WORDS`]..=[`MAX_WORDS`]. The separator must be
    /// printable ASCII (space to `~`), not a letter and not `-`: words consist of lowercase
    /// letters and `-`, so any other separator keeps the passphrase splittable into exactly
    /// one word sequence, and a non-zero byte keeps the compaction pass correct.
    ///
    /// # Errors
    /// [`GeneratorError::InvalidWordCount`] or [`GeneratorError::InvalidSeparator`].
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

/// `words × log2(7776)`: each word is an independent uniform choice from the list. The
/// separator and capitalisation are fixed by the options and add nothing. `words` is already
/// checked to be at most [`MAX_WORDS`], so the conversions cannot fail.
fn passphrase_entropy(words: usize) -> f64 {
    let words = u32::try_from(words).unwrap_or(0);
    let count = u32::try_from(wordlist::WORD_COUNT).unwrap_or(0);
    f64::from(words) * f64::from(count).log2()
}

/// Draws a uniform index in `0..n` by masked rejection sampling (no `%`).
///
/// A 32-bit draw is masked into `0..2^k`, where `2^k` is the smallest power of two `≥ n`, so
/// every masked value is equally likely, and a value `≥ n` is thrown away and redrawn. Each draw is accepted with
/// probability above 1/2, so [`MAX_DRAWS`] failures in a row mean a broken RNG. The only
/// branch is on accept or reject, which says nothing about the accepted value.
///
/// # Errors
/// [`GeneratorError::NoClasses`] for `n = 0`, [`GeneratorError::RngExhausted`] after
/// [`MAX_DRAWS`] rejections.
fn uniform_index<R: CryptoRng + ?Sized>(rng: &mut R, n: u32) -> Result<u32, GeneratorError> {
    if n == 0 {
        return Err(GeneratorError::NoClasses);
    }
    // The smallest `2^k - 1 ≥ n - 1`; `u32::MAX` when `2^k` would not fit in a `u32`.
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
///
/// Every element is read once whatever `index` is, so neither the memory access pattern nor
/// the timing depends on the secret index (§12.3). An index past the end yields 0.
fn ct_select(set: &[u8], index: u32) -> u8 {
    let mut out = 0u8;
    for (i, c) in (0u32..).zip(set) {
        out.conditional_assign(c, i.ct_eq(&index));
    }
    out
}

/// Generates a password in character mode.
///
/// The result is uniform over the strings of `options.length` characters from the enabled
/// classes that contain at least one character of each required class, and its entropy is
/// `log2` of their number ([`CharacterOptions::entropy_bits`]). Each candidate is drawn in
/// full and kept or discarded as a whole; positions are never patched to satisfy a class.
///
/// `rng` must be a CSPRNG; the platform crates pass one backed by the OS (§12.1).
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
        // `present[k]` becomes 1 once a character of enabled class `k` is drawn.
        let mut present = [Choice::from(0); 4];
        for slot in buf.iter_mut() {
            let mut index = uniform_index(rng, alphabet.len)?;
            *slot = ct_select(chars, index);
            // Class membership from the index, `start ≤ index < end`, with constant-time
            // comparisons against every class's range.
            for (seen, (start, end, _)) in present.iter_mut().zip(alphabet.classes()) {
                *seen |= !index.ct_lt(start) & index.ct_lt(end);
            }
            index.zeroize();
        }
        // Every required class seen; classes that are only included count as satisfied.
        // A rejected candidate is overwritten in place by the next one.
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
/// `options.words` words are drawn independently and uniformly from the
/// [`wordlist::WORD_COUNT`] words of [`wordlist::NAME`], joined by the separator, with the
/// first letter of each word uppercased if `capitalize` is set. The entropy is
/// `words × log2(7776)` ([`PassphraseOptions::entropy_bits`]). The assembly's memory access
/// pattern depends only on the word count (see the module documentation); the total length
/// of the result is not hidden.
///
/// `rng` must be a CSPRNG; the platform crates pass one backed by the OS (§12.1).
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
    // The words are assembled only through `assemble_words`, whose memory access pattern does
    // not depend on the words' lengths (CRYPTO.md §12.3). Do not build the passphrase here by
    // appending words: that copies each secret word at a length-dependent offset. If this call
    // goes, `assemble_words` is dead code and `cargo lint` fails.
    let out = assemble_words(options.words, separator, options.capitalize, |slot| {
        let mut index = uniform_index(rng, count)?;
        wordlist::select_word(index, slot);
        index.zeroize();
        Ok(())
    })?;
    Ok(Generated {
        value: ascii_string(out),
        entropy_bits: passphrase_entropy(options.words),
    })
}

/// Assembles `words` words, joined by `separator`, in two passes whose memory access pattern
/// depends only on `words` (CRYPTO.md §12.3). `select` fills the slot for the next word, as
/// [`wordlist::select_word`] does.
///
/// Pass 1 writes word `n` into bytes `n * WORD_WIDTH..(n + 1) * WORD_WIDTH` of a fixed-width
/// buffer, whatever the lengths of the words before it ([`spread_word`]). Pass 2 squeezes out
/// the padding ([`compact`]). The result has its final capacity from the start; truncating it
/// to the total length, which the passphrase reveals anyway, does not reallocate.
fn assemble_words(
    words: usize,
    separator: u8,
    capitalize: bool,
    mut select: impl FnMut(&mut [u8; wordlist::SLOT]) -> Result<(), GeneratorError>,
) -> Result<Zeroizing<Vec<u8>>, GeneratorError> {
    let mut wide = Zeroizing::new(vec![0u8; words * WORD_WIDTH]);
    let mut slot = Zeroizing::new([0u8; wordlist::SLOT]);
    for (n, region) in wide.chunks_exact_mut(WORD_WIDTH).enumerate() {
        select(&mut slot)?;
        // The last word has no separator after it; which word is last is public.
        let after = (n + 1 < words).then_some(separator);
        spread_word(region, &slot, after, capitalize);
    }
    let mut out = Zeroizing::new(vec![0u8; wide.len()]);
    let len = compact(&wide, &mut out);
    out.truncate(len);
    Ok(out)
}

/// Writes one selected word into its fixed-width `region` (`WORD_WIDTH` bytes): the letters,
/// then `separator` (if any) right after the last letter, then zeros. `slot` is as
/// [`wordlist::select_word`] fills it: a length byte, then the letters, zero-filled.
///
/// Every byte of the region is written the same way whatever the word's length: the
/// separator's position is chosen by a constant-time select, not by indexing with the length.
fn spread_word(
    region: &mut [u8],
    slot: &[u8; wordlist::SLOT],
    separator: Option<u8>,
    capitalize: bool,
) {
    let (len, letters) = slot.split_first().unwrap_or((&0, &[]));
    for (i, dst) in (0u8..).zip(region.iter_mut()) {
        // Past the word's end the slot is already zero; the region's last byte has no letter.
        *dst = letters.get(usize::from(i)).copied().unwrap_or(0);
        if let Some(sep) = separator {
            dst.conditional_assign(&sep, i.ct_eq(len));
        }
    }
    if capitalize {
        // The first letter is at offset 0 of the region, a public position. Every word starts
        // with a lowercase letter (the wordlist's compile-time check); the case flip is still a
        // constant-time select rather than a branch on the letter.
        if let Some(first) = region.first_mut() {
            let lower = !first.ct_lt(&b'a') & first.ct_lt(&(b'z' + 1));
            let upper = *first ^ 0x20;
            first.conditional_assign(&upper, lower);
        }
    }
}

/// Moves the non-zero bytes of `wide` to the front of `out`, in order, and returns how many
/// there are. `out` must be at least as long as `wide`. Zero marks padding: no word byte is
/// zero (the wordlist allows only `[a-z-]`) and no separator is ([`PassphraseOptions::check`]
/// allows only printable ASCII).
///
/// The memory access pattern depends only on the two lengths. For each output byte `j`, every
/// input byte is visited; its destination is the number of non-zero bytes before it, kept as a
/// running count in a local rather than looked up, and the one byte whose destination is `j`
/// is kept by a constant-time select. That is `(words × WORD_WIDTH)²` selects, at most 40,000
/// for 20 words, which is small next to the wordlist scans.
fn compact(wide: &[u8], out: &mut [u8]) -> usize {
    for (j, dst) in out.iter_mut().enumerate() {
        let mut dest = 0usize;
        for b in wide {
            let keep = !b.ct_eq(&0);
            dst.conditional_assign(b, keep & dest.ct_eq(&j));
            dest += usize::from(keep.unwrap_u8());
        }
    }
    wide.iter()
        .map(|b| usize::from((!b.ct_eq(&0)).unwrap_u8()))
        .sum()
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
#[expect(
    clippy::indexing_slicing,
    reason = "test code indexes fixtures at known offsets; a panic there fails the test, which CLAUDE.md allows"
)]
mod tests;
