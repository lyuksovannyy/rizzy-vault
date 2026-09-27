//! The embedded passphrase wordlist (CRYPTO.md §12.1): the EFF large wordlist.
//!
//! - **Source.** "EFF's Long Wordlist", `eff_large_wordlist.txt`, published by the Electronic
//!   Frontier Foundation on 2016-07-18 (<https://www.eff.org/dice>). The file is embedded
//!   unmodified: 7,776 lines of `<five dice digits>\t<word>\n`.
//! - **Licence.** CC BY 4.0 (EFF's current terms for its site content). The attribution, and the
//!   duty to show it in every artifact, are in `THIRD_PARTY_NOTICES.md` at the repository root.
//!   The owner decided on 2026-09-26 to keep the list.
//! - **Integrity.** The unit tests pin the file's SHA-256 and check its structure (count, dice
//!   numbering, sorted unique words). The compile-time validation below rejects a malformed
//!   file, so a bad edit fails the build rather than the generator.
//! - **Name and version.** [`NAME`] and [`VERSION`] identify the list, so a generated
//!   passphrase's entropy claim refers to a fixed, reviewable list. Changing the list is a new
//!   version.
//!
//! The generator selects a word by scanning every line of the embedded file and copying the
//! chosen word into a fixed-width slot (a length byte and up to nine letters) with a
//! constant-time conditional assignment, rather than indexing by the secret word number
//! (§12.3). The scan's structure depends only on the public list.

/// The list's name.
pub const NAME: &str = "eff-large-wordlist-2016-07-18";

/// The version of the embedded list. Bumped whenever the list changes.
pub const VERSION: u32 = 1;

/// Number of words: 6^5 = 7,776, one per roll of five dice.
pub const WORD_COUNT: usize = 7776;

/// The longest word, in bytes.
pub const MAX_WORD_LEN: usize = 9;

/// Bytes per slot: the length, then the word, zero-filled.
pub(super) const SLOT: usize = MAX_WORD_LEN + 1;

/// Bytes before the word on each line: five dice digits and a tab.
const DICE_PREFIX: usize = 6;

/// The embedded file, byte for byte as published.
pub(super) const RAW: &[u8] = include_bytes!("eff_large_wordlist.txt");

// The build fails if the embedded file is not exactly 7,776 well-formed lines.
const _: () = assert!(validate(RAW));

/// The lines of the embedded file, without their newlines, in list order.
fn lines() -> impl Iterator<Item = &'static [u8]> {
    RAW.split(|b| *b == b'\n').filter(|line| !line.is_empty())
}

/// Writes word number `index` into `slot` (length byte, then the letters, zero-filled),
/// touching every line of the list the same way whatever `index` is.
///
/// For every line, the length byte and every letter position of the slot get a constant-time
/// conditional assignment whose condition is "this line is word `index`". On the chosen line
/// every position is assigned, with 0 past the word's end, so whatever the slot held before
/// (the previous word, when the caller reuses it) is fully overwritten. An `index` past the
/// end matches no line and leaves the slot unchanged.
pub(super) fn select_word(index: u32, slot: &mut [u8; SLOT]) {
    use subtle::{ConditionallySelectable as _, ConstantTimeEq as _};
    // The loop structure depends only on the public list: 7,776 lines, each word's length
    // known from the file. Only the `hit` choice depends on the secret index.
    for (n, line) in (0u32..).zip(lines()) {
        let word = line.get(DICE_PREFIX..).unwrap_or_default();
        let hit = n.ct_eq(&index);
        let len = u8::try_from(word.len()).unwrap_or(0);
        if let Some((len_slot, letters)) = slot.split_first_mut() {
            len_slot.conditional_assign(&len, hit);
            for (i, dst) in letters.iter_mut().enumerate() {
                dst.conditional_assign(&word.get(i).copied().unwrap_or(0), hit);
            }
        }
    }
}

/// Whether `raw` is exactly `WORD_COUNT` lines of five dice digits (1–6), a tab, and a word of
/// 1–9 bytes from `[a-z-]` starting with a letter, each ending in `\n`.
const fn validate(mut raw: &[u8]) -> bool {
    let mut lines = 0;
    while !raw.is_empty() {
        // Five dice digits and a tab.
        let [
            b'1'..=b'6',
            b'1'..=b'6',
            b'1'..=b'6',
            b'1'..=b'6',
            b'1'..=b'6',
            b'\t',
            rest @ ..,
        ] = raw
        else {
            return false;
        };
        raw = rest;
        // The word, then its newline.
        let mut len = 0;
        loop {
            match raw {
                [b'\n', rest @ ..] => {
                    raw = rest;
                    break;
                }
                [c, rest @ ..] => {
                    if !(c.is_ascii_lowercase() || (*c == b'-' && len > 0)) {
                        return false;
                    }
                    len += 1;
                    raw = rest;
                }
                [] => return false,
            }
        }
        if len == 0 || len > MAX_WORD_LEN {
            return false;
        }
        lines += 1;
    }
    lines == WORD_COUNT
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code indexes fixtures at known offsets; a panic there fails the test, which CLAUDE.md allows"
)]
mod tests {
    //! The embedded file's pinned SHA-256 and structure, the validator's rejections, and the
    //! constant-time selection against plain indexing.

    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::test_util::hex;

    /// Every word, read through the same `lines()` the generator uses.
    fn words() -> Vec<&'static str> {
        lines()
            .map(|line| core::str::from_utf8(&line[DICE_PREFIX..]).unwrap())
            .collect()
    }

    fn selected(n: usize) -> Vec<u8> {
        let mut slot = [0u8; SLOT];
        select_word(u32::try_from(n).unwrap(), &mut slot);
        slot[1..=usize::from(slot[0])].to_vec()
    }

    /// SHA-256 of `eff_large_wordlist.txt` as published. Three independent mirrors of the file
    /// (two with dice numbers, one words-only with identical words) agreed on it when it was
    /// embedded; eff.org itself was not reachable from the build machine.
    const EFF_LARGE_WORDLIST_SHA256: &str =
        "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e";

    #[test]
    fn embedded_file_is_the_published_list() {
        assert_eq!(Sha256::digest(RAW).to_vec(), hex(EFF_LARGE_WORDLIST_SHA256));
        assert!(validate(RAW));
    }

    #[test]
    fn constant_time_selection_reads_the_named_word() {
        let words = words();
        for n in [0, 1, 2, 777, 3888, WORD_COUNT - 2, WORD_COUNT - 1] {
            assert_eq!(selected(n), words[n].as_bytes(), "{n}");
        }
        // Past the end nothing matches and the slot stays zero.
        let mut slot = [0u8; SLOT];
        select_word(u32::try_from(WORD_COUNT).unwrap(), &mut slot);
        assert_eq!(slot, [0u8; SLOT]);
        assert_eq!(lines().count(), WORD_COUNT);
    }

    #[test]
    fn lines_match_the_file() {
        let words = words();
        let text = core::str::from_utf8(RAW).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), WORD_COUNT);
        for (n, line) in lines.iter().enumerate() {
            let (dice, w) = line.split_once('\t').unwrap();
            assert_eq!(words[n], w);
            // Line n is the dice roll n written in base 6 with digits 1–6.
            let mut expected = String::new();
            let mut x = n;
            for _ in 0..5 {
                expected.insert(0, char::from(b'1' + u8::try_from(x % 6).unwrap()));
                x /= 6;
            }
            assert_eq!(dice, expected);
        }
        assert_eq!(words[0], "abacus");
        assert_eq!(words[WORD_COUNT - 1], "zoom");
    }

    #[test]
    fn words_are_sorted_unique_and_lowercase() {
        let words = words();
        for pair in words.windows(2) {
            assert!(pair[0] < pair[1], "{} !< {}", pair[0], pair[1]);
        }
        for w in &words {
            assert!((3..=MAX_WORD_LEN).contains(&w.len()), "{w}");
            assert!(w.as_bytes()[0].is_ascii_lowercase());
            assert!(w.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'));
        }
        let hyphenated: Vec<&str> = words.into_iter().filter(|w| w.contains('-')).collect();
        assert_eq!(hyphenated, ["drop-down", "felt-tip", "t-shirt", "yo-yo"]);
    }

    #[test]
    fn malformed_files_are_rejected() {
        assert!(!validate(b""));
        assert!(!validate(b"11111\tabacus\n"));
        assert!(!validate(&RAW[..RAW.len() - 1]));
        let mut bad = RAW.to_vec();
        bad[0] = b'7';
        assert!(!validate(&bad));
        let mut bad = RAW.to_vec();
        bad[6] = b'A';
        assert!(!validate(&bad));
        let mut bad = RAW.to_vec();
        bad.extend_from_slice(b"66666\tzzz\n");
        assert!(!validate(&bad));
        // Each rule, on the first line ("11111\tabacus\n", 13 bytes).
        assert!(RAW.starts_with(b"11111\tabacus\n"));
        for (at, byte) in [(4, b'0'), (5, b' '), (6, b'-'), (6, b'\n')] {
            let mut bad = RAW.to_vec();
            bad[at] = byte;
            assert!(!validate(&bad), "byte {byte:#04x} at {at}");
        }
        let with_first_word = |word: &[u8]| [b"11111\t", word, b"\n", &RAW[13..]].concat();
        assert!(validate(&with_first_word(b"abcdefgh-")));
        assert!(!validate(&with_first_word(b"abcdefghij")));
        assert!(!validate(&with_first_word(b"")));
    }
}
