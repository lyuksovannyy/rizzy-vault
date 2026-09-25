//! The embedded passphrase wordlist (CRYPTO.md §12.1): the EFF large wordlist.
//!
//! - **Source.** "EFF's Long Wordlist", `eff_large_wordlist.txt`, published by the Electronic
//!   Frontier Foundation on 2016-07-18 (<https://www.eff.org/dice>). The file is embedded
//!   unmodified: 7,776 lines of `<five dice digits>\t<word>\n`.
//! - **Licence.** CC BY 3.0 US; attribution in `THIRD_PARTY_NOTICES.md` at the repository root.
//!   Its compatibility with the project licence is for the owner to confirm (ADR 0017 is
//!   Proposed).
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
pub(super) fn select_word(index: u32, slot: &mut [u8; SLOT]) {
    use subtle::{ConditionallySelectable as _, ConstantTimeEq as _};
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
const fn validate(raw: &[u8]) -> bool {
    let mut i = 0;
    let mut lines = 0;
    while i < raw.len() {
        // Five dice digits.
        let mut d = 0;
        while d < 5 {
            if i >= raw.len() || raw[i] < b'1' || raw[i] > b'6' {
                return false;
            }
            i += 1;
            d += 1;
        }
        if i >= raw.len() || raw[i] != b'\t' {
            return false;
        }
        i += 1;
        // The word.
        let start = i;
        while i < raw.len() && raw[i] != b'\n' {
            let c = raw[i];
            let letter = c >= b'a' && c <= b'z';
            if !(letter || (c == b'-' && i > start)) {
                return false;
            }
            i += 1;
        }
        let len = i - start;
        if len == 0 || len > MAX_WORD_LEN || i >= raw.len() {
            return false;
        }
        i += 1; // '\n'
        lines += 1;
    }
    lines == WORD_COUNT
}

#[cfg(test)]
mod tests {
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
    }
}
