//! Tests of the generator (CRYPTO.md §12.1): chi-square bias checks on index draws,
//! characters, required-class candidates and word choice, entropy values, option validation,
//! and checks that the constant-time passphrase layout matches plain concatenation byte for
//! byte.

use std::collections::HashMap;

use rand_core::Rng as _;

use super::*;
use crate::test_util::seeded_rng;

/// Converts a test count to `f64` exactly (every count here fits in `u32`).
fn f(x: impl TryInto<u32>) -> f64 {
    f64::from(x.try_into().ok().unwrap())
}

/// Pearson's chi-square statistic of observed counts against a uniform expectation.
fn chi_square(counts: &[u64]) -> f64 {
    let total: u64 = counts.iter().sum();
    let expected = f(total) / f(counts.len());
    counts
        .iter()
        .map(|&c| {
            let d = f(c) - expected;
            d * d / expected
        })
        .sum()
}

/// A generous acceptance bound: `df + 6·sqrt(2·df)`, about six standard deviations above the
/// chi-square mean. The seeds are fixed, so the tests are deterministic; the bound only has to
/// separate "uniform" from "biased".
fn bound(bins: usize) -> f64 {
    let df = f(bins - 1);
    df + 6.0 * (2.0 * df).sqrt()
}

#[test]
fn uniform_index_is_unbiased() {
    let mut rng = seeded_rng(1);
    for (n, samples) in [
        (10u32, 50_000usize),
        (26, 52_000),
        (94, 94_000),
        (7776, 777_600),
    ] {
        let mut counts = vec![0u64; n as usize];
        for _ in 0..samples {
            counts[uniform_index(&mut rng, n).unwrap() as usize] += 1;
        }
        let x2 = chi_square(&counts);
        assert!(x2 < bound(n as usize), "n = {n}: chi-square {x2}");
    }
    assert_eq!(uniform_index(&mut rng, 1).unwrap(), 0);
    assert_eq!(uniform_index(&mut rng, 0), Err(GeneratorError::NoClasses));
}

#[test]
fn the_bias_test_has_power() {
    // The naive `byte % 94` sampler the spec forbids: 256 = 2·94 + 68, so values below 68 are
    // 1.5 times as likely. The same test must reject it.
    let mut rng = seeded_rng(2);
    let mut counts = vec![0u64; 94];
    for _ in 0..94_000 {
        let mut b = [0u8; 1];
        rng.fill_bytes(&mut b);
        counts[usize::from(b[0]) % 94] += 1;
    }
    assert!(chi_square(&counts) > 10.0 * bound(94));
}

#[test]
fn a_broken_rng_is_reported_not_looped_on() {
    // An RNG that only ever returns 0xFF… makes every masked draw for n = 94 equal 127.
    let mut rng = crate::test_util::FixedRng::new(&[0xff]);
    assert_eq!(
        uniform_index(&mut rng, 94),
        Err(GeneratorError::RngExhausted)
    );
    assert_eq!(
        generate_password(&mut rng, &CharacterOptions::default()).map(|_| ()),
        Err(GeneratorError::RngExhausted)
    );
}

#[test]
fn characters_are_uniform_within_one_class() {
    let options = CharacterOptions {
        length: 64,
        lowercase: ClassRule::Required,
        uppercase: ClassRule::Excluded,
        digits: ClassRule::Excluded,
        symbols: ClassRule::Excluded,
        exclude_ambiguous: false,
        exclude: CharSet::EMPTY,
        symbol_set: None,
    };
    let mut rng = seeded_rng(3);
    let mut counts = vec![0u64; 26];
    for _ in 0..2000 {
        let pw = generate_password(&mut rng, &options).unwrap();
        assert_eq!(pw.expose_secret().len(), 64);
        for b in pw.expose_secret().bytes() {
            counts[usize::from(b - b'a')] += 1;
        }
    }
    let x2 = chi_square(&counts);
    assert!(x2 < bound(26), "chi-square {x2}");
}

#[test]
fn required_classes_give_a_uniform_result_over_valid_strings() {
    // Lowercase and digits both required, length 2: the valid strings are letter+digit and
    // digit+letter, 2 × 26 × 10 = 520 of them, and whole-candidate rejection must make each
    // equally likely. Patching a position to force a class would not.
    let options = CharacterOptions {
        length: MIN_LENGTH,
        lowercase: ClassRule::Required,
        uppercase: ClassRule::Excluded,
        digits: ClassRule::Required,
        symbols: ClassRule::Excluded,
        exclude_ambiguous: false,
        exclude: CharSet::EMPTY,
        symbol_set: None,
    };
    assert_eq!(options.length, 4);
    // Length 4 has too many valid strings to bin; check the two-character prefix distribution
    // conditioned on nothing, and the per-string validity.
    let mut rng = seeded_rng(4);
    let mut prefixes: HashMap<[u8; 2], u64> = HashMap::new();
    let samples = 52_000;
    for _ in 0..samples {
        let pw = generate_password(&mut rng, &options).unwrap();
        let bytes = pw.expose_secret().as_bytes();
        assert!(bytes.iter().any(u8::is_ascii_lowercase));
        assert!(bytes.iter().any(u8::is_ascii_digit));
        *prefixes.entry([bytes[0], bytes[1]]).or_default() += 1;
    }
    // Exact expected frequency of each 2-character prefix: count the valid completions.
    // With a = 26 letters, d = 10 digits, N = 36, a prefix with both classes has N² = 1296
    // completions; one with only letters needs a digit in the last two: N² − a² = 620; one
    // with only digits: N² − d² = 1196. Valid total = N⁴ − a⁴ − d⁴ = 1_212_640.
    let total = 1_212_640.0f64;
    let mut x2 = 0.0;
    for p0 in LOWER.iter().chain(DIGITS) {
        for p1 in LOWER.iter().chain(DIGITS) {
            let letters = [*p0, *p1].iter().filter(|b| b.is_ascii_lowercase()).count();
            let completions = match letters {
                1 => 1296.0,
                2 => 620.0,
                _ => 1196.0,
            };
            let expected = f(samples) * completions / total;
            let observed = f(prefixes.get(&[*p0, *p1]).copied().unwrap_or(0));
            x2 += (observed - expected).powi(2) / expected;
        }
    }
    assert!(x2 < bound(36 * 36), "chi-square {x2}");
}

#[test]
fn required_class_rejection_matches_brute_force_on_a_tiny_space() {
    // Digits and symbols required, length 4, ambiguous excluded: 8 digits, 31 symbols. Count
    // valid strings by brute force and compare with the entropy formula.
    let options = CharacterOptions {
        length: 4,
        lowercase: ClassRule::Excluded,
        uppercase: ClassRule::Excluded,
        digits: ClassRule::Required,
        symbols: ClassRule::Required,
        exclude_ambiguous: true,
        exclude: CharSet::EMPTY,
        symbol_set: None,
    };
    let alphabet = Alphabet::new(&options).unwrap();
    let chars = alphabet.chars();
    assert_eq!(chars.len(), 39);
    let mut valid = 0u64;
    for a in chars {
        for b in chars {
            for c in chars {
                for d in chars {
                    let s = [*a, *b, *c, *d];
                    if s.iter().any(u8::is_ascii_digit) && s.iter().any(|x| !x.is_ascii_digit()) {
                        valid += 1;
                    }
                }
            }
        }
    }
    assert_eq!(valid, 39u64.pow(4) - 8u64.pow(4) - 31u64.pow(4));
    let bits = options.entropy_bits().unwrap();
    assert!((bits - f(valid).log2()).abs() < 1e-9, "{bits}");
}

#[test]
fn entropy_values() {
    let single = |length| CharacterOptions {
        length,
        lowercase: ClassRule::Included,
        uppercase: ClassRule::Excluded,
        digits: ClassRule::Excluded,
        symbols: ClassRule::Excluded,
        exclude_ambiguous: false,
        exclude: CharSet::EMPTY,
        symbol_set: None,
    };
    for length in [4usize, 20, 256] {
        let bits = single(length).entropy_bits().unwrap();
        assert!((bits - f(length) * 26f64.log2()).abs() < 1e-9);
    }
    // All 94 printable characters, nothing required: 20 × log2(94).
    let all_included = CharacterOptions {
        length: 20,
        lowercase: ClassRule::Included,
        uppercase: ClassRule::Included,
        digits: ClassRule::Included,
        symbols: ClassRule::Included,
        exclude_ambiguous: false,
        exclude: CharSet::EMPTY,
        symbol_set: None,
    };
    let bits = all_included.entropy_bits().unwrap();
    assert!((bits - 20.0 * 94f64.log2()).abs() < 1e-9);
    // Requiring classes removes a little: the default is just below 20 × log2(94) ≈ 131.09.
    let default_bits = CharacterOptions::default().entropy_bits().unwrap();
    assert!(
        default_bits < bits && default_bits > bits - 1.0,
        "{default_bits}"
    );
    // A generated password reports the same figure as its options.
    let pw = generate_password(&mut seeded_rng(5), &CharacterOptions::default()).unwrap();
    assert!((pw.entropy_bits() - default_bits).abs() < 1e-12);
    // Maximum length stays finite.
    let max = CharacterOptions {
        length: MAX_LENGTH,
        ..CharacterOptions::default()
    };
    assert!(max.entropy_bits().unwrap().is_finite());

    let pp = PassphraseOptions::default();
    assert!((pp.entropy_bits().unwrap() - 6.0 * 7776f64.log2()).abs() < 1e-9);
    assert!((pp.entropy_bits().unwrap() - 77.548).abs() < 0.001);
}

#[test]
fn ambiguous_exclusion() {
    let options = CharacterOptions {
        length: 256,
        exclude_ambiguous: true,
        ..CharacterOptions::default()
    };
    let alphabet = Alphabet::new(&options).unwrap();
    assert_eq!(alphabet.chars().len(), 94 - AMBIGUOUS.len());
    let mut rng = seeded_rng(6);
    for _ in 0..50 {
        let pw = generate_password(&mut rng, &options).unwrap();
        assert!(!pw.expose_secret().bytes().any(|b| AMBIGUOUS.contains(&b)));
    }
}

#[test]
fn every_required_class_appears() {
    let mut rng = seeded_rng(7);
    let options = CharacterOptions {
        length: 4,
        exclude_ambiguous: true,
        ..CharacterOptions::default()
    };
    for _ in 0..500 {
        let pw = generate_password(&mut rng, &options).unwrap();
        let b = pw.expose_secret().as_bytes();
        assert_eq!(b.len(), 4);
        assert!(b.iter().any(u8::is_ascii_lowercase));
        assert!(b.iter().any(u8::is_ascii_uppercase));
        assert!(b.iter().any(u8::is_ascii_digit));
        assert!(b.iter().any(u8::is_ascii_punctuation));
    }
}

#[test]
fn option_validation() {
    let mut rng = seeded_rng(8);
    let with = |length, rule| CharacterOptions {
        length,
        lowercase: rule,
        uppercase: rule,
        digits: rule,
        symbols: rule,
        exclude_ambiguous: false,
        exclude: CharSet::EMPTY,
        symbol_set: None,
    };
    for (options, err) in [
        (with(3, ClassRule::Included), GeneratorError::InvalidLength),
        (
            with(257, ClassRule::Included),
            GeneratorError::InvalidLength,
        ),
        (with(20, ClassRule::Excluded), GeneratorError::NoClasses),
    ] {
        assert_eq!(generate_password(&mut rng, &options).map(|_| ()), Err(err));
        assert_eq!(options.entropy_bits(), Err(err));
    }
    // Four required classes fit in four characters; ok.
    assert!(generate_password(&mut rng, &with(4, ClassRule::Required)).is_ok());

    for (words, sep, err) in [
        (2, '.', GeneratorError::InvalidWordCount),
        (21, '.', GeneratorError::InvalidWordCount),
        (6, '-', GeneratorError::InvalidSeparator),
        (6, 'a', GeneratorError::InvalidSeparator),
        (6, 'Z', GeneratorError::InvalidSeparator),
        (6, '\n', GeneratorError::InvalidSeparator),
        (6, '\u{7f}', GeneratorError::InvalidSeparator),
        (6, 'é', GeneratorError::InvalidSeparator),
    ] {
        let options = PassphraseOptions {
            words,
            separator: sep,
            capitalize: false,
            include_number: false,
        };
        assert_eq!(
            generate_passphrase(&mut rng, &options).map(|_| ()),
            Err(err),
            "{sep:?}"
        );
    }
    for sep in [' ', '.', '_', '3', '#', '~'] {
        let options = PassphraseOptions {
            separator: sep,
            ..PassphraseOptions::default()
        };
        assert!(generate_passphrase(&mut rng, &options).is_ok());
    }
}

#[test]
fn passphrases_are_words_from_the_list() {
    let words: std::collections::HashSet<&str> = core::str::from_utf8(wordlist::RAW)
        .unwrap()
        .lines()
        .map(|l| l.split_once('\t').unwrap().1)
        .collect();
    let mut rng = seeded_rng(9);
    for capitalize in [false, true] {
        let options = PassphraseOptions {
            words: 7,
            separator: ' ',
            capitalize,
            include_number: false,
        };
        for _ in 0..30 {
            let pp = generate_passphrase(&mut rng, &options).unwrap();
            let parts: Vec<&str> = pp.expose_secret().split(' ').collect();
            assert_eq!(parts.len(), 7);
            for part in parts {
                assert_eq!(part.as_bytes()[0].is_ascii_uppercase(), capitalize);
                assert!(words.contains(part.to_ascii_lowercase().as_str()), "{part}");
            }
            assert!((pp.entropy_bits() - 7.0 * 7776f64.log2()).abs() < 1e-9);
        }
    }
}

#[test]
fn passphrase_word_choice_is_uniform_and_deterministic() {
    // The constant-time slot scan picks exactly the word the index names.
    let mut rng = seeded_rng(10);
    let options = PassphraseOptions {
        words: 20,
        separator: ' ',
        capitalize: false,
        include_number: false,
    };
    let pp = generate_passphrase(&mut rng, &options).unwrap();
    let mut replay = seeded_rng(10);
    let list: Vec<&str> = core::str::from_utf8(wordlist::RAW)
        .unwrap()
        .lines()
        .map(|l| l.split_once('\t').unwrap().1)
        .collect();
    for word in pp.expose_secret().split(' ') {
        let index = uniform_index(&mut replay, 7776).unwrap() as usize;
        assert_eq!(word, list[index]);
    }
}

/// The embedded list's words, in list order.
fn word_list() -> Vec<&'static str> {
    core::str::from_utf8(wordlist::RAW)
        .unwrap()
        .lines()
        .map(|l| l.split_once('\t').unwrap().1)
        .collect()
}

/// The passphrase `rng` should produce, built the plain way: with the number, the word that
/// gets it and the digit first, then the named words, first letters uppercased, the digit
/// appended to its word, joined with the separator. The fixed-width layout must match it byte
/// for byte.
fn plain_passphrase(rng: &mut impl CryptoRng, options: &PassphraseOptions) -> String {
    let list = word_list();
    let number = options.include_number.then(|| {
        let word = uniform_index(rng, u32::try_from(options.words).unwrap()).unwrap() as usize;
        let digit = uniform_index(rng, 10).unwrap();
        (word, char::from_digit(digit, 10).unwrap())
    });
    let words: Vec<String> = (0..options.words)
        .map(|n| {
            let mut word = list[uniform_index(rng, 7776).unwrap() as usize].to_owned();
            if options.capitalize {
                word[..1].make_ascii_uppercase();
            }
            if let Some((at, digit)) = number
                && at == n
            {
                word.push(digit);
            }
            word
        })
        .collect();
    words.join(options.separator.to_string().as_str())
}

#[test]
fn passphrase_layout_matches_plain_concatenation() {
    // The two-pass layout changes how the passphrase is assembled, not what it is: for the same
    // RNG stream it gives exactly the bytes the plain concatenation gives, with and without the
    // number, and with a digit separator next to the digit.
    for seed in 0..4 {
        for words in [MIN_WORDS, MAX_WORDS] {
            for separator in [' ', '#', '3'] {
                for capitalize in [false, true] {
                    for include_number in [false, true] {
                        let options = PassphraseOptions {
                            words,
                            separator,
                            capitalize,
                            include_number,
                        };
                        let pp = generate_passphrase(&mut seeded_rng(20 + seed), &options).unwrap();
                        let expected = plain_passphrase(&mut seeded_rng(20 + seed), &options);
                        assert_eq!(pp.expose_secret(), expected, "{options:?}");
                        // Allocated once at the fixed-width size and truncated, never grown
                        // (§12.2).
                        assert_eq!(pp.value.capacity(), words * WORD_WIDTH);
                    }
                }
            }
        }
    }
}

#[test]
fn assemble_words_matches_plain_concatenation() {
    // The helper `generate_passphrase` must assemble through (§12.3); called directly, with
    // words of every length side by side, the shortest and longest included.
    let list = word_list();
    let mut picks: Vec<usize> = (3..=wordlist::MAX_WORD_LEN)
        .filter_map(|len| list.iter().position(|w| w.len() == len))
        .collect();
    let reversed: Vec<usize> = picks.iter().rev().copied().collect();
    picks.extend(reversed);
    for words in [1, 2, picks.len()] {
        for (separator, capitalize) in [(b' ', false), (b'#', true)] {
            let mut next = picks.iter();
            let out = assemble_words(words, separator, capitalize, None, |slot| {
                let n = *next.next().unwrap();
                wordlist::select_word(u32::try_from(n).unwrap(), slot);
                Ok(())
            })
            .unwrap();
            let expected: Vec<String> = picks[..words]
                .iter()
                .map(|&n| {
                    let mut word = list[n].to_owned();
                    if capitalize {
                        word[..1].make_ascii_uppercase();
                    }
                    word
                })
                .collect();
            let expected = expected.join(char::from(separator).to_string().as_str());
            assert_eq!(out.as_slice(), expected.as_bytes(), "{words} {separator}");
            assert_eq!(out.capacity(), words * WORD_WIDTH);
        }
    }
    // A failing selection is passed through.
    assert_eq!(
        assemble_words(3, b' ', false, None, |_| Err(GeneratorError::NoClasses)).map(|_| ()),
        Err(GeneratorError::NoClasses)
    );
}

#[test]
fn spread_word_puts_every_byte_at_a_fixed_offset() {
    let list = word_list();
    // One word of every length in the list, including the longest, whose separator takes the
    // region's last byte.
    for len in 3..=wordlist::MAX_WORD_LEN {
        let n = list.iter().position(|w| w.len() == len).unwrap();
        let word = list[n].as_bytes();
        let mut slot = [0u8; wordlist::SLOT];
        wordlist::select_word(u32::try_from(n).unwrap(), &mut slot);
        for separator in [Some(b'#'), None] {
            for capitalize in [false, true] {
                let mut region = [0xAAu8; WORD_WIDTH];
                spread_word(&mut region, &slot, separator, None, capitalize);
                let mut expected = [0u8; WORD_WIDTH];
                expected[..len].copy_from_slice(word);
                if let Some(sep) = separator {
                    expected[len] = sep;
                }
                if capitalize {
                    expected[0] = expected[0].to_ascii_uppercase();
                }
                assert_eq!(region, expected, "{} {separator:?} {capitalize}", list[n]);
            }
        }
    }
}

#[test]
fn constant_time_capitalisation_matches_to_ascii_uppercase() {
    // The select-based case flip agrees with `u8::to_ascii_uppercase` on every byte, so it
    // stays correct for any list, not only one whose words start with a lowercase letter.
    for b in 0..=u8::MAX {
        let mut slot = [0u8; wordlist::SLOT];
        slot[0] = 1;
        slot[1] = b;
        let mut region = [0u8; WORD_WIDTH];
        spread_word(&mut region, &slot, None, None, true);
        assert_eq!(region[0], b.to_ascii_uppercase(), "{b:#04x}");
        assert!(region[1..].iter().all(|&x| x == 0));
    }
}

#[test]
fn compact_keeps_the_non_zero_bytes_in_order() {
    let check = |wide: &[u8]| {
        let expected: Vec<u8> = wide.iter().copied().filter(|&b| b != 0).collect();
        let mut out = vec![0u8; wide.len()];
        let len = compact(wide, &mut out);
        assert_eq!(len, expected.len(), "{wide:?}");
        assert_eq!(out[..len], expected[..], "{wide:?}");
        assert!(out[len..].iter().all(|&b| b == 0), "{wide:?}");
    };
    check(&[]);
    check(&[0; 7]);
    check(b"abcdefg");
    check(&[0, 0, 0, b'z']);
    check(&[b'a', 0, 0, 0]);
    // Random layouts up to the largest passphrase, about half padding.
    let mut rng = seeded_rng(12);
    for _ in 0..300 {
        let len = uniform_index(&mut rng, u32::try_from(MAX_WORDS * WORD_WIDTH + 1).unwrap())
            .unwrap() as usize;
        let wide: Vec<u8> = (0..len)
            .map(|_| {
                let x = rng.next_u32();
                if x & 1 == 0 {
                    0
                } else {
                    u8::try_from(x >> 24).unwrap() | 1
                }
            })
            .collect();
        check(&wide);
    }
}

#[test]
fn ct_select_reads_the_indexed_element() {
    let set = b"abcdef";
    for (i, c) in (0u32..).zip(set) {
        assert_eq!(ct_select(set, i), *c);
    }
    assert_eq!(ct_select(set, 99), 0);
}

#[test]
fn debug_is_redacted() {
    let pw = generate_password(&mut seeded_rng(11), &CharacterOptions::default()).unwrap();
    let text = format!("{pw:?}");
    assert!(text.contains("[REDACTED]"));
    assert!(!text.contains(pw.expose_secret()));
}

// ---------------------------------------------------------------------------------------------
// Exclusions, custom symbols and the passphrase number.

/// Character options with the given rules and nothing excluded.
fn rules(
    length: usize,
    lowercase: ClassRule,
    uppercase: ClassRule,
    digits: ClassRule,
    symbols: ClassRule,
) -> CharacterOptions {
    CharacterOptions {
        length,
        lowercase,
        uppercase,
        digits,
        symbols,
        ..CharacterOptions::default()
    }
}

/// The password `rng` should produce, built the plain way from the documented rules, with no
/// constant-time machinery: the alphabet from the class strings in order, minus ambiguous and
/// excluded characters, symbols restricted to the custom set; then whole candidates drawn and
/// rejected until every required class appears.
fn plain_password(rng: &mut impl CryptoRng, options: &CharacterOptions) -> String {
    let symbols = options.symbol_set.unwrap_or(CharSet::from_ascii(SYMBOLS));
    let mut alphabet: Vec<(u8, usize)> = Vec::new();
    let mut required = Vec::new();
    for (k, (set, rule)) in [
        (LOWER, options.lowercase),
        (UPPER, options.uppercase),
        (DIGITS, options.digits),
        (SYMBOLS, options.symbols),
    ]
    .into_iter()
    .enumerate()
    {
        if rule == ClassRule::Excluded {
            continue;
        }
        if rule == ClassRule::Required {
            required.push(k);
        }
        for &c in set {
            let ambiguous = options.exclude_ambiguous && AMBIGUOUS.contains(&c);
            let custom_out = k == 3 && !symbols.contains(c);
            if !ambiguous && !options.exclude.contains(c) && !custom_out {
                alphabet.push((c, k));
            }
        }
    }
    let n = u32::try_from(alphabet.len()).unwrap();
    loop {
        let candidate: Vec<(u8, usize)> = (0..options.length)
            .map(|_| alphabet[uniform_index(rng, n).unwrap() as usize])
            .collect();
        if required
            .iter()
            .all(|k| candidate.iter().any(|(_, class)| class == k))
        {
            return candidate.iter().map(|(c, _)| char::from(*c)).collect();
        }
    }
}

#[test]
fn char_set_parsing() {
    assert_eq!(CharSet::parse(""), Ok(CharSet::EMPTY));
    let set = CharSet::parse("cab!a").unwrap();
    assert_eq!(set.len(), 4);
    assert_eq!(set, CharSet::parse("!abc").unwrap());
    assert_eq!(set.to_ascii_string(), "!abc");
    assert!(set.contains(b'a') && !set.contains(b'd') && !set.contains(200));
    for bad in [" ", "a b", "\n", "\t", "\u{7f}", "é", "\0"] {
        assert_eq!(
            CharSet::parse(bad),
            Err(GeneratorError::InvalidCharacterSet),
            "{bad:?}"
        );
    }
    // Up to MAX_SET_TEXT_LEN bytes are read; longer text is refused before it is scanned.
    let long = "!".repeat(MAX_SET_TEXT_LEN);
    assert_eq!(CharSet::parse(&long).unwrap().len(), 1);
    let longer = "!".repeat(MAX_SET_TEXT_LEN + 1);
    assert_eq!(
        CharSet::parse(&longer),
        Err(GeneratorError::InvalidCharacterSet)
    );
    // Every printable character fits; the full set is the 94 characters.
    let all: String = (b'!'..=b'~').map(char::from).collect();
    assert_eq!(CharSet::parse(&all).unwrap().len(), 94);
    assert_eq!(CharSet::from_ascii(SYMBOLS).len(), 32);
    assert!(CharSet::from_ascii(b"!?").is_subset(CharSet::from_ascii(SYMBOLS)));
    assert!(!CharSet::from_ascii(b"!a").is_subset(CharSet::from_ascii(SYMBOLS)));
}

#[test]
fn new_options_left_at_their_defaults_change_nothing() {
    // Defaults, and the full symbol set spelled out, draw exactly what the documented
    // algorithm draws from the same RNG stream: the new fields only ever remove characters.
    let spelled_out = CharacterOptions {
        symbol_set: Some(CharSet::from_ascii(SYMBOLS)),
        ..CharacterOptions::default()
    };
    for seed in 0..8 {
        for options in [
            CharacterOptions::default(),
            spelled_out,
            CharacterOptions {
                length: 4,
                exclude_ambiguous: true,
                ..CharacterOptions::default()
            },
        ] {
            let pw = generate_password(&mut seeded_rng(100 + seed), &options).unwrap();
            let expected = plain_password(&mut seeded_rng(100 + seed), &options);
            assert_eq!(pw.expose_secret(), expected, "{options:?}");
        }
        let default =
            generate_password(&mut seeded_rng(100 + seed), &CharacterOptions::default()).unwrap();
        let spelled = generate_password(&mut seeded_rng(100 + seed), &spelled_out).unwrap();
        assert_eq!(default.expose_secret(), spelled.expose_secret());
    }
    assert_eq!(
        CharacterOptions::default().entropy_bits(),
        spelled_out.entropy_bits()
    );
}

#[test]
fn exclusions_and_custom_symbols_follow_the_documented_algorithm() {
    let options = [
        CharacterOptions {
            exclude: CharSet::parse("abcXYZ019!").unwrap(),
            ..CharacterOptions::default()
        },
        CharacterOptions {
            length: 12,
            symbol_set: Some(CharSet::parse("@#_").unwrap()),
            exclude_ambiguous: true,
            ..CharacterOptions::default()
        },
        CharacterOptions {
            length: 6,
            lowercase: ClassRule::Included,
            symbols: ClassRule::Included,
            exclude: CharSet::parse("AEIOU0123").unwrap(),
            symbol_set: Some(CharSet::parse("!").unwrap()),
            ..CharacterOptions::default()
        },
    ];
    for (i, options) in (0u64..).zip(options) {
        for seed in 0..10 {
            let pw = generate_password(&mut seeded_rng(200 + 10 * i + seed), &options).unwrap();
            let expected = plain_password(&mut seeded_rng(200 + 10 * i + seed), &options);
            assert_eq!(pw.expose_secret(), expected, "{options:?}");
        }
    }
}

#[test]
fn excluded_characters_never_appear() {
    let exclude = CharSet::parse("abcXYZ019!@").unwrap();
    let options = CharacterOptions {
        length: 64,
        exclude,
        ..CharacterOptions::default()
    };
    assert_eq!(Alphabet::new(&options).unwrap().chars().len(), 94 - 11);
    let mut rng = seeded_rng(30);
    for _ in 0..200 {
        let pw = generate_password(&mut rng, &options).unwrap();
        assert!(!pw.expose_secret().bytes().any(|b| exclude.contains(b)));
    }
}

#[test]
fn custom_symbols_replace_the_default_set() {
    let options = CharacterOptions {
        length: 32,
        symbol_set: Some(CharSet::parse("#@!").unwrap()),
        ..CharacterOptions::default()
    };
    let alphabet = Alphabet::new(&options).unwrap();
    // Symbols in SYMBOLS order, whatever order they were typed in.
    assert_eq!(&alphabet.chars()[62..], b"!#@");
    let mut rng = seeded_rng(31);
    let mut seen = [false; 3];
    for _ in 0..200 {
        let pw = generate_password(&mut rng, &options).unwrap();
        for b in pw.expose_secret().bytes().filter(u8::is_ascii_punctuation) {
            let k = b"!#@".iter().position(|&s| s == b).unwrap();
            seen[k] = true;
        }
    }
    assert_eq!(seen, [true; 3]);
    // Entropy over the 65-character alphabet.
    let all_included = CharacterOptions {
        length: 20,
        lowercase: ClassRule::Included,
        uppercase: ClassRule::Included,
        digits: ClassRule::Included,
        symbols: ClassRule::Included,
        symbol_set: Some(CharSet::parse("!#@").unwrap()),
        ..CharacterOptions::default()
    };
    let bits = all_included.entropy_bits().unwrap();
    assert!((bits - 20.0 * 65f64.log2()).abs() < 1e-9, "{bits}");
}

#[test]
fn characters_stay_uniform_after_exclusions() {
    // Lowercase only, vowels excluded: 21 letters, each equally likely.
    let options = CharacterOptions {
        length: 64,
        lowercase: ClassRule::Required,
        uppercase: ClassRule::Excluded,
        digits: ClassRule::Excluded,
        symbols: ClassRule::Excluded,
        exclude: CharSet::parse("aeiou").unwrap(),
        ..CharacterOptions::default()
    };
    let consonants: Vec<u8> = LOWER
        .iter()
        .copied()
        .filter(|c| !b"aeiou".contains(c))
        .collect();
    let mut rng = seeded_rng(32);
    let mut counts = vec![0u64; 21];
    for _ in 0..1000 {
        let pw = generate_password(&mut rng, &options).unwrap();
        for b in pw.expose_secret().bytes() {
            counts[consonants.iter().position(|&c| c == b).unwrap()] += 1;
        }
    }
    let x2 = chi_square(&counts);
    assert!(x2 < bound(21), "chi-square {x2}");
    let bits = options.entropy_bits().unwrap();
    assert!((bits - 64.0 * 21f64.log2()).abs() < 1e-9);
}

#[test]
fn required_classes_after_exclusions_are_uniform_over_valid_strings() {
    // Lowercase reduced to {a, b} and digits to {7}, both required, length 4: alphabet
    // {a, b, 7}. The valid strings hold a letter and a 7: 3^4 − 2^4 − 1^4 = 64 of them, and
    // whole-candidate rejection must make each equally likely.
    let mut exclude: String = LOWER[2..].iter().map(|&c| char::from(c)).collect();
    exclude.push_str("012345689");
    let options = CharacterOptions {
        length: 4,
        lowercase: ClassRule::Required,
        uppercase: ClassRule::Excluded,
        digits: ClassRule::Required,
        symbols: ClassRule::Excluded,
        exclude: CharSet::parse(&exclude).unwrap(),
        ..CharacterOptions::default()
    };
    let mut valid: Vec<String> = Vec::new();
    for a in "ab7".chars() {
        for b in "ab7".chars() {
            for c in "ab7".chars() {
                for d in "ab7".chars() {
                    let s: String = [a, b, c, d].iter().collect();
                    if s.contains('7') && s.contains(['a', 'b']) {
                        valid.push(s);
                    }
                }
            }
        }
    }
    assert_eq!(valid.len(), 64);
    let bits = options.entropy_bits().unwrap();
    assert!((bits - 6.0).abs() < 1e-9, "{bits}");
    let mut rng = seeded_rng(33);
    let mut counts = vec![0u64; 64];
    for _ in 0..64_000 {
        let pw = generate_password(&mut rng, &options).unwrap();
        counts[valid.iter().position(|v| v == pw.expose_secret()).unwrap()] += 1;
    }
    let x2 = chi_square(&counts);
    assert!(x2 < bound(64), "chi-square {x2}");
}

#[test]
fn single_character_classes_give_every_permutation_equally() {
    // Each class reduced to one character, all required, length 4: the 24 orderings of
    // "aA0!" are the whole space (acceptance 24/256, above the floor).
    let options = CharacterOptions {
        length: 4,
        exclude: CharSet::parse(
            &(b'!'..=b'~')
                .filter(|c| !b"aA0!".contains(c))
                .map(char::from)
                .collect::<String>(),
        )
        .unwrap(),
        ..CharacterOptions::default()
    };
    let bits = options.entropy_bits().unwrap();
    assert!((bits - 24f64.log2()).abs() < 1e-9, "{bits}");
    let mut rng = seeded_rng(34);
    let mut seen: HashMap<String, u64> = HashMap::new();
    for _ in 0..24_000 {
        let pw = generate_password(&mut rng, &options).unwrap();
        *seen.entry(pw.expose_secret().to_owned()).or_default() += 1;
    }
    assert_eq!(seen.len(), 24);
    let counts: Vec<u64> = seen.values().copied().collect();
    let x2 = chi_square(&counts);
    assert!(x2 < bound(24), "chi-square {x2}");
}

#[test]
fn class_and_alphabet_errors_are_clear() {
    let mut rng = seeded_rng(35);
    let lower = CharSet::from_ascii(LOWER);
    let everything = CharSet::parse(&(b'!'..=b'~').map(char::from).collect::<String>()).unwrap();
    let cases = [
        // A required class fully excluded is refused, naming the class.
        (
            CharacterOptions {
                exclude: lower,
                ..CharacterOptions::default()
            },
            GeneratorError::RequiredClassEmpty(CharClass::Lowercase),
        ),
        (
            CharacterOptions {
                exclude: CharSet::from_ascii(DIGITS),
                ..CharacterOptions::default()
            },
            GeneratorError::RequiredClassEmpty(CharClass::Digits),
        ),
        (
            CharacterOptions {
                symbol_set: Some(CharSet::EMPTY),
                ..CharacterOptions::default()
            },
            GeneratorError::RequiredClassEmpty(CharClass::Symbols),
        ),
        (
            CharacterOptions {
                symbol_set: Some(CharSet::parse("!?").unwrap()),
                exclude: CharSet::parse("!?").unwrap(),
                ..CharacterOptions::default()
            },
            GeneratorError::RequiredClassEmpty(CharClass::Symbols),
        ),
        // Uppercase made empty by ambiguous exclusion is impossible; by the set it is not.
        (
            CharacterOptions {
                exclude: CharSet::from_ascii(UPPER),
                exclude_ambiguous: true,
                ..CharacterOptions::default()
            },
            GeneratorError::RequiredClassEmpty(CharClass::Uppercase),
        ),
        // Everything excluded: an empty alphabet, whatever the rules.
        (
            CharacterOptions {
                exclude: everything,
                ..rules(
                    20,
                    ClassRule::Included,
                    ClassRule::Included,
                    ClassRule::Included,
                    ClassRule::Included,
                )
            },
            GeneratorError::EmptyAlphabet,
        ),
        // No class enabled is still `NoClasses`, exclusions or not.
        (
            CharacterOptions {
                exclude: lower,
                ..rules(
                    20,
                    ClassRule::Excluded,
                    ClassRule::Excluded,
                    ClassRule::Excluded,
                    ClassRule::Excluded,
                )
            },
            GeneratorError::NoClasses,
        ),
    ];
    assert_refused(&mut rng, &cases);
}

#[test]
fn set_length_and_strictness_errors_are_clear() {
    let mut rng = seeded_rng(36);
    let lower = CharSet::from_ascii(LOWER);
    let cases = [
        // A custom symbol set must be ASCII punctuation, even while symbols are off.
        (
            CharacterOptions {
                symbol_set: Some(CharSet::parse("!a").unwrap()),
                ..CharacterOptions::default()
            },
            GeneratorError::InvalidSymbolSet,
        ),
        (
            CharacterOptions {
                symbol_set: Some(CharSet::parse("5").unwrap()),
                symbols: ClassRule::Excluded,
                ..CharacterOptions::default()
            },
            GeneratorError::InvalidSymbolSet,
        ),
        // Length bounds hold with the new options too.
        (
            CharacterOptions {
                length: MIN_LENGTH - 1,
                exclude: lower,
                ..CharacterOptions::default()
            },
            GeneratorError::InvalidLength,
        ),
        (
            CharacterOptions {
                length: MAX_LENGTH + 1,
                symbol_set: Some(CharSet::parse("!").unwrap()),
                ..CharacterOptions::default()
            },
            GeneratorError::InvalidLength,
        ),
        // Three required classes of one character each and 32 symbols, in 4 characters: about
        // one candidate in 1,950 passes, below the floor of one in 1,024.
        (
            CharacterOptions {
                length: 4,
                exclude: CharSet::parse(
                    &(b'!'..=b'~')
                        .filter(|c| c.is_ascii_alphanumeric() && !b"aA0".contains(c))
                        .map(char::from)
                        .collect::<String>(),
                )
                .unwrap(),
                ..CharacterOptions::default()
            },
            GeneratorError::RequirementsTooStrict,
        ),
    ];
    assert_refused(&mut rng, &cases);
}

#[test]
fn emptied_included_classes_and_strict_limits() {
    let mut rng = seeded_rng(37);
    let lower = CharSet::from_ascii(LOWER);
    // The same strict requirements at length 8 pass about one candidate in 160: accepted.
    let longer = CharacterOptions {
        length: 8,
        exclude: CharSet::parse(
            &(b'!'..=b'~')
                .filter(|c| c.is_ascii_alphanumeric() && !b"aA0".contains(c))
                .map(char::from)
                .collect::<String>(),
        )
        .unwrap(),
        ..CharacterOptions::default()
    };
    assert_eq!(longer.validate(), Ok(()));
    let share = acceptance(&Alphabet::new(&longer).unwrap(), 8);
    // Inclusion–exclusion written out for the classes {a}, {A}, {0} and the 32 symbols (N = 35).
    let p = |k: f64| (k / 35.0f64).powi(8);
    let expected =
        1.0 - 3.0 * p(34.0) - p(3.0) + 3.0 * p(33.0) + 3.0 * p(2.0) - p(32.0) - 3.0 * p(1.0);
    assert!((share - expected).abs() < 1e-12, "{share}");
    assert!(share > 1.0 / 160.0 && share < 1.0 / 150.0, "{share}");
    let pw = generate_password(&mut rng, &longer).unwrap();
    for c in ["a", "A", "0"] {
        assert!(pw.expose_secret().contains(c));
    }
    // An included class fully excluded simply contributes nothing.
    let included = CharacterOptions {
        lowercase: ClassRule::Included,
        exclude: lower,
        ..CharacterOptions::default()
    };
    let pw = generate_password(&mut rng, &included).unwrap();
    assert!(!pw.expose_secret().bytes().any(|b| b.is_ascii_lowercase()));
    let plain_upper_digits_symbols = CharacterOptions {
        lowercase: ClassRule::Excluded,
        ..CharacterOptions::default()
    };
    assert!(
        (included.entropy_bits().unwrap() - plain_upper_digits_symbols.entropy_bits().unwrap())
            .abs()
            < 1e-9
    );
    // An empty custom set with symbols only included is fine too.
    let no_symbols = CharacterOptions {
        symbols: ClassRule::Included,
        symbol_set: Some(CharSet::EMPTY),
        ..CharacterOptions::default()
    };
    let pw = generate_password(&mut rng, &no_symbols).unwrap();
    assert!(!pw.expose_secret().bytes().any(|b| b.is_ascii_punctuation()));
}

#[test]
fn acceptance_is_the_share_of_valid_strings() {
    // Brute force on a small space: digits {2..9} and symbols {!, #} required, length 4.
    let options = CharacterOptions {
        length: 4,
        lowercase: ClassRule::Excluded,
        uppercase: ClassRule::Excluded,
        digits: ClassRule::Required,
        symbols: ClassRule::Required,
        exclude: CharSet::parse("01").unwrap(),
        symbol_set: Some(CharSet::parse("#!").unwrap()),
        ..CharacterOptions::default()
    };
    let alphabet = Alphabet::new(&options).unwrap();
    let chars = alphabet.chars().to_vec();
    assert_eq!(chars, b"23456789!#");
    let mut valid = 0u64;
    for a in &chars {
        for b in &chars {
            for c in &chars {
                for d in &chars {
                    let s = [*a, *b, *c, *d];
                    if s.iter().any(u8::is_ascii_digit) && s.iter().any(u8::is_ascii_punctuation) {
                        valid += 1;
                    }
                }
            }
        }
    }
    assert_eq!(valid, 10u64.pow(4) - 8u64.pow(4) - 2u64.pow(4));
    assert!((acceptance(&alphabet, 4) - f(valid) / 10_000.0).abs() < 1e-12);
    let bits = options.entropy_bits().unwrap();
    assert!((bits - f(valid).log2()).abs() < 1e-9, "{bits}");
}

#[test]
fn passphrase_number_entropy() {
    for words in [MIN_WORDS, 6, MAX_WORDS] {
        let options = PassphraseOptions {
            words,
            include_number: true,
            ..PassphraseOptions::default()
        };
        let w = f(words);
        let expected = w * 7776f64.log2() + w.log2() + 10f64.log2();
        assert!((options.entropy_bits().unwrap() - expected).abs() < 1e-9);
        let pp = generate_passphrase(&mut seeded_rng(40), &options).unwrap();
        assert!((pp.entropy_bits() - expected).abs() < 1e-12);
        assert_eq!(options.validate(), Ok(()));
    }
    // Word-count bounds are unchanged by the number.
    for words in [MIN_WORDS - 1, MAX_WORDS + 1] {
        let options = PassphraseOptions {
            words,
            include_number: true,
            ..PassphraseOptions::default()
        };
        assert_eq!(options.validate(), Err(GeneratorError::InvalidWordCount));
        assert_eq!(
            generate_passphrase(&mut seeded_rng(41), &options).map(|_| ()),
            Err(GeneratorError::InvalidWordCount)
        );
    }
}

/// Splits a passphrase back into its words and its number (the word it follows and the digit),
/// as the module documentation says it can be: words are the runs of letters and `-`; between
/// two words stands the separator, or the digit and then the separator; after the last word,
/// nothing or the digit.
fn split_passphrase(text: &str, separator: u8, words: usize) -> (Vec<String>, Option<(usize, u8)>) {
    let bytes = text.as_bytes();
    let is_word = |b: u8| b.is_ascii_alphabetic() || b == b'-';
    let mut out = Vec::new();
    let mut number = None;
    let mut i = 0;
    for n in 0..words {
        let start = i;
        while i < bytes.len() && is_word(bytes[i]) {
            i += 1;
        }
        out.push(text[start..i].to_owned());
        let gap_start = i;
        while i < bytes.len() && !is_word(bytes[i]) {
            i += 1;
        }
        let gap = &bytes[gap_start..i];
        let last = n + 1 == words;
        let digit = match (gap, last) {
            ([], true) => None,
            ([d], true) => Some(*d),
            ([s], false) => {
                assert_eq!(*s, separator);
                None
            }
            ([d, s], false) => {
                assert_eq!(*s, separator);
                Some(*d)
            }
            _ => panic!("unexpected gap {gap:?}"),
        };
        if let Some(d) = digit {
            assert!(d.is_ascii_digit());
            assert!(number.is_none(), "one number only");
            number = Some((n, d));
        }
    }
    assert_eq!(i, bytes.len());
    (out, number)
}

#[test]
fn passphrase_number_splits_back_out() {
    // The result determines the words, the chosen word and the digit, so the space counted by
    // the entropy is the real one; checked against a replay of the RNG stream.
    let list = word_list();
    for separator in [' ', '.', '3', '#'] {
        let options = PassphraseOptions {
            words: 5,
            separator,
            capitalize: false,
            include_number: true,
        };
        for seed in 0..50 {
            let pp = generate_passphrase(&mut seeded_rng(500 + seed), &options).unwrap();
            let sep = u8::try_from(separator).unwrap();
            let (words, number) = split_passphrase(pp.expose_secret(), sep, 5);
            let mut replay = seeded_rng(500 + seed);
            let at = uniform_index(&mut replay, 5).unwrap() as usize;
            let digit = uniform_index(&mut replay, 10).unwrap();
            assert_eq!(number, Some((at, b'0' + u8::try_from(digit).unwrap())));
            for word in words {
                assert_eq!(
                    word,
                    list[uniform_index(&mut replay, 7776).unwrap() as usize]
                );
            }
        }
    }
}

#[test]
fn passphrase_number_position_and_digit_are_uniform() {
    let options = PassphraseOptions {
        words: MIN_WORDS,
        separator: ' ',
        capitalize: false,
        include_number: true,
    };
    let mut rng = seeded_rng(42);
    let mut digits = vec![0u64; 10];
    let mut positions = vec![0u64; MIN_WORDS];
    for _ in 0..4_000 {
        let pp = generate_passphrase(&mut rng, &options).unwrap();
        let (_, number) = split_passphrase(pp.expose_secret(), b' ', MIN_WORDS);
        let (at, d) = number.unwrap();
        positions[at] += 1;
        digits[usize::from(d - b'0')] += 1;
    }
    let x2 = chi_square(&digits);
    assert!(x2 < bound(10), "digits: chi-square {x2}");
    let x2 = chi_square(&positions);
    assert!(x2 < bound(MIN_WORDS), "positions: chi-square {x2}");
}

#[test]
fn spread_word_places_the_digit_at_a_fixed_rule() {
    let list = word_list();
    for len in 3..=wordlist::MAX_WORD_LEN {
        let n = list.iter().position(|w| w.len() == len).unwrap();
        let word = list[n].as_bytes();
        let mut slot = [0u8; wordlist::SLOT];
        wordlist::select_word(u32::try_from(n).unwrap(), &mut slot);
        for separator in [Some(b'#'), Some(b'7'), None] {
            for takes in [false, true] {
                let mut region = [0xAAu8; WORD_WIDTH];
                let digit = Some((Choice::from(u8::from(takes)), b'5'));
                spread_word(&mut region, &slot, separator, digit, false);
                let mut expected = vec![0u8; WORD_WIDTH];
                expected[..len].copy_from_slice(word);
                let mut at = len;
                if takes {
                    expected[at] = b'5';
                    at += 1;
                }
                if let Some(sep) = separator {
                    expected[at] = sep;
                }
                assert_eq!(
                    region.to_vec(),
                    expected,
                    "{} {separator:?} {takes}",
                    list[n]
                );
            }
        }
    }
}

#[test]
fn error_messages_carry_no_input() {
    for e in [
        GeneratorError::EmptyAlphabet,
        GeneratorError::RequiredClassEmpty(CharClass::Symbols),
        GeneratorError::RequirementsTooStrict,
        GeneratorError::InvalidCharacterSet,
        GeneratorError::InvalidSymbolSet,
    ] {
        assert!(!e.to_string().is_empty());
    }
}

/// Checks that every case is refused with its error by generation, entropy and validation.
fn assert_refused(rng: &mut impl CryptoRng, cases: &[(CharacterOptions, GeneratorError)]) {
    for (options, err) in cases {
        assert_eq!(
            generate_password(rng, options).map(|_| ()),
            Err(*err),
            "{options:?}"
        );
        assert_eq!(options.entropy_bits(), Err(*err));
        assert_eq!(options.validate(), Err(*err));
    }
}
