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

/// The passphrase `rng` should produce, built the plain way: the named words, first letters
/// uppercased, joined with the separator. The fixed-width layout must match it byte for byte.
fn plain_passphrase(rng: &mut impl CryptoRng, options: &PassphraseOptions) -> String {
    let list = word_list();
    let words: Vec<String> = (0..options.words)
        .map(|_| {
            let mut word = list[uniform_index(rng, 7776).unwrap() as usize].to_owned();
            if options.capitalize {
                word[..1].make_ascii_uppercase();
            }
            word
        })
        .collect();
    words.join(options.separator.to_string().as_str())
}

#[test]
fn passphrase_layout_matches_plain_concatenation() {
    // The two-pass layout changes how the passphrase is assembled, not what it is: for the same
    // RNG stream it gives exactly the bytes the plain concatenation gives.
    for seed in 0..4 {
        for words in [MIN_WORDS, MAX_WORDS] {
            for separator in [' ', '#'] {
                for capitalize in [false, true] {
                    let options = PassphraseOptions {
                        words,
                        separator,
                        capitalize,
                    };
                    let pp = generate_passphrase(&mut seeded_rng(20 + seed), &options).unwrap();
                    let expected = plain_passphrase(&mut seeded_rng(20 + seed), &options);
                    assert_eq!(pp.expose_secret(), expected, "{options:?}");
                    // Allocated once at the fixed-width size and truncated, never grown (§12.2).
                    assert_eq!(pp.value.capacity(), words * WORD_WIDTH);
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
            let out = assemble_words(words, separator, capitalize, |slot| {
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
        assemble_words(3, b' ', false, |_| Err(GeneratorError::NoClasses)).map(|_| ()),
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
                spread_word(&mut region, &slot, separator, capitalize);
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
        spread_word(&mut region, &slot, None, true);
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
