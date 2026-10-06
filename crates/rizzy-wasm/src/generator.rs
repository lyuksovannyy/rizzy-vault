//! The password generator (CRYPTO.md §12.1; ROADMAP §4.2 "generate"), as `rv generate` offers
//! it: characters or words, drawn from the CSPRNG in Rust. No session is needed.
//!
//! [`generate_password_with_options`] (`generatePasswordWithOptions`) and
//! [`generate_passphrase_with_options`] (`generatePassphraseWithOptions`) take every option of
//! `rizzy-core`'s generator; [`password_entropy`] (`passwordEntropy`) and
//! [`passphrase_entropy`] (`passphraseEntropy`) check the same options and give the entropy
//! without generating, for a live display; [`generator_limits`] (`generatorLimits`) gives the
//! bounds and the default character sets. Refused options throw a `generator_*` code
//! ([`generator_error`]), one per reason, so the UI can say what to change. There is one set of
//! calls, not two: the web vault's generator page and its in-editor generate slot both build
//! their requests from the same options and read the same `generator_*` codes.
//!
//! Every option arrives from JavaScript and is untrusted (ADR 0013 §3 rule 8): character sets
//! are parsed by [`CharSet::parse`], which reads at most [`MAX_SET_TEXT_LEN`] bytes, and the
//! separator must be exactly one character. Options are not secrets; the generated value is.

use core::fmt;

use rizzy_client::rizzy_core::generator::{
    AMBIGUOUS, CharClass, CharSet, CharacterOptions, ClassRule, GeneratorError, MAX_LENGTH,
    MAX_SET_TEXT_LEN, MAX_WORDS, MIN_LENGTH, MIN_WORDS, PassphraseOptions, SYMBOLS,
    generate_passphrase, generate_password,
};
use wasm_bindgen::prelude::wasm_bindgen;
use zeroize::Zeroizing;

use crate::error::CoreError;
use crate::rng::os_rng;

/// A generated password or passphrase and its entropy. The value is wiped when freed.
#[wasm_bindgen]
pub struct Generated {
    /// The value.
    value: Zeroizing<String>,
    /// `log2` of the space it was drawn from, uniformly.
    entropy_bits: f64,
}

impl fmt::Debug for Generated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Generated")
            .field("entropy_bits", &self.entropy_bits)
            .finish_non_exhaustive()
    }
}

#[wasm_bindgen]
impl Generated {
    /// The password or passphrase. A secret.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn value(&self) -> String {
        self.value.as_str().to_owned()
    }

    /// Its entropy in bits, for the UI.
    #[wasm_bindgen(getter, js_name = entropyBits)]
    #[must_use]
    pub fn entropy_bits(&self) -> f64 {
        self.entropy_bits
    }
}

impl From<rizzy_client::rizzy_core::generator::Generated> for Generated {
    fn from(generated: rizzy_client::rizzy_core::generator::Generated) -> Self {
        Self {
            value: Zeroizing::new(generated.expose_secret().to_owned()),
            entropy_bits: generated.entropy_bits(),
        }
    }
}

/// A class rule as JavaScript passes it: `0` excluded, `1` included, `2` required.
pub const RULE_EXCLUDED: u8 = 0;
/// See [`RULE_EXCLUDED`].
pub const RULE_INCLUDED: u8 = 1;
/// See [`RULE_EXCLUDED`].
pub const RULE_REQUIRED: u8 = 2;

/// The code of a class rule other than `0`, `1` or `2`.
pub const GENERATOR_INVALID_RULE: &str = "generator_invalid_rule";

/// The stable `generator_*` code of a refusal (module docs). Codes never change meaning.
///
/// | Error | Code |
/// |---|---|
/// | length out of range | `generator_invalid_length` |
/// | no class enabled | `generator_no_classes` |
/// | more required classes than characters | `generator_too_many_required` |
/// | every character excluded | `generator_empty_alphabet` |
/// | a required class left empty | `generator_required_lowercase_empty`, `…_uppercase_…`, `…_digits_…`, `…_symbols_…` |
/// | required classes too small for the length | `generator_requirements_too_strict` |
/// | a character set with a character outside `!`..=`~`, or too long | `generator_invalid_character_set` |
/// | custom symbols that are not ASCII punctuation | `generator_invalid_symbol_set` |
/// | word count out of range | `generator_invalid_word_count` |
/// | separator not allowed | `generator_invalid_separator` |
/// | RNG failure | `generator_rng_failure` |
/// | anything a later `rizzy-core` adds | `generator_invalid_options` |
#[must_use]
pub fn generator_error(e: GeneratorError) -> CoreError {
    CoreError::new(match e {
        GeneratorError::InvalidLength => "generator_invalid_length",
        GeneratorError::NoClasses => "generator_no_classes",
        GeneratorError::TooManyRequiredClasses => "generator_too_many_required",
        GeneratorError::EmptyAlphabet => "generator_empty_alphabet",
        GeneratorError::RequiredClassEmpty(CharClass::Lowercase) => {
            "generator_required_lowercase_empty"
        }
        GeneratorError::RequiredClassEmpty(CharClass::Uppercase) => {
            "generator_required_uppercase_empty"
        }
        GeneratorError::RequiredClassEmpty(CharClass::Digits) => "generator_required_digits_empty",
        GeneratorError::RequiredClassEmpty(CharClass::Symbols) => {
            "generator_required_symbols_empty"
        }
        GeneratorError::RequirementsTooStrict => "generator_requirements_too_strict",
        GeneratorError::InvalidCharacterSet => "generator_invalid_character_set",
        GeneratorError::InvalidSymbolSet => "generator_invalid_symbol_set",
        GeneratorError::InvalidWordCount => "generator_invalid_word_count",
        GeneratorError::InvalidSeparator => "generator_invalid_separator",
        GeneratorError::RngExhausted => "generator_rng_failure",
        _ => "generator_invalid_options",
    })
}

/// A class rule from its number ([`RULE_EXCLUDED`]).
fn rule(value: u8) -> Result<ClassRule, CoreError> {
    match value {
        RULE_EXCLUDED => Ok(ClassRule::Excluded),
        RULE_INCLUDED => Ok(ClassRule::Included),
        RULE_REQUIRED => Ok(ClassRule::Required),
        _ => Err(CoreError::new(GENERATOR_INVALID_RULE)),
    }
}

/// Builds character options from what JavaScript passes, checking each value: rules are `0`,
/// `1` or `2`, `exclude` and `symbol_set` are parsed by [`CharSet::parse`] (at most
/// [`MAX_SET_TEXT_LEN`] bytes of printable ASCII other than space). `symbol_set` `None`
/// means the default 32 symbols. The options as a whole are checked by the generator.
///
/// # Errors
/// [`GENERATOR_INVALID_RULE`] or `generator_invalid_character_set` ([`generator_error`]).
#[expect(
    clippy::too_many_arguments,
    reason = "the flat argument list is the wasm-bindgen signature; JavaScript passes plain values"
)]
pub fn password_options(
    length: usize,
    lowercase: u8,
    uppercase: u8,
    digits: u8,
    symbols: u8,
    exclude_ambiguous: bool,
    exclude: &str,
    symbol_set: Option<&str>,
) -> Result<CharacterOptions, CoreError> {
    Ok(CharacterOptions {
        length,
        lowercase: rule(lowercase)?,
        uppercase: rule(uppercase)?,
        digits: rule(digits)?,
        symbols: rule(symbols)?,
        exclude_ambiguous,
        exclude: CharSet::parse(exclude).map_err(generator_error)?,
        symbol_set: symbol_set
            .map(CharSet::parse)
            .transpose()
            .map_err(generator_error)?,
    })
}

/// Builds passphrase options from what JavaScript passes. `separator` must be exactly one
/// character; which characters are allowed is the generator's check.
///
/// # Errors
/// `generator_invalid_separator` ([`generator_error`]) for an empty or longer separator.
pub fn passphrase_options(
    words: usize,
    separator: &str,
    capitalize: bool,
    include_number: bool,
) -> Result<PassphraseOptions, CoreError> {
    let mut chars = separator.chars();
    let (Some(separator), None) = (chars.next(), chars.next()) else {
        return Err(generator_error(GeneratorError::InvalidSeparator));
    };
    Ok(PassphraseOptions {
        words,
        separator,
        capitalize,
        include_number,
    })
}

/// A password with every option of the generator: `length` characters; each class's rule
/// ([`RULE_EXCLUDED`] `0`, [`RULE_INCLUDED`] `1`, [`RULE_REQUIRED`] `2`); ambiguous
/// characters left out if asked; the characters of `exclude` never used; the symbols limited
/// to those of `symbol_set` if given (a subset of the 32 ASCII punctuation characters).
///
/// # Errors
/// A `generator_*` code ([`generator_error`], [`GENERATOR_INVALID_RULE`]).
#[wasm_bindgen(js_name = generatePasswordWithOptions)]
#[expect(
    clippy::too_many_arguments,
    reason = "the flat argument list is the wasm-bindgen signature; JavaScript passes plain values"
)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "wasm-bindgen passes an optional string by value"
)]
pub fn generate_password_with_options(
    length: usize,
    lowercase: u8,
    uppercase: u8,
    digits: u8,
    symbols: u8,
    exclude_ambiguous: bool,
    exclude: &str,
    symbol_set: Option<String>,
) -> Result<Generated, CoreError> {
    let options = password_options(
        length,
        lowercase,
        uppercase,
        digits,
        symbols,
        exclude_ambiguous,
        exclude,
        symbol_set.as_deref(),
    )?;
    Ok(generate_password(&mut os_rng(), &options)
        .map_err(generator_error)?
        .into())
}

/// The entropy, in bits, of a password with these options (as
/// [`generate_password_with_options`]), without generating one: the options are checked the
/// same way, so this also validates them for a live display.
///
/// # Errors
/// As [`generate_password_with_options`].
#[wasm_bindgen(js_name = passwordEntropy)]
#[expect(
    clippy::too_many_arguments,
    reason = "the flat argument list is the wasm-bindgen signature; JavaScript passes plain values"
)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "wasm-bindgen passes an optional string by value"
)]
pub fn password_entropy(
    length: usize,
    lowercase: u8,
    uppercase: u8,
    digits: u8,
    symbols: u8,
    exclude_ambiguous: bool,
    exclude: &str,
    symbol_set: Option<String>,
) -> Result<f64, CoreError> {
    password_options(
        length,
        lowercase,
        uppercase,
        digits,
        symbols,
        exclude_ambiguous,
        exclude,
        symbol_set.as_deref(),
    )?
    .entropy_bits()
    .map_err(generator_error)
}

/// A passphrase with every option of the generator: `words` words, joined by `separator`
/// (one printable ASCII character, not a letter and not `-`), capitalised if asked, with one
/// digit appended to one word if `include_number`.
///
/// # Errors
/// A `generator_*` code ([`generator_error`]).
#[wasm_bindgen(js_name = generatePassphraseWithOptions)]
pub fn generate_passphrase_with_options(
    words: usize,
    separator: &str,
    capitalize: bool,
    include_number: bool,
) -> Result<Generated, CoreError> {
    let options = passphrase_options(words, separator, capitalize, include_number)?;
    Ok(generate_passphrase(&mut os_rng(), &options)
        .map_err(generator_error)?
        .into())
}

/// The entropy, in bits, of a passphrase with these options, without generating one.
///
/// # Errors
/// As [`generate_passphrase_with_options`].
#[wasm_bindgen(js_name = passphraseEntropy)]
pub fn passphrase_entropy(
    words: usize,
    separator: &str,
    capitalize: bool,
    include_number: bool,
) -> Result<f64, CoreError> {
    passphrase_options(words, separator, capitalize, include_number)?
        .entropy_bits()
        .map_err(generator_error)
}

/// The generator's bounds and default character sets, for the UI's controls.
#[wasm_bindgen]
#[derive(Clone, Copy, Debug)]
pub struct GeneratorLimits;

#[wasm_bindgen]
impl GeneratorLimits {
    /// Shortest password.
    #[wasm_bindgen(getter, js_name = minLength)]
    #[must_use]
    pub fn min_length(&self) -> usize {
        MIN_LENGTH
    }

    /// Longest password.
    #[wasm_bindgen(getter, js_name = maxLength)]
    #[must_use]
    pub fn max_length(&self) -> usize {
        MAX_LENGTH
    }

    /// Fewest passphrase words.
    #[wasm_bindgen(getter, js_name = minWords)]
    #[must_use]
    pub fn min_words(&self) -> usize {
        MIN_WORDS
    }

    /// Most passphrase words.
    #[wasm_bindgen(getter, js_name = maxWords)]
    #[must_use]
    pub fn max_words(&self) -> usize {
        MAX_WORDS
    }

    /// The default symbols, the 32 ASCII punctuation characters; a custom set is a subset.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn symbols(&self) -> String {
        String::from_utf8_lossy(SYMBOLS).into_owned()
    }

    /// The characters "exclude ambiguous" leaves out.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn ambiguous(&self) -> String {
        String::from_utf8_lossy(AMBIGUOUS).into_owned()
    }

    /// The longest exclude or symbol-set text, in bytes.
    #[wasm_bindgen(getter, js_name = maxSetTextLength)]
    #[must_use]
    pub fn max_set_text_length(&self) -> usize {
        MAX_SET_TEXT_LEN
    }
}

/// The generator's bounds and default character sets ([`GeneratorLimits`]).
#[wasm_bindgen(js_name = generatorLimits)]
#[must_use]
pub fn generator_limits() -> GeneratorLimits {
    GeneratorLimits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_option_reaches_the_generator() {
        let password =
            generate_password_with_options(40, 2, 1, 2, 2, true, "abc", Some("#!".into())).unwrap();
        let value = password.value();
        assert_eq!(value.len(), 40);
        assert!(!value.contains(['a', 'b', 'c']));
        assert!(
            value
                .chars()
                .filter(char::is_ascii_punctuation)
                .all(|c| c == '#' || c == '!')
        );
        assert!(value.chars().any(|c| c.is_ascii_digit()));
        let bits = password_entropy(40, 2, 1, 2, 2, true, "abc", Some("#!".into())).unwrap();
        assert!((bits - password.entropy_bits()).abs() < 1e-12);

        let phrase = generate_passphrase_with_options(4, " ", true, true).unwrap();
        let value = phrase.value();
        assert_eq!(value.split(' ').count(), 4);
        assert_eq!(value.chars().filter(char::is_ascii_digit).count(), 1);
        assert!(
            value
                .split(' ')
                .all(|w| w.starts_with(|c: char| c.is_ascii_uppercase()))
        );
        let bits = passphrase_entropy(4, " ", true, true).unwrap();
        assert!((bits - phrase.entropy_bits()).abs() < 1e-12);
        assert!((bits - (4.0 * 7776f64.log2() + 2.0 + 10f64.log2())).abs() < 1e-9);
    }

    #[test]
    fn refusals_have_one_code_each() {
        let code = |r: Result<f64, CoreError>| r.err().map(|e| e.as_str());
        assert_eq!(
            code(password_entropy(3, 2, 2, 2, 2, false, "", None)),
            Some("generator_invalid_length")
        );
        assert_eq!(
            code(password_entropy(20, 0, 0, 0, 0, false, "", None)),
            Some("generator_no_classes")
        );
        assert_eq!(
            code(password_entropy(20, 3, 2, 2, 2, false, "", None)),
            Some(GENERATOR_INVALID_RULE)
        );
        assert_eq!(
            code(password_entropy(20, 2, 2, 2, 2, false, "0123456789", None)),
            Some("generator_required_digits_empty")
        );
        assert_eq!(
            code(password_entropy(
                20,
                2,
                2,
                2,
                2,
                false,
                "",
                Some(String::new())
            )),
            Some("generator_required_symbols_empty")
        );
        assert_eq!(
            code(password_entropy(20, 2, 2, 2, 2, false, "a b", None)),
            Some("generator_invalid_character_set")
        );
        assert_eq!(
            code(password_entropy(
                20,
                2,
                2,
                2,
                2,
                false,
                "",
                Some("!a".into())
            )),
            Some("generator_invalid_symbol_set")
        );
        let everything: String = (b'!'..=b'~').map(char::from).collect();
        assert_eq!(
            code(password_entropy(20, 1, 1, 1, 1, false, &everything, None)),
            Some("generator_empty_alphabet")
        );
        assert_eq!(
            code(passphrase_entropy(2, ".", false, false)),
            Some("generator_invalid_word_count")
        );
        for separator in ["", "..", "-", "a", "é"] {
            assert_eq!(
                code(passphrase_entropy(6, separator, false, false)),
                Some("generator_invalid_separator"),
                "{separator:?}"
            );
        }
        let limits = generator_limits();
        assert_eq!(
            (
                limits.min_length(),
                limits.max_length(),
                limits.min_words(),
                limits.max_words()
            ),
            (4, 256, 3, 20)
        );
        assert_eq!(limits.symbols().len(), 32);
        assert_eq!(limits.ambiguous(), "lIo0O1|");
        assert_eq!(limits.max_set_text_length(), 256);
    }
}
