// Generator bounds, defaults and refusal wording, mirrored from `@rizzy-vault/core`'s
// `GENERATOR_LIMITS` / `DEFAULT_PASSWORD_OPTIONS` / `DEFAULT_PASSPHRASE_OPTIONS` /
// `GENERATOR_ERROR_MESSAGES`.
//
// They are copied, not re-exported, because this file is loaded on the UI thread, which holds
// no wasm instance and imports only types from `@rizzy-vault/core` (ADR 0013 §4; the eslint
// rule over `apps/web/src/**` enforces it). The values behind them come from Rust
// (`crates/rizzy-wasm/src/generator.rs`); `generator-constants.test.ts` calls the real
// `@rizzy-vault/core` (allowed in `test/**`, which is Node, not the vault page) and checks this
// copy against it, so a value that drifts fails that test instead of silently going stale.
import type { GeneratorLimits, PassphraseOptions, PasswordOptions } from "@rizzy-vault/core";

/** `rizzy-core`'s generator bounds and default character sets. */
export const GENERATOR_LIMITS: GeneratorLimits = {
  minLength: 4,
  maxLength: 256,
  minWords: 3,
  maxWords: 20,
  symbols: "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
  ambiguous: "lIo0O1|",
  maxSetTextLength: 256,
};

/** `rizzy-core`'s defaults: 20 characters, every class required, nothing excluded. */
export const DEFAULT_PASSWORD_OPTIONS: PasswordOptions = {
  length: 20,
  lowercase: "required",
  uppercase: "required",
  digits: "required",
  symbols: "required",
  excludeAmbiguous: false,
  exclude: "",
  symbolSet: null,
};

/** `rizzy-core`'s defaults: six words separated by `.`, not capitalised, no number. */
export const DEFAULT_PASSPHRASE_OPTIONS: PassphraseOptions = {
  words: 6,
  separator: ".",
  capitalize: false,
  includeNumber: false,
};

/** The sentence for each `generator_*` code the core throws (packages/core's own wording). */
export const GENERATOR_ERROR_MESSAGES: Readonly<Record<string, string>> = Object.freeze({
  generator_invalid_length: `Length must be between ${GENERATOR_LIMITS.minLength} and ${GENERATOR_LIMITS.maxLength} characters.`,
  generator_no_classes: "Turn on at least one kind of character.",
  generator_too_many_required: "The password is shorter than the number of required kinds of character.",
  generator_empty_alphabet: "Every character is excluded. Exclude fewer characters.",
  generator_required_lowercase_empty: "Lowercase letters are required, but all of them are excluded.",
  generator_required_uppercase_empty: "Uppercase letters are required, but all of them are excluded.",
  generator_required_digits_empty: "Digits are required, but all of them are excluded.",
  generator_required_symbols_empty: "Symbols are required, but none is left to use.",
  generator_requirements_too_strict:
    "So few characters are left that a password would rarely contain every required kind. Exclude fewer characters, require fewer kinds, or make it longer.",
  generator_invalid_character_set: `Use printable ASCII characters only, without spaces, at most ${GENERATOR_LIMITS.maxSetTextLength}.`,
  generator_invalid_symbol_set: "Custom symbols must be ASCII punctuation characters.",
  generator_invalid_word_count: `A passphrase has between ${GENERATOR_LIMITS.minWords} and ${GENERATOR_LIMITS.maxWords} words.`,
  generator_invalid_separator: "The separator must be one printable ASCII character that is not a letter or a hyphen.",
  generator_invalid_rule: "Each kind of character is excluded, included or required.",
  generator_rng_failure: "The random number generator failed. Reload the page.",
  generator_invalid_options: "These generator options are not valid.",
});

/** The sentence for a `generator_*` code; a generic one for any other code. */
export function generatorErrorMessage(code: string): string {
  return GENERATOR_ERROR_MESSAGES[code] ?? "These generator options are not valid.";
}
