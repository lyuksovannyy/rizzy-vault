// The generator with every option, through packages/core: defaults, each option's effect on
// the output, entropy without generating, and one stable code and message per refusal.
import { beforeAll, describe, expect, it } from "vitest";

import {
  CoreError,
  DEFAULT_PASSPHRASE_OPTIONS,
  DEFAULT_PASSWORD_OPTIONS,
  GENERATOR_ERROR_MESSAGES,
  GENERATOR_LIMITS,
  type PasswordOptions,
  checkPassphraseOptions,
  checkPasswordOptions,
  generatePassphraseWithOptions,
  generatePasswordWithOptions,
  generatorErrorMessage,
  generatorLimits,
  passphraseEntropy,
  passwordEntropy,
} from "../src/index.js";
import { loadCore } from "./load.js";

beforeAll(() => {
  loadCore();
});

/** The code a call throws, or `undefined`. */
function codeOf(f: () => unknown): string | undefined {
  try {
    f();
    return undefined;
  } catch (e) {
    expect(e).toBeInstanceOf(CoreError);
    return (e as CoreError).code;
  }
}

/** Every printable ASCII character but space. */
const PRINTABLE = Array.from({ length: 94 }, (_, i) => String.fromCharCode(33 + i)).join("");

describe("defaults and limits", () => {
  it("match rizzy-core", () => {
    expect(generatorLimits()).toEqual(GENERATOR_LIMITS);
    expect(DEFAULT_PASSWORD_OPTIONS).toEqual({
      length: 20,
      lowercase: "required",
      uppercase: "required",
      digits: "required",
      symbols: "required",
      excludeAmbiguous: false,
      exclude: "",
      symbolSet: null,
    });
    expect(DEFAULT_PASSPHRASE_OPTIONS).toEqual({
      words: 6,
      separator: ".",
      capitalize: false,
      includeNumber: false,
    });
    expect(Object.isFrozen(DEFAULT_PASSWORD_OPTIONS)).toBe(true);
  });

  it("generate with no options at all", () => {
    const password = generatePasswordWithOptions();
    expect(password.value).toHaveLength(20);
    expect(password.entropyBits).toBeCloseTo(passwordEntropy(), 9);
    const phrase = generatePassphraseWithOptions();
    expect(phrase.value.split(".")).toHaveLength(6);
    expect(phrase.entropyBits).toBeCloseTo(6 * Math.log2(7776), 9);
  });
});

describe("password options", () => {
  it("leave out excluded characters and use only the custom symbols", () => {
    for (let i = 0; i < 20; i++) {
      const { value } = generatePasswordWithOptions({
        length: 40,
        exclude: "abcXYZ019",
        symbolSet: "#_",
      });
      expect(value).toHaveLength(40);
      expect(value).not.toMatch(/[abcXYZ019]/);
      expect(value).toMatch(/[#_]/);
      expect(value.replace(/[A-Za-z0-9#_]/g, "")).toBe("");
    }
  });

  it("follow the class rules", () => {
    const digitsOnly = generatePasswordWithOptions({
      length: 12,
      lowercase: "excluded",
      uppercase: "excluded",
      symbols: "excluded",
    });
    expect(digitsOnly.value).toMatch(/^[0-9]{12}$/);
    expect(digitsOnly.entropyBits).toBeCloseTo(12 * Math.log2(10), 9);
    const ambiguous = generatePasswordWithOptions({ length: 200, excludeAmbiguous: true });
    expect(ambiguous.value).not.toMatch(/[lIo0O1|]/);
  });

  it("report entropy over the alphabet that is left", () => {
    const options: Partial<PasswordOptions> = {
      length: 20,
      lowercase: "included",
      uppercase: "included",
      digits: "included",
      symbols: "included",
      symbolSet: "!#@",
    };
    expect(passwordEntropy(options)).toBeCloseTo(20 * Math.log2(65), 9);
    const check = checkPasswordOptions(options);
    expect(check.ok).toBe(true);
    // A set is a set: order and repeats change nothing.
    expect(passwordEntropy({ ...options, symbolSet: "@@#!" })).toBeCloseTo(
      passwordEntropy(options),
      12,
    );
  });

  it("allow an included class to be excluded entirely", () => {
    const { value } = generatePasswordWithOptions({
      lowercase: "included",
      exclude: "abcdefghijklmnopqrstuvwxyz",
    });
    expect(value).not.toMatch(/[a-z]/);
  });
});

describe("passphrase options", () => {
  it("separate, capitalise and add one digit", () => {
    for (let i = 0; i < 20; i++) {
      const { value, entropyBits } = generatePassphraseWithOptions({
        words: 4,
        separator: " ",
        capitalize: true,
        includeNumber: true,
      });
      const words = value.split(" ");
      expect(words).toHaveLength(4);
      expect(words.every((w) => /^[A-Z][a-z-]*[0-9]?$/.test(w))).toBe(true);
      expect(value.replace(/[^0-9]/g, "")).toHaveLength(1);
      expect(entropyBits).toBeCloseTo(4 * Math.log2(7776) + 2 + Math.log2(10), 9);
    }
    expect(passphraseEntropy({ words: 5 })).toBeCloseTo(5 * Math.log2(7776), 9);
  });
});

describe("refusals", () => {
  it("have one code each, with a message", () => {
    const cases: [() => unknown, string][] = [
      [() => generatePasswordWithOptions({ length: 3 }), "generator_invalid_length"],
      [() => generatePasswordWithOptions({ length: 257 }), "generator_invalid_length"],
      [() => generatePasswordWithOptions({ length: 4.5 }), "generator_invalid_length"],
      [() => generatePasswordWithOptions({ length: -1 }), "generator_invalid_length"],
      [() => passwordEntropy({ length: Number.NaN }), "generator_invalid_length"],
      [
        () =>
          passwordEntropy({
            lowercase: "excluded",
            uppercase: "excluded",
            digits: "excluded",
            symbols: "excluded",
          }),
        "generator_no_classes",
      ],
      [() => passwordEntropy({ exclude: "0123456789" }), "generator_required_digits_empty"],
      [
        () => passwordEntropy({ exclude: "ABCDEFGHIJKLMNOPQRSTUVWXYZ" }),
        "generator_required_uppercase_empty",
      ],
      [
        () => passwordEntropy({ exclude: "abcdefghijklmnopqrstuvwxyz" }),
        "generator_required_lowercase_empty",
      ],
      [() => passwordEntropy({ symbolSet: "" }), "generator_required_symbols_empty"],
      [
        () =>
          passwordEntropy({
            lowercase: "included",
            uppercase: "included",
            digits: "included",
            symbols: "included",
            exclude: PRINTABLE,
          }),
        "generator_empty_alphabet",
      ],
      [
        () =>
          passwordEntropy({
            length: 4,
            exclude: PRINTABLE.replace(/[^A-Za-z0-9]/g, "").replace(/[aA0]/g, ""),
          }),
        "generator_requirements_too_strict",
      ],
      [() => passwordEntropy({ exclude: "a b" }), "generator_invalid_character_set"],
      [() => passwordEntropy({ exclude: "é" }), "generator_invalid_character_set"],
      [() => passwordEntropy({ exclude: "!".repeat(257) }), "generator_invalid_character_set"],
      [() => passwordEntropy({ symbolSet: "!a" }), "generator_invalid_symbol_set"],
      [
        () => passwordEntropy({ symbols: "excluded", symbolSet: "5" }),
        "generator_invalid_symbol_set",
      ],
      [
        () => passwordEntropy({ lowercase: "sometimes" as unknown as "required" }),
        "generator_invalid_rule",
      ],
      [() => generatePassphraseWithOptions({ words: 2 }), "generator_invalid_word_count"],
      [() => passphraseEntropy({ words: 21 }), "generator_invalid_word_count"],
      [() => passphraseEntropy({ words: 6.5 }), "generator_invalid_word_count"],
      [() => passphraseEntropy({ separator: "" }), "generator_invalid_separator"],
      [() => passphraseEntropy({ separator: ".." }), "generator_invalid_separator"],
      [() => passphraseEntropy({ separator: "-" }), "generator_invalid_separator"],
      [() => passphraseEntropy({ separator: "a" }), "generator_invalid_separator"],
    ];
    for (const [f, code] of cases) {
      expect(codeOf(f), code).toBe(code);
      expect(GENERATOR_ERROR_MESSAGES[code], code).toBeTruthy();
    }
  });

  it("come back from the checks as a code and a sentence", () => {
    const check = checkPasswordOptions({ exclude: "0123456789" });
    expect(check).toEqual({
      ok: false,
      code: "generator_required_digits_empty",
      message: GENERATOR_ERROR_MESSAGES.generator_required_digits_empty,
    });
    const phrase = checkPassphraseOptions({ words: 2 });
    expect(phrase.ok).toBe(false);
    expect(checkPassphraseOptions({ words: 3, includeNumber: true })).toEqual({
      ok: true,
      entropyBits: passphraseEntropy({ words: 3, includeNumber: true }),
    });
    expect(generatorErrorMessage("something_else")).toBe(
      GENERATOR_ERROR_MESSAGES.generator_invalid_options,
    );
  });
});
