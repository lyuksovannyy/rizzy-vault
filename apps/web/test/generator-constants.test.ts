// `generator-constants.ts` copies values out of `@rizzy-vault/core` (its module docs say why:
// the UI thread imports only types from that package). This test is the check that the copy
// has not drifted from the real thing — it is the one place in `apps/web` allowed to import
// `@rizzy-vault/core` at runtime (eslint config: `test/**` runs in Node, not the vault page).
import {
  GENERATOR_ERROR_MESSAGES as CORE_GENERATOR_ERROR_MESSAGES,
  GENERATOR_LIMITS as CORE_GENERATOR_LIMITS,
  DEFAULT_PASSPHRASE_OPTIONS as CORE_DEFAULT_PASSPHRASE_OPTIONS,
  DEFAULT_PASSWORD_OPTIONS as CORE_DEFAULT_PASSWORD_OPTIONS,
  generatorErrorMessage as coreGeneratorErrorMessage,
  generatorLimits,
} from "@rizzy-vault/core";
import { beforeAll, describe, expect, it } from "vitest";

import {
  DEFAULT_PASSPHRASE_OPTIONS,
  DEFAULT_PASSWORD_OPTIONS,
  GENERATOR_ERROR_MESSAGES,
  GENERATOR_LIMITS,
  generatorErrorMessage,
} from "../src/generator-constants.ts";
import { loadCore } from "./load-core.ts";

beforeAll(() => {
  loadCore();
});

describe("generator-constants", () => {
  it("matches the core's own GENERATOR_LIMITS, both the static copy and Rust's own answer", () => {
    expect(GENERATOR_LIMITS).toEqual(CORE_GENERATOR_LIMITS);
    const fromRust = generatorLimits();
    expect(GENERATOR_LIMITS).toEqual({
      minLength: fromRust.minLength,
      maxLength: fromRust.maxLength,
      minWords: fromRust.minWords,
      maxWords: fromRust.maxWords,
      symbols: fromRust.symbols,
      ambiguous: fromRust.ambiguous,
      maxSetTextLength: fromRust.maxSetTextLength,
    });
  });

  it("matches the core's own defaults", () => {
    expect(DEFAULT_PASSWORD_OPTIONS).toEqual(CORE_DEFAULT_PASSWORD_OPTIONS);
    expect(DEFAULT_PASSPHRASE_OPTIONS).toEqual(CORE_DEFAULT_PASSPHRASE_OPTIONS);
  });

  it("covers exactly the generator_* codes the core knows about, worded exactly as it words them", () => {
    // Key-set equality in both directions: this also catches a code the *core* grows (a new
    // `GeneratorError` variant mapped to a new `generator_*` string in
    // `crates/rizzy-wasm/src/generator.rs` / `packages/core/src/index.ts`) that this UI copy
    // has not been given an entry for yet. Without this, that gap would stay invisible here —
    // `generatorErrorMessage` falls back to the generic message for any code it doesn't
    // recognise, so a merely one-directional check (this copy's keys resolve like the core's)
    // stays green while production silently shows the generic sentence for the new code.
    expect(new Set(Object.keys(GENERATOR_ERROR_MESSAGES))).toEqual(
      new Set(Object.keys(CORE_GENERATOR_ERROR_MESSAGES)),
    );
    for (const code of Object.keys(CORE_GENERATOR_ERROR_MESSAGES)) {
      expect(generatorErrorMessage(code)).toBe(coreGeneratorErrorMessage(code));
    }
    expect(generatorErrorMessage("not_a_real_code")).toBe(coreGeneratorErrorMessage("not_a_real_code"));
  });
});
