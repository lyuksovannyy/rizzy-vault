// The generator's calls to the core, apart from React, so the mapping from UI options to the
// core's calls and the handling of its refusals are tested without a DOM (the pattern of
// `export-flow.ts`'s module docs). The core generates and computes entropy (packages/core,
// `crates/rizzy-wasm/src/generator.rs`); nothing here does either.
import type { CoreClient } from "./core-client.ts";
import type { GeneratorMode } from "./generator-memory.ts";

// Re-imported as types only (ADR 0013 §4): this module's functions take `PasswordOptions` /
// `PassphraseOptions` / `Generated` values the caller already has, and hand them to `client`
// unchanged.
import type { Generated, PassphraseOptions, PasswordOptions } from "@rizzy-vault/core";

/** The part of {@link CoreClient} these steps use, so tests can pass a fake (`export-flow.ts`). */
export type Caller = Pick<CoreClient, "call">;

/** A generated value for `mode`, with `passwordOptions` or `passphraseOptions` as the core sees
 * fit — whichever `mode` does not use is ignored. Rejects with the core's own `generator_*`
 * code (a `CallError`, `core-client.ts`) for options it refuses. */
export function generateValue(
  client: Caller,
  mode: GeneratorMode,
  passwordOptions: PasswordOptions,
  passphraseOptions: PassphraseOptions,
): Promise<Generated> {
  return mode === "password"
    ? client.call("generatePasswordWithOptions", passwordOptions)
    : client.call("generatePassphraseWithOptions", passphraseOptions);
}

/** The entropy, in bits, of `mode`'s current options, without generating a value — for a live
 * display. Throws as {@link generateValue} would. */
export function checkEntropy(
  client: Caller,
  mode: GeneratorMode,
  passwordOptions: PasswordOptions,
  passphraseOptions: PassphraseOptions,
): Promise<number> {
  return mode === "password"
    ? client.call("passwordEntropy", passwordOptions)
    : client.call("passphraseEntropy", passphraseOptions);
}

/** Fills `input` with `generated`'s value. A no-op for an input that is no longer mounted (the
 * popover's target row was removed, or the editor's secret input has not been created yet). */
export function fillGenerated(input: { value: string } | null, generated: Generated): void {
  if (input != null) {
    input.value = generated.value;
  }
}
