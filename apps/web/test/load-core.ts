// Loads `@rizzy-vault/core`'s wasm module for the handful of tests that cross-check this app's
// own copies of core values (`generator-constants.ts` module docs) against the real thing.
// Tests run in Node (`vite.config.ts`'s `test.environment`), not the vault page, so importing
// `@rizzy-vault/core` here is not the ADR 0013 §4 violation it would be in `src/**` (the eslint
// config exempts `test/**` for exactly this reason).
import { readFileSync } from "node:fs";

import { initFromBytes } from "@rizzy-vault/core";

let loaded = false;

/** Loads the module once, idempotently, for tests in this file's directory or any other. */
export function loadCore(): void {
  if (loaded) {
    return;
  }
  const wasm = new URL(
    "../../../packages/core/generated/rizzy_core_bg.wasm",
    import.meta.url,
  );
  initFromBytes(readFileSync(wasm));
  loaded = true;
}
