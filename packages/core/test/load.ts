// Loads the generated wasm module from disk for the tests (`cargo xtask build-wasm` writes it).
import { readFileSync } from "node:fs";

import { initFromBytes } from "../src/index.js";

/** Loads the module once. */
export function loadCore(): void {
  const wasm = new URL("../generated/rizzy_core_bg.wasm", import.meta.url);
  initFromBytes(readFileSync(wasm));
}
