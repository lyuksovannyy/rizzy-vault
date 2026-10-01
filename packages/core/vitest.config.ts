// Vitest for packages/core (ADR 0014 §3 "Vitest for unit tests"). Node environment: the tests
// load the generated wasm module from disk; the end-to-end test talks to a real `rizzy-vault`.
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
    // One Argon2id run takes about a third of a second in wasm (ADR 0013, fact sheet); the
    // end-to-end test runs several, behind a server it starts.
    testTimeout: 120_000,
    hookTimeout: 120_000,
  },
});
