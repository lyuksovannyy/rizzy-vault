// SPDX-License-Identifier: AGPL-3.0-only

// Vitest for packages/i18n (ADR 0014 §3 "Vitest for unit tests"). Node environment, matching
// packages/ui and apps/web: the catalogue and `t` are plain data and string functions. The
// type-level checks in `test/` (`@ts-expect-error` lines) are checked by `pnpm run build`,
// which type-checks this package, tests included.
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
  },
});
