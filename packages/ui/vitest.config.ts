// Vitest for packages/ui (ADR 0014 §3 "Vitest for unit tests"). Node environment, matching
// apps/web and packages/core: this package's tests cover the pure logic behind its components
// (the toast queue reducer, the confirm dialog's focus-trap arithmetic), not DOM rendering —
// there is no jsdom/happy-dom dependency in this workspace (module docs, `src/Toast.tsx`).
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
  },
});
