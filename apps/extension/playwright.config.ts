// Playwright for the extension (ADR 0014 §3). Chromium only: a persistent context loading the
// unpacked `dist/chromium` build (Firefox's `about:debugging` temporary-add-on flow has no
// Playwright-automatable equivalent, so Firefox e2e coverage is `not_done`). Run
// `pnpm run build:chromium` before `pnpm run e2e`.
import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "e2e",
  timeout: 60_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  workers: 1,
  forbidOnly: process.env["CI"] !== undefined,
  retries: 0,
  reporter: "list",
});
