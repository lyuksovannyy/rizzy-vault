// Playwright for the web vault (ADR 0014 §3): end-to-end tests in Chromium against the real
// `rizzy-vault` binary built with `embed-web` (`e2e/server.ts` starts it), so the page runs
// under the server's own CSP and headers (INV-49) exactly as it ships.
import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "e2e",
  timeout: 180_000,
  expect: { timeout: 30_000 },
  fullyParallel: false,
  workers: 1,
  forbidOnly: process.env["CI"] !== undefined,
  retries: 0,
  reporter: "list",
  use: {
    ...devices["Desktop Chrome"],
    trace: "off",
    acceptDownloads: true,
  },
});
