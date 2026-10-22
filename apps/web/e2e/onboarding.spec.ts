// SPDX-License-Identifier: AGPL-3.0-only

// The getting-started guide end to end (ROADMAP §4.5 "Onboarding flow"; `src/onboarding.ts`,
// `src/views/OnboardingView.tsx`): it opens after signup with the focus on its first step,
// never shows the Emergency Kit again, is walked with the keyboard (the kit confirmation) and
// with an import through the existing import form, skips the extension step, and leaves the
// imported items in the vault. Settings opens it again; it stores nothing, so a later login
// does not show it.
import { expect, test } from "@playwright/test";

import { logIn, lockVault, signUpToGuide, watch } from "./helpers.ts";
import { type RunningServer, startServer } from "./server.ts";

let server: RunningServer;

test.beforeAll(async () => {
  server = await startServer();
});

test.afterAll(() => {
  server.stop();
});

/** A Chrome CSV export (name,url,username,password,note) with two logins. */
const CHROME_CSV =
  "name,url,username,password,note\r\n" +
  "Onboard Alpha,https://alpha.example/,alice,alpha-password-1,\r\n" +
  "Onboard Beta,https://beta.example/,bob,beta-password-2,first note\r\n";

test("onboarding: kit confirmed by keyboard, one import, extension skipped, then the vault", async ({ page }) => {
  const { problems } = watch(page);
  const secretKey = await signUpToGuide(page, server.origin, "onboarduser");

  const guide = page.getByRole("region", { name: "Get started" });
  await expect(guide).toBeVisible();
  const steps = guide.getByRole("list", { name: "Steps" });
  await expect(steps.locator('[aria-current="step"]')).toHaveText(/Keep your Emergency Kit safe/);

  // Step 1: the focus is on the step's heading; the kit itself is not shown again.
  await expect(guide.getByRole("heading", { name: "Step 1 of 3: Keep your Emergency Kit safe" })).toBeFocused();
  await expect(page.getByTestId("emergency-kit")).toHaveCount(0);
  await expect(page.getByTestId("kit-secret-key")).toHaveCount(0);
  expect(await page.locator("body").innerText()).not.toContain(secretKey);
  const continueButton = guide.getByRole("button", { name: "Continue" });
  await expect(continueButton).toBeDisabled();

  // Keyboard only: Tab to the confirmation, tick it with Space, Tab to Continue, Enter.
  await page.keyboard.press("Tab");
  const confirmation = guide.getByRole("checkbox", { name: /I saved my Emergency Kit/ });
  await expect(confirmation).toBeFocused();
  await page.keyboard.press("Space");
  await expect(confirmation).toBeChecked();
  await page.keyboard.press("Tab");
  await expect(continueButton).toBeFocused();
  await page.keyboard.press("Enter");

  // Step 2: the existing import form, with the formats it reads.
  await expect(guide.getByRole("heading", { name: "Step 2 of 3: Import from another password manager" })).toBeFocused();
  await expect(steps.getByRole("listitem")).toHaveText([
    "Keep your Emergency Kit safe (done)",
    "Import from another password manager (current)",
    "Install the browser extension (not started)",
  ]);
  await expect(guide.getByRole("list", { name: "Files this import reads:" })).toContainText("Bitwarden JSON");
  await guide.getByLabel("File", { exact: true }).setInputFiles({
    name: "chrome-passwords.csv",
    mimeType: "text/csv",
    buffer: Buffer.from(CHROME_CSV, "utf8"),
  });
  await expect(guide.getByTestId("import-detected")).toHaveText("Recognised: Chrome CSV.");
  await guide.getByRole("button", { name: "Import", exact: true }).click();
  await expect(guide.getByTestId("import-report")).toContainText("Imported 2, skipped 0");
  await guide.getByRole("button", { name: "Continue" }).click();

  // Step 3: static instructions with this server and login name filled in; skipped.
  await expect(guide.getByRole("heading", { name: "Step 3 of 3: Install the browser extension" })).toBeFocused();
  await expect(guide.getByText("chrome://extensions")).toBeVisible();
  await expect(guide.getByText(server.origin, { exact: true })).toBeVisible();
  await expect(guide.getByText("onboarduser", { exact: true })).toBeVisible();
  await expect(guide.locator("a")).toHaveCount(0);
  await guide.getByRole("button", { name: "Skip this step" }).click();

  // The summary, then the vault with the imported items.
  await expect(guide.getByRole("heading", { name: "You are set up" })).toBeFocused();
  const summary = guide.getByRole("list", { name: "How each step ended" });
  await expect(summary).toContainText("Keep your Emergency Kit safe: done");
  await expect(summary).toContainText("Import from another password manager: done");
  await expect(summary).toContainText("Install the browser extension: skipped");
  await guide.getByRole("button", { name: "Go to your vault" }).click();
  await expect(guide).toHaveCount(0);
  const items = page.getByRole("list", { name: "Items" });
  await expect(items.getByRole("button", { name: /Onboard Alpha/ })).toBeVisible();
  await expect(items.getByRole("button", { name: /Onboard Beta/ })).toBeVisible();

  // Settings opens the guide again, from its first step; Close leaves it.
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await page.getByRole("button", { name: "Open the getting-started guide" }).click();
  await expect(guide.getByRole("heading", { name: "Step 1 of 3: Keep your Emergency Kit safe" })).toBeFocused();
  await guide.getByRole("button", { name: "Close the guide" }).click();
  await expect(guide).toHaveCount(0);

  // Nothing about the guide is stored (CRYPTO.md §11.4): no storage key but the theme's, and a
  // later login opens the vault, not the guide. The imported items are on the server.
  const stored = await page.evaluate(() => ({
    local: Object.keys(localStorage).filter((k) => k !== "rizzy-vault.theme"),
    session: Object.keys(sessionStorage),
  }));
  expect(stored).toEqual({ local: [], session: [] });
  await lockVault(page);
  await logIn(page, undefined, secretKey);
  await expect(guide).toHaveCount(0);
  await expect(items.getByRole("button", { name: /Onboard Alpha/ })).toBeVisible();
  await expect(items.getByRole("button", { name: /Onboard Beta/ })).toBeVisible();

  expect(problems).toEqual([]);
});

test("onboarding: every step skips, Back returns, and the vault is empty", async ({ page }) => {
  const { problems } = watch(page);
  await signUpToGuide(page, server.origin, "onboardskip");
  const guide = page.getByRole("region", { name: "Get started" });

  await guide.getByRole("button", { name: "Skip this step" }).click();
  await expect(guide.getByRole("heading", { name: /^Step 2 of 3/ })).toBeFocused();
  await guide.getByRole("button", { name: "Back" }).click();
  await expect(guide.getByRole("heading", { name: /^Step 1 of 3/ })).toBeFocused();
  for (const n of [1, 2, 3]) {
    await expect(guide.getByRole("heading", { name: new RegExp(`^Step ${n} of 3`) })).toBeFocused();
    await guide.getByRole("button", { name: "Skip this step" }).click();
  }
  const summary = guide.getByRole("list", { name: "How each step ended" });
  await expect(summary.getByRole("listitem")).toHaveText([
    "Keep your Emergency Kit safe: skipped",
    "Import from another password manager: skipped",
    "Install the browser extension: skipped",
  ]);
  await guide.getByRole("button", { name: "Go to your vault" }).click();
  await expect(page.getByText("No items yet.")).toBeVisible();

  expect(problems).toEqual([]);
});
