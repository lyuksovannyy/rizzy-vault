// SPDX-License-Identifier: AGPL-3.0-only

// Design review screenshots (docs/design/README.md "Screenshots"): the web vault's key screens,
// light and dark, written as PNGs to docs/design/screenshots/ for the owner to review a visual
// change. Not a check (nothing is compared), so it only runs when asked:
//
//   RIZZY_DESIGN_SCREENSHOTS=after pnpm --filter @rizzy-vault/web exec playwright test e2e/design-screenshots.spec.ts
//
// writes `docs/design/screenshots/web-<screen>-<theme>-after.png`. The value names the set
// (`before`/`after`); without the variable the test is skipped, so the e2e gate never rewrites
// committed files. Playwright's `animations: "disabled"` finishes every running transition and
// animation first, so each frame is the settled state, not a mid-motion one.
import { type Page, expect, test } from "@playwright/test";
import { mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { MARKDOWN_NOTE, dismissToasts, lockVault, newItem, signUpToGuide, watch } from "./helpers.ts";
import { type RunningServer, startServer } from "./server.ts";

const SET = process.env["RIZZY_DESIGN_SCREENSHOTS"] ?? "";
const OUT_DIR = fileURLToPath(new URL("../../../docs/design/screenshots/", import.meta.url));

let server: RunningServer;

test.skip(SET === "", "set RIZZY_DESIGN_SCREENSHOTS=<set name> to write the design screenshots");

test.beforeAll(async () => {
  if (SET !== "") {
    server = await startServer();
  }
});

test.afterAll(() => {
  if (SET !== "") {
    server.stop();
  }
});

/** Writes one screenshot of the viewport. */
async function shot(page: Page, screen: string, theme: string): Promise<void> {
  mkdirSync(OUT_DIR, { recursive: true });
  await page.screenshot({ path: `${OUT_DIR}web-${screen}-${theme}-${SET}.png`, animations: "disabled", caret: "hide" });
}

for (const theme of ["light", "dark"] as const) {
  test(`design screenshots (${theme})`, async ({ page }) => {
    const { problems } = watch(page);
    await page.setViewportSize({ width: 1180, height: 760 });
    await page.emulateMedia({ colorScheme: theme });

    await page.goto(server.origin);
    await expect(page.getByRole("button", { name: "Create an account" })).toBeVisible();
    await shot(page, "login", theme);

    await signUpToGuide(page, server.origin, `design-${theme}`);
    const guide = page.getByRole("region", { name: "Get started" });
    await expect(guide).toBeVisible();
    await shot(page, "onboarding", theme);
    await guide.getByRole("button", { name: "Close the guide" }).click();

    // A few items so the list has rows, and one of them open.
    for (const [title, user] of [
      ["Acme Mail", "ada@acme.example"],
      ["Bank of Example", "ada.lovelace"],
      ["Code Forge", "ada"],
    ] as const) {
      await newItem(page, "Login");
      await page.getByLabel("Title").fill(title);
      await page.getByLabel("Username", { exact: true }).fill(user);
      await page.getByLabel("Password", { exact: true }).fill(`${title}-password-long-enough`);
      await page.getByRole("button", { name: "Save" }).click();
      await expect(page.getByRole("heading", { name: title })).toBeVisible();
    }
    await newItem(page, "Secure Note");
    await page.getByLabel("Title").fill("Home Wi-Fi");
    await page.getByLabel("Notes").fill(MARKDOWN_NOTE);
    await page.getByRole("button", { name: "Save" }).click();
    await expect(page.getByRole("heading", { name: "Home Wi-Fi" })).toBeVisible();
    await page.getByRole("button", { name: /Bank of Example/ }).first().click();
    await expect(page.getByRole("heading", { name: "Bank of Example" })).toBeVisible();
    await dismissToasts(page);
    await page.mouse.move(0, 0);
    await shot(page, "vault-item", theme);

    await page.getByRole("button", { name: "Edit" }).click();
    await expect(page.getByLabel("Title")).toBeVisible();
    await shot(page, "editor", theme);
    await page.getByRole("button", { name: "Cancel" }).click();
    await expect(page.getByRole("heading", { name: "Bank of Example" })).toBeVisible();

    await page.getByRole("button", { name: "New item" }).click();
    await expect(page.getByRole("menu", { name: "New item type" })).toBeVisible();
    await shot(page, "menu", theme);
    await page.keyboard.press("Escape");

    await page.keyboard.press("Control+k");
    const combobox = page.getByRole("combobox", { name: "Command palette" });
    await expect(combobox).toBeVisible();
    await combobox.fill("a");
    await shot(page, "palette", theme);
    await page.keyboard.press("Escape");
    await expect(combobox).toHaveCount(0);

    await page.getByRole("button", { name: "Move to trash" }).click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await shot(page, "dialog", theme);
    await page.keyboard.press("Escape");
    await expect(page.getByRole("dialog")).toHaveCount(0);

    await lockVault(page);
    await expect(page.getByRole("heading", { name: "Unlock rizzy-vault" })).toBeVisible();
    await shot(page, "unlock", theme);

    expect(problems).toEqual([]);
  });
}
