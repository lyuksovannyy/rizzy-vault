// SPDX-License-Identifier: AGPL-3.0-only

// The item view's large-type password display end to end (ROADMAP §4.5; `src/views/LargeType.tsx`,
// `src/largeType.ts`): appears once the password field is revealed, shows one cell per
// character with digits/letters/symbols told apart, and Escape dismisses it and returns focus.
import { expect, test } from "@playwright/test";

import { newItem, signUp, watch } from "./helpers.ts";
import { type RunningServer, startServer } from "./server.ts";

const ITEM_PASSWORD = "Ab3!long-enough-passphrase9";

let server: RunningServer;

test.beforeAll(async () => {
  server = await startServer();
});

test.afterAll(() => {
  server.stop();
});

test("large type: one cell per character, classed by kind, Escape dismisses", async ({ page }) => {
  const { problems } = watch(page);
  await signUp(page, server.origin, "largetypeuser");

  await newItem(page, "Login");
  await page.getByLabel("Title").fill("Large Co");
  await page.getByLabel("Password", { exact: true }).fill(ITEM_PASSWORD);
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "Large Co" })).toBeVisible();

  const passwordRow = page.locator('[data-field="login.password"]');
  // No "Large type" trigger before the field is revealed — it reuses that same reveal, never a
  // second one (`LargeType.tsx`'s module docs).
  await expect(passwordRow.getByRole("button", { name: "Large type" })).toHaveCount(0);
  await passwordRow.getByRole("button", { name: "Reveal" }).click();
  await expect(passwordRow.locator("input[data-secret-field]")).toHaveValue(ITEM_PASSWORD);

  await passwordRow.getByRole("button", { name: "Large type" }).click();
  const dialog = page.getByRole("dialog", { name: "Password" });
  await expect(dialog).toBeVisible();

  const cells = dialog.locator(".large-type-cell");
  await expect(cells).toHaveCount(ITEM_PASSWORD.length);
  expect((await cells.allTextContents()).join("")).toBe(ITEM_PASSWORD);
  // Digits and symbols are classed apart from plain letters (`largeType.ts`'s `charKind`).
  await expect(dialog.locator(".large-type-cell.large-type-digit")).toHaveCount(2); // "3", "9"
  await expect(dialog.locator(".large-type-cell.large-type-symbol")).toHaveCount(3); // "!", "-", "-"

  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  // Focus returns to whatever opened it, like every other dialog in this app (`ConfirmDialog`,
  // `ShortcutsHelp`): the "Large type" button itself.
  await expect(passwordRow.getByRole("button", { name: "Large type" })).toBeFocused();

  expect(problems).toEqual([]);
});
