// SPDX-License-Identifier: AGPL-3.0-only

// The item view's large-type password display end to end (ROADMAP §4.5; `src/views/LargeType.tsx`,
// `src/largeType.ts`): appears once the password field is revealed, shows one cell per
// character with digits/letters/symbols told apart, Escape dismisses it and returns focus, and
// — like every other dialog in the vault — it suppresses the global keyboard shortcuts while
// it is open (`VaultView.tsx`'s modal gate, `packages/ui/src/modalRegistry.ts`).
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

  // Global shortcuts must stay silent while the overlay is open, the same invariant
  // `ConfirmDialog` gets `VaultView.tsx`'s modal gate to enforce — checked with focus on the
  // overlay's own Close button (a `<button>`, which `shortcuts.ts`'s `isTypingTarget` does not
  // treat as a typing target), so nothing but the modal gate itself can be suppressing these.
  await expect(dialog.getByRole("button", { name: "Close" })).toBeFocused();
  await page.keyboard.press("Control+k");
  await expect(page.getByRole("combobox", { name: "Command palette" })).toBeHidden();
  await expect(dialog).toBeVisible();

  await page.keyboard.press("?");
  await expect(page.getByRole("dialog", { name: "Keyboard shortcuts" })).toBeHidden();
  await expect(dialog).toBeVisible();

  await page.keyboard.press("n");
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  // If `N` had fired behind the overlay, the detail pane would now show a blank new-item draft
  // (`ItemsPane.tsx`'s `newItemSignal` effect) instead of the item being read.
  await expect(page.getByRole("heading", { name: "Large Co" })).toBeVisible();
  await expect(page.getByLabel("Title")).toHaveCount(0);
  // Focus returns to whatever opened it, like every other dialog in this app (`ConfirmDialog`,
  // `ShortcutsHelp`): the "Large type" button itself.
  await expect(passwordRow.getByRole("button", { name: "Large type" })).toBeFocused();

  expect(problems).toEqual([]);
});
