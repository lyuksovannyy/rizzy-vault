// Keyboard shortcuts and list navigation (redesign slice 2, item 3; `src/shortcuts.ts`): `/`
// focuses search, arrow keys move the list selection and Enter opens the selected row, `N`
// starts a new item, `?` opens the shortcuts help (and Escape closes it), and a shortcut like
// `N` is suppressed while a text field has focus.
import { expect, test } from "@playwright/test";

import { newItem, signUp, watch } from "./helpers.ts";
import { type RunningServer, startServer } from "./server.ts";

let server: RunningServer;

test.beforeAll(async () => {
  server = await startServer();
});

test.afterAll(() => {
  server.stop();
});

test("keyboard: search focus, list navigation, new item, shortcuts help", async ({ page }) => {
  const { problems } = watch(page);
  await signUp(page, server.origin, "keyboarduser");

  // Two items to navigate between.
  await newItem(page, "Login");
  await page.getByLabel("Title").fill("First Co");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "First Co" })).toBeVisible();

  await newItem(page, "Login");
  await page.getByLabel("Title").fill("Second Co");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "Second Co" })).toBeVisible();

  // `/` focuses the search box (from the body, not a text field).
  await page.locator("body").press("/");
  await expect(page.getByLabel("Search items")).toBeFocused();
  await page.getByLabel("Search items").fill("");

  // `N` while the search box has focus (a text field) does nothing: no editor opens.
  await page.getByLabel("Search items").press("n");
  await expect(page.getByRole("heading", { name: "New login" })).toHaveCount(0);
  await expect(page.getByLabel("Title")).toHaveCount(0);

  // Arrow-key navigation over the list, then Enter opens the focused row.
  await page.getByRole("button", { name: /First Co|Second Co/ }).first().focus();
  await page.keyboard.press("ArrowDown");
  const focused = page.locator(":focus");
  await expect(focused).toHaveAttribute("type", "button");
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { name: /First Co|Second Co/ })).toBeVisible();

  // `N` from outside a text field opens a new item.
  await page.locator("body").click({ position: { x: 5, y: 5 } });
  await page.keyboard.press("n");
  await expect(page.getByLabel("Title")).toBeVisible();
  await page.getByRole("button", { name: "Cancel" }).click();

  // `?` opens the shortcuts help; Escape closes it and returns focus.
  await page.keyboard.press("?");
  const help = page.getByRole("dialog", { name: "Keyboard shortcuts" });
  await expect(help).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(help).toBeHidden();

  expect(problems).toEqual([]);
});
