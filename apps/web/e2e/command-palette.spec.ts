// SPDX-License-Identifier: AGPL-3.0-only

// The command palette end to end (Ctrl/Cmd+K; ROADMAP §4.2/§4.5; `src/views/CommandPalette.tsx`,
// `src/palette.ts`): opens as an ARIA combobox/listbox, searches the decrypted item list by
// title/username/URL host/tag, ranks favorites first, is keyboard-only usable (arrow keys,
// Enter, Escape), opens an item, jumps to a sidebar view, and copies a username/password/TOTP
// code to the real OS clipboard (granted explicitly for this spec, module docs below).
import { expect, test } from "@playwright/test";

import { newItem, signUp, watch } from "./helpers.ts";
import { type RunningServer, startServer } from "./server.ts";

const ITEM_PASSWORD = "palette-hunter2-long-enough";
const TOTP_SECRET = "JBSWY3DPEHPK3PXP";

let server: RunningServer;

test.beforeAll(async () => {
  server = await startServer();
});

test.afterAll(() => {
  server.stop();
});

test("command palette: search, keyboard nav, open, jump to a view, favorites-first", async ({ page }) => {
  const { problems } = watch(page);
  await signUp(page, server.origin, "paletteuser");

  // Two logins: "Alpha Bank" (every action the palette offers: username, password, TOTP) and
  // "Zeta Bank" (just a username), so search/ranking/actions all have something to tell apart.
  await newItem(page, "Login");
  await page.getByLabel("Title").fill("Alpha Bank");
  await page.getByLabel("Username", { exact: true }).fill("alice@example.com");
  await page.getByLabel("Password", { exact: true }).fill(ITEM_PASSWORD);
  await page.getByLabel("One-time password secret (TOTP)", { exact: true }).fill(TOTP_SECRET);
  await page.getByRole("button", { name: "Add a website" }).click();
  await page.getByLabel("New website 1", { exact: true }).fill("https://alpha.example.com/login");
  await page.getByLabel("Add tags (comma-separated)").fill("finance");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "Alpha Bank" })).toBeVisible();

  await newItem(page, "Login");
  await page.getByLabel("Title").fill("Zeta Bank");
  await page.getByLabel("Username", { exact: true }).fill("zeta@example.com");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "Zeta Bank" })).toBeVisible();
  // Favorite it, so it ranks first ahead of "Alpha Bank" wherever both match (ROADMAP §4.2/§4.5
  // "favorites first in the palette").
  await page.getByRole("button", { name: "Add to favorites" }).click();
  await expect(page.getByRole("button", { name: "Remove from favorites" })).toBeVisible();

  // Opening: combobox/listbox ARIA structure, every navigation command listed with no query.
  await page.locator("body").click({ position: { x: 5, y: 5 } });
  await page.keyboard.press("Control+k");
  const combobox = page.getByRole("combobox", { name: "Command palette" });
  await expect(combobox).toBeVisible();
  await expect(combobox).toBeFocused();
  const listbox = page.getByRole("listbox", { name: "Commands" });
  await expect(listbox).toBeVisible();
  await expect(page.getByRole("option", { name: "All items" })).toBeVisible();
  await expect(page.getByRole("option", { name: "Favorites" })).toBeVisible();
  await expect(page.getByRole("option", { name: "Trash" })).toBeVisible();

  // Search by title: both banks match "Bank", favorite ("Zeta Bank") ranked first.
  await combobox.fill("Bank");
  const options = page.getByRole("option");
  await expect(options.first()).toHaveAccessibleName(/Open — Zeta Bank/);
  const names = await options.allTextContents();
  const zetaIndex = names.findIndex((n) => n.includes("Zeta Bank"));
  const alphaIndex = names.findIndex((n) => n.includes("Alpha Bank"));
  expect(zetaIndex).toBeGreaterThanOrEqual(0);
  expect(zetaIndex).toBeLessThan(alphaIndex);

  // Search by username, then by URL host, then by tag — the same fields ItemsPane's own search
  // already covers (fields.ts's `matches`), reused by `itemRowsFor`.
  await combobox.fill("alice@example.com");
  await expect(page.getByRole("option")).toHaveCount(4); // open, copy-username, copy-password, copy-totp
  await combobox.fill("alpha.example.com");
  await expect(page.getByRole("option", { name: /Alpha Bank/ }).first()).toBeVisible();
  await combobox.fill("finance");
  await expect(page.getByRole("option", { name: /Alpha Bank/ }).first()).toBeVisible();
  await combobox.fill("nonexistent-query-xyz");
  await expect(page.getByText("Nothing matches.")).toBeVisible();

  // Keyboard-only: arrow keys move the highlighted option (aria-selected), Enter opens it.
  await combobox.fill("Alpha Bank");
  const openRow = page.getByRole("option", { name: /^Open — Alpha Bank/ });
  await expect(openRow).toHaveAttribute("aria-selected", "true");
  await page.keyboard.press("ArrowDown");
  await expect(openRow).toHaveAttribute("aria-selected", "false");
  const usernameRow = page.getByRole("option", { name: /^Copy username — Alpha Bank/ });
  await expect(usernameRow).toHaveAttribute("aria-selected", "true");
  await page.keyboard.press("ArrowUp");
  await expect(openRow).toHaveAttribute("aria-selected", "true");
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { name: "Alpha Bank" })).toBeVisible();
  await expect(combobox).toBeHidden();

  // Escape closes without acting, and returns focus.
  await page.keyboard.press("Control+k");
  await expect(combobox).toBeVisible();
  await combobox.fill("Zeta");
  await page.keyboard.press("Escape");
  await expect(combobox).toBeHidden();
  await expect(page.getByRole("heading", { name: "Alpha Bank" })).toBeVisible();

  // Opening an item from the palette works even outside the item list's own current scope
  // (favorited-only here), and jumping to a sidebar view works the same way.
  await page.getByRole("button", { name: "Favorites", exact: true }).click();
  await page.keyboard.press("Control+k");
  await combobox.fill("Alpha Bank");
  await page.getByRole("option", { name: /^Open — Alpha Bank/ }).click();
  await expect(page.getByRole("heading", { name: "Alpha Bank" })).toBeVisible();

  await page.keyboard.press("Control+k");
  await page.getByRole("option", { name: "Trash" }).click();
  await expect(combobox).toBeHidden();
  await expect(page.getByText("The trash is empty.")).toBeVisible();

  expect(problems).toEqual([]);
});

test("command palette: copy username/password/TOTP to the real clipboard", async ({ page, context }) => {
  // Clipboard read/write granted explicitly for this one spec (Playwright's documented pattern
  // for testing the Clipboard API in Chromium) — the rest of this app's e2e suite never needs
  // the real OS clipboard, so nothing elsewhere in this repository relies on this permission.
  await context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: server.origin });
  const { problems } = watch(page);
  await signUp(page, server.origin, "paletteclip");

  await newItem(page, "Login");
  await page.getByLabel("Title").fill("Clip Co");
  await page.getByLabel("Username", { exact: true }).fill("clip-user");
  await page.getByLabel("Password", { exact: true }).fill(ITEM_PASSWORD);
  await page.getByLabel("One-time password secret (TOTP)", { exact: true }).fill(TOTP_SECRET);
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "Clip Co" })).toBeVisible();

  const combobox = page.getByRole("combobox", { name: "Command palette" });

  await page.keyboard.press("Control+k");
  await combobox.fill("Clip Co");
  await page.getByRole("option", { name: /^Copy username — Clip Co/ }).click();
  await expect(page.getByText("Username copied for Clip Co.")).toBeVisible();
  await expect(combobox).toBeHidden();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("clip-user");

  await page.keyboard.press("Control+k");
  await combobox.fill("Clip Co");
  await page.getByRole("option", { name: /^Copy password — Clip Co/ }).click();
  await expect(page.getByText("Password copied for Clip Co.")).toBeVisible();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(ITEM_PASSWORD);

  await page.keyboard.press("Control+k");
  await combobox.fill("Clip Co");
  await page.getByRole("option", { name: /^Copy TOTP code — Clip Co/ }).click();
  await expect(page.getByText("TOTP code copied for Clip Co.")).toBeVisible();
  const copiedCode = await page.evaluate(() => navigator.clipboard.readText());
  expect(copiedCode).toMatch(/^\d{6}$/);

  expect(problems).toEqual([]);
});
