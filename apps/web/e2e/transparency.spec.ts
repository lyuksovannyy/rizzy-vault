// SPDX-License-Identifier: AGPL-3.0-only

// The Settings "What the server stores" group end to end (ROADMAP §4.5; `src/views/TransparencyPane.tsx`,
// `src/transparency.ts`): it renders the list and retention rules, and its counts follow the
// vault this browser fetched — one item saved, then moved to the Trash — and it shows the storage
// use the server reports with every account answer (ADR 0048 §5).
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

test("settings: what the server stores, with this browser's counts", async ({ page }) => {
  const { problems } = watch(page);
  await signUp(page, server.origin, "transparencyuser");

  await newItem(page, "Login");
  await page.getByLabel("Title").fill("Counted Co");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "Counted Co" })).toBeVisible();

  await page.getByRole("button", { name: "Settings", exact: true }).click();
  const pane = page.getByRole("region", { name: "What the server stores" });
  await expect(pane).toBeVisible();
  await expect(pane.getByRole("rowheader", { name: "Your login name" })).toBeVisible();
  await expect(pane.getByRole("rowheader", { name: "Session tokens" })).toBeVisible();
  await expect(pane.getByText(/30 days after it was trashed/)).toBeVisible();
  const counts = pane.getByRole("table", { name: "Counts of your vault" });
  await expect(counts.getByRole("row", { name: "Items 1" })).toBeVisible();
  await expect(counts.getByRole("row", { name: "Items in the Trash 0" })).toBeVisible();
  await expect(counts.getByRole("row", { name: "Enrolled devices, active or revoked 0" })).toBeVisible();
  // The server's figure against the default 5 GiB quota, as of the account answer that starts
  // each sync (so before that sync's own upload).
  const usage = pane.getByTestId("storage-usage");
  await expect(usage).toHaveText(/^Used: \d+(\.\d)? (bytes|KiB) of 5\.0 GiB \(0%\)$/);
  await expect(pane.getByText(/Reported by the server and not checked by this browser/)).toBeVisible();

  // The counts follow the vault: trash the item and come back.
  await page.getByRole("button", { name: "All items", exact: true }).click();
  await page.getByRole("button", { name: /Counted Co/ }).first().click();
  await page.getByRole("button", { name: "Move to trash" }).click();
  await page
    .getByRole("dialog", { name: "Move this item to trash?" })
    .getByRole("button", { name: "Move to trash" })
    .click();
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await expect(counts.getByRole("row", { name: "Items 0" })).toBeVisible();
  await expect(counts.getByRole("row", { name: "Items in the Trash 1" })).toBeVisible();
  // The trash's sync read the account after the item's records were stored: they count.
  await expect(usage).toHaveText(/^Used: \d+(\.\d)? (bytes|KiB) of 5\.0 GiB \(0%\)$/);
  await expect(usage).not.toHaveText(/^Used: 0 bytes/);

  expect(problems).toEqual([]);
});
