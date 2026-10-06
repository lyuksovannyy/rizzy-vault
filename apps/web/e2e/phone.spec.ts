// Phone width (redesign slice 2, item 4): at 375×812 the item list and the open item share no
// screen space — opening an item hides the list and shows a back button, which returns to the
// list — and the page never gains horizontal scroll.
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

test.use({ viewport: { width: 375, height: 812 } });

test("phone width: open an item, back, edit, no horizontal scroll", async ({ page }) => {
  const { problems } = watch(page);
  await signUp(page, server.origin, "phoneuser");

  // No horizontal scroll on the vault shell itself.
  const scrollWidth = await page.evaluate(() => document.documentElement.scrollWidth);
  const clientWidth = await page.evaluate(() => document.documentElement.clientWidth);
  expect(scrollWidth).toBeLessThanOrEqual(clientWidth + 1);

  await newItem(page, "Login");
  await page.getByLabel("Title").fill("Phone Co");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "Phone Co" })).toBeVisible();

  // The list is out of the way while the detail pane is open.
  await expect(page.getByRole("list", { name: "Items" })).toBeHidden();
  const backButton = page.getByRole("button", { name: "Back" });
  await expect(backButton).toBeVisible();

  const scrollWidthWithDetail = await page.evaluate(() => document.documentElement.scrollWidth);
  expect(scrollWidthWithDetail).toBeLessThanOrEqual(clientWidth + 1);

  // Edit, save, then back to the list.
  await page.getByRole("button", { name: "Edit" }).click();
  await page.getByLabel("Title").fill("Phone Co Renamed");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "Phone Co Renamed" })).toBeVisible();

  await page.getByRole("button", { name: "Back" }).click();
  await expect(page.getByRole("list", { name: "Items" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Phone Co Renamed" })).toHaveCount(0);

  expect(problems).toEqual([]);
});
