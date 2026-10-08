// The item editor's per-URI match mode (ADR 0037 §4, Accepted M2; ROADMAP §4.4 "Per-URI match
// mode"): picking a mode writes `uri/<id>/match`, it round-trips through a reload, and a
// website the user never touched stays absent (the account default) rather than being pinned
// to "Base domain" merely because an unrelated field was edited and saved.
import { type Page, expect, test } from "@playwright/test";

import { lockVault, logIn, newItem, signUp } from "./helpers.ts";
import { type RunningServer, startServer } from "./server.ts";

let server: RunningServer;

test.beforeAll(async () => {
  server = await startServer();
});

test.afterAll(() => {
  server.stop();
});

async function createLoginWithWebsite(page: Page, title: string, websiteUrl: string): Promise<void> {
  await newItem(page, "Login");
  await page.getByLabel("Title").fill(title);
  await page.getByRole("button", { name: "Add a website" }).click();
  await page.getByLabel("New website 1", { exact: true }).fill(websiteUrl);
}

test("setting a website's match mode to Exact survives a reload", async ({ page }) => {
  const secretKey = await signUp(page, server.origin, "MatchModeUser");

  await createLoginWithWebsite(page, "Exact Mode Site", "https://example.com/login");
  // Default: the select shows "Account default" and the field is not written at all.
  await expect(page.getByLabel("New website 1 match mode")).toHaveValue("0");
  await page.getByLabel("New website 1 match mode").selectOption("4"); // Exact
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "Exact Mode Site" })).toBeVisible();
  await expect(page.getByText("Synced", { exact: true })).toBeVisible();
  await expect(page.getByText("Match: Exact")).toBeVisible();

  await page.getByRole("button", { name: "Edit" }).click();
  await expect(page.getByLabel("Website 1 match mode")).toHaveValue("4");

  // Reload (nothing persists client-side, `vault.spec.ts`'s own "nothing persists" note) → log
  // in again → the item still shows Exact, from the server, not a client-only illusion.
  await page.reload();
  await logIn(page, "MatchModeUser", secretKey);
  await page.getByRole("button", { name: /Exact Mode Site/ }).click();
  await expect(page.getByText("Match: Exact")).toBeVisible();
  await page.getByRole("button", { name: "Edit" }).click();
  await expect(page.getByLabel("Website 1 match mode")).toHaveValue("4");

  await lockVault(page);
});

test("an untouched website's match mode stays Account default after an unrelated edit", async ({ page }) => {
  await signUp(page, server.origin, "MatchModeUser2");

  await createLoginWithWebsite(page, "Untouched Mode Site", "https://example.org/login");
  // Never touch the match-mode select for this row.
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "Untouched Mode Site" })).toBeVisible();
  await expect(page.getByText("Synced", { exact: true })).toBeVisible();
  await expect(page.getByText("Match: Account default")).toBeVisible();

  // An edit of an unrelated field (the title) must not write `uri/<id>/match` as a side effect
  // — the regression this test is for: picking "Account default" in the select must never
  // silently pin the mode to Base domain (`0x0001`) on save.
  await page.getByRole("button", { name: "Edit" }).click();
  await expect(page.getByLabel("Website 1 match mode")).toHaveValue("0");
  await page.getByLabel("Title").fill("Untouched Mode Site (renamed)");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "Untouched Mode Site (renamed)" })).toBeVisible();
  await expect(page.getByText("Match: Account default")).toBeVisible();
  await page.getByRole("button", { name: "Edit" }).click();
  await expect(page.getByLabel("Website 1 match mode")).toHaveValue("0");

  await lockVault(page);
});
