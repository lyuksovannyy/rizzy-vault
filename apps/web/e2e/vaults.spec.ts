// SPDX-License-Identifier: AGPL-3.0-only

// Several vaults in the web vault (ADR 0081 Part A, §A3–§A8): create, rename, move an item into
// a vault and back, copy, the pickers' Personal default, the "All vaults" filter, delete with
// both choices, and the Personal vault offering no delete or rename.
import { type Page, expect, test } from "@playwright/test";

import { dismissToasts, newItem, signUp, watch } from "./helpers.ts";
import { type RunningServer, startServer } from "./server.ts";

let server: RunningServer;

test.beforeAll(async () => {
  server = await startServer();
});

test.afterAll(() => {
  server.stop();
});

test.setTimeout(180_000);

/** The sidebar. */
function sidebar(page: Page) {
  return page.getByRole("navigation", { name: "Vault navigation" });
}

/** Opens the vault management screen. */
async function openVaults(page: Page): Promise<void> {
  await sidebar(page).getByRole("button", { name: "Manage vaults" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Vaults" })).toBeVisible();
}

/** Creates a vault from the management screen. */
async function createVault(page: Page, name: string): Promise<void> {
  await openVaults(page);
  const pane = page.locator(".vaults-pane");
  await pane.getByLabel("Name", { exact: true }).fill(name);
  await pane.getByRole("button", { name: "Create vault" }).click();
  await expect(pane.locator("tbody tr", { hasText: name })).toBeVisible();
  await dismissToasts(page);
}

/** Shows every item ("All vaults", the item list). */
async function allItems(page: Page): Promise<void> {
  await sidebar(page).getByRole("button", { name: "All vaults" }).click();
  await sidebar(page).getByRole("button", { name: "All items", exact: true }).click();
}

/** Saves a new login titled `title`, in `vault` when given (the picker's default otherwise). */
async function newLogin(page: Page, title: string, vault?: string): Promise<void> {
  await newItem(page, "Login");
  if (vault !== undefined) {
    await page.locator(".item-editor").getByLabel("Vault", { exact: true }).selectOption({ label: vault });
  }
  await page.getByLabel("Title").fill(title);
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: title })).toBeVisible();
}

/** The vault labels of the item rows titled `title`, sorted. */
async function rowVaults(page: Page, title: string): Promise<string[]> {
  const rows = page.getByRole("list", { name: "Items" }).getByRole("listitem").filter({ hasText: title });
  return (await rows.locator(".row-vault").allTextContents()).sort();
}

/** Moves or copies the open item to `target`. */
async function sendTo(page: Page, action: "Move" | "Copy", target: string): Promise<void> {
  await page.getByRole("button", { name: `${action} to…` }).click();
  const dialog = page.getByRole("dialog", { name: action === "Move" ? "Move to another vault" : "Copy to another vault" });
  await expect(dialog).toBeVisible();
  await dialog.getByLabel("Target vault").selectOption({ label: target });
  await dialog.getByRole("button", { name: action, exact: true }).click();
  await expect(dialog).toHaveCount(0);
  await dismissToasts(page);
}

test("vaults: create, rename, move and copy, the Personal default and the All vaults filter", async ({ page }) => {
  const { problems } = watch(page);
  await signUp(page, server.origin, "vaultuser");

  // The Personal vault is listed first and offers no rename or delete (§A1).
  await openVaults(page);
  const pane = page.locator(".vaults-pane");
  const personalRow = pane.locator('tbody tr[data-vault-kind="personal"]');
  await expect(personalRow).toContainText("Personal");
  await expect(personalRow.getByRole("button")).toHaveCount(0);

  // Create, then rename (§A3, §A4).
  await createVault(page, "Work");
  await pane.getByRole("button", { name: "Rename Work" }).click();
  const rename = page.getByRole("dialog", { name: "Rename vault" });
  await rename.getByLabel("Name", { exact: true }).fill("Office");
  await rename.getByRole("button", { name: "Save name" }).click();
  await expect(rename).toHaveCount(0);
  await expect(pane.locator("tbody tr", { hasText: "Office" })).toBeVisible();
  await expect(sidebar(page).getByRole("button", { name: "Office" })).toBeVisible();

  // The new-item picker preselects Personal, every time (§A8, no "last used").
  await allItems(page);
  await newItem(page, "Login");
  const picker = page.locator(".item-editor").getByLabel("Vault", { exact: true });
  await expect(picker.locator("option:checked")).toHaveText("Personal");
  await page.getByRole("button", { name: "Cancel" }).click();
  await newLogin(page, "Desk", "Office");
  await newItem(page, "Login");
  await expect(page.locator(".item-editor").getByLabel("Vault", { exact: true }).locator("option:checked")).toHaveText(
    "Personal",
  );
  await page.getByRole("button", { name: "Cancel" }).click();
  await newLogin(page, "Mail");
  expect(await rowVaults(page, "Mail")).toEqual(["Personal"]);
  expect(await rowVaults(page, "Desk")).toEqual(["Office"]);

  // Move into Office and back (§A6).
  await page.getByRole("list", { name: "Items" }).getByRole("button", { name: /Mail/ }).click();
  await sendTo(page, "Move", "Office");
  await expect(page.getByRole("heading", { name: "Mail" })).toBeVisible();
  expect(await rowVaults(page, "Mail")).toEqual(["Office"]);

  // The vault filter: Personal hides it, Office shows it, All vaults shows everything.
  await sidebar(page).getByRole("button", { name: "Personal", exact: true }).click();
  await expect(page.getByRole("list", { name: "Items" })).toHaveCount(0);
  await sidebar(page).getByRole("button", { name: "Office", exact: true }).click();
  await expect(page.getByRole("list", { name: "Items" }).getByRole("listitem")).toHaveCount(2);
  await sidebar(page).getByRole("button", { name: "All vaults" }).click();
  await expect(page.getByRole("list", { name: "Items" }).getByRole("listitem")).toHaveCount(2);

  await page.getByRole("list", { name: "Items" }).getByRole("button", { name: /Mail/ }).click();
  await sendTo(page, "Move", "Personal");
  expect(await rowVaults(page, "Mail")).toEqual(["Personal"]);

  // A copy: a second item, in the other vault; the original stays.
  await sendTo(page, "Copy", "Office");
  expect(await rowVaults(page, "Mail")).toEqual(["Office", "Personal"]);

  // Delete Office with the preselected choice: its items land in Personal (§A5).
  await openVaults(page);
  await pane.getByRole("button", { name: "Delete Office" }).click();
  const del = page.getByRole("dialog", { name: "Delete vault Office" });
  await expect(del.getByRole("radio", { name: "Move its 2 items to Personal, then delete" })).toBeChecked();
  await expect(del.getByRole("radio", { name: "Delete the vault and its 2 items" })).not.toBeChecked();
  const submit = del.getByRole("button", { name: "Delete vault" });
  await expect(submit).toBeDisabled();
  await del.getByLabel("Type the vault's name to confirm").fill("office");
  await expect(submit).toBeDisabled();
  await del.getByLabel("Type the vault's name to confirm").fill("Office");
  await submit.click();
  await expect(del).toHaveCount(0);
  await expect(pane.locator("tbody tr")).toHaveCount(1);
  await expect(sidebar(page).getByRole("button", { name: "Office" })).toHaveCount(0);
  await allItems(page);
  expect(await rowVaults(page, "Mail")).toEqual(["Personal", "Personal"]);
  expect(await rowVaults(page, "Desk")).toEqual(["Personal"]);
  expect(problems).toEqual([]);
});

test("vaults: delete a vault with its items; import and export pick Personal", async ({ page }) => {
  const { problems } = watch(page);
  await signUp(page, server.origin, "vaultdelete");
  await createVault(page, "Scratch");
  await allItems(page);
  await newLogin(page, "Throwaway", "Scratch");
  await newLogin(page, "Keeper");

  // The import and export pickers start on Personal (§A8).
  await sidebar(page).getByRole("button", { name: "Export and import" }).click();
  await expect(page.locator("#import-file")).toBeVisible();
  const importForm = page.locator("form", { has: page.locator("#import-file") });
  await expect(importForm.getByLabel("Vault", { exact: true }).locator("option:checked")).toHaveText("Personal");

  await openVaults(page);
  const pane = page.locator(".vaults-pane");
  await pane.getByRole("button", { name: "Delete Scratch" }).click();
  const del = page.getByRole("dialog", { name: "Delete vault Scratch" });
  await del.getByRole("radio", { name: "Delete the vault and its 1 items" }).check();
  await del.getByLabel("Type the vault's name to confirm").fill("Scratch");
  await del.getByRole("button", { name: "Delete vault" }).click();
  await expect(del).toHaveCount(0);
  await allItems(page);
  await expect(page.getByRole("list", { name: "Items" }).getByRole("button", { name: /Throwaway/ })).toHaveCount(0);
  expect(await rowVaults(page, "Keeper")).toEqual(["Personal"]);
  expect(problems).toEqual([]);
});
