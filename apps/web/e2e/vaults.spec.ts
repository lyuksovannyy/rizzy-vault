// SPDX-License-Identifier: AGPL-3.0-only

// Several vaults in the web vault (ADR 0081 Part A, §A3–§A8): create, rename, move an item into
// a vault and back, copy, the pickers' Personal default, the "All vaults" filter, delete with
// both choices, and the Personal vault offering no delete or rename. A third test exports one
// vault (§A8: the export dialog's vault picker, one payload per vault), imports the file into
// another vault and finds each item where it should be; then deletes a vault from a stale
// session (§A5: `fresh_session_required`, here once from a route), which asks for the Secret
// Key and master password, logs in afresh and retries the delete.
import { readFile } from "node:fs/promises";

import { type Page, expect, test } from "@playwright/test";

import { expectAccessible } from "./a11y.ts";
import { PASSWORD, dismissToasts, newItem, signUp, watch } from "./helpers.ts";
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

test("exports one vault, imports it into another, and deletes a vault from a stale session", async ({ page }) => {
  const FILE_PASSWORD = "a password for this vault's file";
  const { problems } = watch(page);
  const secretKey = await signUp(page, server.origin, "vaultexport");
  await createVault(page, "Work");
  await allItems(page);
  await newLogin(page, "Work login", "Work");
  await newLogin(page, "Home login");
  expect(await rowVaults(page, "Work login")).toEqual(["Work"]);
  expect(await rowVaults(page, "Home login")).toEqual(["Personal"]);

  // §A8: the export holds one vault, the one picked (Personal preselected).
  await page.getByRole("button", { name: "Export and import", exact: true }).click();
  await page.getByLabel("Secret Key", { exact: true }).fill(secretKey);
  await page.getByLabel("Master password", { exact: true }).fill(PASSWORD);
  await page.getByRole("button", { name: "Confirm", exact: true }).click();
  const exportPane = page.getByRole("region", { name: "Export" });
  const exportVault = exportPane.getByLabel("Vault", { exact: true });
  await expect(exportVault.locator("option:checked")).toHaveText("Personal");
  await exportVault.selectOption({ label: "Work" });
  await exportPane.getByLabel("Password for this export file", { exact: true }).fill(FILE_PASSWORD);
  await exportPane.getByLabel("Repeat the password for this export file", { exact: true }).fill(FILE_PASSWORD);
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    exportPane.getByRole("button", { name: "Export encrypted" }).click(),
  ]);
  const exportPath = await download.path();
  expect((await readFile(exportPath)).toString("utf8").startsWith('{"format":"rizzy-vault-export"')).toBe(true);

  // Imported into a new vault: the Work item lands there, and only it.
  await createVault(page, "Restored");
  await page.getByRole("button", { name: "Export and import", exact: true }).click();
  await page.getByLabel("File", { exact: true }).setInputFiles(exportPath);
  await expect(page.getByTestId("import-detected")).toHaveText("Recognised: rizzy-vault encrypted export.");
  const importVault = page.locator('select[name="import-vault"]');
  await expect(importVault.locator("option:checked")).toHaveText("Personal");
  await importVault.selectOption({ label: "Restored" });
  await page.getByLabel("Password of this export file", { exact: true }).fill(FILE_PASSWORD);
  await page.getByRole("button", { name: "Import", exact: true }).click();
  await expect(page.getByTestId("import-report")).toContainText("Imported 1");
  await allItems(page);
  expect(await rowVaults(page, "Work login")).toEqual(["Restored", "Work"]);
  expect(await rowVaults(page, "Home login")).toEqual(["Personal"]);
  await sidebar(page).getByRole("button", { name: "Restored", exact: true }).click();
  await expect(page.getByRole("list", { name: "Items" }).getByRole("listitem")).toHaveCount(1);
  await expect(page.getByRole("list", { name: "Items" }).getByRole("button", { name: /Work login/ })).toBeVisible();
  await dismissToasts(page);

  // §A5: the server needs a fresh login for a delete. The signup's session is fresh, so the
  // first delete is refused here as an older session's would be (403 fresh_session_required).
  let refused = 0;
  let deletes = 0;
  await page.route("**/api/v1/account/commit", async (route) => {
    if (!(route.request().postData() ?? "").includes('"vault_delete"')) {
      await route.continue();
      return;
    }
    deletes++;
    if (refused > 0) {
      await route.continue();
      return;
    }
    refused++;
    await route.fulfill({
      status: 403,
      contentType: "application/json",
      body: JSON.stringify({ error: "fresh_session_required" }),
    });
  });
  await openVaults(page);
  const pane = page.locator(".vaults-pane");
  await pane.getByRole("button", { name: "Delete Restored" }).click();
  const del = page.getByRole("dialog", { name: "Delete vault Restored" });
  await del.getByRole("radio", { name: "Delete the vault and its 1 items" }).check();
  await del.getByLabel("Type the vault's name to confirm").fill("Restored");
  await del.getByRole("button", { name: "Delete vault" }).click();
  // The dialog asks for the Secret Key and master password, then retries the delete.
  const reauth = page.getByRole("dialog", { name: "Confirm it is you" });
  await expect(reauth).toBeVisible();
  expect(refused).toBe(1);
  await expectAccessible(page, "vault delete: confirm it is you");
  await reauth.getByLabel("Secret Key", { exact: true }).fill(secretKey);
  await reauth.getByLabel("Master password", { exact: true }).fill(PASSWORD);
  await reauth.getByRole("button", { name: "Confirm", exact: true }).click();
  await expect(reauth).toHaveCount(0);
  await expect(pane.locator("tbody tr")).toHaveCount(2);
  await expect(sidebar(page).getByRole("button", { name: "Restored" })).toHaveCount(0);
  expect(deletes).toBe(2);
  await page.unroute("**/api/v1/account/commit");
  // The session is the fresh one now: the next sync and the items still work.
  await allItems(page);
  expect(await rowVaults(page, "Work login")).toEqual(["Work"]);
  expect(await rowVaults(page, "Home login")).toEqual(["Personal"]);
  expect(problems.filter((p) => !/403|Forbidden/.test(p))).toEqual([]);
});
