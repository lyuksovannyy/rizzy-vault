// SPDX-License-Identifier: AGPL-3.0-only

// Custom-field autocomplete ids in the item editor (ADR 0076 §2, §10 "Web (Playwright)"):
// setting and clearing an id, the W1, W2, W3 and W5 errors shown inline next to their field,
// the "also used by" warning after a real concurrent merge between two sessions, and an
// imported field without a name shown as "Unnamed field" until it is named. The editor with its
// inline errors and the warning also passes the accessibility audit (`a11y.ts`).
import { type BrowserContext, type Page, expect, test } from "@playwright/test";

import { expectAccessible } from "./a11y.ts";
import { logIn, newItem, signUp, watch } from "./helpers.ts";
import { type RunningServer, startServer } from "./server.ts";

let server: RunningServer;

test.beforeAll(async () => {
  server = await startServer();
});

test.afterAll(() => {
  server.stop();
});

/** Syncs by the header's button and waits until it succeeded with nothing left unsent. */
async function sync(page: Page): Promise<void> {
  await page.getByRole("button", { name: "Sync", exact: true }).click();
  await expect(page.locator(".sync-state")).toHaveText("Synced");
  await expect(page.locator("p.error[role=alert][data-code]")).toHaveCount(0);
}

/** Adds a text custom field to the open editor. */
async function addCustom(page: Page, n: number, label: string, value: string, id?: string): Promise<void> {
  await page.getByRole("button", { name: "Add a custom field" }).click();
  await page.getByLabel(`New custom field ${n} label`, { exact: true }).fill(label);
  await page.getByLabel(`New custom field ${n} value`, { exact: true }).fill(value);
  if (id !== undefined) {
    await page.getByLabel(`New custom field ${n} autocomplete id`, { exact: true }).fill(id);
  }
}

test("autocomplete ids: set, clear, and every inline error", async ({ page }) => {
  const { problems } = watch(page);
  await signUp(page, server.origin, "acuser");
  await newItem(page, "Login");
  await page.getByLabel("Title").fill("Member Co");
  await page.getByLabel("Password", { exact: true }).fill("pw-1");

  // W1: the input lowercases ASCII as typed; a space or a non-ASCII letter is refused inline.
  await addCustom(page, 1, "Member no.", "M-1", "Member No");
  const id1 = page.getByLabel("New custom field 1 autocomplete id", { exact: true });
  await expect(id1).toHaveValue("member no");
  await expect(id1).toHaveAttribute("aria-invalid", "true");
  await expect(page.getByText("Use 1–64 lowercase letters, digits")).toBeVisible();
  await id1.fill("member-no");
  await expect(id1).toHaveAttribute("aria-invalid", "false");

  // Keyboard only: the id input follows the value in tab order and takes typed text.
  await page.getByLabel("New custom field 1 value", { exact: true }).focus();
  await page.keyboard.press("Tab");
  await expect(id1).toBeFocused();
  await page.keyboard.press("ControlOrMeta+a");
  await page.keyboard.type("Member-No");
  await expect(id1).toHaveValue("member-no");
  await page.keyboard.press("Tab");
  // The row's move buttons are disabled while it is the only new row: next is its Remove.
  await expect(page.locator(":focus")).toHaveText("Remove");

  // W2: a reserved id.
  await addCustom(page, 2, "Code", "C-2", "one-time-code");
  await expect(page.getByText("This autocomplete id is reserved for the manager")).toBeVisible();
  // W3: the same id on two fields of the item.
  const id2 = page.getByLabel("New custom field 2 autocomplete id", { exact: true });
  await id2.fill("member-no");
  await expect(page.getByText("Another custom field of this item already uses this autocomplete id.")).toHaveCount(2);
  await expectAccessible(page, "item editor: autocomplete id errors");
  // Save is refused while an error stands, and says why.
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.locator("p.error[role=alert][data-code=autocomplete_duplicate]")).toBeVisible();
  await id2.fill("branch");

  // W5: a field with a value but no Display Name.
  await addCustom(page, 3, "", "orphan");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByText("A display name is required.")).toBeVisible();
  await expect(page.getByLabel("New custom field 3 label", { exact: true })).toHaveAttribute("aria-invalid", "true");
  await page.getByLabel("New custom field 3 label", { exact: true }).fill("Orphan");

  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "Member Co" })).toBeVisible();
  await expect(page.getByText("Synced", { exact: true })).toBeVisible();

  // The editor shows the saved ids; clearing one and changing another write as one edit.
  await page.getByRole("button", { name: "Edit" }).click();
  const saved1 = page.getByLabel("Custom field 1 autocomplete id", { exact: true });
  const saved2 = page.getByLabel("Custom field 2 autocomplete id", { exact: true });
  await expect(saved1).toHaveValue("member-no");
  await expect(saved2).toHaveValue("branch");
  await saved1.fill("");
  await saved2.fill("member-no");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "Member Co" })).toBeVisible();
  await page.getByRole("button", { name: "Edit" }).click();
  await expect(saved1).toHaveValue("");
  await expect(saved2).toHaveValue("member-no");
  // An existing field's Display Name cannot be emptied (W5).
  await page.getByLabel("Custom field 2 label", { exact: true }).fill(" ");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByText("A display name is required.")).toBeVisible();
  expect(problems).toEqual([]);
});

/** The browser contexts that are offline now. */
const offline = new Set<BrowserContext>();

/** Routes every API request of `context` through the offline switch (as `conflict.spec.ts`). */
async function routeApi(context: BrowserContext): Promise<void> {
  await context.route("**/api/v1/**", (route) =>
    offline.has(context) ? route.abort("internetdisconnected") : route.continue(),
  );
}

/** Sets custom field `n`'s id to `id` while offline: the edit stays in the session's memory. */
async function offlineSetId(context: BrowserContext, page: Page, n: number, id: string): Promise<void> {
  offline.add(context);
  await context.setOffline(true);
  await page.getByRole("button", { name: "Edit" }).click();
  await page.getByLabel(`Custom field ${n} autocomplete id`, { exact: true }).fill(id);
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "Merge Co" })).toBeVisible();
  await expect(page.locator("p.error[role=alert][data-code]")).toBeVisible();
}

test("a merge-made duplicate id: a warning names the field that fills; an imported field is unnamed", async ({ browser }) => {
  const contextA = await browser.newContext();
  await routeApi(contextA);
  const a = await contextA.newPage();
  const watchA = watch(a);
  const secretKey = await signUp(a, server.origin, "acmerge");
  await newItem(a, "Login");
  await a.getByLabel("Title").fill("Merge Co");
  await addCustom(a, 1, "Account", "A-1");
  await addCustom(a, 2, "Branch", "B-2");
  await a.getByRole("button", { name: "Save" }).click();
  await expect(a.getByRole("heading", { name: "Merge Co" })).toBeVisible();
  await sync(a);

  const contextB = await browser.newContext();
  await routeApi(contextB);
  const b = await contextB.newPage();
  const watchB = watch(b);
  await b.goto(server.origin);
  await logIn(b, "acmerge", secretKey);
  await b.getByRole("button", { name: /Merge Co/ }).click();
  await expect(b.getByRole("heading", { name: "Merge Co" })).toBeVisible();

  // Each session tags a different field "acct" offline: neither sees the other's write, so
  // neither is refused (W3). After the merge both fields hold it.
  await offlineSetId(contextA, a, 1, "acct");
  await offlineSetId(contextB, b, 2, "acct");
  for (const context of [contextA, contextB]) {
    offline.delete(context);
    await context.setOffline(false);
  }
  await sync(a);
  await sync(b);
  await sync(a);

  for (const page of [a, b]) {
    await page.getByRole("button", { name: "Edit" }).click();
    await expect(page.getByLabel("Custom field 1 autocomplete id", { exact: true })).toHaveValue("acct");
    await expect(page.getByLabel("Custom field 2 autocomplete id", { exact: true })).toHaveValue("acct");
    // Only the second field is shadowed, and the warning names the first: the same on both.
    await expect(
      page.getByText("Autocomplete id “acct” is also used by “Account”; only that field is filled. Change or clear one."),
    ).toHaveCount(1);
  }
  await expectAccessible(a, "item editor: a merge-made duplicate id");
  // An unrelated edit still saves; changing one id resolves the duplicate.
  await a.getByLabel("Title").fill("Merge Co");
  await a.getByLabel("Custom field 2 autocomplete id", { exact: true }).fill("branch");
  await a.getByRole("button", { name: "Save" }).click();
  await expect(a.getByRole("heading", { name: "Merge Co" })).toBeVisible();
  await a.getByRole("button", { name: "Edit" }).click();
  await expect(a.getByText(/is also used by/)).toHaveCount(0);
  await a.getByRole("button", { name: "Cancel" }).click();

  // An imported field without a name (ADR 0076 §2.4): shown as "Unnamed field"; it keeps its
  // value; naming it is the edit that lets it take an id.
  const file = JSON.stringify({
    encrypted: false,
    folders: [],
    collections: [],
    items: [
      {
        id: "11111111-1111-1111-1111-111111111111",
        folderId: null,
        organizationId: null,
        type: 1,
        name: "Imported Co",
        notes: null,
        favorite: false,
        login: { username: "imp", password: "pw", totp: null, uris: [] },
        fields: [{ name: "", value: "nameless-value", type: 0 }],
      },
    ],
  });
  await a.getByRole("button", { name: "Export and import", exact: true }).click();
  await a.getByLabel("File", { exact: true }).setInputFiles({
    name: "bitwarden.json",
    mimeType: "application/json",
    buffer: Buffer.from(file),
  });
  await a.getByRole("button", { name: "Import", exact: true }).click();
  await expect(a.getByTestId("import-report")).toBeVisible({ timeout: 30_000 });
  await a.getByRole("button", { name: "All items", exact: true }).click();
  await a.getByRole("button", { name: /Imported Co/ }).click();
  await expect(a.getByText("Unnamed field", { exact: true })).toBeVisible();
  await a.getByRole("button", { name: "Edit" }).click();
  const unnamed = a.getByLabel("Custom field 1 label", { exact: true });
  await expect(unnamed).toHaveAttribute("placeholder", "Unnamed field");
  await a.getByLabel("Custom field 1 autocomplete id", { exact: true }).fill("imported");
  await a.getByRole("button", { name: "Save" }).click();
  await expect(a.getByText("A display name is required.")).toBeVisible();
  await unnamed.fill("Imported");
  await a.getByRole("button", { name: "Save" }).click();
  await expect(a.getByRole("heading", { name: "Imported Co" })).toBeVisible();
  await expect(a.getByText("Imported", { exact: true })).toBeVisible();

  const real = (p: readonly string[]) =>
    p.filter((x) => !/ERR_INTERNET_DISCONNECTED|Failed to fetch|NetworkError|net::ERR_/.test(x));
  expect(real(watchA.problems)).toEqual([]);
  expect(real(watchB.problems)).toEqual([]);
  await contextA.close();
  await contextB.close();
});
