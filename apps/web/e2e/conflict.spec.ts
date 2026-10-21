// SPDX-License-Identifier: AGPL-3.0-only

// The conflict chooser end to end (ROADMAP §4.5 "edited on Phone and Laptop at the same time —
// keep both / pick one"; ADR 0012 §4 step 5, ADR 0018 §6; `src/views/ConflictChooser.tsx`):
// two sessions of one account, each in its own browser context, edit the same password while
// offline, then sync. Both values stay and the field conflicts. The first round is resolved by
// "pick one" on one session, the second by "keep both" on the other, and each resolution
// reaches the other session through an ordinary sync. Concealed values stay masked in the
// chooser until the user reveals one (ADR 0013 §3 rule 3).
import { type BrowserContext, type Page, expect, test } from "@playwright/test";

import { logIn, newItem, signUp, watch } from "./helpers.ts";
import { type RunningServer, startServer } from "./server.ts";

let server: RunningServer;

test.beforeAll(async () => {
  server = await startServer();
});

test.afterAll(() => {
  server.stop();
});

/** Edits the open item's password to `value` through the editor. */
async function editPassword(page: Page, value: string): Promise<void> {
  await page.getByRole("button", { name: "Edit" }).click();
  await page.getByLabel("Password", { exact: true }).fill(value);
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "Conflict Co" })).toBeVisible();
}

/** Syncs by the header's button and waits until it succeeded with nothing left unsent. */
async function sync(page: Page): Promise<void> {
  await page.getByRole("button", { name: "Sync", exact: true }).click();
  await expect(page.locator(".sync-state")).toHaveText("Synced");
  await expect(page.locator("p.error[role=alert][data-code]")).toHaveCount(0);
}

/** The browser contexts that are offline now (`goOffline`). */
const offline = new Set<BrowserContext>();

/**
 * Takes `context` offline for the vault API. `setOffline` covers the page; the vault's requests
 * come from its core Worker, so they are refused by a route as well, as a lost network would.
 */
async function goOffline(context: BrowserContext): Promise<void> {
  offline.add(context);
  await context.setOffline(true);
}

/** Routes every API request of `context` through the offline switch. */
async function routeApi(context: BrowserContext): Promise<void> {
  await context.route("**/api/v1/**", (route) =>
    offline.has(context) ? route.abort("internetdisconnected") : route.continue(),
  );
}

/** Both sessions go offline, edit the password to their own value, and come back online. */
async function offlineEdits(
  sessions: readonly (readonly [BrowserContext, Page, string])[],
): Promise<void> {
  for (const [context, page, value] of sessions) {
    await goOffline(context);
    await editPassword(page, value);
    // Written to the session's memory, not to the server: the sync after the save failed.
    await expect(page.locator("p.error[role=alert][data-code]")).toBeVisible();
  }
  for (const [context] of sessions) {
    offline.delete(context);
    await context.setOffline(false);
  }
}

/** Console problems, without the failed requests of the offline phase itself. */
function realProblems(problems: readonly string[]): string[] {
  return problems.filter((p) => !/ERR_INTERNET_DISCONNECTED|Failed to fetch|NetworkError|net::ERR_/.test(p));
}

test("an offline conflict between two sessions: pick one, then keep both", async ({ browser }) => {
  const contextA = await browser.newContext();
  await routeApi(contextA);
  const a = await contextA.newPage();
  const watchA = watch(a);
  const secretKey = await signUp(a, server.origin, "conflictuser");
  await newItem(a, "Login");
  await a.getByLabel("Title").fill("Conflict Co");
  await a.getByLabel("Password", { exact: true }).fill("base-password");
  await a.getByRole("button", { name: "Save" }).click();
  await expect(a.getByRole("heading", { name: "Conflict Co" })).toBeVisible();
  await sync(a);

  // A second session of the same account, in a browser context of its own.
  const contextB = await browser.newContext();
  await routeApi(contextB);
  const b = await contextB.newPage();
  const watchB = watch(b);
  await b.goto(server.origin);
  await logIn(b, "conflictuser", secretKey);
  await b.getByRole("button", { name: /Conflict Co/ }).click();
  await expect(b.getByRole("heading", { name: "Conflict Co" })).toBeVisible();

  // Round 1: both edit offline, then sync. Both values stay; the field conflicts on both.
  await offlineEdits([
    [contextA, a, "from-a"],
    [contextB, b, "from-b"],
  ]);
  await sync(a);
  await sync(b);
  await sync(a);
  const rowA = a.locator('[data-field="login.password"]');
  const rowB = b.locator('[data-field="login.password"]');
  await expect(rowA.locator(".badge", { hasText: "conflict" })).toBeVisible();
  await expect(rowB.locator(".badge", { hasText: "conflict" })).toBeVisible();

  // Pick one, on A. The chooser names the devices and masks both passwords.
  await rowA.getByRole("button", { name: "Resolve conflict" }).click();
  const chooserA = rowA.locator(".conflict-chooser");
  await expect(chooserA).toContainText("at the same time");
  const valuesA = chooserA.locator("li.conflict-value");
  await expect(valuesA).toHaveCount(2);
  await expect(chooserA.locator(".masked")).toHaveCount(2);
  await expect(chooserA.locator("input[data-secret-field]")).toHaveCount(0);
  await expect(a.getByText("from-b")).toHaveCount(0);
  const fromB = valuesA.filter({ hasNotText: "this browser" });
  await expect(fromB).toHaveCount(1);
  // Revealing one value shows that value only.
  await fromB.getByRole("button", { name: "Reveal" }).click();
  await expect(fromB.locator("input[data-secret-field]")).toHaveValue("from-b");
  await expect(chooserA.locator("input[data-secret-field]")).toHaveCount(1);
  await fromB.getByRole("button", { name: "Use this value" }).click();
  await expect(a.locator(".sync-state")).toHaveText("Synced");
  await expect(rowA.locator(".badge", { hasText: "conflict" })).toHaveCount(0);
  await rowA.getByRole("button", { name: "Reveal" }).click();
  await expect(rowA.locator("input[data-secret-field]")).toHaveValue("from-b");

  // B learns of the resolution by an ordinary sync: no conflict, the picked value.
  await sync(b);
  await expect(rowB.locator(".badge", { hasText: "conflict" })).toHaveCount(0);
  await rowB.getByRole("button", { name: "Reveal" }).click();
  await expect(rowB.locator("input[data-secret-field]")).toHaveValue("from-b");

  // Round 2: another offline race, resolved by keep both on B.
  await offlineEdits([
    [contextA, a, "second-a"],
    [contextB, b, "second-b"],
  ]);
  await sync(a);
  await sync(b);
  await sync(a);
  await expect(rowB.locator(".badge", { hasText: "conflict" })).toBeVisible();
  await rowB.getByRole("button", { name: "Resolve conflict" }).click();
  const chooserB = rowB.locator(".conflict-chooser");
  await expect(chooserB.locator("li.conflict-value")).toHaveCount(2);
  await expect(chooserB.locator(".masked")).toHaveCount(2);
  await chooserB.getByRole("button", { name: "Keep both" }).click();
  await expect(b.locator(".sync-state")).toHaveText("Synced");
  await expect(rowB.locator(".badge", { hasText: "conflict" })).toHaveCount(0);

  // On both sessions: the password holds one value, and a new hidden field labelled after the
  // device of the other holds the other; together they are the two values of the race.
  await sync(a);
  for (const page of [a, b]) {
    const password = page.locator('[data-field="login.password"]');
    await expect(password.locator(".badge", { hasText: "conflict" })).toHaveCount(0);
    const copy = page.locator('.field[data-field^="field/"]').filter({ hasText: /Password \(from / });
    await expect(copy).toHaveCount(1);
    // Hidden until revealed, like the password itself.
    await expect(copy.locator(".masked")).toHaveCount(1);
    await password.getByRole("button", { name: "Reveal" }).click();
    await copy.getByRole("button", { name: "Reveal" }).click();
    const kept = await password.locator("input[data-secret-field]").inputValue();
    const moved = await copy.locator("input[data-secret-field]").inputValue();
    expect([kept, moved].sort()).toEqual(["second-a", "second-b"]);
  }
  await expect(a.locator(".conflict-chooser")).toHaveCount(0);

  expect(realProblems(watchA.problems)).toEqual([]);
  expect(realProblems(watchB.problems)).toEqual([]);
  await contextA.close();
  await contextB.close();
});
