// SPDX-License-Identifier: AGPL-3.0-only

// Sessions end to end (ADR 0075 §6, §8, §9; `src/views/SessionsSection.tsx`): two web sessions of
// one account, each in its own browser context. A lists both under Settings → Devices, ends B's,
// and B is locked out at its next request with "This session has ended. Log in again." A stale
// session (the server answers `fresh_session_required`, here once from a route) first asks for
// the Secret Key and master password, switches to a fresh login and then ends the others. A
// lock ends the session on the server too. Every new screen and dialog passes the accessibility
// audit (`a11y.ts`), and the section is operated by keyboard alone.
import { type BrowserContext, type Page, expect, test } from "@playwright/test";

import { expectAccessible, expectFocusTrapped, tabTo } from "./a11y.ts";
import { PASSWORD, lockVault, logIn, signUp, watch } from "./helpers.ts";
import { type RunningServer, startServer } from "./server.ts";

let server: RunningServer;

test.beforeAll(async () => {
  server = await startServer();
});

test.afterAll(() => {
  server.stop();
});

/** Opens Settings, from another section first, so the session list loads afresh. */
async function openSettings(page: Page): Promise<void> {
  await page.getByRole("button", { name: "All items" }).click();
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Sessions" })).toBeVisible();
}

/** The session table. */
function table(page: Page) {
  return page.getByRole("table", { name: "Sessions" });
}

/** A second session of the account, in a context of its own. */
async function second(context: BrowserContext, loginName: string, secretKey: string): Promise<Page> {
  const page = await context.newPage();
  await page.goto(server.origin);
  await logIn(page, loginName, secretKey);
  await expect(page.getByRole("button", { name: "Sync", exact: true })).toBeVisible();
  return page;
}

test("one session ends another, which is locked out at its next request", async ({ browser }) => {
  const contextA = await browser.newContext();
  const a = await contextA.newPage();
  const watchA = watch(a);
  const secretKey = await signUp(a, server.origin, "sessionsuser");

  const contextB = await browser.newContext();
  const b = await second(contextB, "sessionsuser", secretKey);
  const watchB = watch(b);

  await openSettings(a);
  const rows = table(a).getByRole("row");
  // The header row, A's own row (marked), and B's.
  await expect(rows).toHaveCount(3);
  await expect(table(a).locator("tr[aria-current=true]")).toContainText("(this session)");
  await expect(table(a).getByRole("button", { name: /^End / })).toHaveCount(1);
  await expectAccessible(a, "settings: sessions");

  await table(a).getByRole("button", { name: /^End / }).click();
  const dialog = a.getByRole("dialog");
  await expectFocusTrapped(a, dialog, "end-session dialog");
  await expectAccessible(a, "end-session dialog");
  await dialog.getByRole("button", { name: "End", exact: true }).click();
  await expect(a.getByRole("status")).toContainText("change your password");
  await expect(rows).toHaveCount(2);

  // B's next request answers 401: it locks, and says why.
  await b.getByRole("button", { name: "Sync", exact: true }).click();
  await expect(b.getByText("This session has ended. Log in again.")).toBeVisible();
  await expect(b.getByLabel("Secret Key", { exact: true })).toBeVisible();
  await expectAccessible(b, "login after the session was ended");
  // Logging in again works.
  await logIn(b, undefined, secretKey);
  await expect(b.getByRole("button", { name: "Sync", exact: true })).toBeVisible();

  // A lock ends the session on the server: A sees B's row go once B locks.
  await openSettings(a);
  await expect(rows).toHaveCount(3);
  await lockVault(b);
  await expect(b.getByLabel("Secret Key", { exact: true })).toBeVisible();
  await expect(async () => {
    await openSettings(a);
    await expect(rows).toHaveCount(2, { timeout: 1_000 });
  }).toPass();

  expect(watchA.problems).toEqual([]);
  expect(watchB.problems.filter((p) => !/401|Unauthorized/.test(p))).toEqual([]);
  await contextA.close();
  await contextB.close();
});

test("a stale session logs in again before it ends the others, by keyboard alone", async ({ browser }) => {
  const contextA = await browser.newContext();
  const a = await contextA.newPage();
  const watchA = watch(a);
  const secretKey = await signUp(a, server.origin, "stalesessions");
  const contextB = await browser.newContext();
  const b = await second(contextB, "stalesessions", secretKey);

  // The server's clock cannot be moved here: the first R4 answers as a session older than five
  // minutes would (ADR 0075 R4, 403 fresh_session_required).
  let refused = false;
  await contextA.route("**/api/v1/sessions/others/end", async (route) => {
    if (refused) {
      await route.continue();
      return;
    }
    refused = true;
    await route.fulfill({
      status: 403,
      contentType: "application/json",
      body: JSON.stringify({ error: "fresh_session_required" }),
    });
  });

  await openSettings(a);
  await expect(table(a).getByRole("row")).toHaveCount(3);
  const kb = a.keyboard;
  const endAll = a.getByRole("button", { name: "End all other sessions" });
  await tabTo(a, endAll, { max: 200 });
  await kb.press("Enter");
  const dialog = a.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await tabTo(a, dialog.getByRole("button", { name: "End", exact: true }));
  await kb.press("Enter");

  const form = a.getByRole("form", { name: "Log in again to end sessions" });
  await expect(form).toBeVisible();
  await expectAccessible(a, "settings: sessions, log in again");
  await tabTo(a, form.getByLabel("Secret Key", { exact: true }));
  await kb.type(secretKey);
  await tabTo(a, form.getByLabel("Master password", { exact: true }));
  await kb.type(PASSWORD);
  await tabTo(a, form.getByRole("button", { name: "Log in and continue" }));
  await kb.press("Enter");
  await expect(a.getByRole("status")).toContainText("Other sessions ended");
  expect(refused).toBe(true);

  // Only A's new session is left: its old one was ended when it switched, B's by R4.
  await openSettings(a);
  await expect(table(a).getByRole("row")).toHaveCount(2);
  await b.getByRole("button", { name: "Sync", exact: true }).click();
  await expect(b.getByText("This session has ended. Log in again.")).toBeVisible();
  // A still works on its new session.
  await a.getByRole("button", { name: "Sync", exact: true }).click();
  await expect(a.locator(".sync-state")).toHaveText("Synced");

  expect(watchA.problems.filter((p) => !/403|Forbidden/.test(p))).toEqual([]);
  await contextA.close();
  await contextB.close();
});

