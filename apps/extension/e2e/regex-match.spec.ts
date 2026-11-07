// SPDX-License-Identifier: AGPL-3.0-only

// A Regex URI end to end (ADR 0097 §2, §3; plan step 4 "one extension e2e that fills on a Regex
// URI"): two Login items are saved through the web vault's editor with match mode Regex and a
// pattern, the extension enrols and syncs, and the inline menu offers exactly the item whose
// pattern matches the page's normalised URL. ADR 0097 §6 step 1's examples, on a local page:
// the anchored pattern of the whole path matches `/login?x=1` (the query is not part of the
// compared URL) and not `/login/other`; the pattern `x=1` never matches, because the query is
// dropped before the pattern runs.
import { createServer, type Server } from "node:http";
import { fileURLToPath } from "node:url";

import { type BrowserContext, type Page, chromium, test as base, expect } from "@playwright/test";

import { TEST_ACCOUNT_PASSWORD, signUp } from "./account.ts";
import { type RunningServer, startServer } from "./server.ts";
import { withProfileDir } from "./profile.ts";

const EXTENSION_PATH = fileURLToPath(new URL("../dist/chromium", import.meta.url));

/** A login page on every path. */
async function startLoginPageServer(): Promise<{ port: number; stop: () => Promise<void> }> {
  const server: Server = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "text/html" });
    res.end(
      "<!doctype html><html><body><form onsubmit=\"return false\">" +
        '<input type="text" autocomplete="username">' +
        '<input type="password">' +
        '<button type="submit">Log in</button>' +
        "</form></body></html>",
    );
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const port = typeof address === "object" && address !== null ? address.port : 0;
  return {
    port,
    stop: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

const test = base.extend<{ server: RunningServer; context: BrowserContext; extensionId: string }>({
  server: async ({}, use) => {
    const server = await startServer();
    await use(server);
    server.stop();
  },
  context: async ({}, use) => {
    await withProfileDir("rizzy-ext-e2e-regex-", async (userDataDir) => {
      const context = await chromium.launchPersistentContext(userDataDir, {
        headless: true,
        channel: "chromium",
        args: [`--disable-extensions-except=${EXTENSION_PATH}`, `--load-extension=${EXTENSION_PATH}`],
      });
      try {
        await use(context);
      } finally {
        await context.close();
      }
    });
  },
  extensionId: async ({ context }, use) => {
    let [worker] = context.serviceWorkers();
    if (worker === undefined) {
      worker = await context.waitForEvent("serviceworker");
    }
    await use(new URL(worker.url()).host);
  },
});

test.setTimeout(120_000);

/** Saves a Login with one website in Regex mode through the web vault's editor. */
async function createRegexLogin(
  page: Page,
  input: { readonly title: string; readonly username: string; readonly websiteUrl: string; readonly pattern: string },
): Promise<void> {
  await page.getByRole("button", { name: "New item" }).click();
  await page.getByRole("menuitem", { name: "Login" }).click();
  await page.getByLabel("Title").fill(input.title);
  await page.getByLabel("Username", { exact: true }).fill(input.username);
  await page.getByLabel("Password", { exact: true }).fill("regex-item-password");
  await page.getByRole("button", { name: "Add a website" }).click();
  await page.getByLabel("New website 1", { exact: true }).fill(input.websiteUrl);
  await page.getByLabel("New website 1 match mode").selectOption("5");
  await page.getByLabel("New website 1 pattern").fill(input.pattern);
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: input.title })).toBeVisible();
  await expect(page.getByText("Synced", { exact: true })).toBeVisible();
}

test("a Regex URI is offered exactly where its pattern matches the compared URL", async ({
  context,
  extensionId,
  server,
}) => {
  const site = await startLoginPageServer();
  try {
    const origin = `http://127.0.0.1:${site.port}`;
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "regexuser");
    await createRegexLogin(setupPage, {
      title: "Regex Anchored",
      username: "anchored@example.com",
      websiteUrl: `${origin}/login`,
      pattern: `^http://127\\.0\\.0\\.1:${site.port}/login$`,
    });
    await createRegexLogin(setupPage, {
      title: "Regex Query",
      username: "query@example.com",
      websiteUrl: `${origin}/login`,
      pattern: "x=1",
    });
    await setupPage.close();

    const popup = await context.newPage();
    await popup.goto(`chrome-extension://${extensionId}/src/popup/index.html`);
    await popup.getByLabel("Server URL").fill(server.origin);
    await popup.getByLabel("Account (login name)").fill("regexuser");
    await popup.getByLabel("Secret Key").fill(secretKey);
    await popup.getByLabel("Master password").fill(TEST_ACCOUNT_PASSWORD);
    await popup.getByRole("button", { name: "Set up" }).click();
    await expect(popup.getByRole("button", { name: "Lock" })).toBeVisible({ timeout: 30_000 });
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });

    // `/login?x=1`: the compared URL is `http://127.0.0.1:<port>/login`. The anchored pattern
    // matches; `x=1` does not, since the query never reaches the pattern.
    const loginPage = await context.newPage();
    await loginPage.goto(`${origin}/login?x=1`);
    const menu = loginPage.frameLocator("iframe[data-rizzy-inline-menu]");
    const anchored = menu.getByRole("button", { name: "Regex Anchored", exact: false });
    await expect(anchored).toContainText("anchored@example.com", { timeout: 15_000 });
    await expect(menu.getByRole("button", { name: "Regex Query", exact: false })).toHaveCount(0);
    await anchored.click();
    await expect(loginPage.locator('input[type="text"]')).toHaveValue("anchored@example.com");
    await expect(loginPage.locator('input[type="password"]')).toHaveValue("regex-item-password");
    await loginPage.close();

    // `/login/other`: the same site, but `$` ends the anchored pattern at `/login`.
    const otherPage = await context.newPage();
    await otherPage.goto(`${origin}/login/other`);
    const otherMenu = otherPage.frameLocator("iframe[data-rizzy-inline-menu]");
    await expect(otherMenu.getByRole("button", { name: "Generate password" })).toBeVisible({ timeout: 15_000 });
    await expect(otherMenu.getByRole("button", { name: "Regex Anchored", exact: false })).toHaveCount(0);
    await expect(otherMenu.getByRole("button", { name: "Regex Query", exact: false })).toHaveCount(0);
    await otherPage.close();
  } finally {
    await site.stop();
  }
});
