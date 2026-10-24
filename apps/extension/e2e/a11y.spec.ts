// SPDX-License-Identifier: AGPL-3.0-only

// The accessibility audit of the extension's own surfaces (ROADMAP §4.5's accessibility Must;
// ADR 0014 §5's "web vault and extension pages"), with `a11y.ts`: the popup in each of its views
// (set up, items, an item, generator, locked), the options page, and the inline menu's
// extension-origin `<iframe>` inside a login page. The popup is operated by keyboard alone
// throughout (`tabTo`): set up, open an item, back, generator, lock, unlock. Self-contained (its
// own server and account), so it runs on its own:
// `pnpm --filter @rizzy-vault/extension exec playwright test e2e/a11y.spec.ts`.
//
// Headless (`headless: true, channel: "chromium"`) for the reason `extension.spec.ts` gives.
import { type BrowserContext, type Locator, type Page, chromium, test as base, expect } from "@playwright/test";
import { mkdtempSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { expectAccessible } from "./a11y.ts";
import { TEST_ACCOUNT_PASSWORD, createLoginItem, signUp } from "./account.ts";
import { type RunningServer, startServer } from "./server.ts";

const EXTENSION_PATH = fileURLToPath(new URL("../dist/chromium", import.meta.url));

/** An accessible login page of its own, so whatever the audit finds there is the inline menu's. */
const LOGIN_PAGE =
  '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Example login</title></head>' +
  '<body><main><h1>Log in</h1><form onsubmit="return false">' +
  '<label for="u">Username</label> <input id="u" type="text" autocomplete="username">' +
  '<label for="p">Password</label> <input id="p" type="password">' +
  '<button type="submit">Log in</button></form></main></body></html>';

const test = base.extend<{ server: RunningServer; context: BrowserContext; extensionId: string }>({
  server: async ({}, use) => {
    const server = await startServer();
    await use(server);
    server.stop();
  },
  context: async ({}, use) => {
    const userDataDir = mkdtempSync(join(tmpdir(), "rizzy-ext-e2e-a11y-"));
    const context = await chromium.launchPersistentContext(userDataDir, {
      headless: true,
      channel: "chromium",
      args: [`--disable-extensions-except=${EXTENSION_PATH}`, `--load-extension=${EXTENSION_PATH}`],
    });
    await use(context);
    await context.close();
  },
  extensionId: async ({ context }, use) => {
    let [worker] = context.serviceWorkers();
    if (worker === undefined) {
      worker = await context.waitForEvent("serviceworker");
    }
    await use(new URL(worker.url()).host);
  },
});

async function openPopup(context: BrowserContext, extensionId: string): Promise<Page> {
  const page = await context.newPage();
  await page.goto(`chrome-extension://${extensionId}/src/popup/index.html`);
  return page;
}

/** Moves the focus to `target` with Tab alone, failing when it is not reached within `max`
 * presses (`apps/web/e2e/a11y.ts`'s `tabTo`). */
async function tabTo(page: Page, target: Locator, max = 40): Promise<void> {
  await expect(target).toBeVisible();
  for (let i = 0; i < max; i++) {
    if (await target.evaluate((el) => el === document.activeElement)) {
      return;
    }
    await page.keyboard.press("Tab");
  }
  expect(await target.evaluate((el) => el === document.activeElement), `${String(target)} not reached by Tab`).toBe(true);
}

test.setTimeout(120_000);

test("a11y: the popup's views, the options page and the inline menu", async ({ context, extensionId, server }) => {
  const loginPage = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "text/html" });
    res.end(LOGIN_PAGE);
  });
  await new Promise<void>((resolve) => loginPage.listen(0, "127.0.0.1", resolve));
  const address = loginPage.address();
  const origin = `http://127.0.0.1:${typeof address === "object" && address !== null ? address.port : 0}/`;
  try {
    // The options page and the popup's set-up view need no account.
    const options = await context.newPage();
    await options.goto(`chrome-extension://${extensionId}/src/options/index.html`);
    await expect(options.getByRole("heading", { name: "rizzy-vault settings" })).toBeVisible();
    // The third-party notices (THIRD_PARTY_NOTICES.md; ADR 0080 owner answer 5).
    const notices = options.getByRole("region", { name: "Third-party notices" });
    await expect(notices).toContainText("EFF's Long Wordlist");
    await expect(notices).toContainText(
      "Default site groups derived from the Bitwarden server's equivalent-domains list via Vaultwarden, AGPL-3.0.",
    );
    await expectAccessible(options, "options page");
    await options.close();

    const popup = await openPopup(context, extensionId);
    await expect(popup.getByLabel("Server URL")).toBeVisible();
    await expectAccessible(popup, "popup: set up this device");

    // An account with one login for the test page, set up from the popup.
    const setup = await context.newPage();
    const secretKey = await signUp(setup, server.origin, "a11yext");
    await createLoginItem(setup, { title: "Audit Site", username: "audit@example.com", password: "audit-pw", websiteUrl: origin });
    await setup.close();
    await popup.bringToFront();
    const kb = popup.keyboard;
    await tabTo(popup, popup.getByLabel("Server URL"));
    await kb.type(server.origin);
    await tabTo(popup, popup.getByLabel("Account (login name)"));
    await kb.type("a11yext");
    await tabTo(popup, popup.getByLabel("Secret Key"));
    await kb.type(secretKey);
    await tabTo(popup, popup.getByLabel("Master password"));
    await kb.type(TEST_ACCOUNT_PASSWORD);
    await tabTo(popup, popup.getByRole("button", { name: "Set up" }));
    await kb.press("Enter");
    await expect(popup.getByRole("button", { name: "Lock" })).toBeVisible({ timeout: 30_000 });
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await expect(popup.getByRole("button", { name: /Audit Site/ })).toBeVisible();
    await expectAccessible(popup, "popup: items");
    await tabTo(popup, popup.getByRole("button", { name: /Audit Site/ }));
    await kb.press("Enter");
    await expect(popup.getByText("audit@example.com")).toBeVisible();
    await expectAccessible(popup, "popup: an item");
    await tabTo(popup, popup.getByRole("button", { name: "Back" }));
    await kb.press("Enter");
    await tabTo(popup, popup.getByRole("button", { name: "Generator" }));
    await kb.press("Enter");
    await expect(popup.getByRole("heading", { name: "Generator" })).toBeVisible();
    await expectAccessible(popup, "popup: generator");

    // The inline menu, in its iframe on the login page.
    const page = await context.newPage();
    await page.goto(origin);
    const menu = page.frameLocator("iframe[data-rizzy-inline-menu]");
    await expect(menu.getByRole("button", { name: /Audit Site/ })).toBeVisible({ timeout: 15_000 });
    await expectAccessible(page, "inline menu (in a login page)");
    await page.close();

    await popup.bringToFront();
    await tabTo(popup, popup.getByRole("button", { name: "Lock" }));
    await kb.press("Enter");
    await expect(popup.getByLabel("Master password")).toBeVisible();
    await expectAccessible(popup, "popup: locked");
    await tabTo(popup, popup.getByLabel("Master password"));
    await kb.type(TEST_ACCOUNT_PASSWORD);
    await kb.press("Enter");
    await expect(popup.getByRole("button", { name: "Lock" })).toBeVisible({ timeout: 30_000 });
  } finally {
    loginPage.closeAllConnections();
    await new Promise<void>((resolve) => loginPage.close(() => resolve()));
  }
});
