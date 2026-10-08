// The save-prompt race fix (`apps/extension/README.md`'s residual note;
// `core-host/save-prompt-location.ts`): a login form whose submit *really* navigates — unlike
// `autofill-and-save.spec.ts`'s own `loginPageHtml`, which deliberately stays on one document
// with `onsubmit="return false"` so it does not hit this race at all — must still get the
// save/update prompt, on the page it navigated to, not nowhere. The two pages here share one
// origin (so the same registrable domain, same tab): a real login form POSTing to `/dashboard`,
// which responds with a second, unrelated page carrying no login fields of its own — exactly the
// shape that broke before this fix, since the content script's own `fields_detected` report
// (gated on finding fields) never fires there at all; only the unconditional `check_save_prompt`
// sent on every load does.
//
// Headless (`headless: true, channel: "chromium"`): see `autofill-and-save.spec.ts`'s own note
// on why the default headless *shell* cannot load extensions.
import { mkdtempSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { type BrowserContext, chromium, test as base, expect } from "@playwright/test";

import { TEST_ACCOUNT_PASSWORD, signUp } from "./account.ts";
import { type RunningServer, startServer } from "./server.ts";

const EXTENSION_PATH = fileURLToPath(new URL("../dist/chromium", import.meta.url));

const USERNAME = "dana@example.com";
const PASSWORD = "a-brand-new-password-456";

function loginPageHtml(): string {
  return (
    "<!doctype html><html><body><form method=\"post\" action=\"/dashboard\">" +
    '<input type="text" autocomplete="username">' +
    '<input type="password">' +
    '<button type="submit">Log in</button>' +
    "</form></body></html>"
  );
}

/** The page the login form's real submit navigates to: no login fields of its own, the common
 * shape of a post-login landing page. `fields_detected` never fires here at all (`report()`'s
 * own early return in `content-script.ts` for an empty field list) — only the unconditional
 * `check_save_prompt` this fix adds can ever deliver the offer on a page like this one. */
function dashboardPageHtml(): string {
  return "<!doctype html><html><body><h1>Welcome back</h1></body></html>";
}

/** A plain HTTP server serving both pages at the same origin (so the same registrable domain,
 * the race fix's whole point), regardless of request method — a real login form's `POST` is
 * never actually read; the content script already captured the field values client-side before
 * the browser ever sent this request. */
async function startLoginAndDashboardServer(): Promise<{ port: number; stop: () => Promise<void> }> {
  const server: Server = createServer((req, res) => {
    res.writeHead(200, { "content-type": "text/html" });
    res.end(req.url === "/dashboard" ? dashboardPageHtml() : loginPageHtml());
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
    const userDataDir = mkdtempSync(join(tmpdir(), "rizzy-ext-e2e-save-race-"));
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

test.setTimeout(120_000);

test("a login form that navigates on submit still gets the save prompt, on the next page", async ({
  context,
  extensionId,
  server,
}) => {
  const site = await startLoginAndDashboardServer();

  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "raceuser");
    await setupPage.close();

    const popup = await context.newPage();
    await popup.goto(`chrome-extension://${extensionId}/src/popup/index.html`);
    await popup.getByLabel("Server URL").fill(server.origin);
    await popup.getByLabel("Account (login name)").fill("raceuser");
    await popup.getByLabel("Secret Key").fill(secretKey);
    await popup.getByLabel("Master password").fill(TEST_ACCOUNT_PASSWORD);
    await popup.getByRole("button", { name: "Set up" }).click();
    await expect(popup.getByRole("button", { name: "Lock" })).toBeVisible({ timeout: 30_000 });

    // --- Submit a real login form that navigates for real, to a second page with no login
    // fields of its own, at the same origin.
    const loginUrl = `http://127.0.0.1:${site.port}/`;
    const page = await context.newPage();
    await page.goto(loginUrl);
    await expect(page.locator('input[data-rizzy-field="password"]')).toHaveCount(1);
    await page.locator('input[type="text"]').fill(USERNAME);
    await page.locator('input[type="password"]').fill(PASSWORD);
    await page.getByRole("button", { name: "Log in" }).click();

    // The navigation really happened (the fix's whole premise): the login form's own fields are
    // gone.
    await expect(page).toHaveURL(/\/dashboard$/);
    await expect(page.getByRole("heading", { name: "Welcome back" })).toBeVisible();
    await expect(page.locator('input[type="password"]')).toHaveCount(0);

    // --- The save prompt still appears, on this page, delivered by the unconditional
    // `check_save_prompt` this fix adds (never by `fields_detected`, which this page's empty
    // field list would never even send).
    const savePrompt = page.locator("[data-rizzy-save-prompt]");
    await expect(savePrompt).toBeVisible({ timeout: 15_000 });
    await expect(savePrompt).toContainText("Save");
    await savePrompt.getByRole("button", { name: "Save", exact: true }).click();
    await expect(savePrompt).toHaveCount(0);

    // --- A reload of the same page, well within the TTL, must not replay the offer a second
    // time (single-use at the location index, `save-prompt-location.test.ts`'s own unit
    // coverage of the same property) — resolving it already deleted the underlying token too.
    await page.reload();
    await page.waitForTimeout(1000);
    await expect(page.locator("[data-rizzy-save-prompt]")).toHaveCount(0);
    await page.close();

    // --- The item really was saved (not merely "the banner went away"): sync and look for it
    // in this device's own item list, the same confirmation `autofill-and-save.spec.ts` uses.
    await popup.bringToFront();
    await popup.getByRole("button", { name: "Sync" }).click();
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.getByLabel("Search").fill("127.0.0.1");
    await expect(popup.getByRole("button", { name: new RegExp(USERNAME.replace(/[.@]/g, "\\$&")) })).toBeVisible();

    await popup.getByRole("button", { name: "Lock" }).click();
    await expect(popup.getByLabel("Master password")).toBeVisible();
    await popup.close();
  } finally {
    await site.stop();
  }
});
