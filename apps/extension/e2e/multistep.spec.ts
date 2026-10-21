// SPDX-License-Identifier: AGPL-3.0-only

// Multi-step login forms end to end (ROADMAP §4.4 M3 "Heuristic multi-step login form support";
// `src/content/login-step.ts`): identifier-first pages (the username alone, the password on the
// next page or revealed later on the same page) and password-only steps get the inline menu on
// each step, and each step's fill writes only that step's own field(s), on that step's own
// trusted click (INV-36; ADR 0037 §5; ADR 0040). Never an automatic fill of a later step from a
// pick on an earlier one, and nothing remembered across a navigation.
//
// Two tests:
// - detection only (no account; the device is not even enrolled, so no menu renders — field
//   detection and its `data-rizzy-field` tags run regardless): every HTML fixture in
//   `test/fixtures/login-steps/` is served to real Chromium and must be tagged exactly as
//   `test/login-step.test.ts` expects from the static reading, including the hostile ones (hidden,
//   off-screen and covered username decoys; a password field in a real cross-origin iframe);
// - the fill flows, with a real enrolled and unlocked device: an identifier-first two-page flow
//   and a same-page reveal flow, each with the negative check that the next step stays empty
//   until a new click on a candidate in that step's own menu.
//
// The cross-origin iframe uses the look-alike-host trick `autofill-and-save.spec.ts` documents:
// `127.0.0.1` and `localhost` on the same port are different origins.
import { mkdtempSync, readFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { type BrowserContext, type Page, chromium, test as base, expect } from "@playwright/test";

import { TEST_ACCOUNT_PASSWORD, createLoginItem, signUp } from "./account.ts";
import { type RunningServer, startServer } from "./server.ts";

const EXTENSION_PATH = fileURLToPath(new URL("../dist/chromium", import.meta.url));
const FIXTURES = fileURLToPath(new URL("../test/fixtures/login-steps/", import.meta.url));

const USERNAME = "bob@example.com";
const PASSWORD = "multi-step-password-42";

/** Serves the fixture files by name (query strings ignored, so the identifier form's GET submit
 * lands on `password-step.html`), with `__IFRAME_ORIGIN__` replaced by the other loopback host
 * on the same port — a different origin from the page's own. */
async function startFixtureServer(): Promise<{ port: number; stop: () => Promise<void> }> {
  let port = 0;
  const server: Server = createServer((req, res) => {
    const name = new URL(req.url ?? "/", "http://fixture.invalid").pathname.slice(1);
    if (!/^[a-z0-9-]+\.html$/.test(name)) {
      res.writeHead(404).end();
      return;
    }
    let html: string;
    try {
      html = readFileSync(FIXTURES + name, "utf8");
    } catch {
      res.writeHead(404).end();
      return;
    }
    const host = req.headers.host ?? "";
    const other = host.startsWith("localhost") ? `http://127.0.0.1:${port}` : `http://localhost:${port}`;
    res.writeHead(200, { "content-type": "text/html" });
    res.end(html.replaceAll("__IFRAME_ORIGIN__", other));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  port = typeof address === "object" && address !== null ? address.port : 0;
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
    const userDataDir = mkdtempSync(join(tmpdir(), "rizzy-ext-e2e-multistep-"));
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

test.setTimeout(150_000);

/** The tags real detection must put on each fixture: element id → `data-rizzy-field` value.
 * Mirrors `test/login-step.test.ts`'s `EXPECTED` (an empty object: no step, nothing tagged). */
const EXPECTED_TAGS: Readonly<Record<string, Readonly<Record<string, "username" | "password">>>> = {
  "one-page.html": { user: "username", pass: "password" },
  "identifier-first.html": { user: "username" },
  "identifier-weak.html": { user: "username" },
  "password-step.html": { pass: "password" },
  "password-step-readonly-user.html": { pass: "password" },
  "same-page-reveal.html": { user: "username" },
  "hidden-username-decoys.html": { user: "username" },
  "password-with-hidden-username-decoy.html": { pass: "password" },
  "covered-username.html": { pass: "password" },
  "cross-origin-iframe-password.html": { user: "username" },
  "iframe-password.html": { pass: "password" },
  "password-no-form.html": { pass: "password" },
  "search-box.html": {},
  "newsletter.html": {},
  "signup-email.html": {},
  "contact-form.html": {},
  "one-time-code.html": {},
  "webauthn-identifier.html": { user: "username" },
  "disabled-password.html": { user: "username" },
};

test("real detection tags each fixture's step fields and nothing else, including hostile pages", async ({ context }) => {
  const fixtures = await startFixtureServer();
  try {
    const page = await context.newPage();
    for (const [name, expected] of Object.entries(EXPECTED_TAGS)) {
      await page.goto(`http://127.0.0.1:${fixtures.port}/${name}`);
      const entries = Object.entries(expected);
      if (entries.length > 0) {
        for (const [id, kind] of entries) {
          await expect(page.locator(`#${id}`), name).toHaveAttribute("data-rizzy-field", kind, { timeout: 15_000 });
        }
      } else {
        // No positive control on a no-step page: wait well past the content script's 250 ms
        // detection debounce instead, then require that nothing at all was tagged.
        await page.waitForTimeout(1_500);
      }
      const tagged = await page.locator("input[data-rizzy-field]").evaluateAll((els) => els.map((el) => el.id).sort());
      expect(tagged, name).toEqual(Object.keys(expected).sort());
    }

    // The cross-origin iframe's own password field: never seen, never tagged (top frame only).
    await page.goto(`http://127.0.0.1:${fixtures.port}/cross-origin-iframe-password.html`);
    await expect(page.locator("#user")).toHaveAttribute("data-rizzy-field", "username", { timeout: 15_000 });
    const frame = page.frameLocator("#pw-frame");
    await expect(frame.locator("#pass")).toBeVisible();
    await page.waitForTimeout(1_500);
    expect(await frame.locator("#pass").getAttribute("data-rizzy-field")).toBeNull();
  } finally {
    await fixtures.stop();
  }
});

async function enrolAndUnlock(context: BrowserContext, extensionId: string, server: RunningServer, siteOrigin: string): Promise<void> {
  const setupPage = await context.newPage();
  const secretKey = await signUp(setupPage, server.origin, "multistep");
  await createLoginItem(setupPage, { title: "Multi-step Site", username: USERNAME, password: PASSWORD, websiteUrl: siteOrigin });
  await setupPage.close();

  const popup = await context.newPage();
  await popup.goto(`chrome-extension://${extensionId}/src/popup/index.html`);
  await popup.getByLabel("Server URL").fill(server.origin);
  await popup.getByLabel("Account (login name)").fill("multistep");
  await popup.getByLabel("Secret Key").fill(secretKey);
  await popup.getByLabel("Master password").fill(TEST_ACCOUNT_PASSWORD);
  await popup.getByRole("button", { name: "Set up" }).click();
  await expect(popup.getByRole("button", { name: "Lock" })).toBeVisible({ timeout: 30_000 });
  await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
  await popup.close();
}

function candidate(page: Page) {
  return page.frameLocator("iframe[data-rizzy-inline-menu]").getByRole("button", { name: "Multi-step Site", exact: false });
}

/** Long enough for any automatic fill to have landed if one were (wrongly) going to: well past
 * the detection debounce, the background round trip and Gate B's 1 s visibility window. */
const NO_AUTOFILL_WAIT_MS = 2_500;

test("identifier-first and same-page reveal flows fill one step per click, never the next step on its own", async ({
  context,
  extensionId,
  server,
}) => {
  const fixtures = await startFixtureServer();
  try {
    const site = `http://127.0.0.1:${fixtures.port}/`;
    await enrolAndUnlock(context, extensionId, server, site);
    const page = await context.newPage();

    await test.step("two pages: the identifier step fills the username only", async () => {
      await page.goto(`${site}identifier-first.html`);
      const menu = page.frameLocator("iframe[data-rizzy-inline-menu]");
      await expect(candidate(page)).toContainText(USERNAME, { timeout: 15_000 });
      await expect(menu.getByText("Fills the username only.")).toBeVisible();
      // No password field on this step, so no generator to fill one.
      await expect(menu.getByRole("button", { name: "Generate password" })).toBeHidden();
      await candidate(page).click();
      await expect(page.locator("#user")).toHaveValue(USERNAME);
      await expect(page.locator("iframe[data-rizzy-inline-menu]")).toHaveCount(0);
    });

    await test.step("two pages: the password step is offered but stays empty until its own click", async () => {
      await page.locator("#next").click();
      await page.waitForURL(/password-step\.html/);
      const menu = page.frameLocator("iframe[data-rizzy-inline-menu]");
      await expect(candidate(page)).toContainText(USERNAME, { timeout: 15_000 });
      await expect(menu.getByText("Fills the password only.")).toBeVisible();
      // The negative check: the pick on the previous page fills nothing here by itself.
      await page.waitForTimeout(NO_AUTOFILL_WAIT_MS);
      await expect(page.locator("#pass")).toHaveValue("");
      await expect(page.locator("#hidden-user")).toHaveValue("");
      await candidate(page).click();
      await expect(page.locator("#pass")).toHaveValue(PASSWORD);
      // The hidden username decoy stays empty: a password-only step fills the password only.
      await expect(page.locator("#hidden-user")).toHaveValue("");
    });

    await test.step("same page: the identifier step fills the username, the hidden password stays empty", async () => {
      await page.goto(`${site}same-page-reveal.html`);
      const menu = page.frameLocator("iframe[data-rizzy-inline-menu]");
      await expect(candidate(page)).toContainText(USERNAME, { timeout: 15_000 });
      await expect(menu.getByText("Fills the username only.")).toBeVisible();
      await candidate(page).click();
      await expect(page.locator("#user")).toHaveValue(USERNAME);
      await expect(page.locator("#pass")).toHaveValue("");
      await expect(page.locator("iframe[data-rizzy-inline-menu]")).toHaveCount(0);
    });

    await test.step("same page: the revealed password step is offered anew and not filled without a new click", async () => {
      await page.locator("#next").click();
      await expect(page.locator("#pass")).toBeVisible();
      await expect(page.locator("#pass")).toHaveAttribute("data-rizzy-field", "password", { timeout: 15_000 });
      await expect(candidate(page)).toContainText(USERNAME, { timeout: 15_000 });
      await page.waitForTimeout(NO_AUTOFILL_WAIT_MS);
      await expect(page.locator("#pass")).toHaveValue("");
      await candidate(page).click();
      await expect(page.locator("#pass")).toHaveValue(PASSWORD);
      await expect(page.locator("#user")).toHaveValue(USERNAME);
    });

    await test.step("a password in a cross-origin iframe is never filled from the top frame's step", async () => {
      await page.goto(`${site}cross-origin-iframe-password.html`);
      await expect(candidate(page)).toContainText(USERNAME, { timeout: 15_000 });
      await candidate(page).click();
      await expect(page.locator("#user")).toHaveValue(USERNAME);
      await page.waitForTimeout(NO_AUTOFILL_WAIT_MS);
      await expect(page.frameLocator("#pw-frame").locator("#pass")).toHaveValue("");
    });
  } finally {
    await fixtures.stop();
  }
});
