// The extension end to end, against the real server (`server.ts`) and a real account created
// through the web vault's own signup (`account.ts`): enrol this device, unlock, offer autofill
// only for the page whose host the saved item's URI actually matches (never for a different
// host, even one that is otherwise identical), fill on a trusted click, save a newly submitted
// login through the save prompt, see it in the web vault from a second, independent session
// after a reload, and lock.
//
// Headless (`headless: true, channel: "chromium"`): the default headless *shell* Playwright
// otherwise launches cannot load extensions; the installed full Chromium's headless mode can.
//
// "Look-alike host": `127.0.0.1` and `localhost` on the very same port and server. They are
// different host strings — exactly what the item's saved URI does and does not match under
// `rizzy-match`'s `BaseDomain` mode for a host with no registrable domain of its own (an IP
// literal or a single-label name): `crates/rizzy-match/src/modes.rs`'s own test coverage
// (`evil_lookalike_never_matches_base_domain`, the IP-literal note next to
// `account_default_resolves_to_base_domain_when_unset`) is exact-host-equality for exactly this
// shape of host, which is what this spec relies on without reaching for real DNS or a second
// machine.
//
// Deliberately NOT a port-based look-alike: `newLogin` below is a second server on the SAME
// host (`127.0.0.1`) with a different port, and the matching item's candidate menu DOES show up
// there too — correctly. ADR 0037 point 5/point 33 ("any other port ... is never part of the
// registrable-domain computation") excludes port from `BaseDomain` matching everywhere,
// including the exact-host fallback this very host shape uses. `newLogin` is only ever used to
// get an item the vault has never saved an exact-URL match for (`findItemForUpdate` IS an exact
// URL compare, port included, so it still offers "save," not "update," there) — it does not,
// and was never meant to, exercise "no candidates for an unrelated host."
import { mkdtempSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { type BrowserContext, type Page, chromium, test as base, expect } from "@playwright/test";

import { TEST_ACCOUNT_PASSWORD, createLoginItem, logIn, signUp } from "./account.ts";
import { type RunningServer, startServer } from "./server.ts";

const EXTENSION_PATH = fileURLToPath(new URL("../dist/chromium", import.meta.url));

const EXISTING_USERNAME = "bob@example.com";
const EXISTING_PASSWORD = "existing-item-password";
const NEW_LOGIN_USERNAME = "carol@example.com";
const NEW_LOGIN_PASSWORD = "brand-new-password-123";

// `onsubmit="return false"`: a real login form's submit button does not instantly tear down the
// document — it POSTs and waits on a server round-trip before the browser navigates anywhere.
// Found empirically while writing this spec: an earlier version of this page had no `onsubmit`
// at all, so clicking "Log in" triggered an immediate same-document GET reload, destroying the
// content script's realm (and the pending `credentials_submitted` round-trip with it) before the
// extension's `save_prompt` answer could ever reach it — not a production bug, confirmed by
// comparing against this fixed page, where the save prompt appears every run. This fixture keeps
// the page from navigating at all, the closest cheap stand-in for "a login form whose submit
// takes long enough for the extension to answer first."
function loginPageHtml(): string {
  return (
    "<!doctype html><html><body><form onsubmit=\"return false\">" +
    '<input type="text" autocomplete="username">' +
    '<input type="password">' +
    '<button type="submit">Log in</button>' +
    "</form></body></html>"
  );
}

/** A plain HTTP server for one test login page, reachable at a fixed port by any hostname that
 * resolves to loopback (`127.0.0.1`, `localhost`): the server itself does no host-header
 * filtering, so the same page is reachable under two different host strings for the
 * "look-alike host" half of this spec. */
async function startLoginPageServer(): Promise<{ port: number; stop: () => Promise<void> }> {
  const server: Server = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "text/html" });
    res.end(loginPageHtml());
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
    const userDataDir = mkdtempSync(join(tmpdir(), "rizzy-ext-e2e-autofill-"));
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

test.setTimeout(120_000);

test("enrol, unlock, host-exact autofill matching, fill, save on submit, sync, and lock", async ({
  context,
  extensionId,
  server,
}) => {
  const matching = await startLoginPageServer();
  const newLogin = await startLoginPageServer();

  try {
    // --- Seed the account: sign up through the real web vault, save one Login item whose URI
    // is the matching test page's exact origin (ADR 0037 §2: saved verbatim; matching happens
    // later, not at save time).
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "extuser");
    const matchingOrigin = `http://127.0.0.1:${matching.port}/`;
    await createLoginItem(setupPage, {
      title: "Matching Site",
      username: EXISTING_USERNAME,
      password: EXISTING_PASSWORD,
      websiteUrl: matchingOrigin,
    });
    await setupPage.close();

    // --- Enrol this browser as a durable device (CRYPTO.md §11.2; ADR 0036 §1) through the
    // popup's own enrol form — never a mocked backend.
    const popup = await openPopup(context, extensionId);
    await popup.getByLabel("Server URL").fill(server.origin);
    await popup.getByLabel("Account (login name)").fill("extuser");
    await popup.getByLabel("Secret Key").fill(secretKey);
    await popup.getByLabel("Master password").fill(TEST_ACCOUNT_PASSWORD);
    await popup.getByRole("button", { name: "Set up" }).click();
    await expect(popup.getByRole("heading", { name: "rizzy-vault" })).toBeVisible();
    await expect(popup.getByRole("button", { name: "Lock" })).toBeVisible({ timeout: 30_000 });
    await expect(popup.getByRole("alert")).toHaveCount(0);
    // `App.tsx`'s "sync on unlock" effect runs in the background the instant this popup becomes
    // unlocked (mirrors `apps/web/src/views/VaultView.tsx`'s own "one sync on mount") — it pulls
    // the "Matching Site" item this setup just saved into this device's own cache. Waiting for
    // the one `Synced.` message is more deterministic than a fixed timeout.
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });

    // --- The matching page offers exactly the one candidate whose saved URI matches this host.
    const matchPage = await context.newPage();
    await matchPage.goto(matchingOrigin);
    const matchMenu = matchPage.frameLocator('iframe[data-rizzy-inline-menu]');
    await expect(matchMenu.getByRole("button")).toContainText("Matching Site", { timeout: 15_000 });
    await expect(matchMenu.getByRole("button")).toContainText(EXISTING_USERNAME);

    // A trusted click fills the page's own fields with the item's real credentials — never a
    // placeholder, never the candidate list's own title/username.
    await matchMenu.getByRole("button").click();
    await expect(matchPage.locator('input[type="text"]')).toHaveValue(EXISTING_USERNAME);
    await expect(matchPage.locator('input[type="password"]')).toHaveValue(EXISTING_PASSWORD);
    await matchPage.close();

    // --- The look-alike host (`localhost`, same port and server, different host string) gets
    // no candidates at all: `127.0.0.1` and `localhost` are not the same saved match under
    // `BaseDomain` mode for a host with no registrable domain of its own.
    const lookalikePage = await context.newPage();
    await lookalikePage.goto(`http://localhost:${matching.port}/`);
    await lookalikePage.waitForTimeout(1500);
    await expect(lookalikePage.locator("iframe[data-rizzy-inline-menu]")).toHaveCount(0);
    await lookalikePage.close();

    // --- Submitting a new login the vault has never seen offers "Save", never an auto-save.
    const newLoginOrigin = `http://127.0.0.1:${newLogin.port}/`;
    const submitPage = await context.newPage();
    await submitPage.goto(newLoginOrigin);
    // The content script's own detection is debounced 250ms behind a `MutationObserver`/initial
    // `schedule()` call (`content-script.ts`), and the submit handler only reads whichever
    // fields that pass already tagged `data-rizzy-field="username"`/`"password"` — clicking
    // "Log in" before that tagging lands means the handler finds no tagged password field and
    // reports nothing at all. Waiting for the tag itself (not a fixed sleep) is exact: the
    // moment it appears, the submit handler is guaranteed to find it too.
    await expect(submitPage.locator('input[data-rizzy-field="password"]')).toHaveCount(1);
    await submitPage.locator('input[type="text"]').fill(NEW_LOGIN_USERNAME);
    await submitPage.locator('input[type="password"]').fill(NEW_LOGIN_PASSWORD);
    await submitPage.getByRole("button", { name: "Log in" }).click();
    const savePrompt = submitPage.locator("[data-rizzy-save-prompt]");
    await expect(savePrompt).toBeVisible({ timeout: 15_000 });
    await expect(savePrompt).toContainText("Save");
    await savePrompt.getByRole("button", { name: "Save", exact: true }).click();
    await expect(savePrompt).toHaveCount(0);
    await submitPage.close();

    // --- Pushes the newly saved item to the server (`DurableSession.sync`, explicit, ADR 0026
    // §4's write order — never implicit inside the save prompt itself).
    await popup.bringToFront();
    await popup.getByRole("button", { name: "Sync" }).click();
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });

    // The new item shows up in this same device's own item list too (not only on the server).
    // No need to click "Items" first: it is the default view right after enrol/unlock, and
    // stays selected, so the button is already `disabled` (`App.tsx`) — clicking a disabled
    // button never resolves, and Playwright would retry forever.
    await popup.getByLabel("Search").fill("127.0.0.1");
    await expect(popup.getByRole("button", { name: new RegExp(NEW_LOGIN_USERNAME) })).toBeVisible();

    // --- A second, independent session (the ephemeral web vault, logging in fresh) sees the
    // item the durable device created and synced: real server-side persistence, not a same-tab
    // illusion.
    const verifyPage = await context.newPage();
    await logIn(verifyPage, server.origin, "extuser", secretKey);
    await verifyPage.reload();
    await logIn(verifyPage, server.origin, "extuser", secretKey);
    // The web vault's own item list shows title + username only (ADR 0013 §3 rule 3), never the
    // saved website URL — `bindings.ts`'s `newLoginChangeset` sets the title to `pageUrl`'s own
    // hostname, "127.0.0.1" here (both test pages share that host; only the port differs), so
    // that, not the full origin string, is what the list button's accessible name contains.
    await expect(verifyPage.getByRole("button", { name: new RegExp(`127\\.0\\.0\\.1.*${NEW_LOGIN_USERNAME.replace(/[.@]/g, "\\$&")}`) })).toBeVisible({
      timeout: 15_000,
    });
    await verifyPage.close();

    // --- Lock, from the popup.
    await popup.bringToFront();
    await popup.getByRole("button", { name: "Lock" }).click();
    await expect(popup.getByLabel("Master password")).toBeVisible();
    await popup.close();
  } finally {
    await matching.stop();
    await newLogin.stop();
  }
});
