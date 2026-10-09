// The long-lived core-holding context's own lifetime, measured, not assumed (ADR 0036 §2's
// design: the offscreen document holds the decrypted `DurableSession` so a real MV3 service
// worker — which Chromium is free to suspend after ~30s of inactivity — never has to). A 6-minute
// idle soak is comfortably past several service-worker suspend/wake cycles, while staying well
// under `DEFAULT_AUTO_LOCK_MS` (15 minutes, `core-host/lifecycle.ts`): if the session were still
// unlocked only because the auto-lock timer simply hadn't fired yet, this soak would not tell us
// that; it tells us the *offscreen document itself* (and the session it holds) survives idling,
// independent of the service worker's own suspend/resume behaviour. `chrome.offscreen.
// hasDocument()` is the one reliable way to ask Chromium this (`extension.spec.ts`'s own spike
// test and doc comment on why `context.pages()`/`backgroundPages()` do not enumerate it).
//
// Headless (`headless: true, channel: "chromium"`), same reasoning as every other spec in this
// directory: only the installed full Chromium's headless mode can load an unpacked extension.
//
// Firefox: not automated. Firefox's background page (no separate service worker, no
// `chrome.offscreen`) does not need this measurement in the first place — `background-page.ts`
// is the long-lived context directly — and Playwright has no supported way to load a Firefox
// extension's background page for introspection the way `chromium.launchPersistentContext`'s
// `--load-extension` does for Chromium. Recorded in `README.md`'s "Known gaps," not re-derived
// here.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { type BrowserContext, chromium, test as base, expect } from "@playwright/test";

import { TEST_ACCOUNT_PASSWORD, signUp } from "./account.ts";
import { type RunningServer, startServer } from "./server.ts";

const EXTENSION_PATH = fileURLToPath(new URL("../dist/chromium", import.meta.url));
const IDLE_MS = 6 * 60 * 1000;

const test = base.extend<{ server: RunningServer; context: BrowserContext; extensionId: string }>({
  server: async ({}, use) => {
    const server = await startServer();
    await use(server);
    server.stop();
  },
  context: async ({}, use) => {
    const userDataDir = mkdtempSync(join(tmpdir(), "rizzy-ext-e2e-lifetime-"));
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

test.setTimeout(8 * 60 * 1000);

test("the unlocked session and its offscreen document survive a 6-minute idle period", async ({ context, extensionId, server }) => {
  const setupPage = await context.newPage();
  const secretKey = await signUp(setupPage, server.origin, "lifetimeuser");
  await setupPage.close();

  const popup = await context.newPage();
  await popup.goto(`chrome-extension://${extensionId}/src/popup/index.html`);
  await popup.getByLabel("Server URL").fill(server.origin);
  await popup.getByLabel("Account (login name)").fill("lifetimeuser");
  await popup.getByLabel("Secret Key").fill(secretKey);
  await popup.getByLabel("Master password").fill(TEST_ACCOUNT_PASSWORD);
  await popup.getByRole("button", { name: "Set up" }).click();
  await expect(popup.getByRole("button", { name: "Lock" })).toBeVisible({ timeout: 30_000 });
  await popup.close();

  let [worker] = context.serviceWorkers();
  if (worker === undefined) {
    worker = await context.waitForEvent("serviceworker");
  }
  expect(await worker.evaluate(() => chrome!.offscreen!.hasDocument())).toBe(true);

  await new Promise<void>((resolve) => setTimeout(resolve, IDLE_MS));

  // The service worker itself may have been suspended and woken back up any number of times
  // during the wait above — fetching it fresh, rather than reusing the handle above, is
  // deliberate: Playwright's own `serviceWorkers()` reflects whichever worker instance is
  // current right now, and a stale handle to a since-terminated worker would make `.evaluate`
  // reject with its own unrelated error rather than answering the question this test asks.
  const workersNow = context.serviceWorkers();
  const currentWorker = workersNow[0] ?? (await context.waitForEvent("serviceworker"));
  expect(await currentWorker.evaluate(() => chrome!.offscreen!.hasDocument())).toBe(true);

  const popupAfter = await context.newPage();
  await popupAfter.goto(`chrome-extension://${extensionId}/src/popup/index.html`);
  // Still unlocked: the popup shows "Lock" (the unlocked view), never the unlock form, and no
  // error banner — the long-lived context's own in-memory session survived the idle period, not
  // merely the on-disk enrolment.
  await expect(popupAfter.getByRole("button", { name: "Lock" })).toBeVisible({ timeout: 15_000 });
  await expect(popupAfter.getByRole("alert")).toHaveCount(0);
  await popupAfter.close();
});
