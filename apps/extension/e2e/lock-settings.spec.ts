// SPDX-License-Identifier: AGPL-3.0-only

// The extension's lock settings (ADR 0110 §1–§4, plan steps 3, 5 and 7; ADR 0111 §3, §7 step 4),
// on the options page and in the long-lived context:
//
// - The Locking group: the defaults and the restart switch's line; the turn-off dialog under
//   Playwright's clock (Cancel and Escape at 0 s, the countdown, a click, Enter and Space at
//   4.5 s ignored, Confirm at 5 s, the live region's two messages); the dimmed state; on again
//   without a dialog; the record written to `storage.local`. axe on the group in both states and
//   on the open dialog, and a keyboard walk (Tab reaches every control, the dimmed ones too;
//   focus starts on Cancel and stays inside the dialog; Escape returns it to the switch).
// - The one-time migration of `rizzy.auto_lock_minutes` (3 → 2 minutes) by a fresh offscreen
//   document, and the options page showing a not yet migrated legacy value.
// - The idle lock: with `idle_minutes: 1` and no extension message, the vault locks after one
//   minute plus one tick (real time: the offscreen document's clock is not the test page's).
// - The OS idle poll (ADR 0111 §7 step 4): activity kept alive by `get_status` every 20 s, the
//   service worker stopped; the popup must show locked within 60 s + 30 s + 15 s. Whether headless
//   Chromium reports `idle` at all is unknown (U); this test is that spike.
import { fileURLToPath } from "node:url";

import { type BrowserContext, type Locator, type Page, type Worker, chromium, test as base, expect } from "@playwright/test";

import { expectAccessible } from "./a11y.ts";
import { TEST_ACCOUNT_PASSWORD, signUp } from "./account.ts";
import { type RunningServer, startServer } from "./server.ts";
import { withProfileDir } from "./profile.ts";

const EXTENSION_PATH = fileURLToPath(new URL("../dist/chromium", import.meta.url));
const KEY = "rizzy.lock_settings";
const LEGACY = "rizzy.auto_lock_minutes";
const recordOf = (s: { auto_lock?: boolean; idle_minutes?: number; lock_on_sleep?: boolean }) =>
  JSON.stringify({ v: 1, auto_lock: true, idle_minutes: 5, lock_on_restart: true, lock_on_sleep: true, ...s });

const test = base.extend<{ server: RunningServer; context: BrowserContext; extensionId: string }>({
  server: async ({}, use) => {
    const server = await startServer();
    await use(server);
    server.stop();
  },
  context: async ({}, use) => {
    await withProfileDir("rizzy-ext-e2e-lock-", async (userDataDir) => {
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
    await use(new URL((await worker(context)).url()).host);
  },
});

async function worker(context: BrowserContext): Promise<Worker> {
  return context.serviceWorkers()[0] ?? (await context.waitForEvent("serviceworker"));
}

async function stored(context: BrowserContext): Promise<Record<string, unknown>> {
  return (await worker(context)).evaluate((keys) => chrome!.storage!.local.get(keys), [KEY, LEGACY]);
}

async function store(context: BrowserContext, items: Record<string, unknown>, remove: string[] = []): Promise<void> {
  await (await worker(context)).evaluate(
    async ([set, del]) => {
      await chrome!.storage!.local.set(set);
      if (del.length > 0) {
        await chrome!.storage!.local.remove(del);
      }
    },
    [items, remove] as const,
  );
}

const master = (group: Locator) => group.getByRole("switch", { name: "Lock the vault automatically" });
const idle = (group: Locator) => group.getByRole("combobox", { name: "Lock after this many minutes idle" });
const restart = (group: Locator) => group.getByRole("switch", { name: "Lock when the browser restarts" });
const sleep = (group: Locator) => group.getByRole("switch", { name: "Lock when the computer sleeps or hibernates" });
const dialogOf = (page: Page) => page.getByRole("alertdialog", { name: "Turn off automatic locking?" });

async function openOptions(context: BrowserContext, extensionId: string): Promise<{ page: Page; group: Locator }> {
  const page = await context.newPage();
  await page.goto(`chrome-extension://${extensionId}/src/options/index.html`);
  const group = page.getByRole("region", { name: "Locking" });
  await expect(idle(group)).toBeEnabled();
  return { page, group };
}

/** Enrols through the popup (which unlocks), and closes it. */
async function enrol(context: BrowserContext, extensionId: string, server: RunningServer, login: string): Promise<void> {
  const setup = await context.newPage();
  const secretKey = await signUp(setup, server.origin, login);
  await setup.close();
  const popup = await context.newPage();
  await popup.goto(`chrome-extension://${extensionId}/src/popup/index.html`);
  await popup.getByLabel("Server URL").fill(server.origin);
  await popup.getByLabel("Account (login name)").fill(login);
  await popup.getByLabel("Secret Key").fill(secretKey);
  await popup.getByLabel("Master password").fill(TEST_ACCOUNT_PASSWORD);
  await popup.getByRole("button", { name: "Set up" }).click();
  await expect(popup.getByRole("button", { name: "Lock" })).toBeVisible({ timeout: 30_000 });
  await popup.close();
}

/** Whether the popup shows the locked view (opening it is itself activity). */
async function popupLocked(context: BrowserContext, extensionId: string): Promise<boolean> {
  const popup = await context.newPage();
  await popup.goto(`chrome-extension://${extensionId}/src/popup/index.html`);
  const lock = popup.getByRole("button", { name: "Lock" });
  const unlock = popup.getByRole("button", { name: "Unlock" });
  await expect(lock.or(unlock)).toBeVisible({ timeout: 30_000 });
  const locked = await unlock.isVisible();
  await popup.close();
  return locked;
}

/** Pauses the page's fake clock at its current time. */
async function pause(page: Page): Promise<void> {
  const now = await page.evaluate(() => Date.now());
  await page.clock.pauseAt(now + 1);
}

test("the Locking group: defaults, the turn-off dialog's 5 s delay, the dimmed state, axe and keyboard", async ({
  context,
  extensionId,
}) => {
  await context.clock.install();
  const { page, group } = await openOptions(context, extensionId);
  await expect(master(group)).toHaveAttribute("aria-checked", "true");
  await expect(idle(group)).toHaveValue("5");
  await expect(restart(group)).toHaveAttribute("aria-checked", "true");
  await expect(restart(group)).toHaveAttribute("aria-disabled", "true");
  await expect(group.getByText("This browser cannot keep the vault unlocked after a restart.")).toBeVisible();
  await expect(sleep(group)).toHaveAttribute("aria-checked", "true");
  await expectAccessible(page, "options: Locking, on");

  // Keyboard: Tab reaches every control, the restart switch (always dimmed) included.
  await master(group).focus();
  for (const next of [idle(group), restart(group), sleep(group)]) {
    await page.keyboard.press("Tab");
    await expect(next).toBeFocused();
  }

  // axe waits for animations to settle, which a paused clock never lets them do: the dialog is
  // audited first, with the clock running, and the timing checked afterwards with it paused.
  const dialog = dialogOf(page);
  const cancel = dialog.getByRole("button", { name: "Keep locking on" });
  const confirm = dialog.getByRole("button", { name: /^Turn off locking/ });
  const live = dialog.locator('[aria-live="polite"]');
  await master(group).focus();
  await page.keyboard.press("Space");
  await expect(dialog).toBeVisible();
  await expect(cancel).toBeFocused();
  await expectAccessible(page, "options: turn-off dialog");
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);

  await pause(page);
  // Cancel at 0 s; then Escape at 0 s, opened with Space.
  await master(group).click();
  await expect(dialog).toBeVisible();
  await expect(cancel).toBeFocused();
  await cancel.click();
  await expect(dialog).toHaveCount(0);
  await expect(master(group)).toBeFocused();
  await page.keyboard.press("Space");
  await expect(dialog).toBeVisible();
  // Tab stays inside the dialog.
  for (let i = 0; i < 4; i++) {
    await page.keyboard.press("Tab");
    expect(await dialog.evaluate((d) => d.contains(document.activeElement))).toBe(true);
  }
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
  await expect(master(group)).toBeFocused();
  await expect(master(group)).toHaveAttribute("aria-checked", "true");
  expect((await stored(context))[KEY]).toBeUndefined();

  // The countdown, a click, Enter and Space at 4.5 s, Confirm at 5 s.
  await master(group).click();
  await expect(confirm).toHaveText("Turn off locking (5)");
  await expect(confirm).toHaveAttribute("aria-disabled", "true");
  await expect(live).toHaveText("You can confirm in 5 seconds.");
  await page.clock.runFor(4_500);
  await expect(confirm).toHaveText("Turn off locking (1)");
  await confirm.click({ force: true });
  await confirm.focus();
  await page.keyboard.press("Enter");
  await page.keyboard.press("Space");
  await expect(dialog).toBeVisible();
  await page.clock.runFor(500);
  await expect(confirm).toHaveText("Turn off locking");
  await expect(live).toHaveText("You can now turn off locking.");
  await confirm.click();
  await expect(dialog).toHaveCount(0);
  await expect(master(group)).toHaveAttribute("aria-checked", "false");
  await expect.poll(async () => (await stored(context))[KEY]).toBe(recordOf({ auto_lock: false }));

  // Dimmed: visible, focusable, aria-disabled, values kept.
  for (const control of [idle(group), restart(group), sleep(group)]) {
    await expect(control).toBeVisible();
    await expect(control).toHaveAttribute("aria-disabled", "true");
  }
  await idle(group).focus();
  await expect(idle(group)).toBeFocused();
  await sleep(group).click({ force: true });
  await expect(sleep(group)).toHaveAttribute("aria-checked", "true");
  await page.clock.resume();
  await expectAccessible(page, "options: Locking, off");
  await pause(page);

  // On again: no dialog, values restored; reopening restarts at 5.
  await master(group).click();
  await expect(dialog).toHaveCount(0);
  await expect(master(group)).toHaveAttribute("aria-checked", "true");
  await expect.poll(async () => (await stored(context))[KEY]).toBe(recordOf({}));
  await master(group).click();
  await page.clock.runFor(3_000);
  await page.keyboard.press("Escape");
  await master(group).click();
  await expect(confirm).toHaveText("Turn off locking (5)");
  await cancel.click();

  // A change of the idle time is written at once.
  await idle(group).selectOption("15");
  await expect.poll(async () => (await stored(context))[KEY]).toBe(recordOf({ idle_minutes: 15 }));
});

test("a saved rizzy.auto_lock_minutes is migrated once by a fresh offscreen document", async ({ context, extensionId }) => {
  // The options page reads a not yet migrated value as its migration (3 → 2 minutes).
  await store(context, { [LEGACY]: 3 }, [KEY]);
  const sw = await worker(context);
  await sw.evaluate(async () => {
    if (await chrome!.offscreen!.hasDocument()) {
      await chrome!.offscreen!.closeDocument();
    }
  });
  await store(context, { [LEGACY]: 3 }, [KEY]);
  const { page, group } = await openOptions(context, extensionId);
  await expect(idle(group)).toHaveValue("2");
  await expect(master(group)).toHaveAttribute("aria-checked", "true");
  // The offscreen document the options page woke wrote the record and removed the old key.
  await expect.poll(async () => (await stored(context))[KEY], { timeout: 15_000 }).toBe(recordOf({ idle_minutes: 2 }));
  expect((await stored(context))[LEGACY]).toBeUndefined();
  await page.close();

  // A record, once present, wins over a legacy value written later; a broken record reads as the
  // defaults.
  await store(context, { [LEGACY]: 60, [KEY]: '{"v":2}' });
  const again = await openOptions(context, extensionId);
  await expect(idle(again.group)).toHaveValue("5");
  expect((await stored(context))[KEY]).toBe('{"v":2}');
});

test.describe("the lock in the long-lived context", () => {
  test.setTimeout(6 * 60 * 1000);

  test("with idle_minutes 1 and no message, the vault locks after one minute plus one tick", async ({
    context,
    extensionId,
    server,
  }) => {
    await store(context, { [KEY]: recordOf({ idle_minutes: 1 }) });
    await enrol(context, extensionId, server, "lockidleuser");
    await new Promise((r) => setTimeout(r, 45_000));
    expect(await popupLocked(context, extensionId)).toBe(false); // also the last activity
    await new Promise((r) => setTimeout(r, 60_000 + 10_000 + 5_000));
    expect(await popupLocked(context, extensionId)).toBe(true);
  });

  test("with locking off nothing locks", async ({ context, extensionId, server }) => {
    await store(context, { [KEY]: recordOf({ auto_lock: false, idle_minutes: 1 }) });
    await enrol(context, extensionId, server, "lockoffuser");
    await new Promise((r) => setTimeout(r, 90_000));
    expect(await popupLocked(context, extensionId)).toBe(false);
  });

  test("the poll reaches the offscreen document: an idle answer locks within IDLE_POLL_MS", async ({
    context,
    extensionId,
    server,
  }) => {
    await store(context, { [KEY]: recordOf({ idle_minutes: 10 }) });
    await enrol(context, extensionId, server, "lockpolluser");
    // The OS cannot be made idle from here, so the service worker's own `queryState` answers
    // "idle"; the push (onStateChanged) is not involved. The next poll must lock.
    await (await worker(context)).evaluate(() => {
      (chrome!.idle as unknown as { queryState: () => Promise<string> }).queryState = async () => "idle";
    });
    const started = Date.now();
    await expect
      .poll(() => popupLocked(context, extensionId), { timeout: 30_000 + 15_000, intervals: [5_000] })
      .toBe(true);
    expect(Date.now() - started).toBeLessThan(45_000);
  });

  test("the OS idle state with the service worker stopped (spike: does headless Chromium report idle?)", async ({
    context,
    extensionId,
    server,
  }) => {
    await store(context, { [KEY]: recordOf({ idle_minutes: 1 }) });
    await enrol(context, extensionId, server, "lockosidleuser");
    // Keep the activity deadline from firing: get_status from an extension page every 20 s.
    const keeper = await context.newPage();
    await keeper.goto(`chrome-extension://${extensionId}/src/options/index.html`);
    await keeper.evaluate(() => {
      setInterval(() => void chrome!.runtime.sendMessage({ type: "get_status" }), 20_000);
    });
    await new Promise((r) => setTimeout(r, 65_000));
    const osState = await (await worker(context)).evaluate(() => chrome!.idle!.queryState(60));
    // ADR 0111 §7 step 4: if headless Chromium never reports idle, the manual check of step 7
    // (apps/extension/README.md) replaces this test; it is skipped, not dropped, and says why.
    test.skip(osState !== "idle", `headless Chromium reports "${osState}" after 65 s without input (U settled: no OS idle here)`);
    const cdp = await context.newCDPSession(keeper);
    await cdp.send("ServiceWorker.enable");
    await cdp.send("ServiceWorker.stopAllWorkers");
    const deadline = Date.now() + 30_000 + 15_000;
    let locked = false;
    while (!locked && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 5_000));
      locked = await keeper.evaluate(async () => {
        const s = (await chrome!.runtime.sendMessage({ type: "get_status" })) as { locked?: boolean } | undefined;
        return s?.locked === true;
      });
    }
    expect(locked).toBe(true);
  });
});

