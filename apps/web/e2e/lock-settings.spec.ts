// SPDX-License-Identifier: AGPL-3.0-only

// The vault lock settings end to end (ADR 0110 §1–§4; Implementation plan, steps 5 and 7;
// INV-127): Settings → Locking, the record `rizzy.lock_settings` in `localStorage`, and the lock
// controller (`src/autolock.ts`, packages/ui `LockSettingsGroup.tsx`).
//
// - The turn-off dialog's timing, under Playwright's clock: Confirm is aria-disabled and inert
//   (click, Enter, Space) at 4.5 s, counts "(5)" … "(1)", works from 5 s; the live region's two
//   messages; Cancel and Escape at 0 s leave locking on; reopening restarts at 5.
// - The dimmed state: with locking off the three sub-options stay visible and focusable, are
//   aria-disabled, ignore activation and keep their values; turning locking on needs no dialog.
// - The idle lock at the chosen N (1 minute: locks after one minute plus one tick, not before),
//   and the sleep lock on a forward wall-clock gap (with the option on; not with it off).
// - Restart: a reload locks; the record survives it; a broken record reads as the defaults.
// - Accessibility: axe on the group in both states and on the open dialog, and a keyboard walk.
import { type Locator, type Page, expect, test } from "@playwright/test";

import { expectAccessible, expectFocusTrapped, tabTo } from "./a11y.ts";
import { logIn, signUp, watch } from "./helpers.ts";
import { type RunningServer, startServer } from "./server.ts";

let server: RunningServer;

test.beforeAll(async () => {
  server = await startServer();
});

test.afterAll(() => {
  server.stop();
});

const DEFAULT_RECORD =
  '{"v":1,"auto_lock":true,"idle_minutes":5,"lock_on_restart":true,"lock_on_sleep":true}';

/** Opens Settings and returns the Locking group, once its settings are read. */
async function openLocking(page: Page): Promise<Locator> {
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  const group = page.getByRole("region", { name: "Locking" });
  await expect(group).toBeVisible();
  await expect(master(group)).not.toHaveAttribute("aria-disabled", "true");
  return group;
}

const master = (group: Locator) => group.getByRole("switch", { name: "Lock the vault automatically" });
const idle = (group: Locator) => group.getByRole("combobox", { name: "Lock after this many minutes idle" });
const restart = (group: Locator) => group.getByRole("switch", { name: "Lock when the browser restarts" });
const sleep = (group: Locator) => group.getByRole("switch", { name: "Lock when the computer sleeps or hibernates" });
const dialogOf = (page: Page) => page.getByRole("alertdialog", { name: "Turn off automatic locking?" });

/** The stored record. */
async function record(page: Page): Promise<string | null> {
  return page.evaluate(() => localStorage.getItem("rizzy.lock_settings"));
}

/** Pauses the page's fake clock at its current time. */
async function pause(page: Page): Promise<void> {
  const now = await page.evaluate(() => Date.now());
  await page.clock.pauseAt(now + 1);
}

test("the defaults, the turn-off dialog's 5 s delay, the dimmed state, and on again", async ({ page }) => {
  const { problems } = watch(page);
  await page.clock.install();
  await signUp(page, server.origin, "LockDialogUser");
  const group = await openLocking(page);

  // The defaults (ADR 0110 §1), and the restart switch on and disabled with its line (§4.1).
  await expect(master(group)).toHaveAttribute("aria-checked", "true");
  await expect(idle(group)).toHaveValue("5");
  await expect(restart(group)).toHaveAttribute("aria-checked", "true");
  await expect(restart(group)).toHaveAttribute("aria-disabled", "true");
  await expect(restart(group)).toHaveAccessibleDescription("This browser cannot keep the vault unlocked after a restart.");
  await expect(sleep(group)).toHaveAttribute("aria-checked", "true");
  await expect(sleep(group)).toHaveAccessibleDescription("Also locks when the screen locks, where this device reports it.");
  await restart(group).click({ force: true });
  await expect(restart(group)).toHaveAttribute("aria-checked", "true");
  await expect(group.getByText("Turn on automatic locking to change these.")).toHaveCount(0);

  await pause(page);
  const dialog = dialogOf(page);
  const cancel = dialog.getByRole("button", { name: "Keep locking on" });
  const confirm = dialog.getByRole("button", { name: /^Turn off locking/ });
  const live = dialog.locator('[aria-live="polite"]');

  // Cancel at 0 s: works at once, locking stays on, focus back on the switch (§2 points 5–6).
  await master(group).click();
  await expect(dialog).toBeVisible();
  await expect(dialog).toHaveAttribute("aria-modal", "true");
  await expect(dialog).toHaveAccessibleDescription(/^Your vault will stay unlocked on this device/);
  await expect(cancel).toBeFocused();
  await cancel.click();
  await expect(dialog).toHaveCount(0);
  await expect(master(group)).toBeFocused();
  await expect(master(group)).toHaveAttribute("aria-checked", "true");

  // Escape at 0 s, opened with Space: the same.
  await page.keyboard.press("Space");
  await expect(dialog).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
  await expect(master(group)).toBeFocused();
  await expect(master(group)).toHaveAttribute("aria-checked", "true");
  expect(await record(page)).toBeNull();

  // The countdown (§2 points 3–4).
  await master(group).click();
  await expect(confirm).toHaveText("Turn off locking (5)");
  await expect(confirm).toHaveAttribute("aria-disabled", "true");
  await expect(live).toHaveText("You can confirm in 5 seconds.");
  await page.clock.runFor(1_000);
  await expect(confirm).toHaveText("Turn off locking (4)");
  await page.clock.runFor(3_500);
  await expect(confirm).toHaveText("Turn off locking (1)");
  await expect(live).toHaveText("You can confirm in 5 seconds.");
  // At 4.5 s a click, Enter and Space change nothing; Confirm stays focusable.
  await confirm.click({ force: true });
  await confirm.focus();
  await expect(confirm).toBeFocused();
  await page.keyboard.press("Enter");
  await page.keyboard.press("Space");
  await expect(dialog).toBeVisible();
  await expect(master(group)).toHaveAttribute("aria-checked", "true");
  // At 5 s it works.
  await page.clock.runFor(500);
  await expect(confirm).toHaveText("Turn off locking");
  await expect(confirm).not.toHaveAttribute("aria-disabled", "true");
  await expect(live).toHaveText("You can now turn off locking.");
  await confirm.click();
  await expect(dialog).toHaveCount(0);
  await expect(master(group)).toHaveAttribute("aria-checked", "false");
  await expect(master(group)).toBeFocused();
  expect(await record(page)).toBe(
    '{"v":1,"auto_lock":false,"idle_minutes":5,"lock_on_restart":true,"lock_on_sleep":true}',
  );

  // Dimmed: visible, focusable, aria-disabled, described, inert, values kept (§1 point 2).
  for (const control of [idle(group), restart(group), sleep(group)]) {
    await expect(control).toBeVisible();
    await expect(control).toHaveAttribute("aria-disabled", "true");
    await expect(control).toHaveAccessibleDescription(/Turn on automatic locking to change these\.$/);
  }
  await expect(group.getByText("Turn on automatic locking to change these.")).toBeVisible();
  await sleep(group).click({ force: true });
  await expect(sleep(group)).toHaveAttribute("aria-checked", "true");
  await master(group).focus();
  await page.keyboard.press("Tab");
  await expect(idle(group)).toBeFocused();
  await page.keyboard.press("ArrowDown");
  await expect(idle(group)).toHaveValue("5");
  // A change event that gets through anyway (Playwright refuses to select in a disabled control)
  // is ignored: the controlled value stays.
  await idle(group).evaluate((el) => {
    const select = el as HTMLSelectElement;
    select.value = "10";
    select.dispatchEvent(new Event("change", { bubbles: true }));
  });
  await expect(idle(group)).toHaveValue("5");
  await page.keyboard.press("Tab");
  await expect(restart(group)).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(sleep(group)).toBeFocused();
  await page.keyboard.press("Space");
  await expect(sleep(group)).toHaveAttribute("aria-checked", "true");
  expect(await record(page)).toContain('"auto_lock":false');

  // On again: no dialog, the kept values editable again (§1 point 3).
  await master(group).click();
  await expect(dialog).toHaveCount(0);
  await expect(master(group)).toHaveAttribute("aria-checked", "true");
  for (const control of [idle(group), sleep(group)]) {
    await expect(control).not.toHaveAttribute("aria-disabled", "true");
  }
  await expect(restart(group)).toHaveAttribute("aria-disabled", "true");
  expect(await record(page)).toBe(DEFAULT_RECORD);

  // Reopening restarts the countdown at 5.
  await master(group).click();
  await page.clock.runFor(3_000);
  await expect(confirm).toHaveText("Turn off locking (2)");
  await page.keyboard.press("Escape");
  await master(group).click();
  await expect(confirm).toHaveText("Turn off locking (5)");
  await cancel.click();
  await expect(master(group)).toHaveAttribute("aria-checked", "true");
  expect(problems).toEqual([]);
});

test("the idle lock fires at the chosen N plus one tick, not before", async ({ page }) => {
  await page.clock.install();
  await signUp(page, server.origin, "LockIdleUser");
  const group = await openLocking(page);
  await idle(group).selectOption("1");
  await expect(idle(group)).toHaveValue("1");
  await expect.poll(() => record(page)).toContain('"idle_minutes":1,');

  await pause(page);
  // The last input, at the paused instant.
  await group.getByRole("heading", { name: "Locking" }).click();
  await page.clock.runFor(55_000);
  await expect(page.getByRole("button", { name: "Account menu" })).toBeVisible();
  await page.clock.runFor(15_000);
  await expect(page.getByText("Locked after inactivity.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Account menu" })).toHaveCount(0);
});

test("a forward wall-clock gap of 2 minutes locks with the sleep option on, not off", async ({ page }) => {
  await page.clock.install();
  const secretKey = await signUp(page, server.origin, "LockSleepUser");
  let group = await openLocking(page);

  // Sleep off: a 200 s jump (under the 5-minute idle time) does not lock.
  await sleep(group).click();
  await expect(sleep(group)).toHaveAttribute("aria-checked", "false");
  await expect.poll(() => record(page)).toContain('"lock_on_sleep":false');
  await pause(page);
  await group.getByRole("heading", { name: "Locking" }).click();
  let now = await page.evaluate(() => Date.now());
  await page.clock.setSystemTime(now + 200_000);
  await page.clock.runFor(10_000);
  await expect(page.getByRole("button", { name: "Account menu" })).toBeVisible();

  // Sleep on: the same jump locks at the next tick.
  await sleep(group).click();
  await expect(sleep(group)).toHaveAttribute("aria-checked", "true");
  await expect.poll(() => record(page)).toBe(DEFAULT_RECORD);
  now = await page.evaluate(() => Date.now());
  await page.clock.setSystemTime(now + 200_000);
  await page.clock.runFor(10_000);
  await expect(page.getByText("Locked because this device slept or its clock jumped.")).toBeVisible();

  // The record outlived the lock; a reload is a restart and always locks (§4.1).
  await page.clock.resume();
  await logIn(page, undefined, secretKey);
  group = await openLocking(page);
  await idle(group).selectOption("15");
  await expect.poll(() => record(page)).toContain('"idle_minutes":15,');
  await page.reload();
  await expect(page.getByRole("button", { name: "Account menu" })).toHaveCount(0);
  await logIn(page, "LockSleepUser", secretKey);
  group = await openLocking(page);
  await expect(idle(group)).toHaveValue("15");

  // A broken record reads as the defaults (§3 point 3).
  await page.evaluate(() =>
    localStorage.setItem(
      "rizzy.lock_settings",
      '{"v":2,"auto_lock":false,"idle_minutes":15,"lock_on_restart":true,"lock_on_sleep":false}',
    ),
  );
  await page.reload();
  await logIn(page, "LockSleepUser", secretKey);
  group = await openLocking(page);
  await expect(master(group)).toHaveAttribute("aria-checked", "true");
  await expect(idle(group)).toHaveValue("5");
  await expect(sleep(group)).toHaveAttribute("aria-checked", "true");
});

test("a11y: the Locking group on and off, the turn-off dialog, and a keyboard walk", async ({ page }) => {
  const { problems } = watch(page);
  await signUp(page, server.origin, "LockA11yUser");
  const group = await openLocking(page);
  await expectAccessible(page, "settings: locking on");

  // Keyboard only: Tab reaches the master switch, Space opens the dialog, focus starts on
  // Cancel, Tab stays inside, Escape closes it and returns focus to the switch.
  await tabTo(page, master(group));
  await page.keyboard.press("Space");
  const dialog = dialogOf(page);
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole("button", { name: "Keep locking on" })).toBeFocused();
  await expectAccessible(page, "turn-off locking dialog");
  await expectFocusTrapped(page, dialog, "turn-off locking dialog");
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
  await expect(master(group)).toBeFocused();

  // Off (after the real 5 s), then the dimmed group: axe, and Tab reaches every control.
  await page.keyboard.press("Space");
  const confirm = dialog.getByRole("button", { name: "Turn off locking", exact: true });
  await expect(confirm).toBeVisible({ timeout: 10_000 });
  await confirm.press("Enter");
  await expect(master(group)).toHaveAttribute("aria-checked", "false");
  await expectAccessible(page, "settings: locking off (dimmed)");
  for (const control of [idle(group), restart(group), sleep(group)]) {
    await tabTo(page, control);
  }
  await tabTo(page, master(group), { backwards: true });
  await page.keyboard.press("Space");
  await expect(master(group)).toHaveAttribute("aria-checked", "true");
  expect(problems).toEqual([]);
});
