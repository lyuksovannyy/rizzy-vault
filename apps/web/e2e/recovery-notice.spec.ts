// SPDX-License-Identifier: AGPL-3.0-only

// The pending-recovery banner (ADR 0045, owner answer 2) and INV-70: the server's advisory
// `pending_recovery` notice is shown as given and changes nothing the vault trusts.
//
// An honest server never sends the notice to a web session (ADR 0045 point 4: an OPAQUE
// session cannot cancel a recovery; `rizzy-domain-auth`'s and `rizzy-server`'s tests check
// that), so here the server lies: a route adds an invented notice to every `account/state`
// answer. The banner appears, with when, how to cancel and that it is not verified, and passes
// the accessibility audit and a keyboard-only walk to its one control. Nothing else moves: the
// vault stays writable and syncs. The first answer without a notice clears it (point 3). A
// notice riding on an answer whose signed state was tampered with is never shown: the sync is
// refused exactly as it is without one.
import { expect, test } from "@playwright/test";

import { expectAccessible, tabTo } from "./a11y.ts";
import { newItem, signUp, watch } from "./helpers.ts";
import { type RunningServer, startServer } from "./server.ts";

let server: RunningServer;

test.beforeAll(async () => {
  server = await startServer();
});

test.afterAll(() => {
  server.stop();
});

test.setTimeout(120_000);

/** What the lying server does to each `account/state` answer. */
type Lie = "none" | "invent" | "tamper";

/** The invented notice: requested 2026-09-21, its wait long over, a recovery before it. */
const INVENTED = {
  opened_at_ms: 1_790_000_000_000,
  available_at_ms: 1_790_259_200_000,
  last_recovery_at_ms: 1_789_000_000_000,
};

test("a pending-recovery notice is shown, and nothing else changes (ADR 0045, INV-70)", async ({ page, context }) => {
  const { problems } = watch(page);
  let lie: Lie = "invent";
  await context.route("**/api/v1/account/state", async (route) => {
    const response = await route.fetch();
    if (lie === "none" || !response.ok()) {
      await route.fulfill({ response });
      return;
    }
    const body = (await response.json()) as Record<string, unknown>;
    body["pending_recovery"] = INVENTED;
    if (lie === "tamper") {
      const state = String(body["account_state"]);
      const mid = Math.floor(state.length / 2);
      body["account_state"] = state.slice(0, mid) + (state[mid] === "A" ? "B" : "A") + state.slice(mid + 1);
    }
    await route.fulfill({ response, json: body });
  });

  await signUp(page, server.origin, "recoverynotice");
  const banner = page.getByTestId("recovery-banner");
  await expect(banner).toBeVisible();
  await expect(banner).toHaveAttribute("role", "alert");
  await expect(banner).toContainText("Account recovery requested");
  await expect(banner).toContainText("Emergency Kit");
  await expect(banner).toContainText("it can be completed now");
  await expect(banner).toContainText("rv recovery cancel");
  await expect(banner).toContainText("This account was last recovered on");
  await expect(banner).toContainText("not verified");

  // INV-70: the notice moved nothing. The vault is writable, a new item saves and syncs.
  await expect(page.locator(".sync-state")).toHaveText("Synced");
  await newItem(page, "Secure Note");
  await page.getByLabel("Title").fill("Kept");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "Kept" })).toBeVisible();
  await expect(page.locator(".sync-state")).toHaveText("Synced");
  await expect(banner).toBeVisible();

  // The audit, and a keyboard-only walk to the banner's control.
  await expectAccessible(page, "pending-recovery banner");
  const review = banner.getByRole("button", { name: "Review your devices" });
  await tabTo(page, review, { max: 120 });
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { level: 1, name: "Settings" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Devices" })).toBeVisible();
  await expectAccessible(page, "settings under the pending-recovery banner");

  // The first answer without a notice clears the banner (ADR 0045 point 3).
  lie = "none";
  await page.getByRole("button", { name: "Sync", exact: true }).click();
  await expect(banner).toHaveCount(0);
  await expect(page.locator(".sync-state")).toHaveText("Synced");

  // A notice on a tampered signed state: refused as without one, and never shown.
  lie = "tamper";
  await page.getByRole("button", { name: "Sync", exact: true }).click();
  await expect(page.locator("p.error[role=alert]")).toBeVisible();
  await expect(banner).toHaveCount(0);

  // An honest answer again: the sync recovers, still no banner.
  lie = "none";
  await page.getByRole("button", { name: "Sync", exact: true }).click();
  await expect(page.locator("p.error[role=alert]")).toHaveCount(0);
  await expect(banner).toHaveCount(0);
  expect(problems.filter((p) => !p.includes("account/state"))).toEqual([]);
});
