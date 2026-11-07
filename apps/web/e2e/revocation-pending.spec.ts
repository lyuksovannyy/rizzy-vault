// SPDX-License-Identifier: AGPL-3.0-only

// A device removal under way on another device, as the web vault shows it (ADR 0091 §2 "What
// clients see", §8 step 7: the `revocation_pending` banner and the suspended state in the
// Devices pane, nothing more; kind 4 cannot revoke).
//
// The account gets a real durable device (enrolled from Node through packages/core, as
// packages/core's own end-to-end test does). A web session cannot open a revocation window, so
// here the server plays the revoking device's part: a route adds `suspended_devices` (that
// device) and an open `revocation_window` to every `account/state` answer, and answers
// `vault/upload` `409 revocation_pending`, as the window's freeze does for every session not
// bound to the revoker.
//
// Checked: the Devices pane says "Suspended" for the device and offers no revoke action; a new
// item is kept (the header counts it unsent), the banner shows ADR 0091 §2's sentence and reads
// go on; both screens pass the axe audit and the keyboard reaches the header's controls past
// the banner; once the freeze lifts, the same upload is retried 15 s later with no user action,
// the banner goes and the vault is synced; the first answer without the notice shows "Active".
import { readFileSync } from "node:fs";

import { type CacheRow, type CacheStore, enrolDevice, fetchTransport, initFromBytes } from "@rizzy-vault/core";
import { expect, test } from "@playwright/test";

import { expectAccessible, tabTo } from "./a11y.ts";
import { PASSWORD, newItem, signUp, watch } from "./helpers.ts";
import { type RunningServer, startServer } from "./server.ts";

let server: RunningServer;

test.beforeAll(async () => {
  server = await startServer();
  initFromBytes(readFileSync(new URL("../../../packages/core/generated/rizzy_core_bg.wasm", import.meta.url)));
});

test.afterAll(() => {
  server.stop();
});

test.setTimeout(150_000);

/** ADR 0091 §2's sentence. */
const SENTENCE = "Another of your devices is removing a device. Changes are paused for up to 10 minutes.";

/** The revoking device the lying answers name: any id (the notice is never verified). */
const REVOKER = Buffer.alloc(16, 0x5a).toString("base64url");

/** Whether two byte arrays hold the same bytes. */
function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

/** An in-memory cache for the Node-side durable device. */
function memoryCacheStore(): CacheStore {
  const rows: CacheRow[] = [];
  return {
    async get(store, key) {
      return rows.find((r) => r.store === store && sameBytes(r.key, key))?.value;
    },
    async put(store, key, value) {
      const i = rows.findIndex((r) => r.store === store && sameBytes(r.key, key));
      if (i >= 0) {
        rows.splice(i, 1);
      }
      rows.push({ store, key, value });
    },
    async delete(store, key) {
      const i = rows.findIndex((r) => r.store === store && sameBytes(r.key, key));
      if (i >= 0) {
        rows.splice(i, 1);
      }
    },
    async list(store) {
      return rows.filter((r) => r.store === store);
    },
  };
}

test("a device removal elsewhere: Suspended, the banner, the retry (ADR 0091 §2)", async ({ page, context }) => {
  const { problems } = watch(page);
  const secretKey = await signUp(page, server.origin, "revocationpending");

  const device = await enrolDevice(
    fetchTransport(server.origin),
    { origin: server.origin, loginName: "revocationpending", secretKey, password: PASSWORD },
    memoryCacheStore(),
  );
  const deviceId = device.deviceId;
  device.lock();

  let freeze = true;
  await context.route("**/api/v1/account/state", async (route) => {
    const response = await route.fetch();
    if (!freeze || !response.ok()) {
      await route.fulfill({ response });
      return;
    }
    const body = (await response.json()) as Record<string, unknown>;
    body["suspended_devices"] = [Buffer.from(deviceId, "hex").toString("base64url")];
    body["revocation_window"] = { revoker_device_id: REVOKER, expires_at_ms: Date.now() + 600_000 };
    await route.fulfill({ response, json: body });
  });
  let refused = 0;
  let uploaded = 0;
  await context.route("**/api/v1/vault/upload", async (route) => {
    if (freeze) {
      refused += 1;
      await route.fulfill({ status: 409, contentType: "application/json", body: '{"error":"revocation_pending"}' });
      return;
    }
    uploaded += 1;
    await route.fallback();
  });

  // A sync brings the new device and the server's notice. Nothing to upload yet: it succeeds.
  await page.getByRole("button", { name: "Sync", exact: true }).click();
  await expect(page.locator(".sync-state")).toHaveText("Synced");
  await expect(page.getByTestId("revocation-banner")).toHaveCount(0);

  // The Devices pane: "Suspended", explained, and no revoke action (kind 4 cannot revoke).
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  const row = page.getByRole("row", { name: new RegExp(deviceId.slice(0, 16)) });
  await expect(row).toBeVisible();
  await expect(row.getByRole("cell", { name: "Suspended" })).toBeVisible();
  await expect(row.getByRole("cell", { name: "Browser extension" })).toBeVisible();
  await expect(page.getByText("A suspended device is being removed by another of your devices")).toBeVisible();
  await expect(page.getByRole("button", { name: /revoke|remove device/i })).toHaveCount(0);
  await expectAccessible(page, "devices: a suspended device");

  // A write while the window is open: kept, counted unsent, the banner shown; reads go on.
  await page.getByRole("button", { name: "All items", exact: true }).click();
  await newItem(page, "Secure Note");
  await page.getByLabel("Title").fill("Paused change");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "Paused change" })).toBeVisible();
  const banner = page.getByTestId("revocation-banner");
  await expect(banner).toBeVisible();
  await expect(banner).toHaveAttribute("role", "status");
  await expect(banner).toContainText(SENTENCE);
  await expect(banner).toContainText("sent again automatically");
  await expect(page.locator(".sync-state")).toHaveText("1 change(s) not synced");
  expect(refused).toBeGreaterThanOrEqual(1);
  // No error under the header while the retry waits: the banner says it.
  await expect(page.getByRole("alert")).toHaveCount(0);
  await expect(page.getByRole("button", { name: /Paused change/ })).toBeVisible();
  await expectAccessible(page, "vault: the revocation_pending banner");

  // Keyboard only, past the banner: the header's Sync, then the item list.
  await page.locator("body").click({ position: { x: 1, y: 1 } });
  await tabTo(page, page.getByRole("button", { name: "Sync", exact: true }));
  await tabTo(page, page.getByRole("button", { name: /Paused change/ }));

  // The freeze lifts: the core's schedule retries the same upload 15 s after the refusal, with
  // no user action, and the banner goes with the sync that succeeds.
  const refusedBefore = refused;
  freeze = false;
  await expect(banner).toHaveCount(0, { timeout: 45_000 });
  await expect(page.locator(".sync-state")).toHaveText("Synced");
  expect(uploaded).toBeGreaterThanOrEqual(1);
  expect(refused).toBe(refusedBefore);

  // The first answer without the notice: the device is Active again.
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await expect(row.getByRole("cell", { name: "Active" })).toBeVisible();
  await expect(page.getByText("A suspended device is being removed by another of your devices")).toHaveCount(0);

  // The refused uploads are the only console errors (the browser logs a 409 answer).
  expect(problems.filter((p) => !/status of 409/.test(p))).toEqual([]);
});
