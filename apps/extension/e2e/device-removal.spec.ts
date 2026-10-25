// SPDX-License-Identifier: AGPL-3.0-only

// The durable device's alarms and "Remove this device" (ADR 0026 §3 kind 7, §4 step 4, §5; the
// replacement text of ADR 0095 §C and §D, which records the owner's answers as `rv` implements
// them), end to end through the popup.
//
// 1. An older copy of the extension's cache (a restored browser profile: here the IndexedDB
//    rows as they were before this device's second write reached the server) sees more of its
//    own history than it holds on its first Fetch. It writes alarm 4 ("device state outdated")
//    with that answer and goes read-only; a browser restart keeps it read-only. Removal is its
//    only resolution, is not blocked by alarm 4, and first uploads the unsent own op the older
//    copy holds, byte for byte. The removal view is audited with axe and walked by keyboard.
// 2. Under alarm 2 ("fork"), which only another flow could clear and this cache is the evidence
//    of, removal is refused and the alarm named, both while locked (the key-less check of the
//    cleartext alarm rows) and while unlocked; the unlocked device is read-only.
//
// Same harness as `lifetime.spec.ts`: headless Chromium, the unpacked `dist/chromium` build, a
// real `rizzy-vault` with the web vault embedded (`server.ts`). The IndexedDB rows are read and
// written from the extension's own service worker, as `storage.spec.ts` reads them.
import { type Server, createServer } from "node:http";
import { fileURLToPath } from "node:url";

import { type BrowserContext, type Locator, type Page, type Worker, chromium, test as base, expect } from "@playwright/test";

import { expectAccessible } from "./a11y.ts";
import { TEST_ACCOUNT_PASSWORD, signUp } from "./account.ts";
import { type RunningServer, startServer } from "./server.ts";
import { withProfileDir } from "./profile.ts";
import { CACHE_DATABASE_NAME } from "../src/cache/stores.ts";

const EXTENSION_PATH = fileURLToPath(new URL("../dist/chromium", import.meta.url));

const test = base.extend<{ server: RunningServer }>({
  server: async ({}, use) => {
    const server = await startServer();
    await use(server);
    server.stop();
  },
});

test.setTimeout(4 * 60 * 1000);

/** A browser over `userDataDir` with the extension loaded. */
function launch(userDataDir: string): Promise<BrowserContext> {
  return chromium.launchPersistentContext(userDataDir, {
    headless: true,
    channel: "chromium",
    args: [`--disable-extensions-except=${EXTENSION_PATH}`, `--load-extension=${EXTENSION_PATH}`],
  });
}

/** The extension's service worker, waiting for it if needed. */
async function worker(context: BrowserContext): Promise<Worker> {
  return context.serviceWorkers()[0] ?? (await context.waitForEvent("serviceworker"));
}

async function openPopup(context: BrowserContext): Promise<Page> {
  const extensionId = new URL((await worker(context)).url()).host;
  const page = await context.newPage();
  await page.goto(`chrome-extension://${extensionId}/src/popup/index.html`);
  return page;
}

/** Moves the focus to `target` with Tab alone (`a11y.spec.ts`'s `tabTo`). */
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

/** A login page for the save prompt, at a fixed loopback port. */
async function startLoginPage(): Promise<{ origin: string; stop: () => Promise<void> }> {
  const server: Server = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "text/html" });
    res.end(
      '<!doctype html><html lang="en"><head><title>Login</title></head><body><form onsubmit="return false">' +
        '<input type="text" autocomplete="username"><input type="password">' +
        '<button type="submit">Log in</button></form></body></html>',
    );
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const port = typeof address === "object" && address !== null ? address.port : 0;
  return {
    origin: `http://127.0.0.1:${port}/`,
    stop: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

/** Writes one new login through the save prompt: one own op, not yet sent. */
async function saveLogin(context: BrowserContext, origin: string, username: string): Promise<void> {
  const page = await context.newPage();
  await page.goto(origin);
  await expect(page.locator('input[data-rizzy-field="password"]')).toHaveCount(1);
  await page.locator('input[type="text"]').fill(username);
  await page.locator('input[type="password"]').fill(`pw-of-${username}`);
  await page.getByRole("button", { name: "Log in" }).click();
  const prompt = page.locator("[data-rizzy-save-prompt]");
  await expect(prompt).toBeVisible({ timeout: 15_000 });
  await prompt.getByRole("button", { name: "Save", exact: true }).click();
  await expect(prompt).toHaveCount(0);
  await page.close();
}

/** Enrols this browser from the popup and waits for its first sync. */
async function enrol(popup: Page, server: RunningServer, loginName: string, secretKey: string): Promise<void> {
  await popup.getByLabel("Server URL").fill(server.origin);
  await popup.getByLabel("Account (login name)").fill(loginName);
  await popup.getByLabel("Secret Key").fill(secretKey);
  await popup.getByLabel("Master password").fill(TEST_ACCOUNT_PASSWORD);
  await popup.getByRole("button", { name: "Set up" }).click();
  await expect(popup.getByRole("button", { name: "Lock" })).toBeVisible({ timeout: 30_000 });
  await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
}

async function unlock(popup: Page): Promise<void> {
  await popup.getByLabel("Master password").fill(TEST_ACCOUNT_PASSWORD);
  await popup.getByRole("button", { name: "Unlock" }).click();
  await expect(popup.getByRole("button", { name: "Lock" })).toBeVisible({ timeout: 30_000 });
}

type Dump = Record<string, [number[], number[]][]>;

/** Every row of the durable-device cache, as byte arrays. */
function dumpCache(sw: Worker): Promise<Dump> {
  return sw.evaluate(async (name) => {
    const done = <T>(r: IDBRequest<T>) =>
      new Promise<T>((resolve, reject) => {
        r.onsuccess = () => resolve(r.result);
        r.onerror = () => reject(r.error);
      });
    const bytes = (v: unknown): number[] =>
      v instanceof ArrayBuffer
        ? [...new Uint8Array(v)]
        : ArrayBuffer.isView(v)
          ? [...new Uint8Array(v.buffer, v.byteOffset, v.byteLength)]
          : [];
    const db = await done(indexedDB.open(name));
    const out: Record<string, [number[], number[]][]> = {};
    for (const store of Array.from(db.objectStoreNames)) {
      const os = db.transaction(store, "readonly").objectStore(store);
      const keys = await done(os.getAllKeys());
      const values = await done(os.getAll());
      out[store] = keys.map((k, i) => [bytes(k), bytes(values[i])]);
    }
    db.close();
    return out;
  }, CACHE_DATABASE_NAME);
}

/** Replaces every row of the durable-device cache by `dump`'s. */
function restoreCache(sw: Worker, dump: Dump): Promise<void> {
  return sw.evaluate(
    async ([name, rows]) => {
      const done = <T>(r: IDBRequest<T>) =>
        new Promise<T>((resolve, reject) => {
          r.onsuccess = () => resolve(r.result);
          r.onerror = () => reject(r.error);
        });
      const db = await done(indexedDB.open(name));
      for (const store of Array.from(db.objectStoreNames)) {
        const os = db.transaction(store, "readwrite").objectStore(store);
        await done(os.clear());
        for (const [key, value] of rows[store] ?? []) {
          await done(os.put(new Uint8Array(value), new Uint8Array(key)));
        }
      }
      db.close();
    },
    [CACHE_DATABASE_NAME, dump] as const,
  );
}

/** The key bytes of every alarm row (`account_objects`, kind 7). */
function alarmKeys(dump: Dump): number[][] {
  return (dump["account_objects"] ?? [])
    .map(([key]) => key)
    .filter((key) => key.length >= 8 && key.slice(0, 8).every((b, i) => b === (i === 7 ? 7 : 0)))
    .map((key) => key.slice(8));
}

/** The names of the extension origin's IndexedDB databases. */
function databases(sw: Worker): Promise<string[]> {
  return sw.evaluate(async () => (await indexedDB.databases()).map((d) => d.name ?? ""));
}

/** How many records the account configuration (`core-host/account-config.ts`) holds. */
function accountConfigRecords(sw: Worker): Promise<number> {
  return sw.evaluate(async () => {
    if (!(await indexedDB.databases()).some((d) => d.name === "rizzy-account-config")) {
      return 0;
    }
    const done = <T>(r: IDBRequest<T>) =>
      new Promise<T>((resolve, reject) => {
        r.onsuccess = () => resolve(r.result);
        r.onerror = () => reject(r.error);
      });
    const db = await done(indexedDB.open("rizzy-account-config"));
    try {
      if (!db.objectStoreNames.contains("config")) {
        return 0;
      }
      return await done(db.transaction("config", "readonly").objectStore("config").count());
    } finally {
      db.close();
    }
  });
}

const READ_ONLY = { name: "This device is read-only" } as const;

test("an older copy of the cache raises alarm 4, a restart keeps it read-only, and Remove this device removes it", async ({
  server,
}) => {
  const page = await startLoginPage();
  try {
    await withProfileDir("rizzy-ext-e2e-removal-", async (userDataDir) => {
      let context = await launch(userDataDir);
      try {
        const setup = await context.newPage();
        const secretKey = await signUp(setup, server.origin, "removaluser");
        await setup.close();
        let popup = await openPopup(context);
        await enrol(popup, server, "removaluser", secretKey);

        // One own op, never sent, in the copy; then it and a second one reach the server.
        await saveLogin(context, page.origin, "first@example.com");
        const older = await dumpCache(await worker(context));
        expect(alarmKeys(older)).toEqual([]);
        await popup.bringToFront();
        await popup.getByRole("button", { name: "Sync" }).click();
        await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
        await saveLogin(context, page.origin, "second@example.com");
        await popup.bringToFront();
        await popup.getByRole("button", { name: "Sync" }).click();
        await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
        await popup.getByRole("button", { name: "Lock" }).click();
        await expect(popup.getByLabel("Master password")).toBeVisible();

        // The older copy comes back; its first sync (on unlock) raises alarm 4.
        await restoreCache(await worker(context), older);
        await unlock(popup);
        await expect(popup.getByText("Sync stopped: the local data is older than this device's own history.")).toBeVisible({
          timeout: 15_000,
        });
        await expect(popup.getByRole("heading", READ_ONLY)).toBeVisible();
        expect(alarmKeys(await dumpCache(await worker(context)))).toEqual([[4]]);
        await expectAccessible(popup, "popup: items, read-only under an alarm");
        await popup.close();
        await context.close();

        // A restart never lifts read-only mode (ADR 0026 §4 step 4).
        context = await launch(userDataDir);
        popup = await openPopup(context);
        await unlock(popup);
        await expect(popup.getByRole("heading", READ_ONLY)).toBeVisible();
        await expect(popup.getByText("the local data is older than this device's own history").first()).toBeVisible();
        await expect(popup.getByText("Remove this device and set it up again to keep using the extension here.")).toBeVisible();
        await expect(popup.getByText("Sync stopped: the local data is older than this device's own history.")).toBeVisible({
          timeout: 15_000,
        });

        // Remove this device, by keyboard alone: the unsent op the older copy holds goes up
        // first, byte for byte, so nothing is lost.
        const kb = popup.keyboard;
        await tabTo(popup, popup.getByRole("button", { name: "Remove this device" }));
        await kb.press("Enter");
        await expect(popup.getByRole("heading", { name: "Remove this device" })).toBeVisible();
        await expect(popup.getByText("Every change made on this device is on the server.")).toBeVisible({ timeout: 30_000 });
        await expectAccessible(popup, "popup: remove this device");
        const remove = popup.getByRole("button", { name: "Remove this device" });
        await expect(remove).toBeDisabled();
        await tabTo(popup, popup.getByRole("checkbox", { name: "Remove this device's local data" }));
        await kb.press("Space");
        await expect(remove).toBeEnabled();
        await tabTo(popup, remove);
        await kb.press("Enter");
        await expect(popup.getByLabel("Server URL")).toBeVisible({ timeout: 15_000 });
        const sw = await worker(context);
        expect(await databases(sw)).not.toContain(CACHE_DATABASE_NAME);
        // The saved account configuration is gone too (the popup's next status read reopens
        // its database, empty).
        expect(await accountConfigRecords(sw)).toBe(0);
      } finally {
        await context.close();
      }
    });
  } finally {
    await page.stop();
  }
});

test("Remove this device is refused, locked and unlocked, while a fork alarm is held", async ({ server }) => {
  await withProfileDir("rizzy-ext-e2e-removal-fork-", async (userDataDir) => {
    const context = await launch(userDataDir);
    try {
      const setup = await context.newPage();
      const secretKey = await signUp(setup, server.origin, "forkuser");
      await setup.close();
      const popup = await openPopup(context);
      await enrol(popup, server, "forkuser", secretKey);
      await popup.getByRole("button", { name: "Lock" }).click();
      await expect(popup.getByLabel("Master password")).toBeVisible();

      // Alarm 2 as `rizzy-client` writes it: `account_objects`, kind 7, key 2.
      const sw = await worker(context);
      const dump = await dumpCache(sw);
      dump["account_objects"] = [...(dump["account_objects"] ?? []), [[0, 0, 0, 0, 0, 0, 0, 7, 2], []]];
      await restoreCache(sw, dump);

      // Locked: the cleartext alarm rows are read without any key.
      const kb = popup.keyboard;
      await tabTo(popup, popup.getByRole("button", { name: "Remove this device" }));
      await kb.press("Enter");
      const refused = popup.getByText(
        "This device cannot be removed while an alarm is raised: the server has shown two versions of this account.",
      );
      await expect(refused).toBeVisible({ timeout: 15_000 });
      await expect(popup.getByRole("checkbox")).toHaveCount(0);
      await expectAccessible(popup, "popup: remove this device, refused");
      await tabTo(popup, popup.getByRole("button", { name: "Cancel" }));
      await kb.press("Enter");

      // Unlocked: the load makes every vault read-only, and removal is refused again.
      await unlock(popup);
      await expect(popup.getByRole("heading", READ_ONLY)).toBeVisible();
      await expect(popup.getByText("Do not remove this device: its local data is the evidence of the alarm.")).toBeVisible();
      await expect(popup.getByText("Sync stopped: the server has shown two versions of this account.")).toBeVisible({
        timeout: 15_000,
      });
      await popup.getByRole("button", { name: "Remove this device" }).click();
      await expect(refused).toBeVisible({ timeout: 15_000 });
      expect(await databases(sw)).toContain(CACHE_DATABASE_NAME);
      expect(alarmKeys(await dumpCache(sw))).toEqual([[2]]);
    } finally {
      await context.close();
    }
  });
});
