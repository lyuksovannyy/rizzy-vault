// Threat model INV-63: "in the browser extension, unlocked key material [...] exists only in
// memory: the service worker, an offscreen document, or `storage.session` [...]. It is never
// written to `storage.local`, `storage.sync` or IndexedDB, and no storage that content scripts
// can read holds secrets. Only wrapped device state is persisted." Its verification: a "test
// that inspects every extension storage area after unlock and after a worker restart".
//
// The story: an account with one login item is created through the web vault; the extension
// enrols (CRYPTO.md §11.2: login, enrolment, the encrypted cache filled by a Fetch) and is
// unlocked; every storage area is dumped from inside the extension's own origin (the service
// worker): `storage.local`, `storage.sync` and `storage.session` (every key), and every record of
// every object store of every IndexedDB database. Then the service worker is stopped (Chromium's
// own `ServiceWorker.stopAllWorkers`, what an MV3 suspension does), the popup wakes it and shows
// the vault again (unlocking with the password if the session did not survive), and the dump and
// the search run again.
//
// What is searched for: the master password, the Secret Key (as printed and without
// separators), and the item's password (a decrypted field); each as text, as the hex of its
// UTF-8 bytes (the dump writes every byte array as lowercase hex) and as base64 at each byte
// alignment. The keys themselves (account, vault, item and device keys, `pw_in`, unlock keys)
// live inside the wasm core, which exposes none of their bytes to JavaScript, so this test
// cannot name them; `rizzy-client`'s own canary (`crates/rizzy-client/src/tests/canary.rs`)
// covers what the server sees, and the `storage.session` snapshot is still empty plumbing
// (`core-host/session-store.ts`).
//
// Positive control: the same search must find the enrolment's login name in IndexedDB (the
// account config, which `account-config.ts` stores as UTF-8 bytes, so it is found as hex), so a
// dump that read nothing, or a search that matches nothing, cannot pass.
//
// Same fixtures and harness as `lifetime.spec.ts`: headless installed Chromium, the unpacked
// `dist/chromium` build, a real `rizzy-vault` with the web vault embedded (`server.ts`).
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { type BrowserContext, type Page, type Worker, chromium, test as base, expect } from "@playwright/test";

import { TEST_ACCOUNT_PASSWORD, createLoginItem, signUp } from "./account.ts";
import { type RunningServer, startServer } from "./server.ts";

const EXTENSION_PATH = fileURLToPath(new URL("../dist/chromium", import.meta.url));
const LOGIN_NAME = "storageuser";
const ITEM_PASSWORD = "inv-63 canary: the item's own password";

const test = base.extend<{ server: RunningServer; context: BrowserContext; extensionId: string }>({
  server: async ({}, use) => {
    const server = await startServer();
    await use(server);
    server.stop();
  },
  context: async ({}, use) => {
    const userDataDir = mkdtempSync(join(tmpdir(), "rizzy-ext-e2e-storage-"));
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

test.setTimeout(3 * 60 * 1000);

/** The current service worker, waiting for one if it was stopped. */
async function currentWorker(context: BrowserContext): Promise<Worker> {
  return context.serviceWorkers()[0] ?? (await context.waitForEvent("serviceworker"));
}

/** Every storage area of the extension's origin, read inside the service worker: one JSON text
 * per area (`storage.local`, `storage.sync`, `storage.session`, and `IndexedDB <db>/<store>` for
 * each object store), byte arrays as lowercase hex. */
async function dumpStorage(worker: Worker): Promise<Record<string, string>> {
  return worker.evaluate(async () => {
    const hex = (bytes: Uint8Array): string => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
    const plain = (value: unknown): unknown => {
      if (value instanceof ArrayBuffer) {
        return hex(new Uint8Array(value));
      }
      if (ArrayBuffer.isView(value)) {
        return hex(new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
      }
      if (Array.isArray(value)) {
        return value.map(plain);
      }
      if (value !== null && typeof value === "object") {
        return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, plain(v)]));
      }
      return value;
    };
    type Area = { get(keys: null): Promise<Record<string, unknown>> };
    const storage = (globalThis as unknown as { chrome: { storage: Record<string, Area | undefined> } }).chrome.storage;
    const out: Record<string, string> = {};
    for (const name of ["local", "sync", "session"]) {
      const area = storage[name];
      out[`storage.${name}`] = area === undefined ? "absent" : JSON.stringify(plain(await area.get(null)));
    }
    const request = <T>(r: IDBRequest<T>): Promise<T> =>
      new Promise((resolve, reject) => {
        r.onsuccess = () => resolve(r.result);
        r.onerror = () => reject(r.error);
      });
    for (const info of await indexedDB.databases()) {
      if (info.name === undefined) {
        continue;
      }
      const db = await request(indexedDB.open(info.name));
      for (const store of Array.from(db.objectStoreNames)) {
        const objects = db.transaction(store, "readonly").objectStore(store);
        const keys = await request(objects.getAllKeys());
        const rows = await request(objects.getAll());
        out[`IndexedDB ${info.name}/${store}`] = JSON.stringify(plain({ keys, rows }));
      }
      db.close();
    }
    return out;
  });
}

/** Unpadded base64 of `bytes`, standard or URL alphabet. */
function base64(bytes: Uint8Array, url: boolean): string {
  const text = Buffer.from(bytes).toString("base64").replace(/=+$/, "");
  return url ? text.replaceAll("+", "-").replaceAll("/", "_") : text;
}

/** Every form of `secret` searched for: the text, the lowercase and uppercase hex of its UTF-8
 * bytes, and base64 (both alphabets) at each of the three byte alignments, cut to the characters
 * that encode only the secret's own bits. */
function forms(secret: string): string[] {
  const bytes = new TextEncoder().encode(secret);
  const hex = Buffer.from(bytes).toString("hex");
  const out = [secret, hex, hex.toUpperCase()];
  for (let shift = 0; shift < 3; shift++) {
    const shifted = new Uint8Array(shift + bytes.length);
    shifted.set(bytes, shift);
    const start = Math.ceil((8 * shift) / 6);
    const end = Math.floor((8 * shifted.length) / 6);
    for (const url of [false, true]) {
      out.push(base64(shifted, url).slice(start, end));
    }
  }
  return out;
}

/** Fails if any of `secrets` is in any area of `dump`, naming the secret and the area only. */
function expectNoSecret(dump: Record<string, string>, secrets: ReadonlyArray<readonly [string, string]>, when: string): void {
  for (const [label, secret] of secrets) {
    for (const form of forms(secret)) {
      for (const [area, text] of Object.entries(dump)) {
        expect(text.includes(form), `${label} in ${area} ${when}`).toBe(false);
      }
    }
  }
  const idb = Object.entries(dump).filter(([area]) => area.startsWith("IndexedDB "));
  const sizes = Object.entries(dump).map(([area, text]) => `${area}: ${text.length}`);
  expect(
    idb.some(([, text]) => forms(LOGIN_NAME).some((form) => text.includes(form))),
    `the dump read IndexedDB ${when} (positive control); areas: ${sizes.join(", ")}`,
  ).toBe(true);
}

/** Stops the extension's running service worker through Chromium's DevTools protocol
 * (`ServiceWorker.stopWorker` on the version the `ServiceWorker` domain reports), from a page of
 * the extension's own origin. */
async function stopServiceWorker(context: BrowserContext, extensionId: string): Promise<void> {
  const page = await context.newPage();
  await page.goto(`chrome-extension://${extensionId}/src/popup/index.html`);
  const cdp = await context.newCDPSession(page);
  type Version = { versionId: string; scriptURL: string; runningStatus: string };
  const running = new Promise<string>((resolve) => {
    cdp.on("ServiceWorker.workerVersionUpdated", (event: { versions: Version[] }) => {
      const version = event.versions.find(
        (v) => v.scriptURL.startsWith(`chrome-extension://${extensionId}/`) && v.runningStatus === "running",
      );
      if (version !== undefined) {
        resolve(version.versionId);
      }
    });
  });
  await cdp.send("ServiceWorker.enable");
  await cdp.send("ServiceWorker.stopWorker", { versionId: await running });
  await page.close();
}

/** Opens the popup; unlocks with the password if the session did not survive. */
async function openUnlocked(context: BrowserContext, extensionId: string): Promise<Page> {
  const popup = await context.newPage();
  await popup.goto(`chrome-extension://${extensionId}/src/popup/index.html`);
  const lock = popup.getByRole("button", { name: "Lock" });
  const unlock = popup.getByRole("button", { name: "Unlock" });
  await expect(lock.or(unlock)).toBeVisible({ timeout: 30_000 });
  if (await unlock.isVisible()) {
    await popup.getByLabel("Master password").fill(TEST_ACCOUNT_PASSWORD);
    await unlock.click();
    await expect(lock).toBeVisible({ timeout: 30_000 });
  }
  return popup;
}

test("no storage area holds a secret after unlock and after a worker restart (INV-63)", async ({
  context,
  extensionId,
  server,
}) => {
  const vault = await context.newPage();
  const secretKey = await signUp(vault, server.origin, LOGIN_NAME);
  await createLoginItem(vault, {
    title: "Canary",
    username: "canary",
    password: ITEM_PASSWORD,
    websiteUrl: "https://canary.example.com/",
  });
  await vault.close();
  const secrets = [
    ["the master password", TEST_ACCOUNT_PASSWORD],
    ["the Secret Key", secretKey],
    ["the Secret Key without separators", secretKey.replaceAll("-", "")],
    ["the item's password", ITEM_PASSWORD],
  ] as const;

  // Enrol and unlock.
  const popup = await context.newPage();
  await popup.goto(`chrome-extension://${extensionId}/src/popup/index.html`);
  await popup.getByLabel("Server URL").fill(server.origin);
  await popup.getByLabel("Account (login name)").fill(LOGIN_NAME);
  await popup.getByLabel("Secret Key").fill(secretKey);
  await popup.getByLabel("Master password").fill(TEST_ACCOUNT_PASSWORD);
  await popup.getByRole("button", { name: "Set up" }).click();
  await expect(popup.getByRole("button", { name: "Lock" })).toBeVisible({ timeout: 30_000 });
  await popup.close();
  expectNoSecret(await dumpStorage(await currentWorker(context)), secrets, "after unlock");

  // Stop the service worker, as an MV3 suspension does, then wake it through the popup. A mark
  // set on the old worker's global object proves the woken one is a new instance.
  await (await currentWorker(context)).evaluate(() => {
    (globalThis as unknown as { inv63Mark?: boolean }).inv63Mark = true;
  });
  await stopServiceWorker(context, extensionId);
  const woken = await openUnlocked(context, extensionId);
  expect(
    await (await currentWorker(context)).evaluate(() => (globalThis as unknown as { inv63Mark?: boolean }).inv63Mark),
    "the service worker was restarted",
  ).toBeUndefined();
  expectNoSecret(await dumpStorage(await currentWorker(context)), secrets, "after a worker restart");
  await woken.close();
});
