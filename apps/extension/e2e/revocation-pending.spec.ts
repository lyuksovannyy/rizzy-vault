// SPDX-License-Identifier: AGPL-3.0-only

// The popup's `revocation_pending` banner (ADR 0091 §2 "What clients see", §8 step 7: the
// extension shows the banner; it has no Devices pane). The server sits behind a small proxy
// (the core-holding offscreen document's requests are not seen by Playwright's `context.route`,
// `recovery-notice.spec.ts`) that plays another device's removal: while `freeze` is on it adds
// an open `revocation_window` to every `account/state` answer and answers `vault/upload`
// `409 revocation_pending`, as the window's freeze does for every session not bound to the
// revoker.
//
// Checked: a login saved on submit is kept while the sync that would send it is refused; the
// banner shows ADR 0091 §2's sentence, passes the axe audit, and the popup stays operable by
// keyboard past it, its items still listed; once the freeze lifts, the popup retries the sync
// 15 s later with no user action, the upload goes through and the banner goes.
// Self-contained: `pnpm --filter @rizzy-vault/extension exec playwright test e2e/revocation-pending.spec.ts`.
import { type BrowserContext, type Locator, type Page, chromium, test as base, expect } from "@playwright/test";
import { type IncomingMessage, type Server, type ServerResponse, createServer, request as httpRequest } from "node:http";
import { fileURLToPath } from "node:url";

import { expectAccessible } from "./a11y.ts";
import { TEST_ACCOUNT_PASSWORD, createLoginItem, signUp } from "./account.ts";
import { type RunningServer, startServer } from "./server.ts";
import { withProfileDir } from "./profile.ts";

const EXTENSION_PATH = fileURLToPath(new URL("../dist/chromium", import.meta.url));

/** ADR 0091 §2's sentence. */
const SENTENCE = "Another of your devices is removing a device. Changes are paused for up to 10 minutes.";

/** The revoking device the lying answers name: any id (the notice is never verified). */
const REVOKER = Buffer.alloc(16, 0x5a).toString("base64url");

interface Proxy {
  readonly origin: string;
  freeze: boolean;
  upstream: URL | undefined;
  /** Uploads answered `409 revocation_pending`, and uploads passed on. */
  readonly counts: { refused: number; uploaded: number };
  close(): void;
}

/** `body`, an `account/state` answer, with the open window added. */
function withWindow(body: Buffer): Buffer {
  const view = JSON.parse(body.toString("utf8")) as Record<string, unknown>;
  view["revocation_window"] = { revoker_device_id: REVOKER, expires_at_ms: Date.now() + 600_000 };
  return Buffer.from(JSON.stringify(view), "utf8");
}

async function startProxy(): Promise<Proxy> {
  const state: { freeze: boolean; upstream: URL | undefined } = { freeze: false, upstream: undefined };
  const counts = { refused: 0, uploaded: 0 };
  const server: Server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const upstream = state.upstream;
      if (upstream === undefined) {
        res.writeHead(502);
        res.end();
        return;
      }
      if (req.url === "/api/v1/vault/upload") {
        if (state.freeze) {
          counts.refused += 1;
          const refusal = Buffer.from('{"error":"revocation_pending"}', "utf8");
          res.writeHead(409, { "content-type": "application/json", "content-length": String(refusal.length) });
          res.end(refusal);
          return;
        }
        counts.uploaded += 1;
      }
      const rewrite = state.freeze && req.url === "/api/v1/account/state";
      const headers = { ...req.headers };
      if (rewrite) {
        // A plain body to rewrite.
        delete headers["accept-encoding"];
      }
      const forward = httpRequest(
        { host: upstream.hostname, port: upstream.port, method: req.method, path: req.url, headers },
        (answer) => {
          if (!rewrite || answer.statusCode !== 200) {
            res.writeHead(answer.statusCode ?? 502, answer.headers);
            answer.pipe(res);
            return;
          }
          const parts: Buffer[] = [];
          answer.on("data", (c: Buffer) => parts.push(c));
          answer.on("end", () => {
            const out = withWindow(Buffer.concat(parts));
            const outHeaders = { ...answer.headers, "content-length": String(out.length) };
            delete outHeaders["transfer-encoding"];
            res.writeHead(200, outHeaders);
            res.end(out);
          });
        },
      );
      forward.on("error", () => {
        res.writeHead(502);
        res.end();
      });
      forward.end(Buffer.concat(chunks));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const port = typeof address === "object" && address !== null ? address.port : 0;
  return {
    origin: `http://127.0.0.1:${port}`,
    counts,
    get freeze() {
      return state.freeze;
    },
    set freeze(value: boolean) {
      state.freeze = value;
    },
    get upstream() {
      return state.upstream;
    },
    set upstream(url: URL | undefined) {
      state.upstream = url;
    },
    close: () => server.close(),
  };
}

/** A login page whose submit stays on the page (`autofill-and-save.spec.ts`'s fixture). */
async function startLoginPageServer(): Promise<{ origin: string; stop: () => void }> {
  const server: Server = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "text/html" });
    res.end(
      '<!doctype html><html lang="en"><head><title>Log in</title></head><body><form onsubmit="return false">' +
        '<input type="text" autocomplete="username" aria-label="User"><input type="password" aria-label="Password">' +
        '<button type="submit">Log in</button></form></body></html>',
    );
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const port = typeof address === "object" && address !== null ? address.port : 0;
  return {
    origin: `http://127.0.0.1:${port}/`,
    stop: () => {
      server.closeAllConnections();
      server.close();
    },
  };
}

const test = base.extend<{ edge: Proxy; server: RunningServer; context: BrowserContext; extensionId: string }>({
  edge: async ({}, use) => {
    const edge = await startProxy();
    await use(edge);
    edge.close();
  },
  server: async ({ edge }, use) => {
    const server = await startServer({ publicOrigin: edge.origin });
    edge.upstream = new URL(server.origin);
    await use(server);
    server.stop();
  },
  context: async ({}, use) => {
    await withProfileDir("rizzy-ext-e2e-revocation-", async (userDataDir) => {
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
    let [worker] = context.serviceWorkers();
    if (worker === undefined) {
      worker = await context.waitForEvent("serviceworker");
    }
    await use(new URL(worker.url()).host);
  },
});

/** Moves the focus to `target` with Tab alone (`recovery-notice.spec.ts`'s `tabTo`). */
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

test.setTimeout(150_000);

test("popup: a sync refused during another device's removal shows the banner and is retried (ADR 0091 §2)", async ({
  context,
  extensionId,
  edge,
  server,
}) => {
  expect(server.origin).not.toBe(edge.origin);
  const loginPage = await startLoginPageServer();
  try {
    const setup = await context.newPage();
    const secretKey = await signUp(setup, edge.origin, "revocationext");
    await createLoginItem(setup, {
      title: "Kept Site",
      username: "kept@example.com",
      password: "kept-pw",
      websiteUrl: "https://kept.example.test/",
    });
    await setup.close();

    const popup = await context.newPage();
    await popup.goto(`chrome-extension://${extensionId}/src/popup/index.html`);
    await popup.getByLabel("Server URL").fill(edge.origin);
    await popup.getByLabel("Account (login name)").fill("revocationext");
    await popup.getByLabel("Secret Key").fill(secretKey);
    await popup.getByLabel("Master password").fill(TEST_ACCOUNT_PASSWORD);
    await popup.getByRole("button", { name: "Set up" }).click();
    await expect(popup.getByRole("button", { name: "Lock" })).toBeVisible({ timeout: 30_000 });
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });

    // Another device opens a revocation window: every write of this device is frozen.
    edge.freeze = true;

    // A login saved on submit: kept in the device's cache, not yet sent.
    const page = await context.newPage();
    await page.goto(loginPage.origin);
    await expect(page.locator('input[data-rizzy-field="password"]')).toHaveCount(1);
    await page.locator('input[type="text"]').fill("paused@example.com");
    await page.locator('input[type="password"]').fill("paused-password-123");
    await page.getByRole("button", { name: "Log in" }).click();
    const savePrompt = page.locator("[data-rizzy-save-prompt]");
    await expect(savePrompt).toBeVisible({ timeout: 15_000 });
    await savePrompt.getByRole("button", { name: "Save", exact: true }).click();
    await expect(savePrompt).toHaveCount(0);
    await page.close();

    // The popup's sync is refused: the banner, the core's sentence; the items are still listed.
    await popup.bringToFront();
    const sync = popup.getByRole("button", { name: "Sync", exact: true });
    await sync.click();
    const banner = popup.getByTestId("revocation-banner");
    await expect(banner).toBeVisible({ timeout: 15_000 });
    await expect(banner).toHaveAttribute("role", "status");
    await expect(banner).toContainText(SENTENCE);
    await expect(banner).toContainText("sent again automatically");
    expect(edge.counts.refused).toBeGreaterThanOrEqual(1);
    const kept = popup.getByRole("button", { name: /Kept Site/ });
    await expect(kept).toBeVisible();
    await expectAccessible(popup, "popup: the revocation_pending banner");

    // Keyboard only, past the banner, to the item list.
    await tabTo(popup, kept);

    // The freeze lifts: the popup retries 15 s after the refusal with no user action, the saved
    // login goes up and the banner goes.
    const refused = edge.counts.refused;
    edge.freeze = false;
    await expect(banner).toHaveCount(0, { timeout: 45_000 });
    await expect(popup.getByText("Synced.")).toBeVisible();
    expect(edge.counts.uploaded).toBeGreaterThanOrEqual(1);
    expect(edge.counts.refused).toBe(refused);
  } finally {
    loginPage.stop();
  }
});
