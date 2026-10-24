// SPDX-License-Identifier: AGPL-3.0-only

// The popup's pending-recovery banner (ADR 0045, owner answer 2) and INV-70: the server's
// advisory `pending_recovery` notice is shown as given and changes nothing the extension
// trusts. The server sits behind a small proxy (the core-holding offscreen document's requests
// are not seen by Playwright's `context.route`, `icons.spec.ts`) that can lie in every
// `account/state` answer: add an invented notice, or add one to an answer whose signed state
// it tampered with. The extension is an enrolled durable device (kind 2), the kind an honest
// server does send the notice to (point 4; `rizzy-domain-auth`'s tests check the server side).
//
// Checked: the banner shows when, how to cancel and that it is not verified; it passes the axe
// audit and the popup stays operable by keyboard alone past it; the items are still listed and
// the sync still succeeds (nothing else moved); an answer without a notice clears it (point 3);
// a notice on a tampered state is never shown and that sync fails as it would without one.
// Self-contained: `pnpm --filter @rizzy-vault/extension exec playwright test e2e/recovery-notice.spec.ts`.
import { type BrowserContext, type Locator, type Page, chromium, test as base, expect } from "@playwright/test";
import { type IncomingMessage, type Server, type ServerResponse, createServer, request as httpRequest } from "node:http";
import { fileURLToPath } from "node:url";

import { expectAccessible } from "./a11y.ts";
import { TEST_ACCOUNT_PASSWORD, createLoginItem, signUp } from "./account.ts";
import { type RunningServer, startServer } from "./server.ts";
import { withProfileDir } from "./profile.ts";

const EXTENSION_PATH = fileURLToPath(new URL("../dist/chromium", import.meta.url));

/** What the lying proxy does to each `account/state` answer. */
type Lie = "none" | "invent" | "tamper";

/** The invented notice: requested 2026-09-21, its wait long over, a recovery before it. */
const INVENTED = {
  opened_at_ms: 1_790_000_000_000,
  available_at_ms: 1_790_259_200_000,
  last_recovery_at_ms: 1_789_000_000_000,
};

interface Proxy {
  readonly origin: string;
  lie: Lie;
  upstream: URL | undefined;
  close(): void;
}

/** `body`, an `account/state` answer, as the lying proxy relays it under `lie`. */
function lieAbout(body: Buffer, lie: Lie): Buffer {
  if (lie === "none") {
    return body;
  }
  const view = JSON.parse(body.toString("utf8")) as Record<string, unknown>;
  view["pending_recovery"] = INVENTED;
  if (lie === "tamper") {
    const state = String(view["account_state"]);
    const mid = Math.floor(state.length / 2);
    view["account_state"] = state.slice(0, mid) + (state[mid] === "A" ? "B" : "A") + state.slice(mid + 1);
  }
  return Buffer.from(JSON.stringify(view), "utf8");
}

async function startProxy(): Promise<Proxy> {
  const state: { lie: Lie; upstream: URL | undefined } = { lie: "none", upstream: undefined };
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
      const rewrite = req.url === "/api/v1/account/state";
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
            const out = lieAbout(Buffer.concat(parts), state.lie);
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
    get lie() {
      return state.lie;
    },
    set lie(value: Lie) {
      state.lie = value;
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
    await withProfileDir("rizzy-ext-e2e-recovery-", async (userDataDir) => {
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

/** Moves the focus to `target` with Tab alone, failing when it is not reached within `max`
 * presses (`a11y.spec.ts`'s `tabTo`). */
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

test.setTimeout(120_000);

test("popup: a pending-recovery notice is shown, and nothing else changes (ADR 0045, INV-70)", async ({
  context,
  extensionId,
  edge,
  server,
}) => {
  expect(server.origin).not.toBe(edge.origin);
  const setup = await context.newPage();
  const secretKey = await signUp(setup, edge.origin, "recoveryext");
  await createLoginItem(setup, {
    title: "Kept Site",
    username: "kept@example.com",
    password: "kept-pw",
    websiteUrl: "https://kept.example.test/",
  });
  await setup.close();

  edge.lie = "invent";
  const popup = await context.newPage();
  await popup.goto(`chrome-extension://${extensionId}/src/popup/index.html`);
  await popup.getByLabel("Server URL").fill(edge.origin);
  await popup.getByLabel("Account (login name)").fill("recoveryext");
  await popup.getByLabel("Secret Key").fill(secretKey);
  await popup.getByLabel("Master password").fill(TEST_ACCOUNT_PASSWORD);
  await popup.getByRole("button", { name: "Set up" }).click();
  await expect(popup.getByRole("button", { name: "Lock" })).toBeVisible({ timeout: 30_000 });

  const banner = popup.getByTestId("recovery-banner");
  await expect(banner).toBeVisible();
  await expect(banner).toHaveAttribute("role", "alert");
  await expect(banner).toContainText("Account recovery requested");
  await expect(banner).toContainText("it can be completed now");
  await expect(banner).toContainText("rv recovery cancel");
  await expect(banner).toContainText("This account was last recovered on");
  await expect(banner).toContainText("not verified");
  // INV-70: nothing else moved. The sync succeeded and the items are there.
  await expect(popup.getByRole("status")).toHaveText("Synced.");
  await expect(popup.getByRole("button", { name: /Kept Site/ })).toBeVisible();
  await expectAccessible(popup, "popup: items under the pending-recovery banner");

  // Keyboard only, past the banner: Sync again (the notice is still served, so it stays).
  const sync = popup.getByRole("button", { name: "Sync", exact: true });
  await tabTo(popup, sync);
  await popup.keyboard.press("Enter");
  await expect(popup.getByRole("status")).toHaveText("Synced.");
  await expect(banner).toBeVisible();

  // The first answer without a notice clears it (ADR 0045 point 3).
  edge.lie = "none";
  await tabTo(popup, sync);
  await popup.keyboard.press("Enter");
  await expect(popup.getByRole("status")).toHaveText("Synced.");
  await expect(banner).toHaveCount(0);

  // A notice on a tampered signed state: that sync fails as it would without one, and the
  // notice is never shown.
  edge.lie = "tamper";
  await sync.click();
  // Any answer but "Synced.": the error code the refused sync reports.
  await expect(popup.getByRole("status")).toHaveText(/^(?!Synced\.$).+/);
  await expect(banner).toHaveCount(0);

  // Honest again: the sync recovers.
  edge.lie = "none";
  await sync.click();
  await expect(popup.getByRole("status")).toHaveText("Synced.");
  await expect(banner).toHaveCount(0);
  await expect(popup.getByRole("button", { name: /Kept Site/ })).toBeVisible();
});
