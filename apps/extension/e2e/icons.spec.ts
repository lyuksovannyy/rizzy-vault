// SPDX-License-Identifier: AGPL-3.0-only

// Item icons in the extension popup (ADR 0052 point 6; packages/ui `ItemIcon`). The server sits
// behind a small proxy that routes `/api/v1/icons/` to a mocked `icons` role and everything
// else to the server, the shape ADR 0052 point 6 gives the operator's reverse proxy (the
// core-holding offscreen document's requests are not seen by Playwright's `context.route`, so
// the mock is a real HTTP endpoint; no request reaches a site). Checks what the extension sends
// (the normalised hostname as the one field, no Authorization header), that the popup shows the
// icon as a decoded `blob:` image with an empty `alt`, that an item without an icon shows none,
// that the popup loads no image from anywhere else, and the axe audit of the item list with
// icons. Self-contained (its own server and account):
// `pnpm --filter @rizzy-vault/extension exec playwright test e2e/icons.spec.ts`.
import { type BrowserContext, chromium, test as base, expect } from "@playwright/test";
import { mkdtempSync } from "node:fs";
import { type IncomingMessage, type Server, type ServerResponse, createServer, request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { expectAccessible } from "./a11y.ts";
import { TEST_ACCOUNT_PASSWORD, createLoginItem, signUp } from "./account.ts";
import { type RunningServer, startServer } from "./server.ts";

const EXTENSION_PATH = fileURLToPath(new URL("../dist/chromium", import.meta.url));

/** A 16×16 PNG, as base64url (what the role returns). */
const PNG = "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8_9hAAAAGUlEQVR4nGOQqzjxnxLMMGrAqAGjBgwXAwC6dV0fK4JiqwAAAABJRU5ErkJggg";

/** What the mocked role saw from the extension (its `Origin` is the extension's). */
interface Seen {
  readonly bodies: string[];
  readonly authorization: (string | undefined)[];
}

/** The proxy: `/api/v1/icons/fetch` answered by the mock (an icon for `icons.example.test`,
 * `404` otherwise), every other request forwarded to `upstream` unchanged. */
interface Proxy {
  readonly origin: string;
  readonly seen: Seen;
  upstream: URL | undefined;
  close(): void;
}

async function startProxy(): Promise<Proxy> {
  const seen: Seen = { bodies: [], authorization: [] };
  const proxy: { upstream: URL | undefined } = { upstream: undefined };
  const server: Server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      if (req.url === "/api/v1/icons/fetch" && req.method === "POST") {
        const text = body.toString("utf8");
        if (String(req.headers["origin"] ?? "").startsWith("chrome-extension://")) {
          seen.bodies.push(text);
          seen.authorization.push(req.headers["authorization"]);
        }
        const hit = text === '{"host":"icons.example.test"}';
        res.writeHead(hit ? 200 : 404, { "content-type": "application/json", "cache-control": "no-store" });
        res.end(hit ? JSON.stringify({ content_type: "image/png", data: PNG }) : '{"error":"not_found"}');
        return;
      }
      const upstream = proxy.upstream;
      if (upstream === undefined) {
        res.writeHead(502);
        res.end();
        return;
      }
      const forward = httpRequest(
        { host: upstream.hostname, port: upstream.port, method: req.method, path: req.url, headers: req.headers },
        (answer) => {
          res.writeHead(answer.statusCode ?? 502, answer.headers);
          answer.pipe(res);
        },
      );
      forward.on("error", () => {
        res.writeHead(502);
        res.end();
      });
      forward.end(body);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const port = typeof address === "object" && address !== null ? address.port : 0;
  return {
    origin: `http://127.0.0.1:${port}`,
    seen,
    get upstream() {
      return proxy.upstream;
    },
    set upstream(url: URL | undefined) {
      proxy.upstream = url;
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
    const userDataDir = mkdtempSync(join(tmpdir(), "rizzy-ext-e2e-icons-"));
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

test.setTimeout(120_000);

test("popup: item icons from the icons role, hostname only, blob: images, audited", async ({
  context,
  extensionId,
  edge,
  server,
}) => {
  expect(server.origin).not.toBe(edge.origin);
  const setup = await context.newPage();
  const secretKey = await signUp(setup, edge.origin, "iconsext");
  await createLoginItem(setup, {
    title: "Icon Site",
    username: "icon@example.com",
    password: "icon-pw",
    websiteUrl: "https://Icons.Example.test/login?next=/private",
  });
  await createLoginItem(setup, {
    title: "Plain Site",
    username: "plain@example.com",
    password: "plain-pw",
    websiteUrl: "https://no-icon.example.test/",
  });
  await setup.close();

  const popup = await context.newPage();
  const images: string[] = [];
  popup.on("request", (r) => {
    if (r.resourceType() === "image") {
      images.push(r.url());
    }
  });
  await popup.goto(`chrome-extension://${extensionId}/src/popup/index.html`);
  await popup.getByLabel("Server URL").fill(edge.origin);
  await popup.getByLabel("Account (login name)").fill("iconsext");
  await popup.getByLabel("Secret Key").fill(secretKey);
  await popup.getByLabel("Master password").fill(TEST_ACCOUNT_PASSWORD);
  await popup.getByRole("button", { name: "Set up" }).click();
  await expect(popup.getByRole("button", { name: "Lock" })).toBeVisible({ timeout: 30_000 });

  const iconRow = popup.getByRole("button", { name: /Icon Site/ });
  const icon = iconRow.locator("img.item-favicon");
  await expect(icon).toBeVisible();
  await expect(icon).toHaveAttribute("alt", "");
  await expect(icon).toHaveAttribute("src", /^blob:chrome-extension:/);
  await expect.poll(() => icon.evaluate((img: HTMLImageElement) => img.complete && img.naturalWidth)).toBe(16);
  await expect(popup.getByRole("button", { name: /Plain Site/ }).locator("img")).toHaveCount(0);
  // The row's accessible name is the item, not the image.
  await expect(iconRow).toHaveAccessibleName(/^Icon Site/);

  // What the extension sent: one normalised hostname per site, without a session.
  expect([...new Set(edge.seen.bodies)].sort()).toEqual(['{"host":"icons.example.test"}', '{"host":"no-icon.example.test"}']);
  for (const auth of edge.seen.authorization) {
    expect(auth).toBeUndefined();
  }
  for (const url of images) {
    expect(url.startsWith("blob:") || url.startsWith(`chrome-extension://${extensionId}/`)).toBe(true);
  }
  await expectAccessible(popup, "popup: items with icons");
});
