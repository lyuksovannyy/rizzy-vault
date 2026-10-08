// What is real today, per `core/bindings.ts`'s gap: the extension loads, its offscreen document
// starts, the popup opens and shows the locked state, and the `storage.session` fallback
// survives the long-lived context being torn down and recreated. "Enrol, unlock, fill a test
// login page, lock" (the task's original E2E description) cannot pass without the
// durable-device bindings and is reported in `not_done`, not faked here with a mocked backend.
//
// This spec doubles as the offscreen/background-page survival spike ADR 0036 §2 assigns to the
// implementation PR: `offscreen document reachable after a short wait` is the measurement.
import { type BrowserContext, chromium, test as base, expect } from "@playwright/test";
import { mkdtempSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const EXTENSION_PATH = fileURLToPath(new URL("../dist/chromium", import.meta.url));

// A minimal login page on real `http://localhost`: the content script's manifest `matches`
// entry only fires on an http(s) origin, never on `about:blank` (`page.setContent`'s origin),
// so the spike measurement below needs an actual HTTP server, not a shortcut.
const TEST_LOGIN_PAGE =
  "<!doctype html><html><body>" +
  '<input type="text" autocomplete="username">' +
  '<input type="password">' +
  "</body></html>";

const test = base.extend<{ context: BrowserContext; extensionId: string; loginPageUrl: string }>({
  context: async ({}, use) => {
    const userDataDir = mkdtempSync(join(tmpdir(), "rizzy-ext-e2e-"));
    const context = await chromium.launchPersistentContext(userDataDir, {
      headless: false,
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
  loginPageUrl: async ({}, use) => {
    const server: Server = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "text/html" });
      res.end(TEST_LOGIN_PAGE);
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    const port = typeof address === "object" && address !== null ? address.port : 0;
    await use(`http://127.0.0.1:${port}/`);
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  },
});

test("the unpacked extension loads and registers a service worker", async ({ extensionId }) => {
  expect(extensionId).toMatch(/^[a-p]{32}$/);
});

test("the offscreen document is reachable after the content script reports fields (ADR 0036 §2 spike)", async ({
  context,
  loginPageUrl,
}) => {
  // The content script only injects on a real http(s) origin matching its manifest pattern, so
  // this navigates to `loginPageUrl` (a real `http://127.0.0.1` server), not `about:blank`.
  // That `fields_detected` message is what makes the service worker call
  // `chrome.offscreen.createDocument` on first use (`background/service-worker.ts`).
  //
  // Measured while writing this spec: `context.pages()`/`backgroundPages()` do NOT enumerate
  // the offscreen document in this Playwright/Chromium combination (traced with the service
  // worker's own console and an explicit try/catch around `createDocument`: it throws no
  // error, yet no `offscreen.html` page ever appears in either list) — a Playwright
  // introspection gap, not an extension bug. Asking the extension itself, through
  // `chrome.offscreen.hasDocument()`, is the one way to get a true answer.
  let [worker] = context.serviceWorkers();
  if (worker === undefined) {
    worker = await context.waitForEvent("serviceworker");
  }
  const page = await context.newPage();
  await page.goto(loginPageUrl);
  await page.waitForTimeout(2000);
  const hasDocument = await worker.evaluate(() => chrome!.offscreen!.hasDocument());
  expect(hasDocument).toBe(true);
});

test("the popup opens and shows the locked state", async ({ context, extensionId }) => {
  const page = await context.newPage();
  await page.goto(`chrome-extension://${extensionId}/src/popup/index.html`);
  await expect(page.getByRole("heading", { name: "rizzy-vault" })).toBeVisible();
  await expect(page.getByLabel("Master password")).toBeVisible();
  // `App.tsx` renders the same "locked" view whether `client.status()` resolved `{ locked:
  // true }` or rejected (e.g. "Could not establish connection", the exact failure a missing
  // offscreen document used to cause on a fresh profile) — only the `role="alert"` error banner
  // distinguishes the two. Without this assertion, a regression that breaks every popup status
  // call would leave this test green.
  await expect(page.getByRole("alert")).toHaveCount(0);
});

test("storage.session survives a popup reload (fallback plumbing, ADR 0036 §2)", async ({ context, extensionId }) => {
  const page = await context.newPage();
  await page.goto(`chrome-extension://${extensionId}/src/popup/index.html`);
  await page.evaluate(async () => {
    // `chrome` is always defined on an extension page; the ambient type only allows for a
    // content-script/test context where it might not be (`src/types/webext.d.ts`). `storage` is
    // also typed optional (absent inside a `chrome.offscreen` document specifically, per that
    // same file's comment) but present on this popup page, a regular extension page.
    await chrome!.storage!.session.set({ probe: "still-here" });
  });
  await page.reload();
  const value = await page.evaluate(async () => (await chrome!.storage!.session.get("probe"))["probe"]);
  expect(value).toBe("still-here");
});

// `content-script.ts`'s `isTopmost` (ADR 0037 §5 "No hidden/invisible field fill", the topmost
// half): a CSS-visible field another element visually covers must not be tagged
// `data-rizzy-field`, so it can never be offered or filled. `OVERLAID_LOGIN_PAGE` puts one
// password field under a full-coverage, higher-`z-index` div and a second, identical field in
// the open, so a bug that disabled detection entirely (rather than specifically the topmost
// check) would also fail this test — it is not enough for the covered field to merely be
// untagged.
const OVERLAID_LOGIN_PAGE =
  "<!doctype html><html><body>" +
  '<div style="position:relative">' +
  '<input id="covered" type="password">' +
  '<div style="position:absolute;inset:0;z-index:1000;background:transparent"></div>' +
  "</div>" +
  '<input id="open" type="password">' +
  "</body></html>";

test("a field visually covered by another element is never tagged for fill (ADR 0037 §5 topmost check)", async ({
  context,
}) => {
  const server = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "text/html" });
    res.end(OVERLAID_LOGIN_PAGE);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const port = typeof address === "object" && address !== null ? address.port : 0;
  try {
    const page = await context.newPage();
    await page.goto(`http://127.0.0.1:${port}/`);
    // The content script's detection is debounced (250ms) behind a `MutationObserver`/initial
    // `schedule()` call; this margin is generous, not tuned to the exact debounce value.
    await page.waitForTimeout(1000);
    const coveredTagged = await page.locator("#covered").getAttribute("data-rizzy-field");
    const openTagged = await page.locator("#open").getAttribute("data-rizzy-field");
    expect(coveredTagged).toBeNull();
    expect(openTagged).toBe("password");
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

// The inline-menu iframe (`src/inline-menu/main.ts`, ADR 0036 §4/§5, INV-36): a candidate's
// `click` handler must require `event.isTrusted`, so a page-script-synthesized click (the
// pre-fix vulnerability — a hostile page could call `.click()` on a candidate and fill without
// any real user gesture) can never pick a candidate. These two tests navigate directly to the
// iframe's own page (no embedding frame, so `window.parent === window`, which this script's own
// `postMessage` origin check accepts) and drive the *same* click target two ways: a real,
// trusted Playwright click (must succeed) and a page-script-dispatched synthetic click, which
// the browser marks `isTrusted: false` (must be silently ignored).
const INLINE_MENU_SHOW = "rizzy-inline-menu-show";

async function openInlineMenuWithOneCandidate(context: BrowserContext, extensionId: string) {
  const page = await context.newPage();
  await page.goto(`chrome-extension://${extensionId}/src/inline-menu/index.html`);
  await page.evaluate(
    ({ showType, itemId }) => {
      (window as unknown as { __picked: string | undefined }).__picked = undefined;
      window.addEventListener("message", (event) => {
        const data = event.data as { type?: unknown; itemId?: unknown };
        if (data?.type === "rizzy-inline-menu-pick") {
          (window as unknown as { __picked: string | undefined }).__picked = data.itemId as string;
        }
      });
      window.postMessage({ type: showType, pageOrigin: location.origin, candidates: [{ itemId, title: "Example", username: "alice" }] }, location.origin);
    },
    { showType: INLINE_MENU_SHOW, itemId: "item-1" },
  );
  await page.waitForSelector("#list button");
  return page;
}

test("a trusted click on a candidate reports the pick (positive control)", async ({ context, extensionId }) => {
  const page = await openInlineMenuWithOneCandidate(context, extensionId);
  await page.locator("#list button").click();
  await expect
    .poll(() => page.evaluate(() => (window as unknown as { __picked: string | undefined }).__picked))
    .toBe("item-1");
});

test("a page-script-synthesized (untrusted) click on a candidate reports nothing", async ({ context, extensionId }) => {
  const page = await openInlineMenuWithOneCandidate(context, extensionId);
  await page.evaluate(() => {
    document.querySelector("#list button")!.dispatchEvent(new MouseEvent("click", { bubbles: true }));
  });
  // No fixed wait proves a negative with certainty, but this gives the (absent) async pick
  // ample time to land before asserting it never did.
  await page.waitForTimeout(300);
  const picked = await page.evaluate(() => (window as unknown as { __picked: string | undefined }).__picked);
  expect(picked).toBeUndefined();
});
