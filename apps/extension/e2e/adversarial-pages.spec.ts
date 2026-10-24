// SPDX-License-Identifier: AGPL-3.0-only

// Adversarial e2e coverage for INV-37 and INV-40 that needs no enrolled account (extension
// loaded only, `extension.spec.ts`'s own fixture shape): hostile pages trying to read, resize or
// message their way around the content script / inline-menu boundary (HANDOFF gap X3,
// `docs/THREAT_MODEL.md` A7, INV-37, INV-40; ADR 0036 §4/§5, ADR 0040).
//
// Already covered elsewhere, not duplicated here:
// - a visually-covered (topmost) field, and a page-script-synthesized click on a real candidate
//   (`extension.spec.ts`);
// - the inline-menu iframe's fixed outer geometry never leaking the saved-candidate count, and
//   the `127.0.0.1`/`localhost` look-alike-host case (`autofill-and-save.spec.ts`);
// - a compromised content script's own `inline_menu_fill_chosen` request being refused by sender
//   identity alone, unit-tested exhaustively against fabricated senders
//   (`test/sender.test.ts`, `test/listener-routing.test.ts`).
//
// Three scenarios need a real enrolled, unlocked device instead (the inline menu renders
// nothing at all — not even the generator button — while the device is locked, which every
// fresh, unenrolled profile in this file is): the HTTPS-saved-credential-on-an-HTTP-page clause
// of INV-37, a forged postMessage into a real rendered menu, and reading into a real rendered
// menu's document. All three live in `adversarial-fill-requests.spec.ts` instead.
import { type BrowserContext, chromium, test as base, expect } from "@playwright/test";
import { createServer, type Server } from "node:http";
import { fileURLToPath } from "node:url";
import { withProfileDir } from "./profile.ts";

const EXTENSION_PATH = fileURLToPath(new URL("../dist/chromium", import.meta.url));

const test = base.extend<{ context: BrowserContext; extensionId: string }>({
  context: async ({}, use) => {
    await withProfileDir("rizzy-ext-e2e-adversarial-", async (userDataDir) => {
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

interface TempServer {
  readonly port: number;
  stop(): Promise<void>;
}

/** A plain HTTP server on `127.0.0.1` serving `html` for every request, closed by `stop`. */
async function startHtmlServer(html: string): Promise<TempServer> {
  const server: Server = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "text/html" });
    res.end(html);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const port = typeof address === "object" && address !== null ? address.port : 0;
  return {
    port,
    stop: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

const SIMPLE_LOGIN_PAGE =
  "<!doctype html><html><body>" +
  '<input id="user" type="text" autocomplete="username">' +
  '<input id="pass" type="password">' +
  "</body></html>";

// ---------------------------------------------------------------------------------------------
// INV-37 clause 3: "Nothing is filled into hidden or invisible fields." Four different ways a
// field can be CSS-invisible, plus one visible control in the same document. The control matters
// as much as the four hidden cases: without it, a bug that disabled detection for every field
// (not only the hidden ones) would also make this test pass.
// ---------------------------------------------------------------------------------------------
const HIDDEN_FIELDS_PAGE =
  "<!doctype html><html><body>" +
  '<input id="display-none" type="password" style="display:none">' +
  '<input id="visibility-hidden" type="password" style="visibility:hidden">' +
  '<input id="opacity-zero" type="password" style="opacity:0">' +
  '<input id="zero-size" type="password" style="width:0;height:0;border:0;padding:0">' +
  '<input id="visible" type="password">' +
  "</body></html>";

test("hidden and invisible fields are never tagged for fill; a visible control field still is (INV-37)", async ({ context }) => {
  const server = await startHtmlServer(HIDDEN_FIELDS_PAGE);
  try {
    const page = await context.newPage();
    await page.goto(`http://127.0.0.1:${server.port}/`);
    // The control: proves detection ran at all, so the absence below means "correctly skipped,"
    // not "detection never happened."
    await expect(page.locator("#visible")).toHaveAttribute("data-rizzy-field", "password", { timeout: 15_000 });
    for (const id of ["display-none", "visibility-hidden", "opacity-zero", "zero-size"]) {
      const tagged = await page.locator(`#${id}`).getAttribute("data-rizzy-field");
      expect(tagged, `#${id} must never be tagged for fill`).toBeNull();
    }
  } finally {
    await server.stop();
  }
});

// ---------------------------------------------------------------------------------------------
// INV-37 clause 2: "Nothing is filled into cross-origin iframes by default." `127.0.0.1` and
// `localhost` are different host strings (the same look-alike-host property
// `autofill-and-save.spec.ts` relies on for its own purposes), so an iframe at one, embedded in a
// page at the other, is genuinely cross-origin. The manifest's `all_frames: false` (checked
// statically by the new `cargo xtask check-manifest`, HANDOFF gap X4) means the content script
// never runs inside that iframe at all, for any host — this test proves the observable
// consequence end to end: no field inside it is ever tagged, and no inline menu ever appears
// inside it.
// ---------------------------------------------------------------------------------------------
test("a cross-origin iframe's login form is never tagged or offered a fill (INV-37)", async ({ context }) => {
  const inner = await startHtmlServer(SIMPLE_LOGIN_PAGE);
  try {
    const outerHtml = `<!doctype html><html><body><iframe id="cross-origin" src="http://localhost:${inner.port}/"></iframe></body></html>`;
    const outer = await startHtmlServer(outerHtml);
    try {
      const page = await context.newPage();
      await page.goto(`http://127.0.0.1:${outer.port}/`);
      const frame = page.frameLocator("#cross-origin");
      await expect(frame.locator("#pass")).toBeVisible({ timeout: 15_000 });
      // Generous margin past the content script's own 250ms detection debounce: if it were
      // (wrongly) injected into this frame, its tag would have landed well before this.
      await page.waitForTimeout(1000);
      const tagged = await frame.locator("#pass").getAttribute("data-rizzy-field");
      expect(tagged).toBeNull();
      await expect(frame.locator("iframe[data-rizzy-inline-menu]")).toHaveCount(0);
      // The outer page has no field of its own, so it must show no menu either.
      await expect(page.locator("iframe[data-rizzy-inline-menu]")).toHaveCount(0);
    } finally {
      await outer.stop();
    }
  } finally {
    await inner.stop();
  }
});

// ---------------------------------------------------------------------------------------------
// INV-40: "There is no `externally_connectable` for web origins. The background treats every
// content-script message as untrusted." Neither manifest declares `externally_connectable`
// (checked statically by `cargo xtask check-manifest`), so a hostile page's own main-world
// script — which always has `chrome.runtime.sendMessage(extensionId, message, callback)`
// available for exactly this one external-messaging purpose, per Chrome's own docs ("pages on
// the web must explicitly be allowed via externally_connectable") — must never reach
// `handleContentScriptRequest`/`handleInlineMenuFillRequest` at all. This is the page-script half
// of "content-script fill requests" in the gap's own wording; the content-script half (a
// compromised content script's own message, which the page cannot inject into) is exhaustively
// unit-tested in `test/sender.test.ts` and `test/listener-routing.test.ts`.
// ---------------------------------------------------------------------------------------------
test("a hostile page's own main-world script cannot reach the background directly (INV-40, no externally_connectable)", async ({
  context,
  extensionId,
}) => {
  const server = await startHtmlServer(SIMPLE_LOGIN_PAGE);
  try {
    const page = await context.newPage();
    await page.goto(`http://127.0.0.1:${server.port}/`);
    await expect(page.locator("#pass")).toHaveAttribute("data-rizzy-field", "password", { timeout: 15_000 });
    const result = await page.evaluate(async (extId) => {
      type ExternalRuntime = {
        sendMessage: (extensionId: string, message: unknown, callback: (response: unknown) => void) => void;
        readonly lastError?: { readonly message?: string };
      };
      const chromeObj = (window as unknown as { chrome?: Record<string, unknown> }).chrome;
      const runtime = (chromeObj as { runtime?: ExternalRuntime } | undefined)?.runtime;
      if (runtime === undefined) {
        return { hasChrome: chromeObj !== undefined, noRuntime: true } as const;
      }
      return new Promise((resolve) => {
        try {
          runtime.sendMessage(
            extId,
            { type: "inline_menu_fill_chosen", itemId: "forged-from-page-main-world", confirmedEquivalence: false },
            (response: unknown) => {
              resolve({ hasChrome: true, noRuntime: false, response, lastError: runtime.lastError?.message });
            },
          );
        } catch (e) {
          resolve({ hasChrome: true, noRuntime: false, thrown: String(e) });
        }
      });
    }, extensionId);
    // Chrome exposes `chrome.runtime` (the one piece of it a web page can see, for exactly this
    // cross-extension-messaging purpose) on a page ONLY when some installed extension's own
    // `externally_connectable.matches` covers that page's origin — confirmed empirically here,
    // not assumed: with only this extension loaded and it declaring no `externally_connectable`
    // at all (INV-40), `window.chrome` itself is present (the browser's ordinary, non-extension
    // page APIs: `loadTimes`/`csi`/`app`) but `window.chrome.runtime` is `undefined`, always —
    // not a browser/config difference this test needs to guard against, but INV-40's own,
    // permanent, observable consequence. The `sendMessage`/`thrown`/`lastError` branch below is
    // kept as a fallback, not the expected path: if a future change ever exposed `chrome.runtime`
    // here, this test must still fail on a real response rather than silently skip past it.
    expect((result as { hasChrome?: boolean }).hasChrome).toBe(true);
    expect((result as { noRuntime?: boolean }).noRuntime).toBe(true);
    expect((result as { response?: unknown }).response).toBeUndefined();
    // The behavioural proof that matters: the page's own password field is still empty, exactly
    // as if this call had never happened.
    await expect(page.locator("#pass")).toHaveValue("");
  } finally {
    await server.stop();
  }
});

// A hostile page's inability to read into the inline-menu iframe's document (cross-origin
// isolation) needs a real rendered menu, which needs a real unlocked device (the menu shows
// nothing at all — not even the generator button — for a device that is locked, i.e. every
// fresh, unenrolled profile this file's other tests use). That test lives in
// `adversarial-fill-requests.spec.ts` instead, alongside the other tests that need an enrolled
// account.
