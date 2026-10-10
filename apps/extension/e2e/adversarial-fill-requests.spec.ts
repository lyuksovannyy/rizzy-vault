// Adversarial e2e coverage for INV-37 and INV-40 that needs a real enrolled device (HANDOFF gap
// X3; `docs/THREAT_MODEL.md` A7, INV-37, INV-40; ADR 0036 §4/§5; ADR 0040). The inline menu
// renders nothing at all — not even the generator button — while the device is locked, so every
// scenario here needs a real `DurableSession`, never a fabricated candidate list:
//
// 1. INV-37 clause 1: "No HTTPS-saved credential is filled into an HTTP page." An HTTP-saved
//    item on the very same page IS offered (the positive control) — without it, this test would
//    also pass if matching were broken entirely, not only the downgrade rule specifically.
// 2. A forged `postMessage` straight into the real inline-menu iframe (bypassing the content
//    script entirely, the one direction `inline-menu/protocol.ts` already documents as
//    forgeable) cannot reveal a credential even for a fabricated candidate a real, trusted
//    Playwright click picks — because `handleInlineMenuFillRequest` (ADR 0040 point 3)
//    re-derives the real candidate list from the tab's own browser-vouched URL and refuses an
//    `itemId` that is not genuinely a member of it, independent of whatever the iframe's own DOM
//    was tricked into rendering.
// 3. The embedding page has no same-origin access to the real menu's document at all
//    (`content-script.ts`'s own module doc on `InlineMenu`) — confirms the cross-origin
//    isolation every other "page cannot script the menu" guarantee in this file and
//    `adversarial-pages.spec.ts` relies on.
// 4. A7's "overlay/clickjacking" scenario (THREAT_MODEL.md, citing DEF CON 33): a page
//    stylesheet rule can make the real inline-menu iframe invisible while it stays fully
//    clickable, because `content-script.ts`'s `InlineMenu` sets position/size/z-index inline on
//    it but never `opacity`. See that test's own comments for what this found.
//
// Setup mirrors `autofill-and-save.spec.ts` (real server, real signup, real popup enrolment) —
// duplicated rather than imported, for the same reason that file gives for not importing from
// `apps/web/e2e`: a small, self-contained spec is worth more here than a cross-file dependency.
import { mkdtempSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { type BrowserContext, type Page, chromium, test as base, expect } from "@playwright/test";

import { TEST_ACCOUNT_PASSWORD, createLoginItem, signUp } from "./account.ts";
import { type RunningServer, startServer } from "./server.ts";

const EXTENSION_PATH = fileURLToPath(new URL("../dist/chromium", import.meta.url));

function loginPageHtml(): string {
  return (
    "<!doctype html><html><body><form onsubmit=\"return false\">" +
    '<input id="user" type="text" autocomplete="username">' +
    '<input id="pass" type="password">' +
    '<button type="submit">Log in</button>' +
    "</form></body></html>"
  );
}

/** A plain HTTP server for one test login page on a fixed loopback port, reachable under both
 * `127.0.0.1` and `localhost` (the server does no host-header filtering) — the same device, two
 * host strings, needed so the downgrade test's "same host, different scheme" item can be saved
 * against `localhost` while the server itself binds the usual loopback address. */
async function startLoginPageServer(): Promise<{ port: number; stop: () => Promise<void> }> {
  const server: Server = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "text/html" });
    res.end(loginPageHtml());
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

const test = base.extend<{ server: RunningServer; context: BrowserContext; extensionId: string }>({
  server: async ({}, use) => {
    const server = await startServer();
    await use(server);
    server.stop();
  },
  context: async ({}, use) => {
    const userDataDir = mkdtempSync(join(tmpdir(), "rizzy-ext-e2e-adversarial-fill-"));
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

async function openPopup(context: BrowserContext, extensionId: string): Promise<Page> {
  const page = await context.newPage();
  await page.goto(`chrome-extension://${extensionId}/src/popup/index.html`);
  return page;
}

async function enrol(context: BrowserContext, extensionId: string, server: RunningServer, loginName: string, secretKey: string): Promise<Page> {
  const popup = await openPopup(context, extensionId);
  await popup.getByLabel("Server URL").fill(server.origin);
  await popup.getByLabel("Account (login name)").fill(loginName);
  await popup.getByLabel("Secret Key").fill(secretKey);
  await popup.getByLabel("Master password").fill(TEST_ACCOUNT_PASSWORD);
  await popup.getByRole("button", { name: "Set up" }).click();
  await expect(popup.getByRole("button", { name: "Lock" })).toBeVisible({ timeout: 30_000 });
  await expect(popup.getByRole("alert")).toHaveCount(0);
  return popup;
}

test.setTimeout(120_000);

test("an HTTPS-saved credential is never offered on the HTTP version of the same host, while an HTTP-saved one is (INV-37)", async ({
  context,
  extensionId,
  server,
}) => {
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "downgradeuser");
    // Saved verbatim (ADR 0037 §2: normalisation and matching happen later, never at save time)
    // — this item is never actually served over TLS; `rizzy-match` only ever parses the saved
    // string, it never connects to it.
    //
    // Titles deliberately avoid the substring "Save": the web vault's own "New item" form has a
    // `button[type=submit]` literally named "Save", and `account.ts`'s `createLoginItem` finds
    // it with a non-exact `getByRole` name match — a title containing "Save" (e.g. "HTTPS
    // Saved") makes that locator ambiguous against this item's own just-created list row.
    await createLoginItem(setupPage, {
      title: "Via HTTPS",
      username: "https-user@example.com",
      password: "https-saved-password",
      websiteUrl: `https://localhost:${page.port}/`,
    });
    await createLoginItem(setupPage, {
      title: "Via HTTP",
      username: "http-user@example.com",
      password: "http-saved-password",
      websiteUrl: `http://localhost:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "downgradeuser", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await visit.goto(`http://localhost:${page.port}/`);
    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    // Positive control first: if this never appears, matching itself is broken, and the
    // downgrade assertion below would be meaningless (it would also pass with matching dead).
    await expect(menu.getByRole("button", { name: "Via HTTP", exact: false })).toBeVisible({ timeout: 15_000 });
    await expect(menu.getByRole("button", { name: "Via HTTPS", exact: false })).toHaveCount(0);
    await visit.close();
  } finally {
    await page.stop();
  }
});

// No positive control in this specific test (no saved item at all, deliberately, to isolate the
// forgery path from matching itself) — "a real trusted click on a real candidate fills" is
// already proven elsewhere in this same suite run (`autofill-and-save.spec.ts`, and the
// downgrade test above), so a bug that broke fill entirely would already be caught there, not
// silently hidden behind this test alone.
test("a forged postMessage directly into the real inline-menu iframe cannot reveal a credential, even for a real trusted click", async ({
  context,
  extensionId,
  server,
}) => {
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "forgeduser");
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "forgeduser", secretKey);
    await popup.close();

    const visit = await context.newPage();
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    // The real content script creates the real iframe the moment it detects the password field
    // (there are no saved items at all, so its own, honest `rizzy-inline-menu-show` carries zero
    // candidates — only the generator button). This test's forged message is sent AFTER that,
    // straight to the same real iframe element, exactly as `protocol.ts`'s own module doc
    // describes: "a hostile page's own script can call `frame.contentWindow.postMessage(...)`
    // just as validly as the content script can."
    const frame = visit.locator("iframe[data-rizzy-inline-menu]");
    await expect(frame).toBeVisible({ timeout: 15_000 });
    // Waits for the real menu's own document to have actually loaded and rendered its honest
    // (zero-candidate) content — not merely for the outer `<iframe>` element to be attached and
    // sized, which can be true for a moment while the frame still sits on its transitional
    // initial document, before the real cross-origin navigation has committed.
    await expect(visit.frameLocator("iframe[data-rizzy-inline-menu]").getByRole("button", { name: "Generate password" })).toBeVisible({
      timeout: 15_000,
    });

    const FORGED_ITEM_ID = "attacker-forged-item-id-does-not-exist";
    await visit.evaluate((forgedItemId) => {
      const el = document.querySelector("iframe[data-rizzy-inline-menu]") as HTMLIFrameElement | null;
      if (el?.contentWindow === null || el?.contentWindow === undefined) {
        throw new Error("adversarial test setup: inline-menu iframe not found");
      }
      el.contentWindow.postMessage(
        {
          type: "rizzy-inline-menu-show",
          pageOrigin: location.origin,
          pageHost: location.hostname,
          candidates: [
            {
              itemId: forgedItemId,
              title: "Fake PayPal (forged by the page)",
              username: "attacker-controlled-label",
              needsWarning: false,
              savedHost: location.hostname,
            },
          ],
        },
        "*",
      );
    }, FORGED_ITEM_ID);

    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const forgedButton = menu.getByRole("button", { name: "Fake PayPal", exact: false });
    await expect(forgedButton).toBeVisible({ timeout: 15_000 });
    // A real, OS-level, trusted Playwright click — not a page-script-synthesized one. The
    // defence this test exists to prove is NOT "untrusted clicks are ignored" (that's
    // `extension.spec.ts`'s own test); it is that a real trusted click on a row the real iframe
    // was merely tricked into *rendering* still cannot reveal anything, because the background
    // re-derives the real candidate list itself and `forgedItemId` is never a member of it.
    await forgedButton.click();
    // No fixed wait proves a negative with certainty, but this gives the (absent) async fill
    // ample time to land before asserting it never did.
    await visit.waitForTimeout(1000);
    await expect(visit.locator("#user")).toHaveValue("");
    await expect(visit.locator("#pass")).toHaveValue("");
    await visit.close();
  } finally {
    await page.stop();
  }
});

test("a hostile page cannot read into a real, rendered inline-menu iframe's document", async ({ context, extensionId, server }) => {
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "readiframeuser");
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "readiframeuser", secretKey);
    await popup.close();

    const visit = await context.newPage();
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    await expect(visit.locator("iframe[data-rizzy-inline-menu]")).toBeVisible({ timeout: 15_000 });
    // Waits for the real cross-origin navigation to have committed (the generator button only
    // renders once `main.ts` has received the real `rizzy-inline-menu-show` message) — without
    // this, `contentDocument` can still be non-null for a moment on the frame's transitional
    // initial document, which is same-origin with this page.
    await expect(visit.frameLocator("iframe[data-rizzy-inline-menu]").getByRole("button", { name: "Generate password" })).toBeVisible({
      timeout: 15_000,
    });
    const result = await visit.evaluate(() => {
      const frame = document.querySelector("iframe[data-rizzy-inline-menu]") as HTMLIFrameElement | null;
      if (frame === null) {
        return { frameMissing: true, contentDocumentIsNull: false, threwOnAccess: false };
      }
      const contentDocumentIsNull = frame.contentDocument === null;
      let threwOnAccess = false;
      try {
        // `contentWindow` itself is always reachable (a `WindowProxy`, never blocked by SOP),
        // but reading `.document` off a genuinely cross-origin one throws a `SecurityError` per
        // the HTML spec's cross-origin window-proxy restrictions.
        void frame.contentWindow?.document;
      } catch {
        threwOnAccess = true;
      }
      return { frameMissing: false, contentDocumentIsNull, threwOnAccess };
    });
    expect(result.frameMissing).toBe(false);
    expect(result.contentDocumentIsNull).toBe(true);
    expect(result.threwOnAccess).toBe(true);
    await visit.close();
  } finally {
    await page.stop();
  }
});

test("KNOWN GAP (fixme): a hostile page can make the real inline-menu iframe invisible via CSS while it stays clickable (A7 overlay/clickjacking, DEF CON 33)", async ({
  context,
  extensionId,
  server,
}) => {
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "clickjackuser");
    await createLoginItem(setupPage, {
      title: "Clickjack Target",
      username: "clickjack-user@example.com",
      password: "clickjack-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "clickjackuser", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "Clickjack Target", exact: false });
    await expect(realCandidate).toBeVisible({ timeout: 15_000 });

    // The attack: `content-script.ts`'s `InlineMenu` sets `position`/`left`/`top`/`width`/
    // `height`/`border`/`zIndex` inline on the menu's own `<iframe>`, but never `opacity` — so a
    // page stylesheet rule for it, with no competing inline declaration to lose to, applies
    // uncontested (no `!important` even needed). THREAT_MODEL.md's A7 mitigation list calls for
    // checking that "the target field AND THE UI are visible and topmost (for example with
    // IntersectionObserver v2 where the browser supports it)" — only the field half is
    // implemented (`content-script.ts`'s `isVisible`/`isTopmost`, run on the FIELD being filled,
    // never on the menu iframe itself).
    await visit.addStyleTag({ content: "iframe[data-rizzy-inline-menu] { opacity: 0; }" });
    // `addStyleTag` appends to `<head>`, a DOM mutation the content script's own
    // `MutationObserver` sees too, which can retrigger `report()` and replace the menu iframe
    // with a fresh one. This margin (double the content script's own 250ms debounce) lets that
    // settle before this test reads anything off whichever iframe exists afterward, so the
    // element the discriminator below checks is the same one the click a few lines down targets.
    await visit.waitForTimeout(500);

    // The real candidate button's own box. Opacity never affects layout, so this is the exact
    // box a real attacker could also learn — not by reading the cross-origin iframe's own
    // content (blocked, per the previous test), but from the outer `<iframe>` element's own,
    // never-protected `getBoundingClientRect()` combined with this extension's published,
    // static inline-menu CSS (open source) to place a decoy over the first row.
    const box = await realCandidate.boundingBox();
    if (box === null) {
      throw new Error("adversarial test setup: could not read the real candidate's bounding box");
    }

    // The discriminator: without this, a bug that made `addStyleTag` a no-op (wrong selector,
    // CSP blocking the injected `<style>`, the frame already gone) would leave the menu fully
    // visible, and the fill a few lines down would just be the ordinary happy path
    // (`autofill-and-save.spec.ts`'s own "a trusted click fills" test) — not evidence of
    // anything. Reading `getComputedStyle` of the SAME outer `<iframe>` element the box above
    // came from (not merely "an iframe matching this selector exists somewhere") pins that the
    // element about to be clicked is genuinely the hidden one, not a fresh, visible replacement.
    const opacity = await visit.locator("iframe[data-rizzy-inline-menu]").evaluate((el) => getComputedStyle(el).opacity);
    expect(opacity).toBe("0");

    // A decoy, visually in the clear now that the real iframe is invisible, sitting exactly
    // where the real candidate renders. Its own `z-index` can never beat the iframe's fixed
    // `2147483647` (the maximum possible value), so it never receives the click itself — the
    // point is that the user, seeing only this decoy, has no way to know their click actually
    // lands on the real, invisible button underneath it.
    await visit.evaluate((rect) => {
      const decoy = document.createElement("div");
      decoy.id = "decoy";
      decoy.textContent = "Free prize — click to claim!";
      decoy.style.position = "fixed";
      decoy.style.left = `${rect.x}px`;
      decoy.style.top = `${rect.y}px`;
      decoy.style.width = `${rect.width}px`;
      decoy.style.height = `${rect.height}px`;
      decoy.style.background = "#eee";
      decoy.style.border = "1px solid #999";
      document.body.appendChild(decoy);
    }, box);

    // A real, OS-level, trusted mouse click at the decoy's own location — not a Playwright
    // locator click, which resolves through the accessibility tree and would "see through" the
    // `opacity: 0` regardless of what is actually painted. `page.mouse.click` is the faithful
    // "the user clicks where they see the decoy" gesture: dispatched via real input events, so
    // the browser marks it `isTrusted: true` exactly like an actual click.
    await visit.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    // No fixed wait proves a negative with certainty, but this gives an async fill ample time to
    // land before the check below.
    await visit.waitForTimeout(1000);

    const passValue = await visit.locator("#pass").inputValue();
    if (passValue !== "") {
      // Per CLAUDE.md and this task: a test that finds a real violation is never weakened. This
      // marks the test `fixme` with exactly what broke it, rather than relaxing the assertion
      // below to match the (wrong) observed behaviour.
      test.fixme(
        true,
        "A7/THREAT_MODEL.md mitigation gap: content-script.ts's InlineMenu never sets `opacity` " +
          "inline on the menu iframe (only position/size/border/zIndex), so a page stylesheet " +
          "rule can hide it while it stays fully clickable — its fixed zIndex (2147483647, the " +
          "maximum) keeps it the hit-test target at that screen location regardless of what the " +
          "page paints underneath. A trusted click at a decoy's location lands on the real, " +
          "invisible candidate button and fills the real credential into the page. Needs a " +
          "visibility check on the inline-menu iframe itself (e.g. IntersectionObserver v2, as " +
          "THREAT_MODEL.md's A7 mitigation list already names) before dispatching a fill, not " +
          "only on the target field (`isVisible`/`isTopmost` in content-script.ts today). Found " +
          "and reported by HANDOFF gap X3's adversarial e2e suite; not fixed here (tests only).",
      );
    }
    expect(passValue).toBe("");
    await visit.close();
  } finally {
    await page.stop();
  }
});
