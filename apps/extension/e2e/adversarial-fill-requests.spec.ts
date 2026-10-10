// SPDX-License-Identifier: AGPL-3.0-only

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
//    forgeable) cannot reveal a credential even for a REAL, currently-valid `itemId` (just one
//    saved for a different host) that a real, trusted Playwright click picks — because
//    `handleInlineMenuFillRequest` (ADR 0040 point 3) re-derives the real candidate list from
//    the tab's own browser-vouched URL and refuses an `itemId` that is not genuinely a member of
//    it, independent of whatever the iframe's own DOM was tricked into rendering. A merely
//    fabricated, nonexistent `itemId` would not exercise that check at all (it would be refused
//    by `revealCredentialsForFill` finding nothing either way), so this uses a real one.
// 3. The embedding page has no same-origin access to the real menu's document at all
//    (`content-script.ts`'s own module doc on `InlineMenu`) — confirms the cross-origin
//    isolation every other "page cannot script the menu" guarantee in this file and
//    `adversarial-pages.spec.ts` relies on.
// 4. A7's "overlay/clickjacking" scenario (THREAT_MODEL.md, citing DEF CON 33; HANDOFF X6): a
//    page stylesheet rule that makes the real inline-menu iframe invisible while it stays fully
//    clickable no longer fills, because `content-script.ts`'s `InlineMenu` now runs its own
//    visibility/topmost gates (`menu-visibility.ts`) on the iframe itself, not only on the
//    target field. The classes after it (opacity, filter, clip-path, mask, transform,
//    content-visibility, mix-blend-mode, a forced `!important` size, the top layer, and the
//    flip-visible-for-the-click timing race) extend the same coverage to every attack class the
//    gates are meant to catch, plus two tests that confirm the gates do NOT over-refuse
//    (same-z-index/later-DOM-order decoy; a scrolled/zoomed page).
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

// This needs a REAL, currently-valid `itemId` to forge with, not a merely fabricated string:
// `handleInlineMenuFillRequest` re-derives the real candidate list from the attacker page's own
// browser-vouched URL and looks `itemId` up in THAT list (`content-handler.ts`'s
// `selectFillCandidate`) — a nonexistent id would be refused by that lookup regardless of
// whether the lookup itself (the actual fix) exists at all, since `revealCredentialsForFill`
// would find nothing for it either way. A real item saved for a DIFFERENT host than the attacker
// page gives the forged message something real to try to steal: if the membership check were
// ever deleted, `revealCredentialsForFill` would happily return that other item's real
// credentials for its real `itemId`, and this test would catch that. `localhost` vs `127.0.0.1`
// (one server, two host strings) is the same look-alike-host pair `startLoginPageServer`'s own
// doc relies on, and `autofill-and-save.spec.ts` already establishes that `rizzy-match` treats
// them as genuinely different, unrelated hosts (no equivalence between them).
test("a forged postMessage directly into the real inline-menu iframe cannot reveal a credential, even for a real trusted click", async ({
  context,
  extensionId,
  server,
}) => {
  test.setTimeout(180_000);
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "forgeduser");
    await createLoginItem(setupPage, {
      title: "Other Host Item",
      username: "otherhost-user@example.com",
      password: "otherhost-target-password",
      websiteUrl: `http://localhost:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "forgeduser", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    // Learn that item's real `itemId` the same way the top-level page already legitimately can:
    // `inline-menu/protocol.ts`'s own module doc on `InlineMenuPickMessage` — every real pick
    // posts `{ type: "rizzy-inline-menu-pick", itemId }` straight to `window.parent` for UI
    // teardown, and `content-script.ts`'s own `#onMessage` listens for exactly this on `window`
    // itself (the same object this page's own scripts share — isolated worlds notwithstanding).
    // Nothing stops a listener this test adds to that same `window` from seeing it too. This is
    // not a new disclosure invented for this test; it is the one channel a page already has
    // today on a real pick, used here only to obtain a real id to forge with — never to assert
    // anything about the disclosure itself. `addInitScript` (not a post-navigation `evaluate`)
    // installs the listener before any page script runs, so there is no race with the real pick.
    const legitVisit = await context.newPage();
    await legitVisit.addInitScript(() => {
      window.addEventListener("message", (event) => {
        const data = event.data as { readonly type?: unknown; readonly itemId?: unknown };
        if (data?.type === "rizzy-inline-menu-pick" && typeof data.itemId === "string") {
          (window as unknown as { __rizzyRealItemId?: string }).__rizzyRealItemId = data.itemId;
        }
      });
    });
    await legitVisit.goto(`http://localhost:${page.port}/`);
    const legitMenu = legitVisit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = legitMenu.getByRole("button", { name: "Other Host Item", exact: false });
    await expect(realCandidate).toBeVisible({ timeout: 15_000 });
    await realCandidate.click();
    // The positive control this test needs: a real trusted click on a real candidate really
    // fills, so the refusal asserted below, on the forged candidate, is evidence of the
    // membership check specifically, not of fill being broken entirely.
    await expect(legitVisit.locator("#pass")).toHaveValue("otherhost-target-password", { timeout: 15_000 });
    const realItemId = await legitVisit.evaluate(() => (window as unknown as { __rizzyRealItemId?: string }).__rizzyRealItemId);
    if (typeof realItemId !== "string" || realItemId === "") {
      throw new Error("adversarial test setup: did not capture a real itemId from the legitimate pick");
    }
    await legitVisit.close();

    const visit = await context.newPage();
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    // The real content script creates the real iframe the moment it detects the password field
    // (no item is saved for `127.0.0.1`, so its own, honest `rizzy-inline-menu-show` carries
    // zero candidates — only the generator button). This test's forged message is sent AFTER
    // that, straight to the same real iframe element, exactly as `protocol.ts`'s own module doc
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
    }, realItemId);

    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const forgedButton = menu.getByRole("button", { name: "Fake PayPal", exact: false });
    await expect(forgedButton).toBeVisible({ timeout: 15_000 });
    // A real, OS-level, trusted Playwright click — not a page-script-synthesized one. The
    // defence this test exists to prove is NOT "untrusted clicks are ignored" (that's
    // `extension.spec.ts`'s own test); it is that a real trusted click on a row the real iframe
    // was merely tricked into *rendering* still cannot reveal anything — even when the claimed
    // `itemId` is a REAL, currently-valid one for a real item (just saved for a different host)
    // — because the background re-derives the real candidate list itself from the attacker
    // page's own URL, and `realItemId` is never a member of it.
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

test("a hostile page cannot fill by making the real inline-menu iframe invisible via CSS while it stays clickable (A7 overlay/clickjacking, DEF CON 33)", async ({
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

    // Fixed (A7/THREAT_MODEL.md gap, HANDOFF X6): `content-script.ts`'s `InlineMenu` now runs
    // Gate A (a continuous rAF loop sampling the frame's real geometry/style/top-layer/hit-test
    // state and toggling its own `pointer-events`) and Gate B (the authoritative,
    // causally-after-click refusal at `apply_fill` arrival, `menu-visibility.ts`'s own module
    // doc). The page here hid the iframe BEFORE the click and never un-hides it, so every Gate-A
    // tick from construction onward is a bad sample; by the time the real click → background →
    // decrypt → push round trip completes, Gate B's trailing-window check sees a recent bad
    // sample and refuses.
    const passValue = await visit.locator("#pass").inputValue();
    expect(passValue).toBe("");
    await visit.close();
  } finally {
    await page.stop();
  }
});

// Mandatory positive control (the task's own requirement, not written by any of the three input
// designs): a real `page.mouse.click` — the same OS-level, hit-tested input path Gate A's
// `pointer-events` toggle and Gate B's `apply_fill`-arrival check both sit in front of, not a
// Playwright locator click (whose own actionability auto-waiting already tolerates a brief
// `pointer-events: none`, so it would not catch "the gate never opens" or "the window check
// always refuses" regressions the way this does).
test("a normal, visible menu still fills via a real page.mouse.click at the real candidate's own screen coordinates (mandatory positive control)", async ({
  context,
  extensionId,
  server,
}) => {
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "mouseclickuser");
    await createLoginItem(setupPage, {
      title: "Mouse Click Target",
      username: "mouseclick-user@example.com",
      password: "mouseclick-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "mouseclickuser", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "Mouse Click Target", exact: false });
    await expect(realCandidate).toBeVisible({ timeout: 15_000 });
    const box = await realCandidate.boundingBox();
    if (box === null) {
      throw new Error("adversarial test setup: could not read the real candidate's bounding box");
    }
    // A short, realistic margin: Gate B refuses a click that lands before the menu's OWN Gate-A
    // rAF loop has ever recorded one real good sample (`menu-visibility.ts`'s own doc — this is
    // deliberate, fail-closed-on-no-history behaviour, not a bug: "a menu clicked before its
    // very first real sample is correctly refused"). A real human always takes well over one
    // animation frame (~16ms) to perceive a freshly rendered menu and click it; Playwright's
    // own `page.mouse.click`, run the instant `toBeVisible()` resolves, can race ahead of that
    // first tick purely as a test artifact. Found and confirmed empirically: this exact test
    // flaked once in a full-suite run with no margin here, immediately after 10 other tests,
    // and passed reliably once this margin was added.
    await visit.waitForTimeout(150);
    await visit.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    await expect(visit.locator("#user")).toHaveValue("mouseclick-user@example.com", { timeout: 15_000 });
    await expect(visit.locator("#pass")).toHaveValue("mouseclick-target-password", { timeout: 15_000 });
    await visit.close();
  } finally {
    await page.stop();
  }
});

/** Sets or clears one inline style property on the real inline-menu iframe's OWN element, via
 * `page.evaluate` (never `addStyleTag`): a `<style>` tag is a `childList` mutation under
 * `document.documentElement`, which the content script's own `MutationObserver` sees and can
 * use to retrigger `report()`, destroying and recreating the `InlineMenu` instance — a fresh
 * instance would compute its own frozen expected rect AFTER the tamper took effect, which would
 * make an ancestor-displacement attack self-heal instead of being caught (see this file's own
 * git history / the task's investigation for why). An inline style write on an existing element
 * is an `attributes` mutation, which this codebase's observer never watches at all (`childList`/
 * `subtree` only), so it never triggers a rebuild — exactly what is needed to test Gate A/B
 * against the SAME, already-constructed `InlineMenu` instance the attack is supposed to defeat. */
async function setIframeStyle(page: Page, prop: string, value: string, important = false): Promise<void> {
  await page.evaluate(
    ([p, v, imp]) => {
      const el = document.querySelector("iframe[data-rizzy-inline-menu]") as HTMLElement | null;
      el?.style.setProperty(p, v, imp ? "important" : "");
    },
    [prop, value, important] as const,
  );
}

async function clearIframeStyle(page: Page, prop: string): Promise<void> {
  await page.evaluate((p) => {
    const el = document.querySelector("iframe[data-rizzy-inline-menu]") as HTMLElement | null;
    el?.style.removeProperty(p);
  }, prop);
}

// Consolidated into one test, one enrolment, one page (deviation from the spec's "one new
// adversarial page per attack class," stated per CLAUDE.md "deviate only with a stated reason"):
// each of these classes shares identical setup (a real signup, a real saved candidate, a real
// `page.mouse.click`, asserting `#user`/`#pass` stay empty) and differs only in which single CSS
// property is tampered with — running each as its own full signup+enrol+sync e2e test (the
// existing tests in this file each take 5-10+ seconds) would multiply this file's runtime by the
// number of classes for no additional coverage, since the gates under test
// (`menu-visibility.ts`'s `isVisibilityChainOk`/`rectsMatch`) are the exact same code path for
// every one of them; only the input values differ, which the unit tests
// (`test/menu-visibility.test.ts`) already exercise directly and exhaustively. This e2e test's
// job is only to confirm the WIRING (`content-script.ts`'s `InlineMenu`) actually reads real
// computed styles/geometry into those functions correctly, end to end, for each class the task
// names.
test("the same real candidate is never filled through filter, clip-path, mask, content-visibility, mix-blend-mode, transform (on the iframe and on an ancestor), or a forced !important size", async ({
  context,
  extensionId,
  server,
}) => {
  test.setTimeout(120_000);
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "csstamperuser");
    await createLoginItem(setupPage, {
      title: "CSS Tamper Target",
      username: "csstamper-user@example.com",
      password: "csstamper-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "csstamperuser", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "CSS Tamper Target", exact: false });
    await expect(realCandidate).toBeVisible({ timeout: 15_000 });
    const box = await realCandidate.boundingBox();
    if (box === null) {
      throw new Error("adversarial test setup: could not read the real candidate's bounding box");
    }
    const center = { x: box.x + box.width / 2, y: box.y + box.height / 2 };

    async function assertStillRefused(clickAt: { readonly x: number; readonly y: number }): Promise<void> {
      // A short margin BEFORE the click, not just after: Gate A only ever learns about a tamper
      // on its own next rAF tick (at most one real animation frame after the style write that
      // precedes this call), and `menu-visibility.ts`'s own Gate-B doc deliberately allows a
      // fill with no startup dwell when NO bad sample has EVER been recorded — correct for a
      // never-tampered menu, but it means a tamper applied and clicked in the exact same instant,
      // with zero observation window, has no history for Gate B to refuse on yet. A real
      // clickjacking page needs the hidden state to persist for at least one rendered frame to
      // have any visual effect in the first place, so this margin matches a realistic attack, not
      // merely a convenient one; found and documented empirically running this test against the
      // real build (first without this margin, which flaked exactly once in a full-suite run).
      await visit.waitForTimeout(150);
      await visit.mouse.click(clickAt.x, clickAt.y);
      await visit.waitForTimeout(600);
      await expect(visit.locator("#user")).toHaveValue("");
      await expect(visit.locator("#pass")).toHaveValue("");
    }

    // 1. filter (e.g. `filter: opacity(0)`): visually identical to the `opacity` property, same
    // box, same click location.
    await setIframeStyle(visit, "filter", "opacity(0)");
    await assertStillRefused(center);
    await clearIframeStyle(visit, "filter");

    // 2. clip-path: clips the whole box away without changing `getBoundingClientRect()`.
    await setIframeStyle(visit, "clip-path", "circle(0px at 0 0)");
    await assertStillRefused(center);
    await clearIframeStyle(visit, "clip-path");

    // 3. mask-image: a fully-transparent mask, same box.
    await setIframeStyle(visit, "mask-image", "linear-gradient(transparent, transparent)");
    await assertStillRefused(center);
    await clearIframeStyle(visit, "mask-image");

    // 4. content-visibility: hidden — skips rendering the iframe's embedded document without
    // collapsing the iframe ELEMENT's own box.
    await setIframeStyle(visit, "content-visibility", "hidden");
    await assertStillRefused(center);
    await clearIframeStyle(visit, "content-visibility");

    // 5. mix-blend-mode: blends the iframe into a same-color background, same box.
    await setIframeStyle(visit, "mix-blend-mode", "multiply");
    await assertStillRefused(center);
    await clearIframeStyle(visit, "mix-blend-mode");

    // 6. transform: scale(0) on the iframe itself — shrinks the box to nothing, centred on the
    // same point (scaling around the default transform-origin, the box's own centre, never
    // moves that centre), so the real candidate's own centre is still the right place to probe.
    await setIframeStyle(visit, "transform", "scale(0)");
    await assertStillRefused(center);
    await clearIframeStyle(visit, "transform");

    // 7. An ancestor transform (on `body`, not the iframe) that displaces the iframe from its
    // frozen expected rect — a MODEST on-screen displacement (not an off-screen translate, which
    // would just make the click miss the iframe entirely for the boring reason that it is no
    // longer there; this is the interesting case, where the iframe is still fully opaque and
    // sitting somewhere else on screen). `setIframeStyle`'s own doc explains why this uses an
    // inline style write (`page.evaluate`), not `addStyleTag`, specifically so the EXISTING
    // `InlineMenu` instance (with its own already-frozen expected rect) is what gets tested,
    // not a freshly reconstructed one whose own fresh rect would already account for the
    // transform and therefore never disagree with it.
    await visit.evaluate(() => {
      document.body.style.setProperty("transform", "translate(60px, 40px)");
    });
    await assertStillRefused({ x: center.x + 60, y: center.y + 40 });
    await visit.evaluate(() => {
      document.body.style.removeProperty("transform");
    });

    // 8. A forced tiny size via an author `!important` rule — should already be blocked by Gate
    // A's default `pointer-events: none` plus the geometry check (a useful cascade-assumption
    // regression test: confirms our OWN `!important` declarations still win where they need to,
    // and that a size mismatch alone is sufficient to refuse). `left`/`top` are unchanged by a
    // width/height-only override, so the forced 1×1 box sits at the real candidate's own
    // top-left corner, not its centre.
    await setIframeStyle(visit, "width", "1px", true);
    await setIframeStyle(visit, "height", "1px", true);
    await assertStillRefused({ x: box.x + 1, y: box.y + 1 });
    await clearIframeStyle(visit, "width");
    await clearIframeStyle(visit, "height");

    await visit.close();
  } finally {
    await page.stop();
  }
});

// Top-layer occlusion (A7/THREAT_MODEL gap, HANDOFF X6): `document.fullscreenElement`,
// `dialog[open]` and `:popover-open` elements render above EVERY z-index by spec, including the
// menu iframe's own maximum (`2147483647`) — the one occlusion class ordinary DOM stacking can
// never produce. A modal `<dialog>` also makes the browser itself refuse to route a click to
// anything underneath it (including the menu), so the discriminator here is
// `getComputedStyle(iframe).pointerEvents` (Gate A's own, page-observable toggle — the accepted
// consequence named in this change's commit message) rather than relying on the click outcome
// alone, which would otherwise prove only "a modal dialog blocks clicks," a browser fact true
// with or without this change.
test("a <dialog> and an open popover covering the menu's rect make Gate A refuse it (top-layer occlusion)", async ({ context, extensionId, server }) => {
  test.setTimeout(60_000);
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "toplayeruser");
    await createLoginItem(setupPage, {
      title: "Top Layer Target",
      username: "toplayer-user@example.com",
      password: "toplayer-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "toplayeruser", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "Top Layer Target", exact: false });
    await expect(realCandidate).toBeVisible({ timeout: 15_000 });

    const pointerEventsIsNone = () => visit.locator("iframe[data-rizzy-inline-menu]").evaluate((el) => getComputedStyle(el).pointerEvents === "none");

    // Baseline: a genuinely untampered, visible menu reaches `pointer-events: auto` within a
    // frame or two of Gate A's own rAF loop.
    await expect.poll(pointerEventsIsNone, { timeout: 5_000 }).toBe(false);

    const box = await realCandidate.boundingBox();
    if (box === null) {
      throw new Error("adversarial test setup: could not read the real candidate's bounding box");
    }

    // 1. A modal <dialog> covering the menu's own rect.
    await visit.evaluate((rect) => {
      const dialog = document.createElement("dialog");
      dialog.id = "rizzy-test-dialog";
      dialog.style.position = "fixed";
      dialog.style.left = `${rect.x}px`;
      dialog.style.top = `${rect.y}px`;
      dialog.style.width = `${rect.width}px`;
      dialog.style.height = `${rect.height}px`;
      dialog.style.margin = "0";
      document.body.appendChild(dialog);
      dialog.showModal();
    }, box);
    await expect.poll(pointerEventsIsNone, { timeout: 5_000 }).toBe(true);
    await visit.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    await visit.waitForTimeout(500);
    await expect(visit.locator("#user")).toHaveValue("");
    await expect(visit.locator("#pass")).toHaveValue("");
    await visit.evaluate(() => {
      const dialog = document.getElementById("rizzy-test-dialog") as HTMLDialogElement | null;
      dialog?.close();
      dialog?.remove();
    });
    // Recovers once the dialog is gone — Gate A is continuous, not a one-shot latch.
    await expect.poll(pointerEventsIsNone, { timeout: 5_000 }).toBe(false);

    // 2. An open popover covering the same rect.
    await visit.evaluate((rect) => {
      const popover = document.createElement("div");
      popover.id = "rizzy-test-popover";
      popover.setAttribute("popover", "manual");
      popover.style.position = "fixed";
      popover.style.left = `${rect.x}px`;
      popover.style.top = `${rect.y}px`;
      popover.style.width = `${rect.width}px`;
      popover.style.height = `${rect.height}px`;
      popover.style.margin = "0";
      document.body.appendChild(popover);
      (popover as HTMLElement & { showPopover?: () => void }).showPopover?.();
    }, box);
    await expect.poll(pointerEventsIsNone, { timeout: 5_000 }).toBe(true);
    await visit.evaluate(() => {
      const popover = document.getElementById("rizzy-test-popover") as (HTMLElement & { hidePopover?: () => void }) | null;
      popover?.hidePopover?.();
      popover?.remove();
    });
    await expect.poll(pointerEventsIsNone, { timeout: 5_000 }).toBe(false);

    await visit.close();
  } finally {
    await page.stop();
  }
});

// Regression check (named explicitly, per the task): a decoy sharing the menu iframe's OWN
// maximum z-index, inserted later in DOM order, should already fail to intercept the click or
// break the fill WITHOUT any of the new gates — ordinary DOM stacking already closes this class
// (the existing, pre-this-change `zIndex: 2147483647` is the maximum value the property can
// hold, so nothing in normal stacking can render above it regardless of DOM order; a decoy at
// the SAME value does not out-rank it as a HIGHER value would need to). Confirms the new gates
// introduce no regression here: the real fill still lands normally.
test("a same-z-index, later-DOM-order decoy does not intercept the real click or break the fill (no-regression check)", async ({
  context,
  extensionId,
  server,
}) => {
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "samezindexuser");
    await createLoginItem(setupPage, {
      title: "Same Z-Index Target",
      username: "samez-user@example.com",
      password: "samez-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "samezindexuser", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "Same Z-Index Target", exact: false });
    await expect(realCandidate).toBeVisible({ timeout: 15_000 });
    const box = await realCandidate.boundingBox();
    if (box === null) {
      throw new Error("adversarial test setup: could not read the real candidate's bounding box");
    }

    await visit.evaluate((rect) => {
      const decoy = document.createElement("div");
      decoy.id = "rizzy-test-same-z-decoy";
      decoy.textContent = "Decoy — same z-index, later in the DOM";
      decoy.style.position = "fixed";
      decoy.style.left = `${rect.x}px`;
      decoy.style.top = `${rect.y}px`;
      decoy.style.width = `${rect.width}px`;
      decoy.style.height = `${rect.height}px`;
      decoy.style.zIndex = "2147483647";
      decoy.style.background = "rgba(255, 0, 0, 0.1)";
      // Inserted AFTER the iframe, which is already in the DOM by the time this runs.
      document.body.appendChild(decoy);
    }, box);
    // Appending the decoy is itself a `childList` mutation under `document.documentElement`,
    // which the content script's own `MutationObserver` sees and can use to retrigger
    // `report()`, rebuilding the `InlineMenu` instance (`setIframeStyle`'s own doc covers this
    // same mechanism). A freshly rebuilt instance needs at least one Gate-A tick to record its
    // own first good sample before Gate B allows a fill — this margin (the same one the existing
    // clickjacking test already uses after its own `addStyleTag`) lets that settle first, so this
    // test exercises the decoy/z-index question, not an unrelated rebuild race.
    await visit.waitForTimeout(500);

    await visit.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    await expect(visit.locator("#user")).toHaveValue("samez-user@example.com", { timeout: 15_000 });
    await expect(visit.locator("#pass")).toHaveValue("samez-target-password", { timeout: 15_000 });
    await visit.close();
  } finally {
    await page.stop();
  }
});

// False-refusal test (named explicitly, per the task): an ordinary scrolled and zoomed page must
// still fill normally. The frame is always `position: fixed`, and its frozen expected rect
// (`menu-visibility.ts`'s `computeExpectedRect`) is computed from the anchor's rect AT
// CONSTRUCTION TIME in viewport (not document) coordinates — ordinary scrolling never changes a
// `position: fixed` element's `getBoundingClientRect()`, so this must not be refused.
// Deviation (CLAUDE.md "deviate only with a stated reason"): the task's own list also names
// "zoomed." CSS `zoom` is a non-standard Blink/WebKit property whose effect on the coordinate
// space `page.mouse.click`/`getBoundingClientRect()` agree on in headless Chromium turned out,
// empirically, to need more investigation than this task's own scroll-invariance point is worth
// — real pinch-zoom (the browser's own page-scale factor) has no simple, reliable Playwright
// control either. Scrolling is the sharper, better-defined version of this invariant anyway
// (`menu-visibility.ts`'s own doc: "ordinary page scrolling must never, by itself, cause a false
// refusal," stated as a hard requirement because the frame is always `position: fixed`), so this
// test covers scrolling only.
test("a scrolled page still fills normally (false-refusal check: scrolling must never, by itself, refuse a fill)", async ({
  context,
  extensionId,
  server,
}) => {
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "scrolluser");
    await createLoginItem(setupPage, {
      title: "Scroll Target",
      username: "scroll-user@example.com",
      password: "scroll-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "scrolluser", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "Scroll Target", exact: false });
    await expect(realCandidate).toBeVisible({ timeout: 15_000 });
    const boxBeforeScroll = await realCandidate.boundingBox();
    if (boxBeforeScroll === null) {
      throw new Error("adversarial test setup: could not read the real candidate's bounding box");
    }
    // Realistic margin before the first real click lands — same reasoning as the positive
    // control's own comment: Gate B refuses a click that arrives before the menu's Gate-A loop
    // has ever recorded one good sample.
    await visit.waitForTimeout(150);

    // Padding that makes the page scrollable, applied to the ALREADY-constructed menu (this is
    // the scenario the invariant is actually about: scrolling a page that already has a menu
    // open, not a page that happens to be pre-scrolled before the menu is ever shown). A style
    // write, not a `childList` mutation, so it does not retrigger the content script's own
    // `MutationObserver`/rebuild — no settle wait is needed.
    await visit.evaluate(() => {
      document.body.style.paddingTop = "1500px";
    });
    await visit.mouse.wheel(0, 700);

    // Re-read the box after scrolling: for a `position: fixed` element, this must be the exact
    // SAME viewport rect as before scrolling — the assertion this test is actually making.
    const boxAfterScroll = await realCandidate.boundingBox();
    if (boxAfterScroll === null) {
      throw new Error("adversarial test setup: the real candidate's iframe disappeared after scrolling");
    }
    expect(Math.abs(boxAfterScroll.x - boxBeforeScroll.x)).toBeLessThanOrEqual(1);
    expect(Math.abs(boxAfterScroll.y - boxBeforeScroll.y)).toBeLessThanOrEqual(1);

    await visit.mouse.click(boxAfterScroll.x + boxAfterScroll.width / 2, boxAfterScroll.y + boxAfterScroll.height / 2);
    await expect(visit.locator("#user")).toHaveValue("scroll-user@example.com", { timeout: 15_000 });
    await expect(visit.locator("#pass")).toHaveValue("scroll-target-password", { timeout: 15_000 });
    await visit.close();
  } finally {
    await page.stop();
  }
});

// False-refusal test, documenting the accepted trade-off rather than hiding it (the task's own
// instruction): a legitimate, unrelated ancestor CSS transition/animation running concurrently
// with a real click IS refused under this design's "only ever refuse more" mandate, because
// `isVisibilityChainOk` treats `filter`/`opacity`/`clip-path`/etc. on ANY ancestor as a binary
// fail-closed signal with no allowance for "it's just a benign page animation." This is a known,
// accepted usability cost of the design (`menu-visibility.ts`'s own module doc on why
// `will-change`/`contain` are deliberately NOT included in this same denylist — the owner's
// trade-off call stops there, not here): a page that runs a decorative fade/opacity transition
// on `body` or `html` while the menu happens to be open loses autofill for as long as the
// transition's own opacity differs from 1. Marked here, not silently matched to whatever the
// code happens to do.
test("a concurrent, unrelated ancestor CSS transition refuses the fill (known, accepted false-refusal trade-off — not a bug)", async ({
  context,
  extensionId,
  server,
}) => {
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "transitionuser");
    await createLoginItem(setupPage, {
      title: "Transition Target",
      username: "transition-user@example.com",
      password: "transition-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "transitionuser", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "Transition Target", exact: false });
    await expect(realCandidate).toBeVisible({ timeout: 15_000 });
    const box = await realCandidate.boundingBox();
    if (box === null) {
      throw new Error("adversarial test setup: could not read the real candidate's bounding box");
    }

    // A decorative, ongoing fade on `body` — nothing to do with the menu at all, and never
    // settling at `opacity: 1`, which is exactly what makes this an accepted cost rather than a
    // one-off transient the trailing window would already tolerate.
    await visit.evaluate(() => {
      const style = document.createElement("style");
      style.textContent = "@keyframes rizzy-test-fade { 0%, 100% { opacity: 0.9; } 50% { opacity: 0.8; } } body { animation: rizzy-test-fade 0.2s linear infinite; }";
      document.head.appendChild(style);
    });
    await visit.waitForTimeout(300);

    await visit.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    await visit.waitForTimeout(600);
    await expect(visit.locator("#user")).toHaveValue("");
    await expect(visit.locator("#pass")).toHaveValue("");
    await visit.close();
  } finally {
    await page.stop();
  }
});

// Best-effort timing attack (the task's own instruction: "acknowledge this one is inherently
// harder to make fully deterministic in Playwright; treat timing flakiness here as expected, not
// as a sign the mechanism is broken"). This is the one scenario that specifically exercises
// GATE B rather than Gate A alone: a page that is hidden by default, flips visible only for the
// instant of a real click, and flips back immediately after — BEFORE the real click →
// background → decrypt → `apply_fill` round trip can possibly land. Gate A's own `pointer-events`
// toggle bounds exposure during the brief visible window (so the OS click can even reach the
// button at all), but it is Gate B's causally-after-click check, at `apply_fill` arrival, that
// actually has to refuse — `menu-visibility.ts`'s own module doc on why.
test("a timed flip-visible-for-the-click, flip-back-after attack is refused (Gate B; best effort, timing-sensitive by nature)", async ({
  context,
  extensionId,
  server,
}) => {
  test.setTimeout(60_000);
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "fliptiminguser");
    await createLoginItem(setupPage, {
      title: "Flip Timing Target",
      username: "fliptiming-user@example.com",
      password: "fliptiming-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "fliptiminguser", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await visit.goto(`http://127.0.0.1:${page.port}/`);

    // A toggleable stylesheet (`disabled`, never added/removed again after this) — toggling
    // `disabled` is neither a `childList` nor an `attributes` mutation under the elements the
    // content script's own `MutationObserver` watches, so it never retriggers a rebuild, which
    // would otherwise reset Gate A/B's own accumulated history on every flip and make this test
    // measure the rebuild race instead of the timing attack it is meant to.
    await visit.evaluate(() => {
      const style = document.createElement("style");
      style.id = "rizzy-test-flip-style";
      style.textContent = "iframe[data-rizzy-inline-menu] { opacity: 0; }";
      document.head.appendChild(style);
      style.disabled = false; // enabled: hidden from the very start
    });

    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "Flip Timing Target", exact: false });
    // Hidden by design: `toBeVisible()` would never resolve here. Only existence is needed.
    await realCandidate.waitFor({ state: "attached", timeout: 15_000 });
    const box = await realCandidate.boundingBox();
    if (box === null) {
      throw new Error("adversarial test setup: could not read the real candidate's bounding box");
    }

    const styleHandle = await visit.evaluateHandle(() => document.getElementById("rizzy-test-flip-style") as HTMLStyleElement);
    // Un-hide: a window generous enough for a real OS click to land and for Gate A's own rAF
    // loop to have sampled at least one real good tick within it (both need at least one real
    // animation frame after this).
    await styleHandle.evaluate((el) => {
      el.disabled = true;
    });
    await visit.waitForTimeout(120);
    await visit.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    // Re-hide immediately after the click — well before the real click → background → decrypt →
    // `apply_fill` round trip can possibly land. The attacker must do this to keep deceiving the
    // user; it is also exactly what lets Gate B's trailing-window check see a fresh bad sample by
    // the time `apply_fill` arrives, regardless of how short the visible flip was.
    await styleHandle.evaluate((el) => {
      el.disabled = false;
    });

    await visit.waitForTimeout(1500);
    await expect(visit.locator("#user")).toHaveValue("");
    await expect(visit.locator("#pass")).toHaveValue("");
    await visit.close();
  } finally {
    await page.stop();
  }
});

// Adversarial-report coverage (owner-reported bypasses against this change's own clickjacking
// mitigation; not yet owner-dated). Each test below reproduces-or-refutes one reported bypass
// against the REAL extension, per this file's own standing methodology (a real device, a real
// click, never a fabricated candidate list). Two bypasses reproduced nothing; one fix (the
// `isFillAllowed` recency requirement in `menu-visibility.ts`) was still applied as defense in
// depth, independent of what any specific reported technique achieved here.

// Reported bypass (critical): an opaque, `pointer-events: none` decoy — same max z-index as the
// frame's own, appended to `document.body` the instant the iframe appears — is claimed to stay
// visually on top (deceiving the user) for the menu's ENTIRE lifetime, no race needed, because
// `pointer-events: none` excludes the decoy from hit-testing (confirmed true in isolation: a
// probe against a plain two-`<div>` page showed `elementFromPoint`/`elementsFromPoint` BOTH skip
// a `pointer-events: none` top element entirely) while the real, clickable frame sits underneath.
//
// REJECTED — does not reproduce against the real `InlineMenu`. `wireInlineMenu`
// (`content-script.ts`) unconditionally destroys and recreates the menu on ANY DOM mutation its
// own `MutationObserver` does not recognise as its own overlay — and the decoy's insertion IS
// such a mutation. The rebuilt iframe is a BRAND NEW element, freshly `appendChild`-ed to the
// then-current end of `document.body`, which places it AFTER the already-inserted decoy in DOM
// order — winning the z-index tie the decoy was counting on, and rendering the REAL menu visibly
// on top, not hidden at all. The diagnostic below confirms this directly: the decoy ends up
// BEFORE the frame in document order, the frame's own `pointer-events` stays `auto`, and
// `elementFromPoint` at the menu's centre returns the real `<iframe>` — so the real click fills
// the REAL, user-visible candidate, exactly the happy path, not a bypass.
test("a one-shot opaque pointer-events:none decoy tying the frame's z-index does not reproduce (reported bypass, critical — rejected: the rebuild-on-mutation cycle re-wins the DOM-order tie)", async ({
  context,
  extensionId,
  server,
}) => {
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "bypassdecoy1");
    await createLoginItem(setupPage, {
      title: "Decoy Bypass Target",
      username: "decoybypass-user@example.com",
      password: "decoybypass-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "bypassdecoy1", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await visit.goto(`http://127.0.0.1:${page.port}/`);

    // The reported attack, verbatim in structure: react to the iframe's FIRST appearance only
    // (`obs.disconnect()`), cover it once with an opaque, `pointer-events: none`,
    // same-max-z-index decoy, and never touch the DOM again.
    await visit.evaluate(() => {
      function coverMenu(frame: HTMLIFrameElement) {
        const r = frame.getBoundingClientRect();
        const decoy = document.createElement("div");
        decoy.id = "rizzy-test-decoy";
        decoy.textContent = "Subscribe to our newsletter";
        Object.assign(decoy.style, {
          position: "fixed",
          left: `${r.left}px`,
          top: `${r.top}px`,
          width: `${r.width}px`,
          height: `${r.height}px`,
          zIndex: "2147483647",
          background: "#fff",
          pointerEvents: "none",
        });
        document.body.appendChild(decoy);
      }
      new MutationObserver((_records, obs) => {
        const f = document.querySelector<HTMLIFrameElement>("iframe[data-rizzy-inline-menu]");
        if (f) {
          coverMenu(f);
          obs.disconnect();
        }
      }).observe(document.body, { childList: true });
    });

    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "Decoy Bypass Target", exact: false });
    await realCandidate.waitFor({ state: "attached", timeout: 15_000 });
    // The decoy's own insertion is a mutation the content script's own observer reacts to
    // (debounced 250ms, same margin the existing same-z-index test already uses) — let that
    // rebuild settle before reading anything.
    await visit.waitForTimeout(1500);

    // The discriminator: the rebuilt, REAL iframe ends up AFTER the decoy in document order
    // (winning the z-index tie), stays fully opaque/hittable, and is what a hit test at the
    // menu's own centre actually returns — the decoy never achieves the claimed "stays on top for
    // the entire lifetime."
    const diag = await visit.evaluate(() => {
      const frame = document.querySelector<HTMLIFrameElement>("iframe[data-rizzy-inline-menu]");
      const decoy = document.getElementById("rizzy-test-decoy");
      if (frame === null || decoy === null) {
        return { frameExists: frame !== null, decoyExists: decoy !== null } as const;
      }
      const decoyIsAfterFrame = (frame.compareDocumentPosition(decoy) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0;
      const r = frame.getBoundingClientRect();
      const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
      return {
        frameExists: true,
        decoyExists: true,
        decoyIsAfterFrame,
        frameOpacity: getComputedStyle(frame).opacity,
        framePointerEvents: getComputedStyle(frame).pointerEvents,
        hitIsFrame: hit === frame,
      } as const;
    });
    expect(diag.frameExists).toBe(true);
    expect(diag.decoyExists).toBe(true);
    expect(diag).toMatchObject({ decoyIsAfterFrame: false, frameOpacity: "1", framePointerEvents: "auto", hitIsFrame: true });

    const box = await realCandidate.boundingBox();
    if (box === null) {
      throw new Error("adversarial test setup: could not read the real candidate's bounding box");
    }
    await visit.mouse.click(box.x + box.width / 2, box.y + box.height / 2);

    // The happy path, not a bypass: the user genuinely saw and clicked the real, visible menu.
    await expect(visit.locator("#user")).toHaveValue("decoybypass-user@example.com", { timeout: 15_000 });
    await expect(visit.locator("#pass")).toHaveValue("decoybypass-target-password", { timeout: 15_000 });
    await visit.close();
  } finally {
    await page.stop();
  }
});

// The same reported bypass, strengthened against the rejection above: a decoy that reacts to
// every rebuild (not a one-shot `obs.disconnect()`), re-covering the NEW iframe each time one
// appears, specifically to keep winning the DOM-order tie forever.
//
// REJECTED for a different reason: reacting to each rebuild by re-inserting the decoy is ITSELF
// a DOM mutation the content script's own observer sees, which triggers yet another rebuild,
// which the decoy reacts to again — a perpetual oscillation (~7 rebuild cycles in 1.5s of an
// otherwise-idle page; load-sensitive, not a fixed count) that never settles. `isFillAllowed`'s
// requirement that a fill only proceeds when the CURRENTLY ACTIVE menu instance has itself
// recorded a real good sample (`menu-visibility.ts`) means a menu this unstable — constantly torn
// down and recreated by the decoy's own reaction to it — essentially never presents a stable,
// clickable instance by the time `apply_fill` arrives for whichever instance was current at click
// time.
//
// This outcome is a RACE, not a deterministic guarantee (the diagnostic in the one-shot test
// above shows moments mid-oscillation where the gates ARE fully open) — confirmed empty over 15
// runs total (`--repeat-each=5` and `--repeat-each=10`, no flakes), not assumed from one green
// run. If this ever flakes non-empty, that is a confirmed intermittent bypass, not a rejection,
// and needs re-triage, not a loosened assertion.
test("a persistently re-covering decoy also does not reproduce (reported bypass, critical — rejected: reacting to each rebuild triggers another rebuild, which never settles)", async ({
  context,
  extensionId,
  server,
}) => {
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "bypassdecoy2");
    await createLoginItem(setupPage, {
      title: "Persistent Decoy Target",
      username: "persistdecoy-user@example.com",
      password: "persistdecoy-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "bypassdecoy2", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await visit.goto(`http://127.0.0.1:${page.port}/`);

    await visit.evaluate(() => {
      (window as unknown as { __covers: number }).__covers = 0;
      let lastFrame: HTMLIFrameElement | null = null;
      function recover() {
        const frame = document.querySelector<HTMLIFrameElement>("iframe[data-rizzy-inline-menu]");
        if (frame === null || frame === lastFrame) return; // react only to a genuinely NEW/rebuilt iframe
        lastFrame = frame;
        document.getElementById("rizzy-test-decoy2")?.remove();
        const r = frame.getBoundingClientRect();
        const decoy = document.createElement("div");
        decoy.id = "rizzy-test-decoy2";
        decoy.textContent = "Subscribe to our newsletter";
        Object.assign(decoy.style, {
          position: "fixed",
          left: `${r.left}px`,
          top: `${r.top}px`,
          width: `${r.width}px`,
          height: `${r.height}px`,
          zIndex: "2147483647",
          background: "#fff",
          pointerEvents: "none",
        });
        document.body.appendChild(decoy); // always appended LAST -> always (momentarily) wins the DOM-order tie
        (window as unknown as { __covers: number }).__covers++;
      }
      new MutationObserver(() => recover()).observe(document.body, { childList: true, subtree: false });
      recover();
    });

    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "Persistent Decoy Target", exact: false });
    await realCandidate.waitFor({ state: "attached", timeout: 15_000 });
    await visit.waitForTimeout(1500);

    const covers = await visit.evaluate(() => (window as unknown as { __covers: number }).__covers);
    // The oscillation this rejection depends on actually happened, not a no-op — the exact count
    // is load-sensitive (debounce timing vs. CI machine speed), so only ">1" is asserted.
    expect(covers).toBeGreaterThan(1);

    const box = await realCandidate.boundingBox();
    if (box === null) {
      throw new Error("adversarial test setup: could not read the real candidate's bounding box");
    }
    await visit.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    await visit.waitForTimeout(1000);

    // Neither filled (the decoy never achieves a stable deceptive state) nor silently left
    // vulnerable — this is the "only ever refuse more" outcome, not the happy path.
    await expect(visit.locator("#user")).toHaveValue("");
    await expect(visit.locator("#pass")).toHaveValue("");
    await visit.close();
  } finally {
    await page.stop();
  }
});

// Reported bypass (high): Gate C (`inline-menu/main.ts`'s IntersectionObserver v2) is claimed to
// take ~9.2s/10.2s to deliver its FIRST entry for a candidate button, leaving `isHiddenByIov2`
// reading its default-unknown ("not hidden") value for the entire realistic human click-timing
// window.
//
// REJECTED on the facts: measured directly against a REAL candidate button inside the REAL
// cross-origin inline-menu iframe (the exact architecture Gate C runs in — `observe()` called
// from inside that document, not a synthetic top-level page), the first entry arrives in
// single-digit-to-low-double-digit milliseconds, not seconds. The assertion below uses a bound
// three orders of magnitude below the reported figure, with generous margin for CI variance.
test("Gate C's IntersectionObserver v2 first entry arrives in milliseconds, not ~9-10s (reported bypass, high — rejected on the facts)", async ({
  context,
  extensionId,
  server,
}) => {
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "bypassiov2lat");
    await createLoginItem(setupPage, {
      title: "Iov2 Latency Target",
      username: "iov2lat-user@example.com",
      password: "iov2lat-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "bypassiov2lat", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "Iov2 Latency Target", exact: false });
    await expect(realCandidate).toBeVisible({ timeout: 15_000 });

    const inlineMenuFrame = visit.frames().find((f) => f.url().includes("inline-menu"));
    if (inlineMenuFrame === undefined) {
      throw new Error("adversarial test setup: could not find the inline-menu frame");
    }
    const iov2Latency = await inlineMenuFrame.evaluate(async () => {
      const supported = typeof IntersectionObserver !== "undefined" && typeof IntersectionObserverEntry !== "undefined" && "isVisible" in IntersectionObserverEntry.prototype;
      if (!supported) {
        return { supported: false, latencyMs: null };
      }
      const btn = document.querySelector("button");
      if (btn === null) {
        return { supported: true, latencyMs: null };
      }
      return await new Promise<{ supported: true; latencyMs: number }>((resolve) => {
        const observeAt = performance.now();
        const obs = new IntersectionObserver(
          (entries) => {
            const [entry] = entries;
            if (entry !== undefined) {
              resolve({ supported: true, latencyMs: performance.now() - observeAt });
              obs.disconnect();
            }
          },
          { threshold: [0, 1], trackVisibility: true, delay: 100 } as IntersectionObserverInit,
        );
        obs.observe(btn);
      });
    });
    // Chromium-only mechanism (Gate C is additive, defense-in-depth): skip the latency assertion
    // where IOv2 is unsupported, rather than fail a bound that has nothing to measure.
    if (iov2Latency.supported) {
      expect(iov2Latency.latencyMs).not.toBeNull();
      // Three orders of magnitude below the reported ~9,200-10,200ms, generous for CI variance.
      expect(iov2Latency.latencyMs as number).toBeLessThan(2000);
    }
    await visit.close();
  } finally {
    await page.stop();
  }
});

// Reported bypass's own activation mechanism: one variant triggers its main-thread stall from a
// `focus` event listener added directly to the `<iframe>` ELEMENT in the PARENT document,
// reasoning that focus moving into the cross-origin child document dispatches `focus` on that
// outer element — a same-origin, zero-privilege signal needing no access into the iframe's own
// document.
//
// REJECTED: that event does not fire here. A real trusted click that moves focus into the real
// cross-origin inline-menu iframe's own document does not dispatch `focus` on the parent's
// `<iframe>` element reference in this architecture, so this specific trigger never runs at all —
// independent grounds from the main-thread-stall test below.
test("a trusted click into the real iframe does not dispatch focus on the parent's iframe element (reported bypass's own trigger — does not fire)", async ({
  context,
  extensionId,
  server,
}) => {
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "bypassfocus");
    await createLoginItem(setupPage, {
      title: "Focus Trigger Target",
      username: "focustrigger-user@example.com",
      password: "focustrigger-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "bypassfocus", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "Focus Trigger Target", exact: false });
    await expect(realCandidate).toBeVisible({ timeout: 15_000 });

    await visit.evaluate(() => {
      (window as unknown as { __focusFired: boolean }).__focusFired = false;
      document.querySelector<HTMLIFrameElement>("iframe[data-rizzy-inline-menu]")?.addEventListener("focus", () => {
        (window as unknown as { __focusFired: boolean }).__focusFired = true;
      });
    });

    const box = await realCandidate.boundingBox();
    if (box === null) {
      throw new Error("adversarial test setup: could not read the real candidate's bounding box");
    }
    await visit.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    await visit.waitForTimeout(500);

    const focusFired = await visit.evaluate(() => (window as unknown as { __focusFired: boolean }).__focusFired);
    expect(focusFired).toBe(false);
    await visit.close();
  } finally {
    await page.stop();
  }
});

// Reported bypass (critical/high): hide the real frame itself (`opacity: 0 !important`, the
// already-fixed fixme reproducer's own technique) and, at the same moment, stall the page's main
// thread for longer than `apply_fill`'s round trip, so Gate A's `requestAnimationFrame` sampler
// never records the resulting bad sample before `apply_fill` arrives. Both reports chose a
// CHOPPED technique (repeated short synchronous bursts plus `setTimeout(fn, 0)` yields)
// specifically to avoid visibly freezing the page.
//
// REJECTED as described, on two independent, verified grounds:
// 1. The chosen (chopped) technique does not achieve the claimed starvation at all. A direct
//    rAF-tick-counting probe against that exact burst pattern (4ms spins + `setTimeout(fn, 0)`,
//    1.5s total) recorded 782 ticks with a maximum gap of 22ms — ordinary ~60fps cadence, not a
//    multi-hundred-millisecond stall. `requestAnimationFrame` callbacks are not meaningfully
//    delayed by a macrotask chain that yields every few milliseconds.
// 2. Even the STRONGER form neither report actually used — one genuine, uninterrupted
//    synchronous block, which trivially DOES stall `requestAnimationFrame` (confirmed below: the
//    block runs start-to-finish, pointer-events is frozen `auto`, and a hit test at block-start
//    correctly targets the real frame) — still does not fill. The real click lands only once the
//    page's main thread frees up (this extension's own content script and the embedding page
//    share that thread in this harness), by which point Gate A's very next tick sees the frame
//    still hidden and records a fresh bad sample before `apply_fill` can arrive.
//
// `isFillAllowed`'s own lack of a recency requirement on `lastGoodSampleAt` — the specific defect
// both reports point at — was still closed as defense in depth (`menu-visibility.ts`), since it
// is cheap, strictly tightens, and the specific reproduction's failure here depends on this
// harness's own thread-sharing behaviour, which is not guaranteed to hold in every configuration.
test("a genuine (uninterrupted) main-thread stall while the frame is hidden still refuses the fill (reported bypass, critical/high — does not reproduce; `isFillAllowed` tightened regardless)", async ({
  context,
  extensionId,
  server,
}) => {
  test.setTimeout(60_000);
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "bypassstall");
    await createLoginItem(setupPage, {
      title: "Stall Bypass Target",
      username: "stallbypass-user@example.com",
      password: "stallbypass-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "bypassstall", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "Stall Bypass Target", exact: false });
    await expect(realCandidate).toBeVisible({ timeout: 15_000 });
    const box = await realCandidate.boundingBox();
    if (box === null) {
      throw new Error("adversarial test setup: could not read the real candidate's bounding box");
    }
    // Let a few genuine good ticks land first (matches both reports' own setup step).
    await visit.waitForTimeout(150);

    // Scheduled via `setTimeout` so this `evaluate()` call returns immediately and Playwright's
    // own `mouse.click` below is free to fire while the page's main thread is actually busy, not
    // serialised after it.
    await visit.evaluate(() => {
      (window as unknown as { __diag: Record<string, unknown> }).__diag = {};
      setTimeout(() => {
        const d = (window as unknown as { __diag: Record<string, unknown> }).__diag;
        const frame = document.querySelector<HTMLIFrameElement>("iframe[data-rizzy-inline-menu]");
        if (frame === null) {
          d["noFrame"] = true;
          return;
        }
        frame.style.setProperty("opacity", "0", "important");
        d["pointerEventsAtBlockStart"] = getComputedStyle(frame).pointerEvents;
        const r = frame.getBoundingClientRect();
        const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
        d["hitAtBlockStart"] = hit === frame ? "frame" : hit ? hit.tagName : "none";
        const t0 = performance.now();
        while (performance.now() - t0 < 1500) {
          /* ONE uninterrupted synchronous block — unlike both reports' own chosen technique */
        }
        d["blockRanMs"] = performance.now() - t0;
      }, 30);
    });
    await visit.waitForTimeout(60); // let the setTimeout fire and the block begin
    await visit.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    await visit.waitForTimeout(3000); // well past the 1500ms block and the full round trip

    const diag = await visit.evaluate(() => (window as unknown as { __diag: Record<string, unknown> }).__diag);
    // Confirms the preconditions the attack's own reasoning depends on actually held (pointer-
    // events frozen `auto`, hit test targeting the real frame, the block ran uninterrupted) —
    // this is a genuine attempt, not a no-op that happens to pass.
    expect(diag["pointerEventsAtBlockStart"]).toBe("auto");
    expect(diag["hitAtBlockStart"]).toBe("frame");
    expect(diag["blockRanMs"] as number).toBeGreaterThanOrEqual(1500);

    await expect(visit.locator("#user")).toHaveValue("");
    await expect(visit.locator("#pass")).toHaveValue("");
    await visit.close();
  } finally {
    await page.stop();
  }
});

