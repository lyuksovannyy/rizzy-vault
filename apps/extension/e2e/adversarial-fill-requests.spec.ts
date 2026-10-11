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

// Third adversarial-report round (THREAT_MODEL.md A7 Residual risk; HANDOFF X6 follow-up #2):
// 4 more reported bypasses. Two reproduced against Gates A/B alone and are now fixed
// (`content-script.ts`/`menu-visibility.ts`, below); one does not reproduce under this
// extension's own real, measured click→apply_fill timing and is rejected with evidence.
//
// Disables IntersectionObserver v2 context-wide — simulating Firefox's total lack of it
// (`inline-menu/main.ts`'s own `IOV2_SUPPORTED` feature-detect reads exactly this absence) — so
// these tests isolate Gates A/B's own floor from Gate C's Chromium-only backstop.
// Chromium-with-IOv2-disabled is a PROXY for Firefox, not Firefox itself: no Firefox Playwright
// harness exists here (HANDOFF, this file's own header comment / `playwright.config.ts`).
async function disableIov2(page: Page): Promise<void> {
  await page.addInitScript(() => {
    if (typeof IntersectionObserverEntry !== "undefined") {
      delete (IntersectionObserverEntry.prototype as unknown as Record<string, unknown>)["isVisible"];
    }
  });
}

/** Methodology guard: confirms IOv2 really is off INSIDE the real cross-origin inline-menu
 * document (not merely in the top frame, which never had it to begin with) — without this, a
 * test that "passes" could be passing only because Gate C silently caught the attack, the exact
 * confound disabling IOv2 exists to remove. */
async function expectIov2Disabled(visit: Page): Promise<void> {
  const inlineMenuFrame = visit.frames().find((f) => f.url().includes("inline-menu"));
  if (inlineMenuFrame === undefined) {
    throw new Error("adversarial test setup: could not find the inline-menu frame");
  }
  const disabled = await inlineMenuFrame.evaluate(() => !("isVisible" in IntersectionObserverEntry.prototype));
  expect(disabled).toBe(true);
}

// Reported bypass (critical; reported twice, independently — one mechanism, consolidated into
// one test per this file's own "one test per attack class" precedent, line 543): a 1×1
// `popover="manual"` element, promoted to the top layer by `showPopover()` (no user gesture
// needed), with `box-shadow: 0 0 0 3000px <opaque>`. `box-shadow` paints far outside its own
// border box but never participates in hit-testing and never changes `getBoundingClientRect()`.
//
// REPRODUCED against Gates A/B alone (confirmed by direct probe against the real built
// extension, IOv2 disabled: `elementFromPoint` at the menu's own centre kept returning the real
// iframe throughout, `pointer-events` stayed `auto`, and the real click filled both fields) — the
// pre-fix `#topLayerRects()`/`isTopLayerClear` compared only each top-layer element's OWN rect,
// never its painted area, so a popover whose rect never changes could blanket the viewport
// unnoticed. With IOv2 left enabled, Chromium's own Gate C backstop already caught this
// (confirmed by the same probe) — exactly the case THREAT_MODEL.md's A7 section's "floor on both
// browsers regardless of Gate C" claim did not actually hold for.
//
// FIXED: `#topLayerRects()` now widens each top-layer element's rect by
// `parseBoxShadowMarginPx`'s parsed box-shadow extent (or substitutes the full viewport rect for
// a non-`none` `filter`, or for a box-shadow shape the parser does not recognise) before it ever
// reaches `isTopLayerClear` — closing the exact demonstrated vector without blocking an ordinary
// `<dialog>`'s small drop shadow (`menu-visibility.test.ts` exercises the parser directly; a
// 0–~16px shadow never reaches a real menu's rect, a 3000px one always does).
test("a 1x1 top-layer popover with an oversized box-shadow cannot blanket-hide the menu while it stays clickable (reported bypass, critical, duplicate reports)", async ({
  context,
  extensionId,
  server,
}) => {
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "bypassboxshadow");
    await createLoginItem(setupPage, {
      title: "Box Shadow Bypass Target",
      username: "boxshadow-user@example.com",
      password: "boxshadow-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "bypassboxshadow", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await disableIov2(visit);
    // Planted before the page even loads (`showPopover()` needs no user gesture), exactly as
    // reported: the attacker's page shows this cover unconditionally on load, before the real
    // inline-menu iframe even exists.
    await visit.addInitScript(() => {
      window.addEventListener("DOMContentLoaded", () => {
        const pop = document.createElement("div");
        (pop as unknown as { popover: string }).popover = "manual";
        Object.assign(pop.style, {
          position: "fixed",
          left: "0px",
          top: "0px",
          width: "1px",
          height: "1px",
          boxShadow: "0 0 0 3000px rgba(20, 20, 20, 0.98)",
        });
        document.body.appendChild(pop);
        (pop as unknown as { showPopover: () => void }).showPopover();
      });
    });
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "Box Shadow Bypass Target", exact: false });
    await expect(realCandidate).toBeVisible({ timeout: 15_000 });
    await expectIov2Disabled(visit);

    const box = await realCandidate.boundingBox();
    if (box === null) {
      throw new Error("adversarial test setup: could not read the real candidate's bounding box");
    }

    // A short margin before reading anything geometry/visibility-dependent: Gate A's rAF loop
    // needs at least one tick to have sampled the popover at all.
    await visit.waitForTimeout(300);

    // The discriminator: confirms the attack setup actually took effect (the popover is really
    // promoted to the top layer, really has the oversized shadow, and its own border box is
    // genuinely tiny — the box-shadow, not the box itself, is what would do the blanketing), and
    // that the FIX is refusing for the reason this test exists to prove — Gate A's own
    // `pointer-events: none` toggle (`InlineMenu`'s own module doc) — not for some unrelated
    // reason. A raw `elementFromPoint` hit test is NOT part of this discriminator: it would
    // itself respect this same `pointer-events: none`, once set, and so cannot distinguish "the
    // fix caught the box-shadow" from "something else refused" — this file's own probe work
    // against the UNFIXED code already established that raw hit-testing alone reaches the real
    // iframe here (box-shadow never participates in hit-testing, by spec).
    const diag = await visit.evaluate(() => {
      const pop = document.querySelector("div[popover]");
      const frame = document.querySelector("iframe[data-rizzy-inline-menu]");
      return {
        popoverExists: pop !== null,
        popoverBoxShadow: pop !== null ? getComputedStyle(pop).boxShadow : null,
        popoverRectTiny: pop !== null ? pop.getBoundingClientRect().width <= 20 : false,
        framePointerEvents: frame !== null ? getComputedStyle(frame).pointerEvents : null,
      };
    });
    expect(diag.popoverExists).toBe(true);
    expect(diag.popoverBoxShadow).not.toBeNull();
    expect(diag.popoverBoxShadow).not.toBe("none");
    expect(diag.popoverRectTiny).toBe(true);
    expect(diag.framePointerEvents).toBe("none");

    await visit.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    await visit.waitForTimeout(1000);

    await expect(visit.locator("#user")).toHaveValue("");
    await expect(visit.locator("#pass")).toHaveValue("");
    await visit.close();
  } finally {
    await page.stop();
  }
});

// Reported bypass (critical): an opaque, `pointer-events: none` decoy sharing the frame's own
// maximum z-index, appended as a LATER sibling, with a synchronous main-thread busy-loop run in
// the SAME call stack as the decoy's own insertion. `document.elementFromPoint` (and
// `elementsFromPoint`, matching THREAT_MODEL.md's own residual-risk note on this exact exclusion)
// skips `pointer-events: none` targets entirely by spec, so neither Gate A's hit test nor a real
// click's own hit-testing ever sees this decoy; the busy-loop is aimed at denying the content
// script's `MutationObserver`-debounced rebuild (the thing that already defeats the plain,
// one-shot/persistent decoy above by re-winning the DOM-order tie) any chance to run until the
// loop returns, since a microtask/macrotask cannot preempt a running synchronous script.
//
// REPRODUCED (confirmed by direct probe against the real built extension, IOv2 left at its
// default EITHER WAY — this one did not even need IOv2 disabled to go through, a stronger result
// than the report itself claimed for Chromium): a real click dispatched during the 700ms stall
// filled both fields 3/3 runs, deterministically. Nothing about the frame's OWN rect/style/hit
// test ever changed (the decoy never touches the frame itself), so the pre-fix Gate A had no
// signal AT ALL to react to regardless of the stall or Gate A's own `requestAnimationFrame`
// cadence — this is a different, independent gap from the already-closed `isFillAllowed` recency
// issue (that one needed a stall to EXCEED the 1-second trailing window; this decoy's 700ms stall
// sits comfortably under it, and still worked, because the defect here is that the decoy is
// invisible to Gate A's checks, not that a sample went stale).
//
// FIXED, cross-browser and independent of timing: `InlineMenu#occludingSiblingRects` detects the
// attack's structural PRECONDITION instead of its paint — any body-level sibling, later than the
// frame in document order, whose own computed `z-index` ties the frame's maximum
// (`MAX_Z_INDEX`) — regardless of `pointer-events`, regardless of whether a rebuild has run yet,
// and regardless of a concurrent main-thread stall (the check only has to run ONCE the main
// thread is free again, at which point the decoy, until a rebuild removes it, is still
// detectable from the DOM alone). Confirmed by direct probe (post-fix, 4 runs, IOv2 both on and
// off) that this closes it without needing to win any tick-ordering race.
test("an opaque pointer-events:none decoy at the frame's own max z-index, inserted together with an uninterrupted main-thread stall, cannot blanket the menu while it stays clickable (reported bypass, critical)", async ({
  context,
  extensionId,
  server,
}) => {
  test.setTimeout(60_000);
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "bypassdecoystall");
    await createLoginItem(setupPage, {
      title: "Decoy Stall Target",
      username: "decoystall-user@example.com",
      password: "decoystall-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "bypassdecoystall", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await disableIov2(visit);
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "Decoy Stall Target", exact: false });
    await expect(realCandidate).toBeVisible({ timeout: 15_000 });
    await expectIov2Disabled(visit);

    const box = await realCandidate.boundingBox();
    if (box === null) {
      throw new Error("adversarial test setup: could not read the real candidate's bounding box");
    }
    await visit.waitForTimeout(150); // let Gate A record a real good sample first

    // Scheduled via `setTimeout` so this `evaluate()` call returns immediately and the real click
    // below is free to fire while the page's main thread is actually busy — same technique as
    // the existing main-thread-stall test above, with a `pointer-events: none` DECOY instead of
    // hiding the frame itself.
    await visit.evaluate((rect) => {
      (window as unknown as { __diag: Record<string, unknown> }).__diag = {};
      setTimeout(() => {
        const d = (window as unknown as { __diag: Record<string, unknown> }).__diag;
        const frame = document.querySelector<HTMLIFrameElement>("iframe[data-rizzy-inline-menu]");
        if (frame === null) {
          d["noFrame"] = true;
          return;
        }
        const decoy = document.createElement("div");
        decoy.id = "rizzy-test-decoy-stall";
        Object.assign(decoy.style, {
          position: "fixed",
          left: `${rect.x}px`,
          top: `${rect.y}px`,
          width: `${rect.width}px`,
          height: `${rect.height}px`,
          zIndex: "2147483647",
          background: "rgba(20, 20, 20, 0.98)",
          pointerEvents: "none",
        });
        document.body.appendChild(decoy); // SAME call stack as the busy loop below
        d["pointerEventsAtStallStart"] = getComputedStyle(frame).pointerEvents;
        const hitEl = document.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2);
        d["hitAtStallStart"] = hitEl === frame ? "frame" : hitEl ? hitEl.tagName : "none";
        const t0 = performance.now();
        while (performance.now() - t0 < 700) {
          /* ONE uninterrupted synchronous block, in the SAME call stack as the decoy insertion */
        }
        d["blockRanMs"] = performance.now() - t0;
      }, 30);
    }, box);
    await visit.waitForTimeout(60); // let the setTimeout fire and the stall begin
    await visit.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    await visit.waitForTimeout(2000); // well past the 700ms block and the full round trip

    const diag = await visit.evaluate(() => (window as unknown as { __diag: Record<string, unknown> }).__diag);
    // Confirms the attack's own preconditions actually held (pointer-events frozen `auto`, raw
    // hit-testing targeting the real frame despite the decoy, the block ran uninterrupted) — a
    // genuine attempt, not a no-op that happens to pass.
    expect(diag["pointerEventsAtStallStart"]).toBe("auto");
    expect(diag["hitAtStallStart"]).toBe("frame");
    expect(diag["blockRanMs"] as number).toBeGreaterThanOrEqual(700);

    await expect(visit.locator("#user")).toHaveValue("");
    await expect(visit.locator("#pass")).toHaveValue("");
    await visit.close();
  } finally {
    await page.stop();
  }
});

// Reported bypass (high; two severities claimed depending on browser — see this test's own
// verdict): an unrelated DOM mutation (e.g. a third-party script appending an empty `<span>`)
// anywhere on the page triggers `wireInlineMenu`'s unconditional rebuild, which replaces the
// closure's `menu`/`activeFillTargets` with a brand-new `InlineMenu` instance. Gate B's
// `apply_fill` listener (`content-script.ts`) checks whichever instance `menu` CURRENTLY is, with
// no check that it is the one instance the user's actual click happened on — so if a rebuild runs
// between the click and `apply_fill`'s arrival, a poisoned (correctly-refusing) instance's history
// is discarded in favour of a fresh, clean one.
//
// REJECTED as a REALISTIC bypass, on the facts, confirmed by direct probe against the real built
// extension (3/3 runs, no artificial delay of any kind): the mechanism depends on a rebuild
// actually completing and replacing `menu` BEFORE `apply_fill` arrives. A rebuild needs (1) an
// unrelated mutation to be observed by the content script's own `MutationObserver`, then (2) its
// debounced `schedule()` to wait a full 250ms before even calling `wireInlineMenu` — at least
// 250ms end to end. `menu-visibility.ts`'s own doc already measured the real click→apply_fill
// round trip directly against this extension's positive-control e2e test at 0.6–5.2ms — roughly
// 50–400× faster than the 250ms floor a rebuild needs. The report's own methodology concedes
// this: it reproduces the mechanism only by ARTIFICIALLY DELAYING `apply_fill`'s delivery inside
// the extension's own internals ("not a measured real-world figure"), which is not a capability a
// hostile WEB PAGE has (THREAT_MODEL.md A7's own "Capabilities" list is page-side JavaScript
// only — nothing about reaching into the extension's own background↔content-script message
// timing). With NO such artificial delay — hiding the page via `opacity: 0` (poisoning the
// current instance; a real click still lands, since opacity never blocks hit-testing),
// clicking, and firing the unrelated mutation (plus un-hiding) immediately afterward, exactly as
// fast as a real page could — the real, fast round trip always wins the race: `menu` is still the
// original, correctly-refusing instance by the time `apply_fill` arrives, every run.
//
// Not fixed (nothing here reproduces under this extension's own real timing, and the fix the
// mechanism would otherwise call for — threading the clicked instance's identity through the
// `apply_fill` message — would change ADR 0040's message shape, which needs an Accepted ADR this
// task does not have). Kept as a regression test: if a future change widens the rebuild debounce,
// speeds up nothing, or otherwise changes this timing relationship, this test is what would catch
// a bypass that starts reproducing for real.
test("an unrelated DOM mutation racing a rebuild against the real click→apply_fill round trip does not reproduce under real timing (reported bypass, high — rejected on the facts)", async ({
  context,
  extensionId,
  server,
}) => {
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "bypassswap");
    await createLoginItem(setupPage, {
      title: "Swap Bypass Target",
      username: "swapbypass-user@example.com",
      password: "swapbypass-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "bypassswap", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "Swap Bypass Target", exact: false });
    await expect(realCandidate).toBeVisible({ timeout: 15_000 });
    const box = await realCandidate.boundingBox();
    if (box === null) {
      throw new Error("adversarial test setup: could not read the real candidate's bounding box");
    }
    await visit.waitForTimeout(150);

    // Poisons the CURRENT instance's Gate A/B history (a real click still lands: opacity never
    // blocks hit-testing).
    await visit.evaluate(() => {
      document.body.style.opacity = "0";
    });
    await visit.waitForTimeout(100); // let a few real bad samples land first

    await visit.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    // As fast as a real hostile page could react — no artificial delay of the extension's own
    // message passing, only ordinary synchronous page script immediately after the click.
    await visit.evaluate(() => {
      document.body.style.opacity = "1"; // un-hide, so a rebuilt instance would start clean
      const span = document.createElement("span");
      span.textContent = "unrelated";
      document.body.appendChild(span); // the unrelated mutation that could trigger a rebuild
    });

    await visit.waitForTimeout(1000);
    await expect(visit.locator("#user")).toHaveValue("");
    await expect(visit.locator("#pass")).toHaveValue("");
    await visit.close();
  } finally {
    await page.stop();
  }
});

// Reported bypass (high; third adversarial round): a decoy sharing the frame's own maximum
// z-index, nested one level inside a plain, unstyled wrapper `<div>` (or a `mode: "open"` Shadow
// DOM host) rather than appended as a DIRECT body-level sibling. No timing trick, no busy-loop —
// a single synchronous insertion is enough, confirmed by THREAT_MODEL.md's own residual-risk note
// (added fixing the prior round's reported bypasses) that this exact nested variant still
// reproduced against `InlineMenu#occludingSiblingRects`, which only ever walked
// `frame.parentElement.children` — direct siblings only.
//
// FIXED: `InlineMenu#deepOccluderRects`/`#scanElementForDeepOccluders` (`content-script.ts`)
// generalize that walk to arbitrary nesting depth and into any OPEN Shadow DOM root. Rebuilt from
// `#frame`'s own siblings whenever a dedicated `MutationObserver` (childList + ALL attributes,
// deliberately unfiltered so a z-index keyed by `id`/`data-*` is also caught, excluding this
// script's own overlay elements + characterData, separate from the content script's own narrower
// one) marks the candidate set dirty — not re-walked unconditionally every Gate-A tick, which
// direct measurement found too expensive (avg 103ms, max 114ms over 20 warmed-up iterations, on a
// synthetic 5000-element page) for a 16ms tick budget, the exact performance objection the second
// adversarial round raised. No busy-loop is needed to "win" against anything: this does not
// depend on `wireInlineMenu`'s debounced rebuild, and the dirty-flag observer reacts in a
// microtask, well before even a fast real click.
async function plantNestedDecoy(visit: Page, rect: { x: number; y: number; width: number; height: number }, variant: "plain-div" | "shadow-dom"): Promise<void> {
  await visit.evaluate(
    ({ rect, variant }) => {
      const decoyStyle = {
        position: "fixed",
        left: `${rect.x}px`,
        top: `${rect.y}px`,
        width: `${rect.width}px`,
        height: `${rect.height}px`,
        zIndex: "2147483647",
        background: "rgba(20, 20, 20, 0.98)",
        pointerEvents: "none",
      };
      if (variant === "plain-div") {
        const wrapper = document.createElement("div");
        wrapper.id = "rizzy-test-nested-decoy-wrapper";
        const decoy = document.createElement("div");
        decoy.id = "rizzy-test-nested-decoy";
        Object.assign(decoy.style, decoyStyle);
        wrapper.appendChild(decoy); // decoy is one level INSIDE the wrapper, not a direct sibling
        document.body.appendChild(wrapper); // the one mutation the content script observes
        return;
      }
      const host = document.createElement("div");
      host.id = "rizzy-test-nested-decoy-shadow-host";
      const root = host.attachShadow({ mode: "open" });
      const decoy = document.createElement("div");
      decoy.id = "rizzy-test-nested-decoy";
      Object.assign(decoy.style, decoyStyle);
      root.appendChild(decoy); // decoy lives inside the OPEN shadow root
      document.body.appendChild(host); // the one mutation the content script observes
    },
    { rect, variant },
  );
  // Deliberately SHORT — one or two animation frames, not the ~250ms `schedule()` debounce that
  // would let `wireInlineMenu` rebuild the menu and launder this specific frame instance's own
  // history away (the mechanism the FIRST adversarial round's one-shot/persistent decoy was
  // correctly rejected on, per `THREAT_MODEL.md`'s own doc — "the rebuild-on-mutation cycle
  // re-wins the DOM-order tie"). This fix must not depend on winning that race either way, so the
  // test has to avoid the race, not merely survive it: long enough for Gate A's own
  // `requestAnimationFrame` tick to run at least once after the mutation, short enough that no
  // rebuild has had a chance to complete.
  await visit.waitForTimeout(60);
}

for (const variant of ["plain-div", "shadow-dom"] as const) {
  test(`a decoy at the frame's own max z-index, nested inside a ${variant === "plain-div" ? "plain wrapper <div>" : "mode:\"open\" Shadow DOM host"}, does not intercept the real click (reported bypass, high — no timing trick needed)`, async ({
    context,
    extensionId,
    server,
  }) => {
    const page = await startLoginPageServer();
    try {
      const setupPage = await context.newPage();
      const secretKey = await signUp(setupPage, server.origin, `nesteddecoy${variant === "plain-div" ? "div" : "shadow"}`);
      await createLoginItem(setupPage, {
        title: "Nested Decoy Target",
        username: "nesteddecoy-user@example.com",
        password: "nesteddecoy-target-password",
        websiteUrl: `http://127.0.0.1:${page.port}/`,
      });
      await setupPage.close();

      const popup = await enrol(context, extensionId, server, `nesteddecoy${variant === "plain-div" ? "div" : "shadow"}`, secretKey);
      await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
      await popup.close();

      // IOv2 disabled, same methodology (and reason) as the box-shadow/backdrop tests above:
      // this isolates Gates A/B, which are what the report's own mechanism is actually about —
      // `InlineMenu#deepOccluderRects`'s structural detection, not Gate C's compositor-level
      // occlusion check. The report also claims this reproduces with IOv2 left at Chromium's
      // default; direct measurement here found otherwise for the no-stall case (Gate C's own
      // IntersectionObserver v2 has time to observe the real occlusion and independently refuses
      // it when nothing stalls the main thread) — a narrower, Chromium-only finding than the
      // report's broadest claim, and the reason IOv2 is disabled here rather than left at
      // default: Firefox has no Gate C at all, and the project's own prior internal probe for
      // this exact nested case (THREAT_MODEL.md A7 residual risk, second adversarial round) used
      // a main-thread stall for the same reason. Gates A/B's own blind spot — the thing this test
      // and this fix are actually about — is independent of IOv2 either way.
      const visit = await context.newPage();
      await disableIov2(visit);
      await visit.goto(`http://127.0.0.1:${page.port}/`);
      const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
      const realCandidate = menu.getByRole("button", { name: "Nested Decoy Target", exact: false });
      await expect(realCandidate).toBeVisible({ timeout: 15_000 });
      await expectIov2Disabled(visit);
      const box = await realCandidate.boundingBox();
      if (box === null) {
        throw new Error("adversarial test setup: could not read the real candidate's bounding box");
      }
      await visit.waitForTimeout(150); // let Gate A record a real good sample first

      await plantNestedDecoy(visit, { x: box.x, y: box.y, width: box.width, height: box.height }, variant);

      // Discriminator: confirms the decoy actually sits where the report claims — opaque,
      // `pointer-events: none`, and (unlike the already-fixed direct-sibling case) NOT a direct
      // child of the frame's own parent, so RAW hit-testing (forcing the frame's own
      // `pointer-events` to `auto` for the single synchronous check, then restoring whatever Gate
      // A currently has it set to — the same technique `content-script.ts`'s own
      // `#pointHitResult` uses, so this reads the decoy's effect on hit-testing independently of
      // whichever value THIS fix's own gates currently have the frame set to) still reaches the
      // real frame underneath the decoy (`pointer-events: none` is excluded from hit-testing by
      // spec) — the decoy's own existence would have been invisible to the narrower, pre-fix
      // sibling-only check regardless of this.
      const diag = await visit.evaluate(
        ({ rect, variant }) => {
          // The Shadow DOM variant's decoy is unreachable via `document.getElementById` at all
          // (it does not pierce shadow boundaries, by spec) — the SAME reason this attack is
          // invisible to anything that only walks the light DOM, this diagnostic has to pierce it
          // deliberately to confirm the test's own setup, not to defend anything.
          const decoy =
            variant === "plain-div"
              ? document.getElementById("rizzy-test-nested-decoy")
              : (document.getElementById("rizzy-test-nested-decoy-shadow-host")?.shadowRoot?.getElementById("rizzy-test-nested-decoy") ?? null);
          const frame = document.querySelector<HTMLIFrameElement>("iframe[data-rizzy-inline-menu]");
          const previous = frame?.style.getPropertyValue("pointer-events") ?? "";
          frame?.style.setProperty("pointer-events", "auto", "important");
          const hitEl = document.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2);
          frame?.style.setProperty("pointer-events", previous === "" ? "none" : previous, "important");
          return {
            decoyExists: decoy !== null,
            decoyIsDirectBodyChild: decoy !== null && decoy.parentElement === document.body,
            rawHitIsFrame: frame !== null && hitEl === frame,
          };
        },
        { rect: box, variant },
      );
      expect(diag.decoyExists).toBe(true);
      expect(diag.decoyIsDirectBodyChild).toBe(false);
      expect(diag.rawHitIsFrame).toBe(true);

      await visit.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
      await visit.waitForTimeout(500);

      await expect(visit.locator("#user")).toHaveValue("");
      await expect(visit.locator("#pass")).toHaveValue("");
      await visit.close();
    } finally {
      await page.stop();
    }
  });
}

// Regression check for THIS fix's own first design (review finding, not a report): an earlier
// version's `MutationObserver` only watched `childList` (mirroring the content script's own
// field-redetection observer) and cached a decoy `Element` the first time it saw one INSERTED,
// never re-examining it. A decoy inserted at a LOW z-index (no reason to be flagged), then raised
// to the frame's own maximum in a LATER task via a plain style write — not a `childList`
// mutation — combined with a main-thread stall to deny any rebuild a chance to run, would have
// slipped past that version even though it never reproduces the actual reported bypass (insertion
// already at the final z-index). The current `#deepOccluderRects` closes this with a DEDICATED
// observer that also watches `attributes: ["style", "class"]` and `characterData` — a z-index
// raised by a plain style write (or a `<style>` tag's `textContent` rewritten in place) marks the
// candidate set dirty and triggers a fresh rebuild on the very next Gate-A tick, regardless of
// which task did the raising or whether any `childList` mutation ever fired.
test("a decoy's z-index raised in a LATER task (no childList mutation) after being inserted at a low z-index is still caught (regression check, not a reported bypass)", async ({
  context,
  extensionId,
  server,
}) => {
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "deferredzindexuser");
    await createLoginItem(setupPage, {
      title: "Deferred Zindex Target",
      username: "deferredz-user@example.com",
      password: "deferredz-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "deferredzindexuser", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await disableIov2(visit);
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "Deferred Zindex Target", exact: false });
    await expect(realCandidate).toBeVisible({ timeout: 15_000 });
    const box = await realCandidate.boundingBox();
    if (box === null) {
      throw new Error("adversarial test setup: could not read the real candidate's bounding box");
    }
    await visit.waitForTimeout(150); // let Gate A record a real good sample first

    // Inserted at a LOW z-index (nested in a wrapper, matching the reported shape): a cached,
    // insertion-time-only scan would see nothing worth flagging here.
    await visit.evaluate((rect) => {
      const wrapper = document.createElement("div");
      wrapper.id = "rizzy-test-deferred-wrapper";
      const decoy = document.createElement("div");
      decoy.id = "rizzy-test-deferred-decoy";
      Object.assign(decoy.style, {
        position: "fixed",
        left: `${rect.x}px`,
        top: `${rect.y}px`,
        width: `${rect.width}px`,
        height: `${rect.height}px`,
        zIndex: "1",
        background: "rgba(20, 20, 20, 0.98)",
        pointerEvents: "none",
      });
      wrapper.appendChild(decoy);
      document.body.appendChild(wrapper);
    }, box);
    await visit.waitForTimeout(60); // one real Gate-A tick, same margin as the sibling tests above

    // Raised to the frame's own maximum in a LATER task — a plain style write, not a `childList`
    // mutation — combined with a stall denying any rebuild a chance to run, same technique as the
    // already-fixed direct-sibling+stall bypass above.
    await visit.evaluate(() => {
      setTimeout(() => {
        const decoy = document.getElementById("rizzy-test-deferred-decoy");
        if (decoy !== null) {
          decoy.style.zIndex = "2147483647";
        }
        const t0 = performance.now();
        while (performance.now() - t0 < 700) {
          /* ONE uninterrupted synchronous block, denying any rebuild a chance to run */
        }
      }, 30);
    });
    await visit.waitForTimeout(60); // let the setTimeout fire and the stall begin
    await visit.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    await visit.waitForTimeout(1000); // well past the 700ms block and the full round trip

    await expect(visit.locator("#user")).toHaveValue("");
    await expect(visit.locator("#pass")).toHaveValue("");
    await visit.close();
  } finally {
    await page.stop();
  }
});

// Named, documented residual (A7, this task): a decoy nested inside a `mode: "closed"` Shadow DOM
// root cannot be detected by `#scanElementForDeepOccluders` or by ANY same-process JavaScript —
// `Element.shadowRoot` returns `null` for a closed root by spec, and no API in any browser this
// extension targets lets an extension content script (or any other non-devtools code sharing the
// page's process) read a closed shadow tree's content. This is not a gap in this fix; it is a
// gap in what the web platform exposes to ANY script, including the one trying to defend against
// it. Left as `test.fixme` rather than silently unlisted, per this task's own instruction for an
// impossible-in-a-browser case.
test.fixme(
  "a decoy nested inside a mode:'closed' Shadow DOM host cannot be detected by any content script — impossible in a browser, not a gap in this fix (Element.shadowRoot is null for a closed root by spec; no same-process API reads one)",
  async () => {
    // Intentionally empty: there is no DOM/CSSOM introspection this or any future content script
    // could add here. A closed shadow root is opaque to every same-process API by design (the
    // same guarantee `inline-menu/protocol.ts` relies on for the extension's OWN iframe content
    // being unreachable from the page). If a future web-platform API changes this, this test
    // should be implemented for real rather than left `fixme`.
  },
);

// Reported bypass (critical): an opaque, `pointer-events: none` `popover::backdrop` blankets the
// viewport while the triggering `popover` element itself stays genuinely tiny (1x1), via
// `<style>#d::backdrop{background:rgba(0,0,0,.95);pointer-events:none}</style>` plus
// `showPopover()`. `::backdrop` is a browser-painted pseudo-element with no corresponding
// `Element`/`Node` at all — `document.querySelectorAll` can never return it, and the pre-fix
// `#topLayerRects()`/`pushOcclusionRect` only ever read the POPOVER ELEMENT's own rect/filter/
// box-shadow, never its `::backdrop`. Report's own claim: refused today only by Gate C
// (IntersectionObserver v2, Chromium-only, defence in depth) — this test removes that confound
// (`disableIov2`) so it actually exercises Gates A/B, matching the report's methodology.
//
// FIXED: `pushBackdropOcclusionRect` (`content-script.ts`) reads `getComputedStyle(el,
// "::backdrop")` (the two-argument pseudo-element form) for every top-layer element and widens the
// occlusion rect to the full viewport whenever it is meaningfully opaque (`isBackdropOccluding`,
// `menu-visibility.ts`) — a native top-layer backdrop is always sized to the full viewport by the
// browser itself, so there is nothing to bound more precisely than that.
test("an opaque pointer-events:none popover::backdrop cannot blanket the menu while the popover element itself stays tiny and clickable (reported bypass, critical)", async ({
  context,
  extensionId,
  server,
}) => {
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "bypassbackdrop");
    await createLoginItem(setupPage, {
      title: "Backdrop Bypass Target",
      username: "backdrop-user@example.com",
      password: "backdrop-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "bypassbackdrop", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await disableIov2(visit);
    // Planted before the page even loads, as reported: `showPopover()` needs no user gesture.
    await visit.addInitScript(() => {
      window.addEventListener("DOMContentLoaded", () => {
        const style = document.createElement("style");
        style.textContent = "#rizzy-test-backdrop-popover::backdrop { background: rgba(20, 20, 20, 0.95); pointer-events: none; }";
        document.head.appendChild(style);
        const pop = document.createElement("div");
        pop.id = "rizzy-test-backdrop-popover";
        (pop as unknown as { popover: string }).popover = "manual";
        Object.assign(pop.style, { position: "fixed", left: "0px", top: "0px", width: "1px", height: "1px" });
        document.body.appendChild(pop);
        (pop as unknown as { showPopover: () => void }).showPopover();
      });
    });
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "Backdrop Bypass Target", exact: false });
    await expect(realCandidate).toBeVisible({ timeout: 15_000 });
    await expectIov2Disabled(visit);

    const box = await realCandidate.boundingBox();
    if (box === null) {
      throw new Error("adversarial test setup: could not read the real candidate's bounding box");
    }
    await visit.waitForTimeout(300);

    // Discriminator: the popover element itself is genuinely tiny (the `::backdrop`, not the
    // popover's own border box, is what would do the blanketing), its `::backdrop` really is
    // opaque, and RAW hit-testing (forcing `pointer-events: auto` on the frame for this one
    // synchronous check, then restoring whatever Gate A currently has it set to — same technique
    // as `content-script.ts`'s own `#pointHitResult`, so this stays a true invariant regardless
    // of whether THIS fix's own gate has already reacted) at the real candidate's centre still
    // reaches the real iframe underneath (`pointer-events: none` on the backdrop excludes it from
    // hit-testing, by spec) — confirming this is the SAME gap the box-shadow-on-the-element-itself
    // fix (above) does not cover.
    const diag = await visit.evaluate((rect) => {
      const pop = document.getElementById("rizzy-test-backdrop-popover");
      const frame = document.querySelector<HTMLIFrameElement>("iframe[data-rizzy-inline-menu]");
      const previous = frame?.style.getPropertyValue("pointer-events") ?? "";
      frame?.style.setProperty("pointer-events", "auto", "important");
      const hitEl = document.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2);
      frame?.style.setProperty("pointer-events", previous === "" ? "none" : previous, "important");
      return {
        popoverExists: pop !== null,
        popoverRectTiny: pop !== null ? pop.getBoundingClientRect().width <= 20 : false,
        rawHitIsFrame: frame !== null && hitEl === frame,
      };
    }, box);
    expect(diag.popoverExists).toBe(true);
    expect(diag.popoverRectTiny).toBe(true);
    expect(diag.rawHitIsFrame).toBe(true);

    await visit.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    await visit.waitForTimeout(1000);

    await expect(visit.locator("#user")).toHaveValue("");
    await expect(visit.locator("#pass")).toHaveValue("");
    await visit.close();
  } finally {
    await page.stop();
  }
});

// False-refusal report (not a credential leak — a denial of autofill availability): a
// legitimate, PERMANENT, non-transitioning ancestor `filter` such as `html { filter:
// grayscale(0.5) }` (real patterns: dark-mode-via-filter theming, duotone/sepia branding, a
// colour-blind accessibility toggle) used to disable the inline menu forever on that page, with
// no recovery, because `isChainNodeOk` treated ANY non-`none` `filter` as a bad sample with no
// allowance for a value that cannot actually hide or occlude anything — unlike Gate B's trailing
// window (which ages out a TRANSIENT bad sample), a permanent ancestor rule never ages out, so a
// page with this styling could never autofill at all. Distinct from the already-documented,
// already-accepted "a concurrent, unrelated ancestor CSS TRANSITION refuses the fill" trade-off
// above (test, line 932): that one is temporary (clears once the transition ends); this one,
// pre-fix, was permanent.
//
// FIXED, narrowly: `isFilterVisibilityPreserving` (`menu-visibility.ts`) allowlists exactly
// `grayscale`/`sepia`/`hue-rotate`/`saturate` — functions that recolour without ever being able to
// erase alpha or collapse luminance to a constant, at any argument value. This test also confirms
// the carve-out stays narrow: a filter that CAN hide content (`opacity(0)`) is still refused on
// the SAME page, alongside the SAME ancestor, proving this is a scoped allowlist, not a general
// loosening of the filter check.
test("a permanent ancestor filter: grayscale (dark-mode theming) no longer refuses the fill forever, but filter: opacity(0) on the same ancestor still does (false-refusal fix, scoped)", async ({
  context,
  extensionId,
  server,
}) => {
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "permanentfilteruser");
    await createLoginItem(setupPage, {
      title: "Permanent Filter Target",
      username: "permfilter-user@example.com",
      password: "permfilter-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "permanentfilteruser", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    // IOv2 disabled: `filter` on an ancestor visually affects the iframe's own COMPOSITED
    // pixels too (grayscale applies to everything painted within the filtered box, cross-origin
    // iframe included), and Chromium's IntersectionObserver v2 is specifically designed to flag
    // exactly that class of ancestor effect (`inline-menu/main.ts`'s own comment: IOv2's
    // `isVisible` is assumed to reflect "opacity/occlusion effects the embedding page applies to
    // the outer `<iframe>` element") — confirmed by direct measurement: with IOv2 left at
    // Chromium's default, Gate C refuses this fill independently of Gates A/B, even for the
    // visibility-preserving `grayscale` this fix allowlists, since IOv2 does not distinguish a
    // visibility-preserving filter function from an erasing one the way `isFilterVisibilityPreserving`
    // does. This fix is scoped to Gates A/B (`menu-visibility.ts`/`content-script.ts`), which is
    // what the false-refusal report is actually about; Gate C staying MORE conservative than
    // Gates A/B on Chromium is accepted defense-in-depth behaviour (`main.ts`'s own doc: "never
    // the sole gate" — the inverse is also true, it is never required to be less strict than the
    // floor either), and Firefox has no Gate C to refuse on in the first place.
    await disableIov2(visit);
    // Applied BEFORE the page loads, via an init script — a permanent, static rule, not a
    // transition: the whole point of this report is that it never changes and never ages out.
    // Waits for `DOMContentLoaded` before touching the DOM (same pattern the backdrop test above
    // uses): `addInitScript` can run before `document.head` exists at all.
    await visit.addInitScript(() => {
      window.addEventListener("DOMContentLoaded", () => {
        const style = document.createElement("style");
        style.id = "rizzy-test-permanent-filter";
        style.textContent = "html { filter: grayscale(0.5); }";
        document.head.appendChild(style);
      });
    });
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "Permanent Filter Target", exact: false });
    await expect(realCandidate).toBeVisible({ timeout: 15_000 });
    await expectIov2Disabled(visit);

    const htmlFilter = await visit.evaluate(() => getComputedStyle(document.documentElement).filter);
    expect(htmlFilter).not.toBe("none");

    const box = await realCandidate.boundingBox();
    if (box === null) {
      throw new Error("adversarial test setup: could not read the real candidate's bounding box");
    }
    // Long enough margin to prove this is not merely "still within some decaying window" — a
    // permanent rule has no window to decay out of; if this were still refusing, no amount of
    // waiting would fix it, which is exactly what the pre-fix report demonstrated.
    await visit.waitForTimeout(1500);

    await visit.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    await expect(visit.locator("#user")).toHaveValue("permfilter-user@example.com", { timeout: 15_000 });
    await expect(visit.locator("#pass")).toHaveValue("permfilter-target-password", { timeout: 15_000 });

    // Negative control, same page, same ancestor: a filter value that CAN hide content must still
    // refuse — proves the fix is a narrow allowlist, not "filter no longer matters."
    await visit.evaluate(() => {
      const style = document.getElementById("rizzy-test-permanent-filter");
      if (style !== null) {
        style.textContent = "html { filter: opacity(0.3); }";
      }
    });
    await visit.waitForTimeout(500);
    const pointerEventsIsNone = () => visit.locator("iframe[data-rizzy-inline-menu]").evaluate((el) => getComputedStyle(el).pointerEvents === "none");
    await expect.poll(pointerEventsIsNone, { timeout: 5_000 }).toBe(true);

    await visit.close();
  } finally {
    await page.stop();
  }
});

// Fourth adversarial round (five reports — three bypasses plus a dedupe, and one false refusal;
// checked the same way, a live device and a real click). Dedupe: of the nine reports triaged in
// this round, three are each a single mechanism reported more than once (the outline top-layer
// escape, reported twice; the deep-occluder box-shadow escape, reported three times — twice as a
// probe against the built extension, once as a standalone attacker-page script that is the same
// primitive; and the deep-occluder pseudo-element escape, reported twice), matching this file's
// own "one test per attack class" precedent (line 1563). Four distinct defects, all reproduced and
// fixed; one false refusal, confirmed and fixed.

// Reported bypass (critical; reported twice, independently — same mechanism, one test): a 1×1
// `popover="manual"` element, promoted to the top layer by `showPopover()` (no user gesture
// needed), styled `outline-style: solid; outline-color: <opaque>; outline-width: 3000px` instead
// of `box-shadow`. `outline` paints a uniform ring outside the border box, never changes
// `getBoundingClientRect()`, and never participates in hit-testing — the exact same shape as the
// already-fixed box-shadow bypass (line 1583), on the exact same code path that fix touched.
//
// REPRODUCED against Gates A/B alone (confirmed by direct probe against the real built extension,
// IOv2 disabled): the pre-fix `pushOcclusionRect` (`content-script.ts`) widened a top-layer
// element's rect for `filter` and `box-shadow` only — it never read `outline` at all, so a popover
// whose own border box stays 1×1 could blanket the viewport via `outline` alone, unnoticed.
//
// FIXED: `pushOcclusionRect` now also widens by `parseOutlineMarginPx`'s parsed outline extent
// (`menu-visibility.ts`, unit-tested directly), taking the larger of the box-shadow and outline
// margins — closing this without blocking an ordinary small `:focus-visible` ring.
test("a 1x1 top-layer popover with an oversized outline cannot blanket-hide the menu while it stays clickable (reported bypass, critical, duplicate reports)", async ({
  context,
  extensionId,
  server,
}) => {
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "bypassoutline");
    await createLoginItem(setupPage, {
      title: "Outline Bypass Target",
      username: "outline-user@example.com",
      password: "outline-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "bypassoutline", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await disableIov2(visit);
    // Planted before the page even loads, exactly as reported: `showPopover()` needs no gesture,
    // and no box-shadow or filter is set at all — only `outline`.
    await visit.addInitScript(() => {
      window.addEventListener("DOMContentLoaded", () => {
        const pop = document.createElement("div");
        (pop as unknown as { popover: string }).popover = "manual";
        Object.assign(pop.style, {
          position: "fixed",
          left: "0px",
          top: "0px",
          width: "1px",
          height: "1px",
          outlineStyle: "solid",
          outlineColor: "rgba(20, 20, 20, 0.98)",
          outlineWidth: "3000px",
        });
        document.body.appendChild(pop);
        (pop as unknown as { showPopover: () => void }).showPopover();
      });
    });
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "Outline Bypass Target", exact: false });
    await expect(realCandidate).toBeVisible({ timeout: 15_000 });
    await expectIov2Disabled(visit);

    const box = await realCandidate.boundingBox();
    if (box === null) {
      throw new Error("adversarial test setup: could not read the real candidate's bounding box");
    }
    await visit.waitForTimeout(300);

    // Discriminator: confirms the popover's own border box stays tiny (the outline, not the box
    // itself, would do the blanketing), the outline is really set, and the fix is refusing for
    // the stated reason (Gate A's `pointer-events: none` toggle) rather than something else.
    const diag = await visit.evaluate(() => {
      const pop = document.querySelector("div[popover]");
      const frame = document.querySelector("iframe[data-rizzy-inline-menu]");
      return {
        popoverExists: pop !== null,
        popoverOutlineWidth: pop !== null ? getComputedStyle(pop).outlineWidth : null,
        popoverOutlineStyle: pop !== null ? getComputedStyle(pop).outlineStyle : null,
        popoverRectTiny: pop !== null ? pop.getBoundingClientRect().width <= 20 : false,
        framePointerEvents: frame !== null ? getComputedStyle(frame).pointerEvents : null,
      };
    });
    expect(diag.popoverExists).toBe(true);
    expect(diag.popoverOutlineStyle).toBe("solid");
    expect(diag.popoverOutlineWidth).toBe("3000px");
    expect(diag.popoverRectTiny).toBe(true);
    expect(diag.framePointerEvents).toBe("none");

    await visit.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    await visit.waitForTimeout(1000);

    await expect(visit.locator("#user")).toHaveValue("");
    await expect(visit.locator("#pass")).toHaveValue("");
    await visit.close();
  } finally {
    await page.stop();
  }
});

// Reported bypass (critical): a top-layer `popover="manual"` host stays 1×1 while its `::before`
// pseudo-element independently declares `position: fixed; inset: 0` plus an opaque background —
// `pushOcclusionRect` only ever reads the HOST element's own rect/filter/box-shadow/outline, which
// structurally cannot see a pseudo-element at all (it has no `Element`/`Node` of its own), the
// same class of gap already closed for `::backdrop` (line 2179) but for `::before`/`::after`
// generated content instead.
//
// REPRODUCED against Gates A/B alone (confirmed by direct probe against the real built extension,
// IOv2 disabled): the host's own `getBoundingClientRect()` stayed 1×1 throughout, raw hit-testing
// at the real candidate's centre still resolved to the real frame, and the real click filled both
// fields.
//
// FIXED: `pushPseudoOcclusionRect` (`content-script.ts`) reads `getComputedStyle(el, "::before")`/
// `"::after"` for every top-layer element and substitutes the full viewport whenever the pseudo
// generates a box, declares `position: fixed`, and paints (`pseudoElementPaintsFixedOverlay`,
// `menu-visibility.ts`, unit-tested directly) — scoped to `position: fixed` specifically (not
// `absolute`, whose containing block this cannot resolve without over-refusing on ordinary
// decorative pseudo-elements; see that function's own doc and the positive-control test below).
test("an opaque position:fixed ::before on a top-layer popover host cannot blanket the menu while the host itself stays tiny and clickable (reported bypass, critical)", async ({
  context,
  extensionId,
  server,
}) => {
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "bypasspseudotop");
    await createLoginItem(setupPage, {
      title: "Pseudo Top Layer Target",
      username: "pseudotop-user@example.com",
      password: "pseudotop-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "bypasspseudotop", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await disableIov2(visit);
    await visit.addInitScript(() => {
      window.addEventListener("DOMContentLoaded", () => {
        const style = document.createElement("style");
        style.textContent =
          "#rizzy-test-pseudo-top-host::before { content: \"\"; position: fixed; inset: 0; background: rgba(20, 20, 20, 0.95); pointer-events: none; }";
        document.head.appendChild(style);
        const host = document.createElement("div");
        host.id = "rizzy-test-pseudo-top-host";
        (host as unknown as { popover: string }).popover = "manual";
        Object.assign(host.style, { position: "fixed", left: "0px", top: "0px", width: "1px", height: "1px" });
        document.body.appendChild(host);
        (host as unknown as { showPopover: () => void }).showPopover();
      });
    });
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "Pseudo Top Layer Target", exact: false });
    await expect(realCandidate).toBeVisible({ timeout: 15_000 });
    await expectIov2Disabled(visit);

    const box = await realCandidate.boundingBox();
    if (box === null) {
      throw new Error("adversarial test setup: could not read the real candidate's bounding box");
    }
    await visit.waitForTimeout(300);

    const diag = await visit.evaluate((rect) => {
      const host = document.getElementById("rizzy-test-pseudo-top-host");
      const frame = document.querySelector<HTMLIFrameElement>("iframe[data-rizzy-inline-menu]");
      const previous = frame?.style.getPropertyValue("pointer-events") ?? "";
      frame?.style.setProperty("pointer-events", "auto", "important");
      const hitEl = document.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2);
      frame?.style.setProperty("pointer-events", previous === "" ? "none" : previous, "important");
      return {
        hostExists: host !== null,
        hostRectTiny: host !== null ? host.getBoundingClientRect().width <= 20 : false,
        hostOwnZIndex: host !== null ? getComputedStyle(host).zIndex : null,
        rawHitIsFrame: frame !== null && hitEl === frame,
      };
    }, box);
    expect(diag.hostExists).toBe(true);
    expect(diag.hostRectTiny).toBe(true);
    expect(diag.rawHitIsFrame).toBe(true);

    await visit.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    await visit.waitForTimeout(1000);

    await expect(visit.locator("#user")).toHaveValue("");
    await expect(visit.locator("#pass")).toHaveValue("");
    await visit.close();
  } finally {
    await page.stop();
  }
});

// Reported bypass (critical; reported three times — twice as a direct probe against the built
// extension, once as a standalone attacker-page script; one mechanism, one test): a plain,
// NON-top-layer `position: fixed` decoy tying the frame's own maximum z-index (`MAX_Z_INDEX`),
// appended as a body-level sibling AFTER the frame, far from the menu's own rect, with
// `box-shadow: 0 0 0 3000px <opaque>`. Two of the three reports claimed a ~700ms main-thread stall
// was a necessary precondition; the third claimed tight (~80ms) timing was sufficient — both are
// consistent: 80ms is well under the content script's own 250ms `schedule()` debounce
// (`content-script.ts`), so the rebuild that would otherwise re-win the DOM-order tie has not run
// yet either way. This test uses the tight-timing form (no busy-loop), matching
// `plantNestedDecoy`'s own established margin (line 1950) and far less flaky than a synchronous
// stall.
//
// REPRODUCED against Gates A/B alone (confirmed by direct probe against the real built extension,
// IOv2 disabled): `#deepOccluderRects` (`content-script.ts`) — unlike `#topLayerRects`, which
// already widens for box-shadow/outline/filter via `pushOcclusionRect` — pushed the decoy's RAW,
// unwidened `getBoundingClientRect()`, which never intersected the menu's expected rect, so
// `isTopLayerClear` reported "clear" even though the decoy's box-shadow visually blanketed the
// menu. Raw hit-testing still resolved to the real frame, and the real click filled both fields.
//
// FIXED: `#deepOccluderRects` now routes an element that qualifies through its OWN z-index
// through `pushOcclusionRect` — the exact same widening the top-layer path already had — instead
// of its raw rect (`content-script.ts`'s own doc on `#deepOccluderQualification`).
test("a far-away, non-top-layer decoy tying the frame's max z-index with an oversized box-shadow cannot blanket the menu while it stays clickable (reported bypass, critical, triplicate reports)", async ({
  context,
  extensionId,
  server,
}) => {
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "bypassdeepshadow");
    await createLoginItem(setupPage, {
      title: "Deep Shadow Bypass Target",
      username: "deepshadow-user@example.com",
      password: "deepshadow-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "bypassdeepshadow", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await disableIov2(visit);
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "Deep Shadow Bypass Target", exact: false });
    await expect(realCandidate).toBeVisible({ timeout: 15_000 });
    await expectIov2Disabled(visit);

    const box = await realCandidate.boundingBox();
    if (box === null) {
      throw new Error("adversarial test setup: could not read the real candidate's bounding box");
    }
    await visit.waitForTimeout(150); // let Gate A record a real good sample first

    const diag = await visit.evaluate((menuBox) => {
      // Placed in the viewport's opposite corner from the real menu (so its own tiny,
      // UNWIDENED rect never geometrically overlaps the menu's) — the report's own methodology
      // for proving the pre-fix rect-intersection check structurally could not see this.
      const decoy = document.createElement("div");
      decoy.id = "rizzy-test-deep-shadow-decoy";
      Object.assign(decoy.style, {
        position: "fixed",
        left: `${window.innerWidth - 1}px`,
        top: `${window.innerHeight - 1}px`,
        width: "1px",
        height: "1px",
        zIndex: "2147483647",
        boxShadow: "0 0 0 3000px rgba(20, 20, 20, 0.98)",
        pointerEvents: "none",
      });
      document.body.appendChild(decoy); // after the frame, a direct body-level sibling
      const frame = document.querySelector<HTMLIFrameElement>("iframe[data-rizzy-inline-menu]");
      const decoyRect = decoy.getBoundingClientRect();
      const intersects = decoyRect.left < menuBox.x + menuBox.width && decoyRect.left + decoyRect.width > menuBox.x && decoyRect.top < menuBox.y + menuBox.height && decoyRect.top + decoyRect.height > menuBox.y;
      return {
        decoyRectIntersectsMenu: intersects,
        framePointerEventsAtInsert: frame !== null ? getComputedStyle(frame).pointerEvents : null,
      };
    }, box);
    expect(diag.decoyRectIntersectsMenu).toBe(false);
    expect(diag.framePointerEventsAtInsert).toBe("auto");

    // Deliberately short — under the 250ms `schedule()` debounce, so the content script's own
    // field-redetection rebuild has not had a chance to re-append a fresh frame after the decoy.
    await visit.waitForTimeout(80);
    await visit.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    await visit.waitForTimeout(500);

    await expect(visit.locator("#user")).toHaveValue("");
    await expect(visit.locator("#pass")).toHaveValue("");
    await visit.close();
  } finally {
    await page.stop();
  }
});

// Reported bypass (critical; reported twice — one mechanism, one test): a body-level sibling
// host, appended AFTER the frame, whose OWN `z-index` stays `"auto"` (so the pre-fix
// `#scanElementForDeepOccluders` never even considers it a candidate), while its `::before`
// pseudo-element independently declares `position: fixed; inset: 0; z-index: 2147483647`. Per
// CSS2.1 Appendix E step 6 (equal z-index within the same stacking context paints in tree order,
// later wins), the pseudo-element's own stacking context ties the frame's and comes after it —
// the host's own (irrelevant) z-index was never the thing that mattered.
//
// REPRODUCED against Gates A/B alone (confirmed by direct probe against the real built extension,
// IOv2 disabled, tight ~80ms timing — no stall needed): the host's own computed z-index stayed
// `"auto"` throughout, confirming the pre-fix scan would never have flagged it by any means, while
// raw hit-testing at the real candidate's centre still resolved to the real frame.
//
// FIXED: `#deepOccluderQualification` (`content-script.ts`) now also checks whether a
// `::before`/`::after` pseudo-element ties the max z-index (`pseudoElementTiesMaxZIndex`,
// `menu-visibility.ts`, unit-tested directly) — only for an element already known to follow the
// frame in tree order, the same bound that keeps the existing host-only check affordable. A
// qualification via a pseudo-element has no rect of its own to widen, so it conservatively
// occludes the full viewport, same as the `::backdrop`/top-layer-pseudo cases.
test("a decoy whose own z-index stays auto but whose ::before ties the frame's max z-index still cannot intercept the real click (reported bypass, critical, duplicate reports)", async ({
  context,
  extensionId,
  server,
}) => {
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "bypassdeeppseudo");
    await createLoginItem(setupPage, {
      title: "Deep Pseudo Bypass Target",
      username: "deeppseudo-user@example.com",
      password: "deeppseudo-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "bypassdeeppseudo", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await disableIov2(visit);
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "Deep Pseudo Bypass Target", exact: false });
    await expect(realCandidate).toBeVisible({ timeout: 15_000 });
    await expectIov2Disabled(visit);

    const box = await realCandidate.boundingBox();
    if (box === null) {
      throw new Error("adversarial test setup: could not read the real candidate's bounding box");
    }
    await visit.waitForTimeout(150); // let Gate A record a real good sample first

    const diag = await visit.evaluate(() => {
      const style = document.createElement("style");
      style.textContent =
        "#rizzy-test-deep-pseudo-host::before { content: \"\"; position: fixed; inset: 0; z-index: 2147483647; background: rgba(20, 20, 20, 0.95); pointer-events: none; }";
      document.head.appendChild(style);
      const host = document.createElement("div");
      host.id = "rizzy-test-deep-pseudo-host";
      document.body.appendChild(host); // after the frame, a direct body-level sibling
      return { hostOwnZIndex: getComputedStyle(host).zIndex };
    });
    expect(diag.hostOwnZIndex).toBe("auto");

    // Deliberately short — under the 250ms `schedule()` debounce, matching the direct-sibling
    // box-shadow test above.
    await visit.waitForTimeout(80);
    await visit.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    await visit.waitForTimeout(500);

    await expect(visit.locator("#user")).toHaveValue("");
    await expect(visit.locator("#pass")).toHaveValue("");
    await visit.close();
  } finally {
    await page.stop();
  }
});

// False-refusal report (not a credential leak — a denial of autofill availability): an open
// popover's `::backdrop` styled with a CSS Color 4 functional notation (`oklch()`/`lab()`/
// `color(display-p3 ...)`) and a near-zero alpha — e.g. Tailwind v4's default palette, which ships
// entirely in `oklch()`. Confirmed by direct probe against real Chromium (not merely against the
// shipped function): `getComputedStyle(el).backgroundColor` for a `background-color` authored in
// `oklch()`/`lab()`/`color(...)` is serialised back in that SAME function notation, never
// converted to `rgb()`, even fully inside the sRGB gamut — unlike `hsl()`, which Chromium does
// convert to `rgba()`. The pre-fix `isBackdropOccluding` (`menu-visibility.ts`) only matched
// `rgb()`/`rgba()`, so every one of these was treated as "unparseable" and refused unconditionally
// ("only ever refuse more" — but the CORRECT value here, after parsing the alpha, is "not
// occluding").
//
// FIXED: `isBackdropOccluding` now also matches `oklch()`/`oklab()`/`lab()`/`lch()`/`hwb()`/
// `color()` (and the modern space/slash form of `rgb()`/`hsl()`), extracting the same trailing
// CSS Color 4 `/ <alpha>` slash syntax (`menu-visibility.test.ts` exercises the parser directly).
// This test also confirms the fix stays a parser, not a loosening: a near-OPAQUE backdrop
// authored the same way still refuses, on the SAME page.
test("a near-transparent oklch() popover::backdrop no longer refuses the fill forever, but a near-opaque one still does (false-refusal fix, scoped)", async ({
  context,
  extensionId,
  server,
}) => {
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "oklchbackdropuser");
    await createLoginItem(setupPage, {
      title: "Oklch Backdrop Target",
      username: "oklchbackdrop-user@example.com",
      password: "oklchbackdrop-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "oklchbackdropuser", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await disableIov2(visit);
    await visit.addInitScript(() => {
      window.addEventListener("DOMContentLoaded", () => {
        const style = document.createElement("style");
        style.id = "rizzy-test-oklch-backdrop-style";
        style.textContent = "#rizzy-test-oklch-popover::backdrop { background: oklch(0 0 0 / 0.01); }";
        document.head.appendChild(style);
        const pop = document.createElement("div");
        pop.id = "rizzy-test-oklch-popover";
        (pop as unknown as { popover: string }).popover = "manual";
        Object.assign(pop.style, { position: "fixed", left: "0px", top: "0px", width: "1px", height: "1px" });
        document.body.appendChild(pop);
        (pop as unknown as { showPopover: () => void }).showPopover();
      });
    });
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "Oklch Backdrop Target", exact: false });
    await expect(realCandidate).toBeVisible({ timeout: 15_000 });
    await expectIov2Disabled(visit);

    // Confirms the real Chromium serialisation this fix depends on, not merely the test's own
    // intent — the whole report hinges on the browser NOT converting this to rgb().
    const backdropBg = await visit.evaluate(() => {
      const pop = document.getElementById("rizzy-test-oklch-popover");
      return pop !== null ? getComputedStyle(pop, "::backdrop").backgroundColor : null;
    });
    expect(backdropBg).toMatch(/^oklch\(/);

    const box = await realCandidate.boundingBox();
    if (box === null) {
      throw new Error("adversarial test setup: could not read the real candidate's bounding box");
    }
    await visit.waitForTimeout(500);

    await visit.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    await expect(visit.locator("#user")).toHaveValue("oklchbackdrop-user@example.com", { timeout: 15_000 });
    await expect(visit.locator("#pass")).toHaveValue("oklchbackdrop-target-password", { timeout: 15_000 });

    // Negative control, same page, same mechanism: a near-OPAQUE oklch() backdrop must still
    // refuse — proves this is a parser fix, not "stop checking backdrop alpha."
    await visit.evaluate(() => {
      const style = document.getElementById("rizzy-test-oklch-backdrop-style");
      if (style !== null) {
        style.textContent = "#rizzy-test-oklch-popover::backdrop { background: oklch(0 0 0 / 0.95); }";
      }
    });
    await visit.waitForTimeout(500);
    const pointerEventsIsNone = () => visit.locator("iframe[data-rizzy-inline-menu]").evaluate((el) => getComputedStyle(el).pointerEvents === "none");
    await expect.poll(pointerEventsIsNone, { timeout: 5_000 }).toBe(true);

    await visit.close();
  } finally {
    await page.stop();
  }
});

// Positive control (false-refusal check, not a reported bypass): an ORDINARY, honestly-coded page
// with a common decorative pattern — a cookie-consent-style widget whose `::before` is a small
// `position: absolute` caret/badge with its own background and a plain (non-`MAX_Z_INDEX`)
// `z-index` — must still fill normally. This is exactly the shape the fourth round's two
// pseudo-element fixes (top-layer and deep-occluder) are deliberately narrow about NOT flagging:
// `pseudoElementPaintsFixedOverlay` requires `position: fixed` (not `absolute`), and
// `pseudoElementTiesMaxZIndex` requires an EXACT tie to `MAX_Z_INDEX` (`2147483647`), never merely
// "high" — real pages essentially never use that exact value by accident.
test("an ordinary decorative ::before (position: absolute, modest z-index) on an unrelated widget does not break autofill (false-refusal check)", async ({
  context,
  extensionId,
  server,
}) => {
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "decorativepseudouser");
    await createLoginItem(setupPage, {
      title: "Decorative Pseudo Target",
      username: "decorativepseudo-user@example.com",
      password: "decorativepseudo-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "decorativepseudouser", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await visit.addInitScript(() => {
      window.addEventListener("DOMContentLoaded", () => {
        const style = document.createElement("style");
        style.textContent =
          "#rizzy-test-decorative-widget { position: fixed; right: 8px; bottom: 8px; z-index: 5; background: #eee; padding: 4px; }" +
          '#rizzy-test-decorative-widget::before { content: "\\25B2"; position: absolute; top: -6px; left: 4px; width: 8px; height: 6px; background: red; z-index: 5; }';
        document.head.appendChild(style);
        const widget = document.createElement("div");
        widget.id = "rizzy-test-decorative-widget";
        widget.textContent = "Cookie settings";
        document.body.appendChild(widget);
      });
    });
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "Decorative Pseudo Target", exact: false });
    await expect(realCandidate).toBeVisible({ timeout: 15_000 });
    const box = await realCandidate.boundingBox();
    if (box === null) {
      throw new Error("adversarial test setup: could not read the real candidate's bounding box");
    }
    await visit.waitForTimeout(500);

    await visit.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    await expect(visit.locator("#user")).toHaveValue("decorativepseudo-user@example.com", { timeout: 15_000 });
    await expect(visit.locator("#pass")).toHaveValue("decorativepseudo-target-password", { timeout: 15_000 });
    await visit.close();
  } finally {
    await page.stop();
  }
});

// Fifth adversarial round. Reported bypass (critical; reported three times, independently, under
// three different test methodologies — one mechanism, one test, per this file's own "one
// mechanism, one test" precedent, line 1563): a decoy appended directly to
// `document.documentElement` — a SIBLING of `<body>`, never a descendant of it — opaque,
// `pointer-events: none`, tying the frame's own maximum z-index, sized to cover the real menu (or
// the whole viewport). No timing trick: the reports' own methodology clicked at both 100ms and
// 600ms after insertion (well past any rebuild debounce) with the same result, since the gap is
// structural, not timing-based.
//
// REPRODUCED against Gates A/B alone (confirmed by direct probe against the real built extension,
// IOv2 disabled, and by reverting the fix below): `#deepOccluderRects` (`content-script.ts`)
// hardcoded its scan root to `#frame.parentElement.children` — `#frame.parentElement` is always
// `document.body` — so a decoy appended to `document.documentElement` itself was never visited by
// `#scanElementForDeepOccluders` on any scan, first or rebuilt: the gap was in the scan's SCOPE,
// not its timing or its content checks. Raw hit-testing still resolved to the real frame
// throughout, since the decoy's own `pointer-events: none` excludes it from hit-testing
// regardless of where it sits in the tree.
//
// FIXED: `#deepOccluderRects` now walks `#frame`'s own ANCESTOR PATH one level at a time —
// `document.body`, then `document.documentElement` — scanning each level's SIBLINGS (never the
// ancestor itself, preserving the pre-existing correctness requirement that `el` must never be a
// node on `#frame`'s own ancestor path), which closes this without special-casing
// `document.documentElement`.
//
// Accepted trade-off (named here, matching this section's own precedent for every prior fix):
// the second round's "self-limiting false-refusal" argument for a body-level sibling — a
// legitimate near-max-z-index widget self-heals because `wireInlineMenu`'s rebuild re-appends the
// frame LAST, under `document.body` — does NOT hold for an `documentElement`-level sibling, since
// every rebuild still only re-appends to `body`, never past a sibling of `body` itself. A
// legitimate widget some page genuinely appends to `document.documentElement` at the frame's own
// exact maximum z-index would now refuse permanently, not merely until the next rebuild — accepted
// given how vanishingly rare that combination is (no ordinary widget is appended as a sibling of
// `<body>` rather than inside it, let alone at this exact z-index) next to the critical bypass it
// closes.
test("a decoy appended to document.documentElement (a sibling of <body>, never a descendant of it) cannot intercept the real click (reported bypass, critical, triplicate reports)", async ({
  context,
  extensionId,
  server,
}) => {
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "bypasshtmlsibling");
    await createLoginItem(setupPage, {
      title: "Html Sibling Bypass Target",
      username: "htmlsibling-user@example.com",
      password: "htmlsibling-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "bypasshtmlsibling", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await disableIov2(visit);
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "Html Sibling Bypass Target", exact: false });
    await expect(realCandidate).toBeVisible({ timeout: 15_000 });
    await expectIov2Disabled(visit);

    const box = await realCandidate.boundingBox();
    if (box === null) {
      throw new Error("adversarial test setup: could not read the real candidate's bounding box");
    }
    await visit.waitForTimeout(150); // let Gate A record a real good sample first

    const diag = await visit.evaluate(() => {
      const decoy = document.createElement("div");
      decoy.id = "rizzy-test-html-sibling-decoy";
      Object.assign(decoy.style, {
        position: "fixed",
        inset: "0",
        zIndex: "2147483647",
        background: "rgba(10, 10, 10, 0.98)",
        pointerEvents: "none",
      });
      document.documentElement.appendChild(decoy); // NOT document.body — a sibling of <body>
      return {
        decoyParentIsHtml: decoy.parentElement === document.documentElement,
        decoyParentIsNotBody: decoy.parentElement !== document.body,
      };
    });
    expect(diag.decoyParentIsHtml).toBe(true);
    expect(diag.decoyParentIsNotBody).toBe(true);

    // No timing trick needed — the gap is structural. Waits comfortably past any rebuild
    // debounce, matching the reports' own "100ms and 600ms, same result" methodology.
    await visit.waitForTimeout(600);
    await visit.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    await visit.waitForTimeout(500);

    await expect(visit.locator("#user")).toHaveValue("");
    await expect(visit.locator("#pass")).toHaveValue("");
    await visit.close();
  } finally {
    await page.stop();
  }
});

// Fifth adversarial round. Reported bypass (critical): a decoy whose OWN `z-index` already ties
// the frame's maximum (qualifying `#deepOccluderQualification` as `"own"`, the pre-existing
// check) while its `::before` independently declares `position: fixed; inset: 0` plus an opaque
// background — a DIFFERENT host shape from the already-fixed "own z-index stays auto, only
// `::before` ties it" case (fourth round): here the host's OWN z-index already qualifies, which
// is exactly what made the pre-fix `#deepOccluderQualification` short-circuit to `"own"` and
// never reach the `::before`/`::after` reads at all.
//
// REPRODUCED against Gates A/B alone (confirmed by direct probe and by reverting the fix):
// `#deepOccluderQualification` returned `"own"` as soon as the host's own z-index tied the
// maximum, and the pre-fix `#deepOccluderRects`'s `"own"` branch called only
// `pushOcclusionRect` — which reads only the HOST's own rect/filter/box-shadow/outline, never a
// pseudo-element's paint — so a `::before` that independently blankets the viewport on that SAME
// element was never checked.
//
// FIXED: the `"own"` branch in `#deepOccluderRects` now ALSO calls `pushPseudoOcclusionRect` for
// `::before` and `::after`, unconditionally, exactly as `#topLayerRects` already does for every
// top-layer element.
test("a decoy whose own z-index already ties the frame's max z-index, AND whose ::before independently blankets the viewport, still cannot intercept the real click (reported bypass, critical)", async ({
  context,
  extensionId,
  server,
}) => {
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "bypassownpseudo");
    await createLoginItem(setupPage, {
      title: "Own Pseudo Bypass Target",
      username: "ownpseudo-user@example.com",
      password: "ownpseudo-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "bypassownpseudo", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await disableIov2(visit);
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "Own Pseudo Bypass Target", exact: false });
    await expect(realCandidate).toBeVisible({ timeout: 15_000 });
    await expectIov2Disabled(visit);

    const box = await realCandidate.boundingBox();
    if (box === null) {
      throw new Error("adversarial test setup: could not read the real candidate's bounding box");
    }
    await visit.waitForTimeout(150);

    const diag = await visit.evaluate(() => {
      const style = document.createElement("style");
      style.textContent =
        "#rizzy-test-own-pseudo-host::before { content: \"\"; position: fixed; inset: 0; background: rgba(20, 20, 20, 0.95); pointer-events: none; }";
      document.head.appendChild(style);
      const host = document.createElement("div");
      host.id = "rizzy-test-own-pseudo-host";
      Object.assign(host.style, {
        position: "fixed",
        left: `${window.innerWidth - 1}px`,
        top: `${window.innerHeight - 1}px`,
        width: "1px",
        height: "1px",
        zIndex: "2147483647",
        pointerEvents: "none",
      });
      document.body.appendChild(host); // after the frame, a direct body-level sibling
      return { hostOwnZIndex: getComputedStyle(host).zIndex };
    });
    expect(diag.hostOwnZIndex).toBe("2147483647");

    // Tight timing, matching the other far-corner/body-sibling decoy tests above (e.g. the "own
    // z-index stays auto" test, line 2745): under the content script's own 250ms field-
    // redetection debounce, so a REBUILD does not re-append a fresh frame AFTER this decoy before
    // the click — which would self-heal this specific instance by an accident of insertion order
    // (the already-documented, already-accepted self-limiting property for an ORDINARY widget),
    // not by this fix, and would defeat the point of this test either way.
    await visit.waitForTimeout(80);
    await visit.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    await visit.waitForTimeout(500);

    await expect(visit.locator("#user")).toHaveValue("");
    await expect(visit.locator("#pass")).toHaveValue("");
    await visit.close();
  } finally {
    await page.stop();
  }
});

// Fifth adversarial round. Reported bypass (high): a 1×1, off-screen, `pointer-events: none`
// carrier with an oversized `font-size` and `color: transparent` (so its own glyph is invisible)
// whose `text-shadow` paints a solid glyph copy far from the carrier's own border box — tying the
// frame's own maximum z-index so it qualifies as a deep-occluder candidate via
// `#deepOccluderQualification`'s `"own"` branch.
//
// REPRODUCED against Gates A/B alone (confirmed by direct probe and by reverting the fix):
// `pushOcclusionRect` (pre-fix) widened an element's rect for `box-shadow`/`outline`/`filter`,
// never `text-shadow` — a carrier whose own rect never intersects the menu therefore left
// `isTopLayerClear` reporting "clear" while the text-shadow visually painted over the real
// candidate.
//
// FIXED: `pushOcclusionRect` now substitutes the full viewport rect for any non-`"none"`
// `text-shadow`, the same conservative answer `filter` already gets — deriving a precise margin
// from the carrier's own rect would be unsound here (the glyph itself already overflows the
// border box via `overflow: visible` plus an oversized `font-size`, before any shadow offset is
// even applied), so this is the one shape in `pushOcclusionRect` that does not attempt a margin at
// all.
test("a text-shadow decoy painting a solid glyph far from its own tiny, off-screen carrier cannot intercept the real click (reported bypass, high)", async ({
  context,
  extensionId,
  server,
}) => {
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "bypasstextshadow");
    await createLoginItem(setupPage, {
      title: "Text Shadow Bypass Target",
      username: "textshadow-user@example.com",
      password: "textshadow-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "bypasstextshadow", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await disableIov2(visit);
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "Text Shadow Bypass Target", exact: false });
    await expect(realCandidate).toBeVisible({ timeout: 15_000 });
    await expectIov2Disabled(visit);

    const box = await realCandidate.boundingBox();
    if (box === null) {
      throw new Error("adversarial test setup: could not read the real candidate's bounding box");
    }
    await visit.waitForTimeout(150);

    const diag = await visit.evaluate((menuBox) => {
      const decoy = document.createElement("div");
      decoy.id = "rizzy-test-text-shadow-decoy";
      decoy.textContent = "█";
      Object.assign(decoy.style, {
        position: "fixed",
        left: "-400px",
        top: "60px",
        width: "1px",
        height: "1px",
        overflow: "visible",
        font: "900 400px/1 monospace",
        color: "transparent",
        whiteSpace: "nowrap",
        pointerEvents: "none",
        textShadow: "500px 40px 0 rgba(0, 0, 0, 0.95)",
        zIndex: "2147483647",
      });
      document.body.appendChild(decoy); // after the frame, a direct body-level sibling
      const decoyRect = decoy.getBoundingClientRect();
      const intersects =
        decoyRect.left < menuBox.x + menuBox.width &&
        decoyRect.left + decoyRect.width > menuBox.x &&
        decoyRect.top < menuBox.y + menuBox.height &&
        decoyRect.top + decoyRect.height > menuBox.y;
      return { decoyRectIntersectsMenu: intersects, textShadow: getComputedStyle(decoy).textShadow };
    }, box);
    expect(diag.decoyRectIntersectsMenu).toBe(false);
    expect(diag.textShadow).not.toBe("none");

    // Tight timing, matching the other far-corner/body-sibling decoy tests (e.g. the deep-shadow
    // test, line 2667): under the content script's own 250ms field-redetection debounce, so a
    // REBUILD does not re-append a fresh frame AFTER this decoy before the click.
    await visit.waitForTimeout(80);
    await visit.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    await visit.waitForTimeout(500);

    await expect(visit.locator("#user")).toHaveValue("");
    await expect(visit.locator("#pass")).toHaveValue("");
    await visit.close();
  } finally {
    await page.stop();
  }
});

// Fifth adversarial round. Reported bypass (high): a far-away, 1×1-content (3×3 border box)
// decoy with `border-image-outset: 300px` and a matching `border-image-width`, tying the frame's
// own maximum z-index — the border-image area paints a solid block far outside the element's own
// border box without ever changing `getBoundingClientRect()` or participating in hit-testing, the
// identical shape `box-shadow`/`outline` already have a carve-out for in `pushOcclusionRect`.
//
// REPRODUCED against Gates A/B alone (confirmed by direct probe and by reverting the fix):
// `pushOcclusionRect` (pre-fix) never read `border-image-source`/`border-image-outset` at all.
//
// FIXED: `pushOcclusionRect` now substitutes the full viewport rect whenever `border-image-source`
// is set and `border-image-outset` is not all-zero (`isAllZeroLengths`, `menu-visibility.ts`,
// unit-tested directly) — gated on OUTSET, not merely on the presence of a border-image, so an
// ordinary decorative border-image with no outset is never falsely widened.
test("a far-away border-image-outset decoy painting a solid block outside its own tiny border box cannot intercept the real click (reported bypass, high)", async ({
  context,
  extensionId,
  server,
}) => {
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "bypassborderimage");
    await createLoginItem(setupPage, {
      title: "Border Image Bypass Target",
      username: "borderimage-user@example.com",
      password: "borderimage-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "bypassborderimage", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await disableIov2(visit);
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "Border Image Bypass Target", exact: false });
    await expect(realCandidate).toBeVisible({ timeout: 15_000 });
    await expectIov2Disabled(visit);

    const box = await realCandidate.boundingBox();
    if (box === null) {
      throw new Error("adversarial test setup: could not read the real candidate's bounding box");
    }
    await visit.waitForTimeout(150);

    const diag = await visit.evaluate((menuBox) => {
      // Placed in the viewport's opposite corner from the real menu (so its own tiny, UNWIDENED
      // rect never geometrically overlaps the menu's), matching `plantNestedDecoy`'s/the deep
      // shadow test's own established pattern.
      const decoy = document.createElement("div");
      decoy.id = "rizzy-test-border-image-decoy";
      Object.assign(decoy.style, {
        position: "fixed",
        left: `${window.innerWidth - 1}px`,
        top: `${window.innerHeight - 1}px`,
        width: "1px",
        height: "1px",
        borderStyle: "solid",
        borderWidth: "1px",
        borderImageSource: "linear-gradient(#000, #000)",
        borderImageSlice: "1 fill",
        borderImageWidth: "3000px",
        borderImageOutset: "3000px",
        pointerEvents: "none",
        zIndex: "2147483647",
      });
      document.body.appendChild(decoy); // after the frame, a direct body-level sibling
      const decoyRect = decoy.getBoundingClientRect();
      const intersects =
        decoyRect.left < menuBox.x + menuBox.width &&
        decoyRect.left + decoyRect.width > menuBox.x &&
        decoyRect.top < menuBox.y + menuBox.height &&
        decoyRect.top + decoyRect.height > menuBox.y;
      return { decoyRectIntersectsMenu: intersects, borderImageOutset: getComputedStyle(decoy).borderImageOutset };
    }, box);
    expect(diag.decoyRectIntersectsMenu).toBe(false);
    expect(diag.borderImageOutset).not.toMatch(/^0(?:px)?( 0(?:px)?){0,3}$/);

    await visit.waitForTimeout(80); // tight timing, matching the deep-shadow test's own margin
    await visit.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    await visit.waitForTimeout(500);

    await expect(visit.locator("#user")).toHaveValue("");
    await expect(visit.locator("#pass")).toHaveValue("");
    await visit.close();
  } finally {
    await page.stop();
  }
});

// Fifth adversarial round. Reported bypass (high; the `<foreignObject>` variant of the same
// primitive lets the decoy carry arbitrary HTML/CSS instead of a flat fill, not independently
// tested here): a far-away, 1×1 `<svg>` host with `overflow: visible` (the UA-stylesheet default
// for the document's OUTERMOST `svg` specifically — only a NESTED `svg`/`symbol`/etc. defaults to
// `hidden`), tying the frame's own maximum z-index, whose child `<rect>` paints a solid block far
// outside the host's own 1×1 box. An SVG child does not carry a meaningful CSS `z-index` of its
// own the way a sibling HTML element would, so the child itself never independently qualifies as
// a deep-occluder candidate — only the HOST's own (tiny) rect was ever checked.
//
// REPRODUCED against Gates A/B alone (confirmed by direct probe and by reverting the fix):
// `pushOcclusionRect` (pre-fix) only ever read the HOST element's own rect/filter/box-shadow/
// outline — none of which sees an `overflow: visible` descendant's paint.
//
// FIXED: `pushOcclusionRect` now unions every descendant's own rect into the result whenever `el`
// does not clip on BOTH axes (`overflow-x`/`overflow-y` not both `hidden`/`clip`) — covering this
// SVG case and the identical HTML analogue (a plain `position: absolute` descendant placed outside
// its unclipped ancestor) in one rule, without blanket-refusing an ordinary clipped widget or a
// childless element. See the next test for the matching false-refusal check.
test("an <svg> host with overflow:visible, whose child paints far outside its own 1x1 box, cannot intercept the real click (reported bypass, high)", async ({
  context,
  extensionId,
  server,
}) => {
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "bypasssvgoverflow");
    await createLoginItem(setupPage, {
      title: "Svg Overflow Bypass Target",
      username: "svgoverflow-user@example.com",
      password: "svgoverflow-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "bypasssvgoverflow", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await disableIov2(visit);
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "Svg Overflow Bypass Target", exact: false });
    await expect(realCandidate).toBeVisible({ timeout: 15_000 });
    await expectIov2Disabled(visit);

    const box = await realCandidate.boundingBox();
    if (box === null) {
      throw new Error("adversarial test setup: could not read the real candidate's bounding box");
    }
    await visit.waitForTimeout(150);

    const diag = await visit.evaluate((menuBox) => {
      const svgNs = "http://www.w3.org/2000/svg";
      const decoy = document.createElementNS(svgNs, "svg") as unknown as SVGSVGElement;
      decoy.id = "rizzy-test-svg-overflow-decoy";
      decoy.setAttribute("width", "1");
      decoy.setAttribute("height", "1");
      Object.assign(decoy.style, {
        position: "fixed",
        left: `${window.innerWidth - 1}px`,
        top: `${window.innerHeight - 1}px`,
        overflow: "visible",
        pointerEvents: "none",
        zIndex: "2147483647",
      });
      const rect = document.createElementNS(svgNs, "rect");
      rect.setAttribute("x", "-3000");
      rect.setAttribute("y", "-3000");
      rect.setAttribute("width", "6000");
      rect.setAttribute("height", "6000");
      rect.setAttribute("fill", "#000");
      decoy.appendChild(rect);
      document.body.appendChild(decoy); // after the frame, a direct body-level sibling
      const hostRect = decoy.getBoundingClientRect();
      const hostRectIntersectsMenu =
        hostRect.left < menuBox.x + menuBox.width &&
        hostRect.left + hostRect.width > menuBox.x &&
        hostRect.top < menuBox.y + menuBox.height &&
        hostRect.top + hostRect.height > menuBox.y;
      return { hostRectTiny: hostRect.width <= 2 && hostRect.height <= 2, hostRectIntersectsMenu, overflow: getComputedStyle(decoy).overflow };
    }, box);
    expect(diag.hostRectTiny).toBe(true);
    expect(diag.hostRectIntersectsMenu).toBe(false);

    await visit.waitForTimeout(80); // tight timing, matching the other far-corner decoy tests
    await visit.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    await visit.waitForTimeout(500);

    await expect(visit.locator("#user")).toHaveValue("");
    await expect(visit.locator("#pass")).toHaveValue("");
    await visit.close();
  } finally {
    await page.stop();
  }
});

// False-refusal check (not a reported bypass) for the unclipped-descendant-union fix above: an
// ORDINARY, honestly-coded `<dialog>` — open but non-modal (`.show()`, so it does not make the
// rest of the page `inert` the way `.showModal()` would, which would confound this check with
// ordinary browser behaviour rather than this extension's own code), positioned far from the real
// menu, with normal in-bounds content (a text node and a `<button>`) and `overflow`'s UA-default
// `visible` on at least one axis — must still fill normally. The new descendant-union logic in
// `pushOcclusionRect` widens `el`'s rect to cover every descendant's own rect whenever `el` does
// not clip on both axes; for an ordinary dialog, every descendant renders INSIDE the dialog's own
// visual box regardless of its `overflow` value, so the union equals the dialog's own (already
// correctly-positioned, non-overlapping) rect — no added false-refusal cost.
test("an ordinary, non-modal open <dialog> elsewhere on screen, with overflow:visible and normal in-bounds content, does not break autofill (false-refusal check)", async ({
  context,
  extensionId,
  server,
}) => {
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "ordinarydialoguser");
    await createLoginItem(setupPage, {
      title: "Ordinary Dialog Target",
      username: "ordinarydialog-user@example.com",
      password: "ordinarydialog-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "ordinarydialoguser", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await visit.addInitScript(() => {
      window.addEventListener("DOMContentLoaded", () => {
        const dialog = document.createElement("dialog");
        dialog.id = "rizzy-test-ordinary-dialog";
        Object.assign(dialog.style, { position: "fixed", right: "8px", bottom: "8px", margin: "0" });
        dialog.textContent = "An ordinary dialog, far from the login form. ";
        const closeButton = document.createElement("button");
        closeButton.type = "button";
        closeButton.textContent = "Close";
        dialog.appendChild(closeButton);
        document.body.appendChild(dialog);
        (dialog as unknown as { show: () => void }).show();
      });
    });
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "Ordinary Dialog Target", exact: false });
    await expect(realCandidate).toBeVisible({ timeout: 15_000 });

    const dialogOverflow = await visit.evaluate(() => {
      const dialog = document.getElementById("rizzy-test-ordinary-dialog");
      return dialog !== null ? { open: dialog.hasAttribute("open"), overflow: getComputedStyle(dialog).overflow } : null;
    });
    expect(dialogOverflow?.open).toBe(true);
    expect(dialogOverflow?.overflow).not.toMatch(/^(hidden|clip)$/);

    const box = await realCandidate.boundingBox();
    if (box === null) {
      throw new Error("adversarial test setup: could not read the real candidate's bounding box");
    }
    await visit.waitForTimeout(500);

    await visit.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    await expect(visit.locator("#user")).toHaveValue("ordinarydialog-user@example.com", { timeout: 15_000 });
    await expect(visit.locator("#pass")).toHaveValue("ordinarydialog-target-password", { timeout: 15_000 });
    await visit.close();
  } finally {
    await page.stop();
  }
});

// Fifth adversarial round. Reported bypass (medium; the report's own methodology could not
// confirm real-world exploitability against the actual iframe that session — Gate C observed a
// transient, non-sustained `isVisible: false` in that configuration, so this task re-ran the
// check empirically with IOv2 disabled rather than taking the report's uncertainty at face
// value): a same-document View Transition's own generated pseudo-element tree
// (`::view-transition-group(...)`/`::view-transition-old(...)`/`::view-transition-new(...)`)
// renders above ALL ordinary z-index stacking, including this frame's own `MAX_Z_INDEX`, and has
// no corresponding `Element`/`Node` at all — not reachable by `#topLayerRects`'s enumeration
// (`document.fullscreenElement`/`dialog[open]`/`:popover-open`, none of which this is) or by
// `#deepOccluderRects`'s DOM walk (the decoy element this test uses is `remove()`d inside the
// transition's own callback, so it is not even a connected node once the pseudo-element tree is
// actually painting). Structurally, this reasoning is correct: neither enumeration-based check
// can see this pseudo-element tree.
//
// DOES NOT REPRODUCE against Gates A/B on Chromium, on the facts — confirmed by direct
// instrumentation of the real built extension (IOv2 disabled), not by taking the report's
// uncertainty at face value: `#pointHitResult`'s own `document.elementFromPoint` call, UNCHANGED
// by any fix, already resolves to `document.documentElement` — not the frame, not `null` — for
// every point in the viewport for the whole duration of ANY active same-document View Transition
// on this Chromium build, regardless of where the transition's own named element is positioned.
// Confirmed with a decoy shrunk to 5×5px in the viewport's opposite corner from the real
// candidate (so nothing the attacker controls visually overlaps the target at all) and with
// `pointer-events: none !important` forced on every `::view-transition-*` pseudo-element (so the
// attacker cannot make the overlay "transparent" to hits either): `elementFromPoint` at the real
// candidate's own center still returned `<html>` for the whole transition window in both cases.
// `isPointHitOk` (`menu-visibility.ts`) therefore already reports a bad sample for the whole
// transition — not through any transition-specific logic, but as a side effect of how Chromium's
// own implementation of View Transitions affects hit-testing document-wide while one is active.
// A real OS-level click is refused for the identical reason (`#sampleOk`'s point-hit check is the
// authoritative measurement Gate A's `pointer-events` toggle acts on). An earlier version of this
// task's own work added a dedicated `document.getAnimations`-based check for this case before
// this empirical pass was run; removed once the pass showed the existing, unmodified point-hit
// check already closes it — per CLAUDE.md's DRY/KISS/YAGNI, redundant code for a non-reproducing
// report is not kept "just in case."
//
// NOT independently confirmed for a hypothetical browser whose View Transitions implementation
// does NOT suppress document-wide hit-testing this way (Firefox has no same-document View
// Transitions support at all today, so this is moot there for now; if/when it ships one, this
// specific protection is a Chromium implementation detail, not a web-platform guarantee, and
// would need re-checking against that implementation rather than assumed to carry over).
test("a same-document View Transition's own pseudo-element overlay does not intercept the real click while active (reported bypass, medium — rejected: Chromium's own hit-testing already refuses it, independent of this codebase)", async ({
  context,
  extensionId,
  server,
}) => {
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "bypassviewtransition");
    await createLoginItem(setupPage, {
      title: "View Transition Bypass Target",
      username: "viewtransition-user@example.com",
      password: "viewtransition-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "bypassviewtransition", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await disableIov2(visit);
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "View Transition Bypass Target", exact: false });
    await expect(realCandidate).toBeVisible({ timeout: 15_000 });
    await expectIov2Disabled(visit);

    const supported = await visit.evaluate(() => typeof document.startViewTransition === "function");
    if (!supported) {
      test.skip(true, "this Chromium build has no document.startViewTransition to exercise");
      return;
    }

    const box = await realCandidate.boundingBox();
    if (box === null) {
      throw new Error("adversarial test setup: could not read the real candidate's bounding box");
    }
    await visit.waitForTimeout(150); // let Gate A record a real good sample first

    await visit.evaluate(() => {
      const style = document.createElement("style");
      style.id = "rizzy-test-view-transition-style";
      // `pointer-events: none` on the pseudo-elements themselves: if the attacker's own theory
      // (clicks pass through to the live frame underneath while the overlay merely occludes it
      // visually, exactly like every other decoy in this file) were correct, this would be what
      // lets the click reach the real candidate. It does not change the outcome below.
      style.textContent =
        "::view-transition-group(decoy), ::view-transition-old(decoy), ::view-transition-new(decoy) { animation-duration: 3s !important; pointer-events: none !important; }";
      document.head.appendChild(style);
      // Deliberately tiny (5x5px) and in the viewport's opposite corner from the real candidate —
      // nothing the attacker controls visually overlaps the target at all, isolating whether the
      // refusal below comes from occluding the target or from the transition itself.
      const decoy = document.createElement("div");
      decoy.id = "rizzy-test-view-transition-decoy";
      Object.assign(decoy.style, { position: "fixed", left: "0px", top: "0px", width: "5px", height: "5px", background: "#fff" });
      decoy.style.setProperty("view-transition-name", "decoy");
      document.body.appendChild(decoy);
      document.startViewTransition(() => {
        decoy.remove();
      });
    });
    await visit.waitForTimeout(200); // let the transition's own pseudo-element tree start animating

    const diag = await visit.evaluate((menuBox) => {
      const getAnimationsWithSubtree = document.getAnimations as unknown as (options?: { readonly subtree?: boolean }) => readonly Animation[];
      const transitioning = getAnimationsWithSubtree.call(document, { subtree: true }).some((a) => {
        const effect = a.effect as unknown as { pseudoElement?: string | null } | null;
        return effect !== null && typeof effect.pseudoElement === "string" && effect.pseudoElement.startsWith("::view-transition");
      });
      // The SAME measurement `#pointHitResult` makes: force the frame's own `pointer-events` to
      // `auto` for this one synchronous check, matching that method's own methodology exactly.
      const frame = document.querySelector<HTMLIFrameElement>("iframe[data-rizzy-inline-menu]");
      const previous = frame?.style.getPropertyValue("pointer-events") ?? "";
      frame?.style.setProperty("pointer-events", "auto", "important");
      const hitEl = document.elementFromPoint(menuBox.x + menuBox.width / 2, menuBox.y + menuBox.height / 2);
      frame?.style.setProperty("pointer-events", previous === "" ? "none" : previous, "important");
      return { transitioning, hitIsFrame: hitEl === frame, hitTagName: hitEl?.tagName ?? null };
    }, box);
    expect(diag.transitioning).toBe(true);
    // The load-bearing assertion: even forcing the frame clickable and measuring at the real
    // candidate's own center, `elementFromPoint` does not resolve to the frame while the
    // transition is active — confirming the refusal below is NOT this codebase refusing a click
    // that would otherwise land correctly.
    expect(diag.hitIsFrame).toBe(false);
    expect(diag.hitTagName).toBe("HTML");

    await visit.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    await visit.waitForTimeout(500);

    await expect(visit.locator("#user")).toHaveValue("");
    await expect(visit.locator("#pass")).toHaveValue("");
    await visit.close();
  } finally {
    await page.stop();
  }
});

// False-refusal check (not a reported bypass; see the rejected report above): an ORDINARY,
// brief, unrelated same-document View Transition (default duration, not extended) must not
// permanently disable autofill — Chromium's own document-wide hit-testing suppression while a
// transition is active must age out once the transition itself ends, the same accepted shape as
// the already-documented concurrent-ancestor-CSS-transition trade-off.
test("an ordinary, brief, unrelated View Transition elsewhere on the page does not permanently disable autofill (false-refusal check)", async ({
  context,
  extensionId,
  server,
}) => {
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "ordinaryviewtransition");
    await createLoginItem(setupPage, {
      title: "Ordinary View Transition Target",
      username: "ordinaryvt-user@example.com",
      password: "ordinaryvt-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "ordinaryviewtransition", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "Ordinary View Transition Target", exact: false });
    await expect(realCandidate).toBeVisible({ timeout: 15_000 });

    const supported = await visit.evaluate(() => typeof document.startViewTransition === "function");
    if (!supported) {
      test.skip(true, "this Chromium build has no document.startViewTransition to exercise");
      return;
    }

    const box = await realCandidate.boundingBox();
    if (box === null) {
      throw new Error("adversarial test setup: could not read the real candidate's bounding box");
    }
    await visit.waitForTimeout(150);

    // An ordinary, short-lived transition on unrelated, ALREADY-PRESENT content — default
    // duration (~250ms), no override — well finished by the time this test clicks. Deliberately
    // a STYLE change on an existing node, not a new node inserted/removed: an insertion would
    // also be a `childList` mutation under `document.documentElement`, which would trigger the
    // content script's own, SEPARATE field-redetection debounce (`installContentScript`'s own
    // `MutationObserver`, `schedule()`) and rebuild the `InlineMenu` instance entirely — a second,
    // unrelated mechanism this test is not about exercising.
    await visit.evaluate(() => {
      document.body.style.setProperty("view-transition-name", "ordinary-body");
      document.startViewTransition(() => {
        document.body.style.setProperty("background-color", "rgb(240, 240, 240)");
      });
    });
    // Past the default transition duration (~250ms) AND, from there, past the full 1s Gate-B
    // trailing window (`DEFAULT_MENU_VISIBILITY_WINDOW_MS`) — `#pointHitResult`'s own
    // `elementFromPoint` call (unchanged, pre-existing) keeps resolving to `document.documentElement`
    // document-wide for as long as this transition is active (see the rejected report above), so
    // the transition's own last BAD sample lands around the 250ms mark, and Gate B refuses until
    // `now - lastBadSampleAt >= windowMs`; the click must land at least `250ms + windowMs` after
    // the transition started, plus margin for jitter.
    await visit.waitForTimeout(2000);

    await visit.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    await expect(visit.locator("#user")).toHaveValue("ordinaryvt-user@example.com", { timeout: 15_000 });
    await expect(visit.locator("#pass")).toHaveValue("ordinaryvt-target-password", { timeout: 15_000 });
    await visit.close();
  } finally {
    await page.stop();
  }
});

// Sixth adversarial round (five reports, three distinct mechanisms after dedupe; checked the
// same way, a live device, a real click, Chromium with IntersectionObserver v2 disabled
// context-wide as a PROXY for Firefox's total lack of it). Two bypasses reproduced and are now
// fixed; one (the cloned-resource sender bypass, and its two same-root-cause variants) reproduced
// but is NOT fixed here — see the dedicated comment above that test.
//
// A stacking-context-escaping ancestor (`isolation: isolate`, or `opacity` anything other than
// EXACTLY 1) plus a low-`z-index` decoy appended as a sibling of `<body>` (reported critical,
// two variants of one mechanism): REPRODUCED against Gates A/B alone (confirmed by direct probe
// against the real built extension and by reverting the fix) — every occlusion check this module
// has (`#deepOccluderQualification`'s own z-index tie, `isChainNodeOk`'s opacity/visibility/
// filter/etc. chain) assumes z-index is compared GLOBALLY against the frame's own
// `MAX_Z_INDEX`. That assumption silently breaks the instant ANY ancestor between the frame and
// `documentElement` establishes its own CSS stacking context (per spec: `isolation: isolate`,
// or ANY `opacity` other than exactly `1`, does this unconditionally) — the ancestor's entire
// subtree, including the frame and its enormous z-index, then collapses to that ancestor's own
// single position in the ROOT stacking context, so a sibling of the ancestor needs only a
// trivially low z-index (not `MAX_Z_INDEX`) to paint above the whole subtree. Neither
// `ChainStyleSample`/`isChainNodeOk` (`menu-visibility.ts`) ever read `isolation` at all, and the
// existing `OPACITY_TOLERANCE` (0.01, there for the VISUAL "looks the same as 1" question) was
// being relied on, with no actual relationship, to also answer the BINARY "did this trigger a
// new stacking context" question — `body { opacity: 0.995 }` passes the 0.01 tolerance
// comfortably while still unconditionally creating a new stacking context per spec.
//
// FIXED: `isChainNodeOk` now also requires `sample.isolation !== "isolate"`, and requires
// `sample.opacity === 1` EXACTLY for this chain check specifically — `OPACITY_TOLERANCE` is
// removed; a transient animation/transition settling at a near-1, non-1 value already falls
// inside the existing, documented, ACCEPTED "ancestor CSS transition refuses for the
// transition's own duration" trade-off (THREAT_MODEL.md A7 residual risk), so this closes a
// permanent, not-yet-covered gap rather than opening a new false-refusal class. Deliberately
// scoped to exactly the two reported triggers: `contain`/`will-change` keep their existing,
// documented exclusion (`isChainNodeOk`'s own doc) untouched — neither of those reported bypasses
// used either property, and reversing that exclusion was not needed to close them.
test("a body{isolation:isolate} ancestor plus a low-z-index decoy appended to document.documentElement cannot intercept the real click (reported bypass, critical)", async ({
  context,
  extensionId,
  server,
}) => {
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "bypassisolation");
    await createLoginItem(setupPage, {
      title: "Isolation Bypass Target",
      username: "isolation-user@example.com",
      password: "isolation-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "bypassisolation", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await disableIov2(visit);
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "Isolation Bypass Target", exact: false });
    await expect(realCandidate).toBeVisible({ timeout: 15_000 });
    await expectIov2Disabled(visit);

    const box = await realCandidate.boundingBox();
    if (box === null) {
      throw new Error("adversarial test setup: could not read the real candidate's bounding box");
    }
    await visit.waitForTimeout(150); // let Gate A record a real good sample first

    const diag = await visit.evaluate(() => {
      document.body.style.isolation = "isolate";
      const decoy = document.createElement("div");
      decoy.id = "rizzy-test-isolation-decoy";
      Object.assign(decoy.style, {
        position: "fixed",
        inset: "0",
        zIndex: "1", // far below MAX_Z_INDEX — only needs to beat <body>'s OWN stacking slot
        background: "rgba(10, 10, 10, 0.98)",
        pointerEvents: "none",
      });
      document.documentElement.appendChild(decoy); // a sibling of <body>, not a descendant
      return { bodyIsolation: getComputedStyle(document.body).isolation, decoyZIndex: getComputedStyle(decoy).zIndex };
    });
    expect(diag.bodyIsolation).toBe("isolate");
    expect(diag.decoyZIndex).toBe("1");

    await visit.waitForTimeout(600); // comfortably past any rebuild debounce
    await visit.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    await visit.waitForTimeout(500);

    await expect(visit.locator("#user")).toHaveValue("");
    await expect(visit.locator("#pass")).toHaveValue("");
    await visit.close();
  } finally {
    await page.stop();
  }
});

test("a body{opacity:0.995} ancestor (within the chain check's own visual tolerance) plus a low-z-index decoy appended to document.documentElement cannot intercept the real click (reported bypass, critical)", async ({
  context,
  extensionId,
  server,
}) => {
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "bypassopacitytie");
    await createLoginItem(setupPage, {
      title: "Opacity Tie Bypass Target",
      username: "opacitytie-user@example.com",
      password: "opacitytie-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "bypassopacitytie", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await disableIov2(visit);
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "Opacity Tie Bypass Target", exact: false });
    await expect(realCandidate).toBeVisible({ timeout: 15_000 });
    await expectIov2Disabled(visit);

    const box = await realCandidate.boundingBox();
    if (box === null) {
      throw new Error("adversarial test setup: could not read the real candidate's bounding box");
    }
    await visit.waitForTimeout(150);

    const diag = await visit.evaluate(() => {
      document.body.style.opacity = "0.995"; // within OPACITY_TOLERANCE's old 0.01 visual slack
      const decoy = document.createElement("div");
      decoy.id = "rizzy-test-opacity-tie-decoy";
      Object.assign(decoy.style, {
        position: "fixed",
        inset: "0",
        zIndex: "1",
        background: "rgba(10, 10, 10, 0.98)",
        pointerEvents: "none",
      });
      document.documentElement.appendChild(decoy);
      return { bodyOpacity: getComputedStyle(document.body).opacity };
    });
    expect(diag.bodyOpacity).toBe("0.995");

    await visit.waitForTimeout(600);
    await visit.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    await visit.waitForTimeout(500);

    await expect(visit.locator("#user")).toHaveValue("");
    await expect(visit.locator("#pass")).toHaveValue("");
    await visit.close();
  } finally {
    await page.stop();
  }
});

// Note on false-refusal scope for the isolation/exact-opacity fix below: `contain`/`will-change`
// on `body`/`documentElement` are deliberately NOT touched by this round (see the fix's own
// comment) — and are not usable as a "fill still works" positive control either, since BOTH
// independently make their element a containing block for `position: fixed` descendants (CSS
// Containment / `will-change`'s own spec note, same family as `transform`/`filter`/`perspective`),
// which moves the frame's real rendered position and already fails `rectsMatch` on its own,
// unconditionally, before this round and after it alike (confirmed by direct probe: pre-fix code
// already refuses a real fill against `body{contain:layout}`/`documentElement{will-change:
// transform}`, for a reason that has nothing to do with isolation/opacity). `isolation: isolate`
// has no such side effect (it creates a stacking context only — never a containing block), which
// is exactly why the two sixth-round tests above can isolate the stacking-context question from
// geometry at all. See THREAT_MODEL.md A7 Residual risk for the accepted cost: a page that sets
// `isolation: isolate` or ANY non-1 `opacity` permanently (not transiently) on `body`/`html` for
// an unrelated reason now loses autofill on that page, the same shape as the already-accepted
// permanent-ancestor-property trade-offs documented there.

// Sixth adversarial round. Reported bypass (critical): one CSS rule, no JavaScript DOM
// manipulation — `body::after { content:''; position:fixed; inset:0; z-index:2147483647;
// background:rgba(10,10,10,.95); pointer-events:none; }`. `body` is the frame's own ANCESTOR
// (`document.body.appendChild(frame)`), not a sibling the deep-occluder sibling-walk would ever
// visit — `#scanElementForDeepOccluders`'s own correctness requirement is that `el` must NEVER be
// a node on the frame's ancestor path (an ancestor's `compareDocumentPosition` flag is
// indistinguishable from an earlier sibling's), so `#deepOccluderRects` deliberately never passes
// `body`/`documentElement` themselves to the pseudo-element check it already runs on every
// SIBLING candidate. Per CSS2.1 Appendix E, `::after` is generated as the LAST box in its own
// host's paint order — unconditionally, regardless of when real children were inserted — so
// `body::after`, at a TIED z-index with the frame (`body`'s own real last child), always paints
// above it. Confirmed by direct probe against the real built extension (IOv2 disabled): the real
// click still lands on the hidden menu underneath.
//
// FIXED: a new `#ancestorPseudoOcclusionRects` (`content-script.ts`) checks each ancestor's OWN
// `::before`/`::after` (never a sibling — that walk is unchanged) via the existing
// `pseudoElementTiesMaxZIndex` (`menu-visibility.ts`), substituting the full viewport whenever one
// ties the frame's maximum z-index. This needs no tree-order reasoning the way the sibling walk
// does: an ancestor's own generated content is unconditionally last in THAT ancestor's own paint
// order, so it always follows the frame (one of its real descendants) regardless of insertion
// order — only a TIE (never a strictly lower z-index) lets it win, which `pseudoElementTiesMaxZIndex`
// already encodes.
test("an opaque body::after tying the frame's own maximum z-index cannot intercept the real click (reported bypass, critical)", async ({
  context,
  extensionId,
  server,
}) => {
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "bypassbodyafter");
    await createLoginItem(setupPage, {
      title: "Body After Bypass Target",
      username: "bodyafter-user@example.com",
      password: "bodyafter-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "bypassbodyafter", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await disableIov2(visit);
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "Body After Bypass Target", exact: false });
    await expect(realCandidate).toBeVisible({ timeout: 15_000 });
    await expectIov2Disabled(visit);

    const box = await realCandidate.boundingBox();
    if (box === null) {
      throw new Error("adversarial test setup: could not read the real candidate's bounding box");
    }
    await visit.waitForTimeout(150);

    const diag = await visit.evaluate(() => {
      const style = document.createElement("style");
      style.textContent =
        "body::after { content: \"\"; position: fixed; inset: 0; z-index: 2147483647; background: rgba(10, 10, 10, 0.95); pointer-events: none; }";
      document.head.appendChild(style);
      const after = getComputedStyle(document.body, "::after");
      return { afterZIndex: after.zIndex };
    });
    expect(diag.afterZIndex).toBe("2147483647");

    await visit.waitForTimeout(600);
    await visit.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    await visit.waitForTimeout(500);

    await expect(visit.locator("#user")).toHaveValue("");
    await expect(visit.locator("#pass")).toHaveValue("");
    await visit.close();
  } finally {
    await page.stop();
  }
});

// False-refusal check (not a reported bypass): `#ancestorPseudoOcclusionRects` must not flag an
// ORDINARY decorative `::after`/`::before` on `body`/`documentElement` — only one that is both
// `position: fixed`/`absolute` (never `static`, per `pseudoElementTiesMaxZIndex`) AND ties the
// frame's own exact maximum z-index. A modest, everyday z-index (page decoration, a themed
// background accent) must keep filling normally, the same "only ever refuse more" scoping round
// four's structurally identical `pushPseudoOcclusionRect` positive control confirmed (line 2861).
test("an ordinary decorative body::after (position: absolute, modest z-index) does not break autofill (false-refusal check)", async ({
  context,
  extensionId,
  server,
}) => {
  const page = await startLoginPageServer();
  try {
    const setupPage = await context.newPage();
    const secretKey = await signUp(setupPage, server.origin, "ordinarybodyafter");
    await createLoginItem(setupPage, {
      title: "Ordinary Body After Target",
      username: "ordinarybodyafter-user@example.com",
      password: "ordinarybodyafter-target-password",
      websiteUrl: `http://127.0.0.1:${page.port}/`,
    });
    await setupPage.close();

    const popup = await enrol(context, extensionId, server, "ordinarybodyafter", secretKey);
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.close();

    const visit = await context.newPage();
    await visit.goto(`http://127.0.0.1:${page.port}/`);
    await visit.evaluate(() => {
      const style = document.createElement("style");
      style.textContent =
        "body::after { content: \"\"; position: absolute; top: 0; left: 0; width: 20px; height: 20px; z-index: 5; background: rgba(0, 100, 200, 0.6); pointer-events: none; }";
      document.head.appendChild(style);
    });
    const menu = visit.frameLocator("iframe[data-rizzy-inline-menu]");
    const realCandidate = menu.getByRole("button", { name: "Ordinary Body After Target", exact: false });
    await expect(realCandidate).toBeVisible({ timeout: 15_000 });
    const box = await realCandidate.boundingBox();
    if (box === null) {
      throw new Error("adversarial test setup: could not read the real candidate's bounding box");
    }
    await visit.waitForTimeout(150);

    await visit.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    await expect(visit.locator("#user")).toHaveValue("ordinarybodyafter-user@example.com", { timeout: 15_000 });
    await expect(visit.locator("#pass")).toHaveValue("ordinarybodyafter-target-password", { timeout: 15_000 });
    await visit.close();
  } finally {
    await page.stop();
  }
});

// Sixth adversarial round. Reported bypass (critical) — NOT a Gate A/B/C occlusion gap, and NOT
// fixed here. `src/inline-menu/index.html` is `web_accessible_resources` to ANY http(s) origin
// (`manifest.chromium.json`), with no instance/frame identity check of any kind: the background's
// `isInlineMenuSender` (`messaging/sender.ts:120-123`) authorizes a privileged request (reveal a
// credential, generate a password) from ANY document whose `sender.id`/`sender.origin` are this
// extension's own — never checking WHICH `<iframe>` sent it, or whether it is the one
// `content-script.ts` itself constructed. A hostile page can embed a SECOND, attacker-controlled
// iframe pointing at that exact same resource; its "Generate password" button
// (`inline-menu/main.ts`, built unconditionally, independent of any `postMessage` from a real
// content script) needs one ordinary trusted click — the attacker's OWN iframe, styled however
// they like, so none of Gates A/B/C (which only ever instrument the ONE iframe
// `content-script.ts`'s own `InlineMenu` constructor builds) are even in play. The generated
// value is pushed to the TAB's content script as `apply_fill`
// (`content-handler.ts`'s `handleInlineMenuGeneratePasswordRequest`) and written into whatever
// field the REAL `InlineMenu` instance is anchored to (`activeFillTargets.passwordField`) —
// gated only on THAT instance's own Gate B (`content-script.ts`'s `apply_fill` listener), which
// is trivially satisfied whenever the real menu is just sitting on the page unattacked (the
// ordinary case: any page with a password field shows the real menu and its "Generate password"
// button unconditionally, `wireInlineMenu`'s own doc, "gap 32").
//
// REPRODUCED against the real built extension (confirmed by direct probe, Chromium, Gates A/B/C
// all left at their default/fixed post-sixth-round state — this path never touches any of them):
// a real trusted Playwright click on the CLONED iframe's own "Generate password" button caused a
// freshly generated password to land in the page's own `#pass` field, with no interaction with
// the real inline-menu iframe at all.
//
// NOT FIXED: closing this needs the background to tell the real inline-menu iframe apart from an
// attacker's clone of the same extension-origin resource — a frame-identity or per-instance-token
// concept `isInlineMenuSender`/ADR 0040's message shape does not have today. That is an
// authentication/protocol change (CLAUDE.md's ADR gate: "Never implement … authentication,
// protocol … without [an Accepted ADR]"), which is the owner's call, not a bypass-triage fix —
// the exact same reasoning this file already applied to the second adversarial round's
// "unrelated DOM mutation racing a rebuild" report ("threading the clicked instance's identity
// through `apply_fill` would change ADR 0040's message shape, which needs an Accepted ADR
// change, not a bypass triage"). Left as `test.fixme`, with the full reproduction kept (not
// emptied out) for whoever picks up the ADR work, and reported to the owner as BLOCKED rather
// than silently left out. Two related reports ride the identical root cause and are not given
// their own test: `inline_menu_fill_chosen`'s informational fields (title/username/savedHost/
// pageHost) are equally forgeable from the same cloned iframe for a genuinely-matching itemId on
// the attacker's own domain (the mechanical two-click/itemId-membership gate is unaffected,
// matching this file's own existing analysis, but the cross-domain warning TEXT the user is
// shown is not), and `src/passkey-consent/index.html` reaches the exact same `isInlineMenuSender`
// sender class on identical terms (`core-host/listener.ts`'s own comment on reusing it "as-is").
// Fixing the root cause fixes all three; none of the three is fixable piecemeal within this
// task's ADR gate.
//
// Verified green (this test body runs and the attack succeeds, i.e. the assertions below pass)
// by temporarily changing `test.fixme` to `test` and running it alone, as of this commit. If a
// future run of it this way FAILS, re-read this comment before assuming the bug is fixed: a
// failure here could equally mean the test itself bit-rotted (selector/button name/helper
// signature drift) rather than the sender model changing — confirm which by reproducing the
// mechanism fresh against whatever code exists then, not by trusting this test's pass/fail alone.
test.fixme(
  "a cloned iframe pointing at the extension's own inline-menu resource can trigger password generation into the real page field — blocked on an ADR (isInlineMenuSender has no frame-identity concept; ADR 0040 would need to change)",
  async ({ context, extensionId, server }) => {
    const page = await startLoginPageServer();
    try {
      const setupPage = await context.newPage();
      const secretKey = await signUp(setupPage, server.origin, "bypassclonediframe");
      await setupPage.close(); // no saved item needed — the generator works with zero candidates

      const popup = await enrol(context, extensionId, server, "bypassclonediframe", secretKey);
      await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
      await popup.close();

      const visit = await context.newPage();
      await visit.goto(`http://127.0.0.1:${page.port}/`);
      // The REAL menu renders unconditionally for any detected password field, even with zero
      // saved candidates (`wireInlineMenu`'s own doc, "gap 32") — no click or focus needed, just
      // like every other test in this file that waits for `iframe[data-rizzy-inline-menu]`.
      await expect(visit.locator("iframe[data-rizzy-inline-menu]")).toHaveCount(1, { timeout: 15_000 });
      await visit.waitForTimeout(150);

      // The attacker's OWN iframe, pointing at the exact same extension resource, visible and
      // clickable (no occlusion trick needed — Gates A/B/C never run against this iframe at all).
      // Positioned away from the real target field on purpose: overlapping it would make this
      // test's OWN clone trip `content-script.ts`'s unrelated, legitimate `isTopmost` occlusion
      // check on the FIELD itself (ADR 0037 §5's "no hidden/invisible field fill"), which would
      // make the real menu fail to rebuild for a reason that has nothing to do with the
      // sender-identity bug this test is about — confirmed by direct probe: an overlapping clone
      // position breaks reproduction via that confound, not via any fix.
      await visit.evaluate((extId) => {
        const clone = document.createElement("iframe");
        clone.id = "rizzy-test-hostile-clone";
        clone.src = `chrome-extension://${extId}/src/inline-menu/index.html`;
        Object.assign(clone.style, { position: "fixed", right: "0", bottom: "0", width: "320px", height: "160px", zIndex: "1" });
        document.body.appendChild(clone);
      }, extensionId);

      // The clone's own insertion is a real (non-"own-overlay") DOM mutation, so
      // `content-script.ts`'s field-redetection debounce (250ms) tears down and rebuilds the
      // REAL menu once before settling — confirmed by direct probe (see the comment above this
      // test) — so this waits past that rebuild, not just past the click round trip.
      const clone = visit.frameLocator("iframe#rizzy-test-hostile-clone");
      const generateButton = clone.getByRole("button", { name: "Generate password" });
      await expect(generateButton).toBeVisible({ timeout: 15_000 });
      await visit.waitForTimeout(600);
      await generateButton.click();
      await visit.waitForTimeout(800);

      const generated = await visit.locator("#pass").inputValue();
      expect(generated.length).toBeGreaterThan(8);
      await visit.close();
    } finally {
      await page.stop();
    }
  },
);
