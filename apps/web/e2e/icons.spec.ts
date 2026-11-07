// SPDX-License-Identifier: AGPL-3.0-only

// Item icons end to end (ADR 0052 point 6; packages/ui `ItemIcon`), against the real server for
// the vault (so its real CSP, `img-src 'self' blob:`, applies) and a mocked `icons` role:
// `/api/v1/icons/fetch` is routed in the browser context, so no request ever reaches a site. It
// checks what leaves the browser (the hostname as the one field, no Authorization header, never
// a full URL), that the browser loads no image from anywhere but the vault's own origin and its
// `blob:` URLs, that the icon shows in the item list and the item header, that an item without
// an icon keeps its type icon, that a rate limit is waited out, and the axe audit of the list
// with icons (the images are decorative: empty `alt`).
//
// ADR 0099: the account's website-icons setting (on by default) and the per-session probe
// (`{"host":""}`, which a role answers `400 invalid_request` and a server without one `404`).
// While the setting is off, Playwright's interception sees no `icons/fetch` request at all, not
// even the probe, across a new login too; with the role off, it sees the probe and no host.
import { type BrowserContext, type Locator, type Page, expect, test } from "@playwright/test";

import { expectAccessible } from "./a11y.ts";
import { ICONS_FETCH_PATH, lockVault, logIn, newItem, signUp, watch } from "./helpers.ts";
import { type RunningServer, startServer } from "./server.ts";

let server: RunningServer;

test.beforeAll(async () => {
  server = await startServer();
});

test.afterAll(() => {
  server.stop();
});

/** A 16×16 PNG, as base64url (what the role returns). */
const PNG = "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8_9hAAAAGUlEQVR4nGOQqzjxnxLMMGrAqAGjBgwXAwC6dV0fK4JiqwAAAABJRU5ErkJggg";

/** The host the mock has an icon for. */
const WITH_ICON = "icons.example.test";

interface Seen {
  bodies: string[];
  authorization: (string | undefined)[];
}

/** The probe's body (ADR 0099 §3). */
const PROBE = '{"host":""}';

/** The disclosure under the switch (ADR 0099 §6), after its bold lead "Show website icons.". */
const DISCLOSURE =
  "To show a site's icon, this app sends the site's host name (for example, example.com) to your server, " +
  "which fetches the icon. The host names are sent without your account name, but the people who run your " +
  "server could still link them to your account. This setting applies to all your devices.";

/** Routes `icons/fetch` of `context` to a mock role: the probe answers `400 invalid_request`
 * (`404 not_found` with `role: false`), an icon for `WITH_ICON`, `404` otherwise, and `429` for
 * the first `limited` host requests. Records every request. */
async function mockIcons(context: BrowserContext, options: { limited?: number; role?: boolean } = {}): Promise<Seen> {
  const seen: Seen = { bodies: [], authorization: [] };
  let limited = options.limited ?? 0;
  const role = options.role ?? true;
  await context.route(`**${ICONS_FETCH_PATH}`, async (route) => {
    const request = route.request();
    const body = request.postData() ?? "";
    seen.bodies.push(body);
    seen.authorization.push(request.headers()["authorization"]);
    if (body === PROBE) {
      await route.fulfill(
        role
          ? { status: 400, contentType: "application/json", body: '{"error":"invalid_request"}' }
          : { status: 404, contentType: "application/json", body: '{"error":"not_found"}' },
      );
      return;
    }
    if (limited > 0) {
      limited -= 1;
      await route.fulfill({ status: 429, contentType: "application/json", headers: { "Retry-After": "1" }, body: '{"error":"rate_limited"}' });
      return;
    }
    if (body === JSON.stringify({ host: WITH_ICON })) {
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ content_type: "image/png", data: PNG }) });
    } else {
      await route.fulfill({ status: 404, contentType: "application/json", body: '{"error":"not_found"}' });
    }
  });
  return seen;
}

/** Every image request the page makes, by URL. */
function imageRequests(page: Page): string[] {
  const urls: string[] = [];
  page.on("request", (r) => {
    if (r.resourceType() === "image") {
      urls.push(r.url());
    }
  });
  return urls;
}

/** Saves a Login item titled `title` with one website. */
async function saveLogin(page: Page, title: string, website: string): Promise<void> {
  await newItem(page, "Login");
  await page.getByLabel("Title").fill(title);
  await page.getByRole("button", { name: "Add a website" }).click();
  await page.getByLabel("New website 1", { exact: true }).fill(website);
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: title })).toBeVisible();
  await expect(page.getByText("Synced", { exact: true })).toBeVisible();
}

test("item icons: only the hostname leaves, the icon is a blob: image, the list passes the audit", async ({ page, context }) => {
  const { problems } = watch(page);
  const violations: string[] = [];
  await page.exposeFunction("reportCspViolation", (text: string) => violations.push(text));
  await page.addInitScript(() => {
    document.addEventListener("securitypolicyviolation", (e) => {
      void (window as unknown as { reportCspViolation(t: string): Promise<void> }).reportCspViolation(
        `${e.violatedDirective} ${e.blockedURI}`,
      );
    });
  });
  const seen = await mockIcons(context);
  const images = imageRequests(page);
  await signUp(page, server.origin, "iconlist");

  await saveLogin(page, "Icon site", "https://Icons.Example.TEST/login?next=/secret#frag");
  await saveLogin(page, "Plain site", "https://no-icon.example.test/");

  const iconRow = page.getByRole("button", { name: /Icon site/ });
  const icon = iconRow.locator("img.item-favicon");
  await expect(icon).toBeVisible();
  await expect(icon).toHaveAttribute("alt", "");
  await expect(icon).toHaveAttribute("src", /^blob:/);
  // Decoded: the CSP let the blob: image load.
  await expect.poll(() => icon.evaluate((img: HTMLImageElement) => img.complete && img.naturalWidth)).toBe(16);
  // The item without an icon keeps its type icon.
  const plainRow = page.getByRole("button", { name: /Plain site/ });
  await expect(plainRow.locator(".row-icon svg")).toBeVisible();
  await expect(plainRow.locator("img")).toHaveCount(0);
  // The item header shows the icon too.
  await iconRow.click();
  await expect(page.locator(".item-header img.item-favicon")).toBeVisible();

  // What left the browser: one hostname per host, normalised, nothing else.
  // The probe first, once (ADR 0099 §3).
  expect(seen.bodies[0]).toBe(PROBE);
  expect([...seen.bodies].sort()).toEqual([PROBE, '{"host":"icons.example.test"}', '{"host":"no-icon.example.test"}']);
  for (const auth of seen.authorization) {
    expect(auth).toBeUndefined();
  }
  for (const body of seen.bodies) {
    expect(body).not.toContain("secret");
    expect(body).not.toContain("https");
  }
  // No image from anywhere but the vault and its own blob: URLs.
  for (const url of images) {
    expect(url.startsWith(server.origin) || url.startsWith("blob:")).toBe(true);
  }
  expect(violations).toEqual([]);

  await expectAccessible(page, "item list with icons");
  expect(problems).toEqual([]);
});

test("item icons: a rate limit is waited out, then the icon shows", async ({ page, context }) => {
  const { problems } = watch(page);
  const seen = await mockIcons(context, { limited: 1 });
  await signUp(page, server.origin, "iconlimit");
  await saveLogin(page, "Limited site", "https://icons.example.test/");
  const icon = page.getByRole("button", { name: /Limited site/ }).locator("img.item-favicon");
  await expect(icon).toBeVisible({ timeout: 15_000 });
  expect(seen.bodies.length).toBeGreaterThanOrEqual(2);
  expect(problems.filter((p) => !/429/.test(p))).toEqual([]);
});

test("item icons: a server without the icons role shows the type icons", async ({ page }) => {
  const { problems } = watch(page);
  const bodies = icoBodies(page);
  await signUp(page, server.origin, "iconnone");
  await saveLogin(page, "No role", "https://icons.example.test/");
  const row = page.getByRole("button", { name: /No role/ });
  await expect(row.locator(".row-icon svg")).toBeVisible();
  await expect(row.locator("img")).toHaveCount(0);
  // The real server has no icons role: it answers the probe 404, and no host follows.
  await expect.poll(() => bodies.length).toBe(1);
  expect(bodies).toEqual([PROBE]);
  // Settings says so, under the switch, which stays on.
  const pane = await openIconSettings(page);
  await expect(pane.getByRole("checkbox", { name: "Show website icons." })).toBeChecked();
  await expect(pane.getByText("This server does not offer website icons.", { exact: true })).toBeVisible();
  expect(bodies).toEqual([PROBE]);
  await expectAccessible(page, "item list without the icons role");
  expect(problems).toEqual([]);
});

/** The bodies of every `icons/fetch` request `page` makes, as Playwright sees them. */
function icoBodies(page: Page): string[] {
  const bodies: string[] = [];
  page.on("request", (r) => {
    if (new URL(r.url()).pathname === ICONS_FETCH_PATH) {
      bodies.push(r.postData() ?? "");
    }
  });
  return bodies;
}

/** Opens Settings → Website icons. */
async function openIconSettings(page: Page): Promise<Locator> {
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  const pane = page.getByRole("region", { name: "Website icons" });
  await expect(pane).toBeVisible();
  return pane;
}

test("website icons: a role that is off gets the probe and no host", async ({ page, context }) => {
  const { problems } = watch(page);
  const seen = await mockIcons(context, { role: false });
  await signUp(page, server.origin, "iconroleoff");
  await saveLogin(page, "Role off", "https://icons.example.test/");
  await saveLogin(page, "Role off too", "https://other.example.test/");
  const row = page.getByRole("button", { name: /Role off too/ });
  await expect(row.locator(".row-icon svg")).toBeVisible();
  await expect.poll(() => seen.bodies.length).toBe(1);
  expect(seen.bodies).toEqual([PROBE]);
  expect(seen.authorization).toEqual([undefined]);
  expect(problems.filter((p) => !/404/.test(p))).toEqual([]);
});

test("website icons: on by default, the disclosure always shown; off sends no icons/fetch request", async ({ page, context }) => {
  const { problems } = watch(page);
  const seen = await mockIcons(context);
  const secretKey = await signUp(page, server.origin, "iconoff");
  await saveLogin(page, "Icon site", "https://icons.example.test/");
  await expect(page.getByRole("button", { name: /Icon site/ }).locator("img.item-favicon")).toBeVisible();
  expect(seen.bodies).toEqual([PROBE, '{"host":"icons.example.test"}']);

  // Settings: the switch is on by default, the disclosure under it.
  const pane = await openIconSettings(page);
  const toggle = pane.getByRole("checkbox", { name: "Show website icons." });
  await expect(toggle).toBeChecked();
  await expect(pane.getByText(DISCLOSURE, { exact: true })).toBeVisible();
  await expect(toggle).toHaveAccessibleDescription(DISCLOSURE);
  await expectAccessible(page, "settings with website icons on");

  // Off: written for the account; the disclosure stays.
  // A click, not `uncheck()`: the switch shows the account's value, which changes once the
  // settings commit is answered.
  await toggle.click();
  await expect(toggle).not.toBeChecked();
  await expect(toggle).toBeEnabled();
  await expect(pane.getByText(DISCLOSURE, { exact: true })).toBeVisible();
  await expectAccessible(page, "settings with website icons off");

  // From here on, nothing may reach icons/fetch: not a host, not the probe.
  const before = seen.bodies.length;
  await page.getByRole("button", { name: "All items", exact: true }).click();
  await saveLogin(page, "Other site", "https://icons.example.test/other");
  await expect(page.getByRole("button", { name: /Icon site/ }).locator(".row-icon svg")).toBeVisible();
  await expect(page.getByRole("button", { name: /Icon site/ }).locator("img")).toHaveCount(0);

  // A new session reads the setting from the account: still off, still silent.
  await lockVault(page);
  await logIn(page, undefined, secretKey);
  await expect(page.getByRole("button", { name: /Other site/ })).toBeVisible();
  await expect(page.getByRole("button", { name: /Other site/ }).locator(".row-icon svg")).toBeVisible();
  await page.waitForTimeout(1000);
  expect(seen.bodies.slice(before)).toEqual([]);
  const again = await openIconSettings(page);
  await expect(again.getByRole("checkbox", { name: "Show website icons." })).not.toBeChecked();
  await expect(again.getByText("This server does not offer website icons.")).toHaveCount(0);
  expect(seen.bodies.slice(before)).toEqual([]);

  // On again: one probe, then the host.
  await again.getByRole("checkbox", { name: "Show website icons." }).click();
  await expect(again.getByRole("checkbox", { name: "Show website icons." })).toBeChecked();
  await page.getByRole("button", { name: "All items", exact: true }).click();
  await expect(page.getByRole("button", { name: /Other site/ }).locator("img.item-favicon")).toBeVisible();
  expect(seen.bodies.slice(before)).toEqual([PROBE, '{"host":"icons.example.test"}']);
  expect(problems).toEqual([]);
});
