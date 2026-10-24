// SPDX-License-Identifier: AGPL-3.0-only

// Item icons end to end (ADR 0052 point 6; packages/ui `ItemIcon`), against the real server for
// the vault (so its real CSP, `img-src 'self' blob:`, applies) and a mocked `icons` role:
// `/api/v1/icons/fetch` is routed in the browser context, so no request ever reaches a site. It
// checks what leaves the browser (the hostname as the one field, no Authorization header, never
// a full URL), that the browser loads no image from anywhere but the vault's own origin and its
// `blob:` URLs, that the icon shows in the item list and the item header, that an item without
// an icon keeps its type icon, that a rate limit is waited out, and the axe audit of the list
// with icons (the images are decorative: empty `alt`).
import { type BrowserContext, type Page, expect, test } from "@playwright/test";

import { expectAccessible } from "./a11y.ts";
import { ICONS_FETCH_PATH, newItem, signUp, watch } from "./helpers.ts";
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

/** Routes `icons/fetch` of `context` to a mock: an icon for `WITH_ICON`, `404` otherwise, and
 * `429` for the first `limited` requests. Records every request. */
async function mockIcons(context: BrowserContext, options: { limited?: number } = {}): Promise<Seen> {
  const seen: Seen = { bodies: [], authorization: [] };
  let limited = options.limited ?? 0;
  await context.route(`**${ICONS_FETCH_PATH}`, async (route) => {
    const request = route.request();
    const body = request.postData() ?? "";
    seen.bodies.push(body);
    seen.authorization.push(request.headers()["authorization"]);
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
  expect([...seen.bodies].sort()).toEqual(['{"host":"icons.example.test"}', '{"host":"no-icon.example.test"}']);
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
  await signUp(page, server.origin, "iconnone");
  await saveLogin(page, "No role", "https://icons.example.test/");
  const row = page.getByRole("button", { name: /No role/ });
  await expect(row.locator(".row-icon svg")).toBeVisible();
  await expect(row.locator("img")).toHaveCount(0);
  await expectAccessible(page, "item list without the icons role");
  expect(problems).toEqual([]);
});
