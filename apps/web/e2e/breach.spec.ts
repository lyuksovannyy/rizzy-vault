// SPDX-License-Identifier: AGPL-3.0-only

// The Watchtower breach check end to end (ADR 0053; `src/views/PasswordHealth.tsx`), against the
// real server for the vault and a mocked `icons` egress: `/api/v1/icons/breach-range` is routed
// in the browser context, so no request ever reaches Have I Been Pwned. It checks what leaves
// the browser (the 5-character prefix and nothing else: no Authorization header, no suffix, no
// password; INV-77), the item view's check, the generator's check, the "Password health"
// report, the "not enabled" state of a server without the route, and the rate-limit retry. Each
// new state passes the axe audit (`a11y.ts`), and the report and the item check are walked with
// the keyboard alone (`tabTo`), as `a11y.spec.ts` and `keyboard-nav.spec.ts` do for the
// other screens.
import { type BrowserContext, type Page, expect, test } from "@playwright/test";

import { expectAccessible, tabTo } from "./a11y.ts";
import { newItem, signUp, watch } from "./helpers.ts";
import { type RunningServer, startServer } from "./server.ts";

let server: RunningServer;

test.beforeAll(async () => {
  server = await startServer();
});

test.afterAll(() => {
  server.stop();
});

/** SHA-1("password") = 5BAA6 1E4C9B93F3F0682250B6CF8331B7EE68FD8 (HIBP's documented example). */
const BREACHED = "password";
const PREFIX = "5BAA6";
const SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";
const RANGE = `0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n${SUFFIX}:52256179\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:0`;

/** What the mocked egress saw. */
interface Seen {
  bodies: string[];
  authorization: (string | undefined)[];
}

/** Routes the breach-check endpoint of `context` to a mock answering `RANGE` (or, while
 * `limited` is above zero, `429`), and records every request. */
async function mockEgress(context: BrowserContext, options: { limited?: number } = {}): Promise<Seen> {
  const seen: Seen = { bodies: [], authorization: [] };
  let limited = options.limited ?? 0;
  await context.route("**/api/v1/icons/breach-range", async (route) => {
    const request = route.request();
    seen.bodies.push(request.postData() ?? "");
    seen.authorization.push(request.headers()["authorization"]);
    if (limited > 0) {
      limited -= 1;
      await route.fulfill({
        status: 429,
        contentType: "application/json",
        headers: { "Retry-After": "1" },
        body: '{"error":"rate_limited"}',
      });
      return;
    }
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ range: RANGE }) });
  });
  return seen;
}

/** Only the prefix, as the one field, without a session token, and nothing of the suffix. */
function expectOnlyPrefixes(seen: Seen): void {
  expect(seen.bodies.length).toBeGreaterThan(0);
  for (const body of seen.bodies) {
    expect(body).toMatch(/^\{"prefix":"[0-9A-F]{5}"\}$/);
    expect(body).not.toContain(SUFFIX.slice(0, 8));
    expect(body).not.toContain(BREACHED);
  }
  for (const auth of seen.authorization) {
    expect(auth).toBeUndefined();
  }
}

/** Saves a Login item titled `title` with `password`. */
async function saveLogin(page: Page, title: string, password: string): Promise<void> {
  await newItem(page, "Login");
  await page.getByLabel("Title").fill(title);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: title })).toBeVisible();
  await expect(page.getByText("Synced", { exact: true })).toBeVisible();
}

test("breach check: an item's password, sending only the prefix", async ({ page, context }) => {
  const { problems } = watch(page);
  const seen = await mockEgress(context);
  await signUp(page, server.origin, "breachitem");
  await saveLogin(page, "Breached site", BREACHED);

  await page.getByRole("button", { name: "Check for breaches" }).click();
  const result = page.getByTestId("item-breach-result");
  await expect(result).toContainText("Found in known data breaches (seen 52,256,179 times)");
  await expect(result).toContainText("Change the password on the website");
  expect(seen.bodies).toEqual([`{"prefix":"${PREFIX}"}`]);
  expectOnlyPrefixes(seen);
  // The check needed no reveal: the password is still masked.
  await expect(page.getByRole("button", { name: "Reveal" })).toBeVisible();
  await expectAccessible(page, "item view with a breach result");
  expect(problems).toEqual([]);
});

test("breach check: the generator, and a server without the breach check", async ({ page, context }) => {
  const { problems } = watch(page);
  await signUp(page, server.origin, "breachgen");
  await saveLogin(page, "Unrouted", BREACHED);

  // No mock: this server runs no icons role, so the route answers 404 not_found.
  await page.getByRole("button", { name: "Check for breaches" }).click();
  await expect(page.getByTestId("item-breach-result")).toHaveText("Breach checking is not enabled on this server.");
  await expectAccessible(page, "item view, breach check not enabled");

  const seen = await mockEgress(context);
  await page.getByRole("button", { name: "Generator", exact: true }).click();
  await page.getByRole("button", { name: "Generate" }).click();
  await page.getByRole("button", { name: "Check for breaches" }).click();
  await expect(page.getByTestId("generator-breach-result")).toHaveText("Not found in known data breaches.");
  expectOnlyPrefixes(seen);
  await expectAccessible(page, "generator with a breach result");
  // The 404s of the unrouted check are the server's answers, not page errors.
  expect(problems.filter((p) => !/404/.test(p))).toEqual([]);
});

test("password health: the report, a rate-limit retry, and the keyboard alone", async ({ page, context }) => {
  const { problems } = watch(page);
  const seen = await mockEgress(context, { limited: 1 });
  await signUp(page, server.origin, "breachhealth");
  await saveLogin(page, "Weak one", BREACHED);
  await saveLogin(page, "Strong one", "q7#Zt!2v-Lm9@xP4&Rw8");
  await newItem(page, "Secure note");
  await page.getByLabel("Title").fill("A note");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "A note" })).toBeVisible();

  const kb = page.keyboard;
  await tabTo(page, page.getByRole("button", { name: "Password health" }));
  await kb.press("Enter");
  await expect(page.getByRole("heading", { level: 1, name: "Password health" })).toBeVisible();
  await expect(page.getByText(/first 5 characters of a hash/)).toBeVisible();
  await expectAccessible(page, "password health, before a check");

  await tabTo(page, page.getByRole("button", { name: "Check all passwords" }));
  await kb.press("Enter");
  const status = page.getByTestId("health-status");
  await expect(status).toHaveText("Checked 2 passwords: 1 found in known data breaches.", { timeout: 20_000 });
  // The first answer was a 429: the report waited and asked again.
  expect(seen.bodies.length).toBe(3);
  expectOnlyPrefixes(seen);
  const found = page.getByRole("region", { name: "Found in data breaches" });
  await expect(found.getByRole("button", { name: "Weak one" })).toBeVisible();
  await expect(found.getByRole("button", { name: "Strong one" })).toHaveCount(0);
  await expectAccessible(page, "password health, with a found item");

  // Open the found item and check it again from its view, by keyboard.
  await tabTo(page, found.getByRole("button", { name: "Weak one" }));
  await kb.press("Enter");
  await expect(page.getByRole("heading", { name: "Weak one" })).toBeVisible();
  await tabTo(page, page.getByRole("button", { name: "Check for breaches" }));
  await kb.press("Enter");
  await expect(page.getByTestId("item-breach-result")).toContainText("Found in known data breaches");
  expect(problems.filter((p) => !/429/.test(p))).toEqual([]);
});
