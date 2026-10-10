// SPDX-License-Identifier: AGPL-3.0-only

// Signup and item creation through the real web vault's own UI (`apps/web/e2e/vault.spec.ts`'s
// `signUp`/`newItem` pattern, duplicated here for the same reason as `server.ts`: separate
// `tsconfig.json` trees, one small self-contained helper). The extension has no signup flow of
// its own (ADR 0036 §3: "Enrolment follows CRYPTO.md §11.2... The Emergency Kit flow does not
// re-run; the extension is a later device, not a signup") — a test account has to exist before
// there is anything to enrol a device *onto*, so this drives the one UI that can create one.
import { type Page, expect } from "@playwright/test";

export const TEST_ACCOUNT_PASSWORD = "correct horse battery staple";

/** Signs up `loginName` on the server at `origin` and confirms the Emergency Kit. Returns the
 * Secret Key, the one value besides the login name and password that enrolling a device needs
 * (CRYPTO.md §11.2). */
export async function signUp(page: Page, origin: string, loginName: string): Promise<string> {
  await page.goto(origin);
  await page.getByRole("button", { name: "Create an account" }).click();
  await page.getByLabel("Login name").fill(loginName);
  await page.getByLabel("Master password", { exact: true }).fill(TEST_ACCOUNT_PASSWORD);
  await page.getByLabel("Repeat the master password", { exact: true }).fill(TEST_ACCOUNT_PASSWORD);
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByTestId("emergency-kit")).toBeVisible();
  const secretKey = (await page.getByTestId("kit-secret-key").textContent()) ?? "";
  await page.getByLabel(/last group of your Secret Key/).fill(secretKey.split("-").at(-1) ?? "");
  await page.getByRole("button", { name: "Create the account" }).click();
  await expect(page.getByRole("button", { name: "Account menu" })).toBeVisible();
  return secretKey;
}

/** Logs in to the web vault (a fresh page, or the same page reloaded — the ephemeral web
 * vault's session holds nothing across a reload, `apps/web/e2e/vault.spec.ts`'s own "reload
 * (nothing persists) → log in again") with `loginName`/`secretKey`/the test account's fixed
 * password. Used to confirm, from a second, independent session, that an item the extension's
 * durable device created and synced really reached the server. */
export async function logIn(page: Page, origin: string, loginName: string, secretKey: string): Promise<void> {
  await page.goto(origin);
  await page.getByLabel("Login name").fill(loginName);
  await page.getByLabel("Secret Key", { exact: true }).fill(secretKey);
  await page.getByLabel("Master password", { exact: true }).fill(TEST_ACCOUNT_PASSWORD);
  // The extension's own inline menu anchors to this page's "Master password" field (it is a
  // password-shaped input like any other) and can geometrically overlap the Log in/Unlock
  // button below it. A real click there lands a `mousedown` on the page first, which blurs the
  // field and tears the menu down (`content-script.ts`'s `InlineMenu`, `#onBlur`); a Playwright
  // locator click runs its actionability check — including "not obscured" — before dispatching
  // any mouse event, so that blur never happens and the click retries against the menu forever.
  // Worse, `wireInlineMenu` rebuilds the menu on *any* qualifying DOM mutation regardless of
  // current focus (`content-script.ts`'s `report`/`schedule`), so even a one-shot blur can lose
  // a race against a menu that reappears a moment later from an unrelated page re-render. Retry
  // the whole focus → blur → wait-absent → click sequence (`toPass`) rather than doing it once:
  // each attempt forces a fresh blur event (destroying whatever menu is currently live) and then
  // races the click against the next possible recreation, so it only fails for good if the menu
  // keeps winning that race for the full ten seconds — a real anomaly, not routine flake.
  const masterPassword = page.getByLabel("Master password", { exact: true });
  const loginButton = page.getByRole("button", { name: /^(Log in|Unlock)$/ });
  await expect(async () => {
    await masterPassword.focus();
    await masterPassword.blur();
    await expect(page.locator("iframe[data-rizzy-inline-menu]")).toHaveCount(0, { timeout: 500 });
    await loginButton.click({ timeout: 500 });
  }).toPass({ timeout: 10_000 });
  await expect(page.getByRole("button", { name: "Account menu" })).toBeVisible();
}

/** Creates one Login item with a single website URI, through the vault's own "New item" UI.
 * `websiteUrl` is saved verbatim as the item's one URI (ADR 0037 §2's normalisation happens at
 * match time, not at save time) — the extension's autofill matching tests use this to seed an
 * item whose saved URI matches exactly one of the test's two local pages. */
export async function createLoginItem(
  page: Page,
  input: { readonly title: string; readonly username: string; readonly password: string; readonly websiteUrl: string },
): Promise<void> {
  await page.getByRole("button", { name: "New item" }).click();
  await page.getByRole("menuitem", { name: "Login" }).click();
  await page.getByLabel("Title").fill(input.title);
  await page.getByLabel("Username", { exact: true }).fill(input.username);
  await page.getByLabel("Password", { exact: true }).fill(input.password);
  await page.getByRole("button", { name: "Add a website" }).click();
  await page.getByLabel("New website 1", { exact: true }).fill(input.websiteUrl);
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: input.title })).toBeVisible();
  await expect(page.getByText("Synced", { exact: true })).toBeVisible();
}
