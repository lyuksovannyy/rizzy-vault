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
  await page.getByRole("button", { name: /^(Log in|Unlock)$/ }).click();
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
