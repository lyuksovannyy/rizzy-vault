// SPDX-License-Identifier: AGPL-3.0-only

// Shared Playwright helpers for the web vault's end-to-end specs (signup/login/lock, the
// secret-field INV-68 check): kept in one module so `vault.spec.ts`, `keyboard-nav.spec.ts` and
// `phone.spec.ts` exercise login/signup/lock the same way, rather than three copies drifting.
import { type Locator, type Page, expect } from "@playwright/test";

export const PASSWORD = "correct horse battery staple";

/** Collects console errors and page errors of a page. */
export function watch(page: Page): { problems: string[] } {
  const problems: string[] = [];
  page.on("console", (m) => {
    if (m.type() === "error") {
      problems.push(`console: ${m.text()}`);
    }
  });
  page.on("pageerror", (e) => problems.push(`pageerror: ${e.message}`));
  return { problems };
}

/** INV-68 on one secret input, before and after its "Show" toggle. */
export async function checkSecretField(field: Locator): Promise<void> {
  const input = field.locator("input[data-secret-field]");
  await expect(input).toHaveAttribute("type", "password");
  await expect(input).toHaveAttribute("spellcheck", "false");
  await expect(input).toHaveAttribute("autocomplete", "off");
  await field.getByRole("button", { name: "Show" }).click();
  await expect(input).toHaveAttribute("type", "text");
  await field.getByRole("button", { name: "Hide" }).click();
  await expect(input).toHaveAttribute("type", "password");
}

/** The secret field whose label is `label`. */
export function secretField(page: Page, label: string): Locator {
  return page.locator(".secret-field").filter({ has: page.getByLabel(label, { exact: true }) });
}

/** Logs in on the login (or unlock) screen. */
export async function logIn(page: Page, loginName: string | undefined, secretKey: string): Promise<void> {
  if (loginName !== undefined) {
    await page.getByLabel("Login name").fill(loginName);
  }
  await page.getByLabel("Secret Key", { exact: true }).fill(secretKey);
  await page.getByLabel("Master password", { exact: true }).fill(PASSWORD);
  await page.getByRole("button", { name: /^(Log in|Unlock)$/ }).click();
  await expect(page.getByRole("button", { name: "Account menu" })).toBeVisible();
}

/** Signs up `name`, confirms the Emergency Kit and closes the getting-started guide that opens
 * after signup; returns the Secret Key. */
export async function signUp(page: Page, origin: string, name: string): Promise<string> {
  const secretKey = await signUpToGuide(page, origin, name);
  await closeGuide(page);
  return secretKey;
}

/** Leaves the getting-started guide (`src/views/OnboardingView.tsx`) through its "Close the
 * guide" button. */
export async function closeGuide(page: Page): Promise<void> {
  const guide = page.getByRole("region", { name: "Get started" });
  await expect(guide).toBeVisible();
  await guide.getByRole("button", { name: "Close the guide" }).click();
  await expect(guide).toHaveCount(0);
}

/** Signs up `name` and confirms the Emergency Kit, leaving the getting-started guide open;
 * returns the Secret Key. */
export async function signUpToGuide(page: Page, origin: string, name: string): Promise<string> {
  await page.goto(origin);
  await page.getByRole("button", { name: "Create an account" }).click();
  await page.getByLabel("Login name").fill(name);
  await page.getByLabel("Master password", { exact: true }).fill(PASSWORD);
  await page.getByLabel("Repeat the master password", { exact: true }).fill(PASSWORD);
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByTestId("emergency-kit")).toBeVisible();
  const secretKey = (await page.getByTestId("kit-secret-key").textContent()) ?? "";
  await page.getByLabel(/last group of your Secret Key/).fill(secretKey.split("-").at(-1) ?? "");
  await page.getByRole("button", { name: "Create the account" }).click();
  await expect(page.getByRole("button", { name: "Account menu" })).toBeVisible();
  return secretKey;
}

/** Opens the single "New item" menu and chooses `typeLabel` (redesign slice 2, item 5). */
export async function newItem(page: Page, typeLabel: string): Promise<void> {
  await page.getByRole("button", { name: "New item" }).click();
  await page.getByRole("menuitem", { name: typeLabel }).click();
}

/** Locks the vault through the account menu (redesign slice 2, item 5). */
export async function lockVault(page: Page): Promise<void> {
  await page.getByRole("button", { name: "Account menu" }).click();
  await page.getByRole("menuitem", { name: "Lock" }).click();
}
