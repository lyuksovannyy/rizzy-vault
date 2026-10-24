// SPDX-License-Identifier: AGPL-3.0-only

// Security keys as a second factor (ADR 0058; CRYPTO.md §11.17) with Chromium's virtual
// authenticator over the DevTools protocol (`WebAuthn.enable`, `WebAuthn.addVirtualAuthenticator`:
// CTAP2, USB, user presence answered automatically). The server runs on `localhost`: a browser
// refuses an IP address as an RP ID. Enrolment in Settings → Two-factor authentication, a login
// that asks for the key after the password, removal, the accessibility audit of the section and
// of the login prompt, and the keyboard-only walk through both.
//
// Security keys are touch-only (ADR 0082): the server's options ask for user verification
// "discouraged" and carry no credProtect extension, which Chromium refused with a
// NotSupportedError under the earlier options (credProtect `userVerificationRequired` with
// `userVerification: "preferred"`). Nothing here alters the server's answers: the real options
// reach the browser, and a key that verified its user at enrolment logs in with a touch alone.
import { type CDPSession, type Page, expect, test } from "@playwright/test";

import { expectAccessible, tabTo } from "./a11y.ts";
import { PASSWORD, lockVault, signUp, watch } from "./helpers.ts";
import { type RunningServer, startServer } from "./server.ts";

let server: RunningServer;

test.beforeAll(async () => {
  server = await startServer("localhost");
});

test.afterAll(() => {
  server.stop();
});

/** A virtual CTAP2 security key on `page`. By default it has no user verification (a key with no
 * PIN); `canVerify` gives it built-in user verification, which succeeds until
 * `WebAuthn.setUserVerified` turns it off. */
async function virtualKey(
  page: Page,
  canVerify = false,
): Promise<{ cdp: CDPSession; authenticatorId: string }> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      ctap2Version: "ctap2_1",
      transport: "usb",
      hasResidentKey: false,
      hasUserVerification: canVerify,
      isUserVerified: canVerify,
      automaticPresenceSimulation: true,
    },
  });
  return { cdp, authenticatorId };
}

/** The `publicKey` member of the options in the next answer from `path`, read as served (the
 * Worker's requests included), without touching the answer. */
async function servedOptions(
  page: Page,
  path: string,
): Promise<{
  userVerification?: string;
  authenticatorSelection?: { userVerification?: string };
  extensions?: Record<string, unknown>;
}> {
  const response = await page
    .context()
    .waitForEvent("response", { predicate: (r) => r.url().endsWith(path) });
  const body = (await response.json()) as { options: string };
  return (JSON.parse(body.options) as { publicKey: Record<string, unknown> }).publicKey;
}

/** The accessibility audit (`a11y.ts`). Its runner opens and closes a helper page, after which
 * this page's virtual authenticator no longer answers (observed with Chromium's CDP
 * environment): the tests audit before attaching it, or attach a fresh one holding the same
 * credential afterwards (`reattach`). */
async function audit(page: Page, screen: string): Promise<void> {
  await expectAccessible(page, screen);
  await page.bringToFront();
}

/** One credential of a virtual authenticator, as `WebAuthn.getCredentials` lists it. */
type VirtualCredential = Parameters<typeof addCredential>[1];

/** `WebAuthn.addCredential` with a typed credential. */
async function addCredential(
  key: { cdp: CDPSession; authenticatorId: string },
  credential: {
    credentialId: string;
    isResidentCredential: boolean;
    rpId?: string;
    privateKey: string;
    userHandle?: string;
    signCount: number;
  },
): Promise<void> {
  await key.cdp.send("WebAuthn.addCredential", { authenticatorId: key.authenticatorId, credential });
}

/** A fresh virtual key holding `credential` (from `WebAuthn.getCredentials`). */
async function reattach(
  page: Page,
  credential: VirtualCredential,
): Promise<{ cdp: CDPSession; authenticatorId: string }> {
  const key = await virtualKey(page);
  await addCredential(key, credential);
  return key;
}

/** Opens Settings → Two-factor authentication's security-key section. */
async function openSecurityKeys(page: Page) {
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  const section = page.getByRole("region", { name: "Security keys" });
  await expect(section).toBeVisible();
  return section;
}

/** Unlocks after a lock, up to the point where the security-key prompt opens. */
async function unlockToKeyPrompt(page: Page, secretKey: string) {
  await lockVault(page);
  await page.getByLabel("Secret Key", { exact: true }).fill(secretKey);
  await page.getByLabel("Master password", { exact: true }).fill(PASSWORD);
  await page.getByRole("button", { name: "Unlock" }).click();
  const prompt = page.getByRole("dialog", { name: "Security key" });
  await expect(prompt).toBeVisible();
  return prompt;
}

test("security key: enrol, log in with it, remove it", async ({ page }) => {
  const { problems } = watch(page);
  const secretKey = await signUp(page, server.origin, "keyuser");

  const section = await openSecurityKeys(page);
  await expect(section.getByText("No security key yet.")).toBeVisible();
  await audit(page, "settings: security keys (none)");
  const { cdp, authenticatorId } = await virtualKey(page);
  // ADR 0082 owner answer: enrolment tells the user a key may ask for its PIN once.
  await expect(section.getByLabel("Name for the new key")).toHaveAccessibleDescription(/ask for their PIN or fingerprint once/);
  await section.getByLabel("Name for the new key").fill("Desk key");
  await section.getByRole("button", { name: "Add security key" }).click();
  await expect(section.getByText('Security key "Desk key" added.')).toBeVisible();
  const list = section.getByRole("list", { name: "Your security keys" });
  await expect(list.getByRole("listitem")).toHaveCount(1);
  await expect(list).toContainText("Desk key");
  const { credentials } = await cdp.send("WebAuthn.getCredentials", { authenticatorId });
  expect(credentials).toHaveLength(1);
  const enrolled = credentials[0];
  if (enrolled === undefined) {
    throw new Error("no credential");
  }
  expect(enrolled.rpId).toBe("localhost");
  expect(enrolled.isResidentCredential).toBe(false);
  await audit(page, "settings: security keys (one)");

  // The next login asks for the key after the password and Secret Key.
  const prompt = await unlockToKeyPrompt(page, secretKey);
  await expect(prompt.getByRole("button", { name: "Use security key" })).toBeFocused();
  await expect(prompt.getByRole("button", { name: "Use a code instead" })).toHaveCount(0);
  await audit(page, "login: security-key prompt");
  const again = await reattach(page, enrolled);
  await prompt.getByRole("button", { name: "Use security key" }).click();
  await expect(page.getByRole("button", { name: "Account menu" })).toBeVisible();
  const after = await again.cdp.send("WebAuthn.getCredentials", {
    authenticatorId: again.authenticatorId,
  });
  expect(after.credentials[0]?.signCount).toBeGreaterThan(enrolled.signCount);

  // Removal, with a confirmation; then the password alone logs in again.
  const settings = await openSecurityKeys(page);
  await settings.getByRole("button", { name: "Remove security key Desk key" }).click();
  const confirm = page.getByRole("dialog", { name: "Remove this security key?" });
  await audit(page, "settings: remove security key");
  await confirm.getByRole("button", { name: "Remove" }).click();
  await expect(settings.getByText('Security key "Desk key" removed.')).toBeVisible();
  await expect(settings.getByText("No security key yet.")).toBeVisible();
  await lockVault(page);
  await page.getByLabel("Secret Key", { exact: true }).fill(secretKey);
  await page.getByLabel("Master password", { exact: true }).fill(PASSWORD);
  await page.getByRole("button", { name: "Unlock" }).click();
  await expect(page.getByRole("button", { name: "Account menu" })).toBeVisible();
  expect(problems).toEqual([]);
});

test("security key: a key that can verify its user logs in with a touch alone", async ({
  page,
}) => {
  const { problems } = watch(page);
  const secretKey = await signUp(page, server.origin, "touchuser");
  const section = await openSecurityKeys(page);
  // A key with built-in user verification. Chromium has it verify at enrolment even under
  // "discouraged" (observed: flags UP|UV|AT), as CTAP 2.1 keys with a PIN do; the facade's
  // earlier rule then demanded UV at every login.
  const { cdp, authenticatorId } = await virtualKey(page, true);
  const enrolOptions = servedOptions(page, "/api/v1/webauthn/enrol/start");
  await section.getByLabel("Name for the new key").fill("PIN key");
  await section.getByRole("button", { name: "Add security key" }).click();
  const creation = await enrolOptions;
  expect(creation.authenticatorSelection?.userVerification).toBe("discouraged");
  expect(creation.extensions ?? {}).not.toHaveProperty("credentialProtectionPolicy");
  expect(creation.extensions ?? {}).not.toHaveProperty("enforceCredentialProtectionPolicy");
  await expect(section.getByText('Security key "PIN key" added.')).toBeVisible();
  const { credentials } = await cdp.send("WebAuthn.getCredentials", { authenticatorId });
  expect(credentials).toHaveLength(1);

  // From now on the key cannot verify its user: a login that needed UV would fail.
  await cdp.send("WebAuthn.setUserVerified", { authenticatorId, isUserVerified: false });
  const loginOptions = servedOptions(page, "/api/v1/webauthn/login/challenge");
  const prompt = await unlockToKeyPrompt(page, secretKey);
  await prompt.getByRole("button", { name: "Use security key" }).click();
  expect((await loginOptions).userVerification).toBe("discouraged");
  await expect(page.getByRole("button", { name: "Account menu" })).toBeVisible();
  const after = await cdp.send("WebAuthn.getCredentials", { authenticatorId });
  expect(after.credentials[0]?.signCount).toBeGreaterThan(credentials[0]?.signCount ?? 0);
  expect(problems).toEqual([]);
});

test("security key: cancelling the prompt ends that login, the next one works", async ({
  page,
}) => {
  const { problems } = watch(page);
  const secretKey = await signUp(page, server.origin, "keycancel");
  await virtualKey(page);
  const section = await openSecurityKeys(page);
  await section.getByLabel("Name for the new key").fill("Travel key");
  await section.getByRole("button", { name: "Add security key" }).click();
  await expect(section.getByText('Security key "Travel key" added.')).toBeVisible();

  const prompt = await unlockToKeyPrompt(page, secretKey);
  await prompt.getByRole("button", { name: "Cancel" }).click();
  await expect(page.getByText("Login cancelled.")).toBeVisible();
  await expect(page.getByRole("dialog", { name: "Security key" })).toHaveCount(0);
  await page.getByLabel("Secret Key", { exact: true }).fill(secretKey);
  await page.getByLabel("Master password", { exact: true }).fill(PASSWORD);
  await page.getByRole("button", { name: "Unlock" }).click();
  await page
    .getByRole("dialog", { name: "Security key" })
    .getByRole("button", { name: "Use security key" })
    .click();
  await expect(page.getByRole("button", { name: "Account menu" })).toBeVisible();
  expect(problems).toEqual([]);
});

test("keyboard: the security-key section and the login prompt", async ({ page }) => {
  const { problems } = watch(page);
  const secretKey = await signUp(page, server.origin, "keykeyboard");
  await virtualKey(page);
  await openSecurityKeys(page);
  await tabTo(page, page.getByLabel("Name for the new key"));
  await page.keyboard.type("Keyboard key");
  await tabTo(page, page.getByRole("button", { name: "Add security key" }));
  await page.keyboard.press("Enter");
  await expect(page.getByText('Security key "Keyboard key" added.')).toBeVisible();
  await tabTo(page, page.getByRole("button", { name: "Remove security key Keyboard key" }));

  const prompt = await unlockToKeyPrompt(page, secretKey);
  await expect(prompt.getByRole("button", { name: "Use security key" })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("button", { name: "Account menu" })).toBeVisible();

  // Removal by keyboard, the confirmation included.
  await openSecurityKeys(page);
  await tabTo(page, page.getByRole("button", { name: "Remove security key Keyboard key" }));
  await page.keyboard.press("Enter");
  const confirm = page.getByRole("dialog", { name: "Remove this security key?" });
  await expect(confirm).toBeVisible();
  await tabTo(page, confirm.getByRole("button", { name: "Remove" }));
  await page.keyboard.press("Enter");
  await expect(page.getByText('Security key "Keyboard key" removed.')).toBeVisible();
  expect(problems).toEqual([]);
});
