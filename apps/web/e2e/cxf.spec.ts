// SPDX-License-Identifier: AGPL-3.0-only

// Passkey import and export through the FIDO Credential Exchange Format (ADR 0074), in the real
// browser against a real server: a bare CXF file of another product (the CXF 1.0 Proposed
// Standard's own Appendix A example, trimmed to its passkey item and one item without a
// passkey) is recognised and imported, and its passkey shows on a new Login; the passkey export
// is gated like the plaintext one (re-authentication, its own warning, a 10-second countdown,
// the typed phrase) and writes a sealed file; a second account imports that file with its
// password and sees the passkey. The dialog is in the axe audit and the keyboard walk too
// (`a11y.spec.ts`, `keyboard-nav.spec.ts`).
import { readFile } from "node:fs/promises";

import { expect, type Page, test } from "@playwright/test";

import { expectAccessible, expectFocusTrapped } from "./a11y.ts";
import { PASSWORD, signUp, watch } from "./helpers.ts";
import { type RunningServer, startServer } from "./server.ts";

let server: RunningServer;

test.beforeAll(async () => {
  server = await startServer();
});

test.afterAll(() => {
  server.stop();
});

/** CXF 1.0 PS errata (2026-03-09), Appendix A: the GitHub item (no passkey) and the WebAuthn.io
 *  passkey item, values unchanged. */
const BARE_CXF = JSON.stringify({
  version: { major: 1, minor: 0 },
  exporterRpId: "exporter.example.com",
  exporterDisplayName: "Exporter app",
  timestamp: 1705228800,
  accounts: [
    {
      id: "DZSXp7iBQY-Fg-OofakQtQ",
      username: "jane_smith",
      email: "jane.smith@example.com",
      collections: [],
      items: [
        {
          id: "9OF-QjVDQo2Wp2xWPw6ZhA",
          title: "GitHub Login",
          credentials: [
            { type: "basic-auth", username: { id: "-eZX0Gw-TzOsBFwt67N7ZA", fieldType: "string", value: "johndoe" } },
            { type: "totp", secret: "JBSWY3DPEHPK3PXP", period: 30, digits: 6, algorithm: "sha256" },
          ],
        },
        {
          id: "akKA3Y0jQRuK7sKplB0Y9w",
          title: "WebAuthn.io",
          credentials: [
            {
              type: "passkey",
              credentialId: "Y3JlZGVudGlhbElkRXhhbXBsZQ",
              rpId: "webauthn.io",
              username: "johndoe",
              userDisplayName: "John Doe",
              userHandle: "cnEzaNHWcYK3coWZjvoaV1Hj9gnI12mKe2dL2HZVFlY",
              key: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgARu_0sCt20EpgVxb4Puq3Ga5VVLpuTY75ngvZlyq3X6hRANCAASmdk1xLsK0oOlhxIPp0d1ZuS0sT9nf6BZtSelhqvLBW0fOL33l_bXgsr_STUHjCLn8l6gcRJwe7OQvbQubZ1dY",
            },
          ],
        },
      ],
    },
  ],
});

/** Confirms the Secret Key and master password on the export pane. */
async function reauthenticate(page: Page, secretKey: string): Promise<void> {
  await page.getByLabel("Secret Key", { exact: true }).fill(secretKey);
  await page.getByLabel("Master password", { exact: true }).fill(PASSWORD);
  await page.getByRole("button", { name: "Confirm", exact: true }).click();
}

/** Opens the item named `name` and checks its passkey row shows `rpId`. */
async function expectPasskey(page: Page, name: string, rpId: string): Promise<void> {
  await page.getByRole("button", { name: "All items", exact: true }).click();
  await page.getByRole("button", { name: new RegExp(name) }).first().click();
  await expect(page.getByRole("heading", { name })).toBeVisible();
  await expect(page.locator("[data-passkey]")).toHaveCount(1);
  await expect(page.locator("[data-passkey]").first()).toContainText(rpId);
}

test("import a CXF passkey file, export the passkeys, and import them into a second account", async ({
  browser,
}) => {
  const FILE_PASSWORD = "a password for the passkey file";
  // A context per account: axe (`expectAccessible`) needs a page of its own context.
  const first = await (await browser.newContext({ acceptDownloads: true })).newPage();
  const { problems } = watch(first);
  const firstKey = await signUp(first, server.origin, "cxfexporter");

  // A bare CXF file: recognised from its bytes, imported without a password; the item without
  // a passkey and the two other credentials are counted, not imported.
  await first.getByRole("button", { name: "Export and import", exact: true }).click();
  await first.getByLabel("File", { exact: true }).setInputFiles({
    name: "passkeys.json",
    mimeType: "application/json",
    buffer: Buffer.from(BARE_CXF, "utf8"),
  });
  await expect(first.getByTestId("import-detected")).toHaveText(
    "Recognised: CXF passkey file (FIDO Credential Exchange Format).",
  );
  await expect(first.getByLabel("Password of this export file", { exact: true })).toHaveCount(0);
  await first.getByRole("button", { name: "Import", exact: true }).click();
  await expect(first.getByTestId("import-report")).toContainText("Imported 1, skipped 1");
  await expect(first.getByTestId("import-report")).toContainText(
    "CXF credentials not imported (only passkeys are): 2.",
  );
  await expectPasskey(first, "John Doe", "webauthn.io");
  await expect(first.getByText("Synced", { exact: true })).toBeVisible();

  // The passkey export: re-authentication, then the dialog with its own warning and the hold.
  await first.getByRole("button", { name: "Export and import", exact: true }).click();
  await reauthenticate(first, firstKey);
  await expect(first.getByTestId("cxf-count")).toHaveText("Passkeys to export: 1.");
  await first.getByRole("button", { name: "Export passkeys…" }).click();
  const dialog = first.getByRole("dialog", { name: "Export passkeys (CXF)" });
  await expect(dialog.getByTestId("cxf-warning")).toContainText("standard CXF credential-exchange document");
  await expect(dialog.getByLabel("Password for this export file", { exact: true })).toBeFocused();
  await expectAccessible(first, "passkey-export dialog");
  await expectFocusTrapped(first, dialog, "passkey-export dialog");
  const confirm = dialog.getByRole("button", { name: "Export passkeys", exact: true });
  await expect(confirm).toBeDisabled();
  await expect(dialog.getByTestId("cxf-countdown")).toContainText("continue in");
  await dialog.getByLabel("Password for this export file", { exact: true }).fill(FILE_PASSWORD);
  await dialog.getByLabel("Repeat the password for this export file", { exact: true }).fill(FILE_PASSWORD);
  await dialog.getByLabel(/to continue/).fill("EXPORT PLAINTEXT");
  await expect(confirm).toBeEnabled({ timeout: 13_000 });
  const [download] = await Promise.all([first.waitForEvent("download"), confirm.click()]);
  expect(download.suggestedFilename()).toMatch(/^rizzy-vault-passkeys-\d{4}-\d{2}-\d{2}\.json$/);
  const exportPath = await download.path();
  const sealed = (await readFile(exportPath)).toString("utf8");
  expect(sealed.startsWith('{"format":"rizzy-vault-cxf-export","version":1,')).toBe(true);
  // Sealed: nothing of the CXF document is readable in the file.
  expect(sealed).not.toContain("webauthn.io");
  expect(sealed).not.toContain("passkey");
  await expect(first.getByText("Wrote 1 passkeys, encrypted.")).toBeVisible();
  // One export per confirmation.
  await expect(first.getByRole("button", { name: "Confirm", exact: true })).toBeVisible();
  expect(problems).toEqual([]);

  // A second account imports the sealed file with its password.
  const second = await (await browser.newContext({ acceptDownloads: true })).newPage();
  await signUp(second, server.origin, "cxfimporter");
  await second.getByRole("button", { name: "Export and import", exact: true }).click();
  await second.getByLabel("File", { exact: true }).setInputFiles(exportPath);
  await expect(second.getByTestId("import-detected")).toHaveText(
    "Recognised: rizzy-vault passkey export (CXF, encrypted).",
  );
  await second.getByLabel("Password of this export file", { exact: true }).fill("wrong");
  await second.getByRole("button", { name: "Import", exact: true }).click();
  await expect(second.locator('[data-code="export_decryption_failed"]')).toBeVisible();
  await second.getByLabel("Password of this export file", { exact: true }).fill(FILE_PASSWORD);
  await second.getByRole("button", { name: "Import", exact: true }).click();
  await expect(second.getByTestId("import-report")).toContainText("Imported 1, skipped 0");
  // The export names each passkey's user from the login's username (ADR 0074 §2), which the
  // import makes the new item's name (§3).
  await expectPasskey(second, "johndoe", "webauthn.io");
});
