// SPDX-License-Identifier: AGPL-3.0-only

// The accessibility audit of the web vault's screens (ROADMAP §4.5's accessibility Must; ADR
// 0014 §5): every screen and dialog below passes `expectAccessible` (`a11y.ts`: axe-core's WCAG
// 2.x A/AA and best-practice rules, and Chromium's own accessibility tree), every modal dialog
// keeps the focus inside it (`expectFocusTrapped`), and the vault also passes under the dark
// theme, forced colours (Windows High Contrast emulation) and at phone width. The conflict
// chooser's state is audited in `conflict.spec.ts`; the Sessions section with two sessions, its
// end dialog, its log-in-again form and the login after a session was ended in
// `sessions.spec.ts`; keyboard-only use of these same screens is `keyboard-nav.spec.ts`. A
// Secure Note rendered from its Markdown (ADR 0062) is audited in every one of those modes too.
import { expect, test } from "@playwright/test";
import { createHmac } from "node:crypto";

import { expectAccessible, expectFocusTrapped } from "./a11y.ts";
import {
  MARKDOWN_NOTE,
  PASSWORD,
  dismissToasts,
  logIn,
  lockVault,
  newItem,
  signUp,
  signUpToGuide,
  watch,
} from "./helpers.ts";
import { M3_TYPES, fieldLine, fillAndSave } from "./m3-types.ts";
import { type RunningServer, startServer } from "./server.ts";

let server: RunningServer;

test.beforeAll(async () => {
  server = await startServer();
});

test.afterAll(() => {
  server.stop();
});

test("a11y: signup, login, the guide, the vault, its dialogs and settings", async ({ page }) => {
  const { problems } = watch(page);

  // Login, and the signup form.
  await page.goto(server.origin);
  await expect(page.getByRole("button", { name: "Create an account" })).toBeVisible();
  await expectAccessible(page, "login");
  await page.getByRole("button", { name: "Create an account" }).click();
  await expect(page.getByLabel("Repeat the master password", { exact: true })).toBeVisible();
  await expectAccessible(page, "signup");
  await page.goto(server.origin);

  // The Emergency Kit, then the getting-started guide's steps.
  const secretKey = await signUpToGuide(page, server.origin, "a11yuser");
  const guide = page.getByRole("region", { name: "Get started" });
  await expectAccessible(page, "getting-started guide: step 1");
  await guide.getByRole("checkbox", { name: /I saved my Emergency Kit/ }).check();
  await guide.getByRole("button", { name: "Continue" }).click();
  await expect(guide.getByRole("heading", { name: /^Step 2 of 3/ })).toBeVisible();
  await expectAccessible(page, "getting-started guide: step 2 (import)");
  await guide.getByRole("button", { name: "Skip this step" }).click();
  await expect(guide.getByRole("heading", { name: /^Step 3 of 3/ })).toBeVisible();
  await expectAccessible(page, "getting-started guide: step 3 (extension)");
  await guide.getByRole("button", { name: "Close the guide" }).click();
  await expect(guide).toHaveCount(0);

  // The empty vault list, the new-item menu, the editor and its generate popover.
  await expectAccessible(page, "vault list (empty)");
  await page.getByRole("button", { name: "New item" }).click();
  await expect(page.getByRole("menu", { name: "New item type" })).toBeVisible();
  await expectAccessible(page, "new-item menu");
  await page.getByRole("menuitem", { name: "Login" }).click();
  await expect(page.getByLabel("Title")).toBeVisible();
  await expectAccessible(page, "item editor (new login)");
  await page.getByRole("button", { name: "Generator settings" }).first().click();
  await expect(page.getByRole("group", { name: "Generator settings" })).toBeVisible();
  await expectAccessible(page, "item editor: generator popover");
  await page.keyboard.press("Escape");
  await expect(page.getByRole("group", { name: "Generator settings" })).toHaveCount(0);
  await page.getByLabel("Title").fill("Audit Co");
  await page.getByLabel("Username", { exact: true }).fill("audit@example.com");
  await page.getByLabel("Password", { exact: true }).fill("audit-password-long-enough");
  await page.getByRole("button", { name: "Add a website" }).click();
  await page.getByLabel("New website 1", { exact: true }).fill("https://audit.example.com/");
  await page.getByLabel("Add tags (comma-separated)").fill("audited");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "Audit Co" })).toBeVisible();

  // The item view, a revealed password, and the large-type dialog.
  await expectAccessible(page, "item view");
  const passwordRow = page.locator('[data-field="login.password"]');
  await passwordRow.getByRole("button", { name: "Reveal" }).click();
  await expect(passwordRow.locator("input[data-secret-field]")).toHaveValue("audit-password-long-enough");
  await expectAccessible(page, "item view: password revealed");
  await passwordRow.getByRole("button", { name: "Large type" }).click();
  const largeType = page.getByRole("dialog", { name: "Password" });
  await expectAccessible(page, "large-type dialog");
  await expectFocusTrapped(page, largeType, "large-type dialog");
  await page.keyboard.press("Escape");
  await expect(largeType).toHaveCount(0);

  // The edit form of a saved item.
  await page.getByRole("button", { name: "Edit" }).click();
  await expect(page.getByRole("heading", { name: "Edit item" })).toBeVisible();
  await expectAccessible(page, "item editor (edit)");
  await page.getByRole("button", { name: "Cancel" }).click();
  await expect(page.getByRole("heading", { name: "Audit Co" })).toBeVisible();

  // The trash confirmation (`ConfirmDialog`), cancelled.
  await page.getByRole("button", { name: "Move to trash" }).click();
  const confirm = page.getByRole("dialog", { name: "Move this item to trash?" });
  await expectAccessible(page, "confirm dialog");
  await expectFocusTrapped(page, confirm, "confirm dialog");
  await page.keyboard.press("Escape");
  await expect(confirm).toHaveCount(0);

  // The command palette, with results, and the shortcuts help.
  await page.keyboard.press("Control+k");
  const palette = page.getByRole("dialog", { name: "Command palette" });
  await expect(page.getByRole("combobox", { name: "Command palette" })).toBeFocused();
  await page.keyboard.type("audit");
  await expect(palette.getByRole("option").first()).toBeVisible();
  await expectAccessible(page, "command palette");
  await expectFocusTrapped(page, palette, "command palette");
  await page.keyboard.press("Escape");
  await expect(palette).toHaveCount(0);
  await page.locator("body").press("?");
  const shortcuts = page.getByRole("dialog", { name: "Keyboard shortcuts" });
  await expectAccessible(page, "shortcuts help");
  await expectFocusTrapped(page, shortcuts, "shortcuts help");
  await page.keyboard.press("Escape");
  await expect(shortcuts).toHaveCount(0);

  // The account menu.
  await page.getByRole("button", { name: "Account menu" }).click();
  await expect(page.getByRole("menuitem", { name: "Lock" })).toBeVisible();
  await expectAccessible(page, "account menu");
  await page.keyboard.press("Escape");

  // The generator, export and import (with the plaintext-export dialog), and settings.
  await page.getByRole("button", { name: "Generator", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Generator" })).toBeVisible();
  await expectAccessible(page, "generator");
  await page.getByRole("button", { name: "Export and import", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Export and import" })).toBeVisible();
  await expectAccessible(page, "export and import");
  await page.getByLabel("Secret Key", { exact: true }).fill(secretKey);
  await page.getByLabel("Master password", { exact: true }).fill(PASSWORD);
  await page.getByRole("button", { name: "Confirm", exact: true }).click();
  await expect(page.getByRole("button", { name: "Export encrypted" })).toBeVisible();
  await expectAccessible(page, "export and import: confirmed");
  await page.getByRole("button", { name: "Export in plaintext…" }).click();
  const plaintext = page.getByRole("dialog", { name: /Plaintext export/ });
  await expect(plaintext).toBeVisible();
  await expectAccessible(page, "plaintext-export dialog");
  await expectFocusTrapped(page, plaintext, "plaintext-export dialog");
  await plaintext.getByRole("button", { name: "Cancel" }).click();
  await expect(plaintext).toHaveCount(0);

  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await expect(page.getByRole("region", { name: "What the server stores" })).toBeVisible();
  await expectAccessible(page, "settings (two-factor, devices, appearance, transparency, guide)");

  // The trash, after a real trash.
  await page.getByRole("button", { name: "All items", exact: true }).click();
  await page.getByRole("button", { name: /Audit Co/ }).first().click();
  await page.getByRole("button", { name: "Move to trash" }).click();
  await confirm.getByRole("button", { name: "Move to trash" }).click();
  await page.getByRole("button", { name: "Trash", exact: true }).click();
  await page.getByRole("button", { name: /Audit Co/ }).first().click();
  await expect(page.getByRole("heading", { name: "Audit Co" })).toBeVisible();
  await expectAccessible(page, "trash: a trashed item");

  // The unlock screen.
  await lockVault(page);
  await expect(page.getByRole("button", { name: "Unlock" })).toBeVisible();
  await expectAccessible(page, "unlock");
  await logIn(page, undefined, secretKey);
  expect(problems).toEqual([]);
});

/** The current RFC 6238 code (SHA-1, 6 digits, 30 s) of a Base32 `secret`: the test plays the
 * authenticator app. */
function totpNow(secret: string): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of secret.replace(/=+$/, "").toUpperCase()) {
    bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
  }
  const key = Buffer.from((bits.match(/.{8}/g) ?? []).map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000)));
  const mac = createHmac("sha1", key).update(counter).digest();
  const offset = (mac[mac.length - 1] ?? 0) & 0x0f;
  return String((mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

test("a11y: two-factor setup and the login code prompt", async ({ page }) => {
  const { problems } = watch(page);
  const secretKey = await signUp(page, server.origin, "a11ytotp");
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await page.getByRole("button", { name: "Set up an authenticator app" }).click();
  const setupKey = page.getByLabel("Setup key (Base32)", { exact: true });
  await expect(setupKey).toBeVisible();
  await expectAccessible(page, "settings: two-factor setup");
  await page.getByLabel("Code from the app").fill(totpNow(await setupKey.inputValue()));
  await page.getByRole("button", { name: "Turn on" }).click();
  await expect(page.getByText("Two-factor authentication is on.")).toBeVisible();

  // The next login asks for the code in a modal dialog.
  await lockVault(page);
  await page.getByLabel("Secret Key", { exact: true }).fill(secretKey);
  await page.getByLabel("Master password", { exact: true }).fill(PASSWORD);
  await page.getByRole("button", { name: "Unlock" }).click();
  const prompt = page.getByRole("dialog", { name: "Two-factor code" });
  await expect(prompt.getByLabel("Code")).toBeFocused();
  await expectAccessible(page, "login: two-factor code prompt");
  await expectFocusTrapped(page, prompt, "two-factor code prompt");
  await prompt.getByRole("button", { name: "Cancel" }).click();
  await expect(prompt).toHaveCount(0);
  expect(problems).toEqual([]);
});

test("a11y: the editor and item view of each M3 item type (ADR 0055)", async ({ page }) => {
  const { problems } = watch(page);
  await signUp(page, server.origin, "a11ym3");
  for (const t of M3_TYPES) {
    await newItem(page, t.menu);
    await expect(page.getByRole("heading", { name: t.heading })).toBeVisible();
    await expectAccessible(page, `editor: ${t.menu}`);
    // A multi-line secret (the SSH private key) revealed in the editor, too.
    if (t.menu === "SSH key") {
      await page.locator(".secret-field").filter({ has: page.getByLabel("Private key", { exact: true }) })
        .getByRole("button", { name: "Show" }).click();
      await expectAccessible(page, "editor: SSH key, private key shown");
    }
    await fillAndSave(page, t);
    await expectAccessible(page, `item view: ${t.menu}`);
    // With a concealed value revealed.
    const secret = t.concealed[0];
    if (secret !== undefined) {
      await fieldLine(page, secret.key).getByRole("button", { name: "Reveal" }).click();
      await expect(fieldLine(page, secret.key).locator("[data-secret-field]")).toBeVisible();
      await expectAccessible(page, `item view: ${t.menu}, ${secret.label} revealed`);
    }
    // The sidebar's filter for the type.
    await page.getByRole("button", { name: t.menu, exact: true }).click();
    await expect(page.locator(".row-title")).toHaveText([t.title]);
    await expectAccessible(page, `items: ${t.menu} filter`);
    await page.getByRole("button", { name: "All items", exact: true }).click();
  }
  expect(problems).toEqual([]);
});

test("a11y: dark theme, forced colours and phone width", async ({ page }) => {
  const { problems } = watch(page);
  await page.emulateMedia({ colorScheme: "dark" });
  await page.goto(server.origin);
  await expect(page.getByRole("button", { name: "Create an account" })).toBeVisible();
  await expectAccessible(page, "login (dark)");
  const secretKey = await signUpToGuide(page, server.origin, "a11ythemes");
  await expectAccessible(page, "getting-started guide (dark)");
  await page.getByRole("region", { name: "Get started" }).getByRole("button", { name: "Close the guide" }).click();
  await newItem(page, "Login");
  await page.getByLabel("Title").fill("Theme Co");
  await page.getByLabel("Password", { exact: true }).fill("theme-password-long-enough");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "Theme Co" })).toBeVisible();
  await expectAccessible(page, "item view (dark)");
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await expect(page.getByRole("region", { name: "What the server stores" })).toBeVisible();
  await expectAccessible(page, "settings (dark)");

  // Forced colours (ADR 0014 §5: Windows High Contrast emulation), light and dark.
  for (const colorScheme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme, forcedColors: "active" });
    await page.getByRole("button", { name: "All items", exact: true }).click();
    await page.getByRole("button", { name: /Theme Co/ }).first().click();
    await expect(page.getByRole("heading", { name: "Theme Co" })).toBeVisible();
    await expectAccessible(page, `item view (forced colours, ${colorScheme})`, { forcedColors: true });
    await page.getByRole("button", { name: "Settings", exact: true }).click();
    await expectAccessible(page, `settings (forced colours, ${colorScheme})`, { forcedColors: true });
  }
  await page.emulateMedia({ colorScheme: "light", forcedColors: "none" });

  // Phone width: the single-pane layout and its menu.
  await page.setViewportSize({ width: 375, height: 812 });
  await page.getByRole("button", { name: "Open menu" }).click();
  await expect(page.getByRole("navigation", { name: "Vault navigation" })).toBeVisible();
  await expectAccessible(page, "phone: menu open");
  await page.getByRole("button", { name: "All items", exact: true }).click();
  await expectAccessible(page, "phone: item list");
  await lockVault(page);
  await expectAccessible(page, "phone: unlock");
  await logIn(page, undefined, secretKey);
  expect(problems).toEqual([]);
});

test("a11y: an item's attachments section, its error and its delete dialog (ADR 0054)", async ({ page }) => {
  const { problems } = watch(page);
  await signUp(page, server.origin, "a11yattach");
  await newItem(page, "Login");
  await page.getByLabel("Title").fill("Attachment audit");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "Attachment audit" })).toBeVisible();
  const section = page.getByRole("region", { name: "Attachments" });
  await expect(section.getByText("No attachments.")).toBeVisible();
  await expectAccessible(page, "item view: empty attachments section");
  const input = section.getByLabel("Attach a file");
  await input.setInputFiles({ name: "notes.txt", mimeType: "text/plain", buffer: Buffer.from("hello attachments") });
  await expect(section.locator("li.attachment")).toHaveCount(1);
  await expectAccessible(page, "item view: one attachment");
  await input.setInputFiles({ name: "big.bin", mimeType: "application/octet-stream", buffer: Buffer.alloc(25 * 1024 * 1024 + 1) });
  await expect(section.getByRole("alert")).toBeVisible();
  await expectAccessible(page, "item view: attachment too large");
  await page.emulateMedia({ colorScheme: "dark" });
  await expectAccessible(page, "item view: attachments (dark)");
  await page.emulateMedia({ colorScheme: "light", forcedColors: "active" });
  await expectAccessible(page, "item view: attachments (forced colours)", { forcedColors: true });
  await page.emulateMedia({ colorScheme: "light", forcedColors: "none" });
  // The "Attached" toast is dismissed first: behind the modal dialog it is inert, which the
  // focusable-element check would otherwise report.
  await dismissToasts(page);
  await section.getByRole("button", { name: "Delete notes.txt" }).click();
  const dialog = page.getByRole("dialog", { name: "Delete this attachment?" });
  await expect(dialog).toBeVisible();
  await expectFocusTrapped(page, dialog, "delete attachment");
  await expectAccessible(page, "delete attachment dialog");
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await page.setViewportSize({ width: 375, height: 812 });
  await expectAccessible(page, "item view: attachments (phone width)");
  expect(problems).toEqual([]);
});

test("a11y: a Secure Note rendered from Markdown, in light, dark, forced colours and phone width", async ({ page }) => {
  const { problems } = watch(page);
  await signUp(page, server.origin, "a11ynote");
  await newItem(page, "Secure note");
  await page.getByLabel("Title").fill("Audit note");
  await page.getByLabel("Notes").fill(MARKDOWN_NOTE);
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "Audit note" })).toBeVisible();
  const rendered = page.locator('[data-field="item.notes"] .md-note');
  await expect(rendered.getByRole("heading", { name: "Wi-Fi and alarm", level: 1 })).toBeVisible();
  await expect(rendered.getByRole("heading", { name: "Six", level: 6 })).toBeVisible();
  await expect(rendered.getByRole("list")).toHaveCount(2);
  await expectAccessible(page, "item view: Secure Note rendered from Markdown");
  await page.emulateMedia({ colorScheme: "dark" });
  await expectAccessible(page, "item view: Secure Note rendered from Markdown (dark)");
  for (const colorScheme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme, forcedColors: "active" });
    await expectAccessible(page, `item view: Secure Note rendered from Markdown (forced colours, ${colorScheme})`, {
      forcedColors: true,
    });
  }
  await page.emulateMedia({ colorScheme: "light", forcedColors: "none" });
  await page.setViewportSize({ width: 375, height: 812 });
  await expectAccessible(page, "item view: Secure Note rendered from Markdown (phone width)");
  expect(problems).toEqual([]);
});
