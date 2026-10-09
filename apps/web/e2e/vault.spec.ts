// The web vault end to end, in Chromium, against the real `rizzy-vault` with `embed-web`:
// signup with the Emergency Kit → the vault → create an item → reload (nothing persists) →
// log in again and see the item → lock → unlock → trash and restore.
//
// Along the way it checks:
// - INV-49: the page's CSP and headers as served, and that nothing on the page violates the
//   CSP (inline script or style, eval, Trusted Types for the Worker URL);
// - INV-68: every secret field has `spellcheck="false"` and `autocomplete="off"` before and
//   after a reveal;
// - the Emergency Kit download.
//
// A second test runs the export and import flow (owner decision 2026-10-05): every export
// behind a re-authentication, the encrypted export under a password for the file, the
// plaintext dialog's 10-second countdown, and an import into a second account that recognises
// the file and round-trips an item.
import { readFile } from "node:fs/promises";

import { type Locator, type Page, expect, test } from "@playwright/test";

import { type RunningServer, startServer } from "./server.ts";

const PASSWORD = "correct horse battery staple";
const ITEM_PASSWORD = "hunter2-but-much-longer";

let server: RunningServer;

test.beforeAll(async () => {
  server = await startServer();
});

test.afterAll(() => {
  server.stop();
});

/** Collects CSP violations and console errors of a page. */
function watch(page: Page): { problems: string[] } {
  const problems: string[] = [];
  page.on("console", (m) => {
    if (m.type() === "error") {
      problems.push(`console: ${m.text()}`);
    }
  });
  page.on("pageerror", (e) => problems.push(`pageerror: ${e.message}`));
  return { problems };
}

/** Records `securitypolicyviolation` events in the page, read back by {@link violations}. */
async function recordViolations(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const w = window as unknown as { __cspViolations: string[] };
    w.__cspViolations = [];
    document.addEventListener("securitypolicyviolation", (e) => {
      w.__cspViolations.push(`${e.violatedDirective} ${e.blockedURI}`);
    });
  });
}

/** The CSP violations recorded so far. */
async function violations(page: Page): Promise<string[]> {
  return page.evaluate(() => (window as unknown as { __cspViolations: string[] }).__cspViolations);
}

/** INV-68 on one secret input, before and after its "Show" toggle. */
async function checkSecretField(field: Locator): Promise<void> {
  const input = field.locator("input[data-secret-field]");
  await expect(input).toHaveAttribute("type", "password");
  await expect(input).toHaveAttribute("spellcheck", "false");
  await expect(input).toHaveAttribute("autocomplete", "off");
  await field.getByRole("button", { name: "Show" }).click();
  await expect(input).toHaveAttribute("type", "text");
  await expect(input).toHaveAttribute("spellcheck", "false");
  await expect(input).toHaveAttribute("autocomplete", "off");
  await field.getByRole("button", { name: "Hide" }).click();
  await expect(input).toHaveAttribute("type", "password");
}

/** The secret field whose label is `label`. */
function secretField(page: Page, label: string): Locator {
  return page.locator(".secret-field").filter({ has: page.getByLabel(label, { exact: true }) });
}

/** Logs in on the login (or unlock) screen. */
async function logIn(page: Page, loginName: string | undefined, secretKey: string): Promise<void> {
  if (loginName !== undefined) {
    await page.getByLabel("Login name").fill(loginName);
  }
  await page.getByLabel("Secret Key", { exact: true }).fill(secretKey);
  await page.getByLabel("Master password", { exact: true }).fill(PASSWORD);
  await page.getByRole("button", { name: /^(Log in|Unlock)$/ }).click();
  await expect(page.getByRole("button", { name: "Account menu" })).toBeVisible();
}

/** Opens the single "New item" menu and chooses `typeLabel` (redesign slice 2, item 5). */
async function newItem(page: Page, typeLabel: string): Promise<void> {
  await page.getByRole("button", { name: "New item" }).click();
  await page.getByRole("menuitem", { name: typeLabel }).click();
}

/** Locks the vault through the account menu (redesign slice 2, item 5: there is no longer a
 * standalone "Lock" button in the top bar). */
async function lockVault(page: Page): Promise<void> {
  await page.getByRole("button", { name: "Account menu" }).click();
  await page.getByRole("menuitem", { name: "Lock" }).click();
}

test("signup, item, reload, login, lock, unlock", async ({ page }) => {
  const { problems } = watch(page);
  await recordViolations(page);

  // The page as served: the INV-49 headers.
  const response = await page.goto(server.origin);
  expect(response?.status()).toBe(200);
  const headers = response?.headers() ?? {};
  const csp = headers["content-security-policy"] ?? "";
  expect(csp).toContain("script-src 'self' 'wasm-unsafe-eval'");
  expect(csp).toContain("frame-ancestors 'none'");
  expect(csp).toContain("require-trusted-types-for 'script'");
  expect(csp).not.toContain("unsafe-inline");
  expect(headers["x-content-type-options"]).toBe("nosniff");
  expect(headers["strict-transport-security"]).toBe("max-age=31536000");

  // The login screen, with its secret fields (INV-68).
  await expect(page.getByRole("heading", { name: "Log in to rizzy-vault" })).toBeVisible();
  await expect(page.getByText("Do not let the browser save your master password")).toBeVisible();
  await checkSecretField(secretField(page, "Secret Key"));
  await checkSecretField(secretField(page, "Master password"));

  // Signup.
  await page.getByRole("button", { name: "Create an account" }).click();
  await page.getByLabel("Login name").fill("Alice");
  await checkSecretField(secretField(page, "Master password"));
  await page.getByLabel("Master password", { exact: true }).fill(PASSWORD);
  await page.getByLabel("Repeat the master password", { exact: true }).fill(PASSWORD);
  await page.getByRole("button", { name: "Continue" }).click();

  // The Emergency Kit, shown once, with a download.
  const kit = page.getByTestId("emergency-kit");
  await expect(kit).toBeVisible();
  const secretKey = (await page.getByTestId("kit-secret-key").textContent()) ?? "";
  expect(secretKey).toMatch(/^RV1-/);
  await expect(page.getByTestId("kit-recovery-code")).toHaveText(/^RVR1-/);
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("button", { name: "Download the kit" }).click(),
  ]);
  await expect(page.getByTestId("kit-warnings")).toContainText("take over your account");
  expect(download.suggestedFilename()).toMatch(/^rizzy-vault-emergency-kit-\d{4}-\d{2}-\d{2}\.html$/);
  const kitFile = await readFile(await download.path());
  expect(kitFile.toString("utf8")).toContain(secretKey);

  // A wrong confirmation is refused; the right one commits and opens the vault.
  await page.getByLabel(/last group of your Secret Key/).fill("ZZZZ");
  await page.getByRole("button", { name: "Create the account" }).click();
  await expect(page.locator('[data-code="emergency_kit_not_confirmed"]')).toBeVisible();
  const lastGroup = secretKey.split("-").at(-1) ?? "";
  await page.getByLabel(/last group of your Secret Key/).fill(lastGroup);
  await page.getByRole("button", { name: "Create the account" }).click();
  await expect(page.getByRole("button", { name: "Account menu" })).toBeVisible();
  await expect(page.getByText("No items yet.")).toBeVisible();

  // Create a login item.
  await newItem(page, "Login");
  await page.getByLabel("Title").fill("Example");
  await page.getByLabel("Username", { exact: true }).fill("alice@example.com");
  await checkSecretField(secretField(page, "Password"));
  await page.getByLabel("Password", { exact: true }).fill(ITEM_PASSWORD);
  await page.getByRole("button", { name: "Add a website" }).click();
  await page.getByLabel("New website 1", { exact: true }).fill("https://example.com/login");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "Example" })).toBeVisible();
  await expect(page.getByText("Synced", { exact: true })).toBeVisible();

  // The URI is a safe link; the password is masked until revealed.
  await expect(page.getByRole("link", { name: "https://example.com/login" })).toHaveAttribute(
    "rel",
    "noopener noreferrer",
  );
  const passwordRow = page.locator('[data-field="login.password"]');
  await expect(passwordRow.getByText("••••••••")).toBeVisible();
  await passwordRow.getByRole("button", { name: "Reveal" }).click();
  const revealed = passwordRow.locator("input[data-secret-field]");
  await expect(revealed).toHaveValue(ITEM_PASSWORD);
  await expect(revealed).toHaveAttribute("type", "text");
  await expect(revealed).toHaveAttribute("spellcheck", "false");
  await expect(revealed).toHaveAttribute("readonly", "");

  // The sidebar's item filters (ItemsPane.tsx's `inScope`): by type, and by favorite.
  await page.getByRole("button", { name: "Card", exact: true }).click();
  await expect(page.getByText("Nothing of this type yet.")).toBeVisible();
  await page.getByRole("button", { name: "Login", exact: true }).click();
  await expect(page.getByRole("button", { name: /Example/ })).toBeVisible();
  await page.getByRole("button", { name: "Favorites", exact: true }).click();
  await expect(page.getByText("No favorites yet. Star an item to find it here.")).toBeVisible();
  await page.getByRole("button", { name: "All items", exact: true }).click();
  await page.getByRole("button", { name: /Example/ }).click();

  // The detail header's favorite toggle: it reuses the editor's own `editItem`/`item.favorite`
  // write (ItemView.tsx module docs), so toggling it is a real, synced write, not a UI-only
  // flag — the row's star and the Favorites filter must both pick it up.
  await page.getByRole("button", { name: "Add to favorites" }).click();
  await expect(page.getByRole("button", { name: "Remove from favorites" })).toBeVisible();
  await expect(page.getByRole("button", { name: /Example/ }).getByLabel("favorite")).toBeVisible();
  await page.getByRole("button", { name: "Favorites", exact: true }).click();
  await expect(page.getByRole("button", { name: /Example/ })).toBeVisible();
  await page.getByRole("button", { name: "All items", exact: true }).click();
  await page.getByRole("button", { name: /Example/ }).click();

  // Reload: the web vault keeps nothing, so it is a new login, and the item comes back from
  // the server.
  await page.reload();
  await expect(page.getByRole("heading", { name: "Log in to rizzy-vault" })).toBeVisible();
  await logIn(page, "alice", secretKey);
  await page.getByRole("button", { name: /Example/ }).click();
  await expect(page.getByRole("heading", { name: "Example" })).toBeVisible();
  await expect(page.getByText("alice@example.com").first()).toBeVisible();

  // Search.
  await page.getByLabel("Search items").fill("nothing-like-it");
  await expect(page.getByText("Nothing matches.")).toBeVisible();
  await page.getByLabel("Search items").fill("exam");
  await expect(page.getByRole("button", { name: /Example/ })).toBeVisible();

  // Lock, then unlock (a new login with the remembered login name).
  await lockVault(page);
  await expect(page.getByRole("heading", { name: "Unlock rizzy-vault" })).toBeVisible();
  await logIn(page, undefined, secretKey);
  await page.getByRole("button", { name: /Example/ }).click();
  const again = page.locator('[data-field="login.password"]');
  await again.getByRole("button", { name: "Reveal" }).click();
  await expect(again.locator("input[data-secret-field]")).toHaveValue(ITEM_PASSWORD);

  // Trash and restore: trashing now confirms through the accessible dialog (redesign slice 2,
  // item 2), not immediately.
  await page.getByRole("button", { name: "Move to trash" }).click();
  await page
    .getByRole("dialog", { name: "Move this item to trash?" })
    .getByRole("button", { name: "Move to trash" })
    .click();
  await expect(page.getByText("No items yet.")).toBeVisible();
  await page.getByRole("button", { name: "Trash", exact: true }).click();
  await page.getByRole("button", { name: /Example/ }).click();
  // A sync must not clear the open trashed item: the trash pane's scope has to be the same
  // stable object on every render, not a fresh `{ kind: "all" }` literal that would make
  // `ItemsPane`'s `[trash, scope]` effect fire (and blank the detail pane) on every sync
  // (VaultView.tsx's `ALL_SCOPE` module docs).
  await page.getByRole("button", { name: "Sync" }).click();
  await expect(page.getByRole("heading", { name: "Example" })).toBeVisible();
  await page.getByRole("button", { name: "Restore" }).click();
  await page.getByRole("button", { name: "All items", exact: true }).click();
  await expect(page.getByRole("button", { name: /Example/ })).toBeVisible();

  // The generator.
  await page.getByRole("button", { name: "Generator", exact: true }).click();
  await page.getByRole("button", { name: "Generate" }).click();
  const generated = page.locator(".generated input[data-secret-field]");
  await expect(generated).toHaveValue(/.{20}/);
  await expect(generated).toHaveAttribute("spellcheck", "false");

  // Settings: Devices (none enrolled; the web session is ephemeral).
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await expect(page.getByText("No enrolled devices.")).toBeVisible();

  expect(await violations(page)).toEqual([]);
  expect(problems).toEqual([]);
});

// Permanent delete (ADR 0018 §3 "Surfacing"; ROADMAP §4.2 "Trash with restore"): the
// confirm dialog (ItemView.tsx's "purge" `ConfirmDialog`) purges on confirm and keeps the
// item on cancel. The wasm `purgeItem` binding and the packages/core wrapper underneath this
// click have their own tests (packages/core, crates/rizzy-wasm); this covers the UI's own
// wiring: the button, the dialog, the toast and the trash list.
test("permanent delete: cancelling the dialog keeps the item, confirming purges it", async ({ page }) => {
  await signUp(page, "purgeuser");
  await newItem(page, "Login");
  await page.getByLabel("Title").fill("ToPurge");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "ToPurge" })).toBeVisible();

  await page.getByRole("button", { name: "Move to trash" }).click();
  await page
    .getByRole("dialog", { name: "Move this item to trash?" })
    .getByRole("button", { name: "Move to trash" })
    .click();
  await page.getByRole("button", { name: "Trash", exact: true }).click();
  await page.getByRole("button", { name: /ToPurge/ }).click();

  // Cancelling leaves the item in the trash.
  await page.getByRole("button", { name: "Delete for good" }).click();
  const dialog = page.getByRole("dialog", { name: "Delete this item for good?" });
  await expect(dialog).toBeVisible();
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await expect(dialog).toBeHidden();
  await expect(page.getByRole("heading", { name: "ToPurge" })).toBeVisible();

  // Confirming purges it for good.
  await page.getByRole("button", { name: "Delete for good" }).click();
  await page
    .getByRole("dialog", { name: "Delete this item for good?" })
    .getByRole("button", { name: "Delete for good" })
    .click();
  await expect(page.getByText("Item deleted for good.")).toBeVisible();
  await expect(page.getByText("The trash is empty.")).toBeVisible();
  await page.getByRole("button", { name: "All items", exact: true }).click();
  await expect(page.getByText("No items yet.")).toBeVisible();
});

test("the editor's generate popover: custom options, save, reload, password present", async ({ page }) => {
  const { problems } = watch(page);
  const secretKey = await signUp(page, "generatoruser");

  await newItem(page, "Login");
  await page.getByLabel("Title").fill("Generated Co");
  await page.getByLabel("Username", { exact: true }).fill("gen@example.com");

  // The password field's generate slot: open the settings popover, turn symbols off and avoid
  // ambiguous characters, then generate from inside the popover (it fills the field and closes).
  // `.secret-edit` is the editor's whole row (SecretField plus its generate slot); `[data-field]`
  // is the item *view*'s own row attribute (ItemView.tsx) and does not apply here.
  const passwordRow = page
    .locator(".secret-edit")
    .filter({ has: page.getByLabel("Password", { exact: true }) });
  await passwordRow.getByRole("button", { name: "Generator settings" }).click();
  const popover = passwordRow.locator(".generator-popover");
  await expect(popover).toBeVisible();
  await popover.getByLabel("Symbols").selectOption("excluded");
  await popover.getByLabel("Avoid look-alike characters").check();
  await popover.getByRole("button", { name: "Generate" }).click();
  await expect(popover).toBeHidden();

  const input = passwordRow.locator("input[data-secret-field]");
  await expect(input).not.toHaveValue("");
  const value = await input.inputValue();
  expect(value).toHaveLength(20);
  expect(value).not.toMatch(/[!-/:-@[-`{-~]/);

  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "Generated Co" })).toBeVisible();
  await expect(page.getByText("Synced", { exact: true })).toBeVisible();

  // Reload: a new login, and the generated password survived the save.
  await page.reload();
  await expect(page.getByRole("heading", { name: "Log in to rizzy-vault" })).toBeVisible();
  await logIn(page, "generatoruser", secretKey);
  await page.getByRole("button", { name: /Generated Co/ }).click();
  const again = page.locator('[data-field="login.password"]');
  await again.getByRole("button", { name: "Reveal" }).click();
  await expect(again.locator("input[data-secret-field]")).toHaveValue(value);

  expect(problems).toEqual([]);
});

test("a login with two websites, a hidden field and a tag: reorder, edit, reload", async ({ page }) => {
  const { problems } = watch(page);
  const secretKey = await signUp(page, "riordan");

  // Create: two websites (added, then swapped before the first save), a hidden custom field
  // and a tag.
  await newItem(page, "Login");
  await page.getByLabel("Title").fill("Reorder Co");
  await page.getByLabel("Username", { exact: true }).fill("riordan@example.com");
  await page.getByLabel("Password", { exact: true }).fill(ITEM_PASSWORD);

  await page.getByRole("button", { name: "Add a website" }).click();
  await page.getByLabel("New website 1", { exact: true }).fill("https://first.example.test");
  await page.getByRole("button", { name: "Add a website" }).click();
  await page.getByLabel("New website 2", { exact: true }).fill("https://second.example.test");
  await page.getByRole("button", { name: "Move new website 1 down" }).click();
  await expect(page.getByLabel("New website 1", { exact: true })).toHaveValue("https://second.example.test");
  await expect(page.getByLabel("New website 2", { exact: true })).toHaveValue("https://first.example.test");

  await page.getByRole("button", { name: "Add a custom field" }).click();
  await page.getByLabel("New custom field 1 label", { exact: true }).fill("PIN");
  await page.getByLabel("New custom field 1 kind", { exact: true }).selectOption("hidden");
  await secretField(page, "Value").locator("input[data-secret-field]").fill("13-37");

  await page.getByLabel("Add tags (comma-separated)").fill("important");

  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "Reorder Co" })).toBeVisible();
  await expect(page.getByText("Synced", { exact: true })).toBeVisible();

  // The item shows the swapped order, the masked field and the tag.
  const links = page.getByRole("link", { name: /example\.test/ });
  await expect(links).toHaveCount(2);
  await expect(links.nth(0)).toHaveText("https://second.example.test");
  await expect(links.nth(1)).toHaveText("https://first.example.test");
  await expect(page.getByText("important", { exact: true })).toBeVisible();

  // Edit: move the first website back down (an immediate write, no Save needed) and rename
  // the custom field's label.
  await page.getByRole("button", { name: "Edit" }).click();
  await expect(page.getByLabel("Website 1", { exact: true })).toHaveValue("https://second.example.test");
  await page.getByRole("button", { name: "Move website 1 down" }).click();
  await expect(page.getByLabel("Website 1", { exact: true })).toHaveValue("https://first.example.test");
  await expect(page.getByLabel("Website 2", { exact: true })).toHaveValue("https://second.example.test");
  await page.getByLabel("Custom field 1 label", { exact: true }).fill("PIN (renamed)");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "Reorder Co" })).toBeVisible();

  // Reload: a new login, and every change — the reorder, the rename, the tag — survived.
  await page.reload();
  await expect(page.getByRole("heading", { name: "Log in to rizzy-vault" })).toBeVisible();
  await logIn(page, "riordan", secretKey);
  await page.getByRole("button", { name: /Reorder Co/ }).click();
  await expect(page.getByRole("heading", { name: "Reorder Co" })).toBeVisible();
  const linksAfter = page.getByRole("link", { name: /example\.test/ });
  await expect(linksAfter.nth(0)).toHaveText("https://first.example.test");
  await expect(linksAfter.nth(1)).toHaveText("https://second.example.test");
  await expect(page.getByText("PIN (renamed)")).toBeVisible();
  await expect(page.getByText("important", { exact: true })).toBeVisible();

  expect(problems).toEqual([]);
});

test("a wrong master password is refused", async ({ page }) => {
  await page.goto(server.origin);
  await page.getByLabel("Login name").fill("nobody");
  await page.getByLabel("Secret Key", { exact: true }).fill("RV1-AAAAAA-AAAAAA-AAAAA-AAAAA-AAAAA-AAAAA");
  await page.getByLabel("Master password", { exact: true }).fill("wrong");
  await page.getByRole("button", { name: "Log in" }).click();
  await expect(page.getByRole("alert")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Log in to rizzy-vault" })).toBeVisible();
});

test("a Caps Lock hint appears while typing and clears when it is masked off", async ({ page }) => {
  // Real OS-level Caps Lock is not something Playwright's `keyboard.press` reliably toggles in
  // a headless browser, so this dispatches the same `keydown` the real key would produce,
  // `modifierCapsLock` set directly (the standard `EventModifierInit` field `getModifierState`
  // reads): `SecretField`'s hint reacts the same way either way, since it only ever reads
  // `getModifierState("CapsLock")` off the event, never a key value (module docs, SecretField.tsx).
  await page.goto(server.origin);
  const password = page.getByLabel("Master password", { exact: true });
  await expect(page.getByText("Caps Lock is on.")).toBeHidden();
  await password.evaluate((el) =>
    el.dispatchEvent(new KeyboardEvent("keydown", { key: "x", modifierCapsLock: true, bubbles: true })),
  );
  await expect(page.getByText("Caps Lock is on.")).toBeVisible();
  await password.evaluate((el) =>
    el.dispatchEvent(new KeyboardEvent("keyup", { key: "x", modifierCapsLock: false, bubbles: true })),
  );
  await expect(page.getByText("Caps Lock is on.")).toBeHidden();

  // Leaving the field (no further keypress in it) clears a stale hint instead of leaving it
  // showing once Caps Lock no longer applies to whatever the user does next. `blur()` only
  // fires if the element had focus to lose, so this focuses it first.
  await password.focus();
  await password.evaluate((el) =>
    el.dispatchEvent(new KeyboardEvent("keydown", { key: "x", modifierCapsLock: true, bubbles: true })),
  );
  await expect(page.getByText("Caps Lock is on.")).toBeVisible();
  await password.blur();
  await expect(page.getByText("Caps Lock is on.")).toBeHidden();
});

test("the server serves only the embedded files", async ({ request }) => {
  for (const path of ["/assets/app.js", "/assets/core-worker.js", "/assets/style.css"]) {
    const r = await request.get(server.origin + path);
    expect(r.status(), path).toBe(200);
    expect(r.headers()["content-security-policy"]).toContain("'wasm-unsafe-eval'");
  }
  const wasm = await request.get(`${server.origin}/assets/rizzy_core_bg.wasm`);
  expect(wasm.headers()["content-type"]).toBe("application/wasm");
  for (const path of ["/assets/", "/assets/APP.JS", "/favicon.ico", "/src/main.tsx"]) {
    const r = await request.get(server.origin + path);
    expect(r.status(), path).toBe(404);
  }
});

/** Signs up `name` and confirms the kit; returns the Secret Key. */
async function signUp(page: Page, name: string): Promise<string> {
  await page.goto(server.origin);
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

/** Confirms the Secret Key and master password on the export pane. */
async function reauthenticate(page: Page, secretKey: string, password = PASSWORD): Promise<void> {
  await page.getByLabel("Secret Key", { exact: true }).fill(secretKey);
  await page.getByLabel("Master password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Confirm", exact: true }).click();
}

test("encrypted export, then import into a second account", async ({ browser }) => {
  const FILE_PASSWORD = "a password for this file only";

  // The first account, with one item.
  const first = await browser.newPage();
  const { problems } = watch(first);
  const firstKey = await signUp(first, "exporter");
  await newItem(first, "Login");
  await first.getByLabel("Title").fill("Round trip");
  await first.getByLabel("Username", { exact: true }).fill("carol@example.com");
  await first.getByLabel("Password", { exact: true }).fill(ITEM_PASSWORD);
  await first.getByRole("button", { name: "Save" }).click();
  await expect(first.getByText("Synced", { exact: true })).toBeVisible();

  // Every export needs the Secret Key and master password again; a wrong one allows nothing.
  await first.getByRole("button", { name: "Export and import", exact: true }).click();
  await expect(first.getByRole("button", { name: "Export encrypted" })).toHaveCount(0);
  await reauthenticate(first, firstKey, "not the master password");
  await expect(first.locator('[data-code="wrong_password_or_secret_key"]')).toBeVisible();
  await expect(first.getByRole("button", { name: "Export encrypted" })).toHaveCount(0);
  await reauthenticate(first, firstKey);

  // The encrypted export, under a password for the file, typed twice.
  await first.getByLabel("Password for this export file", { exact: true }).fill(FILE_PASSWORD);
  await first.getByLabel("Repeat the password for this export file", { exact: true }).fill(FILE_PASSWORD);
  const [download] = await Promise.all([
    first.waitForEvent("download"),
    first.getByRole("button", { name: "Export encrypted" }).click(),
  ]);
  expect(download.suggestedFilename()).toMatch(/^rizzy-vault-export-\d{4}-\d{2}-\d{2}\.json$/);
  const exportPath = await download.path();
  const exported = (await readFile(exportPath)).toString("utf8");
  expect(exported.startsWith('{"format":"rizzy-vault-export"')).toBe(true);
  expect(exported).not.toContain(ITEM_PASSWORD);
  // One export per confirmation: the pane asks again.
  await expect(first.getByRole("button", { name: "Confirm", exact: true })).toBeVisible();

  // The plaintext export: the warning, a 10-second countdown with the button disabled, which
  // starts over when the dialog is opened again; then the phrase.
  await reauthenticate(first, firstKey);
  await first.getByRole("button", { name: "Export in plaintext…" }).click();
  const dialog = first.getByRole("dialog");
  await expect(dialog.getByTestId("plaintext-warning")).toContainText("unencrypted");
  const confirm = dialog.getByRole("button", { name: "Export in plaintext", exact: true });
  await expect(confirm).toBeDisabled();
  await expect(dialog.getByTestId("plaintext-countdown")).toContainText("continue in");
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await first.getByRole("button", { name: "Export in plaintext…" }).click();
  await expect(confirm).toBeDisabled();
  await expect(dialog.getByTestId("plaintext-countdown")).toContainText(/continue in (10|9) s/);
  await dialog.getByLabel(/to continue/).fill("EXPORT PLAINTEXT");
  await first.waitForTimeout(8_000);
  await expect(confirm).toBeDisabled();
  await expect(confirm).toBeEnabled({ timeout: 5_000 });
  const [plain] = await Promise.all([
    first.waitForEvent("download"),
    confirm.click(),
  ]);
  expect(plain.suggestedFilename()).toMatch(/^rizzy-vault-plaintext-.*\.json$/);
  expect((await readFile(await plain.path())).toString("utf8")).toContain(ITEM_PASSWORD);
  expect(problems).toEqual([]);

  // A second account imports the encrypted file: the format is recognised, and the file's
  // password opens it.
  const second = await browser.newPage();
  const secondKey = await signUp(second, "importer");
  expect(secondKey).not.toBe(firstKey);
  await expect(second.getByText("No items yet.")).toBeVisible();
  await second.getByRole("button", { name: "Export and import", exact: true }).click();
  await second.getByLabel("File", { exact: true }).setInputFiles(exportPath);
  await expect(second.getByTestId("import-detected")).toHaveText(
    "Recognised: rizzy-vault encrypted export.",
  );
  await second.getByLabel("Password of this export file", { exact: true }).fill("wrong");
  await second.getByRole("button", { name: "Import", exact: true }).click();
  await expect(second.locator('[data-code="export_decryption_failed"]')).toBeVisible();
  await second.getByLabel("Password of this export file", { exact: true }).fill(FILE_PASSWORD);
  await second.getByRole("button", { name: "Import", exact: true }).click();
  await expect(second.getByTestId("import-report")).toContainText("Imported 1");
  await second.getByRole("button", { name: "All items", exact: true }).click();
  await second.getByRole("button", { name: /Round trip/ }).click();
  await expect(second.getByText("carol@example.com").first()).toBeVisible();
  const row = second.locator('[data-field="login.password"]');
  await row.getByRole("button", { name: "Reveal" }).click();
  await expect(row.locator("input[data-secret-field]")).toHaveValue(ITEM_PASSWORD);
  await first.close();
  await second.close();
});
