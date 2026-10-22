// SPDX-License-Identifier: AGPL-3.0-only

// Keyboard shortcuts and list navigation (redesign slice 2, item 3; `src/shortcuts.ts`): `/`
// focuses search, arrow keys move the list selection and Enter opens the selected row, `N`
// starts a new item, `?` opens the shortcuts help (and Escape closes it), and a shortcut like
// `N` is suppressed while a text field has focus.
//
// "Keyboard only" walks every screen the accessibility audit covers (`a11y.spec.ts`) without
// the pointer: each control is reached with Tab alone (`tabTo`, which fails when it is not
// reached within its bound) and operated with Enter, Space, Escape or typing.
import { expect, test } from "@playwright/test";

import { tabTo } from "./a11y.ts";
import { PASSWORD, newItem, signUp, watch } from "./helpers.ts";
import { type RunningServer, startServer } from "./server.ts";

let server: RunningServer;

test.beforeAll(async () => {
  server = await startServer();
});

test.afterAll(() => {
  server.stop();
});

test("keyboard: search focus, list navigation, new item, shortcuts help", async ({ page }) => {
  const { problems } = watch(page);
  await signUp(page, server.origin, "keyboarduser");

  // Two items to navigate between.
  await newItem(page, "Login");
  await page.getByLabel("Title").fill("First Co");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "First Co" })).toBeVisible();

  await newItem(page, "Login");
  await page.getByLabel("Title").fill("Second Co");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "Second Co" })).toBeVisible();

  // `/` focuses the search box (from the body, not a text field).
  await page.locator("body").press("/");
  await expect(page.getByLabel("Search items")).toBeFocused();
  await page.getByLabel("Search items").fill("");

  // `N` while the search box has focus (a text field) does nothing: no editor opens.
  await page.getByLabel("Search items").press("n");
  await expect(page.getByRole("heading", { name: "New login" })).toHaveCount(0);
  await expect(page.getByLabel("Title")).toHaveCount(0);

  // Arrow-key navigation over the list, then Enter opens the focused row.
  await page.getByRole("button", { name: /First Co|Second Co/ }).first().focus();
  await page.keyboard.press("ArrowDown");
  const focused = page.locator(":focus");
  await expect(focused).toHaveAttribute("type", "button");
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { name: /First Co|Second Co/ })).toBeVisible();

  // `N` from outside a text field opens a new item.
  await page.locator("body").click({ position: { x: 5, y: 5 } });
  await page.keyboard.press("n");
  await expect(page.getByLabel("Title")).toBeVisible();
  await page.getByRole("button", { name: "Cancel" }).click();

  // `?` opens the shortcuts help; Escape closes it and returns focus.
  await page.keyboard.press("?");
  const help = page.getByRole("dialog", { name: "Keyboard shortcuts" });
  await expect(help).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(help).toBeHidden();

  expect(problems).toEqual([]);
});

test("keyboard only: every audited screen is reachable and operable without a pointer", async ({ page }) => {
  const { problems } = watch(page);
  const kb = page.keyboard;
  const button = (name: string | RegExp) => page.getByRole("button", { name, exact: typeof name === "string" });

  // Login screen to signup.
  await page.goto(server.origin);
  await tabTo(page, button("Create an account"));
  await kb.press("Enter");

  // Signup, then the Emergency Kit.
  await tabTo(page, page.getByLabel("Login name"));
  await kb.type("keyboardonly");
  await tabTo(page, page.getByLabel("Master password", { exact: true }));
  await kb.type(PASSWORD);
  await tabTo(page, page.getByLabel("Repeat the master password", { exact: true }));
  await kb.type(PASSWORD);
  await tabTo(page, button("Continue"));
  await kb.press("Enter");
  await expect(page.getByTestId("emergency-kit")).toBeVisible();
  const secretKey = (await page.getByTestId("kit-secret-key").textContent()) ?? "";
  await tabTo(page, page.getByLabel(/last group of your Secret Key/));
  await kb.type(secretKey.split("-").at(-1) ?? "");
  await tabTo(page, button("Create the account"));
  await kb.press("Enter");

  // The getting-started guide: confirm, skip, close.
  const guide = page.getByRole("region", { name: "Get started" });
  await expect(guide).toBeVisible();
  await tabTo(page, guide.getByRole("checkbox", { name: /I saved my Emergency Kit/ }));
  await kb.press("Space");
  await tabTo(page, guide.getByRole("button", { name: "Continue" }));
  await kb.press("Enter");
  await tabTo(page, guide.getByRole("button", { name: "Skip this step" }));
  await kb.press("Enter");
  await tabTo(page, guide.getByRole("button", { name: "Close the guide" }));
  await kb.press("Enter");
  await expect(guide).toHaveCount(0);

  // New item through the menu, the editor, save.
  await tabTo(page, button(/New item/));
  await kb.press("Enter");
  await tabTo(page, page.getByRole("menuitem", { name: "Login" }));
  await kb.press("Enter");
  await tabTo(page, page.getByLabel("Title"));
  await kb.type("Keys Co");
  await tabTo(page, page.getByLabel("Password", { exact: true }));
  await kb.type("keys-password-long-enough");
  await tabTo(page, button("Save"));
  await kb.press("Enter");
  await expect(page.getByRole("heading", { name: "Keys Co" })).toBeVisible();

  // The item view: reveal, large type (Escape), edit and cancel.
  const passwordRow = page.locator('[data-field="login.password"]');
  await tabTo(page, passwordRow.getByRole("button", { name: "Reveal" }));
  await kb.press("Enter");
  await tabTo(page, passwordRow.getByRole("button", { name: "Large type" }));
  await kb.press("Enter");
  await expect(page.getByRole("dialog", { name: "Password" })).toBeVisible();
  await kb.press("Escape");
  await expect(page.getByRole("dialog", { name: "Password" })).toHaveCount(0);
  await tabTo(page, button("Edit"));
  await kb.press("Enter");
  await expect(page.getByRole("heading", { name: "Edit item" })).toBeVisible();
  await tabTo(page, button("Cancel"));
  await kb.press("Enter");
  await expect(page.getByRole("heading", { name: "Keys Co" })).toBeVisible();

  // The generator: generate a value.
  await tabTo(page, button("Generator"));
  await kb.press("Enter");
  await tabTo(page, button("Generate"));
  await kb.press("Enter");
  await expect(page.getByLabel("Generated", { exact: true })).toBeVisible();

  // Export and import: re-authenticate, open and cancel the plaintext dialog with Escape.
  await tabTo(page, button("Export and import"));
  await kb.press("Enter");
  await tabTo(page, page.getByLabel("Secret Key", { exact: true }));
  await kb.type(secretKey);
  await tabTo(page, page.getByLabel("Master password", { exact: true }));
  await kb.type(PASSWORD);
  await kb.press("Enter");
  await tabTo(page, button("Export in plaintext…"));
  await kb.press("Enter");
  const plaintext = page.getByRole("dialog", { name: /Plaintext export/ });
  await expect(plaintext.getByLabel(/to continue/)).toBeFocused();
  await kb.press("Escape");
  await expect(plaintext).toHaveCount(0);
  await expect(button("Export in plaintext…")).toBeFocused();

  // Settings: the theme select, then the getting-started guide again.
  await tabTo(page, button("Settings"));
  await kb.press("Enter");
  await expect(page.getByRole("region", { name: "What the server stores" })).toBeVisible();
  const theme = page.getByLabel("Theme");
  await tabTo(page, theme);
  await kb.press("ArrowDown");
  await expect(theme).toHaveValue("light");
  await tabTo(page, button("Open the getting-started guide"));
  await kb.press("Enter");
  await tabTo(page, guide.getByRole("button", { name: "Close the guide" }));
  await kb.press("Enter");
  await expect(guide).toHaveCount(0);

  // The command palette jumps to a view; the trash through its confirmation dialog.
  await kb.press("Control+k");
  await kb.type("Keys Co");
  await expect(page.getByRole("option", { name: /^Open — Keys Co/ })).toBeVisible();
  await kb.press("Enter");
  await expect(page.getByRole("heading", { name: "Keys Co" })).toBeVisible();
  await tabTo(page, button("Move to trash"));
  await kb.press("Enter");
  const confirm = page.getByRole("dialog", { name: "Move this item to trash?" });
  await expect(confirm.getByRole("button", { name: "Cancel" })).toBeFocused();
  await tabTo(page, confirm.getByRole("button", { name: "Move to trash" }));
  await kb.press("Enter");
  await expect(confirm).toHaveCount(0);
  await tabTo(page, button("Trash"));
  await kb.press("Enter");
  await tabTo(page, page.getByRole("button", { name: /Keys Co/ }));
  await kb.press("Enter");
  await expect(page.getByRole("heading", { name: "Keys Co" })).toBeVisible();

  // Lock through the account menu, and unlock.
  await tabTo(page, button("Account menu"));
  await kb.press("Enter");
  await tabTo(page, page.getByRole("menuitem", { name: "Lock" }));
  await kb.press("Enter");
  await tabTo(page, page.getByLabel("Secret Key", { exact: true }));
  await kb.type(secretKey);
  await tabTo(page, page.getByLabel("Master password", { exact: true }));
  await kb.type(PASSWORD);
  await kb.press("Enter");
  await expect(button("Account menu")).toBeVisible();

  expect(problems).toEqual([]);
});

