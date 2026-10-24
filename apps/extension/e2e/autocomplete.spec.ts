// SPDX-License-Identifier: AGPL-3.0-only

// ADR 0076 end to end in real Chromium with the built extension (§10 "Extension e2e"): a TOTP
// code fills on a 2FA page only on the user's own click, and only where a saved login can
// produce one; custom fields fill by exact token after the menu disclosed them, "(hidden)"
// shown; a page that renames a token after the menu showed, and a hidden custom target, get
// nothing; negative TOTP pages (card security code, SMS code) get no menu; and the
// extension-origin save dialog offers a submitted custom field, which a page cannot tick for the
// user, while the page-DOM banner never offers custom fields.
import { createHmac } from "node:crypto";
import { createServer, type Server } from "node:http";
import { fileURLToPath } from "node:url";

import { type BrowserContext, type FrameLocator, type Locator, type Page, chromium, test as base, expect } from "@playwright/test";

import { TEST_ACCOUNT_PASSWORD, logIn, signUp } from "./account.ts";
import AxeBuilder from "@axe-core/playwright";

import { AXE_TAGS, expectAccessible } from "./a11y.ts";
import { type RunningServer, startServer } from "./server.ts";
import { withProfileDir } from "./profile.ts";

const EXTENSION_PATH = fileURLToPath(new URL("../dist/chromium", import.meta.url));

/** RFC 6238's SHA-1 test secret, Base32. */
const TOTP_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

/** The RFC 6238 SHA-1 code of {@link TOTP_SECRET} at `unixSeconds` (6 digits, 30 s). */
function totpAt(unixSeconds: number): string {
  const key = Buffer.from("12345678901234567890", "ascii");
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(unixSeconds / 30)));
  const mac = createHmac("sha1", key).update(counter).digest();
  const offset = (mac[mac.length - 1] ?? 0) & 0x0f;
  const bin = (mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000;
  return String(bin).padStart(6, "0");
}

const PAGES: Readonly<Record<string, string>> = {
  "/plain":
    '<form id="login" onsubmit="return false">' +
    '<label for="user">Email</label><input id="user" type="text" autocomplete="username">' +
    '<label for="pass">Password</label><input id="pass" type="password" autocomplete="current-password">' +
    '<button type="submit">Log in</button></form>',
  "/2fa":
    '<form id="mfa" action="/2fa" onsubmit="return false"><label for="code">Authentication code</label>' +
    '<input id="code" name="code" type="text" autocomplete="one-time-code" inputmode="numeric" maxlength="6">' +
    '<button type="submit">Verify</button></form>',
  "/custom":
    '<form id="login" onsubmit="return false">' +
    '<input id="user" type="text" autocomplete="username">' +
    '<input id="pass" type="password" autocomplete="current-password">' +
    '<input id="member" type="text" autocomplete="member-no">' +
    '<input id="pin" type="password" autocomplete="pin.code">' +
    '<input id="hiddenpin" type="text" autocomplete="branch" style="display:none">' +
    '<button type="submit">Log in</button></form>',
  "/neg-csc":
    '<form onsubmit="return false"><input id="csc" type="text" autocomplete="cc-csc" inputmode="numeric" maxlength="6" placeholder="2FA code">' +
    '<button type="submit">Verify</button></form>',
  "/neg-sms":
    '<form onsubmit="return false"><label for="sms">Enter the code we sent to your phone by SMS</label>' +
    '<input id="sms" type="text" autocomplete="one-time-code" inputmode="numeric" maxlength="6"><button type="submit">Verify</button></form>',
  "/signup":
    '<form id="login" onsubmit="return false">' +
    '<label for="user">Email</label><input id="user" type="text" autocomplete="username">' +
    '<label for="pass">Password</label><input id="pass" type="password">' +
    '<label for="club">Club card</label><input id="club" type="text" autocomplete="club-card">' +
    '<button type="submit">Log in</button></form>',
};

async function startPages(): Promise<{ port: number; stop: () => Promise<void> }> {
  const server: Server = createServer((req, res) => {
    const body = PAGES[(req.url ?? "/").split("?")[0] ?? "/"] ?? "";
    res.writeHead(200, { "content-type": "text/html" });
    res.end('<!doctype html><html lang="en"><head><title>Test site</title></head><body><main><h1>Test site</h1>' + body + "</main></body></html>");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const port = typeof address === "object" && address !== null ? address.port : 0;
  return {
    port,
    stop: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

const test = base.extend<{ server: RunningServer; context: BrowserContext; extensionId: string }>({
  server: async ({}, use) => {
    const server = await startServer();
    await use(server);
    server.stop();
  },
  context: async ({}, use) => {
    await withProfileDir("rizzy-ext-e2e-autocomplete-", async (userDataDir) => {
      const context = await chromium.launchPersistentContext(userDataDir, {
        headless: true,
        channel: "chromium",
        args: [`--disable-extensions-except=${EXTENSION_PATH}`, `--load-extension=${EXTENSION_PATH}`],
      });
      try {
        await use(context);
      } finally {
        await context.close();
      }
    });
  },
  extensionId: async ({ context }, use) => {
    let [worker] = context.serviceWorkers();
    if (worker === undefined) {
      worker = await context.waitForEvent("serviceworker");
    }
    await use(new URL(worker.url()).host);
  },
});

test.setTimeout(180_000);

/** Creates a login item in the web vault with the given website, optional TOTP secret and
 * custom fields (Display Name, kind, value, autocomplete id). */
async function createItem(
  page: Page,
  item: {
    readonly title: string;
    readonly username: string;
    readonly password: string;
    readonly websiteUrl: string;
    readonly totp?: string;
    /** The vault picked in the editor (ADR 0081 §A8); Personal, the preselected one, when absent. */
    readonly vault?: string;
    readonly custom?: readonly { readonly label: string; readonly kind: "text" | "hidden"; readonly value: string; readonly id: string }[];
  },
): Promise<void> {
  await page.getByRole("button", { name: "New item" }).click();
  await page.getByRole("menuitem", { name: "Login" }).click();
  if (item.vault !== undefined) {
    await page.getByLabel("Vault", { exact: true }).selectOption({ label: item.vault });
  }
  await page.getByLabel("Title").fill(item.title);
  await page.getByLabel("Username", { exact: true }).fill(item.username);
  await page.getByLabel("Password", { exact: true }).fill(item.password);
  if (item.totp !== undefined) {
    await page.getByLabel("One-time password secret (TOTP)", { exact: true }).fill(item.totp);
  }
  await page.getByRole("button", { name: "Add a website" }).click();
  await page.getByLabel("New website 1", { exact: true }).fill(item.websiteUrl);
  for (const [i, field] of (item.custom ?? []).entries()) {
    const n = i + 1;
    await page.getByRole("button", { name: "Add a custom field" }).click();
    await page.getByLabel(`New custom field ${n} label`, { exact: true }).fill(field.label);
    await page.getByLabel(`New custom field ${n} kind`, { exact: true }).selectOption(field.kind);
    if (field.kind === "hidden") {
      await page.locator(".custom-field-row").nth(i).locator("input[data-secret-field]").fill(field.value);
    } else {
      await page.getByLabel(`New custom field ${n} value`, { exact: true }).fill(field.value);
    }
    await page.getByLabel(`New custom field ${n} autocomplete id`, { exact: true }).fill(field.id);
  }
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: item.title })).toBeVisible();
  await expect(page.getByText("Synced", { exact: true })).toBeVisible();
}

async function enrol(context: BrowserContext, extensionId: string, server: RunningServer, loginName: string, secretKey: string): Promise<Page> {
  const popup = await context.newPage();
  await popup.goto(`chrome-extension://${extensionId}/src/popup/index.html`);
  await popup.getByLabel("Server URL").fill(server.origin);
  await popup.getByLabel("Account (login name)").fill(loginName);
  await popup.getByLabel("Secret Key").fill(secretKey);
  await popup.getByLabel("Master password").fill(TEST_ACCOUNT_PASSWORD);
  await popup.getByRole("button", { name: "Set up" }).click();
  await expect(popup.getByRole("button", { name: "Lock" })).toBeVisible({ timeout: 30_000 });
  await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
  return popup;
}

/** A real trusted click at the centre of `locator`, after the menu's visibility gate had its
 * first good samples. */
async function realClick(page: Page, locator: Locator): Promise<void> {
  await expect(locator).toBeVisible({ timeout: 15_000 });
  await page.waitForTimeout(250);
  const box = await locator.boundingBox();
  if (box === null) {
    throw new Error("autocomplete e2e: no bounding box");
  }
  await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
}

function menu(page: Page): FrameLocator {
  return page.frameLocator("iframe[data-rizzy-inline-menu]");
}

test("TOTP and custom-field fill: disclosed before the click, filled only on it, exact tokens only", async ({ context, extensionId, server }) => {
  const withCode = await startPages();
  const withoutCode = await startPages();
  try {
    const setup = await context.newPage();
    const secretKey = await signUp(setup, server.origin, "acext");
    await createItem(setup, {
      title: "Code Co",
      username: "alice@example.com",
      password: "alice-pw",
      websiteUrl: `http://127.0.0.1:${withCode.port}/`,
      totp: TOTP_SECRET,
      custom: [
        { label: "Member no.", kind: "text", value: "M-4242", id: "member-no" },
        { label: "PIN", kind: "hidden", value: "9876", id: "pin.code" },
        { label: "Branch", kind: "text", value: "B-1", id: "branch" },
      ],
    });
    await createItem(setup, {
      title: "Plain Co",
      username: "bob@example.com",
      password: "bob-pw",
      // Another host: matching ignores the port (*Base domain*), so a second site needs one.
      websiteUrl: `http://localhost:${withoutCode.port}/`,
    });
    await setup.close();
    await (await enrol(context, extensionId, server, "acext", secretKey)).close();

    // --- A 2FA page: the menu offers the item that holds a code, says so, and fills only on
    // the click.
    const twofa = await context.newPage();
    await twofa.goto(`http://127.0.0.1:${withCode.port}/2fa`);
    const row = menu(twofa).getByRole("button", { name: /Code Co/ });
    await expect(row).toContainText("Also fills: one-time code", { timeout: 15_000 });
    await expect(menu(twofa).getByText("Fills the one-time code only.")).toBeVisible();
    await expect(twofa.locator("#code")).toHaveValue("");
    await realClick(twofa, row);
    await expect(twofa.locator("#code")).toHaveValue(/^\d{6}$/);
    const filled = await twofa.locator("#code").inputValue();
    const now = Date.now() / 1000;
    expect([totpAt(now - 30), totpAt(now), totpAt(now + 30)]).toContain(filled);
    await twofa.close();

    // --- No TOTP-only menu where no candidate can produce a code (rule (g)), and none on the
    // negative pages, even for the item that has one.
    for (const [host, path] of [
      [`localhost:${withoutCode.port}`, "/2fa"],
      [`127.0.0.1:${withCode.port}`, "/neg-csc"],
      [`127.0.0.1:${withCode.port}`, "/neg-sms"],
    ] as const) {
      const page = await context.newPage();
      await page.goto(`http://${host}${path}`);
      await page.waitForTimeout(2_000);
      await expect(page.locator("iframe[data-rizzy-inline-menu]")).toHaveCount(0);
      await page.close();
    }

    // --- Custom fields: disclosed by Display Name with "(hidden)", filled by exact token on
    // the click; the hidden "branch" target is neither disclosed nor filled.
    const custom = await context.newPage();
    await custom.goto(`http://127.0.0.1:${withCode.port}/custom`);
    const customRow = menu(custom).getByRole("button", { name: /Code Co/ });
    await expect(customRow).toContainText("Also fills: Member no. · PIN (hidden)", { timeout: 15_000 });
    await expect(customRow).not.toContainText("Branch");
    await expect(customRow).not.toContainText("M-4242");
    await expect(customRow).not.toContainText("9876");
    await realClick(custom, customRow);
    await expect(custom.locator("#user")).toHaveValue("alice@example.com");
    await expect(custom.locator("#pass")).toHaveValue("alice-pw");
    await expect(custom.locator("#member")).toHaveValue("M-4242");
    await expect(custom.locator("#pin")).toHaveValue("9876");
    await expect(custom.locator("#hiddenpin")).toHaveValue("");
    await custom.close();

    // --- A page that renames a token after the menu showed it (A7 harvesting): the renamed
    // field gets nothing, not even the value of the token it now claims.
    const renamed = await context.newPage();
    await renamed.goto(`http://127.0.0.1:${withCode.port}/custom`);
    const renamedRow = menu(renamed).getByRole("button", { name: /Code Co/ });
    await expect(renamedRow).toContainText("Member no.", { timeout: 15_000 });
    await renamed.evaluate(() => {
      document.getElementById("member")?.setAttribute("autocomplete", "other-token");
      document.getElementById("hiddenpin")?.setAttribute("autocomplete", "x");
      const pin = document.getElementById("pin");
      pin?.setAttribute("autocomplete", "branch");
    });
    await realClick(renamed, renamedRow);
    await expect(renamed.locator("#pass")).toHaveValue("alice-pw");
    await expect(renamed.locator("#member")).toHaveValue("");
    await expect(renamed.locator("#pin")).toHaveValue("");
    await renamed.close();
  } finally {
    await withCode.stop();
    await withoutCode.stop();
  }
});

test("the save dialog offers a submitted custom field in an extension-origin frame; the page cannot tick it", async ({ context, extensionId, server }) => {
  const pages = await startPages();
  try {
    const setup = await context.newPage();
    const secretKey = await signUp(setup, server.origin, "acsave");
    await setup.close();
    const popup = await enrol(context, extensionId, server, "acsave", secretKey);

    const page = await context.newPage();
    await page.goto(`http://127.0.0.1:${pages.port}/signup`);
    await expect(page.locator("iframe[data-rizzy-inline-menu]")).toHaveCount(1, { timeout: 15_000 });
    await page.locator("#user").fill("dora@example.com");
    await page.locator("#pass").fill("dora-pw");
    await page.locator("#club").fill("CLUB-77");
    await page.getByRole("button", { name: "Log in" }).click();

    // The dialog, not the page-DOM banner.
    await expect(page.locator("iframe[data-rizzy-save-dialog]")).toHaveCount(1, { timeout: 15_000 });
    await expect(page.locator("[data-rizzy-save-prompt]")).toHaveCount(0);
    const dialog = page.frameLocator("iframe[data-rizzy-save-dialog]");
    const box = dialog.getByRole("checkbox", { name: "Add custom field" });
    await expect(box).toBeChecked();
    const name = dialog.getByLabel("Display name for club-card");
    await expect(name).toHaveValue("club-card");
    await expect(dialog.getByText("CLUB-77")).toHaveCount(0);
    // The axe audit of our surface only: the test page's own markup (its custom `autocomplete`
    // tokens, which axe calls malformed) is the site's, not the extension's.
    const audit = await new AxeBuilder({ page }).include("iframe[data-rizzy-save-dialog]").withTags(AXE_TAGS).analyze();
    expect(audit.violations.map((v) => v.id + ": " + v.help), "save dialog: axe violations").toEqual([]);
    expect(audit.passes.length, "save dialog: axe evaluated the frame").toBeGreaterThan(0);
    // Keyboard only: the row's checkbox toggles with Space, and Tab reaches its name and Save.
    await box.focus();
    await page.keyboard.press("Space");
    await expect(box).not.toBeChecked();
    await page.keyboard.press("Space");
    await expect(box).toBeChecked();
    await page.keyboard.press("Tab");
    await expect(name).toBeFocused();
    await page.keyboard.press("Tab");
    await expect(dialog.getByRole("button", { name: "Save" })).toBeFocused();

    // A page script can post into the dialog, but the forged show message names a token the
    // background refuses, so the dialog keeps its state; and the page cannot reach the checkbox
    // or the button at all.
    const reach = await page.evaluate(() => {
      const frame = document.querySelector<HTMLIFrameElement>("iframe[data-rizzy-save-dialog]");
      frame?.contentWindow?.postMessage({ type: "rizzy-save-dialog-show", pageOrigin: location.origin, instanceToken: "123e4567-e89b-42d3-a456-426614174000", token: "forged" }, "*");
      try {
        return frame?.contentDocument === null ? "blocked" : "reachable";
      } catch {
        return "blocked";
      }
    });
    expect(reach).toBe("blocked");
    await expect(box).toBeChecked();

    // An empty Display Name cannot be saved (W5).
    await name.fill(" ");
    await expect(dialog.getByRole("button", { name: "Save" })).toBeDisabled();
    await name.fill("Club card");
    await dialog.getByRole("button", { name: "Save" }).click();
    await page.waitForTimeout(1_000);
    if ((await page.locator("iframe[data-rizzy-save-dialog]").count()) > 0) {
      throw new Error("save dialog failed: " + String(await dialog.getByRole("alert").getAttribute("data-code")));
    }
    await expect(page.locator("iframe[data-rizzy-save-dialog]")).toHaveCount(0, { timeout: 15_000 });
    // Pushes the saved item to the server (an explicit sync, as `autofill-and-save.spec.ts`).
    await popup.bringToFront();
    await popup.getByRole("button", { name: "Sync" }).click();
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.getByLabel("Search").fill("127.0.0.1");
    await expect(popup.getByRole("button", { name: /dora@example\.com/ })).toBeVisible();

    // The item reached the server with the custom field, its id the page's token.
    const verify = await context.newPage();
    // As `autofill-and-save.spec.ts` does: the extension's own menu on the vault's login page
    // can swallow the first attempt (`account.ts`'s `logIn` docs).
    await logIn(verify, server.origin, "acsave", secretKey);
    await verify.reload();
    await logIn(verify, server.origin, "acsave", secretKey);
    await verify.getByRole("button", { name: /127\.0\.0\.1/ }).click();
    const row = verify.locator(".field").filter({ hasText: "Club card" });
    await expect(row).toBeVisible({ timeout: 15_000 });
    await row.getByRole("button", { name: "Reveal" }).click();
    await expect(row.locator("input")).toHaveValue("CLUB-77");
    await verify.getByRole("button", { name: "Edit" }).click();
    await expect(verify.getByLabel("Custom field 1 autocomplete id", { exact: true })).toHaveValue("club-card");
    await verify.close();
  } finally {
    await pages.stop();
  }
});

// ADR 0081 §A8: with two vaults, a new login's save prompt is the extension-origin dialog, whose
// vault picker preselects the Personal vault every time; vault names never enter the page DOM.
test("the save prompt's vault picker preselects Personal (ADR 0081 §A8)", async ({ context, extensionId, server }) => {
  const pages = await startPages();
  try {
    const setup = await context.newPage();
    const secretKey = await signUp(setup, server.origin, "acvaults");
    await setup.getByRole("navigation", { name: "Vault navigation" }).getByRole("button", { name: "Manage vaults" }).click();
    await setup.locator(".vaults-pane").getByLabel("Name", { exact: true }).fill("Work");
    await setup.locator(".vaults-pane").getByRole("button", { name: "Create vault" }).click();
    await expect(setup.locator(".vaults-pane tbody tr", { hasText: "Work" })).toBeVisible();
    await setup.close();
    const popup = await enrol(context, extensionId, server, "acvaults", secretKey);

    const page = await context.newPage();
    await page.goto(`http://127.0.0.1:${pages.port}/plain`);
    await expect(page.locator("iframe[data-rizzy-inline-menu]")).toHaveCount(1, { timeout: 15_000 });
    await page.locator("#user").fill("erin@example.com");
    await page.locator("#pass").fill("erin-pw");
    await page.getByRole("button", { name: "Log in" }).click();

    await expect(page.locator("iframe[data-rizzy-save-dialog]")).toHaveCount(1, { timeout: 15_000 });
    const dialog = page.frameLocator("iframe[data-rizzy-save-dialog]");
    const picker = dialog.getByLabel("Vault", { exact: true });
    await expect(picker).toBeVisible();
    await expect(picker.locator("option:checked")).toHaveText("Personal");
    await expect(picker.locator("option")).toHaveText(["Personal", "Work"]);
    // The page never sees a vault name.
    expect(await page.evaluate(() => document.body.innerText.includes("Work"))).toBe(false);
    const audit = await new AxeBuilder({ page }).include("iframe[data-rizzy-save-dialog]").withTags(AXE_TAGS).analyze();
    expect(audit.violations.map((v) => v.id + ": " + v.help), "save dialog with the vault picker: axe violations").toEqual([]);

    await dialog.getByRole("button", { name: "Save" }).click();
    await expect(page.locator("iframe[data-rizzy-save-dialog]")).toHaveCount(0, { timeout: 15_000 });
    await popup.bringToFront();
    await popup.getByRole("button", { name: "Sync" }).click();
    await expect(popup.getByText("Synced.")).toBeVisible({ timeout: 15_000 });
    await popup.getByLabel("Search").fill("erin");
    // The row shows its vault: Personal, the preselected one.
    await expect(popup.getByRole("button", { name: /erin@example\.com.*Personal/ })).toBeVisible();
  } finally {
    await pages.stop();
  }
});

// ADR 0081 §A7 ("every list row shows its vault") and §A8 ("fill offers items from every
// vault"): the inline menu offers the page's logins of both vaults, each row naming its vault as
// the popup's rows do, and fills one from the vault that is not Personal. The label is static
// text in the extension-origin frame: no opacity or transform motion (a framed security
// surface), and the page's DOM never holds it. The menu with the labels passes the axe audit.
test("the inline menu's rows show their vault (ADR 0081 §A7, §A8)", async ({ context, extensionId, server }) => {
  const pages = await startPages();
  try {
    const setup = await context.newPage();
    const secretKey = await signUp(setup, server.origin, "acvaultrows");
    await setup.getByRole("navigation", { name: "Vault navigation" }).getByRole("button", { name: "Manage vaults" }).click();
    await setup.locator(".vaults-pane").getByLabel("Name", { exact: true }).fill("Work");
    await setup.locator(".vaults-pane").getByRole("button", { name: "Create vault" }).click();
    await expect(setup.locator(".vaults-pane tbody tr", { hasText: "Work" })).toBeVisible();
    await setup.getByRole("navigation", { name: "Vault navigation" }).getByRole("button", { name: "All vaults" }).click();
    const site = `http://127.0.0.1:${pages.port}/`;
    await createItem(setup, { title: "Office Mail", username: "frank@work.example", password: "work-pw", websiteUrl: site, vault: "Work" });
    await createItem(setup, { title: "Home Mail", username: "frank@home.example", password: "home-pw", websiteUrl: site });
    await setup.close();
    await (await enrol(context, extensionId, server, "acvaultrows", secretKey)).close();

    const page = await context.newPage();
    await page.goto(`http://127.0.0.1:${pages.port}/plain`);
    const work = menu(page).getByRole("button", { name: /Office Mail/ });
    const home = menu(page).getByRole("button", { name: /Home Mail/ });
    await expect(work).toBeVisible({ timeout: 15_000 });
    await expect(work).toHaveText("Office Mail (frank@work.example) · Work");
    await expect(home).toHaveText("Home Mail (frank@home.example) · Personal");
    // The page never sees a vault name; only the extension-origin frame shows it.
    expect(await page.evaluate(() => document.body.innerText.includes("Work"))).toBe(false);
    // No opacity or transform motion on the label in the framed surface.
    const frame = page.frames().find((f) => f.url().includes("inline-menu"));
    expect(frame, "the inline-menu frame").toBeDefined();
    // The label and its row: no animation, and no transition that moves opacity or transform
    // (`all` with a zero duration is the initial value, which animates nothing).
    const motion = await frame?.evaluate(() =>
      [...document.querySelectorAll(".item-vault")].flatMap((el) =>
        [el, el.parentElement ?? el].map((node) => {
          const style = getComputedStyle(node);
          const properties = style.transitionProperty.split(",").map((p) => p.trim());
          const durations = style.transitionDuration.split(",").map((d) => parseFloat(d));
          return {
            animation: style.animationName,
            moving: properties.filter(
              (p, i) => ["opacity", "transform", "all"].includes(p) && (durations[i % durations.length] ?? 0) > 0,
            ),
            animations: node.getAnimations().length,
          };
        }),
      ),
    );
    expect(motion).toHaveLength(4);
    for (const m of motion ?? []) {
      expect(m.animation).toBe("none");
      expect(m.moving).toEqual([]);
      expect(m.animations).toBe(0);
    }
    // The page's audit runs in every frame, so it covers the extension-origin menu with its
    // vault labels (`a11y.ts`), as `a11y.spec.ts` audits the menu.
    await expectAccessible(page, "inline menu with vault labels (in a login page)");

    // A login of the vault that is not Personal fills on the user's click. The rows wrap in the
    // menu's fixed height, so the second one is scrolled fully into view first: the visibility
    // gate refuses a click on a row it cannot see whole.
    await work.scrollIntoViewIfNeeded();
    await realClick(page, work);
    await expect(page.locator("#user")).toHaveValue("frank@work.example", { timeout: 15_000 });
    await expect(page.locator("#pass")).toHaveValue("work-pw");
  } finally {
    await pages.stop();
  }
});
