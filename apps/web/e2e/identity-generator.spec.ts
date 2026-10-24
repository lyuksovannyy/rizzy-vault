// SPDX-License-Identifier: AGPL-3.0-only

// The identity generator end to end (ADR 0079 §10, §12 "Web e2e"; `src/views/IdentityGenerator.tsx`,
// `src/views/IdentityDefaultsPane.tsx`): a new identity opens pre-filled; each picker redraws only
// the untouched fields that depend on it; each field's Regenerate button works and Regenerate all
// keeps the fields the user edited; Start blank clears every generated value; with no domain set
// the email stays empty and the field says so; the age select keeps the birthday inside each
// preset, a custom range and an exact age, an invalid value shows its error and redraws nothing,
// and a remembered exact age (set in Settings → Identity generator) reopens as "Exact age"; the
// email field is a plain input; a saved identity keeps every field across a reload and a sync to
// another session; and an imported `identity.sex` that holds other text shows as entered.
import { type Locator, type Page, expect, test } from "@playwright/test";

import { logIn, newItem, signUp, watch } from "./helpers.ts";
import { type RunningServer, startServer } from "./server.ts";

let server: RunningServer;

test.beforeAll(async () => {
  server = await startServer();
});

test.afterAll(() => {
  server.stop();
});

/** The editor's input (or select) of a field key. */
function field(page: Page, key: string): Locator {
  return page.locator(`.item-editor [name="${key}"]`);
}

/** The generator bar. */
function bar(page: Page): Locator {
  return page.getByRole("group", { name: "Generated details" });
}

/** The polite live region of the bar. */
function liveRegion(page: Page): Locator {
  return bar(page).locator("p.sr-only[role=status]");
}

/** The completed age today of a `YYYY-MM-DD` birthday (local date, like the Worker's). */
function ageOf(birthday: string): number {
  const [y, m, d] = birthday.split("-").map(Number);
  const now = new Date();
  let age = now.getFullYear() - (y ?? 0);
  if (now.getMonth() + 1 < (m ?? 0) || (now.getMonth() + 1 === m && now.getDate() < (d ?? 0))) {
    age -= 1;
  }
  return age;
}

/** Waits for the first draw, then returns the birthday's age. */
async function birthdayAge(page: Page): Promise<number> {
  const value = await field(page, "identity.birthday").inputValue();
  expect(value).toMatch(/^\d{4}-\d{2}-\d{2}$/u);
  return ageOf(value);
}

/** Opens "New identity" and waits until the generator has filled it. */
async function newIdentity(page: Page): Promise<void> {
  await newItem(page, "Identity");
  await expect(page.getByRole("heading", { name: "New identity" })).toBeVisible();
  await expect(bar(page)).toBeVisible();
  await expect(field(page, "identity.first_name")).not.toHaveValue("");
}

/** The values of the given keys. */
async function values(page: Page, keys: readonly string[]): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  for (const key of keys) {
    out[key] = await field(page, key).inputValue();
  }
  return out;
}

/** Clicks a field's Regenerate button until its value changes (a redraw may repeat a value). */
async function regenerateUntilChanged(page: Page, key: string, name: string): Promise<void> {
  const before = await field(page, key).inputValue();
  const button = page.getByRole("button", { name: `Regenerate ${name}`, exact: true });
  for (let i = 0; i < 8; i += 1) {
    await button.click();
    await expect(liveRegion(page)).toHaveText(`${name.charAt(0).toUpperCase()}${name.slice(1)} regenerated`);
    if ((await field(page, key).inputValue()) !== before) {
      return;
    }
  }
  throw new Error(`Regenerate ${name} never changed the value`);
}

const ADDRESS = ["identity.address1", "identity.postal_code"];

test("a new identity opens pre-filled; pickers, Regenerate, Regenerate all and Start blank", async ({ page }) => {
  const { problems } = watch(page);
  await signUp(page, server.origin, "IdentityGenUser");
  await newIdentity(page);

  // Pre-filled: every generated field but the email (no domain yet, §8).
  for (const key of [
    "identity.sex",
    "identity.title",
    "identity.first_name",
    "identity.last_name",
    "identity.birthday",
    "identity.username",
    "identity.address1",
    "identity.city",
    "identity.state",
    "identity.postal_code",
    "identity.country",
  ]) {
    await expect(field(page, key), key).not.toHaveValue("");
  }
  const first = await values(page, ["identity.first_name", "identity.last_name", "identity.sex"]);
  await expect(page.getByLabel("Title", { exact: true })).toHaveValue(
    `${first["identity.first_name"]} ${first["identity.last_name"]}`,
  );
  // The sex radio starts at the draw's sex (no default set); the first-time range is 18–27.
  const drawn = first["identity.sex"] === "male" ? "Male" : "Female";
  await expect(bar(page).getByRole("radio", { name: drawn, exact: true })).toBeChecked();
  await expect(bar(page).getByLabel("Age", { exact: true })).toHaveValue("18-27");
  expect(await birthdayAge(page)).toBeGreaterThanOrEqual(18);
  expect(await birthdayAge(page)).toBeLessThanOrEqual(27);
  await expect(page.getByText("Generated details are random and may match real people or places.")).toBeVisible();

  // No domain: the email is empty, says how to get one, and is a plain input with no Regenerate.
  const email = field(page, "identity.email");
  await expect(email).toHaveValue("");
  await expect(page.getByText("Set an email domain to generate addresses")).toBeVisible();
  await expect(email).toHaveAttribute("aria-describedby", /.+/u);
  expect(await email.evaluate((el) => el.tagName)).toBe("INPUT");
  expect(await email.getAttribute("type")).toBeNull();
  expect(await email.getAttribute("list")).toBeNull();
  expect(await email.getAttribute("role")).toBeNull();
  await expect(page.getByRole("button", { name: "Regenerate email" })).toHaveCount(0);
  // Never on edit: the item editor of a saved item has no generator (checked below).

  // Country picker: redraws the address and names, keeps the edited city, the birthday and the
  // username (§4: every step but the birthday and the nickname).
  await field(page, "identity.city").fill("My town");
  let before = await values(page, ["identity.birthday", "identity.username", ...ADDRESS]);
  await bar(page).getByLabel("Country", { exact: true }).selectOption("DE");
  await expect(field(page, "identity.country")).toHaveValue("DE");
  await expect(liveRegion(page)).toContainText("regenerated");
  await expect(field(page, "identity.city")).toHaveValue("My town");
  await expect(field(page, "identity.birthday")).toHaveValue(before["identity.birthday"] ?? "");
  await expect(field(page, "identity.username")).toHaveValue(before["identity.username"] ?? "");
  await expect(field(page, "identity.address1")).not.toHaveValue(before["identity.address1"] ?? "");

  // Sex picker: the sex and the first name follow; the address and birthday stay.
  const other = drawn === "Male" ? "Female" : "Male";
  before = await values(page, ["identity.birthday", ...ADDRESS]);
  await field(page, "identity.last_name").fill("Typed");
  await bar(page).getByRole("radio", { name: other, exact: true }).check();
  await expect(field(page, "identity.sex")).toHaveValue(other.toLowerCase());
  await expect(field(page, "identity.last_name")).toHaveValue("Typed");
  for (const key of ["identity.birthday", ...ADDRESS]) {
    await expect(field(page, key)).toHaveValue(before[key] ?? "");
  }

  // Age picker: only the birthday (the email too, if it were generated).
  before = await values(page, ["identity.first_name", ...ADDRESS]);
  await bar(page).getByLabel("Age", { exact: true }).selectOption("61-65");
  await expect.poll(() => birthdayAge(page)).toBeGreaterThanOrEqual(61);
  expect(await birthdayAge(page)).toBeLessThanOrEqual(65);
  for (const key of ["identity.first_name", ...ADDRESS]) {
    await expect(field(page, key)).toHaveValue(before[key] ?? "");
  }

  // Email style picker: no domain, so the email stays empty; the address stays.
  before = await values(page, ["identity.birthday", ...ADDRESS]);
  await bar(page).getByRole("radio", { name: "Nickname" }).check();
  await expect(liveRegion(page)).not.toHaveText("");
  await expect(email).toHaveValue("");
  for (const key of ["identity.birthday", ...ADDRESS]) {
    await expect(field(page, key)).toHaveValue(before[key] ?? "");
  }

  // Each field's own Regenerate works, and overwrites an edited value.
  await field(page, "identity.first_name").fill("Bob");
  await regenerateUntilChanged(page, "identity.first_name", "first name");
  await expect(field(page, "identity.first_name")).not.toHaveValue("Bob");
  await regenerateUntilChanged(page, "identity.last_name", "last name");
  await expect(field(page, "identity.last_name")).not.toHaveValue("Typed");
  for (const [key, name] of [
    ["identity.birthday", "birthday"],
    ["identity.username", "username"],
    ["identity.address1", "address line 1"],
    ["identity.city", "city"],
    ["identity.postal_code", "postal code"],
    ["identity.phone", "phone"],
  ] as const) {
    await regenerateUntilChanged(page, key, name);
  }
  for (const [key, name] of [
    ["identity.sex", "sex"],
    ["identity.title", "title"],
    ["identity.state", "state or province"],
    ["identity.country", "country"],
  ] as const) {
    await page.getByRole("button", { name: `Regenerate ${name}`, exact: true }).click();
    await expect(liveRegion(page)).toHaveText(`${name.charAt(0).toUpperCase()}${name.slice(1)} regenerated`);
    await expect(field(page, key)).not.toHaveValue("");
  }
  // The sex and country Regenerate keep the pickers' values.
  await expect(field(page, "identity.sex")).toHaveValue(other.toLowerCase());
  await expect(field(page, "identity.country")).toHaveValue("DE");

  // Regenerate all keeps the edited fields and redraws the rest.
  await field(page, "identity.last_name").fill("Edited");
  await field(page, "identity.city").fill("Kept town");
  for (let i = 0; i < 5; i += 1) {
    before = await values(page, ADDRESS);
    await bar(page).getByRole("button", { name: "Regenerate all" }).click();
    await expect(liveRegion(page)).toContainText("All generated fields regenerated");
    if ((await field(page, "identity.address1").inputValue()) !== before["identity.address1"]) {
      break;
    }
  }
  await expect(field(page, "identity.address1")).not.toHaveValue(before["identity.address1"] ?? "");
  await expect(field(page, "identity.last_name")).toHaveValue("Edited");
  await expect(field(page, "identity.city")).toHaveValue("Kept town");

  // Start blank clears every generated value (typed ones stay) and the item name.
  await bar(page).getByRole("button", { name: "Start blank" }).click();
  await expect(liveRegion(page)).toHaveText("Generated values cleared");
  for (const key of [
    "identity.title",
    "identity.first_name",
    "identity.birthday",
    "identity.username",
    "identity.address1",
    "identity.state",
    "identity.postal_code",
    "identity.country",
    "identity.phone",
  ]) {
    await expect(field(page, key), key).toHaveValue("");
  }
  await expect(field(page, "identity.sex")).toHaveValue("");
  await expect(page.getByLabel("Title", { exact: true })).toHaveValue("");
  await expect(field(page, "identity.last_name")).toHaveValue("Edited");
  await expect(field(page, "identity.city")).toHaveValue("Kept town");
  // A picker change does not refill a blank form.
  await bar(page).getByLabel("Age", { exact: true }).selectOption("31-35");
  await expect(liveRegion(page)).toContainText("No field regenerated");
  await expect(field(page, "identity.first_name")).toHaveValue("");

  await page.getByRole("button", { name: "Cancel" }).click();
  expect(problems).toEqual([]);
});

test("the age select: presets, Custom range, Exact age, errors, and this session's last range", async ({ page }) => {
  const { problems } = watch(page);
  await signUp(page, server.origin, "IdentityAgeUser");
  await newIdentity(page);
  const age = bar(page).getByLabel("Age", { exact: true });

  const presets: [string, number, number][] = [
    ["18-27", 18, 27],
    ["28-65", 28, 65],
    ["21-25", 21, 25],
    ["26-30", 26, 30],
    ["31-35", 31, 35],
    ["36-40", 36, 40],
    ["41-45", 41, 45],
    ["46-50", 46, 50],
    ["51-55", 51, 55],
    ["56-60", 56, 60],
    ["61-65", 61, 65],
    ["any", 21, 65],
  ];
  const labels = await age.locator("option").allTextContents();
  expect(labels).toEqual([
    "18–27",
    "28+",
    "21–25",
    "26–30",
    "31–35",
    "36–40",
    "41–45",
    "46–50",
    "51–55",
    "56–60",
    "61–65",
    "Any (21–65)",
    "Custom range",
    "Exact age",
  ]);
  for (const [id, min, max] of presets) {
    await age.selectOption(id);
    await expect.poll(async () => {
      const a = await birthdayAge(page);
      return a >= min && a <= max;
    }, id).toBe(true);
  }

  // Custom range: Min and Max, each labelled.
  await age.selectOption("custom");
  const min = bar(page).getByLabel("Min", { exact: true });
  const max = bar(page).getByLabel("Max", { exact: true });
  await min.fill("30");
  await max.fill("32");
  await expect.poll(async () => {
    const a = await birthdayAge(page);
    return a >= 30 && a <= 32;
  }).toBe(true);

  // Invalid: Min above Max, then out of bounds. Each shows its error, tied to its input, and
  // nothing is redrawn.
  const birthday = await field(page, "identity.birthday").inputValue();
  await min.fill("40");
  await expect(max).toHaveAttribute("aria-invalid", "true");
  const maxError = page.locator(`#${(await max.getAttribute("aria-describedby")) ?? "none"}`);
  await expect(maxError).toHaveText("Max must not be below Min.");
  await min.fill("17");
  await expect(min).toHaveAttribute("aria-invalid", "true");
  const minError = page.locator(`#${(await min.getAttribute("aria-describedby")) ?? "none"}`);
  await expect(minError).toHaveText("Enter an age from 18 to 99.");
  await page.waitForTimeout(300);
  await expect(field(page, "identity.birthday")).toHaveValue(birthday);
  await min.fill("31");
  await expect(min).not.toHaveAttribute("aria-invalid", "true");
  await expect.poll(async () => {
    const a = await birthdayAge(page);
    return a >= 31 && a <= 32;
  }).toBe(true);

  // Exact age: one labelled input.
  await age.selectOption("exact");
  const exact = bar(page).getByLabel("Age (years)", { exact: true });
  await exact.fill("45");
  await expect.poll(() => birthdayAge(page)).toBe(45);
  const exactBirthday = await field(page, "identity.birthday").inputValue();
  await exact.fill("100");
  await expect(exact).toHaveAttribute("aria-invalid", "true");
  await expect(page.locator(`#${(await exact.getAttribute("aria-describedby")) ?? "none"}`)).toHaveText(
    "Enter an age from 18 to 99.",
  );
  await page.waitForTimeout(300);
  await expect(field(page, "identity.birthday")).toHaveValue(exactBirthday);
  await exact.fill("52");
  await expect.poll(() => birthdayAge(page)).toBe(52);

  // Saved: the next new identity of this session starts from that range (session memory only).
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "New identity" })).toHaveCount(0);
  await newIdentity(page);
  await expect(bar(page).getByLabel("Age", { exact: true })).toHaveValue("exact");
  await expect(bar(page).getByLabel("Age (years)", { exact: true })).toHaveValue("52");
  expect(await birthdayAge(page)).toBe(52);
  await page.getByRole("button", { name: "Cancel" }).click();
  expect(problems).toEqual([]);
});

/** Opens Settings → Identity generator. */
async function openIdentitySettings(page: Page): Promise<Locator> {
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  const pane = page.getByRole("region", { name: "Identity generator" });
  await expect(pane).toBeVisible();
  await expect(pane.getByLabel("Default sex")).toBeVisible();
  return pane;
}

/** The item view's shown value of a field. */
function shown(page: Page, key: string): Locator {
  return page.locator(`.field[data-field="${key}"] .field-value`);
}

/** `YYYY-MM-DD` as the item view shows it (en-US, Playwright's default locale). */
function longDate(iso: string): string {
  const [y, m, d] = iso.split("-").map(Number);
  return new Date(Date.UTC(y ?? 0, (m ?? 1) - 1, d ?? 1)).toLocaleDateString("en-US", {
    timeZone: "UTC",
    dateStyle: "long",
  });
}

test("settings defaults and domain; a remembered exact age; saving persists across reload and sync", async ({
  page,
  browser,
}) => {
  const { problems } = watch(page);
  const name = "IdentitySettingsUser";
  const secretKey = await signUp(page, server.origin, name);

  // Settings → Identity generator: an invalid domain is refused inline; a valid one is saved
  // lower-cased with the other defaults (a fresh login, so the commit is taken).
  let pane = await openIdentitySettings(page);
  await pane.getByLabel("Default sex").selectOption("female");
  await pane.getByLabel("Default country").selectOption("SE");
  await pane.getByLabel("Default age").selectOption("exact");
  await pane.getByLabel("Age (years)", { exact: true }).fill("33");
  await pane.getByRole("radio", { name: "Nickname" }).check();
  const domain = pane.getByLabel("Email domain for generated identities");
  await domain.fill("not a domain");
  await pane.getByRole("button", { name: "Save identity defaults" }).click();
  await expect(domain).toHaveAttribute("aria-invalid", "true");
  await expect(pane.getByText("Enter a domain name such as example.com.")).toBeVisible();
  await domain.fill("Example.COM");
  await pane.getByRole("button", { name: "Save identity defaults" }).click();
  await expect(pane.getByRole("status")).toHaveText("The identity generator defaults are saved.");
  await expect(domain).toHaveValue("example.com");
  await expect(pane.getByLabel("Default age")).toHaveValue("exact");

  // A new identity opens with them: the remembered exact age reopens as "Exact age".
  await page.getByRole("button", { name: "All items", exact: true }).click();
  await newIdentity(page);
  await expect(bar(page).getByLabel("Age", { exact: true })).toHaveValue("exact");
  await expect(bar(page).getByLabel("Age (years)", { exact: true })).toHaveValue("33");
  expect(await birthdayAge(page)).toBe(33);
  await expect(bar(page).getByLabel("Country", { exact: true })).toHaveValue("SE");
  await expect(field(page, "identity.country")).toHaveValue("SE");
  await expect(bar(page).getByRole("radio", { name: "Female", exact: true })).toBeChecked();
  await expect(field(page, "identity.sex")).toHaveValue("female");
  await expect(bar(page).getByRole("radio", { name: "Nickname" })).toBeChecked();
  // With a domain, the email is generated, in a plain input.
  const email = field(page, "identity.email");
  await expect(email).toHaveValue(/@example\.com$/u);
  expect(await email.getAttribute("type")).toBeNull();
  expect(await email.getAttribute("list")).toBeNull();
  await expect(page.getByText("Set an email domain to generate addresses")).toHaveCount(0);
  await regenerateUntilChanged(page, "identity.email", "email");
  await expect(email).toHaveValue(/@example\.com$/u);
  // A typed email survives Regenerate all.
  await email.fill("me@example.com");
  await bar(page).getByRole("button", { name: "Regenerate all" }).click();
  await expect(liveRegion(page)).toContainText("All generated fields regenerated");
  await expect(email).toHaveValue("me@example.com");

  // Save, and check every field in the item view.
  await page.getByLabel("Title", { exact: true }).fill("Shopping persona");
  const keys = [
    "identity.sex",
    "identity.title",
    "identity.first_name",
    "identity.last_name",
    "identity.birthday",
    "identity.email",
    "identity.username",
    "identity.address1",
    "identity.city",
    "identity.state",
    "identity.postal_code",
    "identity.country",
  ];
  const saved = await values(page, keys);
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "Shopping persona" })).toBeVisible();
  await expect(page.getByText("Synced", { exact: true })).toBeVisible();

  const checkView = async (p: Page) => {
    for (const key of keys) {
      const value = saved[key] ?? "";
      const expected =
        key === "identity.sex"
          ? "Female"
          : key === "identity.birthday"
            ? longDate(value)
            : key === "identity.country"
              ? // ADR 0079 §1: a two-letter code with the country's name next to it, in the browser's locale.
                await p.evaluate((v) => `${v} (${new Intl.DisplayNames(undefined, { type: "region" }).of(v) ?? v})`, value)
              : value;
      await expect(shown(p, key), key).toHaveText(expected);
    }
  };
  await checkView(page);

  // The edit form has no generator, and shows the stored values in the sex select and date input.
  await page.getByRole("button", { name: "Edit" }).click();
  await expect(page.getByRole("heading", { name: "Edit item" })).toBeVisible();
  await expect(bar(page)).toHaveCount(0);
  await expect(page.getByRole("button", { name: /^Regenerate/u })).toHaveCount(0);
  await expect(field(page, "identity.sex")).toHaveValue("female");
  expect(await field(page, "identity.sex").evaluate((el) => el.tagName)).toBe("SELECT");
  await expect(field(page, "identity.birthday")).toHaveAttribute("type", "date");
  await expect(field(page, "identity.birthday")).toHaveValue(saved["identity.birthday"] ?? "");
  await page.getByRole("button", { name: "Cancel" }).click();

  // A reload, and a log-in: the same fields, from the server.
  await page.reload();
  await logIn(page, name, secretKey);
  await page.getByRole("button", { name: /Shopping persona/u }).click();
  await checkView(page);
  // The settings came back from the server too.
  pane = await openIdentitySettings(page);
  await expect(pane.getByLabel("Email domain for generated identities")).toHaveValue("example.com");
  await expect(pane.getByLabel("Default country")).toHaveValue("SE");

  // A second session of the account syncs the identity.
  const other = await browser.newContext();
  const b = await other.newPage();
  await b.goto(server.origin);
  await logIn(b, name, secretKey);
  await b.getByRole("button", { name: /Shopping persona/u }).click();
  await checkView(b);
  await other.close();
  expect(problems).toEqual([]);
});

test("an identity whose sex and birthday hold other text shows and edits them as entered", async ({ page }) => {
  const { problems } = watch(page);
  await signUp(page, server.origin, "IdentityOtherTextUser");
  const file = JSON.stringify({
    format: "rizzy-vault-plaintext-export",
    version: 1,
    items: [
      {
        id: "ab".repeat(16),
        type: 4,
        trashed: false,
        fields: [
          { key: "item.name", value: { text: "Imported persona" } },
          { key: "identity.first_name", value: { text: "Alex" } },
          { key: "identity.sex", value: { text: "Nonbinary" } },
          { key: "identity.birthday", value: { text: "04/17/1998" } },
        ],
      },
    ],
  });
  await page.getByRole("button", { name: "Export and import", exact: true }).click();
  await page
    .getByLabel("File", { exact: true })
    .setInputFiles({ name: "import.json", mimeType: "application/json", buffer: Buffer.from(file) });
  const importButton = page.getByRole("button", { name: "Import", exact: true });
  await expect(importButton).toBeEnabled({ timeout: 15_000 });
  await importButton.click();
  await expect(page.getByTestId("import-report")).toBeVisible();

  await page.getByRole("button", { name: "All items", exact: true }).click();
  await page.getByRole("button", { name: /Imported persona/u }).click();
  await expect(shown(page, "identity.sex")).toHaveText("Nonbinary");
  await expect(shown(page, "identity.birthday")).toHaveText("04/17/1998");

  // Edited as text, never rewritten: an unrelated edit keeps both values.
  await page.getByRole("button", { name: "Edit" }).click();
  const sex = field(page, "identity.sex");
  expect(await sex.evaluate((el) => el.tagName)).toBe("INPUT");
  await expect(sex).toHaveValue("Nonbinary");
  await expect(field(page, "identity.birthday")).not.toHaveAttribute("type", "date");
  await expect(field(page, "identity.birthday")).toHaveValue("04/17/1998");
  await field(page, "identity.city").fill("Graz");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(shown(page, "identity.city")).toHaveText("Graz");
  await expect(shown(page, "identity.sex")).toHaveText("Nonbinary");
  await expect(shown(page, "identity.birthday")).toHaveText("04/17/1998");
  expect(problems).toEqual([]);
});
