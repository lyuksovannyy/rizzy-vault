// SPDX-License-Identifier: AGPL-3.0-only

// The M3 item types of ADR 0055 end to end: each is created from the "New item" menu, its shown
// fields display as typed, its concealed fields (§4) stay masked until "Reveal" and cross only
// then (ADR 0013 §3 rule 3), each secret input passes INV-68, an SSH private key keeps its line
// breaks (Text "stored as entered", §1), an SSH key without a port shows the default 22 (§1)
// until one is stored, and the sidebar's type filters list each type's items only.
import { expect, test } from "@playwright/test";

import { checkSecretField, newItem, secretField, signUp, watch } from "./helpers.ts";
import { M3_TYPES, PRIVATE_KEY, fieldLine, fillAndSave } from "./m3-types.ts";
import { type RunningServer, startServer } from "./server.ts";

let server: RunningServer;

test.beforeAll(async () => {
  server = await startServer();
});

test.afterAll(() => {
  server.stop();
});

test("M3 item types: create, view, reveal and filter each type", async ({ page }) => {
  const { problems } = watch(page);
  await signUp(page, server.origin, "m3types");

  for (const t of M3_TYPES) {
    await newItem(page, t.menu);
    await expect(page.getByRole("heading", { name: t.heading })).toBeVisible();
    // INV-68 on every concealed field's input, before and after "Show".
    for (const f of t.concealed) {
      const field = secretField(page, f.label);
      if (f.key === "ssh.private_key") {
        // A multi-line secret is a textarea (`SecretField`'s `multiline`), masked by CSS.
        const area = field.locator("textarea[data-secret-field]");
        await expect(area).toHaveAttribute("spellcheck", "false");
        await expect(area).toHaveAttribute("autocomplete", "off");
        await expect(area).toHaveAttribute("data-masked", "true");
        // Masked in Chromium through `-webkit-text-security` (`.secret-masked`, app.css).
        expect(await area.evaluate((el) => getComputedStyle(el).getPropertyValue("-webkit-text-security"))).toBe("disc");
        await field.getByRole("button", { name: "Show" }).click();
        expect(await area.evaluate((el) => getComputedStyle(el).getPropertyValue("-webkit-text-security"))).toBe("none");
        await expect(area).toHaveAttribute("data-masked", "false");
        await expect(area).toHaveAttribute("spellcheck", "false");
        await field.getByRole("button", { name: "Hide" }).click();
        await expect(area).toHaveAttribute("data-masked", "true");
      } else {
        await checkSecretField(field);
      }
    }
    await fillAndSave(page, t);
    await expect(page.locator(".item p.muted").first()).toHaveText(t.menu);

    for (const f of t.shown) {
      await expect(fieldLine(page, f.key)).toContainText(f.value);
    }
    for (const f of t.concealed) {
      const line = fieldLine(page, f.key);
      await expect(line.locator(".masked")).toBeVisible();
      await expect(line).not.toContainText(f.value.split("\n")[0] ?? f.value);
      await line.getByRole("button", { name: "Reveal" }).click();
      const shown = line.locator("[data-secret-field]");
      await expect(shown).toHaveValue(f.value);
      await expect(shown).toHaveAttribute("spellcheck", "false");
      // The view's own "Hide" (not the secret field's mask toggle) drops the revealed value.
      await line.locator(".field-actions").getByRole("button", { name: "Hide" }).click();
      await expect(line.locator(".masked")).toBeVisible();
    }
    expect(await page.content()).not.toContain(t.concealed[0]?.value ?? "-");
  }

  // The SSH key: no port was typed, so the view shows the default; a stored port replaces it.
  await page.getByRole("button", { name: /Deploy key/ }).first().click();
  await expect(page.getByRole("heading", { name: "Deploy key" })).toBeVisible();
  await expect(fieldLine(page, "ssh.port")).toHaveText(/Port\s*22 \(default\)/);
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  await expect(page.getByLabel("Port", { exact: true })).toHaveAttribute("placeholder", "22");
  await page.getByLabel("Port", { exact: true }).fill("2222");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(fieldLine(page, "ssh.port")).toContainText("2222");
  await expect(fieldLine(page, "ssh.port")).not.toContainText("(default)");
  // The private key is still the one typed, line breaks included.
  await fieldLine(page, "ssh.private_key").getByRole("button", { name: "Reveal" }).click();
  await expect(fieldLine(page, "ssh.private_key").locator("textarea")).toHaveValue(PRIVATE_KEY);

  // Each type's sidebar filter lists that type's item and nothing else.
  for (const t of M3_TYPES) {
    await page.getByRole("button", { name: t.menu, exact: true }).click();
    await expect(page.locator(".row-title")).toHaveText([t.title]);
  }
  await page.getByRole("button", { name: "All items", exact: true }).click();
  await expect(page.locator(".row-title")).toHaveCount(M3_TYPES.length);
  expect(problems).toEqual([]);
});
