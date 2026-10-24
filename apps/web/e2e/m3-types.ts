// SPDX-License-Identifier: AGPL-3.0-only

// The four item types of ADR 0055 (ADR 0078 retired the fifth, Bank account) as the web vault's
// end-to-end specs create them: the "New item"
// menu entry, the editor's heading, and a value for each field, by the field's label. Shared by
// `item-types.spec.ts` (create, view, reveal, filter), `a11y.spec.ts` (the axe audit of each
// editor and item view) and `keyboard-nav.spec.ts` (the keyboard-only walk).
import { type Page, expect } from "@playwright/test";

/** One field: its label in the editor and the item view, its key, and the value typed. */
export interface M3Field {
  readonly label: string;
  readonly key: string;
  readonly value: string;
}

/** One M3 type: its menu label, the editor heading, a title, and its shown and concealed fields
 * (ADR 0055 §1, §4). */
export interface M3Type {
  readonly menu: string;
  readonly heading: string;
  readonly title: string;
  readonly shown: readonly M3Field[];
  readonly concealed: readonly M3Field[];
}

/** An SSH private key: multi-line, stored as entered (ADR 0055 §1). */
export const PRIVATE_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----";

export const M3_TYPES: readonly M3Type[] = [
  {
    menu: "SSH key",
    heading: "New SSH key",
    title: "Deploy key",
    shown: [
      { label: "Host", key: "ssh.host", value: "git.example.com" },
      { label: "Username", key: "ssh.username", value: "git" },
      { label: "Public key", key: "ssh.public_key", value: "ssh-ed25519 AAAAC3Nza alice@example.com" },
    ],
    concealed: [
      { label: "Private key", key: "ssh.private_key", value: PRIVATE_KEY },
      { label: "Passphrase", key: "ssh.passphrase", value: "ssh-pass-phrase" },
    ],
  },
  {
    menu: "API credential",
    heading: "New API credential",
    title: "CI token",
    shown: [
      { label: "Service", key: "api.name", value: "Example API" },
      { label: "Endpoint", key: "api.endpoint", value: "https://api.example.com/v1" },
    ],
    concealed: [
      { label: "API key", key: "api.key", value: "AKIAEXAMPLEKEY" },
      { label: "API secret", key: "api.secret", value: "api-secret-value" },
    ],
  },
  {
    menu: "Software license",
    heading: "New software license",
    title: "Editor licence",
    shown: [
      { label: "Product", key: "license.name", value: "Example Editor" },
      { label: "Seats", key: "license.seats", value: "5" },
      { label: "Expires", key: "license.expires", value: "2027-12-31" },
    ],
    concealed: [{ label: "License key", key: "license.key", value: "ABCD-EFGH-IJKL-MNOP" }],
  },
  {
    menu: "Wi-Fi",
    heading: "New Wi-Fi network",
    title: "Home network",
    shown: [
      { label: "Network name (SSID)", key: "wifi.ssid", value: "home-net" },
      { label: "Security type", key: "wifi.security_type", value: "WPA2" },
    ],
    concealed: [{ label: "Wi-Fi password", key: "wifi.password", value: "wifi-password-value" }],
  },
];

/** `t`'s fields in the editor's order (`FIXED_FIELDS` in `src/fields.ts`), so a keyboard walk
 * reaches each one moving forwards only. */
export function inEditorOrder(t: M3Type): M3Field[] {
  return [...t.shown, ...t.concealed].sort((a, b) => EDITOR_ORDER.indexOf(a.key) - EDITOR_ORDER.indexOf(b.key));
}

/** Every M3 key in the editor's order (ADR 0055 §1's table, as `src/fields.ts` lays it out). */
const EDITOR_ORDER = [
  "ssh.host",
  "ssh.port",
  "ssh.username",
  "ssh.private_key",
  "ssh.public_key",
  "ssh.passphrase",
  "api.name",
  "api.key",
  "api.secret",
  "api.endpoint",
  "license.name",
  "license.key",
  "license.seats",
  "license.expires",
  "wifi.ssid",
  "wifi.password",
  "wifi.security_type",
];

/** Fills the open editor for `t` with the pointer and saves it; waits for the item view. */
export async function fillAndSave(page: Page, t: M3Type): Promise<void> {
  await expect(page.getByRole("heading", { name: t.heading })).toBeVisible();
  await page.getByLabel("Title", { exact: true }).fill(t.title);
  for (const f of [...t.shown, ...t.concealed]) {
    await page.getByLabel(f.label, { exact: true }).fill(f.value);
  }
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: t.title })).toBeVisible();
}

/** The item view's line of field `key`. */
export function fieldLine(page: Page, key: string) {
  return page.locator(`.item [data-field="${key}"]`);
}
