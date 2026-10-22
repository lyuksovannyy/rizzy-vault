// SPDX-License-Identifier: AGPL-3.0-only

// Encrypted attachments in the web vault (ADR 0054), in the real browser against a real server:
// attach a two-chunk file to an item, see it listed, download it byte for byte (the core opens
// every chunk where it asked for it and assembles only a complete set, INV-79), check that the
// bytes the server stores are not the file, refuse a file over 25 MiB before it is read, and
// delete it (the server row and the item's fields). The attachments section is in the axe audit
// and the keyboard walk too (`a11y.spec.ts`, `keyboard-nav.spec.ts`).
import { readFile } from "node:fs/promises";

import { expect, test } from "@playwright/test";

import { expectAccessible } from "./a11y.ts";
import { newItem, signUp, watch } from "./helpers.ts";
import { type RunningServer, startServer } from "./server.ts";

let server: RunningServer;

test.beforeAll(async () => {
  server = await startServer();
});

test.afterAll(() => {
  server.stop();
});

/** A file of `len` bytes whose byte i is i mod 251, with a marker the server must never see. */
function fileBytes(len: number, marker: string): Buffer {
  const data = Buffer.alloc(len);
  for (let i = 0; i < len; i += 1) {
    data[i] = i % 251;
  }
  data.write(marker, 1000, "utf8");
  return data;
}

test("attach, download byte for byte, and delete an encrypted file (ADR 0054)", async ({ page }) => {
  const { problems } = watch(page);
  // What the browser sends to the server: no chunk may carry the file's plaintext.
  const bodies: string[] = [];
  page.on("request", (request) => {
    if (request.url().includes("/api/v1/attachments/")) {
      bodies.push(request.postData() ?? "");
    }
  });
  await signUp(page, server.origin, "attachuser");
  await newItem(page, "Login");
  await page.getByLabel("Title").fill("With a file");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "With a file" })).toBeVisible();

  const section = page.getByRole("region", { name: "Attachments" });
  await expect(section.getByText("No attachments.")).toBeVisible();
  const marker = "ATTACHMENT-CANARY-7f3a9c";
  // 600 000 bytes: one full 512 KiB chunk and a short last one.
  const data = fileBytes(600_000, marker);
  await section.getByLabel("Attach a file").setInputFiles({ name: "report.bin", mimeType: "application/x-test", buffer: data });
  await expect(page.getByText("Attached report.bin.")).toBeVisible();
  const row = section.locator("li.attachment");
  await expect(row).toHaveCount(1);
  await expect(row).toContainText("report.bin");
  await expect(row).toContainText("585.9 KiB");
  await expect(row).toContainText("application/x-test");
  await expectAccessible(page, "item view with an attachment");

  // The server got ciphertext only: the marker is in no request body, raw or base64.
  expect(bodies.length).toBeGreaterThanOrEqual(3);
  const b64 = Buffer.from(marker).toString("base64url").slice(2, 20);
  for (const body of bodies) {
    expect(body).not.toContain(marker);
    expect(body).not.toContain(b64);
  }

  // Download: the saved file is the original, byte for byte.
  const downloading = page.waitForEvent("download");
  await section.getByRole("button", { name: "Download report.bin" }).click();
  const download = await downloading;
  expect(download.suggestedFilename()).toBe("report.bin");
  const path = await download.path();
  expect(Buffer.compare(await readFile(path), data)).toBe(0);
  await expect(page.getByText("Downloaded report.bin.")).toBeVisible();

  // Over 25 MiB: refused before anything is read or sent.
  const sent = bodies.length;
  await section
    .getByLabel("Attach a file")
    .setInputFiles({ name: "big.bin", mimeType: "application/octet-stream", buffer: Buffer.alloc(25 * 1024 * 1024 + 1) });
  await expect(section.getByRole("alert")).toContainText("larger than 25 MiB");
  expect(bodies.length).toBe(sent);
  await expect(row).toHaveCount(1);

  // Delete, through the confirmation dialog.
  await section.getByRole("button", { name: "Delete report.bin" }).click();
  const dialog = page.getByRole("dialog", { name: "Delete this attachment?" });
  await expect(dialog).toBeVisible();
  await expectAccessible(page, "delete attachment dialog");
  await dialog.getByRole("button", { name: "Delete attachment" }).click();
  await expect(page.getByText("Deleted report.bin.")).toBeVisible();
  await expect(section.getByText("No attachments.")).toBeVisible();
  expect(bodies.some((b) => b.includes("attachment_id") && !b.includes("envelope"))).toBe(true);
  expect(problems).toEqual([]);
});
