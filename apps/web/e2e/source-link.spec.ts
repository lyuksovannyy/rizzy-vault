// SPDX-License-Identifier: AGPL-3.0-only

// The footer's "Source" link end to end (ADR 0106 §4, implementation step 7; ADR 0017 §7, AGPL
// §13): on the login screen, before anything is typed, a server started with
// `RIZZY_SOURCE_URL` shows "Source" linking exactly there, in a new tab with no opener and no
// referrer; the signup screen has it too, and both pass the accessibility audit with it. A
// server without the setting links to this build's upstream source.
import { expect, test } from "@playwright/test";

import { expectAccessible } from "./a11y.ts";
import { watch } from "./helpers.ts";
import { type RunningServer, startServer } from "./server.ts";

const SOURCE_URL = "https://example.com/src";
const UPSTREAM = "https://github.com/lyuksovannyy/rizzy-vault";

let configured: RunningServer;
let unset: RunningServer;

test.beforeAll(async () => {
  configured = await startServer("127.0.0.1", { RIZZY_SOURCE_URL: SOURCE_URL });
  unset = await startServer();
});

test.afterAll(() => {
  configured.stop();
  unset.stop();
});

test("source link: the configured URL on the login and signup screens", async ({ page }) => {
  const { problems } = watch(page);
  await page.goto(configured.origin);
  await expect(page.getByRole("heading", { name: "Log in to rizzy-vault" })).toBeVisible();
  const footer = page.getByRole("contentinfo");
  const link = footer.getByRole("link", { name: "Source" });
  await expect(link).toBeVisible();
  await expect(link).toHaveAttribute("href", SOURCE_URL);
  await expect(link).toHaveAttribute("target", "_blank");
  await expect(link).toHaveAttribute("rel", "noopener noreferrer");
  await expect(link).toHaveAttribute("title", SOURCE_URL);
  await expect(footer).toHaveText("Source");
  await expectAccessible(page, "login screen with the source link");

  await page.getByRole("button", { name: "Create an account" }).click();
  await expect(page.getByRole("contentinfo").getByRole("link", { name: "Source" })).toHaveAttribute(
    "href",
    SOURCE_URL,
  );
  await expectAccessible(page, "signup screen with the source link");
  expect(problems).toEqual([]);
});

test("source link: unset, this build's upstream source", async ({ page }) => {
  await page.goto(unset.origin);
  const link = page.getByRole("contentinfo").getByRole("link", { name: "Source" });
  await expect(link).toBeVisible();
  const href = await link.getAttribute("href");
  expect(href === UPSTREAM || href?.startsWith(`${UPSTREAM}/`)).toBe(true);
});
