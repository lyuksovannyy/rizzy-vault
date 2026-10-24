// SPDX-License-Identifier: AGPL-3.0-only

// Settings → Website matching end to end (ADR 0037 §6–§7, ADR 0042; ROADMAP §4.4 "User-defined
// equivalence groups + ability to disable a global group"; `src/views/MatchingPane.tsx`): a user
// group widens what autofill offers, the account default narrows it, both survive a new login
// (they are the account's `ACCOUNT_SETTINGS`, from the server, not session memory), a public
// suffix is refused, and the global-group section is honest that this build ships no signed list.
import { type Page, expect, test } from "@playwright/test";

import { logIn, newItem, signUp } from "./helpers.ts";
import { type RunningServer, startServer } from "./server.ts";

let server: RunningServer;

test.beforeAll(async () => {
  server = await startServer();
});

test.afterAll(() => {
  server.stop();
});

async function openMatching(page: Page) {
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  const pane = page.getByRole("region", { name: "Website matching" });
  await expect(pane).toBeVisible();
  return pane;
}

/** Checks `url` in the pane and returns the "Matching items" answer for its host. A new answer
 * replaces the last one; one per host is told apart by its name, so a stale answer never passes. */
async function check(pane: ReturnType<Page["getByRole"]>, url: string) {
  await pane.getByLabel("Website address").fill(url);
  await pane.getByRole("button", { name: "Check", exact: true }).click();
  const answer = pane.getByRole("status", { name: `Matching items on ${new URL(url).hostname}`, exact: true });
  await expect(answer).toBeVisible();
  return answer;
}

test("a user group changes a match, the account default narrows it, and both persist", async ({ page }) => {
  const secretKey = await signUp(page, server.origin, "MatchSettingsUser");

  // A login saved for example.com, its website left at "Account default".
  await newItem(page, "Login");
  await page.getByLabel("Title").fill("Example Login");
  await page.getByRole("button", { name: "Add a website" }).click();
  await page.getByLabel("New website 1", { exact: true }).fill("https://example.com/login");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "Example Login" })).toBeVisible();
  await expect(page.getByText("Synced", { exact: true })).toBeVisible();

  let pane = await openMatching(page);
  await expect(pane.getByLabel("Default match for websites")).toHaveValue("1");
  await expect(pane.getByText("No groups of your own.")).toBeVisible();

  // Before any group: offered on example.com, not on example.net.
  await expect(await check(pane, "https://example.com/")).toContainText("Example Login");
  await expect(await check(pane, "https://example.net/")).toContainText("No item would be offered");

  // A public suffix is refused, with nothing saved.
  await pane.getByLabel("Domains of a new group").fill("co.uk, example.com");
  await pane.getByRole("button", { name: "Add group" }).click();
  await expect(pane.locator('[data-code="equivalence_domain_rejected"]')).toBeVisible();
  await expect(pane.getByText("No groups of your own.")).toBeVisible();

  // Add example.com + example.net: example.net now offers the login, through the group.
  await pane.getByLabel("Domains of a new group").fill("example.com, Example.NET");
  await pane.getByRole("button", { name: "Add group" }).click();
  await expect(pane.getByText("The group is saved.")).toBeVisible();
  const groups = pane.getByRole("list", { name: "Your equivalence groups" });
  await expect(groups).toContainText("example.com, example.net");
  const viaGroup = await check(pane, "https://example.net/");
  await expect(viaGroup).toContainText("Example Login");
  await expect(viaGroup).toContainText("through an equivalence group");

  // The account default: Host stops a subdomain the default Base domain allowed.
  await expect(await check(pane, "https://www.example.com/")).toContainText("Example Login");
  await pane.getByLabel("Default match for websites").selectOption("2"); // Host
  await expect(pane.getByText("The default is saved.")).toBeVisible();
  await expect(await check(pane, "https://www.example.com/")).toContainText("No item would be offered");

  // Global groups: this build ships no signed list (gap G1), so there is nothing to turn off.
  // The default site groups of ADR 0080 are committed in data/equivalence/groups.txt but stay
  // unsigned until the owner signs them offline, and no build can inject a test-key list (the
  // list and its key are compile-time constants of rizzy-match). Until a list ships, the pane's
  // rows for them (long labels, the disclosure, the switches' names) are checked by rendering
  // them from the committed seed in test/match-settings.test.ts; ADR 0080 §8's e2e cases (on by
  // default, a turned-off group stays off across a reload and stops an equivalence-only offer,
  // the warning) are added here in the change that ships the list.
  await expect(pane.getByText("This build ships no signed global list yet")).toBeVisible();
  await expect(pane.getByRole("list", { name: "Global equivalence groups" })).toHaveCount(0);

  // A new login reads the same settings from the server.
  await page.reload();
  await logIn(page, "MatchSettingsUser", secretKey);
  pane = await openMatching(page);
  await expect(pane.getByLabel("Default match for websites")).toHaveValue("2");
  await expect(pane.getByRole("list", { name: "Your equivalence groups" })).toContainText("example.com, example.net");

  // Back to Base domain, and the group removed: example.net offers nothing again.
  await pane.getByLabel("Default match for websites").selectOption("1");
  await expect(pane.getByText("The default is saved.")).toBeVisible();
  await pane.getByRole("button", { name: "Remove the group example.com, example.net" }).click();
  await expect(pane.getByText("The group is removed.")).toBeVisible();
  await expect(pane.getByText("No groups of your own.")).toBeVisible();
  await expect(await check(pane, "https://example.net/")).toContainText("No item would be offered");
  await expect(await check(pane, "https://www.example.com/")).toContainText("Example Login");
});
