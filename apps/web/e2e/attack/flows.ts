// SPDX-License-Identifier: AGPL-3.0-only

// High-level browser flows the adversarial-import spec drives: open the import pane, submit a
// hostile file, sweep every resulting item and tag. Kept apart from the spec itself so the
// spec reads as "what is being asserted", not "how to click through the UI".
import { type Page, expect } from "@playwright/test";

import type { AttackCase, HostileFile } from "./hostile-imports.ts";
import type { LinkInfo, SinkHit } from "./oracles.ts";
import { collectLinks, collectSinks } from "./snapshot.ts";

/** Opens the "Export and import" pane from wherever the vault currently is. */
export async function openTransferPane(page: Page): Promise<void> {
  await page.getByRole("button", { name: "Export and import", exact: true }).click();
}

/** Returns to the "All items" list from wherever the vault currently is. */
export async function openAllItems(page: Page): Promise<void> {
  await page.getByRole("button", { name: "All items", exact: true }).click();
}

/** Uploads `file` and submits the import, auto-recognised. Returns the report text
 * (`import-report`'s `data-testid`) if the import completed, or the error code shown
 * (`[data-code]`) if it was refused — never throws on a clean refusal, since "oversized inputs
 * are rejected cleanly" is itself a passing outcome (`checkOversizedHandling`). */
export async function importHostileFile(page: Page, file: HostileFile): Promise<{ report?: string; code?: string }> {
  await openTransferPane(page);
  await page
    .getByLabel("File", { exact: true })
    .setInputFiles({ name: file.filename, mimeType: file.mimeType, buffer: Buffer.from(file.bytes) });
  const importButton = page.getByRole("button", { name: "Import", exact: true });
  await expect(importButton).toBeEnabled({ timeout: 15_000 });
  await importButton.click();
  const report = page.getByTestId("import-report");
  const errorCode = page.locator("[data-code]");
  await expect(report.or(errorCode)).toBeVisible({ timeout: 30_000 });
  if (await report.isVisible()) {
    return { report: (await report.textContent()) ?? "" };
  }
  return { code: (await errorCode.getAttribute("data-code")) ?? "" };
}

/** Visits one item by its (substring-matched) trace title, collects the sink fingerprint and
 * every rendered link, then returns to the list via "Back" if that control is actually on
 * screen. Never throws on a missing item (an importer may legitimately skip a case, e.g. an
 * oversized value): the caller gets an empty result and decides whether that is itself a
 * finding.
 *
 * Harness bug found and fixed by the nightly sweep's first scale run (triage note, kept so the
 * mistake is not repeated): this used to wait for the "Back" button as the "item opened"
 * signal. `ItemsPane.tsx`'s list and detail panes sit side by side at desktop width — the
 * `.back-button` is in the DOM but not visible there (it is a narrow/mobile affordance only;
 * `Playwright`'s default "Desktop Chrome" device is wide) — so that wait timed out even though
 * the item view had opened correctly (its heading, fields and "Edit"/"Move to trash" buttons
 * were all on screen). The fix waits for the row key's own text instead, and only clicks
 * "Back" when it is actually visible, which holds on both layouts.
 *
 * A second harness bug, found by the same scale run (flaky, not every run): `row.count()` reads
 * the DOM *right now*, with no retry, so a row that had not re-rendered yet right after
 * `ctx.afterWrite()` (`TransferPane.tsx`'s `Import` sets the report text *before* awaiting
 * `afterWrite()`, so "import-report" can be visible a tick before the list actually holds the
 * new items) read as "missing" even though the import had fully succeeded — intermittently all
 * 9 of 9 cases of one format "missing" in one observed run, while the format imported
 * immediately before it, in the very same account, swept cleanly. The fix below waits (bounded)
 * for the row instead of taking one instantaneous snapshot. */
export async function visitItem(
  page: Page,
  baselineScripts: readonly string[],
  traceSubstring: string,
): Promise<{ found: boolean; sinks: SinkHit[]; links: LinkInfo[] }> {
  const row = page.getByRole("button", { name: traceSubstring }).first();
  const appeared = await row
    .waitFor({ state: "visible", timeout: 8_000 })
    .then(() => true)
    .catch(() => false);
  if (!appeared) {
    return { found: false, sinks: [], links: [] };
  }
  await row.click();
  // The row key sits in the detail heading for most formats, but in a plain-text field value
  // (Firefox CSV's username, `hostile-imports.ts`'s `rowKeyOf`) for others; `getByText` finds
  // it either way, which is why `rowKeyOf` exists — "open the right item" must work the same
  // regardless of which rendered field actually carries the key for this format.
  await expect(page.getByText(traceSubstring).first()).toBeVisible();
  const [sinks, links] = await Promise.all([collectSinks(page, baselineScripts), collectLinks(page)]);
  const back = page.getByRole("button", { name: "Back" });
  if ((await back.count()) > 0 && (await back.first().isVisible())) {
    await back.first().click();
  }
  return { found: true, sinks, links };
}

/** Imports `file` and visits every item it describes (`file.cases`, in order), aggregating the
 * sink and link findings. Items the importer skipped (a missing row) are counted separately,
 * not as a silent pass. */
export async function importAndSweep(
  page: Page,
  baselineScripts: readonly string[],
  file: HostileFile,
): Promise<{
  report: { report?: string; code?: string };
  visited: number;
  missing: readonly AttackCase[];
  sinks: SinkHit[];
  links: LinkInfo[];
}> {
  const report = await importHostileFile(page, file);
  const sinks: SinkHit[] = [];
  const links: LinkInfo[] = [];
  const missing: AttackCase[] = [];
  let visited = 0;
  if (report.report !== undefined) {
    await openAllItems(page);
    for (const [index, c] of file.cases.entries()) {
      const rowKey = file.rowKeys[index];
      if (rowKey === undefined) {
        missing.push(c);
        continue;
      }
      const result = await visitItem(page, baselineScripts, rowKey);
      if (result.found) {
        visited += 1;
        sinks.push(...result.sinks);
        links.push(...result.links);
      } else {
        missing.push(c);
      }
    }
  }
  return { report, visited, missing, sinks, links };
}

/** Opens a tag in the sidebar by its (substring-matched) name and collects the sink
 * fingerprint and links there too — the sidebar is a second render path for a tag/folder name
 * besides the item's own detail view. Returns to "All items" afterwards. No-op if the tag is
 * not present (e.g. the importer dropped it as invalid). */
export async function visitTag(
  page: Page,
  baselineScripts: readonly string[],
  tagSubstring: string,
): Promise<{ found: boolean; sinks: SinkHit[] }> {
  const tagButton = page.locator(".sidebar-group button", { hasText: tagSubstring });
  if ((await tagButton.count()) === 0) {
    return { found: false, sinks: [] };
  }
  await tagButton.first().click();
  const sinks = await collectSinks(page, baselineScripts);
  await openAllItems(page);
  return { found: true, sinks };
}
