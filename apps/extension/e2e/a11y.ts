// SPDX-License-Identifier: AGPL-3.0-only

// The accessibility audit for the extension's own pages: the same axe-core rule set and the
// same Chromium accessibility-tree check as the web vault's `apps/web/e2e/a11y.ts` (read its
// module docs), duplicated here for the reason `server.ts` and `account.ts` are: separate
// `tsconfig.json` trees, one small self-contained helper. Keep the two rule lists the same.
//
// The audit runs in the page and every frame in it, so a content page's audit covers the
// extension-origin inline-menu `<iframe>` too. Not covered: real screen readers, and Firefox
// (this suite runs Chromium only, `playwright.config.ts`).
import AxeBuilder from "@axe-core/playwright";
import { type Page, expect } from "@playwright/test";

/** The axe-core tags every audit runs. */
export const AXE_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22a", "wcag22aa", "best-practice"];

/** The axe rules an audit must have evaluated (`apps/web/e2e/a11y.ts`'s list). */
export const REQUIRED_RULES = [
  "button-name",
  "link-name",
  "input-button-name",
  "aria-command-name",
  "aria-input-field-name",
  "aria-toggle-field-name",
  "nested-interactive",
  "label",
  "select-name",
  "image-alt",
  "svg-img-alt",
  "role-img-alt",
  "landmark-one-main",
  "landmark-no-duplicate-main",
  "page-has-heading-one",
  "heading-order",
  "empty-heading",
  "html-has-lang",
  "html-lang-valid",
  "document-title",
  "duplicate-id-aria",
  "aria-hidden-focus",
  "aria-dialog-name",
  "aria-allowed-attr",
  "aria-required-attr",
  "aria-valid-attr",
  "aria-valid-attr-value",
  "aria-required-children",
  "aria-required-parent",
  "color-contrast",
  "frame-title",
];

/** Runs axe over `page` and its frames, then the accessibility-tree check of its main frame;
 * fails on any violation, naming `screen`. */
export async function expectAccessible(page: Page, screen: string): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(AXE_TAGS).analyze();
  const evaluated = new Set(
    [...results.passes, ...results.violations, ...results.incomplete, ...results.inapplicable].map((r) => r.id),
  );
  expect(
    REQUIRED_RULES.filter((id) => !evaluated.has(id)),
    `${screen}: axe rules this audit relies on were not evaluated`,
  ).toEqual([]);
  expect(
    results.violations.map(
      (v) =>
        `${v.id}: ${v.help}\n` +
        v.nodes
          .slice(0, 5)
          .map((n) => `    ${JSON.stringify(n.target)}: ${(n.failureSummary ?? "").replace(/\s+/g, " ")}`)
          .join("\n"),
    ),
    `${screen}: axe violations`,
  ).toEqual([]);
  expect(await focusableAxProblems(page), `${screen}: focusable elements in Chromium's accessibility tree`).toEqual([]);
}

/** Every visible, sequentially focusable element of `page`'s main frame that Chromium's
 * accessibility tree ignores or leaves without a name (`apps/web/e2e/a11y.ts`). */
async function focusableAxProblems(page: Page): Promise<string[]> {
  const cdp = await page.context().newCDPSession(page);
  try {
    await cdp.send("DOM.enable");
    await cdp.send("Accessibility.enable");
    const { result } = await cdp.send("Runtime.evaluate", {
      expression: `Array.from(document.querySelectorAll(
        'a[href], button, input, select, textarea, summary, iframe, [tabindex], [contenteditable="true"]'
      )).filter((el) => el.tabIndex >= 0 && !el.matches(":disabled") && el.checkVisibility({ visibilityProperty: true }))`,
    });
    if (result.objectId === undefined) {
      return ["could not list the focusable elements"];
    }
    const { result: props } = await cdp.send("Runtime.getProperties", { objectId: result.objectId, ownProperties: true });
    const problems: string[] = [];
    for (const prop of props) {
      const objectId = prop.value?.objectId;
      if (!/^\d+$/.test(prop.name) || objectId === undefined) {
        continue;
      }
      const { nodes } = await cdp.send("Accessibility.getPartialAXTree", { objectId, fetchRelatives: false });
      const node = nodes[0];
      const what = prop.value?.description ?? "element";
      if (node === undefined || node.ignored === true) {
        problems.push(`${what}: focusable but ignored in the accessibility tree`);
      } else if ((typeof node.name?.value === "string" ? node.name.value.trim() : "") === "") {
        problems.push(`${what} (role ${String(node.role?.value)}): focusable but has no accessible name`);
      }
    }
    return problems;
  } finally {
    await cdp.detach();
  }
}
