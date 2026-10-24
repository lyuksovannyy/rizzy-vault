// SPDX-License-Identifier: AGPL-3.0-only

// The accessibility checks the web vault's Playwright specs share (ROADMAP §4.5's accessibility
// Must: keyboard-only use, screen-reader labels, WCAG AA contrast; ADR 0014 §5). Three layers:
//
// 1. axe-core (`@axe-core/playwright`, Deque's engine): every WCAG 2.0/2.1/2.2 A and AA rule plus
//    axe's best-practice rules, over the whole rendered page, iframes included. Every violation
//    fails; "needs review" (incomplete) results do not. `REQUIRED_RULES` is the list this repo
//    relies on by name — accessible names of every control, form labels, text alternatives, one
//    main landmark, heading order, document language and title, duplicate ids that ARIA
//    references, focusable elements hidden from the accessibility tree, dialog names, colour
//    contrast — and a run where axe did not evaluate one of them fails, so an axe upgrade that
//    renames or drops a rule cannot silently turn a check off.
// 2. Chromium's own accessibility tree (CDP `Accessibility.getPartialAXTree`, no dependency):
//    every visible, keyboard-focusable element is exposed (not ignored) and has a non-empty
//    accessible name, as the browser itself computes it for assistive technology.
// 3. Dialog focus traps (`expectFocusTrapped`): Tab and Shift+Tab never leave an open modal
//    dialog, which is what `aria-modal="true"` promises a screen-reader user and what
//    `ConfirmDialog`'s trap (`packages/ui`) and the modal registry intend for every dialog.
//
// None of this is a real screen reader (NVDA, JAWS, VoiceOver, TalkBack, Orca), and none of it
// covers the native clients' toolkits, which live in their own repositories (ADR 0019 §6).
import AxeBuilder from "@axe-core/playwright";
import { type Locator, type Page, expect } from "@playwright/test";

/** The axe-core tags every audit runs. */
export const AXE_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22a", "wcag22aa", "best-practice"];

/** The axe rules an audit must have evaluated (module docs, layer 1). A rule that found nothing
 * to check on a screen counts as evaluated ("inapplicable"). */
export const REQUIRED_RULES = [
  // Every interactive control has an accessible name.
  "button-name",
  "link-name",
  "input-button-name",
  "aria-command-name",
  "aria-input-field-name",
  "aria-toggle-field-name",
  "nested-interactive",
  // Form fields have labels.
  "label",
  "select-name",
  // Images have text alternatives or are decorative.
  "image-alt",
  "svg-img-alt",
  "role-img-alt",
  // One main landmark; headings not skipped.
  "landmark-one-main",
  "landmark-no-duplicate-main",
  "page-has-heading-one",
  "heading-order",
  "empty-heading",
  // Document language and title.
  "html-has-lang",
  "html-lang-valid",
  "document-title",
  // No duplicate ids that ARIA references.
  "duplicate-id-aria",
  // Focusable elements are not hidden from the accessibility tree.
  "aria-hidden-focus",
  // Dialogs have names.
  "aria-dialog-name",
  // Valid ARIA.
  "aria-allowed-attr",
  "aria-required-attr",
  "aria-valid-attr",
  "aria-valid-attr-value",
  "aria-required-children",
  "aria-required-parent",
  // WCAG AA contrast of the rendered text.
  "color-contrast",
  // Iframes (the extension's inline menu) have a title.
  "frame-title",
];

/** One formatted axe violation, compact enough to read in a failed assertion. */
function describeViolation(v: { id: string; help: string; nodes: { target: unknown[]; failureSummary?: string }[] }): string {
  const nodes = v.nodes
    .slice(0, 5)
    .map((n) => `    ${JSON.stringify(n.target)}: ${(n.failureSummary ?? "").replace(/\s+/g, " ")}`)
    .join("\n");
  return `${v.id}: ${v.help}\n${nodes}`;
}

/** Waits until no CSS animation or transition is still running on `page` (docs/design/README.md
 * "Motion"): an entrance animation starts from `opacity: 0`, and a colour transition (a theme
 * switch, a hover) passes through in-between colours, while axe measures colour contrast on what
 * is painted, so a screen audited mid-motion would be judged on a frame the user never rests on.
 * Every one of them is finite and short (`cargo xtask generate-tokens` caps them), so this
 * settles within a fraction of a second. The one exception is not waited for: the TOTP ring's
 * `stroke-dashoffset` countdown, which glides by one step every second for as long as the item
 * is open. */
export async function settleAnimations(page: Page): Promise<void> {
  await page.waitForFunction(
    () =>
      document
        .getAnimations()
        .every(
          (a) =>
            a.playState !== "running" ||
            (a instanceof CSSTransition && a.transitionProperty === "stroke-dashoffset"),
        ),
    undefined,
    { timeout: 5_000 },
  );
}

/** Runs axe over `page` (layer 1) and Chromium's accessibility tree check (layer 2), and fails
 * on any violation of either, naming `screen` in the message.
 *
 * With `forcedColors` (the page is under `emulateMedia({ forcedColors: "active" })`), axe's
 * `color-contrast` rule is replaced: Chromium's `getComputedStyle` still reports the author's
 * `-webkit-text-fill-color` there, which axe reads as the text colour although the text is
 * painted in the forced system colour (measured on a screenshot while writing this: the dark
 * theme's `--color-on-accent` reported, white on black painted). Under forced colours the
 * contrast is the user's own palette as long as nothing opts out of it, so the check is instead
 * that no element sets `forced-color-adjust: none` (ADR 0014 §5: the components respect
 * `forced-colors`). */
export async function expectAccessible(page: Page, screen: string, options: { forcedColors?: boolean } = {}): Promise<void> {
  await settleAnimations(page);
  const forced = options.forcedColors === true;
  let builder = new AxeBuilder({ page }).withTags(AXE_TAGS);
  if (forced) {
    builder = builder.disableRules(["color-contrast"]);
    expect(await page.evaluate(() => matchMedia("(forced-colors: active)").matches), `${screen}: forced colours`).toBe(true);
    const optedOut = await page.evaluate(() =>
      Array.from(document.querySelectorAll("*"))
        .filter((el) => getComputedStyle(el).getPropertyValue("forced-color-adjust") === "none")
        .map((el) => `<${el.tagName.toLowerCase()} class="${el.className}">`),
    );
    expect(optedOut, `${screen}: elements opting out of forced colours`).toEqual([]);
  }
  const results = await builder.analyze();
  const evaluated = new Set(
    [...results.passes, ...results.violations, ...results.incomplete, ...results.inapplicable].map((r) => r.id),
  );
  expect(
    REQUIRED_RULES.filter((id) => !evaluated.has(id) && !(forced && id === "color-contrast")),
    `${screen}: axe rules this audit relies on were not evaluated`,
  ).toEqual([]);
  expect(results.violations.map(describeViolation), `${screen}: axe violations`).toEqual([]);
  expect(await focusableAxProblems(page), `${screen}: focusable elements in Chromium's accessibility tree`).toEqual([]);
}

/** Every visible, sequentially focusable element of `page`'s main frame: its exposure in the
 * accessibility tree Chromium hands assistive technology (layer 2). Returns one message per
 * element that is ignored there or has no accessible name. */
export async function focusableAxProblems(page: Page): Promise<string[]> {
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
        continue;
      }
      const name = typeof node.name?.value === "string" ? node.name.value.trim() : "";
      if (name === "") {
        problems.push(`${what} (role ${String(node.role?.value)}): focusable but has no accessible name`);
      }
    }
    return problems;
  } finally {
    await cdp.detach();
  }
}

/** Whether keyboard focus is inside `dialog` right now. */
async function focusInside(dialog: Locator): Promise<boolean> {
  return dialog.evaluate((el) => el.contains(document.activeElement));
}

/** Tab and Shift+Tab keep the focus inside the open modal `dialog` (layer 3): presses each
 * enough times to wrap round every focusable element in it twice. Focus must already be inside
 * it (every dialog here moves it there when it opens). */
export async function expectFocusTrapped(page: Page, dialog: Locator, name: string): Promise<void> {
  await expect(dialog).toBeVisible();
  expect(await focusInside(dialog), `${name}: focus is inside the dialog when it opens`).toBe(true);
  const count = await dialog.evaluate(
    (el) =>
      Array.from(el.querySelectorAll<HTMLElement>("a[href], button, input, select, textarea, [tabindex]")).filter(
        (e) => e.tabIndex >= 0 && !e.matches(":disabled"),
      ).length,
  );
  for (const key of ["Tab", "Shift+Tab"]) {
    for (let i = 0; i < 2 * count + 2; i++) {
      await page.keyboard.press(key);
      expect(await focusInside(dialog), `${name}: focus left the dialog after ${i + 1} × ${key}`).toBe(true);
    }
  }
}

/** Moves the keyboard focus to `target` with Tab alone (or Shift+Tab with `backwards`), failing
 * when it is not reached within `max` presses: the keyboard-only reachability check. */
export async function tabTo(page: Page, target: Locator, options: { max?: number; backwards?: boolean } = {}): Promise<void> {
  const max = options.max ?? 80;
  const key = options.backwards === true ? "Shift+Tab" : "Tab";
  await expect(target).toBeVisible();
  for (let i = 0; i < max; i++) {
    if (await target.evaluate((el) => el === document.activeElement)) {
      return;
    }
    await page.keyboard.press(key);
  }
  expect(await target.evaluate((el) => el === document.activeElement), `${String(target)} not reached by ${key} within ${max} presses`).toBe(true);
}
