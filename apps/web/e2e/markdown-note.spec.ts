// SPDX-License-Identifier: AGPL-3.0-only

// A Secure Note rendered from its Markdown (ADR 0062; THREAT_MODEL INV-88, A16), in the real
// browser against a real server. INV-88's own verification: a note built from an XSS-payload
// corpus (script tags, event-handler attributes, bracketed and bare URLs, raw HTML blocks,
// oversized and pathological input) renders with no script execution and no disallowed element
// in the DOM, mirroring INV-35's method in `adversarial-import.spec.ts`: the window tripwire every
// payload sets if it runs, and the element-sink fingerprint, both from `attack/snapshot.ts`. On top
// of that, every element of the rendered note is checked against the fixed allow-list
// (`attack/markdown-allow-list.ts`): only §5's elements, only the `class` attribute, only fixed
// classes; so no link, image, frame, style or handler (§6–§9). A typed URL stays inert text
// (§6): there is no anchor to follow, and clicking it navigates nowhere.
//
// Also: Copy returns the stored Markdown source unchanged (§12), the editor keeps the plain
// source (§2), and every other item type's notes stay plain text (§2).
import { type Page, expect, test } from "@playwright/test";

import { MARKDOWN_CLASSES, MARKDOWN_TAGS } from "./attack/markdown-allow-list.ts";
import { SINK_PAYLOADS, URI_PAYLOADS } from "./attack/payloads.ts";
import { captureScriptBaseline, collectSinks, installTripwire, readTripwire } from "./attack/snapshot.ts";
import { newItem, signUp, watch } from "./helpers.ts";
import { type RunningServer, startServer } from "./server.ts";

let server: RunningServer;

test.beforeAll(async () => {
  server = await startServer();
});

test.afterAll(() => {
  server.stop();
});

/** The hostile note: every Markdown construct wrapped around HTML, script and URL payloads,
 * entities and unicode tricks, the import harness's sink and URI payloads, and a pathological
 * tail. Kept well under the 64 KiB value limit (ADR 0018 §10). */
const HOSTILE_NOTE = [
  "# Heading <script>window.__rzxHit = true</script>",
  "Some **bold <img src=x onerror=\"window.__rzxHit = true\">** and *em <svg onload=\"window.__rzxHit = true\">*",
  "and ~~del~~ and `<iframe srcdoc=\"<script>parent.__rzxHit = true</script>\">`.",
  "",
  "<div onmouseover=\"window.__rzxHit = true\" style=\"position:fixed;inset:0\">hover me</div>",
  "<style>body { display: none }</style>",
  "<a href=\"javascript:window.__rzxHit = true\">raw anchor</a>",
  "",
  "[bracketed](javascript:window.__rzxHit=true) [data](data:text/html,<script>parent.__rzxHit=true</script>)",
  "[vb](vbscript:msgbox(1)) ![image](https://attacker.example/pixel.png) <https://example.com/>",
  "https://example.com/bare www.example.com",
  "",
  "> quoted <script>window.__rzxHit = true</script>",
  "> > nested is text",
  "",
  "- item <img src=x onerror=\"window.__rzxHit = true\">",
  "1. numbered &lt;script&gt; &#x3C;b&#x3E;",
  "",
  "---",
  "",
  "```html",
  "<script>window.__rzxHit = true</script>",
  "```",
  "",
  "\u202Ereversed\u202C zero\u200Bwidth \u2066isolate\u2069",
  "",
  ...SINK_PAYLOADS.map((p) => p.value),
  "",
  ...URI_PAYLOADS.map((p) => p.value),
  "",
  "*_**__~~".repeat(1500) + "deep" + "~~__**_*".repeat(1500),
  "> ".repeat(2000) + "deep quote",
  "`".repeat(2000),
].join("\n");

/** Every element of the rendered note that breaks the allow-list (module docs). */
async function allowListViolations(page: Page): Promise<string[]> {
  return page.locator('[data-field="item.notes"] .md-note').evaluate(
    (root, { tags, classes }) => {
      const problems: string[] = [];
      for (const el of [root, ...Array.from(root.querySelectorAll("*"))]) {
        const tag = el.tagName.toLowerCase();
        if (!tags.includes(tag)) {
          problems.push(`element ${tag}`);
        }
        for (const attr of Array.from(el.attributes)) {
          if (attr.name !== "class") {
            problems.push(`attribute ${attr.name} on ${tag}`);
          }
        }
        for (const cls of Array.from(el.classList)) {
          if (!classes.includes(cls)) {
            problems.push(`class ${cls.slice(0, 40)} on ${tag}`);
          }
        }
      }
      return problems;
    },
    { tags: [...MARKDOWN_TAGS], classes: [...MARKDOWN_CLASSES] },
  );
}

test("a hostile Secure Note renders inert: no script, no sink, no link (INV-88)", async ({ page, context }) => {
  const { problems } = watch(page);
  await installTripwire(page);
  await signUp(page, server.origin, "markdownuser");
  const baseline = await captureScriptBaseline(page);

  await newItem(page, "Secure note");
  await page.getByLabel("Title").fill("Hostile note");
  await page.getByLabel("Notes").fill(HOSTILE_NOTE);
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "Hostile note" })).toBeVisible();

  const notes = page.locator('[data-field="item.notes"]');
  const rendered = notes.locator(".md-note");
  await expect(rendered).toBeVisible();

  // The allow-listed constructs did render.
  await expect(rendered.locator("h1.md-h1")).toContainText("Heading <script>");
  await expect(rendered.locator("strong.md-strong").first()).toContainText("bold <img");
  await expect(rendered.locator("blockquote.md-blockquote").first()).toContainText("> nested is text");
  // (The tail's line of 2,000 backticks opens a second, unterminated fence.)
  await expect(rendered.locator("pre.md-pre")).toHaveCount(2);
  await expect(rendered.locator("pre.md-pre").first()).toContainText("<script>window.__rzxHit = true</script>");

  // Nothing ran, nothing became a live element, nothing outside the allow-list (§6–§9).
  expect(await readTripwire(page)).toBe(false);
  expect(await collectSinks(page, baseline)).toEqual([]);
  expect(await allowListViolations(page)).toEqual([]);
  await expect(rendered.locator("a, img, iframe, frame, object, embed, script, style, svg, math, form, input, button, link, meta, base")).toHaveCount(0);

  // Typed URLs are literal text, not links (§6): nothing to follow, and a click goes nowhere.
  await expect(rendered).toContainText("[bracketed](javascript:window.__rzxHit=true)");
  await expect(rendered).toContainText("https://example.com/bare");
  const before = page.url();
  const pages = context.pages().length;
  await rendered.getByText("[bracketed](javascript:", { exact: false }).first().click();
  await rendered.getByText("https://example.com/bare", { exact: false }).first().click();
  expect(page.url()).toBe(before);
  expect(context.pages()).toHaveLength(pages);
  expect(await readTripwire(page)).toBe(false);

  // The editor still edits the plain source (§2).
  await page.getByRole("button", { name: "Edit" }).click();
  // (Not compared whole: one import-harness payload carries a character the textarea itself
  // normalises; the Copy test below compares a full source exactly.)
  const editorValue = await page.getByLabel("Notes").inputValue();
  expect(editorValue.startsWith("# Heading <script>window.__rzxHit = true</script>\nSome **bold <img")).toBe(true);
  expect(editorValue).toContain("[bracketed](javascript:window.__rzxHit=true)");
  await page.getByRole("button", { name: "Cancel" }).click();
  await expect(page.getByRole("heading", { name: "Hostile note" })).toBeVisible();

  expect(await readTripwire(page)).toBe(false);
  expect(problems).toEqual([]);
});

test("Copy returns the Markdown source unchanged (§12)", async ({ page, context }) => {
  const { problems } = watch(page);
  await context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: server.origin });
  await signUp(page, server.origin, "markdowncopy");
  const source = "# Title\n\n**bold** and `code`\n- item\n\n<b>raw</b> [x](https://example.com/)";
  await newItem(page, "Secure note");
  await page.getByLabel("Title").fill("Copy note");
  await page.getByLabel("Notes").fill(source);
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "Copy note" })).toBeVisible();

  const notes = page.locator('[data-field="item.notes"]');
  await expect(notes.locator("h1.md-h1")).toHaveText("Title");
  await notes.getByRole("button", { name: "Copy" }).click();
  await expect(notes.getByRole("button", { name: "Copied" })).toBeVisible();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(source);
  expect(problems).toEqual([]);
});

test("other item types keep plain-text notes (§2)", async ({ page }) => {
  const { problems } = watch(page);
  await signUp(page, server.origin, "markdownlogin");
  const source = "# Not a heading\n**not bold** <b>x</b>";
  await newItem(page, "Login");
  await page.getByLabel("Title").fill("Plain login");
  await page.getByLabel("Notes").fill(source);
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "Plain login" })).toBeVisible();

  const notes = page.locator('[data-field="item.notes"]');
  await expect(notes.locator(".field-value")).toHaveText(source);
  await expect(notes.locator(".md-note, h1, strong, b")).toHaveCount(0);
  expect(problems).toEqual([]);
});
