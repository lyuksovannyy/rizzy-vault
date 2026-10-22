// SPDX-License-Identifier: AGPL-3.0-only

// The inertness oracle for rendered Secure Note Markdown (ADR 0062 §3, §5–§9; INV-88), shared
// by `note-markdown.test.ts` and `markdown-fuzz.test.ts`. It judges the static markup React renders
// for a note (`renderToStaticMarkup`, test-only): React escapes every text child, so each `<`
// in that markup starts a real element, and the oracle checks every element against the fixed
// allow-list (`e2e/attack/markdown-allow-list.ts`, shared with the Playwright check): the §5
// element set, no attribute but `class`, and only the renderer's own fixed classes.
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { MARKDOWN_CLASSES, MARKDOWN_TAGS } from "../e2e/attack/markdown-allow-list.ts";
import { NoteMarkdown } from "../src/views/NoteMarkdown.tsx";

/** Every element a rendered note may contain (`markdown-allow-list.ts`). */
export const ALLOWED_TAGS: ReadonlySet<string> = new Set(MARKDOWN_TAGS);

/** Every class a rendered note's elements may carry (`markdown-allow-list.ts`). */
export const ALLOWED_CLASSES: ReadonlySet<string> = new Set(MARKDOWN_CLASSES);

/** The static markup of `source` rendered as a Secure Note's notes. */
export function renderMarkup(source: string): string {
  return renderToStaticMarkup(createElement(NoteMarkdown, { source }));
}

const TAG = /<(\/?)([^\s/>]*)([^>]*)>/g;
const ATTRIBUTES = /^(?: class="([^"]*)")?\s*\/?$/;

/** Every way `markup` breaks the allow-list; empty when it is inert. */
export function inertViolations(markup: string): string[] {
  const problems: string[] = [];
  let tags = 0;
  for (const m of markup.matchAll(TAG)) {
    tags += 1;
    const [whole, closing, name = "", attrs = ""] = m;
    if (!ALLOWED_TAGS.has(name)) {
      problems.push(`element not allowed: ${whole.slice(0, 80)}`);
    }
    if (closing === "/") {
      if (attrs !== "") {
        problems.push(`closing tag with content: ${whole.slice(0, 80)}`);
      }
      continue;
    }
    const a = ATTRIBUTES.exec(attrs);
    if (a === null) {
      problems.push(`attribute not allowed: ${whole.slice(0, 80)}`);
      continue;
    }
    for (const c of (a[1] ?? "").split(" ").filter((x) => x !== "")) {
      if (!ALLOWED_CLASSES.has(c)) {
        problems.push(`class not allowed: ${c.slice(0, 80)}`);
      }
    }
  }
  // Every "<" must have started one of the elements just checked (text is always escaped).
  const opens = markup.split("<").length - 1;
  if (opens !== tags) {
    problems.push(`${opens - tags} unescaped "<" outside an element`);
  }
  return problems;
}
