// SPDX-License-Identifier: AGPL-3.0-only

// The fixed allow-list a rendered Secure Note must stay inside (ADR 0062 §5, §8; INV-88): the
// elements, and the classes, the note's Markdown may render as. Written out here independently
// of `src/views/NoteMarkdown.tsx`, so a renderer change that adds an element, attribute or class
// fails the oracles that use it (`test/markdown-oracle.ts`, `markdown-note.spec.ts`) instead of
// quietly widening what they accept. No attribute other than `class` is ever allowed.

/** Every element a rendered note may contain: the §5 set, the Markdown root (`div`) and the
 * plain fallback's container (`span`). */
export const MARKDOWN_TAGS: readonly string[] = [
  "div",
  "span",
  "h1",
  "h2",
  "h3",
  "h4",
  "h5",
  "h6",
  "p",
  "br",
  "strong",
  "em",
  "del",
  "code",
  "pre",
  "blockquote",
  "ul",
  "ol",
  "li",
  "hr",
];

/** Every class a rendered note's elements may carry: fixed, never from the note (§8). */
export const MARKDOWN_CLASSES: readonly string[] = [
  "field-value",
  "md-note",
  "md-h1",
  "md-h2",
  "md-h3",
  "md-h4",
  "md-h5",
  "md-h6",
  "md-p",
  "md-br",
  "md-strong",
  "md-em",
  "md-del",
  "md-code",
  "md-pre",
  "md-pre-code",
  "md-blockquote",
  "md-ul",
  "md-ol",
  "md-li",
  "md-hr",
];
