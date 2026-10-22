// SPDX-License-Identifier: AGPL-3.0-only

// The Secure Note Markdown parser (ADR 0062; THREAT_MODEL INV-88): a hand-written,
// restricted-subset parser from a note's stored `item.notes` text to a closed AST. The AST
// below is the whole output vocabulary: one variant per construct ADR 0062 §5 allow-lists and
// nothing else. There is no HTML, link, image, style or attribute variant, so no input can
// produce one (§6–§9); `views/NoteMarkdown.tsx` renders this AST to React elements and never
// builds an HTML string (§3). This module only parses: it touches no DOM.
//
// The rules, in full (ADR 0062 §5; a deliberate, documented subset, not CommonMark):
// - Lines are split on `\n`, `\r\n` or `\r`; a NUL becomes U+FFFD. Leading spaces and tabs are
//   ignored when recognising a block construct.
// - `#` to `######`, a space (or tab) and some text: a heading. Seven `#`, or `#tag`, is text.
// - A line of three or more `-` and nothing else: a horizontal rule.
// - A line of three or more backticks opens a fenced code block; any text after them (the
//   language hint) is dropped. It closes at a line of at least as many backticks and nothing
//   else, or at the end of the note when unterminated. Its lines are kept verbatim, never
//   re-parsed.
// - `>` lines: one blockquote, one level (owner answer 2): a further `>` inside it is text.
//   A bare `>` line separates its paragraphs. Only inline markup is recognised inside.
// - `- `, `* ` or `+ ` lines: one bulleted list; `1. ` (one to nine digits) lines: one numbered
//   list, numbered from 1 (a start number is not carried). One level (owner answer 2): an item
//   holds one line of inline content. Switching between bulleted and numbered starts a new
//   list; a blank line ends one.
// - Any other run of non-blank lines: a paragraph, with a line break for each single newline
//   (§5's deliberate deviation from CommonMark's trailing-spaces rule).
// - Inline, within one line (emphasis does not span lines): `**x**` or `__x__` strong, `*x*` or
//   `_x_` emphasis, `~~x~~` strikethrough, a backtick code span (a run of N backticks closes
//   at the next run of exactly N; its content is literal). `_` neither opens nor closes inside
//   a word (`snake_case`). A backslash before ASCII punctuation makes that character literal. An
//   unmatched marker is literal text.
// - Everything else (raw HTML, `[text](url)`, `<url>`, bare URLs, `![image](src)`, tables,
//   footnotes, task boxes, HTML entities: `&lt;` stays those four characters) has no production
//   rule and is literal text (§5–§7; owner answer 7).
//
// Linear time, no backtracking regular expression (§10): one pass over the lines, one pass
// over each line. The emphasis stack holds at most one open frame per marker kind (five), so
// nesting depth is bounded whatever the input, and a node is moved at most once per enclosing
// frame. Code-span closers are found through per-length position lists whose cursors only move
// forward. The only regular expressions are single-character class tests.
//
// Fails closed (§11): a note longer than `MAX_NOTE_RENDER_LENGTH`, or any exception, yields
// `{ kind: "plain" }`: the original stored text as one plain text node, never an HTML string
// and never a crash of the item view.

/** The longest note this module parses, in UTF-16 code units. A stored value is at most
 * 65,536 bytes, type byte included (ADR 0018 §10; `MAX_VALUE_LEN` in `rizzy-core`), and a
 * UTF-8 byte count is never below the UTF-16 length, so a valid note always fits; a longer
 * string is rendered as plain text without being parsed (§10–§11). */
export const MAX_NOTE_RENDER_LENGTH = 65_536;

/** Inline content: the whole inline vocabulary of ADR 0062 §5. */
export type Inline =
  | { readonly kind: "text"; readonly text: string }
  | { readonly kind: "strong"; readonly children: readonly Inline[] }
  | { readonly kind: "em"; readonly children: readonly Inline[] }
  | { readonly kind: "del"; readonly children: readonly Inline[] }
  | { readonly kind: "code"; readonly text: string };

/** One line of inline content. A paragraph's lines render with a line break between them. */
export type Line = readonly Inline[];

/** A heading level, `#` to `######`. */
export type HeadingLevel = 1 | 2 | 3 | 4 | 5 | 6;

/** A block: the whole block vocabulary of ADR 0062 §5. */
export type Block =
  | { readonly kind: "heading"; readonly level: HeadingLevel; readonly content: Line }
  | { readonly kind: "paragraph"; readonly lines: readonly Line[] }
  | { readonly kind: "codeBlock"; readonly text: string }
  | { readonly kind: "blockquote"; readonly paragraphs: readonly (readonly Line[])[] }
  | { readonly kind: "list"; readonly ordered: boolean; readonly items: readonly Line[] }
  | { readonly kind: "rule" };

/** A parsed note: Markdown blocks, or the fail-closed plain-text fallback (§11). */
export type NoteDocument =
  | { readonly kind: "markdown"; readonly blocks: readonly Block[] }
  | { readonly kind: "plain"; readonly text: string };

/** Parses a Secure Note's stored `item.notes` text. Never throws (§11). */
export function parseNote(source: string): NoteDocument {
  try {
    if (source.length > MAX_NOTE_RENDER_LENGTH) {
      return { kind: "plain", text: source };
    }
    return { kind: "markdown", blocks: parseBlocks(source) };
  } catch {
    return { kind: "plain", text: source };
  }
}

// ---- Blocks ----------------------------------------------------------------------------

/** What one source line is, for block recognition. `rest` is the line's inline content. */
type LineClass =
  | { readonly t: "blank" }
  | { readonly t: "fence"; readonly ticks: number }
  | { readonly t: "heading"; readonly level: HeadingLevel; readonly rest: string }
  | { readonly t: "rule" }
  | { readonly t: "quote"; readonly rest: string }
  | { readonly t: "bullet"; readonly rest: string }
  | { readonly t: "ordered"; readonly rest: string }
  | { readonly t: "text"; readonly rest: string };

function splitLines(source: string): string[] {
  return source.replaceAll("\r\n", "\n").replaceAll("\r", "\n").replaceAll("\u0000", "\uFFFD").split("\n");
}

function isBlankChar(c: string | undefined): boolean {
  return c === " " || c === "\t";
}

/** `s` without its leading spaces and tabs. */
function trimIndent(s: string): string {
  let i = 0;
  while (i < s.length && isBlankChar(s[i])) {
    i += 1;
  }
  return s.slice(i);
}

/** How many times `c` repeats in `s` from `from` on. */
function runLength(s: string, from: number, c: string): number {
  let i = from;
  while (i < s.length && s[i] === c) {
    i += 1;
  }
  return i - from;
}

function isDigit(c: string | undefined): boolean {
  return c !== undefined && c >= "0" && c <= "9";
}

function classify(line: string): LineClass {
  const s = trimIndent(line);
  const trimmed = s.trimEnd();
  if (trimmed === "") {
    return { t: "blank" };
  }
  const first = s[0];
  if (first === "`") {
    const ticks = runLength(s, 0, "`");
    if (ticks >= 3) {
      return { t: "fence", ticks };
    }
  }
  if (first === "#") {
    const n = runLength(s, 0, "#");
    const rest = s.slice(n).trim();
    if (n <= 6 && isBlankChar(s[n]) && rest !== "") {
      return { t: "heading", level: n as HeadingLevel, rest };
    }
  }
  if (first === "-" && trimmed.length >= 3 && runLength(trimmed, 0, "-") === trimmed.length) {
    return { t: "rule" };
  }
  if (first === ">") {
    return { t: "quote", rest: s.slice(1).trim() };
  }
  if ((first === "-" || first === "*" || first === "+") && isBlankChar(s[1])) {
    const rest = s.slice(2).trim();
    if (rest !== "") {
      return { t: "bullet", rest };
    }
  }
  if (isDigit(first)) {
    let n = 0;
    while (n < s.length && isDigit(s[n])) {
      n += 1;
    }
    const rest = s.slice(n + 1).trim();
    if (n <= 9 && s[n] === "." && isBlankChar(s[n + 1]) && rest !== "") {
      return { t: "ordered", rest };
    }
  }
  return { t: "text", rest: trimmed };
}

/** Whether `line` closes a fence opened with `ticks` backticks. */
function closesFence(line: string, ticks: number): boolean {
  const s = trimIndent(line).trimEnd();
  return s.length >= ticks && runLength(s, 0, "`") === s.length;
}

function parseBlocks(source: string): Block[] {
  const lines = splitLines(source);
  const classes = lines.map(classify);
  const blocks: Block[] = [];
  let i = 0;
  while (i < lines.length) {
    const c = classes[i];
    if (c === undefined) {
      break;
    }
    switch (c.t) {
      case "blank":
        i += 1;
        break;
      case "fence": {
        const body: string[] = [];
        i += 1;
        while (i < lines.length && !closesFence(lines[i] ?? "", c.ticks)) {
          body.push(lines[i] ?? "");
          i += 1;
        }
        i += 1; // the closing fence, or past the end when unterminated
        blocks.push({ kind: "codeBlock", text: body.join("\n") });
        break;
      }
      case "heading":
        blocks.push({ kind: "heading", level: c.level, content: parseInline(c.rest) });
        i += 1;
        break;
      case "rule":
        blocks.push({ kind: "rule" });
        i += 1;
        break;
      case "quote": {
        const paragraphs: Line[][] = [];
        let current: Line[] = [];
        let q = classes[i];
        while (q !== undefined && q.t === "quote") {
          if (q.rest === "") {
            if (current.length > 0) {
              paragraphs.push(current);
            }
            current = [];
          } else {
            current.push(parseInline(q.rest));
          }
          i += 1;
          q = classes[i];
        }
        if (current.length > 0) {
          paragraphs.push(current);
        }
        if (paragraphs.length > 0) {
          blocks.push({ kind: "blockquote", paragraphs });
        }
        break;
      }
      case "bullet":
      case "ordered": {
        const items: Line[] = [];
        let l = classes[i];
        while (l !== undefined && l.t === c.t) {
          items.push(parseInline(l.rest));
          i += 1;
          l = classes[i];
        }
        blocks.push({ kind: "list", ordered: c.t === "ordered", items });
        break;
      }
      case "text": {
        const paragraph: Line[] = [];
        let l = classes[i];
        while (l !== undefined && l.t === "text") {
          paragraph.push(parseInline(l.rest));
          i += 1;
          l = classes[i];
        }
        blocks.push({ kind: "paragraph", lines: paragraph });
        break;
      }
    }
  }
  return blocks;
}

// ---- Inline ----------------------------------------------------------------------------

const ASCII_PUNCTUATION = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

/** Single-character tests (§10: no backtracking pattern anywhere). */
const WHITESPACE = /^\s$/u;
const ALPHANUMERIC = /^[\p{L}\p{N}]$/u;

/** Whether a neighbour counts as whitespace; the start and the end of the line do. */
function isSpace(c: string | undefined): boolean {
  return c === undefined || WHITESPACE.test(c);
}

function isAlnum(c: string | undefined): boolean {
  return c !== undefined && ALPHANUMERIC.test(c);
}

/** An emphasis marker character. `~` only ever pairs as `~~`. */
type MarkerChar = "*" | "_" | "~";

/** An open emphasis frame: its marker, and the index of its placeholder text node in the
 * output. Unclosed, the placeholder simply stays: the marker reads as literal text. */
interface Frame {
  readonly ch: MarkerChar;
  readonly len: 1 | 2;
  readonly start: number;
}

/** Joins adjacent text nodes and drops empty ones. */
function mergeText(nodes: readonly Inline[]): Inline[] {
  const out: Inline[] = [];
  for (const node of nodes) {
    const last = out[out.length - 1];
    if (node.kind === "text") {
      if (node.text === "") {
        continue;
      }
      if (last !== undefined && last.kind === "text") {
        out[out.length - 1] = { kind: "text", text: last.text + node.text };
        continue;
      }
    }
    out.push(node);
  }
  return out;
}

/** Where each maximal backtick run of one length starts, with a forward-only cursor. */
interface RunList {
  readonly starts: number[];
  cursor: number;
}

/** The maximal backtick runs of `s`, grouped by length. */
function backtickRuns(s: string): Map<number, RunList> {
  const runs = new Map<number, RunList>();
  let i = 0;
  while (i < s.length) {
    if (s[i] === "`") {
      const len = runLength(s, i, "`");
      const list = runs.get(len);
      if (list === undefined) {
        runs.set(len, { starts: [i], cursor: 0 });
      } else {
        list.starts.push(i);
      }
      i += len;
    } else {
      i += 1;
    }
  }
  return runs;
}

/** The start of the first maximal run of exactly `len` backticks at or after `from`, or -1.
 * Calls for one length arrive with increasing `from`, so each cursor only moves forward. */
function nextRun(runs: Map<number, RunList>, len: number, from: number): number {
  const list = runs.get(len);
  if (list === undefined) {
    return -1;
  }
  while (list.cursor < list.starts.length && (list.starts[list.cursor] ?? Infinity) < from) {
    list.cursor += 1;
  }
  return list.starts[list.cursor] ?? -1;
}

/** The index of the innermost open frame of marker character `ch` that holds content (an output
 * longer than its placeholder) and whose marker is `r` long (`exact`) or at most `r` long. */
function innermost(stack: readonly Frame[], ch: MarkerChar, r: number, outLength: number, exact: boolean): number | undefined {
  for (let j = stack.length - 1; j >= 0; j -= 1) {
    const f = stack[j];
    if (f !== undefined && f.ch === ch && (exact ? f.len === r : f.len <= r) && outLength > f.start + 1) {
      return j;
    }
  }
  return undefined;
}

function emphasisNode(frame: Frame, children: Inline[]): Inline {
  if (frame.ch === "~") {
    return { kind: "del", children };
  }
  return frame.len === 2 ? { kind: "strong", children } : { kind: "em", children };
}

/** Parses one line of inline content (module docs). */
export function parseInline(s: string): Inline[] {
  const runs = backtickRuns(s);
  const out: Inline[] = [];
  const stack: Frame[] = [];
  let buf = "";
  const flush = () => {
    if (buf !== "") {
      out.push({ kind: "text", text: buf });
      buf = "";
    }
  };

  let i = 0;
  while (i < s.length) {
    const ch = s[i] ?? "";
    if (ch === "\\" && ASCII_PUNCTUATION.includes(s[i + 1] ?? "a")) {
      buf += s[i + 1] ?? "";
      i += 2;
      continue;
    }
    if (ch === "`") {
      const k = runLength(s, i, "`");
      const close = nextRun(runs, k, i + k);
      if (close === -1) {
        buf += s.slice(i, i + k);
        i += k;
      } else {
        let text = s.slice(i + k, close);
        if (text.length >= 2 && text.startsWith(" ") && text.endsWith(" ") && text.trim() !== "") {
          text = text.slice(1, -1);
        }
        flush();
        out.push({ kind: "code", text });
        i = close + k;
      }
      continue;
    }
    if (ch === "*" || ch === "_" || ch === "~") {
      const k = runLength(s, i, ch);
      const left = s[i - 1];
      const right = s[i + k];
      const canOpen = !isSpace(right) && (ch !== "_" || !isAlnum(left));
      const canClose = !isSpace(left) && (ch !== "_" || !isAlnum(right));
      flush();
      let r = k;
      while (r > 0) {
        if (canClose) {
          // The innermost open frame of this character, with content, whose marker is exactly
          // what is left of the run; failing that, the innermost one that fits in it.
          const j = innermost(stack, ch, r, out.length, true) ?? innermost(stack, ch, r, out.length, false);
          const frame = j === undefined ? undefined : stack[j];
          if (j !== undefined && frame !== undefined) {
            // Frames above it were never closed: their placeholders stay in its children as
            // literal text.
            const children = mergeText(out.splice(frame.start).slice(1));
            out.push(emphasisNode(frame, children));
            stack.length = j;
            r -= frame.len;
            continue;
          }
        }
        if (canOpen) {
          const lens: readonly (1 | 2)[] = ch === "~" ? [2] : [2, 1];
          const len = lens.find((n) => n <= r && !stack.some((f) => f.ch === ch && f.len === n));
          if (len !== undefined) {
            stack.push({ ch, len, start: out.length });
            out.push({ kind: "text", text: ch.repeat(len) });
            r -= len;
            continue;
          }
        }
        out.push({ kind: "text", text: ch.repeat(r) });
        r = 0;
      }
      i += k;
      continue;
    }
    buf += ch;
    i += 1;
  }
  flush();
  return mergeText(out);
}
