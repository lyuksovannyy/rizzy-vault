// SPDX-License-Identifier: AGPL-3.0-only

// The Secure Note Markdown parser (`src/markdown.ts`; ADR 0062 §5, §10–§11): every allow-listed
// construct, the documented deviations from CommonMark, every unrecognised construct staying
// literal text, and the fail-closed and bounded-work rules. The rendered output and the hostile
// corpus are `note-markdown.test.ts`; the generated and mutated inputs `markdown-fuzz.test.ts`.
import { describe, expect, it } from "vitest";

import { type Block, type Inline, MAX_NOTE_RENDER_LENGTH, parseInline, parseNote } from "../src/markdown.ts";

const t = (text: string): Inline => ({ kind: "text", text });
const p = (...lines: Inline[][]): Block => ({ kind: "paragraph", lines });

/** The blocks of `source`, failing if the parser fell back to plain text. */
function blocks(source: string): readonly Block[] {
  const doc = parseNote(source);
  if (doc.kind !== "markdown") {
    throw new Error("unexpected plain fallback");
  }
  return doc.blocks;
}

/** The deepest inline nesting in `nodes`. */
function depth(nodes: readonly Inline[]): number {
  let max = 0;
  for (const n of nodes) {
    if (n.kind === "strong" || n.kind === "em" || n.kind === "del") {
      max = Math.max(max, 1 + depth(n.children));
    }
  }
  return max;
}

describe("block constructs", () => {
  it("parses an empty or blank note to no blocks", () => {
    expect(blocks("")).toEqual([]);
    expect(blocks("  \n\t\n\n")).toEqual([]);
  });

  it("recognises headings of one to six #", () => {
    for (let level = 1; level <= 6; level += 1) {
      expect(blocks(`${"#".repeat(level)} Title`)).toEqual([{ kind: "heading", level, content: [t("Title")] }]);
    }
  });

  it("keeps seven #, a #tag and a bare # as text", () => {
    expect(blocks("####### seven")).toEqual([p([t("####### seven")])]);
    expect(blocks("#tag")).toEqual([p([t("#tag")])]);
    expect(blocks("#")).toEqual([p([t("#")])]);
    expect(blocks("#   ")).toEqual([p([t("#")])]);
  });

  it("breaks a paragraph's lines with br and separates paragraphs at a blank line", () => {
    expect(blocks("one\ntwo\n\nthree")).toEqual([p([t("one")], [t("two")]), p([t("three")])]);
  });

  it("treats CRLF and a lone CR like LF", () => {
    expect(blocks("one\r\ntwo\r\n\r\nthree")).toEqual(blocks("one\ntwo\n\nthree"));
    expect(blocks("one\rtwo")).toEqual(blocks("one\ntwo"));
  });

  it("recognises a rule of three or more - alone, and nothing shorter", () => {
    expect(blocks("---")).toEqual([{ kind: "rule" }]);
    expect(blocks("  -----  ")).toEqual([{ kind: "rule" }]);
    expect(blocks("--")).toEqual([p([t("--")])]);
    // Not a setext heading: the rule just ends the paragraph.
    expect(blocks("text\n---")).toEqual([p([t("text")]), { kind: "rule" }]);
  });

  it("keeps a fenced block verbatim, drops its language hint and never re-parses it", () => {
    expect(blocks("```js\n**x** <script>\n  # not a heading\n```\nafter")).toEqual([
      { kind: "codeBlock", text: "**x** <script>\n  # not a heading" },
      p([t("after")]),
    ]);
  });

  it("runs an unterminated fence to the end of the note", () => {
    expect(blocks("```\na\n\nb")).toEqual([{ kind: "codeBlock", text: "a\n\nb" }]);
  });

  it("closes a fence only at a line of at least as many backticks", () => {
    expect(blocks("````\n```\n`````\nx")).toEqual([
      { kind: "codeBlock", text: "```" },
      p([t("x")]),
    ]);
    expect(blocks("```\na\n``` b")).toEqual([{ kind: "codeBlock", text: "a\n``` b" }]);
  });

  it("groups > lines into one blockquote, split into paragraphs at a bare >", () => {
    expect(blocks("> a\n> b\n>\n> *c*")).toEqual([
      { kind: "blockquote", paragraphs: [[[t("a")], [t("b")]], [[{ kind: "em", children: [t("c")] }]]] },
    ]);
  });

  it("does not nest a blockquote, or recognise a block construct inside one", () => {
    expect(blocks("> > inner\n> # heading\n> - item")).toEqual([
      { kind: "blockquote", paragraphs: [[[t("> inner")], [t("# heading")], [t("- item")]]] },
    ]);
    expect(blocks(">")).toEqual([]);
  });

  it("groups bullet lines of any marker into one list, and numbered lines into another", () => {
    expect(blocks("- a\n* b\n+ c")).toEqual([{ kind: "list", ordered: false, items: [[t("a")], [t("b")], [t("c")]] }]);
    expect(blocks("1. a\n7. b")).toEqual([{ kind: "list", ordered: true, items: [[t("a")], [t("b")]] }]);
  });

  it("starts a new list when bulleted and numbered markers mix, and ends one at a blank line", () => {
    expect(blocks("- a\n1. b\n- c")).toEqual([
      { kind: "list", ordered: false, items: [[t("a")]] },
      { kind: "list", ordered: true, items: [[t("b")]] },
      { kind: "list", ordered: false, items: [[t("c")]] },
    ]);
    expect(blocks("- a\n\n- b")).toHaveLength(2);
  });

  it("does not nest lists: an indented item is an item of the same list", () => {
    expect(blocks("- a\n  - b")).toEqual([{ kind: "list", ordered: false, items: [[t("a")], [t("b")]] }]);
  });

  it("needs a space and some text after a list marker", () => {
    expect(blocks("-a")).toEqual([p([t("-a")])]);
    expect(blocks("- ")).toEqual([p([t("-")])]);
    expect(blocks("1.a")).toEqual([p([t("1.a")])]);
    expect(blocks("1) a")).toEqual([p([t("1) a")])]);
    expect(blocks("1234567890. ten digits")).toEqual([p([t("1234567890. ten digits")])]);
  });

  it("replaces NUL with U+FFFD", () => {
    expect(blocks("a\u0000b")).toEqual([p([t("a\uFFFDb")])]);
  });
});

describe("inline constructs", () => {
  it("parses strong, emphasis, strikethrough and code", () => {
    expect(parseInline("**a** __b__ *c* _d_ ~~e~~ `f`")).toEqual([
      { kind: "strong", children: [t("a")] },
      t(" "),
      { kind: "strong", children: [t("b")] },
      t(" "),
      { kind: "em", children: [t("c")] },
      t(" "),
      { kind: "em", children: [t("d")] },
      t(" "),
      { kind: "del", children: [t("e")] },
      t(" "),
      { kind: "code", text: "f" },
    ]);
  });

  it("nests different markers", () => {
    expect(parseInline("**bold *both* bold**")).toEqual([
      { kind: "strong", children: [t("bold "), { kind: "em", children: [t("both")] }, t(" bold")] },
    ]);
    expect(parseInline("***x***")).toEqual([{ kind: "strong", children: [{ kind: "em", children: [t("x")] }] }]);
  });

  it("keeps unmatched or empty markers as text", () => {
    expect(parseInline("**open")).toEqual([t("**open")]);
    expect(parseInline("close*")).toEqual([t("close*")]);
    expect(parseInline("~single~")).toEqual([t("~single~")]);
    expect(parseInline("****")).toEqual([t("****")]);
    expect(parseInline("a * b * c")).toEqual([t("a * b * c")]);
    expect(parseInline("**a *b**")).toEqual([{ kind: "strong", children: [t("a *b")] }]);
  });

  it("does not open or close _ inside a word, but does * ", () => {
    expect(parseInline("snake_case_name")).toEqual([t("snake_case_name")]);
    expect(parseInline("2*3*4")).toEqual([t("2"), { kind: "em", children: [t("3")] }, t("4")]);
  });

  it("makes escaped ASCII punctuation literal, and keeps any other backslash", () => {
    expect(parseInline("\\*not em\\* \\`x\\` \\a \\")).toEqual([t("*not em* `x` \\a \\")]);
  });

  it("closes a code span at the next run of exactly as many backticks, literally", () => {
    expect(parseInline("``a ` b``")).toEqual([{ kind: "code", text: "a ` b" }]);
    expect(parseInline("`**x** <b>`")).toEqual([{ kind: "code", text: "**x** <b>" }]);
    expect(parseInline("` `` `")).toEqual([{ kind: "code", text: "``" }]);
    expect(parseInline("`` unmatched `")).toEqual([t("`` unmatched `")]);
    expect(parseInline("*a `*` b*")).toEqual([{ kind: "em", children: [t("a "), { kind: "code", text: "*" }, t(" b")] }]);
  });

  it("keeps unicode, bidi controls and zero-width characters as text", () => {
    const tricky = "é 漢字 😀 \u202Eevil\u202C \u2066iso\u2069 zero\u200Bwidth \uFEFF";
    expect(parseInline(tricky)).toEqual([t(tricky)]);
    expect(parseInline("**\u202Eabc**")).toEqual([{ kind: "strong", children: [t("\u202Eabc")] }]);
  });
});

describe("unrecognised constructs stay literal text (ADR 0062 §5–§7)", () => {
  const literal = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<a href=\"javascript:alert(1)\">click</a>",
    "<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>",
    "<style>body{display:none}</style>",
    "<div onmouseover=\"alert(1)\">hover</div>",
    "[text](https://example.com/)",
    "[text](javascript:alert(1))",
    "![image](https://example.com/a.png)",
    "<https://example.com/>",
    "https://example.com/path?q=1",
    "javascript:alert(1)",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "vbscript:msgbox(1)",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "&#x3C;img src=x onerror=alert(1)&#x3E;",
    "&amp; &nbsp; &#0;",
    "[^1]: a footnote",
    "| a | b |",
    "<!-- a comment -->",
  ];
  for (const source of literal) {
    it(`keeps ${JSON.stringify(source)} as text`, () => {
      expect(blocks(source)).toEqual([p([t(source)])]);
    });
  }

  it("keeps a table and a task box as text", () => {
    expect(blocks("| a | b |\n|---|---|\n| 1 | 2 |")).toEqual([p([t("| a | b |")], [t("|---|---|")], [t("| 1 | 2 |")])]);
    expect(blocks("- [ ] task\n- [x] done")).toEqual([{ kind: "list", ordered: false, items: [[t("[ ] task")], [t("[x] done")]] }]);
  });

  it("keeps a raw HTML block as text lines, parsing only the Markdown between", () => {
    expect(blocks("<div>\n**x**\n</div>")).toEqual([p([t("<div>")], [{ kind: "strong", children: [t("x")] }], [t("</div>")])]);
  });
});

describe("fail closed and bounded (ADR 0062 §10–§11)", () => {
  it("renders a note longer than the stored-value limit as plain text, unparsed", () => {
    const huge = "# x\n".repeat(MAX_NOTE_RENDER_LENGTH / 4 + 1);
    expect(parseNote(huge)).toEqual({ kind: "plain", text: huge });
    const fits = "a".repeat(MAX_NOTE_RENDER_LENGTH);
    expect(parseNote(fits).kind).toBe("markdown");
  });

  it("falls back to one plain text node holding the original on any exception", () => {
    const hostile = Object.assign(new String("**x**"), {
      replaceAll(): never {
        throw new Error("boom");
      },
    }) as unknown as string;
    expect(parseNote(hostile)).toEqual({ kind: "plain", text: hostile });
  });

  it("bounds nesting whatever the input", () => {
    const deep = "*_**__~~".repeat(4000) + "x" + "~~__**_*".repeat(4000);
    const [first] = blocks(deep);
    expect(first?.kind).toBe("paragraph");
    const lines = first?.kind === "paragraph" ? first.lines : [];
    expect(depth(lines[0] ?? [])).toBeLessThanOrEqual(5);
    expect(blocks("> ".repeat(20_000) + "x")).toEqual([
      { kind: "blockquote", paragraphs: [[[t("> ".repeat(19_999).trimEnd() + " x")]]] },
    ]);
  });

  it("parses pathological inputs of the maximum size quickly", () => {
    const n = MAX_NOTE_RENDER_LENGTH;
    const cases = [
      "*".repeat(n),
      "_a".repeat(n / 2),
      "*a".repeat(n / 2),
      "**a*".repeat(n / 4),
      "`".repeat(n),
      "`a".repeat(n / 2),
      Array.from({ length: 360 }, (_, i) => "`".repeat(i + 1) + "x").join("").slice(0, n),
      "~~a".repeat(n / 3),
      "\\*".repeat(n / 2),
      "> - # ".repeat(n / 6),
      "- a\n".repeat(n / 4),
      "```\n".repeat(n / 4),
      "\n".repeat(n),
      "<".repeat(n),
    ];
    for (const source of cases) {
      const start = performance.now();
      const doc = parseNote(source);
      const elapsed = performance.now() - start;
      expect(doc.kind).toBe("markdown");
      // Generous for a shared CI host; quadratic behaviour on 64 KiB would take far longer.
      expect(elapsed).toBeLessThan(2000);
    }
  });
});
