// SPDX-License-Identifier: AGPL-3.0-only

// The rendered Secure Note (`src/views/NoteMarkdown.tsx`; ADR 0062 §3, §5–§9, §11; INV-88): the
// exact elements each construct renders as, the plain fallback, a hostile corpus that must
// render inert, and a property test over generated notes that no output ever holds an element,
// attribute or class outside the fixed allow-list (`markdown-oracle.ts`) and that no letter of
// the note is lost. Positive controls first: the oracle flags what it is looking for.
import { describe, expect, it } from "vitest";

import { SINK_PAYLOADS, URI_PAYLOADS } from "../e2e/attack/payloads.ts";
import { PR_SEEDS, freshSeed, mulberry32, randInt } from "../e2e/attack/rng.ts";
import { type Block, type Inline, MAX_NOTE_RENDER_LENGTH, parseNote } from "../src/markdown.ts";
import { ALLOWED_CLASSES, inertViolations, renderMarkup } from "./markdown-oracle.ts";

describe("the inertness oracle (positive controls)", () => {
  it("flags every disallowed element, attribute, class and unescaped markup", () => {
    for (const bad of [
      "<script>alert(1)</script>",
      "<img class=\"md-p\">",
      "<a class=\"md-p\" href=\"https://example.com/\">x</a>",
      "<iframe></iframe>",
      "<style></style>",
      "<p class=\"md-p\" onclick=\"alert(1)\">x</p>",
      "<p style=\"color:red\">x</p>",
      "<p class=\"evil\">x</p>",
      "<p class=\"md-p\" id=\"x\">x</p>",
      "<svg><animate></animate></svg>",
      "<p>x<</p>",
    ]) {
      expect(inertViolations(bad), bad).not.toEqual([]);
    }
  });

  it("accepts the allow-listed markup", () => {
    expect(inertViolations("<div class=\"field-value md-note\"><p class=\"md-p\">a<br class=\"md-br\"/>b &lt;</p><hr class=\"md-hr\"/></div>")).toEqual([]);
  });
});

describe("rendering", () => {
  it("renders every allow-listed construct as its fixed element and class", () => {
    const source = [
      "# Title",
      "",
      "Some **bold** and *em*, ~~gone~~ and `code`.",
      "Next line",
      "",
      "> quoted",
      "",
      "- a",
      "- b",
      "",
      "1. one",
      "",
      "---",
      "",
      "```",
      "<b>x</b>",
      "```",
      "###### six",
    ].join("\n");
    expect(renderMarkup(source)).toBe(
      '<div class="field-value md-note">' +
        '<h1 class="md-h1">Title</h1>' +
        '<p class="md-p">Some <strong class="md-strong">bold</strong> and <em class="md-em">em</em>, ' +
        '<del class="md-del">gone</del> and <code class="md-code">code</code>.<br class="md-br"/>Next line</p>' +
        '<blockquote class="md-blockquote"><p class="md-p">quoted</p></blockquote>' +
        '<ul class="md-ul"><li class="md-li">a</li><li class="md-li">b</li></ul>' +
        '<ol class="md-ol"><li class="md-li">one</li></ol>' +
        '<hr class="md-hr"/>' +
        '<pre class="md-pre"><code class="md-pre-code">&lt;b&gt;x&lt;/b&gt;</code></pre>' +
        '<h6 class="md-h6">six</h6>' +
        "</div>",
    );
  });

  it("renders an empty note as an empty container", () => {
    expect(renderMarkup("")).toBe('<div class="field-value md-note"></div>');
  });

  it("renders the plain fallback as the plain stored text (§11)", () => {
    const huge = "<script>".repeat(MAX_NOTE_RENDER_LENGTH / 8 + 1);
    const markup = renderMarkup(huge);
    expect(markup.startsWith('<span class="field-value">&lt;script&gt;')).toBe(true);
    expect(inertViolations(markup)).toEqual([]);
  });
});

/** A hostile corpus beyond the import harness's (`e2e/attack/payloads.ts`): HTML in every
 * Markdown position, dangerous URL schemes in link and image syntax, entities, and unicode
 * tricks. */
const HOSTILE: readonly string[] = [
  "<script>alert(1)</script>",
  "# <script>alert(1)</script>",
  "**<img src=x onerror=alert(1)>**",
  "*<svg onload=alert(1)>*",
  "~~<iframe src=javascript:alert(1)>~~",
  "`<script>alert(1)</script>`",
  "```html\n<script>alert(1)</script>\n```",
  "> <style>*{display:none}</style>",
  "- <a href=\"javascript:alert(1)\">x</a>\n1. <form action=x><button>go</button></form>",
  "<div onmouseover=\"alert(1)\" style=\"position:fixed;inset:0\">x</div>",
  "<p class=\"md-p\" onclick=alert(1)>class spoof</p>",
  "[click](javascript:alert(1))",
  "[click](JaVaScRiPt:alert(1))",
  "[click](  javascript:alert(1))",
  "[click](data:text/html,<script>alert(1)</script>)",
  "[click](vbscript:msgbox(1))",
  "[click](https://example.com/ \"title\")",
  "[ref][1]\n\n[1]: javascript:alert(1)",
  "![x](https://attacker.example/pixel.png)",
  "![x](data:image/svg+xml,<svg onload=alert(1)>)",
  "<javascript:alert(1)>",
  "<https://example.com/>",
  "https://example.com/ www.example.com mailto:a@example.com",
  "&lt;script&gt;alert(1)&lt;/script&gt;",
  "&#60;script&#62;alert(1)&#60;/script&#62;",
  "&#x3C;img src=x onerror=alert(1)&#x3E;",
  "&amp;lt;b&amp;gt;",
  "<!-- <script>alert(1)</script> -->",
  "<![CDATA[<script>alert(1)</script>]]>",
  "<?xml version=\"1.0\"?><x/>",
  "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
  "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
  "\u202E<script>alert(1)</script>\u202C",
  "*\u200B*\u200B<b\u200B>x</b>",
  "<scr\u0000ipt>alert(1)</scr\u0000ipt>",
  "\uFEFF# heading after a BOM",
  "\uD800 lone surrogates \uDFFF **\uD83D**",
  "**".repeat(5000) + "<script>",
  "> ".repeat(5000) + "<img src=x onerror=alert(1)>",
  "- ".repeat(5000) + "<iframe>",
  ...SINK_PAYLOADS.map((p) => p.value),
  ...URI_PAYLOADS.map((p) => p.value),
];

describe("a hostile corpus renders inert (INV-88)", () => {
  for (const [i, source] of HOSTILE.entries()) {
    it(`payload ${i}: ${JSON.stringify(source.slice(0, 60))}`, () => {
      const doc = parseNote(source);
      expect(doc.kind).toBe("markdown");
      expect(inertViolations(renderMarkup(source))).toEqual([]);
    });
  }
});

/** The tokens generated notes are built from: Markdown markers, hostile HTML and URLs, entities,
 * whitespace, line endings and unicode tricks. Backtick tokens always end in a space or a
 * newline, so a generated fence never carries a language hint, the one place §5 drops letters. */
const TOKENS: readonly string[] = [
  "**",
  "__",
  "*",
  "_",
  "~~",
  "~",
  "` ",
  "`` ",
  "```\n",
  "\\",
  "\n",
  "\n\n",
  "\r\n",
  "\r",
  " ",
  "\t",
  "# ",
  "## ",
  "### ",
  "#### ",
  "##### ",
  "###### ",
  "####### ",
  "> ",
  ">",
  "- ",
  "* ",
  "+ ",
  "1. ",
  "---\n",
  "<script>alert(1)</script>",
  "<img src=x onerror=alert(1)>",
  "<a href=\"javascript:alert(1)\">",
  "</a>",
  "<style>",
  "<iframe srcdoc=x>",
  "<",
  ">",
  "\"",
  "'",
  "=",
  "[link](javascript:alert(1))",
  "![img](data:image/png;base64,AAAA)",
  "javascript:",
  "vbscript:",
  "data:",
  "https://example.com/",
  "&lt;",
  "&#60;",
  "&amp;",
  "<!--",
  "-->",
  "\u202E",
  "\u2066",
  "\u200B",
  "\uFEFF",
  "\u0000",
  "é",
  "漢",
  "😀",
  "word",
  "x",
];

/** A note of up to `maxTokens` random tokens. */
function generate(rand: () => number, maxTokens: number): string {
  let out = "";
  const n = randInt(rand, maxTokens + 1);
  for (let i = 0; i < n; i += 1) {
    out += TOKENS[randInt(rand, TOKENS.length)] ?? "";
  }
  return out;
}

/** Every letter of the parsed note, in order. */
function lettersOfDoc(blocks: readonly Block[]): string {
  const inline = (nodes: readonly Inline[]): string =>
    nodes.map((n) => (n.kind === "text" || n.kind === "code" ? n.text : inline(n.children))).join("");
  return blocks
    .map((b) => {
      switch (b.kind) {
        case "heading":
          return inline(b.content);
        case "paragraph":
          return b.lines.map(inline).join("");
        case "codeBlock":
          return b.text;
        case "blockquote":
          return b.paragraphs.map((lines) => lines.map(inline).join("")).join("");
        case "list":
          return b.items.map(inline).join("");
        case "rule":
          return "";
      }
    })
    .join("")
    .replace(/\P{L}/gu, "");
}

const nightly = process.env["RIZZY_NIGHTLY"] !== undefined;
const SEEDS = nightly
  ? [Number(process.env["RIZZY_NIGHTLY_SEED"] ?? freshSeed(0)) >>> 0]
  : PR_SEEDS;
const CASES = nightly ? 20_000 : 600;

describe("property: generated notes never render an HTML sink", () => {
  for (const seed of SEEDS) {
    it(`seed 0x${seed.toString(16)}: only allow-listed elements, attributes and classes, no letter lost`, () => {
      const rand = mulberry32(seed);
      const seen = new Set<string>();
      for (let c = 0; c < CASES; c += 1) {
        const source = generate(rand, 60);
        const doc = parseNote(source);
        if (doc.kind !== "markdown") {
          throw new Error(`plain fallback for case ${c}: ${JSON.stringify(source)}`);
        }
        const markup = renderMarkup(source);
        for (const m of markup.matchAll(/class="([^"]*)"/g)) {
          for (const cls of (m[1] ?? "").split(" ")) {
            seen.add(cls);
          }
        }
        const problems = inertViolations(markup);
        if (problems.length > 0) {
          throw new Error(`case ${c} ${JSON.stringify(source)}: ${problems.join("; ")}`);
        }
        // NUL becomes U+FFFD (not a letter either way), so letters match one for one.
        expect(lettersOfDoc(doc.blocks), JSON.stringify(source)).toBe(source.replace(/\P{L}/gu, ""));
      }
      // The generator reaches every construct, so the property is not vacuous.
      expect([...ALLOWED_CLASSES].filter((c) => !seen.has(c))).toEqual([]);
    });
  }
});
