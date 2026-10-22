// SPDX-License-Identifier: AGPL-3.0-only

// A mutation fuzzer for the Secure Note Markdown parser (`src/markdown.ts`; ADR 0062 §10–§11;
// CLAUDE.md's "untrusted input … add a fuzz target"). The parser is TypeScript in `apps/web`
// (ADR 0062 §3), so its fuzz target is this seeded harness rather than a cargo-fuzz target under
// `fuzz/`, which only reaches Rust. It mutates a seed corpus (hostile payloads and Markdown) by
// random insertion of tokens and arbitrary UTF-16 code units (lone surrogates included),
// deletion, duplication, splicing and truncation, and checks on every input that:
// - the parser never threw: a note within the size limit always parses to Markdown, never to
//   the exception fallback (§11), which would hide a crash bug;
// - the rendered markup holds only allow-listed elements, attributes and classes
//   (`markdown-oracle.ts`; §5–§9);
// - the work stays bounded (§10).
//
// Budgets mirror the adversarial-import sweep (`e2e/adversarial-import.spec.ts`): two literal seeds
// by default; with `RIZZY_NIGHTLY` set, a fresh seed from the clock (or `RIZZY_NIGHTLY_SEED` for
// a reproducible rerun) and many more iterations. A failure names the seed and iteration.
import { describe, expect, it } from "vitest";

import { SINK_PAYLOADS, URI_PAYLOADS } from "../e2e/attack/payloads.ts";
import { PR_SEEDS, freshSeed, mulberry32, randInt } from "../e2e/attack/rng.ts";
import { MAX_NOTE_RENDER_LENGTH, parseNote } from "../src/markdown.ts";
import { inertViolations, renderMarkup } from "./markdown-oracle.ts";

const CORPUS: readonly string[] = [
  "",
  "# Heading\n\nA **bold** *em* ~~del~~ `code` line\nnext\n\n> quote\n>\n> more\n\n- a\n- b\n\n1. one\n2. two\n\n---\n\n```js\nx\n```",
  "***a*** __*b*__ ~~**c**~~ `` d ` e `` \\*f\\* snake_case_x",
  "<script>alert(1)</script>\n<img src=x onerror=alert(1)>\n[x](javascript:alert(1))\n![y](data:,z)",
  "&lt;b&gt; &#x3C;i&#x3E; &amp;",
  "\u202E\u2066\u200B\uFEFF\u0000\r\n\r",
  ...SINK_PAYLOADS.map((p) => p.value),
  ...URI_PAYLOADS.map((p) => p.value),
];

const TOKENS: readonly string[] = ["**", "__", "*", "_", "~~", "`", "```", "\\", "\n", "\r\n", "# ", "> ", "- ", "1. ", "---", "<", ">", "&", "\"", "javascript:"];

function mutate(rand: () => number, input: string): string {
  let s = input;
  const ops = 1 + randInt(rand, 8);
  for (let k = 0; k < ops; k += 1) {
    const at = randInt(rand, s.length + 1);
    switch (randInt(rand, 7)) {
      case 0:
        s = s.slice(0, at) + (TOKENS[randInt(rand, TOKENS.length)] ?? "") + s.slice(at);
        break;
      case 1:
        s = s.slice(0, at) + String.fromCharCode(randInt(rand, 0x10000)) + s.slice(at);
        break;
      case 2:
        s = s.slice(0, at) + s.slice(at + 1 + randInt(rand, 16));
        break;
      case 3: {
        const end = at + randInt(rand, 32);
        s = s.slice(0, end) + s.slice(at, end) + s.slice(end);
        break;
      }
      case 4: {
        const other = CORPUS[randInt(rand, CORPUS.length)] ?? "";
        const from = randInt(rand, other.length + 1);
        s = s.slice(0, at) + other.slice(from, from + randInt(rand, 64)) + s.slice(at);
        break;
      }
      case 5:
        s = s.slice(0, at);
        break;
      default:
        // Blow-up: repeat the whole input, up to just past the size limit.
        if (s.length > 0 && s.length * 2 <= MAX_NOTE_RENDER_LENGTH + 64) {
          s = s + s;
        }
    }
  }
  return s;
}

const nightly = process.env["RIZZY_NIGHTLY"] !== undefined;
const SEEDS = nightly
  ? [Number(process.env["RIZZY_NIGHTLY_SEED"] ?? freshSeed(1)) >>> 0]
  : PR_SEEDS;
const ITERATIONS = nightly ? 50_000 : 1_500;

describe("fuzz: the Markdown parser", () => {
  for (const seed of SEEDS) {
    it(`seed 0x${seed.toString(16)}: never throws, always inert, bounded`, { timeout: 120_000 }, () => {
      const rand = mulberry32(seed);
      let current = CORPUS[0] ?? "";
      let longest = 0;
      for (let i = 0; i < ITERATIONS; i += 1) {
        // Mostly keep mutating the last input (to reach deep and large ones), sometimes restart.
        const base = randInt(rand, 4) === 0 ? (CORPUS[randInt(rand, CORPUS.length)] ?? "") : current;
        const input = mutate(rand, base);
        const where = `seed 0x${seed.toString(16)} iteration ${i} (length ${input.length})`;
        const start = performance.now();
        const doc = parseNote(input);
        const markup = renderMarkup(input);
        const elapsed = performance.now() - start;
        if (input.length <= MAX_NOTE_RENDER_LENGTH) {
          expect(doc.kind, where).toBe("markdown");
        } else {
          expect(doc, where).toEqual({ kind: "plain", text: input });
        }
        const problems = inertViolations(markup);
        if (problems.length > 0) {
          throw new Error(`${where}: ${problems.slice(0, 3).join("; ")}: ${JSON.stringify(input.slice(0, 200))}`);
        }
        expect(elapsed, where).toBeLessThan(2000);
        longest = Math.max(longest, input.length);
        current = input.length > MAX_NOTE_RENDER_LENGTH ? (CORPUS[1] ?? "") : input;
      }
      // The blow-up mutation reached large inputs, so the bounded-work check was exercised.
      expect(longest).toBeGreaterThan(16 * 1024);
    });
  }
});
