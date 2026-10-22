// SPDX-License-Identifier: AGPL-3.0-only

// `largeType.ts`'s pure character classification for the item view's large-type password
// display (ROADMAP §4.5 "large-type password display"): no DOM in this workspace's Vitest
// (module docs of `@rizzy-vault/ui`'s `Toast.tsx`).
import { describe, expect, it } from "vitest";

import { charCells, charKind } from "../src/largeType.ts";

describe("charKind", () => {
  it("classes ASCII digits as 'digit'", () => {
    for (const d of "0123456789") {
      expect(charKind(d)).toBe("digit");
    }
  });

  it("classes ASCII letters, upper and lower, as 'letter'", () => {
    expect(charKind("a")).toBe("letter");
    expect(charKind("Z")).toBe("letter");
  });

  it("classes a non-ASCII Unicode letter as 'letter' too (an imported or passphrase value)", () => {
    expect(charKind("é")).toBe("letter");
    expect(charKind("λ")).toBe("letter");
  });

  it("classes punctuation and space as 'symbol'", () => {
    for (const s of "!@#$%^&*()_+-=[]{}|;:'\",.<>/?`~ ") {
      expect(charKind(s)).toBe("symbol");
    }
  });

  it("classes an emoji as 'symbol' (not a Unicode letter)", () => {
    expect(charKind("😀")).toBe("symbol");
  });
});

describe("charCells", () => {
  it("is empty for an empty string (boundary: an item with a cleared/empty password)", () => {
    expect(charCells("")).toEqual([]);
  });

  it("classifies each character in order", () => {
    expect(charCells("aB3!")).toEqual([
      { ch: "a", kind: "letter" },
      { ch: "B", kind: "letter" },
      { ch: "3", kind: "digit" },
      { ch: "!", kind: "symbol" },
    ]);
  });

  it("counts by Unicode code point, not UTF-16 code unit — a surrogate-pair emoji is one cell", () => {
    const cells = charCells("a😀b");
    expect(cells).toHaveLength(3);
    expect(cells.map((c) => c.ch)).toEqual(["a", "😀", "b"]);
    expect(cells.map((c) => c.kind)).toEqual(["letter", "symbol", "letter"]);
  });

  it("keeps a literal space as its own cell", () => {
    expect(charCells("a b")).toEqual([
      { ch: "a", kind: "letter" },
      { ch: " ", kind: "symbol" },
      { ch: "b", kind: "letter" },
    ]);
  });

  it("normalizes an NFD (decomposed) accented letter to its single NFC code point, not two cells", () => {
    // "e" + U+0301 COMBINING ACUTE ACCENT: two code points under NFD, one visual character.
    const nfd = "é";
    expect(nfd.normalize("NFC")).toBe("é");
    const cells = charCells(`a${nfd}b`);
    expect(cells).toEqual([
      { ch: "a", kind: "letter" },
      { ch: "é", kind: "letter" },
      { ch: "b", kind: "letter" },
    ]);
  });

  it("still splits a base letter plus a combining mark with no precomposed form into two cells (NFC is best-effort)", () => {
    // U+0325 COMBINING RING BELOW has no precomposed form with "k"; NFC leaves it as two code
    // points, so this still renders as a bare letter cell and a separate mark cell.
    const cells = charCells("k̥");
    expect(cells).toEqual([
      { ch: "k", kind: "letter" },
      { ch: "̥", kind: "symbol" },
    ]);
  });
});
