// SPDX-License-Identifier: AGPL-3.0-only

// The editor's early copies of ADR 0076's W1–W5 checks (`src/autocomplete.ts`), and the
// reserved set's parity with `rizzy-core`, the authority.
import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  RESERVED_AUTOCOMPLETE_IDS,
  autocompleteIdError,
  autocompleteProblems,
  lowercaseAscii,
  shadowedText,
} from "../src/autocomplete.ts";

/** The string literals of `RESERVED_AUTOCOMPLETE_IDS` in `rizzy-core`. */
function rustReserved(): string[] {
  const source = readFileSync(new URL("../../../crates/rizzy-core/src/item/autocomplete.rs", import.meta.url), "utf8");
  const start = source.indexOf("pub const RESERVED_AUTOCOMPLETE_IDS");
  const end = source.indexOf("];", start);
  return [...source.slice(start, end).matchAll(/"([^"]+)"/g)].map((m) => m[1] ?? "");
}

describe("autocomplete ids", () => {
  it("has rizzy-core's reserved set, in order", () => {
    expect(rustReserved()).toHaveLength(70);
    expect(RESERVED_AUTOCOMPLETE_IDS).toEqual(rustReserved());
  });

  it("checks the grammar, then the reserved set", () => {
    expect(autocompleteIdError("custominput")).toBeUndefined();
    expect(autocompleteIdError("a".repeat(64))).toBeUndefined();
    expect(autocompleteIdError("a".repeat(65))).toBe("invalid");
    expect(autocompleteIdError("")).toBe("invalid");
    expect(autocompleteIdError("Member")).toBe("invalid");
    expect(autocompleteIdError("a b")).toBe("invalid");
    expect(autocompleteIdError("café")).toBe("invalid");
    expect(autocompleteIdError("username")).toBe("reserved");
    expect(autocompleteIdError("email")).toBe("reserved");
    expect(autocompleteIdError("section-a")).toBe("reserved");
    expect(autocompleteIdError("section")).toBeUndefined();
  });

  it("lowercases ASCII only", () => {
    expect(lowercaseAscii("Member-NO")).toBe("member-no");
    expect(lowercaseAscii("ÉA B")).toBe("Éa b");
  });

  it("reports W1–W5 per row; a saved duplicate is a warning, not an error", () => {
    const base = { label: "L", kind: "text" as const, savedId: "", edited: true };
    const problems = autocompleteProblems([
      { ...base, key: "a", id: "member" },
      { ...base, key: "b", id: "member" },
      { ...base, key: "c", id: "Bad" },
      { ...base, key: "d", id: "totp" },
      { ...base, key: "e", id: "flag", kind: "boolean" },
      { ...base, key: "f", id: "", label: "  " },
      { ...base, key: "g", id: "", label: "", edited: false },
      { ...base, key: "h", id: "x", savedId: "x" },
      { ...base, key: "i", id: "x", savedId: "x" },
    ]);
    expect(problems.get("a")).toEqual({ id: "duplicate" });
    expect(problems.get("b")).toEqual({ id: "duplicate" });
    expect(problems.get("c")).toEqual({ id: "invalid" });
    expect(problems.get("d")).toEqual({ id: "reserved" });
    expect(problems.get("e")).toEqual({ id: "kind" });
    expect(problems.get("f")).toEqual({ label: "required" });
    expect(problems.has("g")).toBe(false);
    expect(problems.has("h")).toBe(false);
    expect(problems.has("i")).toBe(false);
  });

  it("words the shadowed warning as the ADR does", () => {
    expect(shadowedText("acct", "Account")).toBe(
      "Autocomplete id “acct” is also used by “Account”; only that field is filled. Change or clear one.",
    );
  });
});
