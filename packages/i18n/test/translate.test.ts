// SPDX-License-Identifier: AGPL-3.0-only

// `t`, `interpolate`, `placeholders` and `isMessageKey` (`src/translate.ts`).
import { describe, expect, it } from "vitest";

import { DEFAULT_LOCALE, LOCALES, en, interpolate, isMessageKey, placeholders, t, translator } from "../src/index.ts";

describe("t", () => {
  it("returns the English text of a key", () => {
    expect(t("login.title")).toBe("Log in to rizzy-vault");
    expect(t("errors.locked")).toBe("The vault is locked.");
  });

  it("fills named placeholders", () => {
    expect(t("common.unknownError", { code: "something_new" })).toBe("Something went wrong (something_new).");
  });

  it("is the default locale's translator, and the default locale is English, the only one", () => {
    expect(DEFAULT_LOCALE).toBe("en");
    expect(LOCALES).toEqual(["en"]);
    expect(translator("en")("totp.title")).toBe(t("totp.title"));
  });

  it("checks keys and placeholder values at compile time", () => {
    // Never called: the lines below exist for `tsc` (`pnpm run build`), which fails if any
    // `@ts-expect-error` stops being an error.
    const typeChecks = () => {
      // @ts-expect-error: not a key.
      t("login.nope");
      // @ts-expect-error: the message has a placeholder, so its value is required.
      t("common.unknownError");
      // @ts-expect-error: the value is for another placeholder.
      t("common.unknownError", { name: "x" });
      // @ts-expect-error: the message has no placeholder.
      t("login.title", { code: "x" });
      // @ts-expect-error: "fr" is not a shipped locale.
      translator("fr");
    };
    expect(typeof typeChecks).toBe("function");
  });
});

describe("interpolate", () => {
  it("fills every occurrence and leaves other text alone", () => {
    expect(interpolate("{a} and {b}, then {a} again", { a: "x", b: 2 })).toBe("x and 2, then x again");
    expect(interpolate("no placeholders", { a: "x" })).toBe("no placeholders");
    expect(interpolate("{a}", undefined)).toBe("{a}");
  });

  it("keeps a placeholder without a value as written", () => {
    expect(interpolate("{a} {b}", { a: "x" })).toBe("x {b}");
    // Only own values count, not ones from the prototype.
    expect(interpolate("{toString}", {})).toBe("{toString}");
  });

  it("inserts values verbatim, in one pass", () => {
    // A value holding a placeholder is not filled again.
    expect(interpolate("{a}{b}", { a: "{b}", b: "y" })).toBe("{b}y");
    // `String.prototype.replace`'s `$` patterns do not apply to values.
    expect(interpolate("[{a}]", { a: "$& $1 $$" })).toBe("[$& $1 $$]");
    // Markup stays text; React escapes it when it renders (ADR 0014 §2).
    expect(interpolate("{a}", { a: "<b>x</b>" })).toBe("<b>x</b>");
  });

  it("only treats {identifier} as a placeholder", () => {
    expect(interpolate("{ a } {1a} {} {a-b}", { a: "x" })).toBe("{ a } {1a} {} {a-b}");
  });
});

describe("placeholders", () => {
  it("lists names in order, repeats included", () => {
    expect(placeholders("{a} {b} {a}")).toEqual(["a", "b", "a"]);
    expect(placeholders("none")).toEqual([]);
  });
});

describe("isMessageKey", () => {
  it("is true for catalogue keys only, never for prototype names", () => {
    expect(isMessageKey("login.title")).toBe(true);
    expect(isMessageKey("errors.locked")).toBe(true);
    expect(isMessageKey("login.nope")).toBe(false);
    for (const name of ["constructor", "toString", "__proto__", "hasOwnProperty"]) {
      expect(isMessageKey(name)).toBe(false);
    }
    expect(Object.keys(en).every(isMessageKey)).toBe(true);
  });
});
