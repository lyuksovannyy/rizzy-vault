// SPDX-License-Identifier: AGPL-3.0-only

// Every shipped catalogue is complete and well-formed (`src/en.ts` docs, README.md). The types
// already reject a missing or extra key; these checks cover what they cannot see.
import { describe, expect, it } from "vitest";

import { CATALOGUES, LOCALES, en, placeholders, type MessageKey } from "../src/index.ts";

const KEY = /^[a-z][A-Za-z0-9]*\.[a-z][A-Za-z0-9_]*$/;
const englishKeys = Object.keys(en).sort();

describe.each(LOCALES)("the %s catalogue", (locale) => {
  const catalogue = CATALOGUES[locale];

  it("has exactly the English keys", () => {
    expect(Object.keys(catalogue).sort()).toEqual(englishKeys);
  });

  it("has a non-empty, trimmed text for every key", () => {
    for (const [key, text] of Object.entries(catalogue)) {
      expect(text.trim(), key).toBe(text);
      expect(text.length, key).toBeGreaterThan(0);
      expect(text, key).not.toMatch(/\s{2,}/);
    }
  });

  it("uses the English placeholders, and braces only for placeholders", () => {
    for (const key of englishKeys as MessageKey[]) {
      const text = catalogue[key];
      expect(new Set(placeholders(text)), key).toEqual(new Set(placeholders(en[key])));
      const withoutPlaceholders = text.replace(/\{[A-Za-z][A-Za-z0-9_]*\}/g, "");
      expect(withoutPlaceholders, key).not.toMatch(/[{}]/);
    }
  });
});

describe("the English catalogue", () => {
  it("names keys <area>.<name>", () => {
    for (const key of englishKeys) {
      expect(key).toMatch(KEY);
    }
  });

  it("words error codes without placeholders (no message echoes input, INV-48)", () => {
    const errorKeys = englishKeys.filter((k) => k.startsWith("errors.")) as MessageKey[];
    expect(errorKeys.length).toBeGreaterThan(0);
    for (const key of errorKeys) {
      expect(placeholders(en[key]), key).toEqual([]);
    }
  });
});
