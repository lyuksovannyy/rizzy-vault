// The theme choice in browser storage (src/theme.ts; CRYPTO.md §11.4).
import { describe, expect, it } from "vitest";
import { THEME_STORAGE_KEY, type ThemeStore, loadTheme, saveTheme } from "../src/theme.ts";

function memoryStore(): ThemeStore & { readonly data: Map<string, string> } {
  const data = new Map<string, string>();
  return {
    data,
    getItem: (k) => data.get(k) ?? null,
    setItem: (k, v) => {
      data.set(k, v);
    },
    removeItem: (k) => {
      data.delete(k);
    },
  };
}

const throwing: ThemeStore = {
  getItem: () => {
    throw new Error("blocked");
  },
  setItem: () => {
    throw new Error("blocked");
  },
  removeItem: () => {
    throw new Error("blocked");
  },
};

describe("theme storage", () => {
  it("round-trips light and dark", () => {
    const s = memoryStore();
    saveTheme("dark", s);
    expect(s.data.get(THEME_STORAGE_KEY)).toBe("dark");
    expect(loadTheme(s)).toBe("dark");
    saveTheme("light", s);
    expect(loadTheme(s)).toBe("light");
  });

  it("system removes the entry", () => {
    const s = memoryStore();
    saveTheme("dark", s);
    saveTheme("system", s);
    expect(s.data.has(THEME_STORAGE_KEY)).toBe(false);
    expect(loadTheme(s)).toBe("system");
  });

  it("reads nothing, unknown values and a missing store as system", () => {
    const s = memoryStore();
    expect(loadTheme(s)).toBe("system");
    s.data.set(THEME_STORAGE_KEY, "neon");
    expect(loadTheme(s)).toBe("system");
    expect(loadTheme(undefined)).toBe("system");
  });

  it("survives a store that throws", () => {
    expect(loadTheme(throwing)).toBe("system");
    expect(() => saveTheme("dark", throwing)).not.toThrow();
  });
});
