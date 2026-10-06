// `ConfirmDialog.tsx`'s pure focus-trap arithmetic (module docs there and in `Toast.tsx`: no
// DOM in this workspace's Vitest — the actual trap, Esc and backdrop-close behaviour are
// exercised by the Playwright specs instead).
import { describe, expect, it } from "vitest";

import { nextFocusIndex } from "../src/ConfirmDialog.tsx";

describe("nextFocusIndex", () => {
  it("Tab from the last element wraps to the first", () => {
    expect(nextFocusIndex(2, 1, false)).toBe(0);
  });

  it("Tab in the middle steps forward by one", () => {
    expect(nextFocusIndex(3, 0, false)).toBe(1);
  });

  it("Shift+Tab from the first element wraps to the last", () => {
    expect(nextFocusIndex(2, 0, true)).toBe(1);
  });

  it("Shift+Tab in the middle steps backward by one", () => {
    expect(nextFocusIndex(3, 2, true)).toBe(1);
  });

  it("with nothing focused yet (-1), Tab lands on the first and Shift+Tab on the last", () => {
    expect(nextFocusIndex(3, -1, false)).toBe(0);
    expect(nextFocusIndex(3, -1, true)).toBe(2);
  });

  it("a single focusable element traps on itself either direction", () => {
    expect(nextFocusIndex(1, 0, false)).toBe(0);
    expect(nextFocusIndex(1, 0, true)).toBe(0);
  });

  it("no focusable elements is -1", () => {
    expect(nextFocusIndex(0, -1, false)).toBe(-1);
  });
});
