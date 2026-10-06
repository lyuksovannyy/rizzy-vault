// `shortcuts.ts`'s pure dispatch logic (module docs there: no DOM in this workspace's Vitest).
import { describe, expect, it } from "vitest";

import {
  isTypingTarget,
  moveListSelection,
  shortcutFor,
  type ShortcutEvent,
} from "../src/shortcuts.ts";

function event(over: Partial<ShortcutEvent>): ShortcutEvent {
  return { key: "", ctrlKey: false, metaKey: false, altKey: false, shiftKey: false, target: null, ...over };
}

describe("isTypingTarget", () => {
  it("is false for no target", () => {
    expect(isTypingTarget(null)).toBe(false);
  });

  it("is true for input/textarea/select, case-insensitively", () => {
    expect(isTypingTarget({ tagName: "INPUT" })).toBe(true);
    expect(isTypingTarget({ tagName: "textarea" })).toBe(true);
    expect(isTypingTarget({ tagName: "Select" })).toBe(true);
  });

  it("is false for a button or a div", () => {
    expect(isTypingTarget({ tagName: "BUTTON" })).toBe(false);
    expect(isTypingTarget({ tagName: "DIV" })).toBe(false);
  });

  it("is true for a contenteditable element regardless of tag", () => {
    expect(isTypingTarget({ tagName: "DIV", isContentEditable: true })).toBe(true);
  });
});

describe("shortcutFor", () => {
  it("Escape always fires, even while typing", () => {
    expect(shortcutFor(event({ key: "Escape" }))).toBe("escape");
    expect(shortcutFor(event({ key: "Escape", target: { tagName: "INPUT" } }))).toBe("escape");
  });

  it("Ctrl/Cmd+K focuses search even while typing", () => {
    expect(shortcutFor(event({ key: "k", ctrlKey: true, target: { tagName: "INPUT" } }))).toBe(
      "focus-search",
    );
    expect(shortcutFor(event({ key: "K", metaKey: true }))).toBe("focus-search");
  });

  it("'/' focuses search, but only outside a typing target", () => {
    expect(shortcutFor(event({ key: "/" }))).toBe("focus-search");
    expect(shortcutFor(event({ key: "/", target: { tagName: "INPUT" } }))).toBeUndefined();
  });

  it("'n' opens a new item, 'N' too, only outside a typing target", () => {
    expect(shortcutFor(event({ key: "n" }))).toBe("new-item");
    expect(shortcutFor(event({ key: "N" }))).toBe("new-item");
    expect(shortcutFor(event({ key: "n", target: { tagName: "TEXTAREA" } }))).toBeUndefined();
  });

  it("'?' opens the shortcuts help", () => {
    expect(shortcutFor(event({ key: "?" }))).toBe("help");
  });

  it("an unmapped key is undefined", () => {
    expect(shortcutFor(event({ key: "a" }))).toBeUndefined();
  });

  it("a modified key other than the Ctrl/Cmd+K chord is suppressed", () => {
    expect(shortcutFor(event({ key: "n", ctrlKey: true }))).toBeUndefined();
    expect(shortcutFor(event({ key: "n", altKey: true }))).toBeUndefined();
  });

  it("a contenteditable target suppresses the plain shortcuts", () => {
    expect(shortcutFor(event({ key: "/", target: { tagName: "DIV", isContentEditable: true } }))).toBeUndefined();
  });
});

describe("moveListSelection", () => {
  it("ArrowDown from nothing selected lands on the first row", () => {
    expect(moveListSelection("ArrowDown", 3, -1)).toBe(0);
  });

  it("ArrowDown wraps past the last row to the first", () => {
    expect(moveListSelection("ArrowDown", 3, 2)).toBe(0);
  });

  it("ArrowUp from nothing selected lands on the last row", () => {
    expect(moveListSelection("ArrowUp", 3, -1)).toBe(2);
  });

  it("ArrowUp wraps past the first row to the last", () => {
    expect(moveListSelection("ArrowUp", 3, 0)).toBe(2);
  });

  it("steps by one in the middle of the list", () => {
    expect(moveListSelection("ArrowDown", 5, 1)).toBe(2);
    expect(moveListSelection("ArrowUp", 5, 1)).toBe(0);
  });

  it("is undefined for an empty list or an unrelated key", () => {
    expect(moveListSelection("ArrowDown", 0, -1)).toBeUndefined();
    expect(moveListSelection("Enter", 3, 0)).toBeUndefined();
  });
});
