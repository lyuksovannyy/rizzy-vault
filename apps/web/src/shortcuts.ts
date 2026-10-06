// Keyboard shortcuts (redesign slice 2, item 3): pure dispatch logic, kept separate from the
// `keydown` listener that calls it so it can be unit-tested without a DOM (module docs of
// `@rizzy-vault/ui`'s `Toast.tsx`: this workspace's Vitest runs with no jsdom).
//
// Shortcuts never fire while the user is typing in a form control (`isTypingTarget`), with one
// exception: Escape always fires, because the control the user is typing in might be inside the
// very dialog Escape should close (e.g. the two-factor code field inside `TwoFactorPane`, or a
// text field inside the item editor). Ctrl/Cmd+K is a chord, not a bare letter, so it also fires
// while typing — that convention (a command-palette shortcut always available) is why it is
// offered as an alternative to the bare `/` at all.

/** Minimal shape of the parts of a `KeyboardEvent`/its `target` this module reads, so it does
 * not depend on `lib.dom`'s event types directly and stays trivially testable with plain
 * objects. */
export interface ShortcutEvent {
  readonly key: string;
  readonly ctrlKey: boolean;
  readonly metaKey: boolean;
  readonly altKey: boolean;
  readonly shiftKey: boolean;
  readonly target: ShortcutTarget | null;
}

export interface ShortcutTarget {
  readonly tagName?: string;
  readonly isContentEditable?: boolean;
}

export type ShortcutAction = "focus-search" | "new-item" | "help" | "escape";

const TYPING_TAGS = new Set(["INPUT", "TEXTAREA", "SELECT"]);

/** Whether `target` is a form control (or a contenteditable element) the user could be typing
 * into right now (module docs). */
export function isTypingTarget(target: ShortcutTarget | null): boolean {
  if (target === null) {
    return false;
  }
  if (target.isContentEditable === true) {
    return true;
  }
  const tag = target.tagName;
  return tag !== undefined && TYPING_TAGS.has(tag.toUpperCase());
}

/** Which action, if any, a `keydown` event triggers (module docs). Returns `undefined` for a
 * key with no shortcut, or one suppressed because the user is typing. */
export function shortcutFor(e: ShortcutEvent): ShortcutAction | undefined {
  if (e.key === "Escape") {
    return "escape";
  }
  const chordK = (e.ctrlKey || e.metaKey) && !e.altKey && (e.key === "k" || e.key === "K");
  if (chordK) {
    return "focus-search";
  }
  if (isTypingTarget(e.target) || e.ctrlKey || e.metaKey || e.altKey) {
    return undefined;
  }
  switch (e.key) {
    case "/":
      return "focus-search";
    case "n":
    case "N":
      return "new-item";
    case "?":
      return "help";
    default:
      return undefined;
  }
}

/** Where ArrowUp/ArrowDown move the item list's selection: a plain cyclic index step over
 * `count` rows from `current` (`-1` when nothing is selected yet, so the first ArrowDown lands
 * on row 0). Returns `undefined` for a key this list does not handle, so the list's own
 * `onKeyDown` can let the event continue (e.g. to the browser's native Tab handling) in that
 * case. Exported for its own test; the DOM focus move itself (`ItemsPane.tsx`) is exercised by
 * the keyboard-navigation Playwright spec instead. */
export function moveListSelection(key: string, count: number, current: number): number | undefined {
  if (count <= 0) {
    return undefined;
  }
  if (key === "ArrowDown") {
    return current >= count - 1 ? 0 : current + 1;
  }
  if (key === "ArrowUp") {
    return current <= 0 ? count - 1 : current - 1;
  }
  return undefined;
}
