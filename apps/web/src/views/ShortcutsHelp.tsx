// The keyboard-shortcuts help dialog, opened by `?` (redesign slice 2, item 3; `shortcuts.ts`).
// Not built on `ConfirmDialog` (there is nothing to confirm here, and a single "Close" action
// has no "safe" vs. "dangerous" distinction), but it shares the same overlay/dialog shell,
// Escape-to-close, and a backdrop button, so it still reads and behaves like every other
// dialog in the vault.
import { Fragment, useEffect, useId, useRef } from "react";

const SHORTCUTS: readonly { readonly keys: string; readonly does: string }[] = [
  { keys: "/", does: "Focus the search box" },
  { keys: "Ctrl/Cmd+K", does: "Focus the search box" },
  { keys: "↑ / ↓", does: "Move the item-list selection" },
  { keys: "Enter", does: "Open the selected item" },
  { keys: "Esc", does: "Close a dialog or popover" },
  { keys: "N", does: "New item" },
  { keys: "?", does: "Show this help" },
];

/** The shortcuts help dialog (module docs). */
export function ShortcutsHelp(props: { readonly open: boolean; readonly onClose: () => void }) {
  const titleId = useId();
  const closeRef = useRef<HTMLButtonElement>(null);
  const previouslyFocused = useRef<Element | null>(null);

  useEffect(() => {
    if (!props.open) {
      return;
    }
    previouslyFocused.current = document.activeElement;
    closeRef.current?.focus();
    return () => {
      if (previouslyFocused.current instanceof HTMLElement) {
        previouslyFocused.current.focus();
      }
    };
  }, [props.open]);

  if (!props.open) {
    return null;
  }

  return (
    <div className="overlay">
      <button type="button" className="dialog-backdrop" aria-label="Close" onClick={props.onClose} />
      <div
        className="panel dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        onKeyDown={(e) => {
          if (e.key === "Escape") {
            e.preventDefault();
            props.onClose();
          }
        }}
      >
        <h2 id={titleId}>Keyboard shortcuts</h2>
        <dl className="shortcuts-list">
          {SHORTCUTS.map((s) => (
            <Fragment key={s.keys}>
              <dt>{s.keys}</dt>
              <dd>{s.does}</dd>
            </Fragment>
          ))}
        </dl>
        <div className="actions">
          <button type="button" ref={closeRef} className="secondary" onClick={props.onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
