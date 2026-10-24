// SPDX-License-Identifier: AGPL-3.0-only

// The large-type password display (ROADMAP §4.5 "large-type password display"): an
// already-revealed value shown one character per cell, large enough and with digits, letters
// and symbols coloured apart (`largeType.ts`'s `charCells`) to read unambiguously at a glance —
// the same job 1Password's "Large Type" window does, useful for typing a password into another
// device by eye.
//
// Revealing nothing new beyond the existing reveal path (`ItemView.tsx`'s module docs, ADR 0013
// §3 rule 3): this component only renders a string its caller already holds. It never calls
// into the core itself, and its own "Large type" trigger (`ItemView.tsx`'s `FieldValue`)
// appears only once that field's existing Reveal/Copy `value()` has already crossed the value
// from the Worker — never a second, independent crossing.
//
// Registers with the shared modal registry (`setModalOpen`, `packages/ui/src/modalRegistry.ts`)
// exactly like `ConfirmDialog` does, so `VaultView.tsx`'s global keyboard-shortcut gate
// (`isAnyModalOpen()`) suppresses `N`/`?`/Ctrl+K while this overlay is open (review finding):
// without it, those shortcuts fired right through the overlay whenever focus sat on its own
// Close button, since a `<button>` is not a typing target (`shortcuts.ts`'s `isTypingTarget`) —
// `N` silently swapped the item detail pane to a blank draft mid-read, and `?`/Ctrl+K opened
// another dialog stacked on top.
import { setModalOpen, trapTab } from "@rizzy-vault/ui";
import { useEffect, useId, useRef } from "react";

import { charCells } from "../largeType.ts";

/** The large-type overlay (module docs). Renders nothing while `value` is `undefined`, so a
 * caller can mount it unconditionally and set `value` only once it has one, the same shape as
 * `ConfirmDialog`. */
export function LargeType(props: { readonly label: string; readonly value: string | undefined; readonly onClose: () => void }) {
  const { value, onClose } = props;
  const titleId = useId();
  const closeRef = useRef<HTMLButtonElement>(null);
  const dialogRef = useRef<HTMLDivElement>(null);
  const previouslyFocused = useRef<Element | null>(null);

  useEffect(() => {
    if (value === undefined) {
      return;
    }
    previouslyFocused.current = document.activeElement;
    closeRef.current?.focus();
    // Registers this overlay in the shared "a modal is open" count (`modalRegistry.ts`, module
    // docs above) so the app-wide keyboard-shortcut handler suppresses global shortcuts while
    // it is showing, exactly like `ConfirmDialog` does.
    setModalOpen(true);
    return () => {
      setModalOpen(false);
      if (previouslyFocused.current instanceof HTMLElement) {
        previouslyFocused.current.focus();
      }
    };
  }, [value]);

  if (value === undefined) {
    return null;
  }

  const cells = charCells(value);

  return (
    <div className="overlay">
      <button type="button" className="dialog-backdrop" aria-label="Close" onClick={onClose} />
      <div
        className="panel dialog large-type"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={`${titleId}-value`}
        ref={dialogRef}
        onKeyDown={(e) => {
          if (e.key === "Escape") {
            e.preventDefault();
            onClose();
            return;
          }
          trapTab(e, dialogRef.current);
        }}
      >
        <h2 id={titleId}>{props.label}</h2>
        {/* Decorative: each cell is `aria-hidden`, and the paragraph below carries the same
            text once, as a single screen-reader announcement, rather than this grid announcing
            every cell on its own (module docs). */}
        <div className="large-type-grid" aria-hidden="true">
          {cells.length === 0 ? (
            <span className="large-type-cell large-type-symbol">&nbsp;</span>
          ) : (
            cells.map((c, i) => (
              <span key={i} className={`large-type-cell large-type-${c.kind}`}>
                {c.ch}
              </span>
            ))
          )}
        </div>
        <p id={`${titleId}-value`} className="sr-only">
          {value === "" ? "Empty." : value}
        </p>
        <div className="actions">
          <button type="button" ref={closeRef} className="secondary" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
