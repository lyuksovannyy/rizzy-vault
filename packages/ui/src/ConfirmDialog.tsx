// SPDX-License-Identifier: AGPL-3.0-only

// An accessible confirm dialog (redesign slice 2, item 2), replacing `window.confirm` across
// the web vault: trash, purge, lock-with-unsaved-changes, two-factor disable.
//
// `aria-modal="true"` plus a labelled `role="dialog"`; initial focus lands on the *safe*
// action (cancel), never the destructive one, so a stray Enter after a slow click never
// confirms something destructive; Escape and a backdrop click both cancel; Tab/Shift+Tab cycle
// only inside the dialog (a focus trap) so a sighted keyboard user, and a screen-reader user in
// browse mode, can never tab out to the page behind it.
//
// The trap is `focusTrap.ts`'s, shared with every other modal dialog of the web vault.
import { type KeyboardEvent, useEffect, useRef } from "react";

import { trapTab } from "./focusTrap.ts";
import { setModalOpen } from "./modalRegistry.ts";

export { nextFocusIndex } from "./focusTrap.ts";

/** The props of {@link ConfirmDialog}. */
export interface ConfirmDialogProps {
  readonly open: boolean;
  readonly titleId: string;
  readonly title: string;
  readonly description: string;
  readonly confirmLabel: string;
  readonly cancelLabel?: string;
  /** Styles the confirm button as destructive (`button.danger`). */
  readonly danger?: boolean;
  readonly onConfirm: () => void;
  readonly onCancel: () => void;
}

/** The accessible confirm dialog (module docs). Renders nothing while `open` is false, so a
 * caller can mount it unconditionally and just flip `open`. */
export function ConfirmDialog(props: ConfirmDialogProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);
  const confirmRef = useRef<HTMLButtonElement>(null);
  const previouslyFocused = useRef<Element | null>(null);

  useEffect(() => {
    if (!props.open) {
      return;
    }
    previouslyFocused.current = document.activeElement;
    // Initial focus on the safe action (module docs), not the dialog container: a container
    // `tabIndex={-1}` focus target would need its own extra Tab press to reach the first real
    // control.
    cancelRef.current?.focus();
    // Registers this instance in the shared "a modal is open" count (`modalRegistry.ts`) so the
    // app-wide keyboard-shortcut handler can suppress shortcuts while any confirm dialog,
    // anywhere, is open.
    setModalOpen(true);
    return () => {
      setModalOpen(false);
      // Returns focus to whatever opened the dialog once it closes, so a keyboard user is not
      // dropped back at the top of the page.
      if (previouslyFocused.current instanceof HTMLElement) {
        previouslyFocused.current.focus();
      }
    };
  }, [props.open]);

  if (!props.open) {
    return null;
  }

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key === "Escape") {
      e.preventDefault();
      props.onCancel();
      return;
    }
    trapTab(e, containerRef.current);
  };

  return (
    <div className="overlay">
      {/* The backdrop: a button, not a bare div with an onClick, so it is itself keyboard- and
          screen-reader-reachable like every other clickable control in this codebase, and so
          `no-restricted-syntax`'s click-handler rules have nothing div-specific to flag. */}
      <button type="button" className="dialog-backdrop" aria-label={props.cancelLabel ?? "Cancel"} onClick={props.onCancel} />
      <div
        ref={containerRef}
        className="panel dialog confirm-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby={props.titleId}
        aria-describedby={`${props.titleId}-desc`}
        onKeyDown={onKeyDown}
      >
        <h2 id={props.titleId}>{props.title}</h2>
        <p id={`${props.titleId}-desc`}>{props.description}</p>
        <div className="actions">
          <button type="button" ref={confirmRef} className={props.danger === true ? "danger" : undefined} onClick={props.onConfirm}>
            {props.confirmLabel}
          </button>
          <button type="button" ref={cancelRef} className="secondary" onClick={props.onCancel}>
            {props.cancelLabel ?? "Cancel"}
          </button>
        </div>
      </div>
    </div>
  );
}
