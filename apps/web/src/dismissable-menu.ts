// Escape and outside-click dismissal for a menu/popover (redesign slice 2 follow-up fix, item 3:
// "Esc closes dialogs/popovers and returns focus"). `ConfirmDialog` (packages/ui) already gets
// this through its own `onKeyDown` and backdrop button; this hook gives the same two behaviours
// to the plain `role="menu"` popovers in this app (the "New item" type picker, the account
// menu) which have no backdrop of their own.
import { type RefObject, useEffect } from "react";

/** Wires `open`'s popover to close on Escape (optionally; see `handleEscape`) and on a pointer
 * down outside `anchorRef`'s element (the popover's anchor, which must contain both the trigger
 * button and the popover itself). On an Escape close, focus returns to `triggerRef`'s button;
 * an outside click never forces focus anywhere, since the user is already interacting with
 * whatever they clicked.
 *
 * `handleEscape` defaults to `true`. Pass `false` when the caller already closes this popover on
 * Escape itself (and already returns focus) — the account menu's Escape case in `VaultView`'s
 * single global shortcut switch — so this hook only adds the outside-click half there. */
export function useDismissableMenu(
  open: boolean,
  onClose: () => void,
  anchorRef: RefObject<HTMLElement | null>,
  triggerRef: RefObject<HTMLButtonElement | null>,
  handleEscape = true,
): void {
  useEffect(() => {
    if (!open) {
      return;
    }
    const onKeyDown = (e: KeyboardEvent) => {
      if (handleEscape && e.key === "Escape") {
        e.preventDefault();
        onClose();
        triggerRef.current?.focus();
      }
    };
    const onPointerDown = (e: PointerEvent) => {
      const anchor = anchorRef.current;
      if (anchor !== null && e.target instanceof Node && !anchor.contains(e.target)) {
        onClose();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    document.addEventListener("pointerdown", onPointerDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      document.removeEventListener("pointerdown", onPointerDown);
    };
  }, [open, onClose, anchorRef, triggerRef, handleEscape]);
}
