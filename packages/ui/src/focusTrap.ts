// SPDX-License-Identifier: AGPL-3.0-only

// The Tab/Shift+Tab focus trap every modal dialog shares: `ConfirmDialog` here, and the web
// vault's shortcuts help, large-type overlay, second-factor prompt and plaintext-export dialog.
// `aria-modal="true"` tells a screen reader the page behind is inert, but the browser does not
// make it so: without a trap, Tab from a dialog's last control walks on into the page behind it.
// Moved out of `ConfirmDialog.tsx`, which was the only dialog that trapped, so all of them trap
// the same way.
//
// The arithmetic (`nextFocusIndex`) is a pure function, unit-tested directly (module docs of
// `Toast.tsx` explain why: no DOM, no jsdom dependency in this workspace); the trap itself is
// covered end to end by apps/web's `e2e/a11y.spec.ts`.
import type { KeyboardEvent } from "react";

/** Where Tab/Shift+Tab moves focus next, cycling through `count` focusable elements from
 * `current` (`-1` when nothing inside the dialog is focused yet, e.g. focus was moved there
 * programmatically to the dialog container itself). */
export function nextFocusIndex(count: number, current: number, shiftKey: boolean): number {
  if (count <= 0) {
    return -1;
  }
  if (shiftKey) {
    return current <= 0 ? count - 1 : current - 1;
  }
  return current >= count - 1 ? 0 : current + 1;
}

/** The elements inside `root` that Tab can reach. */
const FOCUSABLE =
  'button:not(:disabled), a[href], input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex="-1"])';

/** Keeps a Tab or Shift+Tab inside `root`: call it from the dialog element's `onKeyDown`. Any
 * other key, or a dialog with nothing focusable, is left alone. */
export function trapTab(e: KeyboardEvent<HTMLElement>, root: HTMLElement | null): void {
  if (e.key !== "Tab" || root === null) {
    return;
  }
  const elements = Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE));
  if (elements.length === 0) {
    return;
  }
  const current = elements.indexOf(document.activeElement as HTMLElement);
  const target = elements[nextFocusIndex(elements.length, current, e.shiftKey)];
  if (target !== undefined) {
    e.preventDefault();
    target.focus();
  }
}
