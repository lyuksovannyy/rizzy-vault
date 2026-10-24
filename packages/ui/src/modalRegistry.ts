// SPDX-License-Identifier: AGPL-3.0-only

// A tiny shared registry of "is any accessible modal dialog open right now" (redesign slice 2
// follow-up fix). Modal dialogs live in several unrelated components across `apps/web` (the
// lock-with-unsaved-changes `ConfirmDialog` in `VaultView`, trash/purge in `ItemView`,
// two-factor disable in `TwoFactorPane`, the large-type password overlay in `LargeType`), each
// with its own local `open`/`value` state invisible to the others. The web vault's single
// global keyboard-shortcut listener (`VaultView`) needs to know whether *any* of them is open,
// so shortcuts like `N` (new item) and `?` (shortcuts help) never fire behind a modal dialog —
// which would break the single safe/dangerous choice a `ConfirmDialog` is built to present, let
// a password being read in large type get silently swapped out from under the user (review
// finding), and would mount or open things on top of or behind whichever dialog is showing.
//
// A plain module-level counter, not a React context: the dialogs that register here are mounted
// in components that do not share a common ancestor below `VaultView`, and the only thing a
// caller needs is a synchronous "is one open" check at the moment a key event is handled, not a
// reactive subscription.
let openCount = 0;

/** Whether any registered modal dialog anywhere in the app — `ConfirmDialog`, `LargeType`, or
 * any future one that calls {@link setModalOpen} — is currently open. */
export function isAnyModalOpen(): boolean {
  return openCount > 0;
}

/** Registers one modal dialog instance opening or closing. Called by `ConfirmDialog` and
 * `LargeType`, on open and on close/unmount, each exactly once per transition so the count stays
 * balanced; nothing else should call this directly. */
export function setModalOpen(open: boolean): void {
  openCount = open ? openCount + 1 : Math.max(0, openCount - 1);
}
