// A tiny shared registry of "is any accessible modal dialog open right now" (redesign slice 2
// follow-up fix). `ConfirmDialog` instances live in several unrelated components across
// `apps/web` (the lock-with-unsaved-changes dialog in `VaultView`, trash/purge in `ItemView`,
// two-factor disable in `TwoFactorPane`), each with its own local `open` state invisible to the
// others. The web vault's single global keyboard-shortcut listener (`VaultView`) needs to know
// whether *any* of them is open, so shortcuts like `N` (new item) and `?` (shortcuts help)
// never fire behind a modal confirm dialog — which would break the single safe/dangerous choice
// the dialog is built to present, and would mount or open things on top of or behind it.
//
// A plain module-level counter, not a React context: the dialogs that register here are mounted
// in components that do not share a common ancestor below `VaultView`, and the only thing a
// caller needs is a synchronous "is one open" check at the moment a key event is handled, not a
// reactive subscription.
let openCount = 0;

/** Whether any `ConfirmDialog` anywhere in the app is currently open. */
export function isAnyModalOpen(): boolean {
  return openCount > 0;
}

/** Registers one `ConfirmDialog` instance opening or closing. Called only by `ConfirmDialog`
 * itself; nothing else should call this directly. */
export function setModalOpen(open: boolean): void {
  openCount = open ? openCount + 1 : Math.max(0, openCount - 1);
}
