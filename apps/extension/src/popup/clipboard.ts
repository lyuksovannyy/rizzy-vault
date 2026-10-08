// Copy-with-clearing (ROADMAP §4.4 "copy... with clipboard clearing"): writes `value` to the
// system clipboard, then after `afterMs` clears it again — but only if the clipboard still holds
// exactly what this call put there, so a later, unrelated copy by the user is never wiped. No
// secret is logged or kept around longer than the clipboard write itself needs it.
const DEFAULT_CLEAR_AFTER_MS = 20_000;

export async function copyWithClearing(value: string, afterMs: number = DEFAULT_CLEAR_AFTER_MS): Promise<void> {
  await navigator.clipboard.writeText(value);
  setTimeout(() => {
    void navigator.clipboard
      .readText()
      .then((current) => {
        if (current === value) {
          return navigator.clipboard.writeText("");
        }
        return undefined;
      })
      .catch(() => {
        // Clipboard read can be refused (focus lost, permission) — nothing to do but leave the
        // clipboard as it is; this is a courtesy clear, not a security boundary (the secret was
        // already on the system clipboard the moment it was copied, same residual any password
        // manager's clipboard copy has).
      });
  }, afterMs);
}
