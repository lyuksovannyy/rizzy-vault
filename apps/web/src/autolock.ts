// Auto-lock after inactivity (THREAT_MODEL §7.1 "I": "Lock clears decrypted state. Auto-lock.").
// Any keyboard, pointer or wheel input restarts the timer. The web vault persists nothing
// (CRYPTO.md §11.4), so a lock means a new OPAQUE login to continue.

/** Idle time before the vault locks itself. A product choice of this M1 web vault. */
export const IDLE_LOCK_MS = 15 * 60_000;

/** The events that count as activity. */
const ACTIVITY = ["keydown", "pointerdown", "wheel", "touchstart"] as const;

/** Calls `onIdle` after `idleMs` without input; returns the function that stops watching. */
export function watchIdle(
  onIdle: () => void,
  idleMs: number = IDLE_LOCK_MS,
  target: Pick<EventTarget, "addEventListener" | "removeEventListener"> = window,
): () => void {
  let timer = setTimeout(onIdle, idleMs);
  const reset = () => {
    clearTimeout(timer);
    timer = setTimeout(onIdle, idleMs);
  };
  for (const name of ACTIVITY) {
    target.addEventListener(name, reset, { passive: true });
  }
  return () => {
    clearTimeout(timer);
    for (const name of ACTIVITY) {
      target.removeEventListener(name, reset);
    }
  };
}
