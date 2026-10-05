// The hold after the plaintext-export warning (owner decision 2026-10-05): a visible countdown,
// and the confirm control disabled until it ends. The core holds the same rule
// (`plaintext_export_hold`, rizzy-client's export gate); this module is the visible half.
//
// The countdown starts when the dialog shows the warning and starts over when the dialog is
// shown again (a new `startCountdown`). It reads the clock, so a tab that slept counts the time
// it slept, as the core does.

/** Whole seconds left of `ms` milliseconds, rounded up: 10 000 → 10, 1 → 1, 0 → 0. */
export function secondsLeft(ms: number): number {
  return Math.max(0, Math.ceil(ms / 1000));
}

/** How often the countdown re-reads the clock. */
const TICK_MS = 250;

/**
 * Counts `holdMs` down from now: calls `onTick` at once and whenever the whole seconds left
 * change, last with 0. Returns the function that stops it early (a closed dialog).
 */
export function startCountdown(
  holdMs: number,
  onTick: (secondsLeft: number) => void,
  now: () => number = Date.now,
): () => void {
  const end = now() + holdMs;
  let shown = secondsLeft(holdMs);
  onTick(shown);
  if (shown === 0) {
    return () => {};
  }
  const timer = setInterval(() => {
    const left = secondsLeft(end - now());
    if (left !== shown) {
      shown = left;
      onTick(left);
    }
    if (left === 0) {
      clearInterval(timer);
    }
  }, TICK_MS);
  return () => clearInterval(timer);
}

/** Whether the plaintext export's confirm control is enabled: the hold is over and nothing runs. */
export function confirmEnabled(secondsLeftNow: number, busy: boolean): boolean {
  return secondsLeftNow === 0 && !busy;
}
