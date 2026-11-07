// SPDX-License-Identifier: AGPL-3.0-only

// The turn-off dialog's countdown arithmetic (ADR 0110 §2 point 3), apart from the component so
// it is unit tested without a DOM (this workspace's Vitest runs in Node).

/** Where the countdown is after `elapsedMs` of the monotonic clock. */
export interface Countdown {
  /** Whether Confirm works. */
  readonly ready: boolean;
  /** The whole seconds left, shown as "Turn off locking (n)"; 0 once ready. */
  readonly seconds: number;
}

/** The countdown after `elapsedMs` of a `delayMs` delay: "(5)" at 0 ms, "(1)" up to the last
 * millisecond, ready at exactly `delayMs`. A negative or non-finite elapsed time counts as 0. */
export function countdown(elapsedMs: number, delayMs: number): Countdown {
  const elapsed = Number.isFinite(elapsedMs) && elapsedMs > 0 ? elapsedMs : 0;
  const remaining = delayMs - elapsed;
  if (remaining <= 0) {
    return { ready: true, seconds: 0 };
  }
  return { ready: false, seconds: Math.ceil(remaining / 1000) };
}

/** Milliseconds until the label next changes (the next whole second of the remaining time), or 0
 * once ready. */
export function nextCountdownChange(elapsedMs: number, delayMs: number): number {
  const elapsed = Number.isFinite(elapsedMs) && elapsedMs > 0 ? elapsedMs : 0;
  const remaining = delayMs - elapsed;
  if (remaining <= 0) {
    return 0;
  }
  const part = remaining % 1000;
  return part === 0 ? 1000 : part;
}
