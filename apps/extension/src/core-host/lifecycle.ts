// Auto-lock (ADR 0036 §3): "a configurable idle timeout (default 15 minutes), lock on
// `chrome.idle`/`browser.idle` reaching `locked` or `idle`, and an explicit 'lock now' action."
// `AutoLockTimer` is the idle-timeout half, written with an injectable clock so it is a plain
// unit test (`test/autolock.test.ts`), not a browser integration test; the `chrome.idle`/
// `browser.idle` half is wired in `offscreen.ts`/`background-page.ts`, which own the real
// browser APIs this module does not touch.
export const DEFAULT_AUTO_LOCK_MS = 15 * 60 * 1000;

/** The one `storage.local` key the options page writes and {@link readAutoLockMs} reads
 * (ADR 0036 §3 "user-configurable"): shared here, not duplicated as a string literal in
 * `options/main.tsx`, so the writer and the reader can never drift (SSOT). Not security-relevant
 * on its own (the timeout is not secret), hence `storage.local`, not `storage.session`. */
export const AUTO_LOCK_MINUTES_STORAGE_KEY = "rizzy.auto_lock_minutes";

export const MIN_AUTO_LOCK_MINUTES = 1;
export const MAX_AUTO_LOCK_MINUTES = 180;

/**
 * Validates and bounds an untrusted `storage.local` value before it ever reaches a timer
 * (`core-context.ts` reads this straight off browser storage, which this extension's own options
 * page writes today but a corrupted profile or a future bug could still leave holding anything).
 * Not a finite number → the documented default (15 minutes); a finite number outside
 * [{@link MIN_AUTO_LOCK_MINUTES}, {@link MAX_AUTO_LOCK_MINUTES}] → clamped to the nearer bound,
 * never the default (a user who saved an out-of-range value still gets *a* working timeout, the
 * closest one in range, not a silent reset to 15); a fractional value → rounded to the nearest
 * whole minute, since the timer has no use for fractional minutes.
 */
export function clampAutoLockMinutes(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return DEFAULT_AUTO_LOCK_MS / 60_000;
  }
  const rounded = Math.round(value);
  if (rounded < MIN_AUTO_LOCK_MINUTES) {
    return MIN_AUTO_LOCK_MINUTES;
  }
  if (rounded > MAX_AUTO_LOCK_MINUTES) {
    return MAX_AUTO_LOCK_MINUTES;
  }
  return rounded;
}

/** Reads the auto-lock timeout the options page saved, validated and bounded
 * ({@link clampAutoLockMinutes}), as milliseconds for {@link AutoLockTimer}'s constructor. Called
 * once, at `core-context.ts`'s `startCoreContext` — not on every tick — so a value saved while
 * the long-lived context is already running takes effect on its next restart, the same
 * granularity `storage.session`'s own restore-at-startup already uses.
 *
 * `ext.storage` is typed optional (`types/webext.d.ts`: absent inside a `chrome.offscreen`
 * document specifically, measured empirically) — the documented default, not a thrown error,
 * where it is missing, the same degrade `session-store.ts`'s `hasSessionStorage` already uses. */
export async function readAutoLockMs(ext: WebExtNamespace): Promise<number> {
  if (ext.storage === undefined) {
    return DEFAULT_AUTO_LOCK_MS;
  }
  const stored = await ext.storage.local.get(AUTO_LOCK_MINUTES_STORAGE_KEY);
  return clampAutoLockMinutes(stored[AUTO_LOCK_MINUTES_STORAGE_KEY]) * 60_000;
}

export interface Clock {
  now(): number;
  setTimeout(callback: () => void, ms: number): number;
  clearTimeout(handle: number): void;
}

/** The real browser clock, used everywhere outside tests. */
export const systemClock: Clock = {
  now: () => Date.now(),
  setTimeout: (callback, ms) => globalThis.setTimeout(callback, ms) as unknown as number,
  clearTimeout: (handle) => globalThis.clearTimeout(handle),
};

/**
 * Fires `onLock` after `timeoutMs` of no {@link AutoLockTimer.activity} call. `activity` is
 * called on every message the long-lived context answers, and on every popup interaction
 * forwarded to it; `setTimeout` default (not configured) matches ADR 0036's recommendation.
 * Locking itself (zeroizing handles, clearing `storage.session`) is the caller's job, done
 * inside `onLock`: this class only tracks time.
 */
export class AutoLockTimer {
  #clock: Clock;
  #timeoutMs: number;
  #onLock: () => void;
  #handle: number | undefined;
  #stopped = true;

  constructor(onLock: () => void, timeoutMs: number = DEFAULT_AUTO_LOCK_MS, clock: Clock = systemClock) {
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
      throw new RangeError("timeoutMs must be a positive, finite number of milliseconds");
    }
    this.#clock = clock;
    this.#timeoutMs = timeoutMs;
    this.#onLock = onLock;
  }

  /** Starts (or restarts) counting down from now. Call once on unlock. */
  start(): void {
    this.#stopped = false;
    this.#reschedule();
  }

  /** Resets the countdown to a full {@link timeoutMs} from now. A no-op once stopped. */
  activity(): void {
    if (this.#stopped) {
      return;
    }
    this.#reschedule();
  }

  /** Cancels the countdown (called by an explicit lock, so it does not also fire later). */
  stop(): void {
    this.#stopped = true;
    if (this.#handle !== undefined) {
      this.#clock.clearTimeout(this.#handle);
      this.#handle = undefined;
    }
  }

  /** The configured timeout, for display in the options page. */
  get timeoutMs(): number {
    return this.#timeoutMs;
  }

  /** Changes the configured timeout; takes effect on the next {@link activity} or {@link start}. */
  setTimeoutMs(timeoutMs: number): void {
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
      throw new RangeError("timeoutMs must be a positive, finite number of milliseconds");
    }
    this.#timeoutMs = timeoutMs;
    if (!this.#stopped) {
      this.#reschedule();
    }
  }

  #reschedule(): void {
    if (this.#handle !== undefined) {
      this.#clock.clearTimeout(this.#handle);
    }
    this.#handle = this.#clock.setTimeout(() => {
      this.#stopped = true;
      this.#handle = undefined;
      this.#onLock();
    }, this.#timeoutMs);
  }
}
