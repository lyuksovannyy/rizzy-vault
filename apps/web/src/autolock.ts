// SPDX-License-Identifier: AGPL-3.0-only

// The web vault's lock controller (ADR 0110 §1–§4; THREAT_MODEL §7.1 "I": "Lock clears decrypted
// state. Auto-lock."). The web vault persists nothing secret (CRYPTO.md §11.4), so a lock means a
// new OPAQUE login to continue, and a reload is a restart that always locks (§4.1).
//
// **The settings** are the per-device record `rizzy.lock_settings` in this origin's `localStorage`
// (ADR 0110 §3), read and written here and parsed and encoded by Rust in the core Worker
// (`lockSettings`/`encodeLockSettings`), so the web vault applies the same rules as every other
// client: a missing or broken record is the defaults (locking on, 5 minutes, restart on, sleep
// on). Storage that throws or is missing (private windows, blocked site data) keeps the choice in
// memory only. Another tab's write arrives as the `storage` event and is applied at once.
//
// **The timer** is {@link LockTimerMirror}: Rust's `LockTimer` (`rizzy-client`'s `lock_settings`)
// rewritten here, because this UI thread does not load the wasm module (ADR 0013 §4: it holds no
// key and imports only types from packages/core). `test/autolock.test.ts` runs both on the same
// random inputs and requires the same answers, and checks these constants against Rust's.
//
// - Input is the tab's `keydown`, `pointerdown`, `wheel` and `touchstart` (§4.3 point 2).
// - Every {@link SLEEP_TICK_MS} a tick checks the idle deadline on both `performance.now()` and
//   `Date.now()`, and the sleep gap: a forward wall-clock jump of at least {@link SLEEP_GAP_MS}
//   since the previous tick locks when "Lock when the computer sleeps or hibernates" is on
//   (§4.2 point 2). The web vault has no screen-lock signal (§4.2 point 4).
// - When the tab becomes visible again the tick runs at once instead of up to 10 s later. This is
//   only an earlier tick, not a sleep signal: ADR 0110 rejects `visibilitychange` as one ("They
//   also fire for discarded and hidden tabs"), and the decision is still the timer's gap rule.
// - A settings change applies at once: the idle deadline is re-checked against the time since
//   the last input, so turning locking on, or a shorter N, locks a vault idle for longer (§1
//   points 3 and 5).
// - With the master toggle off nothing locks automatically; "Lock now", sign-out and session end
//   still do (§1 point 2).
import type { ClockReading, LockReason, LockSettings, LockSettingsChoice } from "@rizzy-vault/core";

/** The `localStorage` key of the record (ADR 0110 §3 point 2). */
export const LOCK_SETTINGS_KEY = "rizzy.lock_settings";

/** "Lock after N minutes idle": the values, in minutes (ADR 0110 §1). */
export const IDLE_MINUTES: readonly number[] = Object.freeze([1, 2, 5, 10, 15, 30, 60, 240]);

/** The turn-off dialog's delay (ADR 0110 §2 point 3). */
export const LOCK_DISABLE_CONFIRM_DELAY_MS = 5_000;

/** The lock timer's tick (ADR 0110 §4.2 point 2). */
export const SLEEP_TICK_MS = 10_000;

/** The forward wall-clock jump between two ticks that counts as a sleep (§4.2 point 2). */
export const SLEEP_GAP_MS = 120_000;

/** The defaults (ADR 0110 §1), used until the stored record is read. */
export const DEFAULT_LOCK_SETTINGS: LockSettings = Object.freeze({
  autoLock: true,
  idleMinutes: 5,
  lockOnRestart: true,
  lockOnSleep: true,
});

/** Whole, non-negative milliseconds, as Rust takes them. */
function ms(v: number): number {
  return Number.isFinite(v) && v > 0 ? Math.floor(v) : 0;
}

/** `a − b`, never below zero (Rust's `saturating_sub`). */
function since(a: number, b: number): number {
  return a > b ? a - b : 0;
}

/** Rust's `LockTimer`, rewritten (module docs): same inputs, same answers. */
export class LockTimerMirror {
  #settings: LockSettingsChoice;
  #lastMonotonic: number;
  #lastWall: number;
  #previousTickWall: number;

  constructor(settings: LockSettingsChoice, now: ClockReading) {
    this.#settings = settings;
    this.#lastMonotonic = ms(now.monotonicMs);
    this.#lastWall = ms(now.wallMs);
    this.#previousTickWall = this.#lastWall;
  }

  /** Records user input at `now`. */
  input(now: ClockReading): void {
    this.#lastMonotonic = ms(now.monotonicMs);
    this.#lastWall = ms(now.wallMs);
  }

  /** One tick: a sleep gap since the previous tick, then the idle deadline. */
  tick(now: ClockReading): LockReason | undefined {
    const wall = ms(now.wallMs);
    const previous = this.#previousTickWall;
    this.#previousTickWall = wall;
    if (this.#settings.autoLock && this.#settings.lockOnSleep && wall >= previous && wall - previous >= SLEEP_GAP_MS) {
      return "sleep";
    }
    return this.idleDue(now);
  }

  /** Applies new settings; re-checks the idle deadline and restarts the sleep baseline. */
  setSettings(settings: LockSettingsChoice, now: ClockReading): LockReason | undefined {
    this.#settings = settings;
    this.#previousTickWall = ms(now.wallMs);
    return this.idleDue(now);
  }

  /** The idle deadline alone, by either clock. */
  idleDue(now: ClockReading): LockReason | undefined {
    if (!this.#settings.autoLock) {
      return undefined;
    }
    const idle = this.#settings.idleMinutes * 60_000;
    const byMonotonic = since(ms(now.monotonicMs), this.#lastMonotonic);
    const byWall = since(ms(now.wallMs), this.#lastWall);
    return byMonotonic >= idle || byWall >= idle ? "idle" : undefined;
  }
}

/** The events that count as activity (§4.3 point 2). */
const ACTIVITY = ["keydown", "pointerdown", "wheel", "touchstart"] as const;

/** What {@link watchLock} uses from the page; injected for tests. */
export interface LockEnvironment {
  readonly target: Pick<EventTarget, "addEventListener" | "removeEventListener">;
  /** The document, for `visibilitychange`; omitted where there is none. */
  readonly document?: Pick<Document, "addEventListener" | "removeEventListener" | "visibilityState">;
  readonly now: () => ClockReading;
  readonly setInterval: (f: () => void, ms: number) => unknown;
  readonly clearInterval: (handle: unknown) => void;
}

/** The browser's page and clocks. */
export function browserLockEnvironment(): LockEnvironment {
  return {
    target: window,
    document,
    now: () => ({ monotonicMs: performance.now(), wallMs: Date.now() }),
    setInterval: (f, t) => setInterval(f, t),
    clearInterval: (h) => clearInterval(h as ReturnType<typeof setInterval>),
  };
}

/** A running lock controller: apply new settings, or stop it. */
export interface LockWatch {
  setSettings(settings: LockSettingsChoice): void;
  stop(): void;
}

/**
 * Watches for the moment to lock (module docs) and calls `onLock` once with the reason; it
 * then stops by itself.
 */
export function watchLock(
  onLock: (reason: LockReason) => void,
  settings: LockSettingsChoice,
  env: LockEnvironment = browserLockEnvironment(),
): LockWatch {
  const timer = new LockTimerMirror(settings, env.now());
  let stopped = false;
  const fire = (reason: LockReason | undefined) => {
    if (reason !== undefined && !stopped) {
      stop();
      onLock(reason);
    }
  };
  const onInput = () => timer.input(env.now());
  const onTick = () => fire(timer.tick(env.now()));
  const onVisibility = () => {
    if (env.document?.visibilityState === "visible") {
      onTick();
    }
  };
  const interval = env.setInterval(onTick, SLEEP_TICK_MS);
  for (const name of ACTIVITY) {
    env.target.addEventListener(name, onInput, { passive: true });
  }
  env.document?.addEventListener("visibilitychange", onVisibility);
  function stop() {
    if (stopped) {
      return;
    }
    stopped = true;
    env.clearInterval(interval);
    for (const name of ACTIVITY) {
      env.target.removeEventListener(name, onInput);
    }
    env.document?.removeEventListener("visibilitychange", onVisibility);
  }
  return {
    setSettings: (next) => {
      if (!stopped) {
        fire(timer.setSettings(next, env.now()));
      }
    },
    stop,
  };
}

/** The browser's `localStorage`, or `undefined` where it is missing or reading it throws. */
function storage(): Storage | undefined {
  try {
    return typeof localStorage === "undefined" ? undefined : localStorage;
  } catch {
    return undefined;
  }
}

/** The stored record text, or `null` when there is none or the storage cannot be read. */
export function readLockRecord(store: Pick<Storage, "getItem"> | undefined = storage()): string | null {
  try {
    return store?.getItem(LOCK_SETTINGS_KEY) ?? null;
  } catch {
    return null;
  }
}

/** Stores the record text (from `encodeLockSettings`); a storage that throws keeps it in memory
 * only. */
export function writeLockRecord(text: string, store: Pick<Storage, "setItem"> | undefined = storage()): void {
  try {
    store?.setItem(LOCK_SETTINGS_KEY, text);
  } catch {
    // Memory only (module docs).
  }
}

/** Calls `onChange` with the new record text when another tab changes it (ADR 0110 §3 point 6);
 * returns the function that stops listening. */
export function watchLockRecord(
  onChange: (record: string | null) => void,
  target: Pick<EventTarget, "addEventListener" | "removeEventListener"> = window,
): () => void {
  const listener = (e: Event) => {
    const key = (e as StorageEvent).key;
    if (key === LOCK_SETTINGS_KEY || key === null) {
      onChange(readLockRecord());
    }
  };
  target.addEventListener("storage", listener);
  return () => target.removeEventListener("storage", listener);
}
