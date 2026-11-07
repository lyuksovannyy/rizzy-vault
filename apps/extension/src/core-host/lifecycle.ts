// SPDX-License-Identifier: AGPL-3.0-only

// The extension's lock controller (ADR 0110 §1–§4; ADR 0111 §3), in the long-lived context that
// holds the core: the offscreen document on Chromium, the background page on Firefox. It applies
// the per-device lock settings (`rizzy.lock_settings`, parsed by Rust's `lock_settings`) and locks
// through one `lock()` on any of:
//
// - **the activity deadline and the sleep gap**: Rust's `LockTimer` (packages/core), ticked every
//   `SLEEP_TICK_MS` (10 s) by the monotonic and the wall clock (ADR 0110 §4.2–§4.3). Activity is
//   every popup or options request the context answers (`handlePopupRequest`);
// - **the OS idle state** (ADR 0111 §3's table): `"idle"` locks while locking is on; `"locked"`
//   only with "Lock when the computer sleeps or hibernates" on as well; `"active"`, any other
//   string or no answer never locks. On Chromium it arrives pushed by the service worker
//   (`idle_state`) or as the answer to a poll this controller sends every `IDLE_POLL_MS` while
//   unlocked and locking is on (`idle_status_query`, §3.1 item 3), because whether
//   `chrome.idle.onStateChanged` wakes a terminated service worker is unknown. On Firefox the
//   persistent background page receives `browser.idle` itself (§3.2) and needs no poll.
//
// With locking off nothing runs: no tick, no poll, and neither idle state locks (§3, first row).
// "Lock now" always locks; it does not pass through here. Every handle is injected, so
// `test/autolock.test.ts` drives the controller with a fake clock and the real Rust timer.

import type { ClockReading, LockReason, LockSettings } from "@rizzy-vault/core";

import { IDLE_POLL_MS } from "../messaging/lock-messages.ts";

export { IDLE_POLL_MS } from "../messaging/lock-messages.ts";

/** ADR 0110 §4.2 point 2's tick (`LOCK_SETTINGS_LIMITS.sleepTickMs`). */
export const SLEEP_TICK_MS = 10_000;

/** `settings.idle_minutes * 60` (ADR 0111 §3, `idleIntervalSeconds`). */
export function idleIntervalSeconds(settings: Pick<LockSettings, "idleMinutes">): number {
  return settings.idleMinutes * 60;
}

/** The part of packages/core's `LockTimer` this controller calls. */
export interface LockTimerLike {
  input(now: ClockReading): void;
  tick(now: ClockReading): LockReason | undefined;
  setSettings(settings: LockSettings, now: ClockReading): LockReason | undefined;
  free(): void;
}

/** What the long-lived context gives the controller. */
export interface LockControllerHost {
  readonly now: () => ClockReading;
  readonly setInterval: (f: () => void, ms: number) => unknown;
  readonly clearInterval: (handle: unknown) => void;
  readonly newTimer: (settings: LockSettings, now: ClockReading) => LockTimerLike;
  /** Locks the session (zeroizes every handle, clears the stores). Called at most once per
   * unlocked session by this controller. */
  readonly lock: (reason: LockReason | "os_idle" | "os_locked") => void;
  /** Chromium only: one `idle_status_query` to the service worker; resolves to its raw answer.
   * Absent on Firefox (no poll). */
  readonly queryIdleStatus?: () => Promise<unknown>;
  /** Applies a polled answer's settings text (Rust's parser, and the migration of a legacy
   * value): returns the settings to apply. */
  readonly settingsOfAnswer?: (answer: unknown) => LockSettings | undefined;
  /** Polled answers' OS idle state, or `undefined` for a malformed answer. */
  readonly stateOfAnswer?: (answer: unknown) => string | undefined;
}

function sameSettings(a: LockSettings, b: LockSettings): boolean {
  return (
    a.autoLock === b.autoLock &&
    a.idleMinutes === b.idleMinutes &&
    a.lockOnRestart === b.lockOnRestart &&
    a.lockOnSleep === b.lockOnSleep
  );
}

export class LockController {
  #host: LockControllerHost;
  #settings: LockSettings;
  #timer: LockTimerLike | undefined;
  #tick: unknown;
  #poll: unknown;
  #polling = false;

  constructor(host: LockControllerHost, settings: LockSettings) {
    this.#host = host;
    this.#settings = settings;
  }

  /** The settings applied now (handed to the core at passkey signing, ADR 0110 §6 point 5). */
  get settings(): LockSettings {
    return this.#settings;
  }

  /** Whether a session is being timed (between {@link unlocked} and {@link locked}). */
  get running(): boolean {
    return this.#timer !== undefined;
  }

  /** Whether the Chromium poll is running (tests, and the e2e's diagnosis). */
  get polling(): boolean {
    return this.#poll !== undefined;
  }

  /** Applies new settings at once (ADR 0111 §3: a change re-checks the deadline and switches the
   * triggers). An unchanged value is a no-op. */
  applySettings(settings: LockSettings): void {
    if (sameSettings(settings, this.#settings)) {
      return;
    }
    this.#settings = settings;
    const timer = this.#timer;
    if (timer === undefined) {
      return;
    }
    const reason = timer.setSettings(settings, this.#host.now());
    if (reason !== undefined) {
      this.#fire(reason);
      return;
    }
    this.#sync();
  }

  /** A session was unlocked: start timing it, and ask once for the settings (Chromium). */
  unlocked(): void {
    this.#stopTimer();
    this.#timer = this.#host.newTimer(this.#settings, this.#host.now());
    this.#sync();
    void this.refreshSettings();
  }

  /** User activity (a popup or options request). */
  activity(): void {
    this.#timer?.input(this.#host.now());
  }

  /** The session was locked by any trigger: stop every timer and the poll. */
  locked(): void {
    this.#stopTimer();
  }

  /** An OS idle state (pushed, polled or, on Firefox, the event): locks only as ADR 0111 §3's
   * table allows. */
  idleState(state: unknown): void {
    if (this.#timer === undefined || !this.#settings.autoLock) {
      return;
    }
    if (state === "idle") {
      this.#fire("os_idle");
    } else if (state === "locked" && this.#settings.lockOnSleep) {
      this.#fire("os_locked");
    }
  }

  /** One query for the settings only (at start and on unlock, ADR 0111 §3.1 item 3): its idle
   * state is not acted on. No-op without a poll channel. */
  async refreshSettings(): Promise<void> {
    const answer = await this.#query();
    if (answer !== undefined) {
      this.#applyAnswerSettings(answer);
    }
  }

  /** A query, or `undefined` for a rejected send or no answer within `IDLE_POLL_MS`. */
  async #query(): Promise<unknown> {
    const query = this.#host.queryIdleStatus;
    if (query === undefined) {
      return undefined;
    }
    let timeout: unknown;
    try {
      return await Promise.race([
        query(),
        new Promise<undefined>((resolve) => {
          timeout = this.#host.setInterval(() => resolve(undefined), IDLE_POLL_MS);
        }),
      ]);
    } catch {
      return undefined;
    } finally {
      this.#host.clearInterval(timeout);
    }
  }

  #applyAnswerSettings(answer: unknown): boolean {
    const settings = this.#host.settingsOfAnswer?.(answer);
    if (settings === undefined) {
      return false;
    }
    this.applySettings(settings);
    return true;
  }

  async #onPoll(): Promise<void> {
    if (this.#polling) {
      return;
    }
    this.#polling = true;
    try {
      const answer = await this.#query();
      if (answer === undefined || this.#timer === undefined) {
        return;
      }
      // Settings first, so a `"locked"` answer is judged by the record it came with.
      if (!this.#applyAnswerSettings(answer)) {
        return;
      }
      this.idleState(this.#host.stateOfAnswer?.(answer));
    } finally {
      this.#polling = false;
    }
  }

  #fire(reason: LockReason | "os_idle" | "os_locked"): void {
    if (this.#timer === undefined) {
      return;
    }
    this.#stopTimer();
    this.#host.lock(reason);
  }

  /** The tick and the poll run exactly while a session is timed and locking is on. */
  #sync(): void {
    const on = this.#timer !== undefined && this.#settings.autoLock;
    if (on && this.#tick === undefined) {
      this.#tick = this.#host.setInterval(() => this.#onTick(), SLEEP_TICK_MS);
    } else if (!on && this.#tick !== undefined) {
      this.#host.clearInterval(this.#tick);
      this.#tick = undefined;
    }
    const pollOn = on && this.#host.queryIdleStatus !== undefined;
    if (pollOn && this.#poll === undefined) {
      this.#poll = this.#host.setInterval(() => void this.#onPoll(), IDLE_POLL_MS);
    } else if (!pollOn && this.#poll !== undefined) {
      this.#host.clearInterval(this.#poll);
      this.#poll = undefined;
    }
  }

  #onTick(): void {
    const reason = this.#timer?.tick(this.#host.now());
    if (reason !== undefined) {
      this.#fire(reason);
    }
  }

  #stopTimer(): void {
    const timer = this.#timer;
    this.#timer = undefined;
    this.#sync();
    timer?.free();
  }
}
