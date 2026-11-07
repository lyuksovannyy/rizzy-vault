// SPDX-License-Identifier: AGPL-3.0-only

// The web vault's lock controller (ADR 0110 §1–§4; `autolock.ts` module docs): its constants and
// its rewrite of Rust's lock timer are checked against the real thing (the core's `LockTimer` on
// the same random inputs), then `watchLock`'s wiring with fake clocks and timers: the idle
// deadline by the monotonic and by the wall clock, the 120 s gap with sleep on and off, a 119 s
// and a backward jump, locking off, a settings change re-checking at once, and the storage
// helpers.
import {
  DEFAULT_LOCK_SETTINGS as CORE_DEFAULTS,
  LockTimer,
  type ClockReading,
  type LockSettingsChoice,
  lockSettingsLimits,
} from "@rizzy-vault/core";
import { beforeAll, describe, expect, it, vi } from "vitest";

import {
  DEFAULT_LOCK_SETTINGS,
  IDLE_MINUTES,
  LOCK_DISABLE_CONFIRM_DELAY_MS,
  LOCK_SETTINGS_KEY,
  type LockEnvironment,
  LockTimerMirror,
  SLEEP_GAP_MS,
  SLEEP_TICK_MS,
  readLockRecord,
  watchLock,
  watchLockRecord,
  writeLockRecord,
} from "../src/autolock.ts";
import { loadCore } from "./load-core.ts";

beforeAll(() => {
  loadCore();
});

describe("the constants", () => {
  it("match Rust's", () => {
    const l = lockSettingsLimits();
    expect(LOCK_SETTINGS_KEY).toBe(l.storageKey);
    expect(IDLE_MINUTES).toEqual(l.idleMinutes);
    expect(LOCK_DISABLE_CONFIRM_DELAY_MS).toBe(l.confirmDelayMs);
    expect(SLEEP_TICK_MS).toBe(l.sleepTickMs);
    expect(SLEEP_GAP_MS).toBe(l.sleepGapMs);
    expect(DEFAULT_LOCK_SETTINGS).toEqual(CORE_DEFAULTS);
  });
});

/** A small deterministic PRNG (mulberry32), so a failure reproduces. */
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4_294_967_296;
  };
}

describe("LockTimerMirror", () => {
  it("answers as Rust's LockTimer on random inputs", () => {
    for (let seed = 1; seed <= 300; seed++) {
      const r = rng(seed);
      const pick = <T,>(xs: readonly T[]): T => xs[Math.floor(r() * xs.length)] as T;
      const settings = (): LockSettingsChoice => ({
        autoLock: r() < 0.8,
        idleMinutes: pick(IDLE_MINUTES),
        lockOnSleep: r() < 0.6,
      });
      let mono = r() * 1e6;
      let wall = 1.8e12 + r() * 1e9;
      const now = (): ClockReading => ({ monotonicMs: mono, wallMs: wall });
      const first = settings();
      const rust = new LockTimer(first, now());
      const mirror = new LockTimerMirror(first, now());
      try {
        for (let step = 0; step < 60; step++) {
          // Mostly ticks; sometimes a sleep (the monotonic clock stops), a jump either way.
          const kind = r();
          const dt = pick([0, 1, 999, 9_999.5, 10_000, 59_999, 60_000, 119_999, 120_000, 300_000, 3_600_000]);
          if (kind < 0.1) {
            wall += dt; // slept: only the wall clock moved
          } else if (kind < 0.15) {
            wall -= dt; // the wall clock went back
            mono += 10_000;
          } else {
            mono += dt;
            wall += dt + (r() < 0.2 ? r() * 200 : 0);
          }
          const op = r();
          if (op < 0.6) {
            expect(mirror.tick(now()), `seed ${seed} step ${step} tick`).toBe(rust.tick(now()));
          } else if (op < 0.85) {
            mirror.input(now());
            rust.input(now());
          } else {
            const s = settings();
            expect(mirror.setSettings(s, now()), `seed ${seed} step ${step} set`).toBe(rust.setSettings(s, now()));
          }
        }
      } finally {
        rust.free();
      }
    }
  });
});

/** Fake page, clocks and interval for `watchLock`. */
function fakeEnv() {
  const target = new EventTarget();
  const doc = Object.assign(new EventTarget(), { visibilityState: "visible" as DocumentVisibilityState });
  let mono = 0;
  let wall = 1_800_000_000_000;
  let tick: (() => void) | undefined;
  const env: LockEnvironment = {
    target,
    document: doc,
    now: () => ({ monotonicMs: mono, wallMs: wall }),
    setInterval: (f, t) => {
      expect(t).toBe(SLEEP_TICK_MS);
      tick = f;
      return 1;
    },
    clearInterval: () => {
      tick = undefined;
    },
  };
  return {
    env,
    target,
    doc,
    /** Both clocks move `ms`, with a tick every 10 s on the way. */
    pass(ms: number) {
      for (let left = ms; left > 0; left -= SLEEP_TICK_MS) {
        const step = Math.min(left, SLEEP_TICK_MS);
        mono += step;
        wall += step;
        if (step === SLEEP_TICK_MS) {
          tick?.();
        }
      }
    },
    /** The device sleeps `ms`: no tick runs and the monotonic clock stops; then one tick. */
    sleep(ms: number) {
      wall += ms;
      tick?.();
    },
    /** The wall clock jumps by `ms` (either way), then one tick. */
    jump(ms: number) {
      wall += ms;
      mono += 1;
      tick?.();
    },
    /** Only the wall clock moves; no tick. */
    wallOnly(ms: number) {
      wall += ms;
    },
    running: () => tick !== undefined,
  };
}

const settings = (autoLock: boolean, idleMinutes: number, lockOnSleep: boolean): LockSettingsChoice => ({
  autoLock,
  idleMinutes,
  lockOnSleep,
});

describe("watchLock", () => {
  it("locks at N minutes plus at most one tick, and input restarts the deadline", () => {
    const f = fakeEnv();
    const onLock = vi.fn();
    watchLock(onLock, settings(true, 1, true), f.env);
    f.pass(50_000);
    f.target.dispatchEvent(new Event("keydown"));
    f.pass(50_000);
    expect(onLock).not.toHaveBeenCalled();
    f.pass(10_000);
    expect(onLock).toHaveBeenCalledWith("idle");
    expect(onLock).toHaveBeenCalledTimes(1);
    expect(f.running()).toBe(false);
    f.pass(600_000);
    expect(onLock).toHaveBeenCalledTimes(1);
  });

  it("counts time asleep by the wall clock even when the monotonic clock stopped", () => {
    const f = fakeEnv();
    const onLock = vi.fn();
    watchLock(onLock, settings(true, 1, false), f.env);
    f.sleep(119_000); // a gap, but sleep detection is off: the idle deadline still sees 119 s
    expect(onLock).toHaveBeenCalledWith("idle");
  });

  it("locks on a 120 s wall-clock gap with sleep on, not with sleep off, not at 119 s or backwards", () => {
    for (const [on, gap, expected] of [
      [true, 120_000, "sleep"],
      [false, 120_000, undefined],
      [true, 119_999, undefined],
      [true, -3_600_000, undefined],
    ] as const) {
      const f = fakeEnv();
      const onLock = vi.fn();
      watchLock(onLock, settings(true, 15, on), f.env);
      f.pass(20_000);
      f.jump(gap);
      expect(onLock.mock.calls[0]?.[0], `${on} ${gap}`).toBe(expected);
    }
  });

  it("runs the tick at once when the tab becomes visible", () => {
    const f = fakeEnv();
    const onLock = vi.fn();
    watchLock(onLock, settings(true, 15, true), f.env);
    f.doc.visibilityState = "hidden";
    f.doc.dispatchEvent(new Event("visibilitychange"));
    expect(onLock).not.toHaveBeenCalled();
    // Asleep for 3 minutes with no tick; the page is shown at wake, before the next tick.
    f.wallOnly(180_000);
    f.doc.visibilityState = "visible";
    f.doc.dispatchEvent(new Event("visibilitychange"));
    expect(onLock).toHaveBeenCalledWith("sleep");
  });

  it("never locks with locking off; turning it on re-checks the deadline at once", () => {
    const f = fakeEnv();
    const onLock = vi.fn();
    const w = watchLock(onLock, settings(false, 1, true), f.env);
    f.pass(600_000);
    f.sleep(1_000_000);
    expect(onLock).not.toHaveBeenCalled();
    w.setSettings(settings(true, 60, true));
    expect(onLock).not.toHaveBeenCalled();
    w.setSettings(settings(true, 5, true));
    expect(onLock).toHaveBeenCalledWith("idle");
  });

  it("applies a shorter N at once, and stop() ends everything", () => {
    const f = fakeEnv();
    const onLock = vi.fn();
    const w = watchLock(onLock, settings(true, 15, true), f.env);
    f.pass(130_000);
    w.setSettings(settings(true, 10, true));
    expect(onLock).not.toHaveBeenCalled();
    w.setSettings(settings(true, 2, true));
    expect(onLock).toHaveBeenCalledWith("idle");
    const g = fakeEnv();
    const onLock2 = vi.fn();
    const w2 = watchLock(onLock2, settings(true, 1, true), g.env);
    w2.stop();
    expect(g.running()).toBe(false);
    w2.setSettings(settings(true, 1, true));
    g.pass(600_000);
    expect(onLock2).not.toHaveBeenCalled();
  });
});

describe("the record in storage", () => {
  it("reads and writes rizzy.lock_settings, and survives a storage that throws", () => {
    const map = new Map<string, string>();
    const store = {
      getItem: (k: string) => map.get(k) ?? null,
      setItem: (k: string, v: string) => void map.set(k, v),
    };
    expect(readLockRecord(store)).toBeNull();
    writeLockRecord("{}", store);
    expect(map.get("rizzy.lock_settings")).toBe("{}");
    expect(readLockRecord(store)).toBe("{}");
    const broken = {
      getItem: () => {
        throw new Error("blocked");
      },
      setItem: () => {
        throw new Error("blocked");
      },
    };
    expect(readLockRecord(broken)).toBeNull();
    expect(() => writeLockRecord("{}", broken)).not.toThrow();
    expect(readLockRecord(undefined)).toBeNull();
  });

  it("hears another tab's change to the key only", () => {
    const target = new EventTarget();
    const onChange = vi.fn();
    const stop = watchLockRecord(onChange, target);
    target.dispatchEvent(Object.assign(new Event("storage"), { key: "rizzy.theme" }));
    expect(onChange).not.toHaveBeenCalled();
    target.dispatchEvent(Object.assign(new Event("storage"), { key: "rizzy.lock_settings" }));
    target.dispatchEvent(Object.assign(new Event("storage"), { key: null }));
    expect(onChange).toHaveBeenCalledTimes(2);
    stop();
    target.dispatchEvent(Object.assign(new Event("storage"), { key: "rizzy.lock_settings" }));
    expect(onChange).toHaveBeenCalledTimes(2);
  });
});
