// The auto-lock timer (ADR 0036 §3: "a configurable idle timeout... default 15 minutes").
// Uses a fake, injectable clock (`lifecycle.ts`'s `Clock`) so this is a pure unit test with no
// real timers and no browser APIs.
import { describe, expect, it, vi } from "vitest";

import {
  AUTO_LOCK_MINUTES_STORAGE_KEY,
  AutoLockTimer,
  DEFAULT_AUTO_LOCK_MS,
  MAX_AUTO_LOCK_MINUTES,
  MIN_AUTO_LOCK_MINUTES,
  type Clock,
  clampAutoLockMinutes,
  readAutoLockMs,
} from "../src/core-host/lifecycle.ts";

function fakeClock(): Clock & { advance: (ms: number) => void; pendingCount: () => number } {
  let now = 0;
  let nextHandle = 1;
  const timers = new Map<number, { at: number; callback: () => void }>();
  return {
    now: () => now,
    setTimeout: (callback, ms) => {
      const handle = nextHandle++;
      timers.set(handle, { at: now + ms, callback });
      return handle;
    },
    clearTimeout: (handle) => {
      timers.delete(handle);
    },
    advance: (ms) => {
      now += ms;
      for (const [handle, timer] of [...timers]) {
        if (timer.at <= now) {
          timers.delete(handle);
          timer.callback();
        }
      }
    },
    pendingCount: () => timers.size,
  };
}

describe("AutoLockTimer", () => {
  it("defaults to 15 minutes (ADR 0036 §3)", () => {
    expect(DEFAULT_AUTO_LOCK_MS).toBe(15 * 60 * 1000);
  });

  it("fires onLock after the timeout with no activity", () => {
    const clock = fakeClock();
    const onLock = vi.fn();
    const timer = new AutoLockTimer(onLock, 1000, clock);
    timer.start();
    clock.advance(999);
    expect(onLock).not.toHaveBeenCalled();
    clock.advance(1);
    expect(onLock).toHaveBeenCalledTimes(1);
  });

  it("activity() resets the countdown to a full timeout", () => {
    const clock = fakeClock();
    const onLock = vi.fn();
    const timer = new AutoLockTimer(onLock, 1000, clock);
    timer.start();
    clock.advance(900);
    timer.activity();
    clock.advance(900);
    expect(onLock).not.toHaveBeenCalled(); // only 900ms since the last activity()
    clock.advance(100);
    expect(onLock).toHaveBeenCalledTimes(1);
  });

  it("stop() cancels the pending lock and clears the scheduled timer", () => {
    const clock = fakeClock();
    const onLock = vi.fn();
    const timer = new AutoLockTimer(onLock, 1000, clock);
    timer.start();
    timer.stop();
    expect(clock.pendingCount()).toBe(0);
    clock.advance(10_000);
    expect(onLock).not.toHaveBeenCalled();
  });

  it("activity() after stop() is a no-op (does not resurrect the timer)", () => {
    const clock = fakeClock();
    const onLock = vi.fn();
    const timer = new AutoLockTimer(onLock, 1000, clock);
    timer.start();
    timer.stop();
    timer.activity();
    expect(clock.pendingCount()).toBe(0);
  });

  it("the configured timeout is user-configurable (ADR 0036 §3)", () => {
    const clock = fakeClock();
    const onLock = vi.fn();
    const timer = new AutoLockTimer(onLock, 1000, clock);
    timer.start();
    timer.setTimeoutMs(5000);
    clock.advance(1000);
    expect(onLock).not.toHaveBeenCalled();
    clock.advance(4000);
    expect(onLock).toHaveBeenCalledTimes(1);
  });

  it("rejects a non-positive timeout", () => {
    expect(() => new AutoLockTimer(() => undefined, 0)).toThrow(RangeError);
    expect(() => new AutoLockTimer(() => undefined, -1)).toThrow(RangeError);
    expect(() => new AutoLockTimer(() => undefined, Number.NaN)).toThrow(RangeError);
  });
});

// The options page's auto-lock minutes must be validated and bounded before `core-context.ts`
// ever hands them to `AutoLockTimer` — a corrupted profile or a future bug could leave
// `storage.local` holding anything, not only what the options page itself ever wrote.
describe("clampAutoLockMinutes", () => {
  it("falls back to the 15-minute default for a missing/non-number/NaN value", () => {
    expect(clampAutoLockMinutes(undefined)).toBe(15);
    expect(clampAutoLockMinutes(null)).toBe(15);
    expect(clampAutoLockMinutes("30")).toBe(15);
    expect(clampAutoLockMinutes(Number.NaN)).toBe(15);
    expect(clampAutoLockMinutes(Number.POSITIVE_INFINITY)).toBe(15);
  });

  it("passes an in-range integer through unchanged", () => {
    expect(clampAutoLockMinutes(1)).toBe(1);
    expect(clampAutoLockMinutes(30)).toBe(30);
    expect(clampAutoLockMinutes(180)).toBe(180);
  });

  it("clamps below MIN_AUTO_LOCK_MINUTES, including zero and negative values", () => {
    expect(clampAutoLockMinutes(0)).toBe(MIN_AUTO_LOCK_MINUTES);
    expect(clampAutoLockMinutes(-5)).toBe(MIN_AUTO_LOCK_MINUTES);
  });

  it("clamps above MAX_AUTO_LOCK_MINUTES, including an overflow value", () => {
    expect(clampAutoLockMinutes(181)).toBe(MAX_AUTO_LOCK_MINUTES);
    expect(clampAutoLockMinutes(1e9)).toBe(MAX_AUTO_LOCK_MINUTES);
  });

  it("rounds a fractional value to the nearest whole minute", () => {
    expect(clampAutoLockMinutes(2.4)).toBe(2);
    expect(clampAutoLockMinutes(2.6)).toBe(3);
  });
});

function fakeExtWithStorage(stored: Record<string, unknown>): Pick<WebExtNamespace, "storage"> {
  return {
    storage: {
      local: {
        get: async (keys) => {
          if (keys === undefined || keys === null) {
            return stored;
          }
          const out: Record<string, unknown> = {};
          for (const k of Array.isArray(keys) ? keys : [keys]) {
            if (k in stored) {
              out[k] = stored[k];
            }
          }
          return out;
        },
        set: async () => undefined,
        remove: async () => undefined,
        clear: async () => undefined,
      },
      session: {
        get: async () => ({}),
        set: async () => undefined,
        remove: async () => undefined,
        clear: async () => undefined,
      },
    },
  };
}

describe("readAutoLockMs", () => {
  it("reads and clamps the stored minutes, returned as milliseconds", async () => {
    const ext = fakeExtWithStorage({ [AUTO_LOCK_MINUTES_STORAGE_KEY]: 30 }) as WebExtNamespace;
    expect(await readAutoLockMs(ext)).toBe(30 * 60_000);
  });

  it("defaults to 15 minutes when nothing is stored", async () => {
    const ext = fakeExtWithStorage({}) as WebExtNamespace;
    expect(await readAutoLockMs(ext)).toBe(DEFAULT_AUTO_LOCK_MS);
  });

  it("clamps an out-of-range stored value instead of defaulting", async () => {
    const ext = fakeExtWithStorage({ [AUTO_LOCK_MINUTES_STORAGE_KEY]: 999 }) as WebExtNamespace;
    expect(await readAutoLockMs(ext)).toBe(MAX_AUTO_LOCK_MINUTES * 60_000);
  });
});
