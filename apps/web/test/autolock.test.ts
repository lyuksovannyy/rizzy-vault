// Auto-lock after inactivity (THREAT_MODEL §7.1 "I"); input restarts the timer.
import { afterEach, describe, expect, it, vi } from "vitest";

import { IDLE_LOCK_MS, watchIdle } from "../src/autolock.ts";

afterEach(() => {
  vi.useRealTimers();
});

describe("watchIdle", () => {
  it("locks after the idle time, and input restarts it", () => {
    vi.useFakeTimers();
    const target = new EventTarget();
    const onIdle = vi.fn();
    const stop = watchIdle(onIdle, 1000, target);
    vi.advanceTimersByTime(900);
    target.dispatchEvent(new Event("keydown"));
    vi.advanceTimersByTime(900);
    expect(onIdle).not.toHaveBeenCalled();
    vi.advanceTimersByTime(200);
    expect(onIdle).toHaveBeenCalledTimes(1);
    stop();
    vi.advanceTimersByTime(5000);
    expect(onIdle).toHaveBeenCalledTimes(1);
  });

  it("defaults to fifteen minutes", () => {
    expect(IDLE_LOCK_MS).toBe(15 * 60_000);
  });
});
