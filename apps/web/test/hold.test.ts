// The hold after the plaintext-export warning (owner decision 2026-10-05): a 10-second
// countdown, the confirm button disabled until it ends, and a new count when the dialog is
// shown again.
import { afterEach, describe, expect, it, vi } from "vitest";

import { confirmEnabled, secondsLeft, startCountdown } from "../src/hold.ts";

afterEach(() => {
  vi.useRealTimers();
});

describe("the plaintext-export hold", () => {
  it("keeps the confirm button disabled for the whole ten seconds", () => {
    vi.useFakeTimers();
    let left = -1;
    const stop = startCountdown(10_000, (s) => {
      left = s;
    });
    expect(left).toBe(10);
    expect(confirmEnabled(left, false)).toBe(false);
    vi.advanceTimersByTime(5_000);
    expect(left).toBe(5);
    expect(confirmEnabled(left, false)).toBe(false);
    vi.advanceTimersByTime(4_900);
    expect(left).toBe(1);
    expect(confirmEnabled(left, false)).toBe(false);
    vi.advanceTimersByTime(100);
    expect(left).toBe(0);
    expect(confirmEnabled(left, false)).toBe(true);
    // Not while an export runs.
    expect(confirmEnabled(left, true)).toBe(false);
    stop();
  });

  it("starts over when the dialog is shown again", () => {
    vi.useFakeTimers();
    let left = -1;
    let stop = startCountdown(10_000, (s) => {
      left = s;
    });
    vi.advanceTimersByTime(8_000);
    expect(left).toBe(2);
    // Closed: the count stops where it was.
    stop();
    vi.advanceTimersByTime(5_000);
    expect(left).toBe(2);
    // Opened again: ten seconds again.
    stop = startCountdown(10_000, (s) => {
      left = s;
    });
    expect(left).toBe(10);
    vi.advanceTimersByTime(9_999);
    expect(confirmEnabled(left, false)).toBe(false);
    vi.advanceTimersByTime(1);
    expect(confirmEnabled(left, false)).toBe(true);
    stop();
  });

  it("counts time the tab slept", () => {
    let now = 1_000_000;
    vi.useFakeTimers();
    let left = -1;
    const stop = startCountdown(
      10_000,
      (s) => {
        left = s;
      },
      () => now,
    );
    now += 60_000;
    vi.advanceTimersByTime(250);
    expect(left).toBe(0);
    stop();
  });

  it("rounds up to whole seconds", () => {
    expect(secondsLeft(10_000)).toBe(10);
    expect(secondsLeft(9_001)).toBe(10);
    expect(secondsLeft(1)).toBe(1);
    expect(secondsLeft(0)).toBe(0);
    expect(secondsLeft(-5)).toBe(0);
  });
});
