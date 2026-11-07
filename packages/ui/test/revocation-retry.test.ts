// SPDX-License-Identifier: AGPL-3.0-only

// `RevocationRetry` (`src/RevocationPendingBanner.tsx`, ADR 0091 §2): the banner shows from the
// first `revocation_pending` refusal, one retry waits at a time, at the core's time, the count
// it passes back grows by one per retry and starts over after a sync that succeeded, and the end
// of the core's schedule (or a lock) takes the banner and the timer away.
import { describe, expect, it } from "vitest";

import { RevocationRetry, type RevocationTimers } from "../src/RevocationPendingBanner.tsx";

/** Timers the test fires by hand. */
function manualTimers() {
  const waiting = new Map<number, { f: () => void; ms: number }>();
  let next = 0;
  const timers: RevocationTimers = {
    set: (f, ms) => {
      next += 1;
      waiting.set(next, { f, ms });
      return next;
    },
    clear: (h) => {
      waiting.delete(h as number);
    },
  };
  /** Fires the one waiting timer; returns its delay. */
  const fire = (): number => {
    const [[id, t]] = [...waiting.entries()] as [[number, { f: () => void; ms: number }]];
    waiting.delete(id);
    t.f();
    return t.ms;
  };
  return { timers, waiting, fire };
}

describe("RevocationRetry", () => {
  it("shows the banner, waits for the core's time, and counts the retries", () => {
    const { timers, waiting, fire } = manualTimers();
    const changes: boolean[] = [];
    const r = new RevocationRetry((p) => changes.push(p), timers);
    let retried = 0;
    const retry = () => {
      retried += 1;
    };

    expect(r.retriesDone).toBe(0);
    expect(r.refused(1_015_000, 1_000_000, retry)).toBe(true);
    expect(r.paused).toBe(true);
    expect(changes).toEqual([true]);
    expect(r.retriesDone).toBe(1);
    expect(waiting.size).toBe(1);

    // A second refusal while the retry waits (a sync after a write) schedules nothing more.
    expect(r.refused(2_000_000, 1_001_000, retry)).toBe(true);
    expect(r.retriesDone).toBe(1);
    expect(waiting.size).toBe(1);

    expect(fire()).toBe(15_000);
    expect(retried).toBe(1);
    expect(r.scheduled).toBe(false);
    expect(r.paused).toBe(true);

    // The retry was refused again: the next one, counted.
    expect(r.refused(1_030_000, 1_015_000, retry)).toBe(true);
    expect(r.retriesDone).toBe(2);
    expect(fire()).toBe(15_000);
    expect(retried).toBe(2);

    // A late timer never fires early: a time in the past waits zero.
    expect(r.refused(1_000, 1_030_000, retry)).toBe(true);
    expect(fire()).toBe(0);
    expect(changes).toEqual([true]);
  });

  it("stops when the core's schedule ends, and starts over after a sync", () => {
    const { timers, waiting, fire } = manualTimers();
    const changes: boolean[] = [];
    const r = new RevocationRetry((p) => changes.push(p), timers);
    const retry = () => undefined;

    r.refused(15_000, 0, retry);
    // The sync succeeded: no timer, no banner, the count starts over.
    r.ended();
    expect(waiting.size).toBe(0);
    expect(r.paused).toBe(false);
    expect(r.retriesDone).toBe(0);
    expect(changes).toEqual([true, false]);

    expect(r.refused(15_000, 0, retry)).toBe(true);
    expect(r.retriesDone).toBe(1);
    // The timer fired and the retry was refused again, past the schedule: stop and report.
    fire();
    expect(r.refused(undefined, 15_000, retry)).toBe(false);
    expect(r.paused).toBe(false);
    expect(r.retriesDone).toBe(0);
    expect(waiting.size).toBe(0);
    expect(changes).toEqual([true, false, true, false]);
  });

  it("drops a fired timer that a lock already cancelled", () => {
    const { timers, waiting } = manualTimers();
    const r = new RevocationRetry(() => undefined, timers);
    let retried = 0;
    r.refused(15_000, 0, () => {
      retried += 1;
    });
    const [t] = [...waiting.values()];
    r.ended();
    t?.f();
    expect(retried).toBe(0);
  });
});
