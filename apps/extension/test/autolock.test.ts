// SPDX-License-Identifier: AGPL-3.0-only

// The extension's lock controller (`src/core-host/lifecycle.ts`; ADR 0110 §3–§4, ADR 0111 §3 and
// §7 step 4) with a fake clock and the real Rust `LockTimer` from packages/core: the poll runs
// only while unlocked with locking on, an `idle` or `locked` answer locks as the table allows, a
// malformed answer or a rejected send does not, a new idle time re-checks the deadline, the
// master switch off stops everything, and a broken record reads as the defaults. The migration
// of `rizzy.auto_lock_minutes` is Rust's (packages/core's `lockSettingsFromLegacyMinutes`),
// checked here for the plan's cases (ADR 0110 plan step 3: 3 → 2, 180 → 60, 0 → 1, absent →
// defaults).
import { readFileSync } from "node:fs";

import { beforeAll, describe, expect, it } from "vitest";

import {
  type ClockReading,
  DEFAULT_LOCK_SETTINGS,
  type LockSettings,
  LockTimer,
  initFromBytes,
  lockSettingsFromLegacyMinutes,
  parseLockSettings,
} from "@rizzy-vault/core";

import { IDLE_POLL_MS, LockController, SLEEP_TICK_MS, idleIntervalSeconds } from "../src/core-host/lifecycle.ts";
import { idleDetectionSeconds, idleStatusAnswerOf } from "../src/messaging/lock-messages.ts";

beforeAll(() => {
  initFromBytes(readFileSync(new URL("../../../packages/core/generated/rizzy_core_bg.wasm", import.meta.url)));
});

const record = (s: Partial<{ auto_lock: boolean; idle_minutes: number; lock_on_sleep: boolean }>) =>
  JSON.stringify({ v: 1, auto_lock: true, idle_minutes: 5, lock_on_restart: true, lock_on_sleep: true, ...s });

/** A clock whose intervals fire only when the test advances it. */
class FakeClock {
  mono = 1_000_000;
  wall = 1_800_000_000_000;
  #next = 1;
  intervals = new Map<number, { f: () => void; ms: number; due: number }>();

  now = (): ClockReading => ({ monotonicMs: this.mono, wallMs: this.wall });
  setInterval = (f: () => void, ms: number): unknown => {
    const id = this.#next++;
    this.intervals.set(id, { f, ms, due: this.mono + ms });
    return id;
  };
  clearInterval = (h: unknown): void => {
    this.intervals.delete(h as number);
  };

  /** Advances both clocks by `ms`, firing each due interval in time order. */
  async advance(ms: number): Promise<void> {
    const end = this.mono + ms;
    for (;;) {
      let first: [number, { f: () => void; ms: number; due: number }] | undefined;
      for (const e of this.intervals) {
        if (e[1].due <= end && (first === undefined || e[1].due < first[1].due)) {
          first = e;
        }
      }
      if (first === undefined) {
        break;
      }
      this.wall += first[1].due - this.mono;
      this.mono = first[1].due;
      first[1].due += first[1].ms;
      first[1].f();
      await flush();
    }
    this.wall += end - this.mono;
    this.mono = end;
    await flush();
  }
}

async function flush(): Promise<void> {
  for (let i = 0; i < 5; i++) {
    await Promise.resolve();
  }
}

interface Setup {
  clock: FakeClock;
  controller: LockController;
  locks: string[];
  queries: number;
  answer: () => Promise<unknown>;
}

function setup(settings: LockSettings = DEFAULT_LOCK_SETTINGS, poll = true): Setup {
  const clock = new FakeClock();
  const s: Setup = {
    clock,
    locks: [],
    queries: 0,
    answer: async () => ({ type: "idle_status", state: "active", settings: null }),
    controller: undefined as unknown as LockController,
  };
  s.controller = new LockController(
    {
      now: clock.now,
      setInterval: clock.setInterval,
      clearInterval: clock.clearInterval,
      newTimer: (st, now) => new LockTimer(st, now),
      lock: (reason) => {
        s.locks.push(reason);
        s.controller.locked();
      },
      ...(poll
        ? {
            queryIdleStatus: () => {
              s.queries += 1;
              return s.answer();
            },
            settingsOfAnswer: (a: unknown) => {
              const ok = idleStatusAnswerOf(a);
              return ok === undefined ? undefined : parseLockSettings(ok.settings);
            },
            stateOfAnswer: (a: unknown) => idleStatusAnswerOf(a)?.state,
          }
        : {}),
    },
    settings,
  );
  return s;
}

describe("the Chromium poll (ADR 0111 §3.1 item 3)", () => {
  it("does not poll while locked, polls every IDLE_POLL_MS once unlocked, and stops on lock", async () => {
    const s = setup();
    await s.clock.advance(3 * IDLE_POLL_MS);
    expect(s.queries).toBe(0);
    s.answer = async () => ({ type: "idle_status", state: "active", settings: record({}) });
    s.controller.unlocked();
    await flush();
    expect(s.queries).toBe(1); // the settings-only query on unlock
    await s.clock.advance(IDLE_POLL_MS);
    expect(s.queries).toBe(2);
    await s.clock.advance(IDLE_POLL_MS);
    expect(s.queries).toBe(3);
    expect(s.locks).toEqual([]);
    s.controller.locked();
    await s.clock.advance(5 * IDLE_POLL_MS);
    expect(s.queries).toBe(3);
    expect(s.controller.polling).toBe(false);
  });

  it("locks on an idle or locked answer, not on active, a malformed answer or a rejected send", async () => {
    for (const [answer, locks] of [
      [{ type: "idle_status", state: "idle", settings: null }, ["os_idle"]],
      [{ type: "idle_status", state: "locked", settings: null }, ["os_locked"]],
      [{ type: "idle_status", state: "active", settings: null }, []],
      [{ type: "idle_status", state: "IDLE", settings: null }, []],
      [{ type: "idle_status", state: "idle", settings: 7 }, []],
      [{ type: "idle_status", settings: null }, []],
      ["idle", []],
      [undefined, []],
    ] as const) {
      const s = setup();
      s.controller.unlocked();
      await flush();
      s.answer = async () => answer;
      await s.clock.advance(IDLE_POLL_MS);
      expect(s.locks, JSON.stringify(answer)).toEqual(locks);
    }
    const rejected = setup();
    rejected.controller.unlocked();
    rejected.answer = () => Promise.reject(new Error("no receiver"));
    await rejected.clock.advance(IDLE_POLL_MS * 2);
    expect(rejected.locks).toEqual([]);
    expect(rejected.controller.running).toBe(true);
  });

  it("with lock_on_sleep off, idle locks but locked and a 120 s clock gap do not", async () => {
    const off = parseLockSettings(record({ lock_on_sleep: false }));
    const s = setup(off);
    s.answer = async () => ({ type: "idle_status", state: "locked", settings: record({ lock_on_sleep: false }) });
    s.controller.unlocked();
    await s.clock.advance(IDLE_POLL_MS);
    s.clock.wall += 120_000;
    await s.clock.advance(SLEEP_TICK_MS);
    expect(s.locks).toEqual([]);
    s.answer = async () => ({ type: "idle_status", state: "idle", settings: record({ lock_on_sleep: false }) });
    await s.clock.advance(IDLE_POLL_MS);
    expect(s.locks).toEqual(["os_idle"]);
  });

  it("with locking off: no poll, no tick, and neither idle, locked nor a clock gap locks", async () => {
    const off = parseLockSettings(record({ auto_lock: false }));
    const s = setup(off);
    s.answer = async () => ({ type: "idle_status", state: "idle", settings: record({ auto_lock: false }) });
    s.controller.unlocked();
    await flush();
    expect(s.queries).toBe(1); // settings only, so turning locking on is learned
    expect(s.clock.intervals.size).toBe(0);
    s.controller.idleState("idle");
    s.controller.idleState("locked");
    s.clock.wall += 120_000;
    await s.clock.advance(60 * 60_000);
    expect(s.locks).toEqual([]);
    expect(s.queries).toBe(1);
  });

  it("a broken settings text applies the defaults", async () => {
    const s = setup(parseLockSettings(record({ auto_lock: false })));
    s.answer = async () => ({ type: "idle_status", state: "active", settings: '{"v":2}' });
    s.controller.unlocked();
    await flush();
    expect(s.controller.settings).toEqual(DEFAULT_LOCK_SETTINGS);
    expect(s.controller.polling).toBe(true);
  });
});

describe("the activity deadline and settings changes (ADR 0110 §4.3, ADR 0111 §3)", () => {
  it("locks after idle_minutes without activity, by one tick, and activity defers it", async () => {
    const s = setup(parseLockSettings(record({ idle_minutes: 1 })), false);
    s.controller.unlocked();
    await s.clock.advance(50_000);
    s.controller.activity();
    await s.clock.advance(55_000);
    expect(s.locks).toEqual([]);
    await s.clock.advance(5_000 + SLEEP_TICK_MS);
    expect(s.locks).toEqual(["idle"]);
  });

  it("a new idle_minutes re-checks the deadline at once", async () => {
    const s = setup(parseLockSettings(record({ idle_minutes: 10 })), false);
    s.controller.unlocked();
    await s.clock.advance(3 * 60_000);
    expect(s.locks).toEqual([]);
    s.controller.applySettings(parseLockSettings(record({ idle_minutes: 2 })));
    expect(s.locks).toEqual(["idle"]);
  });

  it("turning locking on again re-checks the deadline; off stops the tick", async () => {
    const s = setup(parseLockSettings(record({ auto_lock: false, idle_minutes: 1 })), false);
    s.controller.unlocked();
    await s.clock.advance(5 * 60_000);
    expect(s.locks).toEqual([]);
    s.controller.applySettings(parseLockSettings(record({ idle_minutes: 1 })));
    expect(s.locks).toEqual(["idle"]);
  });

  it("a 120 s forward wall-clock jump locks with sleep on (the suspend check)", async () => {
    const s = setup(DEFAULT_LOCK_SETTINGS, false);
    s.controller.unlocked();
    await s.clock.advance(SLEEP_TICK_MS);
    s.clock.wall += 120_000;
    await s.clock.advance(SLEEP_TICK_MS);
    expect(s.locks).toEqual(["sleep"]);
  });

  it("Firefox (no poll channel): the event is applied by the same table", () => {
    const s = setup(DEFAULT_LOCK_SETTINGS, false);
    s.controller.idleState("idle"); // locked: nothing to lock
    expect(s.locks).toEqual([]);
    s.controller.unlocked();
    s.controller.idleState("active");
    expect(s.locks).toEqual([]);
    s.controller.idleState("locked");
    expect(s.locks).toEqual(["os_locked"]);
    expect(idleIntervalSeconds(parseLockSettings(record({ idle_minutes: 10 })))).toBe(600);
  });
});

describe("the record outside Rust (service worker) and the migration", () => {
  it("idleDetectionSeconds reads idle_minutes * 60 of a well-formed record, else 300", () => {
    expect(idleDetectionSeconds(record({ idle_minutes: 240 }))).toBe(14_400);
    expect(idleDetectionSeconds(record({ idle_minutes: 1 }))).toBe(60);
    for (const bad of [
      null,
      undefined,
      "",
      "[]",
      "null",
      '{"v":2,"auto_lock":true,"idle_minutes":60,"lock_on_restart":true,"lock_on_sleep":true}',
      record({ idle_minutes: 3 }),
      record({ auto_lock: "no" as unknown as boolean }),
      record({ idle_minutes: 60 }).padEnd(257, " "),
      '{"v":1,"auto_lock":true,"idle_minutes":60,"lock_on_sleep":true}',
    ]) {
      expect(idleDetectionSeconds(bad), String(bad)).toBe(300);
      // Never longer than Rust's reading of the same text.
      expect(idleDetectionSeconds(bad)).toBe(parseLockSettings(bad).idleMinutes * 60);
    }
  });

  it("migrates rizzy.auto_lock_minutes as ADR 0110 §3 point 5 says", () => {
    const idle = (v: unknown) => lockSettingsFromLegacyMinutes(v)?.idleMinutes;
    expect(idle(3)).toBe(2);
    expect(idle(180)).toBe(60);
    expect(idle(0)).toBe(1);
    expect(idle(15)).toBe(15);
    expect(lockSettingsFromLegacyMinutes(undefined)).toBeUndefined();
    expect(lockSettingsFromLegacyMinutes(2.5)).toBeUndefined();
    expect(lockSettingsFromLegacyMinutes(15)).toEqual({ ...DEFAULT_LOCK_SETTINGS, idleMinutes: 15 });
  });
});
