// SPDX-License-Identifier: AGPL-3.0-only

// The vault lock settings through packages/core (ADR 0110 §1–§4, §6 point 1): the record's
// parser and encoder, the migration, the bounding rule and the lock timer, all Rust's.
import { beforeAll, describe, expect, it } from "vitest";

import {
  CoreError,
  DEFAULT_LOCK_SETTINGS,
  LOCK_SETTINGS_LIMITS,
  LockTimer,
  encodeLockSettings,
  isLockPolicyBounding,
  lockSettingsFromLegacyMinutes,
  lockSettingsLimits,
  parseLockSettings,
} from "../src/index.js";
import { loadCore } from "./load.js";

beforeAll(() => {
  loadCore();
});

/** The code a call throws, or `undefined`. */
function codeOf(f: () => unknown): string | undefined {
  try {
    f();
    return undefined;
  } catch (e) {
    return e instanceof CoreError ? e.code : String(e);
  }
}

const DEFAULT_TEXT =
  '{"v":1,"auto_lock":true,"idle_minutes":5,"lock_on_restart":true,"lock_on_sleep":true}';

describe("lock settings", () => {
  it("the static constants match Rust's", () => {
    expect(lockSettingsLimits()).toEqual(LOCK_SETTINGS_LIMITS);
    expect(parseLockSettings(null)).toEqual(DEFAULT_LOCK_SETTINGS);
  });

  it("round-trips the default record byte for byte", () => {
    expect(encodeLockSettings(DEFAULT_LOCK_SETTINGS)).toBe(DEFAULT_TEXT);
    expect(parseLockSettings(DEFAULT_TEXT)).toEqual(DEFAULT_LOCK_SETTINGS);
  });

  it("reads a broken record as the defaults", () => {
    for (const bad of [
      undefined,
      "",
      "{",
      "[]",
      '{"v":2,"auto_lock":false,"idle_minutes":15,"lock_on_restart":true,"lock_on_sleep":false}',
      '{"v":1,"auto_lock":false,"idle_minutes":3,"lock_on_restart":true,"lock_on_sleep":false}',
      '{"v":1,"auto_lock":"no","idle_minutes":15,"lock_on_restart":true,"lock_on_sleep":false}',
      '{"v":1,"auto_lock":false,"idle_minutes":15,"lock_on_restart":true}',
      `{"v":1,"auto_lock":false,"idle_minutes":15,"lock_on_restart":true,"lock_on_sleep":false}                                                                                                                                                                          `,
    ]) {
      expect(parseLockSettings(bad)).toEqual(DEFAULT_LOCK_SETTINGS);
    }
    // 256 bytes still reads.
    const ok = '{"v":1,"auto_lock":false,"idle_minutes":15,"lock_on_restart":false,"lock_on_sleep":false}';
    expect(parseLockSettings(ok.padEnd(256, " "))).toEqual({
      autoLock: false,
      idleMinutes: 15,
      lockOnRestart: true,
      lockOnSleep: false,
    });
  });

  it("encodes every listed value and refuses any other", () => {
    for (const idleMinutes of LOCK_SETTINGS_LIMITS.idleMinutes) {
      const text = encodeLockSettings({ autoLock: false, idleMinutes, lockOnSleep: false });
      expect(parseLockSettings(text)).toEqual({
        autoLock: false,
        idleMinutes,
        lockOnRestart: true,
        lockOnSleep: false,
      });
    }
    for (const idleMinutes of [0, 3, 180, 1.5, -5, Number.NaN, 70_000]) {
      expect(codeOf(() => encodeLockSettings({ autoLock: true, idleMinutes, lockOnSleep: true }))).toBe(
        "invalid_input",
      );
    }
  });

  it("migrates the extension's minutes (3 → 2, 180 → 60, 0 → 1, 15 kept)", () => {
    const idle = (v: unknown) => lockSettingsFromLegacyMinutes(v)?.idleMinutes;
    expect(idle(3)).toBe(2);
    expect(idle(180)).toBe(60);
    expect(idle(0)).toBe(1);
    expect(idle(-4)).toBe(1);
    expect(idle(15)).toBe(15);
    expect(idle(1e12)).toBe(240);
    expect(idle("15")).toBeUndefined();
    expect(idle(2.5)).toBeUndefined();
    expect(idle(undefined)).toBeUndefined();
    expect(lockSettingsFromLegacyMinutes(15)).toEqual({
      autoLock: true,
      idleMinutes: 15,
      lockOnRestart: true,
      lockOnSleep: true,
    });
  });

  it("is bounding at 1, 2 and 5 minutes with a master-password unlock only", () => {
    for (const idleMinutes of LOCK_SETTINGS_LIMITS.idleMinutes) {
      const on = { autoLock: true, idleMinutes, lockOnSleep: false };
      expect(isLockPolicyBounding(on, true)).toBe(idleMinutes <= 5);
      expect(isLockPolicyBounding(on, false)).toBe(false);
      expect(isLockPolicyBounding({ ...on, autoLock: false }, true)).toBe(false);
    }
  });

  it("runs the lock timer on both clocks", () => {
    const wall = 1_800_000_000_000;
    const t = new LockTimer({ autoLock: true, idleMinutes: 1, lockOnSleep: true }, { monotonicMs: 0.4, wallMs: wall });
    expect(t.tick({ monotonicMs: 10_000.7, wallMs: wall + 10_000 })).toBeUndefined();
    expect(t.tick({ monotonicMs: 20_000, wallMs: wall + 140_000 })).toBe("sleep");
    t.input({ monotonicMs: 30_000, wallMs: wall + 150_000 });
    expect(t.tick({ monotonicMs: 89_999, wallMs: wall + 160_000 })).toBeUndefined();
    expect(t.tick({ monotonicMs: 90_000, wallMs: wall + 170_000 })).toBe("idle");
    expect(
      t.setSettings({ autoLock: false, idleMinutes: 1, lockOnSleep: true }, { monotonicMs: 95_000, wallMs: wall }),
    ).toBeUndefined();
    expect(codeOf(() => t.tick({ monotonicMs: Number.NaN, wallMs: wall }))).toBe("invalid_input");
    t.free();
    expect(codeOf(() => t.tick({ monotonicMs: 0, wallMs: wall }))).toBe("wrong_state");
  });
});
