// SPDX-License-Identifier: AGPL-3.0-only

// `core/client.ts`'s `recoveryNotice` (ADR 0045): the popup's reading of the pending-recovery
// notice from a long-lived-context response. It feeds the banner only (INV-70); anything not of
// the notice's shape reads as no notice, and nothing throws.
import { describe, expect, it } from "vitest";

import { recoveryNotice } from "../src/core/client.ts";

describe("recoveryNotice", () => {
  it("reads a notice, with and without the last recovery", () => {
    expect(recoveryNotice({ openedAtMs: 1, availableAtMs: 2 })).toEqual({ openedAtMs: 1, availableAtMs: 2 });
    expect(recoveryNotice({ openedAtMs: 1, availableAtMs: 2, lastRecoveryAtMs: 0 })).toEqual({
      openedAtMs: 1,
      availableAtMs: 2,
      lastRecoveryAtMs: 0,
    });
  });

  it("reads anything else as no notice", () => {
    for (const value of [
      undefined,
      null,
      0,
      "notice",
      [],
      {},
      { openedAtMs: 1 },
      { availableAtMs: 2 },
      { openedAtMs: "1", availableAtMs: 2 },
      { openedAtMs: 1, availableAtMs: 2n },
      { openedAtMs: 1, availableAtMs: 2, lastRecoveryAtMs: "3" },
      { openedAtMs: 1, availableAtMs: 2, lastRecoveryAtMs: null },
    ]) {
      expect(recoveryNotice(value), JSON.stringify(value, (_k, v: unknown) => (typeof v === "bigint" ? String(v) : v))).toBeUndefined();
    }
  });

  it("never throws on random shapes", () => {
    let seed = 0x45;
    const next = (): number => {
      seed = (seed * 1_103_515_245 + 12_345) % 2_147_483_648;
      return seed;
    };
    const pick = (): unknown => {
      const choices: unknown[] = [undefined, null, 0, -1, Number.NaN, Number.MAX_VALUE, "", "x", true, [], {}];
      return choices[next() % choices.length];
    };
    for (let i = 0; i < 2_000; i++) {
      const value: Record<string, unknown> = {};
      for (const key of ["openedAtMs", "availableAtMs", "lastRecoveryAtMs", "extra"]) {
        if (next() % 3 !== 0) {
          value[key] = pick();
        }
      }
      const read = recoveryNotice(value);
      if (read !== undefined) {
        expect(typeof read.openedAtMs).toBe("number");
        expect(typeof read.availableAtMs).toBe("number");
      }
    }
  });
});
