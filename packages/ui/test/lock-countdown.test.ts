// SPDX-License-Identifier: AGPL-3.0-only

// The turn-off dialog's countdown (ADR 0110 §2 point 3; `lockCountdown.ts`): "(5)" at 0 ms, "(1)"
// up to the last millisecond, ready at exactly 5 000 ms. The
// dialog's DOM behaviour (aria-disabled, ignored activation, focus, live region) is exercised by
// the web vault's Playwright spec `lock-settings.spec.ts`.
import { describe, expect, it } from "vitest";

import { countdown } from "../src/lockCountdown.ts";

describe("countdown", () => {
  it("counts whole seconds down and is ready at exactly the delay", () => {
    expect(countdown(0, 5_000)).toEqual({ ready: false, seconds: 5 });
    expect(countdown(999, 5_000)).toEqual({ ready: false, seconds: 5 });
    expect(countdown(1_000, 5_000)).toEqual({ ready: false, seconds: 4 });
    expect(countdown(4_000, 5_000)).toEqual({ ready: false, seconds: 1 });
    expect(countdown(4_500, 5_000)).toEqual({ ready: false, seconds: 1 });
    expect(countdown(4_999.9, 5_000)).toEqual({ ready: false, seconds: 1 });
    expect(countdown(5_000, 5_000)).toEqual({ ready: true, seconds: 0 });
    expect(countdown(60_000, 5_000)).toEqual({ ready: true, seconds: 0 });
  });

  it("counts a clock that went back, or a broken reading, as no time passed", () => {
    expect(countdown(-10_000, 5_000)).toEqual({ ready: false, seconds: 5 });
    expect(countdown(Number.NaN, 5_000)).toEqual({ ready: false, seconds: 5 });
    expect(countdown(Number.POSITIVE_INFINITY, 5_000)).toEqual({ ready: false, seconds: 5 });
  });
});
