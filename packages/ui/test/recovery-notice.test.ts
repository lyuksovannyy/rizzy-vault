// SPDX-License-Identifier: AGPL-3.0-only

// `RecoveryNoticeBanner.tsx`'s text (ADR 0045; INV-70): what it says for a notice, including the
// values a lying server can put in one. The banner shows what it was given and never fails.
import { describe, expect, it } from "vitest";

import { noticeTime, recoveryNoticeText } from "../src/RecoveryNoticeBanner.tsx";

const T0 = 1_790_000_000_000;
const WAIT = 72 * 3_600_000;

describe("recoveryNoticeText", () => {
  it("says when it was requested, when it can complete, and how to cancel", () => {
    const text = recoveryNoticeText({ openedAtMs: T0, availableAtMs: T0 + WAIT }, T0 + 1);
    expect(text.title).toBe("Account recovery requested");
    expect(text.requested).toContain(noticeTime(T0));
    expect(text.when).toBe(`It can be completed from ${noticeTime(T0 + WAIT)}.`);
    expect(text.consequence).toContain("rv recovery cancel");
    expect(text.last).toBeUndefined();
    expect(text.advisory).toContain("not verified");
  });

  it("says when the wait is over, and the last recovery when the notice has one", () => {
    const text = recoveryNoticeText({ openedAtMs: T0, availableAtMs: T0 + WAIT, lastRecoveryAtMs: T0 - 5 }, T0 + WAIT);
    expect(text.when).toBe("Its waiting period is over: it can be completed now.");
    expect(text.last).toBe(`This account was last recovered on ${noticeTime(T0 - 5)}.`);
  });

  it("prints a forged notice's impossible times without failing", () => {
    expect(noticeTime(Number.MAX_SAFE_INTEGER)).toBe("an unknown time");
    expect(noticeTime(Number.NaN)).toBe("an unknown time");
    const text = recoveryNoticeText(
      { openedAtMs: Number.MAX_VALUE, availableAtMs: -1, lastRecoveryAtMs: Number.POSITIVE_INFINITY },
      0,
    );
    expect(text.requested).toContain("an unknown time");
    expect(text.when).toBe("Its waiting period is over: it can be completed now.");
    expect(text.last).toContain("an unknown time");
  });
});
