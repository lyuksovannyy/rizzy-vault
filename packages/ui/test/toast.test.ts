// `Toast.tsx`'s pure queue reducer (module docs there: no DOM in this workspace's Vitest).
import { describe, expect, it } from "vitest";

import { TOAST_DURATION_MS, toastReducer } from "../src/Toast.tsx";

describe("toastReducer", () => {
  it("add appends a toast to the end of the stack", () => {
    const s1 = toastReducer([], { type: "add", id: "1", kind: "success", message: "Saved" });
    expect(s1).toEqual([{ id: "1", kind: "success", message: "Saved" }]);
    const s2 = toastReducer(s1, { type: "add", id: "2", kind: "error", message: "Failed" });
    expect(s2.map((t) => t.id)).toEqual(["1", "2"]);
  });

  it("dismiss removes only the matching toast", () => {
    const s = [
      { id: "1", kind: "success" as const, message: "A" },
      { id: "2", kind: "error" as const, message: "B" },
    ];
    expect(toastReducer(s, { type: "dismiss", id: "1" })).toEqual([{ id: "2", kind: "error", message: "B" }]);
  });

  it("dismissing an id already gone is a no-op (module docs: it can race its own timer)", () => {
    const s = [{ id: "1", kind: "info" as const, message: "A" }];
    expect(toastReducer(s, { type: "dismiss", id: "nope" })).toEqual(s);
  });

  it("the original array is never mutated", () => {
    const s: ReturnType<typeof toastReducer> = [];
    const s1 = toastReducer(s, { type: "add", id: "1", kind: "info", message: "A" });
    expect(s).toEqual([]);
    expect(s1).not.toBe(s);
  });
});

describe("TOAST_DURATION_MS", () => {
  it("errors stay up at least as long as success/info (module docs: more likely to need re-reading)", () => {
    expect(TOAST_DURATION_MS.error).toBeGreaterThanOrEqual(TOAST_DURATION_MS.success);
    expect(TOAST_DURATION_MS.error).toBeGreaterThanOrEqual(TOAST_DURATION_MS.info);
  });

  it("every duration is positive", () => {
    for (const ms of Object.values(TOAST_DURATION_MS)) {
      expect(ms).toBeGreaterThan(0);
    }
  });
});
