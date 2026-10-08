// `decideClick` (`inline-menu/decide-click.ts`): the exact decision whose hardcoded-`true`
// regression (caught only by code review, not by a test, since nothing exercised it directly)
// is why this file exists at all. ADR 0037 §5.
import { describe, expect, it } from "vitest";

import { decideClick } from "../src/inline-menu/decide-click.ts";

describe("decideClick", () => {
  it("fills immediately for a candidate that never needed the warning", () => {
    expect(decideClick({ itemId: "item-1", needsWarning: false }, new Set())).toEqual({
      action: "fill",
      confirmedEquivalence: false,
    });
  });

  it("warns, not fills, on the first click of an equivalence-only candidate", () => {
    expect(decideClick({ itemId: "item-1", needsWarning: true }, new Set())).toEqual({ action: "warn" });
  });

  // The regression this file exists to catch: `confirmedEquivalence` must be `true` here,
  // never a value that got hardcoded independent of `needsWarning`.
  it("fills with confirmedEquivalence: true on the second click of an equivalence-only candidate", () => {
    expect(decideClick({ itemId: "item-1", needsWarning: true }, new Set(["item-1"]))).toEqual({
      action: "fill",
      confirmedEquivalence: true,
    });
  });

  it("warns again for a different equivalence-only candidate even if another one is already confirmed", () => {
    expect(decideClick({ itemId: "item-2", needsWarning: true }, new Set(["item-1"]))).toEqual({ action: "warn" });
  });

  it("never needs confirmedEquivalence: true for a candidate that never needed the warning, even if confirmed holds stale ids", () => {
    expect(decideClick({ itemId: "item-1", needsWarning: false }, new Set(["item-1"]))).toEqual({
      action: "fill",
      confirmedEquivalence: false,
    });
  });
});
