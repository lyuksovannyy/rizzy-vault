// `content/menu-visibility.ts`'s pure functions, no DOM (this workspace's `vitest`
// `environment: "node"` has none) — same pattern as `decide-click.test.ts` and
// `own-overlay-mutation.test.ts`. A7/THREAT_MODEL.md gap, HANDOFF X6.
import { describe, expect, it } from "vitest";

import {
  DEFAULT_MENU_VISIBILITY_WINDOW_MS,
  computeExpectedRect,
  initMenuVisibilityState,
  isChainNodeOk,
  isFillAllowed,
  isPointHitOk,
  isTopLayerClear,
  isVisibilityChainOk,
  recordSample,
  rectsMatch,
  type ChainStyleSample,
  type MenuVisibilityState,
} from "../src/content/menu-visibility.ts";

/** A chain-node sample with every property at its neutral/default value — the baseline every
 * test below mutates one property of at a time. */
function okSample(): ChainStyleSample {
  return {
    opacity: 1,
    visibility: "visible",
    display: "block",
    filter: "none",
    clipPath: "none",
    mask: "none",
    mixBlendMode: "normal",
    contentVisibility: "visible",
  };
}

describe("rectsMatch", () => {
  const expected = { left: 10, top: 20, width: 240, height: 220 };

  it("matches an identical rect", () => {
    expect(rectsMatch({ left: 10, top: 20, width: 240, height: 220 }, expected)).toBe(true);
  });

  it("matches within the default 1px tolerance", () => {
    expect(rectsMatch({ left: 10.6, top: 19.4, width: 240.9, height: 219.1 }, expected)).toBe(true);
  });

  it("fails outside the tolerance on left/top (an ancestor transform displacing the frame)", () => {
    expect(rectsMatch({ left: 12, top: 20, width: 240, height: 220 }, expected)).toBe(false);
    expect(rectsMatch({ left: 10, top: 22, width: 240, height: 220 }, expected)).toBe(false);
  });

  it("fails on a shrunk size (a forced !important width/height)", () => {
    expect(rectsMatch({ left: 10, top: 20, width: 1, height: 1 }, expected)).toBe(false);
  });

  it("respects a caller-supplied tolerance", () => {
    expect(rectsMatch({ left: 15, top: 20, width: 240, height: 220 }, expected, 10)).toBe(true);
  });
});

describe("computeExpectedRect", () => {
  const viewport = { width: 1000, height: 800 };
  const menuSize = { width: 240, height: 220 };

  it("places the menu directly below the anchor when there is room", () => {
    const rect = computeExpectedRect({ left: 50, top: 100, width: 150, height: 20 }, viewport, menuSize);
    expect(rect).toEqual({ left: 50, top: 120, width: 240, height: 220 });
  });

  it("flips above the anchor when there is no room below", () => {
    // Anchor near the bottom: below (top+height=770+20=790) + menuHeight(220) = 1010 > 800.
    const rect = computeExpectedRect({ left: 50, top: 770, width: 150, height: 20 }, viewport, menuSize);
    expect(rect.top).toBe(770 - 220);
  });

  it("clamps left so the fixed-width box never extends past the right edge", () => {
    const rect = computeExpectedRect({ left: 900, top: 100, width: 150, height: 20 }, viewport, menuSize);
    expect(rect.left).toBe(viewport.width - menuSize.width);
  });

  it("clamps top into the viewport even when neither placement fully fits (a tiny viewport)", () => {
    const tinyViewport = { width: 300, height: 150 };
    const rect = computeExpectedRect({ left: 10, top: 100, width: 50, height: 20 }, tinyViewport, menuSize);
    expect(rect.top).toBeGreaterThanOrEqual(0);
    expect(rect.top).toBeLessThanOrEqual(Math.max(0, tinyViewport.height - menuSize.height));
  });

  it("is a pure function of its inputs, not of any later anchor movement (frozen-at-construction contract)", () => {
    const anchor = { left: 50, top: 100, width: 150, height: 20 };
    const first = computeExpectedRect(anchor, viewport, menuSize);
    anchor.left = 999; // a caller that kept re-reading `anchor` after this would see a different rect
    const second = computeExpectedRect({ left: 50, top: 100, width: 150, height: 20 }, viewport, menuSize);
    expect(second).toEqual(first);
  });
});

describe("isChainNodeOk / isVisibilityChainOk", () => {
  it("passes a fully neutral node", () => {
    expect(isChainNodeOk(okSample())).toBe(true);
  });

  it("fails on reduced opacity (the fixme reproducer's own attack: opacity: 0)", () => {
    expect(isChainNodeOk({ ...okSample(), opacity: 0 })).toBe(false);
  });

  it("tolerates opacity within the ~0.01 tolerance", () => {
    expect(isChainNodeOk({ ...okSample(), opacity: 0.995 })).toBe(true);
  });

  it("fails on visibility: hidden", () => {
    expect(isChainNodeOk({ ...okSample(), visibility: "hidden" })).toBe(false);
  });

  it("fails on display: none", () => {
    expect(isChainNodeOk({ ...okSample(), display: "none" })).toBe(false);
  });

  it("fails on a non-none filter", () => {
    expect(isChainNodeOk({ ...okSample(), filter: "opacity(0)" })).toBe(false);
  });

  it("fails on a non-none clip-path", () => {
    expect(isChainNodeOk({ ...okSample(), clipPath: "circle(0px)" })).toBe(false);
  });

  it("fails on a non-none mask", () => {
    expect(isChainNodeOk({ ...okSample(), mask: "url(#m)" })).toBe(false);
  });

  it("fails on a non-normal mix-blend-mode", () => {
    expect(isChainNodeOk({ ...okSample(), mixBlendMode: "multiply" })).toBe(false);
  });

  it("fails on content-visibility: hidden", () => {
    expect(isChainNodeOk({ ...okSample(), contentVisibility: "hidden" })).toBe(false);
  });

  it("isVisibilityChainOk passes an all-ok chain ({frame, body, documentElement})", () => {
    expect(isVisibilityChainOk([okSample(), okSample(), okSample()])).toBe(true);
  });

  it("isVisibilityChainOk fails if ANY single node in the chain is bad — even deep in the chain", () => {
    expect(isVisibilityChainOk([okSample(), okSample(), { ...okSample(), opacity: 0 }])).toBe(false);
  });

  it("isVisibilityChainOk passes vacuously on an empty chain (should never happen in practice)", () => {
    expect(isVisibilityChainOk([])).toBe(true);
  });
});

describe("isTopLayerClear", () => {
  const expected = { left: 100, top: 100, width: 240, height: 220 };

  it("is clear with no top-layer elements at all", () => {
    expect(isTopLayerClear(expected, [])).toBe(true);
  });

  it("is clear when a top-layer rect does not intersect the menu", () => {
    expect(isTopLayerClear(expected, [{ left: 0, top: 0, width: 10, height: 10 }])).toBe(true);
  });

  it("is NOT clear when a <dialog>/fullscreen/popover rect covers the menu (a top-layer element renders above any z-index)", () => {
    expect(isTopLayerClear(expected, [{ left: 0, top: 0, width: 2000, height: 2000 }])).toBe(false);
  });

  it("is not clear on a partial overlap", () => {
    expect(isTopLayerClear(expected, [{ left: 150, top: 150, width: 50, height: 50 }])).toBe(false);
  });
});

describe("isPointHitOk", () => {
  it("is ok only when the point hits the frame itself", () => {
    expect(isPointHitOk("frame")).toBe(true);
  });

  it("is not ok when another element is on top", () => {
    expect(isPointHitOk("other")).toBe(false);
  });

  // The documented inversion of the target field's own `isTopmost` convention: `null` passes
  // there (routine "below the fold"), but is a BAD sample here, because the menu is clamped
  // into the viewport by construction.
  it("treats 'none' (elementFromPoint returned null) as a BAD sample, unlike the field-level check", () => {
    expect(isPointHitOk("none")).toBe(false);
  });
});

describe("Gate B: initMenuVisibilityState / recordSample / isFillAllowed", () => {
  it("starts with neither timestamp set", () => {
    expect(initMenuVisibilityState()).toEqual({ lastBadSampleAt: undefined, lastGoodSampleAt: undefined });
  });

  it("refuses before any sample has ever been recorded", () => {
    expect(isFillAllowed(initMenuVisibilityState(), 0)).toBe(false);
  });

  it("happy path: continuous good samples allow a fill", () => {
    let state = initMenuVisibilityState();
    state = recordSample(state, 10, true);
    state = recordSample(state, 20, true);
    state = recordSample(state, 30, true);
    expect(isFillAllowed(state, 40)).toBe(true);
  });

  it("permanently bad: a menu that never once samples good is never allowed, however much time passes", () => {
    let state = initMenuVisibilityState();
    state = recordSample(state, 10, false);
    state = recordSample(state, 20, false);
    state = recordSample(state, 30, false);
    expect(isFillAllowed(state, 1_000_000)).toBe(false);
  });

  it("a single good sample with no bad sample ever recorded allows a fill almost immediately (no startup dwell)", () => {
    let state = initMenuVisibilityState();
    state = recordSample(state, 1, true);
    expect(isFillAllowed(state, 2, DEFAULT_MENU_VISIBILITY_WINDOW_MS)).toBe(true);
  });

  it("the flip-attack timing case: hidden, briefly visible, hidden again — refused shortly after the re-hide, even though a good sample did occur", () => {
    let state = initMenuVisibilityState();
    // Hidden from t=0: continuous bad samples.
    for (let t = 0; t <= 100; t += 10) {
      state = recordSample(state, t, false);
    }
    // Attacker flips visible for the click window.
    state = recordSample(state, 110, true);
    state = recordSample(state, 120, true);
    // Attacker flips back to hidden immediately after, to keep deceiving the user.
    state = recordSample(state, 130, false);
    state = recordSample(state, 140, false);
    // apply_fill arrives shortly after the re-hide — well within the window of the last bad
    // sample (140), regardless of how short the earlier visible flip was.
    expect(isFillAllowed(state, 300, DEFAULT_MENU_VISIBILITY_WINDOW_MS)).toBe(false);
  });

  it("bad once, then recovered well outside the window: allowed again (the window self-heals, unlike an unbounded 'ever bad' flag)", () => {
    let state = initMenuVisibilityState();
    state = recordSample(state, 0, false); // one transient bad sample (e.g. a benign load-time hiccup)
    state = recordSample(state, 50, true);
    // `now` is far past `windowMs` since the one bad sample at t=0.
    expect(isFillAllowed(state, 0 + DEFAULT_MENU_VISIBILITY_WINDOW_MS + 1, DEFAULT_MENU_VISIBILITY_WINDOW_MS)).toBe(true);
  });

  it("refuses right at the window boundary and allows just past it", () => {
    const state: MenuVisibilityState = { lastBadSampleAt: 1000, lastGoodSampleAt: 1000 };
    expect(isFillAllowed(state, 1000 + DEFAULT_MENU_VISIBILITY_WINDOW_MS - 1, DEFAULT_MENU_VISIBILITY_WINDOW_MS)).toBe(false);
    expect(isFillAllowed(state, 1000 + DEFAULT_MENU_VISIBILITY_WINDOW_MS, DEFAULT_MENU_VISIBILITY_WINDOW_MS)).toBe(true);
  });

  it("recordSample never mutates its input state (pure)", () => {
    const before = initMenuVisibilityState();
    const snapshot = { ...before };
    recordSample(before, 5, true);
    expect(before).toEqual(snapshot);
  });

  // Adversarial-report finding (not yet owner-dated): a sampler that STOPS TICKING ENTIRELY
  // (e.g. a main-thread stall covering Gate A's own `requestAnimationFrame` loop) never calls
  // `recordSample` at all, so `lastBadSampleAt` can stay `undefined` even while the frame is
  // actually hidden the whole time — the pre-existing trailing-bad-sample check alone had no way
  // to tell that apart from "never been bad, still fine." `isFillAllowed` now also requires
  // `lastGoodSampleAt` itself to be within the trailing window.
  it("refuses once the last good sample is stale, even with no bad sample ever recorded (a stalled sampler, not merely an untouched one)", () => {
    let state = initMenuVisibilityState();
    state = recordSample(state, 0, true); // one real good tick, then the sampler never ticks again
    expect(isFillAllowed(state, DEFAULT_MENU_VISIBILITY_WINDOW_MS + 1, DEFAULT_MENU_VISIBILITY_WINDOW_MS)).toBe(false);
  });

  it("still allows right at the good-sample freshness boundary", () => {
    let state = initMenuVisibilityState();
    state = recordSample(state, 0, true);
    expect(isFillAllowed(state, DEFAULT_MENU_VISIBILITY_WINDOW_MS, DEFAULT_MENU_VISIBILITY_WINDOW_MS)).toBe(true);
  });

  it("a later bad sample cannot make a stale-good state pass again (freshness is checked independently of the bad-sample window)", () => {
    const state: MenuVisibilityState = { lastGoodSampleAt: 0, lastBadSampleAt: 0 };
    // The bad sample is itself old enough to pass its own window, but the good sample is EVEN
    // staler — both conditions must hold.
    expect(isFillAllowed(state, DEFAULT_MENU_VISIBILITY_WINDOW_MS + 1, DEFAULT_MENU_VISIBILITY_WINDOW_MS)).toBe(false);
  });
});
