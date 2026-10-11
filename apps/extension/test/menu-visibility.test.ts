// SPDX-License-Identifier: AGPL-3.0-only

// `content/menu-visibility.ts`'s pure functions, no DOM (this workspace's `vitest`
// `environment: "node"` has none) — same pattern as `decide-click.test.ts` and
// `own-overlay-mutation.test.ts`. A7/THREAT_MODEL.md gap, HANDOFF X6.
import { describe, expect, it } from "vitest";

import {
  DEFAULT_MENU_VISIBILITY_WINDOW_MS,
  MAX_Z_INDEX,
  computeExpectedRect,
  initMenuVisibilityState,
  isAllZeroLengths,
  isBackdropOccluding,
  isChainNodeOk,
  isFillAllowed,
  isFilterVisibilityPreserving,
  isPointHitOk,
  isTopLayerClear,
  isVisibilityChainOk,
  parseBoxShadowMarginPx,
  parseOutlineMarginPx,
  pseudoElementPaintsFixedOverlay,
  pseudoElementTiesMaxZIndex,
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
    isolation: "auto",
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

  // Sixth adversarial round: a stale `~0.01` "looks the same" tolerance had no relationship to
  // the BINARY question this check actually answers (did this node create a CSS stacking
  // context) — per spec, ANY opacity other than EXACTLY `1` creates one unconditionally, which a
  // reported bypass exploited (`body { opacity: 0.995 }` plus a low-z-index sibling-of-`<body>`
  // decoy; see the e2e test). `opacity` is now compared exactly.
  it("no longer tolerates a near-1, non-1 opacity (closed: this used to be a stacking-context escape)", () => {
    expect(isChainNodeOk({ ...okSample(), opacity: 0.995 })).toBe(false);
    expect(isChainNodeOk({ ...okSample(), opacity: 0.9999 })).toBe(false);
  });

  it("still passes at exactly opacity: 1 (no regression from the tolerance removal)", () => {
    expect(isChainNodeOk({ ...okSample(), opacity: 1 })).toBe(true);
  });

  // Sixth adversarial round: `isolation: isolate` creates a CSS stacking context with no other
  // side effect at all (unlike `filter`/`transform`/`contain`/`will-change`, it never changes
  // geometry or visible paint by itself) — a reported bypass exploited exactly this (`body {
  // isolation: isolate }` plus a low-z-index sibling-of-`<body>` decoy; see the e2e test).
  it("fails on isolation: isolate (closed: this used to be a stacking-context escape)", () => {
    expect(isChainNodeOk({ ...okSample(), isolation: "isolate" })).toBe(false);
  });

  it("passes on isolation: auto (the CSS default — no regression)", () => {
    expect(isChainNodeOk({ ...okSample(), isolation: "auto" })).toBe(true);
  });

  it("fails on visibility: hidden", () => {
    expect(isChainNodeOk({ ...okSample(), visibility: "hidden" })).toBe(false);
  });

  it("fails on display: none", () => {
    expect(isChainNodeOk({ ...okSample(), display: "none" })).toBe(false);
  });

  it("fails on a non-none, non-visibility-preserving filter", () => {
    expect(isChainNodeOk({ ...okSample(), filter: "opacity(0)" })).toBe(false);
  });

  // A7 false-refusal fix: a permanent, non-malicious ancestor `filter` (dark-mode/theming,
  // colour-blind assist) must not refuse forever — but only for the narrow, measured
  // visibility-preserving subset `isFilterVisibilityPreserving` allowlists.
  it("still passes on a permanent, visibility-preserving ancestor filter (the measured false refusal: dark-mode grayscale theming)", () => {
    expect(isChainNodeOk({ ...okSample(), filter: "grayscale(0.5)" })).toBe(true);
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

// A7 bypass-1/3 fix: a 1x1 top-layer popover with a huge box-shadow blankets the viewport while
// its own rect stays tiny (`isTopLayerClear`'s own doc). `parseBoxShadowMarginPx` is what lets
// `content-script.ts` widen a top-layer element's rect to account for that before it ever reaches
// `isTopLayerClear`.
describe("parseBoxShadowMarginPx", () => {
  it("returns 0 for 'none'", () => {
    expect(parseBoxShadowMarginPx("none")).toBe(0);
  });

  it("returns 0 for an empty string", () => {
    expect(parseBoxShadowMarginPx("")).toBe(0);
  });

  it("parses a single shadow's offset+blur+spread (the reported attack: huge spread, no blur)", () => {
    // Chromium's computed-style form: `<color> Xpx Ypx BLURpx SPREADpx`.
    expect(parseBoxShadowMarginPx("rgba(20, 20, 20, 0.98) 0px 0px 0px 3000px")).toBe(3000);
  });

  it("includes offset and doubles blur (a deliberately generous, never-under-estimating bound)", () => {
    expect(parseBoxShadowMarginPx("rgb(0, 0, 0) 10px 5px 8px 2px")).toBe(10 + 5 + 2 + 8 * 2);
  });

  it("an ordinary small modal drop-shadow stays small (no false-refusal blast radius)", () => {
    expect(parseBoxShadowMarginPx("rgba(0, 0, 0, 0.15) 0px 4px 12px 0px")).toBeLessThan(40);
  });

  it("inset shadows never paint outside the border box and contribute nothing", () => {
    expect(parseBoxShadowMarginPx("rgb(0, 0, 0) 0px 0px 0px 3000px inset")).toBe(0);
  });

  it("takes the maximum across multiple comma-separated shadows (commas inside rgba() are not boundaries)", () => {
    expect(parseBoxShadowMarginPx("rgba(0, 0, 0, 0.1) 0px 1px 2px 0px, rgba(0, 0, 0, 0.9) 0px 0px 0px 500px")).toBe(500);
  });

  it("an inset shadow alongside a real one still reports the real one's margin", () => {
    expect(parseBoxShadowMarginPx("rgb(0, 0, 0) 0px 0px 0px 10px inset, rgba(20, 20, 20, 0.98) 0px 0px 0px 3000px")).toBe(3000);
  });

  it("returns undefined (never a small number) for a shape this parser does not recognise — the caller must widen its fallback, not narrow it", () => {
    expect(parseBoxShadowMarginPx("something-unparseable")).toBeUndefined();
  });

  it("returns undefined for a negative blur radius (not a valid computed value)", () => {
    expect(parseBoxShadowMarginPx("rgb(0, 0, 0) 0px 0px -5px 0px")).toBeUndefined();
  });
});

// A7 false-refusal fix (reported bypass: a real, permanent `html { filter: grayscale(0.5) }`
// dark-mode/theming/colour-blind-assist rule disabled autofill on that page forever, with no
// recovery, because the pre-fix `isChainNodeOk` treated ANY non-`none` `filter` as bad with no
// allowance for a value that cannot actually hide anything).
describe("isFilterVisibilityPreserving", () => {
  it("passes 'none'", () => {
    expect(isFilterVisibilityPreserving("none")).toBe(true);
  });

  it("passes an empty string", () => {
    expect(isFilterVisibilityPreserving("")).toBe(true);
  });

  it("passes the measured false refusal itself (grayscale theming)", () => {
    expect(isFilterVisibilityPreserving("grayscale(0.5)")).toBe(true);
  });

  it("passes sepia, hue-rotate and saturate at any argument, individually", () => {
    expect(isFilterVisibilityPreserving("sepia(1)")).toBe(true);
    expect(isFilterVisibilityPreserving("hue-rotate(90deg)")).toBe(true);
    expect(isFilterVisibilityPreserving("saturate(0)")).toBe(true);
    expect(isFilterVisibilityPreserving("saturate(5)")).toBe(true);
  });

  it("passes a combination of only allowlisted functions, in any order", () => {
    expect(isFilterVisibilityPreserving("grayscale(0.3) sepia(0.2) hue-rotate(10deg) saturate(1.1)")).toBe(true);
  });

  it("fails on opacity() (the erasure primitive this gate exists to catch)", () => {
    expect(isFilterVisibilityPreserving("opacity(0)")).toBe(false);
  });

  it("fails on brightness(0) and contrast(0) (both collapse every pixel to one constant)", () => {
    expect(isFilterVisibilityPreserving("brightness(0)")).toBe(false);
    expect(isFilterVisibilityPreserving("contrast(0)")).toBe(false);
  });

  it("fails on blur() (can make small text illegible without changing geometry/hit-testing)", () => {
    expect(isFilterVisibilityPreserving("blur(20px)")).toBe(false);
  });

  it("fails on drop-shadow() (an occlusion primitive, same rationale as box-shadow)", () => {
    expect(isFilterVisibilityPreserving("drop-shadow(rgba(0, 0, 0, 0.9) 0px 0px 40px)")).toBe(false);
  });

  it("fails on a url(#...) SVG filter reference (can do anything, including erase alpha)", () => {
    expect(isFilterVisibilityPreserving("url(#custom)")).toBe(false);
  });

  it("fails on invert() (deliberately not in the allowlist — not the measured case)", () => {
    expect(isFilterVisibilityPreserving("invert(1)")).toBe(false);
  });

  it("one disallowed function fails the WHOLE value, even mixed with allowlisted ones", () => {
    expect(isFilterVisibilityPreserving("grayscale(1) blur(2px)")).toBe(false);
  });

  it("fails on an unparseable shape rather than guessing (matches parseBoxShadowMarginPx's own contract)", () => {
    expect(isFilterVisibilityPreserving("something-unparseable")).toBe(false);
  });
});

// A7 bypass fix: a top-layer element's own `::backdrop` pseudo-element has no corresponding
// `Element`/`Node`, so nothing that only reads an Element's own rect/style can see it —
// `isBackdropOccluding` is the pure classifier `content-script.ts`'s `pushBackdropOcclusionRect`
// feeds the already-read `getComputedStyle(el, "::backdrop")` values into.
describe("isBackdropOccluding", () => {
  it("is not occluding when fully transparent (Chromium's own unstyled popover::backdrop default, confirmed by direct probe)", () => {
    expect(isBackdropOccluding("rgba(0, 0, 0, 0)", "none")).toBe(false);
  });

  it("is not occluding for the bare 'transparent' keyword", () => {
    expect(isBackdropOccluding("transparent", "none")).toBe(false);
  });

  it("IS occluding for Chromium's own unstyled dialog::backdrop default (0.1 alpha, confirmed by direct probe) — accepted, since a real native modal dialog already makes the rest of the page inert regardless, so this costs no additional false refusal in practice", () => {
    expect(isBackdropOccluding("rgba(0, 0, 0, 0.1)", "none")).toBe(true);
  });

  it("is occluding for the reported attack's own near-opaque backdrop", () => {
    expect(isBackdropOccluding("rgba(20, 20, 20, 0.95)", "none")).toBe(true);
  });

  it("is occluding for a fully opaque rgb() with no alpha channel at all", () => {
    expect(isBackdropOccluding("rgb(0, 0, 0)", "none")).toBe(true);
  });

  it("is occluding for any backgroundImage, conservatively, regardless of backgroundColor", () => {
    expect(isBackdropOccluding("rgba(0, 0, 0, 0)", "url(cover.png)")).toBe(true);
  });

  it("is occluding on an unparseable backgroundColor (only ever refuse more)", () => {
    expect(isBackdropOccluding("some-future-color-syntax(1 2 3)", "none")).toBe(true);
  });

  // A7 false-refusal fix, fourth adversarial round: confirmed by direct probe against real
  // Chromium — a `background-color` authored in `oklch()`/`lab()`/`color(display-p3 ...)` is
  // serialised back in that SAME function notation, never converted to `rgb()`, even fully inside
  // the sRGB gamut (Tailwind v4's default palette ships entirely in `oklch()`). The pre-fix
  // rgb()-only regex treated every one of these as unparseable and refused unconditionally,
  // disabling autofill on any page with an open, near-transparent popover backdrop authored this
  // way — a false refusal, not a security leak, but one `isBackdropOccluding`'s own doc commits
  // to fixing ("only ever refuse more" cuts both ways: never refuse on a value this CAN parse).
  it("is not occluding for a near-transparent oklch() backdrop (the measured false refusal)", () => {
    expect(isBackdropOccluding("oklch(0 0 0 / 0.01)", "none")).toBe(false);
  });

  it("is not occluding for a near-transparent lab() or color(display-p3 ...) backdrop (same gap, different CSS Color 4 function)", () => {
    expect(isBackdropOccluding("lab(0 0 0 / 0.01)", "none")).toBe(false);
    expect(isBackdropOccluding("color(display-p3 0 0 0 / 0.01)", "none")).toBe(false);
  });

  it("still refuses a near-opaque oklch()/lab() backdrop — the fix parses alpha, it does not stop checking it", () => {
    expect(isBackdropOccluding("oklch(0 0 0 / 0.95)", "none")).toBe(true);
    expect(isBackdropOccluding("lab(0 0 0 / 0.95)", "none")).toBe(true);
  });

  it("defaults to opaque (occluding) for a CSS Color 4 function with no alpha segment at all, same convention as a bare rgb()", () => {
    expect(isBackdropOccluding("oklch(0 0 0)", "none")).toBe(true);
  });

  it("still refuses an explicit 'none' alpha component — an exotic shape this module has not verified the real rendered alpha of (only ever refuse more)", () => {
    expect(isBackdropOccluding("oklch(0 0 0 / none)", "none")).toBe(true);
  });

  // Regression check for the modern-function regex itself (not a realistic getComputedStyle
  // output — a real browser never serialises an empty colour-function body): confirms the
  // broadened regex cannot turn a value that already refused (true) into one that now allows a
  // fill (false), the one direction that would be a security regression rather than a parser
  // improvement. An empty body has no slash, so this defaults to alpha 1 (opaque), same as the
  // bare-function-no-alpha case above — still occluding, same verdict as before this fix (the
  // legacy regex also rejected these, with the same "unparseable → true" result).
  it("still refuses an empty-body modern colour function (regex safety: broadening the match never weakens the alpha default)", () => {
    expect(isBackdropOccluding("rgb()", "none")).toBe(true);
    expect(isBackdropOccluding("color()", "none")).toBe(true);
  });
});

// A7 outline-escape fix, fourth adversarial round: a 1x1 top-layer popover with
// `outline-style: solid; outline-width: 3000px` blankets the viewport exactly like the
// already-fixed box-shadow case — `outline` paints outside the border box and is excluded from
// hit-testing, by spec, same as box-shadow.
describe("parseOutlineMarginPx", () => {
  it("returns 0 when outline-style is 'none', regardless of a leftover outline-width (the UA-stylesheet default on most elements)", () => {
    expect(parseOutlineMarginPx("none", "3px", "0px")).toBe(0);
  });

  it("parses the reported attack's own shape: a 3000px outline, no offset", () => {
    expect(parseOutlineMarginPx("solid", "3000px", "0px")).toBe(3000);
  });

  it("adds a positive outline-offset to the width", () => {
    expect(parseOutlineMarginPx("solid", "10px", "5px")).toBe(15);
  });

  it("a negative offset never subtracts below zero (only ever refuse more)", () => {
    expect(parseOutlineMarginPx("solid", "2px", "-100px")).toBe(0);
  });

  it("an ordinary small focus-ring outline stays small (no false-refusal blast radius)", () => {
    expect(parseOutlineMarginPx("solid", "2px", "2px")).toBeLessThan(10);
  });

  it("treats outline-style: auto (the UA default focus ring) as painting, not as 'none'", () => {
    expect(parseOutlineMarginPx("auto", "3px", "0px")).toBe(3);
  });

  it("returns undefined for a width or offset this cannot parse as a plain px length", () => {
    expect(parseOutlineMarginPx("solid", "thick", "0px")).toBeUndefined();
    expect(parseOutlineMarginPx("solid", "3000px", "unparseable")).toBeUndefined();
  });
});

// A7 pseudo-element deep-occluder fix, fourth adversarial round: a host whose OWN z-index stays
// "auto" can still win the document-order tie against the frame if its `::before`/`::after`
// independently declares a positioned, max-z-index stacking context.
describe("pseudoElementTiesMaxZIndex", () => {
  it("ties when content generates a box, position is non-static, and z-index equals the max", () => {
    expect(pseudoElementTiesMaxZIndex('""', "fixed", String(MAX_Z_INDEX))).toBe(true);
  });

  it("does not tie when content is 'none' (no box is generated at all, regardless of z-index)", () => {
    expect(pseudoElementTiesMaxZIndex("none", "fixed", String(MAX_Z_INDEX))).toBe(false);
  });

  it("does not tie when content is 'normal' (the default: no pseudo-element rule at all)", () => {
    expect(pseudoElementTiesMaxZIndex("normal", "fixed", String(MAX_Z_INDEX))).toBe(false);
  });

  it("does not tie when position is 'static' (z-index has no effect on a static box, by spec)", () => {
    expect(pseudoElementTiesMaxZIndex('""', "static", String(MAX_Z_INDEX))).toBe(false);
  });

  it("does not tie on a z-index below the max", () => {
    expect(pseudoElementTiesMaxZIndex('""', "fixed", "9999")).toBe(false);
  });

  it("ties for position: absolute too (ordinary DOM stacking, not the top-layer paint question)", () => {
    expect(pseudoElementTiesMaxZIndex('""', "absolute", String(MAX_Z_INDEX))).toBe(true);
  });
});

// A7 pseudo-element top-layer fix, fourth adversarial round: a top-layer host (popover/dialog/
// fullscreen) can stay genuinely tiny while its `::before`/`::after` independently paints a
// `position: fixed` overlay — `pushOcclusionRect` only ever reads the HOST element's own rect.
describe("pseudoElementPaintsFixedOverlay", () => {
  it("paints when content generates a box, position is fixed, and the background is opaque (the reported attack's own shape)", () => {
    expect(pseudoElementPaintsFixedOverlay('""', "fixed", "rgba(0, 0, 0, 1)", "none", "none")).toBe(true);
  });

  it("does not paint when content is 'none'", () => {
    expect(pseudoElementPaintsFixedOverlay("none", "fixed", "rgba(0, 0, 0, 1)", "none", "none")).toBe(false);
  });

  it("does not paint when content is 'normal' (no pseudo-element rule at all)", () => {
    expect(pseudoElementPaintsFixedOverlay("normal", "fixed", "rgba(0, 0, 0, 1)", "none", "none")).toBe(false);
  });

  it("does NOT paint for position: absolute, deliberately — a common, ordinary decorative shape (named, narrower scope than this fix closes, not a silent gap)", () => {
    expect(pseudoElementPaintsFixedOverlay('""', "absolute", "rgba(0, 0, 0, 1)", "none", "none")).toBe(false);
  });

  it("does not paint when fixed but fully transparent and no box-shadow (an ordinary, harmless fixed pseudo-element)", () => {
    expect(pseudoElementPaintsFixedOverlay('""', "fixed", "rgba(0, 0, 0, 0)", "none", "none")).toBe(false);
  });

  it("paints via an oversized box-shadow alone, even with a transparent background", () => {
    expect(pseudoElementPaintsFixedOverlay('""', "fixed", "rgba(0, 0, 0, 0)", "none", "rgba(0, 0, 0, 0.9) 0px 0px 0px 3000px")).toBe(true);
  });

  it("paints via a background-image, conservatively, regardless of backgroundColor", () => {
    expect(pseudoElementPaintsFixedOverlay('""', "fixed", "rgba(0, 0, 0, 0)", "url(cover.png)", "none")).toBe(true);
  });
});

// A7 border-image fix, fifth adversarial round: `border-image-outset` can extend the painted
// border-image area beyond the border box without changing `getBoundingClientRect()` or
// participating in hit-testing, the identical shape box-shadow/outline already have a margin
// carve-out for — gated on this parser so an ordinary, zero-outset border-image is never widened.
describe("isAllZeroLengths", () => {
  it("is true for the single-value zero number shape", () => {
    expect(isAllZeroLengths("0")).toBe(true);
  });

  it("is true for the single-value zero length shape", () => {
    expect(isAllZeroLengths("0px")).toBe(true);
  });

  it("is true for the 4-value shorthand, all zero", () => {
    expect(isAllZeroLengths("0px 0px 0px 0px")).toBe(true);
  });

  it("is true for a mix of the zero number and zero length shapes", () => {
    expect(isAllZeroLengths("0 0px 0 0px")).toBe(true);
  });

  it("is false when any one of several values is nonzero (the reported attack's own shape: outset 300px)", () => {
    expect(isAllZeroLengths("300px")).toBe(false);
  });

  it("is false for a nonzero bare-number multiplier", () => {
    expect(isAllZeroLengths("1")).toBe(false);
  });

  it("is false when only one of four values is nonzero", () => {
    expect(isAllZeroLengths("0px 0px 300px 0px")).toBe(false);
  });

  it("is false for a shape this cannot recognise (only ever refuse more, never guess)", () => {
    expect(isAllZeroLengths("calc(1px + 1px)")).toBe(false);
  });
});

describe("MAX_Z_INDEX", () => {
  it("is the largest value the CSS z-index property can hold (matches content-script.ts's own frame.style.zIndex)", () => {
    expect(MAX_Z_INDEX).toBe(2147483647);
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
