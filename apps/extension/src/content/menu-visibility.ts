// SPDX-License-Identifier: AGPL-3.0-only

// The inline-menu iframe's own visibility/topmost checks (A7 / THREAT_MODEL.md gap, HANDOFF
// X6; ADR 0037 §5 "visibility and topmost checks," extended here from the target field — which
// `content-script.ts`'s `isVisible`/`isTopmost` already covered — to the inline-menu iframe
// itself, which had none. Pulled into its own dependency-free module, not left inline in
// `content-script.ts`, for the same reason `inline-menu/decide-click.ts` and
// `content/own-overlay-mutation.ts` already are: this workspace's `vitest` `environment: "node"`
// has no DOM, and `content-script.ts` itself cannot be imported at all under it (its top-level
// `if (window.top === window) { installContentScript(); }` runs at import time). Every function
// here takes plain, already-read values — never a real `Element`/`CSSStyleDeclaration` — so the
// decision logic is unit-testable without a DOM; `content-script.ts` is the only caller that
// ever reads the real DOM and feeds it through.
//
// Two additive gates, matching `content-script.ts`'s own module doc:
//
// GATE A (continuous, every animation frame while an `InlineMenu` is alive): one boolean "ok"
// sample per tick, from {@link rectsMatch} (geometry), {@link isVisibilityChainOk} (opacity,
// visibility, display, filter, clip-path, mask, mix-blend-mode, content-visibility, on the
// frame itself and every ancestor up to `documentElement`) and the top-layer/hit-test checks
// ({@link isTopLayerClear}, {@link isPointHitOk}). Fail-closed: any `false` is a bad sample.
// Gate A toggles the frame's own `pointer-events` from the sample and records when the sample
// happened; by itself it only bounds exposure (a hidden menu stops receiving real OS clicks at
// all) — it does not close the race a timed "flip visible for the click, flip back after" attack
// runs, because `pointer-events` can be flipped back to "none" again before the fill actually
// lands. That is Gate B's job.
//
// GATE B (authoritative, at `apply_fill` arrival): {@link isFillAllowed} is the one check that
// runs causally AFTER the real click → iframe → background → decrypt → push round trip has
// already completed — after BOTH halves of a timed flip, not merely before the click. Before a
// flip, every Gate-A tick is a bad sample, so `lastBadSampleAt` keeps refreshing to "now" and
// `lastGoodSampleAt` never gets set — not eligible. During the brief visible window, some
// tick(s) record good. After the attacker flips back (which they must, to keep deceiving the
// user — leaving it genuinely visible defeats the attack's own purpose), every following tick is
// bad again, so `lastBadSampleAt` keeps refreshing to "now" for as long as the page stays hidden.
// By the time `apply_fill` arrives — several task-hops and at least one more animation frame
// after the click — `lastBadSampleAt` is recent, so the trailing-window check fails, regardless
// of how short the visible flip was. A transient, unrelated hiccup (a benign page animation)
// ages out of the window on its own, rather than permanently poisoning the menu instance the way
// an unbounded "ever bad since creation" flag would.
//
// {@link initMenuVisibilityState}'s own doc records a measured deviation from an earlier
// reading of the design here: `lastBadSampleAt` starts UNSET, not seeded to the menu's
// construction time. Seeding it made every fresh, never-tampered menu unfillable for a full
// `windowMs` after it was shown (confirmed empirically — see that function's doc for the actual
// numbers), which contradicts "only ever refuse more" by refusing fills the unmodified code
// already allowed. `lastGoodSampleAt === undefined` already covers the one case the seed was
// for (a click arriving before any real sample); a genuinely hidden menu still refuses itself
// through real bad samples, with no help from a synthetic one.

/** A plain, already-read rectangle — the shape `DOMRect`/`getBoundingClientRect()` share, kept
 * as a structural interface so this module never imports a DOM type. */
export interface Rect {
  readonly left: number;
  readonly top: number;
  readonly width: number;
  readonly height: number;
}

const GEOMETRY_TOLERANCE_PX = 1;

function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

/**
 * The inline menu's expected on-screen rect, computed ONCE at construction from the anchor
 * field's own rect and the viewport's current size — never re-derived from a live anchor
 * afterward (`content-script.ts` freezes the result and uses it both to position the frame and
 * as Gate A's geometry baseline every tick). Clamped into the viewport: flips above the anchor
 * when there is no room below, and clamps `left`/`top` so the fixed-size box never extends past
 * the right or bottom edge. Without this clamp, "fully inside the viewport" could never pass for
 * an anchor field near the bottom or right edge — a false-refusal bug, not a security feature.
 * Because the frame is always `position: fixed`, this rect is correctly scroll-invariant:
 * ordinary page scrolling must never, by itself, cause a false refusal.
 */
export function computeExpectedRect(anchor: Rect, viewport: Rect | { readonly width: number; readonly height: number }, menuSize: { readonly width: number; readonly height: number }): Rect {
  const anchorBottom = anchor.top + anchor.height;
  const fitsBelow = anchorBottom + menuSize.height <= viewport.height;
  const rawTop = fitsBelow ? anchorBottom : anchor.top - menuSize.height;
  const top = clamp(rawTop, 0, Math.max(0, viewport.height - menuSize.height));
  const left = clamp(anchor.left, 0, Math.max(0, viewport.width - menuSize.width));
  return { left, top, width: menuSize.width, height: menuSize.height };
}

/**
 * Gate A's geometry check: the frame's real, live `getBoundingClientRect()` must equal the
 * frozen expected rect within `tolerancePx`. `getBoundingClientRect()` folds in every ancestor's
 * and the element's own `transform`, so `scale(0)`/off-screen `translate()` on the frame OR on
 * `body`/`html` are caught by this one comparison for free — no separate transform-geometry
 * check is needed.
 */
export function rectsMatch(actual: Rect, expected: Rect, tolerancePx: number = GEOMETRY_TOLERANCE_PX): boolean {
  return (
    Math.abs(actual.left - expected.left) <= tolerancePx &&
    Math.abs(actual.top - expected.top) <= tolerancePx &&
    Math.abs(actual.width - expected.width) <= tolerancePx &&
    Math.abs(actual.height - expected.height) <= tolerancePx
  );
}

/** One node's computed style, already read, for the {@link isVisibilityChainOk} chain — the
 * frame itself plus every ancestor up to and including `documentElement` (today, with the frame
 * appended directly to `document.body`, that chain is exactly `{frame, body, documentElement}`;
 * `content-script.ts` walks `parentElement` generically so this stays correct if the insertion
 * point ever changes). */
export interface ChainStyleSample {
  readonly opacity: number;
  readonly visibility: string;
  readonly display: string;
  readonly filter: string;
  readonly clipPath: string;
  readonly mask: string;
  readonly mixBlendMode: string;
  readonly contentVisibility: string;
}

const OPACITY_TOLERANCE = 0.01;

/**
 * One chain node is "ok" when every property below is at its CSS-default/neutral value.
 * `opacity` does not inherit, so each node's own value must be read (relying on inheritance
 * would miss a hostile rule set directly on the frame, which is exactly the fixme reproducer's
 * attack: `iframe[data-rizzy-inline-menu]{opacity:0}`); `visibility` DOES inherit, so the
 * frame's own computed `visibility` already reflects an ancestor's `hidden` — but Gate A's own
 * inline `!important visibility:visible` on the frame's own element already defeats that for the
 * frame itself, so checking each ancestor's own computed value here is what actually catches a
 * `body`/`html` rule the frame's override cannot reach from outside itself.
 *
 * Deliberately excludes `will-change`/`contain`: real pages use `contain: layout`/
 * `will-change: transform` for ordinary scroll/virtualization performance, and any attack that
 * actually relies on them to break `position: fixed`'s containing block already shows up as a
 * geometry mismatch in {@link rectsMatch}. Adding them as a separate hard gate would cost real
 * false-refusal risk for little additional attack coverage.
 */
export function isChainNodeOk(sample: ChainStyleSample): boolean {
  return (
    Math.abs(sample.opacity - 1) <= OPACITY_TOLERANCE &&
    sample.visibility !== "hidden" &&
    sample.display !== "none" &&
    sample.filter === "none" &&
    sample.clipPath === "none" &&
    sample.mask === "none" &&
    sample.mixBlendMode === "normal" &&
    sample.contentVisibility !== "hidden"
  );
}

/** Fail-closed, binary: the whole chain is ok only when every node's own sample passes
 * {@link isChainNodeOk}. An empty chain (should never happen — the frame is always at least its
 * own node) passes vacuously, since there is nothing in it to fail on. */
export function isVisibilityChainOk(chain: readonly ChainStyleSample[]): boolean {
  return chain.every(isChainNodeOk);
}

/**
 * Explicit rect-intersection of the expected rect against the browser's top layer (every
 * `document.fullscreenElement`, `dialog[open]`, and `:popover-open` element's own rect) — not
 * `elementFromPoint`. The frame's `zIndex: 2147483647` is the maximum possible value and the
 * frame is appended directly to `document.body`, so nothing in ordinary DOM stacking (z-index,
 * DOM order) can ever render above it; only the browser's top layer, which renders above all
 * z-index by spec, can.
 */
export function isTopLayerClear(expected: Rect, topLayerRects: readonly Rect[]): boolean {
  return !topLayerRects.some((rect) => rectsIntersect(expected, rect));
}

function rectsIntersect(a: Rect, b: Rect): boolean {
  return a.left < b.left + b.width && a.left + a.width > b.left && a.top < b.top + b.height && a.top + a.height > b.top;
}

/** The result of `document.elementFromPoint` at the expected rect's center, already classified
 * by the caller: `"frame"` when the element returned is the menu's own `<iframe>`, `"other"` for
 * any other element, `"none"` for `null`. */
export type PointHitResult = "frame" | "other" | "none";

/**
 * A cheap backstop for any occlusion mechanism not already caught by {@link isVisibilityChainOk}
 * / {@link isTopLayerClear} (future top-layer-like APIs, implementation quirks): sampled at the
 * expected rect's center point only (the shape/position tampering classes are already fully
 * covered by the geometry and chain checks, so a grid of points buys nothing here).
 *
 * UNLIKE the existing field-level `isTopmost`'s "null passes" convention in `content-script.ts`,
 * `"none"` here is a BAD sample: the menu is clamped into the viewport by construction (
 * {@link computeExpectedRect}), so `null` means something unusual (overflow-clipping, an
 * ancestor tamper), never the routine "below the fold" case a real page field can legitimately
 * be in.
 */
export function isPointHitOk(result: PointHitResult): boolean {
  return result === "frame";
}

/** Gate B's running state for one `InlineMenu` instance: the two timestamps a Gate-A tick
 * updates, and the one check at `apply_fill` arrival reads. Plain data, not a class, so every
 * transition is a pure function below — `content-script.ts` holds the current value and replaces
 * it each tick. */
export interface MenuVisibilityState {
  readonly lastBadSampleAt: number | undefined;
  readonly lastGoodSampleAt: number | undefined;
}

/**
 * Starts with neither timestamp set — not, as an earlier reading of the spec had it,
 * `lastBadSampleAt` initialized to the construction time ("bad until proven otherwise").
 *
 * Measured deviation, stated per CLAUDE.md ("deviate only with a stated reason"): the
 * construction-time placeholder was meant to guarantee that "a menu clicked before its very
 * first real sample is correctly refused, never accidentally allowed by a timing fluke" — but
 * {@link isFillAllowed}'s OWN first condition, `lastGoodSampleAt === undefined`, already
 * guarantees exactly that, with no help from `lastBadSampleAt` at all: zero samples means zero
 * good samples, which already refuses. Seeding `lastBadSampleAt` to "now" additionally forces
 * every trailing-window check for the next `windowMs` to fail too, REGARDLESS of whether any
 * real bad sample ever occurs — i.e. it makes every fresh, never-tampered menu unfillable for a
 * full `windowMs` after it is shown, attacked or not. Confirmed empirically against a real
 * Chromium build (`adversarial-fill-requests.spec.ts`'s "forged postMessage" test, its own
 * legitimate positive-control click): Gate A's ticks ran from ~274ms to ~396ms after
 * construction, all good, pinning `lastBadSampleAt` at ~274ms (nothing after construction ever
 * sets it to anything else, since {@link recordSample} only touches it on a BAD sample); the
 * real, trusted click landed at ~576ms; `576 - 274 ≈ 302ms < windowMs (1000ms)` — refused, on a
 * page that was never touched by any attack. That is not a race, a timing fluke, or browser
 * throttling — it is arithmetic, and it reproduces on literally every fill of a freshly shown
 * menu, which contradicts this task's own "only ever refuse more" mandate by refusing a
 * legitimate fill the unmodified code already allowed.
 *
 * The flip-attack timeline {@link isFillAllowed}'s own doc walks through is unaffected by this
 * change: a genuinely hidden menu produces its own REAL bad samples continuously (every Gate-A
 * tick while hidden calls {@link recordSample} with `ok: false`, which sets `lastBadSampleAt` to
 * that tick's own time) — it never needed the synthetic construction-time value to be refused,
 * only a real page that is actually hiding it.
 */
export function initMenuVisibilityState(): MenuVisibilityState {
  return { lastBadSampleAt: undefined, lastGoodSampleAt: undefined };
}

/** One Gate-A tick's sample. Pure: returns a new state, never mutates `state`. A good sample
 * refreshes `lastGoodSampleAt` and leaves `lastBadSampleAt` untouched (it ages out of Gate B's
 * window on its own); a bad sample refreshes `lastBadSampleAt` and leaves `lastGoodSampleAt`
 * untouched (once genuinely visible, it stays eligible unless a later bad sample is still within
 * the window at the moment {@link isFillAllowed} is actually checked). */
export function recordSample(state: MenuVisibilityState, now: number, ok: boolean): MenuVisibilityState {
  return ok ? { lastBadSampleAt: state.lastBadSampleAt, lastGoodSampleAt: now } : { lastBadSampleAt: now, lastGoodSampleAt: state.lastGoodSampleAt };
}

/** Tunable (U): comfortably exceeds the realistic click → decrypt → push round trip, including
 * the Chromium offscreen-document → service-worker relay hop, while being short enough that an
 * ordinary page-load fade/transition (typically well under 500 ms) has fully aged out before any
 * real human click occurs. Needs validation against real Chromium/Firefox builds and real human
 * click timing before being trusted as final — a correctness tuning question for the owner, not
 * a security-policy one. */
export const DEFAULT_MENU_VISIBILITY_WINDOW_MS = 1000;

/**
 * Gate B: the only check that runs causally AFTER the full click → iframe → background →
 * decrypt → push round trip, so it is evaluated after BOTH halves of a timed "flip visible for
 * the click, flip back after" attack have already happened — not merely before the click. See
 * this module's own header for the full reasoning; in short: requires at least one real good
 * sample to have EVER been recorded (`lastGoodSampleAt !== undefined` — rules out a
 * permanently-hidden menu on a technicality), that good sample to still be RECENT
 * (`now - lastGoodSampleAt <= windowMs` — see below), AND no bad sample in the trailing
 * `windowMs` window ending at `now` (`lastBadSampleAt === undefined`, or old enough). No separate
 * dwell/settle constant is layered on top: the window itself IS the dwell, applied at the one
 * point in time — `apply_fill` arrival — that actually matters.
 *
 * The `lastGoodSampleAt` recency requirement (adversarial-report finding, not yet owner-dated —
 * recorded per CLAUDE.md "deviate only with a stated reason" at the point it was added): without
 * it, a sampler that STOPS TICKING ENTIRELY — a main-thread stall covering Gate A's own
 * `requestAnimationFrame` loop, not merely a CSS flip `tick()` would still observe — can leave
 * `lastBadSampleAt` permanently `undefined` even while the frame is actually hidden, because
 * {@link recordSample} is the ONLY thing that ever sets either timestamp, and it never runs
 * during a genuine stall. The pre-existing trailing-bad-sample check alone treats
 * `lastBadSampleAt === undefined` as an unconditional pass, with no requirement on HOW LONG ago
 * `lastGoodSampleAt` was recorded — so a stalled-forever sampler reads as "still good," not as
 * "haven't checked in a while, so we don't actually know." Requiring `lastGoodSampleAt` itself to
 * be within the SAME trailing window closes that: once nobody has reported anything — good OR bad
 * — in `windowMs`, this refuses, fail-closed, same as a frame that has been continuously bad the
 * whole time.
 *
 * Reuses `windowMs` rather than a second tunable (DRY/KISS). Measured directly rather than
 * assumed (instrumented `apply_fill` arrival against the real positive-control e2e test,
 * `adversarial-fill-requests.spec.ts`, 5 runs): `now - lastGoodSampleAt` at the moment `apply_fill`
 * is actually processed was 0.6–5.2ms every time — Gate A's `tick()` loop is still running at that
 * point (not yet cancelled; `destroy()` only runs once `requestFill` in `inline-menu/main.ts`
 * settles, and `handleInlineMenuFillRequest` awaits pushing `apply_fill` to the tab before that
 * response resolves — so the push causally PRECEDES teardown here, not the other way around).
 * `windowMs` (1000ms, U) therefore has roughly 200x headroom over the normal gap in this
 * implementation; a future change to that ordering could shrink the margin, which is exactly why
 * this is measured and re-checked, not assumed permanent.
 */
export function isFillAllowed(state: MenuVisibilityState, now: number, windowMs: number = DEFAULT_MENU_VISIBILITY_WINDOW_MS): boolean {
  if (state.lastGoodSampleAt === undefined || now - state.lastGoodSampleAt > windowMs) {
    return false;
  }
  return state.lastBadSampleAt === undefined || now - state.lastBadSampleAt >= windowMs;
}
