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
    isFilterVisibilityPreserving(sample.filter) &&
    sample.clipPath === "none" &&
    sample.mask === "none" &&
    sample.mixBlendMode === "normal" &&
    sample.contentVisibility !== "hidden"
  );
}

/** A function name this `filter` carve-out trusts to never erase or occlude content underneath
 * it — only ones that recolour without touching the alpha/luminance structure a user would need
 * to actually make out the menu's rows. Each is sampled directly against a real browser before
 * being trusted here (A7 false-refusal fix, THREAT_MODEL.md A7 residual risk): `grayscale`,
 * `sepia` and `hue-rotate` only ever recombine or rotate existing channel values, and `saturate`
 * (including `saturate(0)`, plain desaturation) only scales chroma toward or away from the
 * existing luminance — none of the four can, at ANY argument value, reduce a pixel's alpha or
 * collapse its luminance to a single constant the way `opacity()`/`brightness(0)`/`contrast(0)`
 * can. Deliberately excludes `invert`, `blur`, `drop-shadow` and any `url(#...)` SVG filter
 * reference (an SVG filter primitive can do literally anything, including erase alpha) — this
 * carve-out is scoped to the one measured false refusal (a real, permanent `html { filter:
 * grayscale(0.5) }` dark-mode/theming/colour-blind-assist rule), not a general "most filters are
 * fine" relaxation. `clip-path`, `mask` and `mix-blend-mode` get no equivalent carve-out: both
 * can occlude or erase content at some value with no comparably narrow, provably-safe subset
 * (`mix-blend-mode: difference` against a matched backdrop is already an occlusion primitive by
 * itself), and no permanent, whole-page legitimate use case was reported or measured for them the
 * way dark-mode/theming filters were — "only ever refuse more" stays the default; this is a
 * narrow, stated exception for `filter` alone. */
const VISIBILITY_PRESERVING_FILTER_FUNCTIONS = new Set(["grayscale", "sepia", "hue-rotate", "saturate"]);

const FILTER_FUNCTION = /([a-zA-Z-]+)\([^)]*\)/g;

/**
 * `true` for `"none"`, and for a filter value that consists ONLY of calls to functions in
 * {@link VISIBILITY_PRESERVING_FILTER_FUNCTIONS} (any count, any argument, any order) — `false`
 * for anything else, including a filter this cannot confidently parse into a clean function list
 * (matching {@link parseBoxShadowMarginPx}'s own "only ever refuse more" contract: an unrecognised
 * shape refuses, it is never given the benefit of the doubt). A single disallowed function
 * anywhere in the list (e.g. `grayscale(1) blur(2px)`) fails the whole value — there is no partial
 * credit, since the disallowed function alone is already enough to hide content regardless of
 * what else is chained with it.
 */
export function isFilterVisibilityPreserving(filter: string): boolean {
  const trimmed = filter.trim();
  if (trimmed === "" || trimmed === "none") {
    return true;
  }
  const matches = [...trimmed.matchAll(FILTER_FUNCTION)];
  // The parsed function calls must reconstitute the ENTIRE trimmed value (joined by a single
  // space, `getComputedStyle().filter`'s own normalised separator) — anything left over (a bare
  // `url(#x)` reference, a keyword, stray text) means this did not fully understand the value,
  // which must refuse, not pass by accident of a partial match.
  if (matches.length === 0 || matches.map((m) => m[0]).join(" ") !== trimmed) {
    return false;
  }
  return matches.every((m) => VISIBILITY_PRESERVING_FILTER_FUNCTIONS.has(m[1] ?? ""));
}

/** Fail-closed, binary: the whole chain is ok only when every node's own sample passes
 * {@link isChainNodeOk}. An empty chain (should never happen — the frame is always at least its
 * own node) passes vacuously, since there is nothing in it to fail on. */
export function isVisibilityChainOk(chain: readonly ChainStyleSample[]): boolean {
  return chain.every(isChainNodeOk);
}

/**
 * Explicit rect-intersection of the expected rect against a set of occlusion candidates — not
 * `elementFromPoint`, which by spec cannot see a `pointer-events: none` element at all (A7
 * bypass-2 residual, THREAT_MODEL.md's own note on `elementsFromPoint()` sharing the same blind
 * spot) and never reflects paint that escapes an element's own border box (A7 bypass-1/3: a
 * `box-shadow`/`filter` can paint far outside `getBoundingClientRect()`). `content-script.ts`
 * feeds this two independent rect sources, both expanded or substituted conservatively by the
 * caller before reaching here (never narrowed): the browser's top layer (every
 * `document.fullscreenElement`, `dialog[open]`, and `:popover-open` element, widened by
 * {@link parseBoxShadowMarginPx}/a non-`none` `filter`) and any body-level sibling tying the
 * frame's own maximum `z-index` (`2147483647`) that comes after it in document order (the one
 * other way, besides the top layer, that ordinary DOM stacking could ever render something above
 * a `zIndex: 2147483647` element — a strictly LOWER z-index, or an earlier document position at
 * the same z-index, cannot). Nothing in ordinary DOM stacking can otherwise out-rank the frame.
 */
export function isTopLayerClear(expected: Rect, occlusionRects: readonly Rect[]): boolean {
  return !occlusionRects.some((rect) => rectsIntersect(expected, rect));
}

function rectsIntersect(a: Rect, b: Rect): boolean {
  return a.left < b.left + b.width && a.left + a.width > b.left && a.top < b.top + b.height && a.top + a.height > b.top;
}

/**
 * The largest per-side margin any NON-`inset` component of a CSSOM-computed `box-shadow` value
 * can paint beyond its element's own border box (A7 bypass-1/3: a 1×1 top-layer popover with
 * `box-shadow: 0 0 0 3000px <opaque>` blankets the viewport while `getBoundingClientRect()` stays
 * 1×1 and box-shadow never participates in hit-testing — confirmed by direct probe against the
 * real built extension). `getComputedStyle().boxShadow` always normalises every shadow to
 * `<color> Xpx Ypx BLURpx SPREADpx [inset]` (lengths in `px`, color as `rgb()`/`rgba()`) in every
 * browser this extension targets, so this never has to parse another CSS length unit. `inset`
 * shadows paint INSIDE the border box and contribute nothing. Multiple comma-separated shadows
 * (split on top-level commas only — an `rgba(...)` color can itself contain commas) contribute
 * their own maximum. Deliberately returns one uniform margin, not a per-side one: a shadow can be
 * offset asymmetrically (`10px 0 0 3000px` spreads 3000px one way, roughly 2990px the other), but
 * the frame's expected rect can sit anywhere the attacker likes relative to the top-layer element
 * regardless, so a tighter per-side margin buys nothing against a motivated attacker and only
 * adds parsing surface — `|offsetX| + |offsetY| + spread + 2×blur` is a deliberately generous
 * (never-under-estimating) bound: CSS does not give blur's visible extent an exact pixel formula,
 * and over-estimating it only ever refuses MORE, never less.
 *
 * Returns `undefined`, never a small number, for anything this cannot confidently parse (an
 * unexpected computed-style shape from a future browser quirk) — the caller must then widen its
 * own fallback (today: substitute the full viewport rect), never narrow it, matching this
 * module's "only ever refuse more" contract.
 */
export function parseBoxShadowMarginPx(boxShadow: string): number | undefined {
  const trimmed = boxShadow.trim();
  if (trimmed === "" || trimmed === "none") {
    return 0;
  }
  let max = 0;
  for (const shadow of splitTopLevelCommas(trimmed)) {
    const margin = parseOneBoxShadow(shadow.trim());
    if (margin === undefined) {
      return undefined;
    }
    max = Math.max(max, margin);
  }
  return max;
}

function splitTopLevelCommas(value: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < value.length; i += 1) {
    const ch = value[i];
    if (ch === "(") {
      depth += 1;
    } else if (ch === ")") {
      depth -= 1;
    } else if (ch === "," && depth === 0) {
      parts.push(value.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(value.slice(start));
  return parts;
}

const SHADOW_LENGTH_PX = /(-?\d+(?:\.\d+)?)px/g;

function parseOneBoxShadow(shadow: string): number | undefined {
  if (/\binset\b/.test(shadow)) {
    return 0;
  }
  // Strips the colour function (`rgb(...)`/`rgba(...)`) so only the length list remains — every
  // colour this computed style can contain is parenthesised, so removing any parenthesised group
  // removes it cleanly with no colour-keyword list to maintain.
  const withoutColor = shadow.replace(/[a-zA-Z-]+\([^)]*\)/g, "");
  const lengths = [...withoutColor.matchAll(SHADOW_LENGTH_PX)].map((m) => Number(m[1]));
  // `<offset-x> <offset-y> [<blur-radius>] [<spread-radius>]` — 2 to 4 lengths; anything else is
  // a shape this parser does not recognise.
  if (lengths.length < 2 || lengths.length > 4 || lengths.some((n) => Number.isNaN(n))) {
    return undefined;
  }
  const [offsetX, offsetY, blur = 0, spread = 0] = lengths;
  // `offsetX`/`offsetY` cannot actually be `undefined` (the length check above guarantees at
  // least 2 entries) — this guard is only to satisfy `number[]` destructuring's own type, which
  // cannot express that guarantee; `blur < 0` is a real, meaningful rejection of a shape this
  // parser does not expect.
  if (offsetX === undefined || offsetY === undefined || blur < 0) {
    return undefined;
  }
  return Math.abs(offsetX) + Math.abs(offsetY) + spread + blur * 2;
}

/** How opaque a top-layer element's own `::backdrop` pseudo-element's `background-color` must be
 * (its alpha channel) before it counts as occluding (A7 bypass fix: an opaque,
 * `pointer-events: none` `popover::backdrop` blankets the viewport while the popover element
 * itself stays 1×1 — `::backdrop` is a browser-painted box with no corresponding `Element`/`Node`
 * at all, so `content-script.ts`'s own `pushOcclusionRect`, which only ever reads an ELEMENT's own
 * rect/filter/box-shadow, structurally cannot see it; this is checked separately, against
 * `getComputedStyle(el, "::backdrop")`, the two-argument form the pre-fix code never called).
 * Chromium's own UA stylesheet gives an unstyled, author-untouched `dialog::backdrop` a default
 * `rgba(0, 0, 0, 0.1)` (confirmed by direct probe) and an unstyled `popover::backdrop`
 * `rgba(0, 0, 0, 0)` (fully transparent) — set below that default dialog dimming (a real native
 * modal dialog already makes the rest of the page `inert`, independent of these gates, so
 * flagging it too costs no ADDITIONAL false refusal in practice) but clearly above zero, so an
 * untouched popover backdrop (today's overwhelmingly common case: no custom backdrop at all)
 * never trips this. */
const BACKDROP_ALPHA_THRESHOLD = 0.05;

/**
 * Whether a top-layer element's own `::backdrop` pseudo-element visually occludes whatever is
 * behind it: `backgroundImage` anything other than `"none"` (an image backdrop; conservatively
 * always occluding, since this cannot know the image's own transparency), or `backgroundColor`'s
 * alpha channel above {@link BACKDROP_ALPHA_THRESHOLD}. A value this cannot parse as `rgb()`/
 * `rgba()`/`transparent` refuses rather than guesses ("only ever refuse more," matching
 * {@link parseBoxShadowMarginPx}'s own contract) — the one case this does NOT refuse on is the
 * empty string a pseudo-element query can return in a browser/version with no support for the
 * two-argument `getComputedStyle` form, which the caller already treats the same as "transparent"
 * (no backdrop this module can see is not evidence of an occluding one).
 */
export function isBackdropOccluding(backgroundColor: string, backgroundImage: string): boolean {
  const bg = backgroundColor.trim();
  const img = backgroundImage.trim();
  if (img !== "" && img !== "none") {
    return true;
  }
  if (bg === "" || bg === "transparent") {
    return false;
  }
  const match = /^rgba?\(\s*[\d.]+%?\s*,\s*[\d.]+%?\s*,\s*[\d.]+%?\s*(?:,\s*([\d.]+%?)\s*)?\)$/.exec(bg);
  if (match === null) {
    return true;
  }
  const rawAlpha = match[1];
  const alpha = rawAlpha === undefined ? 1 : Number(rawAlpha.endsWith("%") ? Number(rawAlpha.slice(0, -1)) / 100 : rawAlpha);
  return !Number.isFinite(alpha) || alpha > BACKDROP_ALPHA_THRESHOLD;
}

/** The maximum CSS `z-index` value: the frame's own `zIndex: 2147483647` (`content-script.ts`),
 * the largest value the property can hold, so nothing in ordinary DOM stacking can exceed it —
 * only an EQUAL value, combined with a later document position, can paint above it. Shared here
 * (not re-declared in `content-script.ts`) so the one number stays a single source of truth. */
export const MAX_Z_INDEX = 2147483647;

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
