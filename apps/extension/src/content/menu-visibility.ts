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
  readonly isolation: string;
}

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
 * `opacity` is compared EXACTLY against `1`, with no tolerance (sixth adversarial round; an
 * earlier version of this check used a `0.01` "looks the same" tolerance that had no relationship
 * to the question this check actually has to answer): per spec, ANY `opacity` other than exactly
 * `1` unconditionally creates a new CSS stacking context, regardless of how visually close to `1`
 * it is — `body { opacity: 0.995 }` passed the old tolerance comfortably while still collapsing
 * `body`'s entire subtree (the frame included, however large its own `z-index`) to `body`'s own
 * single position in the ROOT stacking context, letting a sibling of `<body>` with a trivially
 * low `z-index` paint above the whole subtree (reported bypass, confirmed by direct probe and by
 * reverting the fix — see the e2e test). `isolation !== "isolate"` is the same reasoning applied
 * to the OTHER property that creates a stacking context with no other side effect at all (unlike
 * `filter`/`transform`/`contain`/`will-change`, `isolation` never changes geometry or visible
 * paint by itself, so {@link rectsMatch} can never catch an attack that relies on it the way the
 * excluded properties below are reasoned to be already caught). A transient animation/transition
 * settling at a near-1, non-`isolate`-vs-`isolate` value is already covered by the existing,
 * accepted "ancestor CSS transition refuses for the transition's own duration" trade-off
 * (THREAT_MODEL.md A7 residual risk) — this closes a PERMANENT gap, not a new transient one.
 *
 * Deliberately excludes `will-change`/`contain`: real pages use `contain: layout`/
 * `will-change: transform` for ordinary scroll/virtualization performance, and any attack that
 * actually relies on them to break `position: fixed`'s containing block already shows up as a
 * geometry mismatch in {@link rectsMatch} (confirmed directly: either property on `body`/
 * `documentElement` already refuses a real fill today, for that reason, independent of this
 * function). Adding them as a separate hard gate would cost real false-refusal risk for little
 * additional attack coverage.
 */
export function isChainNodeOk(sample: ChainStyleSample): boolean {
  return (
    sample.opacity === 1 &&
    sample.visibility !== "hidden" &&
    sample.display !== "none" &&
    isFilterVisibilityPreserving(sample.filter) &&
    sample.clipPath === "none" &&
    sample.mask === "none" &&
    sample.mixBlendMode === "normal" &&
    sample.contentVisibility !== "hidden" &&
    sample.isolation !== "isolate"
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
 * {@link parseBoxShadowMarginPx}/a non-`none` `filter`) and any element ANYWHERE in the document
 * tying the frame's own maximum `z-index` (`2147483647`) that comes after it in document order —
 * not only a direct sibling of `<body>` (fifth adversarial round: a decoy appended directly to
 * `document.documentElement`, a SIBLING of `<body>` rather than a descendant of it, is exactly as
 * reachable this way as one appended to `<body>` itself — see `content-script.ts`'s
 * `#deepOccluderRects`' own doc on walking the frame's whole ancestor path, not merely its
 * immediate parent's children), and not only a light-DOM descendant (an open, `mode: "open"`
 * Shadow DOM root at any depth is reachable the same way) — the one other way, besides the top
 * layer, that ordinary DOM stacking could ever render something above a `zIndex: 2147483647`
 * element (a strictly LOWER z-index, or an earlier document position at the same z-index,
 * cannot). Nothing in ordinary DOM stacking can otherwise out-rank the frame.
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

/**
 * The margin an element's own CSS `outline` can paint beyond its border box (A7 outline-escape
 * fix, fourth adversarial round: a 1×1 top-layer popover with `outline-style: solid;
 * outline-width: 3000px` blankets the viewport exactly like the already-fixed box-shadow case —
 * `outline` paints a uniform ring around the border box, offset outward by `outline-offset` (a
 * NEGATIVE offset pulls the ring inward and contributes nothing extra — this never subtracts,
 * matching {@link parseBoxShadowMarginPx}'s own "only ever refuse more" contract), and like
 * `box-shadow`, never changes `getBoundingClientRect()` and never participates in hit-testing
 * (spec).
 *
 * Zero whenever `outlineStyle` is `"none"` — the one value that means nothing is actually painted
 * regardless of `outline-width` (spec: `outline-width`'s own computed value does not depend on
 * `outline-style`, so a browser can report a non-zero width even for a `none` outline; reading
 * width alone without this check would widen for an outline that paints nothing at all, a
 * needless false-refusal risk on the overwhelming majority of elements, which have some leftover
 * `outline-width` from the UA stylesheet but no visible outline).
 *
 * Returns `undefined`, never a small number, for a width or offset this cannot parse as a plain
 * `px` length (an unexpected computed-style shape from a future browser quirk) — the caller must
 * then widen its own fallback, never narrow it, matching {@link parseBoxShadowMarginPx}'s own
 * contract.
 */
export function parseOutlineMarginPx(outlineStyle: string, outlineWidthPx: string, outlineOffsetPx: string): number | undefined {
  if (outlineStyle.trim() === "none") {
    return 0;
  }
  const width = parsePxLength(outlineWidthPx);
  const offset = parsePxLength(outlineOffsetPx);
  if (width === undefined || offset === undefined) {
    return undefined;
  }
  return Math.max(0, width + offset);
}

const PX_LENGTH = /^(-?\d+(?:\.\d+)?)px$/;

function parsePxLength(value: string): number | undefined {
  const match = PX_LENGTH.exec(value.trim());
  if (match === null) {
    return undefined;
  }
  return Number(match[1]);
}

/**
 * Whether every whitespace-separated token in a CSSOM-computed `border-image-outset` value is
 * zero (A7 border-image fix, fifth adversarial round: a `border-image-source` with a nonzero
 * `border-image-outset` extends the painted border-image area outward from the border box by an
 * author-controlled amount — `getBoundingClientRect()` never reflects this, and like `box-shadow`/
 * `outline`, it never participates in hit-testing — confirmed by direct probe: a 1×1-content
 * element with `border-image-outset: 300px` and a matching `border-image-width` painted a solid
 * ~600×600px block centred on its own tiny box). `border-image-outset` accepts 1–4 values
 * (top/right/bottom/left, CSS's usual shorthand expansion), each either a `<number>` (a multiplier
 * of the corresponding border-width — computed style normalises a zero multiplier to the bare
 * token `"0"`) or a `<length>` (normalised to `"0px"` for zero) — this module does not attempt to
 * compute the actual painted margin from either shape (unlike {@link parseBoxShadowMarginPx}'s
 * `px`-only lengths, a `<number>` multiplier's effective margin depends on `border-width`, which
 * this function is not given), only whether every token is one of the two zero shapes. Anything
 * else — a nonzero number or length in any position — means the border-image area extends beyond
 * the border box by an amount this cannot bound, so the caller must widen its own fallback, never
 * narrow it ("only ever refuse more," matching {@link parseBoxShadowMarginPx}'s own contract); so
 * does a value this cannot recognise as a token list of this shape at all.
 */
export function isAllZeroLengths(value: string): boolean {
  const tokens = value
    .trim()
    .split(/\s+/)
    .filter((token) => token !== "");
  if (tokens.length === 0) {
    return true;
  }
  return tokens.every((token) => /^0(?:\.0+)?(?:px)?$/.test(token));
}

/**
 * Whether a `::before`/`::after` pseudo-element's own computed style indicates it independently
 * ties the frame's maximum z-index in a way that can actually affect paint ORDER (A7
 * pseudo-element deep-occluder fix, fourth adversarial round): a host element whose own z-index
 * stays `"auto"` can still win the document-order tie against the frame if its generated content
 * declares its OWN `position`/`z-index` — CSS2.1 Appendix E step 6 (equal z-index within the same
 * stacking context paints in tree order, later wins) applies to the pseudo-element's own
 * independently-established stacking context exactly as it would to a real sibling element, and
 * `#scanElementForDeepOccluders` (`content-script.ts`) previously only ever read the HOST
 * element's own computed z-index, never its pseudo-elements'.
 *
 * Two conditions, both required, matching spec precisely rather than over-flagging: `content` must
 * generate a real box (`"none"`/`"normal"` renders nothing at all, regardless of any other
 * declared property — the whole stacking-context question is moot with no box to paint), and
 * `position` must not be `"static"` (per spec, `z-index` has no effect on a statically positioned
 * box — only a positioned element, or a flex/grid item, participates in z-index stacking at all,
 * so a static pseudo-element's `z-index` is inert regardless of its value; checking this costs
 * nothing and only ever REDUCES false-refusal risk, never security coverage, since a static
 * pseudo-element genuinely cannot escalate above the frame this way in any browser).
 */
export function pseudoElementTiesMaxZIndex(content: string, position: string, zIndex: string): boolean {
  if (content === "none" || content === "normal") {
    return false;
  }
  if (position === "static") {
    return false;
  }
  const z = Number(zIndex);
  return Number.isFinite(z) && z >= MAX_Z_INDEX;
}

/**
 * Whether a `::before`/`::after` pseudo-element visually paints an overlay that can occlude the
 * menu while escaping its HOST element's own (possibly 1×1) border box (A7 pseudo-element
 * top-layer fix, fourth adversarial round): a top-layer host (a `popover`/`dialog`/fullscreen
 * element `#topLayerRects` already finds) can stay genuinely tiny while its generated content
 * independently declares `position: fixed; inset: 0` plus a background — `pushOcclusionRect`
 * (`content-script.ts`) only ever reads the HOST element's own rect/filter/box-shadow, which never
 * sees this: a pseudo-element has no `Element`/`Node` of its own and no `getBoundingClientRect()`
 * to read, the same structural gap {@link isBackdropOccluding} already closes for `::backdrop`.
 *
 * Scoped to exactly `position: "fixed"` — the one case whose containing block is, in the ordinary
 * case (no transformed/filtered/contained ancestor establishing a different one), the viewport
 * itself, so there is nothing ambiguous to bound. `position: "absolute"` is deliberately NOT
 * treated the same way: its containing block is whichever positioned ancestor is nearest, which
 * this function cannot resolve without replicating CSS containing-block resolution, and
 * `position: absolute` generated content (badges, carets, tooltips) is common, ordinary,
 * decorative CSS — treating every one of those as a full-viewport occluder would be a real,
 * unbounded false-refusal regression, not a narrow fix. Left as a named, narrower scope than this
 * closes, not a silently unclosed gap.
 *
 * Reuses {@link isBackdropOccluding} and {@link parseBoxShadowMarginPx} — the same fail-closed
 * "only ever refuse more" parsers this module already uses for the element-level and `::backdrop`
 * cases — rather than inventing a third paint-opacity classifier.
 */
export function pseudoElementPaintsFixedOverlay(content: string, position: string, backgroundColor: string, backgroundImage: string, boxShadow: string): boolean {
  if (content === "none" || content === "normal") {
    return false;
  }
  if (position !== "fixed") {
    return false;
  }
  if (isBackdropOccluding(backgroundColor, backgroundImage)) {
    return true;
  }
  const shadowMargin = parseBoxShadowMarginPx(boxShadow);
  return shadowMargin === undefined || shadowMargin > 0;
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

/** Legacy comma-separated `rgb()`/`rgba()` — Chromium's own normal serialisation for a
 * `background-color` authored in that notation, or in `hsl()`/`hsla()` (confirmed by direct
 * probe: Chromium converts `hsl()`/`hsla()` back to `rgba()` in computed style, in-gamut or not).
 * The alpha group is optional; its absence means fully opaque (alpha 1), same convention as an
 * omitted 4th channel in the CSS spec itself. */
const LEGACY_RGB_FUNCTION = /^rgba?\(\s*[\d.]+%?\s*,\s*[\d.]+%?\s*,\s*[\d.]+%?\s*(?:,\s*([\d.]+%?)\s*)?\)$/;

/** A CSS Color 4 functional notation — `oklch()`, `oklab()`, `lab()`, `lch()`, `hwb()`,
 * `color(...)`, or the modern space/slash form of `rgb()`/`hsl()` (A7 false-refusal fix, fourth
 * adversarial round: confirmed by direct probe against real Chromium — a `background-color`
 * authored in `oklch()`/`lab()`/`color(display-p3 ...)` is serialised back in that SAME function
 * notation, never converted to `rgb()`, even for a colour fully inside the sRGB gamut; Tailwind
 * v4's entire default palette, and any design-system token authored this way, trips this). The
 * only thing this module needs from any of these is the trailing `/ <alpha>` CSS Color 4 slash
 * syntax — every one of these functions can end in `/ <alpha-value>` right before the closing
 * paren, and every component before it (`L`/`C`/`H`, a colour-space keyword, `none` for a missing
 * component) is irrelevant to occlusion, which only ever cares about alpha. An explicit `none`
 * alpha component is deliberately NOT matched by the capture group below — a rare, exotic shape
 * whose actually-rendered alpha this module has not verified, so per "only ever refuse more" it
 * falls through unmatched and refuses, rather than guessing at a value it is not sure of. No
 * alpha segment at all (no `/`) means fully opaque, same convention as {@link LEGACY_RGB_FUNCTION}
 * and the CSS spec's own default. */
const MODERN_COLOR_FUNCTION = /^(?:rgba?|hsla?|hwb|lab|lch|oklab|oklch|color)\([^/)]*(?:\/\s*([\d.]+%?)\s*)?\)$/i;

/**
 * Whether a top-layer element's own `::backdrop` pseudo-element visually occludes whatever is
 * behind it: `backgroundImage` anything other than `"none"` (an image backdrop; conservatively
 * always occluding, since this cannot know the image's own transparency), or `backgroundColor`'s
 * alpha channel above {@link BACKDROP_ALPHA_THRESHOLD}. `backgroundColor` is matched against
 * {@link LEGACY_RGB_FUNCTION} first, then {@link MODERN_COLOR_FUNCTION} — a value neither
 * recognises refuses rather than guesses ("only ever refuse more," matching
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
  const match = LEGACY_RGB_FUNCTION.exec(bg) ?? MODERN_COLOR_FUNCTION.exec(bg);
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
