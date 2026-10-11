// SPDX-License-Identifier: AGPL-3.0-only

// Combinatorial generator for `clickjacking-fuzz.spec.ts` (THREAT_MODEL.md A7; INV-36/INV-37/
// INV-40; HANDOFF X6 residual-risk log in A7). Produces a random composition of hostile-page
// techniques from THREAT_MODEL.md's own A7 "Capabilities" list and the residual-risk log's
// reported-bypass classes, parameterised and seeded (`prng.ts`) so any case is reproducible
// from its seed alone for minimisation. This module only builds DOM/CSS state on a `Page`; the
// spec file owns screenshotting, clicking and the pixel oracle.
//
// Every trick here targets either the real inline-menu `<iframe data-rizzy-inline-menu>` or an
// ancestor of it (`document.documentElement`), using the SAME CSS properties and DOM shapes
// `adversarial-fill-requests.spec.ts`'s hand-written tests already use (`setIframeStyle`,
// `plantNestedDecoy`, the box-shadow/backdrop tests) — this harness's job is to COMPOSE and
// RANDOMISE parameters across that space at scale, not invent a new attack surface.
import type { Page } from "@playwright/test";

import { type Rng, chance, floatBetween, intBetween, mulberry32, pick } from "./prng.ts";

export interface Rect {
  readonly x: number;
  readonly y: number;
  readonly width: number;
  readonly height: number;
}

const MENU_SELECTOR = "iframe[data-rizzy-inline-menu]";

/** A CSS declaration that, applied alone and persistently to its target with no decoy behind
 * it, makes that target (or whatever it occludes) stop painting visibly. Pulled directly from
 * THREAT_MODEL.md A7's own technique list: "box-shadow/outline/filters/pseudo-elements". */
const ERASING_DECLARATIONS: ReadonlyArray<{ readonly property: string; readonly value: string; readonly validAncestorTarget: boolean }> = [
  { property: "opacity", value: "0", validAncestorTarget: true },
  { property: "visibility", value: "hidden", validAncestorTarget: true },
  { property: "filter", value: "opacity(0)", validAncestorTarget: true },
  { property: "filter", value: "brightness(0)", validAncestorTarget: true },
  { property: "filter", value: "contrast(0)", validAncestorTarget: true },
  { property: "filter", value: "blur(40px)", validAncestorTarget: true },
  { property: "clip-path", value: "inset(100%)", validAncestorTarget: false },
  { property: "clip-path", value: "circle(0 at 50% 50%)", validAncestorTarget: false },
  { property: "mask-image", value: "linear-gradient(rgba(0,0,0,0), rgba(0,0,0,0))", validAncestorTarget: false },
  { property: "content-visibility", value: "hidden", validAncestorTarget: true },
];

export type PaintMethod = "style-tag" | "insert-rule" | "adopted-stylesheet" | "disabled-flip";

export interface PaintTrick {
  readonly kind: "paint";
  readonly target: "iframe" | "ancestor";
  readonly property: string;
  readonly value: string;
  readonly method: PaintMethod;
}

export interface DecoyTrick {
  readonly kind: "decoy";
  readonly nesting: 0 | 1 | 2;
  readonly wrapper: "plain-div" | "shadow-open";
  readonly busyLoopMs: number;
  readonly color: string;
}

export interface TopLayerTrick {
  readonly kind: "top-layer";
  readonly element: "dialog" | "popover";
  readonly boxShadowCss: string;
  readonly backdropAlpha: number;
  readonly color: string;
}

export type Trick = PaintTrick | DecoyTrick | TopLayerTrick;

export interface AmbientState {
  readonly zoom: number;
  readonly scrollX: number;
  readonly scrollY: number;
}

export interface FuzzCase {
  readonly seed: number;
  readonly ambient: AmbientState;
  readonly tricks: readonly Trick[];
  readonly summary: string;
}

function randomColor(rng: Rng): string {
  const r = intBetween(rng, 0, 255);
  const g = intBetween(rng, 0, 255);
  const b = intBetween(rng, 0, 255);
  return `rgb(${r}, ${g}, ${b})`;
}

function randomPaintTrick(rng: Rng): PaintTrick {
  const decl = pick(rng, ERASING_DECLARATIONS);
  const target = decl.validAncestorTarget && chance(rng, 0.5) ? "ancestor" : "iframe";
  const method = pick(rng, ["style-tag", "insert-rule", "adopted-stylesheet", "disabled-flip"] as const);
  return { kind: "paint", target, property: decl.property, value: decl.value, method };
}

function randomDecoyTrick(rng: Rng): DecoyTrick {
  return {
    kind: "decoy",
    nesting: pick(rng, [0, 1, 2] as const),
    wrapper: pick(rng, ["plain-div", "shadow-open"] as const),
    // 0 = no stall; up to 700ms mirrors the longest reproduced busy-loop in THREAT_MODEL.md's
    // A7 residual-risk log (the second adversarial round's "700ms stall ... comfortably under
    // the 1-second trailing window").
    busyLoopMs: chance(rng, 0.6) ? intBetween(rng, 20, 700) : 0,
    color: randomColor(rng),
  };
}

/** Random `box-shadow`, sometimes multiple comma-separated layers and sometimes `inset` (which
 * must NOT extend the occlusion, unlike the others) — the exact shape class THREAT_MODEL.md's
 * A7 log says the real parser (`parseBoxShadowMarginPx`) was built to handle after the "1x1
 * popover with an oversized box-shadow" reports. */
function randomBoxShadow(rng: Rng): string {
  const layerCount = chance(rng, 0.3) ? 2 : 1;
  const layers: string[] = [];
  for (let i = 0; i < layerCount; i += 1) {
    const inset = chance(rng, 0.2) ? "inset " : "";
    const offsetX = intBetween(rng, -20, 20);
    const offsetY = intBetween(rng, -20, 20);
    const blur = intBetween(rng, 0, 60);
    const spread = intBetween(rng, 0, 3000);
    layers.push(`${inset}${offsetX}px ${offsetY}px ${blur}px ${spread}px ${randomColor(rng)}`);
  }
  return layers.join(", ");
}

function randomTopLayerTrick(rng: Rng): TopLayerTrick {
  return {
    kind: "top-layer",
    element: pick(rng, ["dialog", "popover"] as const),
    boxShadowCss: randomBoxShadow(rng),
    // Straddles the real alpha threshold (0.05, `isBackdropOccluding`) on purpose: some cases
    // should NOT occlude (just under it), most should.
    backdropAlpha: floatBetween(rng, 0, 0.6),
    color: randomColor(rng),
  };
}

/** `zoom` is deliberately excluded (fixed at 1), matching a documented decision already in this
 * codebase (`adversarial-fill-requests.spec.ts`'s own "a scrolled page still fills normally"
 * test doc): CSS `zoom` is a non-standard Blink/WebKit property whose effect on the coordinate
 * space `getBoundingClientRect()`/`elementFromPoint`/`page.mouse.click` agree on, in headless
 * Chromium under Playwright's own CDP-driven input, disagrees with itself — this harness
 * independently reproduced that exact mismatch while building this file (seed 7 of an early
 * run: `elementFromPoint` at the computed centre of a zoomed iframe's own reported
 * `getBoundingClientRect()` returned `<html>`, not the iframe), which is a TEST-METHODOLOGY
 * artifact of automating zoom, not a property of the real extension or a real pinch-zoomed
 * user's click. Real page-scale pinch-zoom has no reliable Playwright control either, per the
 * same precedent.
 *
 * An ancestor `transform` is ALSO excluded here (it stayed combinable with the paint tricks'
 * own `target: "ancestor"` case, so the trick space still covers it, just not as a free-standing
 * ambient dimension): the spec file's pixel oracle compares each case's single screenshot
 * against ONE reference captured once per session (see its own module doc for why — repeated
 * `page.screenshot()` calls interspersed with waits were found, empirically, to perturb the
 * real extension's own `requestAnimationFrame`-based visibility sampling under load, so the
 * harness takes at most one screenshot per case). A `transform` can change the frozen rect's own
 * `width`/`height` (a rotated axis-aligned bounding box grows), which would make that
 * single-reference comparison invalid for exactly the cases that use it. Scrolling has no such
 * problem (`getBoundingClientRect()` for the `position: fixed` menu iframe is scroll-invariant,
 * confirmed empirically), so it stays as a free-standing ambient dimension. */
function randomAmbient(rng: Rng): AmbientState {
  const scrolled = chance(rng, 0.3);
  return {
    zoom: 1,
    scrollX: scrolled ? intBetween(rng, 0, 400) : 0,
    scrollY: scrolled ? intBetween(rng, 0, 400) : 0,
  };
}

/** Builds one reproducible case from `seed`. 0-2 tricks are composed (0 is a deliberate benign
 * control: ambient-only, no occlusion at all — a fill must then always succeed). */
export function generateCase(seed: number): FuzzCase {
  const rng = mulberry32(seed);
  const trickCount = chance(rng, 0.12) ? 0 : chance(rng, 0.65) ? 1 : 2;
  const tricks: Trick[] = [];
  for (let i = 0; i < trickCount; i += 1) {
    const family = pick(rng, ["paint", "decoy", "top-layer"] as const);
    if (family === "paint") {
      tricks.push(randomPaintTrick(rng));
    } else if (family === "decoy") {
      tricks.push(randomDecoyTrick(rng));
    } else {
      tricks.push(randomTopLayerTrick(rng));
    }
  }
  const ambient = randomAmbient(rng);
  const summary = tricks.length === 0 ? "benign (ambient only)" : tricks.map((t) => JSON.stringify(t)).join(" + ");
  return { seed, ambient, tricks, summary: `${summary} | ambient=${JSON.stringify(ambient)}` };
}

export async function applyAmbient(page: Page, ambient: AmbientState): Promise<void> {
  await page.evaluate((a) => {
    document.documentElement.style.setProperty("zoom", String(a.zoom));
    window.scrollTo(a.scrollX, a.scrollY);
  }, ambient);
}

/** Applies every trick in `tricks` to the page. For a `paint` trick using `disabled-flip`, the
 * hostile rule starts DISABLED (menu visible) and the page itself flips it on/off on a short
 * self-contained schedule (THREAT_MODEL.md A7 log: "flip-visible-for-the-click, flip-back-after"),
 * so the spec file's own click/sample timing does not have to be synchronised with it — across
 * many seeds, the fixed sampling sweep lands at many different phases of the flip. */
export async function applyTricks(page: Page, rect: Rect, tricks: readonly Trick[]): Promise<void> {
  for (const trick of tricks) {
    if (trick.kind === "paint") {
      await applyPaintTrick(page, trick);
    } else if (trick.kind === "decoy") {
      await applyDecoyTrick(page, rect, trick);
    } else {
      await applyTopLayerTrick(page, rect, trick);
    }
  }
}

async function applyPaintTrick(page: Page, trick: PaintTrick): Promise<void> {
  const selector = trick.target === "iframe" ? MENU_SELECTOR : "html";
  const rule = `${selector} { ${trick.property}: ${trick.value} !important; }`;
  if (trick.method === "style-tag") {
    await page.addStyleTag({ content: rule });
    return;
  }
  await page.evaluate(
    ({ rule, method }) => {
      if (method === "insert-rule") {
        if (document.styleSheets.length === 0) {
          document.head.appendChild(document.createElement("style"));
        }
        const activeSheet = document.styleSheets[document.styleSheets.length - 1];
        activeSheet?.insertRule(rule, activeSheet.cssRules.length);
        return;
      }
      if (method === "adopted-stylesheet") {
        const sheet = new CSSStyleSheet();
        sheet.replaceSync(rule);
        document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet];
        return;
      }
      // disabled-flip: starts disabled (menu visible), then flips on a short, page-owned
      // schedule — see this function's own doc.
      const styleEl = document.createElement("style");
      styleEl.textContent = rule;
      styleEl.disabled = true;
      document.head.appendChild(styleEl);
      const onDelayMs = 40 + Math.floor(Math.random() * 120);
      const offDelayMs = onDelayMs + 30 + Math.floor(Math.random() * 150);
      setTimeout(() => {
        styleEl.disabled = false;
      }, onDelayMs);
      setTimeout(() => {
        styleEl.disabled = true;
      }, offDelayMs);
      setTimeout(() => {
        styleEl.disabled = false;
      }, offDelayMs + 120);
    },
    { rule, method: trick.method },
  );
}

async function applyDecoyTrick(page: Page, rect: Rect, trick: DecoyTrick): Promise<void> {
  await page.evaluate(
    ({ rect, trick }) => {
      const style: Record<string, string> = {
        position: "fixed",
        left: `${rect.x}px`,
        top: `${rect.y}px`,
        width: `${rect.width}px`,
        height: `${rect.height}px`,
        zIndex: "2147483647",
        background: trick.color,
        pointerEvents: "none",
      };
      const decoy = document.createElement("div");
      decoy.className = "rizzy-fuzz-decoy";
      Object.assign(decoy.style, style);

      let mountPoint: Element | ShadowRoot = document.body;
      for (let depth = 0; depth < trick.nesting; depth += 1) {
        if (trick.wrapper === "shadow-open") {
          const host = document.createElement("div");
          host.className = "rizzy-fuzz-decoy-host";
          const root = host.attachShadow({ mode: "open" });
          mountPoint.appendChild(host);
          mountPoint = root;
        } else {
          const wrapper = document.createElement("div");
          wrapper.className = "rizzy-fuzz-decoy-wrapper";
          mountPoint.appendChild(wrapper);
          mountPoint = wrapper;
        }
      }

      const runInsertion = (): void => {
        mountPoint.appendChild(decoy);
      };

      if (trick.busyLoopMs > 0) {
        // The decoy insertion and the busy-loop run in the SAME synchronous call stack
        // (THREAT_MODEL.md A7 log: "a synchronous main-thread busy-loop in the SAME call stack
        // as the decoy's own insertion"), so the content script's mutation handling cannot run
        // between them.
        runInsertion();
        const until = performance.now() + trick.busyLoopMs;
        while (performance.now() < until) {
          // Deliberately busy: denies the microtask/macrotask queue any turn.
        }
      } else {
        runInsertion();
      }
    },
    { rect, trick },
  );
}

async function applyTopLayerTrick(page: Page, rect: Rect, trick: TopLayerTrick): Promise<void> {
  await page.evaluate(
    ({ rect, trick }) => {
      const id = "rizzy-fuzz-top-layer";
      const style = document.createElement("style");
      style.textContent = `
        #${id} { box-shadow: ${trick.boxShadowCss}; background: ${trick.color}; }
        #${id}::backdrop { background: rgba(0, 0, 0, ${trick.backdropAlpha}); }
      `;
      document.head.appendChild(style);

      if (trick.element === "dialog") {
        const dialog = document.createElement("dialog");
        dialog.id = id;
        dialog.style.position = "fixed";
        dialog.style.left = `${rect.x}px`;
        dialog.style.top = `${rect.y}px`;
        dialog.style.width = "4px";
        dialog.style.height = "4px";
        dialog.style.padding = "0";
        dialog.style.margin = "0";
        document.body.appendChild(dialog);
        dialog.showModal();
      } else {
        const el = document.createElement("div");
        el.id = id;
        el.setAttribute("popover", "manual");
        el.style.position = "fixed";
        el.style.left = `${rect.x}px`;
        el.style.top = `${rect.y}px`;
        el.style.width = "1px";
        el.style.height = "1px";
        el.style.padding = "0";
        el.style.margin = "0";
        el.style.border = "none";
        document.body.appendChild(el);
        el.showPopover();
      }
    },
    { rect, trick },
  );
}
