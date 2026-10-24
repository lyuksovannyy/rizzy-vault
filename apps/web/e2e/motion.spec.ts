// SPDX-License-Identifier: AGPL-3.0-only

// The motion system end to end (docs/design/README.md "Motion" and "Accessibility"; ROADMAP §4.5):
//
// - the motion tokens exist in the served CSS, with the limits `cargo xtask generate-tokens`
//   enforces (no duration over 5 s, a short reduced-motion crossfade);
// - with motion allowed, the main surfaces do animate on those tokens (a dialog pops in for
//   --motion-duration-base), so the reduced-motion check below is not passing vacuously;
// - with `prefers-reduced-motion: reduce` (WCAG 2.3.3), walking the same surfaces starts no
//   animation or transition longer than --motion-duration-reduced, none with a delay (no
//   stagger), none that loops, and every distance and scale token is a no-op.
//
// Every animation and transition the page starts is recorded from its `animationstart` /
// `transitionrun` event with the computed timing of its target, so short-lived ones that end
// between two Playwright steps are not missed.
import { type Page, expect, test } from "@playwright/test";

import { settleAnimations } from "./a11y.ts";
import { dismissToasts, lockVault, newItem, signUp, watch } from "./helpers.ts";
import { type RunningServer, startServer } from "./server.ts";

let server: RunningServer;

test.beforeAll(async () => {
  server = await startServer();
});

test.afterAll(() => {
  server.stop();
});

/** One started animation or transition, as recorded in the page. */
interface Motion {
  readonly kind: "animation" | "transition";
  readonly name: string;
  readonly target: string;
  readonly durationMs: number;
  readonly delayMs: number;
  readonly iterations: string;
}

/** Installs the recorder before any page script runs. */
async function recordMotion(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const ms = (s: string): number => Math.round(s.endsWith("ms") ? parseFloat(s) : parseFloat(s) * 1000);
    const pick = (list: string, index: number): string => {
      const parts = list.split(",").map((p) => p.trim());
      return parts[index % parts.length] ?? "0s";
    };
    const describe = (el: EventTarget | null): string =>
      el instanceof Element ? `<${el.tagName.toLowerCase()} class="${el.getAttribute("class") ?? ""}">` : "?";
    const log: unknown[] = [];
    Object.defineProperty(window, "__rvMotion", { value: log });
    document.addEventListener(
      "animationstart",
      (e) => {
        if (!(e.target instanceof Element)) return;
        const style = getComputedStyle(e.target);
        const names = style.animationName.split(",").map((p) => p.trim());
        const i = Math.max(0, names.indexOf(e.animationName));
        log.push({
          kind: "animation",
          name: e.animationName,
          target: describe(e.target),
          durationMs: ms(pick(style.animationDuration, i)),
          delayMs: ms(pick(style.animationDelay, i)),
          iterations: pick(style.animationIterationCount, i),
        });
      },
      true,
    );
    document.addEventListener(
      "transitionrun",
      (e) => {
        if (!(e.target instanceof Element)) return;
        const style = getComputedStyle(e.target);
        const props = style.transitionProperty.split(",").map((p) => p.trim());
        let i = props.indexOf(e.propertyName);
        if (i < 0) i = Math.max(0, props.indexOf("all"));
        log.push({
          kind: "transition",
          name: e.propertyName,
          target: describe(e.target),
          durationMs: ms(pick(style.transitionDuration, i)),
          delayMs: ms(pick(style.transitionDelay, i)),
          iterations: "1",
        });
      },
      true,
    );
  });
}

async function recorded(page: Page): Promise<Motion[]> {
  return page.evaluate(() => (window as unknown as { __rvMotion: Motion[] }).__rvMotion.slice());
}

/** A CSS time (`150ms`, or `.15s` as the production CSS minifier writes it) in milliseconds;
 * `NaN` for anything else. */
function toMs(value: string): number {
  const m = /^(\d*\.?\d+)(ms|s)$/.exec(value);
  if (m === null) return NaN;
  return Math.round(Number(m[1]) * (m[2] === "s" ? 1000 : 1));
}

/** A root custom property's value. */
async function token(page: Page, name: string): Promise<string> {
  return page.evaluate((n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim(), name);
}

/** Walks the surfaces that animate: login, signup, the vault list, opening an item, the editor,
 * the new-item menu, the command palette, a dialog, a toast and the unlock screen. Each surface
 * is left only once its entrance has played out (`settleAnimations`), so every entrance is
 * recorded rather than cut short by the next step. */
async function walk(page: Page, name: string): Promise<void> {
  await page.goto(server.origin);
  await expect(page.getByRole("button", { name: "Create an account" })).toBeVisible();
  await signUp(page, server.origin, name);
  for (const title of ["Motion One", "Motion Two"]) {
    await newItem(page, "Login");
    await page.getByLabel("Title").fill(title);
    await page.getByLabel("Password", { exact: true }).fill(`${title}-password-long-enough`);
    await page.getByRole("button", { name: "Save" }).click();
    await expect(page.getByRole("heading", { name: title })).toBeVisible();
  }
  await page.getByRole("button", { name: /Motion One/ }).first().click();
  await expect(page.getByRole("heading", { name: "Motion One" })).toBeVisible();
  await settleAnimations(page);
  await page.getByRole("button", { name: "Edit" }).click();
  await settleAnimations(page);
  await page.getByRole("button", { name: "Cancel" }).click();
  await page.getByRole("button", { name: "New item" }).click();
  await expect(page.getByRole("menu", { name: "New item type" })).toBeVisible();
  await settleAnimations(page);
  await page.keyboard.press("Escape");
  await page.keyboard.press("Control+k");
  await expect(page.getByRole("combobox", { name: "Command palette" })).toBeVisible();
  await settleAnimations(page);
  await page.keyboard.press("Escape");
  await page.getByRole("button", { name: "Move to trash" }).click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await settleAnimations(page);
  await page.keyboard.press("Escape");
  await dismissToasts(page);
  await lockVault(page);
  await expect(page.getByRole("heading", { name: "Unlock rizzy-vault" })).toBeVisible();
}

test("motion tokens exist and stay within the motion limits", async ({ page }) => {
  await page.goto(server.origin);
  await expect(page.getByRole("button", { name: "Create an account" })).toBeVisible();
  for (const key of ["instant", "fast", "base", "slow", "shimmer", "reduced"]) {
    const value = toMs(await token(page, `--motion-duration-${key}`));
    expect(value, key).toBeGreaterThan(0);
    expect(value, key).toBeLessThanOrEqual(5000);
  }
  expect(toMs(await token(page, "--motion-duration-reduced"))).toBeLessThanOrEqual(200);
  for (const key of ["standard", "emphasized", "decelerate", "accelerate"]) {
    expect(await token(page, `--motion-easing-${key}`), key).toMatch(/^cubic-bezier\(/);
  }
  const loops = parseInt(await token(page, "--motion-loop-max-iterations"), 10);
  expect(loops).toBeGreaterThan(0);
  expect(loops * toMs(await token(page, "--motion-duration-shimmer"))).toBeLessThanOrEqual(5000);
  for (const name of ["--shadow-3", "--radius-3", "--color-surface-raised", "--color-accent-subtle"]) {
    expect(await token(page, name), name).not.toBe("");
  }
});

test("with motion allowed, the surfaces animate on the motion tokens", async ({ page }) => {
  const { problems } = watch(page);
  await recordMotion(page);
  await walk(page, "motionfull");
  const log = await recorded(page);
  const base = toMs(await token(page, "--motion-duration-base"));
  const popIns = log.filter((m) => m.kind === "animation" && m.name === "rv-pop-in");
  expect(popIns.length, JSON.stringify(log)).toBeGreaterThan(0);
  expect(popIns.some((m) => m.durationMs === base), `base ${base}: ${JSON.stringify(log.map((m) => [m.name, m.target]))}`).toBe(true);
  expect(log.some((m) => m.name === "rv-slide-in-end")).toBe(true);
  // WCAG 2.2.2 even with motion allowed: nothing loops forever or runs over 5 s.
  for (const m of log) {
    expect(m.iterations, JSON.stringify(m)).not.toBe("infinite");
    expect(m.durationMs * Math.max(1, Number(m.iterations)), JSON.stringify(m)).toBeLessThanOrEqual(5000);
  }
  expect(problems).toEqual([]);
});

test.describe("reduced motion", () => {
  test("nothing animates longer than the reduced-motion crossfade, and nothing moves", async ({ page }) => {
    const { problems } = watch(page);
    await page.emulateMedia({ reducedMotion: "reduce" });
    await recordMotion(page);
    await walk(page, "motionreduced");
    const budget = toMs(await token(page, "--motion-duration-reduced"));
    expect(budget).toBeGreaterThan(0);
    // The distance and scale tokens are no-ops, so every keyframe built on them only fades.
    for (const key of ["1", "2", "3"]) {
      expect(parseFloat(await token(page, `--motion-distance-${key}`)), key).toBe(0);
    }
    expect(Number(await token(page, "--motion-scale-enter"))).toBe(1);
    expect(Number(await token(page, "--motion-scale-press"))).toBe(1);
    expect(toMs(await token(page, "--motion-stagger-step"))).toBe(0);
    expect(toMs(await token(page, "--motion-duration-shimmer"))).toBe(0);
    const log = await recorded(page);
    expect(log.length, "the walk recorded the crossfades").toBeGreaterThan(0);
    for (const m of log) {
      expect(m.durationMs, JSON.stringify(m)).toBeLessThanOrEqual(budget);
      expect(m.delayMs, JSON.stringify(m)).toBe(0);
      expect(m.iterations, JSON.stringify(m)).toBe("1");
    }
    // And whatever is still running now is within the budget too (the Web Animations API view).
    const running = await page.evaluate(() =>
      document.getAnimations().map((a) => Number(a.effect?.getComputedTiming().duration ?? 0)),
    );
    for (const d of running) {
      expect(d).toBeLessThanOrEqual(budget);
    }
    expect(problems).toEqual([]);
  });
});
