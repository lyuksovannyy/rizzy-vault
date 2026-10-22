// SPDX-License-Identifier: AGPL-3.0-only

// A small, seeded, deterministic PRNG for the fuzz harnesses (`clickjacking-fuzz.spec.ts`,
// `apps/extension/test/messaging-fuzz.test.ts`) — no new npm package, and `Math.random()` is
// not reproducible, which minimisation (re-running one failing seed in isolation) needs.
// mulberry32: public-domain, widely used for exactly this (small state, good-enough statistical
// quality for test-case generation, not cryptographic use).
export type Rng = () => number;

export function mulberry32(seed: number): Rng {
  let a = seed >>> 0;
  return function next(): number {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Integer in `[min, maxInclusive]`. */
export function intBetween(rng: Rng, min: number, maxInclusive: number): number {
  return min + Math.floor(rng() * (maxInclusive - min + 1));
}

/** Float in `[min, max)`. */
export function floatBetween(rng: Rng, min: number, max: number): number {
  return min + rng() * (max - min);
}

export function pick<T>(rng: Rng, options: readonly T[]): T {
  if (options.length === 0) {
    throw new Error("prng: pick from an empty array");
  }
  const index = intBetween(rng, 0, options.length - 1);
  // Safe: index is within [0, length - 1] by construction, noUncheckedIndexedAccess notwithstanding.
  return options[index] as T;
}

export function chance(rng: Rng, probabilityTrue: number): boolean {
  return rng() < probabilityTrue;
}

/** A deterministic 32-bit seed derived from a run id and a case index, so a nightly run's
 * `RIZZY_FUZZ_SEED_START` plus loop index always reproduces the same case for minimisation. */
export function deriveSeed(runSeed: number, caseIndex: number): number {
  return (Math.imul(runSeed ^ 0x9e3779b9, 0x85ebca6b) + caseIndex * 0x27d4eb2d) >>> 0;
}
