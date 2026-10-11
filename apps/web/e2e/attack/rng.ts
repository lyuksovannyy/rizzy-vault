// SPDX-License-Identifier: AGPL-3.0-only

// A tiny seeded PRNG for the adversarial-import harness (`attack-corpus.ts`'s module docs):
// deterministic for the PR budget (`Seeds.Fixed`, mirroring `rizzy-sync`'s convergence suite,
// `crates/rizzy-sync/src/convergence/generate.rs`), and seeded from the clock for the nightly
// budget (`Seeds.Fresh`). No new package: this is the public-domain mulberry32 generator
// (Tommy Ettinger), ~6 lines, not worth a dependency.

/** A `[0, 1)` generator seeded by a 32-bit integer; same seed, same sequence, forever. */
export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** An integer in `[0, max)` from `rand` (a `mulberry32` instance). */
export function randInt(rand: () => number, max: number): number {
  return Math.floor(rand() * max);
}

/** Picks `count` distinct elements of `items`, in `rand`'s order (a partial Fisher-Yates). */
export function pick<T>(rand: () => number, items: readonly T[], count: number): T[] {
  const pool = [...items];
  const out: T[] = [];
  const n = Math.min(count, pool.length);
  for (let i = 0; i < n; i++) {
    const j = i + randInt(rand, pool.length - i);
    [pool[i], pool[j]] = [pool[j] as T, pool[i] as T];
    out.push(pool[i] as T);
  }
  return out;
}

/** The fixed PR-budget seeds (`Seeds.Fixed`): small, literal, reproducible. */
export const PR_SEEDS: readonly number[] = [0x5eed_0001, 0x5eed_0002];

/** A fresh seed for the nightly budget (`Seeds.Fresh`): the clock, mixed with a counter so two
 * calls in the same millisecond still differ. */
export function freshSeed(counter: number): number {
  return (Date.now() ^ Math.imul(counter + 1, 0x9e3779b9)) >>> 0;
}
