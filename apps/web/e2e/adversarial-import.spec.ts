// SPDX-License-Identifier: AGPL-3.0-only

// Adversarial import sweep (threat model A16, A14, A8/A1; THREAT_MODEL.md §7.1, §7.7; INV-35,
// INV-42, INV-49, INV-68; CRYPTO.md §11.4). Generates hostile import files for every supported
// importer with an XSS/injection corpus in every field, imports them into a real server
// (`server.ts`), visits every resulting view, and asserts the security invariants hold — not
// the implementation's current behaviour (`oracles.ts`'s module docs).
//
// Budgets, mirroring `rizzy-sync`'s convergence suite (`crates/rizzy-sync/src/convergence/
// generate.rs`, `Seeds::Fixed`/`Seeds::Fresh`): `adversarial import sweep (PR budget)` runs on
// two small, literal seeds and stays under the file's own `test.setTimeout` well inside a
// minute; `nightly adversarial import sweep` is skipped unless `RIZZY_NIGHTLY` is set, draws a
// fresh seed from the clock (or `RIZZY_NIGHTLY_SEED` for a reproducible rerun), and covers more
// formats and payloads per run. Running it 20+ times with `RIZZY_NIGHTLY=1` (a fresh seed each
// time) is this harness's "scale run": each invocation stays small; breadth comes from running
// it repeatedly, not from one unbounded run (real browser cycles do not scale the way the
// convergence suite's in-process simulations do).
//
// Positive control: `apps/web/test/attack-oracles.test.ts` feeds every oracle a hand-built bad
// `Snapshot` and asserts it is flagged — proof this harness can detect what it is looking for,
// not only that today's app happens to pass it.
import { type Page, expect, test } from "@playwright/test";

import { PASSWORD, signUp, watch } from "./helpers.ts";
import { type RunningServer, startServer } from "./server.ts";
import type { AttackCase } from "./attack/hostile-imports.ts";
import { type ImportFormatId, buildHostileFile } from "./attack/hostile-imports.ts";
import { importAndSweep, visitTag } from "./attack/flows.ts";
import { checkAll, checkOversizedHandling, type Violation } from "./attack/oracles.ts";
import { OVERSIZED_PAYLOADS, SINK_PAYLOADS, TAG_SAFE_PAYLOADS, URI_PAYLOADS } from "./attack/payloads.ts";
import { freshSeed, mulberry32, pick, PR_SEEDS } from "./attack/rng.ts";
import { captureScriptBaseline, collectHeaders, collectStorage, installTripwire, pageIsResponsive } from "./attack/snapshot.ts";

/** Builds the `(field, payload)` cases for one format from a seeded RNG: `sinkFields` get one
 * sink/injection payload each (picked by the RNG, so which payload lands on which field varies
 * seed to seed while staying small), the `uri` field gets `uriCount` URI-scheme payloads, and
 * `tag` gets one tag-safe payload. `extra` sink payloads (beyond one per field) are spread
 * across `title` for breadth without adding fields. */
function buildCases(
  rand: () => number,
  uriCount: number,
  extraTitlePayloads: number,
): AttackCase[] {
  const fields: AttackCase["field"][] = ["title", "username", "notes", "customName", "customValue", "totp"];
  const sinkPicks = pick(rand, SINK_PAYLOADS, fields.length + extraTitlePayloads);
  const cases: AttackCase[] = fields.map((field, i) => ({ field, payload: sinkPicks[i]! }));
  for (let i = 0; i < extraTitlePayloads; i++) {
    cases.push({ field: "title", payload: sinkPicks[fields.length + i]! });
  }
  for (const payload of pick(rand, URI_PAYLOADS, uriCount)) {
    cases.push({ field: "uri", payload });
  }
  const tagPayload = pick(rand, TAG_SAFE_PAYLOADS, 1)[0];
  if (tagPayload !== undefined) {
    cases.push({ field: "tag", payload: tagPayload });
  }
  return cases;
}

/** One run: signs up, imports a hostile file per format, sweeps every item and tag, then
 * checks storage and headers. Returns every oracle violation, with enough context (format,
 * counts) to triage without re-running. */
async function runSweep(
  page: Page,
  origin: string,
  formats: readonly ImportFormatId[],
  seed: number,
  uriCount: number,
  extraTitlePayloads: number,
): Promise<{ violations: Violation[]; detail: string[] }> {
  const rand = mulberry32(seed);
  await installTripwire(page);
  const secretKey = await signUp(page, origin, `atk${seed.toString(16)}`);
  const baseline = await captureScriptBaseline(page);
  const detail: string[] = [];
  const violations: Violation[] = [];
  const secrets = [PASSWORD, secretKey, "correct-horse-battery"];

  for (const format of formats) {
    const cases = buildCases(rand, uriCount, extraTitlePayloads);
    const file = buildHostileFile(format, cases);
    const { report, visited, missing, sinks, links } = await importAndSweep(page, baseline, file);
    detail.push(
      `${format}: ${report.report ?? `refused (${report.code ?? "?"})`}, visited ${visited}/${cases.length}, missing ${missing.length}`,
    );
    // Non-vacuity guards: a run that imports nothing or visits nothing must fail loudly, never
    // pass as "no violations found" — the harness looked at nothing, which is not the same
    // claim as "looked and found nothing clean".
    if (report.report === undefined) {
      violations.push({
        oracle: "harness: import refused",
        detail: `${format}: the import was refused (code=${report.code ?? "?"}), so nothing was swept`,
      });
    }
    if (visited === 0 && cases.length > 0) {
      violations.push({
        oracle: "harness: zero items visited",
        detail: `${format}: 0 of ${cases.length} cases were visited (all missing or the import was refused)`,
      });
    }
    if (visited + missing.length !== cases.length) {
      violations.push({
        oracle: "harness: accounting mismatch",
        detail: `${format}: visited (${visited}) + missing (${missing.length}) != cases (${cases.length})`,
      });
    }
    violations.push(
      ...sinks.map((h) => ({ oracle: "INV-35 sink-fingerprint", detail: `${format}: <${h.tag}> ${h.descriptor}` })),
      ...links
        .filter((l) => l.protocol !== "http:" && l.protocol !== "https:")
        .map((l) => ({ oracle: "INV-42 uri-scheme", detail: `${format}: ${l.protocol} ${l.descriptor}` })),
    );
    const tagCase = cases.find((c) => c.field === "tag");
    if (tagCase !== undefined) {
      const tagResult = await visitTag(page, baseline, tagCase.payload.value.slice(0, 20));
      violations.push(
        ...tagResult.sinks.map((h) => ({
          oracle: "INV-35 sink-fingerprint",
          detail: `${format} tag sidebar: <${h.tag}> ${h.descriptor}`,
        })),
      );
    }
  }

  const tripwireHit = await page.evaluate(() => (window as unknown as { __rzxHit: boolean }).__rzxHit);
  if (tripwireHit) {
    violations.push({ oracle: "INV-35 tripwire", detail: "window.__rzxHit was set during the sweep" });
  }

  const storage = await collectStorage(page);
  violations.push(
    ...checkAll(
      {
        links: [],
        sinkHits: [],
        tripwireHit: false,
        cspViolations: [],
        secretFields: [],
        storage,
        headers: [],
        oversizedImportCrashed: false,
      },
      secrets,
      ["theme"],
    ),
  );

  const headers = await collectHeaders(page, origin, ["/", "/index.html"]);
  violations.push(
    ...checkAll(
      {
        links: [],
        sinkHits: [],
        tripwireHit: false,
        cspViolations: [],
        secretFields: [],
        storage: [],
        headers,
        oversizedImportCrashed: false,
      },
      [],
    ),
  );

  return { violations, detail };
}

/** The oversized-value case (A16 "parser DoS" read narrowly, module docs): one item whose
 * `item.notes` is far past `MAX_TEXT_LEN`. The oracle is only that the import finishes and the
 * page stays responsive, never a hang or a crash. */
async function runOversized(page: Page, origin: string, seed: number): Promise<Violation[]> {
  await installTripwire(page);
  await signUp(page, origin, `ovsz${seed.toString(16)}`);
  const cases: AttackCase[] = OVERSIZED_PAYLOADS.map((payload) => ({ field: "notes", payload }));
  const file = buildHostileFile("rizzy-json", cases);
  await importAndSweep(page, [], file);
  const responsive = await pageIsResponsive(page, 10_000);
  return checkOversizedHandling({
    links: [],
    sinkHits: [],
    tripwireHit: false,
    cspViolations: [],
    secretFields: [],
    storage: [],
    headers: [],
    oversizedImportCrashed: !responsive,
  });
}

test.describe("adversarial import sweep (PR budget)", () => {
  test.setTimeout(60_000);

  let server: RunningServer;
  test.beforeAll(async () => {
    server = await startServer();
  });
  test.afterAll(() => server.stop());

  test("hostile Bitwarden JSON and rizzy-json imports leave no sink, bad link or leaked secret", async ({
    browser,
  }) => {
    const page = await browser.newPage();
    const { problems } = watch(page);
    const seed = PR_SEEDS[0]!;
    const { violations, detail } = await runSweep(page, server.origin, ["rizzy-json", "bitwarden-json"], seed, 2, 0);
    expect(violations, `${detail.join("; ")}\n${JSON.stringify(violations, null, 2)}`).toEqual([]);
    expect(problems, problems.join("\n")).toEqual([]);
    await page.close();
  });

  test("an oversized field is rejected cleanly, no hang, no crash", async ({ browser }) => {
    const page = await browser.newPage();
    const violations = await runOversized(page, server.origin, PR_SEEDS[1]!);
    expect(violations).toEqual([]);
    await page.close();
  });
});

test.describe("nightly adversarial import sweep", () => {
  test.skip(
    process.env["RIZZY_NIGHTLY"] === undefined,
    "nightly budget: broader format/payload coverage on a fresh (or RIZZY_NIGHTLY_SEED-pinned) seed; " +
      "run this repeatedly (20+ times) with RIZZY_NIGHTLY=1 for the harness's scale run, " +
      "not once with a huge case count (real browser cycles, unlike the convergence suite's in-" +
      "process simulations, do not scale that way).",
  );
  test.setTimeout(8 * 60_000);

  let server: RunningServer;
  test.beforeAll(async () => {
    server = await startServer();
  });
  test.afterAll(() => server.stop());

  test("a fresh-seed sweep over a random subset of formats finds no violation", async ({ browser }) => {
    const seedEnv = process.env["RIZZY_NIGHTLY_SEED"];
    const seed = seedEnv !== undefined ? Number.parseInt(seedEnv, 10) : freshSeed(0);
    const rand = mulberry32(seed);
    const allFormats: readonly ImportFormatId[] = [
      "bitwarden-json",
      "1pux",
      "keepass-xml",
      "chrome-csv",
      "firefox-csv",
      "csv",
      "aliasvault-csv",
      "aliasvault-avux",
      "rizzy-json",
    ];
    const formats = pick(rand, allFormats, 3);
    const page = await browser.newPage();
    const { problems } = watch(page);
    const { violations, detail } = await runSweep(page, server.origin, formats, seed, 4, 2);
    expect(
      violations,
      `seed=0x${seed.toString(16)} formats=${formats.join(",")}\n${detail.join("; ")}\n${JSON.stringify(violations, null, 2)}`,
    ).toEqual([]);
    expect(problems, problems.join("\n")).toEqual([]);
    await page.close();
  });

  test("a fresh-seed oversized-value import is rejected cleanly", async ({ browser }) => {
    const seed = freshSeed(1);
    const page = await browser.newPage();
    const violations = await runOversized(page, server.origin, seed);
    expect(violations, `seed=0x${seed.toString(16)}`).toEqual([]);
    await page.close();
  });
});

