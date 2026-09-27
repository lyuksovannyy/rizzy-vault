# Handoff: continue rizzy-vault in a new session

- Written: 2026-09-27, updated at the end of the second Claude Code desktop session that day (host: the owner's Mac).
- Branch: `claude/password-manager-planning-2gg9yc`, clean at the commit that adds this file. Nothing is on `main`, no PR exists, and nothing from 2026-09-26/27 has been pushed.
- Read this file, then [CLAUDE.md](../CLAUDE.md), then [ROADMAP.md](ROADMAP.md) and [docs/README.md](README.md) (the documentation index). Delete this file once its "Next steps" are done (the owner asked for that).

## 1. Where things stand

| Area | State |
|---|---|
| **M0 Foundations** | Done (README.md keeps "not formally closed": no tag or "what we learned" note, ADR 0017 Proposed). |
| **M1 step 1: `rizzy-core` crypto** | **Done**, and the six follow-ups the owner approved on 2026-09-27 are applied (§4). Gate green: 397 tests, 1 ignored (the vector regenerator). |
| **ADR decisions A, B, C** | **Recorded** in ADRs 0018 and 0021 and THREAT_MODEL §9 (`c764920`). Both ADRs have no open question left. |
| **M1 steps 2–5** | Not started. Blocked only on the owner accepting the ADRs (§3). |
| **Merge spike** | `spikes/merge-model/`. Its "Results" now include ADR 0021 server properties 4 and 5 in their two-author form (`321636b`): no violation in 1,549,576 exhaustive schedules or 2.6 M random seeds. |

Commits of this session: `e5c61c2` export/backup field bounds and the `export_fields` fuzz target, `2da94de` CRYPTO.md records what the code does, `a1e24db` xtask default-features rule, `2bb4830` status text and THREAT_MODEL normative, `321636b` spike property 4/5 check, `c764920` ADR 0018/0021 decisions and AR-24 to AR-27.

## 2. Set up and gate

```sh
git checkout claude/password-manager-planning-2gg9yc
rustup toolchain install --no-self-update   # pinned 1.94.1 from rust-toolchain.toml
cargo install cargo-deny --locked
```

The gate is in [CLAUDE.md](../CLAUDE.md) "Before any push" and [CONTRIBUTING.md](../CONTRIBUTING.md). All green at `2bb4830` (later commits change only docs and the spike).

The spike is not in the gate: `cargo test --release --manifest-path spikes/merge-model/Cargo.toml`.

## 3. ADR status

Only the owner changes a `Status:` line (CLAUDE.md; the auto-mode classifier also blocks agents from doing it).

| ADR | Status | What it needs |
|---|---|---|
| 0001–0013, 0015, 0016 | Accepted | – |
| **0020** partial supersession | Proposed, no open questions | Owner accepts it first, or with 0018 and 0021, which rely on it. |
| **0014** UI stack, web platforms only | Proposed, no open questions | Owner accepts. Opens the ADR README gate for M1 server and client scaffolding. |
| **0018** item-record encoding | Proposed, no open questions (decisions 12–16 of 2026-09-27) | Owner accepts. Blocks M1 step 2. |
| **0021** server-side compaction | Proposed, no open questions (decisions 1–9 of 2026-09-27) | Owner accepts before any M1 step 3 code. Review its new **restore generation** (§2: a random 128-bit value per server database, redrawn by `rizzy-vault restore`) and the §1 table of ADR 0012 parts it supersedes. |
| 0019 native clients | Proposed, parked until M3 | Its spikes need real Windows and Linux runners. |
| 0017 licensing | Proposed, deferred by the owner | Needed before external contributions. |

## 4. Done this session, and what it left open

- **Applied** (owner-approved 2026-09-27): the CRYPTO.md readings with a §16 "Decided 2026-09-27" paragraph; the export/backup field bounds (CRYPTO.md §11.14 "Field sizes", `MAX_DATA_FIELD_LEN`) and the `export_fields` fuzz target; the xtask default-features rule; the status text; THREAT_MODEL normative.
- **Decided and recorded:** A (ADR 0018 12–15), B (ADR 0021 1–6, 9), C (THREAT_MODEL AR-24 to AR-27, revisit before M9), plus ADR 0018 decision 16: ADR 0012's snapshot-only M4 transfers (§9 pairing and re-sync, §10 switches) are left to the M4 ADR, which must decide how they meet "Snapshots are claims".
- **Left open, for later steps** (none blocks acceptance):
  - The `rizzy-server` backup reader (M1 step 3) must refuse `data` text over `MAX_DATA_FIELD_LEN` before decoding; `ServerSecretsBackupKey::open` takes bytes. The export JSON reader (M1 step 4) should also cap the whole document before parsing; CRYPTO.md does not say so yet.
  - Durable certificates with an expiry (CRYPTO.md §10.2): rizzy-core has `permits_hlc`; the `rizzy-sync` caller and the server's refusal are M1 steps 2–3.
  - The xtask rule covers ADR 0009's "Required feature sets" crates (plus hkdf), not every row of its crate table; ADR 0009 states `default-features = false` only there. Broader coverage is the owner's call.
  - Spike: in a linear history R1's "older of the two newest" clause is invisible, so only the unit test `two_author_r1_and_properties_4_and_5` pins it; a clamp-sensitive linear-history test was suggested by a reviewer and not added.
  - ADR 0019 line 525 still mentions a `cfg(test)` fixed-nonce hook, which CRYPTO.md §15 item 1 now says does not exist (0019 is parked; fix it when it is reopened).
  - ADR 0007 Decision 3 says ids 0xF0–0xFE are rejected "in release builds"; the code rejects them in every build, which is stricter and allowed.
- **Side effect to clean up:** an agent's probe `cargo +nightly fuzz --version` made rustup auto-install the nightly toolchain (~1.3 GB). cargo-fuzz is not installed. The owner can remove it with `rustup toolchain uninstall nightly`. Never probe with `cargo +<toolchain>`; use `rustup toolchain list`.

### Other open owner items

- **Generator-emitted `unsafe`** (ADR 0019 open question 2): wasm-bindgen and UniFFI glue contains `unsafe`, which `forbid(unsafe_code)` does not see. Settle it before `rizzy-wasm` (M1 step 5); ADR 0019 recommends a small separate ADR correcting ADRs 0013 and 0016.
- ADR 0019's remaining questions wait for M3.

## 5. Next steps, in order

1. **Owner accepts 0020, then 0014, 0018 and 0021** (their act: the `Status:` lines). Then record the "On acceptance" edits each ADR lists: the ADR 0012 status line and README row (owner's act), CRYPTO.md §8.4/§11.6/§15 and §10.2/§11.8 (0018 item 5, 0021 item 4), INV-14, the README index and gates, CLAUDE.md status sentences, ROADMAP "folders or tags" → tags.
2. **M1 step 2:** the item schema per ADR 0018 in `rizzy-core` (`item` module); the `rizzy-sync` record layer and engine per ADR 0012/0018 (HLC, VVs, op log, MV-register merge, tombstones, the evidence merge, strict ADR 0012 §3 header parsing before any field of a verified statement is trusted); convergence property tests seeded from `spikes/merge-model`; regenerate the statement vectors named "canonical_header" over real headers.
3. **M1 step 3:** server (ADR 0010/0011/0021, request signing, CAS with `CasRetry::Fork`/`is_fork`, the healing request and restore generation). It ships with operator docs: self-hosting, compose, and a tested backup/restore.
4. **M1 step 4:** `rizzy-client`, `rv` CLI, import, and the export JSON writer and reader, plus its fuzz target.
5. **M1 step 5:** `rizzy-wasm` and the React web vault (ADR 0014), after the generated-`unsafe` decision.
6. After pushing: trigger `.github/workflows/fuzz.yml` once by `workflow_dispatch`. No fuzz target has run in CI yet. A reviewer ran `export_fields` locally for 61 s (about 9 M inputs, coverage-guided, no sanitizer): no crash.

Each step: build → independent review → adversarial verify → fix → full gate → commit.

## 6. Working agreements and lessons

- **Rust only**, for helpers and scratch checks too, **including subagents**: say so in every agent prompt, and forbid `cargo +<toolchain>` (it auto-installs).
- **Stick to milestones.** No side quests. The owner wants blunt, critical feedback.
- **Document everything as it is built.** The `missing_docs` and `clippy::missing_docs_in_private_items` lints enforce it. Normative docs change in the same change as behaviour. Never recreate `docs/ARCHITECTURE.md`.
- **Prose reviews:** one bounded, blockers-only pass with line budgets; a blocker that needs a decision goes to the owner, not to a fixer. Settle merge semantics with the spike, not prose. Code reviews with find → verify → fix work well.
- **ADR gate:** no code without an Accepted ADR; never change a Status line; an Accepted ADR changes only by a new ADR (full, or partial under ADR 0020 once Accepted), and every superseded part is named.
- **Harness quirks:**
  - The Workflow `isolation: 'worktree'` option creates worktrees at `main`, not HEAD. Create worktrees yourself with `git worktree add --detach <dir> HEAD`, plus an APFS clone of `target/` (`cp -cR target <dir>`), and integrate with `git apply --3way`; stage a patch per item with `git apply --cached` to split commits.
  - Workflow agents were interrupted whenever the owner sent a message. Resume with `resumeFromRunId`; finished agents replay from cache.
- **Commits:** Conventional Commits, `Co-Authored-By:` trailer, never `Signed-off-by`, push only when asked, never to `main`.

## 7. Document map

- Scope: [ROADMAP.md](ROADMAP.md). Docs index: [docs/README.md](README.md). Crypto spec: [CRYPTO.md](CRYPTO.md). Threats and invariants: [THREAT_MODEL.md](THREAT_MODEL.md). Decisions: [adr/README.md](adr/README.md).
- Code docs: `cargo doc --workspace --no-deps --open`. The `rizzy-core` crate page has the module map.
- Spike results: [spikes/merge-model/README.md](../spikes/merge-model/README.md), "Results".
