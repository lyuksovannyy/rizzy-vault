---
name: m1-state
description: M1 progress as of 2026-09-30 — steps 1–4 done (a3fd292, 1,144 tests); step 5 (wasm + web vault) next
metadata:
  type: project
---

As of 2026-09-30 (branch claude/password-manager-planning-2gg9yc at a3fd292, nothing pushed; gate 1,144 tests): M1 steps 1–4 done. ADRs 0001–0028 all Accepted. rv CLI with ADR 0026 store, ADR 0028 transport, export/import (ADR 0027), rotation/revocation (ADR 0025), backup/restore (0023), core dumps (0024).

Next: M1 step 5 — rizzy-wasm (wasm-bindgen over rizzy-client, committed expansion baseline per ADR 0019 §4.1, getrandom wasm_js only there) and the React web vault (ADR 0014), embedded into rizzy-server's web role; OpenAPI generator decision (ADR 0028 Q4) comes with it. JS toolchain deps need justification; ADR 0014 governs.

Known gaps carried forward (not blockers): PostgreSQL restore (ADR 0023 instance lock); rv recovery complete not e2e through the binary (server has no wait setting); local cache never pruned; clipboard output; private CA for rv; password/SK change outside recovery; URI/custom-field edit of existing items; client-side restore healing and stale-epoch re-issue; KDBX and encrypted Bitwarden import (need ADR 0009 crypto approval); fuzz targets never run under cargo-fuzz (CI job after first push); App Store permission text (lawyer); regenerate canonical_header vectors.

Process: classifier blocks me accepting ADRs I drafted — owner sets Status, I mirror the index. Owner messages interrupt workflow agents. omp CLI (external reviewer) was too slow; owner dropped it. Disk is tight: clean after each integration.

**Why:** continuity. **How to apply:** start step 5 when the owner says go. See [[harness-quirks]], [[code-first-parallel-docs]], [[owner-delegates-mechanics]].

## 2026-10-01 gap closing (e9c7fe7, 1,185 tests passing, 8 ignored)
Committed: f95698c ADR 0029 KDBX draft (Proposed; owner must accept or move KDBX out of M1), 59836bc server gaps (PG instance lock, RIZZY_RECOVERY_WAIT_HOURS, TOTP re-seal), 8b2b5d2 vectors over real headers + harness seals envelopes, f64f094 password/SK change + rv 2fa + recovery e2e, e9c7fe7 list editing + vault restore healing + stale-epoch + cache pruning.
Still open: https/private CA (TLS crates need ADR 0009), clipboard (needs crate), account-side healing (ADR 0012 §7 steps 1-3) and post-backup devices, OPAQUE old-setup removal (CRYPTO §5.8 step 4 not concrete), full rotation + SK change combo, list reorder, fuzz CI run after push.

## 2026-10-01 step 5 + gaps (71769b4)
fe16a06 ADRs 0030 (client TLS for rv) and 0031 (retire old OPAQUE setups) Proposed; 02904f2 account-side healing (rotation after backup NOT healable: needs ADR for E_id re-publication); c24dc19 list reorder + SK change with full rotation; 71769b4 rizzy-wasm + packages/core + packages/ui + apps/web, embed-web, .cargo/config.toml check-wasm alias extended (ADR 0016 R1 requires it).
Open: CI jobs for pnpm/wasm/baseline (.github off limits), container image build not run, wasm-bindgen-test crates need approval, wasm size budget (1.92 MB), e2e test a_gateway_error_on_a_commit_keeps_what_was_saved_for_it flaky under full-workspace load. Gotcha: `git stash -u` also stashes .gitignore edits → `git add -A` then sweeps node_modules; stage explicit paths.

## 2026-10-05 (cd1c1ae)
e60d7be ADR 0030 accepted (owner, all recommendations); 69f0c94 ADRs 0032 (heal post-backup rotation) + 0033 (protobuf server<->client API; recommends JSON-only for now with trigger) Proposed; c011f5f rv TLS 1.3 (tokio-rustls, webpki-roots, --ca-file replaces roots, CA must be cA=true); cd1c1ae owner export flow (re-auth before every export, file password twice, format auto-detect on import, 10 s plaintext hold + ADR 0027 typed phrase).
Owner note: "protobuf between clients" meant server<->client, not peer-to-peer.
Open: ADR 0030 Decision 5 wording (webpki does accept self-signed cA=false; rv now refuses non-CA certs) needs a correcting ADR; ADR 0027 note for re-auth/hold; THREAT_MODEL AST-20 line; gate scripts must not pipe through awk (masks exit codes) and must not exceed the 10-min background limit — split cargo and JS.

## 2026-10-05 later (dd037d3, local, 75 commits ahead of origin/main, none signed off)
847bd11 accept 0029/0031/0032 (pushed); 56ca695 + 88b6f92 propose/accept 0034 (export re-auth + hold, supersedes 0027 §5 in part) and 0035 (CA file cA=true only, supersedes 0030 D5 in part); dd037d3 ADR 0031+0032 code + rv lock retry (flock shared with spawned children caused InUse flake).
Open: ADR 0031 has no rule to complete a pending credential change whose own setup was retired (rv keeps it, SetupRetired) — needs an ADR. Merge to main: owner must run `git rebase --signoff origin/main` (DCO, ADR 0017); then I ff main and push (owner asked). ci.yml runs only on main/PR/dispatch; no gh CLI locally.
Disk: macOS update snapshots (MSUPrepareUpdate) eat space; workflow output files can come out empty on ENOSPC — read journal.jsonl. Use mcp__terminal__run_in_terminal when Bash can't write its output file.

## 2026-10-06: merged. Owner ran git rebase --signoff; main and branch pushed at 31a1579 (content = dd037d3). CI on main runs from now; first image/web/fuzz results pending.

## 2026-10-06 owner tried the web vault: not daily-usable (UI, generator options, no URI/custom-field editing, no AliasVault import, no passkeys); guesses M3 is needed for daily use. d561a5c adds AliasVault import to M1. Usability workflow wf_dc4a1991-115 running (wt15-rust: generator options then AliasVault; wt15-web: redesign + item editor, then generator UI). Mistake: I once ran git commit -s by accident (4a85bd6), undone with reset before push; never use -s.
