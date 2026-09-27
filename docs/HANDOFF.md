# Handoff: continue rizzy-vault in a new session

- Written: 2026-09-27, at the end of a Claude Code desktop session (host: the owner's Mac).
- Branch: `claude/password-manager-planning-2gg9yc`, clean at `f428d32`. Nothing is on `main`, no PR exists, and nothing from 2026-09-26/27 has been pushed.
- Read this file, then [CLAUDE.md](../CLAUDE.md), then [ROADMAP.md](ROADMAP.md) and [docs/README.md](README.md) (the documentation index). Delete this file once its "Next steps" are done (the owner asked for that).

## 1. Where things stand

| Area | State |
|---|---|
| **M0 Foundations** | Done. |
| **M1 step 1: `rizzy-core` crypto** | **Done.** Reviewed by 8 independent reviewers, with every finding adversarially verified (68 findings, 58 confirmed, none critical or high). All confirmed findings fixed (`2d6e7bf`). Every public and private item documented, enforced by lints (`4e1bffd`). Gate green: 388 tests, 1 ignored (the vector regenerator). |
| **M1 steps 2–5** | Not started. Blocked on ADR acceptance (§3). |
| **Merge spike** | `spikes/merge-model/` (`f428d32`): a std-only Rust model of the sync merge, outside the shipped crates. Results are in its README "Results". Headline: the op-by-op merge (ADR 0012 plus ADR 0018's tombstone rules) converges in every explored schedule, about 3.3 M. The open cases are all in snapshots, restores and dishonest clients (§4). |

Commits since the previous handoff: `2d6e7bf` review fixes, `6c23c51` ADR answers and old HANDOFF removed, `4e1bffd` documentation pass and lints, `0124ddc` ADR drafts 0019–0021, `f428d32` merge spike.

## 2. Set up and gate

```sh
git checkout claude/password-manager-planning-2gg9yc
rustup toolchain install --no-self-update   # pinned 1.94.1 from rust-toolchain.toml
cargo install cargo-deny --locked
```

The gate is in [CLAUDE.md](../CLAUDE.md) "Before any push" and [CONTRIBUTING.md](../CONTRIBUTING.md): fmt, `cargo lint`, tests, `cargo check-wasm`, `cargo deny check`, `cargo xtask check-deps`, `cargo xtask check-clippy`, the fuzz `cargo check` and `cargo deny`, and `cargo doc`. All green at `f428d32`.

The spike is not in the gate: `cargo test --release --manifest-path spikes/merge-model/Cargo.toml`.

## 3. ADR status

Only the owner changes a `Status:` line (CLAUDE.md; the auto-mode classifier also blocks agents from doing it).

| ADR | Status | What it needs |
|---|---|---|
| 0001–0013, 0015, 0016 | Accepted | – |
| **0014** UI stack, web platforms only | Proposed, **no open questions** | Owner sets it to Accepted. With 0010–0013 Accepted, that opens the ADR README gate for M1 server and client scaffolding. |
| **0020** partial supersession (successor to 0001) | Proposed, **no open questions** | Owner sets it to Accepted, before or with 0018 and 0021, which rely on it. |
| **0018** item-record encoding | Proposed; open questions 12–15, from the spike | Decision A (§4), then acceptance. Blocks M1 step 2. |
| **0021** server-side compaction | Proposed; open questions 1–9, several from the spike | Decisions B and C (§4), then acceptance before M1 step 3 builds compaction. |
| 0019 native clients | Proposed, **parked until M3** | Its spikes need real Windows and Linux runners. |
| 0017 licensing | Proposed, deferred by the owner | Needed before external contributions. |

## 4. Owner decisions

### Approved on 2026-09-27 but NOT applied yet

The workflow applying these was stopped for this handoff. Nothing reached the tree. Redo them, run the gate, and commit.

1. **CRYPTO.md records what the code does** (found by the documentation pass):
   - §9.2: the in-place detached HPKE calls the code uses, which keep plaintext in a zeroizing buffer.
   - §15 item 1: nonces and HPKE `ikm_e` for tier A vectors go through the injected RNG (`ExactRng`/`FixedRng`); there is no fixed-nonce hook.
   - §12.2 Limits: unicode-normalization's internal buffer is not wiped.
   - §10.2:
     - a non-zero `expires_at_ms` must be after `created_at_ms` for every device kind;
     - a device-request with an empty method is rejected;
     - **durable-device certificates (kinds 1–3) may carry an expiry**, and then the kind-4 HLC expiry rule applies (owner: allow, as the code does).
   - §10.2/§4.3: the device-set hash rejects duplicate device ids and foreign-account certificates or revocations.
   - §8.4/§11.6: an item key's creation epoch must not exceed the wrapping `vault_key_epoch`.
   - §5.11: the backup file's `format` string (none is defined in code yet; say which crate defines it).
   - §9.4: ids 0xF0–0xFE are rejected in every build.
   - §8.5: when the fixed-size length check runs (after the AEAD for symmetric envelopes, before any crypto for HPKE).
   - §6.2: message wording.
   - Add a "Decided 2026-09-27" paragraph to §16.
2. **Export and backup parsing:** a size bound before the base64 decode allocates (`export.rs` `open_data_field`, `ExportHeader::from_json_fields`, `decode_16`; `server_seal.rs` `BackupHeader::from_fields`), with negative tests, and a cargo-fuzz target for these parsers (no Argon2id in the fuzz loop).
3. **xtask:** `check-deps` enforces ADR 0009's `default-features = false` on the crypto crates, including blake2 and poly1305. `Declared::default_features` in `metadata.rs` is parsed but no rule uses it.
4. **Stale status text:** CONTRIBUTING.md (header still says M0, no product code), SECURITY.md line 5, and ROADMAP.md line 3 become "M0 done, M1 in progress". Also fix the macro-generated "(device state)" doc string that `secret_key.rs` emits for `RecoveryCode` (CRYPTO.md §11: no client persists a recovery code).
5. **THREAT_MODEL.md header → Normative** (owner decision 2026-09-27), in the style of CRYPTO.md's header.
6. Commit in logical commits on this branch. No push, no `Signed-off-by` (the owner adds it after review).

### Put to the owner, dismissed, to ask again

- **A. ADR 0018** (before the version-1 vectors freeze):
  - adopt the spike's snapshot-absorption rule (DVV join) with the merged-snapshot trigger (open question 13);
  - adopt the evidence merge for dishonest snapshots (open question 14; narrows ADR 0012 §4 step 3 under ADR 0020);
  - adopt a defined `item_key_id` for a re-issued purge (open question 15);
  - decide open question 12 (oversize items).

  Recommended: adopt.
- **B. ADR 0021** (before M1 step 3): adopt as partial supersessions of ADR 0012 §7:
  - two-author covers before an op body is deleted (open question 1);
  - the restore-healing request (open question 4);
  - the revoked-device rules (open question 5);
  - the "already stored" re-upload answer and a restore generation (open question 9).

  Recommended: adopt.
- **C. Known limits for M1,** documented in THREAT_MODEL and the ADRs and revisited before M9:
  - a revocation signed on a restored server (0021 open question 7);
  - a faulty healer as a header's only cover (0021 open question 8);
  - lies about the content of compacted ops (undecidable);
  - two or more colluding faulty devices.

  Recommended: accept for M1, since every device is the owner's own until M9.

Apply A, B and C with a **line budget and one blockers-only review**, never a review loop (see §6).

### Other open owner items

- **Generator-emitted `unsafe`** (ADR 0019 open question 2): wasm-bindgen and UniFFI glue contains `unsafe`, which `forbid(unsafe_code)` does not see (rustc skips external-macro spans). So CLAUDE.md's "unsafe is forbidden in every crate" is literally untrue for binding crates. This must be settled before `rizzy-wasm` (M1 step 5). ADR 0019 recommends a small separate ADR correcting ADRs 0013 and 0016.
- ADR 0019's remaining questions (Windows and Linux binding routes, host-language `unsafe`, desktop HTTP location, milestone staging, artifact hosting, Safari, Windows Hello). They wait for M3.

## 5. Next steps, in order

1. Apply the six approved items in §4 → gate → commit.
2. Ask the owner A, B and C (§4). Write the answers into ADRs 0018 and 0021 (budgets: 0018 ≤ 420 lines, 0021 ≤ 210), then run one blockers-only review.
3. Owner accepts 0020, then 0014, 0018 and 0021 (their act). Then record the "On acceptance" edits each ADR lists: CRYPTO.md §8.4/§15, INV-14, the README index and gates, CLAUDE.md status sentences, ROADMAP "folders or tags" → tags.
4. **M1 step 2:** the item schema per ADR 0018 in `rizzy-core` (`item` module); the `rizzy-sync` record layer and engine per ADR 0012/0018 (HLC, VVs, op log, MV-register merge, tombstones, strict ADR 0012 §3 header parsing before any field of a verified statement is trusted); convergence property tests seeded from `spikes/merge-model`; regenerate the statement vectors named "canonical_header" over real headers.
5. **M1 step 3:** server (ADR 0010/0011/0021, request signing, CAS with `CasRetry::Fork`/`is_fork`). It ships with operator docs: self-hosting, compose, and a tested backup/restore.
6. **M1 step 4:** `rizzy-client`, `rv` CLI, import, and the export JSON writer and reader, plus its fuzz target.
7. **M1 step 5:** `rizzy-wasm` and the React web vault (ADR 0014), after the generated-`unsafe` decision.
8. After pushing: trigger `.github/workflows/fuzz.yml` once by `workflow_dispatch`. No fuzz target has run instrumented yet.

Each step: build → independent review → adversarial verify → fix → full gate → commit.

## 6. Working agreements and lessons

- **Rust only**, for helpers and scratch checks too, **including subagents**: say so in every agent prompt. Agents wrote Python three times on 2026-09-26/27 when a prompt left it out.
- **Stick to milestones.** No side quests. The owner wants blunt, critical feedback.
- **Document everything as it is built.** The `missing_docs` and `clippy::missing_docs_in_private_items` lints enforce it. Normative docs change in the same change as behaviour. Never recreate `docs/ARCHITECTURE.md`.
- **Prose reviews:** one bounded, blockers-only pass with line budgets. A loop-until-dry review of ADR drafts diverged: about 30 new findings a round while the documents ballooned. Settle merge semantics with the spike, not prose. Code reviews with find → verify → fix worked well.
- **ADR gate:** no code without an Accepted ADR; never change a Status line; an Accepted ADR changes only by a new ADR (full, or partial under ADR 0020 once Accepted).
- **Harness quirks:**
  - The Workflow `isolation: 'worktree'` option creates worktrees at `main`, not HEAD. Create worktrees yourself with `git worktree add --detach <dir> HEAD`, plus an APFS clone of `target/` (`cp -cR target <dir>`) per worktree, and integrate with `git apply --3way`.
  - Workflow agents were interrupted whenever the owner sent a message. Resume with `resumeFromRunId`; finished agents replay from cache.
- **Commits:** Conventional Commits, `Co-Authored-By:` trailer, never `Signed-off-by`, push only when asked, never to `main`.

## 7. Document map

- Scope: [ROADMAP.md](ROADMAP.md). Docs index: [docs/README.md](README.md). Crypto spec: [CRYPTO.md](CRYPTO.md). Threats and invariants: [THREAT_MODEL.md](THREAT_MODEL.md). Decisions: [adr/README.md](adr/README.md).
- Code docs: `cargo doc --workspace --no-deps --open`. The `rizzy-core` crate page has the module map.
- Spike results: [spikes/merge-model/README.md](../spikes/merge-model/README.md), "Results".
