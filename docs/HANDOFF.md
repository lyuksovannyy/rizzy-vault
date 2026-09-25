# Handoff: continue rizzy-vault on another host

- Written: 2026-09-25, at the end of a Claude Code cloud session.
- Branch: `claude/password-manager-planning-2gg9yc` (all work is here; nothing is on `main`, no PR exists).
- Read this file, then [CLAUDE.md](../CLAUDE.md), then [ROADMAP.md](ROADMAP.md). Delete this file once its "Next steps" are done.

## 1. Where things stand

| Area | State |
|---|---|
| **M0 Foundations** | **Done.** Workspace, toolchain pin, lints, CI, cargo-deny policy, Dependabot, SessionStart hook, threat model, crypto design, ADRs 0000–0018, SECURITY/CONTRIBUTING/CLAUDE.md. |
| **ADRs** | 0001–0013, 0015, 0016 **Accepted** by the owner (2026-09-25). 0014 (UI stack) **Proposed**, framework decided (React), questions 2–3 open. 0017 (licensing) **Proposed**. 0018 (item record encoding) **Proposed, new, not yet reviewed by the owner**. |
| **M1 step 1: `rizzy-core` crypto** | **Implemented, gate green, NOT yet reviewed.** See §3. Committed as an explicit WIP snapshot. |
| **M1 steps 2–5** | Not started. See §5. |

Owner decisions on record (do not re-ask):
- Secret Key mandatory for every account from M1.
- Native clients (kinds 1–3) sign every request with the device key from M1 (`device-request` statement, CRYPTO.md §5.10). Web vault keeps short-lived bearer tokens.
- UI framework: React.
- Every open question of the accepted ADRs is answered by that ADR's recommendation (written into each ADR's "Owner decisions (2026-09-25)" subsection).

## 2. Set up the new host

```sh
git clone <repo> rizzy-vault && cd rizzy-vault
git checkout claude/password-manager-planning-2gg9yc
# rustup picks the pinned toolchain (1.94.1 + rustfmt, clippy, wasm32) from rust-toolchain.toml:
rustup toolchain install --no-self-update
cargo install cargo-deny --locked          # CI policy checker
```

On Claude Code on the web the SessionStart hook (`.claude/hooks/session-start.sh`) does the above automatically.

**The gate** (all must pass before any push; CI runs the same):

```sh
cargo fmt --all -- --check
cargo lint                                  # clippy, workspace, all targets, -D warnings
cargo test --workspace --locked             # 318 pass, 1 ignored (vector regenerator) at handoff
cargo check-wasm                            # rizzy-core + rizzy-sync for wasm32-unknown-unknown
cargo deny check
cargo xtask check-deps                      # ADR 0016 R1–R8 crate-boundary rules
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
```

Status at handoff: **all seven green** on this host.

## 3. M1 step 1 in detail (`crates/rizzy-core`, `crates/xtask`, `fuzz/`)

Built by four sequential implementer agents against CRYPTO.md (normative). About 25,700 lines of Rust.

| Module | Covers (CRYPTO.md) |
|---|---|
| `encoding`, `labels`, `secret`, `rng`, `error`, `ids` | §2 conventions, the single LABEL registry, zeroizing secret types with redacted `Debug`, injected rand_core 0.10 RNG + opaque-ke rand 0.6 adapter, symmetric and public key ids (§4.4) |
| `kdf` | §6 kdf_id table and floor, Argon2id with caller-owned wiped block memory (argon2 built without `alloc`), NFC, unassigned-code-point rejection (ADR 0004 decision 3) |
| `envelope` (+ `proptests`) | §8.3 UtC+HtE committing XChaCha20-Poly1305, §8.4 purpose registry incl. server-only range, §9.1/§9.5 layout, strict parser, check order |
| `padding` | §8.5 Padmé framing (reader also enforces the exact canonical length) |
| `hpke` | §9.2/§10.1 algorithms 0x10 and 0x12, device-grant PSK (M4 PSKs deferred) |
| `sign` | §9.3 container, every §10.2 statement incl. bundle chain, device-cert kind-4 expiry, account-state CAS rule, op/snapshot hashed form, key-grant, device-auth, device-request |
| `keys` | §4 hierarchy: E_srv, E_local, E_rec, E_id, E_dev, vault self-grant, ITEM_KEY_WRAP, device grants, retired keys, device-set/settings hashes, fingerprint |
| `opaque` | §5 RizzySuiteV1 + RizzyArgon2idKsf (Default is a fail-closed sentinel per §5.1/ADR 0003), single wrapper, Context binding, fake-record path, pw_in with the SK |
| `normalize` | §2 login names and server_origin |
| `secret_key` | §7 RV1-/RVR1- Crockford codec, table-free |
| `totp` | §11.15 HOTP/TOTP SHA1/256/512, otpauth parsing, server verify with replay rejection |
| `generator` | §12.1 rejection-sampled chars and EFF-wordlist passphrases |
| `server_seal` | §5.11 server-side sealing (TOTP secrets, login state, secrets backup) |
| `export` | §11.14 export key + envelope (JSON file writer is a later crate) |
| `test_vectors`, `tests/vectors/*.json` | §15.1 known-answer vectors, replayed byte for byte |
| `crates/xtask` | `cargo xtask check-deps` (ADR 0016 §5), wired into CI's clippy job |
| `fuzz/` | cargo-fuzz targets (excluded from the workspace; need nightly; never run yet) |

**Not done in step 1 (from the builders' reports):**
- The step-1 **review → verify → fix** phases never ran: the workflow was stopped for this handoff while implementer 4 was finishing. Implementer 4's output (xtask, vectors, proptests, fuzz skeleton) passes the gate but was never reported or reviewed.
- Wycheproof suites (§15.3), wasm32 runs of the vectors via wasm-bindgen-test (§15.8), RFC 9807 vectors (only functional OPAQUE tests + a regression hash).
- M4 PSK derivations (password-verifier, resync, pairing), fake-kdf migration policy (only matters once kdf_id 2 exists), export/backup JSON writers, Emergency Kit rendering.
- API polish: `LocalUnlockKey::derive(&Key32)`, `ServerUnlockKey::derive(&SecretArray<64>)`, `RecoveryWrapKey::derive(&SecretArray<16>)` take raw types; the newtypes (`PasswordInput`, `ExportKey`, `RecoveryCode`) call them. Consider tightening the signatures.
- During handoff, `allow-panic-in-tests = true` was added to `clippy.toml` and five test-vector functions got `#[expect(clippy::too_many_lines)]` to get the unfinished test code through the lint gate.
- Lost with the old host: the compile spike and the Python KAT generators lived in the session scratchpad, not the repo. The committed vectors are self-generated by `rizzy-core` (seeded ChaCha20Rng) plus the RFC vectors in unit tests.

Builders resolved ambiguous spec points in the code and documented most of them in doc comments that cite the CRYPTO.md section (grep `CRYPTO.md §` in `crates/rizzy-core/src`). Notable ones the reviewer should check: Padmé canonical-length rejection, TOTP replay rejects every step ≤ last accepted, server_origin normalisation (no IDNA, http/https only), bundle key-type restrictions, HPKE 16 MiB bound.

## 4. Decisions waiting on the owner

1. **Accept ADR 0018** (item record encoding: hand-written canonical binary layout, schema in `rizzy-core`, records in `rizzy-sync`). Blocks M1 step 2. It notes minicbor is BlueOak-1.0.0 (not on the licence allow-list), one reason it chose a hand-written layout.
2. **ADR 0014 questions 2–3**: framework-free share page? desktop reuses `apps/web`? Blocks client scaffolding (ADR README "Gates": 0010–0014 before server and client scaffolding).
3. **EFF wordlist licence** (CC BY 3.0 US, compiled into every build, attribution in `THIRD_PARTY_NOTICES.md`): acceptable next to AGPL-3.0-only and for app stores? Ties into ADR 0017.
4. **ADR 0017 licensing** (AGPL-3.0-only vs or-later, DCO vs CLA): needed before external contributions are merged.

## 5. Next steps, in order

1. **Review M1 step 1** before building on it. Three independent reviewers, read-only, each reporting findings with evidence:
   - *spec*: byte-level conformance to CRYPTO.md (every label, §4.3 derivation, §8.4 purpose/ctx/allow-list, §9 layout, §10.2 statement body, §5 OPAQUE parameters, §6, §7, §8.5, §11.15, §5.11), with scratch tests for suspected deviations;
   - *hygiene*: zeroize/redaction, constant-time comparisons (§12.3), no secret-indexed lookups, RNG injection (`cargo tree` host + wasm32: no getrandom in the rizzy-core closure), parsers never panic or over-allocate, no unwrap/expect/indexing panics in non-test code, opaque-ke only via the wrapper;
   - *tests*: every derivation/purpose/statement has a replayed vector, upstream vectors run through our wrappers, a negative test per rejection rule, §15.4 proptests.

   Then adversarially verify every finding (default: refuted if the evidence doesn't hold), apply the confirmed ones, re-run the gate, commit.
2. **Ask the owner** the §4 questions (ADR 0018 first).
3. **M1 step 2**: item schema per ADR 0018 in `rizzy-core`; `rizzy-sync` engine per ADR 0012 (HLC, version vectors, op log, field-level MV-register merge, tombstones, lazy item-key rotation rules), with convergence property tests on N simulated devices.
4. **M1 step 3 (server)**: `rizzy-proto`, `rizzy-storage` (sqlx, SQLite), domain crates, OPAQUE endpoints, device auth + request signing, account-state CAS, op upload/fetch with server-side validation, TOTP 2FA, backoff (never hard lockout), logging allow-list, backup/restore, core dumps off (INV-60), OCI image + compose (Docker and rootless Podman).
5. **M1 step 4**: `rizzy-client` (sans-I/O flows), `rv` CLI with encrypted local cache, `rizzy-import` (Bitwarden JSON, 1PUX, KeePass, CSV), encrypted export writer.
6. **M1 step 5**: `rizzy-wasm` + React web vault (kind-4 ephemeral device), after ADR 0014 is Accepted.

Each step: build → independent review (several lenses) → adversarial verify → fix → full gate → commit and push. That loop caught two blockers in the crypto docs and 35 real defects in the second review; don't skip it.

## 6. Working agreements

- **ADR gate** ([CLAUDE.md](../CLAUDE.md)): no crypto, protocol, format, boundary or licensing code without an Accepted ADR. Only the owner accepts; record answers in the ADR's Decision section first ([ADR 0001](adr/0001-record-architecture-decisions.md)).
- **Commits**: Conventional Commits; AI work carries a `Co-Authored-By:` trailer; never add `Signed-off-by` for the human; push to this branch only; no PR unless the owner asks.
- **Never recreate `docs/ARCHITECTURE.md`**; the owner deleted it deliberately. ADR 0010/0016 cover its ground.
- **Tone**: the owner asked for blunt, critical feedback. Call weak ideas weak and say why.

## 7. Document map

- Scope and milestones: [ROADMAP.md](ROADMAP.md)
- Threats and invariants (INV-1..69): [THREAT_MODEL.md](THREAT_MODEL.md)
- Crypto spec (normative): [CRYPTO.md](CRYPTO.md)
- Decisions: [adr/README.md](adr/README.md) (index + gates)
- Contributor workflow: [CONTRIBUTING.md](../CONTRIBUTING.md); disclosure: [SECURITY.md](../SECURITY.md)
