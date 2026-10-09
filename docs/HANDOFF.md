# Handoff — 2026-10-09

State at the end of the session of 2026-10-09: what was done, what is in progress, and what comes next.
Delete or rewrite this file when its next steps are done.

## Where things stand

- `main` was at `5922c1d` (ADR 0042 proposed). This branch adds the two Windows CI fixes below and this file.
- ADR 0042 (account-settings layout for website matching) is **Proposed**. Nothing that depends on it is built.
- The CI `test (windows-latest)` job had failed on every push to `main` since `31a1579`. The fix is on this branch.

## Done in this session

1. **Gap audit of M1 and M2.** Every M1/M2 row of the ROADMAP was checked against the code, the docs and the ADRs.
   The audit found 50 gaps, and a completeness pass added 5 more. Each gap went through a verifier that tried to refute it, and all 50 were confirmed.
   **Treat that as weak evidence.** The verifiers did not refute any finding, which suggests they were not strict enough.
   Recheck a gap's evidence before you implement it. The full audit output (evidence, governing ADRs, implementation notes) is `docs/handoff/gap-audit.json` on the branch `wip/client-m1`.
2. **Windows CI fix** (commits `fix(cli): close the cache connection …` and `fix(cli): drop the dead_code expectation …`):
   - `Db::create` in `crates/rizzy-cli/src/db.rs` dropped the SQLite connection after a failed first changeset and then deleted the file. sqlx closes a dropped connection later, on its worker thread, so Windows refused the delete while the handle was still open. The error was discarded, and the leftover file made the next signup or login fail as "already enrolled". That was a user-facing bug, not only a test failure.
   - The fix: the connection is now closed before the file and its rollback journal are removed. `Db::connect` also closes the connection when a pragma fails. The test now checks that the journal is gone and that a retry at the same path succeeds.
   - Separately, an `#[expect(dead_code)]` on `CoreDumpError` was unfulfilled on Windows and is removed.
   - Verified on Linux with the full pre-push list. **Not yet verified on Windows**: the next CI run proves it.

## In progress: work-in-progress branches (untested, unreviewed)

These branches hold work that was interrupted part-way. **Nothing on them has been compiled, tested or reviewed.** Do not merge them as they are.

| Branch | Gaps | State |
|---|---|---|
| `wip/client-m1` | 00 trash auto-purge, 01 password-history view, 02 late-edit/purge notices, 03 web purge tests | About 770 lines across rizzy-client, rizzy-wasm, packages/core, apps/web and rv. Mid-edit. |
| `wip/match-core` | 29 Regex match mode | `rizzy-match/src/modes.rs` started, nothing else. |

The recommendation is to redo `client-m1` as a scoped task and use the WIP diff only as a reference.

## Next work: cleared by an Accepted ADR or needing no ADR

Gap ids refer to the audit file. Ordered by value.

### M1, product

- **00** Trash auto-purge after 30 days (ADR 0012 §5, ADR 0018 §9/§11/§12). `ItemMerge::purge_due` exists, but no client calls it. The server must not purge (ADR 0022). Add a client pass after sync, plus the ADR 0018 §12 test "no auto-purge while an unknown-version restore is parked".
- **01** Password history view. The merge keeps up to 50 entries per field, but no client API returns them, and neither rv nor the web vault shows them.
- **02** Surfacing rules for an edit that arrives after a trash or purge (ADR 0018).
- **03** Tests for the web vault's permanent delete.

### M2, matching and extension

- **29** Regex mode: `decide()` returns `NotSupported`, so a Regex URI never matches (ADR 0037). Check whether a regex crate is approved; if one is not, that needs an ADR 0009 approval first.
- **30** Embedded PSL snapshot: SHA-256 hash asserted against a constant in the source (ADR 0037 §3).
- **27 (a)** Wire `global_list()` into the equivalence view in rizzy-client and rizzy-wasm. Part (b), persisting the highest `list_version`, needs an ADR.
- **31** The fill UI and the equivalence warning should name the page host and the saved host.
- **32** Password generator in the page field, not only in the popup.
- **33** Save vs. update: `findItemForUpdate` ignores the username and matches the URL only exactly. Add tests.
- **35** Passkeys: assertions never return `userHandle`, and `get` ignores `allowCredentials`.
- **34** Firefox build has no automated tests. The extension's Playwright suite is not run in CI (CI edit, see below).
- **36** Community equivalence-list PR process: templates, label, CONTRIBUTING section (ADR 0038).

### Tests and verification that CLAUDE.md, CRYPTO.md or THREAT_MODEL.md require

- **05/42** Wycheproof suites (CRYPTO.md §15 item 3): XChaCha20-Poly1305, ChaCha20-Poly1305, HKDF-SHA-256, HMAC-SHA-256, HMAC-SHA-1, X25519, Ed25519.
- **06** RFC 9807 OPAQUE vectors against the pinned opaque-ke.
- **07/43** KAT vector files run as wasm32 under Node (CRYPTO.md §15 item 8, ADR 0019 §10).
- **09** Tag each malicious-server test with its ETH attack class (CRYPTO.md §15 item 5).
- **04/21** INV-15 canary test, extended to logs at the most verbose level by INV-48.
- **X1** INV-1 request-capture test. **X2** INV-6 per-flow Argon2id count test.
- **X3** INV-37 adversarial-page e2e tests. **X4** INV-40 manifest check (an xtask). **X5** INV-63 storage-inspection test.
- **16** Convergence harness: key rotation (property 6), stale-epoch answers, re-issued ops, kind-4 authors, two or more faulty devices (ADR 0012 §12, ADR 0021 §8).

### Tooling and licensing

- **19** `cargo xtask check-tables` (ADR 0011 point 7, ADR 0016 R4).
- **40** SPDX headers on every source file, plus a check (ADR 0017 Decision 6).

### Docs that contradict the code

Ids 13, 25, 37, 44–49. Affected files: `README.md`, `docs/README.md` (it has 3 broken links, including `adr/0039-passkeys.md`), `SECURITY.md` (its status section), `CONTRIBUTING.md` (its gate list vs `ci.yml`), `docs/rv.md` and the rizzy-cli crate docs ("Not in this build" for shipped features), and the CLAUDE.md ADR status list (it omits ADR 0042, Proposed).

## Blocked: needs the owner

- **ADR 0042 is Proposed.** It blocks gap 28: user-defined equivalence groups, disabling global groups, the account default match mode.
- **New ADRs needed:**
  - 10: notify enrolled devices of a pending or completed recovery;
  - 11: a way back after the OPAQUE `server_setup` is lost;
  - 12: a pending state for `rv recovery complete`;
  - 22: restoring from a `backup-secrets` file;
  - 23: a per-account storage quota;
  - 27 (b): persisting the highest accepted equivalence-list version.
- **14:** open convergence bug. A paged Fetch can put a tombstone cover in one page and its purge in the next, and the merge then refuses the cover. Fixing it touches ADR 0021, so it needs an ADR.
- **24:** with `embed-web`, the `web` role serves more than `/` and `/index.html`, which contradicts ADR 0028 item 15. The code or the ADR must change.
- **08:** normative item-record vectors through real envelopes (ADR 0018 §12) need an owner decision.
- **CI workflow edits.** CLAUDE.md forbids editing `.github/workflows/` without an explicit ask. The edits waiting for that ask:
  - 15: nightly convergence run;
  - 17: rootless Podman and compose;
  - 18: PostgreSQL job (ADR 0011 says M1, while the ROADMAP says Postgres is M3; resolve that conflict too);
  - 34: extension Playwright, Chromium and Firefox;
  - CI wiring for `check-tables` and the INV-40 check.
- **Owner actions:**
  - 26: sign and ship the global equivalence list;
  - 39: run the Fuzz workflow once (no target has ever executed);
  - 20: choose the OpenAPI generator (new dependency);
  - 41: lawyer-drafted App Store permission text (ADR 0017 Decision 3).
