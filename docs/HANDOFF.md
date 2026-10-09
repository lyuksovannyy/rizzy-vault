# Handoff — 2026-10-09 (second session)

State at the end of the second session of 2026-10-09: what was done, and what comes next.
Delete or rewrite this file when its next steps are done.

## Where things stand

- `main` is at `5922c1d` (ADR 0042 proposed). This branch adds the Windows CI fixes, the gap work below and this file.
- ADR 0042 (account-settings layout for website matching) is still **Proposed**. Nothing that depends on it is built.
- The full audit output (evidence, governing ADRs, implementation notes) is `docs/handoff/gap-audit.json` on the branch `wip/client-m1`. Gap ids below refer to it. The `wip/*` branches are superseded by the commits below and can be deleted.
- The Windows CI fix (`Db::create` closes the SQLite connection before removing a failed file) is verified on Linux and macOS. **Not yet verified on Windows**: the next CI run proves it.

## Done

| Gaps | Commit | What |
|---|---|---|
| 00–03 | `feat(client,cli,web): trash auto-purge, password history, late-edit API` | Client trash auto-purge after sync (rv, web vault, extension), with the ADR 0018 §12 "no purge over an unapplied record" test. Password-history API, shown by `rv item show`. Late-edit API. Web permanent-delete tests. |
| 27 (a), 30–33, 35 | `feat(match,extension): HANDOFF M2 gaps 27a, 30-33, 35` | PSL snapshot pinned by SHA-256 and checked in `cargo xtask check-deps`. Global list wired into the equivalence view (empty until a list is signed). Fill UI names the page host and the saved host. Generator in the page's password field. Save vs. update uses the matcher and the username. Passkey `userHandle` and `allowCredentials`. |
| 13, 25, 37, 44–49 | `docs: fix docs that contradict the code` | README, SECURITY, CONTRIBUTING, docs/README, docs/rv.md, rizzy-cli crate docs, CLAUDE.md status list. |

## Next work: cleared by an Accepted ADR or needing no ADR

Recheck each gap's evidence before you implement it: the audit's verifiers refuted nothing, so treat it as weak evidence.

### Product

- **01 (rest)** Web vault view of password history (the client API exists).
- **02 (rest)** Hosts (rv, web vault) surface the late-edit and purge notices (the client API exists).
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

## Blocked: needs the owner

- **ADR 0042 is Proposed.** It blocks gap 28: user-defined equivalence groups, disabling global groups, the account default match mode.
- **29 Regex match mode.** No regex crate is approved (ADR 0009), and ADR 0037 does not say how a regex URI's registrable domain is found for the INV-38 gate. Needs an ADR.
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
  - 34: extension Playwright, Chromium and Firefox (the Firefox build has no automated tests);
  - CI wiring for `check-tables` and the INV-40 check.
- **Owner actions:**
  - 26: sign and ship the global equivalence list;
  - 39: run the Fuzz workflow once (no target has ever executed);
  - 20: choose the OpenAPI generator (new dependency);
  - 41: lawyer-drafted App Store permission text (ADR 0017 Decision 3).
