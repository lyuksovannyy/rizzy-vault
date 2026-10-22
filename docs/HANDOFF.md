# Handoff — 2026-10-21 (M3 fleet integration session)

State at the end of the 2026-10-21 session: what was done, and what comes next.
Delete or rewrite this file when its next steps are done. §2–§7 are carried over from the
2026-10-11 session unchanged except where §1 says otherwise.

## 1. Where things stand

- **Machine moved.** Work now runs on a Linux host (Ubuntu 24.04, 20 cores, 8 GB RAM), not the earlier macOS box. Parallel work uses git worktrees under `~/rizzy-wt/`: `integration/` holds this branch and each track is `~/rizzy-wt/<track>` on branch `wip/<track>`. Tracks are cut from integration HEAD and cherry-picked back. Helper `~/rizzy-wt/bin/wt` (`new`, `adopt`, `list`, `sync`, `integrate`, `gate`, `rm`), `bin/gate.sh [--full]` (the CLAUDE.md list, plus check-tables, the JS/e2e list, both Playwright suites and `RUSTC_BOOTSTRAP=1 expand-bindings` as in CI), and `bin/bg` / `bin/bg-status` to run long commands detached from the agent session. Local tool setup: Node 24 and corepack pnpm in `~/.local/opt/node24`; Chromium's missing system libraries unpacked into `~/.local/opt/pw-libs` (no sudo); sccache. See `~/rizzy-wt/README.md`.
- **Gate.** The full gate (`~/rizzy-wt/bin/gate.sh --full`) is green on `a286537` except rustdoc: Rust 1713 tests passed / 21 ignored, check-tables, web e2e 17 passed / 2 skipped, extension Playwright 66 passed / 4 skipped, `check-js`, `check-manifest`, `expand-bindings`. `67d1c6f` fixed the rustdoc failure (a private intra-doc link in `rizzy-wasm`). It was re-checked with fmt, `cargo lint`, `check-wasm`, `cargo doc -D warnings`, `expand-bindings` and the `rizzy-wasm` tests, all green. Pushed to `origin/claude/password-manager-planning-2gg9yc`.
- `origin/main` is still `5922c1d`. No commit in `origin/main..HEAD` carries `Signed-off-by`. Before `main` is fast-forwarded, the owner runs `git rebase --signoff origin/main` so CI's DCO job passes (ADR 0017 Decision 4).
- **M3 fleet integrated** onto this branch with `cherry-pick -x`: `wip/m3-tokens`, `wip/m3-quadlet`, `wip/m3-palette` and `wip/m3-history`.
  - `m3-history` got its missing review. Fixes are committed: a restored custom field value is checked against the field's current kind; wasm `FieldHistoryView` keys are zeroized and its `Debug` is redacted; the CLI header line is zeroized; web hides Restore when read-only or trashed and remounts rows on sync. The wasm-bindgen expansion baseline was regenerated with identical `unsafe`/`extern`/`no_mangle`/`export_name` counts (945/569/236/268).
  - Favorites UI (§1's old open question for the palette row) exists: the detail-header star, the sidebar Favorites filter and favorites-first ranking in the palette, each covered by e2e (`vault.spec.ts`, `command-palette.spec.ts`).
  - Quadlet is still unverified on a real Podman host (podman is not installed here either).
- **New this session:**
  - `cargo xtask check-tables` (the M1 row, §6), `auth_`/`vault_` only. `storage_*` is skipped and counted, pending the owner (§5 gap 19). It is in CLAUDE.md's and CONTRIBUTING.md's push lists, but not in CI (an owner decision, §5).
  - **Advisory bumps** (the gate was red on `main` too): `rustls` =0.23.46 (RUSTSEC-2026-0346/0347), `webpki-roots` =1.0.10 (RUSTSEC-2026-0381), `rustls-webpki` 0.103.16 in the lockfile (RUSTSEC-2026-0382), and `vite` 8.3.5 (six pnpm audit advisories, check-js). These are patch bumps of exact pins, so **the owner reviews them as ADR 0009 asks** ("a patch release needs a human PR"). CRYPTO.md §3 is updated to the new pins; ADR 0009's own amendment table still names the old versions, because it is Accepted and only the owner edits it.
- **Second wave (2026-10-21).**
  - **Transparency page:** integrated as a client-only Settings group, "What the server stores" (`dae02d6`…`3e4ee56`). Its server-reported byte sizes are blocked: no Accepted ADR defines an endpoint, and ADR 0048 is Proposed.
  - **Force logout:** blocked at the ADR gate. ADR 0075 (Proposed) now drafts it, so it waits for the owner (§3).
  - **Conflict chooser:** integrated: rizzy-client `conflicts.rs`, wasm, core, the web chooser and e2e. Both resolutions are ordinary edits under ADR 0012 §4 step 5 and ADR 0018 §6, and `rizzy-sync` is untouched. **Owner decision:** the ADRs name "keep both" but define no layout. The implementation keeps the shown value and moves each other Text value into a new website or custom field, using only ADR 0018 §7 keys. Concurrent keep-both on two devices yields duplicate copies (documented). Bool, Enum and similar fields resolve only by pick. Bindings `unsafe` went from 945 to 997, all wasm-bindgen glue for the new exports. No `rv` support (no ADR asks for it).
  - **Onboarding:** integrated as a getting-started guide after signup (Emergency Kit confirmation, import, extension instructions), which Settings reopens. Nothing is persisted, because CRYPTO §11.4 allows only the opted-in Secret Key and the theme in browser storage; a remembered "dismissed" state would need an owner change there. The e2e sign-up helpers close the guide, so new sign-up e2e code must too.
  - **Advisory bump:** vitest 4.1.12 (GHSA-qxg6-89mg-rqv8, GHSA-xp26-3454-mjgp). The owner reviews it, as with the earlier bumps.
  - **Multi-step login:** integrated in the extension (`src/content/login-step.ts`): identifier-first, password-only and same-page reveal steps. Each step gets its own menu and needs its own trusted click, and nothing carries across steps or navigations. `inline_menu_fill_chosen` gained an optional `only: "username"|"password"` that can only narrow the values sent, so on a username step the password never reaches the content script (ADR 0036 §4); the lead judged this within §4 rather than a new message type. Not done: save-on-submit across two pages, and a reveal by changing `type`. The hint word lists are unmeasured on real sites.
  - **i18n scaffold:** integrated as `packages/i18n` (`@rizzy-vault/i18n`): a typed English catalogue and `t(key, params)` with `{name}` placeholders, English only, no third-party dependency. The web error messages now come from it (all 45 byte-identical), and LoginView and TotpDialog are migrated as the first slice; the other views still hold literal strings. `packages/config`, named in ADR 0014 §4, does not exist yet, so the package has its own tsconfig.
  - **PostgreSQL, first local run** (Docker `postgres:17-alpine`; the CI job is still the owner's call, §5):
    - `rizzy-storage --ignored` passes: 3 tests, covering migrate/restore/dump, the worker leader lock and the instance lock.
    - `rizzy-domain-vault` hung in `selfgrant::each_check_of_the_lag_rule_refuses`. That test opened a second `Env` while holding the one PostgreSQL slot, which deadlocked. The fix splits it into its own test; 33/33 now pass on PostgreSQL.
    - Server smoke: `migrate`, start and `/api/meta` work, with all 28 tables created. A second server process runs alongside, as ADR 0023 §5's shared instance lock intends.
    - Not yet covered on PostgreSQL: the web e2e, which needs per-server databases in `apps/web/e2e/server.ts`, and `restore`/`secrets rotate` end to end.
    - To rerun: `RIZZY_TEST_POSTGRES_URL=… ~/rizzy-wt/bin/gate.sh` adds the PG steps.
- **Owner decisions of 2026-10-21/22 (in session):**
  - ADR 0042 is Accepted and **implemented** (gap 28):
    - `rizzy-match::settings` holds the tag 0x0001 section, and `rizzy-client::settings` the outer record, CAS write and cache.
    - Known-answer vectors are in `settings/vectors.rs`; the `envelopes.json` ACCOUNT_SETTINGS vector is now a real record, and CRYPTO §15 1(A) is updated.
    - New fuzz target `client_account_settings`; new error codes `settings_update_required`, `equivalence_domain_rejected` and `settings_limit_reached`.
    - wasm and core exports, the web Settings → Website matching pane, and the extension now applying the account default, user groups and disabled groups.
    - Bindings `unsafe` went from 997 to 1063, all generator glue.
    - Open items:
      - Disabling a global group can't be tested in the browser until a signed global list ships (G1, the owner's signing act).
      - Web settings writes need a fresh login session (≤5 min), after which the pane asks to log in again. Reusing the re-auth session would fix this, but that changes the re-auth design.
      - Two rizzy-cli TLS-proxy e2e tests failed once under host load and passed on rerun; they may be flaky.
      - Integration found and fixed a real command-palette focus race: keys typed right after Ctrl+K were lost.
    - Full gate at `5bebe8d`: Rust 1752 passed; web e2e 26 passed / 2 skipped; extension e2e 69 passed / 4 skipped.
  - The dependency bumps are approved (ADR 0009 amendment of 2026-10-21).
  - Accessibility CI is unblocked and integrated: axe and CDP audits of every web and extension screen, a keyboard-only walk, the WCAG AA floor for token pairs, and `generate-tokens --check` in CI. axe-core 4.14.0 is a new devDependency (MPL-2.0). The `ci.yml` edits have not yet run on GitHub Actions.
  - Signing is authorized ("sign it"). **Branch `signed/m3-2026-10-22`** is this branch rewritten onto `origin/main` by `~/rizzy-wt/bin/signoff-branch.sh`:
    - Every commit carries the owner's `Signed-off-by`.
    - Commits authored by the AI identities (Agent, Claude) are re-authored to the owner, with the AI as `Co-Authored-By`, matching how earlier sessions' commits were authored.
    - The final tree is identical to this branch, and `cargo xtask check-signoff` passes.
    - A PR from it to `main` is open. Nothing was pushed to `main`; merging is the owner's act. After the merge, future work branches from `main`.
  - Autocomplete-driven autofill was requested. It needs a new item key and fill-contract changes, so it is drafted as **ADR 0076 (Proposed)**. It also needs a ROADMAP row (its open question 1).
- **"Keep both" (owner question, rephrased).** When two devices change the same field before they sync, the field ends up holding two values at once. The ADRs define "pick one": choose a value, and the others stay only in history. "Keep both" is named in the ROADMAP, but no ADR says where the second value lives, because a field such as a password holds exactly one value. The implementation keeps the shown value in the field and turns each other value into a new field on the same item ("Password (from <device>)", hidden like the original), or a new website entry for URLs. Other shapes are possible:
  - a duplicate item holding the other value;
  - a field that keeps several values side by side (a format change);
  - no "keep both" at all.
  
  Each choice has trade-offs: duplicates if two devices both pick "keep both"; booleans and choice fields cannot be kept twice; extra fields clutter the item. The owner chooses whether the current shape stays.
- **Owner decisions of 2026-10-22:**
  - ADRs 0043, 0044, 0048–0060, 0062, 0071 and 0073–0076 are Accepted. Their acceptance changes are completed in `310711d`…`ab16a67`: "Owner answers at acceptance" with the recommendations, the "On acceptance" doc edits, and the superseded status lines.
  - M5 (sharing) and M6 (aliases/email) are scheduled after v1.0, and ROADMAP §4.4 gains the ADR 0076 row.
  - Implementation runs in waves, one worktree per ADR or per tight group.
- **Open acceptance questions for the owner:**
  1. ADRs 0043 and 0076 each rewrite ADR 0036 §4's first bullet, and 0076's text drops 0043's per-instance register/revoke message. Until a small reconciling ADR settles it, implementations treat **both** as binding: 0043's register/revoke message plus 0076's offer messages.
  2. 0053 and 0058 both claimed CRYPTO §11.16. They are numbered in ADR order: §11.16 is the breach check, §11.17 is WebAuthn 2FA.
  3. ADR 0073's "On acceptance" makes three supply-chain approval records (cosign, the CycloneDX generators, the merge tool) a condition of it binding, and they don't exist yet. 0073's CI signing work waits for them.
  4. ADR 0044 question 1 recommends dropping ADR 0042 §4's public-suffix check. 0042 was accepted first, so the check stays unless a later ADR removes it.
  5. ADR 0071 question 1 had no recommendation. The draft's placement as a new CRYPTO §9.8 was followed.
  6. ADR 0074 question 4 (a bare unencrypted CXF export) needs a ROADMAP §4.10 edit, which is not made.
  7. ADR 0060's purpose 0x0103 (SMTP credentials) has no name or ctx in any ADR. It belongs to the mail work, which is now after v1.0.
  8. ADR 0056 question 5: the allow-list amendment for ADR 0055's item types is still to be written.
  9. ADR 0052 question 7: whether `blob:` goes into `img-src` depends on the implementation's browser test.
  10. Possible gap, unverified: in ADR 0071, `plaintext_len` is in no chunk's AAD, and the ADR's claim that the commitment catches an edit is unchecked.
  11. 0059 keeps webauthn-rs' `attestation` feature on for provenance, while 0058 verifies no attestation. That looks consistent but should be checked.
- **Implemented from the 2026-10-22 batch (wave 1, each full-gated and integrated):**
  - **ADR 0048, storage quota:**
    - `quota_exceeded` (409) and the `AccountView` usage fields.
    - Migration **0006** / schema_version 6. The ADR text says both 0007 and "schema_version 6", so 0006 was used; when ADR 0047 is accepted, it takes the next free number.
    - Startup backfill and daily reconciliation.
    - Usage shown in Settings → What the server stores, and in `rv unlock`.
    - Beyond the letter of §2: rotation and heal-3b also credit the deleted wrap bytes, so the counter stays the sum of the rows.
  - **ADR 0049, web route table:** M1 rows only; `/s/<id>` is refused, since M5 is after v1.0.
  - **ADR 0050, paged Fetch covers:** the held covers. The `ContextNotSettled` residual in §7 was already fixed (`d295b99`); that bullet is stale.
    - **New residual:** with paging during the drain, convergence family 7 at seed `27×0x9e3779b97f4a7c15` reports honest disagreements with no cover held. It also happens on the pre-ADR baseline, so the generated families keep an unpaged drain. It needs its own investigation.
    - `spikes/merge-model` was not extended (it models no paging).
  - **ADR 0044, member rules:** user groups keep refusing dotless names (see 0044 question 1).
  - **ADR 0051, equivalence-list version floor:** cache format 2.
  - **ADR 0043, iframe instance tokens:** the expired-token case is unit-tested only; Firefox was not run.
  - **Bindings:** `unsafe` went from 1063 to 1080, all generator glue.
  - **`gate.sh`:** the workspace test step now always runs on SQLite, and the PG steps get their own database.
- **What is left for agents:** the rest of the 2026-10-22 batch, in waves (0075, 0055 and 0062 running).
- The gap-numbered audit (`docs/handoff/gap-audit.json`), which older gap ids below trace back to, still lives only on branch `wip/client-m1`. Keep that branch; its code is superseded by the commits in §2. `wip/match-core` (one unfinished commit off `main`) is likewise superseded and kept only for reference.

## 2. Done since the last rewrite

| Theme | What |
|---|---|
| URL normalization / INV-38 | `fix(match): strip every trailing dot in normalize_domain`; `fix(match,client): strip every dot the real pipeline can leave trailing`; `fix(match): close the IP-literal trailing-dot-run collision review found`; `fix(match): compare port in Host mode, remove unreachable! panic path`; `fix(match): enforce same-origin iframe gate, honor per-URI match override` |
| A7 inline-menu clickjacking (gap X6) | Nine `fix(extension): close A7 …` commits closing stacking-context/ancestor-pseudo, outline/top-layer, nested-decoy/`popover::backdrop`, box-shadow top-layer, and scan-scope/text-shadow/border gaps; plus "gate the inline-menu iframe's own visibility and topmost state", "close the `lastGoodSampleAt` recency gap in Gate B", and a positive control for `body::after`. SPDX headers added to the new visibility files. |
| A7 bypass triage + passkey e2e hangs | "close `isFillAllowedNow`'s stale-history gap; correct a flaky rejection test"; "close the native-WebAuthn-fallback hang in passkey.spec.ts"; "close the inline-menu-intercept hang in passkey.spec.ts; add `get()` timeout coverage"; "loop the window-blur regression test for determinism; correct THREAT_MODEL.md's 8/8 figure" |
| X3/X4 closed | "adversarial e2e pages for X3, manifest check for X4" and its review-finding follow-up fix both landed: `cargo xtask check-manifest` exists, is tested against the real built manifests, and the opacity-invisible-iframe case X3 flagged is the same one the A7/X6 row above fixed. CI wiring for `check-manifest` is still blocked (§5). |
| Bulk adversarial harnesses | Bulk HTTP attack harness against A1/A15; bulk A4 network-MITM harness for `rv`'s TLS; bulk A6/INV-64 match/client differential-testing harness; bulk A7 clickjacking and messaging fuzz harness; bulk adversarial-import harness for A16/A14/A8/A1; bulk malicious-server mutation harness |
| Sync convergence / gap-14 | "bound `absorb_snapshot`'s join to the causal layer's cut"; "refuse a tombstone `absorb_snapshot`'s bound-capped cut can't settle"; "adopt the offered epoch before healing in `World::upload`"; a rotation writer-rule false positive fixed; seeds pinned for gap-14 (`14-G1`) and a second family-9 `held_snaps` disagreement. One new defect surfaced and pinned as an **ignored** regression, not fixed: `ContextNotSettled` (§7). |
| Licensing | SPDX headers added to source files plus `cargo xtask check-spdx`; a wave-3 and an A7-files SPDX follow-up; `check-spdx` dropped from CLAUDE.md's pre-push list (CI wiring is separate, §5) |
| Docs | "INV-39 requires a strictly higher list version" correction in THREAT_MODEL.md |
| ADR drafting | ADR 0043 proposed and its review blockers fixed; ADR 0044 proposed and its review blockers fixed (both committed). This session's own work — the 30-ADR batch 0045–0074 (§3) — is drafted and corrected on disk but not committed yet (§1). |

## 3. Owner review batch

Every Proposed ADR as of today, oldest first. "Unblocks" is what accepting it clears; "Recommended" compresses its open questions to the call the owner has to make.

| # | Title | MS | Unblocks | Recommended |
|---|---|---|---|---|
| [0033](adr/0033-protobuf-api-encoding.md) | Protocol Buffers encoding for client–server messages | M1/M3 | n/a — owner's current call already stands | Keep "JSON only for now, re-check at M3." |
| [0042](adr/0042-account-settings-matching-layout.md) | ACCOUNT_SETTINGS plaintext: canonical layout and the M2 matching section | M2 | Gap 28 (user-defined equivalence groups, disabling a global group, account match default) | Accept as drafted; blocked purely on acceptance. |
| [0043](adr/0043-inline-menu-instance-token.md) | A per-instance token for the inline-menu and passkey-consent iframes | M2 | Fixes the reproduced clone/clickjacking bypass (§7) | Accept, then implement — code must not pre-empt a Proposed ADR. |
| [0044](adr/0044-equivalence-group-member-rules.md) | Equivalence-group member rules: no IP literals, registrable domains only | M2 | Gap 26 (signing/shipping the real global list) | Accept before any list is signed (§5). |
| [0045](adr/0045-recovery-pending-notification.md) | Server-side notification of pending and completed account recovery | M1 | Gap 10, for `sync`/`unlock`/write commands/`export` | Ship `last_recovery_at_ms` now; loud repeated warning on every reachable command; `rv`'s offline-read commands stay unseen (OQ4). |
| [0046](adr/0046-recovery-pending-device-stage.md) | A recovery-pending device-state stage for `rv recovery complete` | M1 | Gap 12 | Mandatory device-auth short-circuit; `RECORD_VERSION` stays 1; no client-side expiry; abandon (not rebuild) on a stale-cursor resend failure. |
| [0047](adr/0047-opaque-secrets-operator-commands.md) | Operator commands for OPAQUE secrets: restore and invalidate | M1 | Gaps 11/22 | Bare `--confirm`; refuse outside the two diagnosed loss cases; a dedicated `auth_invalidate_pending` table; never mint a fresh bootstrap token on whole loss. |
| [0048](adr/0048-per-account-storage-quota.md) | Per-account storage quota and its wire error code | M1 | Gap 23 | Default 5 GiB / min 256 MiB; `409 quota_exceeded`; headroom tied to `RIZZY_MAX_UPLOAD_BYTES`; back up `storage_account_usage`; one instance-wide value for now. |
| [0049](adr/0049-web-role-route-table.md) | Web role: a fixed, enumerable route table | M1 | Gap 24 — legitimizes `embed-web`'s asset routes | Accept the narrow fix (item 15 in full, item 10's first sentence); extend by amendment later. |
| [0050](adr/0050-paged-fetch-tombstone-boundary.md) | Paged Fetch: tombstone covers that can span a page boundary | M1 | Gap 14 — the one open convergence bug | Accept the INV-27 narrowing (hold-then-report, not an immediate refusal); accept the restart-loses-the-hold M1 limit. |
| [0051](adr/0051-equivalence-list-version-persistence.md) | Persisting the highest accepted equivalence-list version | M2 | Gap 27(b), INV-39's no-downgrade rule | Mandatory format-2 migration; identical key shape across extension and future native leaves. |
| [0052](adr/0052-icon-proxy-role.md) | Icon-proxy (favicon) role: fetch, cache and re-encode mechanism | M3 | Favicon proxying (design row) | HTTPS:443 first, HTTP:80 same-IP fallback only; accept the N×-replica rate-limit multiplication; `blob:` URL instead of `data:` for CSP. |
| [0053](adr/0053-hibp-breach-check-egress.md) | Watchtower/HIBP breach-check egress route | M3 | Breached-password check | Route through the `icons` role; two separate off-by-default flags (icons, breach-check). |
| [0054](adr/0054-attachments-envelope-and-api.md) | Encrypted attachments: chunk layout, storage shape and upload/download API | M3 | Attachments + M5 file Send | 512 KiB chunks / 25 MiB cap; needs 0048 accepted first for its quota error code. |
| [0055](adr/0055-m3-item-type-field-keys.md) | M3 item types: field keys for SSH key, API credential, software license, Wi-Fi and bank account | M3 | The 5 new M3 item types | Drop the dead `ItemTypeClass::ReservedM3`; skip the whole item (not just the field) on a carried wrong-type field. |
| [0056](adr/0056-local-index-recently-used-search.md) | M3 local index: recently-used tracking and client-side search | M3 (`rv`, `rizzy-ffi`) | Recently-used + client-side search | Accept cleartext `item_index` for M3 desktop and `rv` (`rv`'s own INV-61 gap is bigger — no OS mechanism at all); defer FTS5 and notes indexing. |
| [0057](adr/0057-device-state-v2-keystore.md) | Device-state record version 2: OS-keystore-backed local unlock (`E_ks`) | M3 | OS-keychain/biometric unlock prerequisite | Ship `ACCOUNT_KEY_FORWARD` with `E_ks` together; hard refusal on a platform-gate mismatch; keep fetching new epochs with keystore unlock off. |
| [0058](adr/0058-webauthn-2fa-second-factor.md) | WebAuthn/FIDO2 security keys as a server-side second factor | M3 | Server-side WebAuthn 2FA | Request attestation "none," verify nothing on receipt; `p256` stays inside `rizzy-core`. |
| [0059](adr/0059-webauthn-rs-crate-approval.md) | Approving the `webauthn-rs` crate for the server-side WebAuthn/FIDO2 2FA ceremony | M3 | Crate approval for 0058 | Approve `webauthn-rs =0.5.5`, `default-features = false`, `features = ["attestation"]`, confined to `rizzy-domain-auth`. |
| [0060](adr/0060-admin-panel-stack-boundary.md) | Admin panel: web stack, directory and security boundary | M3 | The admin panel | Add admin-auth (INV-69) as its own ADR before any screen merges; signup screen ships Closed/Open only. |
| [0061](adr/0061-notify-websocket-protocol.md) | `notify` role: WebSocket connect authentication and message envelope | M3 | Push/live sync | 20 connections/account default, close-oldest-on-cap; new `AuthService::session_is_live` method. |
| [0062](adr/0062-markdown-notes-sanitization.md) | Markdown-in-notes rendering: sanitization and rendering rules | M3 | Markdown in secure notes | Secure Note only (not every item type) for v1; no bracketed links, images or nesting. |
| [0063](adr/0063-share-snapshot-format.md) | Share snapshot plaintext layout and link/fragment grammar | M5 | Share-link crypto format | Accept narrowing ADR 0018 §7 so `share/…` is always excluded, regardless of owner field choice. |
| [0064](adr/0064-share-api-storage-lifecycle.md) | Share API, storage and lifecycle | M5 | Create/list/revoke share endpoints | `share_`-prefixed tables; accept the INV-34 rewording; rate-limit numbers still open. |
| [0065](adr/0065-share-page-origin-csp.md) | Share recipient page origin and CSP | M5 | The `/s/<share_id>` page | Same origin as the vault for M5 (no separate hostname); accept before/with 0049. |
| [0066](adr/0066-share-email-otp-verification.md) | Recipient email verification by one-time code | M5 | Email-restricted shares | 8-digit / 15-min / 8-attempt code; needs 0064 to refuse share creation when `RIZZY_SMTP_URL` is unset. |
| [0067](adr/0067-send-style-share.md) | Send-style text/file share | M5 | Text-only Send (file Send waits on 0054) | 512 KiB text cap; discriminator placement coordinated with 0063 before either is accepted. |
| [0068](adr/0068-alias-identity-model.md) | Alias identity model, storage, and no-enumeration lookup | M6 | Alias generation/disable/delete | Random high-entropy `local_part` by default; reword ROADMAP's "no enumeration" claim to match THREAT_MODEL's actual answer. |
| [0069](adr/0069-smtp-ingress-architecture.md) | SMTP ingress architecture: listener choice and the smtp↔api protocol | M6 | The inbound SMTP receiver | Hand-roll the SMTP grammar for M6; operator supplies the STARTTLS cert; one deployment-wide `resolve` rate-limit bucket. |
| [0070](adr/0070-mail-auth-crate-approval.md) | Crypto-crate approval: `mail-auth` for SPF/DKIM/DMARC verification | M6 | Crate approval for 0069's auth checks | Approve `mail-auth =0.13.3`, `default-features = false`, `features = ["ring"]`; extend `check-deps` to `rizzy-smtp-ingress`'s closure. |
| [0071](adr/0071-encrypted-db-backup-format.md) | Encrypted scheduled database backup format (`SERVER_DB_BACKUP` envelope) | M8 | Encrypted scheduled backups (encryption half) | 8 MiB chunk length; `backup --encrypt` stays opt-in. |
| [0072](adr/0072-remote-backup-destinations.md) | Remote backup destinations (WebDAV, S3) and destination-credential storage | M8 | Remote backup destinations (storage half) | Timestamp-suffixed object names, no auto-pruning; ship the private-CA-file rule now. |
| [0073](adr/0073-signed-images-sbom-provenance.md) | Signed release images, SBOM and supply-chain provenance | M8 | Signed images / SBOM / provenance | Sign inside ADR 0019 §7's existing release workflow, not a second pipeline; SLSA Build Level 2 for M8. |
| [0074](adr/0074-passkey-cxf-import-export.md) | Passkey import/export via the FIDO Credential Exchange Format (CXF) | M8 | Passkey CXF import/export | Build now; hand-written PKCS#8 reader/writer, no new `p256`/`ed25519-dalek` features. |

**Gaps this batch closes on acceptance:** 10→0045, 12→0046, 11/22→0047, 23→0048, 24→0049, 14→0050, 27(b)→0051, 28→0042 (already drafted, just needs acceptance), 26→0044 then the owner's own signing act (§5), extension/passkey-consent clickjacking→0043. ADRs 0052–0074 close M3/M5/M6/M8 ROADMAP-row blockers that never had a HANDOFF gap number — they come from this session's row-by-row scouting, not the old gap list.

**Reconcile at acceptance (shared numbers).** The batch was drafted in parallel, so shared numbered slots were allocated once, in ADR-number order, and each ADR marks them provisional: proposed invariants INV-70 … INV-100, CRYPTO.md §5.11 server-only purposes 0x0103 (0060 SMTP credentials), 0x0104 (0066), 0x0105 (0071), 0x0106 (0072), migrations 0006 (0047), 0007 (0048), 0008 (0064), and ADR 0028 item 1's endpoint count (+5 → 32 for 0054, +4 → 36 for 0064, +1 → 37 for 0066, +3 → 40 for 0068). If ADRs are accepted out of order, renumber at acceptance. Three things no single ADR could fix, left for whoever accepts the last of them: (1) 0052, 0061 and 0064 each partially supersede ADR 0028 item 1's "Paths and methods" text and the replacement texts do not chain; merge them into one text; (2) ADR 0028's "Retry after an unknown outcome" table has no row for 0054's five attachment endpoints or 0068's three mail endpoints; (3) `Purpose::ALL` reaches 35 once 0060, 0066, 0071 and 0072 all land, and no ADR states that final figure. 0054's clause (c) was read as an amendment to INV-15, not a new invariant; if it is new, ids from INV-80 on shift by one.

## 4. Dependency requests waiting for the owner

| Crate | For | Governing ADR | Crypto | Why |
|---|---|---|---|---|
| `regex` (or `regex-lite`) | Regex match mode, M2 (gap 29) | ADR 0037 §4 (Accepted) | No | Non-crypto per the scout — the registrable-domain gate is already enforced; just `cargo deny` + ordinary justification, not an ADR gate. |
| `aes` 0.9.3 / `cbc` 0.2.1 / `salsa20` 0.11.0 | KDBX import, M3 | ADR 0029 (Accepted) | Yes, pre-approved | The full ADR 0009 checklist already runs inline in ADR 0029 point 2; only the go-ahead to add them to `Cargo.lock` is missing. |
| `wasm-bindgen-test` | wasm32 KAT vectors under Node, M1 (gap 07/43) | ADR 0019 §10 (Accepted) | No | Dev-dependency only; the binding smoke-test is already required. |
| `utoipa` (recommended) | OpenAPI 3.1 description for `/api/v1`, M1 (gap 20) | ADR 0002 pt.3 (Accepted part) | No | Mechanism already required; the generator itself was never chosen. |
| `uniffi` 0.31.2 | `rizzy-ffi`, M3 (macOS) | ADR 0019 §4.1 (Accepted) | No | Pinned per owner decision 8; wait for Spike S1 to run and be recorded first. |
| A vetted image decoder (e.g. `image`) | Icon-proxy re-encode, M3 | 0052 (Proposed) | No | THREAT_MODEL §7.11 requires safe-Rust re-encoding before caching or serving. |
| A Markdown parser + HTML sanitizer | Markdown in notes, M3 | 0062 (Proposed) | No | Neither exists in `apps/web` yet. |
| `qrcode` (rv) + a JS QR library | Secret Key QR transfer, M3 | none — ADR 0004 already covers the string format | No | Pure rendering/scan convenience over an already-Accepted format. |
| `webauthn-rs` 0.5.5 | Server WebAuthn 2FA, M3 | 0058/0059 (Proposed) | Yes | Ceremony correctness (origin/RP-ID binding, counter/clone, attestation) needs an audited crate. |
| `tokio-tungstenite` | `notify` WebSocket, M3 | 0061 (Proposed) | No | Needed via axum's `ws` feature once the protocol ADR lands. |
| `metrics-exporter-prometheus` or hand-rolled | Prometheus metrics, M3 | ADR 0010 §1 (Accepted) | No | Listener boundary already decided; the instrumentation choice is still open (§5). |
| `lettre` (candidate) | Share-verification OTP mail, M5 | 0066 (Proposed) | No | No outbound-mail crate exists yet. |
| `mail-parser` | Inbound SMTP MIME parsing, M6 | 0069 (Proposed) | No | Needs a fuzz target (untrusted-input parser), per CLAUDE.md. |
| `mail-auth` 0.13.3 | SPF/DKIM/DMARC verification, M6 | 0070 (Proposed) | Yes | DKIM signature verification against untrusted, DNS-published keys. |
| An SMTP-listener crate, or hand-rolled | Inbound SMTP receiver, M6 | 0069 (Proposed) | No | Only needed if 0069 picks rizzy-vault's own listener over an MTA front. |

## 5. Other owner decisions (non-ADR)

| Item | Recommendation |
|---|---|
| **CI workflow edits** (gaps 15, 17, 18, 34, 40's CI wiring, plus INV-40/`check-tables` wiring): nightly convergence job, rootless-Podman/compose smoke test, PostgreSQL CI job, extension Chromium+Firefox Playwright (Firefox still has no automated e2e at all, §7), `check-tables`/`check-spdx`/INV-40 CI wiring | Approve as one batch — every item is CI-only and already authorized by an Accepted ADR; the only blocker is CLAUDE.md's edit-ask rule. |
| **26** Sign and ship the global equivalence list | Accept ADR 0044 first (§3), then generate the offline Ed25519 key and sign `list_version 1` — reserved to the owner alone (ADR 0038 §3–4). Also still needed: create the `equivalence-list` GitHub label gap 36's templates already assume exists. |
| **39** Trigger the Fuzz GitHub Actions workflow once | Run it now — 45 targets exist and type-check in CI but have never executed. |
| **20** Choose the OpenAPI generator | `utoipa` (also in §4). |
| **41** App Store additional-permission text | Stays blocked until lawyer review; no agent may draft or commit placeholder text. |
| **08** Normative item-record vectors: rizzy-core JSON schema vs. rizzy-sync Rust constants | Rizzy-core's JSON schema, produced now — ADR 0018 is Accepted, this is pure test coverage. |
| **05/42** Wycheproof + FIPS 180-4 vector files | Approve vendoring (with an ADR 0017 attribution check) plus a dev-dependency-only integration test for the Identity-KSF OPAQUE vectors. |
| **X2/04** A `rizzy-core` `cfg(test)`-only accessor for KSF run counts and private/unlock-key search | Approve, strictly `cfg(test)`-gated so it ships in no release artifact. |
| **06** RFC 9807 OPAQUE vectors (need opaque-ke's Identity KSF) | Approve a dev-dependency-only integration test under `crates/rizzy-core/tests/`. |
| **07/43** KAT vectors as wasm32 under Node | Approve `wasm-bindgen-test` (§4) plus its CI job (folds into the CI batch above). |
| **19** `cargo xtask check-tables` scope | Build the `auth_`/`vault_` check now — already authorized, no blocker (§6); treat `storage_*`/backup-query coverage as a fast-follow once this scope question is answered. |

## 6. Next work cleared now

Implementable now (status partial or not_started, no Proposed ADR in the way). `check-tables` is the only M1 row and the one §5 gap 19 cross-references — do it first; the rest are M3 and unordered among themselves.

| Row | MS | Governing ADR |
|---|---|---|
| `cargo xtask check-tables` (`auth_`/`vault_` prefixes only — `storage_*` scope is open, §5 gap 19) | M1 | ADR 0011 pt.7 + ADR 0016 R4 (Accepted) |
| Heuristic multi-step login form support | M3 | ADR 0036/0037/0040 (Accepted) |
| Design-system cross-toolkit token generator | M3 | ADR 0014 §5 / 0019 §13 (Accepted) |
| Command palette (Cmd/Ctrl+K) | M3 | ADR 0014 (Accepted) |
| Item detail view polish (large-type password display) | M3 | ADR 0014 (Accepted) |
| Accessibility CI checks (contrast, screen reader, native toolkits) | M3 | ADR 0014 §5 / 0019 §13 (Accepted) |
| Transparency page (built client-side from data existing endpoints already return; no new endpoint) | M3 | None governs it; ADR 0028 items 1/14 (Accepted) only constrain it. A server-reported variant would need a new endpoint and so a new ADR (ADR 0048 is Proposed) |
| Onboarding flow (import wizard, Emergency Kit, extension install) | M3 | ADR 0008 / 0014 (Accepted) |
| i18n scaffold (English only) | M3 | ADR 0014 §4 (Accepted) |
| Conflict UI — explicit "keep both / pick one" chooser | M3 | ADR 0012/0018/0021 (Accepted) |
| PostgreSQL support itself (migrations, instance lock exist; only its CI job is blocked, §5) | M3 | ADR 0011 (Accepted) |
| Podman Quadlet units + auto-update | M3 | ADR 0010 §4 (Accepted) |

**Excluded on purpose** because their real dependency is a Proposed ADR, not an Accepted one: every M5 sharing row (0063–0067), every M6 mail/alias row (0068–0070 — including the mailbox-UI and OTP-extraction rows that look `implementable_now` on their own but need the mail pipeline those ADRs build), M3 favicon proxying (0052), Watchtower/HIBP (0053), attachments (0054), the 5 new M3 item types (0055), the local index (0056), OS-keystore unlock (0057), WebAuthn 2FA (0058/0059), the admin panel (0060), push/live sync (0061), Markdown notes (0062), session/device management — force logout (0075: ADR 0028 + CRYPTO §5.10 do not govern it, because item 1 freezes 27 endpoints and none lists or ends sessions, and §5.10 covers only token issuance, device auth and request signing), and M8's backup/signing/CXF rows (0071–0074). `rizzy-ffi`/`uniffi` is also excluded: gated on Spike S1, which has not run, not only on a dependency add.

## 7. Known residuals

- **A7 inline-menu clone.** Any clone of the inline-menu iframe still passes the sender check and can push a generated password into the real field — fixed only by ADR 0043, not yet accepted. Not fixed, only ruled out so far by non-reproduction: a closed shadow DOM and CSSOM as alternate escape routes.
- **The 1000 ms trailing-visibility window** (`isFillAllowed`'s Gate B) is an unvalidated tunable on slow devices — margin was measured against this harness's own positive control, not against real low-end hardware.
- **PSL provenance.** The embedded snapshot's content is pinned by SHA-256 (`cargo xtask check-deps`) and its package version is pinned, but the public-suffix-list project's own upstream commit hash is not recorded anywhere in the repo.
- **Firefox has no automated extension e2e.** The Chromium Playwright suite doesn't run in CI either (§5); Firefox has no suite to run.
- **`ContextNotSettled`** (new this session): a real sync production defect the convergence harness found, pinned as an `#[ignore]`d regression test rather than fixed. Needs triage before gap 16's property coverage can be called complete.
