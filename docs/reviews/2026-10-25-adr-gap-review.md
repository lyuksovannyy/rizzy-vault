# ADR gap review, 2026-10-25

Ten read-only reviewers checked every ADR (0000–0087) against the gap checklist below, in nine ADR ranges plus one cross-cutting pass. The raw findings, each with a quote and a file:line, are in [2026-10-25-raw/](2026-10-25-raw/) (`G01`–`G10`). This file merges duplicates and groups them by theme.

- **Checklist:** unresolved decisions; underspecified mechanisms; contradictions; dangling references; security coverage; drift from the code.
- **Totals:** 240 findings, 3 blockers, 97 major, 140 minor. Several findings were found independently by two to four reviewers.
- **Fix routes:**
  - **owner:** an owner act or question;
  - **erratum:** a new Proposed ADR that corrects an Accepted one;
  - **new ADR:** a missing decision;
  - **draft:** edit a Proposed ADR before acceptance;
  - **doc:** CRYPTO/THREAT_MODEL/ROADMAP/README;
  - **code:** a code fix.

## 1. Blockers

| # | Finding | Raw ids | Route |
|---|---|---|---|
| B1 | **ADR 0046 contradicts ADR 0057 on the device-state record.** 0046 (accepted 2026-10-24) replaced ADR 0026 §2's grammar with a record-version-1 block and says `RECORD_VERSION` stays 1. 0057 (accepted 2026-10-22) writes version 2 with `has_ks`/forward fields. Neither supersedes the other. The code (and the 0046 implementation) follows 0057's version 2. | G05-12 | erratum restating the combined grammar |
| B2 | **The per-account security event log (INV-69) has no ADR.** It is required by INV-69 (Accepted, M3, with a named test), ADR 0058 point 4 / INV-83 ("notify the user" of a cloned key), THREAT_MODEL §7.6 (listed as an M1 mitigation), and the 0085/0086 admin screens (disable user, recovery wait). | G10-15, G09-15, G06-10 | new ADR |
| B3 | **Alias takeover (Proposed ADR 0068).** Deleting a masked-email alias frees its address, so another account can register it and receive the old owner's password resets. There is no tombstone, invariant or test. | G07-12 | draft |

## 2. Accepted texts that contradict each other or the code

| # | Finding | Raw ids | Route |
|---|---|---|---|
| C1 | ADR 0043 and ADR 0076 each give a different binding replacement for ADR 0036 §4's first bullet and ADR 0040 point 2. Each "sends only" list forbids a message the other requires. HANDOFF promised a reconciling ADR. | G08-1 | erratum |
| C2 | ADR 0009's status line lacks "ADR 0029 (…in part)", so 0009's `chacha20` "dev-dependency only" row still binds against 0029. KDBX import can't satisfy both. | G04-4, G10-1 | owner (status line) |
| C3 | Owner answers that live only in commit messages and contradict the Decision text: ADR 0026 answers 5/6 (alarm kind 4, removal under alarm; the code follows the answers), ADR 0028 item 10 (says http origins are not refused; the code refuses them), ADR 0027 §6 ("binds only if Q4 answered yes"; 0055 still treats it as conditional). ADRs 0023–0025 have the same commit-only record, but there the answers agree with the text. | G03-10, G04-1, G03-13, G03-7 | owner (record the answers) + erratum where the text contradicts |
| C4 | ADR 0007 point 6 says backup files are JSON; ADRs 0023 and 0071 define binary containers without superseding it. The CRYPTO.md:809 edit 0071 promised is missing. | G01-8 | erratum + doc |
| C5 | Signup default: ADR 0003 point 9 says invite-only by default (M1); CRYPTO §5.9 says the M1 default is invite-only; ROADMAP has invite-only at M3; the code ships `closed`; Proposed 0087 extends `RIZZY_SIGNUP` without superseding ADR 0048 §1 / 0028 item 12. | G01-4, G10-18, G09-23, G09-22 | owner question, then erratum + draft 0087 |
| C6 | ADR 0037 §2 point 6 (path/query only for *Starts with*/*Regex*) contradicts §4's *Exact* "full normalised URL". The code follows a third reading. | G04-17 | erratum |
| C7 | ADR 0044 owner answer 1 assumes ADR 0042's PSL check covers the same inputs; it rejects dotless names (`nas`) that 0044 says must not be rejected. | G05-7 | owner question |
| C8 | ADR 0045 owner answer 2 (banner in the web vault) contradicts Decision point 4 (no notice to OPAQUE sessions), and point 6 is only half reachable (known; reported to the owner on 2026-10-24). | HANDOFF | owner question |
| C9 | ADR 0029 cancels KDBX Argon2 by killing a Web Worker, which conflicts with ADR 0013's single Worker that holds the vault. | G04-5 | erratum |
| C10 | ADR 0013 §3 rule 2's closed list of secrets that may cross the binding omits the bearer token (already passed to JS, `rizzy-wasm/src/http.rs:124`), request signatures, the 2FA enrolment secret and the KDBX password. | G01-20 | erratum |

## 3. Decisions that Accepted ADRs or M1–M3 ROADMAP rows rely on, with no ADR

| # | Missing decision | Needed by | Raw ids |
|---|---|---|---|
| M1 | **Revoked-device rotation race** ("M3 device-management ADR"). | ADR 0022 point 5, ADR 0006 Risks, CRYPTO §11.6, AR-18; ADR 0075 answer 1 passed it on. | G01-6, G02-14, G07-42, G10-26 |
| M2 | **Outbound notification mail and an account email address.** | ADR 0008 decision 2 (recovery without 2FA relies on it), CRYPTO §11.9, ROADMAP M3. The only design (0066) is Proposed, post-v1.0, and keeps the SMTP password unsealed, against INV-86. | G01-10, G05-10, G10-16, G07-1 |
| M3 | **Native-client repository licensing** (ADR 0019 §15: client licence, App Store permission, Qt LGPL, WinAppSDK). | Before the first M3 client release (macOS). | G02-6, G03-1, G10-27 |
| M4 | **Client TLS policy** for `rizzy-ffi`/`rizzy-ffi-cpp` and the Apple/Android hosts (TLS floor, root store, private CA). ADR 0030 covers rv only. | M3 native clients | G03-2 |
| M5 | **What "disable user" does.** | ADR 0060's M3 admin screen | G06-15, G10-17 |
| M6 | **Metrics endpoint content and access.** | ROADMAP M3; ADR 0060 answer 4 places it | G06-16, G10-20 |
| M7 | **Secret Key QR transfer payload.** | ROADMAP M3 | G10-21 |
| M8 | **WebSocket push.** Only Proposed 0061, which also lacks reconnect/missed-signal rules and a pre-auth socket cap. | ROADMAP M3 | G10-19, G06-18, G06-20 |
| M9 | **AGPL §13 source URL** (version-endpoint field, web footer). ADR 0028's closed lists leave no room for it. | ADR 0017 §7 | G02-5 |
| M10 | **Backup-key retention.** 0071 answer 3 defers it to Proposed 0072, which never prunes. | ADR 0071 | G07-27, G07-31 |
| M11 | **Regex match mode** (engine, dialect, full-match rule, limits); unbuilt. | ADR 0037, M2 Must | G04-16 |
| M12 | **Breach-check endpoint** (path, shape, codes, caps, the two settings). | ADR 0053 | G05-25 |
| M13 | **OpenAPI generator / committed OpenAPI file.** | ADR 0002 | G04-2 |
| M14 | **cargo-vet for the crypto crates** (M1 owner decision); not done and not tracked. | ADR 0009 decision 2 | G01-11 |
| M15 | **Low-end-phone KDF spike result** gating `kdf_id` 1. | ADR 0004 | G01-5 |

## 4. Accepted mechanisms with a data-loss, limit or recovery gap

| # | Finding | Raw ids | Route |
|---|---|---|---|
| D1 | Purging an item (and ADR 0081's move, which purges the source) never deletes its attachments, so blobs and quota leak. Confirmed in code: `move_item`/`purge_item` don't call `attachments/delete`. | G06-1 | erratum + code |
| D2 | Export/import keeps `attachment/<id>/` fields but not the contents or keys, so re-import creates dangling attachments with no warning. | G03-12, G06-2 | new ADR |
| D3 | ADR 0023's 2 GiB backup reader cap is below one account's 5 GiB default quota (attachments are DB rows), so one account can stop `backup`. The promised revisit in 0054 never happened. | G03-6, G06-3 | erratum |
| D4 | Key rotation is one request, capped at 65,536 wraps per vault and by the 32 MiB body limit (about 115k wraps). Nothing caps growth, and no refusal code is defined: a large account can't revoke a stolen device or finish recovery. | G03-9 | new ADR |
| D5 | No cap on security keys per account, although the login state carrying every credential is refused above 64 KiB. The code picked 32 on its own; list/remove endpoints and `pending_id` are defined only in code. | G08-6, G06-11 | erratum |
| D6 | A retired `0x0009` (bank) item on a cross-vault move or "move items to Personal, then delete the vault": the importer refuses unsupported types, so the item can be lost with the vault. | G08-8 | erratum + code |
| D7 | ADR 0042's PSL check runs on read: a PSL update can make a whole ACCOUNT_SETTINGS record unreadable, vault directory included. "Blocks writes until resolved" has no resolution path. | G05-1, G05-2 | erratum |
| D8 | ADR 0046 has no exit when the user can't type the new master password of an interrupted recovery (`device forget` refuses stage 3; INV-71 forbids a new kit). | G05-13 | erratum |
| D9 | ADR 0050: the sync cursor advances past a held header, with no rule for falling back when the hold lapses or is lost on restart; possibly a permanent stall (not confirmed). **Resolved** by [ADR 0109](../adr/0109-sync-cursor-held-header.md) (Accepted 2026-10-25): no permanent stall; the cursor is derived, never stored, passes a held link only for the next page of its own sequence, and rewinds at a lapse or a load. | G05-21 | erratum |
| D10 | ADR 0047 `invalidate` doesn't say what happens to the ADR 0071 backup keys. The implementation keeps them on a setup-only loss and makes fresh ones on a whole loss (owner to confirm). | G05-15 | owner |

## 5. Security coverage

| # | Finding | Raw ids | Route |
|---|---|---|---|
| S1 | A 0-hour recovery wait is accepted on any instance; "0 only on single-account instances" is open question Q-15 and is not enforced. | G01-9 | owner question |
| S2 | Passkeys: `UV=1` on every assertion because the vault was unlocked (possibly 15 min earlier); no per-ceremony verification and no recorded residual. | G04-20 | owner question → erratum or residual |
| S3 | Extension save dialog (ADR 0076): no clickjacking requirement (the code checks only `isTrusted`, with no visibility gate), and its token and sender authentication are unspecified. | G08-3, G08-2 | erratum + code |
| S4 | Favicons (ADR 0052): no user opt-in. The web vault sends every item host on unlock even when the role is off; ROADMAP says "must be optional". | G05-24 | erratum + code |
| S5 | ADR 0036: the `storage.session` unlocked-state fallback can't be built as decided (precondition unmet, snapshot undefined); idle/screen-lock auto-lock doesn't run on Chromium. | G04-13, G04-14 | erratum |
| S6 | Core dumps: `rv` on Windows disables nothing, against INV-60; AR-28 covers only native apps, and the macOS mechanism is unconfirmed. | G03-8 | erratum/residual + code |
| S7 | Default site groups (ADR 0080): all 22 groups were merged with "TODO (owner)" evidence, against ADR 0038 §4 rule 1, and nothing stops signing a list with missing evidence. | G08-12 | code (xtask check) + owner evidence |
| S8 | Imported password history (`pwhist/<id>/value`) is not concealed, and Proposed 0063's "replaced in full" list drops the passkey/ssh/api/license/wifi keys: a share would include private keys and old passwords by default. | G06-6, G06-22 | owner + draft 0063 |
| S9 | ADR 0019 §5.1: image-decode limits and decoder "set in M3", never set. | G03-3 | new ADR |
| S10 | ADR 0021's known limits (AR-24–27) and ADR 0032's vault-only-rotation lag rule are left to M9, but Accepted 0081 Part B doesn't revisit them. | G02-11, G04-8 | erratum (before M9) |

## 6. Proposed drafts: fix before acceptance

- **0085:** the global login/bootstrap buckets let anyone who reaches the listener lock the operator out, against its own §9.1 (G09-14).
- **0085–0087 together:**
  - the acting admin or CLI is recorded three incompatible ways, and invite/settings actions are missing from 0085's audit list (G09-24);
  - INV-107 and purpose `0x0107` could be claimed twice (G10-11).
- **0086:** whether `auth_instance_settings` is in backups (ADR 0023 TABLES) is unstated (G09-20).
- **0087:** must name the ADR 0048 §1 / 0028 item 12 text it changes (G09-23).
- **0083:** leaves 0071's "truncating to `plaintext_len`" sentence binding while calling truncation-reliance non-conforming (G09-11).
- **0084:** the existing plaintext JSON export already holds passkey private keys without saying so (separate ADR recommended).
- **0081 Part B** (Accepted, M9; fix before M9):
  - the membership statement has no signer id (G09-2);
  - Fetch has no seq field (G09-3);
  - `vault_join` is refused after any rekey (G09-1);
  - the post-restore re-publication rule is missing (G09-4);
  - the stale migration numbers collide (G09-5).
- **0079:** the synced "last-used range" can't be written without a fresh session; the code keeps it per session (G08-9).
- **0061, 0063–0070, 0072:** the remaining findings are in the G06 and G07 raw files. The main ones:
  - 0068: alias labels not re-encrypted on rotation; no `local_part` grammar; no list endpoint;
  - 0069: `deliver` lacks the fields in the AAD; no SMTP session limits;
  - 0066: retries outlive the code expiry; anyone with the link can burn every pending code;
  - 0064's whole-bullet replacement erases three Accepted changes;
  - 0065's CSP floor;
  - 0067 and 0063 each defer the Send split to the other.

## 7. Hygiene (minor; doc fixes an agent can make)

Most of the 140 minor findings are stale references, among them:
- migration numbers in 0047 (0006 → 0011), 0048 (0007 → 0006) and 0081 (0008 → 0009);
- 0071's `Purpose::ALL` count;
- 0075 still calling 0052 Proposed;
- THREAT_MODEL INV-67's "M9 ADR" wording, and INV-100's nonexistent release checklist;
- ADR 0009's Amendments missing 0082's third webauthn-rs feature;
- CI rules bound by Accepted ADRs that have no job yet (rootless Podman, PostgreSQL job, nightly convergence run, wasm size budget), mostly already tracked in HANDOFF §5;
- the README row order for 0026.

They are listed with their fix routes in the raw files.

## What came out clean (G10)

- No registry collisions among INV ids, purposes, account-settings tags, error codes or THREAT_MODEL ids.
- Every "ADR NNNN" mention resolves.
- CLAUDE.md's "As of" list matches every status line.
- No Accepted ADR's milestone disagrees with its ROADMAP row.
- Apart from C2 and M3, every "On acceptance" edit is in place.
