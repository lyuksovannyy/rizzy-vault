# Owner decisions needed: Proposed ADRs 0083–0114 (2026-10-25)

Every draft below came out of the [2026-10-25 gap review](2026-10-25-adr-gap-review.md). Each question has the drafter's recommendation; "rec" is short for recommended.

- **Accepting as recommended:** an ADR accepted with "as recommended" takes every recommendation listed for it.
- **Numbers:** invariant (INV-107…125), accepted-risk (AR-30/31) and purpose (0x0107) numbers are provisional, allocated by the lead without collisions. Confirm them at acceptance.

## Already scheduled work, blocked only on acceptance

| ADR | Topic | Open questions (rec) |
|---|---|---|
| [0083](../adr/0083-db-backup-plaintext-len-erratum.md) | 0071 erratum: `plaintext_len` is bound by the reader's framing | none |
| [0084](../adr/0084-bare-cxf-passkey-export.md) | Bare unencrypted CXF export | the same gate as CSV/JSON plus its own warning (rec yes); the plaintext JSON export already holds passkey private keys and says nothing about it, so a separate ADR is needed (rec yes); ROADMAP §4.10 edit |
| [0085](../adr/0085-admin-authentication-bootstrap.md) | Admin login, bootstrap token, TOTP | is token from `secrets init`, armed at first start, enough? (rec yes); TOTP only at M3 (rec yes); admin trusted-proxies setting; known-browser cookie 90 d / 5 / one use |
| [0086](../adr/0086-instance-settings-persistence.md) | Instance settings table, sealed SMTP credential | refuse a 0-hour wait on multi-account instances (rec yes); recovery-wait screen only after 0090 (rec yes); pad the SMTP password (rec yes) |
| [0087](../adr/0087-invite-only-signup-tokens.md) | Invite-only signup | operator CLI before the admin panel (rec yes); **default `RIZZY_SIGNUP` = invite** (rec yes); no unbound invites at v1.0 (rec yes) |
| [0090](../adr/0090-per-account-security-event-log.md) | **Security event log (blocker B2)** | store no IP/user agent (rec none at M3); ROADMAP row in §4.3 at M3 (rec yes); logins that pass KE3 but never finish 2FA stay unlogged (rec accept) |
| [0100](../adr/0100-notification-mail.md) | Notification mail, account email | let a fresh web (OPAQUE) session cancel a pending recovery, via a separate ADR (rec yes); M3 with/after 0086; security-alert mails without per-kind opt-out (rec yes); no private-CA relays at M3 (rec yes); accounts nobody can notify: warn, don't block (rec yes) |
| [0103](../adr/0103-disable-user.md) | Disable user | pause (not cancel) a pending recovery (rec pause); `account_disabled` after full auth (rec yes) |
| [0104](../adr/0104-metrics-endpoint.md) | Metrics on the admin listener, off by default | no metrics from processes without the api role at M3 (rec yes); per-endpoint route labels (rec yes) |
| [0106](../adr/0106-agpl-source-url.md) | AGPL §13 source link | no separate commit member (rec no); formally supersede 0017 §7 (rec no); also replace ADR 0002 point 3's list (rec yes); add an M1 ROADMAP row (rec yes) |
| [0114](../adr/0114-server-settings-list.md) | One settings register (19 names) | owner may add register rows at later acceptances (rec yes); accept the names and bounds the code chose (rec yes) |

## Errata to Accepted ADRs (no behaviour change, or the code already does it)

| ADR | Topic | Open questions (rec) |
|---|---|---|
| [0088](../adr/0088-device-state-record-grammar.md) | **One device-state grammar (blocker B1)** | also replace ADR 0057 §2's partial grammar (rec yes) |
| [0095](../adr/0095-owner-answers-0023-0028-recorded.md) | Owner answers recorded only in commits (0023–0028) | accept the `Retry-After` details the code adds (rec yes) |
| [0098](../adr/0098-security-key-limits-and-endpoints.md) | Security-key caps and the six endpoints | 32 keys × 1,984 B (rec) vs 16 × 4,032 B; no assertion needed to remove a key (rec no) |
| [0109](../adr/0109-sync-cursor-held-header.md) | Sync cursor past a held header: no stall exists, the code's rule is written down | clarification only (rec yes); healing guard (rec yes) |
| [0113](../adr/0113-breach-check-endpoint.md) | Breach endpoint as shipped | upstream failure stays 500 (rec yes); shared 14-day TTL (rec yes) |

## Fixes for real gaps (code changes after acceptance)

| ADR | Topic | Open questions (rec) |
|---|---|---|
| [0068](../adr/0068-alias-identity-model.md) | Alias tombstone (**blocker B3**), post-v1.0 | deleted addresses never reusable (rec never); keep them after account deletion (rec yes); caps 1,000 / 100 per day |
| [0089](../adr/0089-extension-frames-and-save-dialog.md) | One content-script message list; save-dialog clickjacking gates and token | pending prompt lifetime 600 s (rec) vs 120 s; exempt kind-only writes from W5 (rec no) |
| [0091](../adr/0091-revoked-device-rotation-race.md) | Revoked-device rotation race | revocation window length (rec 10 min, fixed) — see the ADR |
| [0092](../adr/0092-rotation-size-limits.md) | Rotation size: write caps + staged rotation | account cap 65,536 (rec) vs 98,304; staging at M3 (rec yes); refuse healing past the vault cap (rec yes); warnings at 80/95 % (rec yes) |
| [0093](../adr/0093-attachment-lifecycle.md) | Attachments deleted after purge; import drops refs; unsupported items refuse moves | carry retired 0x0009 items opaquely (rec no) |
| [0094](../adr/0094-backup-container-limits.md) | Streaming backup, 1 TiB cap | 1 TiB (rec); stdin restore stays in memory at 2 GiB (rec yes); no server-side quota warning (rec no) |
| [0096](../adr/0096-binding-secrets-and-kdbx-worker.md) | Secrets that cross the binding; KDBX inside the one Worker | no cancel after a web KDBX import starts (rec yes); lower the web AES-KDF rounds cap if over 60 s (rec yes); create-and-store passkey call in M3 (rec yes) |
| [0097](../adr/0097-website-matching-corrections.md) | Matching: compared URL, Regex mode, settings readable regardless of PSL | **dotless names (`nas`) in user groups: refuse (rec, option B)** vs allow; approve `regex-lite =0.1.9` (rec yes) |
| [0099](../adr/0099-website-icons-opt-in.md) | Favicons opt-in (ACCOUNT_SETTINGS tag 0x0005) | **default off** (rec) |
| [0102](../adr/0102-native-client-tls.md) | Native-client TLS (1.3 only, private CA through the core) | Android floor API 29 (rec); byte-identical TLS copies vs a new crate (rec copies); Mozilla roots on Windows/Linux (rec) |
| [0105](../adr/0105-secret-key-qr.md) | Secret Key QR (device to device) | no QR on the Emergency Kit (rec); web vault may show it (rec yes); accept the data-dependent encode residual (rec yes); accept 0096 first (rec yes) |
| [0107](../adr/0107-backup-key-retention.md) | Backup keys kept until an evidence-gated retire | ADR 0072 remote scan sources, decided there (rec yes); `secrets restore` reports, doesn't block (rec yes) |
| [0108](../adr/0108-interrupted-recovery-exit.md) | `rv recovery abandon` | server ends older recovery sessions (INV-122) (rec yes); the probes are real recovery starts (rec yes); no `--force` (rec no) |
| [0110](../adr/0110-passkey-user-verification.md) | Passkey UV only after a recent password check | **window 2 min (rec)** vs always vs 5 min vs keep today's; "preferred" when stale: UV=0, no prompt (rec) |
| [0111](../adr/0111-extension-session-and-idle-lock.md) | No storage.session fallback; idle lock on Chromium | **Firefox build moves to MV2 with a persistent page (rec)**; accept with/before 0096 (rec) |
| [0112](../adr/0112-core-dumps-windows-macos.md) | Panic-exit hook; macOS RLIMIT_CORE; Windows residual AR-31 | panic exit status 101 (rec); accept AR-31 rather than withdraw rv on Windows (rec) |

## Policy and legal

| ADR | Topic | Open questions (rec) |
|---|---|---|
| [0101](../adr/0101-native-client-licensing.md) | Client repositories AGPL with two §7 permissions (stores, platform libraries) | client licence AGPL (rec yes); the store permission covers every store class from v1 (rec yes); Mac App Store with iOS in M7 and the Microsoft Store in M3 after legal review (rec); accept the Windows App SDK licence terms if the legal review clears them (rec); Qt exception (rec yes); one expanded legal review (rec yes, cost unknown) |

## Questions the review raised that no draft answers

- **Signup default.** ADR 0003 says invite-only, while the code and CRYPTO.md say `closed`. Settled by accepting 0087 with default invite, or by an erratum to 0003.
- **ADR 0009's status line** lacks the 0029 entry (review C2). Owner act.
- **A 0-hour recovery wait on a multi-account instance** (THREAT_MODEL Q-15). 0086 Q1 recommends refusing it.
- **ADR 0045:** the web-vault banner, and the reach of point 6 (raised 2026-10-24).
- **INV-63 narrowing** by the docs-hygiene track: confirm it is a mechanism edit.
- **Order of acceptance where drafts overlap:**
  - 0096 → 0105, and 0096 with 0111;
  - 0090/0098/0100 all replace ADR 0028 item 1's first sentence: merge at acceptance;
  - 0091/0092/0103 restate ADR 0028 item 3's code list;
  - the settings sentence: accept 0114 first, then the others add rows.
