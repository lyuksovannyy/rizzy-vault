# ADR 0086: Instance settings persistence: the `auth_instance_settings` table, precedence over configuration, and the sealed SMTP credential (`SERVER_SMTP_CREDENTIAL`, 0x0103)

- Status: Proposed
- Date: 2026-10-24
- Deciders: project owner
- Milestone: M3 (`rizzy-domain-auth`, `rizzy-storage` migrations, `rizzy-server` admin panel and `rizzy-vault settings`, `rizzy-core` `server_seal`)

## Context

**The owner's words, verbatim (2026-10-24):** "Settings Persistence Schema ADR (ADR 0060 Question 3): Specifies a database table in the auth domain storage (ADR 0011 follow-up) to persist dynamic runtime settings without requiring daemon restarts. Covers persisting: signup mode (Closed vs Open), account recovery wait duration, and encrypted storage for SMTP credentials (sealed under purpose 0x0103, INV-86)."

[ROADMAP §4.9](../ROADMAP.md#49-server-self-hosting--ops-m1-onward), Should, M3: "Admin panel (user list, disable user, invite-only signup, SMTP settings for notifications)". [ADR 0060](0060-admin-panel-stack-boundary.md) (Accepted 2026-10-22) fixes the panel's stack and boundary — server-rendered Askama pages in `rizzy-server`'s `http/admin_panel/`, served only on `RIZZY_ADMIN_LISTEN` under `ADMIN_CSP`, native form POSTs, no JSON admin API at M3 — and leaves three things to other ADRs. Its §4 says: "**Not fixed here:** the storage schema for what these screens toggle (signup mode, recovery wait, SMTP settings) — no such row exists today, and a toggle needs one that persists without a restart." Its owner answer 3: "The settings-persistence schema is a short ADR 0011 follow-up, required before the schema is implemented, never the implementing PR's call." Owner answer 2 fixes SMTP credentials to "Algorithm 0x01 under the server-only purpose `0x0103` (INV-86)", and the closing paragraph says: "The purpose's name, its ctx and its CRYPTO.md §8.4 row are still undecided and must be fixed by an Accepted ADR before code lands." This is that ADR. Its siblings are admin authentication (ADR 0085, Proposed in parallel; owner answer 5) and invite-only signup (ADR 0087, Proposed in parallel; owner answer 6).

What exists today (read in this worktree, V):

- **Configuration.** `crates/rizzy-server/src/config.rs` reads `RIZZY_*` settings from the environment or a `NAME=value` file, environment over file ([ADR 0028](0028-api-v1-http-conventions.md) item 12). `RIZZY_SIGNUP` is `closed` (default) or `open` into `SignupMode { Closed, Open }`; any other value is a startup error. `RIZZY_RECOVERY_WAIT_HOURS` is "whole hours from 0 to 720 (30 days), default 72", applying "to recoveries started after the setting changed: a pending recovery keeps the release time it was opened with"; 0 logs a startup warning (threat model Q-15's sub-question is open). `rizzy-domain-auth`'s `MAX_RECOVERY_WAIT_MS` is 30 × 24 h. Both values are copied once at startup into `AuthConfig` (`signup: SignupPolicy`, `recovery_wait_ms`), so changing them needs a restart. There is no SMTP setting at all.
- **Storage.** [ADR 0011](0011-storage.md): the `auth` domain owns `auth_`-prefixed tables (rule 5), queries live in `queries/*.sql` (rule 7), portable column types and no JSON columns (rule 4), forward-only migrations per engine (rule 8). This ADR's migration number is the **next free one at implementation**.
- **Server sealing.** [CRYPTO.md §5.11](../CRYPTO.md#511-server-side-encryption-not-zero-knowledge): subkey `HKDF(ikm = server_data_key, salt = empty, info = LABEL("server/<purpose>") ‖ 0x00 ‖ u32(data_key_id), 32)`, Algorithm 0x01, server-only purposes 0x0100–0x01FF; "The DB records the `data_key_id` of every sealed row, and the server refuses to start if a row names an id the file lacks"; rotation by `rizzy-vault secrets rotate --data-key`, after which `worker` re-seals. Its `0x0103` bullet: "It is the same construction as `SERVER_TOTP_SECRET`, with the SMTP password as the plaintext." The code is `rizzy-core`'s `server_seal.rs`, `labels.rs` and `envelope/purpose.rs`, with KATs in `crates/rizzy-core/tests/vectors/{derivations,envelopes}.json`.
- **Invariants.** THREAT_MODEL INV-86: "An SMTP password is sealed at rest with CRYPTO.md §5.11's Algorithm 0x01 server-side envelope, under the server-only purpose `0x0103`. It is never logged (INV-48), and the admin UI never redisplays a saved value, only whether one is set." INV-69: admins authenticate separately with a second factor, the UI has its own CSP and CSRF defence, and "Every admin action, including a change to the recovery waiting period, goes into the affected users' security event log." The §7.19 E-row: "A 0 wait only on single-account instances (Q-15)."
- **Enumeration.** [CRYPTO.md §5.9](../CRYPTO.md#59-account-enumeration): registration is an enumeration oracle; "The M1 default is invite-only signup … Open signup is opt-in, rate-limited per IP".
- **Is SMTP sending in scope, and when?** ROADMAP §4.9's admin-panel row names "SMTP settings for notifications" at **M3, before v1.0** (v1.0 is M8). [ADR 0010](0010-server-shape.md) §1 / [ADR 0022](0022-server-mode-only.md) §2 give `worker` the outbound "SMTP relay for notification mail, if configured (M3)", and [ADR 0008](0008-account-recovery.md) decision 5 notifies "the account email (if mail is configured)". But **no Accepted ADR defines the sender**: what mail is sent, to which address (no account-email column exists), TLS and retry rules. The only design is [ADR 0066](0066-share-email-otp-verification.md) (Proposed, M5, after v1.0), which proposes `RIZZY_SMTP_URL` / `RIZZY_SMTP_FROM` as configuration settings. Receiving mail (M6) and sending from aliases (ROADMAP §4.8, "Won't for v1.0") are unrelated.

The forces: settings must change without a restart; every replica (profile C, M10) must agree; the environment-driven deployments of M1 must keep working; a DB-only reader must not learn the SMTP password; a hijacked admin session must not be able to send the stored password to a server of its choosing; and no new cryptography.

## Decision

**Supersedes: none.** This ADR fulfills ADR 0060 §4's "Not fixed here" paragraph and owner answer 3, adds one table under ADR 0011 rule 5, and gives purpose `0x0103` its name and ctx. It changes no Accepted text. **Numbers:** it uses the reserved server-only purpose 0x0103 (INV-86) and adds no invariant of its own; its siblings are [ADR 0085](0085-admin-authentication-bootstrap.md) (INV-107, 0x0107) and [ADR 0087](0087-invite-only-signup-tokens.md) (INV-108, no purpose).

### 1. The table

One table, owned by `rizzy-domain-auth`, one migration per engine named `NNNN_auth_instance_settings.sql` (NNNN = next free number at implementation). SQLite:

```sql
-- Instance-wide settings an admin changes at run time (ADR 0086). A key has a row only after an
-- admin or `rizzy-vault settings` saved it; without a row the configuration value applies (§2).
CREATE TABLE auth_instance_settings (
    setting_key   TEXT    NOT NULL PRIMARY KEY CHECK (length(setting_key) BETWEEN 1 AND 64),
    value_text    TEXT    CHECK (value_text IS NULL OR length(value_text) BETWEEN 1 AND 1024),
    sealed_value  BLOB    CHECK (sealed_value IS NULL OR length(sealed_value) <= 4096),
    data_key_id   INTEGER CHECK (data_key_id >= 0),
    setting_seq   INTEGER NOT NULL CHECK (setting_seq >= 1),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0),
    updated_kind  TEXT    NOT NULL CHECK (updated_kind IN ('panel', 'cli')),
    updated_admin_id BLOB CHECK (updated_admin_id IS NULL OR length(updated_admin_id) = 16),
    CHECK ((updated_kind = 'panel') = (updated_admin_id IS NOT NULL)),
    CHECK ((value_text IS NOT NULL AND sealed_value IS NULL AND data_key_id IS NULL)
        OR (value_text IS NULL AND sealed_value IS NOT NULL AND data_key_id IS NOT NULL))
) STRICT;
```

PostgreSQL uses `text`, `bytea` and `bigint` with the same checks (`octet_length` for the byte lengths). Every row holds exactly one of a plain value or a sealed value; a sealed row names its `data_key_id` (CRYPTO §5.11). `setting_seq` counts writes of that key from 1 (an aid for the event log and the concurrency test, not a security field). `updated_kind` and `updated_admin_id` record who wrote the row in [ADR 0085](0085-admin-authentication-bootstrap.md) §8.1's actor encoding, the one ADR 0085's audit log and ADR 0087's invites use too: `panel` with the acting admin's `admin_id`, or `cli` with `NULL` when `rizzy-vault settings` (§6) wrote it. There is no foreign key, so removing an admin does not erase who changed what. Every write also appends ADR 0085's `setting_changed` audit row in its transaction (ADR 0085 §9.3), from the panel and the CLI alike. No SQL `CHECK` lists the key names: the set of keys is closed **in Rust** (§1.1), so a later key needs no table rebuild, and an unknown key in the table is a startup error naming the key (it can only come from a DB writer or a newer binary, and `rizzy-storage`'s `migrate.rs` already refuses a database a newer release migrated, with `VersionMissing`).

#### 1.1 Typed keys and value encoding

`value_text` is the key's **canonical ASCII text**, the same syntax as its configuration setting where one exists, parsed by the **same function** `config.rs` uses (one parser, already covered by the `server_config` fuzz target). The writer stores only the canonical form; the reader rejects anything else (no leading zeros, sign, whitespace or upper case), so each value has exactly one encoding.

| Key | Type | Canonical `value_text` | Range / limits | Configuration fallback (§2) | Built-in default |
|---|---|---|---|---|---|
| `signup_mode` | enum | `closed` \| `open` | `invite` is **reserved for ADR 0087** and refused by the parser until that ADR is Accepted and implemented. `RIZZY_SIGNUP`'s own value set is ADR 0048 §1's settings sentence (the binding text of ADR 0028 item 12), which ADR 0087 §10 supersedes to add `invite`; this ADR does not change it | `RIZZY_SIGNUP` | `closed` until ADR 0087 is Accepted and implemented, then `invite` (ADR 0087 owner answer 2, 2026-10-25: the default becomes `invite`) |
| `recovery_wait_hours` | integer | decimal, `0` or no leading zero | 0–720 (= `MAX_RECOVERY_WAIT_MS`), whole hours; 0 under §4 | `RIZZY_RECOVERY_WAIT_HOURS` | 72 |
| `smtp_host` | host | ASCII-lowercased DNS name in A-label form, no trailing dot, 1–253 bytes; or an IPv4 / bracket-free IPv6 literal in its canonical text form | — | none | unset (mail off) |
| `smtp_port` | integer | decimal | 1–65535 | none | — (required with `smtp_host`) |
| `smtp_tls` | enum | `starttls` \| `tls` (implicit TLS) | no plaintext mode; certificate verification always on | none | — (required with `smtp_host`) |
| `smtp_username` | text | UTF-8, no control characters (U+0000–U+001F, U+007F) | 1–254 bytes | none | unset (no SMTP AUTH) |
| `smtp_from` | address | ASCII `local@domain`, domain as for `smtp_host` | 3–254 bytes | none | — (required with `smtp_host`) |
| `smtp_password` | **sealed** | `sealed_value`: a `SERVER_SMTP_CREDENTIAL` envelope (§5) | password 1–512 bytes | none | unset |

**Groups.** `smtp_*` is one group: the SMTP screen and `rizzy-vault settings` write or delete all its rows in one transaction. `smtp_host`, `smtp_port`, `smtp_tls` and `smtp_from` are present together or absent together; `smtp_username` and `smtp_password` are present together or absent together, and only when the group is present. A partial group read from the table is treated as "mail not configured", with a warning naming the keys (never a value of `smtp_password`).

#### 1.2 In the logical backup

`auth_instance_settings` is **in** the logical backup: [ADR 0023](0023-logical-backup-format.md)'s `TABLES` gains it at the end of the `auth_` block, after `auth_pending_recoveries` (it has no foreign key, so any position is valid; this one keeps the `auth_` tables together). That bumps the dump's schema version as any migration does; [ADR 0071](0071-encrypted-db-backup-format.md)'s encrypted container wraps it unchanged.

- **Why in.** Left out, a restored instance would fall back to the configuration value for every saved key without any visible change: signup could reopen, the recovery wait could shrink to the configured value, and the SMTP settings would vanish. The table holds no per-session or short-lived state, the kinds ADR 0023 leaves out.
- **The sealed row.** A restored `smtp_password` row is still a `SERVER_SMTP_CREDENTIAL` envelope under the `server_data_key` its `data_key_id` names, and the backup holds no key. Restoring it therefore needs a secrets file that holds that `data_key_id` (the current key or a retained older one), exactly as the restored `auth_totp_credentials` rows already do. With a secrets file that lacks it, the server refuses to start and names the id (CRYPTO §5.11's rule, §5 "Rotation"); `rizzy-vault settings reset smtp` (§6) is the way out, then re-entering the password. The restore documentation says to keep the secrets file, or its encrypted backup ([ADR 0011](0011-storage.md) owner decision 3), with the database backups.
- **Test** (§8): a dump and restore round trip with every key saved, the SMTP group included: the restored server reads the same effective values and opens the password with the same secrets file; with a secrets file that lacks the row's `data_key_id` it refuses to start, and after `settings reset smtp` it starts with mail off.

### 2. Precedence: the configuration is the default, a saved row wins

For every key, the effective value is, in order:

1. the `auth_instance_settings` row, if one exists;
2. otherwise the configuration value (ADR 0028 item 12: environment over file), if that key has one;
3. otherwise the built-in default.

**No seeding.** First boot writes nothing to the table: a row appears only when an admin saves a screen or an operator runs `rizzy-vault settings set`. Until then, changing `RIZZY_SIGNUP` or `RIZZY_RECOVERY_WAIT_HOURS` and restarting works exactly as in M1. After an admin saves, the row wins, and the configuration value for that key is ignored.

**Visibility.** At startup, for each key whose row overrides a configuration value that is set and differs, the server logs one warning naming the key, both values and the row's `updated_at_ms` (these keys carry no secret; `smtp_*` has no configuration fallback). The screen shows the source of every value ("saved by an admin on …", "from `RIZZY_SIGNUP`", "built-in default") and offers **"Use the configuration value"**, which deletes the row. `rizzy-vault settings reset <key>` does the same offline (§6), which is the way back when the panel is unreachable.

**Why this and not the alternatives.** *Environment always wins, screen read-only when set*: the compose examples and most M1 deployments set `RIZZY_SIGNUP`, so the ROADMAP's toggle would be dead exactly where it is used, and a routine change would need shell access and a restart. *Seed the table from the environment on first boot*: makes every later environment edit silently ineffective even though no admin ever touched the setting. *Drop the configuration settings*: breaks M1 operators and Accepted ADR 0028 item 12. The chosen rule keeps M1 behaviour until an admin acts, and makes the admin's act explicit, visible and reversible.

### 3. Live reload: read at the point of use, no cache

No process caches these values. Each consumer reads the rows it needs **inside the transaction of the action they govern**, through `rizzy-domain-auth`'s Rust API (ADR 0011 rule 5):

- **Signup** reads `signup_mode` before any name lookup, in the signup transaction. The read does not depend on the login name, so it adds no name-dependent timing (CRYPTO §5.9).
- **Recovery start** reads `recovery_wait_hours` in the transaction that opens the pending recovery and computes its release time from it; a pending recovery keeps the release time it was opened with (today's rule, unchanged).
- **`worker`** reads the `smtp_*` group and opens `smtp_password` once per delivery batch, when the sender ADR (§7) exists.
- **The admin screens** read on every GET.

Staleness is therefore **zero across any number of replicas**, bounded only by transaction isolation: an action whose transaction read the old value before the change committed completes under the old value; every action that starts after the commit sees the new one. The cost is one primary-key lookup per signup, recovery start or delivery batch, all of them rare and rate-limited paths. Polling, `LISTEN/NOTIFY` and a `rizzy-bus` event are not needed (Alternatives).

**Fail closed.** At startup the server validates every row (known key, canonical value, complete groups, `data_key_id` present in the secrets file per §5.11) and refuses to start on an error, naming the key — the same rule as a malformed configuration value. A row that fails to parse at the point of use (a DB writer changed it after startup) refuses the action it governs — signup is refused, a recovery start answers a server error, mail is not sent — and logs the key name; it never falls back to a looser value.

### 4. Signup modes and the recovery wait

- **Signup modes.** `closed` and `open` map to today's `SignupPolicy::{Closed, Open}`. `invite` is reserved: its token mechanism, storage and the `SignupPolicy::Invite` wiring are ADR 0087's. Until that ADR is Accepted and implemented, the parser refuses `invite` from the table and from `RIZZY_SIGNUP` alike, and the screen offers only Closed and Open (ADR 0060 owner answer 6). Opening signup on the screen shows CRYPTO §5.9's warning that registration is an enumeration oracle, rate-limited per IP.
- **Recovery wait.** 0–720 whole hours, matching `config.rs` and `MAX_RECOVERY_WAIT_MS`; a change applies to recoveries started after it commits. Saving 0 needs a second, explicit confirmation on the screen stating the §7.19 E-row risk, and is logged as a warning. Whether the server should *refuse* 0 on an instance with more than one account is Q-15's open sub-question, raised here as open question 1; this ADR enforces nothing more until the owner answers.
- **Events (INV-69).** A change to `recovery_wait_hours` writes, in the same transaction as the row, one entry per account into the per-account security event log. That log is ADR 0090 (Proposed, drafted in parallel; `rizzy-server`'s `lib.rs` and ADR 0075 call it "M3's"), so **the recovery-wait screen does not merge before ADR 0090 is Accepted** (open question 2). Signup and SMTP changes affect no single account; they are recorded in `updated_kind` / `updated_admin_id` / `updated_at_ms` and in ADR 0085's `auth_admin_audit` as `setting_changed` (ADR 0085 §9.3).

### 5. The SMTP credential: `SERVER_SMTP_CREDENTIAL`, 0x0103

The existing §5.11 construction, unchanged; this section only names the purpose and fixes its ctx and plaintext layout.

- **Name and label.** `SERVER_SMTP_CREDENTIAL`, purpose `0x0103`, subkey label `server/smtp-credential`: `k = HKDF(ikm = server_data_key, salt = empty, info = LABEL("server/smtp-credential") ‖ 0x00 ‖ u32(data_key_id), 32)`.
- **Key.** The **current** `server_data_key` seals; the row records its `data_key_id`. No new key enters the secrets file, and `backup_keys` are never used.
- **Envelope.** Algorithm 0x01 (CRYPTO §9.1); the purpose is in the server-only range no client allow-list contains (§9.5).
- **ctx** (CRYPTO §2 encodings): `str(smtp_host) ‖ u16 smtp_port ‖ u8 smtp_tls ‖ str(smtp_username)`, where `smtp_host` and `smtp_username` are the canonical texts of §1.1 and `smtp_tls` is 1 for `starttls`, 2 for `tls`. **Why these fields:** the password is bound to the server, port, TLS mode and user it was entered for. A DB writer who points `smtp_host` at their own server, or downgrades the port or TLS mode, gets a seal that no longer opens: `worker` sends nothing and the password never leaves for the attacker's host. The same holds for a hijacked or CSRF-driven admin session (INV-69): the screen refuses to change `smtp_host`, `smtp_port`, `smtp_tls` or `smtp_username` without the password being typed again, so a new endpoint can only ever receive a password its author already knows. `smtp_from` is not bound (changing it sends nothing new to anyone). No account id is bound (the credential is instance-wide), and no sequence number: a singleton cannot be moved between rows, and a DB writer who restores an older complete group restores a configuration an admin once entered — a residual named under Risks.
- **Plaintext.** The password bytes as typed (UTF-8, 1–512 bytes), framed and padded with [CRYPTO §8.5](../CRYPTO.md#85-plaintext-framing-and-padding)'s existing `u32(data_len) ‖ data ‖ zeros` to `max(256, Padmé(4 + data_len))`, so every password up to 252 bytes yields a 256-byte frame and a DB reader does not learn its length. This reuses §8.5's framing unchanged; it is the one way this purpose differs from `SERVER_TOTP_SECRET`, which is unpadded (open question 3). In Rust the opened value is a zeroizing `SmtpPassword` whose `Debug` is redacted (INV-48).
- **Display (INV-86).** The screen never renders the password, not even masked: the field is `type="password"`, `autocomplete="new-password"`, always empty, with "A password is set" or "No password" beside it. Leaving it empty keeps the stored seal only when no ctx field changed.
- **Rotation.** `rizzy-vault secrets rotate --data-key` already makes `worker` re-seal TOTP rows under the new current key; it re-seals the `smtp_password` row in the same pass (open under the old `data_key_id`, seal under the current one with the same ctx, update `sealed_value` and `data_key_id` in one transaction). The old key is dropped only once no row of either kind names it. §5.11's "refuses to start if a row names an id the file lacks" applies to this row unchanged; `rizzy-vault settings reset smtp` (§6) is the way out after a lost data key, followed by re-entering the password.

**CRYPTO.md §8.4 row, applied on acceptance:**

| Purpose | Id | Key / algorithm | Context fields (in order) | First used |
|---|---|---|---|---|
| `SERVER_SMTP_CREDENTIAL` | 0x0103 | server data subkey `server/smtp-credential` / 0x01 (server only, [§5.11](#511-server-side-encryption-not-zero-knowledge)) | str(smtp_host) ‖ u16 smtp_port ‖ u8 smtp_tls ‖ str(smtp_username). Plaintext: the SMTP password, framed and padded per [§8.5](#85-plaintext-framing-and-padding) | M3 (with the sender ADR, §7) |

**Other CRYPTO.md edits on acceptance:** the §5.11 `0x0103` bullet becomes "`SERVER_SMTP_CREDENTIAL` 0x0103 ([ADR 0086](adr/0086-instance-settings-persistence.md)), ctx `str(smtp_host) ‖ u16 smtp_port ‖ u8 smtp_tls ‖ str(smtp_username)`. Binding the endpoint means a password opens only for the server, port, TLS mode and user it was entered for. The plaintext is the SMTP password, framed and padded per §8.5."; §4.3's server-data-subkey row lists `smtp-credential` beside `totp-secret` and `login-state`; §8.5's first sentence lists `SERVER_SMTP_CREDENTIAL`; §5.11 "Rotation" says "re-seals TOTP rows and the SMTP credential row". THREAT_MODEL INV-86's test column gains "a ctx-binding test: changing `smtp_host` in the DB makes the seal fail to open and no mail is sent".

### 6. Admin routes and the offline command

**Admin listener** (ADR 0060 §1–§3: Askama, `ADMIN_CSP`, native POSTs), every route behind ADR 0085's login, second factor and CSRF token; **none merges before ADR 0085 is Accepted** (ADR 0060 owner answer 5):

| Route | Does |
|---|---|
| `GET /admin/settings` | Overview: each key's effective value (the password as set / not set) and its source (§2). |
| `GET, POST /admin/settings/signup` | Closed / Open radio. |
| `GET, POST /admin/settings/recovery-wait` | Hours, 0–720; the 0 confirmation (§4). Waits on open question 2. |
| `GET, POST /admin/settings/smtp` | The group of §1.1; the ctx rule of §5. Waits on §7. |
| `POST /admin/settings/{signup,recovery-wait,smtp}/reset` | "Use the configuration value": deletes the row(s). |

POST bodies are `application/x-www-form-urlencoded`, at most 4 KiB, parsed without panics by the §1.1 parsers; an unknown or repeated field, or an out-of-range value, re-renders the page with a `400` status and a message naming the field, never echoing the password. A successful POST redirects with `303` to the GET (post/redirect/get). No JSON admin API (ADR 0060).

**Offline command** on the server binary, added to `admin.rs`'s command table:

- `rizzy-vault settings show` — every key, effective value, source; `smtp_password` only as set / not set.
- `rizzy-vault settings set signup <closed|open>` and `rizzy-vault settings set recovery-wait <hours>`.
- `rizzy-vault settings set smtp --host H --port P --tls <starttls|tls> --from A [--username U]`, reading the password from **stdin** when `--username` is given (no secret on the command line, ADR 0028 item 12); it needs the secrets file to seal.
- `rizzy-vault settings reset <signup|recovery-wait|smtp>`.

Writes are ordinary transactions through the auth domain API, so they take effect on the next action of every running replica (§3); the lock mode follows `admin.rs`'s table and is fixed in the implementing PR (recommended: no exclusive instance lock, as no other table changes). A CLI write sets `updated_kind = 'cli'` and `updated_admin_id = NULL` and appends a `setting_changed` audit row with actor `cli` (ADR 0085 §8.1, §9.3); a recovery-wait change still writes the security events of §4. `rv` gains nothing.

### 7. SMTP sending: not built here, and the credential waits for it

ROADMAP puts notification mail at M3 (before v1.0), but no Accepted ADR defines the sender (§Context). Storing a password nothing uses is a secret at rest for no benefit, so: **the `smtp_*` keys, `SERVER_SMTP_CREDENTIAL` and the SMTP screen are fixed by this ADR but are implemented only together with the Accepted ADR that defines outbound notification mail.** Until then the `smtp_*` parsers are not compiled into the loader, so a `smtp_*` row is an unknown key and a startup error, and nothing ever writes one. The migration of §1 is generic and needs no change when they arrive. The `signup_mode` and `recovery_wait_hours` keys do not wait for it.

### 8. Implementation plan and tests

Order: (a) table, loader, signup key and screen once ADR 0085 is Accepted; (b) recovery-wait key and screen once ADR 0090 (the security event log, Proposed) is Accepted (open question 2); (c) SMTP once the sender ADR is Accepted (§7). Each step is its own PR passing CLAUDE.md's full gate, `cargo xtask check-tables` included.

- **Storage** (`rizzy-storage`): `NNNN_auth_instance_settings.sql` for SQLite and PostgreSQL; queries `instance_setting_get.sql`, `instance_settings_all.sql`, `instance_setting_upsert.sql`, `instance_setting_delete.sql` under `rizzy-domain-auth/queries/`. Tests: the `CHECK`s reject a row with both or neither value column, a sealed row without `data_key_id`, oversize values; PostgreSQL parity as `#[ignore]`d tests, like the existing ones. `TABLES` gains the table, with §1.2's dump and restore test.
- **Domain** (`rizzy-domain-auth`): `InstanceSettings` API — typed getters read in the caller's transaction, `set` / `reset` with `setting_seq` increment; `SignupPolicy` and `recovery_wait_ms` in `AuthConfig` become the configuration fallback. Unit tests: every §1.1 boundary (`0`, `720`, `721`, `072`, `+1`, ` 72`, `OPEN`, `invite` refused); the §2 precedence matrix (row × environment × file × default); startup refusal on an unknown key, a non-canonical value, a partial group, a missing `data_key_id`; point-of-use fail-closed (signup refused, recovery start errors); concurrency: signup closed in one transaction, a signup in another, each outcome consistent with the commit order; the read happens before the name lookup for real and unknown names alike.
- **Crypto** (`rizzy-core`): `labels::SERVER_SMTP_CREDENTIAL = "server/smtp-credential"`, `Purpose::ServerSmtpCredential` (0x0103, symmetric, §8.5-padded, server-only), `server_seal::{seal_smtp_credential, open_smtp_credential}` and `SmtpPassword` (zeroizing, redacted `Debug`). **KATs**, committed to `tests/vectors/derivations.json` (`server/smtp-credential`, `data_key_id` 1 and 2) and `tests/vectors/envelopes.json` (`SERVER_SMTP_CREDENTIAL` with ctx host `smtp.example.com`, port 587, `starttls`, user `rizzy@example.com`; one 1-byte, one 252-byte and one 253-byte password to pin the 256→Padmé boundary), regenerated by the existing vector generator and checked by its tests; negative vectors: the same envelope opened with each ctx field changed in turn, with the wrong `data_key_id`, with a non-zero padding byte, each failing with `DecryptError`; a test that no client allow-list accepts 0x0103.
- **Server** (`rizzy-server`): the admin pages and `admin.rs` commands of §6; `worker`'s re-seal pass of §5. Tests: Askama adversarial-string rendering for every value the screens show (ADR 0060 §3); CSRF-missing and cross-site POST refused; the SMTP form refuses a ctx change without a password; **INV-86 DB inspection**: the stored `sealed_value` is a 0x01 envelope that opens only with the expected ctx and contains no substring of the password; **log inspection** across save, startup, rotation and a failed open: the password never appears; **ctx binding**: a direct DB edit of `smtp_host` makes the open fail, nothing is sent, the warning names the key; **rotation**: after `secrets rotate --data-key` the row names the new key and opens; `settings reset smtp` restores startup after a removed data key; the recovery-wait INV-69 event test (one event per account, same transaction).
- **Fuzz** (`fuzz/fuzz_targets/`): `instance_settings` — arbitrary `(setting_key, value_text)` pairs and groups through the loader, and arbitrary host / username text through the ctx encoder; `admin_settings_form` — arbitrary form bodies up to and past 4 KiB for each POST route. Neither may panic; both are added to the fuzz manifest checked by `cargo check --manifest-path fuzz/Cargo.toml`.
- **e2e + axe** (Playwright, beside the existing specs with the shared `a11y.ts` axe helper; the exact directory for admin-listener specs is the implementing PR's, U): log in as admin (ADR 0085), toggle signup Closed→Open and sign up on the public listener **without a restart**, reset to the configuration value and see signup refused; with two server processes on one database, a change made through one is in force on the other's next request; recovery wait 72→24 and the 0 confirmation; SMTP save, then assert the DOM never contains the password; `ADMIN_CSP` present on every page; **zero axe violations** on `/admin/settings` and each settings page, in the default state and with a validation error shown.

## Consequences

### Positive

- Signup mode and recovery wait change without a restart and take effect on every replica at once, with no cache to invalidate.
- M1 deployments keep working unchanged until an admin acts; the act is visible, attributed and reversible, online and offline.
- The SMTP password is protected from a DB-only reader (sealed and length-hidden) and is bound to its endpoint, so neither a DB writer nor a hijacked admin session can redirect it to another server.
- No new crypto, no new key, no new configuration setting; one generic table serves later settings.

### Negative

- Two sources of truth per key (row and configuration); an operator who edits `RIZZY_SIGNUP` after an admin saved the screen sees no effect until they reset, mitigated only by the startup warning and the screen's source label.
- A PK lookup on every signup, recovery start and delivery batch.
- Changing the SMTP server or user always means re-typing the password.
- Two of the three screens wait on other ADRs (ADR 0090's security event log, the sender ADR), so the M3 panel ships in steps.
- A restore needs the secrets file holding the sealed row's `data_key_id` (§1.2), as restored TOTP rows already do.

### Risks

- **DB writer.** Someone with write access to the database but not the secrets file can flip `signup_mode` to `open` or `recovery_wait_hours` to 0. That attacker can already rewrite auth tables directly (a pending recovery's release time included); this ADR adds no integrity protection for plain rows and claims none. They can also restore an older complete SMTP group an admin once entered, which then opens; if that old relay is now theirs, the old password reaches them. Accepted: the password is the admin's to rotate at the relay when changing relays.
- **Lost data key** disables mail until the password is re-entered, and refuses startup until `settings reset smtp` (§5.11's existing rule).
- **Ordering across ADRs**: §1's actor columns follow ADR 0085 §8.1 and §4's `invite` reservation follows ADR 0087 §10; if either changes before acceptance, this ADR follows it.

## Alternatives considered

- **One wide single-row table with typed columns.** Stronger SQL typing, but every new setting is a migration and SQLite cannot add a `CHECK` without rebuilding the table; the key/value table with Rust-side typing keeps one migration and reuses `config.rs`'s parsers. Rejected.
- **An in-process cache with polling (e.g. every 5 s on a revision counter) or PostgreSQL `LISTEN/NOTIFY`.** Needed only if reads were hot; they are not. Polling leaves a staleness window in which a closed signup still admits; `NOTIFY` needs a dedicated connection, loses messages on reconnect and has no SQLite equivalent; `rizzy-bus` is in-process today, and its planned M3 `LISTEN/NOTIFY` backend carries hints, "never the record of truth" (its crate docs), so a setting could not depend on it either. Rejected.
- **Environment always wins; screen read-only when set**, and **seed the table at first boot**: see §2. Rejected.
- **`RIZZY_SMTP_URL` with the password inside, as ADR 0066 (Proposed) proposes.** Puts a second password into configuration beside `RIZZY_DATABASE_URL`, unsealed in the environment, and makes the screen read-only or two-sourced for SMTP. Not chosen here (open question 4).
- **`SERVER_TOTP_SECRET`'s exact shape: ctx without the endpoint, unpadded.** Simpler, but lets a DB writer or a hijacked admin session redirect the stored password to their own server, and leaks its length. Rejected.
- **A plaintext SMTP mode for a local relay.** Sends the password in clear on any misrouting; a no-AUTH local relay is the sender ADR's call, not a storage mode. Not offered.
- **Storing the SMTP credential before a sender exists.** A secret at rest that nothing uses. Rejected (§7).

## Open questions for the owner

1. **Q-15's sub-question: refuse a 0 recovery wait when the instance has more than one account?** *Recommendation:* yes, on both write paths (screen and `settings set`): refuse to save 0 unless exactly one account exists, and when a second account is created while the wait is 0, keep the stored 0 but log a warning at each startup and show a banner on `/admin/settings` until the admin raises it. This matches THREAT_MODEL Q-15's recommendation and the §7.19 E-row; the configuration path keeps today's startup warning.
2. **The recovery-wait screen needs the per-account security event log (INV-69), now ADR 0090 (Proposed). Ship the recovery-wait key before ADR 0090 is Accepted?** *Recommendation:* no. Ship signup mode first, and the recovery-wait screen with ADR 0090's log (ADR 0075 and ADR 0058 also wait on it).
3. **Pad the SMTP password with §8.5's framing, although CRYPTO §5.11 currently says "the same construction as `SERVER_TOTP_SECRET`" (unpadded)?** *Recommendation:* yes. Key, subkey derivation and algorithm are identical; the framing is existing §8.5 machinery and hides the password's length from a DB reader at a cost of under 256 bytes.
4. **Outbound mail: which ADR defines the sender, at which milestone, and should ADR 0066 (Proposed) use these rows instead of `RIZZY_SMTP_URL` / `RIZZY_SMTP_FROM`?** *Recommendation:* a short notification-mail ADR at M3 for ADR 0010's `worker` outbound (recovery notices to an account email per ADR 0008 decision 5 — which also needs an account-email field and its own enumeration review), reading only these rows; ADR 0066 is revised before acceptance to read the same rows, so there is one SMTP configuration with one sealed password and no secret in the environment.

## Self-review (blockers only)

- **Gate:** docs only; no Accepted ADR's Status, Context, Decision or Consequences edited; CRYPTO.md and THREAT_MODEL.md edits are listed for acceptance, not made. **None found.**
- **Crypto:** the §5.11 construction, the existing server data key and §8.5's framing are reused unchanged; the only new things are a label, a purpose name and a ctx, which §5.11 and ADR 0060 say an ADR must fix. KAT and negative vectors planned. **None found.**
- **Invariants:** INV-86 (sealed, never logged, never redisplayed), INV-69 (separate admin login, CSRF, CSP, event log for the wait) and CRYPTO §5.9 (name-independent signup check) are kept; INV-69's event-log requirement waits for ADR 0090 (Proposed) and is an explicit merge blocker (§4, open question 2) rather than a gap. **None found.**
- **Scope:** ROADMAP §4.9 is not narrowed; SMTP sending is not designed here and its storage is gated on the ADR that does (§7). **None found.**

## References

- [ADR 0060](0060-admin-panel-stack-boundary.md) §1–§4 and owner answers 2, 3, 5, 6; [ADR 0011](0011-storage.md) rules 4–9; [ADR 0010](0010-server-shape.md) §1 and [ADR 0022](0022-server-mode-only.md) §2 (roles); [ADR 0028](0028-api-v1-http-conventions.md) item 12; [ADR 0008](0008-account-recovery.md) decision 5; [ADR 0058](0058-webauthn-2fa-second-factor.md), [ADR 0077](0077-webauthn-rs-integration-fixes.md), [ADR 0082](0082-security-keys-user-presence-only.md) (the admin second factor ADR 0085 builds on); [ADR 0066](0066-share-email-otp-verification.md) (Proposed); [ADR 0075](0075-session-listing-and-ending.md); ADR 0085 and ADR 0087 (Proposed in parallel).
- [CRYPTO.md](../CRYPTO.md) §2, §4.3, §5.9, §5.11, §8.4, §8.5, §9.1, §9.5, §15.
- [THREAT_MODEL.md](../THREAT_MODEL.md) §7.19, INV-48, INV-69, INV-86, Q-15.
- [ROADMAP.md](../ROADMAP.md) §4.9 (admin panel row, M3), §4.8 (sending from aliases: Won't for v1.0), milestone table (M5, M6 after v1.0).
- Code read: `crates/rizzy-server/src/config.rs`, `crates/rizzy-domain-auth/src/config.rs`, `crates/rizzy-server/src/admin.rs`, `crates/rizzy-server/src/http/admin_panel/mod.rs`, `crates/rizzy-core/src/server_seal.rs`, `crates/rizzy-storage/migrations/`.
