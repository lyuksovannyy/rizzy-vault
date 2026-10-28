# ADR 0114: One server settings register: the `RIZZY_*` names the shipped code reads, one rule for adding a name, and a CI check (supersedes ADR 0048 §1's last sentence)

- Status: Accepted
- Date: 2026-10-25
- Deciders: project owner
- Milestone: M3 (`docs/adr`, `crates/xtask`; no change to what `rizzy-server` accepts)
- Supersedes: on acceptance, in part: [ADR 0048](0048-per-account-storage-quota.md) §1, its last sentence (the settings list, which ADR 0048 §0 names as its replacement of [ADR 0028](0028-api-v1-http-conventions.md) item 12's settings clause, and which is therefore the binding text of that clause). §1 below quotes it word for word and gives the full replacement ([ADR 0020](0020-partial-supersession.md) point 9).

## Context

[ADR 0028](0028-api-v1-http-conventions.md) item 12 froze the server's configuration as the operator's interface: the names are a closed list, the configuration file refuses an unknown name, and a rename keeps the old name working, with a logged warning, for two server releases. [ADR 0048](0048-per-account-storage-quota.md) §0 replaced item 12's settings clause, and §1's last sentence is now the binding list (V: both files at `2c40fee`):

> Settings `RIZZY_ROLES`, `RIZZY_ORIGIN`, `RIZZY_LISTEN` (default `127.0.0.1:8080`), `RIZZY_DATA_DIR` (`/data`), `RIZZY_DATABASE_URL`, `RIZZY_SECRETS_FILE` (`/run/rizzy-secrets/secrets.json`), `RIZZY_SIGNUP` (`closed`|`open`), `RIZZY_TRUSTED_PROXIES`, `RIZZY_LOG_LEVEL`, `RIZZY_WORKER_INTERVAL_SECS`, `RIZZY_MAX_UPLOAD_BYTES`, `RIZZY_ACCOUNT_QUOTA_BYTES`.

Two problems follow from that sentence.

**1. The shipped code already reads names the list lacks.** `crates/rizzy-server/src/config.rs` (V: read at `2c40fee`) declares its names as `pub const` string literals and collects them in `KEYS`, the set the configuration file accepts. Outside its `#[cfg(test)]` module it holds exactly 19 `"RIZZY_*"` literals: the 12 above, `RIZZY_CONFIG` (item 12's first sentence, command line or environment only, not in `KEYS`), and six more:

| Name | Where the code says it comes from | Named by an Accepted ADR? |
|---|---|---|
| `RIZZY_ADMIN_LISTEN` | [ADR 0060](0060-admin-panel-stack-boundary.md) §2 (`Config` gains `admin_listen`, `127.0.0.1:8081`) | No: ADR 0060 gives the field and the default, not the name ("its name follows `RIZZY_LISTEN`'s", says the module doc) |
| `RIZZY_RECOVERY_WAIT_HOURS` | [ADR 0008](0008-account-recovery.md) decision 5 (72 h, admin-configurable from 0 to 30 days) | No: "the name and the unit are this crate's choice, reported to the owner" |
| `RIZZY_BREACH_CHECK` | [ADR 0053](0053-hibp-breach-check-egress.md) item 5 and owner answer 2 (a separate switch, off by default) | No: "this crate's choice" |
| `RIZZY_ICON_CACHE_DIR` | [ADR 0010](0010-server-shape.md) §4 (the `icons` role's cache volume) | No: "this crate's choice" |
| `RIZZY_ICON_CACHE_TTL_SECS` | [ADR 0052](0052-icon-proxy-role.md) point 5 and owner answer 3 (14 days, tunable) | ADR 0052 names it, the list does not; the bounds are the crate's |
| `RIZZY_ICON_CACHE_MAX_BYTES` | ADR 0052 point 5 and owner answer 3 (256 MiB, tunable) | ADR 0052 names it, the list does not; the bounds are the crate's |

So the binding list and the shipped parser disagree today, and nothing would notice the next drift. The server's own help text has drifted as well: `rizzy-vault --help` (`cli.rs` lines 62 and 75–78) lists 13 settings, omits `RIZZY_BREACH_CHECK` and the three `RIZZY_ICON_CACHE_*` names, and names only `api`, `web`, `worker` as roles.

**2. Proposed ADRs race to re-supersede the same sentence.** Five restate the whole sentence with their own addition, and each carries ordering prose for the others; two more touch the same settings without restating it (V: grep of `docs/adr/` for "48 §1" and "item 12" at `2c40fee`):

| ADR (all Proposed) | What it does to the sentence |
|---|---|
| [0066](0066-share-email-otp-verification.md), "What this ADR supersedes" | Adds `RIZZY_SMTP_URL`, `RIZZY_SMTP_FROM`, quoting ADR 0028's older clause (without `RIZZY_ACCOUNT_QUOTA_BYTES`); also replaces item 12's secret-boundary passage |
| [0087](0087-invite-only-signup-tokens.md) §10.1 | `RIZZY_SIGNUP` gains `invite`, and the default moves to `invite` (owner answer 2, 2026-10-25) |
| [0104](0104-metrics-endpoint.md) §11 | Adds `RIZZY_METRICS` (`off`\|`on`) and `RIZZY_METRICS_TOKEN_SHA256` |
| [0106](0106-agpl-source-url.md) §7.2 | Adds `RIZZY_SOURCE_URL` |
| [0113](0113-breach-check-endpoint.md) §9.3 | Adds `RIZZY_BREACH_CHECK`, `RIZZY_ICON_CACHE_DIR`, `_TTL_SECS` and `_MAX_BYTES`, the names already shipped |
| [0100](0100-notification-mail.md) | Adds none ("ADR 0028 item 12: no new `RIZZY_*` setting") and recommends that ADR 0066 drop its two |
| [0086](0086-instance-settings-persistence.md) §1.1–§2 | Adds no name; makes `signup_mode` and `recovery_wait_hours` database rows whose configuration fallback is `RIZZY_SIGNUP` and `RIZZY_RECOVERY_WAIT_HOURS` (a saved row wins) |

Each full restatement is right for one acceptance order only, and ADRs 0106 and 0113 already spell out case analyses over the others. None of them adds the shipped `RIZZY_ADMIN_LISTEN` or `RIZZY_RECOVERY_WAIT_HOURS`, so accepting any of them as written keeps problem 1. Accepting two in the wrong order silently drops a name, and the file parser would then refuse a configuration that worked the day before, which is what item 12's rename rule exists to prevent.

ROADMAP: no row of its own. This is housekeeping for every row that adds a setting ([§4.9](../ROADMAP.md#49-server-self-hosting--ops-m1-onward), server, self-hosting and ops, M1 onward, and its M3 admin-panel row through ADRs 0086 and 0087). It changes no behaviour, no wire format and no secret boundary.

## Decision

### 1. What this ADR supersedes

One Accepted sentence ([ADR 0020](0020-partial-supersession.md) point 9).

**[ADR 0048](0048-per-account-storage-quota.md) §1, its last sentence**, word for word:

> Settings `RIZZY_ROLES`, `RIZZY_ORIGIN`, `RIZZY_LISTEN` (default `127.0.0.1:8080`), `RIZZY_DATA_DIR` (`/data`), `RIZZY_DATABASE_URL`, `RIZZY_SECRETS_FILE` (`/run/rizzy-secrets/secrets.json`), `RIZZY_SIGNUP` (`closed`|`open`), `RIZZY_TRUSTED_PROXIES`, `RIZZY_LOG_LEVEL`, `RIZZY_WORKER_INTERVAL_SECS`, `RIZZY_MAX_UPLOAD_BYTES`, `RIZZY_ACCOUNT_QUOTA_BYTES`.

Replacement, in full:

> Settings are the names in the settings register of [ADR 0114](0114-server-settings-list.md), each with the type, default, bounds and roles the register gives it, and no other. At ADR 0114's acceptance they are `RIZZY_ROLES`, `RIZZY_ORIGIN`, `RIZZY_LISTEN` (default `127.0.0.1:8080`), `RIZZY_ADMIN_LISTEN` (`127.0.0.1:8081`), `RIZZY_DATA_DIR` (`/data`), `RIZZY_DATABASE_URL`, `RIZZY_SECRETS_FILE` (`/run/rizzy-secrets/secrets.json`), `RIZZY_SIGNUP` (`closed`|`open`), `RIZZY_TRUSTED_PROXIES`, `RIZZY_LOG_LEVEL`, `RIZZY_WORKER_INTERVAL_SECS` (60), `RIZZY_MAX_UPLOAD_BYTES` (32 MiB), `RIZZY_ACCOUNT_QUOTA_BYTES` (5 GiB), `RIZZY_RECOVERY_WAIT_HOURS` (72), `RIZZY_BREACH_CHECK` (`off`|`on`), `RIZZY_ICON_CACHE_DIR` (`/cache`), `RIZZY_ICON_CACHE_TTL_SECS` (14 days), `RIZZY_ICON_CACHE_MAX_BYTES` (256 MiB), with the register rows that ADR 0114 §4 gives for each of ADRs 0066, 0087, 0104, 0106 and 0113 Accepted before it. A later ADR adds or changes a setting by adding or replacing a register row (ADR 0114 §3), not by superseding this sentence.

If one of ADRs 0066, 0087, 0104, 0106 or 0113 is Accepted before this ADR, the sentence binding at this ADR's acceptance is that ADR's replacement, not ADR 0048's original. This ADR then supersedes *that* sentence with the same replacement text above; the register already carries that ADR's rows (§4), so nothing it added is lost. The owner records which sentence was superseded on the status lines ("On acceptance", item 1).

Nothing else in ADR 0028 item 12 or ADR 0048 is touched. These stay exactly as they are: item 12's first sentence (`--config <path>` or `RIZZY_CONFIG`, never from the file itself); the file format (64 KiB, `NAME=value`, `#` comments, no quoting; unknown, repeated or malformed lines refused); environment over file, `--roles` over both; `--roles` and `--config` the only flags; no secret on the command line; the secret boundary (the one setting that can carry a secret is `RIZZY_DATABASE_URL`); and the rename rule.

### 2. The register

The **settings register** is the table in the section "Settings register" below, between the markers `<!-- settings-register:begin -->` and `<!-- settings-register:end -->`. It is binding as the list of item 12's settings. It sits outside this ADR's Context, Decision and Consequences on purpose, so that adding a row (§3) never edits the Decision of an Accepted ADR.

Its columns:

- **Name**: the exact `RIZZY_*` name, in backticks, one per row, unique. The CI check (§5) reads only this column.
- **Type and grammar**: what the parser accepts. Anything else refuses startup with an error that names the setting, never its value (`ConfigError::Invalid(name)`).
- **Default**: the value when the name is unset in both the environment and the file.
- **Bounds**: inclusive limits.
- **Used by**: `Config::from_sources` parses **every** name in every invocation, whatever the roles: `serve` with any roles and every admin subcommand (`migrate`, `secrets …`, `backup-secrets`, `backup`, `restore`). An invalid value of any setting therefore refuses every start. This column says which roles *use* the value.
- **Decided by**: the Accepted ADR that fixed the behaviour, and the one that fixed the name where that differs.

At this ADR's drafting the register states what the shipped code reads at `2c40fee` (V: `config.rs`, `log.rs` `Level::parse`, `server.rs` `serve`, `open_services`, `check_icons_isolation` and `icons_state`). Where the parser and an Accepted ADR could differ the register follows the code and the row says so; at that commit none does.

### 3. The rule for later additions

1. **A later ADR that adds, changes or removes a `RIZZY_*` setting** gives, in its own "What this ADR supersedes" section, the exact register row or rows it adds, replaces (quoting the old row in full) or deletes. It does **not** supersede ADR 0048 §1's last sentence, nor this ADR's replacement of it. A rename gives two rows: the new name, and the old name marked "deprecated alias of `RIZZY_NEW`, removed after <release>", per item 12's rename rule.
2. **At that ADR's acceptance the owner applies its rows to the register**, in the same change that sets its status: an owner act, like the status line (ADR 0020 points 3, 4 and 9). The applied row names the accepting ADR in its "Decided by" cell. A row may be in the register before the code reads the name (an Accepted ADR whose implementation has not landed); §5 allows that direction.
3. **Order does not matter.** Rows are keyed by name. Rows from two ADRs overlap only when both change the same name, and then the later-drafted one must quote the other's row as the row it replaces. The register after any set of acceptances is therefore the same whatever order they happen in. Row order carries no meaning; new rows go at the end.
4. **An ADR still worded as a re-supersession** (drafted before this rule and accepted after this ADR without being edited) is applied as its rows only. Its restated sentence is not applied: every such sentence written so far omits names the register holds (`RIZZY_ADMIN_LISTEN`, `RIZZY_RECOVERY_WAIT_HOURS`), so applying it literally would drop them. §4 gives the rows for each of the five ADRs in that position today.
5. **Only an ADR that supersedes this one in the parts it names changes the register's columns or §5's check.**

### 4. The rows ADRs 0066, 0087, 0104, 0106 and 0113 would add

Read from each ADR at `2c40fee`. A cell the ADR leaves unstated says so; that ADR's author fills it before acceptance, and the owner applies the filled cell.

**ADR 0066** (recipient email verification): two new rows.

| Name | Type and grammar | Default | Bounds | Used by | Decided by |
|---|---|---|---|---|---|
| `RIZZY_SMTP_URL` | URL with scheme `smtp://`, `smtps://` or `smtp+starttls://`, optional user and password. **Can carry a secret**: zeroizing buffer, never in `Debug`, a log line or an error (ADR 0066's replacement of item 12's secret-boundary passage) | unset: outbound mail off; `request-email-code` answers `invalid_request` for an email-restricted share | not stated in ADR 0066 (the 64 KiB file cap applies) | `worker` dials SMTP; `api` checks whether it is set | ADR 0066 |
| `RIZZY_SMTP_FROM` | the envelope and display From address; no secret | not stated in ADR 0066 | not stated in ADR 0066 | `worker` | ADR 0066 |

ADR 0100 (Proposed) recommends that ADR 0066 drop both names in favour of ADR 0086's `smtp_*` instance-setting rows. If ADR 0066 is revised that way before acceptance, it adds no row. Its secret-boundary change is a separate part of item 12, which this ADR does not touch.

**ADR 0087** (invite-only signup): replaces the `RIZZY_SIGNUP` row in full with:

| Name | Type and grammar | Default | Bounds | Used by | Decided by |
|---|---|---|---|---|---|
| `RIZZY_SIGNUP` | `closed`, `invite` or `open`, exact lowercase | `invite` (ADR 0087 owner answer 2, 2026-10-25) | none | `api` (signup); `worker` builds the same services | ADR 0028 item 12; `invite` and the default: ADR 0087 §10.1 |

**ADR 0104** (metrics endpoint): two new rows.

| Name | Type and grammar | Default | Bounds | Used by | Decided by |
|---|---|---|---|---|---|
| `RIZZY_METRICS` | `off` or `on`, exact lowercase | `off` (`/metrics` stays the admin listener's plain-text 404) | none | `api` (the admin listener) | ADR 0104 §1 |
| `RIZZY_METRICS_TOKEN_SHA256` | exactly 64 lowercase hex characters, the SHA-256 of the scrape token's ASCII text; a hash, not a key (ADR 0104: "no setting holds a key" stays true) | unset (no token) | exactly 64 characters | `api` (the admin listener) | ADR 0104 §4 |

**ADR 0106** (AGPL §13 source link): one new row.

| Name | Type and grammar | Default | Bounds | Used by | Decided by |
|---|---|---|---|---|---|
| `RIZZY_SOURCE_URL` | `rizzy_proto::meta::SourceUrl` (ADR 0106 §1): printable ASCII only, begins with exactly `https://`, `host` or `host:port`, no userinfo, no bracketed IP literal; not a secret, logged once at `info` at startup | this build's upstream source, a compile-time constant (ADR 0106 §2) | 9 to 2048 bytes | `api` (`/api/meta` `source_url`) | ADR 0106 §1–§2 |

**ADR 0113** (breach-check endpoint): **no new row.** Its four names are already register rows with the type, default and bounds ADR 0113 §6 states (`off`\|`on`, default `off`; `/cache`; 60 to 31 536 000 s, default 1 209 600; at least 1 048 576 bytes, default 268 435 456). If ADR 0113 is Accepted, before or after this ADR, the owner appends "; ADR 0113 §6" to those four rows' "Decided by" cells. Their content is the same either way.

**ADR 0086** (instance settings persistence): **no new row.** If it is Accepted, the owner appends to the "Used by" cells of the `RIZZY_SIGNUP` and `RIZZY_RECOVERY_WAIT_HOURS` rows: "configuration fallback only: an `auth_instance_settings` row wins (ADR 0086 §2)". **ADR 0100**: no row.

### 5. The CI check: `cargo xtask check-settings`

CI must fail when `crates/rizzy-server/src/config.rs` reads a `RIZZY_*` name that is not in the register. The check compares names only, never types, defaults or bounds.

1. **Names the code reads.** Every string literal that is exactly `"RIZZY_[A-Z0-9_]+"` in `crates/rizzy-server/src/config.rs`, outside its `#[cfg(test)]` module (the tests hold deliberate unknowns such as `"RIZZY_NOPE"`). At `2c40fee` that set is the 19 names of the register. A longer literal that only contains a name, such as the message `"RIZZY_ORIGIN is required for the api and worker roles"` in `server.rs`, does not match, and files other than `config.rs` are out of scope.
2. **Names the register holds.** The first cell of every table row between the two markers in `docs/adr/0114-server-settings-list.md`, each a single backticked `RIZZY_*` name. A marker counts only as a line that is exactly the marker, so the markers quoted inline in this ADR's prose do not count. A missing or repeated marker, a malformed first cell or a repeated name fails the check.
3. **Verdict.** A name in (1) and not in (2) fails, with one line per name: `check-settings: config.rs reads RIZZY_X, which is not in ADR 0114's settings register`. A name in (2) and not in (1) does not fail (an Accepted ADR may land before its code, §3 item 2); it is printed as `note: RIZZY_X is in the register but config.rs does not read it yet`.

The check reads both files with a size limit, parses them without panics, and needs no new dependency.

## Settings register

<!-- settings-register:begin -->
| Name | Type and grammar | Default | Bounds | Used by | Decided by |
|---|---|---|---|---|---|
| `RIZZY_CONFIG` | a path; from `--config` or the environment only, refused inside the file | none (no file) | the file is at most 64 KiB | every invocation, before the other settings | ADR 0028 item 12, first sentence (not part of the superseded sentence) |
| `RIZZY_ROLES` | comma-separated, each trimmed: `api`, `web`, `worker`, `icons`; `notify` and `smtp` refused as not in this build; `icons` only alone; `--roles` wins over it | `api,web,worker` | none | role selection | ADR 0010 §1; ADR 0028 item 12; `icons`: ADR 0052, ADR 0053 |
| `RIZZY_ORIGIN` | canonical origin (CRYPTO.md §2, `ServerOrigin::parse`) whose scheme is `https`, or whose host is `localhost` or a loopback address | none; required when `api` or `worker` runs | none | `api`, `worker` | ADR 0028 items 10 and 12 |
| `RIZZY_LISTEN` | socket address (`ip:port`, Rust `SocketAddr`) | `127.0.0.1:8080` | none | `api` and `web` (one listener); `icons` | ADR 0010 §4; ADR 0028 item 12 |
| `RIZZY_ADMIN_LISTEN` | socket address, as `RIZZY_LISTEN` | `127.0.0.1:8081` | none | `api` (always bound while it runs) | behaviour: ADR 0060 §2; name: this ADR |
| `RIZZY_DATA_DIR` | a path | `/data` | none | `api`, `worker`, admin subcommands (the SQLite file and its pre-migration copy); `icons` refuses to start if that SQLite file is visible | ADR 0010 §4; ADR 0011 point 9; ADR 0028 item 12 |
| `RIZZY_DATABASE_URL` | `postgres://` or `postgresql://` URL, non-empty. **Can carry a secret**: zeroizing buffer, never in `Debug`, a log line or an error | unset: SQLite in `RIZZY_DATA_DIR` | none | `api`, `worker`, admin subcommands; `icons` refuses to start when it is set | ADR 0011 point 1; ADR 0028 item 12 |
| `RIZZY_SECRETS_FILE` | a path, not a secret; must resolve outside `RIZZY_DATA_DIR` | `/run/rizzy-secrets/secrets.json` | none | `api`, `worker`, admin subcommands; `icons` refuses to start if it is visible | ADR 0010 §4; ADR 0028 items 12 and 13 |
| `RIZZY_SIGNUP` | `closed` or `open`, exact lowercase | `closed` | none | `api` (signup); `worker` builds the same services | ADR 0028 item 12 |
| `RIZZY_TRUSTED_PROXIES` | comma-separated single IP addresses (Rust `IpAddr`), each trimmed; no CIDR, port, brackets, zone id or host name; an empty element is refused | empty (no proxy); a blank value is empty | none | `api`, `icons` (the `X-Forwarded-For` their rate limits read) | ADR 0028 items 11 and 12 |
| `RIZZY_LOG_LEVEL` | `error`, `warn`, `info` or `debug`, exact lowercase | `info` | none | every invocation | ADR 0028 item 12 |
| `RIZZY_WORKER_INTERVAL_SECS` | whole seconds, decimal | 60 | 1 to 86 400 | `worker` | name: ADR 0028 item 12; default and bounds: this ADR (as shipped) |
| `RIZZY_MAX_UPLOAD_BYTES` | whole bytes, decimal | 33 554 432 (32 MiB) | 33 554 432 to 268 435 456 (256 MiB) | `api` (upload bodies; the quota headroom) | ADR 0028 items 7 and 12 |
| `RIZZY_ACCOUNT_QUOTA_BYTES` | whole bytes, decimal; one number for every account | 5 368 709 120 (5 GiB) | at least 268 435 456 (256 MiB), no maximum | `api` (vault quota); `worker` builds the same services | ADR 0048 §1 |
| `RIZZY_RECOVERY_WAIT_HOURS` | whole hours, decimal; applies to recoveries started after a change; 0 logs a warning at startup | 72 | 0 to 720 (30 days) | `api` (the release time of `E_rec`); `worker` builds the same services | behaviour: ADR 0008 decision 5; name and unit: this ADR |
| `RIZZY_BREACH_CHECK` | `off` or `on`, exact lowercase | `off` | none | `icons` | behaviour: ADR 0053 item 5 and owner answer 2; name: this ADR |
| `RIZZY_ICON_CACHE_DIR` | a path, non-empty; created if missing | `/cache` | none | `icons` | behaviour: ADR 0010 §4; name: this ADR |
| `RIZZY_ICON_CACHE_TTL_SECS` | whole seconds, decimal | 1 209 600 (14 days) | 60 to 31 536 000 (365 days) | `icons` | name and default: ADR 0052 point 5 and owner answer 3; bounds: this ADR |
| `RIZZY_ICON_CACHE_MAX_BYTES` | whole bytes, decimal | 268 435 456 (256 MiB) | at least 1 048 576 (1 MiB), no maximum | `icons` | name and default: ADR 0052 point 5 and owner answer 3; bounds: this ADR |
<!-- settings-register:end -->

"Decimal" means Rust's `str::parse` for the unsigned type the code uses (`u64`, or `usize` for `RIZZY_MAX_UPLOAD_BYTES`); text that does not parse, or a value outside the bounds, refuses startup. Every value is trimmed of surrounding spaces when read from the file.

## Consequences

### Positive

- One binding list that matches the shipped parser, and a check that keeps it that way: a setting added to `config.rs` without an accepted row fails CI.
- Accepting ADRs 0066, 0087, 0104, 0106 and 0113 gives the same result in every order. Their "if X is accepted earlier" prose becomes unnecessary.
- Operators get one table with the type, default, bounds and role of every name, which [docs/self-hosting.md](../self-hosting.md) §4 can mirror.
- The six names the code already reads get a recorded decision instead of "this crate's choice, reported to the owner".

### Negative

- The register is a binding table outside an ADR's Decision. The owner has to apply rows at each later acceptance; a forgotten row shows up only when the implementing change fails the check.
- The check covers names, not types, defaults or bounds. A row and the parser can still disagree on a default without CI noticing.
- One more `xtask` subcommand, one more CI step (an edit to `.github/workflows/`, the owner's to approve), and one more line in the pre-push lists of CLAUDE.md and CONTRIBUTING.md.

### Risks

- A Proposed ADR accepted unedited still reads as a re-supersession. §3 item 4 and "On acceptance" item 3 cover it: the owner applies its rows, not its sentence.
- A literal scan misses a name built at run time (`format!("RIZZY_{x}")`). None exists today, and building setting names at run time would itself break item 12's closed list.

## Alternatives considered

- **Keep re-superseding the sentence, one ADR at a time.** That is what produced five order-dependent restatements, none of which has the shipped `RIZZY_ADMIN_LISTEN`. Rejected.
- **Put the register inside the Decision.** Each later addition would then edit an Accepted ADR's Decision, which CLAUDE.md forbids, or need a new superseding ADR for every setting. Rejected.
- **Make docs/self-hosting.md the register.** It is operator documentation that changes without an ADR; the binding list of an interface ADR 0028 froze should change only through an ADR. It stays a mirror.
- **Fail in the other direction too (every row must be read).** Then an Accepted ADR could not land before its code. Kept as a note only.
- **Check types and defaults as well.** That needs the prose cells parsed into a grammar; out of proportion for now.

## On acceptance

The owner's edits, in the same change that sets this ADR's status:

1. **Status lines.** ADR 0048: "Partially superseded by ADR 0114 (§1, last sentence)". If one of ADRs 0066, 0087, 0104, 0106 or 0113 was Accepted first and superseded that sentence, that ADR's status line names the part ADR 0114 supersedes instead. ADR 0028's status line already names ADR 0048 for item 12 in part; it needs no change unless the owner wants ADR 0114 named there too.
2. **Rows already due.** For each of ADRs 0066, 0087, 0104, 0106, 0113 and 0086 that is Accepted at that moment, apply its §4 rows and cell edits to the register.
3. **The Proposed ADRs' own supersession of the sentence becomes redundant.** These parts are made redundant by §1 and §3. They are Proposed, so they may be edited before acceptance to give their register rows and point at ADR 0114 instead; this ADR does not edit them:
   - ADR 0066, "What this ADR supersedes": the "settings-name sentence" bullet. Its secret-boundary bullet is a different part of item 12 and stays ADR 0066's.
   - ADR 0087: the ADR 0048 part of its Supersedes line, and §10.1 (the replacement sentence and its coordination text).
   - ADR 0104: its Supersedes line, and §11 item 1 (the replacement sentence and "Ordering with ADRs 0087 and 0066").
   - ADR 0106: the ADR 0048 §1 part of its Supersedes line, and §7.2 in full.
   - ADR 0113: the Context paragraph on the settings sentence ("the third gap"), and §9.3 in full.
   - ADR 0086 §1.1, the `signup_mode` row's note that "ADR 0087 §10 supersedes" the sentence: it becomes "ADR 0087 replaces the register's `RIZZY_SIGNUP` row".

   If any of them is accepted unedited, the owner applies it under §3 item 4: its rows, not its sentence.
4. **Index and docs.** The README row for this ADR follows its status. [docs/self-hosting.md](../self-hosting.md) §4's settings table is checked against the register. CLAUDE.md's pre-push list and CONTRIBUTING.md gain `cargo xtask check-settings` when implementation step 2 lands.

## Implementation plan

Docs and tooling only; nothing changes in what `rizzy-server` accepts.

1. **`crates/xtask/src/settings.rs`**, `pub(crate) fn run(root: &Path) -> Result<String, String>`, wired in `crates/xtask/src/main.rs` as `check-settings` and `check-settings --root <dir>` (for fixtures, as `check-tables` does). It reads the two files of §5 with a 1 MiB limit each, cuts `config.rs` at its first top-level `#[cfg(test)]`, scans for exact `"RIZZY_[A-Z0-9_]+"` literals by hand (no regex dependency), parses the register between its markers, and reports as §5 says. Tests over fixture trees: a clean pass; an extra name in `config.rs` fails and is named; `"RIZZY_NOPE"` inside the test module is ignored; a register row not read prints a note and passes; a missing marker, a repeated name and a malformed first cell each fail.
2. **CI and the pre-push list.** One `cargo xtask check-settings` step in the existing lint job. The workflow edit, CLAUDE.md's list and CONTRIBUTING.md's "Checks to run before every push" are the owner's to approve.
3. **A `config.rs` unit test** that `KEYS` is exactly the set of `pub const` `RIZZY_*` names other than `RIZZY_CONFIG`, so the file parser cannot drift from the constants the check reads.
4. **Help text.** `rizzy-vault --help` (`cli.rs` lines 62 and 75–78) lists every register name and names `icons` among the roles; a test asserts that each name in `KEYS` appears in it.

## Open questions for the owner

1. **May the owner amend a register outside an Accepted ADR's Decision when another ADR is accepted?** §2 and §3 rely on it; CLAUDE.md forbids editing only an Accepted ADR's Context, Decision and Consequences. *Recommendation:* yes, as an owner act tied to the accepting ADR, like a status line. If not, the alternative is a separate file (`docs/settings.md`) that only an Accepted ADR may change, with the same CI check pointed at it.
2. **The names, units and bounds the crate chose** (`RIZZY_ADMIN_LISTEN`, `RIZZY_RECOVERY_WAIT_HOURS` in whole hours, `RIZZY_BREACH_CHECK`, `RIZZY_ICON_CACHE_DIR`, the bounds of the cache TTL, the cache cap and the worker interval): accepting this ADR accepts them as shipped. *Recommendation:* accept them as they are. Renaming any now would start item 12's two-release alias rule on an interface already documented in docs/self-hosting.md.

## References

- [ADR 0008](0008-account-recovery.md), [ADR 0010](0010-server-shape.md), [ADR 0011](0011-storage.md), [ADR 0020](0020-partial-supersession.md), [ADR 0028](0028-api-v1-http-conventions.md), [ADR 0048](0048-per-account-storage-quota.md), [ADR 0052](0052-icon-proxy-role.md), [ADR 0053](0053-hibp-breach-check-egress.md), [ADR 0060](0060-admin-panel-stack-boundary.md)
- Proposed: [ADR 0066](0066-share-email-otp-verification.md), [ADR 0086](0086-instance-settings-persistence.md), [ADR 0087](0087-invite-only-signup-tokens.md), [ADR 0100](0100-notification-mail.md), [ADR 0104](0104-metrics-endpoint.md), [ADR 0106](0106-agpl-source-url.md), [ADR 0113](0113-breach-check-endpoint.md)
- `crates/rizzy-server/src/config.rs`, `log.rs`, `cli.rs` and `server.rs` at `2c40fee`; [docs/self-hosting.md](../self-hosting.md) §4; [ROADMAP §4.9](../ROADMAP.md#49-server-self-hosting--ops-m1-onward)
