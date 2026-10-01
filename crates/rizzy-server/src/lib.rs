//! `rizzy-server` — the `rizzy-vault` server binary and the library it runs (roadmap M1 step
//! 3; [ADR 0010], [ADR 0002] point 3, [ADR 0011], [ADR 0021]; ADR 0016 §3 notes: the leaf that
//! wires the domain crates).
//!
//! # What it is
//!
//! One binary, `rizzy-vault`, on axum and tokio ([ADR 0010] §1), with the M1 roles:
//! - **`api`**: every `/api/v1` message of `rizzy-proto` and `GET /api/meta`, over
//!   `rizzy-domain-auth` and `rizzy-domain-vault` ([`http::api`]), with body-size limits, the
//!   bearer token and the per-request device signature (CRYPTO.md §5.10);
//! - **`web`**: the web vault's static page with its CSP ([`http::web`], [`http::security`];
//!   INV-49). The web vault itself is M1 step 5; this build serves ADR 0010 §4's fixed page;
//! - **`worker`**: expired auth state, re-sealing 2FA secrets after a data-key rotation, stale
//!   reconciliation epochs, compaction, `SQLite` space and the pre-migration copy ([`worker`]).
//!
//! It also carries the M1 admin subcommands the ADRs specify ([`admin`]): `secrets init`,
//! `secrets rotate [--data-key]`, `backup-secrets`, `migrate`, and `backup` and `restore` with
//! the logical backup file of ADR 0023 (`rizzy_storage::backup::file`).
//!
//! # Module map
//!
//! | Module | Spec | Purpose |
//! |---|---|---|
//! | [`cli`] | ADR 0010 §1, §4 | The command line and the process entry point |
//! | [`config`] | ADR 0010 §1, §4; ADR 0028 items 10–12 | Settings from a file and the environment |
//! | [`server`] | ADR 0010 §2, §4; ADR 0011 point 9; CRYPTO.md §5.8, §5.11; ADR 0021 §2; ADR 0023 §5 step 1 | Startup checks, the instance lock and its watchdog, serving, graceful shutdown |
//! | [`http`] | ADR 0002 point 3; ADR 0010 §1; ADR 0028; CRYPTO.md §5.10; INV-49, INV-52 | The router, the endpoints, the header parsers, the security headers, the web page |
//! | [`worker`] | ADR 0010 §1, §5; ADR 0011 point 9; ADR 0021 §3, §7; CRYPTO.md §5.11 "Rotation" | The worker loop |
//! | [`bridge`] | ADR 0016 R4 | The two cross-domain traits, wired |
//! | [`secrets_file`] | CRYPTO.md §5.11; ADR 0010 §4 | The secrets file's reader and writer |
//! | [`secrets_backup`] | ADR 0011 owner decision 3; CRYPTO.md §5.11 | The encrypted secrets backup file |
//! | [`admin`] | ADR 0010 §2, §4; ADR 0011; CRYPTO.md §5.8, §5.11 | The admin subcommands |
//! | [`log`] | INV-48 | Allow-listed structured log lines |
//! | [`fsutil`] | ADR 0010 §4 | Bounded reads, 0600 files, atomic replace, the inside-the-data-directory check |
//! | [`sys`] | ADR 0009 "RNG rules"; ADR 0016 R2 | The OS CSPRNG and the clock |
//! | [`coredump`] | INV-60; ADR 0024 | Core dumps off at process start, read back |
//!
//! # Contract
//!
//! - **No `unsafe`** (workspace lint and `#![forbid(unsafe_code)]`), no `unwrap`, `expect`,
//!   `panic!` or print macro outside tests.
//! - **No secret in a log, an error or a `Debug`** (INV-48): log lines take only integers,
//!   source constants and value-free error texts ([`log`]); the database URL, the secrets and
//!   the tokens redact their `Debug`; bodies and headers are never logged.
//! - **Untrusted input is bounded and parsed without panics**: request bodies (size limits,
//!   `rizzy-proto`'s bounded types), request headers ([`http::headers`]), the configuration
//!   file, the secrets file and the database backup file. Fuzz targets: `server_headers`,
//!   `server_config`, `server_secrets_file`; the request bodies are `rizzy-proto`'s
//!   `proto_json`; the backup file is `rizzy-storage`'s `db_backup_parse`.
//! - **Crate wiring** (ADR 0016 §3 notes, R2, R5): internal dependencies are the domain crates,
//!   `rizzy-storage` and `rizzy-bus`; the `rizzy-core` and `rizzy-proto` items the auth
//!   domain's API is written in come through its `types` module, which names them one by one
//!   (whether this crate should depend on the shared crates directly is an ADR 0016 §3 question
//!   for the owner). No sqlx. As a leaf it depends on getrandom directly and passes
//!   `UnwrapErr(SysRng)` to the domains ([`sys`]).
//! - **Core dumps off** (INV-60, ADR 0024): [`cli::main`] disables them before anything else
//!   and refuses to start if the read-back fails ([`coredump`]). As a leaf it may depend on
//!   rustix directly (ADR 0024 point 2).
//!
//! # The HTTP conventions ([ADR 0028])
//!
//! [ADR 0028] freezes, for `v1`, what this crate used to decide on its own. Where each item is
//! applied:
//!
//! | ADR 0028 item | Where |
//! |---|---|
//! | 1 paths and methods, 2 success, 3 errors and `Retry-After` | [`http::api`] (the table, [`http::api::status`]); the router in [`http`] |
//! | 4 bearer token, 5 request signing | [`http::headers`]; the signed request-target and the one `401` in [`http::api`]; the replay window in `rizzy-domain-auth` |
//! | 6 order of checks, 7 body limits, 8 slow and concurrent bodies | [`http::api`] |
//! | 9 listener | [`server::ServeLimits`], [`server::serve_http_with`] |
//! | 10 response headers; the HTTPS origin | [`http::security`]; [`config`] |
//! | 11 rate-limit source and trusted proxies | [`http::headers::client_address`], [`config`] |
//! | 12 configuration | [`config`], [`cli`] |
//! | 13 secrets file | [`secrets_file`], [`secrets_backup`] |
//! | 14 `GET /api/meta`, `Rizzy-Client` | [`http::api::meta`], [`http::headers::client_refused`] |
//! | 15 web role paths | [`http::web`] |
//!
//! The constants clients share (paths, header names, body limits, platform names) are
//! `rizzy-proto`'s. **This crate's readings where the ADR is silent**, each documented where it
//! is applied and reported to the owner: a `429` that comes from no bucket carries a fixed
//! `Retry-After` ([`http::api::RETRY_AFTER_FALLBACK_SECS`]); the `Rizzy-Client` and
//! `X-Forwarded-For` checks run on the 27 `/api/v1` endpoints, before the session check, and
//! not on `GET /api/meta`; a repeated `Authorization`, signing or `Content-Length` field line
//! is refused; another method on the web role's two paths is a plain `405`; a
//! `request_counter` above `i64::MAX` is refused (`rizzy-domain-auth`); the setting
//! `RIZZY_RECOVERY_WAIT_HOURS` (ADR 0008 decision 5), which item 12's list does not name
//! ([`config`]).
//!
//! # Not in this build (reported to the owner)
//!
//! - Deleting an old OPAQUE setup after its grace period (CRYPTO.md §5.8 step 4), and dropping
//!   an unused data key without adding a new one: neither has a command in any ADR ([`admin`]).
//! - A run of the `PostgreSQL` paths against a real server: the instance lock (ADR 0023 §5 step
//!   1; [`server`]), and `restore`, `migrate` and `secrets rotate` under it, are tested on
//!   `SQLite` here and by `rizzy-storage`'s `#[ignore]`d `PostgreSQL` tests.
//! - Recording a change of the recovery waiting period in the users' security event log
//!   (threat model §7.19, INV-69): that log is M3's.
//! - The `embed-web` feature and the web vault (M1 step 5), the admin listener and API (M3),
//!   `notify`, `icons` (M3) and `smtp` (M6).
//! - A setting for the minimum client versions: the list is built in and empty
//!   ([`http::api::MIN_CLIENT_VERSIONS`]), so no client is refused yet.
//!
//! # Tests
//!
//! `tests/http/` drives the router in-process against a real `SQLite` database: the security
//! headers and CSP; oversized bodies; anonymous requests to the large-body endpoints refused
//! before their body is read; the account endpoints' session gating, strict bodies and
//! recovery refusals and rate limit; [ADR 0028]'s conventions (`conventions`: the error table
//! and `Retry-After`, the one `401`, `Content-Length`, no CORS and no compression, the
//! trusted-proxy rule, `/api/meta` and `Rizzy-Client`, the web paths); request signing
//! (`signing`: over a real socket, the request-target bytes verified are the bytes sent, an
//! absolute-form target included, and the replay window's edges); key rotation end to end with
//! `rizzy-client` (`rotation`); and, over a bound localhost port, the header-read timeout and a
//! shutdown that a stalled request cannot hold open. `tests/cli.rs` runs the binary:
//! `--version`, usage errors, configuration errors, the `secrets` commands, and `backup` and
//! `restore` through a pipe and a file with their refusals.
//! `tests/drill.rs` is the operator's backup → wipe → restore drill in its fast form (the operator
//! guide, `docs/self-hosting.md` §10): secrets, `backup` to a file next to the running server,
//! the encrypted secrets backup, `restore` of that file into an empty database with its new
//! restore generation and reconciliation epochs, and the refusals; it also pins that a native
//! file copy restored in place opens no epoch.
//!
//! The end-to-end flows (signup, login, device authentication, signed requests, sync, rotation)
//! run through `rizzy-client`, the one dev-only internal edge ADR 0016 §4 admits.
//!
//! [ADR 0002]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0002-own-protocol.md
//! [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md
//! [ADR 0010]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0010-server-shape.md
//! [ADR 0011]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0011-storage.md
//! [ADR 0021]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0021-server-compaction.md

// Also set by the workspace lint table (ADR 0016 R7); repeated here so that no manifest edit
// alone admits `unsafe` in this crate.
#![forbid(unsafe_code)]
#![cfg_attr(not(test), warn(clippy::missing_docs_in_private_items))]

pub mod admin;
pub mod bridge;
pub mod cli;
pub mod config;
pub mod coredump;
pub mod fsutil;
pub mod http;
pub mod log;
pub mod secrets_backup;
pub mod secrets_file;
pub mod server;
pub mod sys;
pub mod worker;
