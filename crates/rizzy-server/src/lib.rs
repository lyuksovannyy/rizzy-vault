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
//! - **`worker`**: expired auth state, stale reconciliation epochs, compaction, `SQLite` space and
//!   the pre-migration copy ([`worker`]).
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
//! | [`config`] | ADR 0010 §1, §4 | Settings from a file and the environment |
//! | [`server`] | ADR 0010 §2, §4; ADR 0011 point 9; CRYPTO.md §5.8, §5.11; ADR 0021 §2 | Startup checks, serving, graceful shutdown |
//! | [`http`] | ADR 0002 point 3; ADR 0010 §1; CRYPTO.md §5.10; INV-49, INV-52 | The router, the endpoints, the header parsers, the security headers, the web page |
//! | [`worker`] | ADR 0010 §1, §5; ADR 0011 point 9; ADR 0021 §3, §7 | The worker loop |
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
//! # Wire and format details this crate decides
//!
//! No Accepted ADR fixes these; each is documented where it is applied and reported to the
//! owner as a pre-v1.0 choice (ADR 0002 point 5): the endpoint paths and methods, "empty
//! success" as `204`, and the HTTP status of each error code ([`http::api`]); the bearer and
//! request-signing header forms ([`http::headers`]); the body limits, body-read deadlines and
//! the cap on concurrent large bodies ([`http::api`]); the listener's header-read timeout,
//! connection cap and shutdown grace ([`server::ServeLimits`]); the rate-limit source
//! (IPv6 per /64); the configuration file format and setting names ([`config`]); the secrets
//! file layout ([`secrets_file`]); the secrets backup file layout ([`secrets_backup`], which
//! CRYPTO.md §5.11 places here).
//!
//! # Not in this build (reported to the owner)
//!
//! - `rizzy-vault restore` into `PostgreSQL`: ADR 0023 §5's instance lock is not implemented,
//!   so it is refused with a usage error ([`admin`]).
//! - The `embed-web` feature and the web vault (M1 step 5), the admin listener and API (M3),
//!   `notify`, `icons` (M3) and `smtp` (M6), and key rotation: the commit endpoint refuses a
//!   state that rotates a key, so the revocation of CRYPTO.md §11.8 step 3 and the default
//!   recovery of §11.9 step 5 are refused too (the vault half of §11.6 step 9 has no wire form;
//!   [`http::api`]). Password change, settings, self-revocation, suspension, recovery without
//!   rotation and TOTP have endpoints.
//!
//! # Tests
//!
//! `tests/http/` drives the router in-process against a real `SQLite` database: the security
//! headers and CSP; oversized bodies; anonymous requests to the large-body endpoints refused
//! before their body is read; the account endpoints' session gating, strict bodies and
//! recovery refusals and rate limit; and, over a bound localhost port, the header-read timeout and a
//! shutdown that a stalled request cannot hold open. `tests/cli.rs` runs the binary:
//! `--version`, usage errors, configuration errors, the `secrets` commands, and `backup` and
//! `restore` through a pipe and a file with their refusals.
//! `tests/drill.rs` is the operator's backup → wipe → restore drill in its fast form (the operator
//! guide, `docs/self-hosting.md` §10): secrets, `backup` to a file next to the running server,
//! the encrypted secrets backup, `restore` of that file into an empty database with its new
//! restore generation and reconciliation epochs, and the refusals; it also pins that a native
//! file copy restored in place opens no epoch.
//!
//! **Not tested here yet:** the end-to-end flow (signup, login, device authentication, a signed
//! upload and a Fetch with `rizzy-core`'s client-side functions, signature and replay
//! refusals). It needs `rizzy-core`, `rizzy-proto` and `rizzy-sync` in this crate's tests, and
//! ADR 0016 point 4 allows only a `rizzy-client` dev-dependency, which does not exist yet. The
//! domain crates test the same flows without HTTP; the owner decides how the HTTP flow returns.
//!
//! [ADR 0002]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0002-own-protocol.md
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
