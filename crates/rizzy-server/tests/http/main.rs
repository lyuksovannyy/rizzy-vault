//! In-process HTTP tests of `rizzy-vault`'s router over a real `SQLite` database: the security
//! headers and CSP (INV-49), body limits, slow and anonymous clients, the listener's timeouts and
//! bounded shutdown, the uniform error answers, the session gating and strict bodies of the
//! account endpoints (password change, suspension, recovery, TOTP), and the worker as leader on
//! `SQLite`, and key rotation end to end with `rizzy-client` (`rotation`: standard and full
//! rotation, the revocation of CRYPTO.md §11.8, the `state_conflict` retry, ADR 0025).

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests: a failure fails the test, which CLAUDE.md allows in test code"
)]

mod account;
mod common;
mod headers;
mod limits;
mod rotation;
mod worker;
