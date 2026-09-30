//! In-process HTTP tests of `rizzy-vault`'s router over a real `SQLite` database: the security
//! headers and CSP (INV-49), body limits, slow and anonymous clients, the listener's timeouts and
//! bounded shutdown, the uniform error answers, the session gating and strict bodies of the
//! account endpoints (password change, suspension, recovery, TOTP), and the worker as leader on
//! `SQLite`, and key rotation end to end with `rizzy-client` (`rotation`: standard and full
//! rotation, the revocation of CRYPTO.md §11.8, the `state_conflict` retry, ADR 0025).
//!
//! ADR 0028's HTTP conventions are pinned by `conventions` (the error table and `Retry-After`,
//! the one `401`, `Content-Length`, no CORS and no compression, the trusted-proxy rule,
//! `/api/meta` and `Rizzy-Client`, the web role's paths) and `signing` (over a real socket:
//! the request-target bytes verified are the bytes sent, an absolute-form target included; the
//! replay window's edges).

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests: a failure fails the test, which CLAUDE.md allows in test code"
)]

mod account;
mod common;
mod conventions;
mod headers;
mod limits;
mod recovery;
mod rotation;
mod signing;
mod worker;
