// SPDX-License-Identifier: AGPL-3.0-only

//! In-process HTTP tests of `rizzy-vault`'s router over a real `SQLite` database: the security
//! headers and CSP (INV-49), body limits, slow and anonymous clients, the listener's timeouts and
//! bounded shutdown, the uniform error answers, the session gating and strict bodies of the
//! account endpoints (password change, suspension, recovery, TOTP), the worker as leader on
//! `SQLite` with the data-key rotation end to end (`worker`: `secrets rotate --data-key`, the
//! worker's re-seal, the old key dropped; and the recovery-wait setting), and key rotation end to end with `rizzy-client` (`rotation`: standard and full
//! rotation, the revocation of CRYPTO.md §11.8, the `state_conflict` retry, ADR 0025). Retiring old OPAQUE
//! setups end to end (`setups`, ADR 0031). The per-account storage quota (`quota`, ADR 0048): the
//! exact boundary, `quota_exceeded` on the wire, the reconciliation and the backfill. Threat model INV-1 over captured request bodies
//! (`password_equivalents`): registration, login and password change send only OPAQUE messages.
//! A paged Fetch splitting a tombstone cover from its purge across a small page budget, end to
//! end with `rizzy-client` (`paged_fetch`, ADR 0050).
//! Listing and ending sessions (`sessions`, ADR 0075): the gating and strict body of each route,
//! the ended token's `401` byte for byte, a device ending web sessions, another account's id.
//! `WebAuthn` security keys (`webauthn`, ADR 0058): enrolment and login with a software
//! authenticator, the pending row, single use, the state never in a body, gating and strict bodies.
//! Encrypted attachments (`attachments`, ADR 0054): upload, a second device's byte-identical
//! download, retries and conflicts, exact chunk lengths and indices, another account's id, the
//! 25 MiB cap and the quota answered `quota_exceeded`, and the counter released at delete.
//!
//! The admin listener's boundary (`admin_panel`, ADR 0060 §1, §2): its own router under its own
//! CSP, every path a plain `404` at M3, a vault session reaching nothing there, and `/admin/...`
//! a plain `404` on the public listener.
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
mod admin_panel;
mod attachments;
mod attack;
mod common;
mod conventions;
mod headers;
mod limits;
mod paged_fetch;
mod password_equivalents;
mod quota;
mod recovery;
mod rotation;
mod sessions;
mod setups;
mod signing;
mod vaults;
mod webauthn;
mod worker;
