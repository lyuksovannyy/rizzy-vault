//! `rizzy-core` — the single implementation of rizzy-vault's cryptography and data model.
//!
//! Contract for this crate (enforced in review and CI):
//! - No I/O: no filesystem, network, clock or randomness source is reached directly; callers
//!   inject them. This keeps the crate deterministic in tests and portable to
//!   `wasm32-unknown-unknown` (web vault, browser extension) and to `UniFFI` (mobile).
//! - No `unsafe` code (`unsafe_code = "forbid"` at the workspace level).
//! - No cryptographic construction lands here without an accepted ADR in `docs/adr/`.
//!
//! Status: M0 skeleton. Intentionally empty until the crypto design ADRs are accepted.
