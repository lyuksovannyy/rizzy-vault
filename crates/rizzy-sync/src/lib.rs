//! `rizzy-sync` — the mode-agnostic sync engine (Server mode and On-device mode, roadmap M1/M4).
//!
//! Operates only on ciphertext envelopes from `rizzy-core`; it never needs plaintext.
//! Same portability contract as `rizzy-core`: no I/O, no `unsafe`, builds for
//! `wasm32-unknown-unknown`.
//!
//! Status: M0 skeleton. Intentionally empty until the sync engine ADR is accepted.
