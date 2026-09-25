//! `rizzy-sync` — the mode-agnostic sync engine (Server mode and On-device mode, roadmap M1/M4).
//!
//! Everything the server uses from this crate is ciphertext only. The field merge, however,
//! receives decrypted field writes from `rizzy-client` as opaque bytes in zeroizing types, so
//! this crate is in the plaintext audit scope (ADR 0012 section 13, owner decision 6).
//! Same portability contract as `rizzy-core`: no I/O, no `unsafe`, builds for
//! `wasm32-unknown-unknown`.
//!
//! Status: skeleton. ADR 0012 is accepted; code lands in M1 after the item record ADR.
