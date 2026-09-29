//! `rizzy-client` — the sans-I/O client core of rizzy-vault ([ADR 0013] §1–§2, [ADR 0016] §3
//! row `rizzy-client`, [ADR 0019] §5).
//!
//! The security logic every client shares exists here once: signup, login on a new device,
//! unlock on an enrolled device with the account-state checks, device authentication and
//! request signing, the sync driver, item edits through the schema layer, and the encrypted
//! export. Bindings (`rizzy-wasm`, `rizzy-ffi`) and native hosts (`rizzy-cli`) wrap it; no
//! host re-implements a check.
//!
//! # Contract
//!
//! - **No I/O** ([ADR 0016] R1, threat model INV-58): no network, filesystem, clock,
//!   environment, process, thread or randomness source. The host performs HTTP and storage and
//!   passes bytes, time (`now_ms`) and a `rand_core` `CryptoRng` in. `cargo check-wasm` builds
//!   the crate for `wasm32-unknown-unknown`; its `clippy.toml` carries the R1 lists; `cargo
//!   xtask check-deps` keeps its closure on the allow-list of its internal dependencies.
//! - **A state machine, not a transport** ([ADR 0013] §2). Each flow is a chain of typed
//!   states: a step consumes the previous state and the server's typed answer
//!   (`rizzy-proto`), and returns the next state and the next typed request. The host
//!   serialises requests and chooses paths; endpoint paths, methods and the HTTP headers of
//!   the bearer token and request signature are not fixed by any Accepted ADR, so none is
//!   frozen here (`rizzy-proto` "Left open").
//! - **No `unsafe`** (workspace lint and `#![forbid(unsafe_code)]` below).
//! - **Errors, never panics.** One typed [`ClientError`] with stable codes and no secret in it
//!   (ADR 0013 §3 rule 4). `unwrap`, `expect`, `panic!` and indexing are lint errors here.
//! - **Secrets** stay in `rizzy-core`'s zeroizing types (keys, `pw_in`, the Secret Key, the
//!   `export_key`, decrypted item data) or in `Zeroizing` buffers; every type that holds one is
//!   not `Clone` and prints no secret from `Debug` (CRYPTO.md §12.2). Keys never leave the
//!   crate except through the named exceptions of ADR 0013 §3 rule 2: the Emergency Kit
//!   ([`signup::EmergencyKit`]) and the device state (below).
//! - **The server is not trusted.** Every answer is verified before anything in it is
//!   adopted ([`account`], [`sync`]); rollback and fork of the signed account state make the
//!   device read-only (INV-25).
//!
//! # Module map
//!
//! | Module | Spec | Purpose |
//! |---|---|---|
//! | [`error`] | ADR 0013 §3 rule 4 | [`ClientError`] |
//! | [`account`] | CRYPTO.md §10.2, §10.3, §11.2 step 6, §11.3 steps 2–3 | Verifying an account answer; the pin; rollback, fork, identity change |
//! | [`device`] | CRYPTO.md §4.2, §5.6 | The in-memory device state; the offline unlock |
//! | [`signup`] | CRYPTO.md §7, §11 "Secrets before commit", §11.1 | Signup and the Emergency Kit |
//! | [`login`] | CRYPTO.md §5.3, §11.2, §11.4 | Login on a new device, enrolment, the web vault's ephemeral device |
//! | [`unlock`] | CRYPTO.md §11.3 | The online part of an unlock, device grants after a rotation |
//! | [`rotation`] | CRYPTO.md §11.6, §11.8 steps 1–3; ADR 0025 §2 | Standard and full key rotation with an optional revocation: new keys, the auth half, the vault half, the retry rule |
//! | [`session`] | CRYPTO.md §5.10 | Device authentication and request signing |
//! | [`sync`] | ADR 0012 §4, §7; ADR 0018 §3, §10; ADR 0021 §2, §4, §9 | The sync driver of one vault |
//! | [`items`] | ADR 0018 §2, §6–§9; ADR 0012 §5 | Item create, edit, trash, restore, purge and reads; the `rizzy-import` seam |
//! | [`export`] | CRYPTO.md §11.14 | The encrypted export file writer and bounded reader |
//!
//! # Cache policy
//!
//! No Accepted ADR defines the layout of the local encrypted cache or of the device-state
//! record (both are persistent formats, ADR 0001 point 5; ADR 0013 §3 rule 2; ADR 0019 §5).
//! So this crate freezes no format: [`device::DeviceState`] and [`sync::VaultSync`] live in
//! memory only, and a lock is dropping them (their secrets are wiped on drop). The in-memory
//! policy is ADR 0018 §10's: a vault keeps every accepted op header ("Headers kept"), each
//! item's merge state, and the decrypted data of only the ops since the item's newest snapshot,
//! the ops still waiting, and its own unacknowledged ops; the rest is dropped after every Fetch
//! and upload answer. Persisting the device state and the cache is a reported gap.
//!
//! [ADR 0013]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0013-shared-client-core.md
//! [ADR 0016]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0016-workspace-layout.md
//! [ADR 0019]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0019-native-clients.md

// Also set by the workspace lint table (ADR 0016 R7); repeated here so that no manifest edit
// alone admits `unsafe` in this crate.
#![forbid(unsafe_code)]
#![warn(clippy::indexing_slicing, clippy::unreachable)]
#![cfg_attr(not(test), warn(clippy::missing_docs_in_private_items))]

pub mod account;
pub mod device;
pub mod error;
pub mod export;
pub mod items;
pub mod login;
pub mod rotation;
pub mod session;
pub mod signup;
pub mod sync;
pub mod unlock;
mod wire;

pub use error::ClientError;

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code indexes fixtures; a panic there fails the test, which CLAUDE.md allows"
)]
mod tests;
