//! `rizzy-client` — the sans-I/O client core of rizzy-vault ([ADR 0013] §1–§2, [ADR 0016] §3
//! row `rizzy-client`, [ADR 0019] §5).
//!
//! The security logic every client shares exists here once: signup, login on a new device,
//! unlock on an enrolled device with the account-state checks, device authentication and
//! request signing, the sync driver, item edits through the schema layer, import, and the
//! encrypted and plaintext exports. Bindings (`rizzy-wasm`, `rizzy-ffi`) and native hosts
//! (`rizzy-cli`) wrap it; no host re-implements a check.
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
//!   serialises requests and sends them to the paths and with the headers of ADR 0028
//!   (`rizzy_proto::http`).
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
//! | [`credentials`] | CRYPTO.md §11.5, §11.3 step 5 | Master password and Secret Key change, with or without a rotation; following a change made elsewhere |
//! | [`two_factor`] | CRYPTO.md §5.10, §11.15 | Server-side 2FA enrolment (the otpauth URI) and removal requests |
//! | [`session`] | CRYPTO.md §5.10 | Device authentication and request signing |
//! | [`sync`] | ADR 0012 §4, §7; ADR 0018 §3, §10; ADR 0021 §2, §4, §9 | The sync driver of one vault |
//! | [`items`] | ADR 0018 §2, §6–§9; ADR 0012 §5; ADR 0027 §2 steps 3–5 | Item create, edit, trash, restore, purge and reads; the import path, which splits an item over a create op and the ops that follow |
//! | [`lists`] | ADR 0018 §6 "List elements", "List order" | The writes that add, edit and remove URIs, custom fields, password-history entries and tags of an item |
//! | [`export`] | CRYPTO.md §11.14 | The encrypted export file writer and bounded reader |
//! | [`export::payload`] | ADR 0027 §1–§2 | The export payload: encoding, bounded reader, import of our own export as new items |
//! | [`export::plaintext`] | ADR 0027 §3–§5 | Plaintext JSON and CSV behind the typed acknowledgement; the frozen warning texts |
//!
//! Import files of other products, and our own plaintext JSON export, are read by
//! `rizzy-import`, re-exported as [`rizzy_import`] for hosts that link only this crate
//! (`rizzy-cli`, the bindings); its items reach a vault through
//! [`sync::VaultSync::import_items`].
//!
//! # Cache policy
//!
//! [ADR 0026] defines the device-state record and the encrypted local cache, and [`store`]
//! implements them: the record codec, the schema and row model, the changeset each step
//! returns, the floors that never go backwards, and the load, which verifies every row as if
//! it were a server's answer. The host runs the SQL; this crate decides what is written.
//! Nothing decrypted is persisted: [`device::DeviceState`] and [`sync::VaultSync`] are rebuilt
//! at each unlock, and a lock is dropping them (their secrets are wiped on drop). The in-memory
//! policy is ADR 0018 §10's: a vault keeps every accepted op header ("Headers kept"), each
//! item's merge state, and the decrypted data of only the ops since the item's newest snapshot,
//! the ops still waiting, and its own unacknowledged ops; the rest is dropped after every Fetch
//! and upload answer. The cache drops the ciphertext body of a served op too, once a snapshot
//! this device wrote and the server acknowledged covers it ([`store`], "Pruning"). A host that keeps no cache (the web vault) never turns the journal on
//! ([`sync::VaultSync::persist`]).
//!
//! # HTTP
//!
//! [ADR 0028] fixes the paths, methods and headers of `/api/v1`; the constants live in
//! `rizzy-proto` (re-exported as [`rizzy_proto`]), and the host's transport reads them from
//! there. This crate still sends nothing: it hands the host typed requests and the values of
//! the bearer token and request signature.
//!
//! [ADR 0026]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0026-client-device-state-and-cache.md
//! [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md
//! [ADR 0013]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0013-shared-client-core.md
//! [ADR 0016]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0016-workspace-layout.md
//! [ADR 0019]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0019-native-clients.md

// Also set by the workspace lint table (ADR 0016 R7); repeated here so that no manifest edit
// alone admits `unsafe` in this crate.
#![forbid(unsafe_code)]
#![warn(clippy::indexing_slicing, clippy::unreachable)]
#![cfg_attr(not(test), warn(clippy::missing_docs_in_private_items))]

pub mod account;
pub mod credentials;
pub mod device;
pub mod error;
pub mod export;
pub mod items;
pub mod lists;
pub mod login;
pub mod recovery;
pub mod rotation;
pub mod session;
pub mod signup;
pub mod store;
pub mod sync;
pub mod two_factor;
pub mod unlock;
mod wire;

pub use error::ClientError;
/// The importers (ADR 0016 §3 row `rizzy-import`), re-exported so that a host that may depend
/// on this crate only (`rizzy-cli`, a binding) can read an import file and pass its items to
/// [`sync::VaultSync::import_items`].
pub use rizzy_import;
/// The wire types and the HTTP constants of `/api/v1` (ADR 0002 point 3, ADR 0028),
/// re-exported so that a host that may depend on this crate only (`rizzy-cli`, a binding; ADR
/// 0016 §3) can name the request and response types the flows hand it and the paths and
/// headers it sends them with.
pub use rizzy_proto;

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code indexes fixtures; a panic there fails the test, which CLAUDE.md allows"
)]
mod tests;
