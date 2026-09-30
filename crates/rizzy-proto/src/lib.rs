//! `rizzy-proto` — the `/api/v1` request and response types of rizzy-vault (roadmap M1,
//! [ADR 0002] point 3, [ADR 0016] §3).
//!
//! ADR 0002: "Request and response types are Rust types in `rizzy-proto`, shared by the server
//! and every client." JSON over HTTPS; binary fields as base64url without padding (CRYPTO.md
//! §9.6). The server treats envelopes as opaque bytes, and so does this crate: it parses no
//! envelope, statement or OPAQUE message, it only bounds and carries them. `rizzy-core`
//! verifies them and `rizzy-sync` parses the op and snapshot headers, on both sides.
//!
//! # Contract
//!
//! - **No I/O** ([ADR 0016] R1): no filesystem, network, clock, environment, process, thread
//!   or randomness source. It builds for `wasm32-unknown-unknown` (the web vault and the
//!   extension link it through `rizzy-client`), and its `clippy.toml` carries the R1
//!   disallowed-types and disallowed-methods lists. `cargo xtask check-deps` keeps it free of
//!   internal dependencies (§3 row: "–") and limits its closure to its allow-listed external
//!   crates: `serde` with its derive, `base64ct` for base64url, `zeroize` for secrets.
//! - **No `unsafe`** (workspace lint and `#![forbid(unsafe_code)]` below).
//! - **Errors, never panics.** Constructors return [`wire::WireError`]; deserialisers return
//!   the format's error. Neither ever quotes the input (see [`wire`] for `serde_json`'s own
//!   type errors, which callers must not forward or log).
//! - **Untrusted input is bounded.** Every variable field has a limit in its type ([`limits`]):
//!   a byte or text length checked before decoding, or an element count checked while parsing,
//!   with at most [`wire::LIST_PREALLOC_MAX`] elements reserved up front. Requests are parsed
//!   by the server and responses by clients from a server the threat model does not trust, so
//!   both are bounded. The fuzz target `proto_json` parses every type from arbitrary JSON.
//! - **Unknown fields.** Every request type, and every object type a request can contain,
//!   rejects unknown fields (CRYPTO.md §11.1 step 8), so no field can carry `E_dev` or any
//!   other device-only secret (§4.2). Top-level response types and response-only objects
//!   ignore unknown fields, so a later server can add fields (ADR 0002 point 3, additive
//!   changes); an unknown error code reads as [`error::ErrorCode::Unknown`].
//! - **Secrets.** Bearer tokens, invite tokens, TOTP codes, recovery auth tokens and the TOTP
//!   secret are [`wire::SessionToken`], [`wire::SecretText`] and [`wire::SecretFixed`]:
//!   zeroized on drop, `Debug` redacted, no `PartialEq`. Login names, OPAQUE messages,
//!   envelopes, statements and hashes print their length only in `Debug` (threat model
//!   INV-48).
//! - **Nothing signed uses serde.** Signed statements and AAD use CRYPTO.md §2's fixed layouts,
//!   carried here as bytes; JSON is transport only (§2 "Canonical encoding").
//!
//! # Module map
//!
//! | Module | Spec | Purpose |
//! |---|---|---|
//! | [`wire`] | CRYPTO.md §9.6; threat model §7.6 "D", INV-48 | Bounded value types: base64url [`wire::Bytes`], [`wire::Fixed`], [`wire::Id`]; [`wire::Text`], [`wire::List`]; the secrets |
//! | [`limits`] | CRYPTO.md §2, §5.1, §8.5, §9.1–§9.3, §10.2; ADR 0012 §3 | Every size limit, with its source, and the text character sets |
//! | [`error`] | ADR 0002 point 3; ADR 0028 item 3 | [`error::ErrorResponse`] and [`error::ErrorCode`] |
//! | [`meta`] | ADR 0002 point 3, as ADR 0022 amends it; ADR 0028 item 14 | `GET /api/meta`, the `Rizzy-Client` header, the platform names and the version rule |
//! | [`http`] | ADR 0028 items 1, 4, 5 | The endpoint paths, the bearer-token form and the request-signing headers |
//! | [`objects`] | CRYPTO.md §4.2, §8.4, §9.6, §10.1, §10.2 | Signed statements, envelopes, wrapped-key objects with their locators |
//! | [`auth`] | CRYPTO.md §5.3, §5.9, §5.10, §11.1, §11.2; ADR 0002 owner decision 2 | OPAQUE registration and login, device authentication, the request-signing values |
//! | [`account`] | CRYPTO.md §10.1, §10.2, §11.2 step 7, §11.3, §11.4; ADR 0012 §7 healing steps 1–3 | Account state, enrolment, the web vault's kind-4 certificate, bundles, device grants |
//! | [`change`] | CRYPTO.md §11 "Replacing credentials", §11.3 step 5, §11.5, §11.8 steps 0–2, §11.9 steps 5–6; ADR 0012 §6 | OPAQUE re-registration, the atomic commit of a credential, settings, device or key-rotation change (ADR 0025), suspension |
//! | [`recovery`] | CRYPTO.md §11.9; ADR 0008 | Recovery start, cancel and complete |
//! | [`totp`] | CRYPTO.md §5.10, §5.11, §11.15 | Server-side 2FA enrolment and removal |
//! | [`vault`] | ADR 0012 §3, §7; ADR 0021 §2, §4, §9 | Upload, Fetch and the healing request |
//!
//! # The HTTP conventions
//!
//! [ADR 0028] freezes the HTTP side of `v1`, and this crate keeps the constants the server and
//! the clients share: the endpoint paths, the bearer-token form and the request-signing headers
//! ([`http`], items 1, 4 and 5), the body limits ([`limits::MAX_BODY_LEN`],
//! [`limits::DEFAULT_UPLOAD_BODY_LEN`], [`limits::MAX_UPLOAD_BODY_LEN`], item 7), and the
//! `/api/meta` shape, the platform names and the `Rizzy-Client` version rule ([`meta`], item
//! 14). The HTTP status of each error code is item 3's ([`error`]); the server applies it, and
//! clients branch on the code.
//!
//! # Left open, not frozen here
//!
//! No Accepted ADR fixes the invite-token format, so this crate only bounds it.
//!
//! The rotation fields of [`change::CommitChangeRequest`], the vault half
//! ([`change::VaultRotationUpload`]) and the vaults of [`recovery::RecoveryCompleteResponse`]
//! follow ADR 0025 §1; their JSON field names are this crate's choice.
//!
//! JSON field names, the error codes that no spec names, the list-count limits and the upload
//! batch reading ([`vault::UploadResult`]) are this crate's choices. Before v1.0, `v1` may
//! change incompatibly under ADR 0002 point 5.
//!
//! # The `openapi` feature
//!
//! ADR 0002 point 3 generates a checked-in `OpenAPI` 3.1 file from these types, through a schema
//! derive behind the non-default `openapi` feature that only `xtask` enables ([ADR 0016] §3
//! notes). The generator crate is "chosen in M1" and is not chosen yet, so the feature is
//! declared and enables nothing: no schema derive exists, and no `OpenAPI` file is generated or
//! checked. Adding the generator is a dependency change reviewed under CLAUDE.md, with its
//! crate on this crate's R1 allow-list, marked as feature-gated.
//!
//! [ADR 0002]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0002-own-protocol.md
//! [ADR 0016]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0016-workspace-layout.md
//! [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md

// Also set by the workspace lint table (ADR 0016 R7); repeated here so that no manifest edit
// alone admits `unsafe` in this crate.
#![forbid(unsafe_code)]
#![warn(clippy::indexing_slicing, clippy::unreachable)]
#![cfg_attr(not(test), warn(clippy::missing_docs_in_private_items))]

pub mod account;
pub mod auth;
pub mod change;
pub mod error;
pub mod http;
pub mod limits;
pub mod meta;
pub mod objects;
pub mod recovery;
pub mod totp;
pub mod vault;
pub mod wire;

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "the tests edit serde_json::Value objects by key; a panic there fails the test, which CLAUDE.md allows"
)]
mod tests;
