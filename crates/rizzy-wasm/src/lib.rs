//! `rizzy-wasm` — the wasm-bindgen bindings of rizzy-vault's client core for the web vault
//! ([ADR 0013] §1, §3, §4; [ADR 0016] §3 row `rizzy-wasm`; [ADR 0014] §4 `packages/core`).
//!
//! A leaf crate over `rizzy-client`, and like it **sans-I/O**: JavaScript performs every
//! `fetch` and owns the clock; Rust builds every request, verifies every answer and holds
//! every key. The generated glue is reachable only through `packages/core`'s TypeScript
//! wrapper (ADR 0013 §4 "One entry point for UI code"), which runs this module in one
//! dedicated Worker of the web vault (ADR 0013 §4 "Where the core lives").
//!
//! # The shape of every flow
//!
//! ```text
//! const flow = LoginFlow.start(origin, loginName, secretKey, password)
//! while (flow.state === "request") {
//!   const r = flow.request()                       // method, path, body, headers
//!   const res = await fetch(origin + r.path, …)    // the host's transport
//!   flow.respond(res.status, bytes, BigInt(Date.now()))
//! }
//! const session = flow.finish()                    // the handle that holds the keys
//! ```
//!
//! [`SignupFlow`] and the sync of a [`Session`] ([`Session::sync_start`],
//! [`Session::sync_request`], [`Session::sync_respond`]) take the same loop.
//!
//! # Exported API
//!
//! | Export | What |
//! |---|---|
//! | [`SignupFlow`], [`EmergencyKit`] | signup of a web-vault account (CRYPTO.md §11.1, kind 4) |
//! | [`LoginFlow`] | an OPAQUE login with an optional second factor; also a session's re-authentication |
//! | [`Session`] | the unlocked session: sync driver, items, TOTP, export, import, devices, 2FA, lock |
//! | [`ItemDraft`], [`ItemSummary`], [`FieldView`] | item edits and views |
//! | [`HttpRequest`], [`meta_request`], [`check_meta`], [`expect_no_content`] | the requests JavaScript sends and the answers it hands back |
//! | [`generate_password_with_options`] (`generatePasswordWithOptions`), [`generate_passphrase_with_options`] (`generatePassphraseWithOptions`), [`password_entropy`] (`passwordEntropy`), [`passphrase_entropy`] (`passphraseEntropy`), [`generator_limits`] (`generatorLimits`), [`GeneratorLimits`], [`Generated`] | the generator, every option ([`generator`]) |
//! | [`TotpCode`], [`EncryptedExport`], [`ImportReport`], [`DeviceView`], [`TwoFactorEnrolment`] | results |
//! | [`plaintext_export_warning`], [`plaintext_export_phrase`] | the frozen texts of ADR 0027 §5 |
//! | [`plaintext_export_hold_ms`], [`detect_import_format`] | the hold after the plaintext warning; recognising an import file (owner decision 2026-10-05) |
//! | [`CoreError`] | the one thrown error: a stable code ([`error`]) |
//!
//! # Rules of the boundary ([ADR 0013] §3)
//!
//! - **Keys stay in Rust** (rule 1). No call returns an account, vault, item, identity or
//!   device key, `export_key`, `pw_in` or an unlock key. The named exceptions this crate uses:
//!   the master password, the Secret Key, the export password and the 2FA code go in; the
//!   Emergency Kit goes out once ([`SignupFlow::emergency_kit`]); a plaintext export goes out
//!   after a re-authentication, the warning and its hold ([`Session::export_plaintext`]). The OPAQUE session's bearer
//!   token goes out in the `Authorization` value of each request (it is the transport's
//!   credential, ADR 0028 item 4, not a key of rule 1).
//! - **Plaintext crosses at the smallest useful size** (rule 3): summaries for lists,
//!   concealed values only on reveal ([`items`]).
//! - **Errors** are [`CoreError`] codes with no secret in them (rule 4).
//! - **Ciphertext crosses as bytes** (rule 5): request bodies and the encrypted export are
//!   opaque bytes to JavaScript.
//! - **The API is coarse** (rule 6): one call per user action; `rizzy-core`'s primitives are
//!   not exported.
//! - **Bindings are generated** (rule 7): `#[wasm_bindgen]` only; no hand-written `unsafe`
//!   (workspace lint, `#![forbid(unsafe_code)]` below, and `cargo xtask check-deps`'s token
//!   scan). The `unsafe` the generator emits is reviewed as a committed baseline
//!   (`generated/`; ADR 0019 §4.1 (b), owner decision 7; `cargo xtask check-bindings`).
//! - **Host input is untrusted** (rule 8): every value from JavaScript is parsed and bounded
//!   here or in `rizzy-client` as if it came from the network; response bodies are bounded
//!   ([`http`]).
//!
//! # Honest limit
//!
//! In the browser, wasm and JavaScript share one heap, and JavaScript strings cannot be wiped
//! (ADR 0013 §4; CRYPTO.md §12.2), so the master password, Secret Key, recovery code and export
//! password cross as zeroable byte arrays instead ([`secret`]; ADR 0019 §3). The boundary
//! is an audit boundary, not a security boundary (threat model TB-10): an XSS can call this
//! same API.
//!
//! # Host builds
//!
//! The crate also compiles, and its tests run, on the host (ADR 0016 §3 notes). The flows'
//! logic is plain Rust; only the generated glue is wasm-specific.
//!
//! [ADR 0013]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0013-shared-client-core.md
//! [ADR 0014]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0014-ui-stack.md
//! [ADR 0016]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0016-workspace-layout.md

// Also set by the workspace lint table (ADR 0016 R7); repeated here so that no manifest edit
// alone admits `unsafe` in this crate.
#![forbid(unsafe_code)]
#![cfg_attr(not(test), warn(clippy::missing_docs_in_private_items))]

pub mod error;
pub mod generator;
pub mod http;
pub mod items;
mod login;
mod rng;
pub mod secret;
pub mod session;
mod signup;
pub mod sync;

pub use error::CoreError;
pub use generator::{
    Generated, GeneratorLimits, generate_passphrase_with_options, generate_password_with_options,
    generator_limits, passphrase_entropy, password_entropy,
};
pub use http::{HttpRequest, check_meta, expect_no_content, meta_request};
pub use items::{FieldView, ItemDraft, ItemSummary, generate_element_id};
pub use login::LoginFlow;
pub use session::{
    DeviceView, EncryptedExport, ImportReport, Session, TotpCode, TwoFactorEnrolment,
    detect_import_format, plaintext_export_hold_ms, plaintext_export_phrase,
    plaintext_export_warning,
};
pub use signup::{EmergencyKit, SignupFlow};

use wasm_bindgen::prelude::wasm_bindgen;

/// This build's version, as the `Rizzy-Client` header carries it.
#[wasm_bindgen(js_name = coreVersion)]
#[must_use]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

#[cfg(test)]
mod tests;
