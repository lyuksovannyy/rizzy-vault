//! `WebAuthn` passkey ceremonies at the wasm boundary ([ADR 0039] §5: "`rizzy-wasm` exposes the
//! coarse calls... that `rizzy-client`'s state machine implements"), over
//! [`rizzy_client::passkey`].
//!
//! # What crosses, and why
//!
//! [`create_passkey`] is the one place in this crate, besides the master password, Secret Key,
//! export password and Emergency Kit (`lib.rs`'s "Rules of the boundary" rule 1), where key
//! material crosses to JavaScript: [`CreatedPasskey::private_key`] is the fresh credential's
//! raw 32-byte scalar. There is no way around it here — the caller (the extension's
//! background script, or the web vault) must hand that value straight to the existing,
//! generic encrypted item-write call (`Session::create_item`/`edit_item` with an
//! [`crate::items::ItemDraft`] adding a `passkey/<id>/private_key` field) to persist it, the
//! same way a freshly generated login password already crosses so the host can save it into a
//! new item. [`crate::secret`]'s own module docs name the reason this is unavoidable in a
//! shared-heap wasm boundary; the caller must not log it, store it outside the item's
//! encrypted field, or hold it longer than the one save call needs.
//!
//! [`Session::passkey_assertion`](crate::session::Session::passkey_assertion) is the opposite
//! shape: the stored private key never leaves Rust. It is read back from the already-decrypted
//! vault internally (the same pattern [`crate::session::Session::totp`] already uses for a
//! different concealed field) and only the resulting [`PasskeyAssertion`] — never the key —
//! crosses out. [`PasskeyAssertion::user_handle`] closes gap 35(a) of the M2 gap audit: the
//! stored `passkey/<id>/user_handle` is now read back and echoed out for the page's
//! `AuthenticatorAssertionResponse.userHandle`, the same way `credential_id` already was.
//!
//! [`Session::passkey_candidates`](crate::session::Session::passkey_candidates) lists one
//! item's stored passkeys' non-secret metadata — `rp_id`, `user_handle`, `credential_id`,
//! `alg`, `created_ms` — without the private key, for the host to pick which credential to run
//! `passkey_assertion` with and, for gap 35(b), to filter candidates against the page's
//! `allowCredentials` *before* calling it: `get_assertion`/`passkey_assertion` sign with
//! whatever credential the caller selects and do not themselves check it against
//! `allowCredentials` ([`rizzy_client::passkey::get_assertion`]'s own doc, "entirely the
//! caller's"). A host that skips this filtering step would let a relying party's call sign
//! with a credential it did not list — that filtering must run in the host (never only in UI
//! code the page can see) before the one matching `passkey_assertion` call.
//!
//! # What this does not decide
//!
//! Neither call establishes `origin`: both take it as a caller-supplied `&str` and immediately
//! hand it to `rizzy_client::passkey`'s `verify_rp_id` (INV-64, a `pub(crate)` function there,
//! not linkable from here), which can only ever check the relationship between two strings it
//! is given (that function's own scope-boundary docs).
//! Reading `origin` from the browser's own sender information, never from a page-relayed
//! message, and refusing a cross-origin iframe before calling this far at all, are the
//! extension's job ([ADR 0039] §2; [ADR 0036] §4), not this crate's.
//!
//! [ADR 0036]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0036-browser-extension-architecture-and-key-custody.md
//! [ADR 0039]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0039-passkeys-vault-and-extension.md

use rizzy_client::passkey::create_credential;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::error::CoreError;
use crate::rng::os_rng;

/// Everything one `navigator.credentials.create()` ceremony resolves with (ADR 0039 §1), as
/// JavaScript receives it.
#[wasm_bindgen]
#[derive(Clone)]
pub struct CreatedPasskey {
    /// The fresh ES256 private key, 32 bytes: the caller's one job is to encrypt this straight
    /// into a new `passkey/<id>/private_key` field (module docs) and then drop every copy of
    /// it; this crate holds no reference after this struct returns.
    private_key: Vec<u8>,
    /// `passkey/<id>/credential_id`.
    credential_id: Vec<u8>,
    /// `passkey/<id>/public_key_cose`: the hand-written COSE `EC2` map.
    public_key_cose: Vec<u8>,
    /// `clientDataJSON`, for the caller to hand back to the page verbatim.
    client_data_json: Vec<u8>,
    /// The CBOR `attestationObject`, `"none"` format, for the caller to hand back to the page.
    attestation_object: Vec<u8>,
}

impl core::fmt::Debug for CreatedPasskey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CreatedPasskey")
            .field("private_key", &"[REDACTED]")
            .field("credential_id_len", &self.credential_id.len())
            .finish_non_exhaustive()
    }
}

#[wasm_bindgen]
impl CreatedPasskey {
    /// The fresh private key, 32 bytes (module docs: encrypt immediately, never log).
    #[wasm_bindgen(getter, js_name = privateKey)]
    #[must_use]
    pub fn private_key(&self) -> Vec<u8> {
        self.private_key.clone()
    }

    /// `passkey/<id>/credential_id`.
    #[wasm_bindgen(getter, js_name = credentialId)]
    #[must_use]
    pub fn credential_id(&self) -> Vec<u8> {
        self.credential_id.clone()
    }

    /// `passkey/<id>/public_key_cose`.
    #[wasm_bindgen(getter, js_name = publicKeyCose)]
    #[must_use]
    pub fn public_key_cose(&self) -> Vec<u8> {
        self.public_key_cose.clone()
    }

    /// `clientDataJSON`.
    #[wasm_bindgen(getter, js_name = clientDataJson)]
    #[must_use]
    pub fn client_data_json(&self) -> Vec<u8> {
        self.client_data_json.clone()
    }

    /// The CBOR `attestationObject`.
    #[wasm_bindgen(getter, js_name = attestationObject)]
    #[must_use]
    pub fn attestation_object(&self) -> Vec<u8> {
        self.attestation_object.clone()
    }
}

/// Everything one `navigator.credentials.get()` ceremony resolves with (ADR 0039 §2).
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct PasskeyAssertion {
    /// Echoed back unchanged from the caller's own already-stored `credential_id` (ADR 0039
    /// §5, "the API is coarse": the caller does not thread it through a second path).
    credential_id: Vec<u8>,
    /// Echoed back unchanged from the caller's own already-stored `user_handle`, for the
    /// page's `AuthenticatorAssertionResponse.userHandle` (gap 35(a) in the M2 gap audit).
    /// Empty when the caller had none to attach ([`rizzy_client::passkey::Assertion`]'s own
    /// doc on why that should not happen in practice); `js_name = userHandle` with an empty
    /// `Vec` rather than an `Option` because every other byte field on this boundary already
    /// uses an empty `Vec` for "nothing here" (module docs' "Rules of the boundary").
    user_handle: Vec<u8>,
    /// `clientDataJSON`, for the caller to hand back to the page verbatim.
    client_data_json: Vec<u8>,
    /// `authenticatorData`, for the caller to hand back to the page verbatim.
    authenticator_data: Vec<u8>,
    /// The DER-encoded ECDSA signature.
    signature_der: Vec<u8>,
}

#[wasm_bindgen]
impl PasskeyAssertion {
    /// The credential id, echoed back unchanged.
    #[wasm_bindgen(getter, js_name = credentialId)]
    #[must_use]
    pub fn credential_id(&self) -> Vec<u8> {
        self.credential_id.clone()
    }

    /// The user handle, echoed back unchanged (ADR 0039 §1's `passkey/<id>/user_handle`); an
    /// empty `Vec` when there is none to attach.
    #[wasm_bindgen(getter, js_name = userHandle)]
    #[must_use]
    pub fn user_handle(&self) -> Vec<u8> {
        self.user_handle.clone()
    }

    /// `clientDataJSON`.
    #[wasm_bindgen(getter, js_name = clientDataJson)]
    #[must_use]
    pub fn client_data_json(&self) -> Vec<u8> {
        self.client_data_json.clone()
    }

    /// `authenticatorData`.
    #[wasm_bindgen(getter, js_name = authenticatorData)]
    #[must_use]
    pub fn authenticator_data(&self) -> Vec<u8> {
        self.authenticator_data.clone()
    }

    /// The DER-encoded ECDSA signature.
    #[wasm_bindgen(getter, js_name = signatureDer)]
    #[must_use]
    pub fn signature_der(&self) -> Vec<u8> {
        self.signature_der.clone()
    }
}

impl From<rizzy_client::passkey::Assertion> for PasskeyAssertion {
    fn from(assertion: rizzy_client::passkey::Assertion) -> Self {
        Self {
            credential_id: assertion.credential_id,
            user_handle: assertion.user_handle.unwrap_or_default(),
            client_data_json: assertion.client_data_json,
            authenticator_data: assertion.authenticator_data,
            signature_der: assertion.signature_der,
        }
    }
}

/// Runs a `WebAuthn` registration ceremony for one new ES256 passkey (ADR 0039 §1, §2, §4;
/// module docs): checks INV-64, generates a fresh key from this crate's CSPRNG (`os_rng`, a
/// `pub(crate)` item not linkable from here), and assembles every byte structure the page's
/// `create()` promise resolves with. No vault is touched; the caller persists
/// [`CreatedPasskey::private_key`] and the other stored fields through the existing item-write
/// call.
///
/// `origin` must be the browser-verified origin (module docs, "What this does not decide");
/// `rp_id` is the `rpId` the page asked for, already defaulted by the caller to the origin's
/// host if the page omitted it; `challenge` is the relying party's own randomness.
///
/// # Errors
/// `rp_id_rejected` (INV-64), `invalid_input` for a malformed `origin`/`rp_id`.
#[wasm_bindgen(js_name = createPasskey)]
pub fn create_passkey(
    origin: &str,
    rp_id: &str,
    challenge: &[u8],
) -> Result<CreatedPasskey, CoreError> {
    let created = create_credential(&mut os_rng(), origin, rp_id, challenge)?;
    Ok(CreatedPasskey {
        private_key: created.signing_key.to_bytes().expose_secret().to_vec(),
        credential_id: created.credential_id,
        public_key_cose: created.public_key_cose,
        client_data_json: created.client_data_json,
        attestation_object: created.attestation_object,
    })
}

/// One stored passkey's non-secret metadata (ADR 0039 §1), built by
/// [`crate::session::Session::passkey_candidates`] — **never** `private_key` (module docs).
#[wasm_bindgen]
#[derive(Clone)]
pub struct PasskeyCandidate {
    /// The element id (`passkey/<id>/…`'s `<id>`, hex), for a later `passkeyAssertion` call.
    pub(crate) element_id: String,
    /// `passkey/<id>/rp_id`.
    pub(crate) rp_id: String,
    /// `passkey/<id>/user_handle`.
    pub(crate) user_handle: Vec<u8>,
    /// `passkey/<id>/credential_id`, for the host to filter against the page's
    /// `allowCredentials` (gap 35(b)) before picking a candidate to assert with.
    pub(crate) credential_id: Vec<u8>,
    /// `passkey/<id>/alg` (`1` = ES256, `2` = `EdDSA`; ADR 0039 §1).
    pub(crate) alg: u16,
    /// `passkey/<id>/created_ms`.
    pub(crate) created_ms: u64,
}

impl core::fmt::Debug for PasskeyCandidate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PasskeyCandidate")
            .field("element_id", &self.element_id)
            .field("rp_id", &self.rp_id)
            .field("alg", &self.alg)
            .finish_non_exhaustive()
    }
}

#[wasm_bindgen]
impl PasskeyCandidate {
    /// The element id, for a later `passkeyAssertion` call.
    #[wasm_bindgen(getter, js_name = elementId)]
    #[must_use]
    pub fn element_id(&self) -> String {
        self.element_id.clone()
    }

    /// `passkey/<id>/rp_id`.
    #[wasm_bindgen(getter, js_name = rpId)]
    #[must_use]
    pub fn rp_id(&self) -> String {
        self.rp_id.clone()
    }

    /// `passkey/<id>/user_handle`.
    #[wasm_bindgen(getter, js_name = userHandle)]
    #[must_use]
    pub fn user_handle(&self) -> Vec<u8> {
        self.user_handle.clone()
    }

    /// `passkey/<id>/credential_id`.
    #[wasm_bindgen(getter, js_name = credentialId)]
    #[must_use]
    pub fn credential_id(&self) -> Vec<u8> {
        self.credential_id.clone()
    }

    /// `passkey/<id>/alg`.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn alg(&self) -> u16 {
        self.alg
    }

    /// `passkey/<id>/created_ms`.
    #[wasm_bindgen(getter, js_name = createdMs)]
    #[must_use]
    pub fn created_ms(&self) -> u64 {
        self.created_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_a_passkey_for_a_valid_origin_and_rp_id() {
        let created = create_passkey("https://example.com", "example.com", b"chal").unwrap();
        assert_eq!(created.private_key().len(), 32);
        assert_eq!(created.credential_id().len(), 32);
        assert!(!created.public_key_cose().is_empty());
        assert!(!created.client_data_json().is_empty());
        assert!(!created.attestation_object().is_empty());
    }

    #[test]
    fn refuses_an_rp_id_that_fails_inv_64() {
        let error = create_passkey("https://evil.example", "bank.com", b"chal").unwrap_err();
        assert_eq!(error.as_str(), "rp_id_rejected");
    }

    #[test]
    fn debug_never_prints_the_private_key() {
        let created = create_passkey("https://example.com", "example.com", b"chal").unwrap();
        let printed = format!("{created:?}");
        assert!(!printed.contains(&format!("{:?}", created.private_key())));
        assert!(printed.contains("REDACTED"));
    }
}
