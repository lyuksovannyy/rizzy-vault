// SPDX-License-Identifier: AGPL-3.0-only

//! Security keys as a server-side second factor for the web vault ([ADR 0058] as amended by
//! [ADR 0077]; CRYPTO.md §11.17; `rizzy_client::webauthn`).
//!
//! ```text
//! (fresh OPAQUE session)
//! const e = session.securityKeyEnrolResponse(...send(session.securityKeyEnrolRequest()))
//! const credential = await navigator.credentials.create(fromJson(e.options))   // UI thread
//! send(session.securityKeyConfirmRequest(e.enrolmentId, label, toJson(credential)))   // 204
//! const keys = session.securityKeyListResponse(...send(session.securityKeyListRequest()))
//! send(session.securityKeyRemoveRequest(keys[0].credentialId))                        // 204
//! ```
//!
//! The ceremony runs in the browser on the web vault's own origin, never in this module: it only
//! builds the requests and reads the answers. The options and the credential stay JSON text.
//!
//! [ADR 0058]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0058-webauthn-2fa-second-factor.md
//! [ADR 0077]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0077-webauthn-rs-integration-fixes.md

use rizzy_client::ClientError;
use rizzy_client::rizzy_proto::http::paths;
use rizzy_client::rizzy_proto::webauthn::{
    WebauthnCredentialId, WebauthnEnrolStartResponse, WebauthnListResponse,
};
use rizzy_client::rizzy_proto::wire::Id;
use rizzy_client::webauthn::{enrol_confirm_request, remove_request};
use wasm_bindgen::prelude::wasm_bindgen;

use super::Session;
use crate::error::{CoreError, CoreResult};
use crate::http::{self, HttpRequest};

/// A started enrolment: its id (base64url) and the creation options JSON.
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct SecurityKeyEnrolment {
    /// The enrolment id, base64url.
    enrolment_id: String,
    /// The creation options JSON.
    options: String,
}

#[wasm_bindgen]
impl SecurityKeyEnrolment {
    /// The enrolment id, for [`Session::security_key_confirm_request`].
    #[wasm_bindgen(getter, js_name = enrolmentId)]
    #[must_use]
    pub fn enrolment_id(&self) -> String {
        self.enrolment_id.clone()
    }

    /// The options for `navigator.credentials.create` (`{"publicKey": {...}}`, base64url values).
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn options(&self) -> String {
        self.options.clone()
    }
}

/// One enrolled security key, as the account's owner sees it.
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct SecurityKeyRow {
    /// The credential id, base64url: the handle of [`Session::security_key_remove_request`].
    credential_id: String,
    /// The user's label.
    label: String,
    /// When it was enrolled.
    created_ms: u64,
}

#[wasm_bindgen]
impl SecurityKeyRow {
    /// The credential id, base64url.
    #[wasm_bindgen(getter, js_name = credentialId)]
    #[must_use]
    pub fn credential_id(&self) -> String {
        self.credential_id.clone()
    }

    /// The user's label.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn label(&self) -> String {
        self.label.clone()
    }

    /// Enrolment time, Unix milliseconds.
    #[wasm_bindgen(getter, js_name = createdMs)]
    #[must_use]
    pub fn created_ms(&self) -> u64 {
        self.created_ms
    }
}

/// A base64url value as its JSON string form, re-read through the wire type's strict decoder.
fn b64url<T: serde::de::DeserializeOwned>(text: &str) -> CoreResult<T> {
    serde_json::from_value(serde_json::Value::String(text.to_owned()))
        .map_err(|_| ClientError::InvalidInput.into())
}

/// The base64url text of a wire value that serialises to a JSON string.
fn text_of<T: serde::Serialize>(value: &T) -> CoreResult<String> {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .ok_or_else(|| ClientError::InvalidServerResponse.into())
}

#[wasm_bindgen]
impl Session {
    /// `webauthn/enrol/start` (ADR 0058 point 2): needs a fresh OPAQUE session.
    ///
    /// # Errors
    /// `locked`.
    #[wasm_bindgen(js_name = securityKeyEnrolRequest)]
    pub fn security_key_enrol_request(&self) -> Result<HttpRequest, CoreError> {
        Ok(HttpRequest::post_empty(
            paths::WEBAUTHN_ENROL_START,
            Some(&self.inner()?.token),
        ))
    }

    /// Reads the answer to [`Session::security_key_enrol_request`].
    ///
    /// # Errors
    /// `locked`; the server's code (`not_found` when this server cannot be a relying party,
    /// `fresh_session_required`); `invalid_server_response`.
    #[wasm_bindgen(js_name = securityKeyEnrolResponse)]
    pub fn security_key_enrol_response(
        &self,
        status: u16,
        body: &[u8],
    ) -> Result<SecurityKeyEnrolment, CoreError> {
        self.inner()?;
        let answer: WebauthnEnrolStartResponse = http::json(status, body)?;
        Ok(SecurityKeyEnrolment {
            enrolment_id: text_of(&answer.enrolment_id)?,
            options: answer.options.as_str().to_owned(),
        })
    }

    /// `webauthn/enrol/confirm`: the browser's `create()` result as JSON, and the user's label;
    /// its answer is an empty success.
    ///
    /// # Errors
    /// `locked`; `invalid_input` for an empty or over-long label, a bad enrolment id, or JSON
    /// outside the wire bounds.
    #[wasm_bindgen(js_name = securityKeyConfirmRequest)]
    pub fn security_key_confirm_request(
        &self,
        enrolment_id: &str,
        label: &str,
        credential_json: &str,
    ) -> Result<HttpRequest, CoreError> {
        let id: Id = b64url(enrolment_id)?;
        let request = enrol_confirm_request(id, label, credential_json)?;
        HttpRequest::post(
            paths::WEBAUTHN_ENROL_CONFIRM,
            &request,
            Some(&self.inner()?.token),
        )
    }

    /// `webauthn/list`: the account's security keys.
    ///
    /// # Errors
    /// `locked`.
    #[wasm_bindgen(js_name = securityKeyListRequest)]
    pub fn security_key_list_request(&self) -> Result<HttpRequest, CoreError> {
        Ok(HttpRequest::post_empty(
            paths::WEBAUTHN_LIST,
            Some(&self.inner()?.token),
        ))
    }

    /// Reads the answer to [`Session::security_key_list_request`], oldest first. The server's
    /// word, for display.
    ///
    /// # Errors
    /// `locked`; the server's code; `invalid_server_response`.
    #[wasm_bindgen(js_name = securityKeyListResponse)]
    pub fn security_key_list_response(
        &self,
        status: u16,
        body: &[u8],
    ) -> Result<Vec<SecurityKeyRow>, CoreError> {
        self.inner()?;
        let answer: WebauthnListResponse = http::json(status, body)?;
        answer
            .credentials
            .as_slice()
            .iter()
            .map(|k| {
                Ok(SecurityKeyRow {
                    credential_id: text_of(&k.credential_id)?,
                    label: k.label.as_str().to_owned(),
                    created_ms: k.created_ms,
                })
            })
            .collect()
    }

    /// `webauthn/remove` for the key `credential_id` (base64url, from a listed row); needs a
    /// fresh OPAQUE session; its answer is an empty success.
    ///
    /// # Errors
    /// `locked`; `invalid_input` for an id that is not base64url of 1 to 1023 bytes.
    #[wasm_bindgen(js_name = securityKeyRemoveRequest)]
    pub fn security_key_remove_request(
        &self,
        credential_id: &str,
    ) -> Result<HttpRequest, CoreError> {
        let id: WebauthnCredentialId = b64url(credential_id)?;
        let request = remove_request(id.as_slice())?;
        HttpRequest::post(paths::WEBAUTHN_REMOVE, &request, Some(&self.inner()?.token))
    }
}
