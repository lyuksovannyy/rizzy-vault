// SPDX-License-Identifier: AGPL-3.0-only

//! CXF passkey export and the import of our own CXF export ([ADR 0074] §2, §3; CRYPTO.md
//! §11.14 "CXF passkey export").
//!
//! [ADR 0074]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0074-passkey-cxf-import-export.md
//!
//! # The file
//!
//! A sibling of the encrypted export (`super`), tagged `"format":"rizzy-vault-cxf-export"`
//! ([`CXF_FORMAT`]) with the same fields, key derivation and `EXPORT_FILE` envelope. Inside the
//! envelope, instead of ADR 0027's item-list payload (`payload_version` 1):
//!
//! ```text
//! u16(payload_version = 2) ‖ bytes(cxf_json)
//! ```
//!
//! `cxf_json` the UTF-8 CXF document, under the same 16 MiB plaintext cap. The outer tag is
//! cleartext; the authenticated discriminator is `payload_version`, and each reader checks its
//! own: [`VaultSync::import_cxf_encrypted`] refuses a payload of version 1 and
//! [`VaultSync::import_encrypted`] one of version 2, both as [`ClientError::InvalidExportFile`],
//! so swapping the tag fails at dispatch, never silently (ADR 0074 §2, "Why two payload
//! versions under one purpose is safe"). **No bare, unencrypted CXF export exists**: ADR 0074's
//! open question 4 needs a ROADMAP §4.10 edit first (owner answer 4 at acceptance).
//!
//! # The gate
//!
//! [`VaultSync::export_cxf`] takes [`PlaintextExportAuth`] and [`PlaintextExportAck`], the
//! tokens of the plaintext exports (ADR 0074 §2 "Gate"; ADR 0034 point 3 as ADR 0074 §5
//! replaces it): a fresh re-authentication, then [`CXF_EXPORT_WARNING`] (its own text, not ADR
//! 0027 §5's), the 10-second hold, and the typed `EXPORT PLAINTEXT` phrase (owner answer 3).
//! Once decrypted, the document is a complete, portable credential dump.
//!
//! # The document
//!
//! ```text
//! {"version":{"major":1,"minor":0},"exporterRpId":"","exporterDisplayName":"rizzy-vault",
//!  "timestamp":<seconds>,"accounts":[{"id":"<random>","username":"","email":"",
//!  "collections":[],"items":[{"id":"<item id>","title":"<item.name>","credentials":[
//!    {"type":"passkey","credentialId":…,"rpId":…,"username":…,"userDisplayName":…,
//!     "userHandle":…,"key":"<PKCS#8>"}, …]}, …]}]}
//! ```
//!
//! One account; one CXF item per **active** (not trashed) Login item with at least one
//! passkey, in item-id order; one passkey credential per `passkey/<id>/…` element of it
//! (ADR 0074 §2 "Building the item"): `rpId`, `userHandle`, `credentialId` copied; `key` the
//! stored `private_key` re-encoded as PKCS#8 ([`rizzy_core::passkey::pkcs8`]: ES256 with its
//! public key, the form `WebCrypto` and the CXF specification's own example use; `EdDSA` the
//! RFC 8410 form, the seed wrapped as it is); `username` and `userDisplayName` both the Login's
//! displayed `login.username`. `exporterDisplayName` is the fixed `"rizzy-vault"` and
//! `exporterRpId` empty (owner answer 5). An element whose fields cannot make a credential (a
//! field missing, of the wrong type, or an `alg` other than 1 and 2) is left out and counted in
//! [`CxfExport::skipped`]. Trashed items are not exported: a CXF document has no trash, and
//! importing one would bring them back as live items.
//!
//! The writer refuses a document its own reader ([`rizzy_import::cxf`]) would refuse for size:
//! more than [`MAX_ENTRIES`] items or credentials per item, more than [`MAX_JSON_LEN`] bytes or
//! [`MAX_NODES`] values, or a payload over the plaintext cap: [`ClientError::ExportTooLarge`].
//!
//! # Secrets
//!
//! The document is measured, then written into one zeroizing buffer of its final size (the
//! plaintext writer's [`Sink`]); the payload is copied once into another, also exact. Every
//! PKCS#8 key is a [`SecretBytes`]. Only the sealed file leaves this module.

use rizzy_core::encoding::{Reader, put_bytes, put_u16};
use rizzy_core::envelope::symmetric::MAX_PLAINTEXT_LEN;
use rizzy_core::export::CXF_FORMAT;
use rizzy_core::ids::ItemId;
use rizzy_core::item::key::FieldKeyRef;
use rizzy_core::item::schema::{
    ATTR_ALG, ATTR_CREDENTIAL_ID, ATTR_PRIVATE_KEY, ATTR_RP_ID, ATTR_USER_HANDLE, ITEM_NAME,
    LIST_PASSKEY, LOGIN_USERNAME, PASSKEY_ALG_EDDSA, PASSKEY_ALG_ES256,
};
use rizzy_core::item::types::ItemType;
use rizzy_core::item::value::ValueRef;
use rizzy_core::passkey::Es256SigningKey;
use rizzy_core::passkey::pkcs8;
use rizzy_core::rng::CryptoRng;
use rizzy_core::secret::SecretBytes;
use rizzy_import::cxf::{PASSKEY_TYPE, VERSION_MAJOR, VERSION_MINOR};
use rizzy_import::limits::{MAX_ENTRIES, MAX_JSON_LEN, MAX_NODES};
use rizzy_import::{Counts, Format, Warning};
use rizzy_sync::record::LiveSnapshot;

use super::gate::PlaintextExportAuth;
use super::plaintext::{PlaintextExportAck, Sink};
use super::{parse_export_json, read_export, state, write_export_as};
use crate::device::UnlockedDevice;
use crate::error::ClientError;
use crate::sync::VaultSync;

/// The `payload_version` of a CXF payload inside `EXPORT_FILE` (ADR 0074 §2).
pub const CXF_PAYLOAD_VERSION: u16 = 2;

/// `exporterDisplayName` of every CXF document we write (ADR 0074 §2; owner answer 5).
pub const CXF_EXPORTER_DISPLAY_NAME: &str = "rizzy-vault";

/// The warning every host shows before it asks for the `EXPORT PLAINTEXT` phrase for a CXF
/// export (ADR 0074 §2 "Warning": its own constant, not ADR 0027 §5's frozen text). Frozen
/// English source; a translation keeps every sentence.
pub const CXF_EXPORT_WARNING: &str = "Once decrypted with its export password, this file holds a standard CXF credential-exchange document: the private key of every passkey in this vault, in a form any compliant password manager can read. It carries only passkeys, not the rest of this vault.";

/// Length of the random CXF account id, in bytes (base64url in the document).
const ACCOUNT_ID_LEN: usize = 16;

/// What [`VaultSync::export_cxf`] wrote. Counts only.
#[derive(Debug)]
pub struct CxfExport {
    /// The file: JSON, its payload sealed. Not a secret on its own (the export password is).
    pub file: Vec<u8>,
    /// Passkey credentials written.
    pub passkeys: usize,
    /// CXF items written (Login items with at least one passkey).
    pub items: usize,
    /// Passkey elements left out because their fields could not make a credential.
    pub skipped: usize,
}

/// What [`VaultSync::import_cxf_encrypted`] did: the vault's part, and the reader's counts and
/// warnings (positions only, INV-48).
#[derive(Debug, Default)]
pub struct CxfImport {
    /// The new items, in file order.
    pub imported: Vec<ItemId>,
    /// File positions of items this vault refused.
    pub skipped: Vec<usize>,
    /// The reader's totals ([`rizzy_import::cxf`] "What is skipped, and counted").
    pub counts: Counts,
    /// The reader's warnings.
    pub warnings: Vec<Warning>,
}

/// One passkey credential to write, its values borrowed from the item's snapshot except the
/// PKCS#8 key, built here.
struct Passkey<'a> {
    /// `rpId`.
    rp_id: &'a str,
    /// `credentialId`.
    credential_id: &'a [u8],
    /// `userHandle`.
    user_handle: &'a [u8],
    /// `key`: the PKCS#8 DER.
    key: SecretBytes,
}

/// One CXF item: a Login with its passkeys.
struct CxfItem<'a> {
    /// The item's id (the CXF item `id`).
    id: ItemId,
    /// `title`: the displayed `item.name`.
    title: &'a str,
    /// The displayed `login.username`: `username` and `userDisplayName` of every credential.
    username: &'a str,
    /// The credentials, in element-id order.
    credentials: Vec<Passkey<'a>>,
}

/// The passkey attributes of one element while they are collected.
#[derive(Default)]
struct Parts<'a> {
    /// `rp_id`.
    rp_id: Option<&'a str>,
    /// `credential_id`.
    credential_id: Option<&'a [u8]>,
    /// `user_handle`.
    user_handle: Option<&'a [u8]>,
    /// `private_key`.
    private_key: Option<&'a [u8]>,
    /// `alg`.
    alg: Option<u16>,
}

/// The stored private value as PKCS#8 for `alg` (ADR 0074 §2, §4); `None` for another `alg` or
/// a value that is not a key of it.
fn pkcs8_key(alg: u16, private_key: &[u8]) -> Option<SecretBytes> {
    match alg {
        PASSKEY_ALG_ES256 => Es256SigningKey::from_bytes(private_key)
            .ok()
            .map(|key| pkcs8::encode_es256(&key)),
        PASSKEY_ALG_EDDSA => pkcs8::encode_eddsa_seed(private_key).ok(),
        _ => None,
    }
}

/// The CXF item of one live item: `None` unless it is an active Login with passkey elements.
/// `skipped` counts elements that made no credential.
fn cxf_item<'a>(id: ItemId, live: &LiveSnapshot<'a>, skipped: &mut usize) -> Option<CxfItem<'a>> {
    if state::trashed(live) != Some(false) || state::item_type(live) != Some(ItemType::LOGIN) {
        return None;
    }
    let mut title = "";
    let mut username = "";
    let mut elements: Vec<(&'a str, Parts<'a>)> = Vec::new();
    for register in state::fields(live) {
        let key: &'a str = register.key().expose_secret();
        let Some(shown) = state::displayed(register) else {
            continue;
        };
        let Ok(value) = ValueRef::decode(shown.value) else {
            continue;
        };
        if key == ITEM_NAME {
            if let ValueRef::Text(text) = value {
                title = text;
            }
            continue;
        }
        if key == LOGIN_USERNAME {
            if let ValueRef::Text(text) = value {
                username = text;
            }
            continue;
        }
        let Ok(parsed) = FieldKeyRef::parse_str(key) else {
            continue;
        };
        let (Some(LIST_PASSKEY), Some(element), Some(attribute)) =
            (parsed.list(), parsed.element(), parsed.attribute())
        else {
            continue;
        };
        // Registers come in key order, so one element's attributes are adjacent.
        if elements.last().is_none_or(|(e, _)| *e != element) {
            elements.push((element, Parts::default()));
        }
        let Some((_, parts)) = elements.last_mut() else {
            continue;
        };
        match (attribute, value) {
            (ATTR_RP_ID, ValueRef::Text(text)) => parts.rp_id = Some(text),
            (ATTR_CREDENTIAL_ID, ValueRef::Bytes(bytes)) => parts.credential_id = Some(bytes),
            (ATTR_USER_HANDLE, ValueRef::Bytes(bytes)) => parts.user_handle = Some(bytes),
            (ATTR_PRIVATE_KEY, ValueRef::Bytes(bytes)) => parts.private_key = Some(bytes),
            (ATTR_ALG, ValueRef::Enum(alg)) => parts.alg = Some(alg),
            _ => {}
        }
    }
    let mut credentials = Vec::new();
    for (_, parts) in elements {
        let credential = (|| {
            let rp_id = parts.rp_id.filter(|r| !r.is_empty())?;
            let credential_id = parts.credential_id.filter(|c| !c.is_empty())?;
            let user_handle = parts.user_handle.filter(|u| !u.is_empty())?;
            let key = pkcs8_key(parts.alg?, parts.private_key?)?;
            Some(Passkey {
                rp_id,
                credential_id,
                user_handle,
                key,
            })
        })();
        match credential {
            Some(credential) => credentials.push(credential),
            None => *skipped = skipped.saturating_add(1),
        }
    }
    if credentials.is_empty() {
        return None;
    }
    Some(CxfItem {
        id,
        title,
        username,
        credentials,
    })
}

impl Sink {
    /// The CXF document (module docs).
    fn cxf_document(&mut self, timestamp_s: u64, account_id: &[u8], items: &[CxfItem<'_>]) {
        // Root object, version object, its two numbers, the accounts array, the account
        // object, its collections and items arrays.
        self.nodes = self.nodes.saturating_add(4);
        self.put(b"{\"version\":{\"major\":");
        self.json_number(VERSION_MAJOR);
        self.put(b",\"minor\":");
        self.json_number(VERSION_MINOR);
        self.put(b"},\"exporterRpId\":");
        self.json_string("");
        self.put(b",\"exporterDisplayName\":");
        self.json_string(CXF_EXPORTER_DISPLAY_NAME);
        self.put(b",\"timestamp\":");
        self.json_number(timestamp_s);
        self.put(b",\"accounts\":[{\"id\":");
        self.nodes = self.nodes.saturating_add(3);
        self.json_base64(account_id);
        self.put(b",\"username\":");
        self.json_string("");
        self.put(b",\"email\":");
        self.json_string("");
        self.put(b",\"collections\":[],\"items\":[");
        for (index, item) in items.iter().enumerate() {
            if index > 0 {
                self.put(b",");
            }
            self.cxf_item(item);
        }
        self.put(b"]}]}");
    }

    /// One CXF item and its credentials.
    fn cxf_item(&mut self, item: &CxfItem<'_>) {
        // The item object and its credentials array.
        self.nodes = self.nodes.saturating_add(2);
        self.put(b"\n{\"id\":");
        self.json_base64(item.id.as_bytes());
        self.put(b",\"title\":");
        self.json_string(item.title);
        self.put(b",\"credentials\":[");
        for (index, credential) in item.credentials.iter().enumerate() {
            if index > 0 {
                self.put(b",");
            }
            self.nodes = self.nodes.saturating_add(1);
            self.put(b"{\"type\":");
            self.json_string(PASSKEY_TYPE);
            self.put(b",\"credentialId\":");
            self.json_base64(credential.credential_id);
            self.put(b",\"rpId\":");
            self.json_string(credential.rp_id);
            self.put(b",\"username\":");
            self.json_string(item.username);
            self.put(b",\"userDisplayName\":");
            self.json_string(item.username);
            self.put(b",\"userHandle\":");
            self.json_base64(credential.user_handle);
            self.put(b",\"key\":");
            self.json_base64(credential.key.expose_secret());
            self.put(b"}");
        }
        self.put(b"]}");
    }
}

/// Encodes a CXF payload: `u16(2) ‖ bytes(cxf_json)`, in one zeroizing buffer of its exact size.
///
/// # Errors
/// [`ClientError::ExportTooLarge`] above the 16 MiB plaintext cap.
pub fn encode_cxf_payload(cxf_json: &[u8]) -> Result<SecretBytes, ClientError> {
    let len = 2usize.saturating_add(4).saturating_add(cxf_json.len());
    if len > MAX_PLAINTEXT_LEN {
        return Err(ClientError::ExportTooLarge);
    }
    let mut out = Vec::with_capacity(len);
    put_u16(&mut out, CXF_PAYLOAD_VERSION);
    put_bytes(&mut out, cxf_json).map_err(|_| ClientError::ExportTooLarge)?;
    Ok(SecretBytes::from_vec(out))
}

/// Reads a CXF payload and returns the CXF document in it, borrowed.
///
/// # Errors
/// [`ClientError::InvalidExportFile`] for a payload of another version (an item-list payload
/// under a CXF tag included: ADR 0074 §2, the dispatch check), a document over
/// [`MAX_JSON_LEN`], or trailing bytes.
pub fn parse_cxf_payload(payload: &[u8]) -> Result<&[u8], ClientError> {
    const BAD: ClientError = ClientError::InvalidExportFile;
    let mut reader = Reader::new(payload);
    if reader.u16().map_err(|_| BAD)? != CXF_PAYLOAD_VERSION {
        return Err(BAD);
    }
    let json = reader.bytes_max(MAX_JSON_LEN).map_err(|_| BAD)?;
    reader.finish().map_err(|_| BAD)?;
    Ok(json)
}

impl VaultSync {
    /// The number of passkey credentials a CXF export of this vault would hold now, for the
    /// host's dialog. Writes nothing and needs no gate (it reveals a count only).
    ///
    /// # Errors
    /// [`ClientError::ExportOversizeItems`]; [`ClientError::Internal`].
    pub fn cxf_export_passkeys(&self) -> Result<usize, ClientError> {
        let mut skipped = 0;
        Ok(self
            .exported_states()?
            .iter()
            .filter_map(|(id, live)| cxf_item(*id, live, &mut skipped))
            .map(|item| item.credentials.len())
            .sum())
    }

    /// Writes a CXF passkey export of this vault under `export_password` (module docs): the
    /// CXF document, its payload, then one Argon2id run and the `EXPORT_FILE` envelope. Every
    /// refusal of the document comes before the key derivation. Consumes the permission of
    /// [`ExportGate::authorize_plaintext`](super::gate::ExportGate::authorize_plaintext) and the
    /// typed acknowledgement, whatever the outcome (ADR 0074 §2 "Gate").
    ///
    /// # Errors
    /// [`ClientError::ExportOversizeItems`]; [`ClientError::ExportTooLarge`] for a document
    /// above a cap its reader applies or a payload over 16 MiB; [`ClientError::InvalidInput`]
    /// for an empty export password or one with an unassigned code point;
    /// [`ClientError::Internal`].
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the permission and the acknowledgement are consumed by the one export they allow (ADR 0074 §2)"
    )]
    pub fn export_cxf<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        auth: PlaintextExportAuth,
        ack: PlaintextExportAck,
        export_password: &str,
        now_ms: u64,
    ) -> Result<CxfExport, ClientError> {
        let PlaintextExportAck(()) = ack;
        auth.spend();
        let (document, mut export) = self.cxf_document(rng, now_ms)?;
        let payload = encode_cxf_payload(document.expose_secret())?;
        export.file = write_export_as(
            CXF_FORMAT,
            rng,
            export_password,
            payload.expose_secret(),
            now_ms,
        )?;
        Ok(export)
    }

    /// The CXF document of this vault (module docs), in one zeroizing buffer, and the counts of
    /// what it holds (with an empty [`CxfExport::file`]). Private to the crate: it is the
    /// plaintext of [`VaultSync::export_cxf`], which reaches a host only sealed.
    ///
    /// # Errors
    /// As [`VaultSync::export_cxf`], but for the export password.
    pub(crate) fn cxf_document<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        now_ms: u64,
    ) -> Result<(SecretBytes, CxfExport), ClientError> {
        let states = self.exported_states()?;
        let mut skipped = 0;
        let items: Vec<CxfItem<'_>> = states
            .iter()
            .filter_map(|(id, live)| cxf_item(*id, live, &mut skipped))
            .collect();
        if items.len() > MAX_ENTRIES || items.iter().any(|i| i.credentials.len() > MAX_ENTRIES) {
            return Err(ClientError::ExportTooLarge);
        }
        let mut account_id = [0u8; ACCOUNT_ID_LEN];
        rng.fill_bytes(&mut account_id);
        let timestamp_s = now_ms / 1000;
        let mut measure = Sink::measuring();
        measure.cxf_document(timestamp_s, &account_id, &items);
        if measure.len > MAX_JSON_LEN || measure.nodes > MAX_NODES {
            return Err(ClientError::ExportTooLarge);
        }
        let mut sink = Sink::writing(measure.len);
        sink.cxf_document(timestamp_s, &account_id, &items);
        let document = sink.finish(measure.len)?;
        Ok((
            document,
            CxfExport {
                file: Vec::new(),
                passkeys: items.iter().map(|i| i.credentials.len()).sum(),
                items: items.len(),
                skipped,
            },
        ))
    }

    /// Imports our own CXF export file (module docs) with its export password: the tag must be
    /// [`CXF_FORMAT`]; [`read_export`] (the size cap, the strict JSON, the header checks, one
    /// Argon2id run, the envelope); the payload version must be 2; then the same CXF reader a
    /// bare CXF file goes through ([`rizzy_import::cxf`], ADR 0074 §3 "Our own export") and
    /// [`VaultSync::import_items`]. The decrypted payload stays in its zeroizing buffer.
    ///
    /// # Errors
    /// [`ClientError::ReadOnly`] or [`ClientError::InvalidInput`] before the key derivation;
    /// as [`read_export`]; [`ClientError::InvalidExportFile`] for another tag, another payload
    /// version, or a CXF document the reader refuses as a whole (`ExportUpdateRequired` for
    /// another CXF major version); [`ClientError::Internal`], after which the items written so
    /// far stay.
    pub fn import_cxf_encrypted<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        unlocked: &UnlockedDevice,
        file: &[u8],
        export_password: &str,
        now_ms: u64,
    ) -> Result<CxfImport, ClientError> {
        self.check_writable(unlocked)?;
        if parse_export_json(file)?.format != CXF_FORMAT {
            return Err(ClientError::InvalidExportFile);
        }
        let payload = read_export(file, export_password)?;
        let json = parse_cxf_payload(payload.expose_secret())?;
        let parsed = rizzy_import::import(Format::CxfJson, json, rng).map_err(|e| match e {
            rizzy_import::ImportError::UpdateRequired => ClientError::ExportUpdateRequired,
            _ => ClientError::InvalidExportFile,
        })?;
        let done = self.import_items(rng, unlocked, &parsed.items, now_ms)?;
        Ok(CxfImport {
            imported: done.imported,
            skipped: done.skipped,
            counts: parsed.counts,
            warnings: parsed.warnings,
        })
    }
}

#[cfg(test)]
mod tests;
