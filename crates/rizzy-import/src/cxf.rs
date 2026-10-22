// SPDX-License-Identifier: AGPL-3.0-only

//! The FIDO Alliance Credential Exchange Format (CXF) 1.0, passkeys only ([ADR 0074] §1, §3;
//! roadmap §4.10, M8).
//!
//! [ADR 0074]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0074-passkey-cxf-import-export.md
//!
//! **Source.** *Credential Exchange Format*, Proposed Standard with errata,
//! `cxf-v1.0-ps-errata-20260309` (FIDO Alliance; read 2026-10-22): the `Header`, `Account`,
//! `Item` and `Passkey` dictionaries of its §3 and its Appendix A example. CXP, the live
//! device-to-device transfer, is out of scope (ADR 0074 §1, owner answer 1).
//!
//! **Two ways in, one reader** (ADR 0074 §3). A bare CXF JSON document another product wrote
//! (detected by its `accounts` array and integer `version.major`), and the decrypted payload of
//! our own `rizzy-vault-cxf-export` file, which `rizzy-client` opens with its export password and
//! hands here. Both are untrusted (threat model A16).
//!
//! # Document
//!
//! | CXF | Read as |
//! |---|---|
//! | `version.major` | must be 1; another major is [`ImportError::UpdateRequired`]. `minor` is not read (CXF's minor versions are additive) |
//! | `timestamp` (Unix seconds) | required; × 1000 is every imported passkey's `created_ms` |
//! | `exporterRpId`, `exporterDisplayName` | not read |
//! | `accounts[]` → `items[]` → `credentials[]` | each array at most [`MAX_ENTRIES`]; larger is [`ImportError::TooMany`]. Their product is bounded by [`MAX_NODES`] (every element is a JSON node) |
//! | `collections`, `tags`, `scope`, `extensions`, an item's `title` and times | not imported |
//!
//! # Mapping (ADR 0074 §3 "Writes")
//!
//! **One new Login item per imported passkey credential**, with ADR 0039 §1's `passkey/<id>/…`
//! fields:
//!
//! | CXF `Passkey` | rizzy-vault |
//! |---|---|
//! | `rpId` | `passkey/<id>/rp_id` |
//! | `userHandle` (base64url, 1–64 bytes) | `passkey/<id>/user_handle` |
//! | `credentialId` (base64url, 1–1024 bytes) | `passkey/<id>/credential_id` |
//! | `key` (base64url PKCS#8, at most [`MAX_PKCS8_LEN`] bytes) | `passkey/<id>/private_key`: the 32-byte scalar or seed ([`pkcs8`]), concealed |
//! | — | `passkey/<id>/public_key_cose`: **derived** from the private key, never read (CXF carries none), COSE-encoded as ADR 0039 §4 does for a created credential |
//! | the PKCS#8 algorithm identifier | `passkey/<id>/alg`: 1 (ES256) or 2 (`EdDSA`) |
//! | — | `passkey/<id>/discoverable` = true (CXF passkeys are resident by definition) |
//! | `Header.timestamp` × 1000 | `passkey/<id>/created_ms` |
//! | `userDisplayName`, else `username`, else `rpId` | `item.name` |
//! | `username`, else `userDisplayName` | `login.username` |
//! | `fido2Extensions` | not imported (no field holds it): counted in [`Counts::dropped_fields`] and warned [`WarningKind::FieldSkipped`] |
//!
//! # What is skipped, and counted
//!
//! The import report names positions only (INV-48): a warning's entry is the CXF item's
//! position counted across all accounts, in file order. Nothing fails the whole file but the
//! document's own shape (`version`, `timestamp`, `accounts`, an account's `items`) and the caps.
//!
//! - A credential of any other `type` (`basic-auth`, `note`, `totp`, …): not imported
//!   (ADR 0074 §1), [`Counts::skipped_credentials`], warning
//!   [`WarningKind::CredentialTypeSkipped`].
//! - A passkey credential whose `key` names another algorithm or curve: skipped (ADR 0074 §3,
//!   "unknown OID: skip the credential, count it"), [`Counts::skipped_credentials`], warning
//!   [`WarningKind::UnsupportedKeyAlgorithm`].
//! - A passkey credential with a missing, mistyped, malformed or oversize member: skipped
//!   ("per-credential failures skip the credential, never the file"),
//!   [`Counts::skipped_credentials`], warning [`WarningKind::MalformedEntry`] or
//!   [`WarningKind::OversizeEntry`].
//! - A CXF item that yields no Login item (no passkey credential, or none that could be read),
//!   or that is not an object with a `credentials` array: [`Counts::skipped_items`] (ADR 0074 §1,
//!   "skipped and counted").
//!
//! # Secrets
//!
//! The decoded private key goes from a zeroizing buffer through [`pkcs8::parse`] (a
//! [`SecretArray`]) into a zeroizing [`Value`]; it is never logged, and no warning or error
//! carries a byte of it or of any other member.
//!
//! [`SecretArray`]: rizzy_core::secret::SecretArray

use rizzy_core::encoding::{b64url_decode_into, b64url_decoded_len};
use rizzy_core::item::schema::{
    ITEM_NAME, LOGIN_USERNAME, PASSKEY_ALG_EDDSA, PASSKEY_ALG_ES256, PASSKEY_CREDENTIAL_ID_MAX_LEN,
    PASSKEY_USER_HANDLE_MAX_LEN,
};
use rizzy_core::item::types::SupportedType;
use rizzy_core::item::value::Value;
use rizzy_core::passkey::pkcs8::{self, MAX_PKCS8_LEN, Pkcs8Algorithm, Pkcs8Error};
use rizzy_core::passkey::{EdDsaSigningKey, Es256SigningKey};
use rizzy_core::rng::CryptoRng;
use zeroize::Zeroizing;

use crate::Counts;
use crate::error::{ImportError, WarningKind, Warnings};
use crate::item::{ImportedItem, ItemBuilder, PendingPasskey};
use crate::json::{self, Json};
#[cfg(doc)]
use crate::limits::MAX_NODES;
use crate::limits::{MAX_ENTRIES, MAX_JSON_LEN};
use crate::text;

/// The CXF major version this reader knows.
pub const VERSION_MAJOR: u64 = 1;

/// The CXF minor version our writer emits (`rizzy-client`'s CXF export).
pub const VERSION_MINOR: u64 = 0;

/// The credential `type` of a passkey.
pub const PASSKEY_TYPE: &str = "passkey";

/// The longest `rpId` accepted, in bytes: a DNS name's longest text form (RFC 1035 §2.3.4;
/// `WebAuthn`'s RP ID is a domain). Longer is a malformed credential.
pub const MAX_RP_ID_LEN: usize = 253;

/// A JSON number written as plain digits (CDDL `uint`); unlike [`Json::as_u64`], not a string of
/// digits.
fn uint(value: &Json) -> Option<u64> {
    match value {
        Json::Number(digits) => text::parse_u64(digits),
        _ => None,
    }
}

/// Whether `doc` looks like a CXF document: a JSON object with an `accounts` array and an
/// integer `version.major` (ADR 0074 §3, "Bare file"). Only picks the reader; the reader still
/// checks the whole document.
#[must_use]
pub fn looks_like_cxf(doc: &Json) -> bool {
    doc.get("accounts").and_then(Json::as_array).is_some()
        && doc
            .get("version")
            .and_then(|v| v.get("major"))
            .and_then(uint)
            .is_some()
}

/// Imports a CXF document (module docs).
pub(crate) fn import<R: CryptoRng + ?Sized>(
    input: &[u8],
    rng: &mut R,
    warnings: &mut Warnings,
    counts: &mut Counts,
) -> Result<Vec<ImportedItem>, ImportError> {
    let doc = json::parse(input, MAX_JSON_LEN)?;
    if doc.members().is_none() {
        return Err(ImportError::UnexpectedShape);
    }
    let major = doc
        .get("version")
        .and_then(|v| v.get("major"))
        .and_then(uint)
        .ok_or(ImportError::UnexpectedShape)?;
    if major != VERSION_MAJOR {
        return Err(ImportError::UpdateRequired);
    }
    let created_ms = doc
        .get("timestamp")
        .and_then(uint)
        .and_then(|s| s.checked_mul(1000))
        .ok_or(ImportError::UnexpectedShape)?;
    let accounts = doc
        .get("accounts")
        .and_then(Json::as_array)
        .ok_or(ImportError::UnexpectedShape)?;
    if accounts.len() > MAX_ENTRIES {
        return Err(ImportError::TooMany);
    }
    // Check every cap before importing anything.
    let mut all_items = Vec::new();
    for account in accounts {
        let items = account
            .get("items")
            .and_then(Json::as_array)
            .ok_or(ImportError::UnexpectedShape)?;
        if items.len() > MAX_ENTRIES {
            return Err(ImportError::TooMany);
        }
        for item in items {
            let credentials = item.get("credentials").and_then(Json::as_array);
            if credentials.is_some_and(|c| c.len() > MAX_ENTRIES) {
                return Err(ImportError::TooMany);
            }
            all_items.push((item, credentials));
        }
    }
    let mut out = Vec::new();
    for (entry, (item, credentials)) in all_items.into_iter().enumerate() {
        let before = out.len();
        match credentials {
            Some(credentials) if item.members().is_some() => {
                for credential in credentials {
                    if let Some(imported) =
                        credential_item(entry, credential, created_ms, rng, warnings, counts)
                    {
                        out.push(imported);
                    }
                }
            }
            _ => warnings.push(Some(entry), WarningKind::MalformedEntry),
        }
        if out.len() == before {
            counts.skipped_items = counts.skipped_items.saturating_add(1);
        }
    }
    Ok(out)
}

/// Turns one credential into a Login item, or skips it with a warning and a count.
fn credential_item<R: CryptoRng + ?Sized>(
    entry: usize,
    credential: &Json,
    created_ms: u64,
    rng: &mut R,
    warnings: &mut Warnings,
    counts: &mut Counts,
) -> Option<ImportedItem> {
    let mut skip = |warnings: &mut Warnings, kind| {
        warnings.push(Some(entry), kind);
        counts.skipped_credentials = counts.skipped_credentials.saturating_add(1);
        None
    };
    match credential.get("type").and_then(Json::as_str) {
        Some(PASSKEY_TYPE) => {}
        Some(_) => return skip(warnings, WarningKind::CredentialTypeSkipped),
        None => return skip(warnings, WarningKind::MalformedEntry),
    }
    let passkey = match read_passkey(credential, created_ms) {
        Ok(passkey) => passkey,
        Err(kind) => return skip(warnings, kind),
    };
    let username = credential
        .get("username")
        .and_then(Json::as_str)
        .unwrap_or_default();
    let display_name = credential
        .get("userDisplayName")
        .and_then(Json::as_str)
        .unwrap_or_default();
    let rp_id = credential
        .get("rpId")
        .and_then(Json::as_str)
        .unwrap_or_default();
    let extensions = credential.get("fido2Extensions").is_some();
    let mut b = ItemBuilder::new(entry, SupportedType::Login, warnings);
    let name = [display_name, username, rp_id]
        .into_iter()
        .find(|t| !t.trim().is_empty())
        .unwrap_or_default();
    b.set(ITEM_NAME, name);
    b.set(
        LOGIN_USERNAME,
        if username.is_empty() {
            display_name
        } else {
            username
        },
    );
    b.add_passkey(passkey);
    if extensions {
        b.warn(WarningKind::FieldSkipped);
    }
    let imported = b.finish(rng);
    match &imported {
        Some(_) if extensions => {
            counts.dropped_fields = counts.dropped_fields.saturating_add(1);
        }
        Some(_) => {}
        None => counts.skipped_credentials = counts.skipped_credentials.saturating_add(1),
    }
    imported
}

/// Reads and checks a passkey credential's members, deriving its public key (module docs).
fn read_passkey(credential: &Json, created_ms: u64) -> Result<PendingPasskey, WarningKind> {
    let rp_id = credential
        .get("rpId")
        .and_then(Json::as_str)
        .ok_or(WarningKind::MalformedEntry)?;
    if rp_id.is_empty() || rp_id.chars().any(char::is_control) {
        return Err(WarningKind::MalformedEntry);
    }
    if rp_id.len() > MAX_RP_ID_LEN {
        return Err(WarningKind::OversizeEntry);
    }
    let credential_id = decode(
        credential.get("credentialId"),
        PASSKEY_CREDENTIAL_ID_MAX_LEN,
    )?;
    let user_handle = decode(credential.get("userHandle"), PASSKEY_USER_HANDLE_MAX_LEN)?;
    let der = decode(credential.get("key"), MAX_PKCS8_LEN)?;
    let key = pkcs8::parse(&der).map_err(|e| match e {
        Pkcs8Error::UnsupportedAlgorithm => WarningKind::UnsupportedKeyAlgorithm,
        _ => WarningKind::MalformedEntry,
    })?;
    let secret = key.secret().expose_secret();
    let (alg, public_key_cose) = match key.algorithm() {
        Pkcs8Algorithm::Es256 => {
            let public = Es256SigningKey::from_bytes(secret)
                .map_err(|_| WarningKind::MalformedEntry)?
                .verifying_key();
            (PASSKEY_ALG_ES256, cose_key_es256(&public.x(), &public.y()))
        }
        Pkcs8Algorithm::EdDsa => {
            let public = EdDsaSigningKey::from_seed(secret)
                .map_err(|_| WarningKind::MalformedEntry)?
                .verifying_key();
            (PASSKEY_ALG_EDDSA, cose_key_ed25519(&public.to_bytes()))
        }
    };
    let bytes = |b: &[u8]| Value::bytes(b).map_err(|_| WarningKind::MalformedEntry);
    Ok(PendingPasskey {
        rp_id: Value::text(rp_id).map_err(|_| WarningKind::MalformedEntry)?,
        user_handle: bytes(&user_handle)?,
        credential_id: bytes(&credential_id)?,
        private_key: bytes(secret)?,
        public_key_cose: bytes(&public_key_cose)?,
        alg,
        created_ms,
    })
}

/// Decodes a base64url member of 1 to `max` decoded bytes into a zeroizing buffer of its exact
/// size. The size is checked on the string's length before anything is decoded, as
/// [`crate::rizzy_json`] does for its typed values. Strict RFC 4648 §5 base64url, unpadded.
fn decode(value: Option<&Json>, max: usize) -> Result<Zeroizing<Vec<u8>>, WarningKind> {
    let encoded = value
        .and_then(Json::as_str)
        .ok_or(WarningKind::MalformedEntry)?;
    let len = b64url_decoded_len(encoded.len()).ok_or(WarningKind::MalformedEntry)?;
    if len > max {
        return Err(WarningKind::OversizeEntry);
    }
    if len == 0 {
        return Err(WarningKind::MalformedEntry);
    }
    let mut out = Zeroizing::new(vec![0u8; len]);
    let decoded = b64url_decode_into(encoded, &mut out)
        .map_err(|_| WarningKind::MalformedEntry)?
        .len();
    if decoded == len {
        Ok(out)
    } else {
        Err(WarningKind::MalformedEntry)
    }
}

/// The COSE `EC2` key map of an ES256 public key (RFC 9053 §7.1.1), byte for byte the map
/// ADR 0039 §4 writes for a created credential (`rizzy-client`'s `passkey::cbor`; a test there
/// checks the two agree): `{1: 2, 3: -7, -1: 1, -2: x, -3: y}`, 77 bytes.
#[must_use]
pub fn cose_key_es256(x: &[u8; 32], y: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(77);
    out.extend_from_slice(&[0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]);
    out.extend_from_slice(x);
    out.extend_from_slice(&[0x22, 0x58, 0x20]);
    out.extend_from_slice(y);
    out
}

/// The COSE `OKP` key map of an Ed25519 public key (RFC 9053 §7.2, ADR 0039 §4's "COSE `OKP`
/// key map for `EdDSA`"): `{1: 1, 3: -8, -1: 6, -2: x}`, 42 bytes.
#[must_use]
pub fn cose_key_ed25519(x: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(42);
    out.extend_from_slice(&[0xA4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20]);
    out.extend_from_slice(x);
    out
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code indexes fixtures at known offsets; a panic there fails the test, which CLAUDE.md allows"
)]
mod tests;
