//! Bitwarden's unencrypted JSON export (ADR 0002 point 2; M1 imports the unencrypted export
//! only, ADR 0002 owner decision 1).
//!
//! **Document.** An object with `items` (required), and `folders` and `collections` (each
//! `{id, name}`, optional). `"encrypted": true` or `"passwordProtected": true` is an encrypted
//! export and is refused ([`ImportError::EncryptedExport`]): it would need Bitwarden's
//! cryptography, which M1 does not have.
//!
//! **Item mapping.**
//!
//! | Bitwarden | rizzy-vault |
//! |---|---|
//! | `type` 1 / 2 / 3 / 4 | Login / Secure Note / Card / Identity |
//! | `type` 5 (SSH key) and unknown types | Secure Note with a warning; `sshKey.privateKey` as a hidden custom field, `publicKey` and `keyFingerprint` as text ones |
//! | `name`, `notes`, `favorite` | `item.name`, `item.notes`, `item.favorite` |
//! | `creationDate` | `import.created_ms` |
//! | `folderId`, `collectionIds` | tags named after the folder and collections |
//! | `login.username`, `.password`, `.totp` | `login.username`, `.password`, `.totp` |
//! | `login.uris[].uri` | `uri/<id>/value` (the `match` setting is not imported: M1 never writes `match`, owner decision 2) |
//! | `login.fido2Credentials` | not imported (passkeys are M7), warning |
//! | `passwordHistory[]` (`password`, `lastUsedDate`) | `pwhist/<id>/value`, `/ms` |
//! | `card.cardholderName`, `.brand`, `.number`, `.expMonth`, `.expYear`, `.code` | `card.holder`, `.brand`, `.number`, `.exp_month`, `.exp_year`, `.code` |
//! | `identity.*` (18 fields) | `identity.*`; `licenseNumber` is `drivers_license` |
//! | `fields[]`: type 0 text, 1 hidden, 2 boolean | custom fields of kind text, hidden, boolean |
//! | `fields[]`: type 3 linked | not imported (it has no value of its own), warning |
//! | `attachments` | not imported (M3), warning |
//! | `deletedDate` set | entry skipped, warning |
//!
//! A custom field of an unknown type is imported as hidden: the concealed reading cannot
//! expose a secret. Members this table does not name (`id`, `revisionDate`, `reprompt`, …) are
//! metadata, not item content, and are not imported.

use std::collections::BTreeMap;

use rizzy_core::item::schema::{
    CARD_BRAND, CARD_CODE, CARD_EXP_MONTH, CARD_EXP_YEAR, CARD_HOLDER, CARD_NUMBER,
    IDENTITY_ADDRESS1, IDENTITY_ADDRESS2, IDENTITY_ADDRESS3, IDENTITY_CITY, IDENTITY_COMPANY,
    IDENTITY_COUNTRY, IDENTITY_DRIVERS_LICENSE, IDENTITY_EMAIL, IDENTITY_FIRST_NAME,
    IDENTITY_LAST_NAME, IDENTITY_MIDDLE_NAME, IDENTITY_PASSPORT_NUMBER, IDENTITY_PHONE,
    IDENTITY_POSTAL_CODE, IDENTITY_SSN, IDENTITY_STATE, IDENTITY_TITLE, IDENTITY_USERNAME,
    ITEM_NAME, ITEM_NOTES, LOGIN_PASSWORD, LOGIN_TOTP, LOGIN_USERNAME,
};
use rizzy_core::item::types::SupportedType;
use rizzy_core::rng::CryptoRng;

use crate::error::{ImportError, WarningKind, Warnings};
use crate::item::{FieldKind, ImportedItem, ItemBuilder};
use crate::json::{self, Json};
use crate::limits::{MAX_ENTRIES, MAX_JSON_LEN};
use crate::text::is_truthy;
use crate::time;

/// Bitwarden card members and their keys.
const CARD_MAP: [(&str, &str); 6] = [
    ("cardholderName", CARD_HOLDER),
    ("brand", CARD_BRAND),
    ("number", CARD_NUMBER),
    ("expMonth", CARD_EXP_MONTH),
    ("expYear", CARD_EXP_YEAR),
    ("code", CARD_CODE),
];

/// Bitwarden identity members and their keys.
const IDENTITY_MAP: [(&str, &str); 18] = [
    ("title", IDENTITY_TITLE),
    ("firstName", IDENTITY_FIRST_NAME),
    ("middleName", IDENTITY_MIDDLE_NAME),
    ("lastName", IDENTITY_LAST_NAME),
    ("address1", IDENTITY_ADDRESS1),
    ("address2", IDENTITY_ADDRESS2),
    ("address3", IDENTITY_ADDRESS3),
    ("city", IDENTITY_CITY),
    ("state", IDENTITY_STATE),
    ("postalCode", IDENTITY_POSTAL_CODE),
    ("country", IDENTITY_COUNTRY),
    ("company", IDENTITY_COMPANY),
    ("email", IDENTITY_EMAIL),
    ("phone", IDENTITY_PHONE),
    ("ssn", IDENTITY_SSN),
    ("username", IDENTITY_USERNAME),
    ("passportNumber", IDENTITY_PASSPORT_NUMBER),
    ("licenseNumber", IDENTITY_DRIVERS_LICENSE),
];

/// The text of member `name` of `obj`, or `""`.
fn text<'a>(obj: Option<&'a Json>, name: &str) -> &'a str {
    obj.and_then(|o| o.get(name))
        .and_then(Json::as_text)
        .unwrap_or_default()
}

/// A map from `id` to `name` of the `{id, name}` objects in `list`.
fn names(list: Option<&Json>) -> BTreeMap<&str, &str> {
    list.and_then(Json::as_array)
        .unwrap_or_default()
        .iter()
        .filter_map(|f| Some((f.get("id")?.as_str()?, f.get("name")?.as_str()?)))
        .collect()
}

/// Imports a Bitwarden JSON export.
pub(crate) fn import<R: CryptoRng + ?Sized>(
    input: &[u8],
    rng: &mut R,
    warnings: &mut Warnings,
) -> Result<Vec<ImportedItem>, ImportError> {
    let doc = json::parse(input, MAX_JSON_LEN)?;
    if doc.members().is_none() {
        return Err(ImportError::UnexpectedShape);
    }
    if doc.get("encrypted").and_then(Json::as_bool) == Some(true)
        || doc.get("passwordProtected").and_then(Json::as_bool) == Some(true)
    {
        return Err(ImportError::EncryptedExport);
    }
    let items = doc
        .get("items")
        .and_then(Json::as_array)
        .ok_or(ImportError::UnexpectedShape)?;
    if items.len() > MAX_ENTRIES {
        return Err(ImportError::TooMany);
    }
    let folders = names(doc.get("folders"));
    let collections = names(doc.get("collections"));
    let mut out = Vec::new();
    for (entry, item) in items.iter().enumerate() {
        if let Some(imported) = map_item(entry, item, &folders, &collections, rng, warnings) {
            out.push(imported);
        }
    }
    Ok(out)
}

/// Maps one item, or skips it with a warning.
fn map_item<R: CryptoRng + ?Sized>(
    entry: usize,
    item: &Json,
    folders: &BTreeMap<&str, &str>,
    collections: &BTreeMap<&str, &str>,
    rng: &mut R,
    warnings: &mut Warnings,
) -> Option<ImportedItem> {
    if item.members().is_none() {
        warnings.push(Some(entry), WarningKind::MalformedEntry);
        return None;
    }
    if item.get("deletedDate").and_then(Json::as_str).is_some() {
        warnings.push(Some(entry), WarningKind::DeletedEntrySkipped);
        return None;
    }
    let item_type = item.get("type").and_then(Json::as_u64);
    let kind = match item_type {
        Some(1) => SupportedType::Login,
        Some(3) => SupportedType::Card,
        Some(4) => SupportedType::Identity,
        _ => SupportedType::SecureNote,
    };
    let mut b = ItemBuilder::new(entry, kind, warnings);
    if !matches!(item_type, Some(1..=4)) {
        b.warn(WarningKind::ConvertedToSecureNote);
    }
    b.set(ITEM_NAME, text(Some(item), "name"));
    b.set(ITEM_NOTES, text(Some(item), "notes"));
    b.set_favorite(item.get("favorite").and_then(Json::as_bool) == Some(true));
    if let Some(created) = item.get("creationDate").and_then(Json::as_str) {
        b.set_created_ms(time::rfc3339_ms(created));
    }
    if let Some(folder) = item
        .get("folderId")
        .and_then(Json::as_str)
        .and_then(|id| folders.get(id))
    {
        b.add_tag(folder);
    }
    for id in item
        .get("collectionIds")
        .and_then(Json::as_array)
        .unwrap_or_default()
    {
        if let Some(name) = id.as_str().and_then(|id| collections.get(id)) {
            b.add_tag(name);
        }
    }
    type_fields(&mut b, item_type, item);
    for field in item
        .get("fields")
        .and_then(Json::as_array)
        .unwrap_or_default()
    {
        custom_field(&mut b, field);
    }
    for entry in item
        .get("passwordHistory")
        .and_then(Json::as_array)
        .unwrap_or_default()
    {
        let ms = match entry.get("lastUsedDate").and_then(Json::as_str) {
            Some(date) => {
                let ms = time::rfc3339_ms(date);
                if ms.is_none() {
                    b.warn(WarningKind::InvalidTimestamp);
                }
                ms
            }
            None => None,
        };
        b.add_history(text(Some(entry), "password"), ms);
    }
    if item
        .get("attachments")
        .and_then(Json::as_array)
        .is_some_and(|a| !a.is_empty())
    {
        b.warn(WarningKind::AttachmentSkipped);
    }
    b.finish(rng)
}

/// The members of the type-specific object: `login`, `card`, `identity` or `sshKey`.
fn type_fields(b: &mut ItemBuilder<'_>, item_type: Option<u64>, item: &Json) {
    match item_type {
        Some(1) => login(b, item.get("login")),
        Some(3) => {
            let card = item.get("card");
            for (member, key) in CARD_MAP {
                b.set_or_field(
                    key,
                    member,
                    text(card, member),
                    key == CARD_NUMBER || key == CARD_CODE,
                );
            }
        }
        Some(4) => {
            let identity = item.get("identity");
            for (member, key) in IDENTITY_MAP {
                let hidden = key == IDENTITY_SSN || key == IDENTITY_PASSPORT_NUMBER;
                b.set_or_field(key, member, text(identity, member), hidden);
            }
        }
        Some(5) => {
            let ssh = item.get("sshKey");
            b.add_field("privateKey", FieldKind::Hidden, text(ssh, "privateKey"));
            b.add_field("publicKey", FieldKind::Text, text(ssh, "publicKey"));
            b.add_field(
                "keyFingerprint",
                FieldKind::Text,
                text(ssh, "keyFingerprint"),
            );
        }
        _ => {}
    }
}

/// The `login` object of a Login item.
fn login(b: &mut ItemBuilder<'_>, login: Option<&Json>) {
    b.set(LOGIN_USERNAME, text(login, "username"));
    b.set(LOGIN_PASSWORD, text(login, "password"));
    b.set(LOGIN_TOTP, text(login, "totp"));
    for uri in login
        .and_then(|l| l.get("uris"))
        .and_then(Json::as_array)
        .unwrap_or_default()
    {
        b.add_uri(text(Some(uri), "uri"));
    }
    if login
        .and_then(|l| l.get("fido2Credentials"))
        .and_then(Json::as_array)
        .is_some_and(|a| !a.is_empty())
    {
        b.warn(WarningKind::PasskeySkipped);
    }
}

/// One entry of `fields`.
fn custom_field(b: &mut ItemBuilder<'_>, field: &Json) {
    let label = text(Some(field), "name");
    let value = text(Some(field), "value");
    match field.get("type").and_then(Json::as_u64) {
        Some(0) => b.add_field(label, FieldKind::Text, value),
        Some(2) => b.add_bool_field(label, is_truthy(value)),
        Some(3) => b.warn(WarningKind::FieldSkipped),
        // Type 1 is hidden; an unknown type is read as hidden too.
        _ => b.add_field(label, FieldKind::Hidden, value),
    }
}
