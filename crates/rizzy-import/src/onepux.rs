//! 1Password's 1PUX export (ADR 0002 point 2): a zip archive whose `export.data` member is a
//! JSON document. Only that member is read ([`crate::zip`]); attached files under `files/` are
//! never decompressed.
//!
//! **Document.** `accounts[].vaults[].items[]`. An item is the array element itself, or its
//! `item` member (an older layout). Entry positions count items across all accounts and
//! vaults, in file order.
//!
//! **Item mapping.**
//!
//! | 1PUX | rizzy-vault |
//! |---|---|
//! | `categoryUuid` `001` Login, `005` Password | Login |
//! | `002` Credit Card / `003` Secure Note / `004` Identity | Card / Secure Note / Identity |
//! | `006` Document | Secure Note; the file is not imported (M3), warning |
//! | any other category | Secure Note, warning; its fields become custom fields |
//! | `overview.title`, `details.notesPlain` | `item.name`, `item.notes` |
//! | `favIndex` > 0 | `item.favorite` |
//! | `createdAt` (Unix seconds) | `import.created_ms` |
//! | `overview.tags[]` | tags |
//! | `overview.url`, `overview.urls[].url` | URIs (a non-login keeps them as text custom fields) |
//! | `details.loginFields[]` with `designation` `username` / `password` | `login.username` / `login.password` |
//! | other `loginFields[]` | custom fields, hidden when `fieldType` is `P` |
//! | `details.password` (category `005`) | `login.password`; on a type with no password, or one already set, a hidden custom field `password` |
//! | `details.passwordHistory[]` (`value`, `time`) | `pwhist/<id>/value`, `/ms` (logins only) |
//! | section fields, by `id`, on a Credit Card: `cardholder`, `type`, `ccnum`, `cvv`, `pin`, `expiry` | `card.holder`, `.brand`, `.number`, `.code`, `.pin`, `.exp_month` and `.exp_year` |
//! | section fields, by `id`, on an Identity: `firstname`, `initial`, `lastname`, `company`, `email`, `defphone`, `username`, `address` | `identity.first_name`, `.middle_name`, `.last_name`, `.company`, `.email`, `.phone`, `.username`, and `.address1`, `.city`, `.state`, `.postal_code`, `.country` |
//! | the first `totp` section field of a Login | `login.totp` |
//! | every other section field | a custom field named after its `title` (else its `id`); hidden for `concealed`, `creditCardNumber`, `totp` and SSH private keys |
//! | `file` and `documentAttributes` | not imported (M3), warning |
//! | `reference` and value kinds this table does not name | not imported, warning (a plain string or number of an unknown kind is kept as a text field) |
//! | a section field with no `value` object, or a value not in its kind's shape | not imported, warning |
//! | `state` `trashed` | entry skipped, warning |
//!
//! Value formats: `date` (Unix seconds) is written `YYYY-MM-DD`, `monthYear` (`YYYYMM`) is
//! written `YYYY-MM`, and an `address` object is joined with `, `.

use rizzy_core::item::schema::{
    CARD_BRAND, CARD_CODE, CARD_EXP_MONTH, CARD_EXP_YEAR, CARD_HOLDER, CARD_NUMBER, CARD_PIN,
    IDENTITY_ADDRESS1, IDENTITY_CITY, IDENTITY_COMPANY, IDENTITY_COUNTRY, IDENTITY_EMAIL,
    IDENTITY_FIRST_NAME, IDENTITY_LAST_NAME, IDENTITY_MIDDLE_NAME, IDENTITY_PHONE,
    IDENTITY_POSTAL_CODE, IDENTITY_STATE, IDENTITY_USERNAME, ITEM_NAME, ITEM_NOTES, LOGIN_PASSWORD,
    LOGIN_TOTP, LOGIN_USERNAME,
};
use rizzy_core::item::types::SupportedType;
use rizzy_core::rng::CryptoRng;
use zeroize::Zeroizing;

use crate::error::{ImportError, WarningKind, Warnings};
use crate::item::{FieldKind, ImportedItem, ItemBuilder};
use crate::json::{self, Json};
use crate::limits::{MAX_ARCHIVE_LEN, MAX_ENTRIES, MAX_EXPANDED_LEN};
use crate::{text, time, zip};

/// The member of the archive that holds the export.
const EXPORT_DATA: &str = "export.data";

/// Card section fields, by `id`.
const CARD_IDS: [(&str, &str); 5] = [
    ("cardholder", CARD_HOLDER),
    ("type", CARD_BRAND),
    ("ccnum", CARD_NUMBER),
    ("cvv", CARD_CODE),
    ("pin", CARD_PIN),
];

/// Identity section fields, by `id` (the address is handled apart).
const IDENTITY_IDS: [(&str, &str); 7] = [
    ("firstname", IDENTITY_FIRST_NAME),
    ("initial", IDENTITY_MIDDLE_NAME),
    ("lastname", IDENTITY_LAST_NAME),
    ("company", IDENTITY_COMPANY),
    ("email", IDENTITY_EMAIL),
    ("defphone", IDENTITY_PHONE),
    ("username", IDENTITY_USERNAME),
];

/// Address members, in the order they are joined, with their identity keys.
const ADDRESS_PARTS: [(&str, &str); 5] = [
    ("street", IDENTITY_ADDRESS1),
    ("city", IDENTITY_CITY),
    ("state", IDENTITY_STATE),
    ("zip", IDENTITY_POSTAL_CODE),
    ("country", IDENTITY_COUNTRY),
];

/// The text of member `name` of `obj`, or `""`.
fn text_of<'a>(obj: Option<&'a Json>, name: &str) -> &'a str {
    obj.and_then(|o| o.get(name))
        .and_then(Json::as_text)
        .unwrap_or_default()
}

/// The elements of array member `name` of `obj`, or none.
fn array<'a>(obj: Option<&'a Json>, name: &str) -> &'a [Json] {
    obj.and_then(|o| o.get(name))
        .and_then(Json::as_array)
        .unwrap_or_default()
}

/// Imports a 1PUX archive.
pub(crate) fn import<R: CryptoRng + ?Sized>(
    input: &[u8],
    rng: &mut R,
    warnings: &mut Warnings,
) -> Result<Vec<ImportedItem>, ImportError> {
    if input.len() > MAX_ARCHIVE_LEN {
        return Err(ImportError::TooLarge);
    }
    let data = zip::extract(input, EXPORT_DATA, MAX_EXPANDED_LEN)?;
    import_data(&data, rng, warnings)
}

/// Imports the `export.data` document of a 1PUX archive.
pub(crate) fn import_data<R: CryptoRng + ?Sized>(
    data: &[u8],
    rng: &mut R,
    warnings: &mut Warnings,
) -> Result<Vec<ImportedItem>, ImportError> {
    let doc = json::parse(data, MAX_EXPANDED_LEN)?;
    let accounts = doc
        .get("accounts")
        .and_then(Json::as_array)
        .ok_or(ImportError::UnexpectedShape)?;
    let mut out = Vec::new();
    let mut entry = 0usize;
    for account in accounts {
        for vault in array(Some(account), "vaults") {
            for item in array(Some(vault), "items") {
                if entry >= MAX_ENTRIES {
                    return Err(ImportError::TooMany);
                }
                let item = item.get("item").unwrap_or(item);
                if let Some(imported) = map_item(entry, item, rng, warnings) {
                    out.push(imported);
                }
                entry += 1;
            }
        }
    }
    Ok(out)
}

/// Maps one item, or skips it with a warning.
fn map_item<R: CryptoRng + ?Sized>(
    entry: usize,
    item: &Json,
    rng: &mut R,
    warnings: &mut Warnings,
) -> Option<ImportedItem> {
    if item.members().is_none() {
        warnings.push(Some(entry), WarningKind::MalformedEntry);
        return None;
    }
    if item.get("state").and_then(Json::as_str) == Some("trashed") {
        warnings.push(Some(entry), WarningKind::DeletedEntrySkipped);
        return None;
    }
    let category = text_of(Some(item), "categoryUuid");
    let kind = match category {
        "001" | "005" => SupportedType::Login,
        "002" => SupportedType::Card,
        "004" => SupportedType::Identity,
        _ => SupportedType::SecureNote,
    };
    let overview = item.get("overview");
    let details = item.get("details");
    let mut b = ItemBuilder::new(entry, kind, warnings);
    match category {
        "001" | "002" | "003" | "004" | "005" => {}
        "006" => b.warn(WarningKind::AttachmentSkipped),
        _ => b.warn(WarningKind::ConvertedToSecureNote),
    }
    b.set(ITEM_NAME, text_of(overview, "title"));
    b.set(ITEM_NOTES, text_of(details, "notesPlain"));
    b.set_favorite(
        item.get("favIndex")
            .and_then(Json::as_i64)
            .is_some_and(|i| i > 0),
    );
    if let Some(created) = item.get("createdAt") {
        b.set_created_ms(created.as_u64().and_then(time::seconds_ms));
    }
    for tag in array(overview, "tags") {
        b.add_tag(tag.as_str().unwrap_or_default());
    }
    b.add_uri(text_of(overview, "url"));
    for url in array(overview, "urls") {
        b.add_uri(text_of(Some(url), "url"));
    }
    for field in array(details, "loginFields") {
        login_field(&mut b, field);
    }
    // On a type without `login.password`, or when a login field already set it, the value
    // becomes a hidden custom field: it is never dropped.
    b.set_or_field(
        LOGIN_PASSWORD,
        "password",
        text_of(details, "password"),
        true,
    );
    for section in array(details, "sections") {
        for field in array(Some(section), "fields") {
            section_field(&mut b, field);
        }
    }
    for old in array(details, "passwordHistory") {
        let ms = old
            .get("time")
            .and_then(Json::as_u64)
            .and_then(time::seconds_ms);
        b.add_history(text_of(Some(old), "value"), ms);
    }
    if details.and_then(|d| d.get("documentAttributes")).is_some() && category != "006" {
        b.warn(WarningKind::AttachmentSkipped);
    }
    b.finish(rng)
}

/// One entry of `details.loginFields`.
fn login_field(b: &mut ItemBuilder<'_>, field: &Json) {
    let value = text_of(Some(field), "value");
    let label = match text_of(Some(field), "name") {
        "" => text_of(Some(field), "id"),
        name => name,
    };
    let hidden = text_of(Some(field), "fieldType") == "P";
    match text_of(Some(field), "designation") {
        "username" => b.set_or_field(LOGIN_USERNAME, label, value, false),
        "password" => b.set_or_field(LOGIN_PASSWORD, label, value, true),
        _ if value.is_empty() => {}
        _ => b.add_field(
            label,
            if hidden {
                FieldKind::Hidden
            } else {
                FieldKind::Text
            },
            value,
        ),
    }
}

/// One field of a section: its value is an object with one member, whose name is the kind.
fn section_field(b: &mut ItemBuilder<'_>, field: &Json) {
    let id = text_of(Some(field), "id");
    let label = match text_of(Some(field), "title") {
        "" => id,
        title => title,
    };
    let Some((value_kind, value)) = field
        .get("value")
        .and_then(Json::members)
        .and_then(|m| m.first())
        .map(|(k, v)| (k.as_str(), v))
    else {
        b.warn(WarningKind::FieldSkipped);
        return;
    };
    let kind = b.kind();
    let fixed = match kind {
        SupportedType::Card => card_field(b, id, label, value),
        SupportedType::Identity => identity_field(b, id, label, value_kind, value),
        _ => false,
    };
    if fixed {
        return;
    }
    match value_kind {
        "string" | "url" | "phone" | "menu" | "gender" | "creditCardType" => {
            match value.as_text() {
                Some(text) => b.add_field(label, FieldKind::Text, text),
                None => b.warn(WarningKind::FieldSkipped),
            }
        }
        "email" => match value
            .as_text()
            .or_else(|| value.get("email_address").and_then(Json::as_text))
        {
            Some(text) => b.add_field(label, FieldKind::Text, text),
            None => b.warn(WarningKind::FieldSkipped),
        },
        "concealed" | "creditCardNumber" => match value.as_text() {
            Some(text) => b.add_field(label, FieldKind::Hidden, text),
            None => b.warn(WarningKind::FieldSkipped),
        },
        "totp" => match value.as_text() {
            Some(text) if kind == SupportedType::Login => {
                b.set_or_field(LOGIN_TOTP, label, text, true);
            }
            Some(text) => b.add_field(label, FieldKind::Hidden, text),
            None => b.warn(WarningKind::FieldSkipped),
        },
        "date" => match value.as_i64().and_then(date_text) {
            Some(date) => b.add_field(label, FieldKind::Text, &date),
            None => b.warn(WarningKind::FieldSkipped),
        },
        "monthYear" => match value.as_u64().and_then(month_year) {
            Some((year, month)) => {
                let mut out = text::with_capacity(16);
                out.push_str(&year_text(year));
                out.push('-');
                out.push_str(&format_2(month));
                b.add_field(label, FieldKind::Text, &out);
            }
            None => b.warn(WarningKind::FieldSkipped),
        },
        "address" => {
            let joined = join_address(value);
            b.add_field(label, FieldKind::Text, &joined);
        }
        "sshKey" => {
            b.add_field(label, FieldKind::Hidden, text_of(Some(value), "privateKey"));
            let metadata = value.get("metadata");
            b.add_field("publicKey", FieldKind::Text, text_of(metadata, "publicKey"));
            b.add_field(
                "fingerprint",
                FieldKind::Text,
                text_of(metadata, "fingerprint"),
            );
        }
        "file" => b.warn(WarningKind::AttachmentSkipped),
        "reference" => b.warn(WarningKind::FieldSkipped),
        _ => match value.as_text() {
            Some(text) => b.add_field(label, FieldKind::Text, text),
            None => b.warn(WarningKind::FieldSkipped),
        },
    }
}

/// A Credit Card section field that has a fixed key, by `id`. Returns `true` if it was taken.
fn card_field(b: &mut ItemBuilder<'_>, id: &str, label: &str, value: &Json) -> bool {
    if id == "expiry"
        && let Some((year, month)) = value.as_u64().and_then(month_year)
    {
        b.set(CARD_EXP_MONTH, &format_2(month));
        b.set(CARD_EXP_YEAR, &year_text(year));
        return true;
    }
    if let Some(&(_, key)) = CARD_IDS.iter().find(|(i, _)| *i == id)
        && let Some(text) = value.as_text()
    {
        let hidden = matches!(key, CARD_NUMBER | CARD_CODE | CARD_PIN);
        b.set_or_field(key, label, text, hidden);
        return true;
    }
    false
}

/// An Identity section field that has a fixed key, by `id`. Returns `true` if it was taken.
/// Only the first `address` field fills the address keys.
fn identity_field(
    b: &mut ItemBuilder<'_>,
    id: &str,
    label: &str,
    value_kind: &str,
    value: &Json,
) -> bool {
    if value_kind == "address" && id == "address" && !ADDRESS_PARTS.iter().any(|(_, k)| b.has(k)) {
        for (member, key) in ADDRESS_PARTS {
            b.set(key, text_of(Some(value), member));
        }
        return true;
    }
    if let Some(&(_, key)) = IDENTITY_IDS.iter().find(|(i, _)| *i == id) {
        let text = match value_kind {
            "email" => value
                .as_text()
                .or_else(|| value.get("email_address").and_then(Json::as_text)),
            _ => value.as_text(),
        };
        if let Some(text) = text {
            b.set_or_field(key, label, text, false);
            return true;
        }
    }
    false
}

/// `YYYYMM` as `(year, month)`, if the month is 1–12.
fn month_year(value: u64) -> Option<(u64, u64)> {
    let (year, month) = (value / 100, value % 100);
    ((1..=12).contains(&month) && year <= 9999).then_some((year, month))
}

/// A number as two digits, zero-padded, in a zeroizing buffer.
fn format_2(n: u64) -> Zeroizing<String> {
    let mut out = text::with_capacity(20);
    if n < 10 {
        out.push('0');
    }
    push_u64(&mut out, n);
    out
}

/// A year as four digits, zero-padded, in a zeroizing buffer.
fn year_text(year: u64) -> Zeroizing<String> {
    let mut out = text::with_capacity(20);
    for bound in [1000, 100, 10] {
        if year < bound {
            out.push('0');
        }
    }
    push_u64(&mut out, year);
    out
}

/// Appends the decimal digits of `n` without allocating.
fn push_u64(out: &mut String, n: u64) {
    let mut digits = [0u8; 20];
    let mut len = 0;
    let mut rest = n;
    loop {
        if let Some(slot) = digits.get_mut(len) {
            *slot = b'0' + u8::try_from(rest % 10).unwrap_or(0);
        }
        len += 1;
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    for d in digits.iter().take(len).rev() {
        out.push(char::from(*d));
    }
}

/// Unix seconds as `YYYY-MM-DD`, for years 0–9999.
fn date_text(seconds: i64) -> Option<Zeroizing<String>> {
    let (year, month, day) = time::civil_from_days(seconds.div_euclid(86_400));
    let year = u64::try_from(year).ok().filter(|y| *y <= 9999)?;
    let mut out = text::with_capacity(16);
    out.push_str(&year_text(year));
    out.push('-');
    out.push_str(&format_2(u64::from(month)));
    out.push('-');
    out.push_str(&format_2(u64::from(day)));
    Some(out)
}

/// An address object's non-empty parts joined with `, `, in a buffer allocated once.
fn join_address(value: &Json) -> Zeroizing<String> {
    let parts = || {
        ADDRESS_PARTS
            .iter()
            .map(|(member, _)| text_of(Some(value), member))
            .filter(|p| !p.is_empty())
    };
    let len = parts().map(|p| p.len() + 2).sum();
    let mut out = text::with_capacity(len);
    for part in parts() {
        if !out.is_empty() {
            out.push_str(", ");
        }
        out.push_str(part);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        assert_eq!(month_year(202_512), Some((2025, 12)));
        assert_eq!(month_year(202_513), None);
        assert_eq!(format_2(7).as_str(), "07");
        assert_eq!(format_2(12).as_str(), "12");
        assert_eq!(year_text(987).as_str(), "0987");
        assert_eq!(date_text(0).unwrap().as_str(), "1970-01-01");
        assert_eq!(date_text(-86_400).unwrap().as_str(), "1969-12-31");
        assert_eq!(date_text(1_709_210_096).unwrap().as_str(), "2024-02-29");
        assert_eq!(date_text(i64::MAX), None);
    }
}
