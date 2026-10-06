//! `AliasVault`'s plaintext export formats (roadmap §4.2, M1; owner decision 2026-10-06:
//! "`AliasVault` export (added by the owner on 2026-10-06)"), researched from `AliasVault`'s own
//! source (L throughout: `github.com/aliasvault/aliasvault`, read on 2026-10-06, not re-read
//! for this module; the hand-written fixtures of this crate's tests are what prove each row).
//!
//! `AliasVault` writes three export forms; this module reads the two plaintext ones.
//!
//! | Form | Read here | Why / why not |
//! |---|---|---|
//! | `.avux` (`AliasVault` Unencrypted eXport): a zip archive with `manifest.json` at its root | `import_avux` | Plaintext, M1 |
//! | `AliasVault`'s CSV export (web and mobile app) | `import_csv` | Plaintext, M1 |
//! | `.avex` (`AliasVault` Encrypted eXport): the same `manifest.json` payload, Argon2id-then-AES-256-GCM encrypted | not read | Needs `AliasVault`'s own KDF and cipher, which need an ADR 0009 approval first (ADR 0002 point 2, owner decision 1), same as `KeePass` KDBX; its crypto is reported to the owner instead (not in this module: see the M1 `AliasVault` import handoff) |
//!
//! # `.avux`
//!
//! A zip archive (`AvuxExportService.ts`) whose only member this reader looks at is
//! `manifest.json` (`application/json`, pretty-printed, but any valid JSON is accepted); the
//! `attachments/` and `logos/` members, if present, are never opened ([`WarningKind::AttachmentSkipped`]:
//! attachments are M3, and so are favicon images). The manifest's `version` must start with
//! `"1."` ([`ImportError::UnexpectedShape`] otherwise: a later major version may change the
//! shape in a way this reader does not know). Every `AvuxManifest` date (`createdAt`,
//! `updatedAt`, `exportedAt`, …) is an RFC 3339 string (`crate::time::rfc3339_ms`).
//!
//! **Item mapping.**
//!
//! | `.avux` `items[].itemType` | rizzy-vault |
//! |---|---|
//! | `Login` | Login |
//! | `Alias` | Identity (its `alias.*` fields are then ADR 0018 fixed keys, not custom fields) |
//! | `CreditCard` | Card |
//! | `Note` | Secure Note |
//! | any other value | Secure Note, warning; its fields become custom fields the same way |
//!
//! | `.avux` item member | rizzy-vault |
//! |---|---|
//! | `name` | `item.name` |
//! | `createdAt` | `import.created_ms` |
//! | `archivedAt` not null | a boolean custom field `Archived` (M1 has no archive state) |
//! | `logoId` not null | not imported (favicon images are M3), warning ([`WarningKind::AttachmentSkipped`]) |
//! | `folderId` | a tag of the "/"-joined folder names, root first (folders are a UI over `/` in tag names, same as every other importer) |
//! | the item's tags (`itemTags`, `tags[].name`) | tags (blank names are dropped, same as `ItemBuilder::add_tag`) |
//! | `fieldValues[]`, in array order (not `weight`: see below) | the table below, by `fieldKey`; `fieldDefinitionId` instead is a custom field named after its `fieldDefinitions[].label`, hidden when `isHidden` or its `fieldType` is `Password` or `Hidden`. A blank `value` is not imported, same as every text field. |
//! | `totpCodes[]`, first one whose `algorithm`/`digits`/`period` are the default (`SHA1`, 6, 30) | `login.totp` (`secretKey` as entered) |
//! | every other `totpCodes[]` entry | a hidden custom field named after its `name` (or `TOTP`), warning ([`WarningKind::TotpNotConverted`]): building an otpauth URI from `AliasVault`'s settings is a format decision this importer does not make |
//! | `passkeys[]` not empty | not imported (passkeys are M7), warning |
//! | `attachments[]` not empty | not imported (M3), warning |
//!
//! `fieldValues[].fieldKey` (`core/models/src/vault/FieldKey.ts`):
//!
//! | `fieldKey` | rizzy-vault |
//! |---|---|
//! | `login.username` | `login.username` |
//! | `login.password` | `login.password` |
//! | `login.email` | `identity.email` (a custom field `Email` outside an Alias item) |
//! | `login.url` (repeats) | a URI (a text custom field `URL` outside a Login item) |
//! | `card.number` | `card.number` |
//! | `card.cardholder_name` | `card.holder` |
//! | `card.expiry_month` | `card.exp_month` |
//! | `card.expiry_year` | `card.exp_year` |
//! | `card.cvv` | `card.code` |
//! | `card.pin` | `card.pin` |
//! | `alias.first_name` | `identity.first_name` |
//! | `alias.last_name` | `identity.last_name` |
//! | `alias.gender` | a custom field `Gender` (no ADR 0018 field) |
//! | `alias.birthdate` | a custom field `Birth Date` (no ADR 0018 field; kept as the source's `yyyy-MM-dd` text) |
//! | `notes.content` | `item.notes` |
//! | any other string | a custom field named after the raw key (forward compatibility: a future `fieldKey` this reader does not know is kept, not dropped) |
//!
//! Every mapped single-value key above (every row but `login.url`) is written with
//! `ItemBuilder::set_or_field_last`: on an item type the key does not apply to (every one of
//! them but the Alias/Identity and Login/CreditCard rows it is written for), the same value
//! becomes a custom field instead, labelled as the table's right-hand column names it; this
//! part is the same rule [`crate::onepux`] and [`crate::bitwarden`] use for their own
//! type-specific fields (`ItemBuilder::set_or_field`). It differs from them in one way: a
//! second `fieldValues[]` entry for the same key **replaces** the first instead of falling
//! back to a custom field, i.e. the key resolves to the last matching entry in array order,
//! not the first. This matches `AliasVault`'s own importer
//! (`AvuxImportService.ts`'s `extractFieldValues`-equivalent logic), which iterates
//! `fieldValues` in their JSON array order — never sorted by `weight`, which is a UI-ordering
//! hint, not a write-order guarantee — and does a plain overwrite of a single-value system
//! field on every match, so the last one in the array wins. `login.url` is multi-value: every
//! entry is kept, appended in array order (`ItemBuilder::add_uri`), the same as
//! `AliasVault`'s own handling of `ServiceUrls`.
//!
//! # `AliasVault` CSV
//!
//! A CSV export with a header row (`AliasVaultCsvExportService.ts`,
//! `AliasVaultCsvImportService.ts`); columns are found by their exact name, so their order
//! does not matter, and a column the file lacks reads as empty text (older exports have no
//! card columns; the mobile app's export has no card columns but one more alias column,
//! `AliasNickName`, that the web export does not write). A row with any of
//! `CardholderName`, `CardNumber`, `CardExpiryMonth`, `CardExpiryYear`, `CardCvv` or `CardPin`
//! filled is a Card; every other row is a Login (`AliasVault`'s CSV export never writes an
//! Alias or Note row on its own: an alias's identity fields always ride along on a Login or
//! Card row as the table below says, and a Secure Note is exported as a Login with an empty
//! password). Blank rows are skipped; a header lacking `ServiceName` is
//! [`ImportError::UnexpectedShape`] (not an `AliasVault` export).
//!
//! | Column | rizzy-vault |
//! |---|---|
//! | `ServiceName` | `item.name` |
//! | `ServiceUrl` (comma-separated) | URIs |
//! | `Username` | `login.username` |
//! | `CurrentPassword` | `login.password` |
//! | `AliasEmail` | `identity.email` (a custom field `Alias Email` on a Login/Card row) |
//! | `TwoFactorSecret` | `login.totp` (a bare secret or an `otpauth://` URI, exactly as the column holds it: the export already writes the right one for the code's own settings, so this reader does not need to) |
//! | `AliasFirstName`, `AliasLastName` | `identity.first_name`, `.last_name` (custom fields `First Name`, `Last Name` on a Login/Card row) |
//! | `AliasGender`, `AliasBirthDate`, `AliasNickName` | custom fields `Gender`, `Birth Date`, `Nickname` (no ADR 0018 field) |
//! | `CardholderName`, `CardNumber`, `CardExpiryMonth`, `CardExpiryYear`, `CardCvv`, `CardPin` | `card.holder`, `.number`, `.exp_month`, `.exp_year`, `.code`, `.pin` |
//! | `Notes` | `item.notes` |
//! | `FolderPath` ("/"-joined) | a tag |
//! | `CreatedAt` ("MM/dd/yyyy HH:mm:ss", UTC; `crate::time::us_datetime_ms`) | `import.created_ms` |
//! | `UpdatedAt` | not imported (M1 has no "updated" item field; every other importer drops it the same way) |
//! | extra columns past the header | not imported, warning ([`WarningKind::ExtraColumns`]) |

use std::collections::BTreeMap;

use rizzy_core::item::schema::{
    CARD_CODE, CARD_EXP_MONTH, CARD_EXP_YEAR, CARD_HOLDER, CARD_NUMBER, CARD_PIN, IDENTITY_EMAIL,
    IDENTITY_FIRST_NAME, IDENTITY_LAST_NAME, ITEM_NAME, ITEM_NOTES, LOGIN_PASSWORD, LOGIN_TOTP,
    LOGIN_USERNAME,
};
use rizzy_core::item::types::SupportedType;
use rizzy_core::rng::CryptoRng;
use zeroize::Zeroizing;

use crate::csv::{self, Reader};
use crate::error::{ImportError, WarningKind, Warnings};
use crate::item::{FieldKind, ImportedItem, ItemBuilder};
use crate::json::{self, Json};
use crate::limits::{MAX_ARCHIVE_LEN, MAX_CSV_LEN, MAX_ENTRIES, MAX_EXPANDED_LEN, MAX_JSON_LEN};
use crate::{time, zip};

/// The member of an `.avux` archive that holds the manifest.
const MANIFEST_MEMBER: &str = "manifest.json";

/// Deepest folder chain [`folder_path`] follows, as a cycle and runaway-chain guard; `AliasVault`
/// folders nest nowhere near this deep.
const MAX_FOLDER_DEPTH: usize = 64;

/// The TOTP settings a bare `login.totp` secret implies (CRYPTO.md §11.15).
const TOTP_DEFAULT_DIGITS: u64 = 6;
/// See [`TOTP_DEFAULT_DIGITS`].
const TOTP_DEFAULT_PERIOD: u64 = 30;

/// The index of the column named exactly `name`.
fn find(header: &[Zeroizing<String>], name: &str) -> Option<usize> {
    header.iter().position(|h| h.trim() == name)
}

/// The field at `index` of `record`, or empty.
fn field(record: &[Zeroizing<String>], index: Option<usize>) -> &str {
    index.and_then(|i| record.get(i)).map_or("", |f| f.as_str())
}

/// Imports an `AliasVault` CSV export (web or mobile app; module docs).
pub(crate) fn import_csv<R: CryptoRng + ?Sized>(
    input: &[u8],
    rng: &mut R,
    warnings: &mut Warnings,
) -> Result<Vec<ImportedItem>, ImportError> {
    let mut reader = Reader::new(input, MAX_CSV_LEN)?;
    let header = reader.next_record()?.ok_or(ImportError::UnexpectedShape)?;
    let columns = Columns::find(&header)?;
    let column_count = header.len();

    let mut out = Vec::new();
    let mut entry = 0usize;
    while let Some(record) = reader.next_record()? {
        let this_entry = entry;
        entry += 1;
        if csv::is_blank(&record) {
            continue;
        }
        if record.len() > column_count {
            warnings.push(Some(this_entry), WarningKind::ExtraColumns);
        }
        let b = map_csv_row(this_entry, &record, &columns, warnings);
        out.extend(b.finish(rng));
    }
    Ok(out)
}

/// The column indexes of an `AliasVault` CSV header, found once per file.
struct Columns {
    /// `ServiceName`; required.
    service_name: usize,
    /// `FolderPath`.
    folder_path: Option<usize>,
    /// `ServiceUrl`.
    service_url: Option<usize>,
    /// `Username`.
    username: Option<usize>,
    /// `CurrentPassword`.
    password: Option<usize>,
    /// `AliasEmail`.
    alias_email: Option<usize>,
    /// `TwoFactorSecret`.
    totp: Option<usize>,
    /// `AliasGender`.
    gender: Option<usize>,
    /// `AliasFirstName`.
    first_name: Option<usize>,
    /// `AliasLastName`.
    last_name: Option<usize>,
    /// `AliasNickName` (mobile app export only).
    nickname: Option<usize>,
    /// `AliasBirthDate`.
    birth_date: Option<usize>,
    /// `CardholderName` (web export only).
    card_holder: Option<usize>,
    /// `CardNumber` (web export only).
    card_number: Option<usize>,
    /// `CardExpiryMonth` (web export only).
    card_exp_month: Option<usize>,
    /// `CardExpiryYear` (web export only).
    card_exp_year: Option<usize>,
    /// `CardCvv` (web export only).
    card_cvv: Option<usize>,
    /// `CardPin` (web export only).
    card_pin: Option<usize>,
    /// `Notes`.
    notes: Option<usize>,
    /// `CreatedAt`.
    created_at: Option<usize>,
}

impl Columns {
    /// Finds every column by its exact `AliasVault` header name.
    ///
    /// # Errors
    /// [`ImportError::UnexpectedShape`] when the header has no `ServiceName` column: not an
    /// `AliasVault` export.
    fn find(header: &[Zeroizing<String>]) -> Result<Self, ImportError> {
        Ok(Self {
            service_name: find(header, "ServiceName").ok_or(ImportError::UnexpectedShape)?,
            folder_path: find(header, "FolderPath"),
            service_url: find(header, "ServiceUrl"),
            username: find(header, "Username"),
            password: find(header, "CurrentPassword"),
            alias_email: find(header, "AliasEmail"),
            totp: find(header, "TwoFactorSecret"),
            gender: find(header, "AliasGender"),
            first_name: find(header, "AliasFirstName"),
            last_name: find(header, "AliasLastName"),
            nickname: find(header, "AliasNickName"),
            birth_date: find(header, "AliasBirthDate"),
            card_holder: find(header, "CardholderName"),
            card_number: find(header, "CardNumber"),
            card_exp_month: find(header, "CardExpiryMonth"),
            card_exp_year: find(header, "CardExpiryYear"),
            card_cvv: find(header, "CardCvv"),
            card_pin: find(header, "CardPin"),
            notes: find(header, "Notes"),
            created_at: find(header, "CreatedAt"),
        })
    }
}

/// Maps one `AliasVault` CSV data row to an item builder (module docs' column table).
fn map_csv_row<'w>(
    entry: usize,
    record: &[Zeroizing<String>],
    c: &Columns,
    warnings: &'w mut Warnings,
) -> ItemBuilder<'w> {
    let has_card = [
        c.card_holder,
        c.card_number,
        c.card_exp_month,
        c.card_exp_year,
        c.card_cvv,
        c.card_pin,
    ]
    .iter()
    .any(|i| !field(record, *i).is_empty());
    let kind = if has_card {
        SupportedType::Card
    } else {
        SupportedType::Login
    };
    let mut b = ItemBuilder::new(entry, kind, warnings);
    b.set(ITEM_NAME, field(record, Some(c.service_name)));
    for url in field(record, c.service_url).split(',') {
        b.add_uri(url.trim());
    }
    b.set_or_field(LOGIN_USERNAME, "Username", field(record, c.username), false);
    b.set_or_field(LOGIN_PASSWORD, "Password", field(record, c.password), true);
    b.set_or_field(
        IDENTITY_EMAIL,
        "Alias Email",
        field(record, c.alias_email),
        false,
    );
    b.set_or_field(LOGIN_TOTP, "TOTP", field(record, c.totp), true);
    b.add_field("Gender", FieldKind::Text, field(record, c.gender));
    b.set_or_field(
        IDENTITY_FIRST_NAME,
        "First Name",
        field(record, c.first_name),
        false,
    );
    b.set_or_field(
        IDENTITY_LAST_NAME,
        "Last Name",
        field(record, c.last_name),
        false,
    );
    b.add_field("Nickname", FieldKind::Text, field(record, c.nickname));
    b.add_field("Birth Date", FieldKind::Text, field(record, c.birth_date));
    b.set_or_field(
        CARD_HOLDER,
        "Cardholder Name",
        field(record, c.card_holder),
        false,
    );
    b.set_or_field(
        CARD_NUMBER,
        "Card Number",
        field(record, c.card_number),
        true,
    );
    b.set_or_field(
        CARD_EXP_MONTH,
        "Card Expiry Month",
        field(record, c.card_exp_month),
        false,
    );
    b.set_or_field(
        CARD_EXP_YEAR,
        "Card Expiry Year",
        field(record, c.card_exp_year),
        false,
    );
    b.set_or_field(CARD_CODE, "Card CVV", field(record, c.card_cvv), true);
    b.set_or_field(CARD_PIN, "Card PIN", field(record, c.card_pin), true);
    b.set(ITEM_NOTES, field(record, c.notes));
    let folder = field(record, c.folder_path);
    if !folder.trim().is_empty() {
        b.add_tag(folder);
    }
    let created = field(record, c.created_at).trim();
    if !created.is_empty() {
        b.set_created_ms(time::us_datetime_ms(created));
    }
    b
}

/// A folder's name and parent id, by id.
type Folders<'a> = BTreeMap<&'a str, (&'a str, Option<&'a str>)>;

/// The `id` to `(name, parentFolderId)` map of an `.avux` manifest's `folders`.
fn folder_map(list: Option<&Json>) -> Folders<'_> {
    list.and_then(Json::as_array)
        .unwrap_or_default()
        .iter()
        .filter_map(|f| {
            let id = f.get("id")?.as_str()?;
            let name = f.get("name")?.as_str()?;
            let parent = f.get("parentFolderId").and_then(Json::as_str);
            Some((id, (name, parent)))
        })
        .collect()
}

/// The "/"-joined names of `folder_id` and its parents, root first; `None` if `folder_id` is
/// unknown. A cycle, or a chain deeper than [`MAX_FOLDER_DEPTH`], stops early with whatever
/// was resolved so far (never panics, never loops).
fn folder_path(folder_id: &str, folders: &Folders<'_>) -> Option<String> {
    let mut names = Vec::new();
    let mut visited = Vec::new();
    let mut current = Some(folder_id);
    for _ in 0..MAX_FOLDER_DEPTH {
        let Some(id) = current else { break };
        if visited.contains(&id) {
            break;
        }
        visited.push(id);
        let Some((name, parent)) = folders.get(id) else {
            break;
        };
        names.push(*name);
        current = *parent;
    }
    if names.is_empty() {
        return None;
    }
    names.reverse();
    Some(names.join("/"))
}

/// The `id` to `name` map of an `.avux` manifest's `tags`, blank names dropped.
fn tag_map(list: Option<&Json>) -> BTreeMap<&str, &str> {
    list.and_then(Json::as_array)
        .unwrap_or_default()
        .iter()
        .filter_map(|t| {
            let id = t.get("id")?.as_str()?;
            let name = t.get("name")?.as_str()?;
            (!name.trim().is_empty()).then_some((id, name))
        })
        .collect()
}

/// The `itemId` to tag names map of an `.avux` manifest's `itemTags`.
fn item_tag_map<'a>(
    list: Option<&'a Json>,
    tags: &BTreeMap<&'a str, &'a str>,
) -> BTreeMap<&'a str, Vec<&'a str>> {
    let mut map: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for it in list.and_then(Json::as_array).unwrap_or_default() {
        let Some(item_id) = it.get("itemId").and_then(Json::as_str) else {
            continue;
        };
        let Some(tag_id) = it.get("tagId").and_then(Json::as_str) else {
            continue;
        };
        if let Some(name) = tags.get(tag_id) {
            map.entry(item_id).or_default().push(name);
        }
    }
    map
}

/// A custom field definition's label and whether it is concealed, by id.
fn definition_map(list: Option<&Json>) -> BTreeMap<&str, (&str, bool)> {
    list.and_then(Json::as_array)
        .unwrap_or_default()
        .iter()
        .filter_map(|d| {
            let id = d.get("id")?.as_str()?;
            let label = d.get("label").and_then(Json::as_text).unwrap_or_default();
            let hidden = d.get("isHidden").and_then(Json::as_bool) == Some(true)
                || matches!(
                    d.get("fieldType").and_then(Json::as_str),
                    Some("Password" | "Hidden")
                );
            Some((id, (label, hidden)))
        })
        .collect()
}

/// Imports an `.avux` archive (module docs).
pub(crate) fn import_avux<R: CryptoRng + ?Sized>(
    input: &[u8],
    rng: &mut R,
    warnings: &mut Warnings,
) -> Result<Vec<ImportedItem>, ImportError> {
    if input.len() > MAX_ARCHIVE_LEN {
        return Err(ImportError::TooLarge);
    }
    let manifest = zip::extract(input, MANIFEST_MEMBER, MAX_EXPANDED_LEN)?;
    import_manifest(&manifest, rng, warnings)
}

/// Imports an already-extracted `.avux` manifest: for the `import_aliasvault_avux` fuzz
/// target, which reaches the mapping without building a zip first.
pub(crate) fn import_manifest<R: CryptoRng + ?Sized>(
    data: &[u8],
    rng: &mut R,
    warnings: &mut Warnings,
) -> Result<Vec<ImportedItem>, ImportError> {
    let doc = json::parse(data, MAX_JSON_LEN)?;
    if doc.members().is_none() {
        return Err(ImportError::UnexpectedShape);
    }
    match doc.get("version").and_then(Json::as_str) {
        Some(version) if version.starts_with("1.") => {}
        _ => return Err(ImportError::UnexpectedShape),
    }
    let items = doc
        .get("items")
        .and_then(Json::as_array)
        .ok_or(ImportError::UnexpectedShape)?;
    if items.len() > MAX_ENTRIES {
        return Err(ImportError::TooMany);
    }
    let folders = folder_map(doc.get("folders"));
    let tags = tag_map(doc.get("tags"));
    let item_tags = item_tag_map(doc.get("itemTags"), &tags);
    let definitions = definition_map(doc.get("fieldDefinitions"));
    let mut out = Vec::new();
    for (entry, item) in items.iter().enumerate() {
        if let Some(imported) = map_item(
            entry,
            item,
            &folders,
            &item_tags,
            &definitions,
            rng,
            warnings,
        ) {
            out.push(imported);
        }
    }
    Ok(out)
}

/// Maps one `.avux` item, or skips it with a warning.
fn map_item<R: CryptoRng + ?Sized>(
    entry: usize,
    item: &Json,
    folders: &Folders<'_>,
    item_tags: &BTreeMap<&str, Vec<&str>>,
    definitions: &BTreeMap<&str, (&str, bool)>,
    rng: &mut R,
    warnings: &mut Warnings,
) -> Option<ImportedItem> {
    if item.members().is_none() {
        warnings.push(Some(entry), WarningKind::MalformedEntry);
        return None;
    }
    let item_type = item.get("itemType").and_then(Json::as_str).unwrap_or("");
    let kind = match item_type {
        "Login" => SupportedType::Login,
        "Alias" => SupportedType::Identity,
        "CreditCard" => SupportedType::Card,
        // "Note", and any value this reader does not know (`ConvertedToSecureNote` below).
        _ => SupportedType::SecureNote,
    };
    let mut b = ItemBuilder::new(entry, kind, warnings);
    if !matches!(item_type, "Login" | "Alias" | "CreditCard" | "Note") {
        b.warn(WarningKind::ConvertedToSecureNote);
    }
    b.set(
        ITEM_NAME,
        item.get("name").and_then(Json::as_text).unwrap_or_default(),
    );
    if let Some(created) = item.get("createdAt").and_then(Json::as_str) {
        b.set_created_ms(time::rfc3339_ms(created));
    }
    if item.get("archivedAt").and_then(Json::as_str).is_some() {
        b.add_bool_field("Archived", true);
    }
    if item.get("logoId").and_then(Json::as_str).is_some() {
        b.warn(WarningKind::AttachmentSkipped);
    }
    if let Some(path) = item
        .get("folderId")
        .and_then(Json::as_str)
        .and_then(|folder_id| folder_path(folder_id, folders))
    {
        b.add_tag(&path);
    }
    if let Some(item_id) = item.get("id").and_then(Json::as_str) {
        for tag in item_tags.get(item_id).into_iter().flatten() {
            b.add_tag(tag);
        }
    }
    // `fieldValues` is read in array order, not `weight` order: `weight` is a UI-ordering
    // hint, not a write-order guarantee, and `AliasVault`'s own importer
    // (`AvuxImportService.ts`) never sorts by it either (module docs).
    for fv in item
        .get("fieldValues")
        .and_then(Json::as_array)
        .unwrap_or_default()
    {
        apply_field_value(&mut b, fv, definitions);
    }
    totp_codes(
        &mut b,
        item.get("totpCodes")
            .and_then(Json::as_array)
            .unwrap_or_default(),
    );
    if item
        .get("passkeys")
        .and_then(Json::as_array)
        .is_some_and(|a| !a.is_empty())
    {
        b.warn(WarningKind::PasskeySkipped);
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

/// One `fieldValues[]` entry (module docs' `fieldKey` table).
fn apply_field_value(
    b: &mut ItemBuilder<'_>,
    fv: &Json,
    definitions: &BTreeMap<&str, (&str, bool)>,
) {
    let value = fv.get("value").and_then(Json::as_text).unwrap_or_default();
    if value.is_empty() {
        return;
    }
    // A duplicate single-value key resolves last-wins, as `AliasVault`'s own importer does
    // (`set_or_field_last`, module docs); `login.url` is multi-value and already append-only
    // in array order (`add_uri`).
    match fv.get("fieldKey").and_then(Json::as_str) {
        Some("login.username") => b.set_or_field_last(LOGIN_USERNAME, "Username", value, false),
        Some("login.password") => b.set_or_field_last(LOGIN_PASSWORD, "Password", value, true),
        Some("login.email") => b.set_or_field_last(IDENTITY_EMAIL, "Email", value, false),
        Some("login.url") => b.add_uri(value),
        Some("card.number") => b.set_or_field_last(CARD_NUMBER, "Card Number", value, true),
        Some("card.cardholder_name") => {
            b.set_or_field_last(CARD_HOLDER, "Cardholder Name", value, false);
        }
        Some("card.expiry_month") => {
            b.set_or_field_last(CARD_EXP_MONTH, "Card Expiry Month", value, false);
        }
        Some("card.expiry_year") => {
            b.set_or_field_last(CARD_EXP_YEAR, "Card Expiry Year", value, false);
        }
        Some("card.cvv") => b.set_or_field_last(CARD_CODE, "Card CVV", value, true),
        Some("card.pin") => b.set_or_field_last(CARD_PIN, "Card PIN", value, true),
        Some("alias.first_name") => {
            b.set_or_field_last(IDENTITY_FIRST_NAME, "First Name", value, false);
        }
        Some("alias.last_name") => {
            b.set_or_field_last(IDENTITY_LAST_NAME, "Last Name", value, false);
        }
        Some("alias.gender") => b.add_field("Gender", FieldKind::Text, value),
        Some("alias.birthdate") => b.add_field("Birth Date", FieldKind::Text, value),
        Some("notes.content") => b.set_or_field_last(ITEM_NOTES, "Notes", value, false),
        Some(key) => b.add_field(key, FieldKind::Text, value),
        None => {
            let (label, hidden) = fv
                .get("fieldDefinitionId")
                .and_then(Json::as_str)
                .and_then(|id| definitions.get(id))
                .copied()
                .unwrap_or(("", false));
            let kind = if hidden {
                FieldKind::Hidden
            } else {
                FieldKind::Text
            };
            b.add_field(label, kind, value);
        }
    }
}

/// `totpCodes[]`: the first default-settings secret becomes `login.totp`; every other one is
/// kept, hidden, with a warning (module docs).
fn totp_codes(b: &mut ItemBuilder<'_>, codes: &[Json]) {
    let mut assigned = false;
    for code in codes {
        let secret = code
            .get("secretKey")
            .and_then(Json::as_text)
            .unwrap_or_default();
        if secret.is_empty() {
            continue;
        }
        let algorithm = code
            .get("algorithm")
            .and_then(Json::as_text)
            .unwrap_or_default();
        let digits = code.get("digits").and_then(Json::as_u64);
        let period = code.get("period").and_then(Json::as_u64);
        let is_default = algorithm.eq_ignore_ascii_case("SHA1")
            && digits == Some(TOTP_DEFAULT_DIGITS)
            && period == Some(TOTP_DEFAULT_PERIOD);
        let name = code.get("name").and_then(Json::as_text).unwrap_or_default();
        let label = if name.is_empty() { "TOTP" } else { name };
        if !assigned && is_default {
            b.set_or_field(LOGIN_TOTP, label, secret, true);
            assigned = true;
        } else {
            b.warn(WarningKind::TotpNotConverted);
            b.add_field(label, FieldKind::Hidden, secret);
        }
    }
}
