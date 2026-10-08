//! rizzy-vault's own plaintext JSON export, read back ([ADR 0027] §3 and §6; roadmap §4.2).
//!
//! **Document** (ADR 0027 §3). `rizzy-client` writes it; this module reads it:
//!
//! ```text
//! {"format":"rizzy-vault-plaintext-export","version":1,"exported_at":1790000000000,
//!  "items":[{"id":"<32 lowercase hex>","type":1,"trashed":false,"created_ms":…,"modified_ms":…,
//!    "fields":[{"key":"item.name","value":{"text":"Bank"}},
//!              {"key":"login.password","value":{"text":"…"},
//!               "conflicts":[{"text":"…"}],"history":[{"value":{"text":"…"},"ms":…}]}]}]}
//! ```
//!
//! **The file is hostile input** (threat model A16): it is not signed or encrypted, so nothing
//! in it is trusted. It yields only the writes of new items of the importing device, each
//! checked by `rizzy-core`'s [`check_carried`] for [`WriteMode::Import`] (ADR 0027 §6, open
//! question 5 answered "carried"): any key of the ADR 0018 §7 grammar and any value bytes
//! within §10 are kept verbatim, and show as unsupported where this client does not know
//! them. No id, dot, device id or time of the exporting account is reused: `id` and
//! `modified_ms` are ignored, and the item gets a new id from `rizzy-client`.
//!
//! **Whole-file checks; each failure refuses the file** (ADR 0027 §6):
//!
//! | Check | Error |
//! |---|---|
//! | Length ≤ 64 MiB ([`MAX_JSON_LEN`]), before any parsing | [`ImportError::TooLarge`] |
//! | UTF-8; RFC 8259 syntax | [`ImportError::Encoding`]; [`ImportError::Malformed`] |
//! | Nesting ≤ 64 ([`MAX_DEPTH`](crate::limits::MAX_DEPTH); the format needs 8) | [`ImportError::TooDeep`] |
//! | ≤ 4,000,000 JSON values ([`MAX_NODES`](crate::limits::MAX_NODES)) | [`ImportError::TooMany`] |
//! | The root is an object whose `format` is the exact string [`FORMAT`] | [`ImportError::UnexpectedShape`] ("not this format") |
//! | `version` is the integer [`VERSION`] | [`ImportError::UpdateRequired`], never guessed or migrated; [`ImportError::UnexpectedShape`] when the member is missing |
//! | `items` is an array of ≤ 100,000 entries ([`MAX_ENTRIES`]) | [`ImportError::UnexpectedShape`]; [`ImportError::TooMany`] |
//!
//! `exported_at` is optional and ignored. Unknown members of any object are ignored and
//! counted ([`Counts::ignored_members`](crate::Counts)); of duplicate members the first counts
//! (the [`json`] reader's rule) and the others are counted as ignored.
//!
//! **Per item** (ADR 0027 §6). A failure skips the item with a warning that names its
//! position, never the file:
//!
//! | Member | Rule |
//! |---|---|
//! | `type` | required; an integer 0–65,535. A type the schema refuses (unknown, reserved, `0x0000`) and the vault-settings type `0xF001` skip the item ([`WarningKind::UnsupportedItemType`]) |
//! | `fields` | required; an array of ≤ 4,096 entries ([`MAX_ITEM_FIELDS`]) |
//! | `trashed` | optional boolean, default false |
//! | `created_ms` | optional integer fitting a `u64`; written as `import.created_ms` |
//! | `id`, `modified_ms` | ignored |
//! | field `key` | required; the ADR 0018 §7 grammar, 1–160 bytes, no duplicate in the item |
//! | field `value` | required; an object with exactly one type member (below) |
//! | field `conflicts` | ignored; counted as collapsed when it lists a value |
//! | field `history` | of `login.password` on a Login: at most 50 entries `{"value":…,"ms":…}` become `pwhist/<id>/value` and `/ms` with fresh element ids; more are counted as dropped, and so is the history of any other field |
//!
//! **Values become ADR 0018 §6 bytes:**
//!
//! | Type member | JSON | Value |
//! |---|---|---|
//! | `text` | string | Text |
//! | `bytes` | base64url string | Bytes |
//! | `bool` | `true` / `false` | Bool |
//! | `u64` | string of 1–20 decimal digits, no leading zero, fitting a `u64` | U64 |
//! | `enum` | integer 0–65,535 | Enum |
//! | `sort_key` | base64url string of a `SortKey` payload | `SortKey` |
//! | `raw` | base64url string | the decoded bytes verbatim, type byte included |
//!
//! Each value is ≤ 65,536 bytes, type byte included (ADR 0018 §10), checked on the JSON
//! string's length before any base64url decoding; base64url is unpadded and strict
//! (CRYPTO.md §9.6).
//!
//! # Readings (conservative, where ADR 0027 §6 leaves a detail open)
//!
//! - **A write the op may not make.** `check_carried` refuses a known key that belongs to
//!   another item type and a key this client never writes (`share/<id>/secret`, M5's;
//!   `uri/<id>/match` was the same in M1, owner decision 2, and carries from M2 once ADR 0037,
//!   Accepted, assigned its enum values). Such a field is left out, counted
//!   ([`Counts::dropped_fields`](crate::Counts)) and warned about
//!   ([`WarningKind::FieldSkipped`]); the item's other fields are imported. This is how
//!   `rizzy-core` already treats those keys in a restore or duplicate as a new item.
//! - **An empty `raw`** decodes to the Cleared value, which a new item never writes (the
//!   writer leaves a cleared field out): a mistyped member, so the item is skipped.
//! - **A `sort_key` that is not a `SortKey` payload** (empty, over 64 bytes, ending in
//!   `0x00`) is a mistyped member; the writer emits such a value as `raw`.
//! - **History values.** A history entry must have the shape `{"value":…,"ms":…}`, or the item
//!   is skipped; an entry whose value is not a non-empty text is counted as dropped, since
//!   `pwhist/<id>/value` is a Text.
//! - **`item.type` and `import.created_ms` among `fields`.** A `fields` entry with key
//!   `item.type` is ignored (the `type` member decides); one with key `import.created_ms` is
//!   ignored when `created_ms` is present and carried otherwise.
//! - **Size of the whole item.** An item whose writes would exceed what one item's snapshot
//!   may hold (4,096 registers with `@lifecycle`, 12 MiB of snapshot data, ADR 0018 §10) is
//!   skipped ([`WarningKind::OversizeEntry`]): it would be oversize from its first sync.
//! - **The report names positions only** (INV-48): warnings carry an entry's position and a
//!   kind, at most one of each kind per entry; totals are in [`Counts`].
//!
//! [ADR 0027]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0027-export-payload.md

use rizzy_core::encoding::{b64url_decode_into, b64url_decoded_len};
use rizzy_core::item::key::{ElementId, FieldKey};
use rizzy_core::item::schema::{
    ATTR_MS, ATTR_VALUE, IMPORT_CREATED_MS, ITEM_TYPE, LIST_PWHIST, LOGIN_PASSWORD, WriteError,
    WriteMode, WriteSource, check_carried, check_create,
};
use rizzy_core::item::types::{ItemType, SupportedType};
use rizzy_core::item::value::{MAX_VALUE_LEN, SortKey, Value, ValueRef};
use rizzy_core::rng::CryptoRng;
use zeroize::Zeroizing;

use crate::Counts;
use crate::error::{ImportError, WarningKind, Warnings};
use crate::item::{ImportedItem, ImportedWrite};
use crate::json::{self, Json};
use crate::limits::{
    MAX_ENTRIES, MAX_HISTORY, MAX_ITEM_FIELDS, MAX_JSON_LEN, MAX_REGISTERS, MAX_SNAPSHOT_DATA_LEN,
    SNAPSHOT_MARGIN,
};
use crate::text;

/// The `format` value of a rizzy-vault plaintext JSON export (ADR 0027 §3).
pub const FORMAT: &str = "rizzy-vault-plaintext-export";

/// The `version` value of a rizzy-vault plaintext JSON export (ADR 0027 §3).
pub const VERSION: u64 = 1;

/// The members of the root object.
const ROOT_MEMBERS: [&str; 4] = ["format", "version", "exported_at", "items"];
/// The members of an item.
const ITEM_MEMBERS: [&str; 6] = [
    "id",
    "type",
    "trashed",
    "created_ms",
    "modified_ms",
    "fields",
];
/// The members of a field.
const FIELD_MEMBERS: [&str; 4] = ["key", "value", "conflicts", "history"];
/// The members of a history entry.
const HISTORY_MEMBERS: [&str; 2] = ["value", "ms"];
/// The type members of a value object (ADR 0027 §3 "Typed values").
const VALUE_MEMBERS: [&str; 7] = ["text", "bytes", "bool", "u64", "enum", "sort_key", "raw"];

/// Bytes one register of one value adds to snapshot data beyond its key and value:
/// `str(key)` length (4), `u16 m` (2), the dot (24), the HLC (8) and the `bytes(value)` length
/// (4) (ADR 0018 §3).
const REGISTER_OVERHEAD: usize = 42;

/// How many members of `members` the format does not define: every member that is not the
/// first one of a name in `known`.
fn ignored_members(members: &[(Zeroizing<String>, Json)], known: &[&str]) -> usize {
    let mut seen = [false; 8];
    let mut ignored = 0usize;
    for (name, _) in members {
        let slot = known
            .iter()
            .position(|k| *k == name.as_str())
            .and_then(|i| seen.get_mut(i));
        match slot {
            Some(first) if !*first => *first = true,
            _ => ignored = ignored.saturating_add(1),
        }
    }
    ignored
}

/// A JSON integer without sign, fraction or exponent, fitting a `u64`. A string of digits is
/// not one.
fn integer(value: &Json) -> Option<u64> {
    match value {
        Json::Number(digits) => text::parse_u64(digits),
        _ => None,
    }
}

/// Decodes a base64url string of at most `max` decoded bytes into a zeroizing buffer of its
/// exact size. The size is checked on the string's length, before anything is decoded.
fn decode(value: &Json, max: usize) -> Result<Zeroizing<Vec<u8>>, WarningKind> {
    let encoded = value.as_str().ok_or(WarningKind::MalformedEntry)?;
    let len = b64url_decoded_len(encoded.len()).ok_or(WarningKind::MalformedEntry)?;
    if len > max {
        return Err(WarningKind::OversizeEntry);
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

/// Turns a value object into its ADR 0018 §6 bytes (see the module docs). `ignored` counts the
/// members the format does not define.
fn typed_value(value: &Json, ignored: &mut usize) -> Result<Value, WarningKind> {
    const BAD: WarningKind = WarningKind::MalformedEntry;
    const BIG: WarningKind = WarningKind::OversizeEntry;
    let members = value.members().ok_or(BAD)?;
    *ignored = ignored.saturating_add(ignored_members(members, &VALUE_MEMBERS));
    let mut present = VALUE_MEMBERS
        .iter()
        .filter_map(|name| value.get(name).map(|v| (*name, v)));
    let (name, inner) = present.next().ok_or(BAD)?;
    if present.next().is_some() {
        return Err(BAD);
    }
    match name {
        "text" => {
            let text = inner.as_str().ok_or(BAD)?;
            if text.len() >= MAX_VALUE_LEN {
                return Err(BIG);
            }
            Value::text(text).map_err(|_| BIG)
        }
        "bytes" => {
            let raw = decode(inner, MAX_VALUE_LEN - 1)?;
            Value::bytes(&raw).map_err(|_| BIG)
        }
        "bool" => inner.as_bool().map(Value::bool).ok_or(BAD),
        "u64" => {
            let digits = inner.as_str().ok_or(BAD)?;
            if digits.len() > 1 && digits.starts_with('0') {
                return Err(BAD);
            }
            text::parse_u64(digits).map(Value::u64).ok_or(BAD)
        }
        "enum" => integer(inner)
            .and_then(|v| u16::try_from(v).ok())
            .map(Value::enumeration)
            .ok_or(BAD),
        "sort_key" => {
            let raw = decode(inner, MAX_VALUE_LEN - 1)?;
            SortKey::from_slice(&raw)
                .map(|key| Value::sort_key(&key))
                .map_err(|_| BAD)
        }
        "raw" => {
            let raw = decode(inner, MAX_VALUE_LEN)?;
            if raw.is_empty() {
                return Err(BAD);
            }
            Value::copy_from_encoded(&raw).map_err(|_| BIG)
        }
        _ => Err(BAD),
    }
}

/// What importing one item lost, for [`Counts`] and the per-entry warnings.
#[derive(Default)]
struct Tally {
    /// Fields that listed `conflicts`.
    collapsed: usize,
    /// History entries not carried.
    history: usize,
    /// Fields left out because the new item may not write them.
    fields: usize,
}

/// The size of the item being assembled, against what one item's snapshot may hold.
struct Budget {
    /// Writes so far.
    writes: usize,
    /// Snapshot bytes so far, [`SNAPSHOT_MARGIN`] included.
    bytes: usize,
}

impl Budget {
    /// Accounts for one write; fails when the item would be oversize.
    fn add(&mut self, key_len: usize, value_len: usize) -> Result<(), WarningKind> {
        self.writes = self.writes.saturating_add(1);
        self.bytes = self
            .bytes
            .saturating_add(REGISTER_OVERHEAD)
            .saturating_add(key_len)
            .saturating_add(value_len);
        // `@lifecycle` is one of the registers.
        if self.writes >= MAX_REGISTERS || self.bytes > MAX_SNAPSHOT_DATA_LEN {
            Err(WarningKind::OversizeEntry)
        } else {
            Ok(())
        }
    }

    /// Accounts for `write` and returns it.
    fn take(&mut self, key: FieldKey, value: Value) -> Result<ImportedWrite, WarningKind> {
        self.add(key.as_bytes().len(), value.len())?;
        Ok(ImportedWrite::new(key, value))
    }
}

/// Reads the `history` member of a field: the entries of `login.password` on a Login, at most
/// [`MAX_HISTORY`] of them, in file order; everything else is counted as dropped.
fn read_history(
    history: &Json,
    carried: bool,
    tally: &mut Tally,
    ignored: &mut usize,
) -> Result<Vec<(Value, u64)>, WarningKind> {
    let entries = history.as_array().ok_or(WarningKind::MalformedEntry)?;
    if !carried {
        tally.history = tally.history.saturating_add(entries.len());
        return Ok(Vec::new());
    }
    let mut kept = Vec::new();
    for entry in entries {
        let members = entry.members().ok_or(WarningKind::MalformedEntry)?;
        *ignored = ignored.saturating_add(ignored_members(members, &HISTORY_MEMBERS));
        let value = typed_value(
            entry.get("value").ok_or(WarningKind::MalformedEntry)?,
            ignored,
        )?;
        let ms = entry
            .get("ms")
            .and_then(integer)
            .ok_or(WarningKind::MalformedEntry)?;
        let is_password = matches!(value.decode(), Ok(ValueRef::Text(text)) if !text.is_empty());
        if is_password && kept.len() < MAX_HISTORY {
            kept.push((value, ms));
        } else {
            tally.history = tally.history.saturating_add(1);
        }
    }
    Ok(kept)
}

/// Maps one entry of `items` to the writes of a new item, or says why it is skipped.
#[expect(
    clippy::too_many_lines,
    reason = "the per-item rules of ADR 0027 §6, kept together in the order the ADR lists them"
)]
fn map_item<R: CryptoRng + ?Sized>(
    entry: usize,
    item: &Json,
    rng: &mut R,
    tally: &mut Tally,
    ignored: &mut usize,
) -> Result<ImportedItem, WarningKind> {
    const BAD: WarningKind = WarningKind::MalformedEntry;
    let members = item.members().ok_or(BAD)?;
    *ignored = ignored.saturating_add(ignored_members(members, &ITEM_MEMBERS));
    let type_id = item
        .get("type")
        .and_then(integer)
        .and_then(|t| u16::try_from(t).ok())
        .ok_or(BAD)?;
    let fields = item.get("fields").and_then(Json::as_array).ok_or(BAD)?;
    if fields.len() > MAX_ITEM_FIELDS {
        return Err(WarningKind::OversizeEntry);
    }
    let trashed = match item.get("trashed") {
        None => false,
        Some(flag) => flag.as_bool().ok_or(BAD)?,
    };
    let created_ms = match item.get("created_ms") {
        None => None,
        Some(ms) => Some(integer(ms).ok_or(BAD)?),
    };
    let item_type = ItemType::from_id(type_id);
    let kind = item_type
        .supported()
        .filter(|t| t.is_user_item())
        .ok_or(WarningKind::UnsupportedItemType)?;

    let mut budget = Budget {
        writes: 0,
        bytes: SNAPSHOT_MARGIN,
    };
    let mut writes = Vec::with_capacity(fields.len().saturating_add(2));
    let mut keys: Vec<&str> = Vec::with_capacity(fields.len());
    let mut history = Vec::new();
    for field in fields {
        let members = field.members().ok_or(BAD)?;
        *ignored = ignored.saturating_add(ignored_members(members, &FIELD_MEMBERS));
        let key_text = field.get("key").and_then(Json::as_str).ok_or(BAD)?;
        let key = FieldKey::parse(key_text.as_bytes()).map_err(|_| BAD)?;
        keys.push(key_text);
        let value = typed_value(field.get("value").ok_or(BAD)?, ignored)?;
        if field
            .get("conflicts")
            .and_then(Json::as_array)
            .is_some_and(|others| !others.is_empty())
        {
            tally.collapsed = tally.collapsed.saturating_add(1);
        }
        if let Some(entries) = field.get("history") {
            let carried = key_text == LOGIN_PASSWORD && kind == SupportedType::Login;
            history.extend(read_history(entries, carried, tally, ignored)?);
        }
        if key_text == ITEM_TYPE || (key_text == IMPORT_CREATED_MS && created_ms.is_some()) {
            continue;
        }
        match check_carried(
            item_type,
            WriteMode::Import,
            key.as_bytes(),
            value.expose_secret(),
        ) {
            Ok(()) => writes.push(budget.take(key, value)?),
            Err(WriteError::NotWritable | WriteError::WrongItemType) => {
                tally.fields = tally.fields.saturating_add(1);
            }
            Err(_) => return Err(BAD),
        }
    }
    keys.sort_unstable();
    if keys.windows(2).any(|pair| matches!(pair, [a, b] if a == b)) {
        return Err(BAD);
    }
    // More than 50 history entries can only come from a repeated `login.password`, which the
    // duplicate check above has refused; the cap is kept here all the same.
    let overflow = history.len().saturating_sub(MAX_HISTORY);
    tally.history = tally.history.saturating_add(overflow);
    history.truncate(MAX_HISTORY);

    let type_key = FieldKey::parse(ITEM_TYPE.as_bytes()).map_err(|_| BAD)?;
    writes.push(budget.take(type_key, Value::enumeration(type_id))?);
    if let Some(ms) = created_ms {
        let key = FieldKey::parse(IMPORT_CREATED_MS.as_bytes()).map_err(|_| BAD)?;
        writes.push(budget.take(key, Value::u64(ms))?);
    }
    for (value, ms) in history {
        let id = ElementId::generate(rng);
        let value_key = id.key(LIST_PWHIST, ATTR_VALUE).map_err(|_| BAD)?;
        let ms_key = id.key(LIST_PWHIST, ATTR_MS).map_err(|_| BAD)?;
        writes.push(budget.take(value_key, value)?);
        writes.push(budget.take(ms_key, Value::u64(ms))?);
    }
    writes.sort_by(|a, b| a.key().as_bytes().cmp(b.key().as_bytes()));
    if writes
        .windows(2)
        .any(|pair| matches!(pair, [a, b] if a.key().as_bytes() == b.key().as_bytes()))
    {
        return Err(BAD);
    }
    check_create(
        item_type,
        WriteMode::Import,
        writes.iter().map(|w| {
            (
                WriteSource::Carried,
                w.key().as_bytes(),
                w.value().expose_secret(),
            )
        }),
    )
    .map_err(|_| BAD)?;
    Ok(ImportedItem::carried(entry, item_type, writes, trashed))
}

/// Imports a rizzy-vault plaintext JSON export (see the module docs).
pub(crate) fn import<R: CryptoRng + ?Sized>(
    input: &[u8],
    rng: &mut R,
    warnings: &mut Warnings,
    counts: &mut Counts,
) -> Result<Vec<ImportedItem>, ImportError> {
    let doc = json::parse(input, MAX_JSON_LEN)?;
    let members = doc.members().ok_or(ImportError::UnexpectedShape)?;
    if doc.get("format").and_then(Json::as_str) != Some(FORMAT) {
        return Err(ImportError::UnexpectedShape);
    }
    match doc.get("version") {
        Some(version) if integer(version) == Some(VERSION) => {}
        Some(_) => return Err(ImportError::UpdateRequired),
        None => return Err(ImportError::UnexpectedShape),
    }
    let items = doc
        .get("items")
        .and_then(Json::as_array)
        .ok_or(ImportError::UnexpectedShape)?;
    if items.len() > MAX_ENTRIES {
        return Err(ImportError::TooMany);
    }
    let root_ignored = ignored_members(members, &ROOT_MEMBERS);
    if root_ignored > 0 {
        counts.ignored_members = counts.ignored_members.saturating_add(root_ignored);
        warnings.push(None, WarningKind::UnknownMembersIgnored);
    }
    let mut out = Vec::new();
    for (entry, item) in items.iter().enumerate() {
        let mut tally = Tally::default();
        let mut ignored = 0usize;
        let mapped = map_item(entry, item, rng, &mut tally, &mut ignored);
        if ignored > 0 {
            counts.ignored_members = counts.ignored_members.saturating_add(ignored);
            warnings.push(Some(entry), WarningKind::UnknownMembersIgnored);
        }
        match mapped {
            Ok(imported) => {
                if tally.collapsed > 0 {
                    warnings.push(Some(entry), WarningKind::ConflictsCollapsed);
                }
                if tally.history > 0 {
                    warnings.push(Some(entry), WarningKind::HistoryDropped);
                }
                if tally.fields > 0 {
                    warnings.push(Some(entry), WarningKind::FieldSkipped);
                }
                counts.collapsed_conflicts =
                    counts.collapsed_conflicts.saturating_add(tally.collapsed);
                counts.dropped_history = counts.dropped_history.saturating_add(tally.history);
                counts.dropped_fields = counts.dropped_fields.saturating_add(tally.fields);
                out.push(imported);
            }
            Err(kind) => {
                counts.skipped_items = counts.skipped_items.saturating_add(1);
                warnings.push(Some(entry), kind);
            }
        }
    }
    Ok(out)
}
