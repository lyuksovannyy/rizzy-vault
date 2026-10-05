//! Plaintext export: JSON and CSV, behind the warning and the typed acknowledgement
//! ([ADR 0027] §3–§5; ROADMAP §4.2 "plaintext JSON/CSV with scary warning").
//!
//! # The acknowledgement (ADR 0027 §5)
//!
//! A plaintext export holds every secret of the vault, unencrypted. It is reachable only
//! through a call that takes a [`PlaintextExportAck`], and the only way to make one is
//! [`PlaintextExportAck::from_typed_phrase`] with exactly [`PLAINTEXT_EXPORT_PHRASE`]. Before
//! it asks for the phrase, every host shows [`PLAINTEXT_EXPORT_WARNING`] (for CSV, followed by
//! [`csv_export_warning`]). "No flag, setting or environment variable skips this, and `rv`
//! reads the phrase from the terminal, so a plaintext export never runs unattended": this
//! crate offers no other constructor, and an acknowledgement is consumed by the one export it
//! allows. The warning texts are the frozen English source; a translation keeps every
//! sentence.
//!
//! Each export also takes the permission of [`super::gate`]: a fresh re-authentication of the
//! account and, after the warning, a hold of 10 seconds (owner decision 2026-10-05). The
//! acknowledgement stays the ADR's; the gate is in addition to it.
//!
//! The plaintext goes to the host as **one zeroizing byte buffer**, allocated once at its
//! final size (the document is sized in a first pass, then written in a second), so no
//! reallocation leaves a copy behind (CRYPTO.md §12.2). Where the host writes it is ADR 0027
//! §5 "Output file", outside this crate.
//!
//! # JSON (ADR 0027 §3)
//!
//! UTF-8 without BOM, LF line endings, RFC 8259, members in this order:
//!
//! ```text
//! {"format":"rizzy-vault-plaintext-export","version":1,"exported_at":1790000000000,"items":[
//! {"id":"<32 lowercase hex>","type":1,"trashed":false,"created_ms":…,"modified_ms":…,"fields":[
//!   {"key":"item.name","value":{"text":"Bank"}},
//!   {"key":"login.password","value":{"text":"…"},
//!    "conflicts":[{"text":"…"}],"history":[{"value":{"text":"…"},"ms":…}]}]}
//! ]}
//! ```
//!
//! (The line breaks inside an item above are for reading; the writer puts the header, each
//! item and the closing `]}` on a line of its own.)
//!
//! - One entry per exported item of ADR 0027 §1: every live item, Active or Trashed, without
//!   the vault-settings item, ascending by id. An oversize item refuses the export, as it
//!   does the encrypted one ([`ClientError::ExportOversizeItems`]).
//! - `type` is the `item.type` Enum value; `created_ms` and `modified_ms` are ADR 0018 §9's;
//!   `fields` are ascending by key, displayed values only, a cleared field left out.
//! - **Typed values** (ADR 0018 §6): `{"text":s}`, `{"bytes":b64url}`, `{"bool":b}`,
//!   `{"u64":"<decimal>"}` (a string, beyond JavaScript's 2^53), `{"enum":n}`,
//!   `{"sort_key":b64url}`, and `{"raw":b64url}` (the whole value, type byte included) for any
//!   unsupported or malformed value, including Text that is not UTF-8. base64url is unpadded.
//! - `conflicts` lists the other current values; `history` exists only for `login.password`.
//! - No key material, id of another object, dot or device id appears. The document is not
//!   signed or encrypted.
//! - The writer refuses a document above the caps its reader (`rizzy_import::rizzy_json`)
//!   applies: 64 MiB, 4,000,000 JSON values, 100,000 items ([`ClientError::ExportTooLarge`]),
//!   "so every file it writes reads back" (ADR 0027 §6).
//!
//! # CSV (ADR 0027 §4)
//!
//! RFC 4180: UTF-8 without BOM, CRLF, every field quoted, one header row, one row per item.
//! Columns ([`csv_columns`]): `type,name,notes,favorite,tags,uris,login.username,
//! login.password,login.totp`, then every Card key and every Identity key of ADR 0018 §7 in
//! the §7 table's order, by key name. `type` is `login`, `note`, `card` or `identity` (other
//! types are left out); `tags` and `uris` are joined with LF inside the cell, in list order;
//! `favorite` is `true` or empty; a trashed item is left out.
//!
//! - **Lossy by design:** custom fields, password history, conflicts, unknown keys and
//!   unsupported values are not in CSV. [`VaultSync::csv_export_loss`] counts the affected
//!   items for the warning, before the user is asked for the phrase.
//! - **No cell rewriting.** A cell starting with `=`, `+`, `-` or `@` is written as is:
//!   prefixing it (the usual CSV-injection defence) would corrupt passwords. The warning says
//!   not to open the file in a spreadsheet.
//! - There is no reader for this form (ADR 0027 §6).
//!
//! # Readings (where ADR 0027 §3–§5 leaves a detail open)
//!
//! - **An item without a valid `item.type`** is written with `"type":0` (the invalid type id
//!   of ADR 0018 §8); the reader skips it as an unsupported type. **An item without a created
//!   or modified time** has the member left out.
//! - **`conflicts`** lists the current values that are not byte-identical to the displayed
//!   one (byte-identical values count as one value, ADR 0018 §6), in the register's order; a
//!   concurrent Cleared value is `{"raw":""}`.
//! - **`history`** is newest first, and leaves out cleared entries, which have no value.
//! - **N of the CSV warning** ([`CsvLoss::items_losing_data`]) counts the rows that lose
//!   something and the items left out whole (trashed items and items of another type): the
//!   frozen sentence names trashed items among what CSV leaves out, and the larger count is
//!   the one that does not understate a loss.
//! - **`import.created_ms`** is not a CSV column and is not counted as a loss: CSV carries no
//!   time of any item.
//! - **A fixed key of another item type** (a `card.number` on a Login, which a faulty client
//!   may have written) still goes to its column, so it is not lost.
//! - **The typed phrase** is compared exactly: no trimming, no case folding. A host strips
//!   only the line terminator of the line it read.
//!
//! [ADR 0027]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0027-export-payload.md

use std::collections::BTreeMap;

use rizzy_core::encoding::b64url_encode_into;
use rizzy_core::ids::ItemId;
use rizzy_core::item::key::FieldKeyRef;
use rizzy_core::item::order::{ListEntry, compare_list_entries};
use rizzy_core::item::schema::{
    ATTR_ORDER, ATTR_VALUE, Expected, FIXED_KEYS, IMPORT_CREATED_MS, ITEM_FAVORITE, ITEM_NAME,
    ITEM_NOTES, ITEM_TYPE, LIST_TAG, LIST_URI, LOGIN_PASSWORD, LOGIN_TOTP, LOGIN_USERNAME,
    read_value,
};
use rizzy_core::item::tag::tag_name;
use rizzy_core::item::types::{ItemType, SupportedType};
use rizzy_core::item::value::ValueRef;
use rizzy_core::secret::SecretBytes;
use rizzy_import::limits::{MAX_ENTRIES, MAX_JSON_LEN, MAX_NODES};
use rizzy_import::rizzy_json::{FORMAT, VERSION};
use rizzy_sync::record::{LiveSnapshot, SnapshotData};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use super::gate::PlaintextExportAuth;
use super::state;
use crate::error::ClientError;
use crate::sync::VaultSync;

/// The phrase the user types to allow a plaintext export (ADR 0027 §5).
pub const PLAINTEXT_EXPORT_PHRASE: &str = "EXPORT PLAINTEXT";

/// The warning every host shows before it asks for [`PLAINTEXT_EXPORT_PHRASE`] (ADR 0027 §5;
/// the ROADMAP's "scary warning"). Frozen English source; a translation keeps every sentence.
pub const PLAINTEXT_EXPORT_WARNING: &str = "This file will hold every password, one-time-code secret, card number and note of this vault, unencrypted. Anyone and any program that can read the file can read them all, including backup and cloud-sync tools and other users of this computer. rizzy-vault cannot protect, track or erase the file once it is written. Delete it as soon as you have used it. To keep a copy of your vault, use the encrypted export instead.";

/// What the CSV warning adds to [`PLAINTEXT_EXPORT_WARNING`], up to the count N (ADR 0027 §5
/// "CSV adds"). Frozen English source.
pub const CSV_EXPORT_WARNING_BEFORE_COUNT: &str = "Do not open this file in a spreadsheet program: a cell that begins with =, +, - or @ can run as a formula, and saving from a spreadsheet can change your passwords. CSV leaves out custom fields, password history, conflicting values and trashed items; ";

/// What follows the count N in the CSV warning (ADR 0027 §5 "CSV adds"). Frozen English
/// source.
pub const CSV_EXPORT_WARNING_AFTER_COUNT: &str = " items lose data. The JSON export is complete.";

/// The text the CSV export adds to [`PLAINTEXT_EXPORT_WARNING`], with N =
/// `items_losing_data` ([`CsvLoss::items_losing_data`]).
#[must_use]
pub fn csv_export_warning(items_losing_data: usize) -> String {
    format!("{CSV_EXPORT_WARNING_BEFORE_COUNT}{items_losing_data}{CSV_EXPORT_WARNING_AFTER_COUNT}")
}

/// The user's acknowledgement of [`PLAINTEXT_EXPORT_WARNING`]: proof that the phrase was
/// typed. It has one constructor and is consumed by the export it allows (module docs).
#[derive(Debug)]
pub struct PlaintextExportAck(());

impl PlaintextExportAck {
    /// The acknowledgement, if `typed` is exactly [`PLAINTEXT_EXPORT_PHRASE`]. The host shows
    /// the warning first and passes what the user typed, without its line terminator.
    ///
    /// # Errors
    /// [`ClientError::PlaintextExportNotAcknowledged`] for any other text.
    pub fn from_typed_phrase(typed: &str) -> Result<Self, ClientError> {
        if typed == PLAINTEXT_EXPORT_PHRASE {
            Ok(Self(()))
        } else {
            Err(ClientError::PlaintextExportNotAcknowledged)
        }
    }
}

/// What a CSV export of this vault loses (ADR 0027 §4 "Lossy by design"). Counts only.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CsvLoss {
    /// Rows the file will hold.
    pub rows: usize,
    /// Rows that lose something: a custom field, password history, a conflicting value, an
    /// unknown key or an unsupported value.
    pub lossy_rows: usize,
    /// Items left out whole: trashed items, and items of a type CSV has no name for.
    pub left_out: usize,
}

impl CsvLoss {
    /// N of the CSV warning: the items that lose data (module docs, "Readings").
    #[must_use]
    pub const fn items_losing_data(&self) -> usize {
        self.lossy_rows.saturating_add(self.left_out)
    }
}

/// The text columns of the CSV form that are a fixed key's displayed Text, in column order:
/// `name`, `notes`, the three Login keys, then every Card and Identity key in the ADR 0018 §7
/// table's order.
fn csv_text_keys() -> Vec<&'static str> {
    let mut keys = vec![
        ITEM_NAME,
        ITEM_NOTES,
        LOGIN_USERNAME,
        LOGIN_PASSWORD,
        LOGIN_TOTP,
    ];
    keys.extend(
        FIXED_KEYS
            .iter()
            .map(|(key, _)| *key)
            .filter(|key| key.starts_with("card.") || key.starts_with("identity.")),
    );
    keys
}

/// The CSV header row, in order (ADR 0027 §4).
#[must_use]
pub fn csv_columns() -> Vec<&'static str> {
    let mut columns = vec!["type", "name", "notes", "favorite", "tags", "uris"];
    columns.extend(csv_text_keys().into_iter().skip(2));
    columns
}

/// A writer that either measures a document or writes it into a buffer of the measured size.
struct Sink {
    /// The output; `None` while measuring.
    out: Option<Zeroizing<Vec<u8>>>,
    /// Bytes put so far.
    len: usize,
    /// JSON values put so far, as the reader counts them (`rizzy_import::json`).
    nodes: usize,
    /// Whether a write did not fit the buffer, or an encoding step failed.
    failed: bool,
}

impl Sink {
    /// A sink that only measures.
    const fn measuring() -> Self {
        Self {
            out: None,
            len: 0,
            nodes: 0,
            failed: false,
        }
    }

    /// A sink that writes into one zeroizing buffer of `len` bytes.
    fn writing(len: usize) -> Self {
        Self {
            out: Some(Zeroizing::new(Vec::with_capacity(len))),
            len: 0,
            nodes: 0,
            failed: false,
        }
    }

    /// Appends `bytes`. Never grows the buffer: a write past its capacity is recorded as a
    /// failure instead, so no reallocation can leave a copy of the plaintext behind.
    fn put(&mut self, bytes: &[u8]) {
        self.len = self.len.saturating_add(bytes.len());
        if let Some(out) = &mut self.out {
            if out.capacity().saturating_sub(out.len()) < bytes.len() {
                self.failed = true;
            } else {
                out.extend_from_slice(bytes);
            }
        }
    }

    /// The written document, if it is exactly `expected` bytes.
    fn finish(self, expected: usize) -> Result<SecretBytes, ClientError> {
        match self.out {
            Some(out) if !self.failed && out.len() == expected => {
                Ok(SecretBytes::from_zeroizing(out))
            }
            _ => Err(ClientError::Internal),
        }
    }

    /// The decimal digits of `value`.
    fn decimal(&mut self, mut value: u64) {
        let mut digits = Zeroizing::new([0u8; 20]);
        let mut at = digits.len();
        loop {
            at = at.saturating_sub(1);
            if let Some(slot) = digits.get_mut(at) {
                *slot = b'0' + u8::try_from(value % 10).unwrap_or(0);
            }
            value /= 10;
            if value == 0 {
                break;
            }
        }
        if let Some(text) = digits.get(at..) {
            self.put(text);
        }
    }

    /// `bytes` as base64url without padding, encoded through a wiped stack buffer.
    fn base64(&mut self, bytes: &[u8]) {
        let mut buffer = Zeroizing::new([0u8; 64]);
        // 48 bytes are 64 characters, and whole 3-byte groups concatenate without padding.
        for chunk in bytes.chunks(48) {
            match b64url_encode_into(chunk, buffer.as_mut_slice()) {
                Ok(text) => self.put(text.as_bytes()),
                Err(_) => self.failed = true,
            }
        }
    }

    /// A JSON number (one value).
    fn json_number(&mut self, value: u64) {
        self.nodes = self.nodes.saturating_add(1);
        self.decimal(value);
    }

    /// A JSON string (one value): `"`, `\` and the control characters below U+0020 escaped,
    /// everything else as its UTF-8.
    fn json_string(&mut self, text: &str) {
        self.nodes = self.nodes.saturating_add(1);
        self.put(b"\"");
        let bytes = text.as_bytes();
        let mut run = 0usize;
        for (at, byte) in bytes.iter().enumerate() {
            if *byte != b'"' && *byte != b'\\' && *byte >= 0x20 {
                continue;
            }
            if let Some(plain) = bytes.get(run..at) {
                self.put(plain);
            }
            run = at.saturating_add(1);
            match *byte {
                b'"' => self.put(b"\\\""),
                b'\\' => self.put(b"\\\\"),
                control => {
                    const HEX: &[u8; 16] = b"0123456789abcdef";
                    let high = HEX.get(usize::from(control >> 4)).copied().unwrap_or(b'0');
                    let low = HEX
                        .get(usize::from(control & 0x0F))
                        .copied()
                        .unwrap_or(b'0');
                    self.put(&[b'\\', b'u', b'0', b'0', high, low]);
                }
            }
        }
        if let Some(plain) = bytes.get(run..) {
            self.put(plain);
        }
        self.put(b"\"");
    }

    /// A JSON string holding `bytes` as base64url (one value).
    fn json_base64(&mut self, bytes: &[u8]) {
        self.nodes = self.nodes.saturating_add(1);
        self.put(b"\"");
        self.base64(bytes);
        self.put(b"\"");
    }

    /// A typed value object (ADR 0027 §3 "Typed values"): two values, the object and its
    /// member.
    fn json_value(&mut self, encoded: &[u8]) {
        self.nodes = self.nodes.saturating_add(1);
        match ValueRef::decode(encoded) {
            Ok(ValueRef::Text(text)) => {
                self.put(b"{\"text\":");
                self.json_string(text);
            }
            Ok(ValueRef::Bytes(bytes)) => {
                self.put(b"{\"bytes\":");
                self.json_base64(bytes);
            }
            Ok(ValueRef::Bool(flag)) => {
                self.nodes = self.nodes.saturating_add(1);
                self.put(if flag {
                    b"{\"bool\":true"
                } else {
                    b"{\"bool\":false"
                });
            }
            Ok(ValueRef::U64(value)) => {
                self.nodes = self.nodes.saturating_add(1);
                self.put(b"{\"u64\":\"");
                self.decimal(value);
                self.put(b"\"");
            }
            Ok(ValueRef::Enum(value)) => {
                self.put(b"{\"enum\":");
                self.json_number(u64::from(value));
            }
            Ok(ValueRef::SortKey(payload)) => {
                self.put(b"{\"sort_key\":");
                self.json_base64(payload);
            }
            // Unsupported or malformed, and a concurrent Cleared value in `conflicts`.
            Ok(ValueRef::Cleared) | Err(_) => {
                self.put(b"{\"raw\":");
                self.json_base64(encoded);
            }
        }
        self.put(b"}");
    }

    /// One item of the JSON form (module docs).
    fn json_item(&mut self, id: ItemId, live: &LiveSnapshot<'_>) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        // The item object, `id`, `type`, `trashed` and the `fields` array.
        self.nodes = self.nodes.saturating_add(5);
        self.put(b"{\"id\":\"");
        for byte in id.to_bytes() {
            let high = HEX.get(usize::from(byte >> 4)).copied().unwrap_or(b'0');
            let low = HEX.get(usize::from(byte & 0x0F)).copied().unwrap_or(b'0');
            self.put(&[high, low]);
        }
        self.put(b"\",\"type\":");
        self.decimal(u64::from(
            state::item_type(live).map_or(ItemType::INVALID.id(), ItemType::id),
        ));
        self.put(if state::trashed(live) == Some(true) {
            b",\"trashed\":true"
        } else {
            b",\"trashed\":false"
        });
        if let Some(ms) = state::created(live) {
            self.put(b",\"created_ms\":");
            self.json_number(ms);
        }
        if let Some(ms) = state::modified(live) {
            self.put(b",\"modified_ms\":");
            self.json_number(ms);
        }
        self.put(b",\"fields\":[");
        let mut first = true;
        for register in state::fields(live) {
            let Some(shown) = state::displayed(register) else {
                continue;
            };
            if shown.value.is_empty() {
                continue;
            }
            if !first {
                self.put(b",");
            }
            first = false;
            let key = register.key().expose_secret();
            // The field object.
            self.nodes = self.nodes.saturating_add(1);
            self.put(b"{\"key\":");
            self.json_string(key);
            self.put(b",\"value\":");
            self.json_value(shown.value);
            let others: Vec<&[u8]> = register
                .entries()
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != shown.index)
                .map(|(_, entry)| entry.value().expose_secret())
                .filter(|value| !bool::from(value.ct_eq(shown.value)))
                .collect();
            if !others.is_empty() {
                self.nodes = self.nodes.saturating_add(1);
                self.put(b",\"conflicts\":[");
                for (index, value) in others.iter().enumerate() {
                    if index > 0 {
                        self.put(b",");
                    }
                    self.json_value(value);
                }
                self.put(b"]");
            }
            if key == LOGIN_PASSWORD {
                self.json_history(live);
            }
            self.put(b"}");
        }
        self.put(b"]}");
    }

    /// The `history` member of `login.password`, newest first; nothing when it has none.
    fn json_history(&mut self, live: &LiveSnapshot<'_>) {
        let history: Vec<(&[u8], u64)> = state::password_history(live)
            .into_iter()
            .filter(|(value, _)| !value.is_empty())
            .collect();
        if history.is_empty() {
            return;
        }
        self.nodes = self.nodes.saturating_add(1);
        self.put(b",\"history\":[");
        for (index, (value, ms)) in history.iter().enumerate() {
            if index > 0 {
                self.put(b",");
            }
            // The entry object.
            self.nodes = self.nodes.saturating_add(1);
            self.put(b"{\"value\":");
            self.json_value(value);
            self.put(b",\"ms\":");
            self.json_number(*ms);
            self.put(b"}");
        }
        self.put(b"]");
    }

    /// The whole JSON document.
    fn json_document(&mut self, exported_at_ms: u64, items: &[(ItemId, LiveSnapshot<'_>)]) {
        // The root object, `format`, `version` and the `items` array.
        self.nodes = self.nodes.saturating_add(3);
        self.put(b"{\"format\":");
        self.json_string(FORMAT);
        self.put(b",\"version\":");
        self.decimal(VERSION);
        self.put(b",\"exported_at\":");
        self.json_number(exported_at_ms);
        self.put(b",\"items\":[\n");
        for (index, (id, live)) in items.iter().enumerate() {
            if index > 0 {
                self.put(b",\n");
            }
            self.json_item(*id, live);
        }
        if !items.is_empty() {
            self.put(b"\n");
        }
        self.put(b"]}\n");
    }

    /// One CSV cell: quoted, `"` doubled, `lines` joined with LF (RFC 4180).
    fn csv_cell(&mut self, lines: &[&str]) {
        self.put(b"\"");
        for (index, line) in lines.iter().enumerate() {
            if index > 0 {
                self.put(b"\n");
            }
            let mut rest = line.as_bytes();
            while let Some(at) = rest.iter().position(|b| *b == b'"') {
                let (plain, tail) = rest.split_at(at);
                self.put(plain);
                self.put(b"\"\"");
                rest = tail.get(1..).unwrap_or_default();
            }
            self.put(rest);
        }
        self.put(b"\"");
    }

    /// One CSV row of `cells`, each a list of lines, ended with CRLF.
    fn csv_row(&mut self, cells: &[&[&str]]) {
        for (index, cell) in cells.iter().enumerate() {
            if index > 0 {
                self.put(b",");
            }
            self.csv_cell(cell);
        }
        self.put(b"\r\n");
    }
}

/// One row of the CSV form, borrowed from the item's state.
struct CsvRow<'a> {
    /// `login`, `note`, `card` or `identity`.
    kind: &'static str,
    /// The text columns, parallel to [`csv_text_keys`]; `""` for a field without a value.
    text: Vec<&'a str>,
    /// Whether `item.favorite` displays true.
    favorite: bool,
    /// The tag names, in list order.
    tags: Vec<Zeroizing<String>>,
    /// The URIs, in list order.
    uris: Vec<&'a str>,
    /// Whether the item holds something CSV leaves out.
    lossy: bool,
}

/// One URI element while its attributes are collected.
#[derive(Default)]
struct UriParts<'a> {
    /// The `value` the element displays, if it is a Text.
    value: Option<&'a str>,
    /// The `order` the element displays.
    order: Option<&'a [u8]>,
}

/// The CSV row of one item; `None` for an item CSV leaves out (trashed, or of a type other
/// than Login, Secure Note, Card and Identity).
fn csv_row<'a>(live: &LiveSnapshot<'a>, keys: &[&'static str]) -> Option<CsvRow<'a>> {
    if state::trashed(live) != Some(false) {
        return None;
    }
    let kind = match state::item_type(live).and_then(ItemType::supported)? {
        SupportedType::Login => "login",
        SupportedType::SecureNote => "note",
        SupportedType::Card => "card",
        SupportedType::Identity => "identity",
        SupportedType::VaultSettings => return None,
    };
    let mut row = CsvRow {
        kind,
        text: vec![""; keys.len()],
        favorite: false,
        tags: Vec::new(),
        uris: Vec::new(),
        lossy: !state::password_history(live).is_empty(),
    };
    let mut uris: BTreeMap<&'a str, UriParts<'a>> = BTreeMap::new();
    for register in state::fields(live) {
        let key: &'a str = register.key().expose_secret();
        let Some(shown) = state::displayed(register) else {
            continue;
        };
        row.lossy |= shown.conflict;
        let value = shown.value;
        if key == ITEM_TYPE || key == IMPORT_CREATED_MS {
            continue;
        }
        if let Some(slot) = keys
            .iter()
            .position(|k| *k == key)
            .and_then(|column| row.text.get_mut(column))
        {
            match read_value(Expected::Text, value) {
                Some(ValueRef::Text(text)) => *slot = text,
                Some(_) => {}
                None => row.lossy = true,
            }
            continue;
        }
        if key == ITEM_FAVORITE {
            match read_value(Expected::Bool, value) {
                Some(ValueRef::Bool(flag)) => row.favorite = flag,
                Some(_) => {}
                None => row.lossy = true,
            }
            continue;
        }
        let parsed = FieldKeyRef::parse_str(key).ok();
        match parsed.map(|k| (k, k.list(), k.attribute())) {
            Some((tag, Some(LIST_TAG), None)) if !value.is_empty() => {
                match (tag_name(tag), read_value(Expected::TagMarker, value)) {
                    (Ok(name), Some(_)) => row.tags.push(name),
                    _ => row.lossy = true,
                }
            }
            Some((uri, Some(LIST_URI), Some(ATTR_VALUE))) if !value.is_empty() => {
                match (uri.element(), read_value(Expected::Text, value)) {
                    (Some(element), Some(ValueRef::Text(text))) => {
                        uris.entry(element).or_default().value = Some(text);
                    }
                    _ => row.lossy = true,
                }
            }
            Some((uri, Some(LIST_URI), Some(ATTR_ORDER))) => {
                if let Some(element) = uri.element() {
                    uris.entry(element).or_default().order = Some(value);
                }
            }
            // Custom fields, imported password history, shares, a URI's `match`, keys this
            // client does not know: not in CSV.
            _ => row.lossy |= !value.is_empty(),
        }
    }
    let mut listed: Vec<(ListEntry<'a>, &'a str)> = uris
        .into_iter()
        .filter_map(|(element, parts)| {
            Some((
                ListEntry {
                    order: parts.order,
                    element,
                },
                parts.value?,
            ))
        })
        .collect();
    listed.sort_by(|a, b| compare_list_entries(&a.0, &b.0));
    row.uris = listed.into_iter().map(|(_, value)| value).collect();
    Some(row)
}

/// Writes the CSV document into `sink` and returns what it loses.
fn csv_document(sink: &mut Sink, items: &[(ItemId, LiveSnapshot<'_>)]) -> CsvLoss {
    let keys = csv_text_keys();
    let header: Vec<[&str; 1]> = csv_columns().into_iter().map(|c| [c]).collect();
    let header: Vec<&[&str]> = header.iter().map(<[&str; 1]>::as_slice).collect();
    sink.csv_row(&header);
    let mut loss = CsvLoss::default();
    for (_, live) in items {
        let Some(row) = csv_row(live, &keys) else {
            loss.left_out = loss.left_out.saturating_add(1);
            continue;
        };
        loss.rows = loss.rows.saturating_add(1);
        if row.lossy {
            loss.lossy_rows = loss.lossy_rows.saturating_add(1);
        }
        let kind = [row.kind];
        let favorite = [if row.favorite { "true" } else { "" }];
        let tags: Vec<&str> = row.tags.iter().map(|t| t.as_str()).collect();
        let text: Vec<[&str; 1]> = row.text.iter().map(|t| [*t]).collect();
        let mut cells: Vec<&[&str]> = Vec::with_capacity(text.len() + 4);
        cells.push(&kind);
        cells.extend(text.iter().take(2).map(<[&str; 1]>::as_slice));
        cells.push(&favorite);
        cells.push(&tags);
        cells.push(&row.uris);
        cells.extend(text.iter().skip(2).map(<[&str; 1]>::as_slice));
        sink.csv_row(&cells);
    }
    loss
}

impl VaultSync {
    /// The live state of every exported item (ADR 0027 §1), ascending by id.
    ///
    /// # Errors
    /// [`ClientError::ExportOversizeItems`] while an item cannot be encoded
    /// ([`VaultSync::export_blockers`]); [`ClientError::Internal`].
    fn exported_states(&self) -> Result<Vec<(ItemId, LiveSnapshot<'_>)>, ClientError> {
        if !self.export_blockers().is_empty() {
            return Err(ClientError::ExportOversizeItems);
        }
        let mut states = Vec::new();
        for (id, merge) in self.exported_merges() {
            let Ok(Some(SnapshotData::Live(live))) = merge.snapshot_data() else {
                return Err(ClientError::Internal);
            };
            states.push((id, live));
        }
        Ok(states)
    }

    /// The plaintext JSON export of this vault (ADR 0027 §3; module docs), in one zeroizing
    /// buffer. `exported_at_ms` is the host's clock. Consumes the permission of
    /// [`ExportGate::authorize_plaintext`](super::gate::ExportGate::authorize_plaintext) (a fresh
    /// re-authentication and the hold after the warning, owner decision 2026-10-05) and the
    /// acknowledgement.
    ///
    /// # Errors
    /// [`ClientError::ExportOversizeItems`]; [`ClientError::ExportTooLarge`] for a document
    /// above a cap its reader applies; [`ClientError::Internal`].
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the permission and the acknowledgement are consumed by the one export they allow (ADR 0027 §5)"
    )]
    pub fn export_plaintext_json(
        &self,
        auth: PlaintextExportAuth,
        ack: PlaintextExportAck,
        exported_at_ms: u64,
    ) -> Result<SecretBytes, ClientError> {
        let PlaintextExportAck(()) = ack;
        auth.spend();
        let items = self.exported_states()?;
        if items.len() > MAX_ENTRIES {
            return Err(ClientError::ExportTooLarge);
        }
        let mut measure = Sink::measuring();
        measure.json_document(exported_at_ms, &items);
        if measure.len > MAX_JSON_LEN || measure.nodes > MAX_NODES {
            return Err(ClientError::ExportTooLarge);
        }
        let mut sink = Sink::writing(measure.len);
        sink.json_document(exported_at_ms, &items);
        sink.finish(measure.len)
    }

    /// What a CSV export of this vault would lose, for the warning the host shows before it
    /// asks for the phrase ([`csv_export_warning`]). Writes nothing.
    ///
    /// # Errors
    /// [`ClientError::ExportOversizeItems`]; [`ClientError::Internal`].
    pub fn csv_export_loss(&self) -> Result<CsvLoss, ClientError> {
        let items = self.exported_states()?;
        Ok(csv_document(&mut Sink::measuring(), &items))
    }

    /// The plaintext CSV export of this vault (ADR 0027 §4; module docs), in one zeroizing
    /// buffer. Consumes the permission and the acknowledgement, as
    /// [`VaultSync::export_plaintext_json`].
    ///
    /// # Errors
    /// [`ClientError::ExportOversizeItems`]; [`ClientError::Internal`].
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the permission and the acknowledgement are consumed by the one export they allow (ADR 0027 §5)"
    )]
    pub fn export_plaintext_csv(
        &self,
        auth: PlaintextExportAuth,
        ack: PlaintextExportAck,
    ) -> Result<SecretBytes, ClientError> {
        let PlaintextExportAck(()) = ack;
        auth.spend();
        let items = self.exported_states()?;
        let mut measure = Sink::measuring();
        csv_document(&mut measure, &items);
        let mut sink = Sink::writing(measure.len);
        csv_document(&mut sink, &items);
        sink.finish(measure.len)
    }
}

#[cfg(test)]
mod tests {
    use rizzy_core::ids::DeviceId;
    use rizzy_import::json::{self, Json};
    use rizzy_sync::dot::Dot;
    use rizzy_sync::hlc::Hlc;
    use rizzy_sync::record::{Entry, FieldKey, Register, Value};

    use super::*;

    /// One register entry of device `dev`.
    fn entry(dev: u8, seq: u64, ms: u64, value: &[u8]) -> Entry<'_> {
        Entry::new(
            Dot::new(DeviceId::from_bytes([dev; 16]), seq).unwrap(),
            Hlc::from_parts(ms, 0).unwrap(),
            Value::new(value),
        )
    }

    /// A register of a grammar key.
    fn register<'a>(key: &'a str, entries: Vec<Entry<'a>>) -> Register<'a> {
        Register::new(FieldKey::new(key).unwrap(), entries)
    }

    /// The `@lifecycle` register.
    fn lifecycle(value: &[u8]) -> Register<'_> {
        Register::new(FieldKey::LIFECYCLE, vec![entry(1, 1, 5_000, value)])
    }

    /// How many values the reader counts in `doc`.
    fn count(doc: &Json) -> usize {
        1 + match doc {
            Json::Array(items) => items.iter().map(count).sum(),
            Json::Object(members) => members.iter().map(|(_, value)| count(value)).sum(),
            _ => 0,
        }
    }

    /// Writes the JSON document of `items` the way the export does: measured, then written.
    fn json(items: &[(ItemId, LiveSnapshot<'_>)]) -> String {
        let mut measure = Sink::measuring();
        measure.json_document(1_790_000_000_000, items);
        let mut sink = Sink::writing(measure.len);
        sink.json_document(1_790_000_000_000, items);
        assert_eq!(sink.nodes, measure.nodes);
        let nodes = sink.nodes;
        let out = sink.finish(measure.len).unwrap();
        let text = String::from_utf8(out.expose_secret().to_vec()).unwrap();
        // The writer counts values exactly as the reader does, so its cap check is the
        // reader's.
        assert_eq!(
            count(&json::parse(text.as_bytes(), 1 << 20).unwrap()),
            nodes
        );
        text
    }

    #[test]
    fn json_document_is_the_adr_shape() {
        assert_eq!(
            json(&[]),
            "{\"format\":\"rizzy-vault-plaintext-export\",\"version\":1,\
             \"exported_at\":1790000000000,\"items\":[\n]}\n"
        );
        let text = |s: &str| [&[0x01], s.as_bytes()].concat();
        let (name, old, new, other, gone) = (
            text("Bank \"\\\u{7}\n\u{1f} é"),
            text("old"),
            text("new"),
            text("other"),
            text("gone"),
        );
        let u64_value = [&[0x04][..], &u64::MAX.to_be_bytes()].concat();
        let first = LiveSnapshot::new(
            vec![
                lifecycle(&[0x01]),
                register("a.bool", vec![entry(1, 1, 5_000, &[0x03, 0x00])]),
                register("a.bytes", vec![entry(1, 1, 5_000, &[0x02, 0xfb, 0xff])]),
                // Cleared: left out.
                register("a.cleared", vec![entry(1, 1, 5_000, &[])]),
                register("a.raw", vec![entry(1, 1, 5_000, &[0x7f, 0x00])]),
                register("a.sort", vec![entry(1, 1, 5_000, &[0x06, 0x80])]),
                register("a.u64", vec![entry(1, 1, 5_000, &u64_value)]),
                register(
                    "import.created_ms",
                    vec![entry(1, 1, 5_000, &[0x04, 0, 0, 0, 0, 0, 0, 0, 9])],
                ),
                register("item.name", vec![entry(1, 1, 5_000, &name)]),
                register("item.type", vec![entry(1, 1, 5_000, &[0x05, 0x00, 0x01])]),
                // A conflict: the higher HLC displays; the identical value is not listed, the
                // concurrent Cleared one is.
                register(
                    "login.password",
                    vec![
                        entry(1, 3, 7_000, &other),
                        entry(2, 1, 9_000, &new),
                        entry(3, 1, 8_000, &new),
                        entry(4, 1, 8_500, &[]),
                    ],
                ),
            ],
            vec![register(
                "login.password",
                vec![
                    entry(1, 1, 5_000, &old),
                    entry(1, 2, 6_000, &[]),
                    entry(5, 1, 6_500, &gone),
                ],
            )],
        );
        // A trashed item without a valid type or a created time.
        let second = LiveSnapshot::new(
            vec![
                lifecycle(&[0x02]),
                register("item.name", vec![entry(1, 1, 5_000, &[0x01])]),
            ],
            Vec::new(),
        );
        let doc = json(&[
            (ItemId::from_bytes([0xab; 16]), first),
            (ItemId::from_bytes([0xcd; 16]), second),
        ]);
        assert_eq!(
            doc,
            concat!(
                r#"{"format":"rizzy-vault-plaintext-export","version":1,"exported_at":1790000000000,"items":["#,
                "\n",
                r#"{"id":"abababababababababababababababab","type":1,"trashed":false,"created_ms":9,"modified_ms":9000,"fields":["#,
                r#"{"key":"a.bool","value":{"bool":false}},"#,
                r#"{"key":"a.bytes","value":{"bytes":"-_8"}},"#,
                r#"{"key":"a.raw","value":{"raw":"fwA"}},"#,
                r#"{"key":"a.sort","value":{"sort_key":"gA"}},"#,
                r#"{"key":"a.u64","value":{"u64":"18446744073709551615"}},"#,
                r#"{"key":"import.created_ms","value":{"u64":"9"}},"#,
                r#"{"key":"item.name","value":{"text":"Bank \"\\\u0007\u000a\u001f é"}},"#,
                r#"{"key":"item.type","value":{"enum":1}},"#,
                r#"{"key":"login.password","value":{"text":"new"},"#,
                r#""conflicts":[{"text":"other"},{"raw":""}],"#,
                r#""history":[{"value":{"text":"gone"},"ms":6500},{"value":{"text":"old"},"ms":5000}]}"#,
                "]},\n",
                r#"{"id":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","type":0,"trashed":true,"modified_ms":5000,"fields":["#,
                r#"{"key":"item.name","value":{"text":""}}"#,
                "]}\n]}\n",
            )
        );
        // The reader takes the first item and skips the second for its type.
        let read = rizzy_import::import(
            rizzy_import::Format::RizzyPlaintextJson,
            doc.as_bytes(),
            &mut <chacha20::ChaCha20Rng as rand_core::SeedableRng>::seed_from_u64(1),
        );
        let read = read.unwrap();
        assert_eq!(read.items.len(), 1);
        assert_eq!(read.counts.skipped_items, 1);
        assert_eq!(read.counts.collapsed_conflicts, 1);
    }

    #[test]
    fn a_sink_never_grows_its_buffer() {
        let mut sink = Sink::writing(4);
        sink.put(b"abcd");
        assert!(!sink.failed);
        sink.put(b"e");
        assert!(sink.failed);
        assert_eq!(sink.finish(4).unwrap_err(), ClientError::Internal);
        let mut short = Sink::writing(4);
        short.put(b"abc");
        assert_eq!(short.finish(4).unwrap_err(), ClientError::Internal);
        assert_eq!(
            Sink::measuring().finish(0).unwrap_err(),
            ClientError::Internal
        );
    }

    #[test]
    fn csv_cells_are_quoted_and_never_rewritten() {
        let mut sink = Sink::writing(64);
        sink.csv_row(&[&["=1+1"], &["a\"b\"\"c"], &[], &["x", "-y"], &["@z,\r\n"]]);
        let len = sink.len;
        assert_eq!(
            sink.finish(len).unwrap().expose_secret(),
            b"\"=1+1\",\"a\"\"b\"\"\"\"c\",\"\",\"x\n-y\",\"@z,\r\n\"\r\n"
        );
    }

    #[test]
    fn decimals_and_base64() {
        for value in [0u64, 7, 10, 1_790_000_000_000, u64::MAX] {
            let mut sink = Sink::writing(20);
            sink.decimal(value);
            let len = sink.len;
            assert_eq!(
                sink.finish(len).unwrap().expose_secret(),
                value.to_string().as_bytes()
            );
        }
        // Chunked encoding equals the one-shot encoding, at every length around the chunk.
        for len in [0usize, 1, 2, 3, 47, 48, 49, 50, 95, 96, 97, 1_000] {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 7).to_le_bytes()[0]).collect();
            let mut sink = Sink::writing(2 * len + 4);
            sink.base64(&bytes);
            let written = sink.len;
            assert_eq!(
                sink.finish(written).unwrap().expose_secret(),
                rizzy_core::encoding::b64url_encode(&bytes).as_bytes(),
                "{len}"
            );
        }
    }
}
