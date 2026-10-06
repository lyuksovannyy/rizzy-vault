//! Imported items: the field writes of one new item per entry, in the M1 item schema of
//! `rizzy-core` (ADR 0018 §6–§8), and the builder the format mappers fill.
//!
//! **What an imported item is.** The writes of an importer's new item
//! ([`WriteMode::Import`]): `item.type`, the fixed keys of the item's type, and the list
//! elements (URIs, custom fields, password history, tags) with element ids drawn from the
//! injected CSPRNG ([`ElementId::generate`]) and `order` sort keys spread evenly
//! ([`evenly_spaced`]) in source order. `rizzy-client` encodes them through the record layer
//! and encrypts them at once (ADR 0002 point 2); nothing here does I/O or crypto.
//!
//! **Checked before it leaves.** Every write passes [`check_create`] for an import, which
//! covers the key grammar, the 64 KiB value limit and the item type of each key. The writes
//! are sorted by key bytes with no duplicate (ADR 0018 §4). What else holds depends on where
//! the writes come from ([`ImportedItem::source`]):
//!
//! - **Another product's file** ([`WriteSource::Entered`]; the item builder below). This
//!   crate builds each value, so it is checked as an entered write: no empty Text and no blank
//!   field (ADR 0018 §6: "a create op writes no field the user left blank", so empty source
//!   values are simply not written). The item fits one create op: at most [`MAX_WRITES`]
//!   writes, with op data of at most [`MAX_OP_DATA_LEN`] (ADR 0018 §10). A list element that
//!   would break the op limits is dropped whole, with a warning: these mappers keep each item
//!   within one op, so that what is dropped is a whole element and is warned about.
//! - **Our own plaintext JSON export** ([`WriteSource::Carried`]; [`crate::rizzy_json`]). Keys
//!   and value bytes are copied from the file, unknown keys and unsupported values included
//!   (ADR 0027 §6). Such an item may exceed one op: it holds at most
//!   [`MAX_REGISTERS`](crate::limits::MAX_REGISTERS)` - 1` writes whose snapshot fits
//!   [`MAX_SNAPSHOT_DATA_LEN`](crate::limits::MAX_SNAPSHOT_DATA_LEN), and `rizzy-client`'s
//!   import path **splits** the writes over the create op and the ops that follow it
//!   (ADR 0027 §2 step 5: "`import_item` splits them into consecutive ops, as §6 'List order'
//!   already allows"), with `item.type` and `import.created_ms` in the first. It may also be
//!   trashed ([`ImportedItem::trashed`]): the client creates it, then trashes it in one more
//!   op.
//!
//! **Unmapped source fields** become custom fields (`field/<id>/…`, ADR 0018 §7): a text
//! field, or a hidden one where the source marks the value as concealed or secret, so the
//! concealed-by-default rule still holds for them. Nothing is appended to the notes: a custom
//! field keeps its label and concealment, and the notes do not.
//!
//! **Secrets.** Values are encoded once into `rizzy-core`'s zeroizing [`Value`], keys into
//! [`FieldKey`]; neither has `Clone`, and `Debug` prints neither (CRYPTO.md §12.2).

use rizzy_core::item::key::{ElementId, FieldKey, FieldKeyRef};
use rizzy_core::item::order::evenly_spaced;
use rizzy_core::item::schema::{
    ATTR_KIND, ATTR_LABEL, ATTR_MS, ATTR_ORDER, ATTR_VALUE, CustomFieldKind, IMPORT_CREATED_MS,
    ITEM_FAVORITE, ITEM_TYPE, KeyClass, LIST_FIELD, LIST_PWHIST, LIST_URI, WriteMode, WriteSource,
    check_create, classify,
};
use rizzy_core::item::tag::tag_key;
use rizzy_core::item::types::{ItemType, SupportedType};
use rizzy_core::item::value::Value;
use rizzy_core::rng::CryptoRng;

use crate::error::{WarningKind, Warnings};
use crate::limits::{
    MAX_CUSTOM_FIELDS, MAX_HISTORY, MAX_OP_DATA_LEN, MAX_TAGS, MAX_TEXT_LEN, MAX_URIS, MAX_WRITES,
};

/// One field write: a key and its encoded value. `Debug` prints neither.
#[derive(Debug)]
pub struct ImportedWrite {
    /// The field key.
    key: FieldKey,
    /// The encoded value (never Cleared).
    value: Value,
}

impl ImportedWrite {
    /// A write of `value` to `key`.
    pub(crate) fn new(key: FieldKey, value: Value) -> Self {
        Self { key, value }
    }

    /// The field key.
    #[must_use]
    pub fn key(&self) -> &FieldKey {
        &self.key
    }

    /// The encoded value, as the record layer writes it.
    #[must_use]
    pub fn value(&self) -> &Value {
        &self.value
    }

    /// The key and value.
    #[must_use]
    pub fn into_parts(self) -> (FieldKey, Value) {
        (self.key, self.value)
    }
}

/// One imported item: the writes of the new item. `Debug` prints no key or value, and not
/// whether the item is trashed.
pub struct ImportedItem {
    /// The entry's position in the file ([`crate::Warning::entry`]).
    entry: usize,
    /// The item's type.
    item_type: ItemType,
    /// The writes, sorted by key bytes, `item.type` among them.
    writes: Vec<ImportedWrite>,
    /// Where the writes come from: built here, or copied from our own export.
    source: WriteSource,
    /// Whether the item is trashed after it is created.
    trashed: bool,
}

impl core::fmt::Debug for ImportedItem {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ImportedItem")
            .field("entry", &self.entry)
            .finish_non_exhaustive()
    }
}

impl ImportedItem {
    /// An item whose writes were copied from a rizzy-vault plaintext export
    /// ([`WriteSource::Carried`]); `writes` are sorted by key bytes, without duplicates, and
    /// have passed [`check_create`].
    pub(crate) fn carried(
        entry: usize,
        item_type: ItemType,
        writes: Vec<ImportedWrite>,
        trashed: bool,
    ) -> Self {
        Self {
            entry,
            item_type,
            writes,
            source: WriteSource::Carried,
            trashed,
        }
    }

    /// Where the writes come from, for the writer check that `rizzy-client` repeats:
    /// [`WriteSource::Entered`] for another product's file, [`WriteSource::Carried`] for our
    /// own plaintext JSON export (see the module docs).
    #[must_use]
    pub fn source(&self) -> WriteSource {
        self.source
    }

    /// Whether the item is trashed once created: the client writes its create op (and the ops
    /// its writes are split over), then trashes it in one more op (ADR 0027 §2 step 3). Only
    /// an item of our own export can be; another product's deleted entries are skipped.
    #[must_use]
    pub fn trashed(&self) -> bool {
        self.trashed
    }

    /// The entry's position in the file, as warnings give it.
    #[must_use]
    pub fn entry(&self) -> usize {
        self.entry
    }

    /// The item's type.
    #[must_use]
    pub fn item_type(&self) -> ItemType {
        self.item_type
    }

    /// The new item's writes, strictly ascending by key bytes (ADR 0018 §4). One create op for
    /// an [`WriteSource::Entered`] item; possibly more than one op's worth for a
    /// [`WriteSource::Carried`] one (see the module docs).
    #[must_use]
    pub fn writes(&self) -> &[ImportedWrite] {
        &self.writes
    }

    /// The writes, by value.
    #[must_use]
    pub fn into_writes(self) -> Vec<ImportedWrite> {
        self.writes
    }
}

/// How a custom field is shown (ADR 0018 §7 `kind`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FieldKind {
    /// Kind 1: shown.
    Text,
    /// Kind 2: concealed by default.
    Hidden,
}

/// A custom field waiting for its element id.
struct PendingField {
    /// `label`, if not empty.
    label: Option<Value>,
    /// `kind`.
    kind: CustomFieldKind,
    /// `value`, never empty.
    value: Value,
}

/// Encoded size of one write in op data: `str(key) ‖ bytes(value)` (ADR 0018 §3, CRYPTO.md
/// §2: each with a `u32` length).
const fn write_len(key_len: usize, value_len: usize) -> usize {
    8 + key_len + value_len
}

/// Op data bytes before the writes: `record_kind`, `lifecycle`, `u16 n`.
const OP_HEADER_LEN: usize = 4;

/// Length of an element key `list/<32 hex digits>/attribute`.
const fn element_key_len(list: &str, attribute: &str) -> usize {
    list.len() + 1 + 32 + 1 + attribute.len()
}

/// Upper bound of an `order` value: type byte and a sort key of at most 4 bytes
/// ([`evenly_spaced`] uses 1 byte for up to 255 elements).
const ORDER_VALUE_LEN: usize = 5;

/// The label of the custom field a URI becomes on an item that is not a Login.
const URL_LABEL: &str = "URL";

/// `true` if `value` is the Text value `text`: its type byte, then the text's bytes.
fn is_text(value: &Value, text: &str) -> bool {
    value.len() == text.len() + 1 && value.expose_secret().get(1..) == Some(text.as_bytes())
}

/// Collects one entry's fields and turns them into an [`ImportedItem`].
pub(crate) struct ItemBuilder<'w> {
    /// The entry's position in the file.
    entry: usize,
    /// The item's type.
    kind: SupportedType,
    /// Where warnings go.
    warnings: &'w mut Warnings,
    /// Fixed keys and their values, at most one per key.
    fixed: Vec<(&'static str, Value)>,
    /// `item.favorite`.
    favorite: bool,
    /// `import.created_ms`.
    created_ms: Option<u64>,
    /// URIs, in source order.
    uris: Vec<Value>,
    /// Custom fields, in source order.
    fields: Vec<PendingField>,
    /// Password history: value and time.
    history: Vec<(Value, Option<u64>)>,
    /// Tag keys, without duplicates.
    tags: Vec<FieldKey>,
    /// Whether [`WarningKind::TooManyElements`] was recorded for this entry (once per entry).
    warned_full: bool,
}

impl<'w> ItemBuilder<'w> {
    /// Starts an item of type `kind` for the entry at `entry`.
    pub(crate) fn new(entry: usize, kind: SupportedType, warnings: &'w mut Warnings) -> Self {
        Self {
            entry,
            kind,
            warnings,
            fixed: Vec::new(),
            favorite: false,
            created_ms: None,
            uris: Vec::new(),
            fields: Vec::new(),
            history: Vec::new(),
            tags: Vec::new(),
            warned_full: false,
        }
    }

    /// The item's type.
    pub(crate) fn kind(&self) -> SupportedType {
        self.kind
    }

    /// Records a warning about this entry.
    pub(crate) fn warn(&mut self, kind: WarningKind) {
        self.warnings.push(Some(self.entry), kind);
    }

    /// Encodes `text` as a Text value, or warns and returns `None` if it is too long.
    fn text_value(&mut self, text: &str) -> Option<Value> {
        if text.len() > MAX_TEXT_LEN {
            self.warn(WarningKind::ValueTooLong);
            return None;
        }
        let value = Value::text(text).ok();
        if value.is_none() {
            self.warn(WarningKind::ValueTooLong);
        }
        value
    }

    /// `true` if the fixed key `key` belongs to this item's type.
    fn applies(&self, key: &str) -> bool {
        match FieldKeyRef::parse_str(key).map(classify) {
            Ok(KeyClass::Known(spec)) => spec.applies.includes(self.kind),
            _ => false,
        }
    }

    /// Sets the Text key `key` to `text`. Returns `false`, doing nothing, if the key does not
    /// belong to this type or is already set, so the caller can keep the value as a custom
    /// field instead. An empty `text` is not written (and counts as handled), and a too-long
    /// one is warned about.
    pub(crate) fn set(&mut self, key: &'static str, text: &str) -> bool {
        if !self.applies(key) || self.fixed.iter().any(|(k, _)| *k == key) {
            return false;
        }
        if text.is_empty() {
            return true;
        }
        if let Some(value) = self.text_value(text) {
            self.fixed.push((key, value));
        }
        true
    }

    /// As [`ItemBuilder::set`], but a value that cannot go to `key` becomes a custom field
    /// named `label`, hidden if `hidden`. An empty `text` is not written anywhere.
    pub(crate) fn set_or_field(
        &mut self,
        key: &'static str,
        label: &str,
        text: &str,
        hidden: bool,
    ) {
        if text.is_empty() {
            return;
        }
        if !self.set(key, text) {
            let kind = if hidden {
                FieldKind::Hidden
            } else {
                FieldKind::Text
            };
            self.add_field(label, kind, text);
        }
    }

    /// As [`ItemBuilder::set_or_field`], but a repeat of an already-set `key` **replaces** its
    /// value instead of falling back to a custom field: last write wins, not first. Used only
    /// where the source format's own importer resolves a duplicate single-value key this way
    /// (`AliasVault`'s `.avux`, module docs of [`crate::aliasvault`]) rather than by import
    /// order, which `set_or_field` already gives every other format. An empty `text` is not
    /// written anywhere, same as `set_or_field`.
    pub(crate) fn set_or_field_last(
        &mut self,
        key: &'static str,
        label: &str,
        text: &str,
        hidden: bool,
    ) {
        if text.is_empty() {
            return;
        }
        if self.applies(key) {
            if let Some(value) = self.text_value(text) {
                self.fixed.retain(|(k, _)| *k != key);
                self.fixed.push((key, value));
            }
            return;
        }
        let kind = if hidden {
            FieldKind::Hidden
        } else {
            FieldKind::Text
        };
        self.add_field(label, kind, text);
    }

    /// `true` if the fixed key `key` has a value.
    pub(crate) fn has(&self, key: &str) -> bool {
        self.fixed.iter().any(|(k, _)| *k == key)
    }

    /// Sets `item.favorite`.
    pub(crate) fn set_favorite(&mut self, favorite: bool) {
        self.favorite = favorite;
    }

    /// Sets `import.created_ms` from a time the caller read, or warns that it was unreadable.
    pub(crate) fn set_created_ms(&mut self, ms: Option<u64>) {
        match ms {
            Some(ms) => self.created_ms = Some(ms),
            None => self.warn(WarningKind::InvalidTimestamp),
        }
    }

    /// Warns once when a list is full; returns `true` if it is.
    fn full(&mut self, len: usize, cap: usize) -> bool {
        if len < cap {
            return false;
        }
        if !self.warned_full {
            self.warned_full = true;
            self.warn(WarningKind::TooManyElements);
        }
        true
    }

    /// Adds a URI (Login only; on other types it becomes a text custom field labelled `URL`).
    /// Empty values and exact duplicates are skipped, on every type.
    pub(crate) fn add_uri(&mut self, uri: &str) {
        if uri.is_empty() {
            return;
        }
        if self.kind != SupportedType::Login {
            let duplicate = self.fields.iter().any(|f| {
                f.kind == CustomFieldKind::Text
                    && f.label.as_ref().is_some_and(|l| is_text(l, URL_LABEL))
                    && is_text(&f.value, uri)
            });
            if !duplicate {
                self.add_field(URL_LABEL, FieldKind::Text, uri);
            }
            return;
        }
        if self.uris.iter().any(|u| is_text(u, uri)) {
            return;
        }
        if self.full(self.uris.len(), MAX_URIS) {
            return;
        }
        if let Some(value) = self.text_value(uri) {
            self.uris.push(value);
        }
    }

    /// Adds a text or hidden custom field. Skipped if the value is empty: a label alone is not
    /// content, and every CSV column would otherwise leave one on every row.
    pub(crate) fn add_field(&mut self, label: &str, kind: FieldKind, value: &str) {
        if value.is_empty() {
            return;
        }
        if self.full(self.fields.len(), MAX_CUSTOM_FIELDS) {
            return;
        }
        let label = if label.is_empty() {
            None
        } else {
            match self.text_value(label) {
                Some(v) => Some(v),
                None => return,
            }
        };
        let Some(value) = self.text_value(value) else {
            return;
        };
        let kind = match kind {
            FieldKind::Text => CustomFieldKind::Text,
            FieldKind::Hidden => CustomFieldKind::Hidden,
        };
        self.fields.push(PendingField { label, kind, value });
    }

    /// Adds a boolean custom field.
    pub(crate) fn add_bool_field(&mut self, label: &str, value: bool) {
        if self.full(self.fields.len(), MAX_CUSTOM_FIELDS) {
            return;
        }
        let label = if label.is_empty() {
            None
        } else {
            match self.text_value(label) {
                Some(v) => Some(v),
                None => return,
            }
        };
        self.fields.push(PendingField {
            label,
            kind: CustomFieldKind::Boolean,
            value: Value::bool(value),
        });
    }

    /// Adds a password-history entry (Login only; on other types it is warned about and
    /// skipped, since `pwhist/…` belongs to logins, ADR 0018 §7). Empty values are skipped.
    pub(crate) fn add_history(&mut self, password: &str, ms: Option<u64>) {
        if password.is_empty() {
            return;
        }
        if self.kind != SupportedType::Login {
            self.warn(WarningKind::FieldSkipped);
            return;
        }
        if self.full(self.history.len(), MAX_HISTORY) {
            return;
        }
        if let Some(value) = self.text_value(password) {
            self.history.push((value, ms));
        }
    }

    /// Adds a tag (a folder, group or collection is one too; folders are a UI over `/` in tag
    /// names, ADR 0018 §7). An invalid name is warned about and skipped; duplicates are
    /// skipped; leading and trailing whitespace is trimmed and an empty name is skipped.
    pub(crate) fn add_tag(&mut self, name: &str) {
        let name = name.trim();
        if name.is_empty() {
            return;
        }
        match tag_key(name) {
            Ok(key) => {
                if self.tags.iter().any(|t| t.as_bytes() == key.as_bytes()) {
                    return;
                }
                if self.full(self.tags.len(), MAX_TAGS) {
                    return;
                }
                self.tags.push(key);
            }
            Err(_) => self.warn(WarningKind::InvalidTag),
        }
    }

    /// Builds the item: `item.type`, the fixed keys, then as many list elements as fit one
    /// create op, in the order URIs, custom fields, password history, tags. Returns `None`,
    /// with a warning, for an entry with nothing but its type.
    pub(crate) fn finish<R: CryptoRng + ?Sized>(self, rng: &mut R) -> Option<ImportedItem> {
        let item_type = self.kind.item_type();
        let entry = self.entry;
        let Self {
            warnings,
            fixed,
            favorite,
            created_ms,
            uris,
            fields,
            history,
            tags,
            ..
        } = self;
        let mut out = Output {
            writes: Vec::new(),
            count: 0,
            bytes: OP_HEADER_LEN,
            over: false,
        };
        let has_content = !fixed.is_empty()
            || favorite
            || !uris.is_empty()
            || !fields.is_empty()
            || !history.is_empty()
            || !tags.is_empty();
        if !has_content {
            warnings.push(Some(entry), WarningKind::EmptyEntry);
            return None;
        }
        out.fixed(ITEM_TYPE, Value::enumeration(item_type.id()));
        for (key, value) in fixed {
            out.fixed(key, value);
        }
        if favorite {
            out.fixed(ITEM_FAVORITE, Value::bool(true));
        }
        if let Some(ms) = created_ms {
            out.fixed(IMPORT_CREATED_MS, Value::u64(ms));
        }
        out.uris(uris, rng);
        out.fields(fields, rng);
        out.history(history, rng);
        out.tags(tags);
        if out.over {
            warnings.push(Some(entry), WarningKind::ItemTooLarge);
        }
        let mut writes = out.writes;
        writes.sort_by(|a, b| a.key.as_bytes().cmp(b.key.as_bytes()));
        writes.dedup_by(|a, b| a.key.as_bytes() == b.key.as_bytes());
        let checked = check_create(
            item_type,
            WriteMode::Import,
            writes.iter().map(|w| {
                (
                    WriteSource::Entered,
                    w.key.as_bytes(),
                    w.value.expose_secret(),
                )
            }),
        );
        if checked.is_err() || writes.len() > MAX_WRITES {
            warnings.push(Some(entry), WarningKind::MalformedEntry);
            return None;
        }
        Some(ImportedItem {
            entry,
            item_type,
            writes,
            source: WriteSource::Entered,
            trashed: false,
        })
    }
}

/// The writes being assembled, with the op budget: writes and op-data bytes, counted when an
/// element is accepted, before its element id is drawn.
struct Output {
    /// Writes so far.
    writes: Vec<ImportedWrite>,
    /// Writes accepted so far, placed or not.
    count: usize,
    /// Op data bytes accepted so far (an upper bound: `order` values are counted at their
    /// largest).
    bytes: usize,
    /// Whether an element was dropped for the budget.
    over: bool,
}

impl Output {
    /// `true` if `writes` more writes of `bytes` more op-data bytes fit; otherwise records that
    /// something was dropped.
    fn fits(&mut self, writes: usize, bytes: usize) -> bool {
        if self.count + writes <= MAX_WRITES && self.bytes + bytes <= MAX_OP_DATA_LEN {
            true
        } else {
            self.over = true;
            false
        }
    }

    /// Adds one write, counting its bytes. The caller has checked [`Output::fits`] where the
    /// write may not fit.
    fn push(&mut self, key: FieldKey, value: Value) {
        self.reserve(1, write_len(key.as_bytes().len(), value.len()));
        self.place(key, value);
    }

    /// Accepts `writes` writes of `bytes` op-data bytes, placed later by [`Output::place`].
    fn reserve(&mut self, writes: usize, bytes: usize) {
        self.count += writes;
        self.bytes += bytes;
    }

    /// Adds a write that was accepted with [`Output::reserve`].
    fn place(&mut self, key: FieldKey, value: Value) {
        self.writes.push(ImportedWrite { key, value });
    }

    /// Adds a fixed key. The fixed keys of one item are at most about 35 values of at most
    /// 64 KiB each, which could pass 1 MiB only for a crafted entry: then the key is dropped.
    fn fixed(&mut self, key: &str, value: Value) {
        if !self.fits(1, write_len(key.len(), value.len())) {
            return;
        }
        if let Ok(key) = FieldKey::parse(key.as_bytes()) {
            self.push(key, value);
        }
    }

    /// The element key `list/<id>/attribute`, if it builds (it always does for the lists and
    /// attributes used here).
    fn key(id: &ElementId, list: &str, attribute: &str) -> Option<FieldKey> {
        id.key(list, attribute).ok()
    }

    /// Adds the URIs that fit, each with its `order`.
    fn uris<R: CryptoRng + ?Sized>(&mut self, uris: Vec<Value>, rng: &mut R) {
        let value_key = element_key_len(LIST_URI, ATTR_VALUE);
        let order_key = element_key_len(LIST_URI, ATTR_ORDER);
        let kept: Vec<Value> = uris
            .into_iter()
            .filter(|v| {
                let size = write_len(value_key, v.len()) + write_len(order_key, ORDER_VALUE_LEN);
                let fits = self.fits(2, size);
                if fits {
                    self.reserve(2, size);
                }
                fits
            })
            .collect();
        let Ok(orders) = evenly_spaced(kept.len()) else {
            return;
        };
        for (value, order) in kept.into_iter().zip(orders) {
            let id = ElementId::generate(rng);
            if let (Some(vk), Some(ok)) = (
                Self::key(&id, LIST_URI, ATTR_VALUE),
                Self::key(&id, LIST_URI, ATTR_ORDER),
            ) {
                self.place(vk, value);
                self.place(ok, Value::sort_key(&order));
            }
        }
    }

    /// Adds the custom fields that fit, each with its `kind` and `order`.
    fn fields<R: CryptoRng + ?Sized>(&mut self, fields: Vec<PendingField>, rng: &mut R) {
        let label_key = element_key_len(LIST_FIELD, ATTR_LABEL);
        let kind_key = element_key_len(LIST_FIELD, ATTR_KIND);
        let value_key = element_key_len(LIST_FIELD, ATTR_VALUE);
        let order_key = element_key_len(LIST_FIELD, ATTR_ORDER);
        let kept: Vec<PendingField> = fields
            .into_iter()
            .filter(|f| {
                let mut writes = 3;
                // `kind` is an Enum: type byte and two bytes.
                let mut size = write_len(kind_key, 3)
                    + write_len(order_key, ORDER_VALUE_LEN)
                    + write_len(value_key, f.value.len());
                if let Some(label) = &f.label {
                    writes += 1;
                    size += write_len(label_key, label.len());
                }
                let fits = self.fits(writes, size);
                if fits {
                    self.reserve(writes, size);
                }
                fits
            })
            .collect();
        let Ok(orders) = evenly_spaced(kept.len()) else {
            return;
        };
        for (field, order) in kept.into_iter().zip(orders) {
            let id = ElementId::generate(rng);
            let Some(kind_id) = field.kind.id() else {
                continue;
            };
            let (Some(kk), Some(ok)) = (
                Self::key(&id, LIST_FIELD, ATTR_KIND),
                Self::key(&id, LIST_FIELD, ATTR_ORDER),
            ) else {
                continue;
            };
            if let (Some(label), Some(lk)) = (field.label, Self::key(&id, LIST_FIELD, ATTR_LABEL)) {
                self.place(lk, label);
            }
            if let Some(vk) = Self::key(&id, LIST_FIELD, ATTR_VALUE) {
                self.place(vk, field.value);
            }
            self.place(kk, Value::enumeration(kind_id));
            self.place(ok, Value::sort_key(&order));
        }
    }

    /// Adds the password-history entries that fit, each with its `ms` if known.
    fn history<R: CryptoRng + ?Sized>(&mut self, history: Vec<(Value, Option<u64>)>, rng: &mut R) {
        let value_key = element_key_len(LIST_PWHIST, ATTR_VALUE);
        let ms_key = element_key_len(LIST_PWHIST, ATTR_MS);
        for (value, ms) in history {
            let mut writes = 1;
            let mut size = write_len(value_key, value.len());
            if ms.is_some() {
                writes += 1;
                // U64: type byte and eight bytes.
                size += write_len(ms_key, 9);
            }
            if !self.fits(writes, size) {
                continue;
            }
            let id = ElementId::generate(rng);
            if let Some(vk) = Self::key(&id, LIST_PWHIST, ATTR_VALUE) {
                self.push(vk, value);
            }
            if let (Some(ms), Some(mk)) = (ms, Self::key(&id, LIST_PWHIST, ATTR_MS)) {
                self.push(mk, Value::u64(ms));
            }
        }
    }

    /// Adds the tags that fit.
    fn tags(&mut self, tags: Vec<FieldKey>) {
        for key in tags {
            // Bool: type byte and one byte.
            if self.fits(1, write_len(key.as_bytes().len(), 2)) {
                self.push(key, Value::bool(true));
            }
        }
    }
}
