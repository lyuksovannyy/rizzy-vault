// SPDX-License-Identifier: AGPL-3.0-only

//! The M3 local index ([ADR 0056]): the cleartext `item_index` table of the cache, what it
//! holds, how it is kept, and the client-side search over it.
//!
//! # What a row holds (§2)
//!
//! One row per non-tombstoned, user-visible item (Active or Trashed, never the vault-settings
//! item, type `0xF001`): `item_id`, `vault_id` and `item_type` locate it, `display_name` and
//! `search_text` are built by [`project`] from a **closed allow-list** of field keys, and
//! `last_used_ms`/`use_count` are device-local counters set only by [`record_use`].
//!
//! | Type | Indexed (besides `item.name` as `display_name`) |
//! |---|---|
//! | Login | `login.username`, every `uri/<id>/value`, tags, text custom fields |
//! | Secure Note | tags, text custom fields (never `item.notes`: owner answer 1) |
//! | Card | `card.holder`, `card.brand`, tags, text custom fields |
//! | Identity | `identity.title`, `.first_name`, `.middle_name`, `.last_name`, `.company`, `.email`, tags, text custom fields |
//! | Any other type (the M3 types of ADR 0055, an unknown or no valid type) | nothing: `item.name` only (owner answer 5) |
//!
//! "Tags" are the decoded names of the item's displayed `tag/<hex>` elements, the only
//! key-derived content (INV-80); "text custom fields" are `field/<id>/label` and `/value` of a
//! custom field whose `kind` displays 1 (a hidden, boolean or unknown kind contributes nothing,
//! its label included). Only displayed Text values count; a field the merge shows Cleared, or
//! holding another value type, is skipped. Every other key is never read for the index:
//! `login.password`, `login.totp`, `pwhist/*`, `identity.drivers_license`, `item.notes`,
//! hidden custom fields and every key ADR 0055 adds included.
//!
//! Both columns are lower-cased in Rust (`str::to_lowercase`, §5) when they are built. The
//! parts of `search_text` are joined by [`SEPARATOR`], a fixed byte that carries no content; it
//! keeps two adjacent values from forming a match neither holds. A column longer than its cap
//! ([`MAX_DISPLAY_NAME_LEN`], [`MAX_SEARCH_TEXT_LEN`]) is cut at the last character boundary
//! within it, so a stored row always fits the length check a host makes before reading it.
//!
//! # Storage (§3)
//!
//! Every column is cleartext: no envelope, no AAD, no purpose. `LOCAL_CACHE_INDEX` and the local
//! index key stay reserved and unused; this module adds no cryptography. The table is part of
//! cache format 3 ([`super::rows::ITEM_INDEX_TABLE`]); a future migration of it drops and
//! rebuilds it rather than copying its rows ([`Write::IndexReset`]).
//!
//! # How it is kept (§4)
//!
//! - **Built at load.** [`reconcile`] projects every item of every loaded vault from the merge
//!   the load already computed, compares the result with the stored rows and returns the writes
//!   that make them equal; `last_used_ms`/`use_count` of a row that stays are kept. It also
//!   turns tracking on in each vault driver.
//! - **Kept incrementally.** With tracking on, [`VaultSync::take_writes`] appends to the
//!   changeset of each step the [`Write::IndexPut`]/[`Write::IndexDelete`] writes of the items
//!   whose projection changed, so they commit in the same transaction as the ops or snapshots
//!   that changed them; a purge deletes the row.
//! - **Its own failure rule.** A stored row that does not parse ([`IndexRow::parse`]), or a
//!   table the host could not read ([`CacheRows::item_index_unreadable`]), makes [`reconcile`]
//!   drop and rebuild this table alone from the merge. It never fails the load.
//! - **User-triggered rebuild.** [`reindex`] (`rv cache reindex`) drops and rebuilds it.
//!
//! # Search (§5)
//!
//! [`SEARCH`] is the query a `SQLite` host runs: a lower-cased substring match over
//! `display_name` and `search_text` (`LIKE '%term%'`, the term escaped by [`like_pattern`] and
//! lower-cased in Rust, never through `SQLite`'s ASCII-only `lower()`), ordered by
//! `last_used_ms`, most recent first, then by `display_name` and `item_id`. An empty query
//! matches every row, so it is the "recently used" order. [`RECENT`] lists only rows that
//! were used. [`search`] and [`recent`] are the same queries over [`CacheRows`]: the
//! reference a host's SQL is tested against, and the executor of a host without `SQLite`.
//!
//! # Privacy bounds
//!
//! `last_used_ms` and `use_count` are set only when the user views an item, copies a field from
//! it or autofills it; they are never read from a sync op, never uploaded and never compared
//! across devices. They are lost with the row: on a purge, a corrupt table, a [`reindex`] or the
//! loss of the cache. Neither `display_name` nor `search_text` is ever written to a log, an
//! error or `Debug` output: every type here redacts them.
//!
//! [ADR 0056]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0056-local-index-recently-used-search.md

use std::collections::BTreeMap;

use core::fmt;

use rizzy_core::ids::ItemId;
use rizzy_core::item::key::FieldKey;
use rizzy_core::item::schema::{
    ATTR_KIND, ATTR_LABEL, ATTR_VALUE, CARD_BRAND, CARD_HOLDER, CustomFieldKind, IDENTITY_COMPANY,
    IDENTITY_EMAIL, IDENTITY_FIRST_NAME, IDENTITY_LAST_NAME, IDENTITY_MIDDLE_NAME, IDENTITY_TITLE,
    ITEM_NAME, LIST_FIELD, LIST_TAG, LIST_URI, LOGIN_USERNAME,
};
use rizzy_core::item::tag::tag_name;
use rizzy_core::item::types::{ItemType, SupportedType};
use rizzy_core::item::value::{MAX_VALUE_LEN, ValueRef};
use rizzy_sync::merge::ItemLifecycle;
use zeroize::Zeroizing;

use crate::error::ClientError;
use crate::store::rows::{CacheRows, Changeset, Write};
use crate::sync::VaultSync;

/// The byte between two parts of `search_text` (module docs).
pub const SEPARATOR: char = '\n';

/// The most bytes of `item_index.display_name`: twice the largest field value, which covers
/// what lower-casing an `item.name` can add (a character grows by at most half its length).
pub const MAX_DISPLAY_NAME_LEN: usize = 2 * MAX_VALUE_LEN;

/// The most bytes of `item_index.search_text` (1 MiB). An item whose allow-listed fields add up
/// to more is indexed by the first 1 MiB of them.
pub const MAX_SEARCH_TEXT_LEN: usize = 1 << 20;

/// The query a `SQLite` host runs for a search (module docs, "Search"). `?1` is
/// [`like_pattern`] of the query, `?2` the most rows to return. Constant text with bound
/// parameters (INV-53).
pub const SEARCH: &str = "SELECT item_id FROM item_index \
     WHERE display_name LIKE ?1 ESCAPE '\\' OR search_text LIKE ?1 ESCAPE '\\' \
     ORDER BY last_used_ms IS NULL, last_used_ms DESC, display_name, item_id LIMIT ?2";

/// The query a `SQLite` host runs for the "recently used" list: the rows with a
/// `last_used_ms`, most recent first. `?1` is the most rows to return.
pub const RECENT: &str = "SELECT item_id FROM item_index WHERE last_used_ms IS NOT NULL \
     ORDER BY last_used_ms DESC, display_name, item_id LIMIT ?1";

/// One row as [`project`] builds it: everything but the counters.
#[derive(Clone, PartialEq, Eq)]
pub struct IndexEntry {
    /// The item.
    pub item_id: [u8; 16],
    /// Its vault.
    pub vault_id: [u8; 16],
    /// The id of its displayed `item.type`, `0` for an item without a valid type.
    pub item_type: u16,
    /// `item.name`, lower-cased. User content.
    pub display_name: Zeroizing<String>,
    /// The other allow-listed values, lower-cased and joined by [`SEPARATOR`]. User content.
    pub search_text: Zeroizing<String>,
}

impl fmt::Debug for IndexEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IndexEntry([REDACTED])")
    }
}

/// One `item_index` row as the host read it back: untrusted input, parsed by
/// [`IndexRow::parse`]. The encodings are those of the rest of the cache (16-byte ids, a
/// `u64` as its 8-byte big-endian `BLOB`); the two text columns are their UTF-8 bytes.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct IndexRow {
    /// `item_id`.
    pub item_id: Vec<u8>,
    /// `vault_id`.
    pub vault_id: Vec<u8>,
    /// `item_type`.
    pub item_type: i64,
    /// `display_name`. User content; wiped on drop.
    pub display_name: Zeroizing<Vec<u8>>,
    /// `search_text`. User content; wiped on drop.
    pub search_text: Zeroizing<Vec<u8>>,
    /// `last_used_ms`, if the item was used on this device.
    pub last_used_ms: Option<Vec<u8>>,
    /// `use_count`.
    pub use_count: i64,
}

impl fmt::Debug for IndexRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IndexRow([REDACTED])")
    }
}

/// A stored row that parsed: its entry and its counters.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredEntry {
    /// The row without its counters.
    pub entry: IndexEntry,
    /// When the item was last used on this device, in ms since the Unix epoch.
    pub last_used_ms: Option<u64>,
    /// How many times it was used on this device.
    pub use_count: u64,
}

impl fmt::Debug for StoredEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StoredEntry([REDACTED])")
    }
}

impl IndexRow {
    /// The row of `entry` with fresh counters, as a host writes it for a new item.
    #[must_use]
    pub fn new(entry: &IndexEntry) -> Self {
        Self {
            item_id: entry.item_id.to_vec(),
            vault_id: entry.vault_id.to_vec(),
            item_type: i64::from(entry.item_type),
            display_name: Zeroizing::new(entry.display_name.as_bytes().to_vec()),
            search_text: Zeroizing::new(entry.search_text.as_bytes().to_vec()),
            last_used_ms: None,
            use_count: 0,
        }
    }

    /// Parses the row: 16-byte ids, a `u16` type, two UTF-8 columns within their caps, an
    /// 8-byte `last_used_ms` or none, a non-negative `use_count`.
    ///
    /// # Errors
    /// [`ClientError::CacheCorrupt`] for any other row. The caller rebuilds the table
    /// ([`reconcile`]); nothing else of the load depends on it.
    pub fn parse(&self) -> Result<StoredEntry, ClientError> {
        let corrupt = ClientError::CacheCorrupt;
        let item_id = <[u8; 16]>::try_from(self.item_id.as_slice()).map_err(|_| corrupt)?;
        let vault_id = <[u8; 16]>::try_from(self.vault_id.as_slice()).map_err(|_| corrupt)?;
        let item_type = u16::try_from(self.item_type).map_err(|_| corrupt)?;
        let display_name = text_column(&self.display_name, MAX_DISPLAY_NAME_LEN)?;
        let search_text = text_column(&self.search_text, MAX_SEARCH_TEXT_LEN)?;
        let last_used_ms = match &self.last_used_ms {
            None => None,
            Some(bytes) => Some(u64::from_be_bytes(
                <[u8; 8]>::try_from(bytes.as_slice()).map_err(|_| corrupt)?,
            )),
        };
        let use_count = u64::try_from(self.use_count).map_err(|_| corrupt)?;
        Ok(StoredEntry {
            entry: IndexEntry {
                item_id,
                vault_id,
                item_type,
                display_name,
                search_text,
            },
            last_used_ms,
            use_count,
        })
    }
}

/// A text column: UTF-8 within `max` bytes, copied into a zeroizing buffer.
fn text_column(bytes: &[u8], max: usize) -> Result<Zeroizing<String>, ClientError> {
    if bytes.len() > max {
        return Err(ClientError::CacheCorrupt);
    }
    let text = core::str::from_utf8(bytes).map_err(|_| ClientError::CacheCorrupt)?;
    let mut out = Zeroizing::new(String::with_capacity(text.len()));
    out.push_str(text);
    Ok(out)
}

/// The displayed Text value of `key`, if non-empty.
fn text(vault: &VaultSync, item: ItemId, key: &str) -> Option<Zeroizing<String>> {
    let value = vault.field_value(item, key)?;
    match value.decode() {
        Ok(ValueRef::Text(text)) if !text.is_empty() => {
            let mut out = Zeroizing::new(String::with_capacity(text.len()));
            out.push_str(text);
            Some(out)
        }
        _ => None,
    }
}

/// The value of an element attribute: `<list>/<element>/<attribute>`.
fn element_text(
    vault: &VaultSync,
    item: ItemId,
    list: &str,
    element: &str,
    attribute: &str,
) -> Option<Zeroizing<String>> {
    let key = Zeroizing::new(format!("{list}/{element}/{attribute}"));
    text(vault, item, &key)
}

/// `text` lower-cased in Rust (§5), without any U+0000 (which would end the string for
/// `SQLite`'s `LIKE`), and cut to `max` bytes at a character boundary.
fn lowered(text: &str, max: usize) -> Zeroizing<String> {
    let mut lower = Zeroizing::new(text.to_lowercase());
    if lower.contains('\0') {
        lower.retain(|c| c != '\0');
    }
    if lower.len() > max {
        let mut end = max;
        while !lower.is_char_boundary(end) {
            end -= 1;
        }
        lower.truncate(end);
    }
    lower
}

/// The tag names of the item, in list order (an undecodable `tag/<hex>` is skipped, as every
/// view skips it).
fn tag_names(vault: &VaultSync, item: ItemId) -> Vec<Zeroizing<String>> {
    vault
        .list_elements(item, LIST_TAG)
        .into_iter()
        .filter_map(|element| {
            let key = Zeroizing::new(format!("{LIST_TAG}/{}", element.element.as_str()));
            let key = FieldKey::parse(key.as_bytes()).ok()?;
            tag_name(key.as_key()).ok()
        })
        .filter(|name| !name.is_empty())
        .collect()
}

/// The label and value of every text custom field (kind 1), in list order.
fn text_custom_fields(vault: &VaultSync, item: ItemId) -> Vec<Zeroizing<String>> {
    let mut out = Vec::new();
    for element in vault.list_elements(item, LIST_FIELD) {
        let element = element.element.as_str();
        let kind_key = Zeroizing::new(format!("{LIST_FIELD}/{element}/{ATTR_KIND}"));
        let kind = vault.field_value(item, &kind_key);
        let kind = CustomFieldKind::from_displayed(kind.as_ref().and_then(|v| v.decode().ok()));
        if kind != CustomFieldKind::Text {
            continue;
        }
        for attribute in [ATTR_LABEL, ATTR_VALUE] {
            if let Some(value) = element_text(vault, item, LIST_FIELD, element, attribute) {
                out.push(value);
            }
        }
    }
    out
}

/// The row of `item` (module docs, "What a row holds"), or `None` for an item that has none:
/// absent, purged, or the vault-settings item.
#[must_use]
pub fn project(vault: &VaultSync, item: ItemId) -> Option<IndexEntry> {
    if !matches!(
        vault.item_lifecycle(item),
        ItemLifecycle::Active | ItemLifecycle::Trashed
    ) {
        return None;
    }
    let item_type = vault.item_type(item);
    if item_type == Some(ItemType::VAULT_SETTINGS) {
        return None;
    }
    let mut parts: Vec<Zeroizing<String>> = Vec::new();
    let single = |parts: &mut Vec<Zeroizing<String>>, key: &str| {
        if let Some(value) = text(vault, item, key) {
            parts.push(value);
        }
    };
    let supported = item_type.and_then(ItemType::supported);
    match supported {
        Some(SupportedType::Login) => {
            single(&mut parts, LOGIN_USERNAME);
            for element in vault.list_elements(item, LIST_URI) {
                if let Some(uri) =
                    element_text(vault, item, LIST_URI, element.element.as_str(), ATTR_VALUE)
                {
                    parts.push(uri);
                }
            }
        }
        Some(SupportedType::Card) => {
            single(&mut parts, CARD_HOLDER);
            single(&mut parts, CARD_BRAND);
        }
        Some(SupportedType::Identity) => {
            for key in [
                IDENTITY_TITLE,
                IDENTITY_FIRST_NAME,
                IDENTITY_MIDDLE_NAME,
                IDENTITY_LAST_NAME,
                IDENTITY_COMPANY,
                IDENTITY_EMAIL,
            ] {
                single(&mut parts, key);
            }
        }
        _ => {}
    }
    if matches!(
        supported,
        Some(
            SupportedType::Login
                | SupportedType::SecureNote
                | SupportedType::Card
                | SupportedType::Identity
        )
    ) {
        parts.extend(tag_names(vault, item));
        parts.extend(text_custom_fields(vault, item));
    }
    let name = text(vault, item, ITEM_NAME);
    let display_name = lowered(
        name.as_ref().map_or("", |n| n.as_str()),
        MAX_DISPLAY_NAME_LEN,
    );
    Some(IndexEntry {
        item_id: item.to_bytes(),
        vault_id: vault.vault_id().to_bytes(),
        item_type: item_type.map_or(0, ItemType::id),
        display_name,
        search_text: joined(&parts),
    })
}

/// The lower-cased parts joined by [`SEPARATOR`], cut to [`MAX_SEARCH_TEXT_LEN`].
fn joined(parts: &[Zeroizing<String>]) -> Zeroizing<String> {
    let lowered: Vec<Zeroizing<String>> = parts
        .iter()
        .map(|p| lowered(p, MAX_SEARCH_TEXT_LEN))
        .collect();
    let total = lowered
        .iter()
        .map(|p| p.len().saturating_add(SEPARATOR.len_utf8()))
        .sum::<usize>();
    // Reserved up front, so the buffer never moves and leaves no unwiped copy behind.
    let mut out = Zeroizing::new(String::with_capacity(total.min(MAX_SEARCH_TEXT_LEN)));
    for (i, part) in lowered.iter().enumerate() {
        if i > 0 {
            if out.len() + SEPARATOR.len_utf8() > MAX_SEARCH_TEXT_LEN {
                break;
            }
            out.push(SEPARATOR);
        }
        let room = MAX_SEARCH_TEXT_LEN - out.len();
        if part.len() <= room {
            out.push_str(part);
        } else {
            let mut end = room;
            while !part.is_char_boundary(end) {
                end -= 1;
            }
            out.push_str(&part[..end]);
            break;
        }
    }
    out
}

/// Every row of `vault`, by item id.
#[must_use]
pub fn project_vault(vault: &VaultSync) -> BTreeMap<[u8; 16], IndexEntry> {
    vault
        .item_ids()
        .into_iter()
        .filter_map(|item| project(vault, item))
        .map(|entry| (entry.item_id, entry))
        .collect()
}

/// The writes that take a table holding `before` to `after`: an [`Write::IndexPut`] for each
/// new or changed entry, an [`Write::IndexDelete`] for each entry gone. Counters are untouched.
pub(crate) fn diff(
    before: &BTreeMap<[u8; 16], IndexEntry>,
    after: &BTreeMap<[u8; 16], IndexEntry>,
) -> Vec<Write> {
    let mut writes = Vec::new();
    for item_id in before.keys() {
        if !after.contains_key(item_id) {
            writes.push(Write::IndexDelete { item_id: *item_id });
        }
    }
    for (item_id, entry) in after {
        if before.get(item_id) != Some(entry) {
            writes.push(Write::IndexPut(entry.clone()));
        }
    }
    writes
}

/// The stored rows, parsed; `None` if the table must be rebuilt (module docs, "Its own failure
/// rule"): the host could not read it, a row does not parse, or two rows name one item.
fn stored(rows: &CacheRows) -> Option<BTreeMap<[u8; 16], IndexEntry>> {
    if rows.item_index_unreadable {
        return None;
    }
    let mut out = BTreeMap::new();
    for row in &rows.item_index {
        let parsed = row.parse().ok()?;
        if out.insert(parsed.entry.item_id, parsed.entry).is_some() {
            return None;
        }
    }
    Some(out)
}

/// The index writes of a load (§4 "Built at load"): what makes the stored `item_index` equal to
/// the projection of `vaults`, which [`crate::store::load::load`] just rebuilt from `rows`. A
/// row that stays keeps its counters; a row of an item, or a vault, the load does not hold is
/// deleted. A table that cannot be used is dropped and rebuilt instead (module docs), and the
/// counters are lost. Turns tracking on in every driver, so each later step's changeset
/// carries its own index writes.
///
/// The host commits the result like any other changeset, before the first step.
pub fn reconcile(rows: &CacheRows, vaults: &mut [VaultSync]) -> Changeset {
    let mut projected = BTreeMap::new();
    for vault in vaults.iter_mut() {
        let rows = project_vault(vault);
        vault.track_index(rows.clone());
        projected.extend(rows);
    }
    match stored(rows) {
        Some(before) => diff(&before, &projected).into_iter().collect(),
        None => rebuilt(&projected),
    }
}

/// The writes that drop and rebuild the table from `projected`.
fn rebuilt(projected: &BTreeMap<[u8; 16], IndexEntry>) -> Changeset {
    let mut changeset = Changeset::new();
    changeset.push(Write::IndexReset);
    for entry in projected.values() {
        changeset.push(Write::IndexPut(entry.clone()));
    }
    changeset
}

/// Turns tracking on in the driver of a new cache (a signup or an enrolment), whose table is
/// empty: the next [`VaultSync::take_writes`] indexes every item it holds.
pub fn track_new(vault: &mut VaultSync) {
    vault.track_index(BTreeMap::new());
    vault.mark_index_dirty();
}

/// The writes of a user-triggered rebuild (§4, `rv cache reindex`): the table dropped and
/// rebuilt from `vaults`, every counter lost. Tracking stays on, from the rebuilt rows.
pub fn reindex(vaults: &mut [VaultSync]) -> Changeset {
    let mut projected = BTreeMap::new();
    for vault in vaults.iter_mut() {
        let rows = project_vault(vault);
        vault.track_index(rows.clone());
        projected.extend(rows);
    }
    rebuilt(&projected)
}

/// The write that records one use of `item` at `now_ms` (§2: the user viewed it, copied a
/// field from it or autofilled it), or `None` for an item that has no row.
#[must_use]
pub fn record_use(vault: &VaultSync, item: ItemId, now_ms: u64) -> Option<Write> {
    project(vault, item)?;
    Some(Write::IndexUse {
        item_id: item.to_bytes(),
        at_ms: now_ms,
    })
}

/// The query, trimmed and lower-cased in Rust (§5).
#[must_use]
pub fn normalize_query(query: &str) -> Zeroizing<String> {
    let mut term = Zeroizing::new(query.trim().to_lowercase());
    if term.contains('\0') {
        term.retain(|c| c != '\0');
    }
    term
}

/// The `LIKE` pattern of [`SEARCH`]: [`normalize_query`] of `query` with `\`, `%` and `_`
/// escaped by `\`, between two `%`. An empty query gives `%%`, which matches every row.
#[must_use]
pub fn like_pattern(query: &str) -> Zeroizing<String> {
    let term = normalize_query(query);
    let mut out = Zeroizing::new(String::with_capacity(term.len() * 2 + 2));
    out.push('%');
    for c in term.chars() {
        if matches!(c, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('%');
    out
}

/// Whether `haystack` matches `term` as `SQLite`'s `LIKE '%term%'` does without an ICU
/// extension: a substring match, ASCII letters folded, every other character compared as is.
fn like_contains(haystack: &str, term: &str) -> bool {
    if term.is_empty() {
        return true;
    }
    let folded = Zeroizing::new(haystack.to_ascii_lowercase());
    let term = Zeroizing::new(term.to_ascii_lowercase());
    folded.contains(term.as_str())
}

/// The rows of a [`CacheRows`] that parse, in [`SEARCH`]'s order.
fn ordered(rows: &CacheRows) -> Vec<StoredEntry> {
    let mut parsed: Vec<StoredEntry> = rows
        .item_index
        .iter()
        .filter_map(|r| r.parse().ok())
        .collect();
    parsed.sort_by(|a, b| {
        (
            a.last_used_ms.is_none(),
            core::cmp::Reverse(a.last_used_ms),
            a.entry.display_name.as_bytes(),
            a.entry.item_id,
        )
            .cmp(&(
                b.last_used_ms.is_none(),
                core::cmp::Reverse(b.last_used_ms),
                b.entry.display_name.as_bytes(),
                b.entry.item_id,
            ))
    });
    parsed
}

/// [`SEARCH`] over `rows`: the ids of at most `limit` matching rows (module docs).
#[must_use]
pub fn search(rows: &CacheRows, query: &str, limit: usize) -> Vec<ItemId> {
    let term = normalize_query(query);
    ordered(rows)
        .into_iter()
        .filter(|r| {
            like_contains(&r.entry.display_name, &term)
                || like_contains(&r.entry.search_text, &term)
        })
        .take(limit)
        .map(|r| ItemId::from_bytes(r.entry.item_id))
        .collect()
}

/// [`RECENT`] over `rows`: the ids of at most `limit` used rows, most recent first.
#[must_use]
pub fn recent(rows: &CacheRows, limit: usize) -> Vec<ItemId> {
    ordered(rows)
        .into_iter()
        .filter(|r| r.last_used_ms.is_some())
        .take(limit)
        .map(|r| ItemId::from_bytes(r.entry.item_id))
        .collect()
}
