//! What an exported item displays: the readings of one item's merged state (an ADR 0018 §3
//! live snapshot) that the payload import and both plaintext writers share, so that the three
//! agree on every displayed value, conflict and time (ADR 0027 §2 step 3, §3, §4).
//!
//! Everything here is `rizzy-core`'s display rules ([`rizzy_core::item::display`]) applied to
//! the record layer's registers; nothing is decided here. Keys and values are borrowed from
//! the snapshot's buffer and never copied.

use rizzy_core::item::display::{
    Candidate, Lifecycle as Shown, created_ms, hlc_ms, modified_ms, resolve_field,
    resolve_lifecycle,
};
use rizzy_core::item::schema::{IMPORT_CREATED_MS, ITEM_TYPE, LOGIN_PASSWORD};
use rizzy_core::item::types::ItemType;
use rizzy_core::item::value::ValueRef;
use rizzy_sync::record::{Entry, LiveSnapshot, Register};

/// The display-order candidates of a register's entries.
fn candidates<'a>(entries: &[Entry<'a>]) -> Vec<Candidate<'a>> {
    entries
        .iter()
        .map(|e| Candidate {
            hlc: e.hlc().to_u64(),
            device_id: e.dot().device_id(),
            seq: e.dot().seq(),
            value: e.value().expose_secret(),
        })
        .collect()
}

/// What one register displays (ADR 0018 §6 "Display").
pub(crate) struct Displayed<'a> {
    /// The displayed value's encoded bytes; empty for Cleared.
    pub(crate) value: &'a [u8],
    /// Whether the current values are not all byte-identical.
    pub(crate) conflict: bool,
    /// The index of the displayed value among the register's entries.
    pub(crate) index: usize,
}

/// What `register` displays; `None` only for a register without an entry, which the record
/// layer never yields.
pub(crate) fn displayed<'a>(register: &Register<'a>) -> Option<Displayed<'a>> {
    let shown = resolve_field(&candidates(register.entries()))?;
    let entry = register.entries().get(shown.displayed)?;
    Some(Displayed {
        value: entry.value().expose_secret(),
        conflict: shown.conflict,
        index: shown.displayed,
    })
}

/// The current register of `key`, if the item has one.
fn register<'s, 'a>(live: &'s LiveSnapshot<'a>, key: &str) -> Option<&'s Register<'a>> {
    live.registers()
        .iter()
        .find(|r| r.key().expose_secret() == key)
}

/// The candidates of the register of `key`; empty when the item has none.
fn register_candidates<'a>(live: &LiveSnapshot<'a>, key: &str) -> Vec<Candidate<'a>> {
    register(live, key).map_or_else(Vec::new, |r| candidates(r.entries()))
}

/// The registers other than `@lifecycle`, ascending by key.
pub(crate) fn fields<'s, 'a>(
    live: &'s LiveSnapshot<'a>,
) -> impl Iterator<Item = &'s Register<'a>> + 's {
    live.registers().iter().filter(|r| !r.key().is_lifecycle())
}

/// Whether the item displays Trashed ("Active wins", ADR 0012 §5). `None` when `@lifecycle`
/// displays nothing, which the record layer's rule 5 excludes.
pub(crate) fn trashed(live: &LiveSnapshot<'_>) -> Option<bool> {
    let lifecycle = live.registers().iter().find(|r| r.key().is_lifecycle())?;
    let shown = resolve_lifecycle(&candidates(lifecycle.entries()))?;
    Some(shown.shown == Shown::Trashed)
}

/// The item's type, from its displayed `item.type` (ADR 0018 §7, §8); `None` for an item
/// without a valid type.
pub(crate) fn item_type(live: &LiveSnapshot<'_>) -> Option<ItemType> {
    let shown = displayed(register(live, ITEM_TYPE)?)?;
    ItemType::from_displayed(ValueRef::decode(shown.value).ok())
}

/// The ADR 0018 §9 "Created" time, in Unix milliseconds.
pub(crate) fn created(live: &LiveSnapshot<'_>) -> Option<u64> {
    created_ms(
        &register_candidates(live, ITEM_TYPE),
        &register_candidates(live, IMPORT_CREATED_MS),
    )
}

/// The ADR 0018 §9 "Modified" time, in Unix milliseconds.
pub(crate) fn modified(live: &LiveSnapshot<'_>) -> Option<u64> {
    let all: Vec<(&[u8], Vec<Candidate<'_>>)> = live
        .registers()
        .iter()
        .map(|r| (r.key().expose_secret().as_bytes(), candidates(r.entries())))
        .collect();
    modified_ms(all.iter().map(|(key, values)| (*key, values.as_slice())))
}

/// The history of `login.password`, newest first (the pruning order of ADR 0012 §5, highest
/// `(hlc, device_id, seq)` first), each with its time `hlc >> 16`.
pub(crate) fn password_history<'a>(live: &LiveSnapshot<'a>) -> Vec<(&'a [u8], u64)> {
    let Some(group) = live
        .history()
        .iter()
        .find(|g| g.key().expose_secret() == LOGIN_PASSWORD)
    else {
        return Vec::new();
    };
    let mut entries: Vec<&Entry<'a>> = group.entries().iter().collect();
    entries.sort_by_key(|e| core::cmp::Reverse((e.hlc(), e.dot())));
    entries
        .into_iter()
        .map(|e| (e.value().expose_secret(), hlc_ms(e.hlc().to_u64())))
        .collect()
}

/// How many history entries the item holds for fields other than `login.password`
/// (`@lifecycle` is not a field and is not counted).
pub(crate) fn other_history(live: &LiveSnapshot<'_>) -> usize {
    live.history()
        .iter()
        .filter(|g| !g.key().is_lifecycle() && g.key().expose_secret() != LOGIN_PASSWORD)
        .map(|g| g.entries().len())
        .sum()
}
