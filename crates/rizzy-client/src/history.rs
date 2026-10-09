//! An item's password history (ROADMAP §4.2 "Password history per item"; ADR 0012 §5, ADR
//! 0018 §3 "History", §7).
//!
//! "The history of `login.password` is the password history" (ADR 0018 §7): every value an
//! edit or a resolved conflict removed from the register, the newest [`HISTORY_LIMIT`] kept by
//! the merge. History imported from another manager lives on the `pwhist/<id>/value` · `/ms`
//! list (ADR 0018 §7) and is shown with it. [`VaultSync::password_history`] returns both,
//! newest first:
//!
//! - **Edited** entries in the merge's pruning order, highest `(hlc, device_id, seq)` first
//!   (the order of the export's `password_history`, [`crate::export::payload`]), each with the
//!   time of the op that wrote the value (`hlc >> 16`). A Cleared value, a cleared password,
//!   is not a password and is left out.
//! - **Imported** entries in list order, each with its `ms` when that displays a U64.
//!
//! The two are merged by time, newest first; an entry with no time comes last, in its own
//! order. Read-only: nothing here writes, and a tombstone has no history.
//!
//! The values are secrets (ADR 0013 §3 rule 3: reveal on the user's request only): they come in
//! [`Value`]'s zeroizing buffer, and [`HistoryEntry`] prints none of them from `Debug`.

use core::fmt;

use rizzy_core::item::display::hlc_ms;
use rizzy_core::item::schema::{ATTR_MS, ATTR_VALUE, LIST_PWHIST, LOGIN_PASSWORD};
use rizzy_core::item::value::{Value, ValueRef};
/// The most history entries the merge keeps per field, re-exported for hosts.
pub use rizzy_sync::merge::HISTORY_LIMIT;
use rizzy_sync::merge::ItemLifecycle;

use crate::items::ItemId;
use crate::sync::VaultSync;

/// Where a history entry comes from (module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HistorySource {
    /// A value an edit (or a resolved conflict) replaced in `login.password`.
    Edited,
    /// An entry of the imported `pwhist/<id>/…` list.
    Imported,
}

/// One past password. `Debug` prints the source only.
pub struct HistoryEntry {
    /// Where it comes from.
    pub source: HistorySource,
    /// When it was written (edited) or recorded (imported), Unix milliseconds, if known.
    pub at_ms: Option<u64>,
    /// The value, encoded (ADR 0018 §6): Text for every entry this function returns.
    pub value: Value,
}

impl fmt::Debug for HistoryEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HistoryEntry")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

impl VaultSync {
    /// The item's password history, newest first (module docs). Empty for an item that is
    /// not live (absent or purged) or has none.
    #[must_use]
    pub fn password_history(&self, item: ItemId) -> Vec<HistoryEntry> {
        if !matches!(
            self.item_lifecycle(item),
            ItemLifecycle::Active | ItemLifecycle::Trashed
        ) {
            return Vec::new();
        }
        let mut out = self.edited_history(item);
        out.extend(self.imported_history(item));
        // Stable: entries of one time keep the order each source gave them.
        out.sort_by_key(|e| core::cmp::Reverse(e.at_ms.map_or(0, |ms| ms.saturating_add(1))));
        out
    }

    /// The history of `login.password`, in the pruning order, Cleared values left out.
    fn edited_history(&self, item: ItemId) -> Vec<HistoryEntry> {
        let Some(view) = self.merge(item).and_then(|m| m.field(LOGIN_PASSWORD)) else {
            return Vec::new();
        };
        let mut entries = view.history;
        entries.sort_by_key(|e| core::cmp::Reverse((e.hlc(), e.dot())));
        entries
            .iter()
            .filter_map(|e| {
                let value = Value::copy_from_encoded(e.value().expose_secret()).ok()?;
                matches!(value.decode(), Ok(ValueRef::Text(_))).then(|| HistoryEntry {
                    source: HistorySource::Edited,
                    at_ms: Some(hlc_ms(e.hlc().to_u64())),
                    value,
                })
            })
            .collect()
    }

    /// The imported `pwhist` entries the item displays, in list order.
    fn imported_history(&self, item: ItemId) -> Vec<HistoryEntry> {
        self.list_elements(item, LIST_PWHIST)
            .iter()
            .filter_map(|element| {
                let key = |attr: &str| format!("{LIST_PWHIST}/{}/{attr}", element.element.as_str());
                let value = self.field_value(item, &key(ATTR_VALUE))?;
                if !matches!(value.decode(), Ok(ValueRef::Text(_))) {
                    return None;
                }
                let at_ms =
                    self.field_value(item, &key(ATTR_MS))
                        .and_then(|ms| match ms.decode() {
                            Ok(ValueRef::U64(ms)) => Some(ms),
                            _ => None,
                        });
                Some(HistoryEntry {
                    source: HistorySource::Imported,
                    at_ms,
                    value,
                })
            })
            .collect()
    }
}
