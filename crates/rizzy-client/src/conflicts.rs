// SPDX-License-Identifier: AGPL-3.0-only

//! Conflict resolution: "edited on Phone and Laptop at the same time — keep both / pick one"
//! (ROADMAP §4.5, M3; ADR 0012 §4 step 5; ADR 0018 §6 "Display"; ADR 0022 point 3 moved the
//! row to M3).
//!
//! A field is a multi-value register. After concurrent writes it holds several current values;
//! the merge keeps them all, and the display rules of `rizzy-core` show one of them and mark
//! the field as conflicting. ADR 0012 §4 step 5 and ADR 0018 §6 say how a conflict ends:
//! "Picking a value, or any new edit of the field, writes a value whose context covers all of
//! them. That resolves the conflict." Every own op carries the item's version vector as its
//! causal context (ADR 0012 §2), and that covers every value this replica holds, so **a
//! resolution is an ordinary edit** through [`VaultSync::edit_item`]: it passes the same
//! schema checks, syncs, and merges by the same rules on every device. Nothing here changes
//! the merge, the record layer or a format; `rizzy-sync` is not touched.
//!
//! | Call | Writes | Afterwards, on every device |
//! |---|---|---|
//! | [`VaultSync::field_conflict`] | nothing: lists the distinct current values | (read only) |
//! | [`VaultSync::resolve_conflict_pick`] | `key` = the picked value's exact bytes | `key` holds that one value |
//! | [`VaultSync::resolve_conflict_keep_both`] | `key` = the kept value; each other non-empty value in a new list element (below) | `key` holds the kept value; the other values sit in new elements |
//!
//! # Keep both
//!
//! The ADRs name "keep both" without a layout of its own, and the item schema (ADR 0018 §7)
//! has exactly one place where an item holds extra values: its lists. So "keep both" keeps one
//! value in the field and gives every other non-empty value an element of its own, with keys
//! and values ADR 0018 §7 already defines, under a fresh random element id (ADR 0012 §1):
//!
//! - **`uri/<id>/value`**: a new website (`uri/<new>/value`, its `match` copied from the
//!   source website when it has one, and an `order` that appends it).
//! - **`field/<id>/value`** of a text or hidden custom field: a new custom field of the same
//!   kind, labelled with the host's label or, without one, the source field's label.
//! - **A fixed Text field the user edits** (`login.password`, `item.notes`, `card.number`,
//!   …): a new custom field, hidden when the field is concealed by default (ADR 0018 §7
//!   "Concealed by default") and text otherwise, labelled with the host's label (the host knows
//!   the field's display name and the devices' names; this crate holds neither).
//! - **Anything else** (Bool, Enum, order keys, labels, tags, keys only importers write, keys
//!   this build does not know) has no second place to live: only "pick one" resolves it
//!   ([`ClientError::InvalidEdit`]).
//!
//! A Cleared value is never "kept" (it is the absence of a value); picking it is how a user
//! accepts "cleared on X while edited on Y" (ADR 0018 §6).
//!
//! # Convergence and idempotence
//!
//! - **Convergence.** A resolution is one op (or, when a list's `order` keys must be
//!   rewritten first, consecutive ops of one device that end with the field's write, as ADR
//!   0018 §6 "List order" allows). Its context covers every value the resolving device saw, so
//!   on every replica that applies it the field ends with the resolution's value alone (the
//!   multi-value register of ADR 0012 §4, whose result does not depend on delivery order). A
//!   value written concurrently with the resolution, on a device that had not seen it, is not
//!   covered and stays: a new conflict, which is the correct outcome, never a silent loss.
//! - **Two devices resolving at once** each write an op the other did not see. Picking the
//!   same value writes byte-identical values, which count as one value, not a conflict (ADR
//!   0018 §6). Different choices conflict again, visibly. Two concurrent "keep both" add their
//!   copies twice (element ids are random, ADR 0012 §1); the user removes the extra copy.
//! - **Idempotence.** A duplicate delivery of the resolution op is a no-op (ADR 0012 §4 step
//!   3). Asking again for a field that no longer conflicts, or for a value that is no longer
//!   current, writes nothing and fails with [`ClientError::UnknownItem`]: the host re-reads the
//!   listing ([`VaultSync::field_conflict`]) and names values by their dot, never by position
//!   or content, so a sync between the listing and the call cannot resolve to the wrong value.

use core::fmt;

use rizzy_core::ids::ItemId;
use rizzy_core::item::display::hlc_ms;
use rizzy_core::item::key::FieldKey as SchemaKey;
use rizzy_core::item::schema::{
    ATTR_KIND, ATTR_LABEL, ATTR_MATCH, ATTR_VALUE, Concealment, CustomFieldKind, Expected,
    KeyClass, LIST_FIELD, LIST_URI, Writers, classify,
};
use rizzy_core::item::value::{Value, ValueRef};
use rizzy_core::rng::CryptoRng;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::device::UnlockedDevice;
use crate::error::ClientError;
use crate::items::{Dot, FieldEdit, ItemLifecycle};
use crate::lists::{ElementWrite, split_order_ops};
use crate::sync::VaultSync;

/// One of a conflicting field's distinct current values ([`VaultSync::field_conflict`]). A
/// secret: reveal the value only on the user's request (ADR 0013 §3 rule 3). `Debug` redacts
/// every field.
pub struct ConflictValue {
    /// The value, as encoded bytes (ADR 0018 §6). Cleared (0 bytes) for "cleared on X".
    pub value: Value,
    /// The dot of the op that wrote it (ADR 0012 §2): the value's identity within this field,
    /// which [`VaultSync::resolve_conflict_pick`] and [`VaultSync::resolve_conflict_keep_both`]
    /// take. Its device is the device that wrote the value ("edited on X").
    pub dot: Dot,
    /// When it was written: that op's HLC in Unix milliseconds (ADR 0018 §9). Display only.
    pub written_ms: u64,
    /// Whether this is the value the field displays (ADR 0018 §6).
    pub displayed: bool,
}

impl fmt::Debug for ConflictValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConflictValue([REDACTED])")
    }
}

/// Where "keep both" puts the values it moves out of the field (module docs, "Keep both").
enum Target {
    /// New websites.
    Uri {
        /// The source website's displayed `match`, copied to each new website.
        matching: Option<Value>,
    },
    /// New custom fields.
    Field {
        /// The custom field kind's Enum value.
        kind: u16,
        /// The label text; an empty one writes no label.
        label: Zeroizing<String>,
    },
}

impl VaultSync {
    /// The distinct current values of `key` while it conflicts (ADR 0018 §6: "Byte-identical
    /// concurrent values count as one value"): the displayed value first, then the others from
    /// the highest `(hlc, device_id, seq)` down, the order the display rules rank them by. Of
    /// byte-identical values the highest-ranked one stands for all of them. Empty when the
    /// field does not conflict, or the item is absent or purged. A secret: reveal values only
    /// on the user's request.
    #[must_use]
    pub fn field_conflict(&self, item: ItemId, key: &str) -> Vec<ConflictValue> {
        if !matches!(
            self.item_lifecycle(item),
            ItemLifecycle::Active | ItemLifecycle::Trashed
        ) {
            return Vec::new();
        }
        let Some(view) = self.merge(item).and_then(|m| m.field(key)) else {
            return Vec::new();
        };
        let Some(display) = view.display.filter(|d| d.conflict) else {
            return Vec::new();
        };
        let mut ranked: Vec<(bool, &rizzy_sync::record::Entry<'_>)> = view
            .current
            .iter()
            .enumerate()
            .map(|(i, e)| (i == display.displayed, e))
            .collect();
        // The displayed value first, then the rest by rank, highest first.
        ranked.sort_by(|(da, a), (db, b)| {
            db.cmp(da)
                .then_with(|| (b.hlc(), b.dot()).cmp(&(a.hlc(), a.dot())))
        });
        let mut out: Vec<ConflictValue> = Vec::with_capacity(ranked.len());
        for (displayed, entry) in ranked {
            let bytes = entry.value().expose_secret();
            if out
                .iter()
                .any(|v| bool::from(v.value.expose_secret().ct_eq(bytes)))
            {
                continue;
            }
            let Ok(value) = Value::copy_from_encoded(bytes) else {
                continue;
            };
            out.push(ConflictValue {
                value,
                dot: entry.dot(),
                written_ms: hlc_ms(entry.hlc().to_u64()),
                displayed,
            });
        }
        out
    }

    /// "Pick one" (module docs): writes the exact bytes of the value `dot` names in `key`'s
    /// [`VaultSync::field_conflict`] listing back to `key`, an ordinary edit
    /// ([`VaultSync::edit_item`]) whose context covers every current value, so the conflict
    /// ends on every device that applies it. Picking a Cleared value clears the field.
    ///
    /// A custom field's value must still fit the kind the field displays
    /// ([`CustomFieldKind::accepts`]), as for [`VaultSync::restore_field_history`].
    ///
    /// # Errors
    /// [`ClientError::UnknownItem`] when `key` does not conflict or `dot` names none of its
    /// listed values (nothing is written: the second of two identical calls fails here);
    /// [`ClientError::InvalidEdit`] when `key` is not a valid field key or the value no longer
    /// fits the custom field's kind; the errors of [`VaultSync::edit_item`] otherwise
    /// (`UnknownItem` for an item that is not Active).
    pub fn resolve_conflict_pick<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        unlocked: &UnlockedDevice,
        item: ItemId,
        key: &str,
        dot: Dot,
        now_ms: u64,
    ) -> Result<(), ClientError> {
        let value = self
            .field_conflict(item, key)
            .into_iter()
            .find(|v| v.dot == dot)
            .map(|v| v.value)
            .ok_or(ClientError::UnknownItem)?;
        let parsed = SchemaKey::parse(key.as_bytes()).map_err(|_| ClientError::InvalidEdit)?;
        self.check_custom_field_kind(item, &parsed, &value)?;
        self.edit_item(
            rng,
            unlocked,
            item,
            &[FieldEdit {
                key: &parsed,
                value: &value,
            }],
            now_ms,
        )
    }

    /// "Keep both" (module docs): keeps the value `keep` names in `key`, and moves every other
    /// distinct non-empty value of the conflict into a new list element: a new website for
    /// `uri/<id>/value`, a new custom field otherwise. `label` labels the new custom fields;
    /// without one, a custom field's copies take the source field's label, and a fixed field
    /// has none to take ([`ClientError::InvalidInput`]). Ignored for websites. Returns the new
    /// elements' ids (lowercase hex), in the order of the listing.
    ///
    /// All writes go in one op, or, when the list's `order` keys must be rewritten, in
    /// consecutive ops that end with the op writing `key` ([`split_order_ops`]).
    ///
    /// # Errors
    /// [`ClientError::UnknownItem`] when `key` does not conflict or `keep` names none of its
    /// listed values (nothing is written); [`ClientError::InvalidEdit`] when `keep` names a
    /// Cleared value, no other non-empty value is left to keep, a value is not Text, or `key`
    /// is not a field whose values a list can hold (module docs); [`ClientError::InvalidInput`]
    /// for a fixed field without a `label`; the errors of [`VaultSync::plan_list_order`] and
    /// [`VaultSync::edit_item`] otherwise (`UnknownItem` for an item that is not Active).
    #[expect(
        clippy::too_many_arguments,
        reason = "the resolve_conflict_pick arguments, plus the kept value and the label"
    )]
    pub fn resolve_conflict_keep_both<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        unlocked: &UnlockedDevice,
        item: ItemId,
        key: &str,
        keep: Dot,
        label: Option<&str>,
        now_ms: u64,
    ) -> Result<Vec<Zeroizing<String>>, ClientError> {
        let values = self.field_conflict(item, key);
        let kept = values
            .iter()
            .find(|v| v.dot == keep)
            .ok_or(ClientError::UnknownItem)?;
        if kept.value.is_cleared() {
            return Err(ClientError::InvalidEdit);
        }
        let others: Vec<&ConflictValue> = values
            .iter()
            .filter(|v| v.dot != keep && !v.value.is_cleared())
            .collect();
        if others.is_empty() {
            return Err(ClientError::InvalidEdit);
        }
        let is_text = |v: &ConflictValue| matches!(v.value.decode(), Ok(ValueRef::Text(_)));
        if !is_text(kept) || !others.iter().all(|v| is_text(v)) {
            return Err(ClientError::InvalidEdit);
        }
        let parsed = SchemaKey::parse(key.as_bytes()).map_err(|_| ClientError::InvalidEdit)?;
        let target = self.keep_both_target(item, &parsed, label)?;
        let list = match target {
            Target::Uri { .. } => LIST_URI,
            Target::Field { .. } => LIST_FIELD,
        };
        let plan = self.plan_list_order(Some(item), list, &[], others.len(), &[])?;
        if plan.new_orders.len() != others.len() {
            return Err(ClientError::Internal);
        }
        let mut writes: Vec<ElementWrite> = Vec::new();
        let mut elements = Vec::with_capacity(others.len());
        for (other, order) in others.iter().zip(&plan.new_orders) {
            let copy = |v: &Value| Value::copy_from_encoded(v.expose_secret());
            let moved = copy(&other.value).map_err(|_| ClientError::Internal)?;
            let attributes: Vec<(&str, Value)> = match &target {
                Target::Uri { matching } => {
                    let mut a = vec![(ATTR_VALUE, moved)];
                    if let Some(m) = matching {
                        a.push((ATTR_MATCH, copy(m).map_err(|_| ClientError::Internal)?));
                    }
                    a
                }
                Target::Field { kind, label } => {
                    let mut a = vec![(ATTR_KIND, Value::enumeration(*kind)), (ATTR_VALUE, moved)];
                    if !label.is_empty() {
                        a.push((
                            ATTR_LABEL,
                            Value::text(label).map_err(|_| ClientError::InvalidInput)?,
                        ));
                    }
                    a
                }
            };
            let (element, mut element_writes) =
                Self::new_element_writes(rng, list, attributes, Some(order))?;
            let element_key = element
                .key(list, ATTR_VALUE)
                .map_err(|_| ClientError::Internal)?;
            let hex = element_key
                .as_key()
                .element()
                .ok_or(ClientError::Internal)?
                .to_owned();
            elements.push(Zeroizing::new(hex));
            writes.append(&mut element_writes);
        }
        let kept_value = Value::copy_from_encoded(kept.value.expose_secret())
            .map_err(|_| ClientError::Internal)?;
        // The field's own write is in the last op when an order rewrite splits the edit.
        writes.push((parsed, kept_value));
        let ops = if plan.rewritten {
            split_order_ops(plan.writes, writes)
        } else {
            let mut all = plan.writes;
            all.append(&mut writes);
            split_order_ops(Vec::new(), all)
        };
        for op in &ops {
            let edits: Vec<FieldEdit<'_>> = op
                .iter()
                .map(|(key, value)| FieldEdit { key, value })
                .collect();
            self.edit_item(rng, unlocked, item, &edits, now_ms)?;
        }
        Ok(elements)
    }

    /// Where "keep both" puts the other values of `key` (module docs, "Keep both").
    fn keep_both_target(
        &self,
        item: ItemId,
        key: &SchemaKey,
        label: Option<&str>,
    ) -> Result<Target, ClientError> {
        let parts = key.as_key();
        match (parts.list(), parts.element(), parts.attribute()) {
            (Some(LIST_URI), Some(element), Some(ATTR_VALUE)) => {
                let matching = self
                    .field_value(item, &format!("{LIST_URI}/{element}/{ATTR_MATCH}"))
                    .filter(|v| !v.is_cleared());
                Ok(Target::Uri { matching })
            }
            (Some(LIST_FIELD), Some(element), Some(ATTR_VALUE)) => {
                let kind = self.custom_field_kind(item, element);
                if !matches!(kind, CustomFieldKind::Text | CustomFieldKind::Hidden) {
                    return Err(ClientError::InvalidEdit);
                }
                let own = || {
                    let value =
                        self.field_value(item, &format!("{LIST_FIELD}/{element}/{ATTR_LABEL}"));
                    match value.as_ref().map(Value::decode) {
                        Some(Ok(ValueRef::Text(t))) => Zeroizing::new(t.to_owned()),
                        _ => Zeroizing::new(String::new()),
                    }
                };
                let label = label.map_or_else(own, |l| Zeroizing::new(l.to_owned()));
                Ok(Target::Field {
                    kind: kind.id().ok_or(ClientError::Internal)?,
                    label,
                })
            }
            (None, None, None) => {
                let KeyClass::Known(spec) = classify(parts) else {
                    return Err(ClientError::InvalidEdit);
                };
                if spec.expected != Expected::Text || spec.writers != Writers::Any {
                    return Err(ClientError::InvalidEdit);
                }
                let kind = if spec.concealment == Concealment::Shown {
                    CustomFieldKind::Text
                } else {
                    CustomFieldKind::Hidden
                };
                let label = label
                    .filter(|l| !l.is_empty())
                    .ok_or(ClientError::InvalidInput)?;
                Ok(Target::Field {
                    kind: kind.id().ok_or(ClientError::Internal)?,
                    label: Zeroizing::new(label.to_owned()),
                })
            }
            _ => Err(ClientError::InvalidEdit),
        }
    }
}
