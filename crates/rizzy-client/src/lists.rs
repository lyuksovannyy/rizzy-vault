//! List elements of an item: URIs, custom fields, password history and tags (ADR 0018 §6
//! "List elements", "List order", §7 `uri/…`, `field/…`, `pwhist/…`, `tag/…`; ADR 0012 §1).
//!
//! A list is a map from an element id to fields, `list/<elem>/attribute`, so two devices that
//! add, edit or remove elements concurrently merge field by field. This module builds the
//! field writes of the list edits; the host passes them, with any other field writes of the
//! same change, to [`VaultSync::edit_item`] (one op, whose schema checks they pass), or, for a
//! new item, to [`VaultSync::create_item`].
//!
//! | Edit | Writes |
//! |---|---|
//! | Add ([`VaultSync::new_element_writes`]) | each given attribute of a new random element id, and its `order` from [`VaultSync::plan_list_order`] |
//! | Edit | the attribute's key with the new value: `FieldKey::element(list, element, Some(attribute))` |
//! | Move ([`VaultSync::plan_list_order`]) | the moved element's `order`: a key strictly between its new neighbours; or the list's rewrite |
//! | Remove ([`VaultSync::element_removal_writes`]) | Cleared to each attribute of the element that the item holds a register of |
//!
//! # Order (ADR 0018 §6 "List order")
//!
//! Only the lists whose §7 schema has an `order` attribute have an order a writer sets: `uri`
//! and `field`. A tag (`tag/<hex>`) and a password-history entry (`pwhist/<id>/value`, `/ms`)
//! have no `order`, so they sort by element id alone and cannot be moved: §7 defines no key
//! that would hold their place, and this module does not invent one
//! ([`ClientError::InvalidEdit`]).
//!
//! [`VaultSync::plan_list_order`] takes one edit of a list (elements removed, elements added,
//! elements moved) and gives the `order` of every new element and the `order` writes of the
//! existing elements it places:
//!
//! 1. **The order after the edit.** The elements the item displays, in list order, without
//!    the removed ones; the new elements after the last element with a valid `order` (before
//!    the elements without one, which sort last whatever is written, so new elements land
//!    where a reader shows them); then each move in turn: the element taken out and put
//!    first, last, or just before or after another element.
//! 2. **Keys between neighbours.** Every new or moved element gets a key strictly between the
//!    elements on each side of it in that order ([`sort_key_between`]): the one before it (or
//!    the start of the list) and the next element that keeps its key (or the end, when that
//!    element has no `order`, since those sort last). A run of new or moved elements is keyed
//!    left to right. A key with nothing above it is also kept above the highest valid `order`
//!    of every register of the list, removed elements included, as appends always were. The
//!    other elements keep their keys, and only the placed ones are written.
//! 3. **Rewrite.** When no key of at most 64 bytes fits (the neighbours are equal or adjacent,
//!    or 64 bytes of `0xFF` with nothing above), or an element would come after an element
//!    without a valid `order` (no key sorts there), the list's `order` keys are rewritten:
//!    every element of the order after the edit gets [`evenly_spaced`]`(n)` in turn, and the
//!    `order` of every existing one is written ([`OrderPlan::rewritten`]). ADR 0018 §6 has
//!    the rewrite "in one op, or in consecutive ops if one would break §10":
//!    [`split_order_ops`] puts it in the edit's op while the two fit
//!    [`MAX_WRITES_PER_OP`] writes, and otherwise sends the rewrite first, in consecutive ops
//!    of at most that many writes, and the edit's other writes in the op after them. An
//!    `order` write is at most a 160-byte key and a 65-byte value, so 1,024 of them stay far
//!    below the 1 MiB op limit.
//!
//! # Readings (reported)
//!
//! - **Which attributes "the writer holds"** (ADR 0018 §6: "Removing a list element writes
//!   this to each attribute of the element that the writer holds"): every current register of
//!   the item under the element's prefix, layout attributes (`order`, `kind`) included, so a
//!   concurrent edit of the order cannot keep a removed element in place. Clearing a layout
//!   attribute changes no existence; it is the literal reading.
//! - **Keys this client never writes** are left out of a removal: `share/<id>/secret` (M5's to
//!   write and clear) today. `uri/<id>/match` was the same in M1 (ADR 0018 §7 owner decision 2,
//!   "carry it and never write it") and is cleared like any other register from M2, once
//!   ADR 0037 (Accepted) assigned its enum values and moved it to `Writers::Any`. Neither is a
//!   *content* attribute of its element (`match` is layout; a share is not a list this client
//!   edits), so clearing it, alone, never keeps the element existing.
//! - **Tags** have no attributes: a tag is added with Bool `0x01` and removed with Cleared on
//!   its own key (`rizzy_core::item::tag::tag_key`); the generic removal does the same.
//! - **The rewrite covers the elements the item displays,** in the order after the edit. The
//!   registers of removed elements keep their old `order`: writing to an element that does
//!   not exist would not make it exist (`order` is layout), and a removal already cleared it.
//! - **Which keys a rewrite writes:** every element of the list, also those whose position
//!   did not change, as "rewrites that list's `order` keys" reads.

use core::fmt;

use rizzy_core::ids::ItemId;
use rizzy_core::item::key::{ElementId, FieldKey, FieldKeyRef};
use rizzy_core::item::order::{
    AttributeRole, ListEntry, OrderError, attribute_role, compare_list_entries, element_exists,
    evenly_spaced, sort_key_between,
};
use rizzy_core::item::schema::{ATTR_ORDER, Expected, KeyClass, Writers, classify};
use rizzy_core::item::value::{SortKey, Value, ValueRef};
use rizzy_core::rng::CryptoRng;
use zeroize::Zeroizing;

use crate::error::ClientError;
use crate::sync::VaultSync;

/// The most field writes one op carries (ADR 0018 §10), for [`split_order_ops`].
pub const MAX_WRITES_PER_OP: usize = rizzy_sync::record::MAX_WRITES;

/// One element of an item's list, as the item displays it. The element id of a tag is its
/// name, and the attribute values are item data, so `Debug` prints nothing of them.
pub struct ListElement {
    /// The element id: the lowercase hex digits of its key.
    pub element: Zeroizing<String>,
    /// The keys of the element's current registers, ascending.
    pub keys: Vec<FieldKey>,
}

impl fmt::Debug for ListElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ListElement([REDACTED])")
    }
}

/// A field write the host passes on: the final key and the encoded value.
pub type ElementWrite = (FieldKey, Value);

/// Where a move puts an element (module docs, "Order"). Element ids are full hex ids of
/// elements the item displays. Item data; `Debug` redacted.
pub enum ListPlace {
    /// First in the list.
    First,
    /// Last in the list.
    Last,
    /// Just before this element.
    Before(Zeroizing<String>),
    /// Just after this element.
    After(Zeroizing<String>),
}

impl fmt::Debug for ListPlace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::First => "First",
            Self::Last => "Last",
            Self::Before(_) => "Before([REDACTED])",
            Self::After(_) => "After([REDACTED])",
        })
    }
}

/// One move of an existing element. `Debug` redacted.
pub struct ListMove {
    /// The element's full hex id.
    pub element: Zeroizing<String>,
    /// Where it goes.
    pub to: ListPlace,
}

impl fmt::Debug for ListMove {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ListMove")
            .field("to", &self.to)
            .finish_non_exhaustive()
    }
}

/// The order of one edit of a list ([`VaultSync::plan_list_order`]). Holds item data;
/// `Debug` shows the shape only.
pub struct OrderPlan {
    /// The `order` of each new element, in the order they were asked for.
    pub new_orders: Vec<SortKey>,
    /// The `order` writes of existing elements: the moved ones, or, after a rewrite, every
    /// element the list displays.
    pub writes: Vec<ElementWrite>,
    /// Whether the list's `order` keys were rewritten (module docs, "Order" step 3), so
    /// [`split_order_ops`] may put [`OrderPlan::writes`] in ops of their own.
    pub rewritten: bool,
}

impl fmt::Debug for OrderPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OrderPlan")
            .field("new", &self.new_orders.len())
            .field("writes", &self.writes.len())
            .field("rewritten", &self.rewritten)
            .finish()
    }
}

/// The ops of one edit (module docs, "Order" step 3): `rewrite` (the writes of rewritten
/// lists, [`OrderPlan::writes`] with [`OrderPlan::rewritten`]) and `writes` (every other
/// write of the edit) in one op while together they fit [`MAX_WRITES_PER_OP`]; otherwise
/// `rewrite` in consecutive ops of at most [`MAX_WRITES_PER_OP`] writes, then `writes` in one
/// op. An op without writes is left out. The host writes the ops in the order returned.
#[must_use]
pub fn split_order_ops(
    rewrite: Vec<ElementWrite>,
    mut writes: Vec<ElementWrite>,
) -> Vec<Vec<ElementWrite>> {
    if rewrite.len() + writes.len() <= MAX_WRITES_PER_OP {
        let mut one = rewrite;
        one.append(&mut writes);
        return if one.is_empty() {
            Vec::new()
        } else {
            vec![one]
        };
    }
    let mut ops: Vec<Vec<ElementWrite>> = Vec::new();
    let mut current: Vec<ElementWrite> = Vec::with_capacity(MAX_WRITES_PER_OP);
    for write in rewrite {
        if current.len() == MAX_WRITES_PER_OP {
            ops.push(core::mem::take(&mut current));
        }
        current.push(write);
    }
    if !current.is_empty() {
        ops.push(current);
    }
    if !writes.is_empty() {
        ops.push(writes);
    }
    ops
}

/// Whether the ADR 0018 §7 schema gives `list` an `order` attribute (`uri`, `field`).
fn has_order(list: &str) -> bool {
    FieldKey::parse(format!("{list}/00/{ATTR_ORDER}").as_bytes()).is_ok_and(|key| {
        matches!(
            classify(key.as_key()),
            KeyClass::Known(spec) if spec.expected == Expected::SortKey
        )
    })
}

/// One element of the order after an edit ([`VaultSync::plan_list_order`]).
struct Slot {
    /// The existing element's id, or `None` for the new element `new_index`.
    element: Option<Zeroizing<String>>,
    /// The index of a new element among the new ones.
    new_index: usize,
    /// Its `order` payload: the current one, then the placed one.
    key: Option<SortKey>,
    /// New or moved: it gets a key.
    placed: bool,
}

/// A copy of a sort key.
fn copy_key(key: &SortKey) -> Result<SortKey, ClientError> {
    SortKey::from_slice(key.as_bytes()).map_err(|_| ClientError::Internal)
}

/// The index of the existing element `wanted` in `order`.
fn position(order: &[Slot], wanted: &str) -> Result<usize, ClientError> {
    order
        .iter()
        .position(|s| s.element.as_ref().is_some_and(|e| e.as_str() == wanted))
        .ok_or(ClientError::UnknownItem)
}

/// Runs `moves` on `order` in turn (module docs, "Order" step 1); each moved element is
/// placed.
fn apply_moves(order: &mut Vec<Slot>, moves: &[ListMove]) -> Result<(), ClientError> {
    for step in moves {
        let at = position(order, &step.element)?;
        let mut slot = order.remove(at);
        slot.placed = true;
        let to = match &step.to {
            ListPlace::First => 0,
            ListPlace::Last => order.len(),
            ListPlace::Before(other) | ListPlace::After(other) if **other == *step.element => {
                return Err(ClientError::InvalidEdit);
            }
            ListPlace::Before(other) => position(order, other)?,
            ListPlace::After(other) => position(order, other)? + 1,
        };
        order.insert(to, slot);
    }
    Ok(())
}

/// The keys of the placed slots of `order` (module docs, "Order" step 2); `false` when the
/// list must be rewritten instead. `highest` is the highest valid `order` of the list's
/// registers.
fn place_between(order: &mut [Slot], highest: Option<&SortKey>) -> Result<bool, ClientError> {
    for i in 0..order.len() {
        if !order.get(i).is_some_and(|s| s.placed) {
            continue;
        }
        let lower = match i.checked_sub(1).and_then(|before| order.get(before)) {
            None => None,
            // No key sorts after an element without one.
            Some(Slot { key: None, .. }) => return Ok(false),
            Some(Slot { key: Some(key), .. }) => Some(copy_key(key)?),
        };
        let upper = order
            .get(i + 1..)
            .unwrap_or_default()
            .iter()
            .find(|s| !s.placed)
            .and_then(|s| s.key.as_ref())
            .map(copy_key)
            .transpose()?;
        // Nothing above: above every `order` the list's registers hold too.
        let lower = match (&upper, lower, highest) {
            (None, Some(l), Some(h)) if h.as_bytes() > l.as_bytes() => Some(copy_key(h)?),
            (None, None, Some(h)) => Some(copy_key(h)?),
            (_, lower, _) => lower,
        };
        match sort_key_between(
            lower.as_ref().map(SortKey::as_bytes),
            upper.as_ref().map(SortKey::as_bytes),
        ) {
            Ok(key) => {
                if let Some(slot) = order.get_mut(i) {
                    slot.key = Some(key);
                }
            }
            Err(OrderError::NoRoom | OrderError::NotOrdered) => return Ok(false),
            Err(_) => return Err(ClientError::Internal),
        }
    }
    Ok(true)
}

/// The new elements' keys and the existing elements' `order` writes of a keyed `order`.
fn plan_writes(
    list: &str,
    order: Vec<Slot>,
    added: usize,
) -> Result<(Vec<SortKey>, Vec<ElementWrite>), ClientError> {
    let mut new_orders: Vec<Option<SortKey>> = (0..added).map(|_| None).collect();
    let mut writes = Vec::new();
    for slot in order {
        if !slot.placed {
            continue;
        }
        let key = slot.key.ok_or(ClientError::Internal)?;
        match slot.element {
            None => {
                let target = new_orders
                    .get_mut(slot.new_index)
                    .ok_or(ClientError::Internal)?;
                *target = Some(key);
            }
            Some(element) => {
                let field = FieldKey::parse(format!("{list}/{}/{ATTR_ORDER}", *element).as_bytes())
                    .map_err(|_| ClientError::Internal)?;
                writes.push((field, Value::sort_key(&key)));
            }
        }
    }
    let new_orders = new_orders
        .into_iter()
        .map(|k| k.ok_or(ClientError::Internal))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((new_orders, writes))
}

impl VaultSync {
    /// The keys of the item's current registers under `list`, grouped by element id, in key
    /// order.
    fn element_keys(&self, item: ItemId, list: &str) -> Vec<(Zeroizing<String>, Vec<FieldKey>)> {
        let mut groups: Vec<(Zeroizing<String>, Vec<FieldKey>)> = Vec::new();
        for key in self.field_keys(item) {
            let Ok(parsed) = FieldKeyRef::parse(key.as_bytes()) else {
                continue;
            };
            let (Some(name), Some(element)) = (parsed.list(), parsed.element()) else {
                continue;
            };
            if name != list {
                continue;
            }
            let owned = FieldKey::from_ref(parsed);
            match groups.iter_mut().find(|(e, _)| e.as_str() == element) {
                Some((_, keys)) => keys.push(owned),
                None => groups.push((Zeroizing::new(element.to_owned()), vec![owned])),
            }
        }
        groups
    }

    /// The elements of `list` the item displays, in list order, each with the encoded value
    /// its `order` displays.
    fn displayed_elements(&self, item: ItemId, list: &str) -> Vec<(Option<Value>, ListElement)> {
        let mut out: Vec<(Option<Value>, ListElement)> = Vec::new();
        for (element, keys) in self.element_keys(item, list) {
            let shown: Vec<(Option<String>, Value)> = keys
                .iter()
                .filter_map(|k| {
                    let value = self.field_value(item, k.as_str())?;
                    Some((k.as_key().attribute().map(str::to_owned), value))
                })
                .collect();
            let exists = element_exists(
                shown
                    .iter()
                    .map(|(attribute, value)| (attribute.as_deref(), value.expose_secret())),
            );
            if !exists {
                continue;
            }
            let order = shown
                .into_iter()
                .find(|(attribute, _)| attribute.as_deref() == Some(ATTR_ORDER))
                .map(|(_, value)| value);
            out.push((order, ListElement { element, keys }));
        }
        out.sort_by(|(a_order, a), (b_order, b)| {
            compare_list_entries(
                &ListEntry {
                    order: a_order.as_ref().map(Value::expose_secret),
                    element: &a.element,
                },
                &ListEntry {
                    order: b_order.as_ref().map(Value::expose_secret),
                    element: &b.element,
                },
            )
        });
        out
    }

    /// The elements of `list` (`uri`, `field`, `pwhist`, `tag`, …) the item displays: those
    /// one of whose content attributes displays a non-empty value, in list order (`order`,
    /// then element id; ADR 0018 §6).
    #[must_use]
    pub fn list_elements(&self, item: ItemId, list: &str) -> Vec<ListElement> {
        self.displayed_elements(item, list)
            .into_iter()
            .map(|(_, element)| element)
            .collect()
    }

    /// The highest valid `order` among every register of `list` of `item`.
    fn highest_order(&self, item: ItemId, list: &str) -> Option<SortKey> {
        let mut highest: Option<SortKey> = None;
        for (_, keys) in self.element_keys(item, list) {
            for key in keys {
                if key.as_key().attribute() != Some(ATTR_ORDER) {
                    continue;
                }
                let Some(value) = self.field_value(item, key.as_str()) else {
                    continue;
                };
                if let Ok(ValueRef::SortKey(payload)) = value.decode()
                    && highest.as_ref().is_none_or(|h| payload > h.as_bytes())
                    && let Ok(key) = SortKey::from_slice(payload)
                {
                    highest = Some(key);
                }
            }
        }
        highest
    }

    /// The order after an edit of `list` of `item` (module docs, "Order" step 1), before the
    /// moves: the displayed elements without `removed`, keyed ones first, then `added` new
    /// elements, then the elements without a valid `order`.
    fn order_before_moves(
        &self,
        item: Option<ItemId>,
        list: &str,
        removed: &[&str],
        added: usize,
    ) -> Vec<Slot> {
        let displayed = item.map_or_else(Vec::new, |item| self.displayed_elements(item, list));
        let mut keyed = Vec::new();
        let mut unkeyed = Vec::new();
        for (order, element) in displayed {
            if removed.contains(&element.element.as_str()) {
                continue;
            }
            let key = order.as_ref().and_then(|value| {
                ListEntry {
                    order: Some(value.expose_secret()),
                    element: &element.element,
                }
                .sort_key()
                .and_then(|payload| SortKey::from_slice(payload).ok())
            });
            let slot = Slot {
                element: Some(element.element),
                new_index: 0,
                placed: false,
                key,
            };
            if slot.key.is_some() {
                keyed.push(slot);
            } else {
                unkeyed.push(slot);
            }
        }
        let mut order = keyed;
        order.extend((0..added).map(|new_index| Slot {
            element: None,
            new_index,
            key: None,
            placed: true,
        }));
        order.append(&mut unkeyed);
        order
    }

    /// The order of one edit of `list` of `item` (`None` for a new item): `removed` elements
    /// (full hex ids) leave it, `added` new elements join it, and `moves` run in turn (module
    /// docs, "Order"). Returns the `order` of every new element and the `order` writes of the
    /// existing elements; nothing is written here.
    ///
    /// # Errors
    /// [`ClientError::InvalidEdit`] for a list without `order` (tags, password history), a
    /// move relative to the moved element itself, or a list too long to rewrite;
    /// [`ClientError::UnknownItem`] for a moved or neighbouring element the item does not
    /// display (or one removed by the same edit); [`ClientError::Internal`].
    pub fn plan_list_order(
        &self,
        item: Option<ItemId>,
        list: &str,
        removed: &[&str],
        added: usize,
        moves: &[ListMove],
    ) -> Result<OrderPlan, ClientError> {
        if added == 0 && moves.is_empty() {
            return Ok(OrderPlan {
                new_orders: Vec::new(),
                writes: Vec::new(),
                rewritten: false,
            });
        }
        if !has_order(list) {
            return Err(ClientError::InvalidEdit);
        }
        // Step 1.
        let mut order = self.order_before_moves(item, list, removed, added);
        apply_moves(&mut order, moves)?;
        // Step 2, or step 3 when no key fits.
        let highest = item.and_then(|item| self.highest_order(item, list));
        let rewritten = !place_between(&mut order, highest.as_ref())?;
        if rewritten {
            let keys = evenly_spaced(order.len()).map_err(|_| ClientError::InvalidEdit)?;
            for (slot, key) in order.iter_mut().zip(keys) {
                slot.key = Some(key);
                slot.placed = true;
            }
        }
        let (new_orders, writes) = plan_writes(list, order, added)?;
        Ok(OrderPlan {
            new_orders,
            writes,
            rewritten,
        })
    }

    /// `n` `order` keys for elements appended to `list` of `item` (`None` for a new item), in
    /// ascending order: [`VaultSync::plan_list_order`] with `n` new elements and nothing else.
    ///
    /// # Errors
    /// [`ClientError::InvalidEdit`] when the appends would need the list's rewrite (use
    /// [`VaultSync::plan_list_order`], which gives it), or for a list without `order`.
    pub fn append_orders(
        &self,
        item: Option<ItemId>,
        list: &str,
        n: usize,
    ) -> Result<Vec<SortKey>, ClientError> {
        let plan = self.plan_list_order(item, list, &[], n, &[])?;
        if plan.rewritten {
            return Err(ClientError::InvalidEdit);
        }
        Ok(plan.new_orders)
    }

    /// The writes that add one element to `list` under `element` (the caller's choice of id):
    /// each of `attributes` (attribute name and encoded value), and `order` as given (from
    /// [`VaultSync::plan_list_order`]; `None` writes no `order`). The schema checks run when
    /// the host writes them.
    ///
    /// Callers that mint `element` once on the client, before the first attempt to save, and
    /// pass the same id again on every retry get a save that is safe to repeat: writing the
    /// same key to the same value a second time changes nothing (ADR 0018 §6, "a list is a
    /// map from an element id to fields"), so a retry after an unclear outcome (the earlier
    /// attempt's answer was lost, not necessarily refused) cannot create a second element.
    /// [`VaultSync::new_element_writes`] is this, with a fresh id instead.
    ///
    /// # Errors
    /// [`ClientError::InvalidEdit`] for a list or attribute name the key grammar refuses.
    pub fn element_writes(
        element: ElementId,
        list: &str,
        attributes: Vec<(&str, Value)>,
        order: Option<&SortKey>,
    ) -> Result<Vec<ElementWrite>, ClientError> {
        let mut writes = Vec::with_capacity(attributes.len() + 1);
        for (attribute, value) in attributes {
            let key = element
                .key(list, attribute)
                .map_err(|_| ClientError::InvalidEdit)?;
            writes.push((key, value));
        }
        if let Some(order) = order {
            let key = element
                .key(list, ATTR_ORDER)
                .map_err(|_| ClientError::InvalidEdit)?;
            writes.push((key, Value::sort_key(order)));
        }
        Ok(writes)
    }

    /// [`VaultSync::element_writes`] under a new random element id. Returns the id with the
    /// writes.
    ///
    /// # Errors
    /// As [`VaultSync::element_writes`].
    pub fn new_element_writes<R: CryptoRng + ?Sized>(
        rng: &mut R,
        list: &str,
        attributes: Vec<(&str, Value)>,
        order: Option<&SortKey>,
    ) -> Result<(ElementId, Vec<ElementWrite>), ClientError> {
        let element = ElementId::generate(rng);
        let writes = Self::element_writes(element, list, attributes, order)?;
        Ok((element, writes))
    }
}

impl VaultSync {
    /// The writes that remove the element `element` (its full hex id) from `list` of `item`:
    /// Cleared to each attribute of it the item holds a register of, keys an M1 client never
    /// writes left out (module docs).
    ///
    /// # Errors
    /// [`ClientError::UnknownItem`] when the item displays no such element.
    pub fn element_removal_writes(
        &self,
        item: ItemId,
        list: &str,
        element: &str,
    ) -> Result<Vec<ElementWrite>, ClientError> {
        let shown = self
            .list_elements(item, list)
            .into_iter()
            .any(|e| e.element.as_str() == element);
        if !shown {
            return Err(ClientError::UnknownItem);
        }
        let keys = self
            .element_keys(item, list)
            .into_iter()
            .find(|(e, _)| e.as_str() == element)
            .map(|(_, keys)| keys)
            .unwrap_or_default();
        let writes: Vec<ElementWrite> = keys
            .into_iter()
            .filter(|key| {
                !matches!(
                    classify(key.as_key()),
                    KeyClass::Known(spec) if spec.writers == Writers::NotInM1
                )
            })
            .map(|key| (key, Value::cleared()))
            .collect();
        // At least one content attribute is cleared, or the element would still exist.
        let clears_content = writes
            .iter()
            .any(|(key, _)| attribute_role(key.as_key().attribute()) == AttributeRole::Content);
        if clears_content {
            Ok(writes)
        } else {
            Err(ClientError::InvalidEdit)
        }
    }
}
