//! List elements of an item: URIs, custom fields, password history and tags (ADR 0018 §6
//! "List elements", "List order", §7 `uri/…`, `field/…`, `pwhist/…`, `tag/…`; ADR 0012 §1).
//!
//! A list is a map from an element id to fields, `list/<elem>/attribute`, so two devices that
//! add, edit or remove elements concurrently merge field by field. This module builds the
//! field writes of the three list edits; the host passes them, with any other field writes of
//! the same change, to [`VaultSync::edit_item`] (one op, whose schema checks they pass), or,
//! for a new item, to [`VaultSync::create_item`].
//!
//! | Edit | Writes |
//! |---|---|
//! | Add ([`VaultSync::new_element_writes`]) | each given attribute of a new random element id, and its `order` after the list's last element ([`VaultSync::append_orders`]) |
//! | Edit | the attribute's key with the new value: `FieldKey::element(list, element, Some(attribute))` |
//! | Remove ([`VaultSync::element_removal_writes`]) | Cleared to each attribute of the element that the item holds a register of |
//!
//! # Readings (reported)
//!
//! - **Which attributes "the writer holds"** (ADR 0018 §6: "Removing a list element writes
//!   this to each attribute of the element that the writer holds"): every current register of
//!   the item under the element's prefix, layout attributes (`order`, `kind`) included, so a
//!   concurrent edit of the order cannot keep a removed element in place. Clearing a layout
//!   attribute changes no existence; it is the literal reading.
//! - **Keys an M1 client never writes** are left out of a removal: `uri/<id>/match` ("M1
//!   clients carry it and never write it", ADR 0018 §7 owner decision 2) and
//!   `share/<id>/secret` (M5). Neither is a content attribute of its element (`match` is
//!   layout; a share is not a list this client edits), so the element still stops existing.
//! - **Tags** have no attributes: a tag is added with Bool `0x01` and removed with Cleared on
//!   its own key (`rizzy_core::item::tag::tag_key`); the generic removal does the same.
//! - **Order of new elements:** after the highest valid `order` the list displays, each key
//!   strictly above the previous one ([`sort_key_between`] with no upper bound). Elements
//!   without a valid `order` sort last whatever is written (ADR 0018 §6), so they are not
//!   neighbours. If no key fits (64 bytes of `0xFF`), the edit is refused
//!   ([`ClientError::InvalidEdit`]); the list's rewrite with `evenly_spaced` is not in this
//!   build.

use core::fmt;

use rizzy_core::ids::ItemId;
use rizzy_core::item::key::{ElementId, FieldKey, FieldKeyRef};
use rizzy_core::item::order::{
    AttributeRole, ListEntry, attribute_role, compare_list_entries, element_exists,
    sort_key_between,
};
use rizzy_core::item::schema::{ATTR_ORDER, KeyClass, Writers, classify};
use rizzy_core::item::value::{SortKey, Value, ValueRef};
use rizzy_core::rng::CryptoRng;
use zeroize::Zeroizing;

use crate::error::ClientError;
use crate::sync::VaultSync;

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

    /// The elements of `list` (`uri`, `field`, `pwhist`, `tag`, …) the item displays: those
    /// one of whose content attributes displays a non-empty value, in list order (`order`,
    /// then element id; ADR 0018 §6).
    #[must_use]
    pub fn list_elements(&self, item: ItemId, list: &str) -> Vec<ListElement> {
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
        out.into_iter().map(|(_, element)| element).collect()
    }

    /// `n` `order` keys for elements appended to `list` of `item` (`None` for a new item), in
    /// ascending order, each above the highest valid `order` the list's registers display
    /// (module docs, "Order of new elements").
    ///
    /// # Errors
    /// [`ClientError::InvalidEdit`] when no key fits.
    pub fn append_orders(
        &self,
        item: Option<ItemId>,
        list: &str,
        n: usize,
    ) -> Result<Vec<SortKey>, ClientError> {
        let mut highest: Option<Zeroizing<Vec<u8>>> = None;
        if let Some(item) = item {
            for (_, keys) in self.element_keys(item, list) {
                for key in keys {
                    if key.as_key().attribute() != Some(ATTR_ORDER) {
                        continue;
                    }
                    let Some(value) = self.field_value(item, key.as_str()) else {
                        continue;
                    };
                    if let Ok(ValueRef::SortKey(payload)) = value.decode()
                        && highest.as_ref().is_none_or(|h| payload > h.as_slice())
                    {
                        highest = Some(Zeroizing::new(payload.to_vec()));
                    }
                }
            }
        }
        let mut keys = Vec::with_capacity(n);
        for _ in 0..n {
            let next = sort_key_between(highest.as_ref().map(|h| h.as_slice()), None)
                .map_err(|_| ClientError::InvalidEdit)?;
            highest = Some(Zeroizing::new(next.as_bytes().to_vec()));
            keys.push(next);
        }
        Ok(keys)
    }

    /// The writes that add one element to `list`: each of `attributes` (attribute name and
    /// encoded value) under a new random element id, and `order` as given (from
    /// [`VaultSync::append_orders`]; `None` writes no `order`). Returns the element id with the
    /// writes. The schema checks run when the host writes them.
    ///
    /// # Errors
    /// [`ClientError::InvalidEdit`] for a list or attribute name the key grammar refuses.
    pub fn new_element_writes<R: CryptoRng + ?Sized>(
        rng: &mut R,
        list: &str,
        attributes: Vec<(&str, Value)>,
        order: Option<&SortKey>,
    ) -> Result<(ElementId, Vec<ElementWrite>), ClientError> {
        let element = ElementId::generate(rng);
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
        Ok((element, writes))
    }

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
