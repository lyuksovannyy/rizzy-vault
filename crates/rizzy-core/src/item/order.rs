//! List elements and their order (ADR 0018 §6 "List elements", "List order"; ADR 0012 §1).
//!
//! A list (URIs, custom fields, password history, tags) is a map from an element id to fields,
//! `list/<elem>/attribute`. Its order is itself a field, `order`, holding a `SortKey`, so "added a
//! URI on the phone, added another on the laptop" never conflicts (ADR 0012 §1).
//!
//! **Existence.** An element exists while one of its *content* attributes displays a non-empty
//! value. `order`, `match` and `kind` are *layout* attributes and never make an element exist;
//! every other attribute is content, and for `tag/<hex>`, which has no attribute, the key itself
//! is the content attribute ([`attribute_role`], [`element_exists`]). Removing an element writes
//! Cleared to each of its attributes the writer holds (ADR 0018 §6); its registers stay, as every
//! register does (ADR 0018 §4).
//!
//! **Order.** A list sorts by `order`, then by element id; elements without `order` sort last
//! ([`compare_list_entries`]). Element ids compare as their hex digits, which is the bytewise
//! order of the ids. An `order` whose displayed value is not a valid `SortKey` (Cleared,
//! unsupported) counts as no `order`: ADR 0018 names only the absent case, and this is the
//! reading that never puts an unreadable key into the sort.
//!
//! **New sort keys.** [`sort_key_between`] returns a short `SortKey` strictly between two
//! neighbours, reading sort keys as base-256 fractions `0.k₁k₂…` (a `SortKey` never ends in
//! `0x00`, so bytewise order is fraction order). The computation is deterministic, so two
//! devices that insert between the same neighbours write the same key, and the element ids break
//! the tie.
//! When no key of at most 64 bytes fits, the client rewrites that list's `order` keys in one op,
//! or in consecutive ops if one would break the record limits (ADR 0018 §6, §10);
//! [`evenly_spaced`] gives the new keys. Which keys a writer picks is not part of the format:
//! readers accept any valid `SortKey`.

use core::cmp::Ordering;

use zeroize::Zeroizing;

use super::schema::{ATTR_KIND, ATTR_MATCH, ATTR_ORDER};
use super::value::{MAX_SORT_KEY_LEN, SortKey, ValueRef, is_sort_key};

/// Whether an attribute makes its element exist (ADR 0018 §6 "List elements").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AttributeRole {
    /// A content attribute: the element exists while one of these displays a non-empty value.
    Content,
    /// A layout attribute (`order`, `match`, `kind`): never makes an element exist.
    Layout,
}

/// The role of an element key's attribute. `None` is the attribute-less form of `tag/<hex>`,
/// whose key is its own content attribute. Unknown attributes are content.
#[must_use]
pub fn attribute_role(attribute: Option<&str>) -> AttributeRole {
    match attribute {
        Some(ATTR_ORDER | ATTR_MATCH | ATTR_KIND) => AttributeRole::Layout,
        _ => AttributeRole::Content,
    }
}

/// `true` if an element exists: one of its content attributes displays a non-empty value.
/// `attributes` yields each attribute of the element (as [`attribute_role`] takes it) with its
/// displayed encoded value.
#[must_use]
pub fn element_exists<'a>(
    attributes: impl IntoIterator<Item = (Option<&'a str>, &'a [u8])>,
) -> bool {
    attributes.into_iter().any(|(attribute, displayed)| {
        attribute_role(attribute) == AttributeRole::Content && !displayed.is_empty()
    })
}

/// One element of a list, as the list order sees it.
#[derive(Clone, Copy)]
pub struct ListEntry<'a> {
    /// The encoded value the element's `order` attribute displays, or `None` if it has no
    /// `order` register.
    pub order: Option<&'a [u8]>,
    /// The element id, as the hex digits of its key ([`super::key::FieldKeyRef::element`]).
    pub element: &'a str,
}

impl core::fmt::Debug for ListEntry<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ListEntry([REDACTED])")
    }
}

impl<'a> ListEntry<'a> {
    /// The `SortKey` payload the entry sorts by, or `None` if it sorts as "without order".
    #[must_use]
    pub fn sort_key(&self) -> Option<&'a [u8]> {
        match ValueRef::decode(self.order?) {
            Ok(ValueRef::SortKey(payload)) => Some(payload),
            _ => None,
        }
    }
}

/// The list order (ADR 0018 §6): by `order` bytewise, elements without one last, then by
/// element id.
#[must_use]
pub fn compare_list_entries(a: &ListEntry<'_>, b: &ListEntry<'_>) -> Ordering {
    let by_order = match (a.sort_key(), b.sort_key()) {
        (Some(x), Some(y)) => x.cmp(y),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    };
    by_order.then_with(|| a.element.as_bytes().cmp(b.element.as_bytes()))
}

/// Why no sort key was produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OrderError {
    /// A neighbour is not a valid `SortKey` payload (1–64 bytes, last byte not `0x00`).
    InvalidNeighbour,
    /// The lower neighbour is above the upper one.
    NotOrdered,
    /// No `SortKey` of at most 64 bytes lies strictly between the neighbours (they are equal, or
    /// too close). Rewrite the list's `order` keys with [`evenly_spaced`].
    NoRoom,
    /// More keys were asked of [`evenly_spaced`] than it can space.
    TooMany,
}

impl core::fmt::Display for OrderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::InvalidNeighbour => "neighbour is not a valid sort key",
            Self::NotOrdered => "neighbours are out of order",
            Self::NoRoom => "no sort key fits between the neighbours",
            Self::TooMany => "too many sort keys requested",
        })
    }
}

impl core::error::Error for OrderError {}

/// A `SortKey` strictly between `lower` and `upper` (ADR 0018 §6 "List order").
///
/// `None` stands for the start or the end of the list. Keys are read as base-256 fractions
/// `0.k₁k₂…`. Digit by digit, the result copies `lower` (with zeros past its end) until the
/// first position where the upper bound is at least two above it, and puts the midpoint there;
/// where the upper bound is exactly one above, it copies the lower digit and from then on is
/// below `upper` whatever follows. The midpoint is at least 1, so the key never ends in `0x00`.
/// The result is short (one byte more than the common prefix, in the usual case) but not
/// always the shortest possible. Deterministic; never panics.
///
/// # Errors
/// [`OrderError::InvalidNeighbour`] if a bound is not a `SortKey` payload,
/// [`OrderError::NotOrdered`] if `lower > upper`, and [`OrderError::NoRoom`] if no key of at
/// most 64 bytes fits (equal bounds included).
pub fn sort_key_between(lower: Option<&[u8]>, upper: Option<&[u8]>) -> Result<SortKey, OrderError> {
    if lower.is_some_and(|k| !is_sort_key(k)) || upper.is_some_and(|k| !is_sort_key(k)) {
        return Err(OrderError::InvalidNeighbour);
    }
    if let (Some(lo), Some(hi)) = (lower, upper) {
        match lo.cmp(hi) {
            Ordering::Greater => return Err(OrderError::NotOrdered),
            Ordering::Equal => return Err(OrderError::NoRoom),
            Ordering::Less => {}
        }
    }
    let lower = lower.unwrap_or_default();
    // Scratch digits, wiped on drop like every other value buffer.
    let mut out = Zeroizing::new([0u8; MAX_SORT_KEY_LEN]);
    // While `bounded` is `Some`, the digits written so far equal the prefix of `upper`. Once a
    // digit is below `upper`'s, the result stays below it whatever follows.
    let mut bounded = upper;
    for i in 0..MAX_SORT_KEY_LEN {
        let lo = u16::from(lower.get(i).copied().unwrap_or(0));
        // Past its end (only reachable if `upper <= lower`, which is excluded above) an upper
        // bound reads as 0, which leaves no room.
        let hi = bounded.map_or(256, |upper| u16::from(upper.get(i).copied().unwrap_or(0)));
        let digit = if hi >= lo + 2 {
            u16::midpoint(lo, hi)
        } else {
            lo
        };
        let [digit, _] = digit.to_le_bytes();
        if let Some(slot) = out.get_mut(i) {
            *slot = digit;
        }
        if hi >= lo + 2 {
            let key = out.get(..=i).ok_or(OrderError::NoRoom)?;
            return SortKey::from_slice(key).map_err(|_| OrderError::NoRoom);
        }
        if hi > lo {
            bounded = None;
        }
    }
    Err(OrderError::NoRoom)
}

/// `n` sort keys in strictly ascending order, spread evenly over the key space, for rewriting a
/// list's `order` keys when [`sort_key_between`] finds no room (ADR 0018 §6).
///
/// Uses `k` bytes, the fewest with `256^k > n`: key `i` is `⌊(i + 1)·256^k / (n + 1)⌋` written
/// in `k` big-endian bytes, without trailing `0x00` bytes (which leaves its fraction, and so its
/// place in the order, unchanged). Up to 255 elements get one-byte keys, and every list the
/// record limits allow (at most 4,096 registers, ADR 0018 §10) gets keys of at most two bytes.
///
/// # Errors
/// [`OrderError::TooMany`] if `n` is 2^32 or more.
pub fn evenly_spaced(n: usize) -> Result<Vec<SortKey>, OrderError> {
    let count = u64::try_from(n).map_err(|_| OrderError::TooMany)?;
    if count >= 1 << 32 {
        return Err(OrderError::TooMany);
    }
    // The fewest bytes k (1 to 4 here) with 256^k > n.
    let mut k = 1usize;
    while u128::from(count) >> (8 * k) != 0 {
        k += 1;
    }
    let space = 1u128 << (8 * k);
    let mut keys = Vec::with_capacity(n);
    for i in 0..count {
        let point = (u128::from(i) + 1) * space / (u128::from(count) + 1);
        let bytes = Zeroizing::new(point.to_be_bytes());
        let start = bytes.len().checked_sub(k).ok_or(OrderError::TooMany)?;
        let digits = bytes.get(start..).ok_or(OrderError::TooMany)?;
        // `point` is at least 1 (256^k > n), so some digit is non-zero.
        let end = digits
            .iter()
            .rposition(|d| *d != 0)
            .ok_or(OrderError::TooMany)?;
        let key = digits.get(..=end).ok_or(OrderError::TooMany)?;
        keys.push(SortKey::from_slice(key).map_err(|_| OrderError::TooMany)?);
    }
    Ok(keys)
}
