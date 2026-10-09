//! Items across the boundary: what a list or an item view shows, and what an edit asks for
//! (ADR 0013 §3 rule 3, "Plaintext crosses at the smallest useful size"; ADR 0018 §6–§7; the
//! writes are `rizzy-client`'s `items` and `lists`).
//!
//! - **A list** ([`ItemSummary`]) carries the id, the type, the name, the login's username,
//!   the favourite flag, whether a TOTP secret is set, the item's tags and the host of its
//!   first website. Never a concealed value.
//! - **An item view** ([`FieldView`]) carries every displayed field with its key split into
//!   list, element and attribute, its kind, and its value **only if the schema shows it**. A
//!   concealed value (passwords, TOTP secrets, card numbers, hidden custom fields, and to be
//!   safe every key this build does not know) crosses only through
//!   [`crate::Session::reveal_field`], on the user's request.
//! - **An edit** ([`ItemDraft`]) is built in Rust from the user's input, call by call, and
//!   written as one op by [`crate::Session::create_item`] or [`crate::Session::edit_item`],
//!   where every write passes the schema checks. The draft holds the typed values in zeroizing
//!   buffers until then.
//!
//! The draft's calls mirror `rv item create`/`item edit`: `set` (a field, by its final key,
//! including an existing element's attribute such as `uri/<id>/value`), `clear`, `tag` and
//! `untag`, `addUri`, `addCustomField` (text, hidden or boolean) and `removeElement`.

use core::fmt;
use std::collections::HashMap;

use rizzy_client::ClientError;
use rizzy_client::items::{FieldKey, ItemId, ItemLifecycle, ItemType, Value};
use rizzy_client::lists::{ListMove, ListPlace, MAX_WRITES_PER_OP};
use rizzy_client::rizzy_core::item::key::ElementId;
use rizzy_client::rizzy_core::item::schema::{
    ATTR_ALG, ATTR_CREATED_MS, ATTR_CREDENTIAL_ID, ATTR_DISCOVERABLE, ATTR_KIND, ATTR_LABEL,
    ATTR_PRIVATE_KEY, ATTR_PUBLIC_KEY_COSE, ATTR_RP_ID, ATTR_USER_HANDLE, ATTR_VALUE,
    CUSTOM_KIND_BOOLEAN, CUSTOM_KIND_HIDDEN, CUSTOM_KIND_TEXT, Concealment, CustomFieldKind,
    Expected, ITEM_FAVORITE, ITEM_NAME, KeyClass, LIST_FIELD, LIST_PASSKEY, LIST_TAG, LIST_URI,
    LOGIN_TOTP, LOGIN_USERNAME, classify,
};
use rizzy_client::rizzy_core::item::tag::{tag_key, tag_name};
use rizzy_client::rizzy_core::item::value::ValueRef;
use rizzy_client::sync::VaultSync;
use wasm_bindgen::prelude::wasm_bindgen;
use zeroize::Zeroizing;

use crate::error::{CoreError, CoreResult};
use crate::rng::os_rng;

/// The most entries one draft takes: the writes of one op (ADR 0018 §10: 1,024).
pub const MAX_DRAFT_ENTRIES: usize = 1024;

/// The item types the web vault names, as `rv --type` names them.
///
/// No `"passkey"` entry: `0x000A` (the standalone-passkey candidate ADR 0018 reserved) was
/// released back to unassigned by ADR 0039 §1, which puts passkeys on the `passkey/<id>/…` list
/// of an existing Login item instead (`rizzy-core`'s `item::schema::LIST_PASSKEY`).
pub const TYPES: [(&str, ItemType); 9] = [
    ("login", ItemType::LOGIN),
    ("note", ItemType::SECURE_NOTE),
    ("card", ItemType::CARD),
    ("identity", ItemType::IDENTITY),
    ("ssh-key", ItemType::SSH_KEY),
    ("api-credential", ItemType::API_CREDENTIAL),
    ("software-license", ItemType::SOFTWARE_LICENSE),
    ("wifi", ItemType::WIFI),
    ("bank-account", ItemType::BANK_ACCOUNT),
];

/// The name of an item type; `unknown` for one this build does not name.
pub(crate) fn type_name(item_type: Option<ItemType>) -> &'static str {
    TYPES
        .iter()
        .find(|(_, t)| Some(*t) == item_type)
        .map_or("unknown", |(name, _)| name)
}

/// The item type a name names.
pub(crate) fn type_from_name(name: &str) -> CoreResult<ItemType> {
    TYPES
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, t)| *t)
        .ok_or(ClientError::InvalidInput.into())
}

/// Lowercase hex.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

/// The 16 bytes of a 32-digit hex id (an item, element or device id from the host), upper or
/// lower case. Host input: bounded and parsed without panics (ADR 0013 §3 rule 8).
///
/// # Errors
/// `invalid_input` for anything but 32 hex digits.
pub fn parse_id(text: &str) -> CoreResult<[u8; 16]> {
    let bad = || CoreError::from(ClientError::InvalidInput);
    let digits = text.as_bytes();
    if digits.len() != 32 {
        return Err(bad());
    }
    let mut out = [0u8; 16];
    for (byte, pair) in out.iter_mut().zip(digits.chunks_exact(2)) {
        let mut value = 0u8;
        for d in pair {
            let nibble = match d {
                b'0'..=b'9' => d - b'0',
                b'a'..=b'f' => d - b'a' + 10,
                b'A'..=b'F' => d - b'A' + 10,
                _ => return Err(bad()),
            };
            value = (value << 4) | nibble;
        }
        *byte = value;
    }
    Ok(out)
}

/// The item a hex id names.
pub(crate) fn item_id(text: &str) -> CoreResult<ItemId> {
    Ok(ItemId::from_bytes(parse_id(text)?))
}

/// The element id a hex id names.
fn element_id_of(text: &str) -> CoreResult<ElementId> {
    Ok(ElementId::from_bytes(parse_id(text)?))
}

/// A fresh element id (32 lowercase hex digits), for the host to mint once per new list row —
/// a website or a custom field the user is about to add — and pass to [`ItemDraft::add_uri`]
/// or [`ItemDraft::add_custom_field`] on every attempt to save it, the first and any retry
/// alike (module docs, "An edit"). No session is needed: the id carries no key material.
#[wasm_bindgen(js_name = generateElementId)]
#[must_use]
pub fn generate_element_id() -> String {
    let element = ElementId::generate(&mut os_rng());
    hex(element.as_bytes())
}

/// The text of a field, if it holds one.
fn text_field(vault: &VaultSync, item: ItemId, key: &str) -> Option<Zeroizing<String>> {
    let value = vault.field_value(item, key)?;
    match value.decode() {
        Ok(ValueRef::Text(text)) => Some(Zeroizing::new(text.to_owned())),
        _ => None,
    }
}

/// Whether a field is concealed unless revealed: what the schema conceals, and, to be safe,
/// every key this build does not know (as `rv item show` decides).
pub(crate) fn concealed(key: &FieldKey) -> bool {
    match classify(key.as_key()) {
        KeyClass::Known(spec) => spec.concealment != Concealment::Shown,
        _ => true,
    }
}

/// One row of an item list (module docs). Wiped when freed.
#[wasm_bindgen]
pub struct ItemSummary {
    /// The item id, 32 hex digits.
    id: String,
    /// The type's name ([`TYPES`]).
    item_type: &'static str,
    /// `item.name`, or empty.
    title: Zeroizing<String>,
    /// `login.username`, if set.
    username: Option<Zeroizing<String>>,
    /// `item.favorite`.
    favorite: bool,
    /// Whether `login.totp` is set.
    has_totp: bool,
    /// Whether the item is in the trash.
    trashed: bool,
    /// The item's tag names, display order (ADR 0018 §6).
    tags: Vec<Zeroizing<String>>,
    /// The host of the item's first website (`uri` list), if it has one and the host could be
    /// parsed out. Never the full URI, never userinfo, never path or query (module docs).
    website_host: Option<Zeroizing<String>>,
}

impl fmt::Debug for ItemSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ItemSummary")
            .field("id", &self.id)
            .field("item_type", &self.item_type)
            .finish_non_exhaustive()
    }
}

#[wasm_bindgen]
impl ItemSummary {
    /// The item id, 32 lowercase hex digits.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn id(&self) -> String {
        self.id.clone()
    }

    /// The type's name: `login`, `note`, `card`, `identity`, `ssh-key`, `api-credential`,
    /// `software-license`, `wifi`, `bank-account`, `passkey`, or `unknown`.
    #[wasm_bindgen(getter, js_name = itemType)]
    #[must_use]
    pub fn item_type(&self) -> String {
        self.item_type.to_owned()
    }

    /// The item's name, or an empty string.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn title(&self) -> String {
        self.title.as_str().to_owned()
    }

    /// The login's username, or `undefined`.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn username(&self) -> Option<String> {
        self.username.as_ref().map(|u| u.as_str().to_owned())
    }

    /// Whether the item is a favourite.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn favorite(&self) -> bool {
        self.favorite
    }

    /// Whether the item has a TOTP secret ([`crate::Session::totp`]).
    #[wasm_bindgen(getter, js_name = hasTotp)]
    #[must_use]
    pub fn has_totp(&self) -> bool {
        self.has_totp
    }

    /// Whether the item is in the trash.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn trashed(&self) -> bool {
        self.trashed
    }

    /// The item's tag names, display order.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn tags(&self) -> Vec<String> {
        self.tags.iter().map(|t| t.as_str().to_owned()).collect()
    }

    /// The host of the item's first website, or `undefined` (module docs).
    #[wasm_bindgen(getter, js_name = websiteHost)]
    #[must_use]
    pub fn website_host(&self) -> Option<String> {
        self.website_host.as_ref().map(|h| h.as_str().to_owned())
    }
}

/// The summary of `item`, if it is active or trashed and not the vault-settings item.
pub(crate) fn summary(vault: &VaultSync, item: ItemId) -> Option<ItemSummary> {
    let trashed = match vault.item_lifecycle(item) {
        ItemLifecycle::Active => false,
        ItemLifecycle::Trashed => true,
        _ => return None,
    };
    let item_type = vault.item_type(item);
    if item_type == Some(ItemType::VAULT_SETTINGS) {
        return None;
    }
    let favorite = vault
        .field_value(item, ITEM_FAVORITE)
        .is_some_and(|v| matches!(v.decode(), Ok(ValueRef::Bool(true))));
    let has_totp = vault
        .field_value(item, LOGIN_TOTP)
        .is_some_and(|v| matches!(v.decode(), Ok(ValueRef::Text(t)) if !t.is_empty()));
    Some(ItemSummary {
        id: hex(item.as_bytes()),
        item_type: type_name(item_type),
        title: text_field(vault, item, ITEM_NAME).unwrap_or_default(),
        username: text_field(vault, item, LOGIN_USERNAME).filter(|u| !u.is_empty()),
        favorite,
        has_totp,
        trashed,
        tags: item_tags(vault, item),
        website_host: first_website_host(vault, item),
    })
}

/// The item's tag names, in display order ([`VaultSync::list_elements`]'s order over `tag`).
/// A `tag/<hex>` element whose hex is not a name [`tag_key`] could have produced (module docs
/// of `rizzy_core::item::tag`) is skipped: it is carried but never shown as a tag.
fn item_tags(vault: &VaultSync, item: ItemId) -> Vec<Zeroizing<String>> {
    vault
        .list_elements(item, LIST_TAG)
        .into_iter()
        .filter_map(|element| {
            let key =
                FieldKey::parse(format!("{LIST_TAG}/{}", element.element.as_str()).as_bytes())
                    .ok()?;
            tag_name(key.as_key()).ok()
        })
        .collect()
}

/// The host of the item's first website (the first element of the `uri` list that has a
/// `value`), if one is set and a host could be parsed out of it.
fn first_website_host(vault: &VaultSync, item: ItemId) -> Option<Zeroizing<String>> {
    let first = vault.list_elements(item, LIST_URI).into_iter().next()?;
    let key = format!("{LIST_URI}/{}/{ATTR_VALUE}", first.element.as_str());
    let uri = text_field(vault, item, &key)?;
    website_host(&uri)
}

/// The host of a website address the user typed, never its userinfo, path, query or fragment.
///
/// `uri` may or may not carry a scheme (`https://example.com/x` or just `example.com/x`).
/// Whichever authority segment results is split on the last `@` to drop any `user:pass@`
/// userinfo, and on a bracketed IPv6 literal or the first remaining `:` to drop the port.
/// Anything that leaves no host, or that is not useful to show (empty), yields `None`: there is
/// no secret in the result, but a best-effort guess that leaks a path or credential would be
/// worse than showing nothing.
fn website_host(uri: &str) -> Option<Zeroizing<String>> {
    let uri = uri.trim();
    let after_scheme = uri.split_once("://").map_or(uri, |(_, rest)| rest);
    let end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..end];
    let host_and_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if host_and_port.starts_with('[') {
        // An IPv6 literal: the host is up to and including the closing bracket.
        let close = host_and_port.find(']')?;
        &host_and_port[..=close]
    } else {
        host_and_port
            .split_once(':')
            .map_or(host_and_port, |(h, _)| h)
    };
    if host.is_empty() {
        None
    } else {
        Some(Zeroizing::new(host.to_owned()))
    }
}

/// The summaries of the active items, or of the trashed ones.
pub(crate) fn summaries(vault: &VaultSync, trash: bool) -> Vec<ItemSummary> {
    vault
        .item_ids()
        .into_iter()
        .filter_map(|item| summary(vault, item))
        .filter(|s| s.trashed == trash)
        .collect()
}

/// One displayed field of an item (module docs). Wiped when freed.
#[wasm_bindgen]
pub struct FieldView {
    /// The final key (user content: a tag key holds the tag's name).
    key: Zeroizing<String>,
    /// The list, for an element key.
    list: Option<String>,
    /// The element id, for an element key (a tag's is its name's hex).
    element: Option<Zeroizing<String>>,
    /// The attribute, for an element key with one.
    attribute: Option<String>,
    /// The tag's name, for a tag key.
    tag: Option<Zeroizing<String>>,
    /// `text`, `bool`, `number`, `enum`, `bytes`, `sort_key` or `unknown`.
    kind: &'static str,
    /// Whether the value is withheld until revealed.
    concealed: bool,
    /// The value as text, unless concealed or not text-like.
    value: Option<Zeroizing<String>>,
    /// Whether the field holds conflicting values (ADR 0018 §6).
    conflict: bool,
}

impl fmt::Debug for FieldView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FieldView")
            .field("kind", &self.kind)
            .field("concealed", &self.concealed)
            .finish_non_exhaustive()
    }
}

#[wasm_bindgen]
impl FieldView {
    /// The field's final key (`login.password`, `uri/<id>/value`, `tag/<hex>`, …).
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn key(&self) -> String {
        self.key.as_str().to_owned()
    }

    /// The list (`uri`, `field`, `pwhist`, `tag`, …) of an element key, or `undefined`.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn list(&self) -> Option<String> {
        self.list.clone()
    }

    /// The element id of an element key, or `undefined`.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn element(&self) -> Option<String> {
        self.element.as_ref().map(|e| e.as_str().to_owned())
    }

    /// The attribute (`value`, `label`, `kind`, `order`, …) of an element key, or `undefined`.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn attribute(&self) -> Option<String> {
        self.attribute.clone()
    }

    /// The tag's name for a tag key, or `undefined`.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn tag(&self) -> Option<String> {
        self.tag.as_ref().map(|t| t.as_str().to_owned())
    }

    /// The value's kind: `text`, `bool`, `number`, `enum`, `bytes`, `sort_key` or `unknown`.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn kind(&self) -> String {
        self.kind.to_owned()
    }

    /// Whether the value is withheld until [`crate::Session::reveal_field`].
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn concealed(&self) -> bool {
        self.concealed
    }

    /// The value as text (`true`/`false` for a bool, decimal for a number or enum), or
    /// `undefined` when concealed, bytes, an order key or unreadable.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn value(&self) -> Option<String> {
        self.value.as_ref().map(|v| v.as_str().to_owned())
    }

    /// Whether the field holds conflicting values; the one shown is the one shown everywhere.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn conflict(&self) -> bool {
        self.conflict
    }
}

/// The kind and text of a value. Bytes and order keys have no text.
pub(crate) fn kind_and_text(value: &Value) -> (&'static str, Option<Zeroizing<String>>) {
    match value.decode() {
        Ok(ValueRef::Text(text)) => ("text", Some(Zeroizing::new(text.to_owned()))),
        Ok(ValueRef::Bool(flag)) => ("bool", Some(Zeroizing::new(flag.to_string()))),
        Ok(ValueRef::U64(number)) => ("number", Some(Zeroizing::new(number.to_string()))),
        Ok(ValueRef::Enum(number)) => ("enum", Some(Zeroizing::new(number.to_string()))),
        Ok(ValueRef::Bytes(_)) => ("bytes", None),
        Ok(ValueRef::SortKey(_)) => ("sort_key", None),
        Ok(ValueRef::Cleared) | Err(_) => ("unknown", None),
    }
}

/// The item that `id` names, if it is active or trashed.
pub(crate) fn visible_item(vault: &VaultSync, id: &str) -> CoreResult<ItemId> {
    let item = item_id(id)?;
    match vault.item_lifecycle(item) {
        ItemLifecycle::Active | ItemLifecycle::Trashed => Ok(item),
        _ => Err(ClientError::UnknownItem.into()),
    }
}

/// The displayed fields of `item`, concealed values withheld (module docs).
///
/// `vault.field_keys` gives no guarantee about the order of two elements of the same list: the
/// `order` attribute (ADR 0018 §6) is a value elements carry, not a property of the key's
/// bytes. [`reorder_list_elements`] imposes it afterwards, so a host that (like `packages/core`
/// `group`) assumes the elements of one list arrive in display order gets that.
pub(crate) fn fields(vault: &VaultSync, item: ItemId) -> Vec<FieldView> {
    let mut out = Vec::new();
    for key in vault.field_keys(item) {
        let Ok(parsed) = FieldKey::parse(key.as_bytes()) else {
            continue;
        };
        let Some(value) = vault.field_value(item, &key) else {
            continue;
        };
        if value.is_cleared() {
            continue;
        }
        let parts = parsed.as_key();
        let hidden = concealed(&parsed);
        let (kind, text) = kind_and_text(&value);
        out.push(FieldView {
            list: parts.list().map(str::to_owned),
            element: parts.element().map(|e| Zeroizing::new(e.to_owned())),
            attribute: parts.attribute().map(str::to_owned),
            tag: tag_name(parts).ok(),
            kind,
            concealed: hidden,
            value: if hidden { None } else { text },
            conflict: vault.field_conflicts(item, &key),
            key,
        });
    }
    reorder_list_elements(vault, item, &mut out);
    out
}

/// Moves the rows of `out` so that, within each list, an element's attributes come before a
/// later element's, in [`VaultSync::list_elements`]'s order — the order ADR 0018 §6 defines,
/// already used to show an item's websites and custom fields. A row of a fixed key or a tag
/// (`list` is `None`) is not reordered against other such rows: [`Vec::sort_by_key`] is a
/// stable sort, so giving every one of them the same key (`0`) leaves them in their original
/// relative order, interleaved however they land among the ranked rows (`reorder_list_elements`
/// changes which list's rows come first, never a fixed field's or tag's position among its
/// own kind, and `packages/core`'s `group` only reads order within one list).
fn reorder_list_elements(vault: &VaultSync, item: ItemId, out: &mut [FieldView]) {
    let mut lists: Vec<&str> = Vec::new();
    for field in out.iter() {
        if let Some(list) = field.list.as_deref()
            && !lists.contains(&list)
        {
            lists.push(list);
        }
    }
    let mut rank: HashMap<(String, String), usize> = HashMap::new();
    for list in lists {
        for (index, element) in vault.list_elements(item, list).into_iter().enumerate() {
            rank.insert(
                (list.to_owned(), element.element.as_str().to_owned()),
                index,
            );
        }
    }
    out.sort_by_key(
        |field| match (field.list.as_deref(), field.element.as_deref()) {
            (Some(list), Some(element)) => rank
                .get(&(list.to_owned(), element.to_owned()))
                .copied()
                .unwrap_or(usize::MAX),
            _ => 0,
        },
    );
}

/// The value of one field of `item` as text, concealed or not (ADR 0013 §3 rule 3: "A secret
/// field value crosses only when the user reveals it").
pub(crate) fn reveal(vault: &VaultSync, item: ItemId, key: &str) -> CoreResult<Zeroizing<String>> {
    let value = vault
        .field_value(item, key)
        .filter(|v| !v.is_cleared())
        .ok_or(ClientError::UnknownItem)?;
    kind_and_text(&value)
        .1
        .ok_or(ClientError::InvalidInput.into())
}

/// A custom field's kind, as the draft names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CustomKind {
    /// Text, shown.
    Text,
    /// Text, concealed.
    Hidden,
    /// A boolean.
    Boolean,
}

/// A new passkey's fields (ADR 0039 §1), as `createPasskey`'s result hands them straight to
/// [`ItemDraft::add_passkey`]. `user_handle` and `private_key` are zeroizing: the private key
/// in particular must never outlive this one write (`crate::passkey`'s own module docs, "the
/// caller's one job is to encrypt this straight into a new field... and then drop every copy
/// of it"). `credential_id` and `public_key_cose` are not secret — the relying party already
/// has both.
struct NewPasskey {
    /// `passkey/<id>/rp_id`.
    rp_id: Zeroizing<String>,
    /// `passkey/<id>/user_handle`.
    user_handle: Zeroizing<Vec<u8>>,
    /// `passkey/<id>/credential_id`.
    credential_id: Vec<u8>,
    /// `passkey/<id>/private_key`.
    private_key: Zeroizing<Vec<u8>>,
    /// `passkey/<id>/public_key_cose`.
    public_key_cose: Vec<u8>,
    /// `passkey/<id>/alg`: this schema's own small-positive-integer convention (`1` = ES256,
    /// `2` = `EdDSA`), not the real negative COSE id.
    alg: u16,
    /// `passkey/<id>/discoverable`.
    discoverable: bool,
    /// `passkey/<id>/created_ms`.
    created_ms: u64,
}

/// One entry of a draft.
enum Entry {
    /// A field by its final key, with the typed text.
    Set(String, Zeroizing<String>),
    /// A field cleared.
    Clear(String),
    /// A tag added.
    Tag(Zeroizing<String>),
    /// A tag removed.
    Untag(Zeroizing<String>),
    /// A new URI, under the element id the host minted for it.
    AddUri(ElementId, Zeroizing<String>),
    /// A new custom field, under the element id the host minted for it: label, kind, value.
    AddCustom(ElementId, Zeroizing<String>, CustomKind, Zeroizing<String>),
    /// A new passkey, under the element id the host minted for it (ADR 0039 §1).
    AddPasskey(ElementId, Box<NewPasskey>),
    /// An element removed: list, full element id.
    Remove(String, String),
    /// An existing element moved: list, full element id, place.
    Move(String, String, MovePlace),
}

/// Where [`Entry::Move`] puts an element, as the host names it (`"first"`, `"last"`,
/// `"before"`, `"after"`); `Debug` redacted as item data.
pub(crate) enum MovePlace {
    /// First in the list.
    First,
    /// Last in the list.
    Last,
    /// Just before this element (its full hex id).
    Before(String),
    /// Just after this element (its full hex id).
    After(String),
}

/// The changes of one create or edit (module docs). Values are wiped when the draft is freed
/// or written; `Debug` shows the number of entries only.
#[wasm_bindgen]
#[derive(Default)]
pub struct ItemDraft {
    /// The entries, in the order given.
    entries: Vec<Entry>,
}

impl fmt::Debug for ItemDraft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ItemDraft")
            .field("entries", &self.entries.len())
            .finish()
    }
}

#[wasm_bindgen]
impl ItemDraft {
    /// An empty draft.
    #[wasm_bindgen(constructor)]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets a field by its final key: a fixed key (`item.name`, `login.password`, …) or an
    /// attribute of an existing element (`uri/<id>/value`, `field/<id>/value`). The text is
    /// encoded as the schema expects when the draft is written (`true`/`false` for a bool,
    /// decimal for a number or enum).
    ///
    /// # Errors
    /// `invalid_input` past [`MAX_DRAFT_ENTRIES`] entries.
    pub fn set(&mut self, key: &str, text: &str) -> Result<(), CoreError> {
        self.push(Entry::Set(key.to_owned(), Zeroizing::new(text.to_owned())))
    }

    /// Clears a field by its final key.
    ///
    /// # Errors
    /// As [`ItemDraft::set`].
    pub fn clear(&mut self, key: &str) -> Result<(), CoreError> {
        self.push(Entry::Clear(key.to_owned()))
    }

    /// Adds a tag.
    ///
    /// # Errors
    /// As [`ItemDraft::set`].
    pub fn tag(&mut self, name: &str) -> Result<(), CoreError> {
        self.push(Entry::Tag(Zeroizing::new(name.to_owned())))
    }

    /// Removes a tag.
    ///
    /// # Errors
    /// As [`ItemDraft::set`].
    pub fn untag(&mut self, name: &str) -> Result<(), CoreError> {
        self.push(Entry::Untag(Zeroizing::new(name.to_owned())))
    }

    /// Adds a URI, after the item's last one, under `element_id` (32 lowercase hex digits):
    /// the host's choice of id, from [`generate_element_id`] — minted once per row and passed
    /// again on every retry, so that retrying a save after an unclear outcome writes the same
    /// element instead of a second one (module docs; `rizzy_client::sync::VaultSync::element_writes`).
    ///
    /// # Errors
    /// `invalid_input` for an `element_id` that is not 32 hex digits; as [`ItemDraft::set`].
    #[wasm_bindgen(js_name = addUri)]
    pub fn add_uri(&mut self, element_id: &str, uri: &str) -> Result<(), CoreError> {
        let element = element_id_of(element_id)?;
        self.push(Entry::AddUri(element, Zeroizing::new(uri.to_owned())))
    }

    /// Adds a custom field after the item's last one, under `element_id` (as [`ItemDraft::add_uri`]
    /// takes it). `kind` is `text`, `hidden` or `boolean` (whose value is `true` or `false`).
    ///
    /// # Errors
    /// `invalid_input` for another kind or a bad `element_id`; as [`ItemDraft::set`].
    #[wasm_bindgen(js_name = addCustomField)]
    pub fn add_custom_field(
        &mut self,
        element_id: &str,
        label: &str,
        kind: &str,
        value: &str,
    ) -> Result<(), CoreError> {
        let element = element_id_of(element_id)?;
        let kind = match kind {
            "text" => CustomKind::Text,
            "hidden" => CustomKind::Hidden,
            "boolean" => CustomKind::Boolean,
            _ => return Err(ClientError::InvalidInput.into()),
        };
        self.push(Entry::AddCustom(
            element,
            Zeroizing::new(label.to_owned()),
            kind,
            Zeroizing::new(value.to_owned()),
        ))
    }

    /// Adds a new passkey to this item's `passkey/` list (ADR 0039 §1), under `element_id` (as
    /// [`ItemDraft::add_uri`] takes it): the write path for `createPasskey`'s result. The host
    /// must call this immediately with the created private key and never retain a second copy
    /// of it (`NewPasskey`'s own doc comment, not linkable here: it is private). `alg` is `1`
    /// for ES256 or `2` for `EdDSA` (ADR 0039 §1); any other value is refused by the schema
    /// check when the draft is written, not here.
    ///
    /// # Errors
    /// `invalid_input` for a bad `element_id`; as [`ItemDraft::set`].
    #[wasm_bindgen(js_name = addPasskey)]
    #[expect(
        clippy::too_many_arguments,
        reason = "mirrors the fixed field set ADR 0039 §1 defines for one passkey; splitting it into a second builder call would only let a caller forget a field, not simplify anything"
    )]
    pub fn add_passkey(
        &mut self,
        element_id: &str,
        rp_id: &str,
        user_handle: &[u8],
        credential_id: &[u8],
        private_key: &[u8],
        public_key_cose: &[u8],
        alg: u16,
        discoverable: bool,
        created_ms: u64,
    ) -> Result<(), CoreError> {
        let element = element_id_of(element_id)?;
        self.push(Entry::AddPasskey(
            element,
            Box::new(NewPasskey {
                rp_id: Zeroizing::new(rp_id.to_owned()),
                user_handle: Zeroizing::new(user_handle.to_vec()),
                credential_id: credential_id.to_vec(),
                private_key: Zeroizing::new(private_key.to_vec()),
                public_key_cose: public_key_cose.to_vec(),
                alg,
                discoverable,
                created_ms,
            }),
        ))
    }

    /// Moves an existing element (as [`FieldView::element`] gives it) of `list`: `place` is
    /// `first`, `last`, `before` or `after`, and `relative` is the neighbouring element's full
    /// hex id, required for `before`/`after`. Applied only when the draft is written
    /// ([`crate::Session::edit_item`]): moving the same element to the same place twice writes
    /// the same `order` both times, so retrying this is as safe as retrying [`ItemDraft::add_uri`].
    ///
    /// # Errors
    /// `invalid_input` for an unknown `place` or a missing `relative`; as [`ItemDraft::set`].
    #[wasm_bindgen(js_name = moveElement)]
    pub fn move_element(
        &mut self,
        list: &str,
        element: &str,
        place: &str,
        relative: Option<String>,
    ) -> Result<(), CoreError> {
        let to = match place {
            "first" => MovePlace::First,
            "last" => MovePlace::Last,
            "before" => MovePlace::Before(relative.ok_or(ClientError::InvalidInput)?),
            "after" => MovePlace::After(relative.ok_or(ClientError::InvalidInput)?),
            _ => return Err(ClientError::InvalidInput.into()),
        };
        self.push(Entry::Move(list.to_owned(), element.to_owned(), to))
    }

    /// Removes an element (a URI, a custom field, …) of `list` by its full element id, as
    /// [`FieldView::element`] gives it.
    ///
    /// # Errors
    /// As [`ItemDraft::set`].
    #[wasm_bindgen(js_name = removeElement)]
    pub fn remove_element(&mut self, list: &str, element: &str) -> Result<(), CoreError> {
        self.push(Entry::Remove(list.to_owned(), element.to_owned()))
    }

    /// The number of entries.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn length(&self) -> usize {
        self.entries.len()
    }
}

impl ItemDraft {
    /// Adds an entry, within the bound.
    fn push(&mut self, entry: Entry) -> CoreResult<()> {
        if self.entries.len() >= MAX_DRAFT_ENTRIES {
            return Err(ClientError::InvalidInput.into());
        }
        self.entries.push(entry);
        Ok(())
    }

    /// Whether the draft holds nothing.
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A field write.
pub(crate) type Write = (FieldKey, Value);

/// The Text value of user input.
fn text(input: &str) -> CoreResult<Value> {
    Value::text(input).map_err(|_| ClientError::InvalidEdit.into())
}

/// The Bool value of `true`/`yes` or `false`/`no`.
fn boolean(input: &str) -> CoreResult<Value> {
    match input {
        "true" | "yes" => Ok(Value::bool(true)),
        "false" | "no" => Ok(Value::bool(false)),
        _ => Err(ClientError::InvalidEdit.into()),
    }
}

/// The Bytes value of raw bytes (ADR 0039 §1's passkey fields: never user-typed text, so
/// `encode`'s string path is not used for these attributes).
fn bytes(input: &[u8]) -> CoreResult<Value> {
    Value::bytes(input).map_err(|_| ClientError::InvalidEdit.into())
}

/// [`Entry::AddPasskey`]'s writes, under `element`: every fixed field ADR 0039 §1's table
/// lists for one passkey, and no `order` — unlike `uri`/`field`, that table has no
/// `passkey/<id>/order` row, so this list carries no layout order (ADR 0039 §1 is the
/// exhaustive field list, not a starting point to extend; what order a client displays
/// multiple passkeys in is unspecified and left to the owner to decide in a future ADR, not
/// invented here). Split out of [`writes`] only to keep that function's own line count under
/// the workspace lint's cap — the logic is exactly what `writes`' `AddUri`/`AddCustom` arms
/// already do inline, at this one entry's larger, fixed field count.
fn passkey_writes(element: ElementId, passkey: &NewPasskey) -> CoreResult<Vec<Write>> {
    VaultSync::element_writes(
        element,
        LIST_PASSKEY,
        vec![
            (ATTR_RP_ID, text(&passkey.rp_id)?),
            (ATTR_USER_HANDLE, bytes(&passkey.user_handle)?),
            (ATTR_CREDENTIAL_ID, bytes(&passkey.credential_id)?),
            (ATTR_PRIVATE_KEY, bytes(&passkey.private_key)?),
            (ATTR_PUBLIC_KEY_COSE, bytes(&passkey.public_key_cose)?),
            (ATTR_ALG, Value::enumeration(passkey.alg)),
            (ATTR_DISCOVERABLE, Value::bool(passkey.discoverable)),
            (ATTR_CREATED_MS, Value::u64(passkey.created_ms)),
        ],
        None,
    )
    .map_err(Into::into)
}

/// The kind a custom field displays.
fn custom_kind(vault: &VaultSync, item: ItemId, element: &str) -> CustomFieldKind {
    let key = format!("{LIST_FIELD}/{element}/{ATTR_KIND}");
    let value = vault.field_value(item, &key);
    CustomFieldKind::from_displayed(value.as_ref().and_then(|v| v.decode().ok()))
}

/// The encoded value of `text` for `key`, as the schema expects it (as `rv` encodes it). A
/// custom field's value follows the kind the field displays.
fn encode(
    vault: &VaultSync,
    item: Option<ItemId>,
    key: &FieldKey,
    input: &str,
) -> CoreResult<Value> {
    let KeyClass::Known(spec) = classify(key.as_key()) else {
        return Err(ClientError::InvalidEdit.into());
    };
    match spec.expected {
        Expected::CustomFieldValue => {
            let parts = key.as_key();
            match (item, parts.element()) {
                (Some(item), Some(element))
                    if custom_kind(vault, item, element) == CustomFieldKind::Boolean =>
                {
                    boolean(input)
                }
                _ => text(input),
            }
        }
        Expected::Text => text(input),
        Expected::Bool => boolean(input),
        Expected::U64 => input
            .parse()
            .map(Value::u64)
            .map_err(|_| ClientError::InvalidEdit.into()),
        Expected::Enum => input
            .parse()
            .map(Value::enumeration)
            .map_err(|_| ClientError::InvalidEdit.into()),
        _ => Err(ClientError::InvalidEdit.into()),
    }
}

/// A field key from the host.
fn parse_key(text: &str) -> CoreResult<FieldKey> {
    FieldKey::parse(text.as_bytes()).map_err(|_| ClientError::InvalidEdit.into())
}

/// The writes of `draft` for a new item (`item` is `None`) or an existing one. The schema
/// checks run when they are written. Every element id is the host's, carried on the entry
/// (module docs, "An edit"); nothing here draws randomness, so writing the same draft twice
/// produces the same writes.
pub(crate) fn writes(
    vault: &VaultSync,
    item: Option<ItemId>,
    draft: &ItemDraft,
) -> CoreResult<Vec<Write>> {
    let mut out = Vec::new();
    let uris = draft
        .entries
        .iter()
        .filter(|e| matches!(e, Entry::AddUri(..)))
        .count();
    let customs = draft
        .entries
        .iter()
        .filter(|e| matches!(e, Entry::AddCustom(..)))
        .count();
    let mut uri_orders = vault.append_orders(item, LIST_URI, uris)?.into_iter();
    let mut custom_orders = vault.append_orders(item, LIST_FIELD, customs)?.into_iter();
    for entry in &draft.entries {
        match entry {
            Entry::Set(key, input) => {
                let key = parse_key(key)?;
                let value = encode(vault, item, &key, input)?;
                out.push((key, value));
            }
            Entry::Clear(key) => out.push((parse_key(key)?, Value::cleared())),
            Entry::Tag(name) => out.push((
                tag_key(name).map_err(|_| ClientError::InvalidEdit)?,
                Value::bool(true),
            )),
            Entry::Untag(name) => out.push((
                tag_key(name).map_err(|_| ClientError::InvalidEdit)?,
                Value::cleared(),
            )),
            Entry::AddUri(element, uri) => {
                let order = uri_orders.next().ok_or(ClientError::Internal)?;
                let new = VaultSync::element_writes(
                    *element,
                    LIST_URI,
                    vec![(ATTR_VALUE, text(uri)?)],
                    Some(&order),
                )?;
                out.extend(new);
            }
            Entry::AddCustom(element, label, kind, value) => {
                let order = custom_orders.next().ok_or(ClientError::Internal)?;
                let (kind_id, value) = match kind {
                    CustomKind::Text => (CUSTOM_KIND_TEXT, text(value)?),
                    CustomKind::Hidden => (CUSTOM_KIND_HIDDEN, text(value)?),
                    CustomKind::Boolean => (CUSTOM_KIND_BOOLEAN, boolean(value)?),
                };
                let new = VaultSync::element_writes(
                    *element,
                    LIST_FIELD,
                    vec![
                        (ATTR_LABEL, text(label)?),
                        (ATTR_KIND, Value::enumeration(kind_id)),
                        (ATTR_VALUE, value),
                    ],
                    Some(&order),
                )?;
                out.extend(new);
            }
            Entry::AddPasskey(element, passkey) => {
                out.extend(passkey_writes(*element, passkey)?);
            }
            Entry::Remove(list, element) => {
                let item = item.ok_or(ClientError::InvalidEdit)?;
                out.extend(vault.element_removal_writes(item, list, element)?);
            }
            Entry::Move(list, element, place) => {
                let item = item.ok_or(ClientError::InvalidEdit)?;
                let to = match place {
                    MovePlace::First => ListPlace::First,
                    MovePlace::Last => ListPlace::Last,
                    MovePlace::Before(id) => ListPlace::Before(Zeroizing::new(id.clone())),
                    MovePlace::After(id) => ListPlace::After(Zeroizing::new(id.clone())),
                };
                let moves = [ListMove {
                    element: Zeroizing::new(element.clone()),
                    to,
                }];
                let plan = vault.plan_list_order(Some(item), list, &[], 0, &moves)?;
                if plan.writes.len() > MAX_WRITES_PER_OP {
                    return Err(ClientError::InvalidEdit.into());
                }
                out.extend(plan.writes);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_ids_round_trip() {
        let bytes = [0xab_u8; 16];
        let text = hex(&bytes);
        assert_eq!(text.len(), 32);
        assert_eq!(parse_id(&text).unwrap(), bytes);
        assert_eq!(parse_id(&text.to_uppercase()).unwrap(), bytes);
        for bad in ["", "ab", &"g".repeat(32), &"a".repeat(33)] {
            assert!(parse_id(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn type_names_round_trip() {
        for (name, item_type) in TYPES {
            assert_eq!(type_from_name(name).unwrap(), item_type);
            assert_eq!(type_name(Some(item_type)), name);
        }
        assert!(type_from_name("vault-settings").is_err());
        assert_eq!(type_name(None), "unknown");
    }

    #[test]
    fn drafts_are_bounded() {
        let mut draft = ItemDraft::new();
        for _ in 0..MAX_DRAFT_ENTRIES {
            draft.set("item.name", "x").unwrap();
        }
        assert_eq!(draft.length(), MAX_DRAFT_ENTRIES);
        assert!(draft.set("item.name", "x").is_err());
        let id = generate_element_id();
        assert!(
            ItemDraft::new()
                .add_custom_field(&id, "l", "secret", "v")
                .is_err()
        );
        assert!(!format!("{draft:?}").contains('x'));
    }

    #[test]
    fn website_host_strips_userinfo_path_query_and_port() {
        let cases: &[(&str, Option<&str>)] = &[
            (
                "https://user:pass@example.com/x?token=abc",
                Some("example.com"),
            ),
            ("https://example.com", Some("example.com")),
            ("example.com/path", Some("example.com")),
            ("http://example.com:8080/x", Some("example.com")),
            ("https://[2001:db8::1]:8080/x", Some("[2001:db8::1]")),
            ("https://a@b@example.com/", Some("example.com")),
            ("", None),
            ("https://", None),
            ("https:///path", None),
        ];
        for (input, expected) in cases {
            let got = website_host(input);
            assert_eq!(got.as_deref().map(String::as_str), *expected, "{input}");
        }
    }

    #[test]
    fn element_ids_are_generated_and_accepted() {
        let a = generate_element_id();
        let b = generate_element_id();
        assert_eq!(a.len(), 32);
        assert_ne!(a, b, "two draws should not collide");
        let mut draft = ItemDraft::new();
        assert!(draft.add_uri(&a, "https://example.test").is_ok());
        assert!(draft.add_uri("not-hex", "https://example.test").is_err());
        assert!(draft.move_element("uri", &a, "first", None).is_ok());
        assert!(draft.move_element("uri", &a, "before", None).is_err());
    }

    #[test]
    fn add_passkey_accepts_a_valid_element_id_and_rejects_a_bad_one() {
        let id = generate_element_id();
        let private_key = [0xab_u8; 32];
        let mut draft = ItemDraft::new();
        assert!(
            draft
                .add_passkey(
                    &id,
                    "example.com",
                    &[1, 2, 3],
                    &[4, 5, 6],
                    &private_key,
                    &[7, 8, 9],
                    1,
                    true,
                    0
                )
                .is_ok()
        );
        assert_eq!(draft.length(), 1);
        assert!(
            ItemDraft::new()
                .add_passkey(
                    "not-hex",
                    "example.com",
                    &[],
                    &[],
                    &private_key,
                    &[],
                    1,
                    true,
                    0
                )
                .is_err()
        );
        // `ItemDraft`'s own `Debug` impl prints only the entry count, never a field (checked
        // directly here, not only inferred from `drafts_are_bounded`'s unrelated literal): the
        // private key passed in above must never show up in it (module docs on `NewPasskey`,
        // "must never outlive this one write").
        assert_eq!(format!("{draft:?}"), "ItemDraft { entries: 1 }");
    }
}
