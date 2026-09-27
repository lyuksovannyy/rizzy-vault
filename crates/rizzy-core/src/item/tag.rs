//! Tag keys (ADR 0018 §7, owner decision 7).
//!
//! A tag is one field, keyed by its name: `tag/<hex>`, where `<hex>` is the lowercase hex of
//! `UTF-8(NFC(name))`. The normalised name is 1–64 bytes and contains no code point of general
//! category Cc. The value is Bool `0x01` to add the tag and Cleared to remove it; the tag has no
//! attributes. Folders are a UI over `/` in names.
//!
//! **Why by name.** Two devices that add the same tag concurrently write the same key, so the
//! adds merge into one register instead of becoming two tags (owner decision 7). Renaming a tag
//! is therefore one op per tagged item (ADR 0018, Consequences).
//!
//! **Why NFC.** The same name typed on two platforms (a precomposed `é`, or `e` and a combining
//! accent) must give one key. NFC comes from the pinned `unicode-normalization` tables through
//! the crate's one NFC function, the one master passwords use (CRYPTO.md §2), so a table change
//! is reviewed like a crypto bump (ADR 0018, Risks: "Tag keys depend on NFC"). It is NFC, not
//! NFKC: a ligature stays a ligature. There is no trimming and no case folding, so `Work` and
//! `work` are two tags.
//!
//! **Reading a tag back.** [`tag_name`] decodes the hex and accepts it only if it is a name
//! [`tag_key`] could have produced: valid UTF-8, already NFC, no Cc. ADR 0018 does not say what
//! a reader does with a `tag/<hex>` key that breaks this; the key fits the grammar, so the record
//! layer carries it like any unknown key, and this module does not show it as a tag. That keeps
//! `tag_key(tag_name(k)) == k` for every key shown as a tag, so two keys never display as one
//! name. [`super::schema::classify`] calls such a key
//! [`Unknown`](super::schema::KeyClass::Unknown) for the same reason, so the writer checks
//! refuse to write it as a tag: a client that skipped NFC would otherwise add a second register
//! for a tag another device already added (ADR 0018 §7, "Keying by name makes concurrent adds
//! of one tag one register").
//!
//! Tag names are user content (ADR 0018 §2): the normalised name and the decoded name live in
//! zeroizing buffers allocated at their final size, the hex is encoded and decoded with
//! arithmetic ([`super::key`]), and errors carry no part of the name.

use core::fmt;

use unicode_normalization::is_nfc;
use zeroize::Zeroizing;

use super::key::{FieldKey, FieldKeyRef, KeyKind, MAX_ELEMENT_LEN};
use super::schema::LIST_TAG;

/// Longest tag name, in bytes of `UTF-8(NFC(name))` (ADR 0018 §7). It fills the longest `elem`.
pub const MAX_TAG_NAME_LEN: usize = MAX_ELEMENT_LEN;

/// Why a tag name, or a key, is not a valid tag. Carries no part of the name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TagError {
    /// The normalised name is empty or longer than 64 bytes.
    Length,
    /// The name contains a code point of general category Cc (a C0 or C1 control, or DEL).
    Control,
    /// The key is not `tag/<hex>`: another list, a fixed key, or an attribute after the hex.
    NotTagKey,
    /// The key's hex does not decode to UTF-8.
    Encoding,
    /// The key's name is not in NFC, so no writer produced it.
    NotNormalized,
}

impl fmt::Display for TagError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Length => "tag name must be 1 to 64 bytes",
            Self::Control => "tag name contains a control character",
            Self::NotTagKey => "field key is not a tag key",
            Self::Encoding => "tag key does not encode UTF-8",
            Self::NotNormalized => "tag key does not encode a normalised name",
        })
    }
}

impl core::error::Error for TagError {}

/// The key `tag/<hex>` of a tag name: `hex(UTF-8(NFC(name)))` (ADR 0018 §7).
///
/// # Errors
/// [`TagError::Length`] if the normalised name is empty or longer than 64 bytes, and
/// [`TagError::Control`] if it contains a Cc code point.
pub fn tag_key(name: &str) -> Result<FieldKey, TagError> {
    let normalized = Zeroizing::new(crate::kdf::nfc_utf8(name).map_err(|_| TagError::Length)?);
    if normalized.is_empty() || normalized.len() > MAX_TAG_NAME_LEN {
        return Err(TagError::Length);
    }
    // NFC output of a `&str` is UTF-8, so this cannot fail.
    let text = core::str::from_utf8(&normalized).map_err(|_| TagError::Length)?;
    if text.chars().any(char::is_control) {
        return Err(TagError::Control);
    }
    FieldKey::element(LIST_TAG, &normalized, None).map_err(|_| TagError::Length)
}

/// The tag name a `tag/<hex>` key stands for, in a zeroizing buffer.
///
/// Accepted only if [`tag_key`] could have produced the key: the hex is UTF-8, in NFC, and has
/// no Cc code point (the grammar already bounds it to 1–64 bytes). See the module docs for why a
/// key that fails is carried but not shown as a tag.
///
/// # Errors
/// [`TagError::NotTagKey`] for any key that is not `tag/<hex>`, then [`TagError::Encoding`],
/// [`TagError::NotNormalized`] or [`TagError::Control`].
pub fn tag_name(key: FieldKeyRef<'_>) -> Result<Zeroizing<String>, TagError> {
    if key.kind() != KeyKind::Element || key.list() != Some(LIST_TAG) || key.attribute().is_some() {
        return Err(TagError::NotTagKey);
    }
    let bytes = key.element_bytes().ok_or(TagError::NotTagKey)?;
    let text = core::str::from_utf8(&bytes).map_err(|_| TagError::Encoding)?;
    if !is_nfc(text) {
        return Err(TagError::NotNormalized);
    }
    if text.chars().any(char::is_control) {
        return Err(TagError::Control);
    }
    let mut name = Zeroizing::new(String::with_capacity(text.len()));
    name.push_str(text);
    Ok(name)
}
