//! Field keys: the ADR 0018 §7 grammar, its parser and the key builders.
//!
//! ```text
//! field_key = fixed / element
//! fixed     = name 1*( "." name )                    ; login.password
//! element   = name "/" elem [ "/" name ]              ; uri/<id>/value, tag/<hex>
//! name      = %x61-7A *31( %x61-7A / DIGIT / "_" )    ; 1-32 bytes
//! elem      = 1*64( 2hexlc )                          ; a random 16-byte id is 32 digits
//! hexlc     = DIGIT / %x61-66
//! ```
//!
//! On top of the grammar a key is 1–160 bytes (ADR 0018 §7, §10), a separate check because the
//! grammar alone allows longer keys. [`FieldKeyRef::parse`] runs both, and it is the check the
//! record layer applies to every key of every record (ADR 0018 §5 rules 2 and 3), so it must
//! give the same answer on every replica and every platform:
//!
//! - it never panics, never allocates and reads each byte a bounded number of times;
//! - it accepts exactly the grammar: ASCII only, a `name` starts with a lowercase letter and has
//!   at most 32 bytes, a fixed key has at least two names, an element key has one `elem` of an
//!   even number (2–128) of lowercase hex digits and at most one attribute name;
//! - `@lifecycle` ([`super::LIFECYCLE_KEY`]) is not a grammar key and is rejected here; the
//!   record layer handles it before calling this parser (ADR 0018 §5 rule 5).
//!
//! The grammar and the 160-byte limit are frozen with the version-1 vectors (ADR 0018 §5,
//! "Frozen rules"). Which keys *mean* something is the separate, growing registry of
//! [`super::schema`]; a key that fits the grammar but is not in it is carried, never rejected
//! (ADR 0018 §11).
//!
//! **Keys are user content** (ADR 0018 §2). A tag name is part of its key, so [`FieldKey`]
//! lives in a zeroizing buffer and neither key type prints its text from `Debug`. The hex digits
//! of an `elem` are checked, encoded and decoded with arithmetic rather than branches or a table
//! (CRYPTO.md §12.3); the structural bytes (`.`, `/`, names) are not user-chosen text except in
//! keys a newer client defines.
//!
//! **Why this module allocates only in the builders.** The parser borrows from the decrypted
//! plaintext, as ADR 0018 §2 requires of the record parser ("The parser borrows from the
//! decrypted `Zeroizing<Vec<u8>>`"), so no copy of a key exists outside that buffer.

use core::fmt;

use rand_core::CryptoRng;
use zeroize::Zeroizing;

/// Longest field key, in bytes (ADR 0018 §7, §10). The shortest is 1 byte; the grammar makes
/// the shortest valid key 3 bytes (`a.b`), but the length check is separate and runs first.
pub const MAX_KEY_LEN: usize = 160;

/// Longest `name`, in bytes (ADR 0018 §7: a letter and up to 31 more bytes).
pub const MAX_NAME_LEN: usize = 32;

/// Longest `elem`, in bytes of the element it encodes: 64 bytes, 128 hex digits (ADR 0018 §7).
pub const MAX_ELEMENT_LEN: usize = 64;

/// Length of the random element ids of URIs, custom fields, password-history entries and
/// passkeys (ADR 0018 §7, "a random 16-byte id is 32 digits"; On acceptance item 1).
pub const ELEMENT_ID_LEN: usize = 16;

/// Why a byte string is not a field key. Carries no part of the key (ADR 0018 §2: an error
/// reports only a kind, a local diagnostic outside the frozen format).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyError {
    /// The key is empty or longer than [`MAX_KEY_LEN`] bytes (ADR 0018 §10; §5 rule 2).
    Length,
    /// A `name` is empty, longer than 32 bytes, does not start with a lowercase ASCII letter,
    /// or holds a byte outside `[a-z0-9_]` (ADR 0018 §7; §5 rule 3).
    Name,
    /// An `elem` is not an even number, 2 to 128, of lowercase hex digits (ADR 0018 §7; §5
    /// rule 3).
    Element,
    /// The key is neither `fixed` nor `element`: a single name, or more than two `/` (ADR 0018
    /// §7; §5 rule 3).
    Shape,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Length => "field key must be 1 to 160 bytes",
            Self::Name => "field key has an invalid name",
            Self::Element => "field key has an invalid element id",
            Self::Shape => "field key is neither a fixed key nor a list element key",
        })
    }
}

impl core::error::Error for KeyError {}

/// The two productions of `field_key` (ADR 0018 §7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyKind {
    /// `name 1*( "." name )`, for example `login.password`.
    Fixed,
    /// `name "/" elem [ "/" name ]`, for example `uri/<id>/value` or `tag/<hex>`.
    Element,
}

/// Where the parts of a parsed key are, so that an owned key can hand out a borrowed view
/// without parsing again.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Layout {
    /// A fixed key; its names are separated by `.`.
    Fixed,
    /// An element key: the list name is `text[..list_end]`, the `elem` is
    /// `text[list_end + 1..element_end]`, and the attribute, if `element_end` is not the end of
    /// the key, is `text[element_end + 1..]`.
    Element {
        /// Offset of the first `/`.
        list_end: usize,
        /// Offset just past the `elem`: the second `/`, or the length of the key.
        element_end: usize,
    },
}

/// A field key that fits the ADR 0018 §7 grammar and the 1–160-byte limit, borrowed from the
/// buffer it was parsed from.
///
/// It is `Copy` because it is only a view; the bytes stay in the caller's (zeroizing) buffer.
/// `Debug` prints no part of the key. Comparing two keys is the record layer's business
/// (ADR 0018 §4 order): use [`FieldKeyRef::as_bytes`].
#[derive(Clone, Copy)]
pub struct FieldKeyRef<'a> {
    /// The whole key, ASCII.
    text: &'a str,
    /// Where its parts are.
    layout: Layout,
}

impl fmt::Debug for FieldKeyRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FieldKeyRef([REDACTED])")
    }
}

impl<'a> FieldKeyRef<'a> {
    /// Parses a field key from untrusted bytes: the 1–160-byte limit, then the grammar.
    ///
    /// Never panics and never allocates. `@lifecycle` is rejected (it is not a grammar key).
    ///
    /// # Errors
    /// [`KeyError`] saying which rule the bytes break.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, KeyError> {
        if bytes.is_empty() || bytes.len() > MAX_KEY_LEN {
            return Err(KeyError::Length);
        }
        let layout = match bytes.iter().position(|b| *b == b'/') {
            Some(list_end) => parse_element(bytes, list_end)?,
            None => parse_fixed(bytes)?,
        };
        // Every byte was checked to be ASCII above, so this cannot fail.
        let text = core::str::from_utf8(bytes).map_err(|_| KeyError::Name)?;
        Ok(Self { text, layout })
    }

    /// [`FieldKeyRef::parse`] on a string, for keys a writer spells out (the constants of
    /// [`super::schema`]).
    ///
    /// # Errors
    /// As [`FieldKeyRef::parse`].
    pub fn parse_str(text: &'a str) -> Result<Self, KeyError> {
        Self::parse(text.as_bytes())
    }

    /// The whole key.
    #[must_use]
    pub const fn as_str(&self) -> &'a str {
        self.text
    }

    /// The whole key, as bytes: what the record layer encodes with `str()` and orders by
    /// (ADR 0018 §3, §4).
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.text.as_bytes()
    }

    /// Which production the key follows.
    #[must_use]
    pub const fn kind(&self) -> KeyKind {
        match self.layout {
            Layout::Fixed => KeyKind::Fixed,
            Layout::Element { .. } => KeyKind::Element,
        }
    }

    /// The first `name`: the part before the first `.` of a fixed key (`login` in
    /// `login.password`), or the list name of an element key (`uri` in `uri/<id>/value`). The
    /// reserved prefixes of ADR 0018 §7 are namespaces.
    #[must_use]
    pub fn namespace(&self) -> &'a str {
        match self.layout {
            Layout::Fixed => self.text.split('.').next().unwrap_or_default(),
            Layout::Element { list_end, .. } => self.text.get(..list_end).unwrap_or_default(),
        }
    }

    /// The names of a fixed key, in order; `None` for an element key.
    #[must_use]
    pub fn fixed_names(&self) -> Option<core::str::Split<'a, char>> {
        match self.layout {
            Layout::Fixed => Some(self.text.split('.')),
            Layout::Element { .. } => None,
        }
    }

    /// The list name of an element key (`uri`, `field`, `tag`, …); `None` for a fixed key.
    #[must_use]
    pub fn list(&self) -> Option<&'a str> {
        match self.layout {
            Layout::Fixed => None,
            Layout::Element { list_end, .. } => self.text.get(..list_end),
        }
    }

    /// The `elem` of an element key, as its lowercase hex digits; `None` for a fixed key. For a
    /// tag it encodes the tag name ([`super::tag::tag_name`]).
    #[must_use]
    pub fn element(&self) -> Option<&'a str> {
        match self.layout {
            Layout::Fixed => None,
            Layout::Element {
                list_end,
                element_end,
            } => self.text.get(list_end + 1..element_end),
        }
    }

    /// The `elem` of an element key decoded to bytes, in a zeroizing buffer allocated at its
    /// final size; `None` for a fixed key.
    ///
    /// The hex is decoded with arithmetic, not a table or a branch per digit (CRYPTO.md §12.3),
    /// because a tag's element is its name.
    #[must_use]
    pub fn element_bytes(&self) -> Option<Zeroizing<Vec<u8>>> {
        let hex = self.element()?;
        let mut out = Zeroizing::new(Vec::with_capacity(hex.len() / 2));
        for pair in hex.as_bytes().chunks_exact(2) {
            if let [high, low] = pair {
                out.push((hex_value(*high) << 4) | hex_value(*low));
            }
        }
        Some(out)
    }

    /// The attribute name of an element key (`value` in `uri/<id>/value`); `None` for a fixed
    /// key and for an element key without one, such as `tag/<hex>`.
    #[must_use]
    pub fn attribute(&self) -> Option<&'a str> {
        match self.layout {
            Layout::Fixed => None,
            Layout::Element { element_end, .. } => {
                self.text.get(element_end..).and_then(|rest| rest.get(1..))
            }
        }
    }
}

/// A field key that fits the grammar, owned, in a zeroizing buffer allocated at its final size.
///
/// Built by writers ([`FieldKey::element`], [`super::tag::tag_key`]) or copied from a record
/// ([`FieldKey::from_ref`]). No `Clone`, and `Debug` prints no part of the key (ADR 0018 §2,
/// CRYPTO.md §12.2).
pub struct FieldKey {
    /// The key text, wiped on drop.
    text: Zeroizing<String>,
    /// Where its parts are; the text was parsed once, when it was built.
    layout: Layout,
}

impl fmt::Debug for FieldKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FieldKey([REDACTED])")
    }
}

impl FieldKey {
    /// Parses and copies a field key.
    ///
    /// # Errors
    /// As [`FieldKeyRef::parse`].
    pub fn parse(bytes: &[u8]) -> Result<Self, KeyError> {
        FieldKeyRef::parse(bytes).map(Self::from_ref)
    }

    /// Copies a parsed key into a zeroizing buffer of exactly its length.
    #[must_use]
    pub fn from_ref(key: FieldKeyRef<'_>) -> Self {
        let mut text = Zeroizing::new(String::with_capacity(key.text.len()));
        text.push_str(key.text);
        Self {
            text,
            layout: key.layout,
        }
    }

    /// Builds the element key `list "/" hex(element) ["/" attribute]` (ADR 0018 §7), for
    /// example `uri/<id>/value` from an [`ElementId`] or `share/<share_id>/secret` from a share
    /// id.
    ///
    /// The length is checked before anything is allocated, the hex digits are written with
    /// arithmetic (CRYPTO.md §12.3), and the finished key is parsed once more, so the result
    /// always fits the grammar.
    ///
    /// # Errors
    /// [`KeyError::Length`] if the key would be longer than 160 bytes, and the other
    /// [`KeyError`] kinds if `list`, `element` (1–64 bytes) or `attribute` breaks the grammar.
    pub fn element(list: &str, element: &[u8], attribute: Option<&str>) -> Result<Self, KeyError> {
        let len = element
            .len()
            .checked_mul(2)
            .and_then(|hex| hex.checked_add(list.len()))
            .and_then(|n| n.checked_add(1))
            .and_then(|n| n.checked_add(attribute.map_or(0, |a| a.len().saturating_add(1))))
            .ok_or(KeyError::Length)?;
        if len > MAX_KEY_LEN {
            return Err(KeyError::Length);
        }
        let mut text = Zeroizing::new(String::with_capacity(len));
        text.push_str(list);
        text.push('/');
        for byte in element {
            text.push(char::from(hex_digit(byte >> 4)));
            text.push(char::from(hex_digit(byte & 0x0f)));
        }
        if let Some(attribute) = attribute {
            text.push('/');
            text.push_str(attribute);
        }
        let layout = FieldKeyRef::parse(text.as_bytes())?.layout;
        Ok(Self { text, layout })
    }

    /// A borrowed view of the key.
    #[must_use]
    pub fn as_key(&self) -> FieldKeyRef<'_> {
        FieldKeyRef {
            text: &self.text,
            layout: self.layout,
        }
    }

    /// The key text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.text.as_bytes()
    }
}

/// The random 16-byte id of a list element: a URI, a custom field, a password-history entry,
/// a passkey (ADR 0018 §7; ADR 0012 §1 "Field key"). Tags are the exception: their element is
/// the tag name (owner decision 7, [`super::tag`]).
///
/// Drawn from the injected CSPRNG (CRYPTO.md §2, §12.1), so two devices adding an element at
/// the same time never collide, and a list edit never conflicts with another. It becomes part of
/// the element's keys, so `Debug` does not print it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ElementId([u8; ELEMENT_ID_LEN]);

impl fmt::Debug for ElementId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ElementId([REDACTED])")
    }
}

impl ElementId {
    /// Draws a fresh element id from the injected CSPRNG.
    #[must_use]
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut bytes = [0u8; ELEMENT_ID_LEN];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Wraps 16 bytes, for example an element id decoded from an existing key.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; ELEMENT_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// The id's bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ELEMENT_ID_LEN] {
        &self.0
    }

    /// The element key `list/<id>/attribute` of this element.
    ///
    /// # Errors
    /// As [`FieldKey::element`]: `list` or `attribute` breaks the grammar.
    pub fn key(&self, list: &str, attribute: &str) -> Result<FieldKey, KeyError> {
        FieldKey::element(list, &self.0, Some(attribute))
    }
}

/// Checks `element = name "/" elem [ "/" name ]`, given the offset of the first `/`.
fn parse_element(bytes: &[u8], list_end: usize) -> Result<Layout, KeyError> {
    let list = bytes.get(..list_end).unwrap_or_default();
    let after = bytes.get(list_end + 1..).unwrap_or_default();
    let (elem, attribute) = match after.iter().position(|b| *b == b'/') {
        Some(end) => (
            after.get(..end).unwrap_or_default(),
            Some(after.get(end + 1..).unwrap_or_default()),
        ),
        None => (after, None),
    };
    if !is_name(list) {
        return Err(KeyError::Name);
    }
    if !is_element(elem) {
        return Err(KeyError::Element);
    }
    if let Some(attribute) = attribute {
        // An attribute holding a third `/` would fail `is_name` too; it is one part too many,
        // so report the shape.
        if attribute.contains(&b'/') {
            return Err(KeyError::Shape);
        }
        if !is_name(attribute) {
            return Err(KeyError::Name);
        }
    }
    Ok(Layout::Element {
        list_end,
        element_end: list_end + 1 + elem.len(),
    })
}

/// Checks `fixed = name 1*( "." name )` for a key without `/`.
fn parse_fixed(bytes: &[u8]) -> Result<Layout, KeyError> {
    let mut names = 0usize;
    for part in bytes.split(|b| *b == b'.') {
        if !is_name(part) {
            return Err(KeyError::Name);
        }
        names += 1;
    }
    if names < 2 {
        return Err(KeyError::Shape);
    }
    Ok(Layout::Fixed)
}

/// `true` if `part` is a `name`: 1–32 bytes, a lowercase ASCII letter, then lowercase letters,
/// digits and `_` (ADR 0018 §7).
fn is_name(part: &[u8]) -> bool {
    let Some((first, rest)) = part.split_first() else {
        return false;
    };
    part.len() <= MAX_NAME_LEN
        && first.is_ascii_lowercase()
        && rest
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
}

/// `true` if `part` is an `elem`: an even number, 2 to 128, of lowercase hex digits (ADR 0018
/// §7). The digits are checked without a branch per byte, since a tag's element is its name
/// (CRYPTO.md §12.3); only the public length decides early.
fn is_element(part: &[u8]) -> bool {
    if part.is_empty() || part.len() > 2 * MAX_ELEMENT_LEN || !part.len().is_multiple_of(2) {
        return false;
    }
    let bad = part
        .iter()
        .fold(0u32, |acc, b| acc | (1 ^ is_lower_hex(*b)));
    bad == 0
}

/// `1` if `lo <= b <= hi`, else `0`, computed without a branch.
fn in_range(b: u8, lo: u8, hi: u8) -> u32 {
    let below = i32::from(b) - i32::from(lo);
    let above = i32::from(hi) - i32::from(b);
    // Both differences are non-negative exactly when `b` is in range; the sign bit of their OR
    // is then 0.
    1 ^ ((below | above).cast_unsigned() >> 31)
}

/// `1` if `b` is a `hexlc` digit (`0`–`9`, `a`–`f`), else `0`, without a branch.
pub(super) fn is_lower_hex(b: u8) -> u32 {
    in_range(b, b'0', b'9') | in_range(b, b'a', b'f')
}

/// The lowercase hex digit of the low four bits of `nibble`, without a branch or table:
/// `'0' + n`, plus 39 (the distance from `'9' + 1` to `'a'`) when `n > 9`.
pub(super) fn hex_digit(nibble: u8) -> u8 {
    let n = i32::from(nibble & 0x0f);
    // `9 - n` is negative exactly when n > 9; the arithmetic shift turns that into all ones.
    let letter = (9 - n) >> 31;
    let [digit, ..] = (i32::from(b'0') + n + (letter & 0x27)).to_le_bytes();
    digit
}

/// The value of a lowercase hex digit, without a branch or table. Only meaningful for a digit
/// [`is_lower_hex`] accepted.
pub(super) fn hex_value(digit: u8) -> u8 {
    let d = i32::from(digit);
    // `'9' - d` is negative exactly for a letter.
    let letter = (i32::from(b'9') - d) >> 31;
    let [value, ..] = (d - i32::from(b'0') - (letter & 0x27)).to_le_bytes();
    value & 0x0f
}
