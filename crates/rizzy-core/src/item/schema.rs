//! The key registry of the M1 item schema, and the checks a writer runs (ADR 0018 §6–§8, §10,
//! §11).
//!
//! Every key that means something to an M1 client has an entry here ([`classify`]): the value
//! it expects, the item types it belongs to, who may write it and whether it is concealed by
//! default. The entries are the ADR 0018 §7 table:
//!
//! | Key | Value | Types | Writers | Concealed |
//! |---|---|---|---|---|
//! | `item.type` | Enum | all | the create op only | no |
//! | `item.name`, `item.notes` | Text | all | any | no |
//! | `item.favorite` | Bool (absent means false) | all | any | no |
//! | `import.created_ms` | U64 | all | importers only | no |
//! | `field/<id>/label` · `/kind` · `/value` · `/order` | Text · Enum · Text or Bool · `SortKey` | all | any | `value` of a hidden custom field |
//! | `tag/<hex>` | Bool `0x01` | all | any | no |
//! | `share/<share_id>/secret` | Bytes, 32 | all | not in M1 (M5) | yes |
//! | `login.username`, `login.password`, `login.totp` | Text | Login | any | password, TOTP |
//! | `uri/<id>/value` · `/match` · `/order` | Text · Enum · `SortKey` | Login | any; `match`'s values are [ADR 0037] §4 (Accepted, M2) | no |
//! | `pwhist/<id>/value` · `/ms` | Text · U64 | Login | any | no (see below) |
//! | `card.holder`, `.number`, `.brand`, `.exp_month`, `.exp_year`, `.code`, `.pin` | Text | Card | any | number, code, PIN |
//! | `identity.` + 18 names | Text | Identity | any | `ssn`, `passport_number` |
//! | `vault.name`, `vault.icon` | Text | Vault settings | any | no |
//!
//! Keys under the reserved prefixes (`ssh.`, `api.`, `license.`, `wifi.`, `bank.`, `passkey.`,
//! `passkey/`, `attachment/`, and `share/` attributes other than `secret`) are
//! [`KeyClass::Reserved`]; every other grammar key is [`KeyClass::Unknown`], and so is a
//! `tag/<hex>` key whose hex is not a name [`super::tag::tag_key`] could have produced
//! (ADR 0018 §7: UTF-8, NFC, no Cc; see [`super::tag`]). Both are carried byte for byte by the
//! record layer and exported unchanged (ADR 0018 §11). An M1 writer never invents a value for
//! them; it writes one only as Cleared in an edit, or as a value copied verbatim from an
//! existing item (see the writer checks below). A new key needs a line in the ADR that ships
//! it, never a version bump (ADR 0018 §7).
//!
//! **Concealment** is the ADR 0018 §7 list: `login.password`, `login.totp`, `card.number`,
//! `card.code`, `card.pin`, `identity.ssn`, `identity.passport_number`, hidden custom fields and
//! `share/…`. The same fields are left out of an M5 share unless chosen. The list does not name
//! `pwhist/<id>/value`, the imported password history, so this registry does not conceal it;
//! that omission is reported to the owner rather than decided here.
//!
//! **Values that do not fit.** [`read_value`] turns a value that is malformed, of an unknown
//! type, or of a type the key does not expect into "unsupported value"; the record is never
//! rejected for it (ADR 0018 §6). A Cleared value is never unsupported: the field simply has no
//! value.
//!
//! **Writer checks** ([`check_write`], [`check_carried`], [`check_create`]). ADR 0018 §2
//! "Flow": the client validates a write here before the record layer encodes it. The checks are
//! the writer rules of ADR 0018 §6–§8 and §10: the §7 grammar and the 160-byte limit on the
//! final key, the 64 KiB value limit, no field edit of an unsupported type, no blank field in a
//! create op, keys of the item's type only, `item.type` only in the create op and naming the
//! item's own type, `import.created_ms` only from an importer, and no write at all of
//! `share/<id>/secret` (M5's to write and clear). `uri/<id>/match` was the same until
//! [ADR 0037] (Accepted, M2) assigned its enum values, as ADR 0018 §7 anticipated ("the M2 ADR
//! assigns its values"); it is `Writers::Any` from M2. The record-level limits (writes per op,
//! op size) are the record layer's. The two sources of a write differ in what else is checked:
//!
//! - **Entered** ([`check_write`]): a value the user typed, or this client built for the user.
//!   It must be a well-formed value of the type the key expects, never an empty Text, and its
//!   key must be in the M1 schema, with one exception: in an edit, Cleared may also go to a key
//!   outside it, unknown or reserved. ADR 0018 §6 has "Removing a list element writes this to
//!   each attribute of the element that the writer holds", and a URI or custom field may hold
//!   an attribute a newer client added (`uri/<id>/label`, say), which must be cleared too or the
//!   element keeps existing. §11 "An edit writes only the keys the user changed" forbids
//!   rewriting keys the user did not change; removing an element changes all of its
//!   attributes. Which keys the item holds is the caller's to know.
//! - **Carried** ([`check_carried`]): a key and value copied byte for byte from a displayed
//!   value of an existing item, for "Restore it as a new item" from the late registers of a
//!   tombstone (ADR 0018 §3 "Surfacing") and "duplicate as a new item" (§10 "The way out": "a
//!   create op, then edit ops as needed", so a carried write may sit in either op).
//!   Any key the grammar accepts may be carried, unknown and reserved ones included, and the
//!   value bytes are not interpreted beyond the size limit: unknown keys are carried byte for
//!   byte (§11) and unsupported values verbatim (§6), and they would otherwise be lost. A known
//!   key still obeys its item types and writers, and a carried `item.type` must name the new
//!   item's type.
//!
//!   **Import of our own exports** ([ADR 0027] §2 step 3, §6 "Writes", open question 5 answered
//!   "carried"). The same check serves the import of an encrypted export and of the plaintext
//!   JSON export, with [`WriteMode::Import`]: each displayed value of the exported item is a
//!   carried write of the new item, "any key of the grammar and any value bytes within §10 are
//!   kept verbatim and show as unsupported where unknown". With that mode a carried
//!   `import.created_ms` is writable, as it is for every importer; `share/<id>/secret` still is
//!   not (M5's). `uri/<id>/match` may be carried from M2 like any other known key. An import
//!   file is hostile input, and this check is what
//!   keeps a carried write harmless: the key is of the grammar, the value is within the size
//!   limit and never interpreted here, and a known key stays inside its item type.
//!
//! ADR 0018 does not say how restore and duplicate treat keys and values this client cannot
//! read; the carried reading above is this module's, and so is the one below.
//!
//! [ADR 0027]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0027-export-payload.md
//! [ADR 0037]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0037-url-matching-and-autofill-rules.md
//!
//! **`uri/<id>/match` is writable from M2** (ADR 0037, Accepted, assigns its enum values
//! `0x0000`–`0x0006`; unassigned values above that are still accepted here, as any other Enum
//! key's out-of-range value is, and read back as unsupported by the matching layer). Owner
//! decision 2's M1 restriction ("carry it and never write it") no longer applies: removing its
//! URI now clears it too, under the general §6 removal rule, same as `order`; `match` is still a
//! layout attribute for the §6 *existence* rule ([`super::order::element_exists`]), so a removed
//! URI's stale `match` alone never keeps the element "existing" if `value` and `label` are both
//! cleared.

use core::fmt;

use super::key::{FieldKeyRef, KeyError, KeyKind};
use super::tag::tag_name;
use super::types::{ItemType, SupportedType};
use super::value::{MAX_VALUE_LEN, ValueError, ValueRef};

/// `item.type`: Enum, the item's type (ADR 0018 §7, §8).
pub const ITEM_TYPE: &str = "item.type";
/// `item.name`: Text, the title.
pub const ITEM_NAME: &str = "item.name";
/// `item.notes`: Text, the notes; a Secure Note's body. Conflicts are whole-field.
pub const ITEM_NOTES: &str = "item.notes";
/// `item.favorite`: Bool; absent means false. Stored from M1, shown from M3.
pub const ITEM_FAVORITE: &str = "item.favorite";
/// `import.created_ms`: U64, the creation time an importer read; shown as "created" instead of
/// the HLC time (ADR 0018 §9).
pub const IMPORT_CREATED_MS: &str = "import.created_ms";
/// `login.username`: Text.
pub const LOGIN_USERNAME: &str = "login.username";
/// `login.password`: Text. Its history is the password history (ADR 0012 §5).
pub const LOGIN_PASSWORD: &str = "login.password";
/// `login.totp`: Text, an otpauth URI or a Base32 secret as entered, parsed when a code is shown
/// ([`crate::totp`], CRYPTO.md §11.15).
pub const LOGIN_TOTP: &str = "login.totp";
/// `card.holder`: Text.
pub const CARD_HOLDER: &str = "card.holder";
/// `card.number`: Text, as entered or imported.
pub const CARD_NUMBER: &str = "card.number";
/// `card.brand`: Text.
pub const CARD_BRAND: &str = "card.brand";
/// `card.exp_month`: Text.
pub const CARD_EXP_MONTH: &str = "card.exp_month";
/// `card.exp_year`: Text.
pub const CARD_EXP_YEAR: &str = "card.exp_year";
/// `card.code`: Text, the security code.
pub const CARD_CODE: &str = "card.code";
/// `card.pin`: Text.
pub const CARD_PIN: &str = "card.pin";
/// `identity.title`: Text.
pub const IDENTITY_TITLE: &str = "identity.title";
/// `identity.first_name`: Text.
pub const IDENTITY_FIRST_NAME: &str = "identity.first_name";
/// `identity.middle_name`: Text.
pub const IDENTITY_MIDDLE_NAME: &str = "identity.middle_name";
/// `identity.last_name`: Text.
pub const IDENTITY_LAST_NAME: &str = "identity.last_name";
/// `identity.company`: Text.
pub const IDENTITY_COMPANY: &str = "identity.company";
/// `identity.email`: Text.
pub const IDENTITY_EMAIL: &str = "identity.email";
/// `identity.phone`: Text.
pub const IDENTITY_PHONE: &str = "identity.phone";
/// `identity.username`: Text.
pub const IDENTITY_USERNAME: &str = "identity.username";
/// `identity.address1`: Text.
pub const IDENTITY_ADDRESS1: &str = "identity.address1";
/// `identity.address2`: Text.
pub const IDENTITY_ADDRESS2: &str = "identity.address2";
/// `identity.address3`: Text.
pub const IDENTITY_ADDRESS3: &str = "identity.address3";
/// `identity.city`: Text.
pub const IDENTITY_CITY: &str = "identity.city";
/// `identity.state`: Text.
pub const IDENTITY_STATE: &str = "identity.state";
/// `identity.postal_code`: Text.
pub const IDENTITY_POSTAL_CODE: &str = "identity.postal_code";
/// `identity.country`: Text.
pub const IDENTITY_COUNTRY: &str = "identity.country";
/// `identity.ssn`: Text.
pub const IDENTITY_SSN: &str = "identity.ssn";
/// `identity.passport_number`: Text.
pub const IDENTITY_PASSPORT_NUMBER: &str = "identity.passport_number";
/// `identity.drivers_license`: Text.
pub const IDENTITY_DRIVERS_LICENSE: &str = "identity.drivers_license";
/// `vault.name`: Text, the vault's name (vault settings).
pub const VAULT_NAME: &str = "vault.name";
/// `vault.icon`: Text, an identifier from the client's icon set (vault settings).
pub const VAULT_ICON: &str = "vault.icon";

/// List `field`: custom fields, keyed by a random element id.
pub const LIST_FIELD: &str = "field";
/// List `tag`: one element per tag, keyed by the tag name ([`super::tag`]).
pub const LIST_TAG: &str = "tag";
/// List `share` (M5): keyed by the share's 16-byte id.
pub const LIST_SHARE: &str = "share";
/// List `uri` (Login): the login's URLs, keyed by a random element id.
pub const LIST_URI: &str = "uri";
/// List `pwhist` (Login): password history imported from another manager.
pub const LIST_PWHIST: &str = "pwhist";

/// Attribute `label` of a custom field: Text.
pub const ATTR_LABEL: &str = "label";
/// Attribute `kind` of a custom field: Enum, see [`CustomFieldKind`]. A layout attribute.
pub const ATTR_KIND: &str = "kind";
/// Attribute `value` of a custom field, a URI or a password-history entry.
pub const ATTR_VALUE: &str = "value";
/// Attribute `order` of a custom field or a URI: `SortKey`. A layout attribute.
pub const ATTR_ORDER: &str = "order";
/// Attribute `match` of a URI: Enum, values `0x0000`–`0x0006` per ADR 0037 §4 (Accepted, M2). A
/// layout attribute.
pub const ATTR_MATCH: &str = "match";
/// Attribute `secret` of a share: Bytes, 32, the owner's copy of the share secret (M5).
pub const ATTR_SECRET: &str = "secret";
/// Attribute `ms` of a password-history entry: U64, Unix milliseconds.
pub const ATTR_MS: &str = "ms";

/// Length of the owner's copy of a share secret (ADR 0018 §7; CRYPTO.md §11.10).
pub const SHARE_SECRET_LEN: usize = 32;

/// The value a key expects (ADR 0018 §7, "Value" column).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Expected {
    /// Text.
    Text,
    /// Bool.
    Bool,
    /// U64.
    U64,
    /// Enum.
    Enum,
    /// `SortKey`.
    SortKey,
    /// Bytes of exactly this length (the share secret: 32).
    Bytes {
        /// The required payload length.
        len: usize,
    },
    /// Text or Bool, as the custom field's kind says (`field/<id>/value`): Bool for a boolean
    /// field, Text otherwise. [`CustomFieldKind::accepts`] makes the exact check.
    CustomFieldValue,
    /// Bool `0x01`, the only value a tag holds besides Cleared.
    ///
    /// A tag register that displays another non-empty value (Bool `0x00`, say) still makes the
    /// tag exist, because ADR 0018 §6 "List elements" asks only whether the displayed value is
    /// non-empty; the value itself reads as unsupported. ADR 0018 does not say more.
    TagMarker,
}

impl Expected {
    /// `true` if `value` is what the key expects. Cleared is always accepted: it means "no
    /// value", never "unsupported value".
    #[must_use]
    pub fn accepts(self, value: &ValueRef<'_>) -> bool {
        match (self, value) {
            (_, ValueRef::Cleared)
            | (Self::Text | Self::CustomFieldValue, ValueRef::Text(_))
            | (Self::Bool | Self::CustomFieldValue, ValueRef::Bool(_))
            | (Self::U64, ValueRef::U64(_))
            | (Self::Enum, ValueRef::Enum(_))
            | (Self::SortKey, ValueRef::SortKey(_))
            | (Self::TagMarker, ValueRef::Bool(true)) => true,
            (Self::Bytes { len }, ValueRef::Bytes(bytes)) => bytes.len() == len,
            _ => false,
        }
    }
}

/// Which item types a key belongs to (ADR 0018 §7, "Types" column).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Applies {
    /// Every type. Read literally, this includes the vault-settings type; ADR 0018 does not
    /// exclude it.
    All,
    /// One type only.
    Only(SupportedType),
}

impl Applies {
    /// `true` if the key belongs to items of type `item_type`.
    #[must_use]
    pub fn includes(self, item_type: SupportedType) -> bool {
        match self {
            Self::All => true,
            Self::Only(t) => t == item_type,
        }
    }
}

/// Who may write a key (ADR 0018 §7, "Notes" column).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Writers {
    /// Any create or edit.
    Any,
    /// Only the create op, and never changed afterwards: `item.type`. Converting an item is a
    /// new item.
    CreateOnly,
    /// Only an importer's create op: `import.created_ms`.
    ImportOnly,
    /// An M1 client carries the key and never writes it, not even as Cleared or copied into a
    /// new item: `share/<id>/secret`, which M5 writes and clears. `uri/<id>/match` was the same
    /// in M1 (owner decision 2) and moved to [`Writers::Any`] once ADR 0037 (Accepted, M2)
    /// assigned its enum values.
    NotInM1,
}

/// Whether a key's value is concealed by default, and left out of an M5 share unless chosen
/// (ADR 0018 §7, "Concealed by default").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Concealment {
    /// Shown.
    Shown,
    /// Concealed.
    Concealed,
    /// Concealed when the custom field is hidden, or of a kind that displays as hidden
    /// ([`CustomFieldKind::displays_as_hidden`]).
    IfHiddenField,
}

/// What the schema says about one known key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeySpec {
    /// The value it expects.
    pub expected: Expected,
    /// The item types it belongs to.
    pub applies: Applies,
    /// Who may write it.
    pub writers: Writers,
    /// Whether it is concealed by default.
    pub concealment: Concealment,
}

impl KeySpec {
    /// `true` if the key's value is concealed by default. `kind` is the custom field's kind;
    /// it matters only for `field/<id>/value`.
    #[must_use]
    pub fn concealed(&self, kind: CustomFieldKind) -> bool {
        match self.concealment {
            Concealment::Shown => false,
            Concealment::Concealed => true,
            Concealment::IfHiddenField => kind.displays_as_hidden(),
        }
    }
}

/// Builds a registry entry.
const fn spec(
    expected: Expected,
    applies: Applies,
    writers: Writers,
    concealment: Concealment,
) -> KeySpec {
    KeySpec {
        expected,
        applies,
        writers,
        concealment,
    }
}

/// A Text key of `applies`, written by anyone, shown.
const fn text(applies: Applies) -> KeySpec {
    spec(Expected::Text, applies, Writers::Any, Concealment::Shown)
}

/// A Text key of `applies`, written by anyone, concealed by default.
const fn secret_text(applies: Applies) -> KeySpec {
    spec(
        Expected::Text,
        applies,
        Writers::Any,
        Concealment::Concealed,
    )
}

/// Login-only.
const LOGIN: Applies = Applies::Only(SupportedType::Login);
/// Card-only.
const CARD: Applies = Applies::Only(SupportedType::Card);
/// Identity-only.
const IDENTITY: Applies = Applies::Only(SupportedType::Identity);
/// Vault-settings-only.
const VAULT: Applies = Applies::Only(SupportedType::VaultSettings);

/// Every fixed key of the M1 schema, with its entry (ADR 0018 §7).
pub const FIXED_KEYS: [(&str, KeySpec); 35] = [
    (
        ITEM_TYPE,
        spec(
            Expected::Enum,
            Applies::All,
            Writers::CreateOnly,
            Concealment::Shown,
        ),
    ),
    (ITEM_NAME, text(Applies::All)),
    (ITEM_NOTES, text(Applies::All)),
    (
        ITEM_FAVORITE,
        spec(
            Expected::Bool,
            Applies::All,
            Writers::Any,
            Concealment::Shown,
        ),
    ),
    (
        IMPORT_CREATED_MS,
        spec(
            Expected::U64,
            Applies::All,
            Writers::ImportOnly,
            Concealment::Shown,
        ),
    ),
    (LOGIN_USERNAME, text(LOGIN)),
    (LOGIN_PASSWORD, secret_text(LOGIN)),
    (LOGIN_TOTP, secret_text(LOGIN)),
    (CARD_HOLDER, text(CARD)),
    (CARD_NUMBER, secret_text(CARD)),
    (CARD_BRAND, text(CARD)),
    (CARD_EXP_MONTH, text(CARD)),
    (CARD_EXP_YEAR, text(CARD)),
    (CARD_CODE, secret_text(CARD)),
    (CARD_PIN, secret_text(CARD)),
    (IDENTITY_TITLE, text(IDENTITY)),
    (IDENTITY_FIRST_NAME, text(IDENTITY)),
    (IDENTITY_MIDDLE_NAME, text(IDENTITY)),
    (IDENTITY_LAST_NAME, text(IDENTITY)),
    (IDENTITY_COMPANY, text(IDENTITY)),
    (IDENTITY_EMAIL, text(IDENTITY)),
    (IDENTITY_PHONE, text(IDENTITY)),
    (IDENTITY_USERNAME, text(IDENTITY)),
    (IDENTITY_ADDRESS1, text(IDENTITY)),
    (IDENTITY_ADDRESS2, text(IDENTITY)),
    (IDENTITY_ADDRESS3, text(IDENTITY)),
    (IDENTITY_CITY, text(IDENTITY)),
    (IDENTITY_STATE, text(IDENTITY)),
    (IDENTITY_POSTAL_CODE, text(IDENTITY)),
    (IDENTITY_COUNTRY, text(IDENTITY)),
    (IDENTITY_SSN, secret_text(IDENTITY)),
    (IDENTITY_PASSPORT_NUMBER, secret_text(IDENTITY)),
    (IDENTITY_DRIVERS_LICENSE, text(IDENTITY)),
    (VAULT_NAME, text(VAULT)),
    (VAULT_ICON, text(VAULT)),
];

/// The namespaces reserved for the M3 item types (ADR 0018 §7, "Reserved prefixes"): fixed
/// keys `ssh.…`, `api.…`, `license.…`, `wifi.…` and `bank.…`.
const M3_TYPE_NAMESPACES: [&str; 5] = ["ssh", "api", "license", "wifi", "bank"];

/// What a reserved key is reserved for (ADR 0018 §7, "Reserved prefixes").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReservedFor {
    /// `ssh.`, `api.`, `license.`, `wifi.`, `bank.`: the M3 item types.
    M3Types,
    /// `attachment/`: the M3 attachments ADR.
    M3Attachments,
    /// `share/` attributes other than `secret`, and `share/<id>` itself: the M5 ADR.
    M5Share,
    /// `passkey.` and `passkey/`: the M7 passkey ADR.
    M7Passkeys,
}

/// What an M1 client knows about a grammar key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyClass {
    /// A key of the M1 schema.
    Known(KeySpec),
    /// A key under a reserved prefix: a later milestone defines it. Carried byte for byte; an
    /// M1 writer writes it only as Cleared in an edit or copied verbatim ([`check_carried`]).
    Reserved(ReservedFor),
    /// Any other key that fits the grammar: a newer client's key, or a `tag/<hex>` key no
    /// writer of ADR 0018 §7 produces. Carried byte for byte (ADR 0018 §11); an M1 writer writes
    /// it only as Cleared in an edit or copied verbatim ([`check_carried`]).
    Unknown,
}

/// Looks a key up in the M1 schema (ADR 0018 §7).
///
/// A `tag/<hex>` key is a tag only if [`tag_name`] accepts it: its hex is the UTF-8 of an NFC
/// name without a Cc code point, as §7 defines the key. Any other `tag/<hex>` key is
/// [`KeyClass::Unknown`], so it is neither shown as a tag nor written as one, and it is carried
/// like any unknown key ([`super::tag`]). Deciding that decodes the hex into a zeroizing buffer
/// of at most 64 bytes.
#[must_use]
pub fn classify(key: FieldKeyRef<'_>) -> KeyClass {
    match key.kind() {
        KeyKind::Fixed => {
            if let Some((_, spec)) = FIXED_KEYS.iter().find(|(k, _)| *k == key.as_str()) {
                return KeyClass::Known(*spec);
            }
            let namespace = key.namespace();
            if M3_TYPE_NAMESPACES.contains(&namespace) {
                KeyClass::Reserved(ReservedFor::M3Types)
            } else if namespace == "passkey" {
                KeyClass::Reserved(ReservedFor::M7Passkeys)
            } else {
                KeyClass::Unknown
            }
        }
        KeyKind::Element => classify_element(key),
    }
}

/// [`classify`] for an element key, by list name and attribute; a tag key also by its hex.
fn classify_element(key: FieldKeyRef<'_>) -> KeyClass {
    let known = |expected, applies, writers, concealment| {
        KeyClass::Known(spec(expected, applies, writers, concealment))
    };
    let list = key.namespace();
    match (list, key.attribute()) {
        (LIST_FIELD, Some(ATTR_LABEL)) => known(
            Expected::Text,
            Applies::All,
            Writers::Any,
            Concealment::Shown,
        ),
        (LIST_FIELD, Some(ATTR_KIND)) => known(
            Expected::Enum,
            Applies::All,
            Writers::Any,
            Concealment::Shown,
        ),
        (LIST_FIELD, Some(ATTR_VALUE)) => known(
            Expected::CustomFieldValue,
            Applies::All,
            Writers::Any,
            Concealment::IfHiddenField,
        ),
        (LIST_FIELD | LIST_URI, Some(ATTR_ORDER)) => known(
            Expected::SortKey,
            if list == LIST_URI {
                LOGIN
            } else {
                Applies::All
            },
            Writers::Any,
            Concealment::Shown,
        ),
        // A malformed tag key falls through to `Unknown` below.
        (LIST_TAG, None) if tag_name(key).is_ok() => known(
            Expected::TagMarker,
            Applies::All,
            Writers::Any,
            Concealment::Shown,
        ),
        (LIST_SHARE, Some(ATTR_SECRET)) => known(
            Expected::Bytes {
                len: SHARE_SECRET_LEN,
            },
            Applies::All,
            Writers::NotInM1,
            Concealment::Concealed,
        ),
        (LIST_SHARE, _) => KeyClass::Reserved(ReservedFor::M5Share),
        (LIST_URI | LIST_PWHIST, Some(ATTR_VALUE)) => {
            known(Expected::Text, LOGIN, Writers::Any, Concealment::Shown)
        }
        (LIST_URI, Some(ATTR_MATCH)) => {
            known(Expected::Enum, LOGIN, Writers::Any, Concealment::Shown)
        }
        (LIST_PWHIST, Some(ATTR_MS)) => {
            known(Expected::U64, LOGIN, Writers::Any, Concealment::Shown)
        }
        ("passkey", _) => KeyClass::Reserved(ReservedFor::M7Passkeys),
        ("attachment", _) => KeyClass::Reserved(ReservedFor::M3Attachments),
        _ => KeyClass::Unknown,
    }
}

/// The value a known key displays, or `None` for "unsupported value": the bytes do not decode
/// ([`ValueError`]), or decode to a type the key does not expect (ADR 0018 §6). Cleared is
/// returned as [`ValueRef::Cleared`], never as unsupported.
///
/// For `field/<id>/value`, also check [`CustomFieldKind::accepts`] with the field's kind.
#[must_use]
pub fn read_value(expected: Expected, encoded: &[u8]) -> Option<ValueRef<'_>> {
    ValueRef::decode(encoded)
        .ok()
        .filter(|value| expected.accepts(value))
}

/// `field/<id>/kind`, Enum value 1: a text custom field.
pub const CUSTOM_KIND_TEXT: u16 = 1;
/// `field/<id>/kind`, Enum value 2: a hidden custom field, concealed by default.
pub const CUSTOM_KIND_HIDDEN: u16 = 2;
/// `field/<id>/kind`, Enum value 3: a boolean custom field, whose value is a Bool.
pub const CUSTOM_KIND_BOOLEAN: u16 = 3;

/// The kind of a custom field (ADR 0018 §7: `kind` is 1 text, 2 hidden, 3 boolean; an unknown
/// kind displays as hidden).
///
/// It is the decoded value of a `field/<id>/kind` register, item data like any other value, so
/// `Debug` does not print it (ADR 0018 §2).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum CustomFieldKind {
    /// Kind 1: Text value, shown.
    Text,
    /// Kind 2: Text value, concealed by default.
    Hidden,
    /// Kind 3: Bool value.
    Boolean,
    /// Any other kind, a malformed `kind`, or none at all: displays as hidden.
    Unknown,
}

impl fmt::Debug for CustomFieldKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CustomFieldKind([REDACTED])")
    }
}

impl CustomFieldKind {
    /// The kind a `field/<id>/kind` register displays.
    ///
    /// ADR 0018 names only unknown kind values. This client reads an absent `kind` register, a
    /// Cleared or malformed one, and an Enum outside 1–3 the same way, as [`Self::Unknown`],
    /// which displays as hidden: the concealed reading is the one that cannot expose a hidden
    /// value.
    #[must_use]
    pub fn from_displayed(value: Option<ValueRef<'_>>) -> Self {
        match value {
            Some(ValueRef::Enum(CUSTOM_KIND_TEXT)) => Self::Text,
            Some(ValueRef::Enum(CUSTOM_KIND_HIDDEN)) => Self::Hidden,
            Some(ValueRef::Enum(CUSTOM_KIND_BOOLEAN)) => Self::Boolean,
            _ => Self::Unknown,
        }
    }

    /// The Enum value a writer stores; `None` for [`Self::Unknown`], which no M1 writer writes.
    #[must_use]
    pub const fn id(self) -> Option<u16> {
        match self {
            Self::Text => Some(CUSTOM_KIND_TEXT),
            Self::Hidden => Some(CUSTOM_KIND_HIDDEN),
            Self::Boolean => Some(CUSTOM_KIND_BOOLEAN),
            Self::Unknown => None,
        }
    }

    /// `true` for a hidden field and for an unknown kind (ADR 0018 §7).
    #[must_use]
    pub const fn displays_as_hidden(self) -> bool {
        matches!(self, Self::Hidden | Self::Unknown)
    }

    /// `true` if `value` fits a field of this kind: Cleared always; Text for a text or hidden
    /// field; Bool for a boolean field; either for an unknown kind.
    #[must_use]
    pub fn accepts(self, value: &ValueRef<'_>) -> bool {
        matches!(
            (self, value),
            (_, ValueRef::Cleared)
                | (Self::Text | Self::Hidden | Self::Unknown, ValueRef::Text(_))
                | (Self::Boolean | Self::Unknown, ValueRef::Bool(_))
        )
    }
}

/// The op a write belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WriteMode {
    /// The create op of a new item, from the user: a new item, a restore as a new item
    /// (ADR 0018 §3 "Surfacing") or a duplicate (§10 "The way out").
    Create,
    /// The create op of an imported item. The only op that writes `import.created_ms`. When
    /// an imported item does not fit one op, its writes are all checked with this mode and
    /// split over the create op and the ops that follow it (ADR 0027 §2 step 5).
    Import,
    /// An edit of an existing item.
    Edit,
}

impl WriteMode {
    /// `true` for the create op of an item ([`Self::Create`] or [`Self::Import`]).
    #[must_use]
    pub const fn is_create(self) -> bool {
        matches!(self, Self::Create | Self::Import)
    }
}

/// Where the key and value of one write come from (see the module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WriteSource {
    /// Entered by the user, or built by this client for the user: checked by [`check_write`].
    Entered,
    /// Copied byte for byte from a displayed value of an existing item, for a restore or a
    /// duplicate as a new item, or from a displayed value in an export of our own that is being
    /// imported (ADR 0027 §2, §6): checked by [`check_carried`].
    Carried,
}

/// Why a writer must not write a field. Carries no part of the key or value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum WriteError {
    /// The key breaks the grammar or the 160-byte limit (ADR 0018 §10: "Writers check the same
    /// limits, and the §7 grammar on each final key"). `@lifecycle` lands here: a writer sets
    /// the lifecycle through the op's marker, never as a field.
    Key(KeyError),
    /// The value is longer than 65,536 bytes (ADR 0018 §10).
    ValueTooLong,
    /// An entered value is of an unknown type or malformed: a writer never writes one of its
    /// own. (A carried value is not decoded, except a carried `item.type`.)
    MalformedValue,
    /// An entered value other than Cleared for a key that is not in the M1 schema
    /// ([`KeyClass::Unknown`]; a malformed `tag/<hex>` key is one). This client does not
    /// invent content for keys it does not know; it carries them (ADR 0018 §11).
    UnknownKey,
    /// As [`WriteError::UnknownKey`], for a key under a reserved prefix of a later milestone
    /// (ADR 0018 §7).
    ReservedKey,
    /// The item's type is not one this client supports: field edits are not offered
    /// (ADR 0018 §8).
    UnsupportedItemType,
    /// The key belongs to another item type.
    WrongItemType,
    /// The key is not written by this kind of op: `item.type` outside a create op,
    /// `import.created_ms` outside an import, or a key an M1 client never writes.
    NotWritable,
    /// The value's type is not the one the key expects, or `item.type` names another type
    /// than the item's.
    UnexpectedValue,
    /// An empty Text: writers write Cleared instead (ADR 0018 §6).
    EmptyText,
    /// Cleared in a create op: a create op writes no field the user left blank (ADR 0018 §6).
    BlankInCreate,
    /// A create op without `item.type` (ADR 0018 §7: the create op writes it).
    MissingItemType,
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key(e) => write!(f, "invalid field key: {e}"),
            Self::ValueTooLong => f.write_str("value is longer than 65536 bytes"),
            Self::MalformedValue => f.write_str("value is malformed or of an unknown type"),
            Self::UnknownKey => f.write_str("field key is not part of this schema"),
            Self::ReservedKey => f.write_str("field key is reserved for a later version"),
            Self::UnsupportedItemType => f.write_str("items of this type cannot be edited"),
            Self::WrongItemType => f.write_str("field does not belong to this item type"),
            Self::NotWritable => f.write_str("field cannot be written by this operation"),
            Self::UnexpectedValue => f.write_str("value does not fit this field"),
            Self::EmptyText => f.write_str("an emptied field must be written as cleared"),
            Self::BlankInCreate => f.write_str("a new item must not write blank fields"),
            Self::MissingItemType => f.write_str("a new item must write its type"),
        }
    }
}

impl core::error::Error for WriteError {}

/// Checks one entered field write before it is encoded (ADR 0018 §2 "Flow", §6–§8, §10).
///
/// `key` and `value` are the final bytes the record layer will encode. The value must be a
/// well-formed value of the type the key expects, and the key one of the M1 schema for the
/// item's type, except that in an edit Cleared may also go to a key outside the schema: removing
/// a list element clears every attribute of it that the writer holds, including attributes a
/// newer client added (ADR 0018 §6; see the module docs). Which keys the item holds is the
/// caller's to know.
///
/// For `field/<id>/value` the check accepts Text or Bool; the caller also checks
/// [`CustomFieldKind::accepts`] with the kind it writes or displays.
///
/// # Errors
/// [`WriteError`] naming the first rule the write breaks, checked in this order: the key, the
/// value's size and form, the item's type, a blank field in a create op, then the key's entry.
pub fn check_write(
    item_type: ItemType,
    mode: WriteMode,
    key: &[u8],
    value: &[u8],
) -> Result<(), WriteError> {
    let key = FieldKeyRef::parse(key).map_err(WriteError::Key)?;
    let value = match ValueRef::decode(value) {
        Ok(value) => value,
        Err(ValueError::TooLong) => return Err(WriteError::ValueTooLong),
        Err(_) => return Err(WriteError::MalformedValue),
    };
    let supported = item_type
        .supported()
        .ok_or(WriteError::UnsupportedItemType)?;
    if value.is_cleared() && mode.is_create() {
        return Err(WriteError::BlankInCreate);
    }
    let spec = match classify(key) {
        KeyClass::Known(spec) => spec,
        // Only in an edit, here: ADR 0018 §6 element removal.
        KeyClass::Unknown | KeyClass::Reserved(_) if value.is_cleared() => return Ok(()),
        KeyClass::Reserved(_) => return Err(WriteError::ReservedKey),
        KeyClass::Unknown => return Err(WriteError::UnknownKey),
    };
    check_placement(spec, supported, mode)?;
    match value {
        ValueRef::Cleared => Ok(()),
        ValueRef::Text("") => Err(WriteError::EmptyText),
        ValueRef::Enum(id) if key.as_str() == ITEM_TYPE && id != item_type.id() => {
            Err(WriteError::UnexpectedValue)
        }
        _ if spec.expected.accepts(&value) => Ok(()),
        _ => Err(WriteError::UnexpectedValue),
    }
}

/// Checks one carried field write: a key and value copied byte for byte from a displayed
/// value of an existing item, for "Restore it as a new item" (ADR 0018 §3 "Surfacing") or
/// "duplicate as a new item" (§10 "The way out"), or from a displayed value of an item in an
/// export of our own that is being imported (ADR 0027 §2 step 3, §6 "Writes"). See the module
/// docs for why. `mode` is the op the write goes into: the new item's create op, or one of the
/// edit ops that follow it when the copy does not fit one op (§10). An import checks every
/// write of the new item with [`WriteMode::Import`], whichever of its ops the write lands in
/// (ADR 0027 §6: "Every write passes `check_carried` for `WriteMode::Import`"), and puts
/// `item.type` and `import.created_ms` in the first.
///
/// Any key the grammar accepts may be carried, unknown and reserved keys included, with any
/// value bytes up to 65,536; they are not decoded. A known key must still belong to the item's
/// type and be one this op may write, and a carried `item.type` must be the Enum of the item's
/// own type. A carried Cleared carries nothing and is checked as an entered one
/// ([`check_write`]): it is refused in a create op.
///
/// # Errors
/// [`WriteError`] naming the first rule the write breaks, checked in this order: the key, the
/// value's size, the item's type, then the key's entry.
pub fn check_carried(
    item_type: ItemType,
    mode: WriteMode,
    key: &[u8],
    value: &[u8],
) -> Result<(), WriteError> {
    if value.is_empty() {
        return check_write(item_type, mode, key, value);
    }
    let parsed = FieldKeyRef::parse(key).map_err(WriteError::Key)?;
    if value.len() > MAX_VALUE_LEN {
        return Err(WriteError::ValueTooLong);
    }
    let supported = item_type
        .supported()
        .ok_or(WriteError::UnsupportedItemType)?;
    let spec = match classify(parsed) {
        KeyClass::Known(spec) => spec,
        KeyClass::Unknown | KeyClass::Reserved(_) => return Ok(()),
    };
    check_placement(spec, supported, mode)?;
    if parsed.as_str() != ITEM_TYPE {
        return Ok(());
    }
    match ValueRef::decode(value) {
        Ok(ValueRef::Enum(id)) if id == item_type.id() => Ok(()),
        Ok(_) => Err(WriteError::UnexpectedValue),
        Err(_) => Err(WriteError::MalformedValue),
    }
}

/// The rules of a known key that do not look at the value: the item types it belongs to and
/// who writes it (ADR 0018 §7, "Types" and "Notes").
fn check_placement(
    spec: KeySpec,
    item_type: SupportedType,
    mode: WriteMode,
) -> Result<(), WriteError> {
    if !spec.applies.includes(item_type) {
        return Err(WriteError::WrongItemType);
    }
    match spec.writers {
        Writers::Any => Ok(()),
        Writers::CreateOnly if mode.is_create() => Ok(()),
        Writers::ImportOnly if mode == WriteMode::Import => Ok(()),
        Writers::CreateOnly | Writers::ImportOnly | Writers::NotInM1 => {
            Err(WriteError::NotWritable)
        }
    }
}

/// Checks the field writes of a create op: every write passes [`check_write`] or, if carried,
/// [`check_carried`], and one of them is `item.type` (ADR 0018 §7). Each write is its source,
/// key and value. Order and duplicates are the record layer's (ADR 0018 §4).
///
/// A restore or duplicate as a new item enters `item.type` (the type the user confirms,
/// ADR 0018 §3 "Surfacing") and carries the rest.
///
/// # Errors
/// [`WriteError`] for the first write that fails, or [`WriteError::MissingItemType`].
pub fn check_create<'a>(
    item_type: ItemType,
    mode: WriteMode,
    writes: impl IntoIterator<Item = (WriteSource, &'a [u8], &'a [u8])>,
) -> Result<(), WriteError> {
    let mut has_type = false;
    for (source, key, value) in writes {
        match source {
            WriteSource::Entered => check_write(item_type, mode, key, value)?,
            WriteSource::Carried => check_carried(item_type, mode, key, value)?,
        }
        has_type |= key == ITEM_TYPE.as_bytes();
    }
    if has_type {
        Ok(())
    } else {
        Err(WriteError::MissingItemType)
    }
}
