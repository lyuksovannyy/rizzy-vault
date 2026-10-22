// SPDX-License-Identifier: AGPL-3.0-only

//! Item types (ADR 0018 §8, (d)).
//!
//! An item's type is the Enum value of its `item.type` field, written by the create op only and
//! never changed: converting an item is a new item (ADR 0018 §7). The registry:
//!
//! | Id | Type | Milestone |
//! |---|---|---|
//! | `0x0000` | invalid | – |
//! | `0x0001`–`0x0004` | Login, Secure Note, Card, Identity | M1 |
//! | `0x0005`–`0x0009` | SSH key, API credential, Software license, Wi-Fi, Bank account | M3 (ADR 0055 §2) |
//! | `0x000A`–`0xEFFF` | unassigned; each needs an ADR line | – |
//! | `0xF001` | Vault settings (system type) | M1 |
//! | `0xF000`, `0xF002`–`0xFFFF` | reserved for system types | – |
//!
//! **`0x000A`, released** (ADR 0039 §1, 2026-10-07). ADR 0018 owner decision 6 reserved both
//! `0x000A` (a standalone Passkey item type) and the `passkey/` list on Login for "the M7
//! passkey ADR," to pick one. ADR 0039 picked the list (see [`super::schema::LIST_PASSKEY`])
//! and released `0x000A` back to unassigned; it stays permanently retired in practice (ADR 0039
//! Negative consequences), even though an unassigned id is nominally reusable.
//!
//! **The M3 types** (ADR 0055 §2, Accepted 2026-10-22). `0x0005`–`0x0009` moved from "M3,
//! reserved" to assigned, each a [`SupportedType`] variant whose fields are ADR 0055 §1's
//! (`super::schema`). The `ReservedM3` class they mapped to before is gone (ADR 0055 owner
//! answer 2): no id reaches it any more. A client built before ADR 0055 still shows these items as
//! "Unsupported item", as below, and carries their keys byte for byte.
//!
//! **Unknown types** (ADR 0018 §8). An item whose type this client does not support (a reserved
//! or unassigned id, `0x0000`, or no valid `item.type` at all) shows as "Unsupported item, update
//! rizzy-vault". Trash, restore and purge still work; field edits are not offered
//! ([`ItemType::supported`] is `None`, and [`super::schema::check_write`] refuses them). A new
//! type needs no version bump (ADR 0018 §11).
//!
//! **Vault settings** (ADR 0018 §8, ADR 0012 §1). An ordinary item with a random id and type
//! `0xF001`, holding `vault.name` and `vault.icon`. It is never listed, searched, exported as an
//! item, shared or trashed ([`SupportedType::is_user_item`]). The one that counts is the one with
//! the lowest item id among the non-tombstoned items of that type ([`effective_vault_settings`]);
//! a client creates another only when a complete sync finds none. If a faulty client trashes it,
//! it stays in effect; if one purges it, the settings reset to defaults. Its id is random, not
//! derived from `vault_id`: object ids are random (CRYPTO.md §2), and a derived id would tell the
//! server which item holds the settings.

use core::fmt;

use crate::ids::ItemId;

use super::value::ValueRef;

/// An `item.type` id (ADR 0018 §8). Any `u16`; [`ItemType::class`] says what it means to this
/// client.
///
/// The type is the decoded value of the item's `item.type` field. Item data is encrypted so
/// that the server does not learn which items are logins or cards (ADR 0012 §11), and client
/// logs must not tell it either: `Debug` prints no part of the type (ADR 0018 §2, CRYPTO.md
/// §12.2), and neither does it for [`ItemTypeClass`] or [`SupportedType`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ItemType(u16);

impl fmt::Debug for ItemType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ItemType([REDACTED])")
    }
}

impl ItemType {
    /// `0x0000`: invalid.
    pub const INVALID: Self = Self(0x0000);
    /// `0x0001`: Login (M1).
    pub const LOGIN: Self = Self(0x0001);
    /// `0x0002`: Secure Note (M1).
    pub const SECURE_NOTE: Self = Self(0x0002);
    /// `0x0003`: Card (M1).
    pub const CARD: Self = Self(0x0003);
    /// `0x0004`: Identity (M1).
    pub const IDENTITY: Self = Self(0x0004);
    /// `0x0005`: SSH key (M3, ADR 0055).
    pub const SSH_KEY: Self = Self(0x0005);
    /// `0x0006`: API credential (M3, ADR 0055).
    pub const API_CREDENTIAL: Self = Self(0x0006);
    /// `0x0007`: Software license (M3, ADR 0055).
    pub const SOFTWARE_LICENSE: Self = Self(0x0007);
    /// `0x0008`: Wi-Fi (M3, ADR 0055).
    pub const WIFI: Self = Self(0x0008);
    /// `0x0009`: Bank account (M3, ADR 0055).
    pub const BANK_ACCOUNT: Self = Self(0x0009);
    /// `0xF001`: Vault settings, a system type (M1).
    pub const VAULT_SETTINGS: Self = Self(0xF001);

    /// Wraps a type id.
    #[must_use]
    pub const fn from_id(id: u16) -> Self {
        Self(id)
    }

    /// The type id, the Enum value of `item.type`.
    #[must_use]
    pub const fn id(self) -> u16 {
        self.0
    }

    /// The type an `item.type` register displays, if it is a well-formed Enum. `None` when the
    /// register is absent, displays Cleared, or holds another type or a malformed value: such
    /// an item has no valid type and shows as unsupported (ADR 0018 §7).
    #[must_use]
    pub fn from_displayed(value: Option<ValueRef<'_>>) -> Option<Self> {
        match value {
            Some(ValueRef::Enum(id)) => Some(Self(id)),
            _ => None,
        }
    }

    /// What the id means (ADR 0018 §8).
    #[must_use]
    pub const fn class(self) -> ItemTypeClass {
        match self.0 {
            0x0000 => ItemTypeClass::Invalid,
            0x0001 => ItemTypeClass::Supported(SupportedType::Login),
            0x0002 => ItemTypeClass::Supported(SupportedType::SecureNote),
            0x0003 => ItemTypeClass::Supported(SupportedType::Card),
            0x0004 => ItemTypeClass::Supported(SupportedType::Identity),
            0x0005 => ItemTypeClass::Supported(SupportedType::SshKey),
            0x0006 => ItemTypeClass::Supported(SupportedType::ApiCredential),
            0x0007 => ItemTypeClass::Supported(SupportedType::SoftwareLicense),
            0x0008 => ItemTypeClass::Supported(SupportedType::Wifi),
            0x0009 => ItemTypeClass::Supported(SupportedType::BankAccount),
            0x000A..=0xEFFF => ItemTypeClass::Unassigned,
            0xF001 => ItemTypeClass::Supported(SupportedType::VaultSettings),
            _ => ItemTypeClass::ReservedSystem,
        }
    }

    /// The supported type this id names, or `None` for every type this client shows as "Unsupported
    /// item" (ADR 0018 §8, "Unknown type").
    #[must_use]
    pub const fn supported(self) -> Option<SupportedType> {
        match self.class() {
            ItemTypeClass::Supported(t) => Some(t),
            _ => None,
        }
    }
}

/// What an [`ItemType`] id means to this client. `Debug` does not print it.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum ItemTypeClass {
    /// `0x0000`.
    Invalid,
    /// An M1 or M3 type, or the vault-settings system type.
    Supported(SupportedType),
    /// `0x000A`–`0xEFFF`: no ADR assigns it yet. `0x000A` itself was the standalone passkey
    /// candidate ADR 0018 reserved and ADR 0039 released back here (ADR 0039 §1).
    Unassigned,
    /// `0xF000` and `0xF002`–`0xFFFF`: reserved for system types.
    ReservedSystem,
}

impl fmt::Debug for ItemTypeClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ItemTypeClass([REDACTED])")
    }
}

/// The item types this client supports: it shows them and offers field edits. The M1 types,
/// the M3 types of ADR 0055 §2 and the vault-settings system type. `Debug` does not print it.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum SupportedType {
    /// Login: username, password, TOTP, URIs, password history.
    Login,
    /// Secure Note: its body is `item.notes`.
    SecureNote,
    /// Card.
    Card,
    /// Identity.
    Identity,
    /// SSH key (`0x0005`): `ssh.` fields (ADR 0055 §1).
    SshKey,
    /// API credential (`0x0006`): `api.` fields (ADR 0055 §1).
    ApiCredential,
    /// Software license (`0x0007`): `license.` fields (ADR 0055 §1).
    SoftwareLicense,
    /// Wi-Fi (`0x0008`): `wifi.` fields (ADR 0055 §1).
    Wifi,
    /// Bank account (`0x0009`): `bank.` fields (ADR 0055 §1).
    BankAccount,
    /// Vault settings: name and icon of the vault; a system type.
    VaultSettings,
}

impl fmt::Debug for SupportedType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SupportedType([REDACTED])")
    }
}

impl SupportedType {
    /// The type's id.
    #[must_use]
    pub const fn item_type(self) -> ItemType {
        match self {
            Self::Login => ItemType::LOGIN,
            Self::SecureNote => ItemType::SECURE_NOTE,
            Self::Card => ItemType::CARD,
            Self::Identity => ItemType::IDENTITY,
            Self::SshKey => ItemType::SSH_KEY,
            Self::ApiCredential => ItemType::API_CREDENTIAL,
            Self::SoftwareLicense => ItemType::SOFTWARE_LICENSE,
            Self::Wifi => ItemType::WIFI,
            Self::BankAccount => ItemType::BANK_ACCOUNT,
            Self::VaultSettings => ItemType::VAULT_SETTINGS,
        }
    }

    /// `true` for a user item, `false` for the vault-settings system item, which is never
    /// listed, searched, exported as an item, shared or trashed (ADR 0018 §8).
    #[must_use]
    pub const fn is_user_item(self) -> bool {
        !matches!(self, Self::VaultSettings)
    }
}

/// The vault-settings item that counts: the lowest item id among the non-tombstoned items of
/// type `0xF001` (ADR 0018 §8, "Which item counts"). The caller passes exactly those ids; `None`
/// means the vault has none, and the settings are the defaults.
///
/// Item ids are random and public (CRYPTO.md §2), so they compare with `Ord`.
#[must_use]
pub fn effective_vault_settings(candidates: impl IntoIterator<Item = ItemId>) -> Option<ItemId> {
    candidates.into_iter().min()
}
