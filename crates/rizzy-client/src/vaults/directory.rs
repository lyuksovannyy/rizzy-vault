// SPDX-License-Identifier: AGPL-3.0-only

//! The vault directory: `ACCOUNT_SETTINGS` tag `0x0002` ([ADR 0081] §A2).
//!
//! The account's authenticated list of the vaults it holds. It rides in the existing
//! `ACCOUNT_SETTINGS` envelope (purpose 0x0014, account key, ADR 0042), so it is encrypted,
//! written only by the account's own clients, and fresh through the signed `account-state`.
//!
//! ```text
//! tag 0x0002 value
//!   u8  format = 1
//!   u16 n ‖ n × entry            1 ≤ n ≤ MAX_DIRECTORY_ENTRIES (128), strictly ascending by vault_id
//! entry
//!   vault_id (16)
//!   u8  kind                     0 invalid; 1 Personal; 2 owned; 3 joined (Part B); 4–255 unassigned
//!   u16(len) ‖ body
//! body, kind 1:  u8 flags = 0                                                   (len 1)
//! body, kind 2:  u8 flags; if bit 0: u64 membership_seq ‖ membership_hash (32)  (len 1, or 41 with bit 0)
//! body, kind 3:  u8 flags = 0x01 ‖ owner account_id (16) ‖ u64 membership_seq ‖ membership_hash (32)  (len 57)
//! ```
//!
//! - Exactly one kind-1 entry. Flag bits other than bit 0 must be 0.
//! - **Rejected outright** ([`ClientError::InvalidServerResponse`], as ADR 0042 §2 rejects any
//!   violation inside a recognised tag): wrong lengths, trailing bytes, unsorted or duplicate
//!   ids, zero or two kind-1 entries, a set reserved flag bit, `format ≠ 1`, `n` of 0 or above
//!   the limit, kind 0.
//! - **Unknown kinds** (4–255) are kept verbatim on every rewrite; this build never opens or
//!   deletes such a vault (it "needs a newer rizzy-vault").
//! - Kind 2 with bit 0 (a shared owned vault) and kind 3 (a joined vault) are Part B's (M9):
//!   this build parses them, keeps them byte for byte, and never opens such a vault, as it cannot
//!   verify its membership chain ([ADR 0081] §A12).
//!
//! [ADR 0081]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0081-multiple-vaults-personal-and-shared.md

use core::fmt;

use rizzy_core::encoding::{Reader, put_u8, put_u16, put_u64};
use rizzy_core::ids::{AccountId, VaultId};
use rizzy_proto::limits::MAX_DIRECTORY_ENTRIES;

use crate::error::ClientError;

/// The `ACCOUNT_SETTINGS` tag of the vault directory ([ADR 0081] §0 item 6).
///
/// [ADR 0081]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0081-multiple-vaults-personal-and-shared.md
pub const TAG_VAULT_DIRECTORY: u16 = 0x0002;

/// The only `format` this build reads and writes.
pub const DIRECTORY_FORMAT: u8 = 1;

/// Kind 1: the Personal vault.
const KIND_PERSONAL: u8 = 1;
/// Kind 2: a vault the account owns.
const KIND_OWNED: u8 = 2;
/// Kind 3: another account's vault this account joined (Part B).
const KIND_JOINED: u8 = 3;
/// Bit 0 of the flags: "shared", with a membership pin.
const FLAG_SHARED: u8 = 0x01;

/// The highest `vault-membership` statement the account verified for a shared vault ([ADR
/// 0081] §B3, the rollback pin). Part B fills it; this build only carries it.
///
/// [ADR 0081]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0081-multiple-vaults-personal-and-shared.md
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MembershipPin {
    /// The statement's `membership_seq`.
    pub membership_seq: u64,
    /// Its hash.
    pub membership_hash: [u8; 32],
}

/// What one directory entry says a vault is.
#[derive(Clone, PartialEq, Eq)]
pub enum DirectoryKind {
    /// The Personal vault (kind 1).
    Personal,
    /// An owned vault (kind 2); `Some` when it is shared (bit 0, Part B).
    Owned(Option<MembershipPin>),
    /// A joined vault (kind 3, Part B): its owner and the membership pin.
    Joined {
        /// The owning account.
        owner: AccountId,
        /// The membership pin.
        pin: MembershipPin,
    },
    /// A kind this build does not know (4–255), its body kept verbatim.
    Unknown {
        /// The kind byte.
        kind: u8,
        /// The body, as read.
        body: Vec<u8>,
    },
}

impl fmt::Debug for DirectoryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Personal => f.write_str("Personal"),
            Self::Owned(None) => f.write_str("Owned"),
            Self::Owned(Some(_)) => f.write_str("Owned(shared)"),
            Self::Joined { .. } => f.write_str("Joined"),
            Self::Unknown { kind, body } => write!(f, "Unknown({kind}, {} bytes)", body.len()),
        }
    }
}

impl DirectoryKind {
    /// Whether this build may open the vault: the Personal vault and an unshared owned vault.
    /// A shared or joined vault needs Part B's membership checks, an unknown kind a newer build
    /// ([ADR 0081] §A12).
    ///
    /// [ADR 0081]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0081-multiple-vaults-personal-and-shared.md
    #[must_use]
    pub const fn openable(&self) -> bool {
        matches!(self, Self::Personal | Self::Owned(None))
    }
}

/// One directory entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryEntry {
    /// The vault.
    pub vault_id: VaultId,
    /// What it is.
    pub kind: DirectoryKind,
}

/// The parsed vault directory (module docs): at least one entry, exactly one Personal vault,
/// strictly ascending by id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultDirectory {
    /// The entries, ascending by id.
    entries: Vec<DirectoryEntry>,
}

impl VaultDirectory {
    /// The directory of an account with its Personal vault only.
    #[must_use]
    pub fn personal_only(personal: VaultId) -> Self {
        Self {
            entries: vec![DirectoryEntry {
                vault_id: personal,
                kind: DirectoryKind::Personal,
            }],
        }
    }

    /// A directory of `entries`, sorted (the tests' typed vectors).
    #[cfg(test)]
    pub(crate) fn from_entries(mut entries: Vec<DirectoryEntry>) -> Self {
        entries.sort_by_key(|e| e.vault_id);
        Self { entries }
    }

    /// The entries, ascending by id.
    #[must_use]
    pub fn entries(&self) -> &[DirectoryEntry] {
        &self.entries
    }

    /// The Personal vault.
    #[must_use]
    pub fn personal(&self) -> Option<VaultId> {
        self.entries
            .iter()
            .find(|e| e.kind == DirectoryKind::Personal)
            .map(|e| e.vault_id)
    }

    /// The entry of `vault_id`, if listed.
    #[must_use]
    pub fn entry(&self, vault_id: VaultId) -> Option<&DirectoryEntry> {
        self.entries.iter().find(|e| e.vault_id == vault_id)
    }

    /// The number of vaults the account owns, the Personal vault included (kinds 1 and 2).
    #[must_use]
    pub fn owned_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| matches!(e.kind, DirectoryKind::Personal | DirectoryKind::Owned(_)))
            .count()
    }

    /// This directory with a new unshared owned vault ([ADR 0081] §A3).
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] when `vault_id` is listed already;
    /// [`ClientError::VaultLimitReached`] at `MAX_OWNED_VAULTS` owned vaults or
    /// [`MAX_DIRECTORY_ENTRIES`] entries.
    ///
    /// [ADR 0081]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0081-multiple-vaults-personal-and-shared.md
    pub fn with_owned(&self, vault_id: VaultId) -> Result<Self, ClientError> {
        if self.entry(vault_id).is_some() {
            return Err(ClientError::InvalidInput);
        }
        if self.owned_count() >= rizzy_proto::limits::MAX_OWNED_VAULTS
            || self.entries.len() >= MAX_DIRECTORY_ENTRIES
        {
            return Err(ClientError::VaultLimitReached);
        }
        let mut entries = self.entries.clone();
        entries.push(DirectoryEntry {
            vault_id,
            kind: DirectoryKind::Owned(None),
        });
        entries.sort_by_key(|e| e.vault_id);
        Ok(Self { entries })
    }

    /// This directory without the owned vault `vault_id` ([ADR 0081] §A5).
    ///
    /// # Errors
    /// [`ClientError::PersonalVaultProtected`] for the Personal vault (INV-101);
    /// [`ClientError::UnknownVault`] for a vault that is not listed or not an owned vault this
    /// build may delete (a shared, joined or unknown kind).
    ///
    /// [ADR 0081]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0081-multiple-vaults-personal-and-shared.md
    pub fn without(&self, vault_id: VaultId) -> Result<Self, ClientError> {
        match self.entry(vault_id).map(|e| &e.kind) {
            Some(DirectoryKind::Personal) => Err(ClientError::PersonalVaultProtected),
            Some(DirectoryKind::Owned(None)) => Ok(Self {
                entries: self
                    .entries
                    .iter()
                    .filter(|e| e.vault_id != vault_id)
                    .cloned()
                    .collect(),
            }),
            _ => Err(ClientError::UnknownVault),
        }
    }

    /// Parses a tag `0x0002` value (module docs).
    ///
    /// # Errors
    /// [`ClientError::InvalidServerResponse`] for every violation the module docs list.
    pub fn decode(value: &[u8]) -> Result<Self, ClientError> {
        let bad = |_| ClientError::InvalidServerResponse;
        let mut r = Reader::new(value);
        if r.u8().map_err(bad)? != DIRECTORY_FORMAT {
            return Err(ClientError::InvalidServerResponse);
        }
        let n = usize::from(r.u16().map_err(bad)?);
        if n == 0 || n > MAX_DIRECTORY_ENTRIES {
            return Err(ClientError::InvalidServerResponse);
        }
        let mut entries: Vec<DirectoryEntry> = Vec::with_capacity(n);
        let mut personal = 0usize;
        for _ in 0..n {
            let vault_id = VaultId::from_bytes(*r.array::<16>().map_err(bad)?);
            if entries.last().is_some_and(|p| p.vault_id >= vault_id) {
                return Err(ClientError::InvalidServerResponse);
            }
            let kind = r.u8().map_err(bad)?;
            let len = usize::from(r.u16().map_err(bad)?);
            let body = r.take(len).map_err(bad)?;
            let kind = parse_kind(kind, body)?;
            if kind == DirectoryKind::Personal {
                personal += 1;
            }
            entries.push(DirectoryEntry { vault_id, kind });
        }
        r.finish().map_err(bad)?;
        if personal != 1 {
            return Err(ClientError::InvalidServerResponse);
        }
        Ok(Self { entries })
    }

    /// Writes the tag `0x0002` value: every entry, unknown kinds byte for byte.
    ///
    /// # Errors
    /// [`ClientError::Internal`] when the directory breaks its own invariants (no Personal
    /// vault, too many entries, a body over `u16`), which no constructor allows.
    pub fn encode(&self) -> Result<Vec<u8>, ClientError> {
        let n = u16::try_from(self.entries.len()).map_err(|_| ClientError::Internal)?;
        if self.entries.is_empty() || self.entries.len() > MAX_DIRECTORY_ENTRIES {
            return Err(ClientError::Internal);
        }
        let mut out = Vec::new();
        put_u8(&mut out, DIRECTORY_FORMAT);
        put_u16(&mut out, n);
        for entry in &self.entries {
            out.extend_from_slice(entry.vault_id.as_bytes());
            let (kind, body) = encode_kind(&entry.kind);
            put_u8(&mut out, kind);
            put_u16(
                &mut out,
                u16::try_from(body.len()).map_err(|_| ClientError::Internal)?,
            );
            out.extend_from_slice(&body);
        }
        Ok(out)
    }
}

/// The kind of an entry from its kind byte and body.
fn parse_kind(kind: u8, body: &[u8]) -> Result<DirectoryKind, ClientError> {
    let bad = |_| ClientError::InvalidServerResponse;
    let mut r = Reader::new(body);
    let parsed = match kind {
        0 => return Err(ClientError::InvalidServerResponse),
        KIND_PERSONAL => {
            if r.u8().map_err(bad)? != 0 {
                return Err(ClientError::InvalidServerResponse);
            }
            DirectoryKind::Personal
        }
        KIND_OWNED => match r.u8().map_err(bad)? {
            0 => DirectoryKind::Owned(None),
            FLAG_SHARED => DirectoryKind::Owned(Some(pin(&mut r)?)),
            _ => return Err(ClientError::InvalidServerResponse),
        },
        KIND_JOINED => {
            if r.u8().map_err(bad)? != FLAG_SHARED {
                return Err(ClientError::InvalidServerResponse);
            }
            let owner = AccountId::from_bytes(*r.array::<16>().map_err(bad)?);
            DirectoryKind::Joined {
                owner,
                pin: pin(&mut r)?,
            }
        }
        _ => {
            return Ok(DirectoryKind::Unknown {
                kind,
                body: body.to_vec(),
            });
        }
    };
    r.finish().map_err(bad)?;
    Ok(parsed)
}

/// A membership pin: `u64 membership_seq ‖ membership_hash (32)`.
fn pin(r: &mut Reader<'_>) -> Result<MembershipPin, ClientError> {
    let bad = |_| ClientError::InvalidServerResponse;
    Ok(MembershipPin {
        membership_seq: r.u64().map_err(bad)?,
        membership_hash: *r.array::<32>().map_err(bad)?,
    })
}

/// The kind byte and body of an entry.
fn encode_kind(kind: &DirectoryKind) -> (u8, Vec<u8>) {
    let mut body = Vec::new();
    let byte = match kind {
        DirectoryKind::Personal => {
            put_u8(&mut body, 0);
            KIND_PERSONAL
        }
        DirectoryKind::Owned(None) => {
            put_u8(&mut body, 0);
            KIND_OWNED
        }
        DirectoryKind::Owned(Some(p)) => {
            put_u8(&mut body, FLAG_SHARED);
            put_pin(&mut body, p);
            KIND_OWNED
        }
        DirectoryKind::Joined { owner, pin } => {
            put_u8(&mut body, FLAG_SHARED);
            body.extend_from_slice(owner.as_bytes());
            put_pin(&mut body, pin);
            KIND_JOINED
        }
        DirectoryKind::Unknown { kind, body: kept } => {
            body.extend_from_slice(kept);
            *kind
        }
    };
    (byte, body)
}

/// Writes a membership pin.
fn put_pin(out: &mut Vec<u8>, pin: &MembershipPin) {
    put_u64(out, pin.membership_seq);
    out.extend_from_slice(&pin.membership_hash);
}
