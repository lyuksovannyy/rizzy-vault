//! The device certificates the vault domain verifies records against, supplied by the `auth`
//! domain through a trait (ADR 0012 §7 "Upload": "Certificates come from the `auth` domain
//! through a trait"; ADR 0016 R4).
//!
//! `rizzy-domain-vault` never reads an `auth_` table. `rizzy-server` implements
//! [`DeviceDirectory`] by wiring in `rizzy-domain-auth`'s public API, which reads its own tables
//! on the connection it is handed: the connection of the vault domain's write transaction, so
//! the certificates, revocations and suspensions are read under the account lock the upload
//! holds (ADR 0012 §6: "The check, the revocation and every upload run under the account's
//! lock"). A revocation therefore cannot commit between the check and the insert.
//!
//! **The implementer's contract.** [`DeviceDirectory::authors`] returns, for one account:
//! - every device certificate the account holds (kinds 1–4) that verifies under the identity
//!   key of the account's current `identity_epoch` and names the account (CRYPTO.md §10.2 rules
//!   (a) and (b); INV-30), with the fields copied out of the verified certificate;
//! - for each revoked device, its signed `last_accepted_device_seq` (CRYPTO.md §11.8), and for
//!   each suspended one, the suspension of revocation phase 1 (ADR 0012 §6).
//!
//! A certificate that does not verify is left out, so every record it signed is refused.
//!
//! [`DeviceDirectory::account_key`] returns the `account_key_epoch` and `account_key_id` of the
//! account's held signed `account-state`, verified from the stored chain, read on the same
//! connection: what healing step 3b checks a re-published self-grant against (ADR 0032 §3).

use core::fmt;
use core::future::Future;
use std::collections::BTreeMap;

use rizzy_core::ids::{AccountId, DeviceId, PublicKeyId};
use rizzy_core::sign::DeviceVerifyingKey;
use rizzy_core::sign::statements::DeviceKind;
use rizzy_storage::Conn;

/// Where a device stands in revocation (ADR 0012 §6; CRYPTO.md §11.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorStatus {
    /// Neither suspended nor revoked.
    Active,
    /// Suspended by revocation phase 1: "From that commit on … the server rejects the device's
    /// uploads" (ADR 0012 §6). This domain reads that conservatively as every record the device
    /// authored, whoever uploads it, so that H stays the head phase 2 requires.
    Suspended,
    /// Revoked, with the cut-off of its signed `device-revocation`: its ops with `device_seq` ≤
    /// `last_accepted_device_seq` stay valid, nothing later is accepted (CRYPTO.md §11.8 step 4).
    Revoked {
        /// The revocation's `last_accepted_device_seq`.
        last_accepted_device_seq: u64,
    },
}

/// One device's certificate, as the vault domain checks records against it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorCertificate {
    /// The device.
    pub device_id: DeviceId,
    /// Its Ed25519 key, from its verified certificate.
    pub verifying_key: DeviceVerifyingKey,
    /// Its kind (1–4).
    pub device_kind: DeviceKind,
    /// The certificate's `expires_at_ms`, 0 for none (always non-zero for kind 4).
    pub expires_at_ms: u64,
    /// Its revocation state.
    pub status: AuthorStatus,
}

impl AuthorCertificate {
    /// Whether the certificate has expired at the server's clock `now_ms` (ADR 0021 §9
    /// "Revoked and kind-4 authors": the server refuses new snapshots "after the author's …
    /// expiry").
    #[must_use]
    pub const fn expired_at(&self, now_ms: u64) -> bool {
        self.expires_at_ms != 0 && now_ms > self.expires_at_ms
    }

    /// Whether an op with this HLC falls within the certificate's validity: its milliseconds
    /// (top 48 bits) at most `expires_at_ms`, or no expiry (ADR 0012 §7 "Upload"; CRYPTO.md
    /// §10.2 rule (c), which applies to a durable certificate with an expiry too).
    #[must_use]
    pub const fn permits_hlc(&self, hlc: u64) -> bool {
        self.expires_at_ms == 0 || (hlc >> 16) <= self.expires_at_ms
    }
}

/// Two certificates for one device were given to [`Authors::new`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DuplicateDevice;

impl fmt::Display for DuplicateDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("two certificates for one device")
    }
}

impl std::error::Error for DuplicateDevice {}

/// Every certificate of one account, indexed by device and by signing key.
#[derive(Clone, Debug, Default)]
pub struct Authors {
    /// The certificates by device id.
    by_device: BTreeMap<DeviceId, AuthorCertificate>,
    /// Device ids by the `PublicKeyId` of their Ed25519 key, the signer key id a signature
    /// container names (CRYPTO.md §9.3).
    by_key: BTreeMap<PublicKeyId, DeviceId>,
}

impl Authors {
    /// Indexes `certificates`.
    ///
    /// # Errors
    /// [`DuplicateDevice`] if two certificates name one device, or two devices share a key.
    pub fn new(certificates: Vec<AuthorCertificate>) -> Result<Self, DuplicateDevice> {
        let mut authors = Self::default();
        for cert in certificates {
            let key_id = cert.verifying_key.key_id();
            if authors.by_key.insert(key_id, cert.device_id).is_some() {
                return Err(DuplicateDevice);
            }
            if authors.by_device.insert(cert.device_id, cert).is_some() {
                return Err(DuplicateDevice);
            }
        }
        Ok(authors)
    }

    /// The certificate of `device_id`.
    #[must_use]
    pub fn get(&self, device_id: DeviceId) -> Option<&AuthorCertificate> {
        self.by_device.get(&device_id)
    }

    /// The certificate whose Ed25519 key has the signer key id `key_id`.
    #[must_use]
    pub fn by_key_id(&self, key_id: &PublicKeyId) -> Option<&AuthorCertificate> {
        self.by_key.get(key_id).and_then(|d| self.by_device.get(d))
    }

    /// The cut-off of every revoked device (ADR 0012 §6), as
    /// [`VaultChains::cutoffs`](rizzy_sync::compaction::VaultChains) takes them.
    #[must_use]
    pub fn cutoffs(&self) -> BTreeMap<DeviceId, u64> {
        self.by_device
            .values()
            .filter_map(|c| match c.status {
                AuthorStatus::Revoked {
                    last_accepted_device_seq,
                } => Some((c.device_id, last_accepted_device_seq)),
                AuthorStatus::Active | AuthorStatus::Suspended => None,
            })
            .collect()
    }
}

/// The `auth` domain could not answer. Carries a fixed description only, never a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectoryError {
    /// What failed.
    pub what: &'static str,
}

impl fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.what)
    }
}

impl std::error::Error for DirectoryError {}

/// The account key the account's held signed `account-state` names (CRYPTO.md §10.2), as the
/// `auth` domain verified it: what a re-published self-grant is checked against (ADR 0032 §3,
/// healing step 3b). Public values only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountKeyState {
    /// The state's `account_key_epoch`.
    pub account_key_epoch: u32,
    /// The state's `account_key_id`.
    pub account_key_id: [u8; 16],
}

/// The source of device certificates (ADR 0016 R4: a domain that needs something from another
/// defines a trait for it, and `rizzy-server` implements it). See the module docs for the
/// implementer's contract.
pub trait DeviceDirectory: Send + Sync {
    /// Every certificate of `account_id`, with revocation state, read on `conn`: the
    /// connection of the caller's write transaction, which holds the account lock.
    ///
    /// # Errors
    /// [`DirectoryError`] when the certificates cannot be read; the caller fails the request.
    fn authors<'a>(
        &'a self,
        conn: Conn<'a>,
        account_id: AccountId,
    ) -> impl Future<Output = Result<Authors, DirectoryError>> + Send + 'a;

    /// The account key of `account_id`'s held signed `account-state`, verified from the stored
    /// bundle chain, read on `conn` (the caller's write transaction, which holds the account
    /// lock); `None` for an account without a verified state. Healing step 3b checks a
    /// re-published self-grant against it (ADR 0032 §3).
    ///
    /// # Errors
    /// [`DirectoryError`] when the state cannot be read; the caller fails the request.
    fn account_key<'a>(
        &'a self,
        conn: Conn<'a>,
        account_id: AccountId,
    ) -> impl Future<Output = Result<Option<AccountKeyState>, DirectoryError>> + Send + 'a;
}
