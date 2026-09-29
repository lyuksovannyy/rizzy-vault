//! The auth domain's side of the vault domain's certificate source (ADR 0012 §7 "Upload":
//! "Certificates come from the `auth` domain through a trait"; ADR 0016 R4).
//!
//! `rizzy-domain-vault` defines the trait (`DeviceDirectory`) and `rizzy-server` implements it
//! with [`device_authors`], so neither domain depends on the other. The function reads only
//! `auth_` tables, on the connection it is handed: the vault domain's write transaction, which
//! already holds the account lock (ADR 0012 §6), so a revocation or suspension cannot commit
//! between the check and the vault insert.
//!
//! **What it returns** (the implementer's contract of `DeviceDirectory::authors`): every stored
//! device certificate of the account, kinds 1–4, that verifies under the identity key at the
//! head of the account's verified bundle chain and names the account (CRYPTO.md §10.2 rules (a)
//! and (b); INV-30), with its standing in revocation. A certificate that does not verify is left
//! out, so every record it signed is refused. An account without a verified chain and state (an
//! unknown account, or a signup that never finished) has no authors.
//!
//! **A stored revocation that does not verify** under the head (possible between a restore
//! and the re-issue of the revocations, ADR 0012 §7) has no cut-off the server can trust. Such a
//! device is reported [`DeviceStanding::Suspended`]: every record it authored is refused, and no
//! unverified `last_accepted_device_seq` enters the compaction cut-offs (fail closed, as
//! `trust` does for authentication).

use rizzy_core::ids::{AccountId, DeviceId};
use rizzy_core::sign::DeviceVerifyingKey;
use rizzy_core::sign::statements::DeviceKind;
use rizzy_storage::Conn;

use crate::error::AuthError;
use crate::trust::{AccountTrust, reborrow};

/// Where a device stands in revocation (ADR 0012 §6; CRYPTO.md §11.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceStanding {
    /// Neither suspended nor revoked.
    Active,
    /// Suspended by revocation phase 1 (CRYPTO.md §11.8 step 0), or revoked by a stored
    /// revocation that does not verify under the head (module docs).
    Suspended,
    /// Revoked by a verified `device-revocation`, with its signed cut-off.
    Revoked {
        /// The revocation's `last_accepted_device_seq`.
        last_accepted_device_seq: u64,
    },
}

/// One verified device certificate of an account, with the device's standing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceAuthor {
    /// The device.
    pub device_id: DeviceId,
    /// Its Ed25519 key, from the verified certificate.
    pub verifying_key: DeviceVerifyingKey,
    /// Its kind (1–4).
    pub device_kind: DeviceKind,
    /// The certificate's `expires_at_ms`, 0 for none.
    pub expires_at_ms: u64,
    /// Its standing in revocation.
    pub standing: DeviceStanding,
}

/// Every verified device certificate of `account_id`, with its standing, read on `conn` (module
/// docs). The caller's transaction holds the account lock.
///
/// # Errors
/// [`AuthError::Internal`] when the stored chain or state no longer verifies (a damaged or
/// tampered database); storage errors.
pub async fn device_authors(
    mut conn: Conn<'_>,
    account_id: AccountId,
) -> Result<Vec<DeviceAuthor>, AuthError> {
    let trust = match AccountTrust::load(reborrow(&mut conn), account_id).await {
        Ok(trust) => trust,
        Err(AuthError::NotFound) => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let devices = trust.devices(conn).await?;
    Ok(devices
        .certs
        .iter()
        .map(|stored| {
            let cert = &stored.cert;
            let standing = if let Some(rev) = devices.revocation(cert.device_id) {
                DeviceStanding::Revoked {
                    last_accepted_device_seq: rev.revocation.last_accepted_device_seq,
                }
            } else if stored.suspended || devices.is_revoked(cert.device_id) {
                DeviceStanding::Suspended
            } else {
                DeviceStanding::Active
            };
            DeviceAuthor {
                device_id: cert.device_id,
                verifying_key: cert.device_ed25519,
                device_kind: cert.device_kind,
                expires_at_ms: cert.expires_at_ms,
                standing,
            }
        })
        .collect())
}
