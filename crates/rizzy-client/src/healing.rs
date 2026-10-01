//! Account-side restore healing: the client's half of ADR 0012 §7 "Healing a server rollback"
//! steps 1–3 and "A device enrolled after the backup" (threat model §5.8, INV-59), as ADR 0021
//! §9 "Server behind" leaves them binding. The vault side (step 4) is [`crate::sync`]'s `heal`
//! module.
//!
//! # When
//!
//! A device finds the server behind when "the server's `state_seq` is lower" (ADR 0021 §9):
//! [`crate::unlock::verify_unlock`] answers [`ClientError::Rollback`]. The device goes
//! read-only (the host writes the rollback alarm, ADR 0026 §4 step 4) and, still read-only,
//! re-publishes in this order:
//!
//! 1. the bundle chain ([`AccountHealing::bundles`], `healing/bundles`);
//! 2. its newest signed `account-state` with the certificates of that state's device set and
//!    every revocation it holds ([`AccountHealing::account_state`], `healing/account-state`);
//! 3. the vault self-grants it holds ([`AccountHealing::grants`], `healing/grants`).
//!
//! Then it asks for the account answer again and verifies it as at any unlock. "The device
//! leaves read-only once none [of the conditions] holds" (ADR 0021 §9): an answer whose state
//! verifies and is not lower than the pin resolves the rollback alarm. A server that refuses
//! the re-publication (outside the reconciliation epoch the server takes no out-of-band state,
//! INV-59), or still serves the older state afterwards, leaves the alarm in place: a genuine
//! rollback stays an alarm.
//!
//! **A device enrolled after the backup** is unknown to the restored database, so its plain
//! device authentication is refused. It then authenticates with [`reconciliation`]'s objects:
//! "its certificate, the `account-state` that lists it and the bundle chain", plus the
//! certificates of that state's device set and the revocations it holds, which the server needs
//! to see that the state lists the certificate (`rizzy-proto` `Reconciliation`). The server
//! accepts them only during the reconciliation epoch; the device then heals as above.
//!
//! # What is re-published, and from where
//!
//! [`HeldAccount`] is what this device holds of the account, as verified: every bundle it
//! accepted (the cache keeps them, ADR 0026 §1), the device set of its pinned state, and the
//! vault self-grants of that state. Each request is built only from objects that agree with the
//! pin: the pinned bundle must be held, and the held certificates and revocations must reproduce
//! the pinned `device_set_hash`; anything else is [`ClientError::CannotHeal`] and nothing is
//! sent. The server verifies all of it again under the identity key it holds.
//!
//! # Readings (reported)
//!
//! - **Certificates.** "The device certificates of that state's device set": the held
//!   certificates of durable devices that no held revocation names. Revoked devices' and kind-4
//!   certificates are not sent.
//! - **Device grants.** Step 3 also names "key grants … that it holds, or can re-create with
//!   the keys it has". This build persists no `ACCOUNT_KEY_DEVICE_GRANT` (ADR 0026 §1 lists
//!   none), and re-creating one needs the account key of the epoch before the grant's (the
//!   device-grant PSK, CRYPTO.md §10.1), which a rotating device drops once it finalises. So
//!   the list is always empty here.
//! - **What steps 1–3 do not carry.** `E_id`, `E_srv`, the OPAQUE record and `E_rec` are not
//!   re-published (ADR 0012 §7 "What is not re-uploaded" names the OPAQUE record and `E_srv`;
//!   no Accepted text names `E_id`). After a restore to before a key rotation, the server's
//!   `E_id` is still wrapped under the older account key, and the account answer does not
//!   verify after healing ([`ClientError::InvalidServerResponse`]); the server also refuses a
//!   self-grant whose `vault_key_epoch` no stored signed record reached yet
//!   (`rizzy-domain-vault` `keys`), and step 4 comes after step 3. So a rotation made after the
//!   backup is not healed by this build: an open question for the owner, not decided here.
//! - **When no healing is tried.** Only a [`ClientError::Rollback`] starts it. A served state
//!   that does not verify under the pinned bundle (a restore to before a full rotation, whose
//!   state the older identity key signed) is [`ClientError::InvalidServerResponse`] as before.

use std::collections::BTreeMap;

use rizzy_core::keys::device_set_hash;
use rizzy_core::sign::PublicKeyBundle;
use rizzy_proto::account::{
    PublishAccountStateRequest, PublishBundlesRequest, PublishGrantsRequest,
};
use rizzy_proto::auth::Reconciliation;
use rizzy_proto::objects::{AccountStatement, VaultSelfGrant};
use rizzy_proto::wire::{Bytes, List};

use crate::account::{CertifiedDevice, RevokedDevice, VerifiedAccount};
use crate::device::DeviceState;
use crate::error::ClientError;

/// The account objects this device holds, as verified (module docs, "What is re-published").
///
/// Public values only: signed statements and the self-grant envelopes, as served. `Debug` shows
/// counts.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct HeldAccount {
    /// Every bundle this device accepted, by `bundle_seq`, in wire form.
    bundles: BTreeMap<u64, Vec<u8>>,
    /// The certificates of the last verified answer.
    certificates: Vec<CertifiedDevice>,
    /// The revocations of the last verified answer.
    revocations: Vec<RevokedDevice>,
    /// The vault self-grants of the last verified answer, by vault id.
    self_grants: BTreeMap<[u8; 16], VaultSelfGrant>,
}

impl core::fmt::Debug for HeldAccount {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HeldAccount")
            .field("bundles", &self.bundles.len())
            .field("certificates", &self.certificates.len())
            .field("revocations", &self.revocations.len())
            .field("self_grants", &self.self_grants.len())
            .finish()
    }
}

impl HeldAccount {
    /// What a verified account answer holds: for a cache load
    /// ([`crate::store::load::Loaded::account`]) every bundle, the device set and every
    /// self-grant of the file.
    #[must_use]
    pub fn from_account(account: &VerifiedAccount) -> Self {
        let mut held = Self::default();
        held.absorb(account);
        held
    }

    /// The device set of a new enrolment, before any answer with bundles and self-grants was
    /// absorbed. A device built this way cannot heal until it absorbs one (the next load).
    #[must_use]
    pub fn from_devices(
        certificates: Vec<CertifiedDevice>,
        revocations: Vec<RevokedDevice>,
    ) -> Self {
        Self {
            certificates,
            revocations,
            ..Self::default()
        }
    }

    /// Takes in a newer verified answer that the host adopted: its bundles join the held ones
    /// (an unlock's answer carries only those above the pinned one), and its device set and
    /// self-grants replace the held ones.
    pub fn absorb(&mut self, account: &VerifiedAccount) {
        for (seq, wire) in &account.served.bundles {
            self.bundles.insert(*seq, wire.clone());
        }
        self.certificates.clone_from(&account.certificates);
        self.revocations.clone_from(&account.revocations);
        if !account.served.self_grants.is_empty() {
            self.self_grants = account
                .served
                .self_grants
                .iter()
                .map(|(grant, _)| (grant.vault_id.to_bytes(), grant.clone()))
                .collect();
        }
    }
}

/// The three re-publications of ADR 0012 §7 steps 1–3, in the order they are sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountHealing {
    /// Step 1, to `healing/bundles`.
    pub bundles: PublishBundlesRequest,
    /// Step 2, to `healing/account-state`.
    pub account_state: PublishAccountStateRequest,
    /// Step 3, to `healing/grants`.
    pub grants: PublishGrantsRequest,
}

/// The parts every request shares: the held bundle chain up to the pinned bundle, oldest
/// first, and the pinned state's device set.
struct Parts {
    /// The bundles.
    bundles: Vec<AccountStatement>,
    /// The certificates of the set's members.
    certificates: Vec<AccountStatement>,
    /// Every held revocation.
    revocations: Vec<AccountStatement>,
}

/// A bounded wire statement from held bytes; a held statement beyond the bound cannot be sent.
fn statement(wire: &[u8]) -> Result<AccountStatement, ClientError> {
    Bytes::from_slice(wire).map_err(|_| ClientError::CannotHeal)
}

/// Builds [`Parts`] and checks them against the pin (module docs).
fn parts(state: &DeviceState, held: &HeldAccount) -> Result<Parts, ClientError> {
    let pin = &state.pin;
    let pinned_seq = pin.bundle.bundle_seq;
    let pinned = held
        .bundles
        .get(&pinned_seq)
        .and_then(|wire| PublicKeyBundle::verify_self_signed(wire).ok())
        .ok_or(ClientError::CannotHeal)?;
    if pinned.hash() != pin.bundle.hash() {
        return Err(ClientError::CannotHeal);
    }
    let bundles = held
        .bundles
        .range(..=pinned_seq)
        .map(|(_, wire)| statement(wire))
        .collect::<Result<Vec<_>, _>>()?;
    let set = device_set_hash(
        state.account_id,
        held.certificates.iter().map(|c| &c.certificate),
        held.revocations.iter().map(|r| &r.revocation),
    )
    .map_err(|_| ClientError::CannotHeal)?;
    if set != pin.state.device_set_hash {
        return Err(ClientError::CannotHeal);
    }
    let revoked = |c: &CertifiedDevice| {
        held.revocations
            .iter()
            .any(|r| r.revocation.device_id == c.certificate.device_id)
    };
    let certificates = held
        .certificates
        .iter()
        .filter(|c| c.certificate.in_device_set() && !revoked(c))
        .map(|c| statement(&c.wire))
        .collect::<Result<Vec<_>, _>>()?;
    let revocations = held
        .revocations
        .iter()
        .map(|r| statement(&r.wire))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Parts {
        bundles,
        certificates,
        revocations,
    })
}

/// A bounded wire list; a held set beyond the bound cannot be sent in one request.
fn list<T, const N: usize>(items: Vec<T>) -> Result<List<T, N>, ClientError> {
    List::new(items).map_err(|_| ClientError::CannotHeal)
}

/// The re-publications of healing steps 1–3 from what this device holds (module docs).
///
/// # Errors
/// [`ClientError::CannotHeal`] when the held objects do not agree with the pin (the pinned
/// bundle is not held, or the held device set does not reproduce the pinned `device_set_hash`)
/// or exceed the wire limits.
pub fn account_healing(
    state: &DeviceState,
    held: &HeldAccount,
) -> Result<AccountHealing, ClientError> {
    let Parts {
        bundles,
        certificates,
        revocations,
    } = parts(state, held)?;
    // Only the self-grants under the pinned state's account key: older ones the server would
    // keep anyway, and they are not what this device holds now.
    let epoch = state.pin.state.account_key_epoch;
    let self_grants: Vec<VaultSelfGrant> = held
        .self_grants
        .values()
        .filter(|g| g.account_key_epoch == epoch)
        .cloned()
        .collect();
    Ok(AccountHealing {
        bundles: PublishBundlesRequest {
            bundles: list(bundles)?,
        },
        account_state: PublishAccountStateRequest {
            account_state: statement(&state.pin.state_wire)?,
            device_certificates: list(certificates)?,
            device_revocations: list(revocations)?,
        },
        grants: PublishGrantsRequest {
            vault_self_grants: list(self_grants)?,
            device_grants: List::empty(),
        },
    })
}

/// The objects of a certificate-carrying device authentication (module docs, "A device
/// enrolled after the backup"): this device's certificate, the pinned state, the bundle chain,
/// the state's device set and every held revocation.
///
/// # Errors
/// [`ClientError::CannotHeal`] as [`account_healing`], or when the held set has no certificate
/// of this device under its own id (it is not a member of the pinned state).
pub fn reconciliation(
    state: &DeviceState,
    held: &HeldAccount,
) -> Result<Reconciliation, ClientError> {
    let Parts {
        bundles,
        certificates,
        revocations,
    } = parts(state, held)?;
    let own = held
        .certificates
        .iter()
        .find(|c| c.certificate.device_id == state.device_id && c.certificate.in_device_set())
        .ok_or(ClientError::CannotHeal)?;
    if held
        .revocations
        .iter()
        .any(|r| r.revocation.device_id == state.device_id)
    {
        return Err(ClientError::CannotHeal);
    }
    Ok(Reconciliation {
        device_certificate: statement(&own.wire)?,
        account_state: statement(&state.pin.state_wire)?,
        bundles: list(bundles)?,
        device_certificates: list(certificates)?,
        device_revocations: list(revocations)?,
    })
}

#[cfg(test)]
impl HeldAccount {
    /// Replaces the held device set, to build held objects that disagree with the pin.
    pub(crate) fn absorb_devices_for_tests(
        &mut self,
        certificates: Vec<CertifiedDevice>,
        revocations: Vec<RevokedDevice>,
    ) {
        self.certificates = certificates;
        self.revocations = revocations;
    }
}
