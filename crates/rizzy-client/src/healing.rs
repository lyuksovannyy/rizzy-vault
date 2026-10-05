//! Account-side restore healing: the client's half of ADR 0012 §7 "Healing a server rollback"
//! as [ADR 0032] §1–§4 replace its steps 2 and 3 and its "What is not re-uploaded", and of "A
//! device enrolled after the backup" (threat model §5.8, INV-59), as ADR 0021 §9 "Server
//! behind" leaves them binding. The vault side (step 4, and step 3b's request) is
//! [`crate::sync`]'s `heal` module.
//!
//! # When
//!
//! A device finds the server behind when "the server's `state_seq` is lower" (ADR 0021 §9):
//! [`crate::unlock::verify_unlock`] answers [`ClientError::Rollback`]. After a restore to before
//! a full rotation the served state is signed by an older identity key and does not verify under
//! the pin; the host then asks for the chain it holds ([`older_chain_query`]) and
//! [`is_older_chain_rollback`] decides (ADR 0032 §1): a served chain whose head is below the
//! pinned `bundle_seq`, every served bundle byte-identical to the one this device holds at that
//! `bundle_seq`, and a served state that verifies under the served head with a `state_seq` below
//! the pin, is a rollback too. Nothing signed by that older key is accepted; the device only
//! goes read-only and heals. Any other mismatch stays [`ClientError::InvalidServerResponse`].
//!
//! The device goes read-only (the host writes the rollback alarm, ADR 0026 §4 step 4) and,
//! still read-only, re-publishes in this order ([`account_healing`]):
//!
//! 1. the bundle chain ([`AccountHealing::bundles`], `healing/bundles`);
//! 2. its newest signed `account-state` with every certificate and revocation it holds and, as
//!    last served and cached, `E_id` of the state's `identity_epoch` and, when
//!    `settings_seq > 0`, `ACCOUNT_SETTINGS` ([`AccountHealing::account_state`],
//!    `healing/account-state`);
//! 3. (3a) the device grants it holds ([`AccountHealing::grants`], `healing/grants`), then (3b)
//!    per vault the self-grant it holds and its wrap set at that grant's `vault_key_epoch`, in
//!    one `vault/heal` request without records
//!    ([`crate::sync::VaultSync::self_grant_healing_request`] over
//!    [`AccountHealing::self_grants`]).
//!
//! Then it asks for the account answer again and verifies it as at any unlock. "The device
//! leaves read-only once none [of the conditions] holds" (ADR 0021 §9): an answer whose state
//! verifies and is not lower than the pin resolves the rollback alarm, and step 4 (the vault
//! records) follows. A server that refuses the re-publication (outside the reconciliation
//! epoch the server takes no out-of-band state, INV-59), or still serves the older state
//! afterwards, leaves the alarm in place: a genuine rollback stays an alarm.
//!
//! **Steps 5 and 6 need the user** (ADR 0032 §4). Step 5: the device authentication answers
//! `reregister` while the server's OPAQUE record lags its signed state, and a device holding the
//! typed password runs the same-password re-registration of [`crate::reregister`]. Step 6: the
//! recovery repair, by user action ([`recovery_repair`]). A device that missed the rotation and
//! finds no grant catches up by password ([`crate::unlock::catch_up_account_key`]).
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
//! accepted (the cache keeps them, ADR 0026 §1), the certificates and revocations of its pinned
//! state, `E_id` as last served, and the vault self-grants of that state. Each request is built
//! only from objects that agree with the pin: the pinned bundle must be held, the held
//! certificates and revocations must reproduce the pinned `device_set_hash`, and `E_id` must name
//! the pinned `identity_epoch`; anything else is [`ClientError::CannotHeal`] and nothing is sent.
//! `ACCOUNT_SETTINGS` come from the pin, which keeps the ciphertext the state commits to. The
//! server verifies all of it again under the identity key it holds and checks every repair
//! against the signed state it holds (ADR 0032 §3).
//!
//! # Readings (reported)
//!
//! - **Device grants.** Step 3a names the key grants a device holds. This build persists no
//!   `ACCOUNT_KEY_DEVICE_GRANT` (ADR 0026 §1 lists none), and re-creating one needs the account
//!   key of the epoch before the grant's (the device-grant PSK, CRYPTO.md §10.1), which a
//!   rotating device drops once it finalises. So the list is always empty here; ADR 0032 §4's
//!   catch-up by password covers the device that missed the rotation.
//! - **Self-grants travel in step 3b only.** `healing/grants` keeps accepting self-grants
//!   under its older rule (never above an epoch the server verified), which refuses a grant
//!   whose rotation reached the server with no signed record before the restore; this build
//!   sends them in step 3b instead, where the lag rule can raise the vault's epoch.
//! - **The chain asked for after an older identity key** ([`older_chain_query`]): the bundles
//!   above the lowest one this device holds, so every served bundle can be compared byte for
//!   byte with a held one. A restored chain that ends below the lowest held bundle cannot be
//!   compared and stays [`ClientError::InvalidServerResponse`] (the conservative side).
//! - **The two forms of the recovery repair** are chosen by the server's stored row, which the
//!   client cannot see: the host offers the new code by default, and re-typing the current one
//!   only on the user's request; the server refuses a re-typed code unless the stored row's
//!   `recovery_epoch` is the state's and the code is the stored one ([`RecoveryRepairForm`]).
//!
//! [ADR 0032]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0032-healing-rotation-after-backup.md

use std::collections::BTreeMap;

use rizzy_core::envelope::purpose::AccountKeyRecoveryWrapCtx;
use rizzy_core::keys::device_set_hash;
use rizzy_core::rng::CryptoRng;
use rizzy_core::secret_key::RecoveryCode;
use rizzy_core::sign::{AccountState, PublicKeyBundle};
use rizzy_proto::account::{
    AccountStateQuery, AccountView, PublishAccountStateRequest, PublishBundlesRequest,
    PublishGrantsRequest,
};
use rizzy_proto::auth::{Reconciliation, RecoveryRegistration};
use rizzy_proto::change::CommitChangeRequest;
use rizzy_proto::objects::{
    AccountKeyRecoveryWrap, AccountStatement, IdentitySecretKeys, VaultSelfGrant,
};
use rizzy_proto::wire::{Bytes, Fixed, List};
use zeroize::Zeroizing;

use crate::account::{CertifiedDevice, RevokedDevice, VerifiedAccount};
use crate::device::{DeviceState, UnlockedDevice};
use crate::error::{ClientError, internal};
use crate::login::LoggedIn;
use crate::rotation::check_reauth;
use crate::wire::bytes;

/// The account objects this device holds, as verified (module docs, "What is re-published").
///
/// Public values only: signed statements, the self-grant envelopes and `E_id`, as served.
/// `Debug` shows counts.
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
    /// `E_id` of the last verified answer, as served (ADR 0032 §2: "verbatim as last served and
    /// cached").
    identity_secret_keys: Option<IdentitySecretKeys>,
}

impl core::fmt::Debug for HeldAccount {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HeldAccount")
            .field("bundles", &self.bundles.len())
            .field("certificates", &self.certificates.len())
            .field("revocations", &self.revocations.len())
            .field("self_grants", &self.self_grants.len())
            .field("identity_secret_keys", &self.identity_secret_keys.is_some())
            .finish()
    }
}

impl HeldAccount {
    /// What a verified account answer holds: for a cache load
    /// ([`crate::store::load::Loaded::account`]) every bundle, the device set, `E_id` and every
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
    /// (an unlock's answer carries only those above the pinned one), and its device set,
    /// `E_id` and self-grants replace the held ones.
    pub fn absorb(&mut self, account: &VerifiedAccount) {
        for (seq, wire) in &account.served.bundles {
            self.bundles.insert(*seq, wire.clone());
        }
        self.certificates.clone_from(&account.certificates);
        self.revocations.clone_from(&account.revocations);
        if let Some(keys) = &account.served.identity_secret_keys {
            self.identity_secret_keys = Some(keys.clone());
        }
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

/// The account re-publications of ADR 0032 §2 steps 1–3, in the order they are sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountHealing {
    /// Step 1, to `healing/bundles`.
    pub bundles: PublishBundlesRequest,
    /// Step 2, to `healing/account-state`.
    pub account_state: PublishAccountStateRequest,
    /// Step 3a, to `healing/grants`: the device grants this device holds (none in this build,
    /// module docs) and no self-grant.
    pub grants: PublishGrantsRequest,
    /// Step 3b: the self-grant of each vault, under the pinned state's account key, from which
    /// [`crate::sync::VaultSync::self_grant_healing_request`] builds that vault's request.
    pub self_grants: Vec<VaultSelfGrant>,
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
/// bundle is not held, the held device set does not reproduce the pinned `device_set_hash`, or
/// the held `E_id` names another `identity_epoch`) or exceed the wire limits.
pub fn account_healing(
    state: &DeviceState,
    held: &HeldAccount,
) -> Result<AccountHealing, ClientError> {
    let Parts {
        bundles,
        revocations,
        ..
    } = parts(state, held)?;
    let pin = &state.pin.state;
    // ADR 0032 §2: every certificate held, revoked devices' and kind-4 ones included.
    let certificates = held
        .certificates
        .iter()
        .map(|c| statement(&c.wire))
        .collect::<Result<Vec<_>, _>>()?;
    let identity_secret_keys = match &held.identity_secret_keys {
        Some(keys) if keys.identity_epoch == pin.identity_epoch => Some(keys.clone()),
        Some(_) => return Err(ClientError::CannotHeal),
        None => None,
    };
    let account_settings = state
        .pin
        .settings
        .clone()
        .filter(|s| pin.settings_seq > 0 && s.settings_seq == pin.settings_seq);
    // Only the self-grants under the pinned state's account key: older ones are not what this
    // device holds now.
    let self_grants: Vec<VaultSelfGrant> = held
        .self_grants
        .values()
        .filter(|g| g.account_key_epoch == pin.account_key_epoch)
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
            identity_secret_keys,
            account_settings,
        },
        grants: PublishGrantsRequest {
            vault_self_grants: List::empty(),
            device_grants: List::empty(),
        },
        self_grants,
    })
}

/// The account query that shows a restored server's older chain (ADR 0032 §1; module docs,
/// "Readings"): every bundle above the lowest one this device holds, and the settings.
#[must_use]
pub fn older_chain_query(held: &HeldAccount) -> AccountStateQuery {
    let lowest = held.bundles.keys().next().copied().unwrap_or(1);
    AccountStateQuery {
        known_bundle_seq: lowest.saturating_sub(1),
        known_settings_seq: 0,
    }
}

/// Whether `view`, an answer to [`older_chain_query`], shows a restored server's older chain
/// (ADR 0032 §1): at least one bundle served, every served bundle below the pinned `bundle_seq`
/// and byte-identical to the one this device holds at that `bundle_seq`, and the served state
/// verifying under the served head (the highest served bundle) with a `state_seq` below the
/// pinned one. Then the answer is a rollback: the host goes read-only and heals. Nothing of
/// `view` is adopted, and nothing signed by the older key is accepted.
#[must_use]
pub fn is_older_chain_rollback(
    state: &DeviceState,
    held: &HeldAccount,
    view: &AccountView,
) -> bool {
    let pin = &state.pin;
    let mut top = None;
    for wire in view.bundles.as_slice() {
        let Ok(bundle) = PublicKeyBundle::verify_self_signed(wire.as_slice()) else {
            return false;
        };
        let identical = held
            .bundles
            .get(&bundle.bundle_seq)
            .is_some_and(|held| held.as_slice() == wire.as_slice());
        if bundle.bundle_seq >= pin.bundle.bundle_seq
            || !identical
            || bundle.account_id != state.account_id
        {
            return false;
        }
        if top
            .as_ref()
            .is_none_or(|h: &rizzy_core::sign::VerifiedBundle| bundle.bundle_seq > h.bundle_seq)
        {
            top = Some(bundle);
        }
    }
    let Some(newest) = top else {
        return false;
    };
    AccountState::verify(
        view.account_state.as_slice(),
        &newest.identity_ed25519,
        newest.identity_epoch,
    )
    .is_ok_and(|served| {
        served.account_id == state.account_id
            && served.matches_bundle(&newest)
            && served.state_seq < pin.state.state_seq
    })
}

/// The two forms of the recovery repair (ADR 0032 §4 step 6).
pub enum RecoveryRepairForm {
    /// A new code and a new kit (`recovery_epoch + 1`): always allowed while recovery is on, and
    /// the only form the server takes when the restored `H_rec` is an older code's.
    NewCode,
    /// Re-type the current code: `H_rec` and `E_rec` again at the same `recovery_epoch`, under
    /// the current account key. The server takes it only while its stored row lags, its stored
    /// `recovery_epoch` is the state's, and the code is the stored one.
    Retype(RecoveryCode),
}

impl core::fmt::Debug for RecoveryRepairForm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::NewCode => "NewCode",
            Self::Retype(_) => "Retype([REDACTED])",
        })
    }
}

/// A recovery repair with its commit built (ADR 0032 §4 step 6; [`recovery_repair`]). Holds the
/// new recovery code of [`RecoveryRepairForm::NewCode`] until the host has shown it and the user
/// confirmed it ([`RecoveryRepair::confirm_new_code`]); `Debug` is redacted.
pub struct RecoveryRepair {
    /// The commit, for `account/commit` over the fresh OPAQUE session of the login it was built
    /// from.
    request: CommitChangeRequest,
    /// The new code, for [`RecoveryRepairForm::NewCode`].
    new_code: Option<RecoveryCode>,
    /// Whether the user confirmed the new code (always true for a re-typed one).
    confirmed: bool,
}

impl core::fmt::Debug for RecoveryRepair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoveryRepair([REDACTED])")
    }
}

impl RecoveryRepair {
    /// The new recovery code as printed (`RVR1-…`), for [`RecoveryRepairForm::NewCode`]. A
    /// secret: show it once, as part of the new Emergency Kit; never log it.
    #[must_use]
    pub fn new_code(&self) -> Option<Zeroizing<String>> {
        self.new_code.as_ref().map(RecoveryCode::to_formatted)
    }

    /// The user re-typed the last group of the new code (CRYPTO.md §11 "Secrets before commit"
    /// step 2): returns whether it matched, and unlocks [`RecoveryRepair::commit_request`].
    pub fn confirm_new_code(&mut self, typed: &str) -> bool {
        if let Some(code) = &self.new_code {
            self.confirmed = code.matches_last_group(typed);
        }
        self.confirmed
    }

    /// The commit, once the new code is confirmed.
    ///
    /// # Errors
    /// [`ClientError::EmergencyKitNotConfirmed`] before the new code was confirmed.
    pub fn commit_request(&self) -> Result<&CommitChangeRequest, ClientError> {
        if self.confirmed {
            Ok(&self.request)
        } else {
            Err(ClientError::EmergencyKitNotConfirmed)
        }
    }
}

/// The recovery repair of ADR 0032 §4 step 6, by user action: `H_rec` and `E_rec` together, as a
/// credential replacement (CRYPTO.md §11 "Replacing credentials") over the fresh OPAQUE session of
/// `login` (a re-authentication of this device, so after step 5), with a state at
/// `state_seq + 1` signed by the account's identity key. `E_rec` wraps the current account key
/// (the login's, which its signed state names) under the code; the new code of
/// [`RecoveryRepairForm::NewCode`] is drawn from `rng` and moves `recovery_epoch` up by one.
///
/// # Errors
/// [`ClientError::InvalidInput`] when recovery is off (nothing to repair) or the login is not
/// this device's account; the checks of a re-authentication ([`ClientError::Rollback`],
/// [`ClientError::Fork`], [`ClientError::IdentityChangeUnconfirmed`],
/// [`ClientError::AccountKeyRotated`], [`ClientError::InvalidServerResponse`]);
/// [`ClientError::Internal`].
pub fn recovery_repair<R: CryptoRng + ?Sized>(
    rng: &mut R,
    login: &LoggedIn,
    device: &DeviceState,
    unlocked: &UnlockedDevice,
    form: RecoveryRepairForm,
) -> Result<RecoveryRepair, ClientError> {
    check_reauth(login, device, unlocked)?;
    let base = &login.account.pin.state;
    if !base.recovery_enabled {
        return Err(ClientError::InvalidInput);
    }
    let (code, recovery_epoch, new_code) = match form {
        RecoveryRepairForm::NewCode => {
            let code = RecoveryCode::generate(rng);
            let epoch = base
                .recovery_epoch
                .checked_add(1)
                .ok_or(ClientError::Internal)?;
            (code, epoch, true)
        }
        RecoveryRepairForm::Retype(code) => (code, base.recovery_epoch, false),
    };
    let account_key_epoch = base.account_key_epoch;
    let envelope = code
        .wrap_key()
        .map_err(internal)?
        .wrap_account_key(
            rng,
            &AccountKeyRecoveryWrapCtx {
                account_id: base.account_id,
                account_key_epoch,
                recovery_epoch,
            },
            &login.account_key,
        )
        .map_err(internal)?;
    let recovery = RecoveryRegistration {
        recovery_wrap: AccountKeyRecoveryWrap {
            account_key_epoch,
            recovery_epoch,
            envelope: bytes(envelope)?,
        },
        recovery_token_hash: Fixed::from_bytes(code.auth_token().map_err(internal)?.server_hash()),
    };
    let mut next = base.clone();
    next.state_seq = base.state_seq.checked_add(1).ok_or(ClientError::Internal)?;
    next.recovery_epoch = recovery_epoch;
    let state_wire = next
        .sign(login.account.identity.signing_key())
        .map_err(internal)?;
    let request = CommitChangeRequest {
        account_state: bytes(state_wire)?,
        registration_upload: None,
        setup_id: None,
        account_key_server_wrap: None,
        recovery: Some(recovery),
        account_settings: None,
        device_certificates: List::empty(),
        device_revocations: List::empty(),
        bundle: None,
        identity_secret_keys: None,
        retired_secret_keys: List::empty(),
        device_grants: List::empty(),
        recovery_rewrap: None,
        vault_rotation: None,
    };
    Ok(RecoveryRepair {
        request,
        new_code: new_code.then_some(code),
        confirmed: !new_code,
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
