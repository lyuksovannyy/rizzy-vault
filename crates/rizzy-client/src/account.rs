//! Verifying what the server says about the account (CRYPTO.md §11.2 step 6, §11.3 steps
//! 2.3–3; threat model §5.4–§5.6, INV-25, INV-30).
//!
//! The server is not trusted. Everything it serves about the account is checked against the
//! signed `account-state`, and the `account-state` against an identity key this device either
//! opened from `E_id` under an account key it already authenticated (a new device, §11.2), or
//! pinned before (an enrolled device, §11.3). Nothing of an answer is adopted until the whole
//! answer verified: `verify_account_view` returns a [`VerifiedAccount`] or an error, never a
//! partial result.
//!
//! # What is checked (§11.2 step 6)
//!
//! 1. `E_id` opens under the account key, and the identity public keys inside equal the
//!    bundle's.
//! 2. The bundle: for a new device, a self-signed bundle with exactly those keys; for an
//!    enrolled device, the chain from the pinned bundle ([`VerifiedBundle::verify_chain`]),
//!    and a change of identity keys only after the user confirmed the new fingerprint on this
//!    device (§11.3 step 3.2).
//! 3. The `account-state` signature under that identity key and epoch, `account_id`,
//!    `bundle_hash`, `account_key_id` and epoch.
//! 4. For an enrolled device, before anything else is used: rollback and fork against the
//!    persisted state (§11.3 step 2.5); a higher `account_key_epoch` stops here with
//!    [`ClientError::AccountKeyRotated`] (§11.3 step 4).
//! 5. Every certificate and revocation under the identity key, and `device_set_hash` over
//!    them, so the server cannot hide or add a device.
//! 6. `settings_hash` over the served `ACCOUNT_SETTINGS`, or, for an enrolled device whose
//!    pinned `settings_seq` is the state's, over the pinned ones the server left out (§11.3
//!    step 2.2).
//! 7. Every vault self-grant opens under the account key with the state's `account_key_epoch`.
//!
//! # Reading
//!
//! - **Which bundle a new device takes.** §11.2 says "the current bundle"; the response may
//!   list several. The new device takes the self-signed bundle whose keys equal the ones in
//!   `E_id` and whose hash the verified state commits to. Any other served bundle is ignored
//!   (conservative: the state's commitment decides, not the order of the list).
//! - **Duplicate self-grants** for one vault are refused, rather than one being picked.

use rizzy_core::envelope::purpose::{IdentitySecretKeysCtx, VaultKeySelfGrantCtx};
use rizzy_core::ids::{AccountId, VaultId};
use rizzy_core::keys::{AccountFingerprint, AccountKey, IdentityKeys, VaultKey, device_set_hash};
use rizzy_core::sign::{
    AccountState, DeviceCertificate, DeviceRevocation, IdentityVerifyingKey, PublicKeyBundle,
    Verified, VerifiedBundle,
};
use rizzy_proto::account::AccountView;
use rizzy_proto::objects::{AccountSettings, IdentitySecretKeys, VaultSelfGrant};

use crate::error::ClientError;

/// What an enrolled device pinned from the last account answer it accepted (CRYPTO.md §5.6
/// step 1: "the last verified signed account state"; §10.3: the pinned bundle).
///
/// Public values only: the pinned bundle, the persisted `account-state`, and the
/// `ACCOUNT_SETTINGS` ciphertext that state commits to.
///
/// The settings are kept because an enrolled device asks the server to leave them out while
/// their `settings_seq` is unchanged (§11.3 step 2.2, [`crate::unlock::account_state_query`]);
/// the unlock then checks `settings_hash` against the kept envelope (§11.3 step 2.4). `Debug`
/// shows the sequence numbers only, not the settings envelope.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountPin {
    /// The newest bundle this device accepted; its identity keys verify every statement.
    pub(crate) bundle: VerifiedBundle,
    /// The newest `account-state` this device accepted, and its signed wire form.
    pub(crate) state: AccountState,
    /// The state's wire form, as served and verified.
    pub(crate) state_wire: Vec<u8>,
    /// The `ACCOUNT_SETTINGS` the state's `settings_hash` matched (ciphertext); `None` while
    /// `settings_seq = 0`.
    pub(crate) settings: Option<AccountSettings>,
}

impl core::fmt::Debug for AccountPin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AccountPin")
            .field("account_id", &self.state.account_id)
            .field("bundle_seq", &self.bundle.bundle_seq)
            .field("state_seq", &self.state.state_seq)
            .field("settings_seq", &self.state.settings_seq)
            .field("holds_settings", &self.settings.is_some())
            .finish_non_exhaustive()
    }
}

impl AccountPin {
    /// The pinned `ACCOUNT_SETTINGS` (ciphertext), if `settings_seq > 0`.
    #[must_use]
    pub const fn settings(&self) -> Option<&AccountSettings> {
        self.settings.as_ref()
    }

    /// The pinned `account-state`.
    #[must_use]
    pub const fn state(&self) -> &AccountState {
        &self.state
    }

    /// The pinned bundle.
    #[must_use]
    pub const fn bundle(&self) -> &VerifiedBundle {
        &self.bundle
    }

    /// The pinned `account-state`'s signed wire form, as served and verified: the evidence a
    /// host stores with a rollback or fork alarm (ADR 0026 §3, kind 7).
    #[must_use]
    pub fn state_wire(&self) -> &[u8] {
        &self.state_wire
    }

    /// The pinned identity signing key's public half.
    #[must_use]
    pub fn identity_key(&self) -> IdentityVerifyingKey {
        self.bundle.identity_ed25519
    }
}

/// A device certificate that verified, with its wire form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedDevice {
    /// The verified certificate.
    pub certificate: Verified<DeviceCertificate>,
    /// Its signed wire form.
    pub wire: Vec<u8>,
}

/// A device revocation that verified, with its wire form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevokedDevice {
    /// The verified revocation.
    pub revocation: Verified<DeviceRevocation>,
    /// Its signed wire form.
    pub wire: Vec<u8>,
}

/// An account answer that verified in full (see the module docs).
///
/// It holds the identity secret keys and the vault keys, so it is not `Clone`, and `Debug`
/// shows the account id and the state's sequence numbers only.
pub struct VerifiedAccount {
    /// The account.
    pub(crate) account_id: AccountId,
    /// The verified state and its wire form, as the new pin.
    pub(crate) pin: AccountPin,
    /// The identity keys, from `E_id`.
    pub(crate) identity: IdentityKeys,
    /// Every served certificate, verified.
    pub(crate) certificates: Vec<CertifiedDevice>,
    /// Every served revocation, verified.
    pub(crate) revocations: Vec<RevokedDevice>,
    /// The vault keys from the self-grants, one per vault.
    pub(crate) vault_keys: Vec<VaultKey>,
    /// The `ACCOUNT_SETTINGS` the state commits to (ciphertext): served, or kept with the pin
    /// when the server left them out as unchanged.
    pub(crate) settings: Option<AccountSettings>,
    /// The identity keys changed through the bundle chain, and the user confirmed it.
    pub(crate) identity_changed: bool,
    /// The served objects this answer verified, as served, for the cache
    /// ([`crate::store::account_writes`], ADR 0026 §1 "Account objects").
    pub(crate) served: ServedObjects,
}

/// The objects of a verified account answer that the cache keeps as served (ADR 0026 §1):
/// ciphertext and signed statements only.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ServedObjects {
    /// The served bundles that verified as self-signed, each with its `bundle_seq`.
    pub(crate) bundles: Vec<(u64, Vec<u8>)>,
    /// `E_id` with its `identity_epoch`.
    pub(crate) identity_secret_keys: Option<IdentitySecretKeys>,
    /// The vault self-grants, each with the id of the vault key it opened to.
    pub(crate) self_grants: Vec<(VaultSelfGrant, [u8; 16])>,
}

impl ServedObjects {
    /// The objects of `view`, whose self-grants opened to `vault_keys` in the same order.
    fn of_view(view: &AccountView, vault_keys: &[VaultKey]) -> Result<Self, ClientError> {
        let bundles = view
            .bundles
            .as_slice()
            .iter()
            .filter_map(|wire| {
                let bundle = PublicKeyBundle::verify_self_signed(wire.as_slice()).ok()?;
                Some((bundle.bundle_seq, wire.as_slice().to_vec()))
            })
            .collect();
        let mut self_grants = Vec::with_capacity(vault_keys.len());
        for (grant, key) in view.vault_self_grants.as_slice().iter().zip(vault_keys) {
            let key_id = key.key_id().map_err(|_| ClientError::Internal)?;
            self_grants.push((grant.clone(), *key_id.as_bytes()));
        }
        Ok(Self {
            bundles,
            identity_secret_keys: Some(view.identity_secret_keys.clone()),
            self_grants,
        })
    }
}

impl core::fmt::Debug for VerifiedAccount {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VerifiedAccount")
            .field("account_id", &self.account_id)
            .field("state_seq", &self.pin.state.state_seq)
            .field("vaults", &self.vault_keys.len())
            .finish_non_exhaustive()
    }
}

impl VerifiedAccount {
    /// The account.
    #[must_use]
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// The verified `account-state`.
    #[must_use]
    pub const fn state(&self) -> &AccountState {
        &self.pin.state
    }

    /// What an enrolled device persists from this answer.
    #[must_use]
    pub const fn pin(&self) -> &AccountPin {
        &self.pin
    }

    /// The account fingerprint of the verified identity keys (CRYPTO.md §10.3), for display.
    #[must_use]
    pub fn fingerprint(&self) -> AccountFingerprint {
        AccountFingerprint::compute(self.account_id, &self.identity.public_keys())
    }

    /// The verified device certificates.
    #[must_use]
    pub fn certificates(&self) -> &[CertifiedDevice] {
        &self.certificates
    }

    /// The verified revocations.
    #[must_use]
    pub fn revocations(&self) -> &[RevokedDevice] {
        &self.revocations
    }

    /// The vaults this account holds a self-grant for.
    pub fn vault_ids(&self) -> impl Iterator<Item = VaultId> + '_ {
        self.vault_keys.iter().map(VaultKey::vault_id)
    }

    /// Whether the identity keys changed with this answer (after the user confirmed them).
    #[must_use]
    pub const fn identity_changed(&self) -> bool {
        self.identity_changed
    }

    /// The `ACCOUNT_SETTINGS` (ciphertext) the verified state commits to, if any: the served
    /// ones, or the pinned ones when the server left them out as unchanged.
    #[must_use]
    pub const fn settings(&self) -> Option<&AccountSettings> {
        self.settings.as_ref()
    }

    /// Takes the vault key of `vault_id` out of this answer, to build that vault's
    /// [`crate::sync::VaultSync`]. The key stays in Rust memory (ADR 0013 §3 rule 1).
    #[must_use]
    pub fn take_vault_key(&mut self, vault_id: VaultId) -> Option<VaultKey> {
        let at = self
            .vault_keys
            .iter()
            .position(|k| k.vault_id() == vault_id)?;
        Some(self.vault_keys.swap_remove(at))
    }
}

/// How the identity keys of an answer are anchored.
pub(crate) enum Anchor<'a> {
    /// A new device: no pin; the identity keys come from `E_id` under an account key the
    /// caller authenticated (OPAQUE and `E_srv`), and `state.account_key_id` must match it.
    NewDevice,
    /// An enrolled device: the pin, and the fingerprint the user confirmed for a changed
    /// identity, if any (§11.3 step 3.2).
    Enrolled {
        /// The pin.
        pin: &'a AccountPin,
        /// The fingerprint the user confirmed on this device, if the host asked.
        confirmed: Option<&'a AccountFingerprint>,
    },
}

/// The public part of an account answer that verified: everything the identity key signs,
/// checked against each other, before any account key is used (module docs, steps 2–6).
pub(crate) struct PublicAccount {
    /// The bundle the state commits to.
    pub(crate) bundle: VerifiedBundle,
    /// Whether the identity keys changed from the pin (and the user confirmed it).
    pub(crate) identity_changed: bool,
    /// The verified state.
    pub(crate) state: AccountState,
    /// Its wire form.
    pub(crate) state_wire: Vec<u8>,
    /// Every served certificate, verified.
    pub(crate) certificates: Vec<CertifiedDevice>,
    /// Every served revocation, verified.
    pub(crate) revocations: Vec<RevokedDevice>,
    /// The `ACCOUNT_SETTINGS` the state commits to: served, or kept with the pin.
    pub(crate) settings: Option<AccountSettings>,
}

/// Steps 2–6 of the module docs for an enrolled device (the pin anchors the identity key), or
/// for a new device whose bundle [`new_device_bundle`] already chose. The account key is not
/// used here, so a rotated account key is detected before any envelope is opened.
///
/// # Errors
/// As [`verify_account_view`], except [`ClientError::AccountKeyRotated`].
pub(crate) fn verify_public(
    view: &AccountView,
    account_id: AccountId,
    anchor: &Anchor<'_>,
    new_device_bundle: Option<VerifiedBundle>,
) -> Result<PublicAccount, ClientError> {
    let bad = ClientError::InvalidServerResponse;
    let (bundle, identity_changed) = match (anchor, new_device_bundle) {
        (Anchor::NewDevice, Some(bundle)) => (bundle, false),
        (Anchor::NewDevice, None) => return Err(ClientError::Internal),
        (Anchor::Enrolled { pin, confirmed }, _) => {
            let wires: Vec<&[u8]> = view
                .bundles
                .as_slice()
                .iter()
                .map(rizzy_proto::wire::Bytes::as_slice)
                .collect();
            let (head, changed) = pin.bundle.verify_chain(&wires).map_err(|_| bad)?;
            if head.account_id != account_id {
                return Err(bad);
            }
            if changed {
                let shown = AccountFingerprint::compute(account_id, &head.identity_public_keys());
                if confirmed.is_none_or(|c| *c != shown) {
                    return Err(ClientError::IdentityChangeUnconfirmed);
                }
            }
            (head, changed)
        }
    };
    let state_wire = view.account_state.as_slice();
    let state = AccountState::verify(state_wire, &bundle.identity_ed25519, bundle.identity_epoch)
        .map_err(|_| bad)?
        .into_statement();
    if state.account_id != account_id || !state.matches_bundle(&bundle) {
        return Err(bad);
    }
    if let Anchor::Enrolled { pin, .. } = anchor {
        if state.is_rollback(pin.state.state_seq, pin.state.settings_seq) {
            return Err(ClientError::Rollback);
        }
        if state.is_fork(&pin.state) {
            return Err(ClientError::Fork);
        }
    }
    let (certificates, revocations) = verify_devices(view, account_id, &bundle)?;
    let set = device_set_hash(
        account_id,
        certificates.iter().map(|c| &c.certificate),
        revocations.iter().map(|r| &r.revocation),
    )
    .map_err(|_| bad)?;
    if set != state.device_set_hash {
        return Err(bad);
    }
    let settings = effective_settings(view, anchor, &state);
    if !state.matches_settings(settings.as_ref().map(|s| s.envelope.as_slice()))
        || settings
            .as_ref()
            .is_some_and(|s| s.settings_seq != state.settings_seq)
    {
        return Err(bad);
    }
    Ok(PublicAccount {
        bundle,
        identity_changed,
        state,
        state_wire: state_wire.to_vec(),
        certificates,
        revocations,
        settings,
    })
}

/// The `ACCOUNT_SETTINGS` the verified state's `settings_hash` is checked against (§11.3 step
/// 2.4): the served ones if the answer carries them; otherwise, for an enrolled device whose
/// pinned `settings_seq` equals the state's, the pinned ones (the server leaves settings out
/// when the query's `known_settings_seq` is current, [`AccountView::account_settings`]);
/// otherwise none, which matches only `settings_seq = 0`.
///
/// The pinned envelope is only a candidate: the caller still checks it against the new signed
/// `settings_hash`, so a server that leaves out settings that changed fails that check.
fn effective_settings(
    view: &AccountView,
    anchor: &Anchor<'_>,
    state: &AccountState,
) -> Option<AccountSettings> {
    match (view.account_settings.as_ref(), anchor) {
        (Some(served), _) => Some(served.clone()),
        (None, Anchor::Enrolled { pin, .. }) if pin.state.settings_seq == state.settings_seq => {
            pin.settings.clone()
        }
        (None, _) => None,
    }
}

/// Verifies an [`AccountView`] in full (see the module docs).
///
/// # Errors
/// [`ClientError::InvalidServerResponse`] for any failed check; [`ClientError::Rollback`],
/// [`ClientError::Fork`], [`ClientError::IdentityChangeUnconfirmed`] and
/// [`ClientError::AccountKeyRotated`] for an enrolled device.
pub(crate) fn verify_account_view(
    view: &AccountView,
    account_id: AccountId,
    account_key: &AccountKey,
    anchor: &Anchor<'_>,
) -> Result<VerifiedAccount, ClientError> {
    let bad = ClientError::InvalidServerResponse;
    let chosen = match anchor {
        Anchor::NewDevice => Some(new_device_bundle(view, account_id, account_key)?),
        Anchor::Enrolled { .. } => None,
    };
    let public = verify_public(view, account_id, anchor, chosen)?;
    let state = &public.state;
    if matches!(anchor, Anchor::Enrolled { .. }) && state.account_key_epoch > account_key.epoch() {
        return Err(ClientError::AccountKeyRotated);
    }
    if !state.matches_account_key(account_key) {
        return Err(bad);
    }
    // Step 1, now that the key is authenticated by the state: `E_id` opens and matches.
    let identity = open_identity(view, account_id, account_key)?;
    if identity.epoch() != state.identity_epoch
        || identity.public_keys() != public.bundle.identity_public_keys()
    {
        return Err(bad);
    }
    let vault_keys = open_self_grants(view, account_id, account_key, state)?;
    let served = ServedObjects::of_view(view, &vault_keys)?;
    Ok(VerifiedAccount {
        served,
        account_id,
        pin: AccountPin {
            bundle: public.bundle,
            state: public.state,
            state_wire: public.state_wire,
            settings: public.settings.clone(),
        },
        identity,
        certificates: public.certificates,
        revocations: public.revocations,
        vault_keys,
        settings: public.settings,
        identity_changed: public.identity_changed,
    })
}

/// Opens `E_id` with the context the served epoch names; the caller compares the result with
/// the verified state and bundle.
fn open_identity(
    view: &AccountView,
    account_id: AccountId,
    account_key: &AccountKey,
) -> Result<IdentityKeys, ClientError> {
    let ctx = IdentitySecretKeysCtx {
        account_id,
        identity_epoch: view.identity_secret_keys.identity_epoch,
    };
    account_key
        .unwrap_identity_keys(&ctx, view.identity_secret_keys.envelope.as_slice())
        .map_err(|_| ClientError::InvalidServerResponse)
}

/// A new device's bundle: the self-signed bundle of this account whose keys are those in
/// `E_id`, highest `bundle_seq` first. The state's `bundle_hash` is checked by the caller.
fn new_device_bundle(
    view: &AccountView,
    account_id: AccountId,
    account_key: &AccountKey,
) -> Result<VerifiedBundle, ClientError> {
    let identity = open_identity(view, account_id, account_key)?;
    let keys = identity.public_keys();
    view.bundles
        .as_slice()
        .iter()
        .filter_map(|wire| PublicKeyBundle::verify_self_signed(wire.as_slice()).ok())
        .filter(|b| {
            b.account_id == account_id
                && b.identity_epoch == identity.epoch()
                && b.identity_public_keys() == keys
        })
        .max_by_key(|b| b.bundle_seq)
        .ok_or(ClientError::InvalidServerResponse)
}

/// Verifies every served certificate and revocation under the bundle's identity key.
fn verify_devices(
    view: &AccountView,
    account_id: AccountId,
    bundle: &VerifiedBundle,
) -> Result<(Vec<CertifiedDevice>, Vec<RevokedDevice>), ClientError> {
    let bad = ClientError::InvalidServerResponse;
    let mut certificates = Vec::with_capacity(view.device_certificates.as_slice().len());
    for wire in view.device_certificates.as_slice() {
        let certificate = DeviceCertificate::verify(
            wire.as_slice(),
            &bundle.identity_ed25519,
            bundle.identity_epoch,
        )
        .map_err(|_| bad)?;
        if certificate.account_id != account_id {
            return Err(bad);
        }
        certificates.push(CertifiedDevice {
            certificate,
            wire: wire.as_slice().to_vec(),
        });
    }
    let mut revocations = Vec::with_capacity(view.device_revocations.as_slice().len());
    for wire in view.device_revocations.as_slice() {
        let revocation =
            DeviceRevocation::verify(wire.as_slice(), &bundle.identity_ed25519).map_err(|_| bad)?;
        if revocation.account_id != account_id {
            return Err(bad);
        }
        revocations.push(RevokedDevice {
            revocation,
            wire: wire.as_slice().to_vec(),
        });
    }
    Ok((certificates, revocations))
}

/// Opens every vault self-grant with the state's `account_key_epoch`; one grant per vault.
fn open_self_grants(
    view: &AccountView,
    account_id: AccountId,
    account_key: &AccountKey,
    state: &AccountState,
) -> Result<Vec<VaultKey>, ClientError> {
    let bad = ClientError::InvalidServerResponse;
    let mut keys: Vec<VaultKey> = Vec::with_capacity(view.vault_self_grants.as_slice().len());
    for grant in view.vault_self_grants.as_slice() {
        if grant.account_key_epoch != state.account_key_epoch {
            return Err(bad);
        }
        let vault_id = VaultId::from_bytes(grant.vault_id.to_bytes());
        if keys.iter().any(|k| k.vault_id() == vault_id) {
            return Err(bad);
        }
        let ctx = VaultKeySelfGrantCtx {
            account_id,
            vault_id,
            account_key_epoch: state.account_key_epoch,
            vault_key_epoch: grant.vault_key_epoch,
        };
        let key = account_key
            .unwrap_vault_key(&ctx, grant.envelope.as_slice())
            .map_err(|_| bad)?;
        keys.push(key);
    }
    Ok(keys)
}
