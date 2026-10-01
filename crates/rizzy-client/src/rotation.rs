//! Key rotation by an enrolled device (CRYPTO.md §11.6; the revocation of §11.8 steps 1–3;
//! [ADR 0025] §2), as a sans-I/O state machine.
//!
//! ```text
//! (re-authenticate: start_login … complete, over this device's session) ──► LoggedIn
//! upload queued ops, complete Fetch of every vault (VaultSync)
//! start_rotation ──► PendingRotation ── commit_request ──CommitChangeRequest──► host
//!   ├─ 204 ─────────────► PendingRotation::finalize (E_local, E_dev, pin, vault keys)
//!   └─ state_conflict ──► host re-fetches account-state and every vault (complete Fetch)
//!                         ──► PendingRotation::on_state_conflict ──► resend, or finalize
//! ```
//!
//! # What is built (§11.6 steps 2–8)
//!
//! - **Once**, the keys and every object that depends only on them: account key' (epoch + 1),
//!   one vault key' per vault at an epoch above every epoch this device saw
//!   ([`crate::sync::VaultSync`]), for a full rotation new identity keys (epoch + 1) and the new
//!   bundle signed by both identity keys; `E_srv'` under the `server_unlock_key` of this
//!   re-authentication's `export_key`; `E_id'`; `E_rec'` for a kept recovery code; the
//!   re-encrypted `ACCOUNT_SETTINGS` (`settings_seq + 1`) when settings exist; for a full
//!   rotation the old identity X25519 key as a `RETIRED_SECRET_KEY`.
//! - **Per attempt**, from the account state it is built on: for a full rotation the re-issue of
//!   every certificate and revocation under the new identity key and a revocation of every
//!   kind-4 certificate that has not expired; the revocation of [`RotationOptions::revoke`]; a
//!   device grant for every remaining durable device other than this one; the new
//!   `account-state`, signed by the identity key of its `identity_epoch`.
//! - **Per attempt**, the vault half of every vault ([`crate::sync::VaultSync`]): the new
//!   self-grant, this device's exact cursor, every wrap-set row it can open re-wrapped under
//!   vault key' (the item key and its `created_vault_key_epoch` unchanged), the rest dropped
//!   (ADR 0025 §2 step 3; the host reports [`RotationDone::dropped_items`] as unreadable).
//!
//! # Retries (ADR 0025 §2 step 5, CRYPTO.md §10.2)
//!
//! On `state_conflict` the host fetches `account-state` (with [`PendingRotation::state_query`])
//! and runs a complete Fetch of every vault, then calls [`PendingRotation::on_state_conflict`]:
//! - the served state is the one this rotation commits: the commit landed; finalize;
//! - the same `state_seq` and body as the base: rebuild the vault half (same keys, same
//!   signed state), re-sign the kind-4 revocations of a full rotation with H from the new
//!   Fetch (a web-vault upload does not move `account-state`), and resend;
//! - a higher `state_seq` where only `state_seq` and `device_set_hash` changed (a concurrent
//!   enrolment or revocation): rebuild the device grants and the vault half, re-sign under the
//!   same new keys, resend;
//! - a lower `state_seq` ([`ClientError::Rollback`]) or the same `state_seq` with another body
//!   ([`ClientError::Fork`]): go read-only;
//! - anything else changed: [`ClientError::RotationRestart`]; the host drops the pending
//!   rotation (its keys are wiped) and starts again from the re-authentication.
//!
//! After [`MAX_REBUILDS`] rebuilds the next conflict is [`ClientError::VaultKeepsChanging`]
//! ("the vault keeps changing"); the pending rotation is kept.
//!
//! # Secrets before commit (CRYPTO.md §11)
//!
//! The pending rotation holds the new keys until [`PendingRotation::finalize`]. Before the
//! commit is sent, a host that persists its device state writes the pending record
//! ([`PendingRotation::pending_record`]: `E_local'` and `E_dev'` under the new account key)
//! with the commit's exact JSON body (ADR 0026 §2, §4 step 3), and after the commit the cache
//! writes of the new state ([`PendingRotation::store_writes`]). No new Secret Key or recovery
//! code is created here, so no Emergency Kit is due.
//!
//! # Not in this build (reported)
//!
//! - A standalone rotation that issues a **new recovery code** (§11.6 step 5 default): a
//!   rotation by itself keeps the current code (an account with recovery on needs it typed).
//!   A new code is issued only by the rotation of a Secret Key change
//!   (`start_rotation_with`, [`crate::credentials`]) and by recovery ([`crate::recovery`]).
//! - **Re-wrapping older retired keys** (§11.6 step 3): the account view carries no
//!   `RETIRED_SECRET_KEY`, so only the identity key this rotation retires is sent.
//! - A rotation by a **web vault** (kind 4) and the **rotating recovery** of §11.9 step 5 on the
//!   client side; the server accepts both (ADR 0025).
//!
//! [ADR 0025]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0025-rotation-vault-half.md

use core::fmt;
use std::collections::BTreeSet;

use rizzy_core::envelope::purpose::{
    AccountKeyDeviceGrantCtx, AccountKeyRecoveryWrapCtx, AccountKeyServerWrapCtx,
    AccountSettingsCtx, IdentitySecretKeysCtx, ItemKeyWrapCtx, RetiredSecretKeyCtx,
    VaultKeySelfGrantCtx,
};
use rizzy_core::envelope::{open, seal};
use rizzy_core::ids::{AccountId, DeviceId, ItemId, VaultId};
use rizzy_core::keys::{
    AccountKey, GrantSigner, IdentityKeys, VaultKey, device_set_hash,
    seal_account_key_device_grant, settings_hash,
};
use rizzy_core::opaque::PasswordInput;
use rizzy_core::rng::CryptoRng;
use rizzy_core::secret_key::RecoveryCode;
use rizzy_core::sign::{
    AccountState, BundleStep, CasRetry, DeviceCertificate, DeviceKind, DeviceRevocation,
    PublicKeyBundle, VerifiedBundle,
};
use rizzy_proto::account::{AccountStateQuery, AccountView};
use rizzy_proto::auth::RecoveryRegistration;
use rizzy_proto::change::{
    CommitChangeRequest, RetiredSecretKey, VaultRotation, VaultRotationUpload, WrapLocator,
};
use rizzy_proto::objects::{
    AccountKeyRecoveryWrap, AccountKeyServerWrap, AccountSettings, DeviceGrant, IdentitySecretKeys,
    ItemKeyWrap, VaultSelfGrant,
};
use rizzy_proto::vault::SeqVector;
use rizzy_proto::wire::{Fixed, List, SessionToken};

use rizzy_core::envelope::purpose::DeviceSecretKeysCtx;
use rizzy_core::secret_key::SecretKey;

use crate::account::{
    AccountPin, Anchor, CertifiedDevice, RevokedDevice, ServedObjects, verify_public,
};
use crate::credentials::{CredentialPart, NewCredential};
use crate::device::{DeviceState, LocalWrap, UnlockedDevice, wrap_local};
use crate::error::{ClientError, internal};
use crate::login::LoggedIn;
use crate::store;
use crate::store::record::PendingRecord;
use crate::store::rows::{Changeset, Write};
use crate::sync::{Authors, VaultSync, wrap_rows};
use crate::wire::{bytes, id};

/// The most rebuilds after `state_conflict` before [`ClientError::VaultKeepsChanging`] (ADR
/// 0025 §2 step 5: "After 5 attempts that only rebuilt, stop").
pub const MAX_REBUILDS: u32 = 5;

/// The level of a rotation (CRYPTO.md §11.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RotationLevel {
    /// The account key and the vault keys.
    Standard,
    /// Also the identity keys: the default when a lost or stolen device is revoked.
    Full,
}

/// A device the rotation revokes (CRYPTO.md §11.8 steps 0–3): the device suspended before, and
/// H, the head the suspension returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RevokeDevice {
    /// The device.
    pub device_id: DeviceId,
    /// H: `last_accepted_device_seq` of the revocation.
    pub last_accepted_device_seq: u64,
}

/// The choices of a rotation.
#[derive(Clone, Copy)]
pub struct RotationOptions<'a> {
    /// Standard or full.
    pub level: RotationLevel,
    /// The device to revoke with it, if any.
    pub revoke: Option<RevokeDevice>,
    /// The current recovery code, to keep it (§11.6 step 5): required exactly when the
    /// account's recovery is on.
    pub recovery_code: Option<&'a str>,
    /// The host's wall clock, milliseconds since the Unix epoch.
    pub now_ms: u64,
}

impl fmt::Debug for RotationOptions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RotationOptions")
            .field("level", &self.level)
            .field("revoke", &self.revoke)
            .field("keeps_recovery_code", &self.recovery_code.is_some())
            .finish_non_exhaustive()
    }
}

/// What [`PendingRotation::on_state_conflict`] decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConflictOutcome {
    /// The request was rebuilt: send [`PendingRotation::commit_request`] again.
    Resend,
    /// The server already holds this rotation's state: call [`PendingRotation::finalize`].
    Committed,
}

/// The vault half of one vault, built by [`build_vault_half`].
pub(crate) struct VaultHalf {
    /// The upload entry.
    pub(crate) rotation: VaultRotation,
    /// The items of the dropped rows, for the host to report as unreadable.
    pub(crate) dropped_items: Vec<ItemId>,
}

/// Builds the vault half of one vault (ADR 0025 §2 step 3): the self-grant of `new_vault_key`
/// under `new_account_key`, `cursor`, and for every served row: re-wrapped under
/// `new_vault_key` if it opens under a held key of its epoch **and** the opened item key's id
/// is the row's `item_key_id` locator, else dropped. A row whose locator lies is dropped rather
/// than re-filed: the server needs every stored locator covered, and a key under a false
/// locator is none a reader would look up (CRYPTO.md §11.6 reader rule).
///
/// # Errors
/// [`ClientError::InvalidServerResponse`] for two served rows at one locator;
/// [`ClientError::Internal`].
pub(crate) fn build_vault_half<R: CryptoRng + ?Sized>(
    rng: &mut R,
    account_id: AccountId,
    held: &[&VaultKey],
    rows: &[ItemKeyWrap],
    cursor: SeqVector,
    new_account_key: &AccountKey,
    new_vault_key: &VaultKey,
) -> Result<VaultHalf, ClientError> {
    let vault_id = new_vault_key.vault_id();
    let new_epoch = new_vault_key.epoch();
    let grant = new_account_key
        .wrap_vault_key(
            rng,
            &VaultKeySelfGrantCtx {
                account_id,
                vault_id,
                account_key_epoch: new_account_key.epoch(),
                vault_key_epoch: new_epoch,
            },
            new_vault_key,
        )
        .map_err(internal)?;
    let mut seen = BTreeSet::new();
    let mut wraps = Vec::with_capacity(rows.len());
    let mut dropped = Vec::new();
    let mut dropped_items = Vec::new();
    for row in rows {
        let item = ItemId::from_bytes(row.item_id.to_bytes());
        if !seen.insert((row.item_id, row.item_key_id)) {
            return Err(ClientError::InvalidServerResponse);
        }
        let opened = held
            .iter()
            .filter(|k| k.vault_id() == vault_id && k.epoch() == row.vault_key_epoch)
            .find_map(|k| {
                k.unwrap_item_key(
                    &ItemKeyWrapCtx {
                        vault_id,
                        item_id: item,
                        vault_key_epoch: row.vault_key_epoch,
                    },
                    row.envelope.as_slice(),
                )
                .ok()
            })
            .filter(|key| {
                key.key_id()
                    .is_ok_and(|kid| *kid.as_bytes() == row.item_key_id.to_bytes())
            });
        if let Some(item_key) = opened {
            let envelope = new_vault_key
                .wrap_item_key(
                    rng,
                    &ItemKeyWrapCtx {
                        vault_id,
                        item_id: item,
                        vault_key_epoch: new_epoch,
                    },
                    &item_key,
                )
                .map_err(internal)?;
            wraps.push(ItemKeyWrap {
                item_id: row.item_id,
                item_key_id: row.item_key_id,
                vault_key_epoch: new_epoch,
                envelope: bytes(envelope)?,
            });
        } else {
            dropped.push(WrapLocator {
                item_id: row.item_id,
                item_key_id: row.item_key_id,
            });
            dropped_items.push(item);
        }
    }
    Ok(VaultHalf {
        rotation: VaultRotation {
            self_grant: VaultSelfGrant {
                vault_id: id(vault_id.to_bytes()),
                account_key_epoch: new_account_key.epoch(),
                vault_key_epoch: new_epoch,
                envelope: bytes(grant)?,
            },
            cursor,
            item_key_wraps: List::new(wraps).map_err(internal)?,
            dropped: List::new(dropped).map_err(internal)?,
        },
        dropped_items,
    })
}

/// The account-level objects a rotation builds once (module docs).
struct Built {
    /// `E_srv'`.
    e_srv: AccountKeyServerWrap,
    /// `E_id'`.
    e_id: IdentitySecretKeys,
    /// `E_rec'` for a kept code.
    recovery_rewrap: Option<AccountKeyRecoveryWrap>,
    /// `E_rec'` and `H_rec'` of a new code (a Secret Key change's rotation).
    recovery: Option<RecoveryRegistration>,
    /// The re-encrypted settings.
    settings: Option<AccountSettings>,
    /// The retired identity key of a full rotation.
    retired: Vec<RetiredSecretKey>,
    /// The new bundle of a full rotation: wire form and verified value.
    bundle: Option<(Vec<u8>, VerifiedBundle)>,
}

/// The account part of one attempt.
struct AccountPart {
    /// The new state.
    state: AccountState,
    /// Its signed wire form.
    state_wire: Vec<u8>,
    /// Certificates the request carries (a full rotation's re-issues).
    certificates: Vec<CertifiedDevice>,
    /// Revocations the request carries.
    revocations: Vec<RevokedDevice>,
    /// Every certificate after the change.
    all_certificates: Vec<CertifiedDevice>,
    /// Every revocation after the change.
    all_revocations: Vec<RevokedDevice>,
    /// The device grants.
    grants: Vec<DeviceGrant>,
}

/// A rotation built and waiting for the server's commit (module docs). Holds the old and new
/// keys; not `Clone`, `Debug` shows ids and sequence numbers only.
pub struct PendingRotation {
    /// The account.
    account_id: AccountId,
    /// The rotating device.
    device_id: DeviceId,
    /// The options that do not change between attempts.
    level: RotationLevel,
    /// The device revoked, if any.
    revoke: Option<RevokeDevice>,
    /// The host clock at the start.
    now_ms: u64,
    /// The verified state this attempt is built on, with its bundle and settings.
    base: AccountPin,
    /// The certificates of `base`.
    certificates: Vec<CertifiedDevice>,
    /// The revocations of `base`.
    revocations: Vec<RevokedDevice>,
    /// The account key before the rotation: the device-grant PSK comes from it.
    old_account_key: AccountKey,
    /// The account key after it.
    new_account_key: AccountKey,
    /// The identity keys that sign the new state: the new ones in a full rotation.
    signer: IdentityKeys,
    /// The new vault keys, ascending by vault id.
    new_vault_keys: Vec<VaultKey>,
    /// The objects built once.
    built: Built,
    /// `pw_in` of the re-authentication, for `E_local'` if the unlock key is gone.
    pw_in: PasswordInput,
    /// The fresh OPAQUE session's bearer token.
    session_token: SessionToken,
    /// The current attempt's account part.
    account: AccountPart,
    /// The current attempt's vault halves, ascending by vault id.
    vaults: Vec<VaultRotation>,
    /// The items of the dropped rows, per vault.
    dropped_items: Vec<(VaultId, ItemId)>,
    /// The current request.
    request: CommitChangeRequest,
    /// Rebuilds so far.
    rebuilds: u32,
    /// `E_local'` and `E_dev'` as [`PendingRotation::pending_record`] built them, which
    /// [`PendingRotation::finalize`] then adopts unchanged.
    prepared: Option<(LocalWrap, Vec<u8>)>,
    /// The new credential committed with this rotation ([`start_rotation_with`]), if any.
    credential: Option<CredentialPart>,
}

impl fmt::Debug for PendingRotation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingRotation")
            .field("account_id", &self.account_id)
            .field("level", &self.level)
            .field("base_state_seq", &self.base.state.state_seq)
            .field("rebuilds", &self.rebuilds)
            .finish_non_exhaustive()
    }
}

/// What a committed rotation leaves the host.
pub struct RotationDone {
    /// The authors of the new state (a full rotation re-issues every certificate), for the
    /// vaults' next Fetch.
    pub authors: Authors,
    /// The items whose wrap-set row this rotation dropped: unreadable for every device (ADR
    /// 0025 §2 step 3, "Negative").
    pub dropped_items: Vec<(VaultId, ItemId)>,
}

impl fmt::Debug for RotationDone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RotationDone")
            .field("dropped_items", &self.dropped_items.len())
            .finish_non_exhaustive()
    }
}

/// Checks the re-authentication against this device's pin and keys (module docs). Also the
/// check of a credential change ([`crate::credentials`]) and of following one made elsewhere.
pub(crate) fn check_reauth(
    reauth: &LoggedIn,
    device: &DeviceState,
    unlocked: &UnlockedDevice,
) -> Result<(), ClientError> {
    let account = &reauth.account;
    if unlocked.account_id != device.account_id
        || unlocked.device_id != device.device_id
        || account.account_id != device.account_id
    {
        return Err(ClientError::InvalidInput);
    }
    let state = &account.pin.state;
    let pin = &device.pin;
    if state.is_rollback(pin.state.state_seq, pin.state.settings_seq) {
        return Err(ClientError::Rollback);
    }
    if state.is_fork(&pin.state) {
        return Err(ClientError::Fork);
    }
    // A full rotation elsewhere must be confirmed through the unlock flow first (§11.3 step 3).
    if account.pin.bundle.identity_public_keys() != pin.bundle.identity_public_keys() {
        return Err(ClientError::IdentityChangeUnconfirmed);
    }
    // The device holds the current account key (a rotation elsewhere is processed first,
    // §11.3 step 4).
    if !state.matches_account_key(&unlocked.account_key) {
        return Err(ClientError::AccountKeyRotated);
    }
    let own = unlocked.device_keys.public_keys();
    let member = !account
        .revocations
        .iter()
        .any(|r| r.revocation.device_id == device.device_id)
        && account.certificates.iter().any(|c| {
            c.certificate.device_id == device.device_id
                && c.certificate.in_device_set()
                && c.certificate.device_ed25519 == own.ed25519
                && c.certificate.device_x25519 == own.x25519
        });
    if member {
        Ok(())
    } else {
        Err(ClientError::InvalidServerResponse)
    }
}

/// The vaults of `vaults`, one per vault of the account, ascending by id.
fn ordered<'a>(
    account_vaults: &BTreeSet<VaultId>,
    vaults: &[&'a VaultSync],
) -> Result<Vec<&'a VaultSync>, ClientError> {
    let mut out: Vec<&VaultSync> = vaults.to_vec();
    out.sort_by_key(|v| v.vault_id());
    let ids: BTreeSet<VaultId> = out.iter().map(|v| v.vault_id()).collect();
    if ids.len() != out.len() || ids != *account_vaults {
        return Err(ClientError::InvalidInput);
    }
    Ok(out)
}

/// Starts a rotation (module docs): checks the re-authentication `reauth` (a fresh OPAQUE login
/// over this device's session, so the server binds it to this device), generates the new keys,
/// builds every object and the first request.
///
/// `vaults` holds one [`VaultSync`] per vault of the account, each after the device uploaded its
/// queued records and ran a complete Fetch.
///
/// # Errors
/// [`ClientError::InvalidInput`] for another device's state, a vault set that is not the
/// account's, a revoked device that is not a remaining device of the account (or this one), or
/// a recovery code given when recovery is off, missing when it is on, or malformed;
/// [`ClientError::Rollback`], [`ClientError::Fork`], [`ClientError::IdentityChangeUnconfirmed`]
/// and [`ClientError::AccountKeyRotated`] when the re-authentication's account is not the one
/// this device pinned; [`ClientError::SyncRequired`] and [`ClientError::ReadOnly`] from the
/// vaults; [`ClientError::InvalidServerResponse`]; [`ClientError::Internal`].
pub fn start_rotation<R: CryptoRng + ?Sized>(
    rng: &mut R,
    reauth: LoggedIn,
    device: &DeviceState,
    unlocked: &UnlockedDevice,
    vaults: &[&VaultSync],
    options: &RotationOptions<'_>,
) -> Result<PendingRotation, ClientError> {
    start_rotation_with(rng, reauth, device, unlocked, vaults, options, None)
}

/// [`start_rotation`], optionally committing a new credential in the same request: the
/// rotation of a Secret Key change (by default) or of a password change with "also rotate
/// keys" (CRYPTO.md §11.5 "Rotation"). With `credential`:
/// - `E_srv'` is under the new registration's `export_key`, at `password_epoch + 1` and the
///   new `kdf_id`, and the new state carries both;
/// - when `credential` issues a new recovery code (an SK change, §11.6 step 5 forbids keeping
///   the code then), `E_rec'` and `H_rec'` at `recovery_epoch + 1` replace the kept-code rewrap,
///   and [`RotationOptions::recovery_code`] must be `None`;
/// - the pending record and the finalised device state carry the new Secret Key, a new
///   `device_salt`, the new `kdf_id` and `E_local'` under the new password's local unlock key.
///
/// # Errors
/// As [`start_rotation`].
#[expect(
    clippy::too_many_lines,
    reason = "CRYPTO.md §11.6 steps 2–5 and 7 in order, each a few lines, then the first attempt"
)]
pub(crate) fn start_rotation_with<R: CryptoRng + ?Sized>(
    rng: &mut R,
    reauth: LoggedIn,
    device: &DeviceState,
    unlocked: &UnlockedDevice,
    vaults: &[&VaultSync],
    options: &RotationOptions<'_>,
    credential: Option<NewCredential>,
) -> Result<PendingRotation, ClientError> {
    check_reauth(&reauth, device, unlocked)?;
    let LoggedIn {
        pw_in,
        export_key,
        account,
        account_key: old_account_key,
        session_token,
        ..
    } = reauth;
    let account_id = account.account_id;
    let base = account.pin.clone();
    let state = &base.state;
    let account_vaults: BTreeSet<VaultId> = account.vault_ids().collect();
    let ordered_vaults = ordered(&account_vaults, vaults)?;
    if let Some(target) = options.revoke {
        let remaining = target.device_id != device.device_id
            && account.certificates.iter().any(|c| {
                c.certificate.device_id == target.device_id && c.certificate.in_device_set()
            })
            && !account
                .revocations
                .iter()
                .any(|r| r.revocation.device_id == target.device_id);
        if !remaining {
            return Err(ClientError::InvalidInput);
        }
    }
    let issues_code = credential
        .as_ref()
        .is_some_and(|c| c.recovery_code.is_some());
    if issues_code {
        if !state.recovery_enabled || options.recovery_code.is_some() {
            return Err(ClientError::InvalidInput);
        }
    } else if state.recovery_enabled != options.recovery_code.is_some() {
        return Err(ClientError::InvalidInput);
    }

    // Step 2: the new keys.
    let new_account_key = old_account_key
        .generate_next(rng)
        .map_err(|_| ClientError::Internal)?;
    let mut new_vault_keys = Vec::with_capacity(ordered_vaults.len());
    for vault in &ordered_vaults {
        new_vault_keys.push(VaultKey::generate(
            rng,
            vault.vault_id(),
            vault.next_vault_epoch()?,
        ));
    }
    let new_identity = match options.level {
        RotationLevel::Standard => None,
        RotationLevel::Full => Some(IdentityKeys::generate(
            rng,
            state
                .identity_epoch
                .checked_add(1)
                .ok_or(ClientError::Internal)?,
        )),
    };

    // Steps 3–5 and 7 (the bundle): the objects that depend only on the keys.
    let new_epoch = new_account_key.epoch();
    // With a new credential, E_srv' is under its registration's export_key and epochs.
    let (srv_export_key, password_epoch, kdf_id) = match &credential {
        Some(c) => (&c.export_key, c.part.password_epoch, c.part.kdf_id),
        None => (&export_key, state.password_epoch, state.kdf_id),
    };
    let e_srv = srv_export_key
        .server_unlock_key(account_id)
        .map_err(internal)?
        .wrap_account_key(
            rng,
            &AccountKeyServerWrapCtx {
                account_id,
                account_key_epoch: new_epoch,
                password_epoch,
                kdf_id,
            },
            &new_account_key,
        )
        .map_err(internal)?;
    let recovery_rewrap = match options.recovery_code {
        None => None,
        Some(text) => Some(keep_recovery_code(
            rng,
            account_id,
            state,
            &new_account_key,
            text,
        )?),
    };
    let (credential, recovery) = match credential {
        None => (None, None),
        Some(NewCredential {
            part,
            export_key: _,
            recovery_code,
        }) => {
            let recovery = match recovery_code {
                None => None,
                Some(code) => Some(issue_recovery_code(
                    rng,
                    account_id,
                    state,
                    &new_account_key,
                    &code,
                )?),
            };
            (Some(part), recovery)
        }
    };
    let settings = reencrypt_settings(rng, &base, &old_account_key, &new_account_key)?;
    let (signer, bundle, retired) = match new_identity {
        None => (account.identity, None, Vec::new()),
        Some(new_identity) => {
            let (bundle, retired) = change_identity(
                rng,
                &base.bundle,
                account.identity,
                &new_identity,
                &new_account_key,
                options.now_ms,
            )?;
            (new_identity, Some(bundle), vec![retired])
        }
    };
    let e_id = new_account_key
        .wrap_identity_keys(
            rng,
            &IdentitySecretKeysCtx {
                account_id,
                identity_epoch: signer.epoch(),
            },
            &signer,
        )
        .map_err(internal)?;
    let built = Built {
        e_srv: AccountKeyServerWrap {
            account_key_epoch: new_epoch,
            password_epoch,
            kdf_id: kdf_id.get(),
            envelope: bytes(e_srv)?,
        },
        recovery,
        e_id: IdentitySecretKeys {
            identity_epoch: signer.epoch(),
            envelope: bytes(e_id)?,
        },
        recovery_rewrap,
        settings,
        retired,
        bundle,
    };
    let mut pending = PendingRotation {
        account_id,
        device_id: device.device_id,
        level: options.level,
        revoke: options.revoke,
        now_ms: options.now_ms,
        base,
        certificates: account.certificates,
        revocations: account.revocations,
        old_account_key,
        new_account_key,
        signer,
        new_vault_keys,
        built,
        pw_in,
        session_token,
        account: AccountPart {
            state: account.pin.state.clone(),
            state_wire: Vec::new(),
            certificates: Vec::new(),
            revocations: Vec::new(),
            all_certificates: Vec::new(),
            all_revocations: Vec::new(),
            grants: Vec::new(),
        },
        vaults: Vec::new(),
        dropped_items: Vec::new(),
        // Placeholders until the first attempt below replaces them.
        request: CommitChangeRequest {
            account_state: bytes(account.pin.state_wire.clone())?,
            registration_upload: None,
            account_key_server_wrap: None,
            recovery: None,
            account_settings: None,
            device_certificates: List::empty(),
            device_revocations: List::empty(),
            bundle: None,
            identity_secret_keys: None,
            retired_secret_keys: List::empty(),
            device_grants: List::empty(),
            recovery_rewrap: None,
            vault_rotation: None,
        },
        rebuilds: 0,
        prepared: None,
        credential,
    };
    pending.build_account(rng, unlocked, &ordered_vaults)?;
    pending.build_vaults(rng, &ordered_vaults)?;
    pending.assemble()?;
    Ok(pending)
}

impl PendingRotation {
    /// The request to send (`POST` the account commit), over [`PendingRotation::bearer_token`]'s
    /// session. The same bytes are resent after a crash (CRYPTO.md §11 "Secrets before
    /// commit").
    #[must_use]
    pub const fn commit_request(&self) -> &CommitChangeRequest {
        &self.request
    }

    /// The fresh OPAQUE session's bearer token. Never log it.
    #[must_use]
    pub const fn bearer_token(&self) -> &SessionToken {
        &self.session_token
    }

    /// The `account-state` this rotation commits.
    #[must_use]
    pub const fn new_state(&self) -> &AccountState {
        &self.account.state
    }

    /// What to fetch after a `state_conflict`: everything above the base's bundle, and the
    /// settings unless the base holds the current ones.
    #[must_use]
    pub fn state_query(&self) -> AccountStateQuery {
        let held = self
            .base
            .settings
            .as_ref()
            .filter(|s| s.settings_seq == self.base.state.settings_seq);
        AccountStateQuery {
            known_bundle_seq: self.base.bundle.bundle_seq,
            known_settings_seq: held.map_or(0, |s| s.settings_seq),
        }
    }

    /// The account part of an attempt (module docs), on `self.base`.
    #[expect(
        clippy::too_many_lines,
        reason = "CRYPTO.md §11.6 steps 6–8 in order: devices, grants, state"
    )]
    fn build_account<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        unlocked: &UnlockedDevice,
        vaults: &[&VaultSync],
    ) -> Result<(), ClientError> {
        let account_id = self.account_id;
        let base = &self.base.state;
        let full = self.level == RotationLevel::Full;
        let signing = self.signer.signing_key();
        let verifying = *signing.verifying_key();
        let epoch = self.signer.epoch();
        // Certificates: a full rotation re-issues every one under the new identity key.
        let mut certificates = Vec::new();
        let all_certificates: Vec<CertifiedDevice> = if full {
            for held in &self.certificates {
                let cert = DeviceCertificate {
                    identity_epoch: epoch,
                    ..held.certificate.statement().clone()
                };
                let wire = cert.sign(signing).map_err(internal)?;
                let certificate =
                    DeviceCertificate::verify(&wire, &verifying, epoch).map_err(internal)?;
                certificates.push(CertifiedDevice { certificate, wire });
            }
            certificates.clone()
        } else {
            self.certificates.clone()
        };
        // Revocations: a full rotation re-issues every one; the revoked device's; and in a full
        // rotation every kind-4 certificate that has not expired, with H the head this device
        // holds after its complete Fetch (§11.6 step 7).
        let sign_revocation = |r: &DeviceRevocation| -> Result<RevokedDevice, ClientError> {
            let wire = r.sign(signing).map_err(internal)?;
            let revocation = DeviceRevocation::verify(&wire, &verifying).map_err(internal)?;
            Ok(RevokedDevice { revocation, wire })
        };
        let mut revocations = Vec::new();
        if full {
            for held in &self.revocations {
                revocations.push(sign_revocation(held.revocation.statement())?);
            }
        }
        let revoked_before: BTreeSet<DeviceId> = self
            .revocations
            .iter()
            .map(|r| r.revocation.device_id)
            .collect();
        let mut revoked_now: Vec<(DeviceId, u64)> = Vec::new();
        if let Some(target) = self.revoke {
            revoked_now.push((target.device_id, target.last_accepted_device_seq));
        }
        revoked_now.extend(self.web_revocation_heads(&revoked_before, vaults));
        for (device_id, head) in &revoked_now {
            revocations.push(sign_revocation(&DeviceRevocation {
                account_id,
                device_id: *device_id,
                last_accepted_device_seq: *head,
                revoked_at_ms: self.now_ms,
            })?);
        }
        let mut all_revocations: Vec<RevokedDevice> = if full {
            Vec::new()
        } else {
            self.revocations.clone()
        };
        all_revocations.extend(revocations.iter().cloned());
        let set = device_set_hash(
            account_id,
            all_certificates.iter().map(|c| &c.certificate),
            all_revocations.iter().map(|r| &r.revocation),
        )
        .map_err(|_| ClientError::InvalidServerResponse)?;
        // Step 6: a grant for every remaining durable device but this one.
        let revoked: BTreeSet<DeviceId> = all_revocations
            .iter()
            .map(|r| r.revocation.device_id)
            .collect();
        let new_epoch = self.new_account_key.epoch();
        let mut grants = Vec::new();
        for recipient in &all_certificates {
            let c = &recipient.certificate;
            if !c.in_device_set() || revoked.contains(&c.device_id) || c.device_id == self.device_id
            {
                continue;
            }
            let ctx = AccountKeyDeviceGrantCtx {
                account_id,
                account_key_epoch: new_epoch,
                sender_device_id: self.device_id,
                recipient_device_id: c.device_id,
            };
            let grant = seal_account_key_device_grant(
                rng,
                &ctx,
                &self.new_account_key,
                &self.old_account_key,
                c,
                GrantSigner::Device(unlocked.device_keys.signing_key()),
            )
            .map_err(internal)?;
            grants.push(DeviceGrant {
                account_key_epoch: new_epoch,
                sender_device_id: id(self.device_id.to_bytes()),
                recipient_device_id: id(c.device_id.to_bytes()),
                key_grant: bytes(grant)?,
            });
        }
        // Step 8: the state.
        let mut state = base.clone();
        state.state_seq = base.state_seq.checked_add(1).ok_or(ClientError::Internal)?;
        state.identity_epoch = epoch;
        state.account_key_epoch = new_epoch;
        state.account_key_id = self.new_account_key.key_id().map_err(internal)?;
        state.device_set_hash = set;
        if let Some((_, bundle)) = &self.built.bundle {
            state.bundle_hash = *bundle.hash();
        }
        if let Some(settings) = &self.built.settings {
            state.settings_seq = settings.settings_seq;
            state.settings_hash =
                settings_hash(settings.settings_seq, Some(settings.envelope.as_slice()))
                    .ok_or(ClientError::Internal)?;
        }
        // A credential change committed with the rotation (CRYPTO.md §11 "Replacing
        // credentials"): `password_epoch + 1`, the new record's `kdf_id`, and `recovery_epoch
        // + 1` with a new code.
        if let Some(credential) = &self.credential {
            state.password_epoch = credential.password_epoch;
            state.kdf_id = credential.kdf_id;
        }
        if let Some(recovery) = &self.built.recovery {
            state.recovery_epoch = recovery.recovery_wrap.recovery_epoch;
            state.recovery_enabled = true;
        }
        let state_wire = state.sign(signing).map_err(internal)?;
        self.account = AccountPart {
            state,
            state_wire,
            certificates,
            revocations,
            all_certificates,
            all_revocations,
            grants,
        };
        Ok(())
    }

    /// The kind-4 revocations of a full rotation (CRYPTO.md §11.6 step 7), as (device, H): every
    /// web-vault certificate of the base that has not expired, is not this device's, is not
    /// revoked in `revoked_before` and is not [`RotationOptions::revoke`]'s target (which has
    /// its own H), with H the highest head this device holds from it over `vaults` after its
    /// complete Fetch. Empty for a standard rotation.
    fn web_revocation_heads(
        &self,
        revoked_before: &BTreeSet<DeviceId>,
        vaults: &[&VaultSync],
    ) -> Vec<(DeviceId, u64)> {
        if self.level != RotationLevel::Full {
            return Vec::new();
        }
        let target = self.revoke.map(|t| t.device_id);
        self.certificates
            .iter()
            .map(|cert| &cert.certificate)
            .filter(|c| {
                c.device_kind == DeviceKind::WebEphemeral
                    && c.expires_at_ms > self.now_ms
                    && c.device_id != self.device_id
                    && Some(c.device_id) != target
                    && !revoked_before.contains(&c.device_id)
            })
            .map(|c| {
                let head = vaults
                    .iter()
                    .map(|v| v.cursor_of(c.device_id))
                    .max()
                    .unwrap_or(0);
                (c.device_id, head)
            })
            .collect()
    }

    /// Re-signs the kind-4 revocations of the current attempt with H from `vaults` (ADR 0025 §2
    /// step 5, same position). A web-vault device is not in `device_set_hash` (CRYPTO.md §10.2
    /// "Device set"), so its uploads leave `account-state` unchanged, while the server refuses a
    /// revocation whose H is not the current head. The state bytes do not change: the set hash
    /// depends on the revoked device ids only, which stay the same.
    fn refresh_web_revocations(&mut self, vaults: &[&VaultSync]) -> Result<(), ClientError> {
        let revoked_before: BTreeSet<DeviceId> = self
            .revocations
            .iter()
            .map(|r| r.revocation.device_id)
            .collect();
        let signing = self.signer.signing_key();
        let verifying = *signing.verifying_key();
        let mut fresh = Vec::new();
        for (device_id, head) in self.web_revocation_heads(&revoked_before, vaults) {
            let statement = DeviceRevocation {
                account_id: self.account_id,
                device_id,
                last_accepted_device_seq: head,
                revoked_at_ms: self.now_ms,
            };
            let wire = statement.sign(signing).map_err(internal)?;
            let revocation = DeviceRevocation::verify(&wire, &verifying).map_err(internal)?;
            fresh.push(RevokedDevice { revocation, wire });
        }
        for new in fresh {
            let device_id = new.revocation.device_id;
            for list in [
                &mut self.account.revocations,
                &mut self.account.all_revocations,
            ] {
                let slot = list
                    .iter_mut()
                    .find(|r| r.revocation.device_id == device_id)
                    .ok_or(ClientError::Internal)?;
                *slot = new.clone();
            }
        }
        Ok(())
    }

    /// The vault halves of an attempt, from `vaults` (ascending by id, one per new vault key).
    fn build_vaults<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        vaults: &[&VaultSync],
    ) -> Result<(), ClientError> {
        if vaults.len() != self.new_vault_keys.len() {
            return Err(ClientError::InvalidInput);
        }
        let mut halves = Vec::with_capacity(vaults.len());
        let mut dropped = Vec::new();
        for (vault, key) in vaults.iter().zip(&self.new_vault_keys) {
            if vault.vault_id() != key.vault_id() {
                return Err(ClientError::InvalidInput);
            }
            let half = vault.rotation_half(rng, self.account_id, &self.new_account_key, key)?;
            dropped.extend(half.dropped_items.iter().map(|i| (key.vault_id(), *i)));
            halves.push(half.rotation);
        }
        self.vaults = halves;
        self.dropped_items = dropped;
        Ok(())
    }

    /// The request of the current attempt.
    fn assemble(&mut self) -> Result<(), ClientError> {
        let statements = |v: &[CertifiedDevice]| {
            List::new(
                v.iter()
                    .map(|c| bytes(c.wire.clone()))
                    .collect::<Result<Vec<_>, _>>()?,
            )
            .map_err(internal)
        };
        let revocations = List::new(
            self.account
                .revocations
                .iter()
                .map(|r| bytes(r.wire.clone()))
                .collect::<Result<Vec<_>, _>>()?,
        )
        .map_err(internal)?;
        self.request = CommitChangeRequest {
            account_state: bytes(self.account.state_wire.clone())?,
            registration_upload: self
                .credential
                .as_ref()
                .map(|c| c.registration_upload.clone()),
            account_key_server_wrap: Some(self.built.e_srv.clone()),
            recovery: self.built.recovery.clone(),
            account_settings: self.built.settings.clone(),
            device_certificates: statements(&self.account.certificates)?,
            device_revocations: revocations,
            bundle: match &self.built.bundle {
                Some((wire, _)) => Some(bytes(wire.clone())?),
                None => None,
            },
            identity_secret_keys: Some(self.built.e_id.clone()),
            retired_secret_keys: List::new(self.built.retired.clone()).map_err(internal)?,
            device_grants: List::new(self.account.grants.clone()).map_err(internal)?,
            recovery_rewrap: self.built.recovery_rewrap.clone(),
            vault_rotation: Some(VaultRotationUpload::new(self.vaults.clone()).map_err(internal)?),
        };
        Ok(())
    }

    /// Handles a `state_conflict` answer (module docs, "Retries"). `view` is the account answer
    /// to [`PendingRotation::state_query`] over this rotation's session; `vaults` are the
    /// account's vaults after a complete Fetch each.
    ///
    /// # Errors
    /// [`ClientError::Rollback`], [`ClientError::Fork`]: go read-only;
    /// [`ClientError::RotationRestart`]: discard this rotation and start again;
    /// [`ClientError::VaultKeepsChanging`] after [`MAX_REBUILDS`] rebuilds (the pending
    /// rotation stays usable); [`ClientError::SyncRequired`], [`ClientError::InvalidInput`] and
    /// [`ClientError::InvalidServerResponse`] as for [`start_rotation`].
    pub fn on_state_conflict<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        view: &AccountView,
        unlocked: &UnlockedDevice,
        vaults: &[&VaultSync],
    ) -> Result<ConflictOutcome, ClientError> {
        if unlocked.account_id != self.account_id || unlocked.device_id != self.device_id {
            return Err(ClientError::InvalidInput);
        }
        if view.account_state.as_slice() == self.account.state_wire.as_slice() {
            return Ok(ConflictOutcome::Committed);
        }
        let public = match verify_public(
            view,
            self.account_id,
            &Anchor::Enrolled {
                pin: &self.base,
                confirmed: None,
            },
            None,
        ) {
            Ok(public) => public,
            // An identity change elsewhere is a change this rotation cannot absorb.
            Err(ClientError::IdentityChangeUnconfirmed) => {
                return Err(ClientError::RotationRestart);
            }
            Err(e) => return Err(e),
        };
        let same_position = public.state.state_seq == self.base.state.state_seq;
        match self.base.state.cas_retry(&public.state) {
            CasRetry::Rollback => return Err(ClientError::Rollback),
            CasRetry::Fork => return Err(ClientError::Fork),
            CasRetry::Restart => return Err(ClientError::RotationRestart),
            CasRetry::Reapply => {}
        }
        if self.rebuilds >= MAX_REBUILDS {
            return Err(ClientError::VaultKeepsChanging);
        }
        let account_vaults: BTreeSet<VaultId> =
            self.new_vault_keys.iter().map(VaultKey::vault_id).collect();
        let ordered_vaults = ordered(&account_vaults, vaults)?;
        if same_position {
            // Same position: the signed state stays, but a web-vault device may have uploaded
            // since (it does not move `account-state`), so the kind-4 revocations take the new H.
            self.refresh_web_revocations(&ordered_vaults)?;
        } else {
            // Only `state_seq` and `device_set_hash` moved: rebuild the grants on the new set.
            self.base = AccountPin {
                bundle: public.bundle,
                state: public.state,
                state_wire: public.state_wire,
                settings: public.settings,
            };
            self.certificates = public.certificates;
            self.revocations = public.revocations;
            self.build_account(rng, unlocked, &ordered_vaults)?;
        }
        self.build_vaults(rng, &ordered_vaults)?;
        self.assemble()?;
        self.rebuilds += 1;
        Ok(ConflictOutcome::Resend)
    }

    /// After the server acknowledged the commit (or [`ConflictOutcome::Committed`]): re-wraps
    /// `E_local` and `E_dev` under the new account key, pins the new state (and bundle), moves
    /// the new account key into `unlocked` and each new vault key into its [`VaultSync`] (CRYPTO.md
    /// §11 "Secrets before commit" step 5).
    ///
    /// `E_local'` needs the local unlock key: the one `unlocked` kept from the password unlock,
    /// or else one derived again from this re-authentication's password (one Argon2id run).
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] for another device's state or a vault set that is not the
    /// rotated one; the errors of [`VaultSync::adopt_vault_key`]; [`ClientError::Internal`].
    pub fn finalize<R: CryptoRng + ?Sized>(
        mut self,
        rng: &mut R,
        device: &mut DeviceState,
        unlocked: &mut UnlockedDevice,
        vaults: &mut [&mut VaultSync],
    ) -> Result<RotationDone, ClientError> {
        if device.device_id != self.device_id
            || unlocked.device_id != self.device_id
            || device.account_id != self.account_id
            || vaults.len() != self.new_vault_keys.len()
            || !self
                .new_vault_keys
                .iter()
                .all(|k| vaults.iter().any(|v| v.vault_id() == k.vault_id()))
        {
            return Err(ClientError::InvalidInput);
        }
        // A credential change needs `E_local'` under the new password: the one the pending
        // record holds, built now if the host kept none.
        if self.credential.is_some() {
            self.prepare(rng, device, unlocked)?;
        }
        if let Some((local_wrap, device_keys_wrap)) = self.prepared.take() {
            // The envelopes the pending record holds on disk: the finalised state is those
            // bytes, not a second wrap of the same key.
            device.local_wrap = local_wrap;
            device.device_keys_wrap = device_keys_wrap;
        } else {
            let derived;
            let local = if let Some(local) = unlocked.local_unlock_key.as_ref() {
                local
            } else {
                derived = self
                    .pw_in
                    .local_unlock_key(
                        &device.device_salt,
                        device.kdf_id,
                        device.account_id,
                        device.device_id,
                    )
                    .map_err(internal)?;
                &derived
            };
            device.rewrap(rng, local, &self.new_account_key, &unlocked.device_keys)?;
        }
        if let Some(credential) = self.credential.take() {
            credential.apply(device, unlocked);
        }
        device.pin = AccountPin {
            bundle: match self.built.bundle {
                Some((_, bundle)) => bundle,
                None => self.base.bundle,
            },
            state: self.account.state,
            state_wire: self.account.state_wire,
            settings: self.built.settings.or(self.base.settings),
        };
        unlocked.account_key = self.new_account_key;
        for key in self.new_vault_keys {
            let vault = vaults
                .iter_mut()
                .find(|v| v.vault_id() == key.vault_id())
                .ok_or(ClientError::InvalidInput)?;
            vault.adopt_vault_key(key)?;
        }
        Ok(RotationDone {
            authors: Authors::from_statements(
                &self.account.all_certificates,
                &self.account.all_revocations,
            )?,
            dropped_items: self.dropped_items,
        })
    }
}

/// `E_rec'` for a rotation that keeps the current recovery code (CRYPTO.md §11.6 step 5): the
/// wrap key derived from the typed code, the new `account_key_epoch`, the unchanged
/// `recovery_epoch`. The code's format and check characters are verified first, so a typo is
/// caught here rather than leaving an `E_rec'` no code opens.
fn keep_recovery_code<R: CryptoRng + ?Sized>(
    rng: &mut R,
    account_id: AccountId,
    state: &AccountState,
    new_account_key: &AccountKey,
    text: &str,
) -> Result<AccountKeyRecoveryWrap, ClientError> {
    let code = RecoveryCode::parse(text).map_err(|_| ClientError::InvalidInput)?;
    let new_epoch = new_account_key.epoch();
    let envelope = code
        .wrap_key()
        .map_err(internal)?
        .wrap_account_key(
            rng,
            &AccountKeyRecoveryWrapCtx {
                account_id,
                account_key_epoch: new_epoch,
                recovery_epoch: state.recovery_epoch,
            },
            new_account_key,
        )
        .map_err(internal)?;
    Ok(AccountKeyRecoveryWrap {
        account_key_epoch: new_epoch,
        recovery_epoch: state.recovery_epoch,
        envelope: bytes(envelope)?,
    })
}

/// `E_rec'` and `H_rec'` of a new recovery code `code` (CRYPTO.md §11.6 step 5, the default
/// and, after a Secret Key change, the only choice): the new `account_key_epoch` and
/// `recovery_epoch + 1`, as at recovery (§11.9 step 5).
fn issue_recovery_code<R: CryptoRng + ?Sized>(
    rng: &mut R,
    account_id: AccountId,
    state: &AccountState,
    new_account_key: &AccountKey,
    code: &RecoveryCode,
) -> Result<RecoveryRegistration, ClientError> {
    let new_epoch = new_account_key.epoch();
    let recovery_epoch = state
        .recovery_epoch
        .checked_add(1)
        .ok_or(ClientError::Internal)?;
    let envelope = code
        .wrap_key()
        .map_err(internal)?
        .wrap_account_key(
            rng,
            &AccountKeyRecoveryWrapCtx {
                account_id,
                account_key_epoch: new_epoch,
                recovery_epoch,
            },
            new_account_key,
        )
        .map_err(internal)?;
    Ok(RecoveryRegistration {
        recovery_wrap: AccountKeyRecoveryWrap {
            account_key_epoch: new_epoch,
            recovery_epoch,
            envelope: bytes(envelope)?,
        },
        recovery_token_hash: Fixed::from_bytes(code.auth_token().map_err(internal)?.server_hash()),
    })
}

/// `ACCOUNT_SETTINGS` re-encrypted under the new account key with `settings_seq + 1`
/// (CRYPTO.md §11.6 step 3); `None` while `settings_seq = 0`, which stays 0.
pub(crate) fn reencrypt_settings<R: CryptoRng + ?Sized>(
    rng: &mut R,
    base: &AccountPin,
    old_account_key: &AccountKey,
    new_account_key: &AccountKey,
) -> Result<Option<AccountSettings>, ClientError> {
    let seq = base.state.settings_seq;
    if seq == 0 {
        return Ok(None);
    }
    let account_id = base.state.account_id;
    let held = base
        .settings
        .as_ref()
        .ok_or(ClientError::InvalidServerResponse)?;
    let plaintext = open(
        old_account_key.key(),
        &AccountSettingsCtx {
            account_id,
            settings_seq: seq,
        },
        held.envelope.as_slice(),
    )
    .map_err(|_| ClientError::InvalidServerResponse)?;
    let next = seq.checked_add(1).ok_or(ClientError::Internal)?;
    let envelope = seal(
        rng,
        new_account_key.key(),
        &AccountSettingsCtx {
            account_id,
            settings_seq: next,
        },
        plaintext.expose_secret(),
    )
    .map_err(internal)?;
    Ok(Some(AccountSettings {
        settings_seq: next,
        envelope: bytes(envelope)?,
    }))
}

/// The identity change of a full rotation (CRYPTO.md §11.6 steps 2, 3 and 7): the new bundle
/// (`bundle_seq + 1`, signed by the new and the old identity key, checked as the predecessor's
/// successor), and the old identity X25519 key retired under the new account key. The old
/// identity keys are consumed: the signing key is wiped, the X25519 key moves into the
/// `RETIRED_SECRET_KEY`.
fn change_identity<R: CryptoRng + ?Sized>(
    rng: &mut R,
    predecessor: &VerifiedBundle,
    old_identity: IdentityKeys,
    new_identity: &IdentityKeys,
    new_account_key: &AccountKey,
    now_ms: u64,
) -> Result<((Vec<u8>, VerifiedBundle), RetiredSecretKey), ClientError> {
    let keys = new_identity.public_keys();
    let account_id = predecessor.account_id;
    let next = PublicKeyBundle {
        account_id,
        identity_epoch: new_identity.epoch(),
        bundle_seq: predecessor
            .bundle_seq
            .checked_add(1)
            .ok_or(ClientError::Internal)?,
        identity_ed25519: keys.ed25519,
        identity_x25519: keys.x25519,
        mail_x25519: predecessor.mail_x25519,
        pq_required: predecessor.pq_required,
        created_at_ms: now_ms,
        prev_bundle_hash: *predecessor.hash(),
    };
    let wire = next
        .sign_identity_change(
            predecessor,
            new_identity.signing_key(),
            old_identity.signing_key(),
        )
        .map_err(internal)?;
    let Ok((verified, BundleStep::IdentityChanged)) = predecessor.verify_successor(&wire) else {
        return Err(ClientError::Internal);
    };
    let retired_key = old_identity.into_retired_x25519().map_err(internal)?;
    let retired_key_id = retired_key.public_key_id();
    let envelope = new_account_key
        .wrap_retired_key(
            rng,
            &RetiredSecretKeyCtx {
                account_id,
                retired_key_id,
            },
            &retired_key,
        )
        .map_err(internal)?;
    Ok((
        (wire, verified),
        RetiredSecretKey {
            retired_key_id: id(*retired_key_id.as_bytes()),
            envelope: bytes(envelope)?,
        },
    ))
}

impl PendingRotation {
    /// The pending record of this rotation (CRYPTO.md §11 "Secrets before commit" step 3;
    /// ADR 0026 §2 "Pending record"): the Secret Key, salt and `kdf_id` after the commit
    /// (unchanged, unless a credential change rides with the rotation), the new account key as
    /// `E_local'` under the local unlock key of the password that is current after the commit,
    /// and `E_dev'`. The host stores it with the commit's JSON body
    /// ([`crate::store::pending_writes`]) before it sends the commit;
    /// [`PendingRotation::finalize`] then adopts exactly these envelopes, so the state on disk
    /// after a crash and the state after the commit are the same bytes.
    ///
    /// Without a credential change, `E_local'` needs the local unlock key: the one `unlocked`
    /// kept from the password unlock, or else one derived again from the re-authentication's
    /// password (one Argon2id run). With one, the new password's key is derived once (one
    /// Argon2id run, CRYPTO.md §11.5 "Argon2id runs").
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] for another device's state; [`ClientError::Internal`].
    pub fn pending_record<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        device: &DeviceState,
        unlocked: &UnlockedDevice,
    ) -> Result<PendingRecord, ClientError> {
        self.prepare(rng, device, unlocked)?;
        let (local_wrap, device_keys_wrap) = self.prepared.clone().ok_or(ClientError::Internal)?;
        let (secret_key, device_salt, kdf_id) = match &self.credential {
            Some(credential) => (
                &credential.secret_key,
                credential.device_salt,
                credential.kdf_id,
            ),
            None => (&device.secret_key, device.device_salt, device.kdf_id),
        };
        Ok(PendingRecord {
            secret_key: SecretKey::from_slice(secret_key.expose_secret()).map_err(internal)?,
            device_salt,
            kdf_id,
            local_wrap,
            device_keys_wrap: Some(device_keys_wrap),
        })
    }

    /// Builds `E_local'` and `E_dev'` once ([`PendingRotation::pending_record`]).
    fn prepare<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        device: &DeviceState,
        unlocked: &UnlockedDevice,
    ) -> Result<(), ClientError> {
        if device.device_id != self.device_id
            || unlocked.device_id != self.device_id
            || device.account_id != self.account_id
        {
            return Err(ClientError::InvalidInput);
        }
        if self.prepared.is_some() {
            return Ok(());
        }
        let local_wrap = if let Some(credential) = self.credential.as_mut() {
            credential.local_wrap(
                rng,
                device.account_id,
                device.device_id,
                &self.new_account_key,
            )?
        } else {
            let derived;
            let local = if let Some(local) = unlocked.local_unlock_key.as_ref() {
                local
            } else {
                derived = self
                    .pw_in
                    .local_unlock_key(
                        &device.device_salt,
                        device.kdf_id,
                        device.account_id,
                        device.device_id,
                    )
                    .map_err(internal)?;
                &derived
            };
            wrap_local(
                rng,
                local,
                device.account_id,
                device.device_id,
                device.kdf_id,
                &self.new_account_key,
                device.local_password_epoch(),
            )?
        };
        let device_keys_wrap = self
            .new_account_key
            .wrap_device_keys(
                rng,
                &DeviceSecretKeysCtx {
                    account_id: device.account_id,
                    device_id: device.device_id,
                },
                &unlocked.device_keys,
            )
            .map_err(internal)?;
        self.prepared = Some((local_wrap, device_keys_wrap));
        Ok(())
    }

    /// The cache writes of the state this rotation commits (ADR 0026 §4 step 3): the new
    /// `account-state`, the new bundle of a full rotation, the settings, the device set after
    /// the change, `E_id'`, and per vault the new self-grant with the re-wrapped wrap set, so
    /// the wraps on disk open under the vault key on disk. The host appends them to
    /// [`crate::store::finalize_writes`] in the transaction that finalises the commit; call it
    /// before [`PendingRotation::finalize`], which consumes the rotation.
    ///
    /// # Errors
    /// [`ClientError::Internal`].
    pub fn store_writes(&self) -> Result<Changeset, ClientError> {
        let pin = AccountPin {
            bundle: match &self.built.bundle {
                Some((_, bundle)) => bundle.clone(),
                None => self.base.bundle.clone(),
            },
            state: self.account.state.clone(),
            state_wire: self.account.state_wire.clone(),
            settings: self
                .built
                .settings
                .clone()
                .or_else(|| self.base.settings.clone()),
        };
        let mut self_grants = Vec::with_capacity(self.vaults.len());
        for (vault, key) in self.vaults.iter().zip(&self.new_vault_keys) {
            let key_id = *key.key_id().map_err(internal)?.as_bytes();
            self_grants.push((vault.self_grant.clone(), key_id));
        }
        let served = ServedObjects {
            bundles: self
                .built
                .bundle
                .iter()
                .map(|(wire, bundle)| (bundle.bundle_seq, wire.clone()))
                .collect(),
            identity_secret_keys: Some(self.built.e_id.clone()),
            self_grants,
        };
        let mut changeset = store::object_writes(
            &pin,
            &self.account.all_certificates,
            &self.account.all_revocations,
            &served,
        );
        for (vault, key) in self.vaults.iter().zip(&self.new_vault_keys) {
            changeset.push(Write::Wraps {
                vault_id: key.vault_id().to_bytes(),
                epoch: key.epoch(),
                wraps: wrap_rows(key.vault_id(), key.epoch(), vault.item_key_wraps.as_slice()),
            });
        }
        Ok(changeset)
    }
}
