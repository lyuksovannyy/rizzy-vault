//! Opening and loading a cache ([ADR 0026] §4 steps 5 and 7, §5).
//!
//! The file is untrusted input: it is read back from a place anyone with the user's rights can
//! write, and a tampered file must be detected like a malicious server. So the load is two
//! steps, neither of which trusts a column:
//!
//! 1. [`open`]: no key needed. The cache format, every `cache_meta` row, and the device-state
//!    record ([`DeviceRecord::parse`]); the record must name the account, device and origin of
//!    `cache_meta`, and a pending record or a signup-pending stage must come with
//!    `pending_commit`, and only then.
//! 2. The host runs the offline unlock ([`DeviceRecord::unlock`], one Argon2id run), then
//!    [`load`]: every account object is verified as a new device verifies a login answer
//!    (`E_id` under the account key `E_local` gave, the bundle whose keys are those of `E_id`,
//!    the `account-state` under that bundle's identity key, the device set against
//!    `device_set_hash`, the settings against `settings_hash`, every self-grant under the
//!    account key), and every vault is rebuilt through the checks of a Fetch
//!    (`VaultSync::restore`).
//!
//! # How a failure shows (§5)
//!
//! - (a) a missing table or meta key, an unknown format: [`ClientError::CacheCorrupt`] or
//!   [`ClientError::CacheUpdateRequired`] from [`open`]; nothing is read or written.
//! - (b) the record does not parse: [`ClientError::CacheCorrupt`] from [`open`].
//! - (c) `E_local` does not open: [`ClientError::WrongPasswordOrSecretKey`] from the unlock.
//! - (d) `E_dev`, an account object, a statement, a column or an own row fails:
//!   [`ClientError::CacheCorrupt`]; the load fails as a whole, no partial vault is returned.
//! - (e) a body, snapshot envelope or wrap fails under a statement that verified: missing
//!   data, the load stands.
//!
//! No case panics, and none is retried with a check relaxed. The fuzz target
//! `client_cache_load` runs [`open`] and [`load`] over arbitrary and mutated rows.
//!
//! # Alarms
//!
//! An alarm row makes every loaded vault read-only ([`Loaded::alarms`]); a restart never lifts
//! read-only mode (§4 step 4).
//!
//! [ADR 0026]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0026-client-device-state-and-cache.md

use std::collections::BTreeSet;

use core::fmt;

use rizzy_core::ids::VaultId;
use rizzy_core::sign::PublicKeyBundle;
use rizzy_proto::account::AccountView;
use rizzy_proto::limits::{MAX_ENVELOPE_LEN, MAX_UPLOAD_BODY_LEN};
use rizzy_proto::objects::{AccountSettings, IdentitySecretKeys, ItemKeyWrap};
use rizzy_proto::wire::{Bytes, Id, List};
use rizzy_sync::causal::RestoreGeneration;

use crate::account::{Anchor, VerifiedAccount, verify_account_view};
use crate::device::{DeviceState, UnlockedDevice};
use crate::error::ClientError;
use crate::store::floors::{Floors, id16, u64_be};
use crate::store::record::{DeviceRecord, Stage};
use crate::store::rows::{Alarm, CACHE_FORMAT, CacheRows, ObjectRow, kind, meta};
use crate::sync::{Authors, VaultImage, VaultSync};

/// A cache that loaded in full (module docs).
pub struct Loaded {
    /// The device state, with the pin rebuilt from the verified account objects.
    pub device: DeviceState,
    /// The verified account: the state, certificates and revocations the cache holds.
    pub account: VerifiedAccount,
    /// The authors of the account, for the vaults' next Fetch.
    pub authors: Authors,
    /// One driver per vault, with the cache journal on; read-only while an alarm is raised.
    pub vaults: Vec<VaultSync>,
    /// The alarms the cache holds.
    pub alarms: BTreeSet<Alarm>,
    /// The floors of the loaded rows, for [`Floors::admit`].
    pub floors: Floors,
}

impl fmt::Debug for Loaded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Loaded")
            .field("device", &self.device)
            .field("vaults", &self.vaults.len())
            .field("alarms", &self.alarms)
            .finish_non_exhaustive()
    }
}

/// Step 1 of the load (module docs): the format, the meta rows and the device-state record.
///
/// # Errors
/// [`ClientError::CacheUpdateRequired`] for a cache format or record version this build does
/// not know; [`ClientError::CacheCorrupt`].
pub fn open(rows: &CacheRows) -> Result<DeviceRecord, ClientError> {
    let corrupt = ClientError::CacheCorrupt;
    let format = rows.meta.get(meta::FORMAT).ok_or(corrupt)?;
    let format = u16::from_be_bytes(format.as_slice().try_into().map_err(|_| corrupt)?);
    if format > CACHE_FORMAT {
        return Err(ClientError::CacheUpdateRequired);
    }
    if format != CACHE_FORMAT {
        return Err(corrupt);
    }
    // Every key of this format, and no other.
    if rows.meta.len() != meta::ALL.len() || !meta::ALL.iter().all(|k| rows.meta.contains_key(*k)) {
        return Err(corrupt);
    }
    let record = DeviceRecord::parse(rows.device_state.as_ref().ok_or(corrupt)?)?;
    let meta_is = |key: &str, value: &[u8]| rows.meta.get(key).is_some_and(|held| held == value);
    if !meta_is(meta::ACCOUNT_ID, record.account_id().as_bytes())
        || !meta_is(meta::DEVICE_ID, record.device_id().as_bytes())
        || !meta_is(
            meta::SERVER_ORIGIN,
            record.server_origin().as_str().as_bytes(),
        )
    {
        return Err(corrupt);
    }
    let next_device_seq = u64_be(rows.meta.get(meta::NEXT_DEVICE_SEQ).ok_or(corrupt)?)?;
    u64_be(rows.meta.get(meta::HLC).ok_or(corrupt)?)?;
    if next_device_seq == 0 {
        return Err(corrupt);
    }
    // A pending record or a pending signup and the stored commit are written and removed
    // together (§4 step 3).
    let outstanding = record.has_pending() || record.stage() == Stage::SignupPending;
    match &rows.pending_commit {
        Some(request)
            if outstanding && !request.is_empty() && request.len() <= MAX_UPLOAD_BODY_LEN => {}
        None if !outstanding => {}
        _ => return Err(corrupt),
    }
    Ok(record)
}

/// The rows of one `account_objects` kind, ascending by key.
fn objects_of(rows: &CacheRows, kind: i64) -> Vec<&ObjectRow> {
    let mut out: Vec<&ObjectRow> = rows.objects.iter().filter(|o| o.kind == kind).collect();
    out.sort_by(|a, b| a.key.cmp(&b.key));
    out
}

/// A bounded wire byte string from a row's blob: the length check before any parse (§3).
fn bounded<const N: usize>(bytes: &[u8]) -> Result<Bytes<N>, ClientError> {
    Bytes::from_slice(bytes).map_err(|_| ClientError::CacheCorrupt)
}

/// The account view the rows hold: what the server would serve a new device (module docs).
fn account_view(rows: &CacheRows) -> Result<AccountView, ClientError> {
    let corrupt = ClientError::CacheCorrupt;
    if rows
        .objects
        .iter()
        .any(|o| !(kind::BUNDLE..=kind::ALARM).contains(&o.kind))
    {
        return Err(corrupt);
    }
    let statements = |kind: i64| {
        objects_of(rows, kind)
            .into_iter()
            .map(|o| bounded(&o.bytes))
            .collect::<Result<Vec<_>, _>>()
    };
    let state = match objects_of(rows, kind::ACCOUNT_STATE).as_slice() {
        [one] if one.key.is_empty() => bounded(&one.bytes)?,
        _ => return Err(corrupt),
    };
    // The newest `E_id` and the newest settings: keys are big-endian, so the last row.
    let identity = objects_of(rows, kind::IDENTITY_KEYS);
    let identity = identity.last().ok_or(corrupt)?;
    let identity_secret_keys = IdentitySecretKeys {
        identity_epoch: u32::from_be_bytes(
            identity.key.as_slice().try_into().map_err(|_| corrupt)?,
        ),
        envelope: bounded(&identity.bytes)?,
    };
    let account_settings = match objects_of(rows, kind::SETTINGS).last() {
        None => None,
        Some(row) => {
            if row.bytes.len() > MAX_ENVELOPE_LEN {
                return Err(corrupt);
            }
            Some(AccountSettings {
                settings_seq: u64_be(&row.key)?,
                envelope: bounded(&row.bytes)?,
            })
        }
    };
    let mut grants = Vec::with_capacity(rows.vaults.len());
    let mut vault_rows: Vec<_> = rows.vaults.iter().collect();
    vault_rows.sort_by(|a, b| a.vault_id.cmp(&b.vault_id));
    for vault in vault_rows {
        // The column is an index: it must name the vault the grant names.
        if id16(&vault.vault_id)? != vault.self_grant.vault_id.to_bytes()
            || vault.wraps_after_epoch.is_some()
        {
            return Err(corrupt);
        }
        grants.push(vault.self_grant.clone());
    }
    Ok(AccountView {
        account_state: state,
        bundles: List::new(statements(kind::BUNDLE)?).map_err(|_| corrupt)?,
        device_certificates: List::new(statements(kind::CERTIFICATE)?).map_err(|_| corrupt)?,
        device_revocations: List::new(statements(kind::REVOCATION)?).map_err(|_| corrupt)?,
        account_settings,
        identity_secret_keys,
        vault_self_grants: List::new(grants).map_err(|_| corrupt)?,
    })
}

/// The column checks of the account objects (§3 "Columns are indexes, never facts"): each
/// bundle row's key is its `bundle_seq`, each certificate and revocation row's key is its
/// `device_id`, and an alarm's key is an alarm kind.
fn check_object_columns(
    rows: &CacheRows,
    account: &VerifiedAccount,
) -> Result<BTreeSet<Alarm>, ClientError> {
    let corrupt = ClientError::CacheCorrupt;
    for row in objects_of(rows, kind::BUNDLE) {
        let bundle = PublicKeyBundle::verify_self_signed(&row.bytes).map_err(|_| corrupt)?;
        if u64_be(&row.key)? != bundle.bundle_seq || bundle.account_id != account.account_id() {
            return Err(corrupt);
        }
    }
    let certificates = objects_of(rows, kind::CERTIFICATE);
    if certificates.len() != account.certificates().len() {
        return Err(corrupt);
    }
    for (row, verified) in certificates.iter().zip(account.certificates()) {
        if row.key != verified.certificate.device_id.to_bytes() || row.bytes != verified.wire {
            return Err(corrupt);
        }
    }
    let revocations = objects_of(rows, kind::REVOCATION);
    if revocations.len() != account.revocations().len() {
        return Err(corrupt);
    }
    for (row, verified) in revocations.iter().zip(account.revocations()) {
        if row.key != verified.revocation.device_id.to_bytes() || row.bytes != verified.wire {
            return Err(corrupt);
        }
    }
    // Settings and `E_id` rows other than the newest are history; their keys are still read.
    for row in objects_of(rows, kind::SETTINGS) {
        u64_be(&row.key)?;
    }
    for row in objects_of(rows, kind::IDENTITY_KEYS) {
        if row.key.len() != 4 {
            return Err(corrupt);
        }
    }
    let mut alarms = BTreeSet::new();
    for row in objects_of(rows, kind::ALARM) {
        let alarm = match row.key.as_slice() {
            [key] => Alarm::from_u8(*key).ok_or(corrupt)?,
            _ => return Err(corrupt),
        };
        alarms.insert(alarm);
    }
    Ok(alarms)
}

/// Step 2 of the load (module docs). `record` is what [`open`] returned for these rows and
/// `unlocked` what [`DeviceRecord::unlock`] returned for it; `now_ms` is the host's wall clock,
/// for the HLC receive rule.
///
/// # Errors
/// [`ClientError::SignupPending`] and [`ClientError::LocalUnlockUnavailable`] for a record
/// that does not unlock; [`ClientError::InvalidInput`] if `unlocked` is another device's;
/// [`ClientError::CacheCorrupt`] for everything else (§5 (d)).
pub fn load(
    rows: &CacheRows,
    record: &DeviceRecord,
    unlocked: &UnlockedDevice,
    now_ms: u64,
) -> Result<Loaded, ClientError> {
    let corrupt = ClientError::CacheCorrupt;
    if record.stage() == Stage::SignupPending {
        return Err(ClientError::SignupPending);
    }
    if unlocked.account_id() != record.account_id() || unlocked.device_id() != record.device_id() {
        return Err(ClientError::InvalidInput);
    }
    let view = account_view(rows)?;
    let mut account = verify_account_view(
        &view,
        record.account_id(),
        &unlocked.account_key,
        &Anchor::NewDevice,
    )
    .map_err(|_| corrupt)?;
    let alarms = check_object_columns(rows, &account)?;
    let authors = Authors::from_account(&account).map_err(|_| corrupt)?;
    let next_device_seq = u64_be(rows.meta.get(meta::NEXT_DEVICE_SEQ).ok_or(corrupt)?)?;
    let hlc = u64_be(rows.meta.get(meta::HLC).ok_or(corrupt)?)?;

    let mut vault_ids: Vec<VaultId> = account.vault_ids().collect();
    vault_ids.sort();
    // Every row belongs to a vault the account holds a self-grant for.
    let known =
        |vault_id: &[u8]| id16(vault_id).map(|id| vault_ids.iter().any(|v| v.to_bytes() == id));
    for vault_id in rows
        .wraps
        .iter()
        .map(|w| &w.vault_id)
        .chain(rows.ops.iter().map(|o| &o.vault_id))
        .chain(rows.snapshots.iter().map(|s| &s.vault_id))
    {
        if !known(vault_id)? {
            return Err(corrupt);
        }
    }
    let mut vaults = Vec::with_capacity(vault_ids.len());
    let mut vault_keys = Vec::with_capacity(vault_ids.len());
    for vault_id in vault_ids {
        let id_bytes = vault_id.to_bytes();
        let row = rows
            .vaults
            .iter()
            .find(|v| v.vault_id == id_bytes)
            .ok_or(corrupt)?;
        let key = account.take_vault_key(vault_id).ok_or(corrupt)?;
        vault_keys.push((id_bytes, *key.key_id().map_err(|_| corrupt)?.as_bytes()));
        let mut wraps = Vec::new();
        for wrap in rows.wraps.iter().filter(|w| w.vault_id == id_bytes) {
            wraps.push(ItemKeyWrap {
                item_id: Id::from_bytes(id16(&wrap.item_id)?),
                item_key_id: Id::from_bytes(id16(&wrap.item_key_id)?),
                vault_key_epoch: u32::try_from(wrap.vault_key_epoch).map_err(|_| corrupt)?,
                envelope: bounded(&wrap.envelope)?,
            });
        }
        let image = VaultImage {
            next_device_seq,
            hlc,
            generation: row
                .restore_generation
                .as_ref()
                .map(|g| id16(g).map(RestoreGeneration::from_bytes))
                .transpose()?,
            wraps,
            ops: rows.ops.iter().filter(|o| o.vault_id == id_bytes).collect(),
            snapshots: rows
                .snapshots
                .iter()
                .filter(|s| s.vault_id == id_bytes)
                .collect(),
        };
        let mut vault = VaultSync::restore(key, unlocked, &authors, &image, now_ms)?;
        if !alarms.is_empty() {
            vault.set_read_only(true);
        }
        vaults.push(vault);
    }
    let state = account.state();
    let floors = Floors::of_rows(rows, (state.state_seq, state.settings_seq), &vault_keys)?;
    let device = record.to_state(account.pin().clone())?;
    Ok(Loaded {
        device,
        account,
        authors,
        vaults,
        alarms,
        floors,
    })
}
