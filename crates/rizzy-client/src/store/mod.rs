//! The persistent device state and encrypted local cache ([ADR 0026]): the record codec, the
//! row model, the schema, the changeset each step returns, the floors that never go backwards,
//! and the load.
//!
//! "`rizzy-client` owns all of this … The leaves run it" (ADR 0026 §4): this crate does no
//! I/O, so a host (`rv` with sqlx in M1) executes [`rows::SCHEMA`], runs every
//! [`rows::Changeset`] as one transaction after [`floors::Floors::admit`] accepted it, and
//! reads the tables back into [`rows::CacheRows`] for [`load::open`] and [`load::load`].
//!
//! | Module | ADR 0026 | Purpose |
//! |---|---|---|
//! | [`record`] | §2 | The device-state record, version 1 |
//! | [`rows`] | §3 | Schema text, row model, writes, the reference executor |
//! | [`floors`] | §4 "What never goes backwards" | The check every changeset passes |
//! | [`load`] | §4 steps 5 and 7, §5 | Opening and loading a cache as untrusted input |
//!
//! # What is persisted, and what never is (§1)
//!
//! Persisted: the device-state record; the account objects as served (bundles, the newest
//! verified `account-state`, `ACCOUNT_SETTINGS`, certificates, revocations, `E_id`, alarms);
//! per vault the self-grant, the wrap set and the last restore generation; every accepted op
//! statement with the body and carried wrap that matched its signed hashes; the absorbed
//! snapshot records; own records with the restore generation of their first send; the next
//! `device_seq` and the HLC. **Never:** a decrypted value, the merge state, an unwrapped key,
//! the password, `pw_in`, an unlock key, the recovery code, a bearer token, a session id or a
//! request counter. No function of this module takes one of those, and the merge state is
//! rebuilt at each unlock.
//!
//! # Write order (§4)
//!
//! 1. An own op or snapshot is journaled by the vault driver (`own = 1`, the counter
//!    advanced); [`crate::sync::VaultSync::take_writes`] hands the host the rows, and the
//!    host commits them, with the move to `own = 3`, before it sends the upload.
//! 2. A Fetch or upload answer is applied in memory, then its rows are committed before the
//!    next request is released.
//! 3. A pending record and `pending_commit` are written before a commit is sent
//!    ([`pending_writes`]) and removed in the transaction that finalises it.
//! 4. An alarm is written in the transaction that detects it ([`alarm_write`]); no write
//!    removes one.
//!
//! # Pruning (§1, §4 step 2)
//!
//! "Pruning of bodies ADR 0018 §10 no longer needs" runs in the vault driver's steps and
//! reaches the file as [`rows::Write::PruneOpBody`]: the body of a served op row that no
//! retained, waiting or unacknowledged op needs and that a snapshot of this device, acknowledged
//! by the server, covers (the exact rule is `VaultSync`'s `prune_bodies`). A load reads that
//! snapshot row as the cover of the bodiless header, as a Fetch from a compacted server would.
//! Own rows keep their bodies, and **snapshot records are never dropped**: ADR 0021 §9
//! "Headers kept" keeps "every snapshot record they wrote or absorbed", and a healing request
//! sends held snapshots verbatim as covers, so this build reads ADR 0026 §1's "the newest
//! snapshot record(s) per item" as a floor, not a ceiling (reported). The cache therefore holds
//! more ciphertext than ADR 0026 §1 lists, never less, and nothing decrypted.
//!
//! # Not in this build (reported)
//!
//! - **`wraps_after_epoch`** is always `NULL`: the driver asks for the whole wrap set.
//! - **Migrations.** Format 1 is the only format; there is no migration step yet.
//!
//! [ADR 0026]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0026-client-device-state-and-cache.md

pub mod floors;
pub mod load;
pub mod record;
pub mod rows;

use rizzy_proto::limits::MAX_UPLOAD_BODY_LEN;

use crate::account::{AccountPin, CertifiedDevice, RevokedDevice, ServedObjects, VerifiedAccount};
use crate::error::ClientError;
use crate::store::record::DeviceRecord;
use crate::store::rows::{
    Alarm, CACHE_FORMAT, Changeset, ObjectRow, Write, alarm_bytes, kind, meta,
};

/// The first changeset of a new cache (a signup or an enrolment): the `cache_meta` rows and the
/// device-state record. `next_device_seq` starts at 1 (ADR 0012 §2) and the HLC at 0.
///
/// # Errors
/// [`ClientError::Internal`].
pub fn create_writes(record: &DeviceRecord) -> Result<Changeset, ClientError> {
    let mut changeset = Changeset::new();
    let meta_rows: [(&'static str, Vec<u8>); 6] = [
        (meta::FORMAT, CACHE_FORMAT.to_be_bytes().to_vec()),
        (
            meta::SERVER_ORIGIN,
            record.server_origin().as_str().as_bytes().to_vec(),
        ),
        (meta::ACCOUNT_ID, record.account_id().to_bytes().to_vec()),
        (meta::DEVICE_ID, record.device_id().to_bytes().to_vec()),
        (meta::NEXT_DEVICE_SEQ, 1u64.to_be_bytes().to_vec()),
        (meta::HLC, 0u64.to_be_bytes().to_vec()),
    ];
    for (key, value) in meta_rows {
        changeset.push(Write::Meta { key, value });
    }
    changeset.push(Write::DeviceState(record.encode()?));
    Ok(changeset)
}

/// The write that replaces the device-state record, always as a whole (ADR 0026 §2).
///
/// # Errors
/// [`ClientError::Internal`].
pub fn record_write(record: &DeviceRecord) -> Result<Write, ClientError> {
    Ok(Write::DeviceState(record.encode()?))
}

/// The writes of ADR 0026 §4 step 3, before a commit is sent: the device-state record with its
/// pending record, and `request`, the exact JSON body of the commit, so that a restart resends
/// identical bytes.
///
/// # Errors
/// [`ClientError::InvalidInput`] for an empty request or one above [`MAX_UPLOAD_BODY_LEN`];
/// [`ClientError::Internal`].
pub fn pending_writes(record: &DeviceRecord, request: &[u8]) -> Result<Changeset, ClientError> {
    if request.is_empty() || request.len() > MAX_UPLOAD_BODY_LEN {
        return Err(ClientError::InvalidInput);
    }
    Ok([
        record_write(record)?,
        Write::PendingCommit(Some(request.to_vec())),
    ]
    .into_iter()
    .collect())
}

/// The writes that finalise a commit (CRYPTO.md §11 step 5; ADR 0026 §4 step 3): the record
/// without its pending record, and `pending_commit` removed, in one transaction with whatever
/// the caller appends.
///
/// # Errors
/// [`ClientError::Internal`].
pub fn finalize_writes(record: &DeviceRecord) -> Result<Changeset, ClientError> {
    Ok([record_write(record)?, Write::PendingCommit(None)]
        .into_iter()
        .collect())
}

/// The write that raises `alarm` (ADR 0026 §4 step 4), with the conflicting signed statements
/// as evidence. The host commits it in the transaction that detects the alarm and goes
/// read-only; a restart finds the row and stays read-only.
///
/// # Errors
/// [`ClientError::Internal`].
pub fn alarm_write(alarm: Alarm, statements: &[&[u8]]) -> Result<Write, ClientError> {
    Ok(Write::PutObject(ObjectRow {
        kind: kind::ALARM,
        key: vec![alarm.to_u8()],
        bytes: alarm_bytes(statements)?,
    }))
}

/// The account-object writes of a verified state: the state, the device set, and the objects
/// of `served`.
pub(crate) fn object_writes(
    pin: &AccountPin,
    certificates: &[CertifiedDevice],
    revocations: &[RevokedDevice],
    served: &ServedObjects,
) -> Changeset {
    let mut changeset = Changeset::new();
    for (bundle_seq, wire) in &served.bundles {
        changeset.push(Write::PutObject(ObjectRow {
            kind: kind::BUNDLE,
            key: bundle_seq.to_be_bytes().to_vec(),
            bytes: wire.clone(),
        }));
    }
    changeset.push(Write::AccountState {
        wire: pin.state_wire.clone(),
        state_seq: pin.state.state_seq,
        settings_seq: pin.state.settings_seq,
    });
    if let Some(settings) = &pin.settings {
        changeset.push(Write::PutObject(ObjectRow {
            kind: kind::SETTINGS,
            key: settings.settings_seq.to_be_bytes().to_vec(),
            bytes: settings.envelope.as_slice().to_vec(),
        }));
    }
    changeset.push(Write::DeviceSet {
        certificates: certificates
            .iter()
            .map(|c| (c.certificate.device_id.to_bytes(), c.wire.clone()))
            .collect(),
        revocations: revocations
            .iter()
            .map(|r| (r.revocation.device_id.to_bytes(), r.wire.clone()))
            .collect(),
    });
    if let Some(keys) = &served.identity_secret_keys {
        changeset.push(Write::PutObject(ObjectRow {
            kind: kind::IDENTITY_KEYS,
            key: keys.identity_epoch.to_be_bytes().to_vec(),
            bytes: keys.envelope.as_slice().to_vec(),
        }));
    }
    for (grant, vault_key_id) in &served.self_grants {
        changeset.push(Write::VaultGrant {
            grant: grant.clone(),
            vault_key_id: *vault_key_id,
        });
    }
    changeset
}

/// The writes of an account answer that verified in full (ADR 0026 §1 "Account objects", §4
/// step 2): the bundles it served, the `account-state`, the settings the state commits to,
/// the device set, `E_id` and the vault self-grants. The floors refuse it if the state would
/// go backwards; a flow that detects a rollback or a fork writes an alarm instead
/// ([`alarm_write`]).
#[must_use]
pub fn account_writes(account: &VerifiedAccount) -> Changeset {
    object_writes(
        &account.pin,
        &account.certificates,
        &account.revocations,
        &account.served,
    )
}
