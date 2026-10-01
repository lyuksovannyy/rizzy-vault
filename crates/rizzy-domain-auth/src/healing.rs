//! Healing a server rollback (ADR 0012 §7 steps 1–3; THREAT_MODEL §5.8, INV-59).
//!
//! `rizzy-vault restore` opens a reconciliation epoch for every restored account
//! (`rizzy-storage`). While it is open, a device that finds the server behind its own
//! accepted state re-publishes, in this order:
//!
//! 1. [`AuthService::publish_bundles`]: the bundle chain. Each uploaded bundle at or below the
//!    stored head must be the stored one; each above must continue the chain under the chain
//!    rules (CRYPTO.md §10.2, §10.3), so the stored bundle 1 stays the trust root.
//! 2. [`AuthService::publish_account_state`]: its newest `account-state`, with the
//!    certificates of that state's device set and every revocation it holds. The server
//!    accepts any state that verifies under the current identity key (the head) with a
//!    strictly higher `state_seq`, whose device-set hash the uploaded and stored certificates
//!    and revocations reproduce. From then on the general INV-59 checks refuse credentials
//!    older than it and devices it revokes. The epoch ends when a device of the restored set
//!    (its certificate was in the restored database) has done this.
//! 3. [`AuthService::publish_grants`]: device grants and vault self-grants it holds.
//!
//! **Outside the epoch** these calls accept only what the server already holds (a repeat is
//! success): a new state goes through the flow that makes it and its compare-and-swap
//! (enrolment, [`AuthService::commit_change`]), and a new bundle travels with its state (the
//! conservative reading of ADR 0012 §7 "Outside that epoch, a new `account-state` is accepted
//! only by compare-and-swap").

use rizzy_core::ids::{AccountId, DeviceId};
use rizzy_core::sign::{DeviceCertificate, DeviceRevocation, KeyGrant, Verified};
use rizzy_proto::account::{
    PublishAccountStateRequest, PublishBundlesRequest, PublishGrantsRequest,
};
use rizzy_proto::wire::Bytes;
use rizzy_storage::{WriteTx, lock_account, meta};

use crate::AuthService;
use crate::error::AuthError;
use crate::ports::VaultPort;
use crate::rules;
use crate::session::{self, Session, SessionKind};
use crate::sql::{self, exec, fetch_all};
use crate::store;
use crate::trust::{AccountTrust, Devices};

/// The opening time of the account's reconciliation epoch, if it is open at `now_ms`, in the
/// caller's write transaction (which holds the account lock).
///
/// ADR 0012 §7: the epoch ends "after an admin-set limit (default 30 days)". An epoch opened
/// `limit_ms` or longer ago counts as closed here, wherever it is read, and is ended in `tx`,
/// so a late or missed `worker` run
/// ([`AuthService::end_stale_reconciliation_epochs`]) never extends it.
pub(crate) async fn open_epoch(
    tx: &mut WriteTx,
    account: AccountId,
    limit_ms: u64,
    now_ms: u64,
) -> Result<Option<u64>, AuthError> {
    let Some(epoch) = meta::reconciliation_epoch(tx.conn(), account.as_bytes()).await? else {
        return Ok(None);
    };
    let opened_at_ms = sql::sql_u64(epoch.opened_at_ms, "opened_at_ms")?;
    if now_ms.saturating_sub(opened_at_ms) >= limit_ms {
        meta::end_reconciliation_epoch(tx, account.as_bytes()).await?;
        return Ok(None);
    }
    Ok(Some(opened_at_ms))
}

/// Opens the write transaction of a healing call: locks the account, re-reads the session,
/// and returns the verified trust, devices and whether the reconciliation epoch is open, with
/// its opening time.
async fn begin(
    db: &rizzy_storage::Database,
    session: &Session,
    limit_ms: u64,
    now_ms: u64,
) -> Result<(WriteTx, Session, AccountTrust, Devices, Option<u64>), AuthError> {
    let mut tx = db.begin_write().await?;
    lock_account(&mut tx, session.account_id.as_bytes()).await?;
    let session = session::reload(tx.conn(), session, now_ms).await?;
    let trust = AccountTrust::load(tx.conn(), session.account_id).await?;
    let devices = trust.devices(tx.conn()).await?;
    let epoch = open_epoch(&mut tx, session.account_id, limit_ms, now_ms).await?;
    Ok((tx, session, trust, devices, epoch))
}

/// Whether `session` is a device session of a device of the restored set: its durable
/// certificate was stored before the epoch opened at `opened_at_ms` (it was in the restored
/// database) and no stored or `revoking` revocation names it (ADR 0012 §7 "End of the
/// reconciliation epoch").
fn is_restored_device(
    session: &Session,
    devices: &Devices,
    revoking: &[DeviceId],
    opened_at_ms: u64,
) -> bool {
    session.kind == SessionKind::Device
        && session.device_id.is_some_and(|d| {
            devices
                .cert(d)
                .is_some_and(|c| c.cert.in_device_set() && c.stored_at_ms <= opened_at_ms)
                && !devices.is_revoked(d)
                && !revoking.contains(&d)
        })
}

impl<V: VaultPort> AuthService<V> {
    /// Healing step 1 (ADR 0012 §7): stores the bundles that extend the stored chain. Any
    /// session of the account, during the reconciliation epoch; outside it, only bundles the
    /// server already holds.
    ///
    /// # Errors
    /// [`AuthError::InvalidRequest`] for a bundle that does not chain, or a new bundle outside
    /// the epoch; [`AuthError::StateFork`] for another version of a stored bundle (§10.3
    /// "Fork"); storage errors.
    pub async fn publish_bundles(
        &self,
        session: &Session,
        req: &PublishBundlesRequest,
        now_ms: u64,
    ) -> Result<(), AuthError> {
        let (mut tx, _, trust, _, epoch) = begin(
            &self.db,
            session,
            self.config.reconciliation_limit_ms,
            now_ms,
        )
        .await?;
        let wires: Vec<&[u8]> = req.bundles.iter().map(Bytes::as_slice).collect();
        let new = rules::extend_chain(&trust.chain, &wires).map_err(|e| match e {
            rules::ChainExtendError::Fork => AuthError::StateFork,
            rules::ChainExtendError::Invalid => AuthError::InvalidRequest,
        })?;
        if new.is_empty() {
            return Ok(());
        }
        if epoch.is_none() {
            return Err(AuthError::InvalidRequest);
        }
        for (bundle, wire) in &new {
            store::put_bundle(tx.conn(), trust.account_id, bundle.bundle_seq, wire, now_ms).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Healing step 2 (ADR 0012 §7): adopts a strictly newer verified state during the
    /// reconciliation epoch, with the certificates of its device set and every revocation the
    /// device holds, and ends the sessions of the devices it revokes. Ends the epoch when the
    /// uploader is a device of the restored set. A byte-identical repeat of the held state is
    /// success at any time; it too ends the epoch when the uploader is a device of the restored
    /// set and the held state was stored after the epoch opened (so it is newer than the
    /// restored one: another session, which could not end the epoch, adopted it first).
    ///
    /// # Errors
    /// [`AuthError::InvalidRequest`] for statements that do not verify under the head or a
    /// device-set hash they do not reproduce; [`AuthError::StateConflict`] outside the epoch or
    /// for a state not strictly newer; storage errors.
    pub async fn publish_account_state(
        &self,
        session: &Session,
        req: &PublishAccountStateRequest,
        now_ms: u64,
    ) -> Result<(), AuthError> {
        let (mut tx, session, trust, devices, epoch) = begin(
            &self.db,
            session,
            self.config.reconciliation_limit_ms,
            now_ms,
        )
        .await?;
        let account = trust.account_id;
        let head = trust.head()?;
        let wire = req.account_state.as_slice();
        let state = rules::verify_state_at_head(wire, head, account)?;
        if wire == trust.state_wire.as_slice() {
            if let Some(opened_at_ms) = epoch {
                // The state row's storage time tells a state adopted after the restore (stored
                // at or after the epoch opened, while the server ran) from the restored one
                // (stored before the backup was taken, hence before the restore opened it).
                let stored_at_ms = store::state_updated_at(tx.conn(), account).await?;
                if stored_at_ms >= opened_at_ms
                    && is_restored_device(&session, &devices, &[], opened_at_ms)
                {
                    meta::end_reconciliation_epoch(&mut tx, account.as_bytes()).await?;
                }
            }
            tx.commit().await?;
            return Ok(());
        }
        let Some(opened_at_ms) = epoch else {
            tx.commit().await?;
            return Err(AuthError::StateConflict);
        };
        if state.state_seq <= trust.state.state_seq {
            return Err(AuthError::StateConflict);
        }
        let certs = verify_all(&req.device_certificates, |w| {
            rules::verify_certificate(w, head, account)
        })?;
        let revocations = verify_all(&req.device_revocations, |w| {
            rules::verify_revocation(w, head, account)
        })?;
        let supplied: Vec<Verified<DeviceCertificate>> =
            certs.iter().map(|(c, _)| c.clone()).collect();
        let revoked: Vec<Verified<DeviceRevocation>> =
            revocations.iter().map(|(r, _)| r.clone()).collect();
        if rules::device_set(account, &supplied, &revoked)? != state.device_set_hash
            || devices.device_set_with(account, &supplied, &revoked)? != state.device_set_hash
        {
            return Err(AuthError::InvalidRequest);
        }
        for (cert, wire) in &certs {
            store::put_cert(tx.conn(), cert, wire, now_ms).await?;
        }
        for (revocation, wire) in &revocations {
            store::put_revocation(tx.conn(), revocation, wire, now_ms).await?;
            session::end_device(tx.conn(), account, revocation.device_id).await?;
        }
        let changed = exec!(
            tx.conn(),
            sql::STATE_REPLACE,
            &account.as_bytes()[..],
            sql::u64_sql(state.state_seq, "state_seq")?,
            wire,
            sql::u64_sql(now_ms, "updated_at_ms")?,
        )?;
        if changed != 1 {
            return Err(AuthError::StateConflict);
        }
        let revoking: Vec<DeviceId> = revocations.iter().map(|(r, _)| r.device_id).collect();
        if is_restored_device(&session, &devices, &revoking, opened_at_ms) {
            meta::end_reconciliation_epoch(&mut tx, account.as_bytes()).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Healing step 3 (ADR 0012 §7): device grants and vault self-grants the device holds, during
    /// the reconciliation epoch. Each device grant must be addressed to a durable device of the
    /// account, at an `account_key_epoch` no higher than the state's, and verify under its
    /// sender's certificate (a revoked sender too, CRYPTO.md §11.3 step 4.2) or, for a sender
    /// the server holds no durable certificate for, under the identity key. Self-grants go to
    /// [`VaultPort::store_self_grants`], which keeps a newer stored one. Outside the epoch, a
    /// request whose every grant the server already holds byte for byte is a success that stores
    /// nothing (ADR 0028, "re-sent grants are accepted").
    ///
    /// # Errors
    /// [`AuthError::InvalidRequest`] for a grant that does not verify or fit, or a call outside
    /// the epoch that carries a grant the server does not hold; storage errors.
    pub async fn publish_grants(
        &self,
        session: &Session,
        req: &PublishGrantsRequest,
        now_ms: u64,
    ) -> Result<(), AuthError> {
        let (mut tx, _, trust, devices, epoch) = begin(
            &self.db,
            session,
            self.config.reconciliation_limit_ms,
            now_ms,
        )
        .await?;
        let account = trust.account_id;
        if epoch.is_none() {
            // ADR 0028 "Retry after an unknown outcome", row "Healing": "re-sent grants are
            // accepted". Outside the epoch a request is a success only when the server already
            // holds every grant it carries, byte for byte; it then stores nothing.
            if held_already(&self.vault, &mut tx, account, req).await? {
                tx.commit().await?;
                return Ok(());
            }
            return Err(AuthError::InvalidRequest);
        }
        let head = trust.head()?;
        for grant in &req.device_grants {
            let recipient = devices
                .cert(DeviceId::from_bytes(grant.recipient_device_id.to_bytes()))
                .filter(|c| c.cert.in_device_set())
                .ok_or(AuthError::InvalidRequest)?;
            let sender = devices
                .cert(DeviceId::from_bytes(grant.sender_device_id.to_bytes()))
                .filter(|c| c.cert.in_device_set());
            let verified = match sender {
                Some(s) => KeyGrant::verify(grant.key_grant.as_slice(), &s.cert.device_ed25519),
                None => KeyGrant::verify(grant.key_grant.as_slice(), &head.identity_ed25519),
            }
            .map_err(|_| AuthError::InvalidRequest)?;
            let addressed = *verified.recipient_key_id()
                == recipient
                    .cert
                    .device_x25519
                    .key_id(rizzy_core::ids::KeyType::DeviceX25519);
            if !addressed || grant.account_key_epoch > trust.state.account_key_epoch {
                return Err(AuthError::InvalidRequest);
            }
            exec!(
                tx.conn(),
                sql::GRANT_UPSERT,
                &account.as_bytes()[..],
                &grant.recipient_device_id.as_bytes()[..],
                i64::from(grant.account_key_epoch),
                &grant.sender_device_id.as_bytes()[..],
                grant.key_grant.as_slice(),
                sql::u64_sql(now_ms, "stored_at_ms")?,
            )?;
        }
        self.vault
            .store_self_grants(&mut tx, account, req.vault_self_grants.as_slice(), now_ms)
            .await?;
        tx.commit().await?;
        Ok(())
    }
}

/// Whether the server holds every grant of `req` byte for byte: each device grant as the
/// stored row of its recipient, epoch and sender, and each self-grant among the account's
/// current self-grants under its `account_key_epoch`. In the caller's write transaction.
async fn held_already<V: VaultPort>(
    vault: &V,
    tx: &mut WriteTx,
    account: AccountId,
    req: &PublishGrantsRequest,
) -> Result<bool, AuthError> {
    for grant in &req.device_grants {
        let rows: Vec<(i64, Vec<u8>, Vec<u8>)> = fetch_all!(
            tx.conn(),
            (i64, Vec<u8>, Vec<u8>),
            sql::GRANTS_FOR_DEVICE,
            &account.as_bytes()[..],
            &grant.recipient_device_id.as_bytes()[..]
        )?;
        let held = rows.iter().any(|(epoch, sender, record)| {
            i64::from(grant.account_key_epoch) == *epoch
                && sender.as_slice() == grant.sender_device_id.as_bytes().as_slice()
                && record.as_slice() == grant.key_grant.as_slice()
        });
        if !held {
            return Ok(false);
        }
    }
    for grant in &req.vault_self_grants {
        let stored = vault
            .self_grants(tx.conn(), account, grant.account_key_epoch)
            .await?;
        if !stored.contains(grant) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Verified statements, each with its wire form.
pub(crate) type Checked<S> = Vec<(Verified<S>, Vec<u8>)>;

/// Verifies every statement of a list, keeping each with its wire form; duplicates of one
/// device are refused.
pub(crate) fn verify_all<S, F>(
    wires: &rizzy_proto::wire::List<
        rizzy_proto::objects::AccountStatement,
        { rizzy_proto::limits::MAX_DEVICE_STATEMENTS },
    >,
    verify: F,
) -> Result<Checked<S>, AuthError>
where
    S: DeviceStatement,
    F: Fn(&[u8]) -> Result<Verified<S>, AuthError>,
{
    let mut out: Checked<S> = Vec::with_capacity(wires.len());
    for wire in wires {
        let statement = verify(wire.as_slice())?;
        if out.iter().any(|(s, _)| s.device() == statement.device()) {
            return Err(AuthError::InvalidRequest);
        }
        out.push((statement, wire.as_slice().to_vec()));
    }
    Ok(out)
}

/// A statement about one device.
pub(crate) trait DeviceStatement {
    /// The device it is about.
    fn device(&self) -> DeviceId;
}

impl DeviceStatement for DeviceCertificate {
    fn device(&self) -> DeviceId {
        self.device_id
    }
}

impl DeviceStatement for DeviceRevocation {
    fn device(&self) -> DeviceId {
        self.device_id
    }
}
