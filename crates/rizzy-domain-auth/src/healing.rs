//! Healing a server rollback (ADR 0012 §7 steps 1–3, as ADR 0032 §2–§3 replace steps 2 and 3;
//! THREAT_MODEL §5.8, INV-59).
//!
//! `rizzy-vault restore` opens a reconciliation epoch for every restored account
//! (`rizzy-storage`). A device that finds the server behind its own accepted state re-publishes,
//! in this order:
//!
//! 1. [`AuthService::publish_bundles`]: the bundle chain. Each uploaded bundle at or below the
//!    stored head must be the stored one; each above must continue the chain under the chain
//!    rules (CRYPTO.md §10.2, §10.3), so the stored bundle 1 stays the trust root. During the
//!    epoch only.
//! 2. [`AuthService::publish_account_state`]: its newest `account-state`, with every certificate
//!    and revocation it holds and, as last served, `E_id` and `ACCOUNT_SETTINGS` (ADR 0032 §2).
//!    During the epoch the server accepts any state that verifies under the current identity
//!    key (the head) with a strictly higher `state_seq`, whose device-set hash the uploaded and
//!    stored certificates and revocations reproduce; outside it, only the held state re-sent
//!    byte for byte. From then on the general INV-59 checks refuse credentials older than it and
//!    devices it revokes. The epoch ends when a device of the restored set (its certificate was
//!    in the restored database) has done this.
//! 3. [`AuthService::publish_grants`] (step 3a): device grants it holds. The vault self-grants
//!    and wrap sets travel per vault in `vault/heal` (step 3b, `rizzy-domain-vault`), under the
//!    lag rule only: a self-grant in a step 3a request is accepted only when the server already
//!    holds it byte for byte, inside the epoch or outside it, and is never stored from there. A
//!    self-grant stored outside the lag rule would no longer lag (its `account_key_epoch` would
//!    be the state's) while the vault's `vault_key_epoch` and wrap set stayed behind, so step 3b
//!    could never repair the vault (ADR 0032 §3; ADR 0012 §7 step 2 as ADR 0032 replaces it).
//!
//! **The lag rule** (ADR 0032 §3). An object lags when the server's copy disagrees with the
//! signed `account-state` it holds, which happens only after a restore (every flow that rotates
//! writes the objects and the state in one transaction). Step 2 repairs a lagging `E_id` or
//! `ACCOUNT_SETTINGS` inside or outside the epoch, checked against the held state, never
//! against the request, over a device session of a durable device of the held device set only
//! (`repair_lagging`). The first valid repair wins: the server cannot tell a junk envelope under
//! a copied `key_id` from a genuine one, and clients reject it when it does not open.
//!
//! **Outside the epoch** steps 1 and 3a accept only what the server already holds (a repeat is
//! success): a new state goes through the flow that makes it and its compare-and-swap
//! (enrolment, [`AuthService::commit_change`]), and a new bundle travels with its state (the
//! conservative reading of ADR 0012 §7 "Outside that epoch, a new `account-state` is accepted
//! only by compare-and-swap").

use rizzy_core::envelope::parse::{EnvelopeRef, parse_for_purpose};
use rizzy_core::envelope::purpose::{PlaintextRule, Purpose};
use rizzy_core::ids::{AccountId, DeviceId};
use rizzy_core::sign::{AccountState, DeviceCertificate, DeviceRevocation, KeyGrant, Verified};
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

    /// Healing step 2 ([ADR 0032] §2, replacing ADR 0012 §7 step 2): adopts a strictly newer
    /// verified state during the reconciliation epoch, with every certificate and revocation
    /// the device holds, and ends the sessions of the devices it revokes; then repairs `E_id`
    /// and `ACCOUNT_SETTINGS` where the server's copy lags the held signed state (the lag rule,
    /// `repair_lagging`), inside or outside the epoch. All of it in one transaction under the
    /// account lock.
    ///
    /// A byte-identical repeat of the held state is accepted at any time (ADR 0028 "Retry", row
    /// "Healing"); it too ends the epoch when the uploader is a device of the restored set and
    /// the held state was stored after the epoch opened (so it is newer than the restored one:
    /// another session, which could not end the epoch, adopted it first).
    ///
    /// **Certificates** (§2): each must verify under the chain head. One of the new state's
    /// device set is stored; one outside it (a revoked device's, a kind-4 one, both re-issued by
    /// a full rotation) is stored only when the stored certificate of that `device_id` has the
    /// same device keys, and is left out otherwise: with no stored certificate of that device
    /// it is left out too (this crate's reading of "if any", the stricter one).
    ///
    /// [ADR 0032]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0032-healing-rotation-after-backup.md
    ///
    /// # Errors
    /// [`AuthError::InvalidRequest`] for statements that do not verify under the head, a
    /// device-set hash they do not reproduce, or an `E_id` or `ACCOUNT_SETTINGS` that fails the
    /// lag rule's checks; [`AuthError::StateConflict`] outside the epoch or for a state not
    /// strictly newer; [`AuthError::Unauthorized`] for a repair of a lagging object over a
    /// session that is not a device session of a durable device of the held device set;
    /// storage errors. Nothing is stored on any error.
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
        } else {
            let Some(opened_at_ms) = epoch else {
                tx.commit().await?;
                return Err(AuthError::StateConflict);
            };
            if state.state_seq <= trust.state.state_seq {
                return Err(AuthError::StateConflict);
            }
            adopt_state(
                &mut tx,
                &session,
                &trust,
                &devices,
                (&state, wire),
                req,
                opened_at_ms,
                now_ms,
            )
            .await?;
        }
        // ADR 0032 §3: the lag repairs, checked against the signed state now held.
        let current = AccountTrust::load(tx.conn(), account).await?;
        let current_devices = current.devices(tx.conn()).await?;
        repair_lagging(&mut tx, &session, &current, &current_devices, req, now_ms).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Healing step 3a (ADR 0032 §2): device grants the device holds, during the reconciliation
    /// epoch. Each device grant must be addressed to a durable device of the account, at an
    /// `account_key_epoch` no higher than the state's, and verify under its sender's certificate
    /// (a revoked sender too, CRYPTO.md §11.3 step 4.2) or, for a sender the server holds no
    /// durable certificate for, under the identity key. A vault self-grant is repaired only by
    /// the lag rule of step 3b (module docs): here it must be one the server already holds byte
    /// for byte, and nothing of it is stored. Outside the epoch, a request whose every grant the
    /// server already holds byte for byte is a success that stores nothing (ADR 0028, "re-sent
    /// grants are accepted").
    ///
    /// # Errors
    /// [`AuthError::InvalidRequest`] for a grant that does not verify or fit, a self-grant the
    /// server does not hold, or a call outside the epoch that carries a grant the server does not
    /// hold; storage errors.
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
        // ADR 0032 §3: a self-grant is repaired only by the lag rule (`vault/heal`, step 3b).
        if !self_grants_held(&self.vault, &mut tx, account, req).await? {
            return Err(AuthError::InvalidRequest);
        }
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
    self_grants_held(vault, tx, account, req).await
}

/// Whether the server holds every self-grant of `req` byte for byte, among the account's
/// current self-grants under its `account_key_epoch`. In the caller's write transaction.
async fn self_grants_held<V: VaultPort>(
    vault: &V,
    tx: &mut WriteTx,
    account: AccountId,
    req: &PublishGrantsRequest,
) -> Result<bool, AuthError> {
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

/// The adoption half of healing step 2 inside the reconciliation epoch (ADR 0012 §7 step 2 as
/// ADR 0032 §2 replaces it): every certificate and revocation verifies under the head and
/// reproduces the new state's `device_set_hash`, alone and with the stored ones; the members'
/// certificates, the re-issued non-members' ones that keep their stored device keys, and the
/// revocations are stored; the revoked devices' sessions end; the state replaces the held one;
/// the epoch ends when the uploader is a device of the restored set.
#[expect(
    clippy::too_many_arguments,
    reason = "the verified parts of one step-2 request, passed once from `publish_account_state`"
)]
async fn adopt_state(
    tx: &mut WriteTx,
    session: &Session,
    trust: &AccountTrust,
    devices: &Devices,
    (state, wire): (&Verified<AccountState>, &[u8]),
    req: &PublishAccountStateRequest,
    opened_at_ms: u64,
    now_ms: u64,
) -> Result<(), AuthError> {
    let account = trust.account_id;
    let head = trust.head()?;
    let certs = verify_all(&req.device_certificates, |w| {
        rules::verify_certificate(w, head, account)
    })?;
    let revocations = verify_all(&req.device_revocations, |w| {
        rules::verify_revocation(w, head, account)
    })?;
    let supplied: Vec<Verified<DeviceCertificate>> = certs.iter().map(|(c, _)| c.clone()).collect();
    let revoked: Vec<Verified<DeviceRevocation>> =
        revocations.iter().map(|(r, _)| r.clone()).collect();
    if rules::device_set(account, &supplied, &revoked)? != state.device_set_hash
        || devices.device_set_with(account, &supplied, &revoked)? != state.device_set_hash
    {
        return Err(AuthError::InvalidRequest);
    }
    let revoking: Vec<DeviceId> = revocations.iter().map(|(r, _)| r.device_id).collect();
    for (cert, wire) in &certs {
        let member = cert.in_device_set()
            && !revoking.contains(&cert.device_id)
            && !devices.is_revoked(cert.device_id);
        if !member {
            // ADR 0032 §2: outside the device set, only with the stored device keys.
            let same_keys = trust
                .stored_certificate(tx.conn(), cert.device_id)
                .await?
                .is_some_and(|stored| {
                    stored.device_ed25519 == cert.device_ed25519
                        && stored.device_x25519 == cert.device_x25519
                        && stored.device_kind == cert.device_kind
                });
            if !same_keys {
                continue;
            }
        }
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
    if is_restored_device(session, devices, &revoking, opened_at_ms) {
        meta::end_reconciliation_epoch(tx, account.as_bytes()).await?;
    }
    Ok(())
}

/// Whether `envelope` parses as a symmetric envelope of `purpose` (its algorithm on the
/// purpose's allow-list and, for a fixed-size purpose, exactly that plaintext length) whose
/// header `key_id` is `key_id` (ADR 0032 §3). The server cannot open it: a junk envelope under a
/// copied `key_id` passes, and clients detect it (CRYPTO.md §11.2 step 6).
pub(crate) fn symmetric_under(envelope: &[u8], purpose: Purpose, key_id: &[u8; 16]) -> bool {
    let Ok(EnvelopeRef::Symmetric(parsed)) =
        parse_for_purpose(envelope, purpose.client_decrypt_allow_list())
    else {
        return false;
    };
    let length_ok = match purpose.plaintext_rule() {
        PlaintextRule::Fixed(len) => parsed.ciphertext().len() == len,
        PlaintextRule::Padded | PlaintextRule::Unpadded | PlaintextRule::Unspecified => true,
    };
    length_ok && parsed.key_id() == key_id
}

/// The lag rule of ADR 0032 §3 for `E_id` and `ACCOUNT_SETTINGS`, against the signed state
/// `held` that the server holds (never against the request):
///
/// - **`E_id`** lags when its envelope header `key_id` is not `account_key_id`. A replacement
///   parses as a symmetric `IDENTITY_SECRET_KEYS` envelope under `account_key_id` and names the
///   state's `identity_epoch`; it is stored with the state's `identity_epoch`.
/// - **`ACCOUNT_SETTINGS`** lags, while `settings_seq > 0`, when the stored envelope is missing,
///   at another `settings_seq` or hashes to another `settings_hash`. A replacement must hash to
///   `settings_hash` at the state's `settings_seq`.
///
/// A lagging object is repaired only over a device session of a durable device of the held
/// device set (not revoked, suspended or expired, kinds 1–3; a kind-4, OPAQUE-only or recovery
/// session is refused). An object that does not lag is not written: a byte-identical or
/// otherwise valid repeat is success (the first valid repair wins); an invalid one is refused.
/// An object the request does not carry is left as it is.
async fn repair_lagging(
    tx: &mut WriteTx,
    session: &Session,
    held: &AccountTrust,
    devices: &Devices,
    req: &PublishAccountStateRequest,
    now_ms: u64,
) -> Result<(), AuthError> {
    let account = held.account_id;
    let state = &held.state;
    let key_id = *state.account_key_id.as_bytes();
    let may_repair = session.kind == SessionKind::Device
        && session
            .device_id
            .is_some_and(|d| devices.usable_durable(d, now_ms).is_some());
    if let Some(keys) = &req.identity_secret_keys {
        let envelope = keys.envelope.as_slice();
        let valid = keys.identity_epoch == state.identity_epoch
            && symmetric_under(envelope, Purpose::IdentitySecretKeys, &key_id);
        if !valid {
            return Err(AuthError::InvalidRequest);
        }
        let lags = store::identity(tx.conn(), account)
            .await?
            .is_none_or(|(_, stored)| {
                !symmetric_under(&stored, Purpose::IdentitySecretKeys, &key_id)
            });
        if lags {
            if !may_repair {
                return Err(AuthError::Unauthorized);
            }
            store::put_identity(tx.conn(), account, state.identity_epoch, envelope, now_ms).await?;
        }
    }
    if let Some(settings) = &req.account_settings {
        let envelope = settings.envelope.as_slice();
        let valid = state.settings_seq > 0
            && settings.settings_seq == state.settings_seq
            && state.matches_settings(Some(envelope));
        if !valid {
            return Err(AuthError::InvalidRequest);
        }
        let lags = store::settings(tx.conn(), account)
            .await?
            .is_none_or(|(seq, stored)| {
                seq != state.settings_seq || !state.matches_settings(Some(&stored))
            });
        if lags {
            if !may_repair {
                return Err(AuthError::Unauthorized);
            }
            exec!(
                tx.conn(),
                sql::SETTINGS_UPSERT,
                &account.as_bytes()[..],
                sql::u64_sql(state.settings_seq, "settings_seq")?,
                envelope,
                sql::u64_sql(now_ms, "updated_at_ms")?,
            )?;
        }
    }
    Ok(())
}
