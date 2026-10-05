//! Devices: device authentication and request signing (CRYPTO.md §5.10), enrolment (§11.2
//! step 7), the web vault's certificate (§11.4), device grants (§10.1, §11.3 step 4) and
//! suspension, the first phase of revocation (§11.8 step 0; ADR 0012 §6).
//!
//! **Device authentication.** The server issues a 32-byte random challenge with a 60 s TTL
//! for a durable device (kinds 1–3) whose certificate the head of the stored chain vouches
//! for, that no stored revocation names, that is not suspended and not expired. The answer is
//! one `device-auth` signature container; the server rebuilds the message from its canonical
//! origin, the account, the device and the challenge it issued (read and deleted in one
//! statement), and verifies it with `verify_strict` against that certificate's key.
//!
//! **Certificate-carrying device authentication** (ADR 0012 §7 "A device enrolled after the
//! backup", INV-59) is accepted only while the account's reconciliation epoch is open (and
//! not past its admin-set limit). The device sends its certificate, the `account-state` that
//! lists it and the bundle chain, with the certificates of that state's device set and the
//! revocations it holds; the chain must extend the stored one under the chain rules, the
//! certificate and state must verify under its head, the state must be strictly newer than
//! the stored one or byte-identical to it, and the carried set (this certificate among it)
//! must reproduce the state's `device_set_hash`, alone and with the stored statements. The same objects come again with the answer, are verified again, and
//! only after the signature verified are the chain extension and the certificate stored, so
//! nothing is stored before the device proved it holds the key.
//!
//! **Request signing.** Every request over a device session carries a `request_counter` and a
//! `device-request` signature over the origin, the session and the request as received; each
//! counter is accepted at most once, within a sliding window of 64, updated in the same
//! transaction under the account lock.

use rizzy_core::ids::DeviceId;
use rizzy_core::rng::CryptoRng;
use rizzy_core::sign::{
    DeviceAuth, DeviceCertificate, DeviceRequest, DeviceRevocation, Verified, VerifiedBundle,
};
use rizzy_proto::account::{
    AckDeviceGrantsRequest, DeviceGrantsResponse, EnrolDeviceRequest,
    UploadWebDeviceCertificateRequest,
};
use rizzy_proto::auth::{
    DeviceAuthFinishRequest, DeviceAuthFinishResponse, DeviceAuthStartRequest,
    DeviceAuthStartResponse, Reconciliation, RequestSignature,
};
use rizzy_proto::objects::DeviceGrant;
use rizzy_proto::wire::{Bytes, Fixed, Id, List};
use rizzy_storage::{WriteTx, lock_account};

use crate::config::{CHALLENGE_TTL_MS, MAX_REQUEST_COUNTER};
use crate::error::AuthError;
use crate::healing::{open_epoch, verify_all};
use crate::ports::VaultPort;
use crate::rules;
use crate::session::{self, Session, SessionKind};
use crate::sql::{self, exec, fetch_all, fetch_opt};
use crate::store::{self, Offered};
use crate::trust::{AccountTrust, Devices};
use crate::{AuthService, account_id, device_id, over_limit};

/// The parts of an HTTP request a `device-request` signature covers, as the server received
/// them (CRYPTO.md §5.10: "the method, the path and query, and `SHA-256(request body)`").
#[derive(Clone, Copy, Debug)]
pub struct RequestParts<'a> {
    /// The HTTP method, as received.
    pub method: &'a str,
    /// The path and query, as received.
    pub path_and_query: &'a str,
    /// The request body, as received.
    pub body: &'a [u8],
}

/// A device that authenticates with a certificate the restored database lacks, after its
/// objects verified (ADR 0012 §7).
struct Reconciled {
    /// The bundles that extend the stored chain, with their wire form.
    new_bundles: Vec<(VerifiedBundle, Vec<u8>)>,
    /// The device's certificate, verified under the extended chain's head.
    cert: Verified<DeviceCertificate>,
    /// Its wire form.
    cert_wire: Vec<u8>,
}

/// Verifies the objects of a certificate-carrying device authentication (ADR 0012 §7):
/// the chain extends the stored one; the certificate and the state verify under its head for
/// this account and device; the state is strictly newer than the stored one, or
/// byte-identical to it; and the state lists the certificate: the carried certificates (this
/// one among them) and revocations reproduce its `device_set_hash`, and so do they together
/// with the stored ones (the check [`AuthService::publish_account_state`] makes). The caller
/// has checked that the epoch is open.
fn verify_reconciliation(
    trust: &AccountTrust,
    devices: &Devices,
    rec: &Reconciliation,
    device: DeviceId,
    now_ms: u64,
) -> Result<Reconciled, AuthError> {
    if devices.is_revoked(device) {
        return Err(AuthError::Unauthorized);
    }
    let account = trust.account_id;
    let wires: Vec<&[u8]> = rec.bundles.iter().map(Bytes::as_slice).collect();
    let new = rules::extend_chain(&trust.chain, &wires).map_err(|_| AuthError::Unauthorized)?;
    let head = match new.last() {
        Some((bundle, _)) => bundle,
        None => trust.head()?,
    };
    let cert = rules::verify_certificate(rec.device_certificate.as_slice(), head, account)
        .map_err(|_| AuthError::Unauthorized)?;
    let state = rules::verify_state_at_head(rec.account_state.as_slice(), head, account)
        .map_err(|_| AuthError::Unauthorized)?;
    let newer = state.state_seq > trust.state.state_seq
        || rec.account_state.as_slice() == trust.state_wire.as_slice();
    let usable = cert.device_id == device
        && cert.in_device_set()
        && (cert.expires_at_ms == 0 || now_ms < cert.expires_at_ms);
    if !newer || !usable {
        return Err(AuthError::Unauthorized);
    }
    // The state lists this certificate (ADR 0012 §7 "the `account-state` that lists it").
    let certs = verify_all(&rec.device_certificates, |w| {
        rules::verify_certificate(w, head, account)
    })
    .map_err(|_| AuthError::Unauthorized)?;
    let revocations = verify_all(&rec.device_revocations, |w| {
        rules::verify_revocation(w, head, account)
    })
    .map_err(|_| AuthError::Unauthorized)?;
    let listed = certs
        .iter()
        .any(|(c, w)| c.device_id == device && w.as_slice() == rec.device_certificate.as_slice());
    if !listed || revocations.iter().any(|(r, _)| r.device_id == device) {
        return Err(AuthError::Unauthorized);
    }
    let supplied: Vec<Verified<DeviceCertificate>> = certs.iter().map(|(c, _)| c.clone()).collect();
    let revoked: Vec<Verified<DeviceRevocation>> =
        revocations.iter().map(|(r, _)| r.clone()).collect();
    let reproduces =
        |hash: Result<[u8; 32], AuthError>| hash.is_ok_and(|h| h == state.device_set_hash);
    if !reproduces(rules::device_set(account, &supplied, &revoked))
        || !reproduces(devices.device_set_with(account, &supplied, &revoked))
    {
        return Err(AuthError::Unauthorized);
    }
    Ok(Reconciled {
        new_bundles: new.into_iter().map(|(b, w)| (b, w.to_vec())).collect(),
        cert,
        cert_wire: rec.device_certificate.as_slice().to_vec(),
    })
}

/// The key a device authenticates with: its stored certificate, or a reconciled one.
enum DeviceKey {
    /// A stored, usable certificate.
    Stored(Verified<DeviceCertificate>),
    /// A certificate carried with the request during the reconciliation epoch.
    Reconciled(Reconciled),
}

impl DeviceKey {
    /// The certificate.
    const fn cert(&self) -> &Verified<DeviceCertificate> {
        match self {
            Self::Stored(cert) => cert,
            Self::Reconciled(r) => &r.cert,
        }
    }
}

/// Resolves the key of `device` of `trust`'s account for device authentication, in `tx`.
async fn device_key(
    tx: &mut WriteTx,
    trust: &AccountTrust,
    device: DeviceId,
    reconciliation: Option<&Reconciliation>,
    reconciliation_limit_ms: u64,
    now_ms: u64,
) -> Result<DeviceKey, AuthError> {
    let devices = trust.devices(tx.conn()).await?;
    if let Some(stored) = devices.usable_durable(device, now_ms) {
        return Ok(DeviceKey::Stored(stored.cert.clone()));
    }
    // A stored certificate the head vouches for but that is revoked, suspended, expired or
    // kind 4 is refused; only a device the database does not know may reconcile.
    let Some(rec) = reconciliation else {
        return Err(AuthError::Unauthorized);
    };
    if devices.cert(device).is_some()
        || open_epoch(tx, trust.account_id, reconciliation_limit_ms, now_ms)
            .await?
            .is_none()
    {
        return Err(AuthError::Unauthorized);
    }
    verify_reconciliation(trust, &devices, rec, device, now_ms).map(DeviceKey::Reconciled)
}

impl<V: VaultPort> AuthService<V> {
    /// Device authentication, step 1 (CRYPTO.md §5.10 step 1): a 32-byte challenge with a 60 s
    /// TTL, for a usable durable device, or during the reconciliation epoch for a device whose
    /// carried objects verify (ADR 0012 §7).
    ///
    /// # Errors
    /// [`AuthError::Unauthorized`] for an unknown account or device, a revoked, suspended,
    /// expired or kind-4 device, or carried objects that do not verify; storage errors.
    pub async fn device_auth_start<R: CryptoRng + Send + ?Sized>(
        &self,
        rng: &mut R,
        req: &DeviceAuthStartRequest,
        now_ms: u64,
    ) -> Result<DeviceAuthStartResponse, AuthError> {
        let account = account_id(&req.account_id);
        let device = device_id(&req.device_id);
        let mut tx = self.db.begin_write().await?;
        lock_account(&mut tx, account.as_bytes()).await?;
        let trust = AccountTrust::load(tx.conn(), account)
            .await
            .map_err(not_found_is_unauthorized)?;
        device_key(
            &mut tx,
            &trust,
            device,
            req.reconciliation.as_ref(),
            self.config.reconciliation_limit_ms,
            now_ms,
        )
        .await?;
        let mut challenge = [0u8; rizzy_core::sign::statements::CHALLENGE_LEN];
        rng.fill_bytes(&mut challenge);
        exec!(
            tx.conn(),
            sql::CHALLENGE_INSERT,
            &challenge[..],
            &account.as_bytes()[..],
            &device.as_bytes()[..],
            sql::u64_sql(now_ms.saturating_add(CHALLENGE_TTL_MS), "expires_at_ms")?,
        )?;
        tx.commit().await?;
        Ok(DeviceAuthStartResponse {
            challenge: Fixed::from_bytes(challenge),
        })
    }

    /// Device authentication, steps 2–3 (CRYPTO.md §5.10): takes the challenge (at most once),
    /// verifies the `device-auth` container against the device's certificate, and issues a
    /// device session with its `session_id` for request signing.
    ///
    /// During the reconciliation epoch a device the restored database does not know sends the
    /// same `reconciliation` objects as with [`AuthService::device_auth_start`]; they are
    /// verified again, and stored (the chain extension and the certificate) only after the
    /// signature verified.
    ///
    /// # Errors
    /// [`AuthError::Unauthorized`] for an unknown, expired or used challenge, a challenge for
    /// another device, a bad signature, or a device that may not authenticate; storage errors.
    pub async fn device_auth_finish<R: CryptoRng + Send + ?Sized>(
        &self,
        rng: &mut R,
        req: &DeviceAuthFinishRequest,
        now_ms: u64,
    ) -> Result<DeviceAuthFinishResponse, AuthError> {
        let account = account_id(&req.account_id);
        let mut tx = self.db.begin_write().await?;
        lock_account(&mut tx, account.as_bytes()).await?;
        let outcome = self.device_auth_locked(&mut tx, rng, req, now_ms).await;
        // The challenge is gone from the take on: committed with a refusal, and deleted again
        // in its own transaction after any failure that rolls `tx` back.
        self.settle_single_use(
            tx,
            outcome,
            sql::CHALLENGE_DELETE,
            &req.challenge.as_bytes()[..],
        )
        .await
    }

    /// The part of [`AuthService::device_auth_finish`] under the account lock: takes the
    /// challenge, verifies the signature and issues the session. The caller settles `tx` with
    /// [`AuthService::settle_single_use`].
    async fn device_auth_locked<R: CryptoRng + Send + ?Sized>(
        &self,
        tx: &mut WriteTx,
        rng: &mut R,
        req: &DeviceAuthFinishRequest,
        now_ms: u64,
    ) -> Result<DeviceAuthFinishResponse, AuthError> {
        let account = account_id(&req.account_id);
        let device = device_id(&req.device_id);
        let row: Option<(Vec<u8>, Vec<u8>, i64)> = fetch_opt!(
            tx.conn(),
            (Vec<u8>, Vec<u8>, i64),
            sql::CHALLENGE_TAKE,
            &req.challenge.as_bytes()[..]
        )?;
        let valid = row.is_some_and(|(a, d, expires)| {
            a[..] == account.as_bytes()[..]
                && d[..] == device.as_bytes()[..]
                && sql::sql_u64(expires, "expires_at_ms").is_ok_and(|e| now_ms < e)
        });
        if !valid {
            return Err(AuthError::Unauthorized);
        }
        let trust = AccountTrust::load(tx.conn(), account)
            .await
            .map_err(not_found_is_unauthorized)?;
        let key = device_key(
            tx,
            &trust,
            device,
            req.reconciliation.as_ref(),
            self.config.reconciliation_limit_ms,
            now_ms,
        )
        .await?;
        let message = DeviceAuth {
            server_origin: &self.config.server_origin,
            account_id: account,
            device_id: device,
            challenge: req.challenge.to_bytes(),
        };
        if message
            .verify(req.signature.as_bytes(), &key.cert().device_ed25519)
            .is_err()
        {
            return Err(AuthError::Unauthorized);
        }
        if let DeviceKey::Reconciled(rec) = &key {
            for (bundle, wire) in &rec.new_bundles {
                store::put_bundle(tx.conn(), account, bundle.bundle_seq, wire, now_ms).await?;
            }
            store::put_cert(tx.conn(), &rec.cert, &rec.cert_wire, now_ms).await?;
        }
        let (token, session) = session::create(
            tx.conn(),
            rng,
            account,
            Some(device),
            SessionKind::Device,
            now_ms,
            self.config.device_session_ttl_ms,
        )
        .await?;
        // The device signature verified; the flag says whether the record names a setup other
        // than the current one (ADR 0031 point 2) or lags the signed state (ADR 0032 §4 step 5:
        // "`reregister: true` while the record lags"). The state is the one this transaction
        // read, after any reconciliation above.
        let reregister = store::credential(tx.conn(), account.as_bytes())
            .await?
            .is_some_and(|c| self.needs_reregistration(c.setup_id) || c.lags(&trust.state));
        Ok(DeviceAuthFinishResponse {
            session_token: token,
            session_id: Id::from_bytes(session.session_id.to_bytes()),
            reregister,
        })
    }

    /// Authenticates one request (CRYPTO.md §5.10): the bearer token's session, and for a
    /// device session the `device-request` signature over the request as received, with its
    /// `request_counter` accepted at most once within the window of 64.
    ///
    /// The window is read and written in one write transaction, under the account lock, and
    /// only after the signature verified (ADR 0028 item 5 "Replay window"): a forged request
    /// cannot move it, a restart does not reset it, and replicas share it. The counter is
    /// spent once this returns `Ok`, even if the request then fails in its flow. A counter
    /// above [`MAX_REQUEST_COUNTER`] is refused.
    ///
    /// A device session without a signature, and an OPAQUE or recovery session with one, are
    /// refused: native clients sign every request over a device session and only those (the
    /// web vault keeps bearer tokens).
    ///
    /// # Errors
    /// [`AuthError::Unauthorized`] for an unknown or expired token, a missing or bad
    /// signature, a replayed or too old counter, or a device no longer usable (revoked,
    /// suspended, expired); storage errors.
    pub async fn authenticate_request(
        &self,
        token: &[u8],
        signature: Option<&RequestSignature>,
        request: RequestParts<'_>,
        now_ms: u64,
    ) -> Result<Session, AuthError> {
        let Some(signature) = signature else {
            let mut tx = self.db.begin_read().await?;
            let session = session::load(tx.conn(), token, now_ms).await?;
            tx.finish().await?;
            return if session.kind == SessionKind::Device {
                Err(AuthError::Unauthorized)
            } else {
                Ok(session)
            };
        };
        // The session row keeps the highest accepted counter in a signed 64-bit column that
        // admits no negative value (`request_counter_max`), so a counter above `i64::MAX`
        // cannot be recorded. It is refused like every other unusable counter (ADR 0028 item 5
        // "One answer"), before anything is read: a client starts at 1 and adds 1 per request,
        // so it never gets there.
        if signature.request_counter > MAX_REQUEST_COUNTER {
            return Err(AuthError::Unauthorized);
        }
        let mut tx = self.db.begin_write().await?;
        let session = session::load(tx.conn(), token, now_ms).await?;
        let (SessionKind::Device, Some(device)) = (session.kind, session.device_id) else {
            return Err(AuthError::Unauthorized);
        };
        lock_account(&mut tx, session.account_id.as_bytes()).await?;
        // Re-read under the lock, so two concurrent requests see each other's counters.
        let session = session::reload(tx.conn(), &session, now_ms).await?;
        let trust = AccountTrust::load(tx.conn(), session.account_id).await?;
        let devices = trust.devices(tx.conn()).await?;
        let cert = devices
            .usable_durable(device, now_ms)
            .ok_or(AuthError::Unauthorized)?;
        let message = DeviceRequest {
            server_origin: &self.config.server_origin,
            account_id: session.account_id,
            device_id: device,
            session_id: session.session_id,
            request_counter: signature.request_counter,
            method: request.method,
            path_and_query: request.path_and_query,
            body_hash: DeviceRequest::body_hash(request.body),
        };
        message
            .verify(signature.signature.as_bytes(), &cert.cert.device_ed25519)
            .map_err(|_| AuthError::Unauthorized)?;
        let window = session
            .window
            .accept(signature.request_counter)
            .ok_or(AuthError::Unauthorized)?;
        session::store_window(tx.conn(), &session, window).await?;
        tx.commit().await?;
        Ok(session)
    }

    /// The first half of [`Self::authenticate_request`], from the headers alone: the bearer
    /// token's unexpired session, and whether its kind fits the presence of a signature (a
    /// device session must carry one, any other session must not). It reads no body and
    /// verifies no signature, so it never authenticates a request by itself; it lets the
    /// caller refuse a request before reading a large body (threat model §7.6 "D"), and the
    /// caller then calls [`Self::authenticate_request`] over the body as received.
    ///
    /// # Errors
    /// [`AuthError::Unauthorized`] for an unknown or expired token, or a kind that does not
    /// fit `signed`; storage errors.
    pub async fn session_for_token(
        &self,
        token: &[u8],
        signed: bool,
        now_ms: u64,
    ) -> Result<Session, AuthError> {
        let mut tx = self.db.begin_read().await?;
        let session = session::load(tx.conn(), token, now_ms).await?;
        tx.finish().await?;
        if (session.kind == SessionKind::Device) == signed {
            Ok(session)
        } else {
            Err(AuthError::Unauthorized)
        }
    }

    /// Enrolment of a new durable device (CRYPTO.md §11.2 step 7) over a fresh OPAQUE session:
    /// its certificate and the new `account-state` (`state_seq + 1`, only `device_set_hash`
    /// changed, over exactly the stored set plus this device), applied by compare-and-swap. A
    /// byte-identical repeat is success.
    ///
    /// # Errors
    /// - [`AuthError::FreshSessionRequired`];
    /// - [`AuthError::InvalidRequest`]: a statement does not verify, a kind-4 or expired
    ///   certificate, a state that changes anything but the device set, or a device-set hash
    ///   that is not the stored set plus this device;
    /// - [`AuthError::StateConflict`], [`AuthError::StateFork`]: the compare-and-swap lost;
    /// - [`AuthError::Conflict`]: the device id is taken;
    /// - storage errors.
    pub async fn enrol_device(
        &self,
        session: &Session,
        req: &EnrolDeviceRequest,
        now_ms: u64,
    ) -> Result<(), AuthError> {
        let account = session.account_id;
        let mut tx = self.db.begin_write().await?;
        lock_account(&mut tx, account.as_bytes()).await?;
        session::reload(tx.conn(), session, now_ms)
            .await?
            .require_fresh_opaque(now_ms)?;
        let trust = AccountTrust::load(tx.conn(), account).await?;
        let devices = trust.devices(tx.conn()).await?;
        let head = trust.head()?;
        let cert = rules::verify_certificate(req.device_certificate.as_slice(), head, account)?;
        let state = rules::verify_state_at_head(req.account_state.as_slice(), head, account)?;
        if devices.cert(cert.device_id).is_some() || devices.is_revoked(cert.device_id) {
            let repeat = devices
                .cert(cert.device_id)
                .is_some_and(|c| c.wire == req.device_certificate.as_slice())
                && trust.state_wire == req.account_state.as_slice();
            return if repeat {
                Ok(())
            } else {
                Err(AuthError::Conflict)
            };
        }
        if !cert.in_device_set() || (cert.expires_at_ms != 0 && cert.expires_at_ms <= now_ms) {
            return Err(AuthError::InvalidRequest);
        }
        if store::place_offered(
            &trust.state,
            &trust.state_wire,
            &state,
            req.account_state.as_slice(),
        )? == Offered::Repeat
        {
            // The same state without this device's certificate: not a repeat of this
            // enrolment.
            return Err(AuthError::Conflict);
        }
        let expected = devices.device_set_with(account, core::slice::from_ref(&cert), &[])?;
        if !rules::only_device_set_advances(&trust.state, &state)
            || expected != state.device_set_hash
        {
            return Err(AuthError::InvalidRequest);
        }
        store::put_cert(tx.conn(), &cert, req.device_certificate.as_slice(), now_ms).await?;
        store::cas_state(
            tx.conn(),
            account,
            trust.state.state_seq,
            &state,
            req.account_state.as_slice(),
            now_ms,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// The web vault's ephemeral kind-4 certificate (CRYPTO.md §11.4), over the OPAQUE session
    /// of that web login: verified under the current identity key for the session's account,
    /// kind 4, unexpired. It joins no device set and publishes no state. A byte-identical repeat
    /// is success.
    ///
    /// The account's kind-4 certificates are bounded
    /// ([`AuthConfig::max_web_certificates`](crate::AuthConfig::max_web_certificates)): an
    /// expired one that no revocation names and that authored nothing the server holds
    /// ([`VaultPort::device_head`] is 0) verifies nothing any peer needs, and a full rotation
    /// need not re-issue it (§11.6 step 7: only those that "authored a retained op or snapshot
    /// or \[have\] not expired"), so it is deleted here, under the account lock.
    ///
    /// # Errors
    /// [`AuthError::Unauthorized`] for a session that is not an OPAQUE session;
    /// [`AuthError::InvalidRequest`] for a certificate that does not verify, is durable or has
    /// expired; [`AuthError::Conflict`] for a taken device id; [`AuthError::RateLimited`] when
    /// the account holds `max_web_certificates` kind-4 certificates that cannot be deleted
    /// yet; storage errors.
    pub async fn upload_web_certificate(
        &self,
        session: &Session,
        req: &UploadWebDeviceCertificateRequest,
        now_ms: u64,
    ) -> Result<(), AuthError> {
        let account = session.account_id;
        let mut tx = self.db.begin_write().await?;
        lock_account(&mut tx, account.as_bytes()).await?;
        let session = session::reload(tx.conn(), session, now_ms).await?;
        if session.kind != SessionKind::Opaque {
            return Err(AuthError::Unauthorized);
        }
        let trust = AccountTrust::load(tx.conn(), account).await?;
        let devices = trust.devices(tx.conn()).await?;
        let cert =
            rules::verify_certificate(req.device_certificate.as_slice(), trust.head()?, account)?;
        if cert.in_device_set() || now_ms >= cert.expires_at_ms {
            return Err(AuthError::InvalidRequest);
        }
        if let Some(held) = devices.cert(cert.device_id) {
            return if held.wire == req.device_certificate.as_slice() {
                Ok(())
            } else {
                Err(AuthError::Conflict)
            };
        }
        if devices.is_revoked(cert.device_id) {
            return Err(AuthError::Conflict);
        }
        let kept = self
            .prune_web_certificates(&mut tx, &devices, now_ms)
            .await?;
        if kept >= self.config.max_web_certificates {
            // Commit the deletions made so far; the upload itself is refused.
            tx.commit().await?;
            return Err(AuthError::RateLimited {
                retry_after_ms: None,
            });
        }
        store::put_cert(tx.conn(), &cert, req.device_certificate.as_slice(), now_ms).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Deletes the account's kind-4 certificates that are expired at `now_ms`, named by no
    /// revocation, and authored nothing the server holds, and returns how many kind-4
    /// certificates remain (see [`AuthService::upload_web_certificate`]).
    async fn prune_web_certificates(
        &self,
        tx: &mut WriteTx,
        devices: &Devices,
        now_ms: u64,
    ) -> Result<usize, AuthError> {
        let mut kept = 0usize;
        for stored in devices.certs.iter().filter(|c| !c.cert.in_device_set()) {
            let cert = &stored.cert;
            let expired = cert.expires_at_ms != 0 && cert.expires_at_ms <= now_ms;
            let deletable = expired
                && !devices.is_revoked(cert.device_id)
                && self
                    .vault
                    .device_head(tx.conn(), cert.account_id, cert.device_id)
                    .await?
                    == 0;
            if deletable {
                exec!(
                    tx.conn(),
                    sql::CERT_DELETE,
                    &cert.account_id.as_bytes()[..],
                    &cert.device_id.as_bytes()[..],
                )?;
            } else {
                kept = kept.saturating_add(1);
            }
        }
        Ok(kept)
    }

    /// This device's pending `ACCOUNT_KEY_DEVICE_GRANT`s, lowest epoch first (CRYPTO.md
    /// §11.3 step 4.1), over its device session. Fetching does not consume them (§10.1).
    ///
    /// # Errors
    /// [`AuthError::Unauthorized`] for a session that is not a device session; storage errors.
    pub async fn device_grants(
        &self,
        session: &Session,
        now_ms: u64,
    ) -> Result<DeviceGrantsResponse, AuthError> {
        let mut tx = self.db.begin_read().await?;
        let session = session::reload(tx.conn(), session, now_ms).await?;
        let device = device_of(&session)?;
        let rows: Vec<(i64, Vec<u8>, Vec<u8>)> = fetch_all!(
            tx.conn(),
            (i64, Vec<u8>, Vec<u8>),
            sql::GRANTS_FOR_DEVICE,
            &session.account_id.as_bytes()[..],
            &device.as_bytes()[..]
        )?;
        tx.finish().await?;
        let grants = rows
            .into_iter()
            .map(|(epoch, sender, record)| {
                Ok(DeviceGrant {
                    account_key_epoch: sql::sql_u32(epoch, "account_key_epoch")?,
                    sender_device_id: Id::from_bytes(sql::id16(&sender, "sender_device_id")?),
                    recipient_device_id: Id::from_bytes(device.to_bytes()),
                    key_grant: Bytes::new(record).map_err(over_limit)?,
                })
            })
            .collect::<Result<Vec<_>, AuthError>>()?;
        Ok(DeviceGrantsResponse {
            grants: List::new(grants).map_err(over_limit)?,
        })
    }

    /// The separate acknowledgement of CRYPTO.md §10.1: the device persisted its re-wrapped
    /// keys up to `req.account_key_epoch`, so its grants up to that epoch are deleted.
    ///
    /// # Errors
    /// [`AuthError::Unauthorized`] for a session that is not a device session; storage errors.
    pub async fn ack_device_grants(
        &self,
        session: &Session,
        req: &AckDeviceGrantsRequest,
        now_ms: u64,
    ) -> Result<(), AuthError> {
        let mut tx = self.db.begin_write().await?;
        lock_account(&mut tx, session.account_id.as_bytes()).await?;
        let session = session::reload(tx.conn(), session, now_ms).await?;
        let device = device_of(&session)?;
        exec!(
            tx.conn(),
            sql::GRANTS_ACK,
            &session.account_id.as_bytes()[..],
            &device.as_bytes()[..],
            i64::from(req.account_key_epoch),
        )?;
        tx.commit().await?;
        Ok(())
    }

    /// Revocation phase 1, `suspend(device_id)` (CRYPTO.md §11.8 step 0; ADR 0012 §6): from this
    /// commit on the server rejects the device's uploads and device authentication and ends
    /// its sessions. Returns H, the highest `device_seq` the server holds from it
    /// ([`VaultPort::device_head`]). Repeating it returns H again.
    ///
    /// Needs a fresh OPAQUE re-authentication of another durable device in the set: an OPAQUE
    /// session that [`AuthService::login_finish`] bound to that device.
    ///
    /// # Errors
    /// [`AuthError::FreshSessionRequired`]; [`AuthError::NotFound`] for a device that is not a
    /// durable, unrevoked device of the account; [`AuthError::InvalidRequest`] for the caller's
    /// own device; storage errors.
    pub async fn suspend_device(
        &self,
        session: &Session,
        target: DeviceId,
        now_ms: u64,
    ) -> Result<u64, AuthError> {
        let (mut tx, trust, devices) = self.revoker(session, target, now_ms).await?;
        let account = trust.account_id;
        let held = devices.cert(target).ok_or(AuthError::NotFound)?;
        if !held.suspended {
            exec!(
                tx.conn(),
                sql::CERT_SUSPEND,
                &account.as_bytes()[..],
                &target.as_bytes()[..],
                sql::u64_sql(now_ms, "suspended_at_ms")?,
            )?;
            session::end_device(tx.conn(), account, target).await?;
        }
        let last_seq = self.vault.device_head(tx.conn(), account, target).await?;
        tx.commit().await?;
        Ok(last_seq)
    }

    /// Lifts a suspension (ADR 0012 §6: "Only a fresh session of another device in the device
    /// set can lift a suspension"), under the same session rule as
    /// [`AuthService::suspend_device`].
    ///
    /// # Errors
    /// As [`AuthService::suspend_device`].
    pub async fn unsuspend_device(
        &self,
        session: &Session,
        target: DeviceId,
        now_ms: u64,
    ) -> Result<(), AuthError> {
        let (mut tx, trust, _) = self.revoker(session, target, now_ms).await?;
        exec!(
            tx.conn(),
            sql::CERT_UNSUSPEND,
            &trust.account_id.as_bytes()[..],
            &target.as_bytes()[..],
        )?;
        tx.commit().await?;
        Ok(())
    }

    /// The session rule of suspension: a fresh OPAQUE session bound to a usable durable device
    /// other than `target`, and `target` a durable, unrevoked device of the account. Returns
    /// the locked transaction with the verified trust and devices.
    async fn revoker(
        &self,
        session: &Session,
        target: DeviceId,
        now_ms: u64,
    ) -> Result<(WriteTx, AccountTrust, Devices), AuthError> {
        let account = session.account_id;
        let mut tx = self.db.begin_write().await?;
        lock_account(&mut tx, account.as_bytes()).await?;
        let session = session::reload(tx.conn(), session, now_ms).await?;
        session.require_fresh_opaque(now_ms)?;
        let trust = AccountTrust::load(tx.conn(), account).await?;
        let devices = trust.devices(tx.conn()).await?;
        let own = session.device_id.ok_or(AuthError::FreshSessionRequired)?;
        if devices.usable_durable(own, now_ms).is_none() {
            return Err(AuthError::FreshSessionRequired);
        }
        if own == target {
            return Err(AuthError::InvalidRequest);
        }
        let known = devices
            .cert(target)
            .is_some_and(|c| c.cert.in_device_set() && !devices.is_revoked(target));
        if !known {
            return Err(AuthError::NotFound);
        }
        Ok((tx, trust, devices))
    }
}

/// The device of a device session.
fn device_of(session: &Session) -> Result<DeviceId, AuthError> {
    match (session.kind, session.device_id) {
        (SessionKind::Device, Some(device)) => Ok(device),
        _ => Err(AuthError::Unauthorized),
    }
}

/// An unknown account answers like any other authentication failure.
fn not_found_is_unauthorized(e: AuthError) -> AuthError {
    match e {
        AuthError::NotFound => AuthError::Unauthorized,
        other => other,
    }
}
