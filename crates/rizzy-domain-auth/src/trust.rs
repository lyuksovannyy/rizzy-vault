//! What the server believes about an account's keys, re-verified from storage.
//!
//! The server never trusts its own database for public keys beyond what the specs allow. Its
//! root is the account's stored bundle chain: bundle 1 must be self-signed, and every later
//! bundle a verified successor ([`rules::verify_chain_from_start`]), so the head's identity
//! key is the one the chain vouches for. Everything else the server relies on is re-verified
//! under that key each time it is used: the current `account-state`, each device certificate,
//! each revocation. A row a database writer altered then fails verification instead of being
//! served as authentic. What a database writer who also re-signs with a key of their own can
//! do is replace the whole chain; clients catch that against their pinned identity key
//! (CRYPTO.md §10.3, INV-25), and the server cannot, which is the limit the threat model
//! accepts for a malicious server (A2).
//!
//! **Statements the head does not vouch for.** After a full rotation every certificate and
//! revocation is re-issued under the new identity key (CRYPTO.md §11.6 step 7), so a stored
//! certificate that does not verify under the head is left out: that device cannot
//! authenticate and is not served (INV-30). This also happens, legitimately, during a
//! reconciliation epoch after a restore, between a device re-publishing a newer bundle chain
//! and re-publishing the re-issued certificates (ADR 0012 §7). A stored revocation that does
//! not verify is not served either, but its device still counts as revoked here: an
//! unverifiable revocation never re-admits a device (fail closed).

use rizzy_core::ids::{AccountId, DeviceId};
use rizzy_core::sign::{
    AccountState, DeviceCertificate, DeviceRevocation, Verified, VerifiedBundle,
};
use rizzy_storage::Conn;

use crate::error::AuthError;
use crate::rules;
use crate::sql::{self, fetch_all, fetch_opt};

/// A stored certificate row: device id, kind, certificate, suspension time, storage time.
type CertRow = (Vec<u8>, i64, Vec<u8>, Option<i64>, i64);

/// Error for a stored statement that no longer verifies: an inconsistent or tampered database.
pub(crate) const TAMPERED: AuthError = AuthError::Internal("a stored statement does not verify");

/// The account's verified keys and state, loaded in one transaction.
#[derive(Debug)]
pub(crate) struct AccountTrust {
    /// The account.
    pub(crate) account_id: AccountId,
    /// The stored bundle chain, verified from bundle 1, oldest first; never empty.
    pub(crate) chain: Vec<VerifiedBundle>,
    /// The stored wire form of each bundle of `chain`, in the same order.
    pub(crate) chain_wires: Vec<Vec<u8>>,
    /// The current `account-state`, verified under the identity key of the bundle it commits
    /// to.
    pub(crate) state: Verified<AccountState>,
    /// The state's wire form as stored.
    pub(crate) state_wire: Vec<u8>,
}

impl AccountTrust {
    /// Loads and verifies the chain and the state of `account_id`.
    ///
    /// # Errors
    /// [`AuthError::NotFound`] when the account has no bundle or no state (an unknown account,
    /// or a name reserved by a signup that never finished); [`AuthError::Internal`] when a
    /// stored statement does not verify; storage errors.
    pub(crate) async fn load(mut conn: Conn<'_>, account_id: AccountId) -> Result<Self, AuthError> {
        let id = &account_id.as_bytes()[..];
        let rows: Vec<(i64, Vec<u8>)> =
            fetch_all!(reborrow(&mut conn), (i64, Vec<u8>), sql::BUNDLES_ALL, id)?;
        if rows.is_empty() {
            return Err(AuthError::NotFound);
        }
        let chain_wires: Vec<Vec<u8>> = rows.into_iter().map(|(_, b)| b).collect();
        let wires: Vec<&[u8]> = chain_wires.iter().map(Vec::as_slice).collect();
        let chain = rules::verify_chain_from_start(&wires).map_err(|_| TAMPERED)?;
        if chain.iter().any(|b| b.account_id != account_id) {
            return Err(TAMPERED);
        }
        let (_, state_wire): (i64, Vec<u8>) =
            fetch_opt!(reborrow(&mut conn), (i64, Vec<u8>), sql::STATE_GET, id)?
                .ok_or(AuthError::NotFound)?;
        let state = verify_stored_state(&chain, &state_wire, account_id)?;
        Ok(Self {
            account_id,
            chain,
            chain_wires,
            state,
            state_wire,
        })
    }

    /// The head of the chain: the current identity key (CRYPTO.md §10.2 "Which identity key
    /// verifies what").
    pub(crate) fn head(&self) -> Result<&VerifiedBundle, AuthError> {
        self.chain.last().ok_or(TAMPERED)
    }

    /// The stored wire form of the head bundle.
    pub(crate) fn head_wire(&self) -> Result<&[u8], AuthError> {
        self.chain_wires.last().map(Vec::as_slice).ok_or(TAMPERED)
    }

    /// Every stored certificate and revocation of the account, verified under the head's
    /// identity key (see the module docs for the ones that do not verify).
    pub(crate) async fn devices(&self, mut conn: Conn<'_>) -> Result<Devices, AuthError> {
        let head = self.head()?;
        let id = &self.account_id.as_bytes()[..];
        let cert_rows: Vec<CertRow> = fetch_all!(reborrow(&mut conn), CertRow, sql::CERTS_ALL, id)?;
        let mut certs = Vec::with_capacity(cert_rows.len());
        for (device_id, _kind, wire, suspended, stored_at) in cert_rows {
            let Ok(cert) = rules::verify_certificate(&wire, head, self.account_id) else {
                continue;
            };
            if cert.device_id.as_bytes()[..] != device_id[..] {
                return Err(TAMPERED);
            }
            certs.push(StoredCert {
                cert,
                wire,
                suspended: suspended.is_some(),
                stored_at_ms: sql::sql_u64(stored_at, "stored_at_ms")?,
            });
        }
        let rev_rows: Vec<(Vec<u8>, Vec<u8>)> = fetch_all!(
            reborrow(&mut conn),
            (Vec<u8>, Vec<u8>),
            sql::REVOCATIONS_ALL,
            id
        )?;
        let mut revocations = Vec::with_capacity(rev_rows.len());
        let mut revoked_unverified = Vec::new();
        for (device_id, wire) in rev_rows {
            let device_id = DeviceId::from_bytes(sql::id16(&device_id, "revocation device_id")?);
            match rules::verify_revocation(&wire, head, self.account_id) {
                Ok(revocation) if revocation.device_id == device_id => {
                    revocations.push(StoredRevocation { revocation, wire });
                }
                Ok(_) => return Err(TAMPERED),
                Err(_) => revoked_unverified.push(device_id),
            }
        }
        Ok(Devices {
            certs,
            revocations,
            revoked_unverified,
        })
    }
}

impl AccountTrust {
    /// The stored certificate of `device_id` verified under the bundle of the chain whose
    /// identity key signed it, whichever epoch that is: unlike [`AccountTrust::devices`], which
    /// keeps only what the head vouches for. ADR 0032 §2 compares a re-issued certificate
    /// outside the device set with it ("stored only with the device keys of the stored
    /// certificate of that `device_id`"). `None` when no stored certificate of that device
    /// verifies under any bundle of the chain.
    ///
    /// # Errors
    /// Storage errors.
    pub(crate) async fn stored_certificate(
        &self,
        conn: Conn<'_>,
        device_id: DeviceId,
    ) -> Result<Option<Verified<DeviceCertificate>>, AuthError> {
        let id = &self.account_id.as_bytes()[..];
        let rows: Vec<CertRow> = fetch_all!(conn, CertRow, sql::CERTS_ALL, id)?;
        for (stored_id, _kind, wire, _suspended, _stored_at) in rows {
            if stored_id[..] != device_id.as_bytes()[..] {
                continue;
            }
            for bundle in self.chain.iter().rev() {
                if let Ok(cert) = rules::verify_certificate(&wire, bundle, self.account_id)
                    && cert.device_id == device_id
                {
                    return Ok(Some(cert));
                }
            }
        }
        Ok(None)
    }
}

/// Reborrows a [`Conn`] for one more query.
pub(crate) fn reborrow<'a>(conn: &'a mut Conn<'_>) -> Conn<'a> {
    match conn {
        Conn::Sqlite(c) => Conn::Sqlite(c),
        Conn::Postgres(c) => Conn::Postgres(c),
    }
}

/// Verifies a stored state under the identity key of the bundle it commits to.
fn verify_stored_state(
    chain: &[VerifiedBundle],
    wire: &[u8],
    account_id: AccountId,
) -> Result<Verified<AccountState>, AuthError> {
    // The state verifies only under the key of its own identity epoch; try the chain's
    // bundles newest first.
    for bundle in chain.iter().rev() {
        if let Ok(state) =
            AccountState::verify(wire, &bundle.identity_ed25519, bundle.identity_epoch)
        {
            if state.account_id != account_id || rules::bundle_for_state(chain, &state).is_none() {
                return Err(TAMPERED);
            }
            return Ok(state);
        }
    }
    Err(TAMPERED)
}

/// One stored device certificate, verified.
#[derive(Debug, Clone)]
pub(crate) struct StoredCert {
    /// The verified certificate.
    pub(crate) cert: Verified<DeviceCertificate>,
    /// Its wire form, as stored.
    pub(crate) wire: Vec<u8>,
    /// Whether the device is suspended (CRYPTO.md §11.8 step 0).
    pub(crate) suspended: bool,
    /// When the stored certificate bytes were written: a certificate stored before a
    /// reconciliation epoch opened was in the restored database.
    pub(crate) stored_at_ms: u64,
}

/// One stored device revocation, verified.
#[derive(Debug, Clone)]
pub(crate) struct StoredRevocation {
    /// The verified revocation.
    pub(crate) revocation: Verified<DeviceRevocation>,
    /// Its wire form, as stored.
    pub(crate) wire: Vec<u8>,
}

/// Every verified certificate and revocation of an account.
#[derive(Debug)]
pub(crate) struct Devices {
    /// The certificates that verify under the head, by device id.
    pub(crate) certs: Vec<StoredCert>,
    /// The revocations that verify under the head, by device id.
    pub(crate) revocations: Vec<StoredRevocation>,
    /// Devices with a stored revocation that does not verify under the head: still revoked.
    pub(crate) revoked_unverified: Vec<DeviceId>,
}

impl Devices {
    /// The stored, verified certificate of `device_id`.
    pub(crate) fn cert(&self, device_id: DeviceId) -> Option<&StoredCert> {
        self.certs.iter().find(|c| c.cert.device_id == device_id)
    }

    /// The stored, verified revocation of `device_id`.
    pub(crate) fn revocation(&self, device_id: DeviceId) -> Option<&StoredRevocation> {
        self.revocations
            .iter()
            .find(|r| r.revocation.device_id == device_id)
    }

    /// Whether `device_id` is revoked by any stored revocation, verified or not.
    pub(crate) fn is_revoked(&self, device_id: DeviceId) -> bool {
        self.revocation(device_id).is_some() || self.revoked_unverified.contains(&device_id)
    }

    /// Whether `device_id` may authenticate or act as a device now: a stored certificate the
    /// head vouches for, durable (kinds 1–3; the web vault logs in with OPAQUE every time,
    /// CRYPTO.md §11.4), not revoked, not suspended, not expired at `now_ms`.
    pub(crate) fn usable_durable(&self, device_id: DeviceId, now_ms: u64) -> Option<&StoredCert> {
        self.cert(device_id).filter(|c| {
            c.cert.in_device_set()
                && !c.suspended
                && !self.is_revoked(device_id)
                && (c.cert.expires_at_ms == 0 || now_ms < c.cert.expires_at_ms)
        })
    }

    /// The device-set hash (CRYPTO.md §10.2) of these certificates and revocations after
    /// `new_certs` replace the stored certificate of their device (or join the set) and
    /// `new_revocations` replace or join the stored revocations, as a new state would commit
    /// to.
    pub(crate) fn device_set_with(
        &self,
        account_id: AccountId,
        new_certs: &[Verified<DeviceCertificate>],
        new_revocations: &[Verified<DeviceRevocation>],
    ) -> Result<[u8; 32], AuthError> {
        let mut certs: Vec<Verified<DeviceCertificate>> = self
            .certs
            .iter()
            .filter(|c| !new_certs.iter().any(|n| n.device_id == c.cert.device_id))
            .map(|c| c.cert.clone())
            .collect();
        certs.extend(new_certs.iter().cloned());
        let mut revs: Vec<Verified<DeviceRevocation>> = self
            .revocations
            .iter()
            .filter(|r| {
                !new_revocations
                    .iter()
                    .any(|n| n.device_id == r.revocation.device_id)
            })
            .map(|r| r.revocation.clone())
            .collect();
        revs.extend(new_revocations.iter().cloned());
        rules::device_set(account_id, &certs, &revs)
    }
}
