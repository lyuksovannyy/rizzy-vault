//! The signed account objects a client verifies (CRYPTO.md §11.2 steps 5–6, §11.3 step 2.2,
//! §11.9 step 3): [`AuthService::account_view`] and the builder the login and recovery flows
//! share.
//!
//! Everything served here was re-verified from the stored bundle chain first ([`crate::trust`]):
//! the state under its identity key, each certificate and revocation under the head. The
//! client verifies all of it again against its own pins (INV-25); the server's copy is never
//! the authority.

use rizzy_proto::account::{AccountStateQuery, AccountView};
use rizzy_proto::objects::{AccountSettings, IdentitySecretKeys};
use rizzy_proto::wire::{Bytes, List};
use rizzy_storage::Conn;

use crate::error::AuthError;
use crate::ports::VaultPort;
use crate::session::Session;
use crate::store;
use crate::trust::{AccountTrust, Devices, reborrow};
use crate::{AuthService, over_limit};

/// Which bundles and settings a view carries.
#[derive(Clone, Copy, Debug)]
pub(crate) enum ViewScope {
    /// After a login or a recovery release: the current bundle, and the settings if any
    /// (§11.2 step 5: "the current bundle").
    Current,
    /// After a login where the client asks for the whole chain (recovery, §11.9 step 4
    /// verifies the bundle and state as §11.2 step 6 does): every bundle.
    Chain,
    /// After an [`AccountStateQuery`]: every bundle above the cached `bundle_seq`, and the
    /// settings only if `settings_seq` changed (§11.3 step 2.2).
    Since(AccountStateQuery),
}

/// Builds the view of an account from a verified trust and its verified devices.
pub(crate) async fn build<V: VaultPort>(
    vault: &V,
    mut conn: Conn<'_>,
    trust: &AccountTrust,
    devices: &Devices,
    scope: ViewScope,
) -> Result<AccountView, AuthError> {
    let bundles: Vec<Vec<u8>> = match scope {
        ViewScope::Current => vec![trust.head_wire()?.to_vec()],
        ViewScope::Chain => trust.chain_wires.clone(),
        ViewScope::Since(q) => trust
            .chain
            .iter()
            .zip(&trust.chain_wires)
            .filter(|(b, _)| b.bundle_seq > q.known_bundle_seq)
            .map(|(_, w)| w.clone())
            .collect(),
    };
    let bundles = bundles
        .into_iter()
        .map(Bytes::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(over_limit)?;
    let settings = store::settings(reborrow(&mut conn), trust.account_id).await?;
    let known_settings = match scope {
        ViewScope::Since(q) => Some(q.known_settings_seq),
        ViewScope::Current | ViewScope::Chain => None,
    };
    let account_settings = match settings {
        Some((seq, envelope)) if seq == trust.state.settings_seq && known_settings != Some(seq) => {
            Some(AccountSettings {
                settings_seq: seq,
                envelope: Bytes::new(envelope).map_err(over_limit)?,
            })
        }
        _ => None,
    };
    let (identity_epoch, e_id) = store::identity(reborrow(&mut conn), trust.account_id)
        .await?
        .ok_or(AuthError::Internal("an account without E_id"))?;
    let grants = vault
        .self_grants(
            reborrow(&mut conn),
            trust.account_id,
            trust.state.account_key_epoch,
        )
        .await?;
    Ok(AccountView {
        account_state: Bytes::new(trust.state_wire.clone()).map_err(over_limit)?,
        bundles: List::new(bundles).map_err(over_limit)?,
        device_certificates: List::new(
            devices
                .certs
                .iter()
                .map(|c| Bytes::new(c.wire.clone()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(over_limit)?,
        )
        .map_err(over_limit)?,
        device_revocations: List::new(
            devices
                .revocations
                .iter()
                .map(|r| Bytes::new(r.wire.clone()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(over_limit)?,
        )
        .map_err(over_limit)?,
        account_settings,
        identity_secret_keys: IdentitySecretKeys {
            identity_epoch,
            envelope: Bytes::new(e_id).map_err(over_limit)?,
        },
        vault_self_grants: List::new(grants).map_err(over_limit)?,
    })
}

impl<V: VaultPort> AuthService<V> {
    /// The unlock's online part (CRYPTO.md §11.3 step 2.2): the current `account-state`, every
    /// bundle above `query.known_bundle_seq`, the certificates and revocations, `E_id`, the
    /// self-grants, and `ACCOUNT_SETTINGS` if `settings_seq` changed.
    ///
    /// Any authenticated session of the account may read it: a device session, an OPAQUE
    /// session, or the recovery-only session (which covers the reads the recovery's rotation
    /// needs, §11.9 step 3).
    ///
    /// # Errors
    /// [`AuthError::Unauthorized`] for an expired session; [`AuthError::Internal`] when a
    /// stored statement does not verify; storage errors.
    pub async fn account_view(
        &self,
        session: &Session,
        query: AccountStateQuery,
        now_ms: u64,
    ) -> Result<AccountView, AuthError> {
        let mut tx = self.db.begin_read().await?;
        crate::session::reload(tx.conn(), session, now_ms).await?;
        let trust = AccountTrust::load(tx.conn(), session.account_id).await?;
        let devices = trust.devices(tx.conn()).await?;
        let view = build(
            &self.vault,
            tx.conn(),
            &trust,
            &devices,
            ViewScope::Since(query),
        )
        .await?;
        tx.finish().await?;
        Ok(view)
    }
}
