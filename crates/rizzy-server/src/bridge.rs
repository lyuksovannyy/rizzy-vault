//! The two cross-domain traits, implemented by wiring in the other domain's public API
//! ([ADR 0016] R4: "A domain that needs something from another defines a trait for it.
//! `rizzy-server` implements the trait by wiring in the other domain's public API").
//!
//! - [`VaultBridge`] is the `auth` domain's [`VaultPort`], over `rizzy_domain_vault::port`.
//! - [`AuthDirectory`] is the `vault` domain's [`DeviceDirectory`], over
//!   `rizzy_domain_auth::directory::device_authors`.
//!
//! Both run on the transaction or connection they are handed, so every cross-domain read or
//! write joins the caller's one transaction and account lock (ADR 0011 "Transactions and
//! concurrency"). Neither holds state.
//!
//! **Errors.** A vault-side refusal answers the auth flow with the matching auth error
//! (`NotFound` and `Invalid` as `InvalidRequest`); a storage or integrity failure is an
//! [`AuthError::Internal`] naming the port, never a value. A certificate read that fails is a
//! [`DirectoryError`], and the upload fails.
//!
//! **Rotation.** The vault half of a key rotation (CRYPTO.md §11.6 step 9) has no wire form yet
//! (`rizzy-proto` defines no rotation request, and `rizzy-domain-vault` has no rotation
//! upload), so [`VaultBridge`]'s rotation type is the uninhabited [`NoRotation`]: no rotation
//! can be built, and `apply_rotation` can never run.
//!
//! [ADR 0016]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0016-workspace-layout.md

use rizzy_domain_auth::directory::{DeviceStanding, device_authors};
use rizzy_domain_auth::types::VaultSelfGrant;
use rizzy_domain_auth::types::{AccountId, DeviceId};
use rizzy_domain_auth::{AuthError, PersonalVault, VaultPort};
use rizzy_domain_vault::port;
use rizzy_domain_vault::{
    AuthorCertificate, AuthorStatus, Authors, DeviceDirectory, DirectoryError,
    PersonalVaultOutcome, VaultError,
};
use rizzy_storage::{Conn, WriteTx};

/// The vault half of a key rotation: none can exist in this build (module docs).
#[derive(Debug)]
pub enum NoRotation {}

/// The `auth` domain's view of the `vault` domain (module docs).
#[derive(Clone, Copy, Debug, Default)]
pub struct VaultBridge;

/// Maps a vault error inside an auth flow.
fn vault_error(e: &VaultError) -> AuthError {
    match e {
        VaultError::NotFound | VaultError::Invalid => AuthError::InvalidRequest,
        _ => AuthError::Internal("the vault domain failed inside an auth flow"),
    }
}

impl VaultPort for VaultBridge {
    type Rotation = NoRotation;

    async fn apply_rotation(
        &self,
        _tx: &mut WriteTx,
        _account_id: AccountId,
        _new_account_key_epoch: u32,
        rotation: &Self::Rotation,
        _now_ms: u64,
    ) -> Result<(), AuthError> {
        match *rotation {}
    }

    async fn create_personal_vault(
        &self,
        tx: &mut WriteTx,
        account_id: AccountId,
        grant: &VaultSelfGrant,
        now_ms: u64,
    ) -> Result<PersonalVault, AuthError> {
        match port::create_personal_vault(tx, account_id, grant, now_ms).await {
            Ok(PersonalVaultOutcome::Created) => Ok(PersonalVault::Created),
            Ok(PersonalVaultOutcome::Identical) => Ok(PersonalVault::Identical),
            Ok(PersonalVaultOutcome::Conflict) => Ok(PersonalVault::Conflict),
            Err(e) => Err(vault_error(&e)),
        }
    }

    async fn self_grants(
        &self,
        conn: Conn<'_>,
        account_id: AccountId,
        account_key_epoch: u32,
    ) -> Result<Vec<VaultSelfGrant>, AuthError> {
        port::self_grants(conn, account_id, account_key_epoch)
            .await
            .map_err(|e| vault_error(&e))
    }

    async fn store_self_grants(
        &self,
        tx: &mut WriteTx,
        account_id: AccountId,
        grants: &[VaultSelfGrant],
        now_ms: u64,
    ) -> Result<(), AuthError> {
        port::store_self_grants(tx, account_id, grants, now_ms)
            .await
            .map_err(|e| vault_error(&e))
    }

    async fn device_head(
        &self,
        conn: Conn<'_>,
        account_id: AccountId,
        device_id: DeviceId,
    ) -> Result<u64, AuthError> {
        port::device_head(conn, account_id, device_id)
            .await
            .map_err(|e| vault_error(&e))
    }
}

/// The `vault` domain's view of the `auth` domain's certificates (module docs).
#[derive(Clone, Copy, Debug, Default)]
pub struct AuthDirectory;

impl DeviceDirectory for AuthDirectory {
    async fn authors<'a>(
        &'a self,
        conn: Conn<'a>,
        account_id: AccountId,
    ) -> Result<Authors, DirectoryError> {
        let authors = device_authors(conn, account_id)
            .await
            .map_err(|_| DirectoryError {
                what: "the auth domain could not read the account's certificates",
            })?;
        Authors::new(
            authors
                .into_iter()
                .map(|a| AuthorCertificate {
                    device_id: a.device_id,
                    verifying_key: a.verifying_key,
                    device_kind: a.device_kind,
                    expires_at_ms: a.expires_at_ms,
                    status: match a.standing {
                        DeviceStanding::Active => AuthorStatus::Active,
                        DeviceStanding::Suspended => AuthorStatus::Suspended,
                        DeviceStanding::Revoked {
                            last_accepted_device_seq,
                        } => AuthorStatus::Revoked {
                            last_accepted_device_seq,
                        },
                    },
                })
                .collect(),
        )
        .map_err(|_| DirectoryError {
            what: "two certificates name one device or one key",
        })
    }
}
