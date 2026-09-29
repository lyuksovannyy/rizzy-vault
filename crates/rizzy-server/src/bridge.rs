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
//! (`NotFound` and `Invalid` as `InvalidRequest`, `StateConflict` as `StateConflict`); a
//! storage or integrity failure is an [`AuthError::Internal`] naming the port, never a value
//! (INV-48). A certificate read that fails is a [`DirectoryError`], and the upload fails.
//!
//! **Rotation** (ADR 0025 §3–§4). [`VaultBridge`]'s rotation type is the parsed vault half,
//! `rizzy_proto::change::VaultRotationUpload`, and `apply_rotation` runs
//! `rizzy_domain_vault::rotation::apply_rotation` on the commit's own transaction, under the
//! account lock the `auth` domain took, before its compare-and-swap. The recovery answer's
//! vaults come from `rizzy_domain_vault::port::recovery_vaults` on the same transaction.
//!
//! [ADR 0016]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0016-workspace-layout.md

use rizzy_domain_auth::directory::{DeviceStanding, device_authors};
use rizzy_domain_auth::types::{AccountId, DeviceId};
use rizzy_domain_auth::types::{RecoveryVault, VaultRotationUpload, VaultSelfGrant};
use rizzy_domain_auth::{AuthError, PersonalVault, VaultPort};
use rizzy_domain_vault::{
    AuthorCertificate, AuthorStatus, Authors, DeviceDirectory, DirectoryError,
    PersonalVaultOutcome, VaultError,
};
use rizzy_domain_vault::{port, rotation};
use rizzy_storage::{Conn, WriteTx};

/// The `auth` domain's view of the `vault` domain (module docs).
#[derive(Clone, Copy, Debug, Default)]
pub struct VaultBridge;

/// Maps a vault error inside an auth flow.
fn vault_error(e: &VaultError) -> AuthError {
    match e {
        VaultError::NotFound | VaultError::Invalid => AuthError::InvalidRequest,
        VaultError::StateConflict => AuthError::StateConflict,
        _ => AuthError::Internal("the vault domain failed inside an auth flow"),
    }
}

impl VaultPort for VaultBridge {
    type Rotation = VaultRotationUpload;

    fn rotation_from_wire(upload: VaultRotationUpload) -> Self::Rotation {
        upload
    }

    async fn apply_rotation(
        &self,
        tx: &mut WriteTx,
        account_id: AccountId,
        new_account_key_epoch: u32,
        new_account_key_id: [u8; 16],
        rotation: &Self::Rotation,
        now_ms: u64,
    ) -> Result<(), AuthError> {
        rotation::apply_rotation(
            tx,
            account_id,
            new_account_key_epoch,
            &new_account_key_id,
            rotation,
            now_ms,
        )
        .await
        .map_err(|e| vault_error(&e))
    }

    async fn recovery_vaults(
        &self,
        conn: Conn<'_>,
        account_id: AccountId,
    ) -> Result<Vec<RecoveryVault>, AuthError> {
        port::recovery_vaults(conn, account_id)
            .await
            .map_err(|e| vault_error(&e))
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
