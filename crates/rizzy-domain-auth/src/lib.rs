//! `rizzy-domain-auth` — the server's auth domain (roadmap M1 step 3; [ADR 0016] §3 row
//! `rizzy-domain-auth`; [ADR 0010] §5; CRYPTO.md §5, §10.2, §11): OPAQUE server side,
//! sessions, device authentication and request signing, devices, key bundles, the signed
//! account state, key grants, server-side 2FA, account recovery and the short-lived auth
//! state, over `rizzy-storage`. Server mode only ([ADR 0022]).
//!
//! # What this crate is, and is not
//!
//! Domain logic with no HTTP: [`AuthService`] takes `rizzy-proto` request types (or, where
//! `rizzy-proto` has none yet, the typed arguments listed under "Left open"), checks them,
//! and runs every read-and-write in one `rizzy-storage` transaction under the account lock
//! ([ADR 0011] "Transactions and concurrency"). The axum wiring, header extraction and
//! status codes are `rizzy-server`'s. The vault domain's side of the cross-domain
//! flows is a trait, [`VaultPort`] ([ADR 0016] R4), which `rizzy-server` implements.
//!
//! # Contract
//!
//! - **Every signature and statement is verified with `rizzy-core`**: bundles, certificates,
//!   revocations, `account-state`s, key grants, `device-auth` and `device-request`. The
//!   server's own database is re-verified from the stored bundle chain on every use
//!   (the private `trust` module); a row that no longer verifies is never served as authentic.
//! - **Randomness and time are injected**: every function that draws takes a
//!   `rizzy_core::rng::CryptoRng` and every function that needs the time takes `now_ms`
//!   ([ADR 0016] R2 (b)).
//! - **Nothing secret reaches the database in the clear** (INV-8, INV-50): bearer tokens as
//!   `SHA-256(token)`, the OPAQUE login state sealed as `SERVER_LOGIN_STATE`, TOTP secrets
//!   sealed as `SERVER_TOTP_SECRET` (CRYPTO.md §5.11), no server secret at all.
//! - **Nothing is logged** by this crate, and errors carry no value ([`AuthError`], INV-48).
//!   Secret types redact their `Debug` and zeroize on drop.
//! - **Enumeration** (CRYPTO.md §5.9, INV-7): an unknown login name runs the same OPAQUE
//!   code path as a real one, over a fake credential id; nothing that differs is computed
//!   before KE3 verifies. Recovery compares a dummy hash for unknown names. Every
//!   authentication failure is the one [`AuthError::Unauthorized`].
//! - **Bound parameters only** (ADR 0011 point 2, INV-53): every query is a `.sql` file under
//!   `queries/`; this crate's `clippy.toml` bans sqlx's escape hatches.
//! - **No `unsafe`**, no `unwrap`/`expect`/`panic!` outside tests.
//!
//! # Module map
//!
//! | Module | Spec | Purpose |
//! |---|---|---|
//! | [`config`] | ADR 0008 decision 5; ADR 0010 §5; ADR 0012 §7; CRYPTO.md §5.9, §5.10 | [`AuthConfig`]: origin, signup policy, lifetimes, recovery wait, rate limits |
//! | [`secrets`] | CRYPTO.md §5.8, §5.11; ADR 0010 §4 | [`ServerSecrets`] (`format = 1`): generation, rotation, dropping unused data keys, startup checks against the database |
//! | [`rules`] | CRYPTO.md §10.2, §11 | Pure checks on untrusted statements and state transitions; the request-counter window |
//! | [`ports`] | ADR 0016 R4 | [`VaultPort`], the vault domain's side |
//! | [`session`] | CRYPTO.md §5.10; INV-8 | Sessions: token hashes, kinds, freshness |
//! | [`directory`] | ADR 0012 §7 "Upload"; ADR 0016 R4 | [`directory::device_authors`]: the verified certificates `rizzy-server` hands the vault domain |
//! | [`types`] | ADR 0016 §3 notes, R4 | The `rizzy-core` and `rizzy-proto` items this API is written in, re-exported one by one for `rizzy-server` |
//! | [`error`] | ADR 0002 point 3 | [`AuthError`] and its API code |
//! | `signup` | CRYPTO.md §11.1, §5.9 | [`AuthService::register_start`], [`AuthService::register_finish`] |
//! | `login` | CRYPTO.md §5.9–§5.11, §11.2, §11.15; INV-7, INV-59 | [`AuthService::login_start`], [`AuthService::login_finish`] |
//! | `device` | CRYPTO.md §5.10, §10.1, §11.2 step 7, §11.4, §11.8 step 0; ADR 0012 §6, §7 | Device authentication, request signing, enrolment, web certificates, grants, suspension |
//! | `change` | CRYPTO.md §11 "Replacing credentials", §11.3 step 5, §11.5, §11.6, §11.8, §11.9 step 6 | [`AuthService::commit_change`]: every atomic change of the signed state with credentials, keys or devices |
//! | `recovery` | CRYPTO.md §11.9; ADR 0008 | [`AuthService::recovery_start`], [`AuthService::recovery_cancel`], [`AuthService::recovery_complete`] |
//! | `totp` | CRYPTO.md §5.11, §11.15 | Server-side 2FA enrolment and removal |
//! | `requests` | CRYPTO.md §11 "Replacing credentials", §11.5, §11.8 step 0, §11.9, §11.15 | The `rizzy-proto` entry points of the flows above that take typed arguments ([`AuthService::commit_change_request`] and the others) |
//! | `healing` | ADR 0012 §7 "Healing a server rollback" steps 1–3; INV-59 | The reconciliation epoch after a restore |
//! | `maintenance` | ADR 0010 §5; ADR 0012 §7; CRYPTO.md §5.11 "Rotation" | What `worker` runs: expired auth state, stale reconciliation epochs, re-sealing TOTP secrets after a data-key rotation |
//!
//! # Readings of the specs (the conservative choice, where they leave room)
//!
//! - **Signup reserves the name at `register_start`.** [`RegisterFinishRequest`] carries no
//!   login name, so the binding of name to `account_id` is stored when the OPAQUE registration
//!   starts (CRYPTO.md §11.1 step 4.2). A reserved name whose signup never finished stays
//!   reserved; no Accepted ADR says when to release it (listed as open).
//! - **Fake `kdf_id`.** Only `kdf_id` 1 exists in M1, so an unknown name always gets 1
//!   (CRYPTO.md §5.9: "While every record is on `kdf_id` 1, it is always 1").
//! - **2FA failure consumes the login.** The sealed login state is read and deleted in one
//!   transaction (§5.11), so a login that verified KE3 but lacked a valid TOTP code must start
//!   again.
//! - **INV-59 is applied everywhere, not only after a restore**: a login whose record's
//!   `password_epoch` is below the signed state's, a recovery whose `H_rec` epoch is not the
//!   state's current one (or whose state says recovery is off), and a device a stored
//!   revocation names are refused.
//! - **Outside the reconciliation epoch, healing only accepts repeats**: every new
//!   `account-state` goes through the flow that makes it (enrolment, [`AuthService::commit_change`])
//!   and its compare-and-swap; bundles and grants are published through those flows too.
//! - **A revocation without a rotation** is accepted only in the self-revocation shape of
//!   CRYPTO.md §11.3 step 5 (one new durable device and one revoked device, over a fresh OPAQUE
//!   session); every other revocation must come with the rotation of §11.8 step 3.
//! - **Replacing an OPAQUE record ends the logins started before it**: every pending login
//!   state of the account is deleted under the account lock (§11.5 step 5, §11.9 step 6,
//!   INV-59).
//! - **Signup counts INV-7's buckets too**: per source (§5.9), per (name, source) and per name.
//! - **The reconciliation epoch's limit holds where the epoch is read**, not only when
//!   `worker` runs; a byte-identical re-upload by a device of the restored set ends the epoch
//!   when the held state was adopted after the restore. A certificate-carrying device
//!   authentication carries the certificates of the state's device set, so the server checks
//!   that the state lists the device (ADR 0012 §7; the wire shape is left open, see below).
//! - **Kind-4 certificates are bounded per account** ([`AuthConfig::max_web_certificates`]):
//!   expired ones that authored nothing are deleted, which §11.6 step 7 allows since a full
//!   rotation need not re-issue them.
//!
//! # Left open, not frozen here
//!
//! No Accepted ADR fixes these, so this crate does not define them:
//! - nothing about the rotation half of [`AuthService::commit_change`] any more: ADR 0025 §1
//!   shapes `rizzy_proto::change::CommitChangeRequest`'s rotation fields, and the `requests`
//!   entry point maps them onto [`AccountChange`] (its vault half through
//!   [`VaultPort::rotation_from_wire`]). Recovery, suspension, TOTP and the other changes have
//!   their `rizzy-proto` requests, and typed entry points ([`RecoveryRelease`],
//!   [`TotpEnrolment`]) beside them;
//! - the invite-token format and who issues invites (the admin API is M3): [`InviteVerifier`];
//! - the secrets file's byte layout is not this crate's (ADR 0028 item 13 fixes it, `rizzy-server`
//!   reads and writes it): [`ServerSecrets`] takes and gives its parts;
//! - how devices and the account email are notified of a new device, a pending or completed
//!   recovery (the `notify` role is M3): the flows return what the server needs to notify;
//! - when an unfinished signup's name reservation is released;
//! - the rate-limit numbers, session lifetimes and the kind-4 certificate bound
//!   ([`RateLimits`], [`AuthConfig`]);
//! - the wire shape of the device-set statements a certificate-carrying device
//!   authentication sends (`rizzy_proto::auth::Reconciliation`'s `device_certificates` and
//!   `device_revocations` mirror `PublishAccountStateRequest`; ADR 0012 §7 names none).
//!
//! # Tests
//!
//! `tests/auth/` runs against real SQLite files: signup, login, device authentication and a
//! signed request end to end with `rizzy-core`'s client-side functions, replay rejection,
//! compare-and-swap races and forks, revocation, the recovery wait, 2FA, re-sealing after a
//! data-key rotation, the reconciliation epoch, and the indistinguishability of unknown and
//! real login names.
//!
//! [ADR 0010]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0010-server-shape.md
//! [ADR 0011]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0011-storage.md
//! [ADR 0016]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0016-workspace-layout.md
//! [ADR 0022]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0022-server-mode-only.md
//! [`RegisterFinishRequest`]: rizzy_proto::auth::RegisterFinishRequest

#![forbid(unsafe_code)]
#![cfg_attr(not(test), warn(clippy::missing_docs_in_private_items))]

pub mod config;
pub mod directory;
pub mod error;
pub mod ports;
pub mod rules;
pub mod secrets;
pub mod session;

mod change;
mod device;
mod healing;
mod login;
mod maintenance;
mod ratelimit;
mod recovery;
mod requests;
mod signup;
mod sql;
mod store;
mod totp;
mod trust;
mod view;

use std::sync::Arc;

use rizzy_core::ids::{AccountId, DeviceId};
use rizzy_proto::wire::{Id, WireError};
use rizzy_storage::{Database, WriteTx};

pub use change::{AccountChange, MAX_RETIRED_KEYS, RecoveryUpload, RetiredSecretKey};
pub use config::{AuthConfig, ConfigError, InviteVerifier, RateLimits, RateRule, SignupPolicy};
pub use device::RequestParts;
pub use error::AuthError;
pub use maintenance::{Purged, Resealed};
pub use ports::{PersonalVault, VaultPort};
pub use recovery::{RecoveryPending, RecoveryRelease};
pub use secrets::{ServerSecrets, StartupCheckError};
pub use session::{Session, SessionKind};
pub use totp::TotpEnrolment;

pub mod types {
    //! The `rizzy-core` and `rizzy-proto` items that [`crate::AuthService`]'s public API is
    //! written in, or that its caller needs to wire it (ADR 0016 R4: "`rizzy-server` implements
    //! the trait by wiring in the other domain's public API"), named one by one.
    //!
    //! ADR 0016 §3 lets `rizzy-server` depend on the domain crates, not on `rizzy-core` or
    //! `rizzy-proto`. A caller of this crate still has to name the types its methods take and
    //! return, so this module re-exports exactly those, and no whole crate: the ids and origin
    //! of the [`crate::VaultPort`] trait and [`crate::AuthConfig`]; the key types of
    //! [`crate::ServerSecrets`] and of its sealed backup (CRYPTO.md §5.8, §5.11); and the
    //! `/api/v1` wire types of the flows' requests, answers and errors, with the header-level
    //! pieces of CRYPTO.md §5.10. Whether `rizzy-server` should instead depend on the shared
    //! crates directly is the owner's decision (an ADR 0016 §3 change); until then, nothing
    //! beyond this list is reachable through this crate.

    /// Ids of the vault port and sessions.
    pub use rizzy_core::ids::{AccountId, DeviceId};
    /// The configured origin ([`crate::AuthConfig::new`]).
    pub use rizzy_core::normalize::ServerOrigin;
    /// The `server_setup` and `enum_key` of [`crate::ServerSecrets`] (CRYPTO.md §5.8).
    pub use rizzy_core::opaque::{EnumKey, SERVER_SETUP_LEN, ServerSetup};
    /// The data keys of [`crate::ServerSecrets`] and the sealed backup of the secrets file
    /// (CRYPTO.md §5.11).
    pub use rizzy_core::server_seal::{BackupHeader, ServerDataKey, ServerSecretsBackupKey};
    /// The backup key's KDF, its passphrase and plaintext type, the RNG trait every flow
    /// takes, and the bound on a sealed field (CRYPTO.md §5.11 "Backup").
    pub use rizzy_core::{
        export::MAX_DATA_FIELD_LEN, kdf::KdfId, rng::CryptoRng, secret::SecretBytes,
    };

    /// `/api/v1` errors and `/api/meta` (ADR 0002 point 3).
    pub use rizzy_proto::error::{ErrorCode, ErrorResponse};
    /// `/api/meta` and the `Rizzy-Client` header (ADR 0002 point 3, as ADR 0022 amends it; ADR
    /// 0028 item 14).
    pub use rizzy_proto::meta::{
        API_V1, ApiVersion, CLIENT_HEADER, ClientHeader, META_PATH, MetaResponse, MinClientVersion,
        Platform, Version, client_too_old,
    };
    /// The self-grants [`crate::VaultPort`] moves between the domains.
    pub use rizzy_proto::objects::VaultSelfGrant;
    /// The bearer token and the request signature, as the headers carry them (CRYPTO.md
    /// §5.10).
    pub use rizzy_proto::{
        auth::RequestSignature,
        limits::SIGNATURE_CONTAINER_LEN,
        wire::{Fixed, List, SessionToken, b64url_len},
    };
    /// The vault half of a rotation and the vaults of a recovery answer, which
    /// [`crate::VaultPort`] hands to and takes from the vault domain (ADR 0025 §1).
    pub use rizzy_proto::{change::VaultRotationUpload, recovery::RecoveryVault};
    /// The HTTP conventions the server applies and clients follow (ADR 0028 items 1, 4, 5 and
    /// 7): the endpoint paths, the bearer scheme, the request-signing headers, the body limits.
    pub use rizzy_proto::{
        http::{
            BEARER_SCHEME, BEARER_TOKEN_CHARS, MAX_REQUEST_COUNTER_DIGITS, REQUEST_COUNTER_HEADER,
            REQUEST_SIGNATURE_CHARS, REQUEST_SIGNATURE_HEADER, paths,
        },
        limits::{DEFAULT_UPLOAD_BODY_LEN, MAX_BODY_LEN, MAX_UPLOAD_BODY_LEN},
    };
}

/// The auth domain: every flow of this crate, over one database.
///
/// Holds the database handle, the server secrets, the configuration and the vault domain's
/// [`VaultPort`]. Cheap to share behind an `Arc`; every method takes `&self`.
#[derive(Debug)]
pub struct AuthService<V> {
    /// The database.
    db: Database,
    /// The server secrets file's contents (CRYPTO.md §5.11).
    secrets: Arc<ServerSecrets>,
    /// The configuration, validated.
    config: AuthConfig,
    /// The vault domain's side of the cross-domain flows.
    vault: V,
}

impl<V: VaultPort> AuthService<V> {
    /// Builds the service. Run [`ServerSecrets::check_database`] first: the server refuses to
    /// start if it fails (CRYPTO.md §5.8, §5.11).
    ///
    /// # Errors
    /// [`ConfigError`] when the configuration is outside the bounds the specs set.
    pub fn new(
        db: Database,
        secrets: Arc<ServerSecrets>,
        config: AuthConfig,
        vault: V,
    ) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self {
            db,
            secrets,
            config,
            vault,
        })
    }

    /// The configuration.
    #[must_use]
    pub const fn config(&self) -> &AuthConfig {
        &self.config
    }

    /// The database.
    #[must_use]
    pub const fn database(&self) -> &Database {
        &self.db
    }

    /// Ends the transaction of a flow that took a row used at most once (a sealed login state,
    /// CRYPTO.md §5.11; a device-auth challenge, §5.10) with `outcome`.
    ///
    /// On success, and on a refusal of the flow (see [`is_refusal`]), `tx` is committed, so the
    /// take stands together with what the refusal counted (a TOTP attempt). Any other error
    /// (storage, an internal inconsistency such as a TOTP secret sealed under a data key the
    /// secrets file lacks) rolls `tx` back, which would restore the taken row; the row is then
    /// deleted again in its own transaction with `discard` (one bound parameter, `key`), so it
    /// stays used at most once whatever went wrong after the take. A failure of that deletion
    /// is returned instead of `outcome`'s error, as it is the one that leaves the row usable
    /// until its 60 s expiry.
    pub(crate) async fn settle_single_use<T>(
        &self,
        tx: WriteTx,
        outcome: Result<T, AuthError>,
        discard: &'static str,
        key: &[u8],
    ) -> Result<T, AuthError> {
        match outcome {
            Ok(value) => {
                tx.commit().await?;
                Ok(value)
            }
            Err(e) if is_refusal(&e) => {
                tx.commit().await?;
                Err(e)
            }
            Err(e) => {
                let rolled_back = tx.rollback().await;
                let mut discard_tx = self.db.begin_write().await?;
                sql::exec!(discard_tx.conn(), discard, key)?;
                discard_tx.commit().await?;
                rolled_back?;
                Err(e)
            }
        }
    }
}

/// Whether `e` is a refusal a flow decided on, whose transaction is committed (the writes made
/// up to the refusal, such as taking a single-use row or counting an attempt, stand), as
/// opposed to a failure that rolls the transaction back.
pub(crate) const fn is_refusal(e: &AuthError) -> bool {
    matches!(
        e,
        AuthError::Unauthorized
            | AuthError::InvalidRequest
            | AuthError::SecondFactorRequired
            | AuthError::RateLimited { .. }
    )
}

/// The account id a wire id names.
pub(crate) const fn account_id(id: &Id) -> AccountId {
    AccountId::from_bytes(id.to_bytes())
}

/// The device id a wire id names.
pub(crate) const fn device_id(id: &Id) -> DeviceId {
    DeviceId::from_bytes(id.to_bytes())
}

/// A stored object that no longer fits its wire limit: the database is inconsistent.
pub(crate) fn over_limit(_: WireError) -> AuthError {
    AuthError::Internal("a stored object exceeds its wire limit")
}
