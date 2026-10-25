// SPDX-License-Identifier: AGPL-3.0-only

//! Recovery with the Emergency Kit (CRYPTO.md §11.9), on a computer where this account is not
//! enrolled.
//!
//! - `rv recovery start` sends `{login_name, recovery_auth_token}` to `recovery/start`. The
//!   server opens the pending recovery, notifies every enrolled device and starts the waiting
//!   period (72 h by default); the command prints when the recovery can be completed.
//! - `rv recovery complete`, after the wait: `recovery/complete`, then the client flow of
//!   `rizzy_client::recovery`: `E_rec` opens under the typed code, the whole answer is
//!   verified, a new master password is set, a **new Secret Key and recovery code** are
//!   generated, the new Emergency Kit is printed and confirmed, the cache is written in stage 3
//!   (recovery-pending), and the commit replaces the credentials, rotates the account and vault
//!   keys (unless `--skip-rotation`), and enrols this computer as a device (see "Secrets before
//!   commit" below).
//! - `rv recovery cancel`, on an enrolled device: cancels a pending recovery (§11.9 step 2:
//!   "Any enrolled device with a device-authenticated session can cancel").
//! - Every command that goes online on an enrolled device warns, loudly and every time, while
//!   the server reports a pending recovery ([ADR 0045] open question 3), and `rv account
//!   status` shows it ([`notice_warning`], [`status`]). The notice is the server's word,
//!   never verified and never read by a check (INV-70); `item list`/`show`/`totp` and
//!   `generate` stay offline and never see it (ADR 0045 point 9).
//!
//! [ADR 0045]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0045-recovery-pending-notification.md
//! - `rv recovery repair`, on an enrolled device, after the server was restored from a backup
//!   (ADR 0032 §4 step 6): replaces the server's `H_rec` and `E_rec` together, with a new code
//!   and kit, or with `--retype` the current code ([`repair`]).
//!
//! A computer that still holds this account's cache must run `rv device forget` first: its
//! device state is under the forgotten password and cannot be carried over.
//!
//! # Secrets before commit ([ADR 0046] §2)
//!
//! After the new kit is confirmed, and **before** `account/commit` is sent, the whole cache of
//! the new device is created in one transaction: the device-state record in stage 3, the exact
//! commit body as `pending_commit`, the account objects after the commit and the wrap sets
//! (`PendingRecovery::store_writes`). The account's lock is taken as soon as the answer of
//! `recovery/complete` names the account, before any secret is generated, and held to the end.
//! The answer to the commit then decides:
//!
//! - acknowledged: the record becomes stage 1 and the stored body is removed; the device syncs;
//! - refused with an `/api/v1` error ([`CliError::refuses_commit`]): nothing was applied, the
//!   cache is removed again and the kit shown is void;
//! - `setup_retired` (ADR 0031 point 8): the registration is restarted once with the same
//!   `pw_in`, the stored body rewritten with only its upload, `setup_id` and `E_srv'` replaced,
//!   and resent;
//! - anything else (no answer, a proxy's error page, `internal`, a rate limit): the stage-3
//!   cache stays, and the next `rv recovery complete` settles it.
//!
//! # Settling a stage-3 record ([ADR 0046] §2 "Finding the record", §3)
//!
//! Before it asks for anything, `rv recovery complete` opens every cache file of the data
//! directory ([`enrolled_accounts`]). A stage-3 record for the server given is settled, and no
//! login name, recovery code or new password is asked for a new attempt:
//!
//! 1. The new master password of the unfinished attempt unlocks the record
//!    (`DeviceRecord::unlock_recovery_pending`); a wrong one fails here, with no round trip.
//! 2. Device authentication with the record's own device id and **no** reconciliation objects.
//!    Success proves the commit landed and this device stands: the record is finalised and the
//!    device opens and syncs like any enrolled one. A `401` proves nothing: next step.
//! 3. An OPAQUE login with the record's Secret Key and the password, under `--name`. Success,
//!    or `second_factor_required` (answered only once the password matched): the commit landed.
//!    The record is finalised, nothing is removed, and the user is told this device was not
//!    accepted and must be enrolled again. A wrong-credentials answer: the commit did not land,
//!    next step. Anything else: the record stays, and the command stops.
//! 4. The original recovery code is typed again and `recovery/complete` answered: its
//!    recovery-only session resends the stored body **byte for byte** (a byte-identical repeat
//!    is success, ADR 0028); `setup_retired` as above. Acknowledged: finalised as in step 2.
//!    `unauthorized` from `recovery/complete` (the pending recovery was cancelled) or any
//!    refusal of the resend (`state_conflict`, `unauthorized`, …): step 5. Anything else: the
//!    record stays.
//! 5. Abandon: the cache file is deleted under the lock, every row the pre-commit write created
//!    with it, in one step. Step 3 proved this attempt's commit is not the live one, so its kit
//!    is void; the user runs `rv recovery complete` from the start.
//!
//! No step generates a secret: the resume never builds a commit, so this computer holds at most
//! one unconfirmed recovery commit's secrets per account (threat model INV-71). A new attempt
//! for an account whose cache file exists is refused ([`CliError::AlreadyEnrolled`]) before
//! any secret is generated, and every other command, `rv device forget` included, refuses a
//! stage-3 record and points at `rv recovery complete`.
//!
//! [ADR 0046]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0046-recovery-pending-device-stage.md

use rizzy_client::ClientError;
use rizzy_client::account::RecoveryNotice;
use rizzy_client::identity_gen::CivilDate;
use rizzy_client::login::{LoginInput, start_login};
use rizzy_client::recovery::{PendingRecovery, RecoveryInput, RecoveryOptions, start_recovery};
use rizzy_client::rizzy_proto::auth::{
    DeviceAuthFinishResponse, DeviceAuthStartResponse, LoginFinishResponse, LoginStartResponse,
};
use rizzy_client::rizzy_proto::change::{CommitChangeRequest, ReregisterStartResponse};
use rizzy_client::rizzy_proto::error::ErrorCode;
use rizzy_client::rizzy_proto::http::paths;
use rizzy_client::rizzy_proto::recovery::{RecoveryCompleteResponse, RecoveryStartResponse};
use rizzy_client::rizzy_proto::wire::SessionToken;
use rizzy_client::session::{
    device_auth_finish_recovery_pending, device_auth_start_recovery_pending,
};
use rizzy_client::signup::DeviceKind;
use rizzy_client::store::floors::Floors;
use rizzy_client::store::load;
use rizzy_client::store::record::{DeviceRecord, Stage};
use rizzy_client::store::{self};
use rizzy_client::sync::VaultSync;
use rizzy_client::vaults::VaultCatalog;
use zeroize::Zeroizing;

use crate::commands::delete_account_files;
use crate::db::Db;
use crate::device::{Device, Env, copy_token};
use crate::error::CliError;
use crate::http::{Auth, Http};
use crate::paths::{AccountLock, cache_path, check_data_dir, enrolled_accounts, ensure_data_dir};
use crate::sys::{OsRng, now_ms, os_rng};

/// `recovery start`.
///
/// # Errors
/// [`CliError::Server`] with `unauthorized` for a wrong code or an unknown name (one answer,
/// CRYPTO.md §5.9); the transport's errors.
pub async fn start(env: &mut Env<'_>, server: &str, login_name: &str) -> Result<(), CliError> {
    let http = Http::new(server, &env.trust)?;
    let code = env.ui.secret("Recovery code (RVR1-…)")?;
    let started = start_recovery(&RecoveryInput {
        server_origin: http.origin().as_str(),
        login_name,
        recovery_code: &code,
    })?;
    let answer: RecoveryStartResponse = http
        .post(paths::RECOVERY_START, &started.request()?, Auth::None)
        .await?;
    let wait_s = answer
        .available_at_ms
        .saturating_sub(now_ms())
        .div_ceil(1000);
    env.ui.note(&format!(
        "Recovery requested. Every enrolled device is told and can cancel it. It can be \
         completed in {} h {} min with `rv recovery complete`.",
        wait_s / 3600,
        (wait_s % 3600) / 60
    ));
    env.ui.print(&answer.available_at_ms.to_string())
}

/// `recovery complete` (module docs). `rotate` is the default; `false` is `--skip-rotation`.
///
/// # Errors
/// [`CliError::RateLimited`] while the waiting period runs; [`CliError::AlreadyEnrolled`] if
/// this computer holds the account's cache; the flow's and the transport's errors; while a
/// stage-3 record is settled, the error that left it unsettled or abandoned.
pub async fn complete(
    env: &mut Env<'_>,
    server: &str,
    login_name: &str,
    rotate: bool,
) -> Result<(), CliError> {
    let http = Http::new(server, &env.trust)?;
    // ADR 0046 §2: a stage-3 record for this server is settled before anything is asked.
    if let Some(account) = pending_recovery(env, &http).await? {
        return Box::pin(resume(env, http, login_name, account)).await;
    }
    let prepared = Box::pin(prepare_with(env, http, login_name)).await?;
    let prepared = Box::pin(prepared.build(env, rotate)).await?;
    Box::pin(prepared.commit(env)).await
}

/// The steps of a new recovery attempt up to its pre-commit write (module docs, "Secrets before
/// commit"): `recovery/complete`, the new credentials, the kit printed and confirmed, the
/// stage-3 cache created. Dropping the result is a crash before the commit is sent; the next
/// `rv recovery complete` settles the record. [`complete`] first looks for a stage-3 record
/// to settle; this does not, and relies on the refusal of an account whose cache file exists.
///
/// # Errors
/// As [`complete`].
pub async fn prepare(
    env: &mut Env<'_>,
    server: &str,
    login_name: &str,
    rotate: bool,
) -> Result<PreparedRecovery, CliError> {
    let http = Http::new(server, &env.trust)?;
    let prepared = Box::pin(prepare_with(env, http, login_name)).await?;
    Box::pin(prepared.build(env, rotate)).await
}

/// The account of a stage-3 record for `http`'s origin in the data directory, if there is one
/// (ADR 0046 §2 "Finding the record on the next invocation"). A cache another process holds,
/// or one that does not open, is passed over: if it is the recovered account's, the refusal of
/// a new attempt for an account whose file exists stops that attempt before any secret is
/// generated.
async fn pending_recovery(env: &Env<'_>, http: &Http) -> Result<Option<[u8; 16]>, CliError> {
    for account in enrolled_accounts(&env.data_dir)? {
        let Ok(lock) = AccountLock::acquire(&env.data_dir, &account) else {
            continue;
        };
        let Ok(mut db) = Db::open(&cache_path(&env.data_dir, &account)).await else {
            continue;
        };
        let rows = db.read().await;
        db.close().await;
        drop(lock);
        let Ok(rows) = rows else { continue };
        // `keystore_capable = false`, as everywhere in `rv` (ADR 0057 §2, INV-81).
        let Ok(record) = load::open(&rows, false) else {
            continue;
        };
        if record.stage() == Stage::RecoveryPending
            && record.server_origin().as_str() == http.origin().as_str()
        {
            return Ok(Some(account));
        }
    }
    Ok(None)
}

/// A recovery attempt whose `recovery/complete` answer verified, the account's lock taken.
struct Opened {
    /// The transport.
    http: Http,
    /// The verified recovery.
    recovered: rizzy_client::recovery::Recovered,
    /// The account's lock, taken before any secret is generated (INV-71).
    lock: AccountLock,
    /// The account id.
    account: [u8; 16],
}

/// `recovery/complete` with the typed code, the answer verified, and the account's lock taken
/// with no cache file for it (INV-71: no second kit while one may be live).
async fn prepare_with(env: &mut Env<'_>, http: Http, login_name: &str) -> Result<Opened, CliError> {
    let code = env.ui.secret("Recovery code (RVR1-…)")?;
    let started = start_recovery(&RecoveryInput {
        server_origin: http.origin().as_str(),
        login_name,
        recovery_code: &code,
    })?;
    let answer: RecoveryCompleteResponse = http
        .post(paths::RECOVERY_COMPLETE, &started.request()?, Auth::None)
        .await?;
    drop(code);
    let recovered = started.open(answer)?;
    let account = recovered.account().account_id().to_bytes();
    if cache_path(&env.data_dir, &account).exists() {
        return Err(CliError::AlreadyEnrolled);
    }
    ensure_data_dir(&env.data_dir)?;
    let lock = AccountLock::acquire(&env.data_dir, &account)?;
    // Checked again under the lock: another `rv` may have written its stage-3 file since.
    if cache_path(&env.data_dir, &account).exists() {
        return Err(CliError::AlreadyEnrolled);
    }
    Ok(Opened {
        http,
        recovered,
        lock,
        account,
    })
}

impl Opened {
    /// The new credentials over the recovery-only session, the kit printed and confirmed, then
    /// the stage-3 cache written (module docs).
    async fn build(self, env: &mut Env<'_>, rotate: bool) -> Result<PreparedRecovery, CliError> {
        let Self {
            http,
            recovered,
            lock,
            account,
        } = self;
        let password = env.ui.secret("New master password")?;
        let again = env.ui.secret("New master password, again")?;
        if *password != *again {
            return Err(CliError::BadInput("the two passwords differ"));
        }
        if !rotate {
            env.ui.note(
                "Skipping the key rotation: anyone who holds the old recovery code and an old \
                 copy of the server's data can still read this account's future items.",
            );
        }
        let token = copy_token(recovered.bearer_token());
        let mut rng = os_rng();
        let (reregistering, request) = recovered.start_commit(
            &mut rng,
            &RecoveryOptions {
                new_password: &password,
                rotate,
                device_kind: DeviceKind::DesktopCli,
                now_ms: now_ms(),
            },
        )?;
        let answer: ReregisterStartResponse = http
            .post(
                paths::ACCOUNT_REREGISTER_START,
                &request,
                Auth::Bearer(&token),
            )
            .await?;
        let mut pending = reregistering.finish(&mut rng, &answer)?;

        // Secrets before commit (CRYPTO.md §11): the new kit is shown and confirmed first.
        let kit = pending.emergency_kit();
        env.ui
            .print("NEW EMERGENCY KIT — the old one no longer works. Print it or write it down.")?;
        env.ui
            .print(&format!("Server:        {}", kit.server_origin()))?;
        env.ui
            .print(&format!("Login name:    {}", kit.login_name()))?;
        env.ui
            .print(&format!("Secret Key:    {}", kit.secret_key()))?;
        if let Some(new_code) = kit.recovery_code() {
            env.ui.print(&format!("Recovery code: {new_code}"))?;
        }
        let typed = env
            .ui
            .line("Type the last four characters of the Secret Key to confirm you saved the kit")?;
        pending.confirm_kit(typed.trim())?;

        // ADR 0046 §2: the stage-3 cache with the exact body, before the commit leaves.
        let body =
            serde_json::to_vec(pending.commit_request()?).map_err(|_| ClientError::Internal)?;
        let first = pending.store_writes(&body)?;
        let mut floors = Floors::empty();
        floors.admit(&first)?;
        let db = Db::create(&cache_path(&env.data_dir, &account), &first).await?;
        Ok(PreparedRecovery {
            http,
            pending,
            body,
            token,
            lock,
            db,
            floors,
            account,
            password,
        })
    }
}

/// A recovery after its pre-commit write: the kit is confirmed and the stage-3 cache, with the
/// exact `account/commit` body, is on disk. Dropping it is a crash before the commit: the next
/// `rv recovery complete` settles the record (module docs).
pub struct PreparedRecovery {
    /// The transport.
    http: Http,
    /// The recovery, waiting for the commit.
    pending: PendingRecovery,
    /// The exact body stored as `pending_commit`.
    body: Vec<u8>,
    /// The recovery-only session (a secret).
    token: SessionToken,
    /// The account's lock.
    lock: AccountLock,
    /// The stage-3 cache.
    db: Db,
    /// Its floors.
    floors: Floors,
    /// The account id.
    account: [u8; 16],
    /// The new master password, which the unlock of the new device reuses.
    password: Zeroizing<String>,
}

impl std::fmt::Debug for PreparedRecovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedRecovery").finish_non_exhaustive()
    }
}

impl PreparedRecovery {
    /// The exact body stored as `pending_commit`, which every send of this attempt sends.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Sends the commit and settles the attempt on its answer (module docs, "Secrets before
    /// commit"); on the acknowledgement the record becomes stage 1 and the device syncs once.
    ///
    /// # Errors
    /// The answer that refused the commit (the cache is then removed), or that left it
    /// outstanding (the stage-3 cache stays); the flow's errors.
    pub async fn commit(self, env: &mut Env<'_>) -> Result<(), CliError> {
        let Self {
            http,
            pending,
            body,
            token,
            lock,
            mut db,
            mut floors,
            account,
            password,
        } = self;
        let record = pending.device().record(Stage::RecoveryPending)?;
        let sent = send_commit(
            &http,
            &mut db,
            &record,
            pending.unlocked(),
            &password,
            body,
            &token,
        )
        .await;
        match sent {
            Ok(()) => {}
            Err(refused) if refused.refuses_commit() => {
                // An `/api/v1` refusal: nothing was applied, so the file holds no enrolment.
                abandon(env, &account, db, lock).await?;
                env.ui.note(
                    "The server did not apply the recovery: nothing changed on the account, and \
                     the Emergency Kit shown above is void.",
                );
                return Err(refused);
            }
            Err(kept) => {
                env.ui.note(if kept.outcome_unknown() {
                    "Whether the server applied the recovery is unknown. It is saved on this \
                     computer: run `rv recovery complete` again with the same server and login \
                     name to settle it. Keep both Emergency Kits until then."
                } else {
                    "The recovery was not sent through. It is saved on this computer: run \
                     `rv recovery complete` again later with the same server and login name to \
                     finish it. Keep both Emergency Kits until then."
                });
                return Err(kept);
            }
        }

        // The server acknowledged: this computer is a device of the account.
        let finalise = store::finalize_writes(&pending.device().record(Stage::Committed)?)?;
        floors.admit(&finalise)?;
        db.write(&finalise).await?;
        let done = pending.finalize()?;
        // ADR 0081 §A7: a driver per recovered vault. Which one is Personal is the directory's
        // word, read by the first sync; until then the legacy rule opens a lone vault and none of
        // several.
        let mut vaults = Vec::with_capacity(done.vault_keys.len());
        for vault_key in done.vault_keys {
            vaults.push(VaultSync::new(vault_key, &done.unlocked, 1)?);
        }
        if vaults.is_empty() {
            return Err(CliError::Client(ClientError::Internal));
        }
        let ids: Vec<_> = vaults.iter().map(VaultSync::vault_id).collect();
        let catalog = VaultCatalog::check(None, &ids);
        let mut device = Device::enrolled(
            lock,
            db,
            floors,
            http,
            done.device,
            done.unlocked,
            (done.certificates, done.revocations, done.authors),
            (vaults, catalog),
            password,
            env.sign_outs.clone(),
        )?;
        if done.dropped_items > 0 {
            env.ui.note(&format!(
                "{} item keys could not be opened and were dropped: those items are no longer \
                 readable.",
                done.dropped_items
            ));
        }
        env.ui.note(
            "The account is recovered. Every other device must log in again with the new master \
             password and Secret Key.",
        );
        device.sync(env.ui).await
    }
}

/// Sends the stored recovery commit `body` over the recovery-only session `token`. On
/// `setup_retired` (ADR 0031 point 8; CRYPTO.md §11 "Replacing credentials") the registration
/// is restarted once with the same `pw_in` (the record's Secret Key and `password`), only the
/// upload, the `setup_id` and `E_srv'` of the stored request are replaced, the new body is
/// stored over the old one, and it is sent once.
async fn send_commit(
    http: &Http,
    db: &mut Db,
    record: &DeviceRecord,
    unlocked: &rizzy_client::device::UnlockedDevice,
    password: &str,
    body: Vec<u8>,
    token: &SessionToken,
) -> Result<(), CliError> {
    let sent = http
        .post_bytes_empty(paths::ACCOUNT_COMMIT, body.clone(), Auth::Bearer(token))
        .await;
    match sent {
        Err(e) if e.restarts_registration() => {
            let mut rng = os_rng();
            let restart = record.registration_restart(&mut rng, password)?;
            let answer: ReregisterStartResponse = http
                .post(
                    paths::ACCOUNT_REREGISTER_START,
                    &restart.reregister_request(),
                    Auth::Bearer(token),
                )
                .await?;
            // The stored body is parsed back only through `rizzy-proto` (ADR 0026 §3).
            let mut request: CommitChangeRequest =
                serde_json::from_slice(&body).map_err(|_| ClientError::CacheCorrupt)?;
            restart.rebuild_commit(&mut rng, &answer, unlocked, &mut request)?;
            let rebuilt = serde_json::to_vec(&request).map_err(|_| ClientError::Internal)?;
            db.write(&store::pending_writes(record, &rebuilt)?).await?;
            http.post_bytes_empty(paths::ACCOUNT_COMMIT, rebuilt, Auth::Bearer(token))
                .await
        }
        other => other,
    }
}

/// ADR 0046 §3 step 5: removes the account's cache file, and with it, at once, every row the
/// pre-commit write created (`cache_meta`, the stage-3 record, `pending_commit`, the account
/// objects, the wrap sets), under the account's lock. A later `rv recovery complete` finds no
/// cache file for the account.
async fn abandon(
    env: &Env<'_>,
    account: &[u8; 16],
    db: Db,
    lock: AccountLock,
) -> Result<(), CliError> {
    db.close().await;
    delete_account_files(env, account, lock)
}

/// The note when a stage-3 record stays for the next run.
const STILL_UNSETTLED: &str = "The unfinished recovery is still saved on this computer. Run \
     `rv recovery complete` again with the same server and login name to settle it. Keep both \
     Emergency Kits until then.";

/// The note when a stage-3 record was abandoned.
const ABANDONED: &str = "The unfinished recovery did not reach the server and was discarded \
     from this computer: the Emergency Kit it showed is void. Run `rv recovery start` or \
     `rv recovery complete` again to recover the account.";

/// Settles the stage-3 record of `account` (module docs, "Settling a stage-3 record"; ADR 0046
/// §3).
#[expect(
    clippy::too_many_lines,
    reason = "the five steps of ADR 0046 §3 in their one order"
)]
async fn resume(
    env: &mut Env<'_>,
    http: Http,
    login_name: &str,
    account: [u8; 16],
) -> Result<(), CliError> {
    check_data_dir(&env.data_dir)?;
    let lock = AccountLock::acquire(&env.data_dir, &account)?;
    let mut db = Db::open(&cache_path(&env.data_dir, &account)).await?;
    let mut rows = db.read().await?;
    let record = load::open(&rows, false)?;
    // Settled by another `rv` between the search and the lock.
    if record.stage() != Stage::RecoveryPending {
        return Err(CliError::AlreadyEnrolled);
    }
    let stored = rows
        .pending_commit
        .take()
        .ok_or(ClientError::CacheCorrupt)?;
    drop(rows);
    env.ui.note(
        "A recovery started on this computer was not finished. It is settled first; no new \
         Emergency Kit is made while it is unsettled.",
    );

    // Step 1: every later step needs the record's keys.
    let password = env
        .ui
        .secret("New master password chosen in the unfinished recovery")?;
    let unlocked = record.unlock_recovery_pending(&password)?;

    // Step 2: the device-auth short-circuit, never with reconciliation objects.
    match device_auth_probe(&http, &record, &unlocked).await {
        Ok(()) => {
            env.ui
                .note("The server had applied the recovery. Finishing it on this computer…");
            return finish_resumed(env, lock, db, record, account, password).await;
        }
        Err(CliError::Server(ErrorCode::Unauthorized)) => {}
        Err(e) => {
            env.ui.note(STILL_UNSETTLED);
            return Err(e);
        }
    }

    // Step 3: did the account's credentials move? The existing login, used read-only.
    let mut rng = os_rng();
    match login_probe(&http, &mut rng, &record, login_name, &password).await {
        Probe::Landed => {
            db.write(&store::finalize_writes(&record.committed())?)
                .await?;
            db.close().await;
            drop(lock);
            env.ui.note(
                "The server had applied the recovery: the Emergency Kit it showed and its master \
                 password are the account's. The server no longer accepts this computer as a \
                 device (it may have been revoked): run `rv device forget`, then `rv login` \
                 with the new kit.",
            );
            return Err(CliError::Server(ErrorCode::Unauthorized));
        }
        Probe::NotLanded => {}
        Probe::Unknown(e) => {
            env.ui.note(STILL_UNSETTLED);
            return Err(e);
        }
    }

    // Step 4: this attempt's commit is not the live one. Resend it through recovery.
    env.ui.note(
        "The server has not applied the unfinished recovery. It is sent again with a new \
         recovery session.",
    );
    let code = env
        .ui
        .secret("Recovery code (RVR1-…) of the unfinished recovery")?;
    let started = start_recovery(&RecoveryInput {
        server_origin: http.origin().as_str(),
        login_name,
        recovery_code: &code,
    })?;
    let answer: Result<RecoveryCompleteResponse, CliError> = http
        .post(paths::RECOVERY_COMPLETE, &started.request()?, Auth::None)
        .await;
    drop(code);
    let token = match answer {
        Ok(answer) if answer.account_id.to_bytes() == record.account_id().to_bytes() => {
            answer.session_token
        }
        Ok(_) => {
            env.ui.note(STILL_UNSETTLED);
            return Err(CliError::BadInput(
                "the login name is not the unfinished recovery's account",
            ));
        }
        // The pending recovery was cancelled, or another credential change raced it (§3 step
        // 4): step 3 already ruled out "it landed as mine".
        Err(refused @ CliError::Server(ErrorCode::Unauthorized)) => {
            abandon(env, &account, db, lock).await?;
            env.ui.note(ABANDONED);
            return Err(refused);
        }
        Err(e) => {
            env.ui.note(STILL_UNSETTLED);
            return Err(e);
        }
    };
    let sent = send_commit(
        &http, &mut db, &record, &unlocked, &password, stored, &token,
    )
    .await;
    match sent {
        Ok(()) => finish_resumed(env, lock, db, record, account, password).await,
        // `state_conflict`, `unauthorized` or any other refusal: not applied, and step 3
        // proved no commit of this attempt is live, so abandoning cannot discard a live kit.
        Err(refused) if refused.refuses_commit() => {
            abandon(env, &account, db, lock).await?;
            env.ui.note(ABANDONED);
            Err(refused)
        }
        Err(e) => {
            env.ui.note(STILL_UNSETTLED);
            Err(e)
        }
    }
}

/// The record finalised (stage 1, `pending_commit` removed) once the commit is known to have
/// landed, then the device opened like any enrolled one and synced (ADR 0046 §3 step 2).
async fn finish_resumed(
    env: &mut Env<'_>,
    lock: AccountLock,
    mut db: Db,
    record: DeviceRecord,
    account: [u8; 16],
    password: Zeroizing<String>,
) -> Result<(), CliError> {
    db.write(&store::finalize_writes(&record.committed())?)
        .await?;
    db.close().await;
    drop(lock);
    env.account = Some(account);
    let mut device = Device::open_with_password(env, password).await?;
    env.ui.note(
        "The account is recovered. Every other device must log in again with the new master \
         password and Secret Key.",
    );
    device.sync(env.ui).await
}

/// ADR 0046 §3 step 2: `device-auth/start` and `finish` with the stage-3 record's own device
/// id and keys, and no reconciliation objects. The session it opens is not used.
async fn device_auth_probe(
    http: &Http,
    record: &DeviceRecord,
    unlocked: &rizzy_client::device::UnlockedDevice,
) -> Result<(), CliError> {
    let start: DeviceAuthStartResponse = http
        .post(
            paths::DEVICE_AUTH_START,
            &device_auth_start_recovery_pending(record)?,
            Auth::None,
        )
        .await?;
    let finish = device_auth_finish_recovery_pending(record, unlocked, &start)?;
    let _session: DeviceAuthFinishResponse = http
        .post(paths::DEVICE_AUTH_FINISH, &finish, Auth::None)
        .await?;
    Ok(())
}

/// The outcome of the OPAQUE-login probe (ADR 0046 §3 step 3).
enum Probe {
    /// The login succeeded or asked for the second factor: the commit landed.
    Landed,
    /// The answer of wrong credentials: the server's credentials are still the old ones.
    NotLanded,
    /// Neither answer cleanly: the record stays.
    Unknown(CliError),
}

/// ADR 0046 §3 step 3: an OPAQUE login under `login_name` with the record's Secret Key and
/// `password`. Only a commit of this attempt registered that pair, so the answer tells whether
/// it landed. The session a success opens is dropped unused; no second factor is asked for.
async fn login_probe(
    http: &Http,
    rng: &mut OsRng,
    record: &DeviceRecord,
    login_name: &str,
    password: &str,
) -> Probe {
    let secret_key = record.secret_key_text();
    let input = LoginInput {
        server_origin: http.origin().as_str(),
        login_name,
        secret_key: &secret_key,
        password,
    };
    let (started, request) = match start_login(rng, &input) {
        Ok(started) => started,
        Err(e) => return Probe::Unknown(e.into()),
    };
    let answer: LoginStartResponse = match http.post(paths::LOGIN_START, &request, Auth::None).await
    {
        Ok(answer) => answer,
        Err(e) => return Probe::Unknown(e),
    };
    // The OPAQUE envelope opens only under the registration this pair made: a wrong-credentials
    // answer here is the server holding the old credentials.
    let finish = match started.finish(rng, &answer, None) {
        Ok((_awaiting, finish)) => finish,
        Err(ClientError::WrongPasswordOrSecretKey) => return Probe::NotLanded,
        Err(e) => return Probe::Unknown(e.into()),
    };
    let finished: Result<LoginFinishResponse, CliError> =
        http.post(paths::LOGIN_FINISH, &finish, Auth::None).await;
    match finished {
        // The session a success opens is dropped unused.
        Ok(_) | Err(CliError::Server(ErrorCode::SecondFactorRequired)) => Probe::Landed,
        Err(CliError::Server(ErrorCode::Unauthorized)) => Probe::NotLanded,
        Err(e) => Probe::Unknown(e),
    }
}

/// `recovery cancel`: on an enrolled device, over its device session.
///
/// # Errors
/// As [`Device::open`] and [`Device::online`]; the transport's errors.
pub async fn cancel(env: &mut Env<'_>) -> Result<(), CliError> {
    let mut device = Device::open(env).await?;
    device.online(env.ui).await?;
    if device.cancel_recovery().await? {
        env.ui.note("The pending recovery was cancelled.");
    } else {
        env.ui.note("No recovery was pending.");
    }
    Ok(())
}

/// A time the server reported, in UTC to the minute ("2026-10-24 13:05 UTC"): `rv` cannot read
/// the local time zone (see `today_utc` in `commands.rs`). A value no calendar date holds (a
/// forged one) prints as seconds since the Unix epoch.
#[must_use]
pub fn utc_text(ms: u64) -> String {
    let day_ms = 86_400_000;
    let date = i64::try_from(ms / day_ms)
        .ok()
        .and_then(CivilDate::from_days);
    match date {
        Some(date) => {
            let minutes = (ms % day_ms) / 60_000;
            format!("{date} {:02}:{:02} UTC", minutes / 60, minutes % 60)
        }
        None => format!("{} s after the Unix epoch", ms / 1000),
    }
}

/// The loud warning every online command prints while the server reports a pending recovery
/// (ADR 0045 open question 3): when it was requested, when it can complete, and how to cancel
/// it. It says what it is: the server's word, which rv's own checks never use (INV-70).
#[must_use]
pub fn notice_warning(notice: RecoveryNotice, now_ms: u64) -> String {
    let when = if notice.wait_over(now_ms) {
        "Its waiting period is over: it can be completed now.".to_owned()
    } else {
        let hours = (notice.available_at_ms - now_ms).div_ceil(3_600_000);
        format!(
            "It can be completed from {} (in about {hours} h).",
            utc_text(notice.available_at_ms)
        )
    };
    let mut text = format!(
        "WARNING: the server reports that a recovery of this account with the Emergency Kit was \
         requested on {}. {when} Whoever completes it gets a new master password and Secret \
         Key for this account. If you did not request it, run `rv recovery cancel` now.",
        utc_text(notice.opened_at_ms)
    );
    if let Some(last) = notice.last_recovery_at_ms {
        text.push_str(" The account was last recovered on ");
        text.push_str(&utc_text(last));
        text.push('.');
    }
    text.push_str(
        " (This notice is the server's word, not verified: rv's checks of the account never \
         depend on it, and a server could also hide a recovery.)",
    );
    text
}

/// `account status` (ADR 0045, owner answer 2): goes online on this device, so the account
/// answer is verified as every online command verifies it, then prints the account, the
/// server, the storage figure and the recovery notice the server reported, all of the last
/// three as the server's word.
///
/// # Errors
/// As [`Device::open`] and [`Device::online`].
pub async fn status(env: &mut Env<'_>) -> Result<(), CliError> {
    let mut device = Device::open(env).await?;
    device.online(env.ui).await?;
    env.ui
        .print(&format!("account:  {}", device.account_hex()))?;
    env.ui.print(&format!(
        "server:   {}",
        device.state().server_origin().as_str()
    ))?;
    env.ui
        .print("state:    verified (signed by the account's identity key)")?;
    if let Some(usage) = device.usage() {
        env.ui
            .print(&format!("storage:  {}", crate::commands::usage_text(usage)))?;
    }
    match device.recovery_notice() {
        Some(notice) => {
            let now = now_ms();
            let when = if notice.wait_over(now) {
                "can be completed now".to_owned()
            } else {
                format!("can be completed from {}", utc_text(notice.available_at_ms))
            };
            env.ui.print(&format!(
                "recovery: PENDING, requested {}, {when}",
                utc_text(notice.opened_at_ms)
            ))?;
            if let Some(last) = notice.last_recovery_at_ms {
                env.ui
                    .print(&format!("last recovery: {}", utc_text(last)))?;
            }
        }
        None => env.ui.print("recovery: none pending")?,
    }
    env.ui.note(
        "The recovery status is the server's word, not verified: a server can hide a recovery or \
         invent one. Cancel one you did not request with `rv recovery cancel`.",
    );
    Ok(())
}

/// `recovery repair`, on an enrolled device (ADR 0032 §4 step 6): after a restore the server's
/// `H_rec` and `E_rec` may lag the account, and recovery is refused until the user repairs them.
/// The device goes online (healing the server first if it is behind), re-authenticates with
/// the master password, and commits `H_rec` and `E_rec` together: a new recovery code and kit
/// by default, or the current code re-typed with `--retype`.
///
/// # Errors
/// As [`Device::open`] and [`Device::repair_recovery`].
pub async fn repair(env: &mut Env<'_>, name: &str, retype: bool) -> Result<(), CliError> {
    let mut device = Device::open(env).await?;
    Box::pin(device.repair_recovery(env.ui, name, retype)).await
}

#[cfg(test)]
mod tests {
    //! The texts of the recovery notice (ADR 0045), including the values a forged notice can
    //! carry (INV-70: whatever it says, it is printed, never trusted, and never panics).

    use super::*;

    /// 2026-09-21 14:13:20 UTC.
    const T0: u64 = 1_790_000_000_000;
    /// 72 h.
    const WAIT: u64 = 72 * 3_600_000;

    #[test]
    fn times_print_in_utc_to_the_minute() {
        assert_eq!(utc_text(0), "1970-01-01 00:00 UTC");
        assert_eq!(utc_text(T0), "2026-09-21 14:13 UTC");
        assert_eq!(utc_text(T0 + WAIT), "2026-09-24 14:13 UTC");
        // Beyond any calendar date the generator knows: seconds, no panic.
        assert_eq!(
            utc_text(u64::MAX),
            format!("{} s after the Unix epoch", u64::MAX / 1000)
        );
    }

    #[test]
    fn the_warning_says_when_and_how_to_cancel() {
        let notice = RecoveryNotice {
            opened_at_ms: T0,
            available_at_ms: T0 + WAIT,
            last_recovery_at_ms: None,
        };
        let waiting = notice_warning(notice, T0 + 1);
        assert!(waiting.starts_with("WARNING: "), "{waiting}");
        assert!(
            waiting.contains("requested on 2026-09-21 14:13 UTC"),
            "{waiting}"
        );
        assert!(
            waiting.contains("from 2026-09-24 14:13 UTC (in about 72 h)"),
            "{waiting}"
        );
        assert!(waiting.contains("rv recovery cancel"), "{waiting}");
        assert!(waiting.contains("not verified"), "{waiting}");
        assert!(!waiting.contains("last recovered"), "{waiting}");
        let over = notice_warning(notice, T0 + WAIT);
        assert!(over.contains("it can be completed now"), "{over}");
        let last = notice_warning(
            RecoveryNotice {
                last_recovery_at_ms: Some(1_789_000_000_000),
                ..notice
            },
            T0,
        );
        assert!(
            last.contains("last recovered on 2026-09-10 00:26 UTC"),
            "{last}"
        );
        // A forged, impossible notice still prints.
        let forged = notice_warning(
            RecoveryNotice {
                opened_at_ms: u64::MAX,
                available_at_ms: u64::MAX,
                last_recovery_at_ms: Some(u64::MAX),
            },
            0,
        );
        assert!(forged.contains("rv recovery cancel"), "{forged}");
    }
}
