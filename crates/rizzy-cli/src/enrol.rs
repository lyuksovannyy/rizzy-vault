//! Becoming a device: signup (CRYPTO.md §11.1) and login on a new device with its enrolment
//! (§11.2), each ending with a cache file ([ADR 0026]).
//!
//! # Signup, in the order of "Secrets before commit" (CRYPTO.md §11)
//!
//! 1. Everything is built (`start_signup`, `SignupStarted::finish`).
//! 2. The Emergency Kit is printed, and the user re-types the last group of the Secret Key.
//!    The kit is the one time the Secret Key and the recovery code are shown; `rv` prints it
//!    to standard output because the command's purpose is to hand it over (INV-56).
//! 3. The cache is created in stage 2: the device-state record, the exact `register/finish`
//!    body, the account objects (`PendingSignup::store_writes`).
//! 4. `register/finish` is sent.
//! 5. On the acknowledgement the record becomes stage 1 and the stored body is removed.
//!
//! If the answer never arrives, or is one that does not say what the server did (a proxy's
//! error page, `internal`, a rate limit; [`CliError::refuses_commit`]), the stage-2 file
//! stays and the next `rv` command resends the stored body
//! ([`crate::device::Device::open`]). Only if the server refuses the signup with an `/api/v1`
//! error was nothing registered: the stage-2 file is removed again, since it holds no
//! enrolment.
//!
//! # Login
//!
//! The OPAQUE login, then the enrolment as a durable device of kind "desktop or CLI". The
//! cache is written once the server acknowledged the enrolment.
//!
//! **An open gap between two Accepted documents (reported to the owner, not decided here).**
//! CRYPTO.md §11.2 step 7 writes `E_dev` and `E_local` locally before the certificate is
//! uploaded, and ADR 0028 makes a byte-identical repeat of `devices/enrol` a success. ADR 0026
//! defines a pending stage for signup only: it has no record stage or `pending_commit` form
//! for an enrolment, and inventing one here would freeze a persistent format no ADR defines.
//! So nothing is persisted before `devices/enrol` is sent, and the repeat cannot be used. A
//! crash, or an answer that leaves the outcome unknown, between the send and the cache write
//! can leave a certified device on the server whose keys exist nowhere. `rv` says so
//! precisely when it sees such an answer: the device shows in `rv device list` on another
//! device and is revoked from there, and `rv login` is simply run again.
//!
//! [ADR 0026]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0026-client-device-state-and-cache.md

use rizzy_client::ClientError;
use rizzy_client::login::LoginInput;
use rizzy_client::rizzy_proto::auth::RegisterStartResponse;
use rizzy_client::rizzy_proto::error::ErrorCode;
use rizzy_client::rizzy_proto::http::paths;
use rizzy_client::rizzy_proto::meta::{API_V1, META_PATH, MetaResponse};
use rizzy_client::signup::{DeviceKind, SignupInput, start_signup};
use rizzy_client::store::floors::Floors;
use rizzy_client::store::record::Stage;
use rizzy_client::store::rows::Changeset;
use rizzy_client::store::{self};
use rizzy_client::sync::{Authors, VaultSync};
use zeroize::Zeroizing;

use crate::db::Db;
use crate::device::{Device, Env, copy_token, opaque_login};
use crate::error::CliError;
use crate::http::{Auth, Http};
use crate::paths::{AccountLock, cache_path, ensure_data_dir};
use crate::sys::{now_ms, os_rng};

/// How often an enrolment is rebuilt when another device changed the account between the
/// login and the enrolment (`state_conflict`).
const ENROL_ATTEMPTS: usize = 3;

/// Checks that the server speaks `v1` (ADR 0028 item 14), before anything secret is typed.
async fn check_server(http: &Http) -> Result<(), CliError> {
    let meta: MetaResponse = http.get(META_PATH, Auth::None).await?;
    if meta.api_versions.iter().any(|v| v.as_str() == API_V1) {
        Ok(())
    } else {
        Err(CliError::Server(ErrorCode::ApiVersionGone))
    }
}

/// Asks for a new master password twice.
fn new_password(env: &mut Env<'_>) -> Result<Zeroizing<String>, CliError> {
    let password = env.ui.secret("New master password")?;
    let again = env.ui.secret("New master password, again")?;
    if *password != *again {
        return Err(CliError::BadInput("the two passwords differ"));
    }
    Ok(password)
}

/// Creates the cache of a new enrolment: the directory, the lock, the file with its first
/// changeset behind the floors.
async fn create_cache(
    env: &Env<'_>,
    account: &[u8; 16],
    first: &Changeset,
) -> Result<(AccountLock, Db, Floors), CliError> {
    ensure_data_dir(&env.data_dir)?;
    let lock = AccountLock::acquire(&env.data_dir, account)?;
    let mut floors = Floors::empty();
    floors.admit(first)?;
    let db = Db::create(&cache_path(&env.data_dir, account), first).await?;
    Ok((lock, db, floors))
}

/// A signup after step 3 of "Secrets before commit": the kit is confirmed and the stage-2
/// cache, with the exact `register/finish` body, is on disk. Dropping it is a crash before
/// the commit: the next `rv` command resends the stored body ([`Device::open`]).
pub struct PreparedSignup {
    /// The transport.
    http: Http,
    /// The signup, waiting for the commit.
    pending: rizzy_client::signup::PendingSignup,
    /// The exact body stored as `pending_commit`.
    body: Vec<u8>,
    /// The account's lock.
    lock: AccountLock,
    /// The stage-2 cache.
    db: Db,
    /// Its floors.
    floors: Floors,
    /// The account id.
    account: [u8; 16],
    /// The new master password, for the device's first session.
    password: Zeroizing<String>,
}

impl std::fmt::Debug for PreparedSignup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedSignup").finish_non_exhaustive()
    }
}

/// `rv signup` (module docs). Returns the enrolled device, already synced once.
///
/// # Errors
/// [`CliError::AlreadyEnrolled`]; the flow's and the transport's errors.
pub async fn signup(
    env: &mut Env<'_>,
    server: &str,
    login_name: &str,
    recovery_code: bool,
    invite: bool,
) -> Result<Device, CliError> {
    let prepared = Box::pin(prepare_signup(
        env,
        server,
        login_name,
        recovery_code,
        invite,
    ))
    .await?;
    Box::pin(prepared.commit(env)).await
}

/// Steps 1–3 of a signup (module docs): everything built, the Emergency Kit printed and
/// confirmed, the stage-2 cache written.
///
/// # Errors
/// [`CliError::AlreadyEnrolled`]; the flow's and the transport's errors.
pub async fn prepare_signup(
    env: &mut Env<'_>,
    server: &str,
    login_name: &str,
    recovery_code: bool,
    invite: bool,
) -> Result<PreparedSignup, CliError> {
    let http = Http::new(server, &env.trust)?;
    check_server(&http).await?;
    let invite = if invite {
        Some(env.ui.secret("Invite token")?)
    } else {
        None
    };
    let password = new_password(env)?;
    let mut rng = os_rng();
    let input = SignupInput {
        server_origin: http.origin().as_str(),
        login_name,
        password: &password,
        invite: invite.as_deref().map(String::as_str),
        issue_recovery_code: recovery_code,
        device_kind: DeviceKind::DesktopCli,
        now_ms: now_ms(),
    };
    let (started, request) = start_signup(&mut rng, &input)?;
    let answer: RegisterStartResponse = http
        .post(paths::REGISTER_START, &request, Auth::None)
        .await?;
    let mut pending = started.finish(&mut rng, &answer)?;

    // Step 2: the kit, then the confirmation.
    let kit = pending.emergency_kit();
    env.ui
        .print("EMERGENCY KIT — print it or write it down, and keep it offline.")?;
    env.ui
        .print(&format!("Server:        {}", kit.server_origin()))?;
    env.ui
        .print(&format!("Login name:    {}", kit.login_name()))?;
    env.ui
        .print(&format!("Secret Key:    {}", kit.secret_key()))?;
    if let Some(code) = kit.recovery_code() {
        env.ui.print(&format!("Recovery code: {code}"))?;
    }
    env.ui.note(
        "The Secret Key is needed, with your master password, to log in on a new device. \
         Nobody can recover it for you.",
    );
    let typed = env
        .ui
        .line("Type the last four characters of the Secret Key to confirm you saved the kit")?;
    pending.confirm_kit(typed.trim())?;

    // Step 3: the stage-2 cache with the exact body, before the commit leaves.
    let body = serde_json::to_vec(pending.commit_request()?).map_err(|_| ClientError::Internal)?;
    let first = pending.store_writes(&body)?;
    let account = pending
        .pending_device()
        .ok_or(ClientError::Internal)?
        .account_id()
        .to_bytes();
    let (lock, db, floors) = create_cache(env, &account, &first).await?;
    Ok(PreparedSignup {
        http,
        pending,
        body,
        lock,
        db,
        floors,
        account,
        password,
    })
}

impl PreparedSignup {
    /// Steps 4 and 5 (module docs): sends the commit, finalises the record, and syncs the new
    /// device once.
    ///
    /// # Errors
    /// An error that leaves the outcome unknown ([`CliError::refuses_commit`] is false) leaves
    /// the stage-2 cache for the next run to finish; a refusal by the server removes it
    /// (nothing was registered) and is returned.
    pub async fn commit(self, env: &mut Env<'_>) -> Result<Device, CliError> {
        let Self {
            http,
            pending,
            body,
            lock,
            mut db,
            mut floors,
            account,
            password,
        } = self;
        match http
            .post_bytes_empty(paths::REGISTER_FINISH, body, Auth::None)
            .await
        {
            Ok(()) => {}
            // Only an `/api/v1` refusal proves nothing was registered. Any other failure (no
            // answer, a proxy's error page, `internal`, a rate limit) leaves the outcome
            // unknown: the account may exist, and this file is then its only device state.
            Err(kept) if !kept.refuses_commit() => {
                env.ui.note(if kept.outcome_unknown() {
                    "Whether the server registered the signup is unknown. It is saved, and the \
                     Emergency Kit shown above stays valid: run any rv command to finish it."
                } else {
                    "The signup was not sent through. It is saved, and the Emergency Kit shown \
                     above stays valid: run any rv command later to finish it."
                });
                return Err(kept);
            }
            Err(refused) => {
                // Nothing was registered, so the file holds no enrolment: the kit shown above
                // is void, and a new signup starts from nothing.
                db.close().await;
                let _ = std::fs::remove_file(cache_path(&env.data_dir, &account));
                env.ui
                    .note("The server refused the signup. The Emergency Kit shown above is void.");
                return Err(refused);
            }
        }
        let signed_up = pending.finalize()?;
        let state = signed_up.device.ok_or(ClientError::Internal)?;
        let finalise = store::finalize_writes(&state.record(Stage::Committed)?)?;
        floors.admit(&finalise)?;
        db.write(&finalise).await?;
        let vault = VaultSync::new(signed_up.vault_key, &signed_up.unlocked, 1)?;
        let mut device = Device::enrolled(
            lock,
            db,
            floors,
            http,
            state,
            signed_up.unlocked,
            (
                vec![signed_up.own_certificate.clone()],
                Vec::new(),
                Authors::from_statements(&[signed_up.own_certificate], &[])?,
            ),
            vault,
            password,
        )?;
        device.sync(env.ui).await?;
        Ok(device)
    }
}

/// `rv login` (module docs). Returns the enrolled device, already synced once.
///
/// # Errors
/// [`CliError::AlreadyEnrolled`] before anything is enrolled; the flow's and the transport's
/// errors.
pub async fn login(env: &mut Env<'_>, server: &str, login_name: &str) -> Result<Device, CliError> {
    let http = Http::new(server, &env.trust)?;
    check_server(&http).await?;
    let secret_key = env.ui.secret("Secret Key (RV1-…)")?;
    let password = env.ui.secret("Master password")?;
    let mut rng = os_rng();
    let input = LoginInput {
        server_origin: http.origin().as_str(),
        login_name,
        secret_key: &secret_key,
        password: &password,
    };
    for _ in 0..ENROL_ATTEMPTS {
        let logged_in = opaque_login(&http, &mut rng, env.ui, &input, None).await?;
        // Before a certificate is published: this account is not enrolled here already.
        let account = logged_in.account().account_id().to_bytes();
        if cache_path(&env.data_dir, &account).exists() {
            return Err(CliError::AlreadyEnrolled);
        }
        let token = copy_token(logged_in.bearer_token());
        let (pending, request) = logged_in.enrol(&mut rng, DeviceKind::DesktopCli, now_ms())?;
        match http
            .post_empty(paths::DEVICES_ENROL, &request, Auth::Bearer(&token))
            .await
        {
            Ok(()) => {}
            // Another device changed the account in between: log in again and rebuild.
            Err(CliError::Server(ErrorCode::StateConflict)) => continue,
            Err(e) => {
                if e.outcome_unknown() {
                    // Module docs, "Login": nothing was persisted, so the outcome cannot be
                    // settled by a resend. The user is told what may now exist.
                    env.ui.note(
                        "Whether the server enrolled this device is unknown, and nothing was \
                         saved here. Run `rv login` again. If the first attempt did reach the \
                         server, the account now lists one extra device that nothing can use: \
                         find it with `rv device list` on a device that works and revoke it \
                         with `rv device revoke`.",
                    );
                }
                return Err(e);
            }
        }
        let enrolled = pending.finalize();
        let mut first = store::create_writes(&enrolled.device.record(Stage::Committed)?)?;
        first.append(store::account_writes(&enrolled.account));
        let (lock, db, floors) = create_cache(env, &account, &first).await?;
        let mut account_view = enrolled.account;
        let vault_id = account_view
            .vault_ids()
            .next()
            .ok_or(ClientError::InvalidServerResponse)?;
        let vault_key = account_view
            .take_vault_key(vault_id)
            .ok_or(ClientError::InvalidServerResponse)?;
        let vault = VaultSync::new(vault_key, &enrolled.unlocked, 1)?;
        let mut device = Device::enrolled(
            lock,
            db,
            floors,
            http,
            enrolled.device,
            enrolled.unlocked,
            (
                account_view.certificates().to_vec(),
                account_view.revocations().to_vec(),
                Authors::from_account(&account_view)?,
            ),
            vault,
            password,
        )?;
        device.sync(env.ui).await?;
        return Ok(device);
    }
    Err(CliError::Server(ErrorCode::StateConflict))
}
