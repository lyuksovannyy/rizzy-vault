//! Recovery with the Emergency Kit (CRYPTO.md §11.9), on a computer where this account is not
//! enrolled.
//!
//! - `rv recovery start` sends `{login_name, recovery_auth_token}` to `recovery/start`. The
//!   server opens the pending recovery, notifies every enrolled device and starts the waiting
//!   period (72 h by default); the command prints when the recovery can be completed.
//! - `rv recovery complete`, after the wait: `recovery/complete`, then the client flow of
//!   `rizzy_client::recovery`: `E_rec` opens under the typed code, the whole answer is
//!   verified, a new master password is set, a **new Secret Key and recovery code** are
//!   generated, the new Emergency Kit is printed and confirmed, and the commit replaces the
//!   credentials, rotates the account and vault keys (unless `--skip-rotation`), and enrols
//!   this computer as a device. The cache is created once the server acknowledged (see "An
//!   open gap" below).
//! - `rv recovery cancel`, on an enrolled device: cancels a pending recovery (§11.9 step 2:
//!   "Any enrolled device with a device-authenticated session can cancel").
//!
//! A computer that still holds this account's cache must run `rv device forget` first: its
//! device state is under the forgotten password and cannot be carried over.
//!
//! # An open gap between two Accepted documents (reported to the owner, not decided here)
//!
//! CRYPTO.md §11 "Secrets before commit" names recovery: step 3, "a durable client (kind
//! 1–3) persists a pending record in its device state", comes before step 4, "Upload", and
//! ADR 0028 makes a byte-identical repeat of `account/commit` a success. But a recovering
//! computer has no device state yet, and ADR 0026 defines a pending stage for signup only
//! (`stage = 2` with a `RegisterFinishRequest`): it has no record stage and no
//! `pending_commit` form for a recovery commit. Writing one here would freeze a persistent
//! format no ADR defines (CLAUDE.md "The ADR gate"), so `rv` persists nothing before the
//! commit is sent and cannot use the repeat.
//!
//! What that costs: after a crash, or an answer that leaves the outcome unknown, between the
//! send and the cache write, the server may have applied the recovery (new credentials, this
//! computer certified as a device) while the device keys exist nowhere. The confirmed new kit
//! is what survives: `rv login` with it enrols this computer anew, and the orphan device is
//! revoked from `rv device list`. `rv` cannot tell which kit is valid in that case, and says
//! exactly that ([`complete`]).

use rizzy_client::ClientError;
use rizzy_client::recovery::{RecoveryInput, RecoveryOptions, start_recovery};
use rizzy_client::rizzy_proto::change::ReregisterStartResponse;
use rizzy_client::rizzy_proto::http::paths;
use rizzy_client::rizzy_proto::recovery::{RecoveryCompleteResponse, RecoveryStartResponse};
use rizzy_client::signup::DeviceKind;
use rizzy_client::store::floors::Floors;
use rizzy_client::sync::VaultSync;

use crate::db::Db;
use crate::device::{Device, Env, copy_token};
use crate::error::CliError;
use crate::http::{Auth, Http};
use crate::paths::{AccountLock, cache_path, ensure_data_dir};
use crate::sys::{now_ms, os_rng};

/// `recovery start`.
///
/// # Errors
/// [`CliError::Server`] with `unauthorized` for a wrong code or an unknown name (one answer,
/// CRYPTO.md §5.9); the transport's errors.
pub async fn start(env: &mut Env<'_>, server: &str, login_name: &str) -> Result<(), CliError> {
    let http = Http::new(server)?;
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

/// `recovery complete`. `rotate` is the default; `false` is `--skip-rotation`.
///
/// # Errors
/// [`CliError::RateLimited`] while the waiting period runs; [`CliError::AlreadyEnrolled`] if
/// this computer holds the account's cache; the flow's and the transport's errors.
#[expect(
    clippy::too_many_lines,
    reason = "the recovery steps in their one order"
)]
pub async fn complete(
    env: &mut Env<'_>,
    server: &str,
    login_name: &str,
    rotate: bool,
) -> Result<(), CliError> {
    let http = Http::new(server)?;
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
    let password = env.ui.secret("New master password")?;
    let again = env.ui.secret("New master password, again")?;
    if *password != *again {
        return Err(CliError::BadInput("the two passwords differ"));
    }
    if !rotate {
        env.ui.note(
            "Skipping the key rotation: anyone who holds the old recovery code and an old copy \
             of the server's data can still read this account's future items.",
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

    if let Err(e) = http
        .post_empty(
            paths::ACCOUNT_COMMIT,
            pending.commit_request()?,
            Auth::Bearer(&token),
        )
        .await
    {
        // Module docs, "An open gap": nothing was persisted, so the outcome cannot be settled
        // by a resend. The user is told exactly what may now be true.
        if e.outcome_unknown() {
            env.ui.note(
                "Whether the server applied the recovery is unknown, and nothing was saved \
                 here. KEEP BOTH Emergency Kits. If the server applied it, only the NEW kit \
                 shown above and the new master password work: `rv login` with them enrols \
                 this computer, and the account then lists one extra device that nothing can \
                 use; revoke it with `rv device revoke`. If the server did not apply it, \
                 nothing changed on the account: the old kit's recovery code is still the \
                 account's, and the kit shown above is void.",
            );
        } else {
            env.ui.note(
                "The server did not apply the recovery: nothing changed on the account, and \
                 the Emergency Kit shown above is void.",
            );
        }
        return Err(e);
    }

    // The server acknowledged: this computer is a device of the account. Its cache.
    let first = pending.store_writes()?;
    let done = pending.finalize()?;
    ensure_data_dir(&env.data_dir)?;
    let lock = AccountLock::acquire(&env.data_dir, &account)?;
    let mut floors = Floors::empty();
    floors.admit(&first)?;
    let db = Db::create(&cache_path(&env.data_dir, &account), &first).await?;
    let mut vault_keys = done.vault_keys.into_iter();
    // M1: one personal vault per account.
    let (Some(vault_key), None) = (vault_keys.next(), vault_keys.next()) else {
        return Err(CliError::Client(ClientError::InvalidServerResponse));
    };
    let vault = VaultSync::new(vault_key, &done.unlocked, 1)?;
    let mut device = Device::enrolled(
        lock,
        db,
        floors,
        http,
        done.device,
        done.unlocked,
        (done.certificates, done.revocations, done.authors),
        vault,
        password,
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
