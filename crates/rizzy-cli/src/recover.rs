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
//!   generated, the new Emergency Kit is printed and confirmed, and the commit replaces the
//!   credentials, rotates the account and vault keys (unless `--skip-rotation`), and enrols
//!   this computer as a device. The cache is created once the server acknowledged (see "An
//!   open gap" below).
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
use rizzy_client::account::RecoveryNotice;
use rizzy_client::identity_gen::CivilDate;
use rizzy_client::recovery::{RecoveryInput, RecoveryOptions, start_recovery};
use rizzy_client::rizzy_proto::change::ReregisterStartResponse;
use rizzy_client::rizzy_proto::http::paths;
use rizzy_client::rizzy_proto::recovery::{RecoveryCompleteResponse, RecoveryStartResponse};
use rizzy_client::signup::DeviceKind;
use rizzy_client::store::floors::Floors;
use rizzy_client::sync::VaultSync;
use rizzy_client::vaults::VaultCatalog;

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
    let http = Http::new(server, &env.trust)?;
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
    // ADR 0081 §A7: a driver per recovered vault. Which one is Personal is the directory's word,
    // read by the first sync; until then the legacy rule opens a lone vault and none of several.
    let mut vaults = Vec::with_capacity(done.vault_keys.len());
    for vault_key in done.vault_keys {
        vaults.push(VaultSync::new(vault_key, &done.unlocked, 1)?);
    }
    if vaults.is_empty() {
        return Err(CliError::Client(ClientError::InvalidServerResponse));
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
