//! The account-level flows of an enrolled device that need a fresh OPAQUE session: a master
//! password or Secret Key change (CRYPTO.md §11.5), following such a change made on another
//! device (§11.3 step 5), and server-side 2FA enrolment and removal (§5.10, §11.15).
//!
//! # A password or Secret Key change ([`Device::change_credentials`])
//!
//! 1. The device syncs (a rotating change needs the complete Fetch, ADR 0025 §2 step 1), and
//!    re-authenticates with the current password over its session (one Argon2id run): the
//!    server marks the session fresh for 5 minutes.
//! 2. `rizzy_client::credentials` builds the new registration, `E_srv'`, the new state and,
//!    with a rotation, the rotation's objects.
//! 3. A new Secret Key comes with a new Emergency Kit, printed and confirmed by re-typing the
//!    last group (CRYPTO.md §11 "Secrets before commit" step 2).
//! 4. The pending record (`E_local'` under the new password, one Argon2id run) and the exact
//!    commit body are written in one transaction before the commit leaves (ADR 0026 §4 step
//!    3), and the commit runs through the rotation's send and finalisation
//!    ([`Device::send_rotation`], [`Device::finish_rotation`]): the same retry rule, the same
//!    rule for when a pending record is dropped.
//!
//! # Settling an interrupted change at start
//!
//! The pending record of a credential change unlocks with the **new** password only, so the
//! settling run asks for it. Whether the server holds the change:
//! - a rotating change: as for any rotation, by the account key the pending record holds;
//! - a change without a rotation: the account key does not tell, so the served state decides
//!   when it can (byte-identical: applied; a state that verifies under this device's own keys
//!   at its own `password_epoch`: not applied), and otherwise an OPAQUE login with the pending
//!   Secret Key and the new password: it succeeds exactly when the server holds the new
//!   credential (a wrong one answers "wrong password or Secret Key"). Only then is the pending
//!   record adopted.
//!
//! A change found not applied is sent again over a login with the current credentials. When
//! those no longer log in either, the credentials were changed again elsewhere: the record is
//! dropped (a change found not applied holds no key the device needs: one without a rotation
//! keeps the account key, and a rotation is found not applied by its account key) and the
//! device follows the other change as in §11.3 step 5. Whenever a credential change is
//! dropped, the user is told which credentials and which kit to keep.
//!
//! # A change that ends without the server holding it
//!
//! A change refused for good, or one that never left the device, is dropped, and the user is
//! told plainly that the new kit it showed is void and the previous one stays valid. The kit's
//! header and the final message say that the old kit stops working only once the change is
//! made, and, when a Secret Key change issues no new recovery code while recovery is on, that
//! the old kit's recovery code stays valid. A login older than four minutes is renewed after
//! the kit is confirmed, so copying the kit by hand does not run past the server's 5-minute
//! window for the commit.
//!
//! # 2FA ([`Device::totp_enable`], [`Device::totp_disable`])
//!
//! Over a fresh re-authentication: enrolment start, the otpauth URI and the Base32 secret
//! printed once (the command's purpose, INV-56), the code from the user's authenticator read
//! from the terminal or standard input (never the command line), the confirmation. Removal
//! needs a current code; one the re-authentication's login already used is refused by the
//! server (§11.15: only a step above the last accepted one), so the user waits for the next
//! code.

use std::time::{Duration, Instant};

use rizzy_client::ClientError;
use rizzy_client::credentials::{
    CredentialChangeInput, PendingCredentialChange, follow_credential_change,
    start_credential_change,
};
use rizzy_client::device::DeviceState;
use rizzy_client::device::UnlockedDevice;
use rizzy_client::login::LoginInput;
use rizzy_client::rizzy_proto::account::AccountView;
use rizzy_client::rizzy_proto::change::{CommitChangeRequest, ReregisterStartResponse};
use rizzy_client::rizzy_proto::http::paths;
use rizzy_client::rizzy_proto::totp::TotpEnrolStartResponse;
use rizzy_client::rizzy_proto::wire::SessionToken;
use rizzy_client::store::record::{DeviceRecord, Stage};
use rizzy_client::two_factor::{TotpEnrolment, disable_request};
use rizzy_client::unlock::verify_unlock;
use zeroize::Zeroizing;

use super::{Device, Flight, RotationInFlight, copy_token, opaque_login};
use crate::error::CliError;
use crate::http::Auth;
use crate::sys::now_ms;
use crate::ui::Ui;

/// What `rv` asks to change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialChange {
    /// A new master password; `rotate` is "also rotate keys" (CRYPTO.md §11.5, opt-in).
    Password {
        /// Whether to rotate the account key and the vault keys too.
        rotate: bool,
    },
    /// A new Secret Key; `rotate` is the default, `false` the explicit opt-out.
    SecretKey {
        /// Whether to rotate the account key and the vault keys too.
        rotate: bool,
        /// Whether that rotation is full: also new identity keys (CRYPTO.md §11.6 "Full",
        /// the "kit was stolen" choice). Only with `rotate`.
        full: bool,
    },
}

/// Asks for a new master password twice.
fn new_password(ui: &mut dyn Ui) -> Result<Zeroizing<String>, CliError> {
    let password = ui.secret("New master password")?;
    let again = ui.secret("New master password, again")?;
    if *password != *again {
        return Err(CliError::BadInput("the two passwords differ"));
    }
    Ok(password)
}

/// How long after the change's login the device logs in once more before the commit: the
/// server takes it only within `FRESH_SESSION_MS` (5 minutes, `rizzy-domain-auth`) of a login,
/// and a minute is left for the rotation and the commit's way.
const RELOGIN_AFTER: Duration = Duration::from_secs(4 * 60);

/// What a change's new Emergency Kit carried, for what the user is told about the old one.
#[derive(Clone, Copy, Debug)]
struct ShownKit {
    /// The kit carries a new recovery code.
    new_recovery_code: bool,
    /// Recovery is on and the kit carries no new code: the old kit's code stays the valid one.
    old_recovery_code_kept: bool,
}

/// What a finished credential change did, for the final message of `rv`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CredentialOutcome {
    /// How many items the rotation left unreadable (0 without a rotation).
    pub dropped_items: usize,
    /// The new Secret Key came without a new recovery code while recovery is on: the recovery
    /// code of the earlier Emergency Kit stays valid and must be kept.
    pub old_recovery_code_kept: bool,
}

/// Tells the user that a change ended without the server holding it: whatever new kit it
/// showed is void, and the previous credentials and Emergency Kit stay the valid ones.
fn change_not_made(ui: &mut dyn Ui, shown: Option<ShownKit>) {
    ui.note(match shown {
        Some(ShownKit {
            new_recovery_code: true,
            ..
        }) => {
            "The change was NOT made: the server does not hold it. The new Emergency Kit shown \
             above is void, its Secret Key and its recovery code alike. Your previous master \
             password, Secret Key and Emergency Kit, with its recovery code, stay the valid \
             ones: keep them. Run the command again to make the change."
        }
        Some(_) => {
            "The change was NOT made: the server does not hold it. The new Emergency Kit shown \
             above is void. Your previous master password, Secret Key and Emergency Kit stay \
             the valid ones: keep them. Run the command again to make the change."
        }
        None => {
            "The change was NOT made: the server does not hold it. Your current master \
             password stays the valid one. Run the command again to make the change."
        }
    });
}

/// Shows the change's new Emergency Kit, if it has one, and has it confirmed by re-typing the
/// last group (CRYPTO.md §11 "Secrets before commit" step 2). Returns what the kit carried.
///
/// What the kit shows decides what the user is told about the old one: a change that issues
/// no new recovery code while recovery is on leaves the old kit's code the only valid one
/// (CRYPTO.md §11.5 step 4: a new code only "when the default rotation issues one"), so the
/// header does not tell the user to drop the old kit.
fn show_kit(
    ui: &mut dyn Ui,
    pending: &mut PendingCredentialChange,
    recovery_on: bool,
) -> Result<Option<ShownKit>, CliError> {
    let Some(kit) = pending.emergency_kit() else {
        return Ok(None);
    };
    let shown = ShownKit {
        new_recovery_code: kit.recovery_code().is_some(),
        old_recovery_code_kept: kit.recovery_code().is_none() && recovery_on,
    };
    ui.print(if shown.old_recovery_code_kept {
        "NEW EMERGENCY KIT — once the change is made, the Secret Key of your old kit no longer \
         works, but the old kit's recovery code stays valid and is not on this one. Print it or \
         write it down."
    } else {
        "NEW EMERGENCY KIT — once the change is made, the old kit no longer works. Print it or \
         write it down."
    })?;
    ui.print(&format!("Server:        {}", kit.server_origin()))?;
    ui.print(&format!("Login name:    {}", kit.login_name()))?;
    ui.print(&format!("Secret Key:    {}", kit.secret_key()))?;
    match kit.recovery_code() {
        Some(code) => ui.print(&format!("Recovery code: {code}"))?,
        None if recovery_on => ui.note(
            "The recovery code of your earlier Emergency Kit stays valid: keep it with the new \
             kit.",
        ),
        None => {}
    }
    let typed =
        ui.line("Type the last four characters of the Secret Key to confirm you saved the kit")?;
    if let Err(e) = pending.confirm_kit(typed.trim()) {
        change_not_made(ui, Some(shown));
        return Err(e.into());
    }
    Ok(Some(shown))
}

impl Device {
    /// A password or Secret Key change (module docs).
    ///
    /// # Errors
    /// [`CliError::Alarm`] when the device is read-only; the flows' and the transport's
    /// errors. An answer that leaves the commit's outcome unknown leaves the pending record
    /// for the next run to settle, and the user is told; a change that ends without reaching
    /// the server, or that the server refused for good, is dropped, and the user is told that
    /// the kit it showed is void.
    pub async fn change_credentials(
        &mut self,
        ui: &mut dyn Ui,
        login_name: &str,
        change: CredentialChange,
    ) -> Result<CredentialOutcome, CliError> {
        self.sync(ui).await?;
        self.check_writable()?;
        let (new_secret_key, rotate, full_rotation) = match change {
            CredentialChange::Password { rotate } => (false, rotate, false),
            CredentialChange::SecretKey { rotate, full } => (true, rotate, full),
        };
        let recovery_on = self.state.pin().state().recovery_enabled;
        let recovery_code = if rotate && !new_secret_key && recovery_on {
            Some(ui.secret(
                "Recovery code from your Emergency Kit (it stays valid after the rotation)",
            )?)
        } else {
            None
        };
        let password = if new_secret_key {
            Zeroizing::new(self.password.as_str().to_owned())
        } else {
            new_password(ui)?
        };
        if !rotate {
            ui.note(if new_secret_key {
                "Skipping the key rotation: an old copy of the server's data still opens with \
                 the old Secret Key and the master password, and yields the current account key."
            } else {
                "The keys are not rotated. If the old password leaked, run `rv password --rotate` \
                 or `rv rotate` as well."
            });
        }
        // §11.5 step 1: a fresh OPAQUE session with the current password.
        let logged_in_at = Instant::now();
        let reauth = self.reauth(ui, login_name).await?;
        let mut token = copy_token(reauth.bearer_token());
        let input = CredentialChangeInput {
            login_name,
            new_password: &password,
            new_secret_key,
            rotate,
            full_rotation,
            recovery_code: recovery_code.as_deref().map(String::as_str),
            now_ms: now_ms(),
        };
        let (started, request) =
            start_credential_change(&mut self.rng, reauth, &self.state, &self.unlocked, &input)?;
        let answer: ReregisterStartResponse = self
            .http
            .post(
                paths::ACCOUNT_REREGISTER_START,
                &request,
                Auth::Bearer(&token),
            )
            .await?;
        let mut pending = started.finish(
            &mut self.rng,
            &answer,
            &self.state,
            &self.unlocked,
            &[&self.vault],
        )?;
        // Secrets before commit (CRYPTO.md §11): the new kit is shown and confirmed first.
        let shown = show_kit(ui, &mut pending, recovery_on)?;
        // The server takes the commit only within FRESH_SESSION_MS (5 minutes) of the login
        // (CRYPTO.md §11 "Replacing credentials"). Copying the kit by hand can take longer, so
        // the device logs in once more when the first login is close to that limit. The
        // registration upload is not bound to a session, so the new token commits it.
        if logged_in_at.elapsed() >= RELOGIN_AFTER {
            ui.note("Logging in once more: the server takes the change only right after a login.");
            match self.reauth(ui, login_name).await {
                Ok(again) => token = copy_token(again.bearer_token()),
                Err(e) => {
                    change_not_made(ui, shown);
                    return Err(e);
                }
            }
        }
        let flight = self.commit_credentials(ui, pending, token, shown).await?;
        // The server holds the new credential: this run goes on with it.
        self.password = password;
        let dropped_items = Box::pin(self.finish_rotation(ui, flight)).await?;
        Ok(CredentialOutcome {
            dropped_items,
            old_recovery_code_kept: shown.is_some_and(|s| s.old_recovery_code_kept),
        })
    }

    /// Writes the pending record and the commit body, and sends the commit
    /// ([`Device::send_rotation`]). When it fails, the user is told what holds: a change whose
    /// outcome is unknown stays saved, and one that never reached the server or was refused
    /// for good is dropped, with any kit it showed void.
    async fn commit_credentials(
        &mut self,
        ui: &mut dyn Ui,
        mut pending: PendingCredentialChange,
        token: SessionToken,
        shown: Option<ShownKit>,
    ) -> Result<RotationInFlight, CliError> {
        let pending_record =
            match pending.pending_record(&mut self.rng, &self.state, &self.unlocked) {
                Ok(record) => record,
                Err(e) => {
                    change_not_made(ui, shown);
                    return Err(e.into());
                }
            };
        self.record = self
            .state
            .record(Stage::Committed)?
            .with_pending(pending_record);
        let mut flight = RotationInFlight {
            pending: Flight::Credential(Box::new(pending)),
            token,
        };
        if let Err(e) = self.send_rotation(&mut flight).await {
            if !matches!(e, CliError::Alarm(_)) {
                // The stored body is there exactly while a commit is persisted and not
                // settled; without it, the change never reached the server or was refused for
                // good, and nothing of it is kept.
                if self.pending_commit.is_some() {
                    ui.note(
                        "The change is not finished, and whether the server applied it may be \
                         unknown. It stays saved on this device: the next rv command that goes \
                         online asks for the new master password and settles it. Until then, \
                         open this device with the current one, and keep both Emergency Kits.",
                    );
                } else {
                    change_not_made(ui, shown);
                }
            }
            return Err(e);
        }
        Ok(flight)
    }

    /// Whether the server holds the stored commit `request` (module docs, "Settling"):
    /// `credential` is the login name and the new password of a credential change.
    pub(super) async fn settled(
        &mut self,
        ui: &mut dyn Ui,
        request: &CommitChangeRequest,
        promoted: &DeviceRecord,
        pending_unlocked: &UnlockedDevice,
        view: &AccountView,
        credential: Option<&(String, Zeroizing<String>)>,
    ) -> Result<bool, CliError> {
        let plain = request.registration_upload.is_some() && request.vault_rotation.is_none();
        let Some((name, new_password)) = credential.filter(|_| plain) else {
            return self
                .pending_applied(request, promoted, pending_unlocked, view)
                .await;
        };
        if view.account_state == request.account_state {
            return Ok(true);
        }
        // The served state against this device's own (pre-change) keys: only a state that
        // verifies under them at this device's `password_epoch` (every credential change bumps
        // it) proves the change is not on the server. Every other outcome (a password change,
        // a later rotation, an identity change, a rollback or a fork) leaves it open, and the
        // login below decides: a change applied and then followed by a rotation elsewhere must
        // not be resent under the old credentials, which no longer log in. An alarm the served
        // state warrants is raised by the refresh that follows either way.
        let mut probe: DeviceState = self.record.to_state(self.state.pin().clone())?;
        if verify_unlock(&mut probe, &self.unlocked, view, None).is_ok() {
            return Ok(false);
        }
        let secret_key = promoted.secret_key_text();
        let origin = self.http.origin().as_str().to_owned();
        let input = LoginInput {
            server_origin: &origin,
            login_name: name,
            secret_key: &secret_key,
            password: new_password,
        };
        let session = self
            .session
            .as_mut()
            .ok_or(CliError::Client(ClientError::Internal))?;
        match opaque_login(
            &self.http,
            &mut self.rng,
            ui,
            &input,
            Some((session, &self.unlocked)),
        )
        .await
        {
            Ok(_) => Ok(true),
            Err(CliError::Client(ClientError::WrongPasswordOrSecretKey)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// §11.3 step 5 (module docs): asks for the new master password, logs in with it and the
    /// stored Secret Key (if that fails, with a new Secret Key the user types), and re-creates
    /// `E_local` in memory. The caller verifies the answer again and writes the record.
    pub(super) async fn follow_credential_change(
        &mut self,
        ui: &mut dyn Ui,
    ) -> Result<(), CliError> {
        ui.note(
            "The master password or the Secret Key of this account was changed on another \
             device. Enter the new one to go on; this device then uses it.",
        );
        let name = ui.line("Login name")?;
        let password = ui.secret("New master password")?;
        let origin = self.http.origin().as_str().to_owned();
        let mut secret_key = self.record.secret_key_text();
        let mut asked_key = false;
        let login = loop {
            let input = LoginInput {
                server_origin: &origin,
                login_name: &name,
                secret_key: &secret_key,
                password: &password,
            };
            let session = self
                .session
                .as_mut()
                .ok_or(CliError::Client(ClientError::Internal))?;
            match opaque_login(
                &self.http,
                &mut self.rng,
                ui,
                &input,
                Some((session, &self.unlocked)),
            )
            .await
            {
                Ok(login) => break login,
                // The stored Secret Key no longer works: it was changed too.
                Err(CliError::Client(ClientError::WrongPasswordOrSecretKey)) if !asked_key => {
                    asked_key = true;
                    secret_key = ui.secret("New Secret Key (RV1-…) from the new Emergency Kit")?;
                }
                Err(e) => return Err(e),
            }
        };
        follow_credential_change(&mut self.rng, login, &mut self.state, &mut self.unlocked)?;
        self.password = password;
        Ok(())
    }

    /// `rv 2fa enable` (module docs).
    ///
    /// # Errors
    /// The flows' and the transport's errors; `unauthorized` for a wrong code.
    pub async fn totp_enable(&mut self, ui: &mut dyn Ui, login_name: &str) -> Result<(), CliError> {
        self.online(ui).await?;
        let reauth = self.reauth(ui, login_name).await?;
        let token = copy_token(reauth.bearer_token());
        drop(reauth);
        let answer: TotpEnrolStartResponse = self
            .http
            .post_no_body(paths::TOTP_ENROL_START, Auth::Bearer(&token))
            .await?;
        let enrolment =
            TotpEnrolment::from_response(&answer, self.http.origin().as_str(), login_name)?;
        drop(answer);
        ui.print("Add this to your authenticator app (shown once):")?;
        ui.print(&format!(
            "otpauth URI:   {}",
            enrolment.otpauth_uri().as_str()
        ))?;
        ui.print(&format!(
            "Secret:        {}",
            enrolment.secret_base32().as_str()
        ))?;
        let code = ui.secret("The current code from your authenticator app")?;
        let request = enrolment.confirm_request(&code)?;
        self.http
            .post_empty(paths::TOTP_ENROL_CONFIRM, &request, Auth::Bearer(&token))
            .await?;
        ui.note("Two-factor login is on: every login now asks for a code.");
        Ok(())
    }

    /// `rv 2fa disable` (module docs).
    ///
    /// # Errors
    /// The flows' and the transport's errors; `unauthorized` for a wrong or used code.
    pub async fn totp_disable(
        &mut self,
        ui: &mut dyn Ui,
        login_name: &str,
    ) -> Result<(), CliError> {
        self.online(ui).await?;
        let reauth = self.reauth(ui, login_name).await?;
        let token = copy_token(reauth.bearer_token());
        drop(reauth);
        let code = ui.secret(
            "A current code from your authenticator app (a new one, not the one used to log in)",
        )?;
        let request = disable_request(&code)?;
        self.http
            .post_empty(paths::TOTP_DISABLE, &request, Auth::Bearer(&token))
            .await?;
        ui.note("Two-factor login is off.");
        Ok(())
    }
}
