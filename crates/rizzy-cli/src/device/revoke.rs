// SPDX-License-Identifier: AGPL-3.0-only

//! Removing devices from the account ([ADR 0091] §3; the host side of
//! `rizzy_client::revocation`): [`Device::revoke_devices`], its cancellation
//! [`Device::unsuspend_devices`], and what a device learns about removals when it goes online.
//!
//! # The flow (§3)
//!
//! 1. **Settle first.** [`Device::online`] settles a pending record before a command gets
//!    here, so a removal never starts on top of another pending commit.
//! 2. **Choose.** The command names the devices; the reason decides the rotation
//!    ([`Removal`]): "lost or stolen" (the default) is a full rotation, by default with a new
//!    Secret Key in the same commit (§4); "wiped and handed over" is a standard rotation.
//! 3. **Re-authenticate and suspend at once.** A fresh OPAQUE login bound to this device, then
//!    `devices/suspend` for each chosen device in ascending id order, each H kept. Suspension
//!    comes before anything slow.
//! 4. **Secrets.** By default the new Secret Key's Emergency Kit (with a new recovery code
//!    where recovery is on) is generated, shown and confirmed here, after a sync (the change
//!    is built on completely fetched vaults, and rebuilt in step 5). Without a new Secret Key
//!    the current recovery code is typed instead, where recovery is on (it stays valid).
//! 5. **Renew, fetch, build.** The login is renewed when it nears the server's 5-minute limit;
//!    `devices/suspend` again for the first chosen device renews the window, and its H must be
//!    step 3's (`check_renewed_head`): on a mismatch the flow starts again at step 3 once, and
//!    stops on a second one. Then `account/state`, fetched after that suspend, this device's
//!    own uploads and a complete Fetch (ADR 0025 §2 step 1), and the rotation built, or
//!    rebuilt, on them, with one revocation per chosen device.
//! 6. **Persist and commit**: the pending record and the exact commit, then `account/commit`
//!    ([`Device::send_rotation`]).
//! 7. **On `state_conflict`** the renewing suspend runs again before each rebuild
//!    ([`RotationInFlight::renew`]).
//! 8. **Crash.** The next run settles the pending record as for any rotation. With none, but
//!    devices still suspended, every command that goes online names them with the two
//!    commands that finish or cancel their removal (`Device::removal_notes`).
//!
//! An error before the commit leaves the chosen devices suspended: they can do nothing until
//! the removal is finished or cancelled, which is the safe side for a lost device.
//!
//! # A revoked device with a pending commit (§3)
//!
//! Its stored commit can never land. When device authentication is refused while a pending
//! record is held, the device logs in over OPAQUE (the account credentials, which it may still
//! know) and reads the account: only when that answer, verified from the pin, holds a
//! revocation of this very device (`own_revocation`) is the pending record deleted, unsent.
//! The device then stays refused by the server, and the user is told that `rv device forget`
//! deletes its local data. Anything less (no login, no verified revocation) keeps the record.
//!
//! [ADR 0091]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0091-revoked-device-rotation-race.md

use std::time::Instant;

use rizzy_client::ClientError;
use rizzy_client::credentials::{CredentialChangeInput, start_credential_change};
use rizzy_client::login::{LoggedIn, LoginInput};
use rizzy_client::revocation::{check_renewed_head, own_revocation};
use rizzy_client::rizzy_proto::account::AccountView;
use rizzy_client::rizzy_proto::change::{
    DeviceSuspensionRequest, ReregisterStartResponse, SuspendDeviceResponse,
};
use rizzy_client::rizzy_proto::http::paths;
use rizzy_client::rizzy_proto::limits::MAX_DEVICE_STATEMENTS;
use rizzy_client::rizzy_proto::wire::{Id, SessionToken};
use rizzy_client::rotation::{
    ConflictOutcome, RevokeDevice, RotationLevel, RotationOptions, start_rotation,
};
use rizzy_client::store::record::Stage;
use rizzy_client::store::rows::Alarm;
use rizzy_client::unlock::{account_state_query, identity_change_fingerprint};
use rizzy_core::ids::DeviceId;
use zeroize::Zeroizing;

use super::credentials::{RELOGIN_AFTER, change_not_made, show_kit};
use super::{CredentialOutcome, Device, Flight, RotationInFlight, copy_token, opaque_login};
use crate::error::CliError;
use crate::http::Auth;
use crate::paths::hex;
use crate::sys::now_ms;
use crate::ui::{Checkpoint, Ui};

/// Why the devices are removed (ADR 0091 §3 step 2, §4), which decides the rotation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Removal {
    /// "Lost or stolen", the default: a full rotation and a new Secret Key in the same commit,
    /// with a new Emergency Kit.
    Lost,
    /// "Lost or stolen" with "Keep my Secret Key (only if nobody can learn your master
    /// password)": a full rotation, the Secret Key kept.
    LostKeepSecretKey,
    /// "Wiped and handed over": a standard rotation, the Secret Key kept.
    Wiped,
}

/// What step 5's renewing suspend found.
enum Renewal {
    /// H held; the login renewed on the way, when it was.
    Held(Option<Box<LoggedIn>>),
    /// H moved: a bug or a malicious server.
    Moved,
}

impl Device {
    /// Removes `targets` from the account (module docs), with a rotation as `removal` says.
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] for no device, too many, or this device;
    /// [`ClientError::InvalidServerResponse`] when H moved twice; [`CliError::Alarm`]; the
    /// flows' and the transport's errors. An answer that leaves the commit's outcome unknown
    /// leaves the pending record for the next run to settle.
    pub async fn revoke_devices(
        &mut self,
        ui: &mut dyn Ui,
        login_name: &str,
        targets: &[DeviceId],
        removal: Removal,
    ) -> Result<CredentialOutcome, CliError> {
        self.check_writable()?;
        let mut chosen = targets.to_vec();
        chosen.sort_unstable();
        chosen.dedup();
        if chosen.is_empty()
            || chosen.len() > MAX_DEVICE_STATEMENTS
            || chosen.contains(&self.state.device_id())
        {
            return Err(CliError::Client(ClientError::InvalidInput));
        }
        let mut restarted = false;
        loop {
            let attempt = match removal {
                Removal::Lost => {
                    Box::pin(self.revoke_with_new_secret_key(ui, login_name, &chosen)).await?
                }
                Removal::LostKeepSecretKey | Removal::Wiped => {
                    let level = if removal == Removal::Wiped {
                        RotationLevel::Standard
                    } else {
                        RotationLevel::Full
                    };
                    Box::pin(self.revoke_keeping_secret_key(ui, login_name, &chosen, level)).await?
                }
            };
            match attempt {
                Some(outcome) => return Ok(outcome),
                None if !restarted => {
                    restarted = true;
                    ui.note(
                        "The server reported a different state for a device being removed \
                         while it was suspended. Starting the removal again.",
                    );
                }
                None => {
                    ui.note(
                        "The server reported a different state for a device being removed \
                         twice, which a correct server never does: the removal is stopped. \
                         The devices stay suspended; nothing else was changed.",
                    );
                    return Err(CliError::Client(ClientError::InvalidServerResponse));
                }
            }
        }
    }

    /// The default removal: steps 3–8 with a new Secret Key in the commit. `None` when H
    /// moved (step 5), with the shown kit declared void.
    async fn revoke_with_new_secret_key(
        &mut self,
        ui: &mut dyn Ui,
        login_name: &str,
        chosen: &[DeviceId],
    ) -> Result<Option<CredentialOutcome>, CliError> {
        let recovery_on = self.state.pin().state().recovery_enabled;
        let (reauth, logged_in_at, revoke) = self.suspend_chosen(ui, login_name, chosen).await?;
        let first = *revoke.first().ok_or(ClientError::Internal)?;
        let mut token = copy_token(reauth.bearer_token());
        // The change is built on vaults the device uploaded and fetched completely (ADR 0025
        // §2 step 1), here already after the suspension; step 5 fetches again up to H.
        self.sync(ui).await?;
        // Step 4: the new Secret Key under the same master password, its kit shown and
        // confirmed before anything is committed (CRYPTO.md §11 "Secrets before commit").
        let password = Zeroizing::new(self.password.as_str().to_owned());
        let input = CredentialChangeInput {
            login_name,
            new_password: &password,
            new_secret_key: true,
            rotate: true,
            full_rotation: true,
            recovery_code: None,
            revoke: &revoke,
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
            &self.vaults.open_refs(),
        )?;
        let shown = show_kit(ui, &mut pending, recovery_on)?;
        ui.checkpoint(Checkpoint::KitConfirmed)?;
        // Step 5. The change was built before the vaults were fetched up to H, so it is rebuilt
        // on the state and the vaults as they are after the renewing suspend.
        let rebuilt = async {
            match self
                .renew_window(ui, login_name, &mut token, logged_in_at, first)
                .await?
            {
                Renewal::Held(_) => {}
                Renewal::Moved => return Ok(false),
            }
            let view = self.state_after_suspend(ui, &token).await?;
            let all = self.vaults.open_refs();
            let result = pending.on_state_conflict(&mut self.rng, &view, &self.unlocked, &all);
            self.rebased(result, &view).await?;
            Ok::<_, CliError>(true)
        }
        .await;
        match rebuilt {
            Ok(true) => {}
            Ok(false) => {
                change_not_made(ui, shown);
                return Ok(None);
            }
            Err(e) => {
                if !matches!(e, CliError::Alarm(_)) {
                    change_not_made(ui, shown);
                }
                return Err(e);
            }
        }
        // Step 6, and step 7 on a conflict.
        let flight = self
            .commit_credentials(ui, pending, token, shown, Some(first))
            .await?;
        ui.checkpoint(Checkpoint::Acknowledged)?;
        let dropped_items = Box::pin(self.finish_rotation(ui, flight)).await?;
        Ok(Some(CredentialOutcome {
            dropped_items,
            old_recovery_code_kept: shown.is_some_and(|s| s.old_recovery_code_kept),
        }))
    }

    /// Steps 3–8 without a new Secret Key: a rotation at `level` carrying the revocations.
    /// `None` when H moved (step 5).
    async fn revoke_keeping_secret_key(
        &mut self,
        ui: &mut dyn Ui,
        login_name: &str,
        chosen: &[DeviceId],
        level: RotationLevel,
    ) -> Result<Option<CredentialOutcome>, CliError> {
        let (reauth, logged_in_at, revoke) = self.suspend_chosen(ui, login_name, chosen).await?;
        let first = *revoke.first().ok_or(ClientError::Internal)?;
        let mut token = copy_token(reauth.bearer_token());
        // Step 4: the current recovery code stays valid and is re-wrapped (CRYPTO.md §11.6).
        let recovery_code = if self.state.pin().state().recovery_enabled {
            Some(ui.secret(
                "Recovery code from your Emergency Kit (it stays valid after the rotation)",
            )?)
        } else {
            None
        };
        // Step 5.
        let reauth = match self
            .renew_window(ui, login_name, &mut token, logged_in_at, first)
            .await?
        {
            Renewal::Held(again) => again.map_or(reauth, |login| *login),
            Renewal::Moved => return Ok(None),
        };
        let view = self.state_after_suspend(ui, &token).await?;
        let base = reauth.account().pin().state_wire().to_vec();
        let options = RotationOptions {
            level,
            revoke: &revoke,
            recovery_code: recovery_code.as_deref().map(String::as_str),
            now_ms: now_ms(),
        };
        let all = self.vaults.open_refs();
        let mut pending = start_rotation(
            &mut self.rng,
            reauth,
            &self.state,
            &self.unlocked,
            &all,
            &options,
        )?;
        // The login's account is from before the renewing suspend: a state that moved since
        // is the one the rotation is rebuilt on.
        if view.account_state.as_slice() != base.as_slice() {
            let all = self.vaults.open_refs();
            let result = pending.on_state_conflict(&mut self.rng, &view, &self.unlocked, &all);
            self.rebased(result, &view).await?;
        }
        let pending_record = pending.pending_record(&mut self.rng, &self.state, &self.unlocked)?;
        self.record = self
            .state
            .record(Stage::Committed)?
            .with_pending(pending_record);
        // Step 6, and step 7 on a conflict.
        let mut flight = RotationInFlight {
            pending: Flight::Rotation(Box::new(pending)),
            token,
            renew: Some(first),
        };
        if let Err(e) = self.send_rotation(ui, &mut flight).await {
            Self::rotation_unfinished(ui, self.pending_commit.is_some(), &e);
            return Err(e);
        }
        ui.checkpoint(Checkpoint::Acknowledged)?;
        let dropped_items = Box::pin(self.finish_rotation(ui, flight)).await?;
        Ok(Some(CredentialOutcome {
            dropped_items,
            old_recovery_code_kept: false,
        }))
    }

    /// Step 3: a fresh OPAQUE login bound to this device, then each chosen device suspended,
    /// in ascending id order (`chosen` is sorted), each with its H.
    async fn suspend_chosen(
        &mut self,
        ui: &mut dyn Ui,
        login_name: &str,
        chosen: &[DeviceId],
    ) -> Result<(LoggedIn, Instant, Vec<RevokeDevice>), CliError> {
        let logged_in_at = Instant::now();
        let reauth = self.reauth(ui, login_name).await?;
        let mut revoke = Vec::with_capacity(chosen.len());
        for &device_id in chosen {
            let head = self.suspend(reauth.bearer_token(), device_id).await?;
            revoke.push(RevokeDevice {
                device_id,
                last_accepted_device_seq: head,
            });
        }
        ui.note(if chosen.len() == 1 {
            "The device is suspended: from now on the server refuses it."
        } else {
            "The devices are suspended: from now on the server refuses them."
        });
        ui.checkpoint(Checkpoint::Suspended)?;
        Ok((reauth, logged_in_at, revoke))
    }

    /// `devices/suspend` of `device_id` over the fresh OPAQUE session `token` (CRYPTO.md
    /// §11.8 step 0): opens, or renews, this device's revocation window; returns H.
    pub(super) async fn suspend(
        &self,
        token: &SessionToken,
        device_id: DeviceId,
    ) -> Result<u64, CliError> {
        let answer: SuspendDeviceResponse = self
            .http
            .post(
                paths::DEVICES_SUSPEND,
                &DeviceSuspensionRequest {
                    device_id: Id::from_bytes(device_id.to_bytes()),
                },
                Auth::Bearer(token),
            )
            .await?;
        Ok(answer.last_accepted_device_seq)
    }

    /// Step 5's renewal: a new login when the first nears the server's limit (`token` then
    /// becomes its token), and `devices/suspend` again for `first`, whose H must not move.
    async fn renew_window(
        &mut self,
        ui: &mut dyn Ui,
        login_name: &str,
        token: &mut SessionToken,
        logged_in_at: Instant,
        first: RevokeDevice,
    ) -> Result<Renewal, CliError> {
        let mut again = None;
        if logged_in_at.elapsed() >= RELOGIN_AFTER {
            ui.note("Logging in once more: the server takes the removal only right after a login.");
            let login = self.reauth(ui, login_name).await?;
            *token = copy_token(login.bearer_token());
            again = Some(Box::new(login));
        }
        let head = self.suspend(token, first.device_id).await?;
        Ok(
            if check_renewed_head(first.last_accepted_device_seq, head).is_ok() {
                Renewal::Held(again)
            } else {
                Renewal::Moved
            },
        )
    }

    /// Step 5's reads, after the renewing suspend: `account/state` over `token`, then this
    /// device's own uploads and a complete Fetch (ADR 0025 §2 step 1), which reach H.
    async fn state_after_suspend(
        &mut self,
        ui: &mut dyn Ui,
        token: &SessionToken,
    ) -> Result<AccountView, CliError> {
        let view: AccountView = self
            .http
            .post(
                paths::ACCOUNT_STATE,
                &account_state_query(&self.state),
                Auth::Bearer(token),
            )
            .await?;
        self.sync(ui).await?;
        Ok(view)
    }

    /// The outcome of rebuilding a built change on `view` before it was ever sent: a rollback
    /// or a fork is the alarm (written in the transaction that detects it, ADR 0026 §4 step 4).
    async fn rebased(
        &mut self,
        result: Result<ConflictOutcome, ClientError>,
        view: &AccountView,
    ) -> Result<(), CliError> {
        match result {
            Ok(ConflictOutcome::Resend) => Ok(()),
            // Nothing was sent, so nothing can have landed.
            Ok(ConflictOutcome::Committed) => Err(CliError::Client(ClientError::Internal)),
            Err(e @ (ClientError::Rollback | ClientError::Fork)) => {
                let alarm = if matches!(e, ClientError::Rollback) {
                    Alarm::Rollback
                } else {
                    Alarm::Fork
                };
                let pinned = self.state.pin().state_wire().to_vec();
                Err(self
                    .alarm(alarm, &[&pinned, view.account_state.as_slice()])
                    .await)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Cancels the removal of `targets` (§3 step 8, "Cancel"): `devices/unsuspend` for each,
    /// over a fresh OPAQUE login bound to this device. The last one closes this device's
    /// revocation window.
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] for no device or this device; the flows' and the
    /// transport's errors.
    pub async fn unsuspend_devices(
        &mut self,
        ui: &mut dyn Ui,
        login_name: &str,
        targets: &[DeviceId],
    ) -> Result<(), CliError> {
        let mut chosen = targets.to_vec();
        chosen.sort_unstable();
        chosen.dedup();
        if chosen.is_empty() || chosen.contains(&self.state.device_id()) {
            return Err(CliError::Client(ClientError::InvalidInput));
        }
        let reauth = self.reauth(ui, login_name).await?;
        for device_id in chosen {
            self.http
                .post_empty(
                    paths::DEVICES_UNSUSPEND,
                    &DeviceSuspensionRequest {
                        device_id: Id::from_bytes(device_id.to_bytes()),
                    },
                    Auth::Bearer(reauth.bearer_token()),
                )
                .await?;
        }
        Ok(())
    }

    /// The suspended, unrevoked devices of the account, as the server last reported them
    /// (advisory, for display: ADR 0091 §2 "What clients see").
    #[must_use]
    pub fn suspended_devices(&self) -> &[DeviceId] {
        self.account
            .as_ref()
            .map_or(&[], |a| a.revocation_notice().suspended.as_slice())
    }

    /// §3 step 8: with no pending record, a removal the server reports half done (a device
    /// still suspended) is named, with the commands that finish or cancel it.
    pub(super) fn removal_notes(&self, ui: &mut dyn Ui) {
        if self.record.has_pending() {
            return;
        }
        let own = self.state.device_id();
        for id in self.suspended_devices().iter().filter(|id| **id != own) {
            let id = hex(id.as_bytes());
            ui.note(&format!(
                "The removal of device {id} was started and not finished: it is suspended (the \
                 server refuses it) but not removed. Finish removing it with `rv device revoke \
                 {id} --name <login>`, or cancel with `rv device unsuspend {id} --name <login>`."
            ));
        }
    }

    /// §3 "A revoked device with a pending commit": device authentication answered
    /// `refused` while a pending record is held. The record is deleted, unsent, only when an
    /// OPAQUE login's account answer, verified from the pin, holds a revocation of this device;
    /// `refused` is returned either way (the device stays refused).
    pub(super) async fn refused_with_pending(
        &mut self,
        ui: &mut dyn Ui,
        refused: CliError,
    ) -> CliError {
        ui.note(
            "The server refused this device, and a change it started is still saved here. A \
             login with your master password tells whether this device was removed from the \
             account on another device.",
        );
        match self.own_revocation_probe(ui).await {
            Ok(true) => {}
            Ok(false) => {
                ui.note(
                    "The account does not show this device as removed: the saved change stays.",
                );
                return refused;
            }
            Err(_) => {
                ui.note(
                    "Whether this device was removed could not be told (the login or the \
                     account's answer failed): the saved change stays.",
                );
                return refused;
            }
        }
        if let Err(e) = self.abandon_pending().await {
            return e;
        }
        ui.note(
            "This device was removed from the account on another device. Its saved change was \
             deleted without being sent, and it no longer syncs: the server refuses it. What it \
             holds stays readable here offline; `rv device forget` deletes its local data.",
        );
        refused
    }

    /// The OPAQUE login and the verified account answer of [`Device::refused_with_pending`]:
    /// whether a verified revocation names this device. A changed identity is shown and must
    /// be confirmed first, as on any refresh.
    async fn own_revocation_probe(&mut self, ui: &mut dyn Ui) -> Result<bool, CliError> {
        let name = ui.line("Login name")?;
        let secret_key = self.record.secret_key_text();
        let origin = self.http.origin().as_str().to_owned();
        let input = LoginInput {
            server_origin: &origin,
            login_name: &name,
            secret_key: &secret_key,
            password: &self.password,
        };
        let login = opaque_login(&self.http, &mut self.rng, ui, &input, None).await?;
        let view: AccountView = self
            .http
            .post(
                paths::ACCOUNT_STATE,
                &account_state_query(&self.state),
                Auth::Bearer(login.bearer_token()),
            )
            .await?;
        let confirmed = match identity_change_fingerprint(&self.state, &view)? {
            None => None,
            Some(fingerprint) => {
                if !Self::confirm_identity(ui, &fingerprint)? {
                    return Ok(false);
                }
                Some(fingerprint)
            }
        };
        Ok(own_revocation(&self.state, &view, confirmed.as_ref())?)
    }
}
