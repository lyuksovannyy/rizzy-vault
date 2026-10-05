//! Restore healing for `rv`: the host steps, in order. The client's rules are
//! `rizzy_client::healing` (the account, ADR 0012 §7 steps 1–3 as ADR 0032 §2 replaces them)
//! and `rizzy_client::sync`'s `heal` module (the vault, ADR 0021 §9 "Server behind", "Healing
//! request", "Stale epoch"; ADR 0032 step 3b).
//!
//! # The account ([`Device::heal_account`])
//!
//! When the account answer is a rollback (the server's `state_seq` below the pin, or a restored
//! chain older than the pinned bundle, ADR 0032 §1), the alarm is written first
//! ([`Device::refresh`]), then, still read-only:
//!
//! 1. `POST healing/bundles`, `healing/account-state` (with every certificate, revocation,
//!    `E_id` and `ACCOUNT_SETTINGS` held), `healing/grants`, then the vault's step 3b request
//!    (its self-grant and wrap set) to `vault/heal`, with what
//!    [`rizzy_client::healing::account_healing`] built from the held objects, in that order;
//!    each is a re-publication the server verifies under the identity key it holds and checks
//!    against the signed state it holds, and a repeat of what it holds is a success;
//! 2. the account answer again, verified as at any unlock: a state not below the pin lifts the
//!    alarm in the transaction that adopts it;
//! 3. a new device authentication, whose `reregister` says whether the server's OPAQUE record
//!    lags the healed state: then [`Device::online`] re-registers it with the typed password
//!    (ADR 0032 §4 step 5).
//!
//! A refusal (outside the reconciliation epoch the server takes no out-of-band state, INV-59)
//! or a still older answer leaves the alarm: a genuine rollback stays read-only, and the next
//! run tries again. A device the restored server does not know authenticates with its
//! certificate first ([`Device::authenticate`]).
//!
//! # The vault ([`Device::heal`])
//!
//! 1. A complete Fetch has run: it evaluated "Server behind" and gave the server's heads.
//! 2. [`VaultSync::healing_request`](rizzy_client::sync::VaultSync::healing_request) builds
//!    the request from the records this file holds; nothing is written for it (every record
//!    it carries is a row already).
//! 3. `POST vault/heal`. The server stores all of it or nothing.
//! 4. The answer is applied and its rows (the re-published own ops at `own = 2`, the restore
//!    generation) are committed before the next request (ADR 0026 §4 step 2).
//! 5. A complete Fetch again: the vault leaves read-only once the server's heads and wrap set
//!    are at least this device's.
//!
//! A refusal, or no answer, changes no row: the vault stays read-only, and the next `rv sync`
//! builds the same request again (the server answers "already stored" for what it kept).
//!
//! # Credentials that need the user (ADR 0032 §4)
//!
//! - **A device that missed the rotation** ([`Device::catch_up`]) and finds no grant logs in
//!   with the typed password and its Secret Key, opens `E_srv` and re-wraps its keys; while the
//!   server's record still lags (`credentials_stale`) it adopts nothing and says to open a
//!   device that saw the change.
//! - **The recovery repair** ([`Device::repair_recovery`], `rv recovery repair`): `H_rec` and
//!   `E_rec` together, a new code and kit by default or the current code re-typed.

use rizzy_client::ClientError;
use rizzy_client::healing::{RecoveryRepairForm, account_healing, recovery_repair};
use rizzy_client::login::LoginInput;
use rizzy_client::rizzy_proto::account::AccountView;
use rizzy_client::rizzy_proto::error::ErrorCode;
use rizzy_client::rizzy_proto::http::paths;
use rizzy_client::rizzy_proto::vault::HealingResponse;
use rizzy_client::store::rows::Alarm;
use rizzy_client::unlock::catch_up_account_key;
use rizzy_core::keys::AccountFingerprint;
use rizzy_core::secret_key::RecoveryCode;
use serde::Serialize;

use super::{Device, copy_token, opaque_login};
use crate::error::CliError;
use crate::http::Auth;
use crate::ui::Ui;

impl Device {
    /// Re-publishes the account objects this device holds to a server whose account state is
    /// behind (module docs, "The account"). The caller asks for the account answer again.
    ///
    /// # Errors
    /// [`CliError::Alarm`] with the rollback alarm when nothing can be re-published or the
    /// server refuses it; the transport's errors.
    pub(super) async fn heal_account(&mut self, ui: &mut dyn Ui) -> Result<(), CliError> {
        let Ok(healing) = account_healing(&self.state, &self.held) else {
            ui.note(
                "This device cannot send its newer account state back to the server: the vault \
                 stays read-only.",
            );
            return Err(CliError::Alarm(Alarm::Rollback));
        };
        ui.note(
            "The server shows an older account state than this device holds (a restore from a \
             backup?). Sending the newer one back.",
        );
        // Step 3b (ADR 0032 §2): the vault's self-grant and its wrap set, before any record.
        let vault_id = self.vault.vault_id().to_bytes();
        let Ok(step_3b) = healing
            .self_grants
            .iter()
            .find(|g| g.vault_id.to_bytes() == vault_id)
            .map(|grant| self.vault.self_grant_healing_request(grant))
            .transpose()
        else {
            ui.note(
                "This device cannot send its vault key back to the server (it has not fetched \
                 the vault since its key changed): the vault stays read-only.",
            );
            return Err(CliError::Alarm(Alarm::Rollback));
        };
        let sent = async {
            self.call_empty(paths::HEALING_BUNDLES, &healing.bundles)
                .await?;
            self.call_empty(paths::HEALING_ACCOUNT_STATE, &healing.account_state)
                .await?;
            self.call_empty(paths::HEALING_GRANTS, &healing.grants)
                .await?;
            if let Some(request) = &step_3b {
                let _answer: HealingResponse = self.call(paths::VAULT_HEAL, request).await?;
            }
            Ok(())
        }
        .await;
        match sent {
            Ok(()) => Ok(()),
            Err(CliError::Server(_)) => {
                ui.note(
                    "The server refused this device's newer account state: it may have been \
                     rolled back. The vault stays read-only.",
                );
                Err(CliError::Alarm(Alarm::Rollback))
            }
            Err(e) => Err(e),
        }
    }

    /// `POST path` over the device session, with the empty answer. A session the server
    /// ended is renewed once.
    async fn call_empty<T: Serialize>(
        &mut self,
        path: &'static str,
        value: &T,
    ) -> Result<(), CliError> {
        for attempt in 0..2 {
            let session = self
                .session
                .as_mut()
                .ok_or(CliError::Client(ClientError::Internal))?;
            match self
                .http
                .post_empty(path, value, Auth::Device(session, &self.unlocked))
                .await
            {
                Err(CliError::Server(
                    rizzy_client::rizzy_proto::error::ErrorCode::Unauthorized,
                )) if attempt == 0 => {
                    self.authenticate().await?;
                }
                other => return other,
            }
        }
        Err(CliError::Client(ClientError::Internal))
    }

    /// Heals the vault if the last Fetch found the server behind this device, or a stale answer
    /// calls for re-publishing (module docs). Does nothing otherwise.
    ///
    /// # Errors
    /// [`ClientError::CannotHeal`] when no complete request can be built or the server is still
    /// behind after it was stored; the server's refusal; the transport's and the flows' errors.
    pub async fn heal(&mut self, ui: &mut dyn Ui) -> Result<(), CliError> {
        if !self.vault.needs_healing() {
            return Ok(());
        }
        let Some(request) = self.vault.healing_request()? else {
            return Ok(());
        };
        ui.note(
            "The server has lost changes this device holds (a restore from a backup?). \
             Sending them back.",
        );
        let answer: Result<HealingResponse, CliError> =
            self.call(paths::VAULT_HEAL, &request).await;
        let response = match answer {
            Ok(response) => response,
            Err(e) => {
                self.vault.healing_refused();
                return Err(e);
            }
        };
        let outcome = self.vault.apply_healing_response(&response)?;
        self.flush().await?;
        self.fetch().await?;
        if self.vault.needs_healing() {
            return Err(CliError::Client(ClientError::CannotHeal));
        }
        ui.note(&format!(
            "The server has the lost changes again: {} edits and {} item keys sent back.",
            outcome.ops, outcome.wraps
        ));
        Ok(())
    }
}

impl Device {
    /// ADR 0032 §4 "A device that missed the rotation": the account answer `view` names a newer
    /// account key and the server holds no grant for this device. With the master password typed
    /// for this run, an OPAQUE login over the device session (CRYPTO.md §11.2 steps 2–6) opens
    /// `E_srv` to the key the signed state names, and `E_local` and `E_dev` are re-wrapped under
    /// it ([`catch_up_account_key`]); the caller then verifies the answer again and writes the
    /// record with it. While the server's login record still lags the restored account
    /// (`credentials_stale`), nothing is adopted and the device stays on its key: an enrolled
    /// device that saw the change must heal the server first.
    pub(super) async fn catch_up(
        &mut self,
        ui: &mut dyn Ui,
        view: &AccountView,
        confirmed: Option<&AccountFingerprint>,
    ) -> Result<(), CliError> {
        ui.note(
            "The account key was changed on another device, and the server holds no key for \
             this device (it was restored from a backup?). Logging in with the master password \
             to catch up.",
        );
        let name = ui.line("Login name")?;
        let origin = self.http.origin().as_str().to_owned();
        let secret_key = self.record.secret_key_text();
        let input = LoginInput {
            server_origin: &origin,
            login_name: name.trim(),
            secret_key: &secret_key,
            password: &self.password,
        };
        let session = self
            .session
            .as_mut()
            .ok_or(CliError::Client(ClientError::Internal))?;
        let login = match opaque_login(
            &self.http,
            &mut self.rng,
            ui,
            &input,
            Some((session, &self.unlocked)),
        )
        .await
        {
            Ok(login) => login,
            Err(e @ CliError::Server(ErrorCode::CredentialsStale)) => {
                ui.note(
                    "Open a device that saw the change first: it repairs the server, and this \
                     device then catches up.",
                );
                return Err(e);
            }
            Err(e) => return Err(e),
        };
        catch_up_account_key(
            &mut self.rng,
            &mut self.state,
            &mut self.unlocked,
            view,
            login,
            confirmed,
        )?;
        ui.note("This device holds the account's current key again.");
        Ok(())
    }
}

impl Device {
    /// `rv recovery repair` (ADR 0032 §4 step 6, by user action): after a restore the server's
    /// `H_rec` and `E_rec` may lag the account, and `recovery/start` refuses the code until they
    /// are replaced together. The device goes online (healing the server first when it is
    /// behind), re-authenticates with the master password over its device session (a fresh
    /// OPAQUE session, so after the re-registration of step 5), builds the repair
    /// ([`recovery_repair`]) and commits it, then takes the new state.
    ///
    /// - Default: a new recovery code and a new Emergency Kit (`recovery_epoch + 1`), shown and
    ///   confirmed before the commit. Always taken while recovery is on; the only form after a
    ///   change of the code since the backup, whose restored `H_rec` may be an exposed code's.
    /// - `--retype`: the current code, typed; the server takes it only when the code did not
    ///   change since the backup and is the stored one, else `invalid_request`, and the user is
    ///   told to repair with a new code.
    ///
    /// # Errors
    /// [`CliError::BadInput`] when recovery is off or the typed code is malformed;
    /// [`ClientError::EmergencyKitNotConfirmed`] when the new code is not confirmed; the server's
    /// refusal; the flows' and the transport's errors.
    pub async fn repair_recovery(
        &mut self,
        ui: &mut dyn Ui,
        name: &str,
        retype: bool,
    ) -> Result<(), CliError> {
        self.online(ui).await?;
        self.check_writable()?;
        if !self.state.pin().state().recovery_enabled {
            return Err(CliError::BadInput(
                "recovery is off for this account: there is no recovery code to repair",
            ));
        }
        let form = if retype {
            let typed = ui.secret("Current recovery code (RVR1-…)")?;
            let code = RecoveryCode::parse(typed.trim())
                .map_err(|_| CliError::BadInput("that is not a recovery code (RVR1-…)"))?;
            RecoveryRepairForm::Retype(code)
        } else {
            RecoveryRepairForm::NewCode
        };
        let login = self.reauth(ui, name).await?;
        let mut repair = recovery_repair(&mut self.rng, &login, &self.state, &self.unlocked, form)?;
        if let Some(code) = repair.new_code() {
            let origin = self.http.origin().as_str().to_owned();
            let secret_key = self.record.secret_key_text();
            ui.print(
                "NEW EMERGENCY KIT — once the repair is made, the recovery code of your earlier \
                 kits no longer works. Print it or write it down.",
            )?;
            ui.print(&format!("Server:        {origin}"))?;
            ui.print(&format!("Login name:    {name}"))?;
            ui.print(&format!("Secret Key:    {}", secret_key.as_str()))?;
            ui.print(&format!("Recovery code: {}", code.as_str()))?;
            let typed = ui.line(
                "Type the last four characters of the recovery code to confirm you saved the kit",
            )?;
            if !repair.confirm_new_code(typed.trim()) {
                ui.note("The repair was not made: the new recovery code was not confirmed.");
                return Err(CliError::Client(ClientError::EmergencyKitNotConfirmed));
            }
        }
        let body =
            serde_json::to_vec(repair.commit_request()?).map_err(|_| ClientError::Internal)?;
        let token = copy_token(login.bearer_token());
        drop(login);
        match self
            .http
            .post_bytes_empty(paths::ACCOUNT_COMMIT, body, Auth::Bearer(&token))
            .await
        {
            Ok(()) => {}
            Err(e @ CliError::Server(ErrorCode::InvalidRequest)) if retype => {
                ui.note(
                    "The server did not take the re-typed code: it changed after the backup, it \
                     is not the current one, or nothing needs repairing. Run `rv recovery repair` \
                     without --retype for a new code and kit.",
                );
                return Err(e);
            }
            Err(e) if e.outcome_unknown() => {
                ui.note(
                    "Whether the repair was made is unknown. Keep the new kit and your earlier \
                     one, and run `rv recovery repair` again.",
                );
                return Err(e);
            }
            Err(e) => return Err(e),
        }
        self.refresh(ui).await?;
        ui.note(if retype {
            "The recovery code works again."
        } else {
            "The recovery repair was made: only the new kit's recovery code works from now on."
        });
        Ok(())
    }
}
