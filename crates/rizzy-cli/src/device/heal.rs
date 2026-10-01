//! Restore healing for `rv`: the host steps, in order. The client's rules are
//! `rizzy_client::healing` (the account, ADR 0012 §7 steps 1–3) and `rizzy_client::sync`'s
//! `heal` module (the vault, ADR 0021 §9 "Server behind", "Healing request", "Stale epoch").
//!
//! # The account ([`Device::heal_account`])
//!
//! When the account answer is a rollback (the server's `state_seq` below the pin), the alarm is
//! written first ([`Device::refresh`]), then, still read-only:
//!
//! 1. `POST healing/bundles`, `healing/account-state`, `healing/grants` with what
//!    [`rizzy_client::healing::account_healing`] built from the held objects, in that order;
//!    each is a re-publication the server verifies under the identity key it holds, and a
//!    repeat of what it holds is a success;
//! 2. the account answer again, verified as at any unlock: a state not below the pin lifts the
//!    alarm in the transaction that adopts it.
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

use rizzy_client::ClientError;
use rizzy_client::healing::account_healing;
use rizzy_client::rizzy_proto::http::paths;
use rizzy_client::rizzy_proto::vault::HealingResponse;
use rizzy_client::store::rows::Alarm;
use serde::Serialize;

use super::Device;
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
        let sent = async {
            self.call_empty(paths::HEALING_BUNDLES, &healing.bundles)
                .await?;
            self.call_empty(paths::HEALING_ACCOUNT_STATE, &healing.account_state)
                .await?;
            self.call_empty(paths::HEALING_GRANTS, &healing.grants)
                .await
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
