//! Restore healing for `rv` (ADR 0021 §9 "Server behind", "Healing request", "Stale epoch";
//! the client's rules are `rizzy_client::sync`'s `heal` module): the host steps, in order.
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
use rizzy_client::rizzy_proto::http::paths;
use rizzy_client::rizzy_proto::vault::HealingResponse;

use super::Device;
use crate::error::CliError;
use crate::ui::Ui;

impl Device {
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
