// SPDX-License-Identifier: AGPL-3.0-only

//! The upload that comes first in "remove this device" ([ADR 0026] §5 as [ADR 0095] §D
//! replaces it, the owner's decision on open question 6; `rv`'s `Device::upload_unsent`).
//!
//! ```text
//! start ──► per open vault: Fetch (one page: a restore generation) ──► Upload of the unsent own
//!   rows, byte for byte (ops in chain order, then snapshots) ──► … until an answer acknowledges
//!   nothing more (a conflict, a stale_epoch) or nothing is left ──► next vault ──► idle
//! ```
//!
//! Every step is `rizzy-client`'s: [`VaultSync::unsent_upload_request`] signs no new dot,
//! re-issues nothing and writes no snapshot, and journals the rows it hands out as sent (§4
//! step 1), so the host drains after every call here, before the request goes out. It runs
//! with or without alarm 4 (it is that alarm's only resolution) and is refused under alarms 1
//! to 3, which refuse removal itself. A Fetch that shows more own history, or an upload with a
//! conflict at an own dot, raises alarm 4 as in a sync (ADR 0095 §C), and the upload goes on: it
//! signs nothing new. Any error ends it, and the host then says how many own ops and snapshots
//! are still unacknowledged (`rv`: "could not be uploaded now"); nothing more is tried.
//!
//! [ADR 0026]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0026-client-device-state-and-cache.md
//! [ADR 0095]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0095-owner-answers-0023-0028-recorded.md

use rizzy_client::rizzy_core::ids::VaultId;
use rizzy_client::rizzy_proto::http::paths;
use rizzy_client::rizzy_proto::vault::{FetchResponse, UploadResponse};
use rizzy_client::store::rows::Alarm;
use rizzy_client::sync::VaultSync;

use crate::error::{CoreError, CoreResult, WRONG_STATE};
use crate::http::{self, HttpRequest};
use crate::sync::Ctx;
use crate::vaults::VaultSet;

/// Where the upload is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Not running.
    Idle,
    /// The vault's Fetch is outstanding.
    Fetch,
    /// An upload is outstanding; the vault's unacknowledged counts before it.
    Upload((usize, usize)),
}

/// The removal upload's step driver (module docs).
#[derive(Debug)]
pub(crate) struct UnsentUpload {
    /// Where it is.
    phase: Phase,
    /// The outstanding request.
    pending: Option<HttpRequest>,
    /// The vaults still to upload, last first.
    queue: Vec<VaultId>,
    /// The vault of the outstanding request.
    current: Option<VaultId>,
}

impl Default for UnsentUpload {
    fn default() -> Self {
        Self {
            phase: Phase::Idle,
            pending: None,
            queue: Vec::new(),
            current: None,
        }
    }
}

impl UnsentUpload {
    /// Whether it is running.
    pub(crate) fn running(&self) -> bool {
        self.phase != Phase::Idle
    }

    /// The outstanding request.
    pub(crate) fn request(&self) -> Option<HttpRequest> {
        self.pending.as_ref().map(HttpRequest::duplicate)
    }

    /// Starts it over every open vault ([`VaultSet::sync_order`], as `rv`'s `open_ids`).
    ///
    /// # Errors
    /// `wrong_state` while it runs; as the first Fetch request.
    pub(crate) fn start(&mut self, ctx: &mut Ctx<'_>) -> CoreResult<()> {
        if self.running() {
            return Err(CoreError::new(WRONG_STATE));
        }
        let mut queue = ctx.vaults.sync_order();
        queue.reverse();
        self.queue = queue;
        let started = self.next_vault(ctx);
        self.end_on_error(started)
    }

    /// Passes in the answer to the outstanding request.
    ///
    /// # Errors
    /// `wrong_state` when nothing is outstanding; the answer's refusal; the flows'. Any error
    /// ends the upload.
    pub(crate) fn respond(
        &mut self,
        mut ctx: Ctx<'_>,
        status: u16,
        body: &[u8],
        now_ms: u64,
    ) -> CoreResult<()> {
        let stepped = self.step(&mut ctx, status, body, now_ms);
        self.end_on_error(stepped)
    }

    /// Ends it without an answer. Rows already handed out stay marked sent (§4 step 1: a crash
    /// between the mark and the send counts as sent), so nothing is lost by dropping it.
    pub(crate) fn abort(&mut self) {
        *self = Self::default();
    }

    /// Ends the upload when `result` is an error.
    fn end_on_error(&mut self, result: CoreResult<()>) -> CoreResult<()> {
        if result.is_err() {
            self.abort();
        }
        result
    }

    /// One answer.
    fn step(&mut self, ctx: &mut Ctx<'_>, status: u16, body: &[u8], now_ms: u64) -> CoreResult<()> {
        match self.phase {
            Phase::Idle => Err(CoreError::new(WRONG_STATE)),
            Phase::Fetch => {
                let response: FetchResponse = http::json(status, body)?;
                let vault = self.vault(ctx.vaults)?;
                let outcome = vault.apply_fetch(&*ctx.authors, &response, now_ms)?;
                if outcome.own_history_ahead {
                    vault.set_read_only(true);
                    ctx.raise(Alarm::DeviceStateOutdated, &[])?;
                }
                self.upload_next(ctx)
            }
            Phase::Upload(before) => {
                let response: UploadResponse = http::json(status, body)?;
                let vault = self.vault(ctx.vaults)?;
                let outcome = vault.apply_upload_response(&response)?;
                let after = vault.unacknowledged();
                if outcome.own_conflict {
                    vault.set_read_only(true);
                    ctx.raise(Alarm::DeviceStateOutdated, &[])?;
                }
                if after == before {
                    // The server takes no more of them (a conflict, a stale epoch): this vault
                    // is done, as in `rv`.
                    return self.next_vault(ctx);
                }
                self.upload_next(ctx)
            }
        }
    }

    /// The current vault's driver.
    fn vault<'v>(&self, vaults: &'v mut VaultSet) -> CoreResult<&'v mut VaultSync> {
        vaults.get_mut(self.current.ok_or(CoreError::new(WRONG_STATE))?)
    }

    /// The next vault's Fetch, or the end after the last vault.
    fn next_vault(&mut self, ctx: &mut Ctx<'_>) -> CoreResult<()> {
        let Some(vault_id) = self.queue.pop() else {
            *self = Self::default();
            return Ok(());
        };
        self.current = Some(vault_id);
        let request = self.vault(ctx.vaults)?.fetch_request()?;
        self.pending = Some(
            ctx.signer
                .build(paths::VAULT_FETCH, &request, ctx.unlocked)?,
        );
        self.phase = Phase::Fetch;
        Ok(())
    }

    /// The current vault's next upload of unsent rows, or the next vault when none is left.
    fn upload_next(&mut self, ctx: &mut Ctx<'_>) -> CoreResult<()> {
        let vault = self.vault(ctx.vaults)?;
        let Some(request) = vault.unsent_upload_request()? else {
            return self.next_vault(ctx);
        };
        let before = vault.unacknowledged();
        self.pending = Some(
            ctx.signer
                .build(paths::VAULT_UPLOAD, &request, ctx.unlocked)?,
        );
        self.phase = Phase::Upload(before);
        Ok(())
    }
}
