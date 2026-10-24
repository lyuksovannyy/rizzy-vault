// SPDX-License-Identifier: AGPL-3.0-only

//! The sync step driver of a web-vault session: the steps `rv sync` takes (ADR 0012 §7; ADR
//! 0021 §9; `rizzy-cli`'s `Device::sync`), one request at a time, for JavaScript to carry.
//!
//! ```text
//! start ──► account/state (the account, verified against the session's pin) ──► Fetch (pages until complete)
//!   ├─ server behind (restore from a backup) ──► vault/heal ──► Fetch ──► still behind: cannot_heal
//!   └─► Upload (own ops, then own snapshots, one request each) ──► Fetch (until complete) ──► idle
//! ```
//!
//! The host loops on [`crate::Session::sync_request`] and [`crate::Session::sync_respond`]
//! until the request is `undefined`. Every step is `rizzy-client`'s [`VaultSync`]: what is
//! verified, applied, re-issued or healed is decided there. When the host cannot carry a
//! request (the connection failed, the answer was too large or broke off), it ends the sync
//! with [`crate::Session::sync_abort`]: the outcome is unknown, the unsent own ops stay queued,
//! and the next sync sends them again (`SyncDriver::abort`).
//!
//! # Differences from `rv`, all on the conservative side
//!
//! - **Nothing is persisted** (CRYPTO.md §11.4): there is no journal and no write order to
//!   keep. An own op lives in memory until the server acknowledges it; a lock or a closed tab
//!   before that loses it, and [`crate::Session::unsent_changes`] says how many are waiting.
//! - **The account first.** Every sync starts with `account/state`, as `rv`'s `online` does: the
//!   answer is verified against the pin of the session's login
//!   ([`rizzy_client::login::verify_web_refresh`]), and its certificates and revocations become
//!   the authors the Fetch verifies ops under, so the ops of devices and web sessions certified
//!   after this login verify instead of being dropped. A vault key the answer carries at a new
//!   epoch is adopted ([`VaultSync::adopt_vault_key`]). A rollback or fork makes the vault
//!   read-only and ends the sync with `rollback` or `fork`.
//! - **A rotation of the account key or the identity keys** elsewhere ends the sync with
//!   `account_key_rotated` or `identity_change_unconfirmed`: a web session holds no device grant
//!   and no stored pin to confirm against, so the host logs in again, which reads the account at
//!   its new epoch. A `vault_key_rotated` or `stale_epoch` refusal that the refresh did not
//!   resolve ends it with [`crate::error::VAULT_KEY_ROTATED`], with the same answer. The
//!   session's unsent ops are lost then.
//! - **An older copy of this device's history** cannot exist for an ephemeral device; if the
//!   server shows one anyway (`own_history_ahead`, `own_conflict`), the vault becomes read-only
//!   and the sync ends with `device_state_outdated`, as in `rv`.
//! - **One healing round per vault and sync**, as `rv` does; a second need is `cannot_heal`.
//! - **Every vault, one after the other** ([ADR 0081] §A7): after the account answer the vault
//!   set follows the catalog (`crate::vaults`: new vaults get a driver, dropped ones are
//!   removed), then each open vault runs Fetch → heal → Upload → Fetch in turn, the Personal
//!   vault first. A `client_too_old` refusal of one vault's request marks only that vault as
//!   needing an update (§A12) and the next vault follows; any other error ends the sync.
//!
//! [ADR 0081]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0081-multiple-vaults-personal-and-shared.md

use rizzy_client::ClientError;
use rizzy_client::account::VerifiedAccount;
use rizzy_client::device::UnlockedDevice;
use rizzy_client::login::{verify_web_refresh, web_account_query};
use rizzy_client::rizzy_core::ids::VaultId;
use rizzy_client::rizzy_proto::account::AccountView;
use rizzy_client::rizzy_proto::error::ErrorCode;
use rizzy_client::rizzy_proto::http::paths;
use rizzy_client::rizzy_proto::vault::{FetchResponse, HealingResponse, UploadResponse};
use rizzy_client::rizzy_proto::wire::SessionToken;
use rizzy_client::session::DeviceSession as ClientDeviceSession;
use rizzy_client::sync::{Authors, VaultSync};
use serde::Serialize;

use crate::error::{CoreError, CoreResult, VAULT_KEY_ROTATED, WRONG_STATE};
use crate::http::{self, HttpRequest};
use crate::rng::Rng;
use crate::vaults::VaultSet;

/// How a step signs the request it builds (module docs; `crate::device`'s module docs, "Sync
/// and items"): a bearer-only OPAQUE session (the web vault) or a device-authenticated one,
/// which additionally signs every request with the device key (CRYPTO.md §5.10; ADR 0028 item
/// 5). The same [`VaultSync`]/[`Authors`] steps run either way; only how the outgoing
/// [`HttpRequest`] is authorised differs, so this lives beside [`Ctx`] rather than in
/// `rizzy-client`, which decides none of it (`rizzy_proto::http`'s header constants do).
pub(crate) enum Signer<'a> {
    /// The web vault's OPAQUE session.
    Bearer(&'a SessionToken),
    /// A durable device's authenticated session.
    Device(&'a mut ClientDeviceSession),
}

impl Signer<'_> {
    /// Builds and, for [`Signer::Device`], signs one `POST` to `path`.
    ///
    /// # Errors
    /// `internal` if `body` does not serialise; as
    /// [`rizzy_client::session::DeviceSession::sign_request`].
    fn build<T: Serialize>(
        &mut self,
        path: &'static str,
        body: &T,
        unlocked: &UnlockedDevice,
    ) -> CoreResult<HttpRequest> {
        match self {
            Self::Bearer(token) => HttpRequest::post(path, body, Some(token)),
            Self::Device(session) => HttpRequest::post_signed(path, body, session, unlocked),
        }
    }
}

/// What follows a complete Fetch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AfterFetch {
    /// Heal if the server is behind, else upload.
    HealOrUpload,
    /// After a healing request: the server must no longer be behind; then upload.
    CheckHealed,
    /// The final Fetch: the sync is done.
    Done,
}

/// Where the driver is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// No sync running.
    Idle,
    /// The account refresh is outstanding.
    Account,
    /// A Fetch page is outstanding.
    Fetch(AfterFetch),
    /// A healing request is outstanding.
    Heal,
    /// An upload is outstanding.
    Upload,
}

/// What a step works on: the session's parts, borrowed.
pub(crate) struct Ctx<'a> {
    /// The vaults (ADR 0081 §A7: a sync round fetches every vault in the directory).
    pub(crate) vaults: &'a mut VaultSet,
    /// The verified account of the last login or refresh.
    pub(crate) account: &'a mut VerifiedAccount,
    /// The account's authors.
    pub(crate) authors: &'a mut Authors,
    /// This device's keys.
    pub(crate) unlocked: &'a UnlockedDevice,
    /// How a request is authorised (module docs).
    pub(crate) signer: Signer<'a>,
    /// The RNG.
    pub(crate) rng: &'a mut Rng,
}

/// The sync step driver (module docs).
#[derive(Debug)]
pub(crate) struct SyncDriver {
    /// Where it is.
    phase: Phase,
    /// The outstanding request.
    pending: Option<HttpRequest>,
    /// Whether this sync already sent a healing request for the current vault.
    healed: bool,
    /// The vaults still to sync, in order (ADR 0081 §A7).
    queue: Vec<VaultId>,
    /// The vault being synced.
    current: Option<VaultId>,
    /// The vaults the last account answer dropped (deleted elsewhere, ADR 0081 §A5), for a
    /// host with a cache to delete their rows.
    dropped: Vec<VaultId>,
}

impl Default for SyncDriver {
    fn default() -> Self {
        Self {
            phase: Phase::Idle,
            pending: None,
            healed: false,
            queue: Vec::new(),
            current: None,
            dropped: Vec::new(),
        }
    }
}

impl SyncDriver {
    /// Whether a sync is running.
    pub(crate) fn running(&self) -> bool {
        self.phase != Phase::Idle
    }

    /// Starts a sync with the account refresh.
    ///
    /// # Errors
    /// `wrong_state` while a sync is running.
    pub(crate) fn start(&mut self, ctx: &mut Ctx<'_>) -> CoreResult<()> {
        if self.running() {
            return Err(CoreError::new(WRONG_STATE));
        }
        self.healed = false;
        self.queue.clear();
        self.current = None;
        let query = web_account_query(ctx.account);
        self.pending = Some(
            ctx.signer
                .build(paths::ACCOUNT_STATE, &query, ctx.unlocked)?,
        );
        self.phase = Phase::Account;
        Ok(())
    }

    /// The outstanding request, or `None` when the sync is done or not running.
    pub(crate) fn request(&self) -> Option<HttpRequest> {
        self.pending.as_ref().map(HttpRequest::duplicate)
    }

    /// Passes in the answer to the outstanding request. Any error ends the sync; a host that
    /// has no answer ends it with [`SyncDriver::abort`].
    ///
    /// # Errors
    /// `wrong_state` with no request outstanding; the vault's errors (`invalid_server_response`,
    /// `device_state_outdated`, `cannot_heal`, …); `vault_key_rotated`; the server's code.
    pub(crate) fn respond(
        &mut self,
        mut ctx: Ctx<'_>,
        status: u16,
        body: &[u8],
        now_ms: u64,
    ) -> CoreResult<()> {
        if self.pending.is_none() {
            return Err(CoreError::new(WRONG_STATE));
        }
        let phase = self.phase;
        self.pending = None;
        let result = self.step(&mut ctx, phase, status, body, now_ms);
        if result.is_err() {
            self.phase = Phase::Idle;
            self.pending = None;
            self.queue.clear();
            self.current = None;
        }
        result
    }

    /// The vaults the account answers of this sync dropped, since the last call.
    pub(crate) fn take_dropped(&mut self) -> Vec<VaultId> {
        core::mem::take(&mut self.dropped)
    }

    /// The driver of the vault being synced.
    fn vault<'v>(&self, vaults: &'v mut VaultSet) -> CoreResult<&'v mut VaultSync> {
        vaults.get_mut(self.current.ok_or(CoreError::new(WRONG_STATE))?)
    }

    /// The next vault's Fetch, or the end of the sync after the last vault.
    fn next_vault(&mut self, ctx: &mut Ctx<'_>) -> CoreResult<()> {
        loop {
            if self.queue.is_empty() {
                self.current = None;
                self.phase = Phase::Idle;
                return Ok(());
            }
            let vault_id = self.queue.remove(0);
            if ctx.vaults.get(vault_id).is_err() {
                continue;
            }
            self.current = Some(vault_id);
            self.healed = false;
            return self.fetch(ctx, AfterFetch::HealOrUpload);
        }
    }

    /// ADR 0081 §A12: a `client_too_old` refusal of one vault's request marks only that vault
    /// "needs an update" and the sync goes on with the next vault.
    fn too_old(&mut self, ctx: &mut Ctx<'_>, status: u16, body: &[u8]) -> Option<CoreResult<()>> {
        if http::server_code(status, body) != Some(ErrorCode::ClientTooOld) {
            return None;
        }
        let vault_id = self.current?;
        ctx.vaults.mark_too_new(vault_id);
        Some(self.next_vault(ctx))
    }

    /// Ends the running sync without an answer: the host could not carry the outstanding
    /// request (the connection failed, the answer was too large or broke off mid-read). A no-op
    /// when no sync runs.
    ///
    /// The outcome of the request is unknown, and nothing is lost by dropping it (ADR 0028,
    /// "Retry after an unknown outcome"):
    /// - an account refresh or a Fetch page changed nothing on the server;
    /// - an upload: the sent own ops stay unacknowledged in the vault, so the next sync's upload
    ///   sends them again verbatim, and the server answers "already stored" for any it stored
    ///   (`rizzy-client`'s `upload_request` rebuilds the in-flight list from the
    ///   unacknowledged chain);
    /// - a healing request is dropped as refused ([`VaultSync::healing_refused`]): no row
    ///   changes, the vault stays read-only, and the next sync's Fetch shows whether the server
    ///   stored it; an own op it carried is then acknowledged through the upload path ("already
    ///   stored"), as `rizzy-client`'s healing docs describe for a lost healing answer.
    pub(crate) fn abort(&mut self, vaults: &mut VaultSet) {
        if self.phase == Phase::Heal
            && let Ok(vault) = self.vault(vaults)
        {
            vault.healing_refused();
        }
        self.phase = Phase::Idle;
        self.pending = None;
        self.queue.clear();
        self.current = None;
    }

    /// One answer in `phase`.
    fn step(
        &mut self,
        ctx: &mut Ctx<'_>,
        phase: Phase,
        status: u16,
        body: &[u8],
        now_ms: u64,
    ) -> CoreResult<()> {
        match phase {
            Phase::Idle => Err(CoreError::new(WRONG_STATE)),
            Phase::Account => {
                let view: AccountView = http::json(status, body)?;
                let dropped = adopt_account(ctx, &view)?;
                self.dropped.extend(dropped);
                self.queue = ctx.vaults.sync_order();
                self.next_vault(ctx)
            }
            Phase::Fetch(then) => {
                if let Some(next) = self.too_old(ctx, status, body) {
                    return next;
                }
                let response: FetchResponse = http::json(status, body)?;
                let vault = self.vault(ctx.vaults)?;
                let outcome = vault.apply_fetch(&*ctx.authors, &response, now_ms)?;
                if outcome.own_history_ahead {
                    vault.set_read_only(true);
                    return Err(ClientError::DeviceStateOutdated.into());
                }
                if !response.complete {
                    return self.fetch(ctx, then);
                }
                match then {
                    AfterFetch::HealOrUpload => self.heal_or_upload(ctx),
                    AfterFetch::CheckHealed => {
                        if self.vault(ctx.vaults)?.needs_healing() {
                            return Err(ClientError::CannotHeal.into());
                        }
                        self.upload_next(ctx)
                    }
                    AfterFetch::Done => self.next_vault(ctx),
                }
            }
            Phase::Heal => {
                let response: HealingResponse = match http::json(status, body) {
                    Ok(response) => response,
                    Err(e) => {
                        self.vault(ctx.vaults)?.healing_refused();
                        if let Some(next) = self.too_old(ctx, status, body) {
                            return next;
                        }
                        return Err(e);
                    }
                };
                self.vault(ctx.vaults)?.apply_healing_response(&response)?;
                self.fetch(ctx, AfterFetch::CheckHealed)
            }
            Phase::Upload => {
                if let Some(next) = self.too_old(ctx, status, body) {
                    return next;
                }
                let response: UploadResponse = http::json(status, body)?;
                let vault = self.vault(ctx.vaults)?;
                let outcome = vault.apply_upload_response(&response)?;
                if outcome.own_conflict {
                    vault.set_read_only(true);
                    return Err(ClientError::DeviceStateOutdated.into());
                }
                if outcome.rejected.contains(&ErrorCode::StaleEpoch) {
                    return Err(CoreError::new(VAULT_KEY_ROTATED));
                }
                if let Some(code) = outcome.rejected.first() {
                    return Err(CoreError::server(*code));
                }
                self.upload_next(ctx)
            }
        }
    }

    /// Sends a Fetch page; `then` follows the complete Fetch.
    fn fetch(&mut self, ctx: &mut Ctx<'_>, then: AfterFetch) -> CoreResult<()> {
        let request = self.vault(ctx.vaults)?.fetch_request()?;
        self.pending = Some(
            ctx.signer
                .build(paths::VAULT_FETCH, &request, ctx.unlocked)?,
        );
        self.phase = Phase::Fetch(then);
        Ok(())
    }

    /// After a complete Fetch: a healing request when the server is behind and this sync has
    /// not healed yet, else the uploads.
    fn heal_or_upload(&mut self, ctx: &mut Ctx<'_>) -> CoreResult<()> {
        if !self.vault(ctx.vaults)?.needs_healing() {
            return self.upload_next(ctx);
        }
        if self.healed {
            return Err(ClientError::CannotHeal.into());
        }
        match self.vault(ctx.vaults)?.healing_request()? {
            Some(request) => {
                self.healed = true;
                self.pending = Some(
                    ctx.signer
                        .build(paths::VAULT_HEAL, &request, ctx.unlocked)?,
                );
                self.phase = Phase::Heal;
                Ok(())
            }
            None => self.upload_next(ctx),
        }
    }

    /// The next upload, or the final Fetch when nothing is queued.
    fn upload_next(&mut self, ctx: &mut Ctx<'_>) -> CoreResult<()> {
        let vault = self.vault(ctx.vaults)?;
        match vault.upload_request(ctx.rng, ctx.unlocked) {
            Ok(Some(request)) => {
                self.pending = Some(ctx.signer.build(
                    paths::VAULT_UPLOAD,
                    &request,
                    ctx.unlocked,
                )?);
                self.phase = Phase::Upload;
                Ok(())
            }
            Ok(None) => self.fetch(ctx, AfterFetch::Done),
            Err(ClientError::VaultKeyRotated) => Err(CoreError::new(VAULT_KEY_ROTATED)),
            // ADR 0021 §9 "Stale epoch": re-publish through a healing request, once.
            Err(ClientError::HealingRequired) if !self.healed => {
                self.fetch(ctx, AfterFetch::HealOrUpload)
            }
            Err(e) => Err(e.into()),
        }
    }
}

/// Verifies a refreshed account answer and adopts it: the authors, and the vault set brought in
/// step with the account's catalog (module docs, "The account first"; `crate::vaults`): each
/// held vault's key at a new epoch, new vaults, dropped vaults (returned). A rollback or fork
/// makes the vaults read-only.
fn adopt_account(ctx: &mut Ctx<'_>, view: &AccountView) -> CoreResult<Vec<VaultId>> {
    let mut fresh = match verify_web_refresh(ctx.account, ctx.unlocked, view) {
        Ok(fresh) => fresh,
        Err(e @ (ClientError::Rollback | ClientError::Fork)) => {
            for vault in ctx.vaults.all_mut() {
                vault.set_read_only(true);
            }
            return Err(e.into());
        }
        Err(e) => return Err(e.into()),
    };
    let authors = Authors::from_account(&fresh)?;
    let dropped = ctx.vaults.reconcile(&mut fresh, ctx.unlocked)?;
    *ctx.authors = authors;
    *ctx.account = fresh;
    Ok(dropped)
}
