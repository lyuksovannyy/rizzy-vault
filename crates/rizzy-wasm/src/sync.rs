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
//! - **One healing round per sync**, as `rv` does; a second need is `cannot_heal`.

use rizzy_client::ClientError;
use rizzy_client::account::VerifiedAccount;
use rizzy_client::device::UnlockedDevice;
use rizzy_client::login::{verify_web_refresh, web_account_query};
use rizzy_client::rizzy_proto::account::AccountView;
use rizzy_client::rizzy_proto::error::ErrorCode;
use rizzy_client::rizzy_proto::http::paths;
use rizzy_client::rizzy_proto::vault::{FetchResponse, HealingResponse, UploadResponse};
use rizzy_client::rizzy_proto::wire::SessionToken;
use rizzy_client::sync::{Authors, VaultSync};

use crate::error::{CoreError, CoreResult, VAULT_KEY_ROTATED, WRONG_STATE};
use crate::http::{self, HttpRequest};
use crate::rng::Rng;

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
    /// The vault.
    pub(crate) vault: &'a mut VaultSync,
    /// The verified account of the last login or refresh.
    pub(crate) account: &'a mut VerifiedAccount,
    /// The account's authors.
    pub(crate) authors: &'a mut Authors,
    /// The ephemeral device's keys.
    pub(crate) unlocked: &'a UnlockedDevice,
    /// The bearer session.
    pub(crate) token: &'a SessionToken,
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
    /// Whether this sync already sent a healing request.
    healed: bool,
}

impl Default for SyncDriver {
    fn default() -> Self {
        Self {
            phase: Phase::Idle,
            pending: None,
            healed: false,
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
    pub(crate) fn start(&mut self, ctx: &Ctx<'_>) -> CoreResult<()> {
        if self.running() {
            return Err(CoreError::new(WRONG_STATE));
        }
        self.healed = false;
        let query = web_account_query(ctx.account);
        self.pending = Some(HttpRequest::post(
            paths::ACCOUNT_STATE,
            &query,
            Some(ctx.token),
        )?);
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
        }
        result
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
    pub(crate) fn abort(&mut self, vault: &mut VaultSync) {
        if self.phase == Phase::Heal {
            vault.healing_refused();
        }
        self.phase = Phase::Idle;
        self.pending = None;
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
                adopt_account(ctx, &view)?;
                self.fetch(ctx, AfterFetch::HealOrUpload)
            }
            Phase::Fetch(then) => {
                let response: FetchResponse = http::json(status, body)?;
                let outcome = ctx.vault.apply_fetch(&*ctx.authors, &response, now_ms)?;
                if outcome.own_history_ahead {
                    ctx.vault.set_read_only(true);
                    return Err(ClientError::DeviceStateOutdated.into());
                }
                if !response.complete {
                    return self.fetch(ctx, then);
                }
                match then {
                    AfterFetch::HealOrUpload => self.heal_or_upload(ctx),
                    AfterFetch::CheckHealed => {
                        if ctx.vault.needs_healing() {
                            return Err(ClientError::CannotHeal.into());
                        }
                        self.upload_next(ctx)
                    }
                    AfterFetch::Done => {
                        self.phase = Phase::Idle;
                        Ok(())
                    }
                }
            }
            Phase::Heal => {
                let response: HealingResponse = match http::json(status, body) {
                    Ok(response) => response,
                    Err(e) => {
                        ctx.vault.healing_refused();
                        return Err(e);
                    }
                };
                ctx.vault.apply_healing_response(&response)?;
                self.fetch(ctx, AfterFetch::CheckHealed)
            }
            Phase::Upload => {
                let response: UploadResponse = http::json(status, body)?;
                let outcome = ctx.vault.apply_upload_response(&response)?;
                if outcome.own_conflict {
                    ctx.vault.set_read_only(true);
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
    fn fetch(&mut self, ctx: &Ctx<'_>, then: AfterFetch) -> CoreResult<()> {
        let request = ctx.vault.fetch_request()?;
        self.pending = Some(HttpRequest::post(
            paths::VAULT_FETCH,
            &request,
            Some(ctx.token),
        )?);
        self.phase = Phase::Fetch(then);
        Ok(())
    }

    /// After a complete Fetch: a healing request when the server is behind and this sync has
    /// not healed yet, else the uploads.
    fn heal_or_upload(&mut self, ctx: &mut Ctx<'_>) -> CoreResult<()> {
        if !ctx.vault.needs_healing() {
            return self.upload_next(ctx);
        }
        if self.healed {
            return Err(ClientError::CannotHeal.into());
        }
        match ctx.vault.healing_request()? {
            Some(request) => {
                self.healed = true;
                self.pending = Some(HttpRequest::post(
                    paths::VAULT_HEAL,
                    &request,
                    Some(ctx.token),
                )?);
                self.phase = Phase::Heal;
                Ok(())
            }
            None => self.upload_next(ctx),
        }
    }

    /// The next upload, or the final Fetch when nothing is queued.
    fn upload_next(&mut self, ctx: &mut Ctx<'_>) -> CoreResult<()> {
        match ctx.vault.upload_request(ctx.rng, ctx.unlocked) {
            Ok(Some(request)) => {
                self.pending = Some(HttpRequest::post(
                    paths::VAULT_UPLOAD,
                    &request,
                    Some(ctx.token),
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

/// Verifies a refreshed account answer and adopts it: the authors, and the vault key at a new
/// epoch (module docs, "The account first"). A rollback or fork makes the vault read-only.
fn adopt_account(ctx: &mut Ctx<'_>, view: &AccountView) -> CoreResult<()> {
    let mut fresh = match verify_web_refresh(ctx.account, ctx.unlocked, view) {
        Ok(fresh) => fresh,
        Err(e @ (ClientError::Rollback | ClientError::Fork)) => {
            ctx.vault.set_read_only(true);
            return Err(e.into());
        }
        Err(e) => return Err(e.into()),
    };
    let authors = Authors::from_account(&fresh)?;
    let key = fresh
        .take_vault_key(ctx.vault.vault_id())
        .ok_or(ClientError::InvalidServerResponse)?;
    // ADR 0025 §4: a second key at a seen epoch is a fork (the vault is now read-only), a key
    // below the held epoch a rollback; either way nothing of the answer is adopted.
    match ctx.vault.adopt_vault_key(key) {
        Ok(()) => {}
        Err(e @ ClientError::Rollback) => {
            ctx.vault.set_read_only(true);
            return Err(e.into());
        }
        Err(e) => return Err(e.into()),
    }
    *ctx.authors = authors;
    *ctx.account = fresh;
    Ok(())
}
