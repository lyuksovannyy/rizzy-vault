//! The browser extension's durable device (ADR 0036 §1: device kind 2; CRYPTO.md §11.2 new
//! device, §11.3 unlock, §5.10 device authentication).
//!
//! # The split (written before this module's code, as CLAUDE.md's Implementation Flow and the
//! task that opened this module require)
//!
//! Every decision below is already [`rizzy_client`]'s, unchanged, because checking `rv`'s own
//! `crates/rizzy-cli/src/{enrol.rs,device.rs}` against `rizzy_client::login`/`device`/`session`
//! found no business logic left in `rv` to move: `rv`'s `enrol.rs::login` is already ~70 lines
//! of HTTP-and-`sqlx` glue over [`rizzy_client::login::start_login`]/[`rizzy_client::login::LoggedIn::enrol`]
//! and [`rizzy_client::store::create_writes`]/[`account_writes`](rizzy_client::store::account_writes);
//! `rv`'s `Device::enrolled` starts with `session: None` — a durable device is *not*
//! device-authenticated right after enrolment either, in `rv` or here. [ADR 0016] R1
//! ("host-agnostic logic … moves down into `rizzy-client`") is therefore already satisfied;
//! this module is the wasm-bindgen glue `rv`'s `enrol.rs`/`device.rs` are for a native host,
//! following [`crate::login::LoginFlow`]'s established request/response shape (this crate's
//! own module docs, "The shape of every flow") rather than inventing another one.
//!
//! ```text
//! EnrolFlow.start ──login/start──► respond ──login/finish──► respond
//!   ├─ needs_totp ──► state "needs_totp" ──provideTotp──► (again from login/start)
//!   └─ verified ──devices/enrol──► respond ──► state "done" ──finish()──► EnrolResult
//!        (device_kind fixed to Extension = 2, ADR 0036 §1; not taken from the host)
//!
//! DeviceSession.unlock(cacheDump, password, now) ───────────────────────► DeviceSession
//!   (offline: §11.3 step 1, then the local verify/load of ADR 0026 §4 step 5; no network)
//!   .authStart() ──device-auth/start──► authRespond ──device-auth/finish──► authRespond
//!   ── state "done" ──► isAuthenticated() == true, requests may be signed
//! ```
//!
//! # What is deferred (reported; see the task's `not_done`, not silently dropped)
//!
//! - **Sync and items.** [`DeviceSession`] holds the unlocked keys and, once authenticated, a
//!   signing session, but exposes no `sync_*`/items calls yet. `rizzy-wasm`'s existing
//!   [`crate::session::Session`] (the web vault's ephemeral device) already calls
//!   `rizzy_client::sync`/`items` the right way; the follow-up is threading a persisted
//!   [`rizzy_client::sync::VaultSync`] (`persist()`-ed, ADR 0026 §4) and this module's
//!   [`crate::store`] codec through the *same* calls, not new ones — `Session`'s methods
//!   already are thin wasm glue over `rizzy_client`, so there is no business logic to port
//!   there either, only the plumbing of a cache-backed `VaultSync` instead of an in-memory-only
//!   one. Confirmed while writing `crates/rizzy-client/src/tests/durable_device.rs`:
//!   [`rizzy_client::store::load::Loaded::vaults`] already hands back ready-to-use
//!   [`rizzy_client::sync::VaultSync`] values built from the cache's `vaults`/`wraps` rows, so
//!   a reopened `DeviceSession` must take its vaults from there, never rebuild one with
//!   `take_vault_key`/`VaultSync::new` itself (that path is only for a *brand-new* vault grant,
//!   which `object_writes`/`load::load` already handle the same way for every device kind).
//! - **ADR 0031/0032 resend and reconciliation.** `EnrolFlow` does not retry a
//!   `state_conflict` the way `rv` does (restart the whole flow, §11.2's "lost
//!   compare-and-swap" reading); a host restarts `EnrolFlow::start` itself for now.
//!   `device_auth_start_reconciling`/`device_auth_finish_reconciling` (ADR 0012 §7, a device
//!   enrolled after a restore) are not wired into [`DeviceSession`]'s auth flow.
//! - **Same-password re-registration** (ADR 0031 point 2, `logged_in.reregister()` /
//!   `device_auth`'s `reregister` flag) is read by neither flow yet; `rizzy-wasm`'s
//!   `LoginFlow` already has the pattern to copy.
//!
//! [ADR 0016]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0016-workspace-layout.md

use core::fmt;

use rizzy_client::ClientError;
use rizzy_client::account::VerifiedAccount;
use rizzy_client::device::{DeviceState, UnlockedDevice};
use rizzy_client::items::{FieldEdit, ItemId};
use rizzy_client::login::{
    Enrolled, LoggedIn, LoginAwaitingSession, LoginInput, LoginStarted, start_login,
};
use rizzy_client::passkey::get_assertion;
use rizzy_client::rizzy_core::item::key::ElementId;
use rizzy_client::rizzy_core::item::schema::{ATTR_CREDENTIAL_ID, ATTR_PRIVATE_KEY, LIST_PASSKEY};
use rizzy_client::rizzy_core::item::value::ValueRef;
use rizzy_client::rizzy_core::passkey::Es256SigningKey;
use rizzy_client::rizzy_core::sign::DeviceKind;
use rizzy_client::rizzy_proto::auth::{
    DeviceAuthFinishResponse, DeviceAuthStartResponse, LoginFinishResponse, LoginStartResponse,
};
use rizzy_client::rizzy_proto::error::ErrorCode;
use rizzy_client::rizzy_proto::http::paths;
use rizzy_client::rizzy_proto::wire::SessionToken;
use rizzy_client::session::{
    DeviceSession as ClientDeviceSession, device_auth_finish, device_auth_start,
};
use rizzy_client::store::floors::Floors;
use rizzy_client::store::rows::CacheRows;
use rizzy_client::store::{self, record::Stage as RecordStage};
use rizzy_client::sync::{Authors, VaultSync};
use wasm_bindgen::prelude::wasm_bindgen;
use zeroize::Zeroizing;

use crate::error::{CoreError, CoreResult, WRONG_STATE};
use crate::http::{self, HttpRequest};
use crate::items::{self, FieldView, ItemDraft, ItemSummary, hex, type_from_name, visible_item};
use crate::passkey::PasskeyAssertion;
use crate::rng::{Rng, os_rng};
use crate::secret::take_secret;
use crate::store::{CacheDelta, KvRow, decode_rows, encode_rows};
use crate::sync::{Ctx, Signer, SyncDriver};

/// A copy of a bearer token (as `rv`'s `copy_token` does): the only way to keep using one after
/// the value that owns it (here, [`LoggedIn`]) is consumed by the next step.
fn copy_token(token: &SessionToken) -> SessionToken {
    SessionToken::new(Zeroizing::new(*token.expose_secret()))
}

/// What the user typed, kept until the flow ends. Wiped on drop; `Debug` redacted.
struct Credentials {
    /// The server origin, as dialled.
    origin: String,
    /// The login name.
    login_name: String,
    /// The Secret Key.
    secret_key: Zeroizing<String>,
    /// The master password.
    password: Zeroizing<String>,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Credentials([REDACTED])")
    }
}

/// Where an [`EnrolFlow`] is.
enum FlowStage {
    /// `login/start` is outstanding.
    Start(Box<LoginStarted>),
    /// `login/finish` is outstanding.
    Finish(LoginAwaitingSession),
    /// `devices/enrol` is outstanding.
    Enrol(Box<rizzy_client::login::PendingEnrolment>),
    /// The account has 2FA and the login carried no code.
    NeedsTotp,
    /// Enrolled; the result is ready for [`EnrolFlow::finish`].
    Done(Box<Enrolled>),
    /// Failed, or the result was taken.
    Spent,
}

/// Enrols this device as a durable device, `device_kind` 2 (ADR 0036 §1, module docs).
#[wasm_bindgen]
pub struct EnrolFlow {
    /// The typed input.
    input: Credentials,
    /// The second factor, if given.
    totp: Option<Zeroizing<String>>,
    /// Where the flow is.
    stage: FlowStage,
    /// The outstanding request.
    pending: Option<HttpRequest>,
    /// How often the flow went through `login/start`.
    starts: u8,
    /// The RNG.
    rng: Rng,
}

impl fmt::Debug for EnrolFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnrolFlow")
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

/// How often an enrolment restarts for a second factor before it gives up (as
/// [`crate::login::LoginFlow`]'s `MAX_STARTS`).
const MAX_STARTS: u8 = 3;

#[wasm_bindgen]
impl EnrolFlow {
    /// Starts enrolling this device. `server_origin` is the origin the extension talks to;
    /// `secret_key` and `password` are UTF-8 bytes (`TextEncoder`), never strings, and both
    /// arrays hold zeroes when the call returns, whatever its outcome.
    ///
    /// # Errors
    /// `invalid_input` for an origin, login name or Secret Key that does not parse, or a TOTP
    /// code outside its bounds.
    #[wasm_bindgen(js_name = start)]
    pub fn start(
        server_origin: &str,
        login_name: &str,
        secret_key: &mut [u8],
        password: &mut [u8],
        totp: Option<String>,
    ) -> Result<EnrolFlow, CoreError> {
        let secret_key = take_secret(secret_key);
        let password = take_secret(password);
        let mut flow = Self {
            input: Credentials {
                origin: server_origin.to_owned(),
                login_name: login_name.to_owned(),
                secret_key: secret_key?,
                password: password?,
            },
            totp: totp.map(Zeroizing::new),
            stage: FlowStage::Spent,
            pending: None,
            starts: 0,
            rng: os_rng(),
        };
        flow.restart()?;
        Ok(flow)
    }

    /// `"request"` while a request is outstanding, `"needs_totp"`, `"done"`, or `"failed"`.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn state(&self) -> String {
        match self.stage {
            FlowStage::Start(_) | FlowStage::Finish(_) | FlowStage::Enrol(_) => "request",
            FlowStage::NeedsTotp => "needs_totp",
            FlowStage::Done(_) => "done",
            FlowStage::Spent => "failed",
        }
        .to_owned()
    }

    /// The outstanding request. The same request again on every call until an answer is
    /// passed in.
    ///
    /// # Errors
    /// `wrong_state` when nothing is outstanding.
    pub fn request(&self) -> Result<HttpRequest, CoreError> {
        self.pending
            .as_ref()
            .map(HttpRequest::duplicate)
            .ok_or(CoreError::new(WRONG_STATE))
    }

    /// Passes in the answer to the outstanding request. `now_ms` is the host's clock, used for
    /// the enrolment's certificate timestamp.
    ///
    /// # Errors
    /// `wrong_password_or_secret_key`; `kdf_not_allowed`, `origin_mismatch`,
    /// `invalid_server_response`; the server's code; `wrong_state`. After an error the flow is
    /// `"failed"`, except `wrong_state`.
    pub fn respond(&mut self, status: u16, body: &[u8], now_ms: u64) -> Result<(), CoreError> {
        if self.pending.is_none() {
            return Err(CoreError::new(WRONG_STATE));
        }
        let stage = core::mem::replace(&mut self.stage, FlowStage::Spent);
        self.pending = None;
        match self.step(stage, status, body, now_ms) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.stage = FlowStage::Spent;
                self.pending = None;
                Err(e)
            }
        }
    }

    /// The second factor, after the state became `"needs_totp"`.
    ///
    /// # Errors
    /// `wrong_state`; `invalid_input` for a code outside its bounds.
    #[wasm_bindgen(js_name = provideTotp)]
    pub fn provide_totp(&mut self, code: &str) -> Result<(), CoreError> {
        if !matches!(self.stage, FlowStage::NeedsTotp) {
            return Err(CoreError::new(WRONG_STATE));
        }
        self.totp = Some(Zeroizing::new(code.to_owned()));
        self.restart()
    }

    /// The result of a finished enrolment. Consumes the flow.
    ///
    /// # Errors
    /// `wrong_state` unless the state is `"done"`.
    pub fn finish(self) -> Result<EnrolResult, CoreError> {
        match self.stage {
            FlowStage::Done(enrolled) => EnrolResult::new(*enrolled).map_err(CoreError::from),
            _ => Err(CoreError::new(WRONG_STATE)),
        }
    }
}

impl EnrolFlow {
    /// (Re)starts the OPAQUE login from `login/start`.
    fn restart(&mut self) -> CoreResult<()> {
        if self.starts >= MAX_STARTS {
            self.stage = FlowStage::Spent;
            return Err(CoreError::server(ErrorCode::SecondFactorRequired));
        }
        self.starts += 1;
        let input = LoginInput {
            server_origin: &self.input.origin,
            login_name: &self.input.login_name,
            secret_key: &self.input.secret_key,
            password: &self.input.password,
        };
        let (started, request) = start_login(&mut self.rng, &input).inspect_err(|_| {
            self.stage = FlowStage::Spent;
        })?;
        self.pending = Some(HttpRequest::post(paths::LOGIN_START, &request, None)?);
        self.stage = FlowStage::Start(Box::new(started));
        Ok(())
    }

    /// One answer, at `stage`.
    fn step(&mut self, stage: FlowStage, status: u16, body: &[u8], now_ms: u64) -> CoreResult<()> {
        match stage {
            FlowStage::Start(started) => {
                let answer: LoginStartResponse = http::json(status, body)?;
                let totp = self.totp.as_ref().map(|t| t.as_str());
                let (awaiting, finish) = (*started).finish(&mut self.rng, &answer, totp)?;
                self.pending = Some(HttpRequest::post(paths::LOGIN_FINISH, &finish, None)?);
                self.stage = FlowStage::Finish(awaiting);
                Ok(())
            }
            FlowStage::Finish(awaiting) => {
                match http::server_code(status, body) {
                    Some(ErrorCode::SecondFactorRequired) if self.totp.is_none() => {
                        self.stage = FlowStage::NeedsTotp;
                        return Ok(());
                    }
                    Some(ErrorCode::Unauthorized) => {
                        return Err(ClientError::WrongPasswordOrSecretKey.into());
                    }
                    _ => {}
                }
                let answer: LoginFinishResponse = http::json(status, body)?;
                let logged_in: LoggedIn = awaiting.complete(answer)?;
                let token = copy_token(logged_in.bearer_token());
                let (pending_enrol, request) =
                    logged_in.enrol(&mut self.rng, DeviceKind::Extension, now_ms)?;
                self.pending = Some(HttpRequest::post(
                    paths::DEVICES_ENROL,
                    &request,
                    Some(&token),
                )?);
                self.stage = FlowStage::Enrol(Box::new(pending_enrol));
                Ok(())
            }
            FlowStage::Enrol(pending_enrol) => {
                // `devices/enrol` answers with no body on success (ADR 0028 item 2).
                http::empty(status, body)?;
                self.stage = FlowStage::Done(Box::new(pending_enrol.finalize()));
                Ok(())
            }
            FlowStage::NeedsTotp | FlowStage::Done(_) | FlowStage::Spent => {
                Err(CoreError::new(WRONG_STATE))
            }
        }
    }
}

/// The result of a finished [`EnrolFlow`]: the cache rows to persist before anything else
/// (ADR 0026 §4 step 1, "secrets before commit") and the session to continue with. `.session()`
/// takes the session; call it exactly once.
#[wasm_bindgen]
pub struct EnrolResult {
    /// The device-state record and the first account objects, as cache rows (module docs,
    /// [`crate::store`]). A host persists every one of these, in one transaction, before using
    /// the session.
    cache_rows: Vec<KvRow>,
    /// The session, until [`EnrolResult::session`] takes it.
    session: Option<DeviceSession>,
}

impl fmt::Debug for EnrolResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnrolResult")
            .field("cache_rows", &self.cache_rows.len())
            .field("session_taken", &self.session.is_none())
            .finish()
    }
}

impl EnrolResult {
    /// Builds the result of `enrolled`. Every step here must succeed or nothing is returned:
    /// a partial or empty `cache_rows` that the host went on to treat as success would publish
    /// this device's certificate on the server while persisting nothing of it locally — not a
    /// state a fallback default may paper over (advisor review).
    ///
    /// Also builds this device's driver of the account's first vault, exactly as
    /// [`crate::session::Session::from_web`] does for the ephemeral device (module docs, "Sync
    /// and items"): [`VaultSync::new`] at `next_device_seq` 1, with
    /// [`VaultSync::persist`] turned on so the very first write journals its own cache rows.
    ///
    /// # Errors
    /// [`ClientError::Internal`] if the device-state record, the first changeset, or a vault's
    /// self-grant does not encode; [`ClientError::InvalidServerResponse`] if the account answer
    /// carries no vault key.
    fn new(enrolled: Enrolled) -> Result<Self, ClientError> {
        let record = enrolled.device.record(RecordStage::Committed)?;
        let mut changeset = store::create_writes(&record)?;
        changeset.append(store::account_writes(&enrolled.account));
        // The floors this device's own writes are checked against from now on, admitted to
        // the state right after this first changeset (`crates/rizzy-cli/src/device.rs`'s
        // `commit` does the same before its first write of a brand-new cache).
        let mut floors = Floors::empty();
        floors.admit(&changeset)?;
        let mut rows = CacheRows::default();
        rows.apply(&changeset);
        let cache_rows = encode_rows(&rows)?;

        let mut account = enrolled.account;
        let vault_id = account
            .vault_ids()
            .next()
            .ok_or(ClientError::InvalidServerResponse)?;
        let vault_key = account
            .take_vault_key(vault_id)
            .ok_or(ClientError::InvalidServerResponse)?;
        let authors = Authors::from_account(&account)?;
        let mut vault = VaultSync::new(vault_key, &enrolled.unlocked, 1)?;
        vault.persist();

        Ok(Self {
            cache_rows,
            session: Some(DeviceSession::from_parts(
                enrolled.device,
                enrolled.unlocked,
                account,
                authors,
                vec![vault],
                rows,
                floors,
            )),
        })
    }
}

#[wasm_bindgen]
impl EnrolResult {
    /// The cache rows to persist (a copy; module docs).
    #[wasm_bindgen(getter, js_name = cacheRows)]
    #[must_use]
    pub fn cache_rows(&self) -> Vec<KvRow> {
        self.cache_rows.clone()
    }

    /// Takes the session. `wrong_state` on a second call.
    ///
    /// # Errors
    /// `wrong_state` if already taken.
    pub fn session(&mut self) -> Result<DeviceSession, CoreError> {
        self.session.take().ok_or(CoreError::new(WRONG_STATE))
    }
}

/// Where a [`DeviceSession`]'s device authentication (§5.10) is.
enum AuthStage {
    /// Not yet started.
    Idle,
    /// `device-auth/start` is outstanding.
    Start,
    /// `device-auth/finish` is outstanding.
    Finish,
    /// Authenticated; requests may be signed.
    Done(ClientDeviceSession),
    /// Failed.
    Spent,
}

/// A durable device, unlocked (module docs). Holds the account key and the device keys (inside
/// `rizzy-client`'s [`UnlockedDevice`]), the verified account and this device's vault drivers
/// (module docs, "Sync and items"), and, once [`DeviceSession::auth_respond`] finishes, the
/// device-authenticated session that can sign requests. [`DeviceSession::lock`] drops all of
/// it; every secret type wipes itself on drop, as does freeing the JavaScript object.
///
/// Only the account's first vault (module docs, "Sync and items"; [`crate::session::Session`]
/// makes the same choice for the ephemeral device) is exposed through the item and sync calls
/// below; a future multi-vault build would index `DeviceSession::vaults` by id instead of
/// always `DeviceSession::vault_ref`'s `[0]`.
#[wasm_bindgen]
pub struct DeviceSession {
    /// The device state (account id, device id, server origin, and the wraps; no secret this
    /// type's `Debug` would print).
    device: DeviceState,
    /// The unlocked keys.
    unlocked: UnlockedDevice,
    /// The verified account of enrolment or the last refresh.
    account: VerifiedAccount,
    /// The account's authors, for op verification.
    authors: Authors,
    /// This device's driver of each vault the account holds a self-grant for; `[0]` is the
    /// personal vault every call below operates on (struct docs).
    vaults: Vec<VaultSync>,
    /// A mirror of every row this device's cache holds, kept in step with `vaults`'/`account`'s
    /// own writes so `DeviceSession::drain_cache_writes` can diff the encoded rows before and
    /// after a step (`crate::store::CacheDelta`'s module docs). Never a secret by itself: the
    /// same opaque, encrypted columns a host already persists.
    cache: CacheRows,
    /// The floors this device's own writes are checked against before they are admitted
    /// (`rizzy_client::store::floors::Floors`'s module docs).
    floors: Floors,
    /// Device authentication.
    auth: AuthStage,
    /// The outstanding auth request.
    pending: Option<HttpRequest>,
    /// The sync step driver (`crate::sync`'s module docs); the same one
    /// [`crate::session::Session`] uses, with `Signer::Device` in place of
    /// [`Signer::Bearer`].
    sync: SyncDriver,
    /// The RNG for item writes and sync.
    rng: Rng,
}

impl fmt::Debug for DeviceSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceSession")
            .field("account_id", &self.unlocked.account_id())
            .field("device_id", &self.unlocked.device_id())
            .field("vaults", &self.vaults.len())
            .finish_non_exhaustive()
    }
}

impl DeviceSession {
    /// Wraps an already-unlocked device (used by [`EnrolResult::new`] and
    /// [`DeviceSession::unlock`]).
    fn from_parts(
        device: DeviceState,
        unlocked: UnlockedDevice,
        account: VerifiedAccount,
        authors: Authors,
        vaults: Vec<VaultSync>,
        cache: CacheRows,
        floors: Floors,
    ) -> Self {
        Self {
            device,
            unlocked,
            account,
            authors,
            vaults,
            cache,
            floors,
            auth: AuthStage::Idle,
            pending: None,
            sync: SyncDriver::default(),
            rng: os_rng(),
        }
    }

    /// The personal vault, read-only (struct docs). A write goes through a direct
    /// `self.vaults.first_mut()` instead, inline beside the other fields it needs at once
    /// (`self.rng`, `self.unlocked`): a `&mut self` accessor here would borrow every field for
    /// as long as the vault reference lives, which is exactly what `create_item`/`sync_start`
    /// must not do.
    ///
    /// # Errors
    /// [`ClientError::Internal`] if this device holds no vault at all, which [`EnrolResult::new`]
    /// and [`DeviceSession::unlock`] never produce.
    fn vault_ref(&self) -> CoreResult<&VaultSync> {
        self.vaults
            .first()
            .ok_or_else(|| ClientError::Internal.into())
    }

    /// The cache writes of every step since the last drain, diffed against the current
    /// `cache` mirror (`crate::store::CacheDelta`'s module docs): this device's own vault
    /// writes ([`VaultSync::take_writes`]) and the account's current object rows
    /// (`rizzy_client::store::account_writes`), recomputed every time rather than only when the
    /// account actually refreshed, which needs no visibility into the sync driver's phase and
    /// costs nothing extra: a row whose bytes did not change is never in the diff.
    ///
    /// # Errors
    /// [`ClientError::Internal`] if the changeset breaks a floor (never, for a changeset this
    /// device's own steps produced over its own `floors`) or a row does not encode.
    fn drain_cache_writes(&mut self) -> CoreResult<CacheDelta> {
        let mut changeset = store::account_writes(&self.account);
        for vault in &mut self.vaults {
            changeset.append(vault.take_writes());
        }
        if changeset.is_empty() {
            return Ok(CacheDelta::default());
        }
        self.floors.admit(&changeset).map_err(CoreError::from)?;
        let before = encode_rows(&self.cache).map_err(CoreError::from)?;
        self.cache.apply(&changeset);
        let after = encode_rows(&self.cache).map_err(CoreError::from)?;
        Ok(CacheDelta::diff(&before, &after))
    }

    /// Runs a lifecycle op on an item (as [`crate::session::Session::lifecycle`]).
    fn lifecycle(
        &mut self,
        id: &str,
        op: fn(&mut VaultSync, &mut Rng, &UnlockedDevice, ItemId, u64) -> Result<(), ClientError>,
        now_ms: u64,
    ) -> CoreResult<()> {
        if self.sync.running() {
            return Err(CoreError::new(WRONG_STATE));
        }
        let item = items::item_id(id)?;
        let vault = self
            .vaults
            .first_mut()
            .ok_or_else(|| CoreError::from(ClientError::Internal))?;
        op(vault, &mut self.rng, &self.unlocked, item, now_ms)?;
        Ok(())
    }
}

#[wasm_bindgen]
impl DeviceSession {
    /// Unlocks a persisted device from its cache rows (module docs; ADR 0026 §4 step 5, offline
    /// part then the local verify). No network: every account object it checks is the cache's
    /// own. `password` is UTF-8 bytes, zeroed when the call returns. `now_ms` is the host's
    /// clock, for the HLC receive rule.
    ///
    /// # Errors
    /// `cache_corrupt`; `wrong_password_or_secret_key`; `signup_pending`;
    /// `local_unlock_unavailable`; `cache_update_required` for a newer cache format.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "wasm-bindgen hands this exported call ownership of the JS array as Vec<KvRow>, never a slice"
    )]
    pub fn unlock(
        cache_rows: Vec<KvRow>,
        password: &mut [u8],
        now_ms: u64,
    ) -> Result<Self, CoreError> {
        let password = take_secret(password)?;
        let rows = decode_rows(&cache_rows).map_err(CoreError::from)?;
        let record = store::load::open(&rows).map_err(CoreError::from)?;
        let unlocked = record.unlock(password.as_str()).map_err(CoreError::from)?;
        let loaded =
            store::load::load(&rows, &record, &unlocked, now_ms).map_err(CoreError::from)?;
        // `load::load` already built this device's vault drivers from the cache's own
        // `vaults`/`wraps` rows, with the cache journal on (module docs, "Sync and items");
        // nothing here calls `take_vault_key`/`VaultSync::new` itself.
        Ok(Self::from_parts(
            loaded.device,
            unlocked,
            loaded.account,
            loaded.authors,
            loaded.vaults,
            rows,
            loaded.floors,
        ))
    }

    /// The account, hex.
    #[wasm_bindgen(getter, js_name = accountId)]
    #[must_use]
    pub fn account_id(&self) -> String {
        hex(&self.unlocked.account_id().to_bytes())
    }

    /// This device, hex.
    #[wasm_bindgen(getter, js_name = deviceId)]
    #[must_use]
    pub fn device_id(&self) -> String {
        hex(&self.unlocked.device_id().to_bytes())
    }

    /// `"idle"`, `"request"`, `"done"`, or `"failed"` (module docs).
    #[wasm_bindgen(getter, js_name = authState)]
    #[must_use]
    pub fn auth_state(&self) -> String {
        match self.auth {
            AuthStage::Idle => "idle",
            AuthStage::Start | AuthStage::Finish => "request",
            AuthStage::Done(_) => "done",
            AuthStage::Spent => "failed",
        }
        .to_owned()
    }

    /// Starts device authentication (§5.10 step 1): builds the `device-auth/start` request.
    ///
    /// # Errors
    /// `wrong_state` unless `authState` is `"idle"` or `"failed"` (retrying after a failure
    /// starts again).
    #[wasm_bindgen(js_name = authStart)]
    pub fn auth_start(&mut self) -> Result<(), CoreError> {
        if !matches!(self.auth, AuthStage::Idle | AuthStage::Spent) {
            return Err(CoreError::new(WRONG_STATE));
        }
        let request = device_auth_start(&self.device);
        self.pending = Some(HttpRequest::post(paths::DEVICE_AUTH_START, &request, None)?);
        self.auth = AuthStage::Start;
        Ok(())
    }

    /// The outstanding auth request.
    ///
    /// # Errors
    /// `wrong_state` when nothing is outstanding.
    #[wasm_bindgen(js_name = authRequest)]
    pub fn auth_request(&self) -> Result<HttpRequest, CoreError> {
        self.pending
            .as_ref()
            .map(HttpRequest::duplicate)
            .ok_or(CoreError::new(WRONG_STATE))
    }

    /// Passes in the answer to the outstanding auth request.
    ///
    /// # Errors
    /// `invalid_server_response`; the server's code; `wrong_state`.
    #[wasm_bindgen(js_name = authRespond)]
    pub fn auth_respond(&mut self, status: u16, body: &[u8]) -> Result<(), CoreError> {
        if self.pending.is_none() {
            return Err(CoreError::new(WRONG_STATE));
        }
        self.pending = None;
        let stage = core::mem::replace(&mut self.auth, AuthStage::Spent);
        match self.auth_step(&stage, status, body) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.auth = AuthStage::Spent;
                self.pending = None;
                Err(e)
            }
        }
    }

    /// Whether a request may be signed right now ([`DeviceSession::sign_request`] would
    /// succeed).
    #[wasm_bindgen(js_name = isAuthenticated)]
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        matches!(self.auth, AuthStage::Done(_))
    }

    /// Signs one request with the device key (CRYPTO.md §5.10 "Request signing"): the
    /// `device-request` counter signature and the bearer token, as the host's transport needs
    /// them. `body` is the exact bytes the host will send.
    ///
    /// # Errors
    /// `wrong_state` unless `isAuthenticated()`; `invalid_input` for an empty method or path;
    /// `session_exhausted` if the per-session counter would wrap (re-authenticate: call
    /// [`DeviceSession::auth_start`] again).
    #[wasm_bindgen(js_name = signRequest)]
    pub fn sign_request(
        &mut self,
        method: &str,
        path_and_query: &str,
        body: &[u8],
    ) -> Result<SignedRequest, CoreError> {
        let AuthStage::Done(session) = &mut self.auth else {
            return Err(CoreError::new(WRONG_STATE));
        };
        let signature = session
            .sign_request(&self.unlocked, method, path_and_query, body)
            .map_err(CoreError::from)?;
        Ok(SignedRequest {
            bearer: Zeroizing::new(format!(
                "Bearer {}",
                session.bearer_token().to_b64url().as_str()
            )),
            request_counter: signature.request_counter,
            signature: Zeroizing::new(signature.signature.to_b64url()),
        })
    }

    /// Whether the vault refuses writes (the server is behind this device, or the history
    /// check failed).
    ///
    /// # Errors
    /// As `DeviceSession::vault_ref`.
    #[wasm_bindgen(getter, js_name = readOnly)]
    pub fn read_only(&self) -> Result<bool, CoreError> {
        Ok(self.vault_ref()?.is_read_only())
    }

    /// How many own ops the server has not acknowledged yet: what a lock now would lose (the
    /// cache keeps them, unlike the ephemeral web vault; a later unlock resends them).
    ///
    /// # Errors
    /// As `DeviceSession::vault_ref`.
    #[wasm_bindgen(getter, js_name = unsentChanges)]
    pub fn unsent_changes(&self) -> Result<usize, CoreError> {
        Ok(self.vault_ref()?.unacknowledged().0)
    }

    /// Whether a sync is running.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn syncing(&self) -> bool {
        self.sync.running()
    }

    /// Starts a sync (`crate::sync`'s module docs), signed with this device's key
    /// (`Signer::Device`) rather than a bearer-only session.
    ///
    /// # Errors
    /// `wrong_state` while a sync runs; as `DeviceSession::vault_ref`; `locked` is never
    /// returned (a [`DeviceSession`] with no vault cannot exist).
    #[wasm_bindgen(js_name = syncStart)]
    pub fn sync_start(&mut self) -> Result<(), CoreError> {
        let AuthStage::Done(session) = &mut self.auth else {
            return Err(CoreError::new(WRONG_STATE));
        };
        let mut ctx = Ctx {
            vault: self
                .vaults
                .first_mut()
                .ok_or_else(|| CoreError::from(ClientError::Internal))?,
            account: &mut self.account,
            authors: &mut self.authors,
            unlocked: &self.unlocked,
            signer: Signer::Device(session),
            rng: &mut self.rng,
        };
        self.sync.start(&mut ctx)
    }

    /// The sync's outstanding request, or `undefined` when the sync is done.
    #[wasm_bindgen(js_name = syncRequest)]
    #[must_use]
    pub fn sync_request(&self) -> Option<HttpRequest> {
        self.sync.request()
    }

    /// Passes in the answer to the outstanding request. `now_ms` is the host's clock. Any
    /// error ends the sync. On success, call `DeviceSession::drain_cache_writes` before the
    /// next request is released (ADR 0026 §4 step 2; struct docs) — before calling
    /// [`DeviceSession::sync_request`] again.
    ///
    /// # Errors
    /// As [`crate::sync`] describes; as `DeviceSession::vault_ref`.
    #[wasm_bindgen(js_name = syncRespond)]
    pub fn sync_respond(&mut self, status: u16, body: &[u8], now_ms: u64) -> Result<(), CoreError> {
        let AuthStage::Done(session) = &mut self.auth else {
            return Err(CoreError::new(WRONG_STATE));
        };
        let ctx = Ctx {
            vault: self
                .vaults
                .first_mut()
                .ok_or_else(|| CoreError::from(ClientError::Internal))?,
            account: &mut self.account,
            authors: &mut self.authors,
            unlocked: &self.unlocked,
            signer: Signer::Device(session),
            rng: &mut self.rng,
        };
        self.sync.respond(ctx, status, body, now_ms)
    }

    /// Ends the running sync when the host could not carry its outstanding request
    /// (`crate::sync`'s module docs, [`crate::session::Session::sync_abort`]). A no-op when no
    /// sync runs.
    ///
    /// # Errors
    /// As `DeviceSession::vault_ref`.
    #[wasm_bindgen(js_name = syncAbort)]
    pub fn sync_abort(&mut self) -> Result<(), CoreError> {
        self.sync.abort(
            self.vaults
                .first_mut()
                .ok_or_else(|| CoreError::from(ClientError::Internal))?,
        );
        Ok(())
    }

    /// The cache writes of every step since the last call (struct docs,
    /// `crate::store::CacheDelta`'s module docs): empty when nothing changed. A host persists
    /// `puts` and `deletes` in one transaction across their stores, then continues — before the
    /// next [`DeviceSession::sync_request`], and before this call's own createItem/editItem/…
    /// result is treated as saved.
    ///
    /// # Errors
    /// [`ClientError::Internal`] if a row does not encode (never, for this device's own rows).
    #[wasm_bindgen(js_name = drainCacheWrites)]
    pub fn drain_cache_writes_js(&mut self) -> Result<CacheDelta, CoreError> {
        self.drain_cache_writes()
    }

    /// The active items, or the trashed ones, as summaries (no concealed value).
    ///
    /// # Errors
    /// As `DeviceSession::vault_ref`.
    pub fn items(&self, trash: bool) -> Result<Vec<ItemSummary>, CoreError> {
        Ok(items::summaries(self.vault_ref()?, trash))
    }

    /// One item's summary.
    ///
    /// # Errors
    /// As `DeviceSession::vault_ref`; `invalid_input` for an id that is not 32 hex digits;
    /// `unknown_item`.
    pub fn item(&self, id: &str) -> Result<ItemSummary, CoreError> {
        let vault = self.vault_ref()?;
        let item = visible_item(vault, id)?;
        items::summary(vault, item).ok_or(ClientError::UnknownItem.into())
    }

    /// One item's displayed fields; concealed values are withheld.
    ///
    /// # Errors
    /// As [`DeviceSession::item`].
    #[wasm_bindgen(js_name = itemFields)]
    pub fn item_fields(&self, id: &str) -> Result<Vec<FieldView>, CoreError> {
        let vault = self.vault_ref()?;
        let item = visible_item(vault, id)?;
        Ok(items::fields(vault, item))
    }

    /// One field's value as text, concealed or not: call it only on the user's request.
    ///
    /// # Errors
    /// As [`DeviceSession::item`]; `unknown_item` for a field the item does not display;
    /// `invalid_input` for a value with no text form.
    #[wasm_bindgen(js_name = revealField)]
    pub fn reveal_field(&self, id: &str, key: &str) -> Result<String, CoreError> {
        let vault = self.vault_ref()?;
        let item = visible_item(vault, id)?;
        Ok(items::reveal(vault, item, key)?.as_str().to_owned())
    }

    /// Produces a `WebAuthn` assertion for one stored passkey (`passkey/<passkey_id>/…` on
    /// item `id`, ADR 0039 §1, §2; [`crate::passkey`] module docs — the extension's own
    /// durable-device path there: this crate's other passkey call, [`crate::passkey::create_passkey`],
    /// needs no session at all). The stored private key is read and used here, never
    /// returned: only the resulting [`PasskeyAssertion`] crosses to JavaScript, the same
    /// pattern [`DeviceSession::reveal_field`] uses for a different concealed field (text
    /// there; this one is never text-revealable at all, module docs).
    ///
    /// `origin` must be the browser-verified origin — the extension's background script reads
    /// it from the browser's own sender information, never from the intercepted
    /// `navigator.credentials.get()` call's relayed payload ([ADR 0036] §4; [`crate::passkey`]
    /// module docs, "What this does not decide"); `rp_id` is the page's requested `rpId`,
    /// already defaulted by the caller to `origin`'s host if the page omitted it.
    ///
    /// # Errors
    /// As [`DeviceSession::item`]; `invalid_input` when `passkey_id` is not a valid element
    /// id, the item has no such passkey, or its stored key is not a valid 32-byte scalar;
    /// otherwise whatever `get_assertion` returns (`rp_id_rejected` for INV-64).
    ///
    /// [ADR 0036]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0036-browser-extension-architecture-and-key-custody.md
    #[wasm_bindgen(js_name = passkeyAssertion)]
    pub fn passkey_assertion(
        &self,
        id: &str,
        passkey_id: &str,
        origin: &str,
        rp_id: &str,
        challenge: &[u8],
    ) -> Result<PasskeyAssertion, CoreError> {
        let vault = self.vault_ref()?;
        let item = visible_item(vault, id)?;
        let bad = || CoreError::from(ClientError::InvalidInput);
        let element = ElementId::from_bytes(items::parse_id(passkey_id)?);

        let credential_id_key = element
            .key(LIST_PASSKEY, ATTR_CREDENTIAL_ID)
            .map_err(|_| bad())?;
        let credential_id = match vault
            .field_value(item, credential_id_key.as_str())
            .ok_or_else(bad)?
            .decode()
        {
            Ok(ValueRef::Bytes(bytes)) => bytes.to_vec(),
            _ => return Err(bad()),
        };

        let private_key_key = element
            .key(LIST_PASSKEY, ATTR_PRIVATE_KEY)
            .map_err(|_| bad())?;
        let signing_key = match vault
            .field_value(item, private_key_key.as_str())
            .ok_or_else(bad)?
            .decode()
        {
            Ok(ValueRef::Bytes(bytes)) => Es256SigningKey::from_bytes(bytes).map_err(|_| bad())?,
            _ => return Err(bad()),
        };

        let assertion = get_assertion(&signing_key, &credential_id, origin, rp_id, challenge)?;
        Ok(assertion.into())
    }

    /// Creates an item of `item_type` (a name of [`crate::items::TYPES`]) with the draft's
    /// writes. Returns the new item's id. `DeviceSession::drain_cache_writes` after this
    /// call returns the rows to persist (struct docs).
    ///
    /// # Errors
    /// `wrong_state` while a sync runs; as `DeviceSession::vault_ref`; `invalid_input` for an
    /// unknown type; `invalid_edit` for a write the schema refuses; `read_only`.
    #[wasm_bindgen(js_name = createItem)]
    pub fn create_item(
        &mut self,
        item_type: &str,
        draft: &ItemDraft,
        now_ms: u64,
    ) -> Result<String, CoreError> {
        if self.sync.running() {
            return Err(CoreError::new(WRONG_STATE));
        }
        let item_type = type_from_name(item_type)?;
        let writes = items::writes(self.vault_ref()?, None, draft)?;
        let edits: Vec<FieldEdit<'_>> = writes
            .iter()
            .map(|(key, value)| FieldEdit { key, value })
            .collect();
        let vault = self
            .vaults
            .first_mut()
            .ok_or_else(|| CoreError::from(ClientError::Internal))?;
        let item = vault.create_item(&mut self.rng, &self.unlocked, item_type, &edits, now_ms)?;
        Ok(hex(item.as_bytes()))
    }

    /// Edits an active item with the draft's writes, as one op.
    /// `DeviceSession::drain_cache_writes` after this call returns the rows to persist.
    ///
    /// # Errors
    /// As [`DeviceSession::create_item`]; `unknown_item` for an item that is not active;
    /// `invalid_edit` for an empty draft.
    #[wasm_bindgen(js_name = editItem)]
    pub fn edit_item(&mut self, id: &str, draft: &ItemDraft, now_ms: u64) -> Result<(), CoreError> {
        if draft.is_empty() {
            return Err(ClientError::InvalidEdit.into());
        }
        if self.sync.running() {
            return Err(CoreError::new(WRONG_STATE));
        }
        let item = items::item_id(id)?;
        let writes = items::writes(self.vault_ref()?, Some(item), draft)?;
        let edits: Vec<FieldEdit<'_>> = writes
            .iter()
            .map(|(key, value)| FieldEdit { key, value })
            .collect();
        let vault = self
            .vaults
            .first_mut()
            .ok_or_else(|| CoreError::from(ClientError::Internal))?;
        vault.edit_item(&mut self.rng, &self.unlocked, item, &edits, now_ms)?;
        Ok(())
    }

    /// Moves an active item to the trash. `DeviceSession::drain_cache_writes` after this
    /// call returns the rows to persist.
    ///
    /// # Errors
    /// `wrong_state` while a sync runs; `unknown_item`; `read_only`.
    #[wasm_bindgen(js_name = trashItem)]
    pub fn trash_item(&mut self, id: &str, now_ms: u64) -> Result<(), CoreError> {
        self.lifecycle(id, VaultSync::trash_item::<Rng>, now_ms)
    }

    /// Restores a trashed item.
    ///
    /// # Errors
    /// As [`DeviceSession::trash_item`].
    #[wasm_bindgen(js_name = restoreItem)]
    pub fn restore_item(&mut self, id: &str, now_ms: u64) -> Result<(), CoreError> {
        self.lifecycle(id, VaultSync::restore_item::<Rng>, now_ms)
    }

    /// Purges a trashed item for good.
    ///
    /// # Errors
    /// As [`DeviceSession::trash_item`]; `invalid_edit` when the writer rules refuse.
    #[wasm_bindgen(js_name = purgeItem)]
    pub fn purge_item(&mut self, id: &str, now_ms: u64) -> Result<(), CoreError> {
        self.lifecycle(id, VaultSync::purge_item::<Rng>, now_ms)
    }

    /// Zeroizes every handle this session holds (ADR 0013 §3 rule 1). Consumes the session;
    /// dropping it does the same.
    pub fn lock(self) {}
}

impl DeviceSession {
    /// One answer of the auth state machine.
    fn auth_step(&mut self, stage: &AuthStage, status: u16, body: &[u8]) -> CoreResult<()> {
        match stage {
            AuthStage::Start => {
                let challenge: DeviceAuthStartResponse = http::json(status, body)?;
                let finish = device_auth_finish(&self.device, &self.unlocked, &challenge)
                    .map_err(CoreError::from)?;
                self.pending = Some(HttpRequest::post(paths::DEVICE_AUTH_FINISH, &finish, None)?);
                self.auth = AuthStage::Finish;
                Ok(())
            }
            AuthStage::Finish => {
                let answer: DeviceAuthFinishResponse = http::json(status, body)?;
                self.auth = AuthStage::Done(ClientDeviceSession::new(&self.device, answer));
                Ok(())
            }
            AuthStage::Idle | AuthStage::Done(_) | AuthStage::Spent => {
                Err(CoreError::new(WRONG_STATE))
            }
        }
    }
}

/// A signed request's values, for the host's transport (`DeviceSession::sign_request`'s
/// module docs on why these cross as values, never a header string built here): ADR 0028 item
/// 5 already fixes the header names (`Rizzy-Request-Counter`/`Rizzy-Request-Signature`,
/// `rizzy_proto::http::REQUEST_COUNTER_HEADER`/`REQUEST_SIGNATURE_HEADER`; `crate::http`'s
/// `post_signed` already builds a [`crate::http::HttpRequest`] with them for a sync request),
/// this type exists for a signed call a host makes outside the sync driver. Both secrets wipe
/// on drop, as does freeing the JavaScript object; `Debug` shows neither.
#[wasm_bindgen]
#[derive(Clone)]
pub struct SignedRequest {
    /// The `Authorization` header value.
    bearer: Zeroizing<String>,
    /// The `device-request` counter.
    request_counter: u64,
    /// The signature, base64url.
    signature: Zeroizing<String>,
}

impl fmt::Debug for SignedRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedRequest")
            .field("request_counter", &self.request_counter)
            .finish_non_exhaustive()
    }
}

#[wasm_bindgen]
impl SignedRequest {
    /// The `Authorization` header value. A secret: never log it.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn bearer(&self) -> String {
        self.bearer.as_str().to_owned()
    }

    /// The `device-request` counter, for the host's own signature header.
    #[wasm_bindgen(getter, js_name = requestCounter)]
    #[must_use]
    pub fn request_counter(&self) -> u64 {
        self.request_counter
    }

    /// The signature, base64url.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn signature(&self) -> String {
        self.signature.as_str().to_owned()
    }
}

#[cfg(test)]
mod tests {
    use rizzy_client::rizzy_core::secret_key::SecretKey;

    use super::*;

    const ORIGIN: &str = "https://vault.example.com";

    fn bytes(text: &str) -> Vec<u8> {
        text.as_bytes().to_vec()
    }

    fn secret_key() -> String {
        SecretKey::generate(&mut os_rng())
            .to_formatted()
            .to_string()
    }

    #[test]
    fn an_enrol_flow_starts_with_login_start_and_refuses_bad_input() {
        let error = EnrolFlow::start(
            "not an origin",
            "alice",
            &mut bytes(&secret_key()),
            &mut bytes("pw"),
            None,
        )
        .unwrap_err();
        assert_eq!(error.as_str(), "invalid_input");

        let mut flow = EnrolFlow::start(
            ORIGIN,
            "alice",
            &mut bytes(&secret_key()),
            &mut bytes("pw"),
            None,
        )
        .unwrap();
        assert_eq!(flow.state(), "request");
        let request = flow.request().unwrap();
        assert_eq!(request.path(), "/api/v1/login/start");
        assert!(request.authorization().is_none());

        let error = flow
            .respond(429, br#"{"error":"rate_limited"}"#, 0)
            .unwrap_err();
        assert_eq!(error.as_str(), "server_rate_limited");
        assert_eq!(flow.state(), "failed");
        assert_eq!(flow.finish().unwrap_err().as_str(), "wrong_state");
    }

    #[test]
    fn out_of_order_calls_are_refused() {
        let mut flow = EnrolFlow::start(
            ORIGIN,
            "alice",
            &mut bytes(&secret_key()),
            &mut bytes("pw"),
            None,
        )
        .unwrap();
        assert_eq!(
            flow.provide_totp("123456").unwrap_err().as_str(),
            "wrong_state"
        );
        assert_eq!(flow.state(), "request");
    }

    #[test]
    fn a_device_session_rejects_an_empty_cache_dump() {
        let error = DeviceSession::unlock(vec![], &mut bytes("pw"), 0).unwrap_err();
        assert_eq!(error.as_str(), "cache_corrupt");
    }

    #[test]
    fn an_incomplete_dump_is_cache_corrupt_not_a_panic() {
        let error = DeviceSession::unlock(
            vec![KvRow::new("cache_meta", b"format".to_vec(), vec![0, 1])],
            &mut bytes("pw"),
            0,
        )
        .unwrap_err();
        assert_eq!(error.as_str(), "cache_corrupt");
    }
}
