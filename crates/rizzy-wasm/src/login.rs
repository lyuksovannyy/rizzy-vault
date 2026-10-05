//! The web vault's login (CRYPTO.md §11.4: "Every session is an OPAQUE login", §11.2 steps
//! 1–6) as a request/response loop for JavaScript.
//!
//! ```text
//! LoginFlow.start ──login/start──► respond ──login/finish──► respond
//!   ├─ second_factor_required ──► state "needs_totp" ──provideTotp──► (again from login/start)
//!   └─ verified ──devices/web-certificate (kind 4, 12 h)──► respond ──► state "done" ──finish──► Session
//! ```
//!
//! The host loops: while [`LoginFlow::state`] is `"request"`, send [`LoginFlow::request`] and
//! pass the answer to [`LoginFlow::respond`]. On `"needs_totp"` it asks the user and calls
//! [`LoginFlow::provide_totp`]; on `"done"`, [`LoginFlow::finish`] returns the [`Session`].
//! Every check is `rizzy-client`'s ([`rizzy_client::login`]); this module only orders the steps.
//!
//! # Readings
//!
//! - **A second factor** restarts the OPAQUE login from `login/start` with the code, as `rv`
//!   does: a login state is taken once by the server (ADR 0028, "Single use"), so the finish
//!   cannot be resent. A host that knows the account has 2FA passes the code to
//!   [`LoginFlow::start`] and saves the second Argon2id run.
//! - **`unauthorized`** on `login/finish` is a wrong password or Secret Key, or an unknown
//!   account; the server does not say which (CRYPTO.md §5.9), and neither does this flow.
//! - **Unlock and lock.** The web vault has no device state and no offline unlock (CRYPTO.md
//!   §11.4): unlocking is a new login, and a lock drops the [`Session`].
//! - **Re-authentication** for a plaintext export ([`Session::reauth`]) runs the same OPAQUE
//!   steps, keeps none of the new login's keys and uploads no certificate.
//! - **Moving to the server's current OPAQUE setup** ([ADR 0031] point 2). When `login/finish`
//!   answers `reregister`, the session login holds the typed password, so before the ephemeral
//!   certificate it runs the same-password re-registration over its OPAQUE session
//!   (`account/reregister/start`, then `account/commit`; [`rizzy_client::reregister`]), once
//!   per login. It is transparent: any failure (a lost compare-and-swap, a refusal, a bad
//!   answer) skips it, the login goes on, and the next login tries again. A re-authentication
//!   does not run it.
//!
//! [ADR 0031]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0031-retiring-old-opaque-setups.md

use core::fmt;

use rizzy_client::ClientError;
use rizzy_client::login::{
    LoggedIn, LoginAwaitingSession, LoginInput, LoginStarted, WebSession, start_login,
};
use rizzy_client::reregister::{PendingReregistration, ReregistrationStarted};
use rizzy_client::rizzy_core::ids::AccountId;
use rizzy_client::rizzy_proto::auth::{LoginFinishResponse, LoginStartResponse};
use rizzy_client::rizzy_proto::change::ReregisterStartResponse;
use rizzy_client::rizzy_proto::error::ErrorCode;
use rizzy_client::rizzy_proto::http::paths;
use wasm_bindgen::prelude::wasm_bindgen;
use zeroize::Zeroizing;

use crate::error::{CoreError, CoreResult, WRONG_STATE};
use crate::http::{self, HttpRequest};
use crate::rng::{Rng, os_rng};
use crate::secret::take_secret;
use crate::session::Session;

/// How often a login restarts for a second factor before it gives up.
const MAX_STARTS: u8 = 3;

/// What the user typed, kept in Rust until the flow ends (a second-factor restart needs it).
/// Wiped on drop; `Debug` redacted.
pub(crate) struct Credentials {
    /// The server origin, as dialled (`location.origin`).
    pub(crate) origin: String,
    /// The login name.
    pub(crate) login_name: String,
    /// The Secret Key.
    pub(crate) secret_key: Zeroizing<String>,
    /// The master password.
    pub(crate) password: Zeroizing<String>,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Credentials([REDACTED])")
    }
}

/// What the flow is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Purpose {
    /// A web-vault session: an ephemeral kind-4 device is certified at the end.
    Session,
    /// A re-authentication of an open session (plaintext export): only the verified account
    /// id is kept.
    Reauth,
}

/// Where the flow is.
enum Stage {
    /// `login/start` is outstanding.
    Start(Box<LoginStarted>),
    /// `login/finish` is outstanding.
    Finish(LoginAwaitingSession),
    /// `account/reregister/start` of the same-password re-registration is outstanding (ADR
    /// 0031 point 2).
    Reregister(Box<LoggedIn>, ReregistrationStarted),
    /// Its `account/commit` is outstanding.
    ReregisterCommit(Box<LoggedIn>, Box<PendingReregistration>),
    /// `devices/web-certificate` is outstanding.
    Certificate(Box<WebSession>),
    /// The account has 2FA and the login carried no code.
    NeedsTotp,
    /// A session is ready.
    Done(Box<WebSession>),
    /// A re-authentication verified this account.
    Reauthenticated(AccountId),
    /// Failed, or its result was taken.
    Spent,
}

/// A login in progress (module docs). Holds `pw_in`, the `export_key` and later the keys of the
/// ephemeral device, all in Rust memory; `Debug` shows the state only.
#[wasm_bindgen]
pub struct LoginFlow {
    /// The typed input.
    input: Credentials,
    /// The second factor, if given.
    totp: Option<Zeroizing<String>>,
    /// Session or re-authentication.
    purpose: Purpose,
    /// Where the flow is.
    stage: Stage,
    /// The outstanding request.
    pending: Option<HttpRequest>,
    /// How often the flow went through `login/start`.
    starts: u8,
    /// The RNG.
    rng: Rng,
}

impl fmt::Debug for LoginFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginFlow")
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

#[wasm_bindgen]
impl LoginFlow {
    /// Starts a web-vault login. `server_origin` is the origin the vault was loaded from;
    /// `totp` is the second factor if the host already has it. No Argon2id runs yet.
    ///
    /// `secret_key` and `password` are UTF-8 bytes (`TextEncoder`), never strings; both arrays
    /// hold zeroes when the call returns, whatever its outcome ([`crate::secret`]).
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
    ) -> Result<LoginFlow, CoreError> {
        // Both are taken, and so wiped, before either error returns.
        let secret_key = take_secret(secret_key);
        let password = take_secret(password);
        Self::begin(
            Credentials {
                origin: server_origin.to_owned(),
                login_name: login_name.to_owned(),
                secret_key: secret_key?,
                password: password?,
            },
            totp.map(Zeroizing::new),
            Purpose::Session,
        )
    }

    /// `"request"` while a request is outstanding, `"needs_totp"`, `"done"`, or `"failed"`
    /// after an error or once the result was taken.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn state(&self) -> String {
        match self.stage {
            Stage::Start(_)
            | Stage::Finish(_)
            | Stage::Reregister(..)
            | Stage::ReregisterCommit(..)
            | Stage::Certificate(_) => "request",
            Stage::NeedsTotp => "needs_totp",
            Stage::Done(_) | Stage::Reauthenticated(_) => "done",
            Stage::Spent => "failed",
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

    /// Passes in the answer to the outstanding request: its status and body bytes. `now_ms`
    /// is the host's clock (`Date.now()`), for the ephemeral certificate. The Argon2id run
    /// happens in the call that takes the `login/start` answer.
    ///
    /// # Errors
    /// `wrong_password_or_secret_key`; `kdf_not_allowed`, `origin_mismatch`,
    /// `invalid_server_response` (the answer did not verify); the server's code; `wrong_state`.
    /// After an error the flow is `"failed"`, except `wrong_state`.
    pub fn respond(&mut self, status: u16, body: &[u8], now_ms: u64) -> Result<(), CoreError> {
        if self.pending.is_none() {
            return Err(CoreError::new(WRONG_STATE));
        }
        let stage = core::mem::replace(&mut self.stage, Stage::Spent);
        self.pending = None;
        match self.step(stage, status, body, now_ms) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.stage = Stage::Spent;
                self.pending = None;
                Err(e)
            }
        }
    }

    /// The second factor, after the state became `"needs_totp"`: the login starts again with
    /// it.
    ///
    /// # Errors
    /// `wrong_state`; `invalid_input` for a code outside its bounds.
    #[wasm_bindgen(js_name = provideTotp)]
    pub fn provide_totp(&mut self, code: &str) -> Result<(), CoreError> {
        if !matches!(self.stage, Stage::NeedsTotp) {
            return Err(CoreError::new(WRONG_STATE));
        }
        self.totp = Some(Zeroizing::new(code.to_owned()));
        self.restart()
    }

    /// The session of a finished login. Consumes the flow.
    ///
    /// # Errors
    /// `wrong_state` unless the state is `"done"` for a session login.
    pub fn finish(self) -> Result<Session, CoreError> {
        let LoginFlow { input, stage, .. } = self;
        match stage {
            Stage::Done(web) => Session::from_web(*web, input.origin, input.login_name),
            _ => Err(CoreError::new(WRONG_STATE)),
        }
    }
}

impl LoginFlow {
    /// A flow for `input`, at `login/start`.
    pub(crate) fn begin(
        input: Credentials,
        totp: Option<Zeroizing<String>>,
        purpose: Purpose,
    ) -> CoreResult<Self> {
        let mut flow = Self {
            input,
            totp,
            purpose,
            stage: Stage::Spent,
            pending: None,
            starts: 0,
            rng: os_rng(),
        };
        flow.restart()?;
        Ok(flow)
    }

    /// (Re)starts the OPAQUE login from `login/start`.
    fn restart(&mut self) -> CoreResult<()> {
        if self.starts >= MAX_STARTS {
            self.stage = Stage::Spent;
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
            self.stage = Stage::Spent;
        })?;
        self.pending = Some(HttpRequest::post(paths::LOGIN_START, &request, None)?);
        self.stage = Stage::Start(Box::new(started));
        Ok(())
    }

    /// One answer, at `stage`.
    fn step(&mut self, stage: Stage, status: u16, body: &[u8], now_ms: u64) -> CoreResult<()> {
        match stage {
            Stage::Start(started) => {
                let answer: LoginStartResponse = http::json(status, body)?;
                let totp = self.totp.as_ref().map(|t| t.as_str());
                let (awaiting, finish) = (*started).finish(&mut self.rng, &answer, totp)?;
                self.pending = Some(HttpRequest::post(paths::LOGIN_FINISH, &finish, None)?);
                self.stage = Stage::Finish(awaiting);
                Ok(())
            }
            Stage::Finish(awaiting) => {
                match http::server_code(status, body) {
                    Some(ErrorCode::SecondFactorRequired) if self.totp.is_none() => {
                        self.stage = Stage::NeedsTotp;
                        return Ok(());
                    }
                    Some(ErrorCode::Unauthorized) => {
                        return Err(ClientError::WrongPasswordOrSecretKey.into());
                    }
                    _ => {}
                }
                let answer: LoginFinishResponse = http::json(status, body)?;
                let logged_in = awaiting.complete(answer)?;
                if self.purpose == Purpose::Session && logged_in.reregister() {
                    return self.reregister(logged_in, now_ms);
                }
                self.logged_in(logged_in, now_ms)
            }
            Stage::Reregister(login, started) => {
                let built = http::json::<ReregisterStartResponse>(status, body)
                    .and_then(|answer| Ok(started.finish_login(&mut self.rng, &answer, &login)?))
                    .and_then(|pending| {
                        let request = HttpRequest::post(
                            paths::ACCOUNT_COMMIT,
                            pending.commit_request(),
                            Some(login.bearer_token()),
                        )?;
                        Ok((pending, request))
                    });
                match built {
                    Ok((pending, request)) => {
                        self.pending = Some(request);
                        self.stage = Stage::ReregisterCommit(login, Box::new(pending));
                        Ok(())
                    }
                    // Transparent (module docs): the login goes on without it.
                    Err(_) => self.logged_in(*login, now_ms),
                }
            }
            Stage::ReregisterCommit(mut login, pending) => {
                if http::empty(status, body).is_ok() {
                    // The server holds the new record and state: the login pins the state.
                    login.adopt_reregistration(*pending)?;
                }
                self.logged_in(*login, now_ms)
            }
            Stage::Certificate(web) => {
                http::empty(status, body)?;
                self.stage = Stage::Done(web);
                Ok(())
            }
            Stage::NeedsTotp | Stage::Done(_) | Stage::Reauthenticated(_) | Stage::Spent => {
                Err(CoreError::new(WRONG_STATE))
            }
        }
    }

    /// ADR 0031 point 2 (module docs): starts the same-password re-registration over the
    /// login's OPAQUE session; if it cannot even start, the login goes on without it.
    fn reregister(&mut self, logged_in: LoggedIn, now_ms: u64) -> CoreResult<()> {
        let started = logged_in
            .start_reregistration(&mut self.rng)
            .map_err(CoreError::from)
            .and_then(|(started, request)| {
                let request = HttpRequest::post(
                    paths::ACCOUNT_REREGISTER_START,
                    &request,
                    Some(logged_in.bearer_token()),
                )?;
                Ok((started, request))
            });
        match started {
            Ok((started, request)) => {
                self.pending = Some(request);
                self.stage = Stage::Reregister(Box::new(logged_in), started);
                Ok(())
            }
            Err(_) => self.logged_in(logged_in, now_ms),
        }
    }

    /// After a verified login: the ephemeral device (CRYPTO.md §11.4), or the end of a
    /// re-authentication.
    fn logged_in(&mut self, logged_in: LoggedIn, now_ms: u64) -> CoreResult<()> {
        match self.purpose {
            Purpose::Session => {
                let (web, request) = logged_in.web_device(&mut self.rng, now_ms)?;
                self.pending = Some(HttpRequest::post(
                    paths::DEVICES_WEB_CERTIFICATE,
                    &request,
                    Some(&web.session_token),
                )?);
                self.stage = Stage::Certificate(Box::new(web));
            }
            Purpose::Reauth => {
                self.stage = Stage::Reauthenticated(logged_in.account().account_id());
            }
        }
        Ok(())
    }

    /// The account a finished re-authentication verified.
    pub(crate) const fn reauthenticated(&self) -> Option<AccountId> {
        match self.stage {
            Stage::Reauthenticated(account) => Some(account),
            _ => None,
        }
    }

    /// The purpose, for the session's check.
    pub(crate) const fn purpose(&self) -> Purpose {
        self.purpose
    }
}
