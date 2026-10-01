//! The web vault's signup (CRYPTO.md §11.1, "Web-vault signup (kind 4)") as a request/response
//! loop for JavaScript, in the order of "Secrets before commit" (CRYPTO.md §11).
//!
//! ```text
//! SignupFlow.start ──register/start──► respond (Argon2id) ──► state "confirm_kit"
//!   emergencyKit() (once) ──► confirmKit(last group of the Secret Key)
//!   ──register/finish──► respond ──► state "done" ──login()──► LoginFlow
//! ```
//!
//! # Readings
//!
//! - **Nothing is persisted.** A web-vault signup keeps no device state (CRYPTO.md §11.4); the
//!   commit is built once and [`SignupFlow::request`] returns the same bytes until an answer
//!   arrives, so a host that lost the answer to `register/finish` sends it again, which the
//!   server treats as success (§11.1 step 8; ADR 0028 "Register finish"). If the page is
//!   closed before the answer, the outcome is unknown and the kit already shown is the only
//!   record: the user logs in with it, or signs up again under another name.
//! - **The kit goes out once** (ADR 0013 §3 rule 2): [`SignupFlow::emergency_kit`] answers
//!   `already_shown` the second time. The host renders it, asks the user to re-type the last
//!   group of the Secret Key, and forgets it.
//! - **`register/finish` returns no session** (ADR 0028 item 2: an empty success), so the
//!   session is a login, as every web-vault session is (§11.4). [`SignupFlow::login`] starts it
//!   with the signup's origin, login name, Secret Key and password, which stay in Rust until
//!   then. That login certifies a second ephemeral kind-4 device: the signup's own certificate
//!   (§11.1 step 5) has no session to sign ops under. Both expire after 12 h.

use core::fmt;

use rizzy_client::rizzy_proto::auth::RegisterStartResponse;
use rizzy_client::rizzy_proto::http::paths;
use rizzy_client::signup::{DeviceKind, PendingSignup, SignupInput, SignupStarted, start_signup};
use wasm_bindgen::prelude::wasm_bindgen;
use zeroize::Zeroizing;

use crate::error::{ALREADY_SHOWN, CoreError, WRONG_STATE};
use crate::http::{self, HttpRequest};
use crate::login::{Credentials, LoginFlow, Purpose};
use crate::rng::{Rng, os_rng};
use crate::secret::{give_secret, take_secret};

/// Where the flow is.
enum Stage {
    /// `register/start` is outstanding.
    Start(Box<SignupStarted>),
    /// Every object is built; the kit waits for its confirmation.
    Kit(Box<PendingSignup>),
    /// `register/finish` is outstanding.
    Commit(Box<PendingSignup>),
    /// The server acknowledged the commit.
    Done,
    /// Failed, or its result was taken.
    Spent,
}

/// The Emergency Kit (CRYPTO.md §7): the one time the Secret Key and the recovery code leave
/// the core (ADR 0013 §3 rule 2). Wiped when freed; `Debug` redacted.
#[wasm_bindgen]
pub struct EmergencyKit {
    /// The server URL.
    server_origin: String,
    /// The login name, normalised.
    login_name: String,
    /// The Secret Key, `RV1-…`.
    secret_key: Zeroizing<String>,
    /// The recovery code, `RVR1-…`, if one was issued.
    recovery_code: Option<Zeroizing<String>>,
}

impl fmt::Debug for EmergencyKit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EmergencyKit([REDACTED])")
    }
}

#[wasm_bindgen]
impl EmergencyKit {
    /// The server URL.
    #[wasm_bindgen(getter, js_name = serverOrigin)]
    #[must_use]
    pub fn server_origin(&self) -> String {
        self.server_origin.clone()
    }

    /// The login name, as the server stores it (normalised).
    #[wasm_bindgen(getter, js_name = loginName)]
    #[must_use]
    pub fn login_name(&self) -> String {
        self.login_name.clone()
    }

    /// The Secret Key as printed, as UTF-8 bytes the host zeroes after rendering ([`crate::secret`]).
    /// A secret: render it, never log it.
    #[wasm_bindgen(getter, js_name = secretKey)]
    #[must_use]
    pub fn secret_key(&self) -> Vec<u8> {
        give_secret(&self.secret_key)
    }

    /// The recovery code as printed, as UTF-8 bytes the host zeroes after rendering, or
    /// `undefined` if the user opted out. A secret.
    #[wasm_bindgen(getter, js_name = recoveryCode)]
    #[must_use]
    pub fn recovery_code(&self) -> Option<Vec<u8>> {
        self.recovery_code.as_deref().map(|c| give_secret(c))
    }
}

/// A signup in progress (module docs). Holds every new key in Rust memory; `Debug` shows the
/// state only.
#[wasm_bindgen]
pub struct SignupFlow {
    /// What the user typed; the Secret Key is filled in once generated.
    input: Credentials,
    /// Where the flow is.
    stage: Stage,
    /// The outstanding request.
    pending: Option<HttpRequest>,
    /// Whether the kit was handed out.
    kit_shown: bool,
    /// The RNG.
    rng: Rng,
}

impl fmt::Debug for SignupFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignupFlow")
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

#[wasm_bindgen]
impl SignupFlow {
    /// Starts a web-vault signup. `server_origin` is the origin the vault was loaded from;
    /// `invite` the invite token if the server requires one; `issue_recovery_code` is on by
    /// default in the UI (§11.9). Generates every secret; no Argon2id runs yet.
    ///
    /// # Errors
    /// `invalid_input` for an origin or login name that does not normalise, a password the
    /// new-password rules refuse (empty, or an unassigned code point; CRYPTO.md §2), or an
    /// invite token outside its bounds.
    ///
    /// `password` is UTF-8 bytes (`TextEncoder`), never a string; the array holds zeroes when
    /// the call returns, whatever its outcome ([`crate::secret`]).
    pub fn start(
        server_origin: &str,
        login_name: &str,
        password: &mut [u8],
        invite: Option<String>,
        issue_recovery_code: bool,
        now_ms: u64,
    ) -> Result<SignupFlow, CoreError> {
        let password = take_secret(password)?;
        let mut rng = os_rng();
        let invite = invite.map(Zeroizing::new);
        let (started, request) = start_signup(
            &mut rng,
            &SignupInput {
                server_origin,
                login_name,
                password: password.as_str(),
                invite: invite.as_ref().map(|i| i.as_str()),
                issue_recovery_code,
                device_kind: DeviceKind::WebEphemeral,
                now_ms,
            },
        )?;
        Ok(Self {
            input: Credentials {
                origin: server_origin.to_owned(),
                login_name: login_name.to_owned(),
                secret_key: Zeroizing::new(String::new()),
                password,
            },
            stage: Stage::Start(Box::new(started)),
            pending: Some(HttpRequest::post(paths::REGISTER_START, &request, None)?),
            kit_shown: false,
            rng,
        })
    }

    /// `"request"` while a request is outstanding, `"confirm_kit"`, `"done"`, or `"failed"`.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn state(&self) -> String {
        match self.stage {
            Stage::Start(_) | Stage::Commit(_) => "request",
            Stage::Kit(_) => "confirm_kit",
            Stage::Done => "done",
            Stage::Spent => "failed",
        }
        .to_owned()
    }

    /// The outstanding request; the same bytes on every call until an answer is passed in.
    ///
    /// # Errors
    /// `wrong_state` when nothing is outstanding.
    pub fn request(&self) -> Result<HttpRequest, CoreError> {
        self.pending
            .as_ref()
            .map(HttpRequest::duplicate)
            .ok_or(CoreError::new(WRONG_STATE))
    }

    /// Passes in the answer to the outstanding request. The `register/start` answer runs the
    /// registration's Argon2id and builds every object of the commit.
    ///
    /// # Errors
    /// `invalid_server_response`; the server's code (`server_invalid_request` for a login name
    /// already taken is not distinguished, CRYPTO.md §5.9); `wrong_state`. After an error the
    /// flow is `"failed"`, except `wrong_state` and an error answer to `register/finish`, which
    /// leaves the commit outstanding so that the host may send it again.
    pub fn respond(&mut self, status: u16, body: &[u8]) -> Result<(), CoreError> {
        if self.pending.is_none() {
            return Err(CoreError::new(WRONG_STATE));
        }
        match core::mem::replace(&mut self.stage, Stage::Spent) {
            Stage::Start(started) => {
                self.pending = None;
                let answer: RegisterStartResponse = http::json(status, body)?;
                let pending = (*started).finish(&mut self.rng, &answer)?;
                self.input.secret_key =
                    Zeroizing::new(pending.emergency_kit().secret_key().to_owned());
                self.stage = Stage::Kit(Box::new(pending));
                Ok(())
            }
            Stage::Commit(pending) => match http::empty(status, body) {
                Ok(()) => {
                    pending.finalize()?;
                    self.pending = None;
                    self.stage = Stage::Done;
                    Ok(())
                }
                Err(e) => {
                    // The outcome may be unknown (a proxy's page); the byte-identical repeat
                    // is safe, so the commit stays outstanding.
                    self.stage = Stage::Commit(pending);
                    Err(e)
                }
            },
            other => {
                self.stage = other;
                Err(CoreError::new(WRONG_STATE))
            }
        }
    }

    /// The Emergency Kit, once, after the `register/start` answer (state `"confirm_kit"`).
    ///
    /// # Errors
    /// `already_shown` on a second call; `wrong_state` before the kit exists.
    #[wasm_bindgen(js_name = emergencyKit)]
    pub fn emergency_kit(&mut self) -> Result<EmergencyKit, CoreError> {
        let Stage::Kit(pending) = &self.stage else {
            return Err(CoreError::new(WRONG_STATE));
        };
        if self.kit_shown {
            return Err(CoreError::new(ALREADY_SHOWN));
        }
        self.kit_shown = true;
        let kit = pending.emergency_kit();
        Ok(EmergencyKit {
            server_origin: kit.server_origin().to_owned(),
            login_name: kit.login_name().to_owned(),
            secret_key: Zeroizing::new(kit.secret_key().to_owned()),
            recovery_code: kit.recovery_code().map(|c| Zeroizing::new(c.to_owned())),
        })
    }

    /// Confirms the kit with the last group of four characters of the Secret Key (§7), after
    /// it was shown. Releases the commit (`register/finish`).
    ///
    /// # Errors
    /// `emergency_kit_not_confirmed` if `typed` does not match (the state stays
    /// `"confirm_kit"`); `wrong_state` before the kit was shown.
    #[wasm_bindgen(js_name = confirmKit)]
    pub fn confirm_kit(&mut self, typed: &str) -> Result<(), CoreError> {
        if !self.kit_shown {
            return Err(CoreError::new(WRONG_STATE));
        }
        let Stage::Kit(pending) = &mut self.stage else {
            return Err(CoreError::new(WRONG_STATE));
        };
        pending.confirm_kit(typed)?;
        let request = HttpRequest::post(paths::REGISTER_FINISH, pending.commit_request()?, None)?;
        if let Stage::Kit(pending) = core::mem::replace(&mut self.stage, Stage::Spent) {
            self.stage = Stage::Commit(pending);
        }
        self.pending = Some(request);
        Ok(())
    }

    /// After `"done"`: the first session's login with the signup's credentials (module docs).
    /// Consumes the flow.
    ///
    /// # Errors
    /// `wrong_state` unless the state is `"done"`; as [`LoginFlow::start`].
    pub fn login(self) -> Result<LoginFlow, CoreError> {
        let SignupFlow { input, stage, .. } = self;
        match stage {
            Stage::Done => LoginFlow::begin(input, None, Purpose::Session),
            _ => Err(CoreError::new(WRONG_STATE)),
        }
    }
}
