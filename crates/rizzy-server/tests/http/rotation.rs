//! Key rotation end to end over HTTP ([ADR 0025]; CRYPTO.md §11.6, §11.8): real clients
//! (`rizzy-client`, the dev-only edge ADR 0016 §4 owner decision 4 admits) sign up, log in,
//! enrol, authenticate their devices, write items, sync, and rotate through the router, over the
//! real bridge between the two domains and a real `SQLite` database.
//!
//! - [`a_standard_rotation_commits_retries_and_is_followed`]: a standard rotation that keeps the
//!   recovery code; an upload that lands between the rotator's Fetch and its commit makes the
//!   commit `409 state_conflict` with nothing changed, and the client's retry rule rebuilds and
//!   commits; a byte-identical resend succeeds; a device that did not rotate gets `stale_epoch`
//!   for an op at the old epoch, then follows through its grant and reads every item.
//! - [`a_revocation_with_a_full_rotation_locks_the_device_out`]: suspension, then the revocation
//!   with a full rotation in one commit; the revoked device can no longer authenticate, the
//!   rotator reads everything at the new epoch, and a new login verifies the new bundle.
//! - [`an_upload_racing_a_commit_is_ordered_over_http`]: ADR 0025 §5's race through the real
//!   commit path, on a multi-threaded runtime: exactly one of the upload and the commit wins.
//!
//! [ADR 0025]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0025-rotation-vault-half.md

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use chacha20::ChaCha20Rng;
use chacha20::rand_core::SeedableRng as _;
use rizzy_client::ClientError;
use rizzy_client::account::VerifiedAccount;
use rizzy_client::device::{DeviceState, UnlockedDevice};
use rizzy_client::items::{FieldEdit, FieldKey, ItemId, ItemType, Value};
use rizzy_client::login::{Enrolled, LoggedIn, LoginInput, start_login};
use rizzy_client::rotation::{
    ConflictOutcome, RevokeDevice, RotationLevel, RotationOptions, start_rotation,
};
use rizzy_client::session::{DeviceSession, device_auth_finish, device_auth_start};
use rizzy_client::signup::{DeviceKind, SignedUp, SignupInput, start_signup};
use rizzy_client::sync::{Authors, VaultSync};
use rizzy_client::unlock::{account_state_query, apply_device_grants, verify_unlock};
use rizzy_domain_auth::types::{ErrorCode, SessionToken};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::common::{ORIGIN, Reply, Server, block_on, send_via};

/// Every test account's master password.
pub(crate) const PASSWORD: &str = "correct horse battery staple";

/// The login name.
pub(crate) const NAME: &str = "alice";

/// The item field every test writes.
pub(crate) const FIELD: &str = "login.password";

/// The host's wall clock.
pub(crate) fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

/// How a request authenticates.
pub(crate) enum Auth<'a> {
    /// No session.
    None,
    /// A bearer token alone (an OPAQUE or recovery session).
    Bearer(&'a SessionToken),
    /// A device session: the bearer token and the `device-request` signature (CRYPTO.md §5.10).
    Device(&'a mut DeviceSession, &'a UnlockedDevice),
}

/// Sends `method path` with `body`.
pub(crate) async fn call(
    server: &Server,
    method: &str,
    path: &str,
    body: Vec<u8>,
    auth: Auth<'_>,
) -> Reply {
    server.send(request(method, path, body, auth)).await
}

/// The request `method path` with `body`, authenticated by `auth`.
pub(crate) fn request(method: &str, path: &str, body: Vec<u8>, auth: Auth<'_>) -> Request<Body> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    match auth {
        Auth::None => {}
        Auth::Bearer(token) => {
            request = request.header(
                "authorization",
                format!("Bearer {}", token.to_b64url().as_str()),
            );
        }
        Auth::Device(session, unlocked) => {
            let signature = session.sign_request(unlocked, method, path, &body).unwrap();
            request = request
                .header(
                    "authorization",
                    format!("Bearer {}", session.bearer_token().to_b64url().as_str()),
                )
                .header(
                    "rizzy-request-counter",
                    signature.request_counter.to_string(),
                )
                .header("rizzy-request-signature", signature.signature.to_b64url());
        }
    }
    request.body(Body::from(body)).unwrap()
}

/// `POST path` with `value` as JSON.
pub(crate) async fn post<T: Serialize>(
    server: &Server,
    path: &str,
    value: &T,
    auth: Auth<'_>,
) -> Reply {
    call(
        server,
        "POST",
        path,
        serde_json::to_vec(value).unwrap(),
        auth,
    )
    .await
}

/// `POST path` that must answer `204 No Content`.
pub(crate) async fn post_empty<T: Serialize>(
    server: &Server,
    path: &str,
    value: &T,
    auth: Auth<'_>,
) {
    let reply = post(server, path, value, auth).await;
    assert_eq!(
        reply.status,
        StatusCode::NO_CONTENT,
        "{path}: {}",
        String::from_utf8_lossy(&reply.body)
    );
}

/// Signs up a durable device, with a recovery code when `recovery`; returns the Secret Key and
/// the code, as the Emergency Kit shows them.
pub(crate) async fn signup(
    server: &Server,
    rng: &mut ChaCha20Rng,
    recovery: bool,
) -> (SignedUp, String, Option<String>) {
    let input = SignupInput {
        server_origin: ORIGIN,
        login_name: NAME,
        password: PASSWORD,
        invite: None,
        issue_recovery_code: recovery,
        device_kind: DeviceKind::DesktopCli,
        now_ms: now_ms(),
    };
    let (started, request) = start_signup(rng, &input).unwrap();
    let reply = post(server, "/api/v1/register/start", &request, Auth::None).await;
    let mut pending = started.finish(rng, &reply.json()).unwrap();
    let kit = pending.emergency_kit();
    let code = kit.recovery_code().map(str::to_owned);
    let sk = kit.secret_key().to_owned();
    let last = kit.secret_key().rsplit('-').next().unwrap().to_owned();
    pending.confirm_kit(&last).unwrap();
    post_empty(
        server,
        "/api/v1/register/finish",
        pending.commit_request().unwrap(),
        Auth::None,
    )
    .await;
    (pending.finalize().unwrap(), sk, code)
}

/// Device authentication (CRYPTO.md §5.10).
pub(crate) async fn device_session(
    server: &Server,
    state: &DeviceState,
    unlocked: &UnlockedDevice,
) -> Result<DeviceSession, StatusCode> {
    let start = post(
        server,
        "/api/v1/device-auth/start",
        &device_auth_start(state),
        Auth::None,
    )
    .await;
    if start.status != StatusCode::OK {
        return Err(start.status);
    }
    let finish = device_auth_finish(state, unlocked, &start.json()).unwrap();
    let reply = post(server, "/api/v1/device-auth/finish", &finish, Auth::None).await;
    if reply.status != StatusCode::OK {
        return Err(reply.status);
    }
    Ok(DeviceSession::new(state, reply.json()))
}

/// The authentication of a login: over the device session when there is one.
fn reauth_auth<'a>(device: &'a mut Option<(&mut DeviceSession, &UnlockedDevice)>) -> Auth<'a> {
    match device {
        Some((session, unlocked)) => Auth::Device(session, unlocked),
        None => Auth::None,
    }
}

/// A copy of a bearer token, for a request sent while its owner is borrowed.
pub(crate) fn copy_token(token: &SessionToken) -> SessionToken {
    SessionToken::new(Zeroizing::new(*token.expose_secret()))
}

/// An OPAQUE login; with `device`, a re-authentication over that device's session, which the
/// server binds to the device (CRYPTO.md §11.6 step 1, §11.8 step 0).
async fn login(
    server: &Server,
    rng: &mut ChaCha20Rng,
    sk: &str,
    mut device: Option<(&mut DeviceSession, &UnlockedDevice)>,
) -> LoggedIn {
    let input = LoginInput {
        server_origin: ORIGIN,
        login_name: NAME,
        secret_key: sk,
        password: PASSWORD,
    };
    let (started, request) = start_login(rng, &input).unwrap();
    let reply = post(
        server,
        "/api/v1/login/start",
        &request,
        reauth_auth(&mut device),
    )
    .await;
    let (awaiting, finish) = started.finish(rng, &reply.json(), None).unwrap();
    let reply = post(
        server,
        "/api/v1/login/finish",
        &finish,
        reauth_auth(&mut device),
    )
    .await;
    awaiting.complete(reply.json()).unwrap()
}

/// A device of the test: its state, keys, session, vault and the authors it verifies with.
pub(crate) struct Client {
    /// The device state.
    pub(crate) state: DeviceState,
    /// Its unlocked keys.
    pub(crate) unlocked: UnlockedDevice,
    /// Its device session.
    pub(crate) session: DeviceSession,
    /// The personal vault.
    vault: VaultSync,
    /// The account's authors.
    authors: Authors,
}

impl Client {
    /// The client of a fresh signup.
    pub(crate) async fn signed_up(server: &Server, up: SignedUp) -> Self {
        let state = up.device.unwrap();
        let unlocked = up.unlocked;
        let session = device_session(server, &state, &unlocked).await.unwrap();
        let vault = VaultSync::new(up.vault_key, &unlocked, 1).unwrap();
        let authors = Authors::from_statements(&[up.own_certificate], &[]).unwrap();
        Self {
            state,
            unlocked,
            session,
            vault,
            authors,
        }
    }

    /// The client of a device enrolled by login.
    async fn enrolled(server: &Server, enrolled: Enrolled) -> Self {
        let Enrolled {
            device: state,
            unlocked,
            mut account,
            ..
        } = enrolled;
        let session = device_session(server, &state, &unlocked).await.unwrap();
        let vault_id = account.vault_ids().next().unwrap();
        let key = account.take_vault_key(vault_id).unwrap();
        let vault = VaultSync::new(key, &unlocked, 1).unwrap();
        let authors = Authors::from_account(&account).unwrap();
        Self {
            state,
            unlocked,
            session,
            vault,
            authors,
        }
    }

    /// The account answer over the device session, verified against the pin (CRYPTO.md §11.3).
    pub(crate) async fn account_view(&mut self, server: &Server) -> serde_json::Value {
        let query = account_state_query(&self.state);
        post(
            server,
            "/api/v1/account/state",
            &query,
            Auth::Device(&mut self.session, &self.unlocked),
        )
        .await
        .json()
    }

    /// Refreshes the pin and the authors (a device enrolled since, a rotation).
    async fn refresh(&mut self, server: &Server) -> VerifiedAccount {
        let view = self.account_view(server).await;
        let view = serde_json::from_value(view).unwrap();
        let account = verify_unlock(&mut self.state, &self.unlocked, &view, None).unwrap();
        self.authors = Authors::from_account(&account).unwrap();
        account
    }

    /// Fetches until complete.
    async fn fetch(&mut self, server: &Server) {
        loop {
            let request = self.vault.fetch_request().unwrap();
            let reply = post(
                server,
                "/api/v1/vault/fetch",
                &request,
                Auth::Device(&mut self.session, &self.unlocked),
            )
            .await;
            let response = reply.json();
            self.vault
                .apply_fetch(&self.authors, &response, now_ms())
                .unwrap();
            if response.complete {
                return;
            }
        }
    }

    /// Fetches, uploads everything queued, then Fetches until complete (ADR 0025 §2 step 1).
    /// Returns the refusals of the upload.
    pub(crate) async fn sync(&mut self, server: &Server, rng: &mut ChaCha20Rng) -> Vec<ErrorCode> {
        self.fetch(server).await;
        let mut rejected = Vec::new();
        while let Some(up) = self.vault.upload_request(rng, &self.unlocked).unwrap() {
            let reply = post(
                server,
                "/api/v1/vault/upload",
                &up,
                Auth::Device(&mut self.session, &self.unlocked),
            )
            .await;
            let outcome = self.vault.apply_upload_response(&reply.json()).unwrap();
            if !outcome.rejected.is_empty() {
                rejected.extend(outcome.rejected);
                break;
            }
        }
        self.fetch(server).await;
        rejected
    }

    /// Follows a rotation made elsewhere (CRYPTO.md §11.3 step 4): the grant of the new account
    /// key, its acknowledgement, the new pin and authors, and the new vault key adopted.
    async fn follow(&mut self, server: &Server, rng: &mut ChaCha20Rng) {
        let view = serde_json::from_value(self.account_view(server).await).unwrap();
        assert_eq!(
            verify_unlock(&mut self.state, &self.unlocked, &view, None).unwrap_err(),
            ClientError::AccountKeyRotated
        );
        let grants = call(
            server,
            "GET",
            "/api/v1/devices/grants",
            Vec::new(),
            Auth::Device(&mut self.session, &self.unlocked),
        )
        .await
        .json();
        let mut unlocked = self.state.unlock(PASSWORD).unwrap();
        let ack =
            apply_device_grants(rng, &mut self.state, &mut unlocked, &view, &grants, None).unwrap();
        self.unlocked = unlocked;
        post_empty(
            server,
            "/api/v1/devices/grants/ack",
            &ack,
            Auth::Device(&mut self.session, &self.unlocked),
        )
        .await;
        let mut account = self.refresh(server).await;
        let vault_id = account.vault_ids().next().unwrap();
        self.vault
            .adopt_vault_key(account.take_vault_key(vault_id).unwrap())
            .unwrap();
    }

    /// Creates an item with `value` in its password field.
    pub(crate) fn create(&mut self, rng: &mut ChaCha20Rng, value: &str) -> ItemId {
        let key = FieldKey::parse(FIELD.as_bytes()).unwrap();
        let value = Value::text(value).unwrap();
        self.vault
            .create_item(
                rng,
                &self.unlocked,
                ItemType::LOGIN,
                &[FieldEdit {
                    key: &key,
                    value: &value,
                }],
                now_ms(),
            )
            .unwrap()
    }

    /// Writes `value` into the password field of `item`.
    fn edit(&mut self, rng: &mut ChaCha20Rng, item: ItemId, value: &str) {
        let key = FieldKey::parse(FIELD.as_bytes()).unwrap();
        let value = Value::text(value).unwrap();
        self.vault
            .edit_item(
                rng,
                &self.unlocked,
                item,
                &[FieldEdit {
                    key: &key,
                    value: &value,
                }],
                now_ms(),
            )
            .unwrap();
    }

    /// The password field of `item`, as encoded bytes.
    pub(crate) fn read(&self, item: ItemId) -> Vec<u8> {
        self.vault
            .field_value(item, FIELD)
            .unwrap()
            .expose_secret()
            .to_vec()
    }
}

/// A login on a new device and its enrolment (CRYPTO.md §11.2 step 7).
async fn enrol(server: &Server, rng: &mut ChaCha20Rng, sk: &str) -> Enrolled {
    let logged_in = login(server, rng, sk, None).await;
    let token = copy_token(logged_in.bearer_token());
    let (pending, request) = logged_in
        .enrol(rng, DeviceKind::DesktopCli, now_ms())
        .unwrap();
    post_empty(
        server,
        "/api/v1/devices/enrol",
        &request,
        Auth::Bearer(&token),
    )
    .await;
    pending.finalize()
}

/// ADR 0025 §5: a standard rotation (CRYPTO.md §11.6) over HTTP, its `state_conflict` retry,
/// its byte-identical resend, a stale-epoch upload, and the other device following.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one story in the order of CRYPTO.md §11.6 and §11.3 step 4"
)]
fn a_standard_rotation_commits_retries_and_is_followed() {
    block_on(async {
        let server = Server::start().await;
        let mut rng = ChaCha20Rng::seed_from_u64(70);
        let (up, sk, code) = signup(&server, &mut rng, true).await;
        let code = code.unwrap();
        let mut a = Client::signed_up(&server, up).await;
        let first = a.create(&mut rng, "one");
        let second = a.create(&mut rng, "two");
        assert!(a.sync(&server, &mut rng).await.is_empty());

        let mut c = Client::enrolled(&server, enrol(&server, &mut rng, &sk).await).await;
        assert!(c.sync(&server, &mut rng).await.is_empty());
        assert_eq!(c.read(first), a.read(first));
        a.refresh(&server).await;
        assert!(a.sync(&server, &mut rng).await.is_empty());

        // A re-authenticates over its device session and builds the rotation.
        let reauth = login(&server, &mut rng, &sk, Some((&mut a.session, &a.unlocked))).await;
        let options = RotationOptions {
            level: RotationLevel::Standard,
            revoke: None,
            recovery_code: Some(&code),
            now_ms: now_ms(),
        };
        let mut pending = start_rotation(
            &mut rng,
            reauth,
            &a.state,
            &a.unlocked,
            &[&a.vault],
            &options,
        )
        .unwrap();

        // C's upload lands between A's Fetch and A's commit: refused, and nothing changed.
        c.edit(&mut rng, first, "c-was-here");
        assert!(c.sync(&server, &mut rng).await.is_empty());
        let before = a.account_view(&server).await;
        let token = copy_token(pending.bearer_token());
        let reply = post(
            &server,
            "/api/v1/account/commit",
            pending.commit_request(),
            Auth::Bearer(&token),
        )
        .await;
        assert_eq!(reply.status, StatusCode::CONFLICT);
        assert_eq!(reply.error(), "state_conflict");
        assert_eq!(a.account_view(&server).await, before);

        // The retry rule: fetch, re-read the state, rebuild the vault half, resend.
        assert!(a.sync(&server, &mut rng).await.is_empty());
        let view = post(
            &server,
            "/api/v1/account/state",
            &pending.state_query(),
            Auth::Bearer(&token),
        )
        .await
        .json();
        assert_eq!(
            pending
                .on_state_conflict(&mut rng, &view, &a.unlocked, &[&a.vault])
                .unwrap(),
            ConflictOutcome::Resend
        );
        post_empty(
            &server,
            "/api/v1/account/commit",
            pending.commit_request(),
            Auth::Bearer(&token),
        )
        .await;
        // A byte-identical resend (a crash after sending) is success.
        post_empty(
            &server,
            "/api/v1/account/commit",
            pending.commit_request(),
            Auth::Bearer(&token),
        )
        .await;
        let done = pending
            .finalize(&mut rng, &mut a.state, &mut a.unlocked, &mut [&mut a.vault])
            .unwrap();
        assert!(done.dropped_items.is_empty());
        a.authors = done.authors;
        assert_eq!(a.vault.vault_key_epoch(), 1);
        assert!(a.sync(&server, &mut rng).await.is_empty());
        assert_eq!(a.read(first), c.read(first));
        a.edit(&mut rng, second, "two-after");
        assert!(a.sync(&server, &mut rng).await.is_empty());

        // C still writes at the old epoch: `stale_epoch` (ADR 0021 §9, ADR 0025 §4).
        c.edit(&mut rng, first, "stale");
        assert_eq!(c.sync(&server, &mut rng).await, vec![ErrorCode::StaleEpoch]);
        // Nothing is re-sent unchanged: C must adopt the new vault key first.
        assert_eq!(
            c.vault.upload_request(&mut rng, &c.unlocked).unwrap_err(),
            ClientError::VaultKeyRotated
        );

        // C follows (CRYPTO.md §11.3 step 4): its grant, the new self-grant, every item.
        c.follow(&server, &mut rng).await;
        // ADR 0025 §4: the refused op is re-issued under a fresh item key at the new epoch with
        // the same `device_seq`, and stored.
        assert!(c.sync(&server, &mut rng).await.is_empty());
        assert_eq!(c.read(second), a.read(second));
        assert!(a.sync(&server, &mut rng).await.is_empty());
        let stale = Value::text("stale").unwrap();
        assert_eq!(c.read(first), stale.expose_secret());
        assert_eq!(a.read(first), stale.expose_secret());
        // C writes again, and can rotate itself: nothing of its chain is stuck.
        c.edit(&mut rng, first, "c-again");
        assert!(c.sync(&server, &mut rng).await.is_empty());
        assert!(a.sync(&server, &mut rng).await.is_empty());
        assert_eq!(a.read(first), c.read(first));
        let c_reauth = login(&server, &mut rng, &sk, Some((&mut c.session, &c.unlocked))).await;
        start_rotation(
            &mut rng,
            c_reauth,
            &c.state,
            &c.unlocked,
            &[&c.vault],
            &RotationOptions {
                level: RotationLevel::Standard,
                revoke: None,
                recovery_code: Some(&code),
                now_ms: now_ms(),
            },
        )
        .unwrap();

        // A device enrolled after the rotation holds no old key: it reads every item through the
        // re-wrapped rows alone.
        let mut d = Client::enrolled(&server, enrol(&server, &mut rng, &sk).await).await;
        assert_eq!(d.vault.vault_key_epoch(), 1);
        assert!(d.sync(&server, &mut rng).await.is_empty());
        assert_eq!(d.read(first), a.read(first));
        assert_eq!(d.read(second), a.read(second));
    });
}
/// Upload-versus-rotation races over HTTP: `RIZZY_TEST_HTTP_RACE_RUNS`, or 3 (each run pays a
/// re-authentication and, when the rotation wins, the other device's password unlock). The
/// ADR 0025 §5 figure of 1,000 runs is `rizzy-domain-vault`'s race test; this one checks the
/// same rule through the real commit path.
fn http_race_runs() -> u32 {
    std::env::var("RIZZY_TEST_HTTP_RACE_RUNS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3)
}

/// Runs `f` on a multi-threaded runtime, so spawned requests run truly in parallel.
fn block_on_threads<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

/// ADR 0025 §5 through the real commit path: `/account/commit` (`AuthService::commit_change`,
/// the bridge's vault half and the `cas_state`, in one transaction under the account lock)
/// racing `/vault/upload` of an op built from the state before the rotation, both on tasks of a
/// multi-threaded runtime. Exactly one of "upload stored, commit `409 state_conflict`" or
/// "commit `204`, upload `stale_epoch`" happens in every run, never both and never neither; in
/// the second case the other device follows, re-issues its op, and the next run starts at the
/// new epoch. Which one wins is up to the scheduler, so the test does not require both.
#[test]
fn an_upload_racing_a_commit_is_ordered_over_http() {
    block_on_threads(async {
        let server = Server::start().await;
        let mut rng = ChaCha20Rng::seed_from_u64(72);
        let (up, sk, _) = signup(&server, &mut rng, false).await;
        let mut a = Client::signed_up(&server, up).await;
        let item = a.create(&mut rng, "start");
        assert!(a.sync(&server, &mut rng).await.is_empty());
        let mut c = Client::enrolled(&server, enrol(&server, &mut rng, &sk).await).await;
        assert!(c.sync(&server, &mut rng).await.is_empty());
        a.refresh(&server).await;
        let (mut upload_first, mut commit_first) = (0u32, 0u32);
        for run in 0..http_race_runs() {
            assert!(a.sync(&server, &mut rng).await.is_empty());
            let reauth = login(&server, &mut rng, &sk, Some((&mut a.session, &a.unlocked))).await;
            let pending = start_rotation(
                &mut rng,
                reauth,
                &a.state,
                &a.unlocked,
                &[&a.vault],
                &RotationOptions {
                    level: RotationLevel::Standard,
                    revoke: None,
                    recovery_code: None,
                    now_ms: now_ms(),
                },
            )
            .unwrap();
            let token = copy_token(pending.bearer_token());
            let commit = request(
                "POST",
                "/api/v1/account/commit",
                serde_json::to_vec(pending.commit_request()).unwrap(),
                Auth::Bearer(&token),
            );
            c.edit(&mut rng, item, &format!("race-{run}"));
            let upload = c
                .vault
                .upload_request(&mut rng, &c.unlocked)
                .unwrap()
                .unwrap();
            let upload = request(
                "POST",
                "/api/v1/vault/upload",
                serde_json::to_vec(&upload).unwrap(),
                Auth::Device(&mut c.session, &c.unlocked),
            );
            let (commit, upload) = if run % 2 == 0 {
                let commit = tokio::spawn(send_via(server.router.clone(), commit));
                let upload = tokio::spawn(send_via(server.router.clone(), upload));
                (commit.await.unwrap(), upload.await.unwrap())
            } else {
                let upload = tokio::spawn(send_via(server.router.clone(), upload));
                let commit = tokio::spawn(send_via(server.router.clone(), commit));
                (commit.await.unwrap(), upload.await.unwrap())
            };
            assert_eq!(upload.status, StatusCode::OK);
            let outcome = c.vault.apply_upload_response(&upload.json()).unwrap();
            match (
                commit.status,
                outcome.acknowledged,
                outcome.rejected.as_slice(),
            ) {
                (StatusCode::CONFLICT, 1, []) => {
                    assert_eq!(commit.error(), "state_conflict");
                    upload_first += 1;
                }
                (StatusCode::NO_CONTENT, 0, [ErrorCode::StaleEpoch]) => {
                    commit_first += 1;
                    let done = pending
                        .finalize(&mut rng, &mut a.state, &mut a.unlocked, &mut [&mut a.vault])
                        .unwrap();
                    a.authors = done.authors;
                    c.follow(&server, &mut rng).await;
                }
                (status, acknowledged, rejected) => {
                    panic!("run {run}: commit {status}, upload {acknowledged} stored, {rejected:?}")
                }
            }
            assert!(c.sync(&server, &mut rng).await.is_empty());
            assert!(a.sync(&server, &mut rng).await.is_empty());
            assert_eq!(a.read(item), c.read(item));
        }
        assert_eq!(upload_first + commit_first, http_race_runs());
    });
}

/// ADR 0025 §5 and CRYPTO.md §11.8: suspend a device, then revoke it with a full rotation in
/// one commit. The revoked device is locked out; the rotator reads every item, its own and the
/// revoked device's, at the new epoch; a new login verifies the new bundle.
#[test]
fn a_revocation_with_a_full_rotation_locks_the_device_out() {
    block_on(async {
        let server = Server::start().await;
        let mut rng = ChaCha20Rng::seed_from_u64(71);
        let (up, sk, _) = signup(&server, &mut rng, false).await;
        let mut a = Client::signed_up(&server, up).await;
        let own = a.create(&mut rng, "a");
        assert!(a.sync(&server, &mut rng).await.is_empty());
        let mut b = Client::enrolled(&server, enrol(&server, &mut rng, &sk).await).await;
        b.sync(&server, &mut rng).await;
        let theirs = b.create(&mut rng, "b");
        assert!(b.sync(&server, &mut rng).await.is_empty());
        a.refresh(&server).await;
        assert!(a.sync(&server, &mut rng).await.is_empty());
        assert_eq!(a.read(theirs), b.read(theirs));

        // Phase 1 (§11.8 step 0): A, re-authenticated over its own device, suspends B.
        let reauth = login(&server, &mut rng, &sk, Some((&mut a.session, &a.unlocked))).await;
        let b_id = Base64UrlUnpadded::encode_string(&b.state.device_id().to_bytes());
        let reply = post(
            &server,
            "/api/v1/devices/suspend",
            &serde_json::json!({ "device_id": b_id }),
            Auth::Bearer(reauth.bearer_token()),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK);
        let head = reply.json::<serde_json::Value>()["last_accepted_device_seq"]
            .as_u64()
            .unwrap();
        assert!(head >= 1);
        // B's session ended with the suspension.
        let refused = post(
            &server,
            "/api/v1/vault/fetch",
            &b.vault.fetch_request().unwrap(),
            Auth::Device(&mut b.session, &b.unlocked),
        )
        .await;
        assert_eq!(refused.status, StatusCode::UNAUTHORIZED);

        // Steps 1–3: the revocation and the full rotation, one commit.
        assert!(a.sync(&server, &mut rng).await.is_empty());
        let options = RotationOptions {
            level: RotationLevel::Full,
            revoke: Some(RevokeDevice {
                device_id: b.state.device_id(),
                last_accepted_device_seq: head,
            }),
            recovery_code: None,
            now_ms: now_ms(),
        };
        let pending = start_rotation(
            &mut rng,
            reauth,
            &a.state,
            &a.unlocked,
            &[&a.vault],
            &options,
        )
        .unwrap();
        assert!(pending.commit_request().bundle.is_some());
        assert!(pending.commit_request().device_grants.is_empty());
        let token = copy_token(pending.bearer_token());
        post_empty(
            &server,
            "/api/v1/account/commit",
            pending.commit_request(),
            Auth::Bearer(&token),
        )
        .await;
        let done = pending
            .finalize(&mut rng, &mut a.state, &mut a.unlocked, &mut [&mut a.vault])
            .unwrap();
        a.authors = done.authors;
        assert_eq!(a.state.pin().state().identity_epoch, 1);

        // B is locked out for good; A reads everything at the new epoch.
        assert_eq!(
            device_session(&server, &b.state, &b.unlocked)
                .await
                .unwrap_err(),
            StatusCode::UNAUTHORIZED
        );
        assert!(a.sync(&server, &mut rng).await.is_empty());
        assert_eq!(a.vault.vault_key_epoch(), 1);
        // A device enrolled after the rotation reads both items through the re-wrapped rows
        // alone, and accepts B's ops up to H under B's re-issued certificate.
        let mut d = Client::enrolled(&server, enrol(&server, &mut rng, &sk).await).await;
        assert_eq!(d.vault.vault_key_epoch(), 1);
        assert!(d.sync(&server, &mut rng).await.is_empty());
        assert_eq!(d.read(own), a.read(own));
        assert_eq!(d.read(theirs), a.read(theirs));
        // A new login verifies the new bundle chain and state.
        let again = login(&server, &mut rng, &sk, None).await;
        assert_eq!(again.account().state().identity_epoch, 1);
        assert_eq!(again.account().state().account_key_epoch, 1);
    });
}
