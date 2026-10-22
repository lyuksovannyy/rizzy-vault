// SPDX-License-Identifier: AGPL-3.0-only

//! Listing and ending sessions (ADR 0075 §4–§6, §11 "Domain"). Every test here runs on
//! PostgreSQL too when `RIZZY_TEST_POSTGRES_URL` is set ([`Env::on_either_engine`]), for the
//! four new queries' parity (§10).

use rizzy_core::ids::SessionId;
use rizzy_core::opaque::{PasswordInput, client_login_start};
use rizzy_core::secret_key::SecretKey;
use rizzy_domain_auth::config::FRESH_SESSION_MS;
use rizzy_domain_auth::{AuthError, Session, SessionKind};
use rizzy_proto::auth::LoginStartRequest;
use rizzy_proto::limits::MAX_SESSIONS_LISTED;
use rizzy_proto::session::{SessionKindView, SessionListResponse};
use rizzy_proto::wire::{SessionToken, Text};

use crate::common::{Client, DeviceSession, Env, block_on, bytes, request, wid};
use crate::requests::password_change;

/// 72 h in ms: the default recovery wait.
const WAIT: u64 = 72 * 3_600_000;

impl Env {
    /// A plain OPAQUE login (the web vault's): its token and session.
    async fn web(&mut self, client: &Client) -> (SessionToken, Session) {
        let login = self.login(client).await;
        let session = self.bearer(&login.response.session_token).await;
        (login.response.session_token, session)
    }

    /// A device session of the client's first device: the client side and the session.
    async fn native(&mut self, client: &Client) -> (DeviceSession, Session) {
        let mut ds = self.device_auth(client, &client.devices[0]).await.unwrap();
        let session = self
            .signed(client, &client.devices[0], &mut ds, b"")
            .await
            .unwrap();
        (ds, session)
    }

    /// An OPAQUE re-authentication bound to the device of `device`.
    async fn bound(&mut self, client: &Client, device: &Session) -> (SessionToken, Session) {
        let (name, password) = (client.name.clone(), client.password.clone());
        let login = self
            .login_as(&name, &password, &client.secret_key, None, Some(device))
            .await
            .unwrap();
        let session = self.bearer(&login.response.session_token).await;
        (login.response.session_token, session)
    }

    /// Opens a pending recovery and waits it out.
    async fn wait_out_recovery(&mut self, client: &Client) {
        let token = client.recovery_token();
        let source = self.source.clone();
        self.svc
            .recovery_start(&client.name, &token, &source, self.now)
            .await
            .unwrap();
        self.tick(WAIT);
    }

    /// The recovery-only session of a recovery [`Env::wait_out_recovery`] waited out.
    async fn recovery_session(&mut self, client: &Client) -> (SessionToken, Session) {
        let token = client.recovery_token();
        let source = self.source.clone();
        let release = self
            .svc
            .recovery_complete(&mut self.rng, &client.name, &token, &source, self.now)
            .await
            .unwrap();
        let session = self.bearer(&release.session_token).await;
        (release.session_token, session)
    }

    /// Whether a bearer token still authenticates.
    async fn live(&self, token: &SessionToken) -> bool {
        self.svc
            .authenticate_request(token.expose_secret(), None, request(b"{}"), self.now)
            .await
            .is_ok()
    }

    /// Whether a device session still authenticates a signed request.
    async fn live_device(&self, client: &Client, ds: &mut DeviceSession) -> bool {
        self.signed(client, &client.devices[0], ds, b"")
            .await
            .is_ok()
    }

    /// The caller's list.
    async fn list(&self, session: &Session) -> SessionListResponse {
        self.svc.list_sessions(session, self.now).await.unwrap()
    }
}

/// The ids of a list, in order.
fn ids(list: &SessionListResponse) -> Vec<[u8; 16]> {
    list.sessions
        .iter()
        .map(|s| s.session_id.to_bytes())
        .collect()
}

/// §11 item 1: the account's own unexpired sessions, newest first, `current` exactly once,
/// `device_id` on device and bound sessions only; a recovery-only caller may not list.
#[test]
fn list_shows_the_accounts_live_sessions() {
    block_on(async {
        let mut env = Env::on_either_engine(7501, |_| {}).await;
        let client = env.signup("sam", "pw").await;
        let other = env.signup("tess", "pw").await;

        // A session that has expired but is not swept yet.
        let (_, expired) = env.web(&client).await;
        env.tick(3_600_000);
        let (_, theirs) = env.web(&other).await;

        let (_, web) = env.web(&client).await;
        env.tick(1);
        let (_, device) = env.native(&client).await;
        env.tick(1);
        let (_, bound) = env.bound(&client, &device).await;
        env.tick(1);
        // Two sessions created in the same millisecond: by `session_id` bytes, ascending.
        let (_, twin_a) = env.native(&client).await;
        let (_, twin_b) = env.native(&client).await;
        let (low, high) = if twin_a.session_id.to_bytes() < twin_b.session_id.to_bytes() {
            (twin_a, twin_b)
        } else {
            (twin_b, twin_a)
        };

        let list = env.list(&web).await;
        assert!(!list.truncated);
        assert_eq!(
            ids(&list),
            [
                low.session_id.to_bytes(),
                high.session_id.to_bytes(),
                bound.session_id.to_bytes(),
                device.session_id.to_bytes(),
                web.session_id.to_bytes(),
            ]
        );
        assert!(!ids(&list).contains(&expired.session_id.to_bytes()));
        assert!(!ids(&list).contains(&theirs.session_id.to_bytes()));
        let current: Vec<_> = list.sessions.iter().filter(|s| s.current).collect();
        assert_eq!(current.len(), 1);
        assert_eq!(current[0].session_id.to_bytes(), web.session_id.to_bytes());

        let by_id = |id: SessionId| {
            list.sessions
                .iter()
                .find(|s| s.session_id.to_bytes() == id.to_bytes())
                .unwrap()
                .clone()
        };
        let device_id = wid(client.devices[0].id.to_bytes());
        let w = by_id(web.session_id);
        assert_eq!((w.kind, w.device_id), (SessionKindView::Opaque, None));
        assert_eq!(w.created_at_ms, web.created_at_ms);
        assert_eq!(w.expires_at_ms, web.expires_at_ms);
        let d = by_id(device.session_id);
        assert_eq!(
            (d.kind, d.device_id),
            (SessionKindView::Device, Some(device_id))
        );
        let b = by_id(bound.session_id);
        assert_eq!(
            (b.kind, b.device_id),
            (SessionKindView::Opaque, Some(device_id))
        );

        // A device caller sees the same list, with itself marked.
        let from_device = env.list(&device).await;
        assert_eq!(ids(&from_device), ids(&list));
        let marked: Vec<_> = from_device.sessions.iter().filter(|s| s.current).collect();
        assert_eq!(marked.len(), 1);
        assert_eq!(
            marked[0].session_id.to_bytes(),
            device.session_id.to_bytes()
        );

        // A recovery-only caller may not list.
        env.wait_out_recovery(&client).await;
        let (_, recovery) = env.recovery_session(&client).await;
        assert_eq!(recovery.kind, SessionKind::Recovery);
        assert!(matches!(
            env.svc.list_sessions(&recovery, env.now).await,
            Err(AuthError::Unauthorized)
        ));
    });
}

/// §11 item 1: 257 live sessions list as 256 and `truncated`.
#[test]
fn list_is_bounded() {
    block_on(async {
        let mut env = Env::on_either_engine(7502, |_| {}).await;
        let client = env.signup("uma", "pw").await;
        for _ in 0..MAX_SESSIONS_LISTED {
            env.device_auth(&client, &client.devices[0]).await.unwrap();
        }
        env.tick(1);
        // The 257th, and the newest: listed first.
        let (_, caller) = env.native(&client).await;
        let list = env.list(&caller).await;
        assert_eq!(list.sessions.len(), MAX_SESSIONS_LISTED);
        assert!(list.truncated);
        assert_eq!(
            list.sessions.as_slice()[0].session_id.to_bytes(),
            caller.session_id.to_bytes()
        );
        assert!(list.sessions.as_slice()[0].current);
        let rest = &ids(&list)[1..];
        assert!(rest.windows(2).all(|w| w[0] < w[1]));
    });
}

/// §11 item 2: sign-out works for each kind; the token is then unknown, and a repeat answers
/// `Unauthorized`.
#[test]
fn current_end_for_every_kind() {
    block_on(async {
        let mut env = Env::on_either_engine(7503, |_| {}).await;
        let client = env.signup("vic", "pw").await;
        env.wait_out_recovery(&client).await;

        let (token, web) = env.web(&client).await;
        env.svc.end_current_session(&web, env.now).await.unwrap();
        assert!(!env.live(&token).await);
        assert!(matches!(
            env.svc.end_current_session(&web, env.now).await,
            Err(AuthError::Unauthorized)
        ));

        let (mut ds, device) = env.native(&client).await;
        env.svc.end_current_session(&device, env.now).await.unwrap();
        assert!(!env.live_device(&client, &mut ds).await);
        assert!(matches!(
            env.svc.end_current_session(&device, env.now).await,
            Err(AuthError::Unauthorized)
        ));

        let (token, recovery) = env.recovery_session(&client).await;
        env.svc
            .end_current_session(&recovery, env.now)
            .await
            .unwrap();
        assert!(!env.live(&token).await);
        assert!(matches!(
            env.svc.end_current_session(&recovery, env.now).await,
            Err(AuthError::Unauthorized)
        ));
    });
}

/// §11 item 3, the callers: fresh OPAQUE and device accepted, stale OPAQUE refused with
/// `FreshSessionRequired`, recovery-only with `Unauthorized`.
#[test]
fn end_caller_rules() {
    block_on(async {
        let mut env = Env::on_either_engine(7504, |_| {}).await;
        let client = env.signup("wes", "pw").await;
        env.wait_out_recovery(&client).await;

        let (stale_token, stale) = env.web(&client).await;
        env.tick(FRESH_SESSION_MS + 1);
        let (t1, s1) = env.web(&client).await;
        let (t2, s2) = env.web(&client).await;
        assert!(matches!(
            env.svc.end_session(&stale, s1.session_id, env.now).await,
            Err(AuthError::FreshSessionRequired)
        ));
        assert!(matches!(
            env.svc.end_other_sessions(&stale, env.now).await,
            Err(AuthError::FreshSessionRequired)
        ));
        assert!(env.live(&t1).await);

        // A fresh OPAQUE caller ends another OPAQUE session.
        let (fresh_token, fresh) = env.web(&client).await;
        env.svc
            .end_session(&fresh, s1.session_id, env.now)
            .await
            .unwrap();
        assert!(!env.live(&t1).await);
        assert!(env.live(&fresh_token).await);

        // A device caller, long after its creation, ends one too: it needs no freshness.
        let (_, device) = env.native(&client).await;
        env.tick(FRESH_SESSION_MS + 1);
        env.svc
            .end_session(&device, s2.session_id, env.now)
            .await
            .unwrap();
        assert!(!env.live(&t2).await);

        // A recovery-only caller is refused, for R3 and R4.
        let (_, recovery) = env.recovery_session(&client).await;
        assert!(matches!(
            env.svc
                .end_session(&recovery, stale.session_id, env.now)
                .await,
            Err(AuthError::Unauthorized)
        ));
        assert!(matches!(
            env.svc.end_other_sessions(&recovery, env.now).await,
            Err(AuthError::Unauthorized)
        ));
        assert!(env.live(&stale_token).await);
    });
}

/// §11 item 3, the targets: a device session is refused; another account's, an unknown and
/// an expired id get the same `NotFound`; the caller's own id ends the caller.
#[test]
fn end_target_rules() {
    block_on(async {
        // OPAQUE sessions expire after 10 minutes here, device sessions after an hour.
        let mut env = Env::on_either_engine(7505, |c| c.opaque_session_ttl_ms = 600_000).await;
        let client = env.signup("xia", "pw").await;
        let other = env.signup("yan", "pw").await;
        let (_, expired) = env.web(&client).await;
        env.tick(600_000);

        let (mut ds, device) = env.native(&client).await;
        let (_, device_b) = env.native(&client).await;
        let (_, theirs) = env.web(&other).await;

        assert!(matches!(
            env.svc
                .end_session(&device, device_b.session_id, env.now)
                .await,
            Err(AuthError::InvalidRequest)
        ));
        // A device session's own id is a device target too; R2 is its sign-out.
        assert!(matches!(
            env.svc
                .end_session(&device, device.session_id, env.now)
                .await,
            Err(AuthError::InvalidRequest)
        ));

        let unknown = SessionId::from_bytes([0x5a; 16]);
        let mut answers = Vec::new();
        for target in [theirs.session_id, unknown, expired.session_id] {
            let answer = env.svc.end_session(&device, target, env.now).await;
            assert!(matches!(answer, Err(AuthError::NotFound)), "{answer:?}");
            answers.push(format!("{answer:?}"));
        }
        assert!(answers.windows(2).all(|w| w[0] == w[1]));
        // Nothing of the other account ended.
        assert_eq!(env.list(&theirs).await.sessions.len(), 1);
        assert!(env.live_device(&client, &mut ds).await);

        // The caller's own id ends the caller, as R2 would.
        let (own_token, own) = env.web(&client).await;
        env.svc
            .end_session(&own, own.session_id, env.now)
            .await
            .unwrap();
        assert!(!env.live(&own_token).await);
        assert!(matches!(
            env.svc.end_current_session(&own, env.now).await,
            Err(AuthError::Unauthorized)
        ));
    });
}

/// §11 item 4: R4 ends every OPAQUE and recovery-only session but the caller's, and no device
/// session, the caller's own device's included; it succeeds when there is nothing to end.
#[test]
fn others_end_leaves_device_sessions() {
    block_on(async {
        let mut env = Env::on_either_engine(7506, |_| {}).await;
        let client = env.signup("zed", "pw").await;
        let other = env.signup("abe", "pw").await;
        env.wait_out_recovery(&client).await;

        let (mut caller_ds, caller) = env.native(&client).await;
        let (mut twin_ds, _) = env.native(&client).await;
        let (web_token, _) = env.web(&client).await;
        let (bound_token, _) = env.bound(&client, &caller).await;
        let (recovery_token, _) = env.recovery_session(&client).await;
        let (theirs_token, _) = env.web(&other).await;

        env.svc.end_other_sessions(&caller, env.now).await.unwrap();
        assert!(!env.live(&web_token).await);
        assert!(!env.live(&bound_token).await);
        assert!(!env.live(&recovery_token).await);
        assert!(env.live(&theirs_token).await);
        assert!(env.live_device(&client, &mut caller_ds).await);
        assert!(env.live_device(&client, &mut twin_ds).await);
        let left = env.list(&caller).await;
        assert_eq!(left.sessions.len(), 2);
        assert!(
            left.sessions
                .iter()
                .all(|s| s.kind == SessionKindView::Device)
        );

        // Nothing left to end: still `Ok`.
        env.svc.end_other_sessions(&caller, env.now).await.unwrap();

        // A fresh OPAQUE caller keeps itself.
        let (fresh_token, fresh) = env.web(&client).await;
        let (another_token, _) = env.web(&client).await;
        env.svc.end_other_sessions(&fresh, env.now).await.unwrap();
        assert!(env.live(&fresh_token).await);
        assert!(!env.live(&another_token).await);
        assert!(env.live_device(&client, &mut caller_ds).await);
    });
}

/// §11 item 5 (R5): a session ended between its authentication and the commit of a password
/// change made with it cannot commit, and the change writes nothing.
#[test]
fn an_ended_session_cannot_commit_a_password_change() {
    block_on(async {
        let mut env = Env::on_either_engine(7507, |_| {}).await;
        let client = env.signup("bea", "old-password").await;
        let (_, changer) = env.web(&client).await;
        let new_sk = SecretKey::generate(&mut env.rng);
        let (commit, _) =
            password_change(&mut env, &client, &changer, "new-password", &new_sk).await;

        // Another fresh session ends it before the commit.
        let (_, ender) = env.web(&client).await;
        env.svc
            .end_session(&ender, changer.session_id, env.now)
            .await
            .unwrap();
        assert!(matches!(
            env.svc
                .commit_change_request(&changer, commit, env.now)
                .await,
            Err(AuthError::Unauthorized)
        ));

        // Nothing changed: the old password logs in, the new one does not.
        let name = client.name.clone();
        assert!(
            env.login_as(&name, "new-password", &new_sk, None, None)
                .await
                .is_err()
        );
        env.login_as(&name, "old-password", &client.secret_key, None, None)
            .await
            .unwrap();
    });
}

/// §11 item 6 (INV-7, §7): with the per-name login bucket in backoff from an unauthenticated
/// flood, a device session still ends the web sessions.
#[test]
fn a_login_flood_does_not_stop_a_device_from_ending_sessions() {
    block_on(async {
        let mut env = Env::on_either_engine(7508, |c| {
            c.rate_limits.login_per_name.max_attempts = 3;
        })
        .await;
        let client = env.signup("cal", "pw").await;
        let (web_token, _) = env.web(&client).await;
        let (_, device) = env.native(&client).await;

        // The flood: every attempt from a new source, until the per-name cap refuses.
        let mut refused = false;
        for source in 0u32..16 {
            let sk = SecretKey::generate(&mut env.rng);
            let pw_in = PasswordInput::derive("guess", &sk).unwrap();
            let (_, ke1) = client_login_start(&mut env.rng, &pw_in).unwrap();
            let req = LoginStartRequest {
                login_name: Text::new(client.name.clone()).unwrap(),
                ke1: bytes(ke1),
            };
            let answer = env
                .svc
                .login_start(&mut env.rng, &req, &source.to_be_bytes(), None, env.now)
                .await;
            if matches!(answer, Err(AuthError::RateLimited { .. })) {
                refused = true;
                break;
            }
        }
        assert!(refused, "the flood must put the name in backoff");

        env.svc.end_other_sessions(&device, env.now).await.unwrap();
        assert!(!env.live(&web_token).await);
        assert_eq!(env.list(&device).await.sessions.len(), 1);
    });
}
