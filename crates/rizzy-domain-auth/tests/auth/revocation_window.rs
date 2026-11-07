// SPDX-License-Identifier: AGPL-3.0-only

//! The suspension and the revocation window ([ADR 0091] §1, §2; its §7 tests 1, 2, 3, 6 and 8 on
//! the auth domain's side).
//!
//! Every test runs on an account with the owner's devices A (the revoker R) and B, and the
//! stolen device D, through real SQLite (and PostgreSQL when `RIZZY_TEST_POSTGRES_URL` is set,
//! `Env::on_either_engine`). "Nothing is written" is checked by comparing, before and after a
//! refused request, the logical dump of every backed-up table (state, certificates, wraps,
//! credentials, recovery rows), the session ids and the stored window row.
//!
//! The vault writes of §2's left column (`vault/upload`, `vault/heal`, the three attachment
//! writes) are the vault domain's: `rizzy-domain-vault`'s `tests/vault/window.rs` covers them,
//! and `rizzy-server`'s `tests/http/revocation_window.rs` covers them through the real bridge,
//! with the op D signed uploaded over B's session (§7 test 1's op case).
//!
//! [ADR 0091]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0091-revoked-device-rotation-race.md

use rizzy_core::envelope::purpose::AccountKeyServerWrapCtx;
use rizzy_core::ids::AccountId;
use rizzy_core::kdf::KdfId;
use rizzy_core::keys::{IdentityKeys, RecoveryAuthToken};
use rizzy_core::opaque::{PasswordInput, client_registration_finish, client_registration_start};
use rizzy_core::secret::SecretArray;
use rizzy_core::secret_key::SecretKey;
use rizzy_core::sign::{AccountState, DeviceCertificate, DeviceKind, DeviceRevocation};
use rizzy_core::totp::{TotpParams, TotpSecret};
use rizzy_domain_auth::config::REVOCATION_WINDOW_MS;
use rizzy_domain_auth::revocation::{RevocationWindow, stored_window};
use rizzy_domain_auth::{AccountChange, AuthConfig, AuthError, RecoveryUpload, Session};
use rizzy_proto::account::{
    AccountStateQuery, AccountView, EnrolDeviceRequest, PublishAccountStateRequest,
    PublishBundlesRequest, PublishGrantsRequest, UploadWebDeviceCertificateRequest,
};
use rizzy_proto::auth::RecoveryRegistration;
use rizzy_proto::objects::{AccountKeyServerWrap, VaultSelfGrant};
use rizzy_proto::webauthn::WebauthnRemoveRequest;
use rizzy_proto::wire::{Fixed, Id, List};
use rizzy_storage::Dump;

use crate::common::{
    Client, Device, DeviceSession, Env, Login, block_on, bytes, recovery_wrap, wid,
};
use crate::requests::password_change;
use crate::restore::{reconcile, restore};
use crate::revocation::{enrol, rotation};

/// The revoker R: the signup device.
pub(crate) const A: usize = 0;
/// The owner's second device.
pub(crate) const B: usize = 1;
/// The stolen device.
pub(crate) const D: usize = 2;

/// The master password of every account here.
pub(crate) const PASSWORD: &str = "pw";

/// A change for the in-memory vault port.
pub(crate) type Change = AccountChange<Vec<VaultSelfGrant>>;

/// What a refused request must leave as it was.
#[derive(Debug, PartialEq)]
pub(crate) struct Snap {
    /// Every backed-up table.
    dump: Dump,
    /// Every session id.
    sessions: Vec<Vec<u8>>,
    /// The stored window row.
    window: Option<RevocationWindow>,
}

/// The account, its devices and the sessions the tests use.
pub(crate) struct Fixture {
    /// The server.
    pub(crate) env: Env,
    /// The owner's client: devices A, B, D, then any extra.
    pub(crate) client: Client,
    /// A's device session, as the server returns it for a signed request.
    pub(crate) a_dev: Session,
    /// A's OPAQUE re-authentication, bound to A: R's session, and its export key.
    pub(crate) a_login: Login,
    /// The session of `a_login`.
    pub(crate) a_fresh: Session,
    /// B's device session.
    pub(crate) b_dev: Session,
    /// B's fresh OPAQUE re-authentication, bound to B.
    pub(crate) b_fresh: Session,
    /// The thief's fresh OPAQUE session with the password and the SK, bound to no device.
    pub(crate) thief: Session,
    /// H per device index, as the last suspend returned it.
    pub(crate) heads: Vec<u64>,
}

/// An OPAQUE re-authentication bound to `device` (CRYPTO.md §11.8 step 0's session).
pub(crate) async fn reauth(env: &mut Env, client: &Client, device: usize) -> (Login, Session) {
    let (_, own) = device_session(env, client, device).await;
    let (name, password) = (client.name.clone(), client.password.clone());
    let login = env
        .login_as(&name, &password, &client.secret_key, None, Some(&own))
        .await
        .unwrap();
    let fresh = env.bearer(&login.response.session_token).await;
    assert_eq!(fresh.device_id, Some(client.devices[device].id));
    (login, fresh)
}

/// A device session of `device` and the session one signed request over it yields.
pub(crate) async fn device_session(
    env: &mut Env,
    client: &Client,
    device: usize,
) -> (DeviceSession, Session) {
    let mut ds = env
        .device_auth(client, &client.devices[device])
        .await
        .unwrap();
    let session = env
        .signed(client, &client.devices[device], &mut ds, b"")
        .await
        .unwrap();
    (ds, session)
}

/// The account view over `session`.
pub(crate) async fn view(env: &Env, session: &Session) -> Result<AccountView, AuthError> {
    env.svc
        .account_view(
            session,
            AccountStateQuery {
                known_bundle_seq: 1,
                known_settings_seq: 0,
            },
            env.now,
        )
        .await
}

/// The stored window row of `account`, open or expired.
pub(crate) async fn window_row(env: &Env, account: AccountId) -> Option<RevocationWindow> {
    let mut tx = env.db.begin_read().await.unwrap();
    let row = stored_window(tx.conn(), account).await.unwrap();
    tx.finish().await.unwrap();
    row
}

/// Every session id, ascending.
pub(crate) async fn session_ids(env: &Env) -> Vec<Vec<u8>> {
    let mut tx = env.db.begin_read().await.unwrap();
    let ids: Vec<Vec<u8>> = rizzy_storage::on_engine!(tx.conn(), |c| {
        sqlx::query_scalar::<_, Vec<u8>>("SELECT session_id FROM auth_sessions ORDER BY session_id")
            .fetch_all(&mut *c)
            .await
            .unwrap()
    });
    tx.finish().await.unwrap();
    ids
}

/// What a refused request must not change.
pub(crate) async fn snap(env: &Env, account: AccountId) -> Snap {
    Snap {
        dump: env.db.dump().await.unwrap(),
        sessions: session_ids(env).await,
        window: window_row(env, account).await,
    }
}

/// A commit of `state` alone.
pub(crate) fn bare_change(state: Vec<u8>) -> Change {
    AccountChange {
        account_state: bytes(state),
        bundle: None,
        registration_upload: None,
        setup_id: None,
        account_key_server_wrap: None,
        identity_secret_keys: None,
        recovery: RecoveryUpload::None,
        account_settings: None,
        retired_secret_keys: List::empty(),
        device_certificates: List::empty(),
        device_revocations: List::empty(),
        device_grants: List::empty(),
        vault_rotation: None,
        vault_create: None,
        vault_delete: None,
    }
}

/// The TOTP code at `now_ms`.
fn code_at(secret: &TotpSecret, now_ms: u64) -> String {
    TotpParams::DEFAULT
        .code_at(secret, now_ms / 1000)
        .unwrap()
        .to_digits()
        .to_string()
}

impl Fixture {
    /// An account with `devices` durable devices (A, B, D, then any extra), A's and B's fresh
    /// re-authentications, their device sessions and the thief's session. No window is open.
    pub(crate) async fn new(
        seed: u64,
        devices: usize,
        adjust: impl FnOnce(&mut AuthConfig),
    ) -> Self {
        Self::over(Env::on_either_engine(seed, adjust).await, devices).await
    }

    /// As [`Fixture::new`], over `env`.
    pub(crate) async fn over(mut env: Env, devices: usize) -> Self {
        let mut client = env.signup("rev", PASSWORD).await;
        for _ in 1..devices {
            let device = enrol(&mut env, &mut client).await;
            client.devices.push(device);
        }
        let (_, a_dev) = device_session(&mut env, &client, A).await;
        let (a_login, a_fresh) = reauth(&mut env, &client, A).await;
        let (_, b_dev) = device_session(&mut env, &client, B).await;
        let (_, b_fresh) = reauth(&mut env, &client, B).await;
        let thief = env.login(&client).await;
        let thief = env.bearer(&thief.response.session_token).await;
        assert_eq!(thief.device_id, None);
        Self {
            env,
            client,
            a_dev,
            a_login,
            a_fresh,
            b_dev,
            b_fresh,
            thief,
            heads: vec![0; devices],
        }
    }

    /// The account.
    pub(crate) const fn account(&self) -> AccountId {
        self.client.account_id
    }

    /// A suspends `device` over its fresh re-authentication, with H set to `10 + device`
    /// first; returns H.
    pub(crate) async fn suspend(&mut self, device: usize) -> u64 {
        let id = self.client.devices[device].id;
        let h = 10 + u64::try_from(device).unwrap();
        self.env.vault.set_head(self.client.account_id, id, h);
        let head = self
            .env
            .svc
            .suspend_device(&self.a_fresh, id, self.env.now)
            .await
            .unwrap();
        assert_eq!(head, h);
        self.heads[device] = head;
        head
    }

    /// R repeats the suspend of `device`: H again.
    pub(crate) async fn head_again(&self, device: usize) -> u64 {
        self.env
            .svc
            .suspend_device(&self.a_fresh, self.client.devices[device].id, self.env.now)
            .await
            .unwrap()
    }

    /// The snapshot of what a refused request must not change.
    pub(crate) async fn snap(&self) -> Snap {
        snap(&self.env, self.account()).await
    }

    /// Asserts that `outcome` is `revocation_pending` and that nothing changed since `before`.
    pub(crate) async fn frozen(&self, outcome: Option<AuthError>, before: &Snap) {
        assert!(
            matches!(outcome, Some(AuthError::RevocationPending)),
            "expected revocation_pending, got {outcome:?}"
        );
        assert!(self.snap().await == *before, "a refused request wrote");
    }

    /// The expiry of the window the account view shows over B's device session.
    pub(crate) async fn shown_window(&self) -> Option<u64> {
        view(&self.env, &self.b_dev)
            .await
            .unwrap()
            .revocation_window
            .map(|w| w.expires_at_ms)
    }

    /// The suspended devices the account view shows.
    pub(crate) async fn shown_suspended(&self) -> Vec<Id> {
        view(&self.env, &self.b_dev)
            .await
            .unwrap()
            .suspended_devices
            .as_slice()
            .to_vec()
    }

    /// The wire id of device `i`.
    pub(crate) fn id(&self, i: usize) -> Id {
        wid(self.client.devices[i].id.to_bytes())
    }

    /// The revocation of `targets` (at their last H) with a standard rotation sent by A, which
    /// grants the new account key to every other unrevoked device. The client already holds the
    /// revocations and the new keys; it adopts the returned state once the commit succeeds.
    pub(crate) fn revocation_change(
        &mut self,
        targets: &[usize],
    ) -> (Change, (AccountState, Vec<u8>)) {
        let account_id = self.client.account_id;
        let mut wires = Vec::new();
        for &t in targets {
            let wire = DeviceRevocation {
                account_id,
                device_id: self.client.devices[t].id,
                last_accepted_device_seq: self.heads[t],
                revoked_at_ms: self.env.now,
            }
            .sign(self.client.identity.signing_key())
            .unwrap();
            self.client.revocations.push(
                DeviceRevocation::verify(&wire, self.client.identity.signing_key().verifying_key())
                    .unwrap(),
            );
            wires.push(bytes(wire));
        }
        let revoked: Vec<_> = self
            .client
            .revocations
            .iter()
            .map(|r| r.statement().device_id)
            .collect();
        let devices = core::mem::take(&mut self.client.devices);
        let recipients: Vec<&Device> = devices
            .iter()
            .enumerate()
            .filter(|(i, d)| *i != A && !revoked.contains(&d.id))
            .map(|(_, d)| d)
            .collect();
        let (_, mut change) = rotation(
            &mut self.env,
            &mut self.client,
            &self.a_login.export_key,
            &devices[A],
            &recipients,
        );
        self.client.devices = devices;
        let set = self
            .client
            .device_set(&self.client.devices.iter().collect::<Vec<_>>());
        let key_id = self.client.account_key.key_id().unwrap();
        let next = self.client.next_state(|s| {
            s.account_key_epoch += 1;
            s.account_key_id = key_id;
            s.device_set_hash = set;
        });
        change.account_state = bytes(next.1.clone());
        change.device_revocations = List::new(wires).unwrap();
        (change, next)
    }
}

/// An enrolment request for a new durable device of `client`.
pub(crate) fn enrolment(
    env: &mut Env,
    client: &Client,
) -> (Device, EnrolDeviceRequest, (AccountState, Vec<u8>)) {
    let device = client.make_device(&mut env.rng, env.now);
    let mut members: Vec<&Device> = client.devices.iter().collect();
    members.push(&device);
    let set = client.device_set(&members);
    let next = client.next_state(|s| s.device_set_hash = set);
    let req = EnrolDeviceRequest {
        device_certificate: bytes(device.cert_wire.clone()),
        account_state: bytes(next.1.clone()),
    };
    (device, req, next)
}

/// A kind-4 certificate upload valid for an hour.
pub(crate) fn web_certificate(env: &mut Env, client: &Client) -> UploadWebDeviceCertificateRequest {
    let keys = rizzy_core::keys::DeviceKeys::generate(&mut env.rng);
    let id = rizzy_core::ids::DeviceId::generate(&mut env.rng);
    let web = client.certify(
        id,
        keys,
        DeviceKind::WebEphemeral,
        env.now,
        env.now + 3_600_000,
    );
    UploadWebDeviceCertificateRequest {
        device_certificate: bytes(web.cert_wire),
    }
}

/// An empty healing step 3a: success in and outside a reconciliation epoch.
pub(crate) fn empty_grants() -> PublishGrantsRequest {
    PublishGrantsRequest {
        vault_self_grants: List::empty(),
        device_grants: List::empty(),
    }
}

// §7 test 1: what the server refuses from the suspension commit on (§1).

/// §1: after the suspend, D's `device-auth/start` is `unauthorized`; the attempt writes
/// nothing and leaves H.
#[test]
fn suspended_device_cannot_authenticate() {
    block_on(async {
        let mut fx = Fixture::new(9101, 3, |_| {}).await;
        fx.env
            .device_auth(&fx.client, &fx.client.devices[D])
            .await
            .unwrap();
        let head = fx.suspend(D).await;
        let before = fx.snap().await;
        let start = rizzy_proto::auth::DeviceAuthStartRequest {
            account_id: wid(fx.client.account_id.to_bytes()),
            device_id: fx.id(D),
            reconciliation: None,
        };
        assert!(matches!(
            fx.env
                .svc
                .device_auth_start(&mut fx.env.rng, &start, fx.env.now)
                .await,
            Err(AuthError::Unauthorized)
        ));
        assert!(matches!(
            fx.env.device_auth(&fx.client, &fx.client.devices[D]).await,
            Err(AuthError::Unauthorized)
        ));
        assert!(fx.snap().await == before);
        assert_eq!(fx.head_again(D).await, head);
    });
}

/// §1: every session D held, its device session and an OPAQUE re-authentication bound to it,
/// is `unauthorized` from the suspension on; B's and the thief's are not affected.
#[test]
fn suspended_device_sessions_end() {
    block_on(async {
        let mut fx = Fixture::new(9102, 3, |_| {}).await;
        let (mut d_ds, d_dev) = device_session(&mut fx.env, &fx.client, D).await;
        let (d_login, d_fresh) = reauth(&mut fx.env, &fx.client, D).await;
        let head = fx.suspend(D).await;
        let before = fx.snap().await;

        let token = d_ds.token.expose_secret().to_vec();
        for signed in [true, false] {
            assert!(matches!(
                fx.env
                    .svc
                    .session_for_token(&token, signed, fx.env.now)
                    .await,
                Err(AuthError::Unauthorized)
            ));
        }
        assert!(matches!(
            fx.env
                .signed(&fx.client, &fx.client.devices[D], &mut d_ds, b"")
                .await,
            Err(AuthError::Unauthorized)
        ));
        assert!(matches!(
            fx.env
                .svc
                .authenticate_request(
                    d_login.response.session_token.expose_secret(),
                    None,
                    crate::common::request(b"{}"),
                    fx.env.now
                )
                .await,
            Err(AuthError::Unauthorized)
        ));
        // A session held from before is reloaded on every call, and is gone.
        assert!(matches!(
            view(&fx.env, &d_dev).await,
            Err(AuthError::Unauthorized)
        ));
        assert!(matches!(
            view(&fx.env, &d_fresh).await,
            Err(AuthError::Unauthorized)
        ));
        assert!(fx.snap().await == before);
        view(&fx.env, &fx.b_dev).await.unwrap();
        view(&fx.env, &fx.thief).await.unwrap();
        assert_eq!(fx.head_again(D).await, head);
    });
}

/// §1: D can fetch no grant. A rotation before the suspension leaves a grant for D pending;
/// after the suspension D's device session is gone and D cannot open another, while B still
/// gets its own grant.
#[test]
fn suspended_device_gets_no_grant() {
    block_on(async {
        let mut fx = Fixture::new(9103, 3, |_| {}).await;
        let devices = core::mem::take(&mut fx.client.devices);
        let (_, mut change) = rotation(
            &mut fx.env,
            &mut fx.client,
            &fx.a_login.export_key,
            &devices[A],
            &[&devices[B], &devices[D]],
        );
        fx.client.devices = devices;
        let key_id = fx.client.account_key.key_id().unwrap();
        let next = fx.client.next_state(|s| {
            s.account_key_epoch += 1;
            s.account_key_id = key_id;
        });
        change.account_state = bytes(next.1.clone());
        fx.env
            .svc
            .commit_change(&fx.a_fresh, &change, fx.env.now)
            .await
            .unwrap();
        fx.client.adopt(next);
        let (_, d_dev) = device_session(&mut fx.env, &fx.client, D).await;
        let pending = fx.env.svc.device_grants(&d_dev, fx.env.now).await.unwrap();
        assert_eq!(pending.grants.len(), 1);

        let head = fx.suspend(D).await;
        let before = fx.snap().await;
        assert!(matches!(
            fx.env.svc.device_grants(&d_dev, fx.env.now).await,
            Err(AuthError::Unauthorized)
        ));
        assert!(
            fx.env
                .device_auth(&fx.client, &fx.client.devices[D])
                .await
                .is_err()
        );
        assert!(fx.snap().await == before);
        let theirs = fx
            .env
            .svc
            .device_grants(&fx.b_dev, fx.env.now)
            .await
            .unwrap();
        assert_eq!(theirs.grants.len(), 1);
        assert_eq!(fx.head_again(D).await, head);
    });
}

// §7 test 2: the window, one test per auth entry of §2's left column.

/// `account/commit`: a password change from the thief's session and from B's re-authentication,
/// and a bare commit from B's device session, are refused and write nothing; R's password change
/// commits and leaves the window open (only a revocation or a recovery commit closes it). A
/// byte-identical repeat of R's applied commit from B's device session succeeds in the window.
#[test]
fn window_freezes_commit() {
    block_on(async {
        let mut fx = Fixture::new(9110, 3, |_| {}).await;
        fx.suspend(D).await;
        let new_sk = SecretKey::generate(&mut fx.env.rng);
        for session in [fx.thief.clone(), fx.b_fresh.clone()] {
            // `account/reregister/start` is in the right column.
            let (commit, _) =
                password_change(&mut fx.env, &fx.client, &session, "new", &new_sk).await;
            let before = fx.snap().await;
            let outcome = fx
                .env
                .svc
                .commit_change_request(&session, commit, fx.env.now)
                .await;
            fx.frozen(outcome.err(), &before).await;
        }
        let next = fx.client.next_state(|_| {});
        let before = fx.snap().await;
        let outcome = fx
            .env
            .svc
            .commit_change(&fx.b_dev, &bare_change(next.1), fx.env.now)
            .await;
        fx.frozen(outcome.err(), &before).await;

        let (commit, next) =
            password_change(&mut fx.env, &fx.client, &fx.a_fresh, "new", &new_sk).await;
        fx.env
            .svc
            .commit_change_request(&fx.a_fresh, commit.clone(), fx.env.now)
            .await
            .unwrap();
        fx.client.adopt(next);
        assert!(fx.shown_window().await.is_some());
        // The byte-identical repeat is checked before the freeze.
        fx.env
            .svc
            .commit_change_request(&fx.b_dev, commit, fx.env.now)
            .await
            .unwrap();
        assert!(fx.shown_window().await.is_some());
    });
}

/// `devices/enrol`: refused from the thief and from B; R enrols; a byte-identical repeat of
/// the applied enrolment from the thief's session succeeds during the window.
#[test]
fn window_freezes_enrolment() {
    block_on(async {
        let mut fx = Fixture::new(9111, 3, |_| {}).await;
        fx.suspend(D).await;
        let (device, req, next) = enrolment(&mut fx.env, &fx.client);
        for session in [&fx.thief, &fx.b_fresh] {
            let before = fx.snap().await;
            let outcome = fx.env.svc.enrol_device(session, &req, fx.env.now).await;
            fx.frozen(outcome.err(), &before).await;
        }
        fx.env
            .svc
            .enrol_device(&fx.a_fresh, &req, fx.env.now)
            .await
            .unwrap();
        fx.client.adopt(next);
        fx.client.devices.push(device);
        fx.env
            .svc
            .enrol_device(&fx.thief, &req, fx.env.now)
            .await
            .unwrap();
        assert!(fx.shown_window().await.is_some());
        let new = fx.client.devices.len() - 1;
        fx.env
            .device_auth(&fx.client, &fx.client.devices[new])
            .await
            .unwrap();
    });
}

/// `devices/web-certificate`: refused from the thief's and B's sessions; R's uploads.
#[test]
fn window_freezes_web_certificate() {
    block_on(async {
        let mut fx = Fixture::new(9112, 3, |_| {}).await;
        fx.suspend(D).await;
        let req = web_certificate(&mut fx.env, &fx.client);
        for session in [&fx.thief, &fx.b_fresh] {
            let before = fx.snap().await;
            let outcome = fx
                .env
                .svc
                .upload_web_certificate(session, &req, fx.env.now)
                .await;
            fx.frozen(outcome.err(), &before).await;
        }
        let before = fx.snap().await;
        fx.env
            .svc
            .upload_web_certificate(&fx.a_fresh, &req, fx.env.now)
            .await
            .unwrap();
        assert!(fx.snap().await.dump != before.dump);
    });
}

/// `devices/suspend`: a second revoker's suspend is refused before anything is suspended; R's
/// repeat renews the window, as does R's suspend of another device; the renewal moves the
/// expiry; the boundaries are `expires_at_ms - 1` (refused) and `expires_at_ms` (accepted);
/// expiry lifts only the freeze.
#[test]
fn window_suspend_renewal_and_boundaries() {
    block_on(async {
        let mut fx = Fixture::new(9113, 4, |_| {}).await;
        let opened = fx.env.now;
        assert_eq!(fx.shown_window().await, None);
        assert!(fx.shown_suspended().await.is_empty());
        fx.suspend(D).await;
        assert_eq!(fx.shown_window().await, Some(opened + REVOCATION_WINDOW_MS));
        assert_eq!(fx.shown_suspended().await, vec![fx.id(D)]);
        let row = window_row(&fx.env, fx.account()).await.unwrap();
        assert_eq!(row.revoker, fx.client.devices[A].id);
        assert_eq!(row.opened_at_ms, opened);

        // A second revoker: B suspends D, or the fourth device. Nothing is suspended.
        for target in [D, 3] {
            let before = fx.snap().await;
            let outcome = fx
                .env
                .svc
                .suspend_device(&fx.b_fresh, fx.client.devices[target].id, fx.env.now)
                .await;
            fx.frozen(outcome.err(), &before).await;
        }
        assert_eq!(fx.shown_suspended().await, vec![fx.id(D)]);

        // R renews a minute later by repeating the suspend of D, then by suspending the fourth.
        fx.env.tick(60_000);
        fx.suspend(D).await;
        assert_eq!(
            fx.shown_window().await,
            Some(fx.env.now + REVOCATION_WINDOW_MS)
        );
        fx.env.tick(60_000);
        fx.suspend(3).await;
        let renewed = fx.env.now + REVOCATION_WINDOW_MS;
        assert_eq!(fx.shown_window().await, Some(renewed));
        let row = window_row(&fx.env, fx.account()).await.unwrap();
        assert_eq!(row.opened_at_ms, opened);
        let mut suspended = vec![fx.id(D), fx.id(3)];
        suspended.sort_by_key(|id| id.to_bytes());
        assert_eq!(fx.shown_suspended().await, suspended);

        // The first expiry has passed, the renewed one has not.
        for now in [opened + REVOCATION_WINDOW_MS, renewed - 1] {
            fx.env.now = now;
            let before = fx.snap().await;
            let outcome = fx
                .env
                .svc
                .publish_grants(&fx.b_dev, &empty_grants(), fx.env.now)
                .await;
            fx.frozen(outcome.err(), &before).await;
            assert_eq!(fx.shown_window().await, Some(renewed));
        }
        fx.env.now = renewed;
        assert_eq!(fx.shown_window().await, None);
        fx.env
            .svc
            .publish_grants(&fx.b_dev, &empty_grants(), fx.env.now)
            .await
            .unwrap();
        // That write deleted the expired row.
        assert_eq!(window_row(&fx.env, fx.account()).await, None);
        // Expiry lifts only the freeze: both stay suspended and D stays out.
        assert_eq!(fx.shown_suspended().await, suspended);
        assert!(
            fx.env
                .device_auth(&fx.client, &fx.client.devices[D])
                .await
                .is_err()
        );
        // After the expiry another device may open a window.
        let (_, b_fresh) = reauth(&mut fx.env, &fx.client, B).await;
        fx.env
            .svc
            .suspend_device(&b_fresh, fx.client.devices[D].id, fx.env.now)
            .await
            .unwrap();
        let row = window_row(&fx.env, fx.account()).await.unwrap();
        assert_eq!(row.revoker, fx.client.devices[B].id);
    });
}

/// `devices/unsuspend`: refused for B; R's unsuspend of one of two suspended devices keeps the
/// window; R's unsuspend of the last one deletes the row, and other devices' writes succeed.
#[test]
fn window_unsuspend_closes_on_the_last() {
    block_on(async {
        let mut fx = Fixture::new(9114, 4, |_| {}).await;
        fx.suspend(D).await;
        fx.suspend(3).await;
        let before = fx.snap().await;
        let outcome = fx
            .env
            .svc
            .unsuspend_device(&fx.b_fresh, fx.client.devices[D].id, fx.env.now)
            .await;
        fx.frozen(outcome.err(), &before).await;

        fx.env
            .svc
            .unsuspend_device(&fx.a_fresh, fx.client.devices[3].id, fx.env.now)
            .await
            .unwrap();
        assert!(window_row(&fx.env, fx.account()).await.is_some());
        assert_eq!(fx.shown_suspended().await, vec![fx.id(D)]);
        let before = fx.snap().await;
        let outcome = fx
            .env
            .svc
            .publish_grants(&fx.b_dev, &empty_grants(), fx.env.now)
            .await;
        fx.frozen(outcome.err(), &before).await;

        fx.env
            .svc
            .unsuspend_device(&fx.a_fresh, fx.client.devices[D].id, fx.env.now)
            .await
            .unwrap();
        assert_eq!(window_row(&fx.env, fx.account()).await, None);
        assert_eq!(fx.shown_window().await, None);
        assert!(fx.shown_suspended().await.is_empty());
        fx.env
            .svc
            .publish_grants(&fx.b_dev, &empty_grants(), fx.env.now)
            .await
            .unwrap();
        let req = web_certificate(&mut fx.env, &fx.client);
        fx.env
            .svc
            .upload_web_certificate(&fx.thief, &req, fx.env.now)
            .await
            .unwrap();
        fx.env
            .device_auth(&fx.client, &fx.client.devices[D])
            .await
            .unwrap();
    });
}

/// The three healing writes: refused over B's device session; R's device session re-sends the
/// held chain, the held state and no grants successfully.
#[test]
fn window_freezes_healing() {
    block_on(async {
        let mut fx = Fixture::new(9115, 3, |_| {}).await;
        fx.suspend(D).await;
        let bundles = PublishBundlesRequest {
            bundles: List::new(vec![bytes(fx.client.bundle_wire.clone())]).unwrap(),
        };
        let state = PublishAccountStateRequest {
            account_state: bytes(fx.client.state_wire.clone()),
            device_certificates: List::new(
                fx.client
                    .devices
                    .iter()
                    .map(|d| bytes(d.cert_wire.clone()))
                    .collect(),
            )
            .unwrap(),
            device_revocations: List::empty(),
            identity_secret_keys: None,
            account_settings: None,
        };
        let grants = empty_grants();
        let before = fx.snap().await;
        let outcome = fx
            .env
            .svc
            .publish_bundles(&fx.b_dev, &bundles, fx.env.now)
            .await;
        fx.frozen(outcome.err(), &before).await;
        let outcome = fx
            .env
            .svc
            .publish_account_state(&fx.b_dev, &state, fx.env.now)
            .await;
        fx.frozen(outcome.err(), &before).await;
        let outcome = fx
            .env
            .svc
            .publish_grants(&fx.b_dev, &grants, fx.env.now)
            .await;
        fx.frozen(outcome.err(), &before).await;

        fx.env
            .svc
            .publish_bundles(&fx.a_dev, &bundles, fx.env.now)
            .await
            .unwrap();
        fx.env
            .svc
            .publish_account_state(&fx.a_dev, &state, fx.env.now)
            .await
            .unwrap();
        fx.env
            .svc
            .publish_grants(&fx.a_dev, &grants, fx.env.now)
            .await
            .unwrap();
    });
}

/// `totp/enrol/confirm`: the thief's confirm of its own pending enrolment (`totp/enrol/start`
/// is in the right column) is refused; R's enrolment confirms.
#[test]
fn window_freezes_totp_confirm() {
    block_on(async {
        let mut fx = Fixture::new(9116, 3, |_| {}).await;
        fx.suspend(D).await;
        let pending = fx
            .env
            .svc
            .totp_enrol_start(&mut fx.env.rng, &fx.thief, fx.env.now)
            .await
            .unwrap();
        let code = code_at(&pending.secret, fx.env.now);
        let before = fx.snap().await;
        let outcome = fx
            .env
            .svc
            .totp_enrol_confirm(&fx.thief, pending.totp_credential_seq, &code, fx.env.now)
            .await;
        fx.frozen(outcome.err(), &before).await;

        let own = fx
            .env
            .svc
            .totp_enrol_start(&mut fx.env.rng, &fx.a_fresh, fx.env.now)
            .await
            .unwrap();
        let code = code_at(&own.secret, fx.env.now);
        fx.env
            .svc
            .totp_enrol_confirm(&fx.a_fresh, own.totp_credential_seq, &code, fx.env.now)
            .await
            .unwrap();
    });
}

/// `totp/disable`: with TOTP enrolled before the window, the thief's disable is refused; R's
/// disables it.
#[test]
fn window_freezes_totp_disable() {
    block_on(async {
        let mut fx = Fixture::new(9117, 3, |_| {}).await;
        let own = fx
            .env
            .svc
            .totp_enrol_start(&mut fx.env.rng, &fx.a_fresh, fx.env.now)
            .await
            .unwrap();
        let code = code_at(&own.secret, fx.env.now);
        fx.env
            .svc
            .totp_enrol_confirm(&fx.a_fresh, own.totp_credential_seq, &code, fx.env.now)
            .await
            .unwrap();
        fx.env.tick(31_000);
        fx.suspend(D).await;
        let code = code_at(&own.secret, fx.env.now);
        let before = fx.snap().await;
        let outcome = fx.env.svc.totp_disable(&fx.thief, &code, fx.env.now).await;
        fx.frozen(outcome.err(), &before).await;
        fx.env
            .svc
            .totp_disable(&fx.a_fresh, &code, fx.env.now)
            .await
            .unwrap();
    });
}

/// `webauthn/enrol/confirm`: the thief's confirm of a security key is refused (its
/// `webauthn/enrol/start`, in the right column, stored only its ceremony state, which no
/// snapshot here covers); R enrols the same key.
#[test]
fn window_freezes_webauthn_confirm() {
    block_on(async {
        let mut fx = Fixture::new(9118, 3, |_| {}).await;
        fx.suspend(D).await;
        let key = crate::webauthn::SoftKey::new(&mut fx.env, 1);
        let before = fx.snap().await;
        let thief = fx.thief.clone();
        let outcome =
            crate::webauthn::enrol(&mut fx.env, &thief, &key, crate::webauthn::UP, "k").await;
        fx.frozen(outcome.err(), &before).await;
        let a_fresh = fx.a_fresh.clone();
        crate::webauthn::enrol(&mut fx.env, &a_fresh, &key, crate::webauthn::UP, "k")
            .await
            .unwrap();
        let list = fx.env.svc.webauthn_list(&thief).await.unwrap();
        assert_eq!(list.credentials.len(), 1);
    });
}

/// `webauthn/remove`: with a key enrolled before the window, the thief's removal is refused;
/// R's removes it.
#[test]
fn window_freezes_webauthn_remove() {
    block_on(async {
        let mut fx = Fixture::new(9119, 3, |_| {}).await;
        let key = crate::webauthn::SoftKey::new(&mut fx.env, 2);
        let a_fresh = fx.a_fresh.clone();
        crate::webauthn::enrol(&mut fx.env, &a_fresh, &key, crate::webauthn::UP, "k")
            .await
            .unwrap();
        fx.suspend(D).await;
        let list = fx.env.svc.webauthn_list(&fx.thief).await.unwrap();
        let req = WebauthnRemoveRequest {
            credential_id: list.credentials.as_slice()[0].credential_id.clone(),
        };
        let before = fx.snap().await;
        let outcome = fx
            .env
            .svc
            .webauthn_remove(&fx.thief, &req, fx.env.now)
            .await;
        fx.frozen(outcome.err(), &before).await;
        fx.env
            .svc
            .webauthn_remove(&fx.a_fresh, &req, fx.env.now)
            .await
            .unwrap();
        let list = fx.env.svc.webauthn_list(&fx.thief).await.unwrap();
        assert!(list.credentials.is_empty());
    });
}

/// `sessions/end`: neither the thief nor B can end another session; R ends the thief's.
#[test]
fn window_freezes_end_session() {
    block_on(async {
        let mut fx = Fixture::new(9120, 3, |_| {}).await;
        fx.suspend(D).await;
        let (thief, b_fresh, b_dev) = (fx.thief.clone(), fx.b_fresh.clone(), fx.b_dev.clone());
        for (caller, target) in [(&thief, &b_fresh), (&b_fresh, &thief), (&b_dev, &thief)] {
            let before = fx.snap().await;
            let outcome = fx
                .env
                .svc
                .end_session(caller, target.session_id, fx.env.now)
                .await;
            fx.frozen(outcome.err(), &before).await;
        }
        fx.env
            .svc
            .end_session(&fx.a_fresh, thief.session_id, fx.env.now)
            .await
            .unwrap();
        assert!(matches!(
            view(&fx.env, &thief).await,
            Err(AuthError::Unauthorized)
        ));
    });
}

/// `sessions/others/end`: refused from the thief and from B; R ends the others.
#[test]
fn window_freezes_end_other_sessions() {
    block_on(async {
        let mut fx = Fixture::new(9121, 3, |_| {}).await;
        fx.suspend(D).await;
        for caller in [fx.thief.clone(), fx.b_fresh.clone(), fx.b_dev.clone()] {
            let before = fx.snap().await;
            let outcome = fx.env.svc.end_other_sessions(&caller, fx.env.now).await;
            fx.frozen(outcome.err(), &before).await;
        }
        fx.env
            .svc
            .end_other_sessions(&fx.a_fresh, fx.env.now)
            .await
            .unwrap();
        assert!(matches!(
            view(&fx.env, &fx.thief).await,
            Err(AuthError::Unauthorized)
        ));
        view(&fx.env, &fx.a_fresh).await.unwrap();
    });
}

/// `recovery/cancel`: a recovery started during the window (`recovery/start` is in the right
/// column) cannot be cancelled from B's device session; R's device session cancels it.
#[test]
fn window_freezes_recovery_cancel() {
    block_on(async {
        let mut fx = Fixture::new(9122, 3, |_| {}).await;
        fx.suspend(D).await;
        let token = fx.client.recovery_token();
        let source = fx.env.source.clone();
        let started = fx
            .env
            .svc
            .recovery_start(&fx.client.name, &token, &source, fx.env.now)
            .await
            .unwrap();
        assert!(started.opened);
        let before = fx.snap().await;
        let outcome = fx.env.svc.recovery_cancel(&fx.b_dev, fx.env.now).await;
        fx.frozen(outcome.err(), &before).await;
        assert!(
            fx.env
                .svc
                .recovery_cancel(&fx.a_dev, fx.env.now)
                .await
                .unwrap()
        );
    });
}

/// The certificate-carrying `device-auth/finish`: refused for B with no session created and
/// nothing written; R's same-shaped request gets past the freeze (outside a reconciliation
/// epoch it then succeeds or fails on its own rules, never with `revocation_pending`). The
/// plain variant from B succeeds.
#[test]
fn window_freezes_reconciling_device_auth() {
    block_on(async {
        let mut fx = Fixture::new(9123, 3, |_| {}).await;
        fx.suspend(D).await;
        let state = fx.client.state_wire.clone();
        let before = fx.snap().await;
        let outcome = {
            let set: Vec<&Device> = fx.client.devices.iter().collect();
            reconcile(&mut fx.env, &fx.client, &fx.client.devices[B], &state, &set).await
        };
        fx.frozen(outcome.err(), &before).await;
        let own = {
            let set: Vec<&Device> = fx.client.devices.iter().collect();
            reconcile(&mut fx.env, &fx.client, &fx.client.devices[A], &state, &set).await
        };
        let own = own.err();
        assert!(
            !matches!(own, Some(AuthError::RevocationPending)),
            "{own:?}"
        );
        fx.env
            .device_auth(&fx.client, &fx.client.devices[B])
            .await
            .unwrap();
    });
}

/// Every right-column auth endpoint succeeds during a window, from sessions not bound to R,
/// and leaves the window open.
#[test]
fn window_leaves_the_right_column() {
    block_on(async {
        let mut fx = Fixture::new(9124, 3, |c| c.recovery_wait_ms = 0).await;
        fx.suspend(D).await;
        // account/state over every kind of session not bound to R.
        for session in [&fx.thief, &fx.b_fresh, &fx.b_dev] {
            let seen = view(&fx.env, session).await.unwrap();
            assert!(seen.revocation_window.is_some());
        }
        // login/* for the thief again, and plain device-auth/* for B.
        let thief = fx.env.login(&fx.client).await;
        let thief = fx.env.bearer(&thief.response.session_token).await;
        let (_, b_dev) = device_session(&mut fx.env, &fx.client, B).await;
        // devices/grants and devices/grants/ack.
        fx.env.svc.device_grants(&b_dev, fx.env.now).await.unwrap();
        fx.env
            .svc
            .ack_device_grants(
                &b_dev,
                &rizzy_proto::account::AckDeviceGrantsRequest {
                    account_key_epoch: fx.client.state.account_key_epoch,
                },
                fx.env.now,
            )
            .await
            .unwrap();
        // account/reregister/start.
        let pw_in = PasswordInput::derive_for_new_password("x", &fx.client.secret_key).unwrap();
        let (_, m1) = client_registration_start(&mut fx.env.rng, &pw_in).unwrap();
        fx.env
            .svc
            .reregister_start(&thief, &bytes(m1), fx.env.now)
            .await
            .unwrap();
        // totp/enrol/start, webauthn/enrol/start, webauthn/list.
        fx.env
            .svc
            .totp_enrol_start(&mut fx.env.rng, &thief, fx.env.now)
            .await
            .unwrap();
        fx.env
            .svc
            .webauthn_enrol_start(&mut fx.env.rng, &thief, fx.env.now)
            .await
            .unwrap();
        fx.env.svc.webauthn_list(&thief).await.unwrap();
        // sessions/list and sessions/current/end.
        let listed = fx.env.svc.list_sessions(&thief, fx.env.now).await.unwrap();
        assert!(!listed.sessions.is_empty());
        fx.env
            .svc
            .end_current_session(&fx.b_fresh, fx.env.now)
            .await
            .unwrap();
        // recovery/start and recovery/complete.
        let token = fx.client.recovery_token();
        let source = fx.env.source.clone();
        let name = fx.client.name.clone();
        fx.env
            .svc
            .recovery_start(&name, &token, &source, fx.env.now)
            .await
            .unwrap();
        fx.env
            .svc
            .recovery_complete(&mut fx.env.rng, &name, &token, &source, fx.env.now)
            .await
            .unwrap();
        assert!(window_row(&fx.env, fx.account()).await.is_some());
    });
}

/// The revocation commit: refused from B, accepted from R, and it deletes the row; then a
/// byte-identical repeat from B and other devices' writes succeed.
#[test]
fn revocation_commit_closes_the_window() {
    block_on(async {
        let mut fx = Fixture::new(9125, 3, |_| {}).await;
        fx.suspend(D).await;
        let (change, next) = fx.revocation_change(&[D]);
        let before = fx.snap().await;
        let outcome = fx
            .env
            .svc
            .commit_change(&fx.b_fresh, &change, fx.env.now)
            .await;
        fx.frozen(outcome.err(), &before).await;
        fx.env
            .svc
            .commit_change(&fx.a_fresh, &change, fx.env.now)
            .await
            .unwrap();
        fx.client.adopt(next);
        assert_eq!(window_row(&fx.env, fx.account()).await, None);
        assert_eq!(fx.shown_window().await, None);
        // D is revoked, no longer listed as suspended.
        assert!(fx.shown_suspended().await.is_empty());
        fx.env
            .svc
            .commit_change(&fx.b_dev, &change, fx.env.now)
            .await
            .unwrap();
        fx.env
            .svc
            .publish_grants(&fx.b_dev, &empty_grants(), fx.env.now)
            .await
            .unwrap();
        let req = web_certificate(&mut fx.env, &fx.client);
        fx.env
            .svc
            .upload_web_certificate(&fx.thief, &req, fx.env.now)
            .await
            .unwrap();
        assert!(
            fx.env
                .device_auth(&fx.client, &fx.client.devices[D])
                .await
                .is_err()
        );
    });
}

/// Runs a recovery to its commit (CRYPTO.md §11.9) with the configured wait at 0: start and
/// complete, then the recovery session commits `password_epoch + 1` under a new Secret Key and
/// `recovery_epoch + 1` with a new code. The client follows only when the commit succeeds.
pub(crate) async fn recovery_commit(env: &mut Env, client: &mut Client) -> Result<(), AuthError> {
    let token = client.recovery_token();
    let source = env.source.clone();
    let name = client.name.clone();
    env.svc
        .recovery_start(&name, &token, &source, env.now)
        .await?;
    let release = env
        .svc
        .recovery_complete(&mut env.rng, &name, &token, &source, env.now)
        .await?;
    let session = env.bearer(&release.session_token).await;
    let new_sk = SecretKey::generate(&mut env.rng);
    let pw_in = PasswordInput::derive_for_new_password(&client.password, &new_sk).unwrap();
    let (reg_state, m1) = client_registration_start(&mut env.rng, &pw_in).unwrap();
    let (setup_id, m2) = env
        .svc
        .reregister_start(&session, &bytes(m1), env.now)
        .await?;
    let reg = client_registration_finish(
        &mut env.rng,
        reg_state,
        &pw_in,
        m2.as_slice(),
        KdfId::DEFAULT,
    )
    .unwrap();
    let password_epoch = client.state.password_epoch + 1;
    let recovery_epoch = client.state.recovery_epoch + 1;
    let e_srv = reg
        .export_key
        .server_unlock_key(client.account_id)
        .unwrap()
        .wrap_account_key(
            &mut env.rng,
            &AccountKeyServerWrapCtx {
                account_id: client.account_id,
                account_key_epoch: client.state.account_key_epoch,
                password_epoch,
                kdf_id: KdfId::DEFAULT,
            },
            &client.account_key,
        )
        .unwrap();
    let old_code = core::mem::replace(
        &mut client.recovery_code,
        SecretArray::<16>::generate(&mut env.rng),
    );
    let e_rec = recovery_wrap(&mut env.rng, client, recovery_epoch);
    let next = client.next_state(|s| {
        s.password_epoch = password_epoch;
        s.recovery_epoch = recovery_epoch;
    });
    let change = AccountChange {
        registration_upload: Some(bytes(reg.upload)),
        setup_id: Some(setup_id),
        account_key_server_wrap: Some(AccountKeyServerWrap {
            account_key_epoch: client.state.account_key_epoch,
            password_epoch,
            kdf_id: 1,
            envelope: bytes(e_srv),
        }),
        recovery: RecoveryUpload::Register(RecoveryRegistration {
            recovery_wrap: e_rec,
            recovery_token_hash: Fixed::from_bytes(
                RecoveryAuthToken::derive(&client.recovery_code)
                    .unwrap()
                    .server_hash(),
            ),
        }),
        ..bare_change(next.1.clone())
    };
    match env.svc.commit_change(&session, &change, env.now).await {
        Ok(()) => {
            client.adopt(next);
            client.secret_key = new_sk;
            Ok(())
        }
        Err(e) => {
            client.recovery_code = old_code;
            Err(e)
        }
    }
}

/// The recovery commit is never frozen and deletes the row; the suspension survives it, and a
/// later write by another device is not refused.
#[test]
fn recovery_commit_closes_the_window() {
    block_on(async {
        let mut fx = Fixture::new(9126, 3, |c| c.recovery_wait_ms = 0).await;
        fx.suspend(D).await;
        recovery_commit(&mut fx.env, &mut fx.client).await.unwrap();
        assert_eq!(window_row(&fx.env, fx.account()).await, None);
        // The recovery commit ended every session; B authenticates again.
        assert!(matches!(
            view(&fx.env, &fx.b_dev).await,
            Err(AuthError::Unauthorized)
        ));
        let (_, b_dev) = device_session(&mut fx.env, &fx.client, B).await;
        fx.b_dev = b_dev;
        assert_eq!(fx.shown_window().await, None);
        assert_eq!(fx.shown_suspended().await, vec![fx.id(D)]);
        fx.env
            .svc
            .publish_grants(&fx.b_dev, &empty_grants(), fx.env.now)
            .await
            .unwrap();
        assert!(
            fx.env
                .device_auth(&fx.client, &fx.client.devices[D])
                .await
                .is_err()
        );
    });
}

// §7 test 6: concurrent revokers.

/// A and B both start revoking D: exactly one window opens (A's), B's suspend is
/// `revocation_pending`; after A's revocation commit B sees D revoked, and its suspend of D is
/// `not_found`.
#[test]
fn concurrent_revokers() {
    block_on(async {
        let mut fx = Fixture::new(9130, 3, |_| {}).await;
        fx.suspend(D).await;
        let before = fx.snap().await;
        let outcome = fx
            .env
            .svc
            .suspend_device(&fx.b_fresh, fx.client.devices[D].id, fx.env.now)
            .await;
        fx.frozen(outcome.err(), &before).await;
        let row = window_row(&fx.env, fx.account()).await.unwrap();
        assert_eq!(row.revoker, fx.client.devices[A].id);

        let (change, next) = fx.revocation_change(&[D]);
        fx.env
            .svc
            .commit_change(&fx.a_fresh, &change, fx.env.now)
            .await
            .unwrap();
        fx.client.adopt(next);

        let seen = view(&fx.env, &fx.b_fresh).await.unwrap();
        assert_eq!(seen.device_revocations.len(), 1);
        let rev = DeviceRevocation::verify(
            seen.device_revocations.as_slice()[0].as_slice(),
            fx.client.identity.signing_key().verifying_key(),
        )
        .unwrap();
        assert_eq!(rev.statement().device_id, fx.client.devices[D].id);
        assert!(seen.revocation_window.is_none());
        assert!(seen.suspended_devices.is_empty());
        assert!(matches!(
            fx.env
                .svc
                .suspend_device(&fx.b_fresh, fx.client.devices[D].id, fx.env.now)
                .await,
            Err(AuthError::NotFound)
        ));
        assert_eq!(window_row(&fx.env, fx.account()).await, None);
    });
}

// §7 test 8: the SK change in the revocation commit.

/// One commit with `password_epoch + 1` (a new OPAQUE registration under a new Secret Key),
/// `account_key_epoch + 1`, `identity_epoch + 1` (a full rotation: a bundle signed by both
/// identity keys, every certificate re-issued), `recovery_epoch + 1` (a new code) and two new
/// revocations is accepted; then the old password with the old SK fails OPAQUE login, the new
/// SK logs in, and the thief's session is gone.
#[test]
fn sk_change_in_the_revocation_commit() {
    block_on(async {
        let mut fx = Fixture::new(9140, 4, |_| {}).await;
        fx.suspend(D).await;
        fx.suspend(3).await;
        let account_id = fx.client.account_id;
        let new_sk = SecretKey::generate(&mut fx.env.rng);

        // The new OPAQUE registration under the new SK, over R's fresh session.
        let pw_in = PasswordInput::derive_for_new_password(PASSWORD, &new_sk).unwrap();
        let (reg_state, m1) = client_registration_start(&mut fx.env.rng, &pw_in).unwrap();
        let (setup_id, m2) = fx
            .env
            .svc
            .reregister_start(&fx.a_fresh, &bytes(m1), fx.env.now)
            .await
            .unwrap();
        let reg = client_registration_finish(
            &mut fx.env.rng,
            reg_state,
            &pw_in,
            m2.as_slice(),
            KdfId::DEFAULT,
        )
        .unwrap();

        // New identity keys and the bundle that carries them, signed by both keys.
        let old_identity = core::mem::replace(
            &mut fx.client.identity,
            IdentityKeys::generate(&mut fx.env.rng, 1),
        );
        let bundle = rizzy_core::sign::PublicKeyBundle {
            account_id,
            identity_epoch: 1,
            bundle_seq: 2,
            identity_ed25519: *fx.client.identity.signing_key().verifying_key(),
            identity_x25519: fx.client.identity.public_keys().x25519,
            mail_x25519: None,
            pq_required: false,
            created_at_ms: fx.env.now,
            prev_bundle_hash: *fx.client.bundle.hash(),
        };
        let bundle_wire = bundle
            .sign_identity_change(
                &fx.client.bundle,
                fx.client.identity.signing_key(),
                old_identity.signing_key(),
            )
            .unwrap();
        let (bundle, _) = fx.client.bundle.verify_successor(&bundle_wire).unwrap();

        // Every certificate re-issued under the new key, and both revocations under it.
        let new_key = *fx.client.identity.signing_key().verifying_key();
        let reissued: Vec<_> = fx
            .client
            .devices
            .iter()
            .map(|d| {
                let cert = DeviceCertificate {
                    identity_epoch: 1,
                    ..d.cert.statement().clone()
                };
                let wire = cert.sign(fx.client.identity.signing_key()).unwrap();
                (DeviceCertificate::verify(&wire, &new_key, 1).unwrap(), wire)
            })
            .collect();
        let mut revocations = Vec::new();
        let mut rev_wires = Vec::new();
        for t in [D, 3] {
            let wire = DeviceRevocation {
                account_id,
                device_id: fx.client.devices[t].id,
                last_accepted_device_seq: fx.heads[t],
                revoked_at_ms: fx.env.now,
            }
            .sign(fx.client.identity.signing_key())
            .unwrap();
            revocations.push(DeviceRevocation::verify(&wire, &new_key).unwrap());
            rev_wires.push(bytes(wire));
        }
        let set = rizzy_core::keys::device_set_hash(
            account_id,
            reissued.iter().map(|(c, _)| c),
            revocations.iter(),
        )
        .unwrap();

        // The rotation: a new account key, E_id', the self-grant and B's grant from A.
        let devices = core::mem::take(&mut fx.client.devices);
        let (_, mut change) = rotation(
            &mut fx.env,
            &mut fx.client,
            &fx.a_login.export_key,
            &devices[A],
            &[&devices[B]],
        );
        fx.client.devices = devices;
        let password_epoch = fx.client.state.password_epoch + 1;
        let recovery_epoch = fx.client.state.recovery_epoch + 1;
        let account_key_epoch = fx.client.account_key.epoch();
        // E_srv' under the new registration's export key and the new password epoch.
        let e_srv = reg
            .export_key
            .server_unlock_key(account_id)
            .unwrap()
            .wrap_account_key(
                &mut fx.env.rng,
                &AccountKeyServerWrapCtx {
                    account_id,
                    account_key_epoch,
                    password_epoch,
                    kdf_id: KdfId::DEFAULT,
                },
                &fx.client.account_key,
            )
            .unwrap();
        fx.client.recovery_code = SecretArray::<16>::generate(&mut fx.env.rng);
        let e_rec = recovery_wrap(&mut fx.env.rng, &fx.client, recovery_epoch);
        let key_id = fx.client.account_key.key_id().unwrap();
        let bundle_hash = *bundle.hash();
        let next = fx.client.next_state(|s| {
            s.identity_epoch = 1;
            s.bundle_hash = bundle_hash;
            s.account_key_epoch = account_key_epoch;
            s.account_key_id = key_id;
            s.device_set_hash = set;
            s.password_epoch = password_epoch;
            s.recovery_epoch = recovery_epoch;
        });
        change.account_state = bytes(next.1.clone());
        change.bundle = Some(bytes(bundle_wire.clone()));
        change.device_certificates =
            List::new(reissued.iter().map(|(_, w)| bytes(w.clone())).collect()).unwrap();
        change.device_revocations = List::new(rev_wires).unwrap();
        change.registration_upload = Some(bytes(reg.upload));
        change.setup_id = Some(setup_id);
        change.account_key_server_wrap = Some(AccountKeyServerWrap {
            account_key_epoch,
            password_epoch,
            kdf_id: 1,
            envelope: bytes(e_srv),
        });
        change.recovery = RecoveryUpload::Register(RecoveryRegistration {
            recovery_wrap: e_rec,
            recovery_token_hash: Fixed::from_bytes(
                RecoveryAuthToken::derive(&fx.client.recovery_code)
                    .unwrap()
                    .server_hash(),
            ),
        });

        fx.env
            .svc
            .commit_change(&fx.a_fresh, &change, fx.env.now)
            .await
            .unwrap();
        fx.client.adopt(next);
        fx.client.bundle = bundle;
        fx.client.bundle_wire = bundle_wire;
        fx.client.revocations = revocations;
        for (device, (cert, wire)) in fx.client.devices.iter_mut().zip(reissued) {
            device.cert = cert;
            device.cert_wire = wire;
        }
        let old_sk = core::mem::replace(&mut fx.client.secret_key, new_sk);

        // The window is closed; the thief's session ended with the password epoch.
        assert_eq!(window_row(&fx.env, account_id).await, None);
        assert!(matches!(
            view(&fx.env, &fx.thief).await,
            Err(AuthError::Unauthorized)
        ));
        // The old password with the old SK fails; with the new SK it logs in.
        let name = fx.client.name.clone();
        assert!(matches!(
            fx.env.login_as(&name, PASSWORD, &old_sk, None, None).await,
            Err(AuthError::Unauthorized)
        ));
        let login = fx.env.login(&fx.client).await;
        assert_eq!(
            login.response.account_key_server_wrap.password_epoch,
            password_epoch
        );
        let session = fx.env.bearer(&login.response.session_token).await;
        let seen = view(&fx.env, &session).await.unwrap();
        assert_eq!(seen.device_revocations.len(), 2);
        assert!(seen.suspended_devices.is_empty());
        for t in [D, 3] {
            assert!(
                fx.env
                    .device_auth(&fx.client, &fx.client.devices[t])
                    .await
                    .is_err()
            );
        }
        fx.env
            .device_auth(&fx.client, &fx.client.devices[A])
            .await
            .unwrap();
    });
}

// §7 test 3: the window is not backed up.

/// A dump taken while a window is open holds no `auth_revocation_windows` table; a restore of
/// it has no window (another device's write is not refused) while the suspension survives.
#[test]
fn backup_holds_no_window() {
    block_on(async {
        let mut fx = Fixture::over(Env::new(9150).await, 3).await;
        fx.suspend(D).await;
        assert!(window_row(&fx.env, fx.account()).await.is_some());
        let backup = fx.env.db.dump().await.unwrap();
        assert!(
            backup
                .tables
                .iter()
                .all(|t| t.table != "auth_revocation_windows")
        );
        assert!(
            backup
                .tables
                .iter()
                .any(|t| t.table == "auth_device_certificates")
        );

        restore(&mut fx.env, &backup, |_| {}).await;
        assert_eq!(window_row(&fx.env, fx.account()).await, None);
        let (_, b_dev) = device_session(&mut fx.env, &fx.client, B).await;
        fx.b_dev = b_dev;
        assert_eq!(fx.shown_window().await, None);
        assert_eq!(fx.shown_suspended().await, vec![fx.id(D)]);
        fx.env
            .svc
            .publish_grants(&fx.b_dev, &empty_grants(), fx.env.now)
            .await
            .unwrap();
        let thief = fx.env.login(&fx.client).await;
        let thief = fx.env.bearer(&thief.response.session_token).await;
        let req = web_certificate(&mut fx.env, &fx.client);
        fx.env
            .svc
            .upload_web_certificate(&thief, &req, fx.env.now)
            .await
            .unwrap();
        assert!(
            fx.env
                .device_auth(&fx.client, &fx.client.devices[D])
                .await
                .is_err()
        );
    });
}
