//! The whole happy path, and the checks a client runs on what the server returns.

use rizzy_core::envelope::purpose::{AccountKeyServerWrapCtx, IdentitySecretKeysCtx};
use rizzy_core::kdf::KdfId;
use rizzy_core::keys::device_set_hash;
use rizzy_core::sign::{AccountState, DeviceCertificate, PublicKeyBundle};
use rizzy_domain_auth::{AuthError, SessionKind};
use rizzy_proto::account::AccountStateQuery;

use crate::common::{Env, block_on};

/// Signup, login on a new device with the §11.2 step 6 checks, device authentication and a
/// signed request, then replays.
#[test]
fn signup_login_device_auth_and_signed_requests() {
    block_on(async {
        let mut env = Env::new(1).await;
        let client = env
            .signup("Alice@Example.com", "correct horse battery staple")
            .await;

        // Login (§11.2): the client verifies everything the server returned.
        let login = env.login(&client).await;
        let r = &login.response;
        assert_eq!(r.account_id.to_bytes(), client.account_id.to_bytes());
        let wrap = &r.account_key_server_wrap;
        let key = login
            .export_key
            .server_unlock_key(client.account_id)
            .unwrap()
            .unwrap_account_key(
                &AccountKeyServerWrapCtx {
                    account_id: client.account_id,
                    account_key_epoch: wrap.account_key_epoch,
                    password_epoch: wrap.password_epoch,
                    kdf_id: KdfId::from_u16(wrap.kdf_id).unwrap(),
                },
                wrap.envelope.as_slice(),
            )
            .unwrap();
        let bundle =
            PublicKeyBundle::verify_self_signed(r.account.bundles.as_slice()[0].as_slice())
                .unwrap();
        let state = AccountState::verify(
            r.account.account_state.as_slice(),
            &bundle.identity_ed25519,
            bundle.identity_epoch,
        )
        .unwrap();
        assert!(state.matches_account_key(&key));
        assert!(state.matches_bundle(&bundle));
        assert!(state.matches_settings(None));
        let identity = key
            .unwrap_identity_keys(
                &IdentitySecretKeysCtx {
                    account_id: client.account_id,
                    identity_epoch: r.account.identity_secret_keys.identity_epoch,
                },
                r.account.identity_secret_keys.envelope.as_slice(),
            )
            .unwrap();
        assert_eq!(identity.public_keys(), bundle.identity_public_keys());
        let certs: Vec<_> = r
            .account
            .device_certificates
            .iter()
            .map(|w| DeviceCertificate::verify(w.as_slice(), &bundle.identity_ed25519, 0).unwrap())
            .collect();
        assert_eq!(
            device_set_hash(client.account_id, certs.iter(), []).unwrap(),
            state.device_set_hash
        );
        assert_eq!(r.account.vault_self_grants.len(), 1);
        let opaque = env.bearer(&r.session_token).await;
        assert_eq!(opaque.kind, SessionKind::Opaque);
        assert!(opaque.is_fresh_opaque(env.now));

        // Device authentication and request signing (§5.10).
        let device = &client.devices[0];
        let mut session = env.device_auth(&client, device).await.unwrap();
        let s = env
            .signed(&client, device, &mut session, b"one")
            .await
            .unwrap();
        assert_eq!(s.kind, SessionKind::Device);
        assert_eq!(s.device_id, Some(device.id));
        env.signed(&client, device, &mut session, b"two")
            .await
            .unwrap();

        // A replayed counter, even with a fresh valid signature, is refused.
        let replay = env.signed_with(&client, device, &session, 1, b"one").await;
        assert!(matches!(replay, Err(AuthError::Unauthorized)));
        // Out of order within the window is fine, once.
        env.signed_with(&client, device, &session, 10, b"x")
            .await
            .unwrap();
        env.signed_with(&client, device, &session, 5, b"y")
            .await
            .unwrap();
        assert!(
            env.signed_with(&client, device, &session, 5, b"y")
                .await
                .is_err()
        );
        // 64 or more behind the highest is refused.
        env.signed_with(&client, device, &session, 100, b"z")
            .await
            .unwrap();
        assert!(
            env.signed_with(&client, device, &session, 36, b"z")
                .await
                .is_err()
        );
        env.signed_with(&client, device, &session, 37, b"z")
            .await
            .unwrap();

        // Without a signature a device session is refused; a signature by another key too.
        let unsigned = env
            .svc
            .authenticate_request(
                session.token.expose_secret(),
                None,
                crate::common::request(b"{}"),
                env.now,
            )
            .await;
        assert!(matches!(unsigned, Err(AuthError::Unauthorized)));
        let other = client.make_device(&mut env.rng, env.now);
        let forged = crate::common::Device {
            id: device.id,
            keys: other.keys,
            cert: other.cert,
            cert_wire: other.cert_wire,
        };
        let bad = env.signed_with(&client, &forged, &session, 200, b"f").await;
        assert!(matches!(bad, Err(AuthError::Unauthorized)));

        // The unlock view (§11.3 step 2.2) serves only what changed.
        let view = env
            .svc
            .account_view(
                &s,
                AccountStateQuery {
                    known_bundle_seq: 1,
                    known_settings_seq: 0,
                },
                env.now,
            )
            .await
            .unwrap();
        assert!(view.bundles.is_empty());
        assert_eq!(view.account_state.as_slice(), client.state_wire.as_slice());

        // The session outlives its challenge (60 s); a new challenge answers at most once.
        env.tick(61_000);
        env.signed_with(&client, device, &session, 101, b"late")
            .await
            .unwrap();
        env.device_auth(&client, device).await.unwrap();
        // The session ends after its lifetime (1 h by default).
        env.tick(3_600_000);
        assert!(
            env.signed_with(&client, device, &session, 102, b"x")
                .await
                .is_err()
        );
    });
}

/// A byte-identical repeat of a signup commit is success; any difference is a conflict, and a
/// taken name is refused.
#[test]
fn signup_is_idempotent_and_names_are_unique() {
    block_on(async {
        let mut env = Env::new(2).await;
        let (client, finish) = env.signup_full("bob", "pw one").await;
        env.svc.register_finish(&finish, env.now).await.unwrap();
        let mut changed = finish.clone();
        changed.identity_secret_keys.envelope =
            crate::common::bytes(vec![0x11; finish.identity_secret_keys.envelope.len()]);
        assert!(matches!(
            env.svc.register_finish(&changed, env.now).await,
            Err(AuthError::Conflict)
        ));
        env.login(&client).await;
        // Another account for the same name.
        let taken = env.signup_attempt("BOB").await;
        assert!(matches!(taken, Err(AuthError::Conflict)));
        // An unknown login name format is refused before any lookup.
        let bad = env.signup_attempt("bob smith").await;
        assert!(matches!(bad, Err(AuthError::InvalidRequest)));
    });
}

/// Signup is closed by default and invite-only when configured (CRYPTO.md §5.9).
#[test]
fn signup_policies() {
    block_on(async {
        let mut env = Env::with_config(3, |c| {
            c.signup = rizzy_domain_auth::SignupPolicy::Closed;
        })
        .await;
        assert!(matches!(
            env.signup_attempt("carol").await,
            Err(AuthError::SignupRefused)
        ));
        let mut env = Env::with_config(4, |c| {
            c.signup =
                rizzy_domain_auth::SignupPolicy::Invite(Box::new(crate::common::TestInvites));
        })
        .await;
        assert!(matches!(
            env.signup_attempt("carol").await,
            Err(AuthError::SignupRefused)
        ));
    });
}

impl Env {
    /// Only the `register_start` of a signup for `name`, with a fresh account id.
    pub(crate) async fn signup_attempt(
        &mut self,
        name: &str,
    ) -> Result<rizzy_proto::auth::RegisterStartResponse, AuthError> {
        let secret_key = rizzy_core::secret_key::SecretKey::generate(&mut self.rng);
        let pw_in =
            rizzy_core::opaque::PasswordInput::derive_for_new_password("x", &secret_key).unwrap();
        let (_, m1) = rizzy_core::opaque::client_registration_start(&mut self.rng, &pw_in).unwrap();
        let account = rizzy_core::ids::AccountId::generate(&mut self.rng);
        let Ok(login_name) = rizzy_proto::wire::Text::new(name.to_owned()) else {
            return Err(AuthError::InvalidRequest);
        };
        let start = rizzy_proto::auth::RegisterStartRequest {
            invite: None,
            login_name,
            account_id: crate::common::wid(account.to_bytes()),
            registration_request: crate::common::bytes(m1),
        };
        self.svc
            .register_start(&start, &self.source, self.now)
            .await
    }
}

/// Every flow's future is `Send`, so the server can run it on a multi-threaded runtime (axum
/// requires it). Checked at compile time; the futures are dropped unpolled.
#[test]
fn flow_futures_are_send() {
    fn send<T: Send>(_: T) {}
    block_on(async {
        let mut env = Env::new(5).await;
        let (client, finish) = env.signup_full("sam", "pw").await;
        let login = env.login(&client).await;
        let session = env.bearer(&login.response.session_token).await;
        let id = crate::common::wid([1; 16]);
        let stmt = crate::common::bytes(vec![1]);
        let msg = crate::common::bytes(vec![1]);
        let svc = &env.svc;
        let rng = &mut env.rng;
        let now = env.now;
        send(svc.purge_expired(now));
        send(svc.end_stale_reconciliation_epochs(now));
        send(svc.recovery_start("sam", &[0; 32], b"", now));
        send(svc.recovery_cancel(&session, now));
        send(svc.totp_enrol_confirm(&session, 1, "000000", now));
        send(svc.totp_disable(&session, "000000", now));
        send(svc.device_grants(&session, now));
        send(svc.suspend_device(&session, client.devices[0].id, now));
        send(svc.account_view(
            &session,
            AccountStateQuery {
                known_bundle_seq: 0,
                known_settings_seq: 0,
            },
            now,
        ));
        send(svc.authenticate_request(b"", None, crate::common::request(b""), now));
        send(svc.totp_enrol_start(rng, &session, now));
        send(svc.register_finish(&finish, now));
        send(svc.register_start(
            &rizzy_proto::auth::RegisterStartRequest {
                invite: None,
                login_name: rizzy_proto::wire::Text::new("x".to_owned()).unwrap(),
                account_id: id,
                registration_request: msg.clone(),
            },
            b"",
            now,
        ));
        let start = rizzy_proto::auth::LoginStartRequest {
            login_name: rizzy_proto::wire::Text::new("x".to_owned()).unwrap(),
            ke1: msg.clone(),
        };
        send(svc.login_start(rng, &start, b"", Some(&session), now));
        let finish_login = rizzy_proto::auth::LoginFinishRequest {
            login_id: id,
            ke3: msg.clone(),
            totp: None,
        };
        send(svc.login_finish(rng, &finish_login, b"", Some(&session), now));
        let das = rizzy_proto::auth::DeviceAuthStartRequest {
            account_id: id,
            device_id: id,
            reconciliation: None,
        };
        send(svc.device_auth_start(rng, &das, now));
        let daf = rizzy_proto::auth::DeviceAuthFinishRequest {
            account_id: id,
            device_id: id,
            challenge: rizzy_proto::wire::Fixed::from_bytes([0; 32]),
            signature: rizzy_proto::wire::Fixed::from_bytes([0; 82]),
            reconciliation: None,
        };
        send(svc.device_auth_finish(rng, &daf, now));
        send(svc.recovery_complete(rng, "sam", &[0; 32], b"", now));
        send(svc.reregister_start(&session, &msg, now));
        send(svc.unsuspend_device(&session, client.devices[0].id, now));
        let enrol = rizzy_proto::account::EnrolDeviceRequest {
            device_certificate: stmt.clone(),
            account_state: stmt.clone(),
        };
        send(svc.enrol_device(&session, &enrol, now));
        let web = rizzy_proto::account::UploadWebDeviceCertificateRequest {
            device_certificate: stmt.clone(),
        };
        send(svc.upload_web_certificate(&session, &web, now));
        let ack = rizzy_proto::account::AckDeviceGrantsRequest {
            account_key_epoch: 0,
        };
        send(svc.ack_device_grants(&session, &ack, now));
        let change = rizzy_domain_auth::AccountChange::<Vec<rizzy_proto::objects::VaultSelfGrant>> {
            account_state: stmt.clone(),
            bundle: None,
            registration_upload: None,
            account_key_server_wrap: None,
            identity_secret_keys: None,
            recovery: rizzy_domain_auth::RecoveryUpload::None,
            account_settings: None,
            retired_secret_keys: Vec::new(),
            device_certificates: rizzy_proto::wire::List::empty(),
            device_revocations: rizzy_proto::wire::List::empty(),
            device_grants: rizzy_proto::wire::List::empty(),
            vault_rotation: None,
        };
        send(svc.commit_change(&session, &change, now));
        let bundles = rizzy_proto::account::PublishBundlesRequest {
            bundles: rizzy_proto::wire::List::empty(),
        };
        send(svc.publish_bundles(&session, &bundles, now));
        let state = rizzy_proto::account::PublishAccountStateRequest {
            account_state: stmt.clone(),
            device_certificates: rizzy_proto::wire::List::empty(),
            device_revocations: rizzy_proto::wire::List::empty(),
        };
        send(svc.publish_account_state(&session, &state, now));
        let grants = rizzy_proto::account::PublishGrantsRequest {
            vault_self_grants: rizzy_proto::wire::List::empty(),
            device_grants: rizzy_proto::wire::List::empty(),
        };
        send(svc.publish_grants(&session, &grants, now));
    });
}

/// A device-auth challenge answers at most once, only for the device it was issued to, and
/// only within its 60 s; a signature bound to another origin is refused (§5.10 step 4).
#[test]
fn challenges_are_single_use_and_bound() {
    block_on(async {
        let mut env = Env::new(6).await;
        let mut client = env.signup("tia", "pw").await;
        let device = client.devices.remove(0);
        let other = client.make_device(&mut env.rng, env.now);
        let start = rizzy_proto::auth::DeviceAuthStartRequest {
            account_id: crate::common::wid(client.account_id.to_bytes()),
            device_id: crate::common::wid(device.id.to_bytes()),
            reconciliation: None,
        };
        let sign = |origin: &rizzy_core::normalize::ServerOrigin, challenge: [u8; 32]| {
            rizzy_core::sign::DeviceAuth {
                server_origin: origin,
                account_id: client.account_id,
                device_id: device.id,
                challenge,
            }
            .sign(device.keys.signing_key())
            .unwrap()
        };
        let finish = |challenge: rizzy_proto::auth::Challenge, sig: [u8; 82], id| {
            rizzy_proto::auth::DeviceAuthFinishRequest {
                account_id: crate::common::wid(client.account_id.to_bytes()),
                device_id: crate::common::wid(id),
                challenge,
                signature: rizzy_proto::wire::Fixed::from_bytes(sig),
                reconciliation: None,
            }
        };
        let origin = crate::common::origin();
        let evil = rizzy_core::normalize::ServerOrigin::parse("https://evil.example").unwrap();

        // Another origin's signature, then another device's id: refused, and each uses up the
        // challenge.
        for (o, id) in [(&evil, device.id), (&origin, other.id)] {
            let c = env
                .svc
                .device_auth_start(&mut env.rng, &start, env.now)
                .await
                .unwrap();
            let req = finish(
                c.challenge,
                sign(o, c.challenge.to_bytes()).to_bytes(),
                id.to_bytes(),
            );
            let r = env
                .svc
                .device_auth_finish(&mut env.rng, &req, env.now)
                .await;
            assert!(matches!(r, Err(AuthError::Unauthorized)));
        }
        // The right answer works once.
        let c = env
            .svc
            .device_auth_start(&mut env.rng, &start, env.now)
            .await
            .unwrap();
        let req = finish(
            c.challenge,
            sign(&origin, c.challenge.to_bytes()).to_bytes(),
            device.id.to_bytes(),
        );
        env.svc
            .device_auth_finish(&mut env.rng, &req, env.now)
            .await
            .unwrap();
        assert!(matches!(
            env.svc
                .device_auth_finish(&mut env.rng, &req, env.now)
                .await,
            Err(AuthError::Unauthorized)
        ));
        // A challenge older than 60 s is refused.
        let c = env
            .svc
            .device_auth_start(&mut env.rng, &start, env.now)
            .await
            .unwrap();
        env.tick(60_000);
        let req = finish(
            c.challenge,
            sign(&origin, c.challenge.to_bytes()).to_bytes(),
            device.id.to_bytes(),
        );
        assert!(matches!(
            env.svc
                .device_auth_finish(&mut env.rng, &req, env.now)
                .await,
            Err(AuthError::Unauthorized)
        ));
    });
}
