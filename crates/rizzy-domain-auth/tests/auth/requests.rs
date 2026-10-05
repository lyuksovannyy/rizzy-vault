//! The `rizzy-proto` entry points (`*_request`) that the server's account endpoints call:
//! password change, settings, self-revocation, suspension, recovery and TOTP, each built from
//! the wire request type and checked end to end with `rizzy-core`'s client side. The HTTP
//! layer over them is tested in `rizzy-server`'s `tests/http/account.rs`, which cannot run a
//! client (ADR 0016 §3).

use rizzy_core::envelope::purpose::AccountKeyServerWrapCtx;
use rizzy_core::kdf::KdfId;
use rizzy_core::keys::{RecoveryAuthToken, settings_hash};
use rizzy_core::opaque::{PasswordInput, client_registration_finish, client_registration_start};
use rizzy_core::secret::SecretArray;
use rizzy_core::sign::DeviceRevocation;
use rizzy_core::totp::{TotpParams, TotpSecret};
use rizzy_domain_auth::AuthError;
use rizzy_domain_auth::config::FRESH_SESSION_MS;
use rizzy_proto::account::{AccountStateQuery, EnrolDeviceRequest};
use rizzy_proto::auth::{LoginName, RecoveryRegistration, TotpCode};
use rizzy_proto::change::{CommitChangeRequest, DeviceSuspensionRequest, ReregisterStartRequest};
use rizzy_proto::objects::{AccountKeyServerWrap, AccountSettings};
use rizzy_proto::recovery::{RecoveryAuthToken as WireToken, RecoveryRequest};
use rizzy_proto::totp::{TotpDisableRequest, TotpEnrolConfirmRequest};
use rizzy_proto::wire::{Fixed, List};
use zeroize::Zeroizing;

use crate::common::{Client, Device, Env, block_on, bytes, recovery_wrap, wid};

/// A commit of `state` alone.
fn bare(state: Vec<u8>) -> CommitChangeRequest {
    CommitChangeRequest {
        account_state: bytes(state),
        registration_upload: None,
        setup_id: None,
        account_key_server_wrap: None,
        recovery: None,
        account_settings: None,
        device_certificates: List::empty(),
        device_revocations: List::empty(),
        bundle: None,
        identity_secret_keys: None,
        retired_secret_keys: List::empty(),
        device_grants: List::empty(),
        recovery_rewrap: None,
        vault_rotation: None,
    }
}

/// The recovery request for `name` with `token`.
fn recovery_request(name: &str, token: [u8; 32]) -> RecoveryRequest {
    RecoveryRequest {
        login_name: LoginName::from_str(name).unwrap(),
        recovery_auth_token: WireToken::new(Zeroizing::new(token)),
    }
}

/// The server's code for `secret` at `now_ms`.
fn code_at(secret: &TotpSecret, now_ms: u64) -> TotpCode {
    let digits = TotpParams::DEFAULT
        .code_at(secret, now_ms / 1000)
        .unwrap()
        .to_digits();
    TotpCode::new(&digits).unwrap()
}

/// Enrols a new durable device over a fresh OPAQUE session and returns it.
async fn enrol(env: &mut Env, client: &mut Client) -> Device {
    let login = env.login(client).await;
    let session = env.bearer(&login.response.session_token).await;
    let device = client.make_device(&mut env.rng, env.now);
    let mut members: Vec<&Device> = client.devices.iter().collect();
    members.push(&device);
    let set = client.device_set(&members);
    let next = client.next_state(|s| s.device_set_hash = set);
    let req = EnrolDeviceRequest {
        device_certificate: bytes(device.cert_wire.clone()),
        account_state: bytes(next.1.clone()),
    };
    env.svc.enrol_device(&session, &req, env.now).await.unwrap();
    client.adopt(next);
    device
}

/// Registers `password` with a new Secret Key over `session` and builds the commit of
/// `password_epoch + 1` (CRYPTO.md §11.5 steps 3–5). Returns the commit and the new state.
async fn password_change(
    env: &mut Env,
    client: &Client,
    session: &rizzy_domain_auth::Session,
    password: &str,
    secret_key: &rizzy_core::secret_key::SecretKey,
) -> (
    CommitChangeRequest,
    (rizzy_core::sign::AccountState, Vec<u8>),
) {
    let pw_in = PasswordInput::derive_for_new_password(password, secret_key).unwrap();
    let (reg_state, m1) = client_registration_start(&mut env.rng, &pw_in).unwrap();
    let m2 = env
        .svc
        .reregister_start_request(
            session,
            &ReregisterStartRequest {
                registration_request: bytes(m1),
            },
            env.now,
        )
        .await
        .unwrap();
    let reg = client_registration_finish(
        &mut env.rng,
        reg_state,
        &pw_in,
        m2.registration_response.as_slice(),
        KdfId::DEFAULT,
    )
    .unwrap();
    let password_epoch = client.state.password_epoch + 1;
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
    let next = client.next_state(|s| s.password_epoch = password_epoch);
    let commit = CommitChangeRequest {
        registration_upload: Some(bytes(reg.upload)),
        setup_id: Some(m2.setup_id),
        account_key_server_wrap: Some(AccountKeyServerWrap {
            account_key_epoch: client.state.account_key_epoch,
            password_epoch,
            kdf_id: 1,
            envelope: bytes(e_srv),
        }),
        ..bare(next.1.clone())
    };
    (commit, next)
}

#[test]
fn password_change_from_the_wire_types() {
    block_on(async {
        let mut env = Env::new(70).await;
        let mut client = env.signup("lea", "old-password").await;

        // A session older than 5 minutes may not re-register (CRYPTO.md §11.5 step 1).
        let stale = env.login(&client).await;
        let stale = env.bearer(&stale.response.session_token).await;
        env.tick(FRESH_SESSION_MS + 1);
        let refused = env
            .svc
            .reregister_start_request(
                &stale,
                &ReregisterStartRequest {
                    registration_request: bytes(vec![0; 32]),
                },
                env.now,
            )
            .await;
        assert!(matches!(refused, Err(AuthError::FreshSessionRequired)));

        let login = env.login(&client).await;
        let fresh = env.bearer(&login.response.session_token).await;
        // A state that rotates the account key, without the rotation objects: refused.
        let rotating = client.next_state(|s| s.account_key_epoch += 1);
        assert!(matches!(
            env.svc
                .commit_change_request(&fresh, bare(rotating.1), env.now)
                .await,
            Err(AuthError::InvalidRequest)
        ));

        let new_sk = rizzy_core::secret_key::SecretKey::generate(&mut env.rng);
        let (commit, next) =
            password_change(&mut env, &client, &fresh, "new-password", &new_sk).await;
        // Without the new record the step is incomplete: refused.
        let partial = CommitChangeRequest {
            registration_upload: None,
            setup_id: None,
            ..commit.clone()
        };
        assert!(matches!(
            env.svc
                .commit_change_request(&fresh, partial.clone(), env.now)
                .await,
            Err(AuthError::InvalidRequest)
        ));
        env.svc
            .commit_change_request(&fresh, commit.clone(), env.now)
            .await
            .unwrap();
        // The change ended every OPAQUE session (§11.5 step 5); device sessions continue, and a
        // byte-identical repeat over one is success (§11 "Secrets before commit").
        assert!(matches!(
            env.svc
                .commit_change_request(&fresh, commit.clone(), env.now)
                .await,
            Err(AuthError::Unauthorized)
        ));
        let mut ds = env.device_auth(&client, &client.devices[0]).await.unwrap();
        let device_session = env
            .signed(&client, &client.devices[0], &mut ds, b"")
            .await
            .unwrap();
        env.svc
            .commit_change_request(&device_session, commit.clone(), env.now)
            .await
            .unwrap();
        client.adopt(next);

        // The old password is refused; the new one logs in.
        let name = client.name.clone();
        assert!(matches!(
            env.login_as(&name, "old-password", &client.secret_key, None, None)
                .await,
            Err(AuthError::Unauthorized)
        ));
        client.secret_key = new_sk;
        client.password = "new-password".to_owned();
        env.login(&client).await;
    });
}

#[test]
fn settings_change_over_a_device_session() {
    block_on(async {
        let mut env = Env::new(71).await;
        let mut client = env.signup("max", "pw").await;
        let mut ds = env.device_auth(&client, &client.devices[0]).await.unwrap();
        let session = env
            .signed(&client, &client.devices[0], &mut ds, b"")
            .await
            .unwrap();
        let envelope = b"settings-envelope".to_vec();
        let hash = settings_hash(1, Some(&envelope)).unwrap();
        let next = client.next_state(|s| {
            s.settings_seq = 1;
            s.settings_hash = hash;
        });
        // Settings the state does not commit to: refused.
        let wrong = CommitChangeRequest {
            account_settings: Some(AccountSettings {
                settings_seq: 1,
                envelope: bytes(b"other".to_vec()),
            }),
            ..bare(next.1.clone())
        };
        assert!(matches!(
            env.svc
                .commit_change_request(&session, wrong.clone(), env.now)
                .await,
            Err(AuthError::InvalidRequest)
        ));
        let commit = CommitChangeRequest {
            account_settings: Some(AccountSettings {
                settings_seq: 1,
                envelope: bytes(envelope.clone()),
            }),
            ..bare(next.1.clone())
        };
        env.svc
            .commit_change_request(&session, commit.clone(), env.now)
            .await
            .unwrap();
        client.adopt(next);
        let view = env
            .svc
            .account_view(
                &session,
                AccountStateQuery {
                    known_bundle_seq: 1,
                    known_settings_seq: 0,
                },
                env.now,
            )
            .await
            .unwrap();
        assert_eq!(
            view.account_settings.unwrap().envelope.as_slice(),
            envelope.as_slice()
        );
        // A device session may not change the password.
        let other_sk = rizzy_core::secret_key::SecretKey::generate(&mut env.rng);
        let (commit, _) = password_change(&mut env, &client, &session, "other", &other_sk).await;
        assert!(matches!(
            env.svc
                .commit_change_request(&session, commit.clone(), env.now)
                .await,
            Err(AuthError::FreshSessionRequired)
        ));
    });
}

#[test]
fn suspension_and_self_revocation_from_the_wire_types() {
    block_on(async {
        let mut env = Env::new(72).await;
        let mut client = env.signup("ned", "pw").await;
        let second = enrol(&mut env, &mut client).await;
        client.devices.push(second);

        // A re-authenticates from its device session; the fresh session is bound to A.
        let mut a_ds = env.device_auth(&client, &client.devices[0]).await.unwrap();
        let a_session = env
            .signed(&client, &client.devices[0], &mut a_ds, b"")
            .await
            .unwrap();
        let (name, password) = (client.name.clone(), client.password.clone());
        let reauth = env
            .login_as(&name, &password, &client.secret_key, None, Some(&a_session))
            .await
            .unwrap();
        let fresh = env.bearer(&reauth.response.session_token).await;

        let target = |device: &Device| DeviceSuspensionRequest {
            device_id: wid(device.id.to_bytes()),
        };
        env.vault
            .set_head(client.account_id, client.devices[1].id, 4);
        let answer = env
            .svc
            .suspend_device_request(&fresh, &target(&client.devices[1]), env.now)
            .await
            .unwrap();
        assert_eq!(answer.last_accepted_device_seq, 4);
        assert!(env.device_auth(&client, &client.devices[1]).await.is_err());
        // The caller's own device, and a device the account does not hold, are refused.
        assert!(matches!(
            env.svc
                .suspend_device_request(&fresh, &target(&client.devices[0]), env.now)
                .await,
            Err(AuthError::InvalidRequest)
        ));
        let stranger = client.make_device(&mut env.rng, env.now);
        assert!(matches!(
            env.svc
                .suspend_device_request(&fresh, &target(&stranger), env.now)
                .await,
            Err(AuthError::NotFound)
        ));
        // An OPAQUE session not bound to a device may not lift it.
        let unbound = env.login(&client).await;
        let unbound = env.bearer(&unbound.response.session_token).await;
        assert!(matches!(
            env.svc
                .unsuspend_device_request(&unbound, &target(&client.devices[1]), env.now)
                .await,
            Err(AuthError::FreshSessionRequired)
        ));
        env.svc
            .unsuspend_device_request(&fresh, &target(&client.devices[1]), env.now)
            .await
            .unwrap();
        env.device_auth(&client, &client.devices[1]).await.unwrap();

        // The self-revocation of CRYPTO.md §11.3 step 5: a new certificate for this device and
        // the revocation of its old id, without a rotation, over a fresh OPAQUE session.
        let replacement = client.make_device(&mut env.rng, env.now);
        let old = client.devices.remove(1);
        let revocation = DeviceRevocation {
            account_id: client.account_id,
            device_id: old.id,
            last_accepted_device_seq: 4,
            revoked_at_ms: env.now,
        };
        let rev_wire = revocation.sign(client.identity.signing_key()).unwrap();
        client.revocations.push(
            DeviceRevocation::verify(&rev_wire, client.identity.signing_key().verifying_key())
                .unwrap(),
        );
        let mut members: Vec<&Device> = client.devices.iter().collect();
        members.push(&replacement);
        let set = client.device_set(&members);
        let next = client.next_state(|s| s.device_set_hash = set);
        let commit = CommitChangeRequest {
            device_certificates: List::new(vec![bytes(replacement.cert_wire.clone())]).unwrap(),
            device_revocations: List::new(vec![bytes(rev_wire)]).unwrap(),
            ..bare(next.1.clone())
        };
        env.svc
            .commit_change_request(&fresh, commit.clone(), env.now)
            .await
            .unwrap();
        client.adopt(next);
        assert!(env.device_auth(&client, &old).await.is_err());
        env.device_auth(&client, &replacement).await.unwrap();
    });
}

#[test]
fn recovery_from_the_wire_types() {
    block_on(async {
        let mut env = Env::with_config(73, |c| {
            c.recovery_wait_ms = 0;
            // This test makes more attempts for one name than the default buckets allow.
            c.rate_limits.recovery_per_name_source.max_attempts = 100;
            c.rate_limits.recovery_per_name.max_attempts = 100;
        })
        .await;
        let mut client = env.signup("ora", "lost").await;
        let token = client.recovery_token();
        let source = env.source.clone();

        // An unknown name and a wrong code: one answer.
        for req in [
            recovery_request("nobody", token),
            recovery_request("ora", [0x11; 32]),
        ] {
            assert!(matches!(
                env.svc.recovery_start_request(&req, &source, env.now).await,
                Err(AuthError::Unauthorized)
            ));
            assert!(matches!(
                env.svc
                    .recovery_complete_request(&mut env.rng, &req, &source, env.now)
                    .await,
                Err(AuthError::Unauthorized)
            ));
        }

        // Start, then a device cancels it: complete is refused.
        let req = recovery_request("ora", token);
        let started = env
            .svc
            .recovery_start_request(&req, &source, env.now)
            .await
            .unwrap();
        assert_eq!(started.available_at_ms, env.now);
        let mut ds = env.device_auth(&client, &client.devices[0]).await.unwrap();
        let device_session = env
            .signed(&client, &client.devices[0], &mut ds, b"")
            .await
            .unwrap();
        let cancelled = env
            .svc
            .recovery_cancel_request(&device_session, env.now)
            .await
            .unwrap();
        assert!(cancelled.cancelled);
        assert!(
            !env.svc
                .recovery_cancel_request(&device_session, env.now)
                .await
                .unwrap()
                .cancelled
        );
        // An OPAQUE session may not cancel (a device session only, §11.9 step 2).
        let login = env.login(&client).await;
        let opaque = env.bearer(&login.response.session_token).await;
        assert!(matches!(
            env.svc.recovery_cancel_request(&opaque, env.now).await,
            Err(AuthError::Unauthorized)
        ));
        assert!(matches!(
            env.svc
                .recovery_complete_request(&mut env.rng, &req, &source, env.now)
                .await,
            Err(AuthError::Unauthorized)
        ));

        // Start again and complete: E_rec at the state's epochs and a recovery-only session.
        env.svc
            .recovery_start_request(&req, &source, env.now)
            .await
            .unwrap();
        let release = env
            .svc
            .recovery_complete_request(&mut env.rng, &req, &source, env.now)
            .await
            .unwrap();
        assert_eq!(release.account_id, wid(client.account_id.to_bytes()));
        assert_eq!(
            release.recovery_wrap.recovery_epoch,
            client.state.recovery_epoch
        );
        assert_eq!(
            release.account.account_state.as_slice(),
            client.state_wire.as_slice()
        );
        let recovery_session = env.bearer(&release.session_token).await;

        // The recovery commit without a rotation: a new password, a new Secret Key, a new code.
        let new_sk = rizzy_core::secret_key::SecretKey::generate(&mut env.rng);
        let (commit, _) =
            password_change(&mut env, &client, &recovery_session, "found", &new_sk).await;
        // A new password alone, without a new code, is not a recovery commit.
        assert!(matches!(
            env.svc
                .commit_change_request(&recovery_session, commit.clone(), env.now)
                .await,
            Err(AuthError::FreshSessionRequired)
        ));
        client.recovery_code = SecretArray::<16>::generate(&mut env.rng);
        let recovery_epoch = client.state.recovery_epoch + 1;
        let e_rec = recovery_wrap(&mut env.rng, &client, recovery_epoch);
        let next = client.next_state(|s| {
            s.password_epoch += 1;
            s.recovery_epoch = recovery_epoch;
        });
        let commit = CommitChangeRequest {
            recovery: Some(RecoveryRegistration {
                recovery_wrap: e_rec,
                recovery_token_hash: Fixed::from_bytes(
                    RecoveryAuthToken::derive(&client.recovery_code)
                        .unwrap()
                        .server_hash(),
                ),
            }),
            ..CommitChangeRequest {
                account_state: bytes(next.1.clone()),
                ..commit
            }
        };
        env.svc
            .commit_change_request(&recovery_session, commit.clone(), env.now)
            .await
            .unwrap();
        client.adopt(next);
        client.secret_key = new_sk;
        client.password = "found".to_owned();

        // Every session ended; the old code is refused, the new one and the new password work.
        assert!(
            env.signed(&client, &client.devices[0], &mut ds, b"")
                .await
                .is_err()
        );
        assert!(matches!(
            env.svc.recovery_start_request(&req, &source, env.now).await,
            Err(AuthError::Unauthorized)
        ));
        env.svc
            .recovery_start_request(
                &recovery_request("ora", client.recovery_token()),
                &source,
                env.now,
            )
            .await
            .unwrap();
        env.login(&client).await;
    });
}

#[test]
fn totp_from_the_wire_types() {
    block_on(async {
        let mut env = Env::new(74).await;
        let client = env.signup("pia", "pw").await;
        let (name, password) = (client.name.clone(), client.password.clone());
        let login = env.login(&client).await;
        let fresh = env.bearer(&login.response.session_token).await;

        // A device session is not a fresh OPAQUE session.
        let mut ds = env.device_auth(&client, &client.devices[0]).await.unwrap();
        let device_session = env
            .signed(&client, &client.devices[0], &mut ds, b"")
            .await
            .unwrap();
        assert!(matches!(
            env.svc
                .totp_enrol_start_request(&mut env.rng, &device_session, env.now)
                .await,
            Err(AuthError::FreshSessionRequired)
        ));

        let enrolment = env
            .svc
            .totp_enrol_start_request(&mut env.rng, &fresh, env.now)
            .await
            .unwrap();
        assert_eq!(enrolment.totp_credential_seq, 1);
        let secret = TotpSecret::from_slice(enrolment.secret.expose_secret()).unwrap();
        // A wrong code and an unknown enrolment do not confirm.
        let confirm = |seq: u32, code: TotpCode| TotpEnrolConfirmRequest {
            totp_credential_seq: seq,
            code,
        };
        assert!(matches!(
            env.svc
                .totp_enrol_confirm_request(
                    &fresh,
                    &confirm(1, TotpCode::new("000000").unwrap()),
                    env.now
                )
                .await,
            Err(AuthError::Unauthorized)
        ));
        assert!(matches!(
            env.svc
                .totp_enrol_confirm_request(&fresh, &confirm(2, code_at(&secret, env.now)), env.now)
                .await,
            Err(AuthError::NotFound)
        ));
        env.svc
            .totp_enrol_confirm_request(&fresh, &confirm(1, code_at(&secret, env.now)), env.now)
            .await
            .unwrap();
        assert!(matches!(
            env.login_as(&name, &password, &client.secret_key, None, None)
                .await,
            Err(AuthError::SecondFactorRequired)
        ));

        // Removal with a current code over a fresh session; logins need no code after it.
        env.tick(30_000);
        let code = code_at(&secret, env.now);
        let login = env
            .login_as(
                &name,
                &password,
                &client.secret_key,
                Some(code.expose_secret()),
                None,
            )
            .await
            .unwrap();
        let fresh = env.bearer(&login.response.session_token).await;
        env.tick(30_000);
        assert!(matches!(
            env.svc
                .totp_disable_request(
                    &fresh,
                    &TotpDisableRequest {
                        code: TotpCode::new("000000").unwrap()
                    },
                    env.now
                )
                .await,
            Err(AuthError::Unauthorized)
        ));
        env.svc
            .totp_disable_request(
                &fresh,
                &TotpDisableRequest {
                    code: code_at(&secret, env.now),
                },
                env.now,
            )
            .await
            .unwrap();
        env.login(&client).await;
    });
}
