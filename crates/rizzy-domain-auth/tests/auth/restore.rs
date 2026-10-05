//! The reconciliation epoch after a restore (THREAT_MODEL §5.8, INV-59; ADR 0012 §7): the
//! restore drill of INV-59 with a password change and an enrolment made after the backup; the
//! end of the epoch on a repeated state and at its limit; the device-set check of a
//! certificate-carrying device authentication.

use rizzy_core::envelope::purpose::AccountKeyServerWrapCtx;
use rizzy_core::kdf::KdfId;
use rizzy_core::opaque::{PasswordInput, client_registration_finish, client_registration_start};
use rizzy_domain_auth::{AccountChange, AuthConfig, AuthError, RecoveryUpload, Session};
use rizzy_proto::account::{EnrolDeviceRequest, PublishAccountStateRequest, PublishGrantsRequest};
use rizzy_proto::auth::{DeviceAuthFinishRequest, DeviceAuthStartRequest, Reconciliation};
use rizzy_proto::objects::{AccountKeyServerWrap, VaultSelfGrant};
use rizzy_proto::wire::{Fixed, List};
use rizzy_storage::{Database, Dump, RestoreGeneration, SqliteOptions, WriterLock};

use crate::common::{Client, Device, DeviceSession, Env, block_on, bytes, origin, wid};

/// Re-registers OPAQUE with `password` over `session` (a password change when `bump`, else a
/// same-password re-registration) and commits it.
pub(crate) async fn reregister(
    env: &mut Env,
    client: &mut Client,
    session: &Session,
    password: &str,
    bump: bool,
) -> Result<(), AuthError> {
    let pw_in = PasswordInput::derive_for_new_password(password, &client.secret_key).unwrap();
    let (state, m1) = client_registration_start(&mut env.rng, &pw_in).unwrap();
    let (setup_id, m2) = env
        .svc
        .reregister_start(session, &bytes(m1), env.now)
        .await?;
    let reg =
        client_registration_finish(&mut env.rng, state, &pw_in, m2.as_slice(), KdfId::DEFAULT)
            .unwrap();
    let pe = client.state.password_epoch + u32::from(bump);
    let e_srv = reg
        .export_key
        .server_unlock_key(client.account_id)
        .unwrap()
        .wrap_account_key(
            &mut env.rng,
            &AccountKeyServerWrapCtx {
                account_id: client.account_id,
                account_key_epoch: client.account_key.epoch(),
                password_epoch: pe,
                kdf_id: KdfId::DEFAULT,
            },
            &client.account_key,
        )
        .unwrap();
    let next = client.next_state(|s| s.password_epoch = pe);
    let change = AccountChange::<Vec<VaultSelfGrant>> {
        account_state: bytes(next.1.clone()),
        bundle: None,
        registration_upload: Some(bytes(reg.upload)),
        setup_id: Some(setup_id),
        account_key_server_wrap: Some(AccountKeyServerWrap {
            account_key_epoch: client.account_key.epoch(),
            password_epoch: pe,
            kdf_id: 1,
            envelope: bytes(e_srv),
        }),
        identity_secret_keys: None,
        recovery: RecoveryUpload::None,
        account_settings: None,
        retired_secret_keys: rizzy_proto::wire::List::empty(),
        device_certificates: List::empty(),
        device_revocations: List::empty(),
        device_grants: List::empty(),
        vault_rotation: None,
    };
    env.svc.commit_change(session, &change, env.now).await?;
    client.adopt(next);
    password.clone_into(&mut client.password);
    Ok(())
}

/// Device authentication carrying a certificate, the state `state_wire` that lists it, the
/// chain, and the certificates of that state's device set (`set`, which lists `device` for a
/// real one).
async fn reconcile(
    env: &mut Env,
    client: &Client,
    device: &Device,
    state_wire: &[u8],
    set: &[&Device],
) -> Result<DeviceSession, AuthError> {
    let rec = Reconciliation {
        device_certificate: bytes(device.cert_wire.clone()),
        account_state: bytes(state_wire.to_vec()),
        bundles: List::new(vec![bytes(client.bundle_wire.clone())]).unwrap(),
        device_certificates: List::new(set.iter().map(|d| bytes(d.cert_wire.clone())).collect())
            .unwrap(),
        device_revocations: List::empty(),
    };
    let start = DeviceAuthStartRequest {
        account_id: wid(client.account_id.to_bytes()),
        device_id: wid(device.id.to_bytes()),
        reconciliation: Some(rec.clone()),
    };
    let challenge = env
        .svc
        .device_auth_start(&mut env.rng, &start, env.now)
        .await?
        .challenge;
    let o = origin();
    let signature = rizzy_core::sign::DeviceAuth {
        server_origin: &o,
        account_id: client.account_id,
        device_id: device.id,
        challenge: challenge.to_bytes(),
    }
    .sign(device.keys.signing_key())
    .unwrap();
    let finish = DeviceAuthFinishRequest {
        account_id: wid(client.account_id.to_bytes()),
        device_id: wid(device.id.to_bytes()),
        challenge,
        signature: Fixed::from_bytes(signature.to_bytes()),
        reconciliation: Some(rec),
    };
    let done = env
        .svc
        .device_auth_finish(&mut env.rng, &finish, env.now)
        .await?;
    Ok(DeviceSession {
        token: done.session_token,
        session_id: rizzy_core::ids::SessionId::from_bytes(done.session_id.to_bytes()),
        counter: 1,
        reregister: done.reregister,
    })
}

/// Restores `backup` into a new database a second after now, which opens a reconciliation
/// epoch for every account, and serves it with `adjust`ed configuration a second later.
async fn restore(env: &mut Env, backup: &Dump, adjust: impl FnOnce(&mut AuthConfig)) {
    env.tick(1_000);
    let path = env.dir.join("restored.db");
    let lock = WriterLock::acquire(&path).unwrap();
    let db = Database::open_sqlite(&SqliteOptions::new(&path), lock)
        .await
        .unwrap();
    db.restore(
        backup,
        RestoreGeneration([7; 16]),
        i64::try_from(env.now).unwrap(),
    )
    .await
    .unwrap();
    env.secrets
        .check_database(&db, env.now)
        .await
        .unwrap()
        .unwrap();
    env.reopen(db, adjust);
    env.tick(1_000);
}

/// A device session of `device`, used for one signed request.
async fn device_session(env: &mut Env, client: &Client, device: &Device) -> Session {
    let mut ds = env.device_auth(client, device).await.unwrap();
    env.signed(client, device, &mut ds, b"").await.unwrap()
}

/// Whether the reconciliation epoch is open, as the healing calls see it: an empty healing step 3
/// (a success in and outside the epoch, ADR 0028 "re-sent grants are accepted") ends an epoch
/// past its limit, then the epoch row is read.
async fn epoch_open(env: &Env, session: &Session) -> bool {
    let empty = PublishGrantsRequest {
        vault_self_grants: List::empty(),
        device_grants: List::empty(),
    };
    env.svc
        .publish_grants(session, &empty, env.now)
        .await
        .unwrap();
    let mut tx = env.db.begin_read().await.unwrap();
    let open = rizzy_storage::meta::reconciliation_epoch(tx.conn(), session.account_id.as_bytes())
        .await
        .unwrap()
        .is_some();
    tx.finish().await.unwrap();
    open
}

#[test]
fn restore_drill_reconciliation_epoch() {
    block_on(async {
        let mut env = Env::new(60).await;
        let mut client = env.signup("lea", "old password").await;
        let backup = env.db.dump().await.unwrap();

        // After the backup: enrol B, then change the password.
        let login = env.login(&client).await;
        let fresh = env.bearer(&login.response.session_token).await;
        let b = client.make_device(&mut env.rng, env.now);
        let set = client.device_set(&[&client.devices[0], &b]);
        let next = client.next_state(|s| s.device_set_hash = set);
        env.svc
            .enrol_device(
                &fresh,
                &EnrolDeviceRequest {
                    device_certificate: bytes(b.cert_wire.clone()),
                    account_state: bytes(next.1.clone()),
                },
                env.now,
            )
            .await
            .unwrap();
        client.adopt(next);
        client.devices.push(b);
        reregister(&mut env, &mut client, &fresh, "new password", true)
            .await
            .unwrap();
        env.login(&client).await;

        // Restore the backup into a new database.
        restore(&mut env, &backup, |_| {}).await;

        // The residual risk: until a device presents the newer state, the old password works.
        let secret_key =
            rizzy_core::secret_key::SecretKey::from_slice(client.secret_key.expose_secret())
                .unwrap();
        env.login_as("lea", "old password", &secret_key, None, None)
            .await
            .unwrap();

        // B, enrolled after the backup, is unknown: it authenticates only with its objects.
        let b_dev = client.devices.pop().unwrap();
        assert!(env.device_auth(&client, &b_dev).await.is_err());
        // The carried set must list B: B alone does not reproduce the state's set.
        assert!(matches!(
            reconcile(&mut env, &client, &b_dev, &client.state_wire, &[&b_dev]).await,
            Err(AuthError::Unauthorized)
        ));
        let set = [&client.devices[0], &b_dev];
        let mut b_session = reconcile(&mut env, &client, &b_dev, &client.state_wire, &set)
            .await
            .unwrap();
        env.signed(&client, &b_dev, &mut b_session, b"")
            .await
            .unwrap();
        client.devices.push(b_dev);

        // A, from the restored set, re-publishes its newest state: adopted, epoch ended.
        let a = &client.devices[0];
        let mut a_ds = env.device_auth(&client, a).await.unwrap();
        let a_session = env.signed(&client, a, &mut a_ds, b"").await.unwrap();
        let publish = PublishAccountStateRequest {
            account_state: bytes(client.state_wire.clone()),
            device_certificates: List::new(
                client
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
        env.svc
            .publish_account_state(&a_session, &publish, env.now)
            .await
            .unwrap();

        // INV-59: the old password is refused now; so is the new one until a device
        // re-registers it (the restore lost that record).
        let old = env
            .login_as("lea", "old password", &secret_key, None, None)
            .await;
        assert!(matches!(old, Err(AuthError::Unauthorized)));
        let new = env
            .login_as("lea", "new password", &secret_key, None, None)
            .await;
        assert!(matches!(new, Err(AuthError::Unauthorized)));
        reregister(&mut env, &mut client, &a_session, "new password", false)
            .await
            .unwrap();
        env.login(&client).await;

        // The epoch ended: an unknown device gets no challenge, a newer state is refused.
        let c = client.make_device(&mut env.rng, env.now);
        assert!(matches!(
            reconcile(
                &mut env,
                &client,
                &c,
                &client.state_wire,
                &[&client.devices[0], &c]
            )
            .await,
            Err(AuthError::Unauthorized)
        ));
        let newer = client.next_state(|s| s.state_seq += 1);
        let publish = PublishAccountStateRequest {
            account_state: bytes(newer.1),
            ..publish
        };
        assert!(matches!(
            env.svc
                .publish_account_state(&a_session, &publish, env.now)
                .await,
            Err(AuthError::StateConflict)
        ));
    });
}

/// Enrols a new durable device over `fresh` after the backup, as the drill does.
async fn enrol_after_backup(env: &mut Env, client: &mut Client, fresh: &Session) {
    let b = client.make_device(&mut env.rng, env.now);
    let set = client.device_set(&[&client.devices[0], &b]);
    let next = client.next_state(|s| s.device_set_hash = set);
    env.svc
        .enrol_device(
            fresh,
            &EnrolDeviceRequest {
                device_certificate: bytes(b.cert_wire.clone()),
                account_state: bytes(next.1.clone()),
            },
            env.now,
        )
        .await
        .unwrap();
    client.adopt(next);
    client.devices.push(b);
}

/// ADR 0012 §7: the epoch ends once a device of the restored set has uploaded a verified state
/// newer than the restored one, also when another session (which cannot end it) adopted that
/// state first and the restored device's upload is a byte-identical repeat.
#[test]
fn restored_device_repeating_an_adopted_state_ends_the_epoch() {
    block_on(async {
        let mut env = Env::new(61).await;
        let mut client = env.signup("mia", "pw").await;
        let backup = env.db.dump().await.unwrap();
        let login = env.login(&client).await;
        let fresh = env.bearer(&login.response.session_token).await;
        enrol_after_backup(&mut env, &mut client, &fresh).await;
        restore(&mut env, &backup, |_| {}).await;

        // An OPAQUE session adopts the newest state first: the epoch stays open.
        let login = env.login(&client).await;
        let opaque = env.bearer(&login.response.session_token).await;
        let publish = PublishAccountStateRequest {
            account_state: bytes(client.state_wire.clone()),
            device_certificates: List::new(
                client
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
        env.svc
            .publish_account_state(&opaque, &publish, env.now)
            .await
            .unwrap();
        assert!(epoch_open(&env, &opaque).await);

        // A repeat by the same OPAQUE session changes nothing.
        env.svc
            .publish_account_state(&opaque, &publish, env.now)
            .await
            .unwrap();
        assert!(epoch_open(&env, &opaque).await);

        // A, of the restored set, uploads the same state: a repeat, and the epoch ends.
        let a = device_session(&mut env, &client, &client.devices[0]).await;
        env.svc
            .publish_account_state(&a, &publish, env.now)
            .await
            .unwrap();
        assert!(!epoch_open(&env, &a).await);

        // ADR 0028 "re-sent grants are accepted": after the epoch, the same device re-sends
        // the self-grants the server holds (its step 3, after the step 2 that ended the epoch),
        // a success that stores nothing; a grant the server does not hold is refused.
        let view = env
            .svc
            .account_view(
                &a,
                rizzy_proto::account::AccountStateQuery {
                    known_bundle_seq: 0,
                    known_settings_seq: 0,
                },
                env.now,
            )
            .await
            .unwrap();
        assert!(!view.vault_self_grants.is_empty());
        let resent = PublishGrantsRequest {
            vault_self_grants: view.vault_self_grants.clone(),
            device_grants: List::empty(),
        };
        env.svc.publish_grants(&a, &resent, env.now).await.unwrap();
        let other = PublishGrantsRequest {
            vault_self_grants: List::new(vec![crate::common::self_grant(&mut env.rng, &client)])
                .unwrap(),
            device_grants: List::empty(),
        };
        assert!(matches!(
            env.svc.publish_grants(&a, &other, env.now).await,
            Err(AuthError::InvalidRequest)
        ));
    });
}

/// ADR 0012 §7: a certificate-carrying device authentication needs "the `account-state` that
/// lists it". The held state, byte-identical, does not list a device it was never enrolled
/// in, whatever set the device claims.
#[test]
fn reconciliation_needs_a_state_that_lists_the_device() {
    block_on(async {
        let mut env = Env::new(62).await;
        let client = env.signup("noa", "pw").await;
        let backup = env.db.dump().await.unwrap();
        restore(&mut env, &backup, |_| {}).await;
        let a = device_session(&mut env, &client, &client.devices[0]).await;
        assert!(epoch_open(&env, &a).await);

        // A certificate the identity key signed, for a device no state lists.
        let d = client.make_device(&mut env.rng, env.now);
        let held = client.state_wire.clone();
        for set in [
            vec![&client.devices[0], &d],
            vec![&client.devices[0]],
            vec![&d],
        ] {
            assert!(matches!(
                reconcile(&mut env, &client, &d, &held, &set).await,
                Err(AuthError::Unauthorized)
            ));
        }
        assert!(env.device_auth(&client, &d).await.is_err());
    });
}

/// ADR 0012 §7: the epoch ends after the admin-set limit, even when no `worker` run ended it.
#[test]
fn reconciliation_limit_holds_without_the_worker() {
    block_on(async {
        let mut env = Env::new(63).await;
        let mut client = env.signup("ora", "pw").await;
        let backup = env.db.dump().await.unwrap();
        let login = env.login(&client).await;
        let fresh = env.bearer(&login.response.session_token).await;
        enrol_after_backup(&mut env, &mut client, &fresh).await;
        restore(&mut env, &backup, |c| c.reconciliation_limit_ms = 60_000).await;
        let a = device_session(&mut env, &client, &client.devices[0]).await;
        assert!(epoch_open(&env, &a).await);

        env.tick(60_000);
        assert!(!epoch_open(&env, &a).await);
        // B, enrolled after the backup, can no longer reconcile.
        let set = [&client.devices[0], &client.devices[1]];
        assert!(matches!(
            reconcile(
                &mut env,
                &client,
                &client.devices[1],
                &client.state_wire,
                &set
            )
            .await,
            Err(AuthError::Unauthorized)
        ));
    });
}

/// ADR 0032 §3 and finding "self-grants outside the lag rule": inside the reconciliation epoch,
/// healing step 3a (`healing/grants`) no longer stores a vault self-grant. A self-grant stored
/// there would stop lagging (its `account_key_epoch` the state's) while the vault's epoch and
/// wrap set stayed behind, so step 3b could never repair the vault. Only the stored self-grant,
/// byte for byte, is accepted; any other, at the same or a newer account epoch, is refused and
/// nothing changes.
#[test]
fn healing_grants_never_store_a_self_grant() {
    block_on(async {
        let mut env = Env::new(64).await;
        let client = env.signup("pia", "pw").await;
        let backup = env.db.dump().await.unwrap();
        restore(&mut env, &backup, |_| {}).await;
        let a = device_session(&mut env, &client, &client.devices[0]).await;
        assert!(epoch_open(&env, &a).await);
        let query = || rizzy_proto::account::AccountStateQuery {
            known_bundle_seq: 0,
            known_settings_seq: 0,
        };
        let held = env
            .svc
            .account_view(&a, query(), env.now)
            .await
            .unwrap()
            .vault_self_grants;
        assert_eq!(held.len(), 1);

        // The stored self-grant, re-sent: a success that stores nothing.
        let resent = PublishGrantsRequest {
            vault_self_grants: held.clone(),
            device_grants: List::empty(),
        };
        env.svc.publish_grants(&a, &resent, env.now).await.unwrap();

        // Another envelope at the same epochs, and one at a newer account epoch: refused.
        let same_epochs = crate::common::self_grant(&mut env.rng, &client);
        let mut newer: VaultSelfGrant = same_epochs.clone();
        newer.account_key_epoch += 1;
        newer.vault_key_epoch += 1;
        for grant in [same_epochs, newer] {
            let request = PublishGrantsRequest {
                vault_self_grants: List::new(vec![grant]).unwrap(),
                device_grants: List::empty(),
            };
            assert!(matches!(
                env.svc.publish_grants(&a, &request, env.now).await,
                Err(AuthError::InvalidRequest)
            ));
        }
        let after = env
            .svc
            .account_view(&a, query(), env.now)
            .await
            .unwrap()
            .vault_self_grants;
        assert_eq!(after, held);
        assert!(epoch_open(&env, &a).await);
    });
}
