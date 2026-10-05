//! Device revocation (CRYPTO.md §11.8; ADR 0012 §6): suspension, then the revocation with a
//! standard rotation in one atomic change.

use rizzy_core::envelope::purpose::{
    AccountKeyDeviceGrantCtx, AccountKeyServerWrapCtx, IdentitySecretKeysCtx,
};
use rizzy_core::kdf::KdfId;
use rizzy_core::keys::{
    AccountKey, GrantSender, GrantSigner, open_account_key_device_grant,
    seal_account_key_device_grant,
};
use rizzy_core::opaque::ExportKey;
use rizzy_core::sign::DeviceRevocation;
use rizzy_domain_auth::{AccountChange, AuthError, RecoveryUpload};
use rizzy_proto::account::{AccountStateQuery, EnrolDeviceRequest};
use rizzy_proto::objects::{AccountKeyServerWrap, DeviceGrant, IdentitySecretKeys};
use rizzy_proto::wire::List;

use crate::common::{Client, Device, Env, block_on, bytes, recovery_wrap, self_grant, wid};

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

/// The rotation half of a change: a new account key, `E_srv'`, `E_id'`, the self-grant, `E_rec'`
/// and a grant for each of `recipients`, sent by `sender`.
fn rotation(
    env: &mut Env,
    client: &mut Client,
    export_key: &ExportKey,
    sender: &Device,
    recipients: &[&Device],
) -> (
    AccountKey,
    AccountChange<Vec<rizzy_proto::objects::VaultSelfGrant>>,
) {
    let rng = &mut env.rng;
    let old = client.account_key.generate_next(rng).unwrap();
    let old = core::mem::replace(&mut client.account_key, old);
    client.vault_key = client.vault_key.generate_next(rng).unwrap();
    let account_id = client.account_id;
    let epoch = client.account_key.epoch();
    let e_srv = export_key
        .server_unlock_key(account_id)
        .unwrap()
        .wrap_account_key(
            rng,
            &AccountKeyServerWrapCtx {
                account_id,
                account_key_epoch: epoch,
                password_epoch: client.state.password_epoch,
                kdf_id: KdfId::DEFAULT,
            },
            &client.account_key,
        )
        .unwrap();
    let e_id = client
        .account_key
        .wrap_identity_keys(
            rng,
            &IdentitySecretKeysCtx {
                account_id,
                identity_epoch: client.identity.epoch(),
            },
            &client.identity,
        )
        .unwrap();
    let grants: Vec<DeviceGrant> = recipients
        .iter()
        .map(|r| {
            let ctx = AccountKeyDeviceGrantCtx {
                account_id,
                account_key_epoch: epoch,
                sender_device_id: sender.id,
                recipient_device_id: r.id,
            };
            let grant = seal_account_key_device_grant(
                rng,
                &ctx,
                &client.account_key,
                &old,
                &r.cert,
                GrantSigner::Device(sender.keys.signing_key()),
            )
            .unwrap();
            DeviceGrant {
                account_key_epoch: epoch,
                sender_device_id: wid(sender.id.to_bytes()),
                recipient_device_id: wid(r.id.to_bytes()),
                key_grant: bytes(grant),
            }
        })
        .collect();
    let grant = self_grant(rng, client);
    let e_rec = recovery_wrap(rng, client, client.state.recovery_epoch);
    let change = AccountChange {
        account_state: bytes(vec![0]),
        bundle: None,
        registration_upload: None,
        setup_id: None,
        account_key_server_wrap: Some(AccountKeyServerWrap {
            account_key_epoch: epoch,
            password_epoch: client.state.password_epoch,
            kdf_id: 1,
            envelope: bytes(e_srv),
        }),
        identity_secret_keys: Some(IdentitySecretKeys {
            identity_epoch: client.identity.epoch(),
            envelope: bytes(e_id),
        }),
        recovery: RecoveryUpload::Rewrap(e_rec),
        account_settings: None,
        retired_secret_keys: List::empty(),
        device_certificates: List::empty(),
        device_revocations: List::empty(),
        device_grants: List::new(grants).unwrap(),
        vault_rotation: Some(vec![grant]),
    };
    (old, change)
}

/// Suspend, then revoke with a standard rotation; the revoked device is locked out, the
/// remaining one opens its grant, and H must still be the head.
#[test]
fn suspend_then_revoke_with_rotation() {
    block_on(async {
        let mut env = Env::new(30).await;
        let mut client = env.signup("gus", "pw").await;
        let second = enrol(&mut env, &mut client).await;
        client.devices.push(second);
        let third = enrol(&mut env, &mut client).await;
        client.devices.push(third);
        let [dev_a, dev_b, dev_c] = [0_usize, 1, 2];

        // B has a session; A re-authenticates with OPAQUE from its device session.
        let mut b_session = env
            .device_auth(&client, &client.devices[dev_b])
            .await
            .unwrap();
        let mut a_ds = env
            .device_auth(&client, &client.devices[dev_a])
            .await
            .unwrap();
        let a_session = env
            .signed(&client, &client.devices[dev_a], &mut a_ds, b"")
            .await
            .unwrap();
        let (name, password) = (client.name.clone(), client.password.clone());
        let reauth = env
            .login_as(&name, &password, &client.secret_key, None, Some(&a_session))
            .await
            .unwrap();
        let fresh = env.bearer(&reauth.response.session_token).await;
        assert_eq!(fresh.device_id, Some(client.devices[dev_a].id));

        // An OPAQUE session not bound to a device cannot suspend.
        let unbound = env.login(&client).await;
        let unbound = env.bearer(&unbound.response.session_token).await;
        assert!(matches!(
            env.svc
                .suspend_device(&unbound, client.devices[dev_b].id, env.now)
                .await,
            Err(AuthError::FreshSessionRequired)
        ));

        // Phase 1: suspend B. Its session ends and it can no longer authenticate.
        env.vault
            .set_head(client.account_id, client.devices[dev_b].id, 7);
        let head = env
            .svc
            .suspend_device(&fresh, client.devices[dev_b].id, env.now)
            .await
            .unwrap();
        assert_eq!(head, 7);
        assert!(
            env.signed(&client, &client.devices[dev_b], &mut b_session, b"")
                .await
                .is_err()
        );
        assert!(
            env.device_auth(&client, &client.devices[dev_b])
                .await
                .is_err()
        );

        // Phase 2: the revocation, the new state and the rotation, atomically.
        let revocation = DeviceRevocation {
            account_id: client.account_id,
            device_id: client.devices[dev_b].id,
            last_accepted_device_seq: head,
            revoked_at_ms: env.now,
        };
        let rev_wire = revocation.sign(client.identity.signing_key()).unwrap();
        let rev =
            DeviceRevocation::verify(&rev_wire, client.identity.signing_key().verifying_key())
                .unwrap();
        let devices = core::mem::take(&mut client.devices);
        let (old_key, mut change) = rotation(
            &mut env,
            &mut client,
            &reauth.export_key,
            &devices[dev_a],
            &[&devices[dev_c]],
        );
        client.devices = devices;
        client.revocations.push(rev);
        let set = client.device_set(&client.devices.iter().collect::<Vec<_>>());
        let key_id = client.account_key.key_id().unwrap();
        let next = client.next_state(|s| {
            s.account_key_epoch += 1;
            s.account_key_id = key_id;
            s.device_set_hash = set;
        });
        change.account_state = bytes(next.1.clone());
        change.device_revocations = List::new(vec![bytes(rev_wire.clone())]).unwrap();

        // Without C's grant the change is refused.
        let grants = change.device_grants.clone();
        change.device_grants = List::empty();
        assert!(matches!(
            env.svc.commit_change(&fresh, &change, env.now).await,
            Err(AuthError::InvalidRequest)
        ));
        change.device_grants = grants;
        // The server now holds more from B than the revocation names: refused (§11.8 step 3).
        env.vault
            .set_head(client.account_id, client.devices[dev_b].id, 8);
        assert!(matches!(
            env.svc.commit_change(&fresh, &change, env.now).await,
            Err(AuthError::StateConflict)
        ));
        env.vault
            .set_head(client.account_id, client.devices[dev_b].id, 7);
        env.svc
            .commit_change(&fresh, &change, env.now)
            .await
            .unwrap();
        // A repeat is success.
        env.svc
            .commit_change(&fresh, &change, env.now)
            .await
            .unwrap();
        client.adopt(next);

        // B stays out; C opens its grant with the previous key and gets the new one.
        assert!(
            env.device_auth(&client, &client.devices[dev_b])
                .await
                .is_err()
        );
        let mut c_ds = env
            .device_auth(&client, &client.devices[dev_c])
            .await
            .unwrap();
        let c_session = env
            .signed(&client, &client.devices[dev_c], &mut c_ds, b"")
            .await
            .unwrap();
        let pending = env.svc.device_grants(&c_session, env.now).await.unwrap();
        assert_eq!(pending.grants.len(), 1);
        let grant = &pending.grants.as_slice()[0];
        let opened = open_account_key_device_grant(
            grant.key_grant.as_slice(),
            &AccountKeyDeviceGrantCtx {
                account_id: client.account_id,
                account_key_epoch: grant.account_key_epoch,
                sender_device_id: rizzy_core::ids::DeviceId::from_bytes(
                    grant.sender_device_id.to_bytes(),
                ),
                recipient_device_id: client.devices[dev_c].id,
            },
            &client.devices[dev_c].keys,
            &old_key,
            GrantSender::Device(&client.devices[dev_a].cert),
        )
        .unwrap();
        assert!(client.state.matches_account_key(&opened));
        env.svc
            .ack_device_grants(
                &c_session,
                &rizzy_proto::account::AckDeviceGrantsRequest {
                    account_key_epoch: 1,
                },
                env.now,
            )
            .await
            .unwrap();
        assert!(
            env.svc
                .device_grants(&c_session, env.now)
                .await
                .unwrap()
                .grants
                .is_empty()
        );

        // The view serves the revocation and the new state; the password still logs in and
        // E_srv is at the new epoch.
        let view = env
            .svc
            .account_view(
                &c_session,
                AccountStateQuery {
                    known_bundle_seq: 1,
                    known_settings_seq: 0,
                },
                env.now,
            )
            .await
            .unwrap();
        assert_eq!(view.device_revocations.len(), 1);
        assert_eq!(view.account_state.as_slice(), client.state_wire.as_slice());
        let again = env.login(&client).await;
        assert_eq!(again.response.account_key_server_wrap.account_key_epoch, 1);
    });
}

/// A revocation without a rotation, other than the self-revocation shape, is refused, and so
/// is one of a device that was not suspended first.
#[test]
fn revocation_rules() {
    block_on(async {
        let mut env = Env::new(31).await;
        let mut client = env.signup("hal", "pw").await;
        let b = enrol(&mut env, &mut client).await;
        client.devices.push(b);
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
        let revocation = DeviceRevocation {
            account_id: client.account_id,
            device_id: client.devices[1].id,
            last_accepted_device_seq: 0,
            revoked_at_ms: env.now,
        };
        let rev_wire = revocation.sign(client.identity.signing_key()).unwrap();
        let rev =
            DeviceRevocation::verify(&rev_wire, client.identity.signing_key().verifying_key())
                .unwrap();
        let set = rizzy_core::keys::device_set_hash(
            client.account_id,
            client.devices.iter().map(|d| &d.cert),
            [&rev],
        )
        .unwrap();
        let next = client.next_state(|s| s.device_set_hash = set);
        let change = AccountChange::<Vec<rizzy_proto::objects::VaultSelfGrant>> {
            account_state: bytes(next.1),
            bundle: None,
            registration_upload: None,
            setup_id: None,
            account_key_server_wrap: None,
            identity_secret_keys: None,
            recovery: RecoveryUpload::None,
            account_settings: None,
            retired_secret_keys: rizzy_proto::wire::List::empty(),
            device_certificates: List::empty(),
            device_revocations: List::new(vec![bytes(rev_wire)]).unwrap(),
            device_grants: List::empty(),
            vault_rotation: None,
        };
        // No rotation and not a self-revocation: refused.
        assert!(matches!(
            env.svc.commit_change(&fresh, &change, env.now).await,
            Err(AuthError::InvalidRequest)
        ));
    });
}

/// A full rotation (CRYPTO.md §11.6 step 7) revoking a lost device: a new bundle signed by
/// both identity keys, every certificate re-issued under the new key, the revocation under the
/// new key, and a state of the new identity epoch. Afterwards the old identity key vouches for
/// nothing the server serves.
#[test]
fn full_rotation_revokes_a_lost_device() {
    block_on(async {
        let mut env = Env::new(32).await;
        let mut client = env.signup("ian", "pw").await;
        let lost = enrol(&mut env, &mut client).await;
        client.devices.push(lost);
        let mut ds = env.device_auth(&client, &client.devices[0]).await.unwrap();
        let own = env
            .signed(&client, &client.devices[0], &mut ds, b"")
            .await
            .unwrap();
        let (name, password) = (client.name.clone(), client.password.clone());
        let reauth = env
            .login_as(&name, &password, &client.secret_key, None, Some(&own))
            .await
            .unwrap();
        let fresh = env.bearer(&reauth.response.session_token).await;
        let lost_id = client.devices[1].id;
        let head = env
            .svc
            .suspend_device(&fresh, lost_id, env.now)
            .await
            .unwrap();

        // New identity keys, and the bundle that carries them, signed by both keys.
        let old_identity = core::mem::replace(
            &mut client.identity,
            rizzy_core::keys::IdentityKeys::generate(&mut env.rng, 1),
        );
        let bundle = rizzy_core::sign::PublicKeyBundle {
            account_id: client.account_id,
            identity_epoch: 1,
            bundle_seq: 2,
            identity_ed25519: *client.identity.signing_key().verifying_key(),
            identity_x25519: client.identity.public_keys().x25519,
            mail_x25519: None,
            pq_required: false,
            created_at_ms: env.now,
            prev_bundle_hash: *client.bundle.hash(),
        };
        let bundle_wire = bundle
            .sign_identity_change(
                &client.bundle,
                client.identity.signing_key(),
                old_identity.signing_key(),
            )
            .unwrap();
        let (bundle, _) = client.bundle.verify_successor(&bundle_wire).unwrap();

        // Every certificate re-issued, and the revocation, under the new key.
        let new_key = *client.identity.signing_key().verifying_key();
        let reissue = |d: &Device| {
            let cert = rizzy_core::sign::DeviceCertificate {
                identity_epoch: 1,
                ..d.cert.statement().clone()
            };
            let wire = cert.sign(client.identity.signing_key()).unwrap();
            (
                rizzy_core::sign::DeviceCertificate::verify(&wire, &new_key, 1).unwrap(),
                wire,
            )
        };
        let reissued: Vec<_> = client.devices.iter().map(reissue).collect();
        let rev_wire = DeviceRevocation {
            account_id: client.account_id,
            device_id: lost_id,
            last_accepted_device_seq: head,
            revoked_at_ms: env.now,
        }
        .sign(client.identity.signing_key())
        .unwrap();
        let rev = DeviceRevocation::verify(&rev_wire, &new_key).unwrap();
        let set = rizzy_core::keys::device_set_hash(
            client.account_id,
            reissued.iter().map(|(c, _)| c),
            [&rev],
        )
        .unwrap();

        let devices = core::mem::take(&mut client.devices);
        let (_, mut change) = rotation(&mut env, &mut client, &reauth.export_key, &devices[0], &[]);
        client.devices = devices;
        let key_id = client.account_key.key_id().unwrap();
        let bundle_hash = *bundle.hash();
        let next = client.next_state(|s| {
            s.identity_epoch = 1;
            s.bundle_hash = bundle_hash;
            s.account_key_epoch += 1;
            s.account_key_id = key_id;
            s.device_set_hash = set;
        });
        change.account_state = bytes(next.1.clone());
        change.bundle = Some(bytes(bundle_wire.clone()));
        change.device_certificates =
            List::new(reissued.iter().map(|(_, w)| bytes(w.clone())).collect()).unwrap();
        change.device_revocations = List::new(vec![bytes(rev_wire)]).unwrap();

        // Leaving out a re-issued certificate is refused.
        let all = change.device_certificates.clone();
        change.device_certificates = List::new(vec![bytes(reissued[0].1.clone())]).unwrap();
        assert!(matches!(
            env.svc.commit_change(&fresh, &change, env.now).await,
            Err(AuthError::InvalidRequest)
        ));
        change.device_certificates = all;
        env.svc
            .commit_change(&fresh, &change, env.now)
            .await
            .unwrap();
        // A byte-identical resend of the applied full rotation is success (CRYPTO.md §11
        // "Secrets before commit"), although its bundle is now the stored head.
        env.svc
            .commit_change(&fresh, &change, env.now)
            .await
            .unwrap();
        client.adopt(next);
        client.bundle = bundle;
        client.bundle_wire = bundle_wire;

        // The remaining device authenticates under its re-issued certificate; the lost one
        // never again; everything served verifies under the new identity key.
        let mut ds = env.device_auth(&client, &client.devices[0]).await.unwrap();
        let s = env
            .signed(&client, &client.devices[0], &mut ds, b"")
            .await
            .unwrap();
        assert!(env.device_auth(&client, &client.devices[1]).await.is_err());
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
        assert_eq!(view.bundles.len(), 1);
        for w in &view.device_certificates {
            rizzy_core::sign::DeviceCertificate::verify(w.as_slice(), &new_key, 1).unwrap();
        }
        assert_eq!(view.account_state.as_slice(), client.state_wire.as_slice());
        assert_eq!(view.identity_secret_keys.identity_epoch, 1);
    });
}
