//! The signed account state: enrolment by compare-and-swap, lost races, forks and repeats
//! (CRYPTO.md §10.2, §11.2 step 7; INV-25).

use rizzy_core::sign::{AccountState, CasRetry, DeviceKind};
use rizzy_domain_auth::AuthError;
use rizzy_proto::account::{
    AccountStateQuery, EnrolDeviceRequest, UploadWebDeviceCertificateRequest,
};

use crate::common::{Client, Device, Env, block_on, bytes};

/// The enrolment request of `device` on top of the client's current state.
fn enrolment(client: &Client, device: &Device) -> (EnrolDeviceRequest, (AccountState, Vec<u8>)) {
    let mut members: Vec<&Device> = client.devices.iter().collect();
    members.push(device);
    let set = client.device_set(&members);
    let next = client.next_state(|s| s.device_set_hash = set);
    (
        EnrolDeviceRequest {
            device_certificate: bytes(device.cert_wire.clone()),
            account_state: bytes(next.1.clone()),
        },
        next,
    )
}

/// Two devices enrol on the same base: the first wins, the second's state is a fork at the
/// same `state_seq` and is refused, and the loser's own comparison says "re-apply".
#[test]
fn enrolment_race_fork_and_repeat() {
    block_on(async {
        let mut env = Env::new(20).await;
        let mut client = env.signup("erin", "pw").await;
        let login = env.login(&client).await;
        let session = env.bearer(&login.response.session_token).await;

        let b = client.make_device(&mut env.rng, env.now);
        let c = client.make_device(&mut env.rng, env.now);
        let (enrol_b, state_b) = enrolment(&client, &b);
        let (enrol_c, state_c) = enrolment(&client, &c);

        env.svc
            .enrol_device(&session, &enrol_b, env.now)
            .await
            .unwrap();
        // The loser: the same state_seq with another body is refused, never stored.
        let lost = env.svc.enrol_device(&session, &enrol_c, env.now).await;
        assert!(matches!(lost, Err(AuthError::StateFork)));
        assert_eq!(
            lost.unwrap_err().code(),
            rizzy_proto::error::ErrorCode::StateConflict
        );
        // A repeat of the committed enrolment is success.
        env.svc
            .enrol_device(&session, &enrol_b, env.now)
            .await
            .unwrap();

        // The loser re-fetches, and CRYPTO.md §10.2's rules say: re-apply on top.
        let base = client.state.clone();
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
        let current = AccountState::verify(
            view.account_state.as_slice(),
            client.identity.signing_key().verifying_key(),
            0,
        )
        .unwrap();
        assert_eq!(*current, state_b.0);
        assert_eq!(base.cas_retry(&current), CasRetry::Reapply);
        // A device that had accepted C's state (served by a malicious server) sees a fork.
        assert!(current.is_fork(&state_c.0));
        assert_eq!(state_c.0.cas_retry(&current), CasRetry::Fork);

        // Re-applied on top of B's enrolment, C's enrolment goes through.
        client.devices.push(b);
        client.adopt(state_b);
        let (enrol_c2, state_c2) = enrolment(&client, &c);
        env.svc
            .enrol_device(&session, &enrol_c2, env.now)
            .await
            .unwrap();
        client.devices.push(c);
        client.adopt(state_c2);

        // An older state is a conflict; a state that skips a number too.
        let (old, _) = enrolment(&client, &client.make_device(&mut env.rng, env.now));
        let mut stale = old.clone();
        stale.account_state = bytes(client.next_state(|s| s.state_seq -= 2).1);
        assert!(matches!(
            env.svc.enrol_device(&session, &stale, env.now).await,
            Err(AuthError::StateConflict)
        ));
        let mut skip = old;
        skip.account_state = bytes(client.next_state(|s| s.state_seq += 1).1);
        assert!(matches!(
            env.svc.enrol_device(&session, &skip, env.now).await,
            Err(AuthError::StateConflict)
        ));

        // A state that changes more than the device set is refused.
        let d = client.make_device(&mut env.rng, env.now);
        let (mut sneaky, _) = enrolment(&client, &d);
        let mut members: Vec<&Device> = client.devices.iter().collect();
        members.push(&d);
        let set = client.device_set(&members);
        sneaky.account_state = bytes(
            client
                .next_state(|s| {
                    s.device_set_hash = set;
                    s.recovery_enabled = false;
                })
                .1,
        );
        assert!(matches!(
            env.svc.enrol_device(&session, &sneaky, env.now).await,
            Err(AuthError::InvalidRequest)
        ));
        // A device-set hash that hides a device is refused.
        let (mut hiding, _) = enrolment(&client, &d);
        let only = client.device_set(&[&client.devices[0], &d]);
        hiding.account_state = bytes(client.next_state(|s| s.device_set_hash = only).1);
        assert!(matches!(
            env.svc.enrol_device(&session, &hiding, env.now).await,
            Err(AuthError::InvalidRequest)
        ));

        // Enrolment needs a fresh OPAQUE session (≤ 5 min).
        env.tick(5 * 60_000 + 1);
        let (late, _) = enrolment(&client, &d);
        assert!(matches!(
            env.svc.enrol_device(&session, &late, env.now).await,
            Err(AuthError::FreshSessionRequired)
        ));
    });
}

/// The web vault's kind-4 certificate joins no device set; a durable one is refused there.
#[test]
fn web_certificate_upload() {
    block_on(async {
        let mut env = Env::new(21).await;
        let client = env.signup("fay", "pw").await;
        let login = env.login(&client).await;
        let session = env.bearer(&login.response.session_token).await;
        let keys = rizzy_core::keys::DeviceKeys::generate(&mut env.rng);
        let id = rizzy_core::ids::DeviceId::generate(&mut env.rng);
        let web = client.certify(
            id,
            keys,
            DeviceKind::WebEphemeral,
            env.now,
            env.now + 3_600_000,
        );
        let req = UploadWebDeviceCertificateRequest {
            device_certificate: bytes(web.cert_wire.clone()),
        };
        env.svc
            .upload_web_certificate(&session, &req, env.now)
            .await
            .unwrap();
        env.svc
            .upload_web_certificate(&session, &req, env.now)
            .await
            .unwrap();
        // It cannot device-authenticate: the web vault logs in with OPAQUE (§11.4).
        assert!(matches!(
            env.device_auth(&client, &web).await,
            Err(AuthError::Unauthorized)
        ));
        // The state is unchanged, and the certificate is served.
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
        assert_eq!(view.account_state.as_slice(), client.state_wire.as_slice());
        assert_eq!(view.device_certificates.len(), 2);
        // A durable certificate is refused on this path.
        let durable = client.make_device(&mut env.rng, env.now);
        let bad = UploadWebDeviceCertificateRequest {
            device_certificate: bytes(durable.cert_wire),
        };
        assert!(matches!(
            env.svc
                .upload_web_certificate(&session, &bad, env.now)
                .await,
            Err(AuthError::InvalidRequest)
        ));
    });
}

/// Two enrolments race for real: both requests run concurrently, one commits, the other is
/// refused as the second version of the same `state_seq`.
#[test]
fn concurrent_enrolments_one_wins() {
    block_on(async {
        let mut env = Env::new(22).await;
        let client = env.signup("gil", "pw").await;
        let login = env.login(&client).await;
        let session = env.bearer(&login.response.session_token).await;
        let b = client.make_device(&mut env.rng, env.now);
        let c = client.make_device(&mut env.rng, env.now);
        let (enrol_b, _) = enrolment(&client, &b);
        let (enrol_c, _) = enrolment(&client, &c);
        let (rb, rc) = crate::common::join2(
            Box::pin(env.svc.enrol_device(&session, &enrol_b, env.now)),
            Box::pin(env.svc.enrol_device(&session, &enrol_c, env.now)),
        )
        .await;
        let outcomes = [rb.is_ok(), rc.is_ok()];
        assert_eq!(outcomes.iter().filter(|ok| **ok).count(), 1);
        assert!(matches!(rb.err().or(rc.err()), Some(AuthError::StateFork)));
    });
}

/// Kind-4 certificates are bounded per account: past the limit an upload is refused (never a
/// login), and an expired one that authored nothing is deleted to make room, while one that
/// authored an op the server holds is kept (CRYPTO.md §11.6 step 7).
#[test]
fn web_certificates_are_bounded() {
    block_on(async {
        let mut env = Env::with_config(23, |c| c.max_web_certificates = 2).await;
        let client = env.signup("hal", "pw").await;
        let upload = |env: &mut Env| {
            let now = env.now;
            let keys = rizzy_core::keys::DeviceKeys::generate(&mut env.rng);
            let id = rizzy_core::ids::DeviceId::generate(&mut env.rng);
            let web = client.certify(id, keys, DeviceKind::WebEphemeral, now, now + 3_600_000);
            let req = UploadWebDeviceCertificateRequest {
                device_certificate: bytes(web.cert_wire.clone()),
            };
            (web, req)
        };
        let login = env.login(&client).await;
        let session = env.bearer(&login.response.session_token).await;
        let (w1, r1) = upload(&mut env);
        let (_, r2) = upload(&mut env);
        let (_, r3) = upload(&mut env);
        for r in [&r1, &r2] {
            env.svc
                .upload_web_certificate(&session, r, env.now)
                .await
                .unwrap();
        }
        assert!(matches!(
            env.svc.upload_web_certificate(&session, &r3, env.now).await,
            Err(AuthError::RateLimited)
        ));
        // Logins still work at the limit.
        env.login(&client).await;

        // Both expire; the first authored an op the server holds, the second nothing.
        env.tick(3_600_000);
        env.vault.set_head(client.account_id, w1.id, 1);
        let login = env.login(&client).await;
        let session = env.bearer(&login.response.session_token).await;
        let (_, r4) = upload(&mut env);
        env.svc
            .upload_web_certificate(&session, &r4, env.now)
            .await
            .unwrap();
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
        // The durable device, the first web certificate (it authored an op) and the new one.
        assert_eq!(view.device_certificates.len(), 3);
        let served: Vec<&[u8]> = view
            .device_certificates
            .iter()
            .map(rizzy_proto::wire::Bytes::as_slice)
            .collect();
        assert!(served.contains(&w1.cert_wire.as_slice()));
        assert!(served.contains(&r4.device_certificate.as_slice()));
    });
}
