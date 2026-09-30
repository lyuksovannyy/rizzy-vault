//! Recovery with the Emergency Kit end to end over HTTP (CRYPTO.md §11.9), with the client flow
//! of `rizzy-client` (`recovery`) against the real auth and vault domains: `recovery/start`,
//! `recovery/complete`, the re-registration over the recovery-only session, and the recovery
//! commit with the default standard rotation and the recovering device's own enrolment, or
//! with the rotation skipped.
//!
//! The waiting period is 0 here ([`Server::start_with_recovery_wait`]); the default 72 h and
//! its answer are covered by `rizzy-domain-auth`'s own tests.

use axum::http::StatusCode;
use chacha20::ChaCha20Rng;
use chacha20::rand_core::SeedableRng as _;
use rizzy_client::ClientError;
use rizzy_client::items::ItemId;
use rizzy_client::login::{LoginInput, start_login};
use rizzy_client::recovery::{RecoveryDone, RecoveryInput, RecoveryOptions, start_recovery};
use rizzy_client::signup::DeviceKind;
use rizzy_client::sync::VaultSync;
use rizzy_client::unlock::{apply_device_grants, verify_unlock};

use crate::common::{ORIGIN, Server, block_on};
use crate::rotation::{
    Auth, Client, FIELD, NAME, PASSWORD, call, copy_token, device_session, now_ms, post,
    post_empty, signup,
};

/// The master password set by the recovery.
const NEW_PASSWORD: &str = "a brand new master password";

/// Runs a recovery with `code` to its commit. Returns the recovered device and the new kit's
/// Secret Key and recovery code.
async fn recover(
    server: &Server,
    rng: &mut ChaCha20Rng,
    code: &str,
    rotate: bool,
) -> (RecoveryDone, String, String) {
    let started = start_recovery(&RecoveryInput {
        server_origin: ORIGIN,
        login_name: NAME,
        recovery_code: code,
    })
    .unwrap();
    // Step 2: the pending recovery; a repeat returns the same one.
    for _ in 0..2 {
        let reply = post(
            server,
            "/api/v1/recovery/start",
            &started.request().unwrap(),
            Auth::None,
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.error());
    }
    // Step 3, after the (zero) wait; step 4: `E_rec` opens and the whole answer verifies.
    let reply = post(
        server,
        "/api/v1/recovery/complete",
        &started.request().unwrap(),
        Auth::None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    let recovered = started.open(reply.json()).unwrap();
    let token = copy_token(recovered.bearer_token());
    // Step 5: the new credentials, over the recovery-only session.
    let (reregistering, request) = recovered
        .start_commit(
            rng,
            &RecoveryOptions {
                new_password: NEW_PASSWORD,
                rotate,
                device_kind: DeviceKind::DesktopCli,
                now_ms: now_ms(),
            },
        )
        .unwrap();
    let reply = post(
        server,
        "/api/v1/account/reregister/start",
        &request,
        Auth::Bearer(&token),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    let mut pending = reregistering.finish(rng, &reply.json()).unwrap();
    // Secrets before commit: no commit before the new kit is confirmed.
    assert_eq!(
        pending.commit_request().unwrap_err(),
        ClientError::EmergencyKitNotConfirmed
    );
    let kit = pending.emergency_kit();
    let secret_key = kit.secret_key().to_owned();
    let new_code = kit.recovery_code().unwrap().to_owned();
    assert_ne!(new_code, code);
    let last = secret_key.rsplit('-').next().unwrap().to_owned();
    pending.confirm_kit(&last).unwrap();
    // Step 6.
    post_empty(
        server,
        "/api/v1/account/commit",
        pending.commit_request().unwrap(),
        Auth::Bearer(&token),
    )
    .await;
    // The recovery ended its own session: a repeat is refused, not applied twice.
    let again = post(
        server,
        "/api/v1/account/commit",
        pending.commit_request().unwrap(),
        Auth::Bearer(&token),
    )
    .await;
    assert_eq!(again.status, StatusCode::UNAUTHORIZED);
    (pending.finalize().unwrap(), secret_key, new_code)
}

/// The recovered device authenticates, fetches and reads `item`.
async fn read_as_recovered(server: &Server, done: RecoveryDone, item: ItemId) -> Vec<u8> {
    let mut session = device_session(server, &done.device, &done.unlocked)
        .await
        .unwrap();
    let key = done.vault_keys.into_iter().next().unwrap();
    let mut vault = VaultSync::new(key, &done.unlocked, 1).unwrap();
    loop {
        let reply = post(
            server,
            "/api/v1/vault/fetch",
            &vault.fetch_request().unwrap(),
            Auth::Device(&mut session, &done.unlocked),
        )
        .await;
        let response = reply.json();
        let outcome = vault
            .apply_fetch(&done.authors, &response, now_ms())
            .unwrap();
        assert!(outcome.reports.is_empty(), "{outcome:?}");
        if response.complete {
            break;
        }
    }
    vault
        .field_value(item, FIELD)
        .unwrap()
        .expose_secret()
        .to_vec()
}

/// An OPAQUE login's first round trip with `password` and `sk`; whether the server and the
/// client accept the credentials.
async fn can_log_in(server: &Server, rng: &mut ChaCha20Rng, sk: &str, password: &str) -> bool {
    let input = LoginInput {
        server_origin: ORIGIN,
        login_name: NAME,
        secret_key: sk,
        password,
    };
    let (started, request) = start_login(rng, &input).unwrap();
    let reply = post(server, "/api/v1/login/start", &request, Auth::None).await;
    started.finish(rng, &reply.json(), None).is_ok()
}

/// CRYPTO.md §11.9 with the default standard rotation: the old password, Secret Key and
/// recovery code stop working; the recovering client is enrolled as a device in the same
/// commit and reads every item at the new epoch; the device that was already enrolled opens
/// its grant from the new device and is then told the password changed.
#[test]
#[expect(clippy::too_many_lines, reason = "one recovery followed step by step")]
fn a_recovery_rotates_replaces_the_credentials_and_enrols_the_device() {
    block_on(async {
        let server = Server::start_with_recovery_wait(0).await;
        let mut rng = ChaCha20Rng::seed_from_u64(90);
        let (up, old_sk, code) = signup(&server, &mut rng, true).await;
        let code = code.unwrap();
        let mut a = Client::signed_up(&server, up).await;
        let item = a.create(&mut rng, "kept");
        assert!(a.sync(&server, &mut rng).await.is_empty());

        let (done, new_sk, new_code) = recover(&server, &mut rng, &code, true).await;
        assert_eq!(done.dropped_items, 0);
        assert_eq!(done.device.pin().state().account_key_epoch, 1);
        assert_eq!(done.device.pin().state().password_epoch, 1);
        assert_eq!(done.device.pin().state().recovery_epoch, 2);
        assert_eq!(done.certificates.len(), 2);
        let recovered_device = done.device.device_id();

        // The credentials: only the new password with the new Secret Key logs in.
        assert!(!can_log_in(&server, &mut rng, &old_sk, PASSWORD).await);
        assert!(!can_log_in(&server, &mut rng, &new_sk, PASSWORD).await);
        assert!(can_log_in(&server, &mut rng, &new_sk, NEW_PASSWORD).await);
        // The old code starts nothing any more; the new one does.
        let old = start_recovery(&RecoveryInput {
            server_origin: ORIGIN,
            login_name: NAME,
            recovery_code: &code,
        })
        .unwrap();
        let reply = post(
            &server,
            "/api/v1/recovery/start",
            &old.request().unwrap(),
            Auth::None,
        )
        .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        let new = start_recovery(&RecoveryInput {
            server_origin: ORIGIN,
            login_name: NAME,
            recovery_code: &new_code,
        })
        .unwrap();
        let reply = post(
            &server,
            "/api/v1/recovery/start",
            &new.request().unwrap(),
            Auth::None,
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK);

        // The device that was enrolled before: every session ended (§11.9 step 6); it
        // authenticates again with its device key, opens the grant the recovered device
        // signed, and is then told the password changed (§11.3 step 5).
        let refused = call(
            &server,
            "POST",
            "/api/v1/account/state",
            b"{}".to_vec(),
            Auth::Device(&mut a.session, &a.unlocked),
        )
        .await;
        assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
        a.session = device_session(&server, &a.state, &a.unlocked)
            .await
            .unwrap();
        let view = serde_json::from_value(a.account_view(&server).await).unwrap();
        assert_eq!(
            verify_unlock(&mut a.state, &a.unlocked, &view, None).unwrap_err(),
            ClientError::AccountKeyRotated
        );
        let grants: rizzy_client::rizzy_proto::account::DeviceGrantsResponse = call(
            &server,
            "GET",
            "/api/v1/devices/grants",
            Vec::new(),
            Auth::Device(&mut a.session, &a.unlocked),
        )
        .await
        .json();
        assert_eq!(grants.grants.len(), 1);
        assert_eq!(
            grants.grants.as_slice()[0].sender_device_id.to_bytes(),
            recovered_device.to_bytes()
        );
        let mut a_unlocked = a.state.unlock(PASSWORD).unwrap();
        apply_device_grants(
            &mut rng,
            &mut a.state,
            &mut a_unlocked,
            &view,
            &grants,
            None,
        )
        .unwrap();
        assert_eq!(
            verify_unlock(&mut a.state, &a_unlocked, &view, None).unwrap_err(),
            ClientError::PasswordChangedElsewhere
        );

        // The recovered device reads the item through the re-wrapped rows alone.
        assert_eq!(read_as_recovered(&server, done, item).await, a.read(item));
        // A login on a further device with the new kit verifies the recovered account.
        let input = LoginInput {
            server_origin: ORIGIN,
            login_name: NAME,
            secret_key: &new_sk,
            password: NEW_PASSWORD,
        };
        let (started, request) = start_login(&mut rng, &input).unwrap();
        let reply = post(&server, "/api/v1/login/start", &request, Auth::None).await;
        let (awaiting, finish) = started.finish(&mut rng, &reply.json(), None).unwrap();
        let reply = post(&server, "/api/v1/login/finish", &finish, Auth::None).await;
        let again = awaiting.complete(reply.json()).unwrap();
        assert_eq!(again.account().state().recovery_epoch, 2);
        assert_eq!(again.account().certificates().len(), 2);
    });
}

/// "Skip rotation" (§11.9 step 5): the account key and the vault key stay, the credentials
/// and the recovery code are replaced, and the device is enrolled.
#[test]
fn a_recovery_without_rotation_keeps_the_keys() {
    block_on(async {
        let server = Server::start_with_recovery_wait(0).await;
        let mut rng = ChaCha20Rng::seed_from_u64(91);
        let (up, old_sk, code) = signup(&server, &mut rng, true).await;
        let mut a = Client::signed_up(&server, up).await;
        let item = a.create(&mut rng, "kept");
        assert!(a.sync(&server, &mut rng).await.is_empty());

        let (done, new_sk, _) = recover(&server, &mut rng, &code.unwrap(), false).await;
        let state = done.device.pin().state().clone();
        assert_eq!(state.account_key_epoch, 0);
        assert_eq!((state.password_epoch, state.recovery_epoch), (1, 2));
        assert!(!can_log_in(&server, &mut rng, &old_sk, PASSWORD).await);
        assert!(can_log_in(&server, &mut rng, &new_sk, NEW_PASSWORD).await);
        assert_eq!(read_as_recovered(&server, done, item).await, a.read(item));
    });
}

/// A wrong code is refused before anything is sent when its check characters fail, and by the
/// server, like an unknown name, when they do not.
#[test]
fn a_wrong_recovery_code_is_refused() {
    block_on(async {
        let server = Server::start_with_recovery_wait(0).await;
        let mut rng = ChaCha20Rng::seed_from_u64(92);
        let (_, _, code) = signup(&server, &mut rng, true).await;
        let code = code.unwrap();
        // A typo.
        let mut typo = code.clone();
        let last = typo.pop().unwrap();
        typo.push(if last == '2' { '3' } else { '2' });
        assert_eq!(
            start_recovery(&RecoveryInput {
                server_origin: ORIGIN,
                login_name: NAME,
                recovery_code: &typo,
            })
            .unwrap_err(),
            ClientError::InvalidInput
        );
        // A well-formed code of another account.
        let other = Server::start().await;
        let (_, _, foreign) = signup(&other, &mut rng, true).await;
        let started = start_recovery(&RecoveryInput {
            server_origin: ORIGIN,
            login_name: NAME,
            recovery_code: &foreign.unwrap(),
        })
        .unwrap();
        for path in ["/api/v1/recovery/start", "/api/v1/recovery/complete"] {
            let reply = post(&server, path, &started.request().unwrap(), Auth::None).await;
            assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        }
    });
}
