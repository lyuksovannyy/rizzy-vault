//! Credential change tests (CRYPTO.md §11.5 with the rotation of §11.6) against the fake
//! server of the parent module: a Secret Key change with a full rotation ("the kit was
//! stolen"), committed through the rotation module's fake account commit.

use rizzy_proto::change::{ReregisterStartRequest, ReregisterStartResponse};

use super::rotation::{fetch, reauth, settle, signup_with_code};
use super::*;
use crate::credentials::{CredentialChangeInput, start_credential_change};
use crate::rotation::RotationLevel;

impl Server {
    /// `account/reregister/start`: an OPAQUE registration under the account's credential
    /// identifier.
    fn reregister_start(&self, req: &ReregisterStartRequest) -> ReregisterStartResponse {
        let id = CredentialIdentifier::for_account(self.stored().account_id);
        let m2 = server_registration_start(&self.setup, req.registration_request.as_slice(), &id)
            .unwrap();
        ReregisterStartResponse {
            registration_response: bytes(&m2),
        }
    }
}

/// Whether an OPAQUE login with `sk` and the password succeeds.
fn logs_in(server: &mut Server, rng: &mut ChaCha20Rng, sk: &str) -> bool {
    let input = LoginInput {
        server_origin: ORIGIN,
        login_name: "alice",
        secret_key: sk,
        password: PASSWORD,
    };
    let Ok((started, request)) = start_login(rng, &input) else {
        return false;
    };
    let answer = server.login_start(&request);
    let Ok((awaiting, finish)) = started.finish(rng, &answer, None) else {
        return false;
    };
    server
        .login_finish(&finish)
        .ok()
        .is_some_and(|done| awaiting.complete(done).is_ok())
}

/// CRYPTO.md §11.5 "SK change" with §11.6 "Full": a new Secret Key, a new recovery code (an
/// SK change never keeps the code), the account and vault keys rotated, and new identity keys
/// (a new bundle chained to the old one, the device certificate re-issued, the new state
/// signed by the new key). The device follows its own commit; the new Secret Key logs in and
/// the old one does not; the items stay readable.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one change: refusals, build, kit, request checks, commit, finalisation, after"
)]
fn a_secret_key_change_with_a_full_rotation_replaces_the_identity_keys() {
    let mut rng = ChaCha20Rng::seed_from_u64(90);
    let mut server = Server::new(91);
    let (mut a, code) = signup_with_code(&mut server, &mut rng);
    let mut a_state = a.device.take().unwrap();
    let sk = secret_key_text(&a_state);
    let authors = server.authors();
    let (mut vault, mut a_unlocked, items) = synced_writer(&mut server, &mut rng, a, &authors, 1);
    settle(&mut server, &mut rng, &mut vault, &a_unlocked);
    let old_bundle = PublicKeyBundle::verify_self_signed(&server.stored().bundles[0]).unwrap();

    let input = CredentialChangeInput {
        login_name: "alice",
        new_password: PASSWORD,
        new_secret_key: true,
        rotate: true,
        full_rotation: true,
        recovery_code: None,
        now_ms: T0 + 10_000,
    };
    // A full rotation is a level of a rotation: without one it is refused.
    let login = reauth(&mut server, &mut rng, &sk);
    let without = CredentialChangeInput {
        rotate: false,
        ..input
    };
    assert_eq!(
        start_credential_change(&mut rng, login, &a_state, &a_unlocked, &without).unwrap_err(),
        ClientError::InvalidInput
    );
    // The standard level stays the default of a rotating change.
    let login = reauth(&mut server, &mut rng, &sk);
    let standard = CredentialChangeInput {
        full_rotation: false,
        ..input
    };
    let (started, request) =
        start_credential_change(&mut rng, login, &a_state, &a_unlocked, &standard).unwrap();
    let response = server.reregister_start(&request);
    let pending = started
        .finish(&mut rng, &response, &a_state, &a_unlocked, &[&vault])
        .unwrap();
    assert_eq!(pending.rotation_level(), Some(RotationLevel::Standard));
    assert!(pending.new_state().identity_epoch == 0);
    drop(pending);

    // The full one.
    let login = reauth(&mut server, &mut rng, &sk);
    let (started, request) =
        start_credential_change(&mut rng, login, &a_state, &a_unlocked, &input).unwrap();
    let response = server.reregister_start(&request);
    let mut pending = started
        .finish(&mut rng, &response, &a_state, &a_unlocked, &[&vault])
        .unwrap();
    assert!(pending.rotates());
    assert_eq!(pending.rotation_level(), Some(RotationLevel::Full));
    // Secrets before commit: a new kit with a new Secret Key and a new recovery code.
    let kit = pending.emergency_kit().unwrap();
    let new_sk = kit.secret_key().to_owned();
    let new_code = kit.recovery_code().unwrap().to_owned();
    assert_ne!(new_sk, sk);
    assert_ne!(new_code, code);
    assert_eq!(
        pending.commit_request().unwrap_err(),
        ClientError::EmergencyKitNotConfirmed
    );
    pending
        .confirm_kit(new_sk.rsplit('-').next().unwrap())
        .unwrap();
    let base = a_state.pin().state();
    let (recovery_epoch, state_seq) = (base.recovery_epoch + 1, base.state_seq + 1);
    let state = pending.new_state();
    assert_eq!(
        (
            state.identity_epoch,
            state.account_key_epoch,
            state.password_epoch,
            state.recovery_epoch,
            state.state_seq
        ),
        (1, 1, 1, recovery_epoch, state_seq)
    );
    let commit = pending.commit_request().unwrap().clone();
    assert!(commit.registration_upload.is_some());
    assert!(commit.recovery.is_some() && commit.recovery_rewrap.is_none());
    assert!(commit.identity_secret_keys.is_some());
    assert_eq!(commit.retired_secret_keys.len(), 1, "the old identity key");
    assert_eq!(commit.device_certificates.len(), 1, "re-issued");
    // The new bundle chains to the old one, holds new identity keys, and signs the new state
    // and the re-issued certificate.
    let (new_bundle, _) = old_bundle
        .verify_successor(commit.bundle.as_ref().unwrap().as_slice())
        .unwrap();
    assert_eq!(new_bundle.identity_epoch, 1);
    assert_ne!(
        new_bundle.identity_ed25519.as_bytes(),
        old_bundle.identity_ed25519.as_bytes()
    );
    AccountState::verify(
        commit.account_state.as_slice(),
        &new_bundle.identity_ed25519,
        1,
    )
    .unwrap();
    assert!(
        AccountState::verify(
            commit.account_state.as_slice(),
            &old_bundle.identity_ed25519,
            1
        )
        .is_err()
    );
    let certificate = DeviceCertificate::verify(
        commit.device_certificates.as_slice()[0].as_slice(),
        &new_bundle.identity_ed25519,
        1,
    )
    .unwrap();
    assert_eq!(certificate.device_id, a_state.device_id());
    // The pending record carries the new Secret Key.
    let record = pending
        .pending_record(&mut rng, &a_state, &a_unlocked)
        .unwrap();
    assert_eq!(record.secret_key.to_formatted().to_string(), new_sk);

    server.commit_rotation(&commit).unwrap();
    let done = pending
        .finalize(&mut rng, &mut a_state, &mut a_unlocked, &mut [&mut vault])
        .unwrap();
    assert!(done.dropped_items.is_empty());
    assert_eq!(a_unlocked.account_key.epoch(), 1);
    assert_eq!(a_state.pin().state().identity_epoch, 1);
    assert_eq!(secret_key_text(&a_state), new_sk);

    // The device verifies the served state under its new pin, and opens with the password.
    // (Served as the real server does: the bundles above the query's `known_bundle_seq`, here
    // the pinned one again, which the chain accepts as unchanged.)
    let mut view = server.view();
    view.bundles = List::new(vec![bytes(server.stored().bundles.last().unwrap())]).unwrap();
    verify_unlock(&mut a_state, &a_unlocked, &view, None).unwrap();
    assert_eq!(a_state.unlock(PASSWORD).unwrap().account_key.epoch(), 1);
    // Only the new Secret Key logs in.
    assert!(!logs_in(&mut server, &mut rng, &sk));
    assert!(logs_in(&mut server, &mut rng, &new_sk));
    // The items stay readable under the rotated keys.
    fetch(&server, &mut vault);
    assert!(vault.field_value(items[0], LOGIN_PASSWORD).is_some());
}
