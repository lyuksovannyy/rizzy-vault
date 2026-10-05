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
            setup_id: self.setup_id,
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

impl Server {
    /// The account commit of a change without a rotation (a credential change or a
    /// same-password re-registration): compare-and-swap on `state_seq`, then the new record,
    /// `E_srv` and state. A byte-identical repeat succeeds.
    fn commit_plain(
        &mut self,
        req: &rizzy_proto::change::CommitChangeRequest,
    ) -> Result<(), rizzy_proto::error::ErrorCode> {
        use rizzy_proto::error::ErrorCode;
        let s = self.stored();
        if req.account_state.as_slice() == s.state.as_slice() {
            return Ok(());
        }
        if req.vault_rotation.is_some() || req.setup_id != Some(self.setup_id) {
            return Err(ErrorCode::InvalidRequest);
        }
        let bundle = PublicKeyBundle::verify_self_signed(s.bundles.last().unwrap()).unwrap();
        let verify = |wire: &[u8]| {
            AccountState::verify(wire, &bundle.identity_ed25519, bundle.identity_epoch)
                .map(rizzy_core::sign::Verified::into_statement)
        };
        let current = verify(&s.state).unwrap();
        let new = verify(req.account_state.as_slice()).map_err(|_| ErrorCode::InvalidRequest)?;
        if new.state_seq != current.state_seq + 1 {
            return Err(ErrorCode::StateConflict);
        }
        let upload = req
            .registration_upload
            .as_ref()
            .ok_or(ErrorCode::InvalidRequest)?;
        let s = self.account.as_mut().unwrap();
        s.password_file = server_registration_finish(upload.as_slice())
            .unwrap()
            .to_bytes();
        s.e_srv = req.account_key_server_wrap.clone().unwrap();
        s.state = req.account_state.as_slice().to_vec();
        Ok(())
    }

    /// `secrets rotate`, a restart, and `secrets retire-setups` of the old setup: a new setup
    /// under the next `setup_id`, the old one gone.
    fn replace_setup(&mut self, seed: u64) {
        self.setup = ServerSetup::generate(&mut ChaCha20Rng::seed_from_u64(seed));
        self.setup_id += 1;
    }
}

/// `commit` with its OPAQUE upload, `setup_id` and `E_srv` envelope blanked: what a restarted
/// registration must leave byte for byte (ADR 0031 point 8).
fn without_registration(
    commit: &rizzy_proto::change::CommitChangeRequest,
) -> rizzy_proto::change::CommitChangeRequest {
    let mut copy = commit.clone();
    copy.registration_upload = None;
    copy.setup_id = None;
    if let Some(wrap) = copy.account_key_server_wrap.as_mut() {
        wrap.envelope = bytes(b"-");
    }
    copy
}

/// ADR 0031 point 8: a pending Secret Key change refused with `setup_retired` reruns its
/// registration with the same `pw_in`; only the upload, the `setup_id` and `E_srv'` change, the
/// new Secret Key and the pending record stay, and a second restart fails.
#[test]
fn a_change_refused_setup_retired_restarts_only_its_registration() {
    let mut rng = ChaCha20Rng::seed_from_u64(310);
    let mut server = Server::new(311);
    let (mut a, _) = signup_with_code(&mut server, &mut rng);
    let mut a_state = a.device.take().unwrap();
    let sk = secret_key_text(&a_state);
    let mut a_unlocked = a.unlocked;
    let input = CredentialChangeInput {
        login_name: "alice",
        new_password: PASSWORD,
        new_secret_key: true,
        rotate: false,
        full_rotation: false,
        recovery_code: None,
        now_ms: T0 + 10_000,
    };
    let login = reauth(&mut server, &mut rng, &sk);
    let (started, request) =
        start_credential_change(&mut rng, login, &a_state, &a_unlocked, &input).unwrap();
    let response = server.reregister_start(&request);
    assert_eq!(response.setup_id, 1);
    let vault_id = crate::rizzy_core::ids::VaultId::generate(&mut rng);
    let vault = VaultSync::new(
        crate::rizzy_core::keys::VaultKey::generate(&mut rng, vault_id, 0),
        &a_unlocked,
        1,
    )
    .unwrap();
    let mut pending = started
        .finish(&mut rng, &response, &a_state, &a_unlocked, &[&vault])
        .unwrap();
    // A restart needs the released commit.
    assert_eq!(
        pending.restart_registration(&mut rng).unwrap_err(),
        ClientError::EmergencyKitNotConfirmed
    );
    let new_sk = pending.emergency_kit().unwrap().secret_key().to_owned();
    pending
        .confirm_kit(new_sk.rsplit('-').next().unwrap())
        .unwrap();
    let record = pending
        .pending_record(&mut rng, &a_state, &a_unlocked)
        .unwrap();
    let first = pending.commit_request().unwrap().clone();
    assert_eq!(first.setup_id, Some(1));

    // The server retired setup 1 meanwhile: `setup_retired`, and the registration restarts.
    server.replace_setup(312);
    let again = pending.restart_registration(&mut rng).unwrap();
    let response = server.reregister_start(&again);
    assert_eq!(response.setup_id, 2);
    pending
        .on_registration_restarted(&mut rng, &response)
        .unwrap();
    let second = pending.commit_request().unwrap().clone();
    assert_eq!(second.setup_id, Some(2));
    assert_ne!(second.registration_upload, first.registration_upload);
    assert_ne!(
        second.account_key_server_wrap.as_ref().unwrap().envelope,
        first.account_key_server_wrap.as_ref().unwrap().envelope
    );
    assert_eq!(without_registration(&second), without_registration(&first));
    assert_eq!(second.account_state, first.account_state);
    // The pending record (new Secret Key, salt, E_local') is unchanged.
    let after = pending
        .pending_record(&mut rng, &a_state, &a_unlocked)
        .unwrap();
    assert_eq!(
        after.secret_key.expose_secret(),
        record.secret_key.expose_secret()
    );
    assert_eq!(after.device_salt, record.device_salt);
    // At most once.
    assert_eq!(
        pending.restart_registration(&mut rng).unwrap_err(),
        ClientError::SetupRetired
    );
    server.commit_plain(&second).unwrap();
    let mut vaults: [&mut VaultSync; 0] = [];
    pending
        .finalize(&mut rng, &mut a_state, &mut a_unlocked, &mut vaults)
        .unwrap();
    assert_eq!(secret_key_text(&a_state), new_sk);
    // The new record works under the new setup, with the new Secret Key only.
    assert!(logs_in(&mut server, &mut rng, &new_sk));
    assert!(!logs_in(&mut server, &mut rng, &sk));
}

/// ADR 0031 point 2: a login answered `reregister` runs the same-password re-registration over
/// its session: the same `pw_in`, `state_seq + 1` and nothing else, the echoed `setup_id`, and
/// `E_srv'` at the state's locator. The record then logs in under the new setup.
#[test]
fn a_reregister_answer_moves_the_record_with_the_same_password() {
    let mut rng = ChaCha20Rng::seed_from_u64(320);
    let mut server = Server::new(321);
    let (mut a, _) = signup_with_code(&mut server, &mut rng);
    let a_state = a.device.take().unwrap();
    let sk = secret_key_text(&a_state);
    assert!(!reauth(&mut server, &mut rng, &sk).reregister());

    server.reregister = true;
    let mut login = reauth(&mut server, &mut rng, &sk);
    assert!(login.reregister());
    let base = login.account().state().clone();
    // `secrets rotate` and a restart: new registrations use setup 2, the old record still
    // logs in under 1 (the fake keeps one setup, so the login above came first).
    let old_setup = core::mem::replace(
        &mut server.setup,
        ServerSetup::generate(&mut ChaCha20Rng::seed_from_u64(322)),
    );
    server.setup_id = 2;
    let (started, request) = login.start_reregistration(&mut rng).unwrap();
    let response = server.reregister_start(&request);
    // A start made from a login does not finish as a device's.
    let pending = started.finish_login(&mut rng, &response, &login).unwrap();
    let commit = pending.commit_request().clone();
    assert_eq!(commit.setup_id, Some(2));
    let new = pending.new_pin().state();
    assert_eq!(new.state_seq, base.state_seq + 1);
    assert_eq!(
        AccountState {
            state_seq: base.state_seq,
            ..new.clone()
        },
        base
    );
    let wrap = commit.account_key_server_wrap.as_ref().unwrap();
    assert_eq!(
        (wrap.account_key_epoch, wrap.password_epoch, wrap.kdf_id),
        (
            base.account_key_epoch,
            base.password_epoch,
            base.kdf_id.get()
        )
    );
    assert!(
        commit.recovery.is_none()
            && commit.vault_rotation.is_none()
            && commit.device_certificates.is_empty()
    );
    server.commit_plain(&commit).unwrap();
    login.adopt_reregistration(pending).unwrap();
    assert_eq!(login.account().state().state_seq, base.state_seq + 1);
    drop(old_setup);
    server.reregister = false;
    // The same password and Secret Key log in under the new setup.
    assert!(logs_in(&mut server, &mut rng, &sk));
    // The device path: the same flow from the device state and the typed password.
    let (device_started, _) =
        crate::reregister::start_device_reregistration(&mut rng, &a_state, PASSWORD).unwrap();
    assert_eq!(
        device_started
            .finish_login(&mut rng, &response, &login)
            .unwrap_err(),
        ClientError::InvalidInput
    );
}

/// ADR 0031 point 8 at signup: a commit refused with `setup_retired` restarts `register/start`
/// with the same name, account and `pw_in`; the kit and the keys stay.
#[test]
fn a_signup_refused_setup_retired_restarts_its_registration() {
    let mut rng = ChaCha20Rng::seed_from_u64(330);
    let mut server = Server::new(331);
    let input = SignupInput {
        server_origin: ORIGIN,
        login_name: "Alice",
        password: PASSWORD,
        invite: Some("invite-token"),
        issue_recovery_code: false,
        device_kind: DeviceKind::DesktopCli,
        now_ms: T0,
    };
    let (started, request) = start_signup(&mut rng, &input).unwrap();
    let account_id = AccountId::from_bytes(request.account_id.to_bytes());
    let response = server.register_start(&request);
    let mut pending = started.finish(&mut rng, &response).unwrap();
    let kit = pending.emergency_kit();
    let sk = kit.secret_key().to_owned();
    pending.confirm_kit(sk.rsplit('-').next().unwrap()).unwrap();
    let first = pending.commit_request().unwrap().clone();
    assert_eq!(first.setup_id, 1);

    server.replace_setup(332);
    let again = pending.restart_registration(&mut rng).unwrap();
    assert_eq!(again.account_id, request.account_id);
    assert_eq!(again.login_name.as_str(), "alice");
    assert_eq!(
        again.invite.as_ref().map(|i| i.expose_secret().to_owned()),
        Some("invite-token".to_owned())
    );
    let response = server.register_start(&again);
    pending
        .on_registration_restarted(&mut rng, &response)
        .unwrap();
    let second = pending.commit_request().unwrap().clone();
    assert_eq!(second.setup_id, 2);
    assert_ne!(second.registration_upload, first.registration_upload);
    let blank = |r: &RegisterFinishRequest| {
        let mut r = r.clone();
        r.registration_upload = bytes(b"-");
        r.setup_id = 0;
        r.account_key_server_wrap.envelope = bytes(b"-");
        r
    };
    assert_eq!(blank(&second), blank(&first));
    assert_eq!(
        pending.restart_registration(&mut rng).unwrap_err(),
        ClientError::SetupRetired
    );
    server.register_finish(account_id, &second);
    pending.finalize().unwrap();
    assert!(logs_in(&mut server, &mut rng, &sk));
}

/// ADR 0032 §1: a restore to before a full rotation serves a state the older identity key
/// signed. Under the pin it does not verify (no answer is taken from that key), and only the
/// older-chain check over the bundles this device holds calls it a rollback: every served
/// bundle below the pinned one and byte-identical to the held one, the state verifying under
/// the served head with a lower `state_seq`.
#[test]
fn a_restore_to_before_a_full_rotation_is_an_older_chain_rollback() {
    use crate::healing::{HeldAccount, is_older_chain_rollback, older_chain_query};
    use crate::unlock::account_state_query;

    let mut rng = ChaCha20Rng::seed_from_u64(97);
    let mut server = Server::new(98);
    let (mut a, _code) = signup_with_code(&mut server, &mut rng);
    let mut a_state = a.device.take().unwrap();
    let sk = secret_key_text(&a_state);
    let authors = server.authors();
    let (mut vault, mut a_unlocked, _items) = synced_writer(&mut server, &mut rng, a, &authors, 1);
    settle(&mut server, &mut rng, &mut vault, &a_unlocked);
    let first = verify_unlock(&mut a_state, &a_unlocked, &server.view(), None).unwrap();
    let mut held = HeldAccount::from_account(&first);
    let backup = (
        server.stored().bundles.clone(),
        server.stored().state.clone(),
    );

    let input = CredentialChangeInput {
        login_name: "alice",
        new_password: PASSWORD,
        new_secret_key: true,
        rotate: true,
        full_rotation: true,
        recovery_code: None,
        now_ms: T0 + 10_000,
    };
    let login = reauth(&mut server, &mut rng, &sk);
    let (started, request) =
        start_credential_change(&mut rng, login, &a_state, &a_unlocked, &input).unwrap();
    let response = server.reregister_start(&request);
    let mut pending = started
        .finish(&mut rng, &response, &a_state, &a_unlocked, &[&vault])
        .unwrap();
    let new_sk = pending.emergency_kit().unwrap().secret_key().to_owned();
    pending
        .confirm_kit(new_sk.rsplit('-').next().unwrap())
        .unwrap();
    let commit = pending.commit_request().unwrap().clone();
    server.commit_rotation(&commit).unwrap();
    pending
        .finalize(&mut rng, &mut a_state, &mut a_unlocked, &mut [&mut vault])
        .unwrap();
    let mut view = server.view();
    view.bundles = List::new(vec![bytes(server.stored().bundles.last().unwrap())]).unwrap();
    let after = verify_unlock(&mut a_state, &a_unlocked, &view, None).unwrap();
    held.absorb(&after);
    let pinned = a_state.pin().state_wire().to_vec();

    // The restore puts the chain of one bundle and the state it signed back.
    {
        let s = server.account.as_mut().unwrap();
        s.bundles = backup.0;
        s.state = backup.1;
    }
    // Served as the real server does: the bundles above the query's `known_bundle_seq`.
    let since = |query: &rizzy_proto::account::AccountStateQuery| {
        let mut view = server.view_since(query);
        view.bundles = List::new(
            view.bundles
                .as_slice()
                .iter()
                .filter(|w| {
                    PublicKeyBundle::verify_self_signed(w.as_slice())
                        .is_ok_and(|b| b.bundle_seq > query.known_bundle_seq)
                })
                .cloned()
                .collect(),
        )
        .unwrap();
        view
    };
    let usual = since(&account_state_query(&a_state));
    assert!(usual.bundles.is_empty());
    assert_eq!(
        verify_unlock(&mut a_state, &a_unlocked, &usual, None).unwrap_err(),
        ClientError::InvalidServerResponse
    );
    assert!(!is_older_chain_rollback(&a_state, &held, &usual));
    let query = older_chain_query(&held);
    assert_eq!(query.known_bundle_seq, 0);
    let older = since(&query);
    assert!(is_older_chain_rollback(&a_state, &held, &older));
    // Nothing was adopted.
    assert_eq!(a_state.pin().state_wire(), pinned.as_slice());

    // Any other mismatch stays an invalid answer: a held set that lacks the served bundle, a
    // served state the head does not verify, a served bundle that differs from the held one.
    let lacking = HeldAccount::from_account(&after);
    assert!(!is_older_chain_rollback(&a_state, &lacking, &older));
    let mut newer_state = older.clone();
    newer_state.account_state = bytes(&pinned);
    assert!(!is_older_chain_rollback(&a_state, &held, &newer_state));
    let mut other_bundle = older.clone();
    other_bundle.bundles = List::new(
        older
            .bundles
            .as_slice()
            .iter()
            .chain(view.bundles.as_slice())
            .cloned()
            .collect(),
    )
    .unwrap();
    assert!(!is_older_chain_rollback(&a_state, &held, &other_bundle));
}

/// ADR 0032 §4 step 6, the client side: a new code moves `recovery_epoch` up by one and must be
/// confirmed before its commit is released; a re-typed code keeps the epoch and carries the
/// same `H_rec`. Both carry `E_rec` under the current account key at `state_seq + 1`, signed by
/// the identity key, and nothing else.
#[test]
fn the_recovery_repair_builds_both_forms() {
    use rizzy_core::envelope::purpose::AccountKeyRecoveryWrapCtx;
    use rizzy_core::secret_key::RecoveryCode;

    use crate::healing::{RecoveryRepairForm, recovery_repair};

    let mut rng = ChaCha20Rng::seed_from_u64(99);
    let mut server = Server::new(100);
    let (mut a, code) = signup_with_code(&mut server, &mut rng);
    let a_state = a.device.take().unwrap();
    let sk = secret_key_text(&a_state);
    let a_unlocked = a.unlocked;
    let identity = PublicKeyBundle::verify_self_signed(&server.stored().bundles[0]).unwrap();
    let opens = |typed: &str, commit: &rizzy_proto::change::CommitChangeRequest| {
        let state = AccountState::verify(
            commit.account_state.as_slice(),
            &identity.identity_ed25519,
            0,
        )
        .unwrap()
        .into_statement();
        let recovery = commit.recovery.as_ref().unwrap();
        let typed = RecoveryCode::parse(typed).unwrap();
        assert_eq!(
            recovery.recovery_token_hash.to_bytes(),
            typed.auth_token().unwrap().server_hash()
        );
        let key = typed
            .wrap_key()
            .unwrap()
            .unwrap_account_key(
                &AccountKeyRecoveryWrapCtx {
                    account_id: state.account_id,
                    account_key_epoch: recovery.recovery_wrap.account_key_epoch,
                    recovery_epoch: recovery.recovery_wrap.recovery_epoch,
                },
                recovery.recovery_wrap.envelope.as_slice(),
            )
            .unwrap();
        assert!(state.matches_account_key(&key));
        assert!(commit.registration_upload.is_none() && commit.vault_rotation.is_none());
        state
    };
    let base = a_state.pin().state().clone();

    let login = reauth(&mut server, &mut rng, &sk);
    let mut repair = recovery_repair(
        &mut rng,
        &login,
        &a_state,
        &a_unlocked,
        RecoveryRepairForm::NewCode,
    )
    .unwrap();
    assert_eq!(
        repair.commit_request().unwrap_err(),
        ClientError::EmergencyKitNotConfirmed
    );
    let new_code = repair.new_code().unwrap().to_string();
    assert_ne!(new_code, code);
    assert!(!repair.confirm_new_code("ZZZZ"));
    assert!(repair.confirm_new_code(new_code.rsplit('-').next().unwrap()));
    let state = opens(&new_code, repair.commit_request().unwrap());
    let mut expected = base.clone();
    expected.state_seq += 1;
    expected.recovery_epoch += 1;
    assert_eq!(state, expected);

    let login = reauth(&mut server, &mut rng, &sk);
    let retype = recovery_repair(
        &mut rng,
        &login,
        &a_state,
        &a_unlocked,
        RecoveryRepairForm::Retype(RecoveryCode::parse(&code).unwrap()),
    )
    .unwrap();
    assert!(retype.new_code().is_none());
    let state = opens(&code, retype.commit_request().unwrap());
    let mut expected = base;
    expected.state_seq += 1;
    assert_eq!(state, expected);
}
