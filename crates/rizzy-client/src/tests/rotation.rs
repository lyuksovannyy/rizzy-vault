//! Rotation flow tests (CRYPTO.md §11.6; ADR 0025 §2) against the fake server of the parent
//! module, which here also plays the account commit of a rotation with the checks these tests
//! need: the compare-and-swap on `state_seq`, the exact cursor and a covered wrap set (ADR 0025
//! §3). `rizzy-server`'s own tests run the real checks.

use std::collections::BTreeSet;

use rizzy_core::envelope::purpose::{ItemKeyWrapCtx, VaultKeySelfGrantCtx};
use rizzy_core::keys::{ItemKey, VaultKey};
use rizzy_proto::account::DeviceGrantsResponse;
use rizzy_proto::change::CommitChangeRequest;
use rizzy_proto::error::ErrorCode;
use rizzy_proto::objects::{ItemKeyWrap, KeyEnvelope};

use super::*;
use crate::login::LoggedIn;
use crate::rotation::{
    ConflictOutcome, MAX_REBUILDS, RotationLevel, RotationOptions, start_rotation,
};
use crate::unlock::apply_device_grants;

impl Server {
    /// The account commit of a rotation (module docs). A byte-identical repeat succeeds.
    fn commit_rotation(&mut self, req: &CommitChangeRequest) -> Result<(), ErrorCode> {
        let s = self.stored();
        if req.account_state.as_slice() == s.state.as_slice() {
            return Ok(());
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
            .vault_rotation
            .as_ref()
            .ok_or(ErrorCode::InvalidRequest)?;
        let [vault] = upload.vaults() else {
            return Err(ErrorCode::InvalidRequest);
        };
        if vault.cursor != self.heads() {
            return Err(ErrorCode::StateConflict);
        }
        let stored: BTreeSet<(Id, Id)> = self
            .wraps
            .iter()
            .map(|w| (w.item_id, w.item_key_id))
            .collect();
        let covered: BTreeSet<(Id, Id)> = vault
            .item_key_wraps
            .iter()
            .map(|w| (w.item_id, w.item_key_id))
            .chain(vault.dropped.iter().map(|d| (d.item_id, d.item_key_id)))
            .collect();
        if stored != covered {
            return Err(ErrorCode::StateConflict);
        }
        let s = self.account.as_mut().unwrap();
        s.state = req.account_state.as_slice().to_vec();
        s.e_srv = req.account_key_server_wrap.clone().unwrap();
        s.e_id = req.identity_secret_keys.clone().unwrap();
        s.grants = vec![vault.self_grant.clone()];
        self.wraps = vault.item_key_wraps.as_slice().to_vec();
        for chain in self.ops.values_mut() {
            for record in chain.values_mut() {
                record.key_wrap = None;
            }
        }
        self.device_grants
            .extend(req.device_grants.as_slice().iter().cloned());
        Ok(())
    }
}

/// Signs up with a recovery code and returns it with the signup.
fn signup_with_code(server: &mut Server, rng: &mut ChaCha20Rng) -> (SignedUp, String) {
    let input = SignupInput {
        server_origin: ORIGIN,
        login_name: "Alice",
        password: PASSWORD,
        invite: None,
        issue_recovery_code: true,
        device_kind: DeviceKind::DesktopCli,
        now_ms: T0,
    };
    let (started, request) = start_signup(rng, &input).unwrap();
    let account_id = AccountId::from_bytes(request.account_id.to_bytes());
    let response = server.register_start(&request);
    let mut pending = started.finish(rng, &response).unwrap();
    let kit = pending.emergency_kit();
    let code = kit.recovery_code().unwrap().to_owned();
    let last = kit.secret_key().rsplit('-').next().unwrap().to_owned();
    pending.confirm_kit(&last).unwrap();
    server.register_finish(account_id, pending.commit_request().unwrap());
    (pending.finalize().unwrap(), code)
}

/// A fresh OPAQUE login of the account (the re-authentication of CRYPTO.md §11.6 step 1).
fn reauth(server: &mut Server, rng: &mut ChaCha20Rng, sk: &str) -> LoggedIn {
    let input = LoginInput {
        server_origin: ORIGIN,
        login_name: "alice",
        secret_key: sk,
        password: PASSWORD,
    };
    let (started, request) = start_login(rng, &input).unwrap();
    let answer = server.login_start(&request);
    let (awaiting, finish) = started.finish(rng, &answer, None).unwrap();
    awaiting
        .complete(server.login_finish(&finish).unwrap())
        .unwrap()
}

/// Logs in on another new device and enrols it (any number of devices already enrolled).
fn enrol_another(server: &mut Server, rng: &mut ChaCha20Rng, sk: &str) -> crate::login::Enrolled {
    let (pending, enrol) = reauth(server, rng, sk)
        .enrol(rng, DeviceKind::DesktopCli, T0 + 1000)
        .unwrap();
    server.enrol(&enrol);
    pending.finalize()
}

/// A complete Fetch of `vault`.
fn fetch(server: &Server, vault: &mut VaultSync) {
    let authors = server.authors();
    let response = server.fetch(&vault.fetch_request().unwrap());
    vault.apply_fetch(&authors, &response, T0).unwrap();
}

/// Uploads everything `vault` has queued (ops, then the snapshots they make due), then runs a
/// complete Fetch: the state a rotation starts from (ADR 0025 §2 step 1).
fn settle(
    server: &mut Server,
    rng: &mut ChaCha20Rng,
    vault: &mut VaultSync,
    unlocked: &UnlockedDevice,
) {
    while let Some(up) = vault.upload_request(rng, unlocked).unwrap() {
        let answer = server.upload(&up);
        vault.apply_upload_response(&answer).unwrap();
    }
    fetch(server, vault);
}

/// The login-password field key.
fn password_key() -> SchemaKey {
    SchemaKey::parse(LOGIN_PASSWORD.as_bytes()).unwrap()
}

/// Writes `text` into the password of `item` and uploads it.
fn edit_and_upload(
    server: &mut Server,
    rng: &mut ChaCha20Rng,
    vault: &mut VaultSync,
    unlocked: &UnlockedDevice,
    item: ItemId,
    text: &str,
) -> UploadRequest {
    let key = password_key();
    let value = Value::text(text).unwrap();
    vault
        .edit_item(
            rng,
            unlocked,
            item,
            &[FieldEdit {
                key: &key,
                value: &value,
            }],
            T0 + 50_000,
        )
        .unwrap();
    let up = vault.upload_request(rng, unlocked).unwrap().unwrap();
    let answer = server.upload(&up);
    vault.apply_upload_response(&answer).unwrap();
    up
}

/// ADR 0025 §2 and CRYPTO.md §11.6, end to end against the fake: A rotates (keeping the
/// recovery code); the rows come back under the new vault key with the same item keys; A's
/// next edit of an old item uses a fresh item key (the writer rule); B, which did not rotate,
/// opens its grant, the new self-grant and every item.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one story: rotate, commit, finalize, write, and the other device following"
)]
fn a_rotation_commits_and_the_other_device_follows() {
    let mut rng = ChaCha20Rng::seed_from_u64(40);
    let mut server = Server::new(41);
    let (mut a, code) = signup_with_code(&mut server, &mut rng);
    let mut a_state = a.device.take().unwrap();
    let sk = secret_key_text(&a_state);
    let b = login_and_enrol(&mut server, &mut rng, &sk);
    let vault_id = a.vault_key.vault_id();
    let authors = server.authors();
    let (mut vault, mut a_unlocked, items) = synced_writer(&mut server, &mut rng, a, &authors, 2);
    let old_key_ids: Vec<_> = items.iter().map(|i| vault.item_key_ids(*i)[0].0).collect();

    // Rotation needs a complete Fetch after the upload.
    let options = RotationOptions {
        level: RotationLevel::Standard,
        revoke: None,
        recovery_code: Some(&code),
        now_ms: T0 + 10_000,
    };
    let login = reauth(&mut server, &mut rng, &sk);
    assert_eq!(
        start_rotation(&mut rng, login, &a_state, &a_unlocked, &[&vault], &options).unwrap_err(),
        ClientError::SyncRequired
    );
    settle(&mut server, &mut rng, &mut vault, &a_unlocked);
    // Recovery is on: the current code is required, and must be well-formed.
    for wrong in [None, Some("RVR1-0000")] {
        let login = reauth(&mut server, &mut rng, &sk);
        let options = RotationOptions {
            recovery_code: wrong,
            ..options
        };
        assert_eq!(
            start_rotation(&mut rng, login, &a_state, &a_unlocked, &[&vault], &options)
                .unwrap_err(),
            ClientError::InvalidInput
        );
    }
    // What an attacker with the old password and a pre-rotation backup holds (INV-19): the old
    // account key (here from `E_local`, which opens with the old password) and `E_srv`.
    let before = a_state.unlock(PASSWORD).unwrap();
    let old_e_srv = server.stored().e_srv.clone();
    let login = reauth(&mut server, &mut rng, &sk);
    let pending =
        start_rotation(&mut rng, login, &a_state, &a_unlocked, &[&vault], &options).unwrap();
    let request = pending.commit_request().clone();
    assert_eq!(pending.new_state().account_key_epoch, 1);
    assert_eq!(request.device_grants.len(), 1);
    assert!(request.recovery_rewrap.is_some() && request.bundle.is_none());
    server.commit_rotation(&request).unwrap();
    // A resend of the same bytes is success (CRYPTO.md §11 "Secrets before commit").
    server.commit_rotation(&request).unwrap();
    let done = pending
        .finalize(&mut rng, &mut a_state, &mut a_unlocked, &mut [&mut vault])
        .unwrap();
    assert!(done.dropped_items.is_empty());
    assert_eq!(a_unlocked.account_key.epoch(), 1);
    assert_eq!(vault.vault_key_epoch(), 1);
    assert_eq!(a_state.pin().state().account_key_epoch, 1);
    // INV-19: the old key opens none of the new objects, and the old `E_srv` is gone.
    let stored = server.stored();
    assert_ne!(stored.e_srv, old_e_srv);
    assert!(
        before
            .account_key
            .unwrap_identity_keys(
                &rizzy_core::envelope::purpose::IdentitySecretKeysCtx {
                    account_id: a_state.account_id(),
                    identity_epoch: 0,
                },
                stored.e_id.envelope.as_slice(),
            )
            .is_err()
    );
    for account_key_epoch in [0, 1] {
        assert!(
            before
                .account_key
                .unwrap_vault_key(
                    &VaultKeySelfGrantCtx {
                        account_id: a_state.account_id(),
                        vault_id,
                        account_key_epoch,
                        vault_key_epoch: 1,
                    },
                    stored.grants[0].envelope.as_slice(),
                )
                .is_err()
        );
    }
    assert!(server.wraps.iter().all(|w| w.vault_key_epoch == 1));

    // The served rows are at epoch 1 and wrap the same item keys.
    fetch(&server, &mut vault);
    let new_self_grant = &server.stored().grants[0];
    assert_eq!(new_self_grant.vault_key_epoch, 1);
    for (item, old_id) in items.iter().zip(&old_key_ids) {
        assert!(vault.item_key_ids(*item).iter().any(|(k, _)| k == old_id));
    }
    assert!(server.wraps.iter().all(|w| w.vault_key_epoch == 1));

    // The writer rule: an edit of an old item uses a fresh item key, carried as a wrap at the new
    // epoch, and the old key is never used again for writing.
    let up = edit_and_upload(
        &mut server,
        &mut rng,
        &mut vault,
        &a_unlocked,
        items[0],
        "new",
    );
    let Record::Op(op) = &up.records.as_slice()[0] else {
        panic!("an op first");
    };
    assert!(op.key_wrap.is_some());
    let keys = vault.item_key_ids(items[0]);
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[1].1, 1);

    // A's E_local now holds the new key.
    let again = a_state.unlock(PASSWORD).unwrap();
    assert_eq!(again.account_key.epoch(), 1);

    // B, which did not rotate, follows through its grant (CRYPTO.md §11.3 step 4).
    let mut b_state = b.device;
    let mut b_unlocked = b_state.unlock(PASSWORD).unwrap();
    let view = server.view();
    assert_eq!(
        verify_unlock(&mut b_state, &b_unlocked, &view, None).unwrap_err(),
        ClientError::AccountKeyRotated
    );
    let grants = DeviceGrantsResponse {
        grants: List::new(
            server
                .device_grants
                .iter()
                .filter(|g| g.recipient_device_id.to_bytes() == b_state.device_id().to_bytes())
                .cloned()
                .collect(),
        )
        .unwrap(),
    };
    apply_device_grants(
        &mut rng,
        &mut b_state,
        &mut b_unlocked,
        &view,
        &grants,
        None,
    )
    .unwrap();
    let mut b_account = verify_unlock(&mut b_state, &b_unlocked, &view, None).unwrap();
    let b_key = b_account.take_vault_key(vault_id).unwrap();
    assert_eq!(b_key.epoch(), 1);
    let mut b_vault = VaultSync::new(b_key, &b_unlocked, 1).unwrap();
    fetch(&server, &mut b_vault);
    assert_eq!(
        b_vault
            .field_value(items[0], LOGIN_PASSWORD)
            .unwrap()
            .expose_secret(),
        Value::text("new").unwrap().expose_secret()
    );
    assert!(b_vault.field_value(items[1], LOGIN_PASSWORD).is_some());
}

/// ADR 0025 §2 step 5 and CRYPTO.md §10.2: every branch of the retry rule, with an upload and
/// an enrolment racing the rotation, and the rebuild limit.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the retry branches of ADR 0025 §2 step 5, one after the other on one pending rotation"
)]
fn a_rotation_retries_by_the_cas_rule() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let mut server = Server::new(43);
    let (mut a, code) = signup_with_code(&mut server, &mut rng);
    let a_state = a.device.take().unwrap();
    let sk = secret_key_text(&a_state);
    let mut b = login_and_enrol(&mut server, &mut rng, &sk);
    let vault_id = a.vault_key.vault_id();
    let authors = server.authors();
    let (mut vault, a_unlocked, _) = synced_writer(&mut server, &mut rng, a, &authors, 1);
    settle(&mut server, &mut rng, &mut vault, &a_unlocked);
    let options = RotationOptions {
        level: RotationLevel::Standard,
        revoke: None,
        recovery_code: Some(&code),
        now_ms: T0 + 10_000,
    };
    let login = reauth(&mut server, &mut rng, &sk);
    let mut pending =
        start_rotation(&mut rng, login, &a_state, &a_unlocked, &[&vault], &options).unwrap();
    let first_state = pending.commit_request().account_state.clone();

    // An upload lands before the commit: the cursor is below the head.
    let b_key = b.account.take_vault_key(vault_id).unwrap();
    let mut b_vault = VaultSync::new(b_key, &b.unlocked, 1).unwrap();
    fetch(&server, &mut b_vault);
    let key = password_key();
    let value = Value::text("b").unwrap();
    b_vault
        .create_item(
            &mut rng,
            &b.unlocked,
            ItemType::LOGIN,
            &[FieldEdit {
                key: &key,
                value: &value,
            }],
            T0 + 20_000,
        )
        .unwrap();
    let up = b_vault
        .upload_request(&mut rng, &b.unlocked)
        .unwrap()
        .unwrap();
    server.upload(&up);
    assert_eq!(
        server.commit_rotation(pending.commit_request()),
        Err(ErrorCode::StateConflict)
    );
    // Same state: only the vault half is rebuilt, the signed state is byte-identical. Without a
    // new Fetch the rebuilt cursor is still behind, and the server refuses again.
    assert_eq!(
        pending
            .on_state_conflict(&mut rng, &server.view(), &a_unlocked, &[&vault])
            .unwrap(),
        ConflictOutcome::Resend
    );
    assert_eq!(
        server.commit_rotation(pending.commit_request()),
        Err(ErrorCode::StateConflict)
    );
    fetch(&server, &mut vault);
    assert_eq!(
        pending
            .on_state_conflict(&mut rng, &server.view(), &a_unlocked, &[&vault])
            .unwrap(),
        ConflictOutcome::Resend
    );
    assert_eq!(pending.commit_request().account_state, first_state);
    assert_eq!(pending.commit_request().device_grants.len(), 1);

    // An enrolment lands: only `state_seq` and the device set moved. The grants are rebuilt for
    // the new set and the state is re-signed on top of it.
    let c = enrol_another(&mut server, &mut rng, &sk);
    assert_eq!(
        server.commit_rotation(pending.commit_request()),
        Err(ErrorCode::StateConflict)
    );
    assert_eq!(
        pending
            .on_state_conflict(&mut rng, &server.view(), &a_unlocked, &[&vault])
            .unwrap(),
        ConflictOutcome::Resend
    );
    assert_eq!(pending.new_state().state_seq, 4);
    let recipients: BTreeSet<[u8; 16]> = pending
        .commit_request()
        .device_grants
        .iter()
        .map(|g| g.recipient_device_id.to_bytes())
        .collect();
    assert_eq!(
        recipients,
        [
            b.device.device_id().to_bytes(),
            c.device.device_id().to_bytes()
        ]
        .into()
    );

    // Other changes: a rollback, a fork, and a state where more than the device set moved.
    let base = c.account.state().clone();
    let base_wire = server.stored().state.clone();
    let older = {
        let mut s = base.clone();
        s.state_seq -= 1;
        s.sign(c.account.identity.signing_key()).unwrap()
    };
    server.account.as_mut().unwrap().state = older;
    assert_eq!(
        pending
            .on_state_conflict(&mut rng, &server.view(), &a_unlocked, &[&vault])
            .unwrap_err(),
        ClientError::Rollback
    );
    let forked = {
        let mut s = base.clone();
        s.mail_key_epoch = 9;
        s.sign(c.account.identity.signing_key()).unwrap()
    };
    server.account.as_mut().unwrap().state = forked;
    assert_eq!(
        pending
            .on_state_conflict(&mut rng, &server.view(), &a_unlocked, &[&vault])
            .unwrap_err(),
        ClientError::Fork
    );
    server.account.as_mut().unwrap().state = base_wire.clone();
    serve_state(&mut server, &c.account, &base, |s| s.password_epoch += 1);
    assert_eq!(
        pending
            .on_state_conflict(&mut rng, &server.view(), &a_unlocked, &[&vault])
            .unwrap_err(),
        ClientError::RotationRestart
    );

    // The rebuild limit: after five rebuilds the next conflict stops the retries.
    server.account.as_mut().unwrap().state = base_wire;
    for _ in 3..MAX_REBUILDS {
        assert_eq!(
            pending
                .on_state_conflict(&mut rng, &server.view(), &a_unlocked, &[&vault])
                .unwrap(),
            ConflictOutcome::Resend
        );
    }
    assert_eq!(
        pending
            .on_state_conflict(&mut rng, &server.view(), &a_unlocked, &[&vault])
            .unwrap_err(),
        ClientError::VaultKeepsChanging
    );
    // The pending rotation is kept: its request still commits, and a conflict answered after
    // the commit landed is recognised as committed.
    server.commit_rotation(pending.commit_request()).unwrap();
    assert_eq!(
        pending
            .on_state_conflict(&mut rng, &server.view(), &a_unlocked, &[&vault])
            .unwrap(),
        ConflictOutcome::Committed
    );
}

/// ADR 0025 §2 step 3: rows that do not open under a held key, or whose locator names another
/// key, are dropped (and reported); the rest are re-wrapped with their item key unchanged. And
/// ADR 0025 §4: a second key at a seen epoch is a fork alarm.
#[test]
fn the_vault_half_drops_what_it_cannot_open_and_keys_are_never_reused() {
    let mut rng = ChaCha20Rng::seed_from_u64(44);
    let mut server = Server::new(45);
    let a = signup(&mut server, &mut rng, DeviceKind::DesktopCli);
    let account_id = a.unlocked.account_id;
    let vault_id = a.vault_key.vault_id();
    let authors = server.authors();
    let (mut vault, unlocked, items) = synced_writer(&mut server, &mut rng, a, &authors, 1);
    // A row under an unknown key, and a real wrap filed under another item key id.
    let stranger = VaultKey::generate(&mut rng, vault_id, 0);
    let wrap = |key: &VaultKey, rng: &mut ChaCha20Rng, item: ItemId| {
        let item_key = ItemKey::generate(rng, 0);
        key.wrap_item_key(
            rng,
            &ItemKeyWrapCtx {
                vault_id,
                item_id: item,
                vault_key_epoch: 0,
            },
            &item_key,
        )
        .unwrap()
    };
    let junk_item = ItemId::from_bytes([0x71; 16]);
    let junk = wrap(&stranger, &mut rng, junk_item);
    server.wraps.push(ItemKeyWrap {
        item_id: Id::from_bytes(junk_item.to_bytes()),
        item_key_id: Id::from_bytes([0x72; 16]),
        vault_key_epoch: 0,
        envelope: KeyEnvelope::new(junk).unwrap(),
    });
    let first = server.wraps[0].clone();
    server.wraps.push(ItemKeyWrap {
        item_id: first.item_id,
        item_key_id: Id::from_bytes([0x74; 16]),
        ..first
    });
    settle(&mut server, &mut rng, &mut vault, &unlocked);

    let new_account_key = unlocked.account_key.generate_next(&mut rng).unwrap();
    let new_vault_key = VaultKey::generate(&mut rng, vault_id, 1);
    let half = vault
        .rotation_half(&mut rng, account_id, &new_account_key, &new_vault_key)
        .unwrap();
    assert_eq!(half.dropped_items.len(), 2);
    assert_eq!(half.rotation.dropped.len(), 2);
    assert_eq!(half.rotation.item_key_wraps.len(), 1);
    assert_eq!(half.rotation.cursor, server.heads());
    let rewrap = &half.rotation.item_key_wraps.as_slice()[0];
    let opened = new_vault_key
        .unwrap_item_key(
            &ItemKeyWrapCtx {
                vault_id,
                item_id: items[0],
                vault_key_epoch: 1,
            },
            rewrap.envelope.as_slice(),
        )
        .unwrap();
    assert_eq!(opened.created_vault_key_epoch(), 0);
    assert_eq!(
        *opened.key_id().unwrap().as_bytes(),
        rewrap.item_key_id.to_bytes()
    );
    let grant = new_account_key
        .unwrap_vault_key(
            &VaultKeySelfGrantCtx {
                account_id,
                vault_id,
                account_key_epoch: 1,
                vault_key_epoch: 1,
            },
            half.rotation.self_grant.envelope.as_slice(),
        )
        .unwrap();
    assert!(grant.matches_key_id(&new_vault_key.key_id().unwrap()));
    // A key at an epoch not above every epoch seen is refused.
    let reused = VaultKey::generate(&mut rng, vault_id, 0);
    assert!(
        vault
            .rotation_half(&mut rng, account_id, &new_account_key, &reused)
            .is_err()
    );

    // Adopting: the new key at epoch 1; then another key at epoch 1 is a fork, and read-only.
    vault.adopt_vault_key(new_vault_key).unwrap();
    assert_eq!(vault.vault_key_epoch(), 1);
    let other = VaultKey::generate(&mut rng, vault_id, 1);
    assert_eq!(vault.adopt_vault_key(other), Err(ClientError::Fork));
    assert!(vault.is_read_only());
    let older = VaultKey::generate(&mut rng, vault_id, 0);
    assert_eq!(vault.adopt_vault_key(older), Err(ClientError::Fork));
}

/// The signed header of an uploaded own op, verified under its author's certificate.
fn uploaded_header(authors: &Authors, record: &Record) -> OpHeader {
    let Record::Op(op) = record else {
        panic!("an op");
    };
    let wire = op.statement.as_slice();
    let author = authors.signer(wire).unwrap();
    let verified = OpStatement::verify(wire, &author.verifying_key).unwrap();
    OpHeader::parse_statement(&verified).unwrap()
}

/// An answer that refuses the first record of `up` with `error` under `generation`, and leaves
/// the rest unprocessed.
fn refuse_first(up: &UploadRequest, error: ErrorCode, generation: [u8; 16]) -> UploadResponse {
    let results = (0..up.records.as_slice().len())
        .map(|i| {
            if i == 0 {
                UploadResult::Rejected { error }
            } else {
                UploadResult::NotProcessed
            }
        })
        .collect();
    UploadResponse {
        restore_generation: Fixed::from_bytes(generation),
        results: List::new(results).unwrap(),
    }
}

/// ADR 0025 §4 and ADR 0021 §9 "Stale epoch": an own op answered `stale_epoch` is not sent
/// again until the new vault key is adopted; then it and the later old-epoch op of the chain
/// are re-issued with the same `device_seq`, `vault_prev_seq`, HLC and causal context, at the
/// new epoch, under a fresh item key whose wrap the first carries; they are stored and the
/// chain goes on. An op the server may have stored and served before a restore is never
/// re-issued: it is re-published verbatim in a healing request.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one chain through a stale answer, a re-issue, a restore and its healing"
)]
fn a_stale_epoch_answer_reissues_the_ops_under_the_new_key() {
    let mut rng = ChaCha20Rng::seed_from_u64(50);
    let mut server = Server::new(51);
    let (a, _) = signup_with_code(&mut server, &mut rng);
    let vault_id = a.vault_key.vault_id();
    let authors = server.authors();
    let (mut vault, unlocked, items) = synced_writer(&mut server, &mut rng, a, &authors, 1);
    settle(&mut server, &mut rng, &mut vault, &unlocked);
    let key = password_key();
    let edit = |vault: &mut VaultSync, rng: &mut ChaCha20Rng, text: &str, at: u64| {
        let value = Value::text(text).unwrap();
        vault
            .edit_item(
                rng,
                &unlocked,
                items[0],
                &[FieldEdit {
                    key: &key,
                    value: &value,
                }],
                at,
            )
            .unwrap();
    };
    edit(&mut vault, &mut rng, "first", T0 + 20_000);
    edit(&mut vault, &mut rng, "second", T0 + 20_001);
    let sent = vault.upload_request(&mut rng, &unlocked).unwrap().unwrap();
    assert_eq!(sent.records.as_slice().len(), 2);
    let before: Vec<OpHeader> = sent
        .records
        .as_slice()
        .iter()
        .map(|r| uploaded_header(&authors, r))
        .collect();
    let outcome = vault
        .apply_upload_response(&refuse_first(
            &sent,
            ErrorCode::StaleEpoch,
            server.generation,
        ))
        .unwrap();
    assert_eq!(outcome.rejected, vec![ErrorCode::StaleEpoch]);

    // Not re-sent unchanged: the new vault key must be adopted first.
    assert_eq!(
        vault.upload_request(&mut rng, &unlocked).unwrap_err(),
        ClientError::VaultKeyRotated
    );
    vault
        .adopt_vault_key(VaultKey::generate(&mut rng, vault_id, 1))
        .unwrap();
    let reissued = vault.upload_request(&mut rng, &unlocked).unwrap().unwrap();
    let records = reissued.records.as_slice();
    assert_eq!(records.len(), 2);
    for (record, old) in records.iter().zip(&before) {
        let header = uploaded_header(&authors, record);
        assert_eq!(header.vault_key_epoch, 1);
        let expected = OpHeader {
            vault_key_epoch: 1,
            ..old.clone()
        };
        assert_eq!(header, expected);
    }
    let (Record::Op(first), Record::Op(second)) = (&records[0], &records[1]) else {
        panic!("two ops");
    };
    let wrap = first.key_wrap.as_ref().unwrap();
    assert!(second.key_wrap.is_none());
    let fresh = vault.item_key_ids(items[0]);
    assert_eq!(fresh.last().unwrap().1, 1);
    assert_eq!(
        fresh.last().unwrap().0.as_bytes(),
        &wrap.item_key_id.to_bytes()
    );
    let answer = server.upload(&reissued);
    assert_eq!(
        vault.apply_upload_response(&answer).unwrap().acknowledged,
        2
    );
    settle(&mut server, &mut rng, &mut vault, &unlocked);
    assert_eq!(
        vault
            .field_value(items[0], LOGIN_PASSWORD)
            .unwrap()
            .expose_secret(),
        Value::text("second").unwrap().expose_secret()
    );

    // A stale answer under another restore generation: the op may have been stored and served
    // before the restore, so it is never re-issued (ADR 0021 §9).
    edit(&mut vault, &mut rng, "third", T0 + 20_002);
    let sent = vault.upload_request(&mut rng, &unlocked).unwrap().unwrap();
    let seq = uploaded_header(&authors, &sent.records.as_slice()[0])
        .dot
        .seq();
    vault
        .apply_upload_response(&refuse_first(&sent, ErrorCode::StaleEpoch, [9; 16]))
        .unwrap();
    assert!(vault.may_have_been_served(seq));
    vault
        .adopt_vault_key(VaultKey::generate(&mut rng, vault_id, 2))
        .unwrap();
    assert_eq!(
        vault.upload_request(&mut rng, &unlocked).unwrap_err(),
        ClientError::HealingRequired
    );

    // It is re-published verbatim in a healing request instead (the restored server answers
    // under the new generation), acknowledged, and never re-issued.
    server.generation = [9; 16];
    vault
        .apply_fetch(
            &authors,
            &server.fetch(&vault.fetch_request().unwrap()),
            T0 + 20_003,
        )
        .unwrap();
    assert!(vault.needs_healing());
    let heal = vault.healing_request().unwrap().unwrap();
    assert_eq!(heal.records.as_slice(), &sent.records.as_slice()[..1]);
    let answer = server.heal(&heal).unwrap();
    assert_eq!(
        vault
            .apply_healing_response(&answer)
            .unwrap()
            .own_acknowledged,
        1
    );
    assert!(!vault.needs_healing());
    if let Some(up) = vault.upload_request(&mut rng, &unlocked).unwrap() {
        assert!(
            up.records
                .as_slice()
                .iter()
                .all(|r| matches!(r, Record::Snapshot(_)))
        );
    }
}

/// ADR 0021 §9 "Stale epoch" and "Already stored": the healing request that re-published a
/// maybe-served own op was stored, but its answer was lost. The next Fetch shows the op at the
/// server's own head, so no healing request is built for it (its range starts above that
/// head) and the driver does not stay blocked: the normal upload re-sends it verbatim, the
/// server answers "already stored", and that acknowledges it. It is never re-issued.
#[test]
fn a_republished_op_whose_heal_answer_was_lost_is_acknowledged_as_already_stored() {
    let mut rng = ChaCha20Rng::seed_from_u64(54);
    let mut server = Server::new(55);
    let (a, _) = signup_with_code(&mut server, &mut rng);
    let vault_id = a.vault_key.vault_id();
    let authors = server.authors();
    let (mut vault, unlocked, items) = synced_writer(&mut server, &mut rng, a, &authors, 1);
    settle(&mut server, &mut rng, &mut vault, &unlocked);
    let key = password_key();
    let value = Value::text("third").unwrap();
    vault
        .edit_item(
            &mut rng,
            &unlocked,
            items[0],
            &[FieldEdit {
                key: &key,
                value: &value,
            }],
            T0 + 20_000,
        )
        .unwrap();
    let sent = vault.upload_request(&mut rng, &unlocked).unwrap().unwrap();
    // A stale answer under another restore generation: the op may have been stored and served.
    vault
        .apply_upload_response(&refuse_first(&sent, ErrorCode::StaleEpoch, [9; 16]))
        .unwrap();
    vault
        .adopt_vault_key(VaultKey::generate(&mut rng, vault_id, 1))
        .unwrap();
    assert_eq!(
        vault.upload_request(&mut rng, &unlocked).unwrap_err(),
        ClientError::HealingRequired
    );
    server.generation = [9; 16];
    vault
        .apply_fetch(
            &authors,
            &server.fetch(&vault.fetch_request().unwrap()),
            T0 + 20_001,
        )
        .unwrap();
    let heal = vault.healing_request().unwrap().unwrap();
    assert_eq!(heal.records.as_slice(), &sent.records.as_slice()[..1]);
    // The server stores it; the answer never arrives.
    server.heal(&heal).unwrap();
    vault.healing_refused();
    assert!(
        vault.needs_healing(),
        "the last Fetch is older than the heal"
    );

    // The next Fetch shows the op stored: nothing to heal, and the upload is not blocked.
    vault
        .apply_fetch(
            &authors,
            &server.fetch(&vault.fetch_request().unwrap()),
            T0 + 20_002,
        )
        .unwrap();
    assert!(!vault.needs_healing());
    assert_eq!(vault.healing_request().unwrap(), None);
    let again = vault.upload_request(&mut rng, &unlocked).unwrap().unwrap();
    assert_eq!(
        again.records.as_slice()[0],
        sent.records.as_slice()[0],
        "re-sent verbatim, never re-issued"
    );
    let answer = server.upload(&again);
    assert_eq!(answer.results.as_slice()[0], UploadResult::AlreadyStored);
    let outcome = vault.apply_upload_response(&answer).unwrap();
    assert!(outcome.rejected.is_empty());
    assert!(outcome.acknowledged >= 1);
    assert_eq!(vault.unacknowledged().0, 0);
    settle(&mut server, &mut rng, &mut vault, &unlocked);
    assert_eq!(
        vault
            .field_value(items[0], LOGIN_PASSWORD)
            .unwrap()
            .expose_secret(),
        value.expose_secret()
    );
}

/// The H of every revocation a rotation request carries, verified under its new bundle's
/// identity key.
fn revocation_heads(request: &CommitChangeRequest) -> Vec<u64> {
    let bundle =
        PublicKeyBundle::verify_self_signed(request.bundle.as_ref().unwrap().as_slice()).unwrap();
    request
        .device_revocations
        .iter()
        .map(|wire| {
            rizzy_core::sign::DeviceRevocation::verify(wire.as_slice(), &bundle.identity_ed25519)
                .unwrap()
                .last_accepted_device_seq
        })
        .collect()
}

/// ADR 0025 §2 step 5 with a full rotation: a web-vault device uploads between two attempts.
/// Its certificate is not in the device set, so `account-state` does not move and the retry is
/// at the same position; the signed state stays byte-identical, and the kind-4 revocation is
/// re-signed with H taken from the new Fetch (the server refuses one whose H is not the head).
#[test]
fn a_full_rotation_retry_renews_the_web_revocation_head() {
    let mut rng = ChaCha20Rng::seed_from_u64(52);
    let mut server = Server::new(53);
    let (mut a, code) = signup_with_code(&mut server, &mut rng);
    let a_state = a.device.take().unwrap();
    let sk = secret_key_text(&a_state);
    let vault_id = a.vault_key.vault_id();
    let authors = server.authors();
    let (mut vault, a_unlocked, _) = synced_writer(&mut server, &mut rng, a, &authors, 1);

    // A web-vault session of the account writes one op.
    let (mut web, upload) = reauth(&mut server, &mut rng, &sk)
        .web_device(&mut rng, T0 + 1000)
        .unwrap();
    server
        .account
        .as_mut()
        .unwrap()
        .certs
        .push(upload.device_certificate.as_slice().to_vec());
    let web_key = web.account.take_vault_key(vault_id).unwrap();
    let mut web_vault = VaultSync::new(web_key, &web.unlocked, 1).unwrap();
    fetch(&server, &mut web_vault);
    let key = password_key();
    let web_write =
        |server: &mut Server, web_vault: &mut VaultSync, rng: &mut ChaCha20Rng, at: u64| {
            let value = Value::text("w").unwrap();
            web_vault
                .create_item(
                    rng,
                    &web.unlocked,
                    ItemType::LOGIN,
                    &[FieldEdit {
                        key: &key,
                        value: &value,
                    }],
                    at,
                )
                .unwrap();
            let up = web_vault
                .upload_request(rng, &web.unlocked)
                .unwrap()
                .unwrap();
            server.upload(&up);
        };
    web_write(&mut server, &mut web_vault, &mut rng, T0 + 2000);
    settle(&mut server, &mut rng, &mut vault, &a_unlocked);

    let options = RotationOptions {
        level: RotationLevel::Full,
        revoke: None,
        recovery_code: Some(&code),
        now_ms: T0 + 10_000,
    };
    let login = reauth(&mut server, &mut rng, &sk);
    let mut pending =
        start_rotation(&mut rng, login, &a_state, &a_unlocked, &[&vault], &options).unwrap();
    let first_state = pending.commit_request().account_state.clone();
    assert_eq!(revocation_heads(pending.commit_request()), vec![1]);

    // The web session uploads again before the commit; the server refuses the rotation with
    // `state_conflict` (its cursor and the revocation's H are behind: `rizzy-server`'s tests;
    // this fake checks neither a full rotation's new identity key nor H), at the same position.
    web_write(&mut server, &mut web_vault, &mut rng, T0 + 20_000);
    fetch(&server, &mut vault);
    assert_eq!(
        pending
            .on_state_conflict(&mut rng, &server.view(), &a_unlocked, &[&vault])
            .unwrap(),
        ConflictOutcome::Resend
    );
    assert_eq!(pending.commit_request().account_state, first_state);
    assert_eq!(revocation_heads(pending.commit_request()), vec![2]);
}
