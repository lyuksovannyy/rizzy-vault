//! Account-side restore healing tests (ADR 0012 §7 steps 1–3, "A device enrolled after the
//! backup"; ADR 0021 §9 "Server behind") against the fake server of the parent module, which
//! here also plays a restore (its account rows put back to an earlier copy) and the
//! reconciliation epoch's acceptance of a re-published state. `rizzy-domain-auth`'s own tests
//! run the real server checks, and `rizzy-cli`'s end-to-end tests the real binary.

use rizzy_core::keys::device_set_hash;
use rizzy_core::sign::Verified;
use rizzy_proto::account::PublishAccountStateRequest;
use rizzy_proto::error::ErrorCode;

use super::*;
use crate::healing::{HeldAccount, account_healing, reconciliation};
use crate::session::{device_auth_finish_reconciling, device_auth_start_reconciling};
use crate::store::floors::Floors;
use crate::store::rows::{Alarm, Changeset, Write};

/// The account rows a backup of the fake server holds.
struct Backup {
    /// The state.
    state: Vec<u8>,
    /// The certificates.
    certs: Vec<Vec<u8>>,
}

impl Server {
    /// A backup of the account rows.
    fn backup(&self) -> Backup {
        let s = self.stored();
        Backup {
            state: s.state.clone(),
            certs: s.certs.clone(),
        }
    }

    /// Puts the account rows of `backup` back, as `rizzy-vault restore` does.
    fn restore(&mut self, backup: &Backup) {
        let s = self.account.as_mut().unwrap();
        s.state.clone_from(&backup.state);
        s.certs.clone_from(&backup.certs);
    }

    /// Healing step 2 as the real server checks it during the reconciliation epoch (or, with
    /// `epoch_open` false, refuses it outside the epoch): a state that verifies under the head
    /// with a strictly higher `state_seq`, whose carried device set reproduces its hash.
    fn publish_state(
        &mut self,
        req: &PublishAccountStateRequest,
        epoch_open: bool,
    ) -> Result<(), ErrorCode> {
        let s = self.stored();
        if req.account_state.as_slice() == s.state.as_slice() {
            return Ok(());
        }
        if !epoch_open {
            return Err(ErrorCode::StateConflict);
        }
        let bundle = PublicKeyBundle::verify_self_signed(s.bundles.last().unwrap()).unwrap();
        let verify_state = |wire: &[u8]| {
            AccountState::verify(wire, &bundle.identity_ed25519, bundle.identity_epoch)
                .map(Verified::into_statement)
        };
        let new =
            verify_state(req.account_state.as_slice()).map_err(|_| ErrorCode::InvalidRequest)?;
        let held = verify_state(&s.state).unwrap();
        if new.state_seq <= held.state_seq {
            return Err(ErrorCode::StateConflict);
        }
        let certs: Vec<_> = req
            .device_certificates
            .as_slice()
            .iter()
            .map(|w| DeviceCertificate::verify(w.as_slice(), &bundle.identity_ed25519, 0).unwrap())
            .collect();
        let set = device_set_hash(s.account_id, certs.iter(), core::iter::empty()).unwrap();
        if set != new.device_set_hash {
            return Err(ErrorCode::InvalidRequest);
        }
        let s = self.account.as_mut().unwrap();
        s.state = req.account_state.as_slice().to_vec();
        s.certs = req
            .device_certificates
            .as_slice()
            .iter()
            .map(|c| c.as_slice().to_vec())
            .collect();
        Ok(())
    }
}

/// A restore to before an enrolment: the device that holds the newer state finds the server
/// behind (a rollback), re-publishes the bundle chain, its state with the device set and its
/// self-grants, and the answer then verifies; the enrolled device, unknown to the restored
/// server, carries its certificate with its device authentication.
#[test]
fn a_restored_account_state_is_re_published_and_verifies_again() {
    let mut rng = ChaCha20Rng::seed_from_u64(91);
    let mut server = Server::new(92);
    let a = signup(&mut server, &mut rng, DeviceKind::DesktopCli);
    let mut a_state = a.device.unwrap();
    let backup = server.backup();
    let sk = secret_key_text(&a_state);
    let b = login_and_enrol(&mut server, &mut rng, &sk);
    let a_unlocked = a_state.unlock(PASSWORD).unwrap();
    let account = verify_unlock(&mut a_state, &a_unlocked, &server.view(), None).unwrap();
    assert_eq!(a_state.pin().state().state_seq, 2);
    let held = HeldAccount::from_account(&account);

    server.restore(&backup);
    assert_eq!(
        verify_unlock(&mut a_state, &a_unlocked, &server.view(), None).unwrap_err(),
        ClientError::Rollback
    );

    // Steps 1–3, built from what A holds: its pinned state, the whole device set, the bundle
    // chain up to the pinned bundle, and the self-grant under the pinned account key.
    let healing = account_healing(&a_state, &held).unwrap();
    assert_eq!(
        healing.account_state.account_state.as_slice(),
        a_state.pin().state_wire()
    );
    assert_eq!(healing.account_state.device_certificates.len(), 2);
    assert!(healing.account_state.device_revocations.is_empty());
    assert_eq!(
        healing
            .bundles
            .bundles
            .as_slice()
            .iter()
            .map(|b| b.as_slice().to_vec())
            .collect::<Vec<_>>(),
        server.stored().bundles
    );
    assert_eq!(
        healing.grants.vault_self_grants.as_slice(),
        server.stored().grants
    );
    assert!(healing.grants.device_grants.is_empty());

    // Outside the reconciliation epoch the server refuses it: still a rollback.
    assert_eq!(
        server.publish_state(&healing.account_state, false),
        Err(ErrorCode::StateConflict)
    );
    assert_eq!(
        verify_unlock(&mut a_state, &a_unlocked, &server.view(), None).unwrap_err(),
        ClientError::Rollback
    );
    // During the epoch it is adopted, and the answer verifies at the pin again.
    server.publish_state(&healing.account_state, true).unwrap();
    let healed = verify_unlock(&mut a_state, &a_unlocked, &server.view(), None).unwrap();
    assert_eq!(healed.state().state_seq, 2);
    assert_eq!(healed.certificates().len(), 2);

    // B, enrolled after the backup: its reconciliation objects name its own certificate, the
    // pinned state that lists it, the chain and the set.
    let b_state = b.device;
    let b_held = HeldAccount::from_account(&b.account);
    let rec = reconciliation(&b_state, &b_held).unwrap();
    assert_eq!(
        rec.device_certificate.as_slice(),
        b.own_certificate.wire.as_slice()
    );
    assert_eq!(rec.account_state.as_slice(), b_state.pin().state_wire());
    assert_eq!(rec.device_certificates.len(), 2);
    assert_eq!(rec.bundles.len(), 1);
    let start = device_auth_start_reconciling(&b_state, rec.clone());
    assert_eq!(start.reconciliation.as_ref(), Some(&rec));
    assert_eq!(start.device_id.to_bytes(), b_state.device_id().to_bytes());
    let challenge = server.device_auth_start(&start);
    let finish =
        device_auth_finish_reconciling(&b_state, &b.unlocked, &challenge, rec.clone()).unwrap();
    assert_eq!(finish.reconciliation, Some(rec));
    // The signature is the plain device-auth container: the fake server, which holds B's
    // certificate again after the heal, accepts it.
    server.device_auth_finish(&finish).unwrap();
}

/// Nothing is built from held objects that do not agree with the pin: no pinned bundle held,
/// a device set that does not reproduce the pinned hash, or (for the reconciliation) no own
/// certificate in the set. A genuine rollback with nothing to heal it stays a rollback.
#[test]
fn healing_is_refused_without_matching_held_objects() {
    let mut rng = ChaCha20Rng::seed_from_u64(93);
    let mut server = Server::new(94);
    let a = signup(&mut server, &mut rng, DeviceKind::DesktopCli);
    let mut a_state = a.device.unwrap();
    let a_own = a.own_certificate.clone();
    let backup = server.backup();
    let sk = secret_key_text(&a_state);
    let b = login_and_enrol(&mut server, &mut rng, &sk);
    let a_unlocked = a_state.unlock(PASSWORD).unwrap();
    let account = verify_unlock(&mut a_state, &a_unlocked, &server.view(), None).unwrap();

    // A fresh enrolment's held set has no bundle yet.
    let bare = HeldAccount::from_devices(account.certificates().to_vec(), Vec::new());
    assert_eq!(
        account_healing(&a_state, &bare).unwrap_err(),
        ClientError::CannotHeal
    );
    assert_eq!(
        reconciliation(&a_state, &bare).unwrap_err(),
        ClientError::CannotHeal
    );
    // A held set older than the pin (A's certificate only) does not reproduce its hash.
    let mut stale = HeldAccount::from_account(&account);
    stale.absorb_devices_for_tests(vec![a_own], Vec::new());
    assert_eq!(
        account_healing(&a_state, &stale).unwrap_err(),
        ClientError::CannotHeal
    );
    // B's state with a held set that lacks B: no own certificate to carry.
    let b_state = b.device;
    let mut foreign = HeldAccount::from_account(&b.account);
    foreign.absorb_devices_for_tests(
        account
            .certificates()
            .iter()
            .filter(|c| c.certificate.device_id != b_state.device_id())
            .cloned()
            .collect(),
        Vec::new(),
    );
    assert_eq!(
        reconciliation(&b_state, &foreign).unwrap_err(),
        ClientError::CannotHeal
    );

    // The restore, and no healing material that verifies: the answer stays a rollback.
    server.restore(&backup);
    assert_eq!(
        verify_unlock(&mut a_state, &a_unlocked, &server.view(), None).unwrap_err(),
        ClientError::Rollback
    );
    assert_eq!(a_state.pin().state().state_seq, 2);
}

/// The rollback alarm is cleared only in the changeset that adopts a verified state (ADR 0021
/// §9 "Server behind": "the device leaves read-only once none holds"), never on its own; a fork
/// alarm is never cleared.
#[test]
fn the_rollback_alarm_is_cleared_only_with_an_adopted_state() {
    let mut floors = Floors::empty();
    let state = |seq: u64, wire: &[u8]| Write::AccountState {
        wire: wire.to_vec(),
        state_seq: seq,
        settings_seq: 0,
    };
    let first: Changeset = [
        state(2, b"state two"),
        crate::store::alarm_write(Alarm::Rollback, &[b"state two", b"state one"]).unwrap(),
    ]
    .into_iter()
    .collect();
    floors.admit(&first).unwrap();

    let refused = |floors: &Floors, writes: Vec<Write>| {
        let mut probe = floors.clone();
        let changeset: Changeset = writes.into_iter().collect();
        assert_eq!(probe.admit(&changeset).unwrap_err(), ClientError::Internal);
    };
    refused(&floors, vec![Write::ClearAlarm(Alarm::Rollback)]);
    refused(&floors, vec![Write::ClearAlarm(Alarm::Fork)]);
    refused(
        &floors,
        vec![Write::ClearAlarm(Alarm::Fork), state(2, b"state two")],
    );
    // An older state cannot come with it either: the state rule refuses the changeset.
    refused(
        &floors,
        vec![Write::ClearAlarm(Alarm::Rollback), state(1, b"state one")],
    );
    let resolved: Changeset = [Write::ClearAlarm(Alarm::Rollback), state(2, b"state two")]
        .into_iter()
        .collect();
    floors.admit(&resolved).unwrap();
}
