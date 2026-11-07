// SPDX-License-Identifier: AGPL-3.0-only

//! Device revocation on the client ([ADR 0091] §3, §5; §7 test 7) against the fake server of
//! the parent module:
//!
//! - a served rotation whose newest grant is signed by a device the new state revokes leaves the
//!   device read-only with its old key (§5), while the honest grant of the same rotation opens;
//! - a rotation that revokes this device makes it delete its pending record unsent (§3 "A
//!   revoked device with a pending commit");
//! - the revocation set of [`RotationOptions::revoke`], the retry of `revocation_pending` and
//!   the advisory notice.
//!
//! [ADR 0091]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0091-revoked-device-rotation-race.md

use rizzy_core::envelope::purpose::AccountKeyDeviceGrantCtx;
use rizzy_core::keys::{GrantSender, GrantSigner, open_account_key_device_grant};
use rizzy_core::keys::seal_account_key_device_grant;
use rizzy_proto::account::{DeviceGrantsResponse, RevocationWindowNotice};
use rizzy_proto::objects::DeviceGrant;

use super::rotation::{fetch, reauth, settle, signup_with_code};
use super::*;
use crate::revocation::{
    MAX_REVOCATION_RETRIES, REVOCATION_RETRY_MS, RevocationNotice, check_renewed_head,
    next_revocation_retry, own_revocation,
};
use crate::rotation::{RevokeDevice, RotationLevel, RotationOptions, start_rotation};
use crate::store::record::Stage;
use crate::unlock::apply_device_grants;

/// Logs in on another new device and enrols it.
fn enrol(server: &mut Server, rng: &mut ChaCha20Rng, sk: &str) -> crate::login::Enrolled {
    let (pending, enrol) = reauth(server, rng, sk)
        .enrol(rng, DeviceKind::DesktopCli, T0 + 1000)
        .unwrap();
    server.enrol(&enrol);
    pending.finalize()
}

/// The grants `server` holds for `device`.
fn grants_for(server: &Server, device: DeviceId) -> DeviceGrantsResponse {
    DeviceGrantsResponse {
        grants: List::new(
            server
                .device_grants
                .iter()
                .filter(|g| g.recipient_device_id.to_bytes() == device.to_bytes())
                .cloned()
                .collect(),
        )
        .unwrap(),
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one story: three devices, a revocation, a forged grant, an honest one, the revoked device"
)]
fn a_grant_from_a_revoked_device_is_refused_and_the_revoked_device_drops_its_pending_record() {
    let mut rng = ChaCha20Rng::seed_from_u64(91);
    let mut server = Server::new(92);
    let (mut a, code) = signup_with_code(&mut server, &mut rng);
    let mut a_state = a.device.take().unwrap();
    let sk = secret_key_text(&a_state);
    let mut b = enrol(&mut server, &mut rng, &sk);
    let mut d = enrol(&mut server, &mut rng, &sk);
    let vault_id = a.vault_key.vault_id();
    let authors = server.authors();
    let (mut vault, mut a_unlocked, _items) = synced_writer(&mut server, &mut rng, a, &authors, 1);
    settle(&mut server, &mut rng, &mut vault, &a_unlocked);
    let d_id = d.device.device_id();

    // D, the device about to be revoked, holds a pending commit of its own: a rotation it built
    // and persisted (secrets before commit, step 3) but has not sent.
    let mut d_vault = VaultSync::new(
        d.account.take_vault_key(vault_id).unwrap(),
        &d.unlocked,
        1,
    )
    .unwrap();
    fetch(&server, &mut d_vault);
    let d_options = RotationOptions {
        level: RotationLevel::Standard,
        revoke: &[],
        recovery_code: Some(&code),
        now_ms: T0 + 9_000,
    };
    let d_login = reauth(&mut server, &mut rng, &sk);
    let mut d_pending = start_rotation(
        &mut rng,
        d_login,
        &d.device,
        &d.unlocked,
        &[&d_vault],
        &d_options,
    )
    .unwrap();
    let d_record = d
        .device
        .record(Stage::Committed)
        .unwrap()
        .with_pending(
            d_pending
                .pending_record(&mut rng, &d.device, &d.unlocked)
                .unwrap(),
        );
    assert!(d_record.has_pending());

    // A revokes D: the set names it once, with its H (the server holds no op from D).
    let revoke = [RevokeDevice {
        device_id: d_id,
        last_accepted_device_seq: 0,
    }];
    let options = RotationOptions {
        level: RotationLevel::Standard,
        revoke: &revoke,
        recovery_code: Some(&code),
        now_ms: T0 + 10_000,
    };
    // A device named twice, or this device itself, is refused.
    for wrong in [
        vec![revoke[0], revoke[0]],
        vec![RevokeDevice {
            device_id: a_state.device_id(),
            last_accepted_device_seq: 0,
        }],
    ] {
        let login = reauth(&mut server, &mut rng, &sk);
        let options = RotationOptions {
            revoke: &wrong,
            ..options
        };
        assert_eq!(
            start_rotation(&mut rng, login, &a_state, &a_unlocked, &[&vault], &options)
                .unwrap_err(),
            ClientError::InvalidInput
        );
    }
    let login = reauth(&mut server, &mut rng, &sk);
    let pending =
        start_rotation(&mut rng, login, &a_state, &a_unlocked, &[&vault], &options).unwrap();
    let request = pending.commit_request().clone();
    assert_eq!(request.device_revocations.len(), 1);
    // The grants go to the remaining devices only: B, not D.
    assert_eq!(request.device_grants.len(), 1);
    assert_eq!(
        request.device_grants.as_slice()[0].recipient_device_id.to_bytes(),
        b.device.device_id().to_bytes()
    );
    server.commit_rotation(&request).unwrap();
    pending
        .finalize(&mut rng, &mut a_state, &mut a_unlocked, &mut [&mut vault])
        .unwrap();
    assert_eq!(a_unlocked.account_key.epoch(), 1);

    // §5: a malicious server pairs the revocation of D with a grant from D. The grant itself is
    // well formed (it opens under D's certificate), but its sender is revoked by the very state
    // whose key it delivers.
    let view = server.view();
    // B unlocks with its password, as the follower of a rotation does (§11.3 step 4).
    let mut b_unlocked = b.device.unlock(PASSWORD).unwrap();
    // D enrolled last, so its verified account holds both certificates.
    let b_cert = d
        .account
        .certificates()
        .iter()
        .find(|c| c.certificate.device_id == b.device.device_id())
        .unwrap()
        .certificate
        .clone();
    let d_cert = d
        .account
        .certificates()
        .iter()
        .find(|c| c.certificate.device_id == d_id)
        .unwrap()
        .certificate
        .clone();
    let ctx = AccountKeyDeviceGrantCtx {
        account_id: a_state.account_id(),
        account_key_epoch: 1,
        sender_device_id: d_id,
        recipient_device_id: b.device.device_id(),
    };
    let forged = seal_account_key_device_grant(
        &mut rng,
        &ctx,
        &a_unlocked.account_key,
        &b_unlocked.account_key,
        &b_cert,
        GrantSigner::Device(d.unlocked.device_keys.signing_key()),
    )
    .unwrap();
    assert!(
        open_account_key_device_grant(
            &forged,
            &ctx,
            &b_unlocked.device_keys,
            &b_unlocked.account_key,
            GrantSender::Device(&d_cert),
        )
        .is_ok()
    );
    let forged = DeviceGrantsResponse {
        grants: List::new(vec![DeviceGrant {
            account_key_epoch: 1,
            sender_device_id: Id::from_bytes(d_id.to_bytes()),
            recipient_device_id: Id::from_bytes(b.device.device_id().to_bytes()),
            key_grant: bytes(&forged),
        }])
        .unwrap(),
    };
    assert_eq!(
        verify_unlock(&mut b.device, &b_unlocked, &view, None).unwrap_err(),
        ClientError::AccountKeyRotated
    );
    assert_eq!(
        apply_device_grants(
            &mut rng,
            &mut b.device,
            &mut b_unlocked,
            &view,
            &forged,
            None
        )
        .unwrap_err(),
        ClientError::InvalidServerResponse
    );
    // B stays read-only with the old key; nothing was adopted.
    assert_eq!(b_unlocked.account_key.epoch(), 0);
    assert_eq!(b.device.unlock(PASSWORD).unwrap().account_key.epoch(), 0);
    // The honest grant, from A, opens.
    let honest = grants_for(&server, b.device.device_id());
    apply_device_grants(
        &mut rng,
        &mut b.device,
        &mut b_unlocked,
        &view,
        &honest,
        None,
    )
    .unwrap();
    assert_eq!(b_unlocked.account_key.epoch(), 1);

    // §3: D learns of its own revocation from a verified view, and deletes its pending record
    // without resending it.
    assert!(own_revocation(&d.device, &view, None).unwrap());
    let d_record = d_record.without_pending();
    assert!(!d_record.has_pending());
    // Nothing of D's reached the server: the state is A's revocation commit.
    assert_eq!(
        server.stored().state.as_slice(),
        request.account_state.as_slice()
    );
    // B is not revoked.
    assert!(!own_revocation(&b.device, &view, None).unwrap());
}

#[test]
fn the_revocation_pending_retry_is_bounded() {
    let d = DeviceId::from_bytes([7; 16]);
    let now = T0;
    // The first retry after 15 s, whatever the window says.
    assert_eq!(
        next_revocation_retry(0, now, Some((d, now))),
        Some(now + REVOCATION_RETRY_MS)
    );
    // Then every 15 s until `expires_at_ms + 5 s`.
    let expires = now + 600_000;
    assert_eq!(
        next_revocation_retry(3, expires - 10_000, Some((d, expires))),
        Some(expires + 5_000)
    );
    assert_eq!(
        next_revocation_retry(3, expires - 9_999, Some((d, expires))),
        None
    );
    // No window in the fresh state: retry, bounded by the count.
    assert_eq!(
        next_revocation_retry(40, now, None),
        Some(now + REVOCATION_RETRY_MS)
    );
    assert_eq!(next_revocation_retry(MAX_REVOCATION_RETRIES, now, None), None);
    // 41 tries span the 10-minute window and its grace.
    assert!(u64::from(MAX_REVOCATION_RETRIES) * REVOCATION_RETRY_MS >= 605_000);
    // The renewing suspend must return the same H.
    assert_eq!(check_renewed_head(4, 4), Ok(()));
    assert_eq!(
        check_renewed_head(4, 5),
        Err(ClientError::InvalidServerResponse)
    );
}

#[test]
fn the_revocation_notice_is_read_as_served() {
    let mut rng = ChaCha20Rng::seed_from_u64(93);
    let mut server = Server::new(94);
    let _signed_up = signup_with_code(&mut server, &mut rng);
    let mut view = server.view();
    assert_eq!(RevocationNotice::of_view(&view), RevocationNotice::default());
    assert!(!RevocationNotice::of_view(&view).removal_in_progress());
    view.suspended_devices = List::new(vec![Id::from_bytes([1; 16])]).unwrap();
    view.revocation_window = Some(RevocationWindowNotice {
        revoker_device_id: Id::from_bytes([2; 16]),
        expires_at_ms: T0,
    });
    let notice = RevocationNotice::of_view(&view);
    assert_eq!(notice.suspended, vec![DeviceId::from_bytes([1; 16])]);
    assert_eq!(notice.window, Some((DeviceId::from_bytes([2; 16]), T0)));
    assert!(notice.removal_in_progress());
}
