// SPDX-License-Identifier: AGPL-3.0-only

//! The auth side of a rotation stage request (ADR 0092 §4 "Opening", step 1): the session is
//! authorised as the rotation commit it prepares (a fresh OPAQUE session; never a device
//! session or a stale OPAQUE one), and `base_state_seq` must be the stored `state_seq`
//! (`state_conflict`). The vault-side checks are the vault domain's (`tests/vault/rotation.rs`);
//! the fake vault port here answers the request's row count.

use rizzy_domain_auth::AuthError;
use rizzy_domain_auth::config::FRESH_SESSION_MS;
use rizzy_proto::change::{StageRequest, WrapLocator};
use rizzy_proto::wire::{Id, List};

use crate::common::{Env, block_on};

/// A stage request on `base_state_seq` with one dropped row.
fn request(base_state_seq: u64) -> StageRequest {
    StageRequest {
        rotation_id: Id::from_bytes([0x51; 16]),
        base_state_seq,
        account_key_id: Id::from_bytes([0x52; 16]),
        vault_id: Id::from_bytes([0x53; 16]),
        vault_key_epoch: 1,
        item_key_wraps: List::new(Vec::new()).unwrap(),
        dropped: List::new(vec![WrapLocator {
            item_id: Id::from_bytes([0x54; 16]),
            item_key_id: Id::from_bytes([0x55; 16]),
        }])
        .unwrap(),
    }
}

#[test]
fn staging_is_authorised_as_the_rotation_commit() {
    block_on(async {
        let mut env = Env::new(92).await;
        let client = env.signup("stella", "pw").await;
        let seq = client.state.state_seq;
        // A device session may not stage (it may not rotate either).
        let mut ds = env.device_auth(&client, &client.devices[0]).await.unwrap();
        let device = env
            .signed(&client, &client.devices[0], &mut ds, b"")
            .await
            .unwrap();
        assert!(matches!(
            env.svc
                .stage_rotation(&device, &request(seq), env.now)
                .await,
            Err(AuthError::FreshSessionRequired)
        ));
        // A stale OPAQUE session may not either.
        let stale = env.login(&client).await;
        let stale = env.bearer(&stale.response.session_token).await;
        env.tick(FRESH_SESSION_MS + 1);
        assert!(matches!(
            env.svc.stage_rotation(&stale, &request(seq), env.now).await,
            Err(AuthError::FreshSessionRequired)
        ));
        // A fresh OPAQUE session: `base_state_seq` must be the stored one.
        let login = env.login(&client).await;
        let fresh = env.bearer(&login.response.session_token).await;
        assert!(matches!(
            env.svc
                .stage_rotation(&fresh, &request(seq + 1), env.now)
                .await,
            Err(AuthError::StateConflict)
        ));
        let answer = env
            .svc
            .stage_rotation(&fresh, &request(seq), env.now)
            .await
            .unwrap();
        assert_eq!(answer.staged_rows, 1);
    });
}
