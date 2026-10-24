// SPDX-License-Identifier: AGPL-3.0-only

//! Several vaults per account over HTTP (ADR 0081 Part A, §A3, §A5, §A9, §A11), driven by
//! `rizzy-client`: a `vault_create` commit over a device session, the account answer's
//! per-vault summaries, the delete's fresh-session rule (`403 fresh_session_required` over a
//! device session), the Personal vault refused (`400 invalid_request`, INV-101), and the quota
//! released by the delete.

use axum::http::StatusCode;
use chacha20::ChaCha20Rng;
use chacha20::rand_core::SeedableRng as _;
use rizzy_client::sync::VaultSync;
use rizzy_client::vaults::{VaultCatalog, create_vault, delete_vault};

use crate::common::{Server, block_on};
use crate::rotation::{Auth, Client, login, post, post_empty, signup};

const COMMIT: &str = "/api/v1/account/commit";

/// The account answer's vaults as `(id hex, kind, bytes_used)`, and its total `bytes_used`.
fn summaries(view: &serde_json::Value) -> (Vec<(String, u64, u64)>, u64) {
    let vaults = view["vaults"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            (
                v["vault_id"].as_str().unwrap().to_owned(),
                v["kind"].as_u64().unwrap(),
                v["bytes_used"].as_u64().unwrap(),
            )
        })
        .collect();
    (vaults, view["bytes_used"].as_u64().unwrap())
}

#[test]
fn a_vault_is_created_summarised_and_deleted_over_http() {
    block_on(async {
        let server = Server::start().await;
        let mut rng = ChaCha20Rng::seed_from_u64(0x81);
        let (up, sk, _) = signup(&server, &mut rng, false).await;
        let mut client = Client::signed_up(&server, up).await;
        let account = client.refresh(&server).await;
        let (vaults, _) = summaries(&client.account_view(&server).await);
        assert_eq!(vaults.len(), 1);
        assert_eq!(vaults[0].1, 1, "signup's vault is the Personal vault");
        let personal = VaultCatalog::of_account(&account, &client.unlocked)
            .unwrap()
            .personal()
            .unwrap();

        // §A3: created over the device session, with its settings.
        let pending = create_vault(&mut rng, &account, &client.unlocked).unwrap();
        let owned = pending.vault_id();
        post_empty(
            &server,
            COMMIT,
            pending.commit_request(),
            Auth::Device(&mut client.session, &client.unlocked),
        )
        .await;
        let mut account = client.refresh(&server).await;
        let catalog = VaultCatalog::of_account(&account, &client.unlocked).unwrap();
        assert!(catalog.alarms().is_empty(), "{:?}", catalog.alarms());
        assert!(catalog.is_open(owned) && catalog.is_open(personal));
        let (vaults, _) = summaries(&client.account_view(&server).await);
        assert_eq!(vaults.len(), 2);
        assert!(vaults.iter().any(|v| v.1 == 2));

        // An item in the new vault: its bytes are counted against it.
        let key = account.take_vault_key(owned).unwrap();
        let personal_vault = std::mem::replace(
            &mut client.vault,
            VaultSync::new(key, &client.unlocked, 100).unwrap(),
        );
        let _ = client.sync(&server, &mut rng).await;
        client.create(&mut rng, "in the owned vault");
        assert!(client.sync(&server, &mut rng).await.is_empty());
        let (vaults, total_before) = summaries(&client.account_view(&server).await);
        let owned_bytes = vaults.iter().find(|v| v.1 == 2).unwrap().2;
        assert!(owned_bytes > 0);
        client.vault = personal_vault;

        // §A5: a device session cannot delete; a fresh OPAQUE session can.
        let account = client.refresh(&server).await;
        let pending = delete_vault(&mut rng, &account, &client.unlocked, owned).unwrap();
        let reply = post(
            &server,
            COMMIT,
            pending.commit_request(),
            Auth::Device(&mut client.session, &client.unlocked),
        )
        .await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
        assert_eq!(reply.error(), "fresh_session_required");
        let reauth = login(
            &server,
            &mut rng,
            &sk,
            Some((&mut client.session, &client.unlocked)),
        )
        .await;
        let token = crate::rotation::copy_token(reauth.bearer_token());
        // INV-101: the Personal vault is refused by the server too.
        let mut forged = pending.commit_request().clone();
        forged.vault_delete = Some(rizzy_client::rizzy_proto::wire::Id::from_bytes(
            personal.to_bytes(),
        ));
        let reply = post(&server, COMMIT, &forged, Auth::Bearer(&token)).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        assert_eq!(reply.error(), "invalid_request");
        post_empty(
            &server,
            COMMIT,
            pending.commit_request(),
            Auth::Bearer(&token),
        )
        .await;
        let account = client.refresh(&server).await;
        let catalog = VaultCatalog::of_account(&account, &client.unlocked).unwrap();
        assert!(catalog.alarms().is_empty());
        assert!(!catalog.is_open(owned));
        let (vaults, total_after) = summaries(&client.account_view(&server).await);
        assert_eq!(vaults.len(), 1);
        assert_eq!(
            total_after,
            total_before - owned_bytes,
            "the delete releases its bytes"
        );
    });
}
