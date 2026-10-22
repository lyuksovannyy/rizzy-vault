// SPDX-License-Identifier: AGPL-3.0-only

//! Encrypted attachments over HTTP (ADR 0054 §2, §6, §7): a real client seals a file with
//! `rizzy-client`, sends the five `/api/v1/attachments/*` requests through the router as a
//! device, and a second device of the account — which never saw the upload — fetches the item,
//! reads the wrap through `attachments/get` and downloads a byte-identical file. Also: retries
//! and conflicts, the exact-length and index checks, another account's id answered
//! `not_found`, the 25 MiB cap and the ADR 0048 quota answered `quota_exceeded`, the counter
//! charged at create and released at delete, and every request under the 1 MiB body limit.

use axum::http::StatusCode;
use chacha20::ChaCha20Rng;
use chacha20::rand_core::SeedableRng as _;
use rizzy_client::attachments::{AttachmentUpload, delete_request};
use rizzy_client::rizzy_core::attachment::{CHUNK_SIZE, MAX_ATTACHMENT_LEN};
use rizzy_client::rizzy_proto::attachments::{
    AttachmentRequest, CreateAttachmentRequest, DownloadChunkRequest, DownloadChunkResponse,
    GetAttachmentResponse,
};
use rizzy_client::rizzy_proto::limits::MAX_BODY_LEN;
use rizzy_server::config;
use rizzy_storage::lock_account;

use crate::common::{Server, block_on};
use crate::rotation::{Auth, Client, enrol, now_ms, post, post_empty, signup, signup_named};

const CREATE: &str = "/api/v1/attachments/create";
const GET: &str = "/api/v1/attachments/get";
const UPLOAD: &str = "/api/v1/attachments/upload-chunk";
const DOWNLOAD: &str = "/api/v1/attachments/download-chunk";
const DELETE: &str = "/api/v1/attachments/delete";

/// `len` bytes, byte `i` = `i mod 251`.
fn file(len: usize) -> Vec<u8> {
    (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect()
}

/// The counted bytes of an attachment of `size` bytes: its wrap and every chunk envelope.
fn counted(size: u64) -> u64 {
    122 + size + 90 * size.div_ceil(CHUNK_SIZE as u64)
}

/// Sends the declaration and every chunk of `upload` as `client`.
async fn send(server: &Server, client: &mut Client, upload: &AttachmentUpload) {
    let create = upload.create_request();
    post_empty(
        server,
        CREATE,
        &create,
        Auth::Device(&mut client.session, &client.unlocked),
    )
    .await;
    for i in 0..upload.chunk_count() {
        let request = upload.chunk_request(i).unwrap();
        assert!(serde_json::to_vec(&request).unwrap().len() < MAX_BODY_LEN);
        post_empty(
            server,
            UPLOAD,
            &request,
            Auth::Device(&mut client.session, &client.unlocked),
        )
        .await;
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one end-to-end story: upload, retries, a second device's download, delete"
)]
fn a_second_device_downloads_the_same_bytes_and_delete_releases_the_quota() {
    block_on(async {
        let server = Server::start().await;
        let mut rng = ChaCha20Rng::seed_from_u64(0x54);
        let (up, sk, _) = signup(&server, &mut rng, false).await;
        let mut a = Client::signed_up(&server, up).await;
        let item = a.create(&mut rng, "login");
        assert!(a.sync(&server, &mut rng).await.is_empty());
        let before = a.account_view(&server).await["bytes_used"]
            .as_u64()
            .unwrap();

        let data = file(2 * CHUNK_SIZE + 4321);
        let upload = a
            .vault
            .add_attachment(
                &mut rng,
                &a.unlocked,
                item,
                "scan.png",
                "image/png",
                &data,
                now_ms(),
            )
            .unwrap();
        let id = upload.attachment_id();
        send(&server, &mut a, &upload).await;
        // Retries are no-ops; another envelope at a stored index conflicts.
        post_empty(
            &server,
            CREATE,
            &upload.create_request(),
            Auth::Device(&mut a.session, &a.unlocked),
        )
        .await;
        let first = upload.chunk_request(0).unwrap();
        post_empty(
            &server,
            UPLOAD,
            &first,
            Auth::Device(&mut a.session, &a.unlocked),
        )
        .await;
        let mut changed = first.clone();
        let mut bytes = changed.envelope.as_slice().to_vec();
        bytes[200] ^= 1;
        changed.envelope = rizzy_client::rizzy_proto::wire::Bytes::new(bytes).unwrap();
        let reply = post(
            &server,
            UPLOAD,
            &changed,
            Auth::Device(&mut a.session, &a.unlocked),
        )
        .await;
        assert_eq!(reply.error(), "record_conflict");
        // The item op goes up after the chunks here; either order leaves the server consistent.
        assert!(a.sync(&server, &mut rng).await.is_empty());
        let after = a.account_view(&server).await["bytes_used"]
            .as_u64()
            .unwrap();
        assert!(after >= before + counted(u64::try_from(data.len()).unwrap()));

        // A second device: it learns the attachment from the item, the wrap from the server.
        let mut b = Client::enrolled(&server, enrol(&server, &mut rng, &sk).await).await;
        assert!(b.sync(&server, &mut rng).await.is_empty());
        let listed = b.vault.attachments(item);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name.as_str(), "scan.png");
        let mut download = b.vault.begin_download(item, id).unwrap();
        let reply = post(
            &server,
            GET,
            &download.get_request(),
            Auth::Device(&mut b.session, &b.unlocked),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK);
        let answer: GetAttachmentResponse = reply.json();
        b.vault
            .accept_attachment_key(&mut download, &answer)
            .unwrap();
        for i in 0..download.chunk_count() {
            let request = download.chunk_request(i).unwrap();
            let reply = post(
                &server,
                DOWNLOAD,
                &request,
                Auth::Device(&mut b.session, &b.unlocked),
            )
            .await;
            assert!(reply.body.len() < MAX_BODY_LEN);
            let answer: DownloadChunkResponse = reply.json();
            download.accept_response(i, &answer).unwrap();
        }
        assert_eq!(download.finish().unwrap().as_slice(), data.as_slice());

        // Delete: the blob goes, the quota is released, and a repeat is not_found.
        let held = a.account_view(&server).await["bytes_used"]
            .as_u64()
            .unwrap();
        post_empty(
            &server,
            DELETE,
            &delete_request(id),
            Auth::Device(&mut b.session, &b.unlocked),
        )
        .await;
        let released = a.account_view(&server).await["bytes_used"]
            .as_u64()
            .unwrap();
        assert_eq!(released + counted(u64::try_from(data.len()).unwrap()), held);
        b.vault
            .remove_attachment(&mut rng, &b.unlocked, item, id, now_ms())
            .unwrap();
        assert!(b.sync(&server, &mut rng).await.is_empty());
        assert!(b.vault.attachments(item).is_empty());
        let reply = post(
            &server,
            DELETE,
            &delete_request(id),
            Auth::Device(&mut b.session, &b.unlocked),
        )
        .await;
        assert_eq!(reply.error(), "not_found");
        let gone = DownloadChunkRequest {
            attachment_id: delete_request(id).attachment_id,
            chunk_index: 0,
        };
        let reply = post(
            &server,
            DOWNLOAD,
            &gone,
            Auth::Device(&mut b.session, &b.unlocked),
        )
        .await;
        assert_eq!(reply.error(), "not_found");
        // The first device learns of the second (its certificate), then sees the removal.
        a.refresh(&server).await;
        assert!(a.sync(&server, &mut rng).await.is_empty());
        assert!(a.vault.attachments(item).is_empty());
    });
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one story per refusal over one declared attachment reads best in one test"
)]
fn lengths_indices_ownership_and_the_cap_are_enforced() {
    block_on(async {
        let server = Server::start().await;
        let mut rng = ChaCha20Rng::seed_from_u64(0x55);
        let (up, _, _) = signup(&server, &mut rng, false).await;
        let mut a = Client::signed_up(&server, up).await;
        let item = a.create(&mut rng, "x");
        assert!(a.sync(&server, &mut rng).await.is_empty());
        let data = file(1000);
        let upload = a
            .vault
            .add_attachment(
                &mut rng,
                &a.unlocked,
                item,
                "a.txt",
                "text/plain",
                &data,
                now_ms(),
            )
            .unwrap();
        let create = upload.create_request();
        post_empty(
            &server,
            CREATE,
            &create,
            Auth::Device(&mut a.session, &a.unlocked),
        )
        .await;

        // A chunk of the wrong length, and one past the count.
        let mut chunk = upload.chunk_request(0).unwrap();
        let mut short = chunk.envelope.as_slice().to_vec();
        short.pop();
        let original = core::mem::replace(
            &mut chunk.envelope,
            rizzy_client::rizzy_proto::wire::Bytes::new(short).unwrap(),
        );
        let reply = post(
            &server,
            UPLOAD,
            &chunk,
            Auth::Device(&mut a.session, &a.unlocked),
        )
        .await;
        assert_eq!(reply.error(), "invalid_request");
        chunk.envelope = original;
        chunk.chunk_index = 1;
        let reply = post(
            &server,
            UPLOAD,
            &chunk,
            Auth::Device(&mut a.session, &a.unlocked),
        )
        .await;
        assert_eq!(reply.error(), "not_found");

        // Over the cap: quota_exceeded, before anything is stored.
        let mut big = create.clone();
        big.attachment_id = rizzy_client::rizzy_proto::wire::Id::from_bytes([9; 16]);
        big.total_plaintext_len = MAX_ATTACHMENT_LEN + 1;
        let reply = post(
            &server,
            CREATE,
            &big,
            Auth::Device(&mut a.session, &a.unlocked),
        )
        .await;
        assert_eq!(reply.error(), "quota_exceeded");

        // Another account sees nothing of it.
        let (up, _, _) = signup_named(&server, &mut rng, "bob@example.com", false).await;
        let mut bob = Client::signed_up(&server, up).await;
        let id = AttachmentRequest {
            attachment_id: create.attachment_id,
        };
        for path in [GET, DELETE] {
            let reply = post(
                &server,
                path,
                &id,
                Auth::Device(&mut bob.session, &bob.unlocked),
            )
            .await;
            assert_eq!(reply.error(), "not_found", "{path}");
        }
        let fetch = DownloadChunkRequest {
            attachment_id: create.attachment_id,
            chunk_index: 0,
        };
        let reply = post(
            &server,
            DOWNLOAD,
            &fetch,
            Auth::Device(&mut bob.session, &bob.unlocked),
        )
        .await;
        assert_eq!(reply.error(), "not_found");
        chunk.chunk_index = 0;
        let reply = post(
            &server,
            UPLOAD,
            &chunk,
            Auth::Device(&mut bob.session, &bob.unlocked),
        )
        .await;
        assert_eq!(reply.error(), "not_found");
        // Nor can it declare an attachment in this account's vault.
        let reply = post(
            &server,
            CREATE,
            &CreateAttachmentRequest {
                attachment_id: rizzy_client::rizzy_proto::wire::Id::from_bytes([8; 16]),
                ..create.clone()
            },
            Auth::Device(&mut bob.session, &bob.unlocked),
        )
        .await;
        assert_eq!(reply.error(), "not_found");

        // The owner still uploads and reads it.
        post_empty(
            &server,
            UPLOAD,
            &chunk,
            Auth::Device(&mut a.session, &a.unlocked),
        )
        .await;
        let reply = post(
            &server,
            DOWNLOAD,
            &fetch,
            Auth::Device(&mut a.session, &a.unlocked),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK);
    });
}

#[test]
fn create_is_refused_past_the_account_quota() {
    block_on(async {
        let quota: u64 = 256 << 20;
        let quota_text = quota.to_string();
        let server =
            Server::start_with(&[(config::ACCOUNT_QUOTA_BYTES, quota_text.as_str())]).await;
        let db = server.services.db.clone();
        let mut rng = ChaCha20Rng::seed_from_u64(0x56);
        let (up, _, _) = signup(&server, &mut rng, false).await;
        let mut a = Client::signed_up(&server, up).await;
        let account = a.state.account_id().to_bytes();
        let item = a.create(&mut rng, "x");
        assert!(a.sync(&server, &mut rng).await.is_empty());
        let size: u64 = 3000;
        // Leave exactly one attachment's counted bytes of room.
        let mut w = db.begin_write().await.unwrap();
        lock_account(&mut w, &account).await.unwrap();
        rizzy_storage::quota::reconcile(&mut w, &account, quota - counted(size), true, 1)
            .await
            .unwrap();
        w.commit().await.unwrap();

        let data = file(usize::try_from(size).unwrap());
        let fits = a
            .vault
            .add_attachment(
                &mut rng,
                &a.unlocked,
                item,
                "a",
                "text/plain",
                &data,
                now_ms(),
            )
            .unwrap();
        post_empty(
            &server,
            CREATE,
            &fits.create_request(),
            Auth::Device(&mut a.session, &a.unlocked),
        )
        .await;
        let over = a
            .vault
            .add_attachment(
                &mut rng,
                &a.unlocked,
                item,
                "b",
                "text/plain",
                &data[..1],
                now_ms(),
            )
            .unwrap();
        let reply = post(
            &server,
            CREATE,
            &over.create_request(),
            Auth::Device(&mut a.session, &a.unlocked),
        )
        .await;
        assert_eq!(reply.error(), "quota_exceeded");
        assert_eq!(
            a.account_view(&server).await["bytes_used"]
                .as_u64()
                .unwrap(),
            quota
        );
    });
}
