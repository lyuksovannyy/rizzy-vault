//! The browser extension's durable device, kind 2 (ADR 0036 §1), against the fake server of
//! the parent module: this is the "wasm-free" convergence test the M2 durable-device task asks
//! for, proving the split `crates/rizzy-wasm/src/device.rs` documents is correct before any
//! wasm binding or TypeScript exists. Every step below is exactly what
//! `rizzy-wasm::device::EnrolFlow`/`DeviceSession` call, with no network and no wasm: enrol,
//! persist the cache rows a host would write, reopen them as a fresh browser session would
//! (`DeviceRecord` → offline unlock → `store::load::load`, ADR 0026 §4 step 5), authenticate
//! (§5.10), sign a request and run one Fetch.

use super::*;
use crate::store;
use crate::store::load;
use crate::store::record::Stage;
use crate::store::rows::CacheRows;

/// Enrolment persists a cache a fresh session can reopen, unlock, authenticate and sync from,
/// for `device_kind` `Extension` (2) — the kind `rv`'s own tests never exercise, since `rv` is
/// always `DesktopCli`. Also covers a write and a reopen after it (module docs).
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one end-to-end story: enrol, persist, reopen, authenticate, sync, write, upload, and a third reopen that reads the write back, in order (as signup_login_enrol_unlock_and_sync)"
)]
fn extension_device_enrols_persists_cache_reloads_and_syncs() {
    let mut rng = ChaCha20Rng::seed_from_u64(99);
    let mut server = Server::new(100);
    let owner = signup(&mut server, &mut rng, DeviceKind::DesktopCli);
    let sk = secret_key_text(owner.device.as_ref().unwrap());

    // Enrols a second device, kind `Extension`, exactly as `LoggedIn::enrol` and
    // `EnrolDeviceRequest` already work for every other kind (module docs: nothing here is
    // kind-specific in `rizzy-client`).
    let input = LoginInput {
        server_origin: ORIGIN,
        login_name: "alice",
        secret_key: &sk,
        password: PASSWORD,
    };
    let (started, request) = start_login(&mut rng, &input).unwrap();
    let answer = server.login_start(&request);
    let (awaiting, finish) = started.finish(&mut rng, &answer, None).unwrap();
    let response = server.login_finish(&finish).unwrap();
    let logged_in = awaiting.complete(response).unwrap();
    let (pending, enrol) = logged_in
        .enrol(&mut rng, DeviceKind::Extension, T0 + 1000)
        .unwrap();
    server.enrol(&enrol);
    let enrolled = pending.finalize();
    assert_eq!(
        enrolled.own_certificate.certificate.device_kind,
        DeviceKind::Extension
    );

    // The cache rows a host (the extension's IndexedDB adapter, through
    // `rizzy-wasm::store::encode_rows`) would persist before using the session at all (ADR
    // 0026 §4 step 1, "secrets before commit").
    let record = enrolled.device.record(Stage::Committed).unwrap();
    let mut changeset = store::create_writes(&record).unwrap();
    changeset.append(store::account_writes(&enrolled.account));
    let mut rows = CacheRows::default();
    rows.apply(&changeset);

    // A fresh browser session: nothing above is kept, only `rows` (as if just read back from
    // IndexedDB). The offline unlock first (CRYPTO.md §11.3 step 1), then the local verify of
    // every account object the cache holds, no network (ADR 0026 §4 step 5).
    let reopened_record = load::open(&rows).unwrap();
    assert_eq!(
        reopened_record.unlock("wrong password").unwrap_err(),
        ClientError::WrongPasswordOrSecretKey
    );
    let reopened_unlocked = reopened_record.unlock(PASSWORD).unwrap();
    let loaded = load::load(&rows, &reopened_record, &reopened_unlocked, T0 + 2000).unwrap();
    assert_eq!(loaded.device.device_id(), enrolled.unlocked.device_id());
    assert_eq!(loaded.account.state().state_seq, 2);

    // Device authentication (§5.10): the reopened state authenticates exactly as any other
    // durable device does.
    let mut session = device_session(&mut server, &loaded.device, &reopened_unlocked);
    let signature = session
        .sign_request(&reopened_unlocked, "POST", "/api/v1/vault/upload", b"{}")
        .unwrap();
    assert_eq!(signature.request_counter, 1);

    // Sync: one Fetch against the reopened, authenticated device finds nothing new (the owner
    // created no item), proving the reopened state is usable, not just loadable. `load::load`
    // already built this vault's driver from the cache's `vaults`/`wraps` rows (`Loaded.vaults`
    // module docs): a reopened session never calls `take_vault_key`/`VaultSync::new` itself.
    let authors = loaded.authors;
    let mut vault = loaded.vaults.into_iter().next().unwrap();
    let mut floors = loaded.floors;
    let fetch_request = vault.fetch_request().unwrap();
    let fetch_response = server.fetch(&fetch_request);
    let outcome = vault
        .apply_fetch(&authors, &fetch_response, T0 + 3000)
        .unwrap();
    assert_eq!(outcome.applied, 0);

    // The full M2 cycle `crates/rizzy-wasm/src/device.rs`'s module docs describe
    // (`DeviceSession`'s "Sync and items"): this reopened device writes an item, the write is
    // journaled (the cache is on, straight from `load::load`), uploaded, and the journaled rows
    // admit against the floors `load::load` built — exactly what
    // `DeviceSession::drain_cache_writes` does, without any wasm binding in the way. A *third*
    // reopen of the cache this produces then reads the item back, proving the extension's
    // write path, not only its read path, survives a lock and reopen.
    let name_key = SchemaKey::parse(rizzy_core::item::schema::ITEM_NAME.as_bytes()).unwrap();
    let user_key = SchemaKey::parse(LOGIN_USERNAME.as_bytes()).unwrap();
    let name = Value::text("Extension item").unwrap();
    let username = Value::text("extension-user").unwrap();
    let item = vault
        .create_item(
            &mut rng,
            &reopened_unlocked,
            ItemType::LOGIN,
            &[
                FieldEdit {
                    key: &name_key,
                    value: &name,
                },
                FieldEdit {
                    key: &user_key,
                    value: &username,
                },
            ],
            T0 + 3500,
        )
        .unwrap();

    // Drains and admits the write's own rows (ADR 0026 §4 step 1), as a host would before
    // using the session for anything else.
    let own_changeset = vault.take_writes();
    assert!(!own_changeset.is_empty());
    floors.admit(&own_changeset).unwrap();
    rows.apply(&own_changeset);

    // Uploads the op, drains and admits the upload's own rows (ADR 0026 §4 step 2).
    let upload = vault
        .upload_request(&mut rng, &reopened_unlocked)
        .unwrap()
        .unwrap();
    let answer = server.upload(&upload);
    let outcome = vault.apply_upload_response(&answer).unwrap();
    assert_eq!(outcome.acknowledged, 1);
    let upload_changeset = vault.take_writes();
    assert!(!upload_changeset.is_empty());
    floors.admit(&upload_changeset).unwrap();
    rows.apply(&upload_changeset);

    // A third reopen, from the rows this cycle persisted, with nothing of `vault`/`floors`
    // carried over: the item this device wrote is there, through the same offline unlock and
    // local verify every reopen runs.
    let third_record = load::open(&rows).unwrap();
    let third_unlocked = third_record.unlock(PASSWORD).unwrap();
    let third_loaded = load::load(&rows, &third_record, &third_unlocked, T0 + 4000).unwrap();
    let mut third_vault = third_loaded.vaults.into_iter().next().unwrap();
    assert_eq!(third_vault.item_ids(), vec![item]);
    assert_eq!(third_vault.item_type(item), Some(ItemType::LOGIN));
    let shown = third_vault.field_value(item, LOGIN_USERNAME).unwrap();
    assert!(matches!(
        ValueRef::decode(shown.expose_secret()).unwrap(),
        ValueRef::Text("extension-user")
    ));
    // Nothing new to sync: the upload above already acknowledged this device's only op.
    let fetch_request = third_vault.fetch_request().unwrap();
    let fetch_response = server.fetch(&fetch_request);
    let outcome = third_vault
        .apply_fetch(&third_loaded.authors, &fetch_response, T0 + 4500)
        .unwrap();
    assert_eq!(outcome.applied, 0);
}
