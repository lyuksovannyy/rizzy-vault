//! Surfacing tests for an edit that arrives after a trash or a purge (ADR 0012 §5 "Active
//! wins"; ADR 0018 §3 "Surfacing"): `VaultSync::concurrent_trash_device`,
//! `VaultSync::late_edit_devices`, `VaultSync::mark_late_edits_surfaced` and
//! `VaultSync::restore_late_as_new_item`.

use rizzy_core::item::schema::LOGIN_USERNAME;

use super::*;

/// Like [`login_and_enrol`], but without its "exactly one certificate so far" assertion: these
/// tests enrol a third and fourth device on one account.
fn enrol_another_device(
    server: &mut Server,
    rng: &mut ChaCha20Rng,
    sk: &str,
) -> crate::login::Enrolled {
    let input = LoginInput {
        server_origin: ORIGIN,
        login_name: "alice",
        secret_key: sk,
        password: PASSWORD,
    };
    let (started, request) = start_login(rng, &input).unwrap();
    let answer = server.login_start(&request);
    let (awaiting, finish) = started.finish(rng, &answer, None).unwrap();
    let response = server.login_finish(&finish).unwrap();
    let logged_in = awaiting.complete(response).unwrap();
    let (pending, enrol) = logged_in
        .enrol(rng, DeviceKind::DesktopCli, T0 + 1000)
        .unwrap();
    server.enrol(&enrol);
    pending.finalize()
}

/// Edits `key` to `text` on `item`.
fn edit(
    vault: &mut VaultSync,
    rng: &mut ChaCha20Rng,
    unlocked: &UnlockedDevice,
    item: ItemId,
    key: &str,
    text: &str,
    now_ms: u64,
) {
    let field_key = SchemaKey::parse(key.as_bytes()).unwrap();
    let value = Value::text(text).unwrap();
    vault
        .edit_item(
            rng,
            unlocked,
            item,
            &[FieldEdit {
                key: &field_key,
                value: &value,
            }],
            now_ms,
        )
        .unwrap();
}

/// "Deleted on X while it was being edited on Y": Active wins over a concurrent trash
/// (ADR 0012 §5), and `concurrent_trash_device` names the device that trashed it.
#[test]
fn concurrent_trash_device_names_the_losing_device() {
    let mut rng = ChaCha20Rng::seed_from_u64(400);
    let mut server = Server::new(401);
    let a = signup(&mut server, &mut rng, DeviceKind::DesktopCli);
    let sk = secret_key_text(a.device.as_ref().unwrap());
    let vault_id = a.vault_key.vault_id();
    let authors = server.authors();
    let (mut a_vault, a_unlocked, items) = synced_writer(&mut server, &mut rng, a, &authors, 1);
    let item = items[0];

    let b = login_and_enrol(&mut server, &mut rng, &sk);
    let b_authors = Authors::from_account(&b.account).unwrap();
    let mut b_account = b.account;
    let mut b_vault =
        VaultSync::new(b_account.take_vault_key(vault_id).unwrap(), &b.unlocked, 1).unwrap();
    b_vault
        .apply_fetch(
            &b_authors,
            &server.fetch(&b_vault.fetch_request().unwrap()),
            T0 + 1,
        )
        .unwrap();

    let c = enrol_another_device(&mut server, &mut rng, &sk);
    let c_authors = Authors::from_account(&c.account).unwrap();
    let mut c_account = c.account;
    let mut c_vault =
        VaultSync::new(c_account.take_vault_key(vault_id).unwrap(), &c.unlocked, 1).unwrap();
    c_vault
        .apply_fetch(
            &c_authors,
            &server.fetch(&c_vault.fetch_request().unwrap()),
            T0 + 2,
        )
        .unwrap();

    // A edits (writes Active); B trashes. Neither has seen the other's op yet: concurrent.
    edit(
        &mut a_vault,
        &mut rng,
        &a_unlocked,
        item,
        LOGIN_USERNAME,
        "still-active",
        T0 + 10,
    );
    b_vault
        .trash_item(&mut rng, &b.unlocked, item, T0 + 10)
        .unwrap();
    let a_up = a_vault
        .upload_request(&mut rng, &a_unlocked)
        .unwrap()
        .unwrap();
    server.upload(&a_up);
    let b_up = b_vault
        .upload_request(&mut rng, &b.unlocked)
        .unwrap()
        .unwrap();
    server.upload(&b_up);

    c_vault
        .apply_fetch(
            &c_authors,
            &server.fetch(&c_vault.fetch_request().unwrap()),
            T0 + 20,
        )
        .unwrap();
    assert_eq!(c_vault.item_lifecycle(item), ItemLifecycle::Active);
    assert_eq!(
        c_vault.concurrent_trash_device(item),
        Some(b.unlocked.device_id)
    );

    // No notice when there is nothing concurrent to lose.
    let other_signup = signup(&mut server, &mut rng, DeviceKind::DesktopCli);
    let (other_vault, _other_unlocked, other_items) =
        synced_writer(&mut server, &mut rng, other_signup, &authors, 1);
    assert_eq!(other_vault.concurrent_trash_device(other_items[0]), None);
}

/// "An edit from Laptop arrived for an item you deleted permanently. Restore it as a new
/// item?" (ADR 0018 §3 "Surfacing"): an edit concurrent with a purge is kept as a late value,
/// surfaced once, and can be restored as a new item.
#[test]
fn late_edit_is_surfaced_once_and_can_be_restored() {
    let mut rng = ChaCha20Rng::seed_from_u64(402);
    let mut server = Server::new(403);
    let w = signup(&mut server, &mut rng, DeviceKind::DesktopCli);
    let sk = secret_key_text(w.device.as_ref().unwrap());
    let vault_id = w.vault_key.vault_id();
    let authors = server.authors();
    let (mut writer, w_unlocked, items) = synced_writer(&mut server, &mut rng, w, &authors, 1);
    let item = items[0];

    // A second device fetches the item while it is still active, then goes offline.
    let late = login_and_enrol(&mut server, &mut rng, &sk);
    let late_authors = Authors::from_account(&late.account).unwrap();
    let mut late_account = late.account;
    let mut late_vault = VaultSync::new(
        late_account.take_vault_key(vault_id).unwrap(),
        &late.unlocked,
        1,
    )
    .unwrap();
    late_vault
        .apply_fetch(
            &late_authors,
            &server.fetch(&late_vault.fetch_request().unwrap()),
            T0 + 1,
        )
        .unwrap();

    // The writer trashes and purges the item.
    writer
        .trash_item(&mut rng, &w_unlocked, item, T0 + 10)
        .unwrap();
    writer
        .purge_item(&mut rng, &w_unlocked, item, T0 + 11)
        .unwrap();
    let up = writer
        .upload_request(&mut rng, &w_unlocked)
        .unwrap()
        .unwrap();
    server.upload(&up);

    // The reader learns about the purge.
    let reader = enrol_another_device(&mut server, &mut rng, &sk);
    let reader_authors = Authors::from_account(&reader.account).unwrap();
    let mut reader_account = reader.account;
    let mut reader_vault = VaultSync::new(
        reader_account.take_vault_key(vault_id).unwrap(),
        &reader.unlocked,
        1,
    )
    .unwrap();
    reader_vault
        .apply_fetch(
            &reader_authors,
            &server.fetch(&reader_vault.fetch_request().unwrap()),
            T0 + 12,
        )
        .unwrap();
    assert_eq!(reader_vault.item_lifecycle(item), ItemLifecycle::Purged);
    assert!(reader_vault.late_edit_devices(item).is_empty());

    // The offline device edits the item, unaware it was purged: concurrent with the purge.
    edit(
        &mut late_vault,
        &mut rng,
        &late.unlocked,
        item,
        LOGIN_USERNAME,
        "late-value",
        T0 + 9,
    );
    let late_up = late_vault
        .upload_request(&mut rng, &late.unlocked)
        .unwrap()
        .unwrap();
    server.upload(&late_up);

    // The reader now sees the late edit, surfaced once.
    reader_vault
        .apply_fetch(
            &reader_authors,
            &server.fetch(&reader_vault.fetch_request().unwrap()),
            T0 + 13,
        )
        .unwrap();
    assert_eq!(reader_vault.item_lifecycle(item), ItemLifecycle::Purged);
    assert_eq!(
        reader_vault.late_edit_devices(item),
        vec![late.unlocked.device_id]
    );
    reader_vault.mark_late_edits_surfaced(item);
    assert!(reader_vault.late_edit_devices(item).is_empty());

    // Restoring creates a new item from the late value; the tombstone is unchanged.
    let restored = reader_vault
        .restore_late_as_new_item(&mut rng, &reader.unlocked, item, ItemType::LOGIN, T0 + 14)
        .unwrap();
    assert_ne!(restored, item);
    assert_eq!(reader_vault.item_lifecycle(restored), ItemLifecycle::Active);
    let username = reader_vault.field_value(restored, LOGIN_USERNAME).unwrap();
    assert!(matches!(
        ValueRef::decode(username.expose_secret()).unwrap(),
        ValueRef::Text("late-value")
    ));
    assert_eq!(reader_vault.item_lifecycle(item), ItemLifecycle::Purged);
}
