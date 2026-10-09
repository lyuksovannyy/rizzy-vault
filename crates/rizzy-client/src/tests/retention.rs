//! `VaultSync::auto_purge_due` tests (ADR 0012 §5 "manually, or automatically once an item has
//! been in the trash for the retention period"; ADR 0018 §9 "Trashed at", §11 "No purge over an
//! unapplied record").

use rizzy_core::item::schema::VAULT_NAME;
use rizzy_core::keys::VaultKey;

use super::lists::one_item;
use super::*;

/// A retention period distinct from [`rizzy_sync::merge::TRASH_RETENTION_MS`], so these tests
/// do not depend on the default.
const RETENTION_MS: u64 = 86_400_000;

#[test]
fn not_due_before_retention() {
    let (_server, mut rng, mut vault, unlocked, item) = one_item(200);
    vault
        .trash_item(&mut rng, &unlocked, item, T0 + 1_000)
        .unwrap();
    let due = vault
        .auto_purge_due(
            &mut rng,
            &unlocked,
            T0 + 1_000 + RETENTION_MS - 1,
            RETENTION_MS,
        )
        .unwrap();
    assert!(due.is_empty());
    assert_eq!(vault.item_lifecycle(item), ItemLifecycle::Trashed);
}

#[test]
fn due_exactly_at_retention_purges() {
    let (_server, mut rng, mut vault, unlocked, item) = one_item(201);
    vault
        .trash_item(&mut rng, &unlocked, item, T0 + 1_000)
        .unwrap();
    let due = vault
        .auto_purge_due(&mut rng, &unlocked, T0 + 1_000 + RETENTION_MS, RETENTION_MS)
        .unwrap();
    assert_eq!(due, vec![item]);
    assert_eq!(vault.item_lifecycle(item), ItemLifecycle::Purged);
}

#[test]
fn restored_item_is_never_purged() {
    let (_server, mut rng, mut vault, unlocked, item) = one_item(202);
    vault
        .trash_item(&mut rng, &unlocked, item, T0 + 1_000)
        .unwrap();
    vault
        .restore_item(&mut rng, &unlocked, item, T0 + 1_001)
        .unwrap();
    let due = vault
        .auto_purge_due(
            &mut rng,
            &unlocked,
            T0 + 1_001 + RETENTION_MS * 10,
            RETENTION_MS,
        )
        .unwrap();
    assert!(due.is_empty());
    assert_eq!(vault.item_lifecycle(item), ItemLifecycle::Active);
}

#[test]
fn read_only_vault_purges_nothing() {
    let (_server, mut rng, mut vault, unlocked, item) = one_item(203);
    vault
        .trash_item(&mut rng, &unlocked, item, T0 + 1_000)
        .unwrap();
    vault.set_read_only(true);
    let due = vault
        .auto_purge_due(
            &mut rng,
            &unlocked,
            T0 + 1_000 + RETENTION_MS * 10,
            RETENTION_MS,
        )
        .unwrap();
    assert!(due.is_empty());
    assert_eq!(vault.item_lifecycle(item), ItemLifecycle::Trashed);
}

/// ADR 0018 §8 "Vault settings": "If a faulty client trashes it, it stays in effect." The
/// vault-settings item must never be auto-purged, even though a naive retention-only check
/// would purge it once it is trashed.
#[test]
fn vault_settings_item_is_never_auto_purged() {
    let (_server, mut rng, mut vault, unlocked, _login_item) = one_item(204);
    let name_key = SchemaKey::parse(VAULT_NAME.as_bytes()).unwrap();
    let name_value = Value::text("Personal").unwrap();
    let settings = vault
        .create_item(
            &mut rng,
            &unlocked,
            ItemType::VAULT_SETTINGS,
            &[FieldEdit {
                key: &name_key,
                value: &name_value,
            }],
            T0 + 2_000,
        )
        .unwrap();
    vault
        .trash_item(&mut rng, &unlocked, settings, T0 + 2_001)
        .unwrap();
    let due = vault
        .auto_purge_due(
            &mut rng,
            &unlocked,
            T0 + 2_001 + RETENTION_MS * 10,
            RETENTION_MS,
        )
        .unwrap();
    assert!(
        due.is_empty(),
        "the vault-settings item must never be auto-purged"
    );
    assert_eq!(vault.item_lifecycle(settings), ItemLifecycle::Trashed);
}

/// ADR 0018 §11 "No purge over an unapplied record": while a client holds any unapplied record
/// of an item, manual or automatic, it issues no Purge for it. A parked unknown-version record
/// is one way to hold one; a served body that fails verification (`WaitReason::Rejected`) is
/// another, and is what this test constructs, the same technique
/// `fetch_drops_forged_records` uses for a withheld wrap. Both land in
/// `VaultLog::waiting`, which `VaultSync::holds_unapplied` and so `auto_purge_due` consult.
#[test]
fn no_auto_purge_while_an_unapplied_record_is_held() {
    let mut rng = ChaCha20Rng::seed_from_u64(205);
    let mut server = Server::new(206);
    let w = signup(&mut server, &mut rng, DeviceKind::DesktopCli);
    let sk = secret_key_text(w.device.as_ref().unwrap());
    let vault_id = w.vault_key.vault_id();
    let authors = server.authors();
    let (mut writer, w_unlocked, items) = synced_writer(&mut server, &mut rng, w, &authors, 1);
    let item = items[0];

    let r = login_and_enrol(&mut server, &mut rng, &sk);
    let r_authors = Authors::from_account(&r.account).unwrap();
    let mut r_account = r.account;
    let mut reader =
        VaultSync::new(r_account.take_vault_key(vault_id).unwrap(), &r.unlocked, 1).unwrap();
    reader
        .apply_fetch(
            &r_authors,
            &server.fetch(&reader.fetch_request().unwrap()),
            T0 + 1,
        )
        .unwrap();
    assert_eq!(reader.item_lifecycle(item), ItemLifecycle::Active);

    writer
        .trash_item(&mut rng, &w_unlocked, item, T0 + 2_000)
        .unwrap();
    let up = writer
        .upload_request(&mut rng, &w_unlocked)
        .unwrap()
        .unwrap();
    server.upload(&up);
    reader
        .apply_fetch(
            &r_authors,
            &server.fetch(&reader.fetch_request().unwrap()),
            T0 + 2_001,
        )
        .unwrap();
    assert_eq!(reader.item_lifecycle(item), ItemLifecycle::Trashed);

    // The vault key rotates and the writer adopts it (the `rotation` tests' shortcut for the
    // grant ceremony); its item key for X is now stale at the new epoch, so its next op on X
    // carries a fresh item key and wrap (CRYPTO.md §11.6 writer rule). The writer restores the
    // item under that fresh key, but the served wrap is withheld: the reader cannot open the
    // body, which is held as `BodyStatus::Waiting` (the same technique
    // `fetch_drops_forged_records` uses), never applied.
    writer
        .adopt_vault_key(VaultKey::generate(&mut rng, vault_id, 1))
        .unwrap();
    writer
        .restore_item(&mut rng, &w_unlocked, item, T0 + 2_002)
        .unwrap();
    let up = writer
        .upload_request(&mut rng, &w_unlocked)
        .unwrap()
        .unwrap();
    server.upload(&up);
    let mut response = server.fetch(&reader.fetch_request().unwrap());
    let mut ops = response.ops.into_vec();
    ops[0].key_wrap = None;
    response.ops = List::new(ops).unwrap();
    response.item_key_wraps = List::empty();
    let outcome = reader
        .apply_fetch(&r_authors, &response, T0 + 2_003)
        .unwrap();
    assert_eq!(outcome.applied, 0);
    assert_eq!(reader.item_lifecycle(item), ItemLifecycle::Trashed);
    assert!(
        reader.holds_unapplied(item),
        "the withheld-wrap body must be held as waiting, not dropped"
    );

    let due = reader
        .auto_purge_due(
            &mut rng,
            &r.unlocked,
            T0 + 2_003 + RETENTION_MS * 10,
            RETENTION_MS,
        )
        .unwrap();
    assert!(
        due.is_empty(),
        "no auto-purge while an unapplied record is held (ADR 0018 §11)"
    );
    assert_eq!(reader.item_lifecycle(item), ItemLifecycle::Trashed);
}
