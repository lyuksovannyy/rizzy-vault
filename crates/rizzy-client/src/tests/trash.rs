//! The trash beyond the single-item calls (`crate::trash`): the automatic purge after the
//! retention period (ADR 0012 §5, ADR 0018 §9, §11, §12), the late-edit and concurrent-trash
//! notices with "Restore it as a new item" (ADR 0018 §3 "Surfacing"), and the password
//! history (`crate::history`; ADR 0018 §7).

use rizzy_core::item::schema::{ATTR_MS, ATTR_VALUE, LIST_PWHIST};

use super::*;
use crate::history::{HISTORY_LIMIT, HistorySource};
use crate::trash::DEFAULT_TRASH_RETENTION_MS as RETENTION;

/// One device's vault and keys.
struct Dev {
    /// The vault.
    vault: VaultSync,
    /// The unlocked device.
    unlocked: UnlockedDevice,
}

impl Dev {
    /// Fetches, uploads what is queued, and fetches again, at `now`.
    fn sync(&mut self, server: &mut Server, rng: &mut ChaCha20Rng, authors: &Authors, now: u64) {
        self.vault
            .apply_fetch(
                authors,
                &server.fetch(&self.vault.fetch_request().unwrap()),
                now,
            )
            .unwrap();
        if let Some(up) = self.vault.upload_request(rng, &self.unlocked).unwrap() {
            let answer = server.upload(&up);
            self.vault.apply_upload_response(&answer).unwrap();
        }
        self.vault
            .apply_fetch(
                authors,
                &server.fetch(&self.vault.fetch_request().unwrap()),
                now,
            )
            .unwrap();
    }

    /// Writes `login.password` = `text` on `item`.
    fn set_password(&mut self, rng: &mut ChaCha20Rng, item: ItemId, text: &str, now: u64) {
        let key = SchemaKey::parse(LOGIN_PASSWORD.as_bytes()).unwrap();
        let value = Value::text(text).unwrap();
        self.vault
            .edit_item(
                rng,
                &self.unlocked,
                item,
                &[FieldEdit {
                    key: &key,
                    value: &value,
                }],
                now,
            )
            .unwrap();
    }

    /// Creates a Login item whose password is `text`.
    fn create(&mut self, rng: &mut ChaCha20Rng, text: &str, now: u64) -> ItemId {
        let key = SchemaKey::parse(LOGIN_PASSWORD.as_bytes()).unwrap();
        let value = Value::text(text).unwrap();
        self.vault
            .create_item(
                rng,
                &self.unlocked,
                ItemType::LOGIN,
                &[FieldEdit {
                    key: &key,
                    value: &value,
                }],
                now,
            )
            .unwrap()
    }
}

/// Two devices of one account, both synced once, with the authors that know both.
fn pair(seed: u64) -> (Server, ChaCha20Rng, Authors, Dev, Dev) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut server = Server::new(seed + 1);
    let a = signup(&mut server, &mut rng, DeviceKind::DesktopCli);
    let sk = secret_key_text(a.device.as_ref().unwrap());
    let vault_id = a.vault_key.vault_id();
    let b = login_and_enrol(&mut server, &mut rng, &sk);
    let authors = Authors::from_account(&b.account).unwrap();
    let mut b_account = b.account;
    let mut a = Dev {
        vault: VaultSync::new(a.vault_key, &a.unlocked, 1).unwrap(),
        unlocked: a.unlocked,
    };
    let mut b = Dev {
        vault: VaultSync::new(b_account.take_vault_key(vault_id).unwrap(), &b.unlocked, 1).unwrap(),
        unlocked: b.unlocked,
    };
    a.sync(&mut server, &mut rng, &authors, T0);
    b.sync(&mut server, &mut rng, &authors, T0);
    (server, rng, authors, a, b)
}

/// The text of an encoded Text value.
fn text(value: &Value) -> String {
    match value.decode().unwrap() {
        ValueRef::Text(t) => t.to_owned(),
        _ => panic!("text"),
    }
}

#[test]
fn auto_purge_waits_for_the_retention_period() {
    let (mut server, mut rng, authors, mut a, _b) = pair(60);
    let trashed_at = T0 + 100;
    let old = a.create(&mut rng, "p", T0 + 10);
    let restored = a.create(&mut rng, "q", T0 + 11);
    let active = a.create(&mut rng, "r", T0 + 12);
    for item in [old, restored] {
        a.vault
            .trash_item(&mut rng, &a.unlocked, item, trashed_at)
            .unwrap();
    }
    a.vault
        .restore_item(&mut rng, &a.unlocked, restored, trashed_at + 1)
        .unwrap();
    a.sync(&mut server, &mut rng, &authors, trashed_at + 2);

    // Not before the retention period has passed.
    let early = trashed_at + RETENTION - 1;
    assert!(
        a.vault
            .purge_expired(&mut rng, &a.unlocked, early, RETENTION)
            .unwrap()
            .is_empty()
    );
    assert_eq!(a.vault.item_lifecycle(old), ItemLifecycle::Trashed);

    // A read-only vault purges nothing and reports no error.
    let due = trashed_at + RETENTION;
    a.vault.set_read_only(true);
    assert!(
        a.vault
            .purge_expired(&mut rng, &a.unlocked, due, RETENTION)
            .unwrap()
            .is_empty()
    );
    a.vault.set_read_only(false);

    // Exactly at trashed-at + retention: only the trashed item, never a restored or active one.
    assert_eq!(
        a.vault
            .purge_expired(&mut rng, &a.unlocked, due, RETENTION)
            .unwrap(),
        vec![old]
    );
    assert_eq!(a.vault.item_lifecycle(old), ItemLifecycle::Purged);
    assert_eq!(a.vault.item_lifecycle(restored), ItemLifecycle::Active);
    assert_eq!(a.vault.item_lifecycle(active), ItemLifecycle::Active);
    // Nothing is due twice.
    assert!(
        a.vault
            .purge_expired(&mut rng, &a.unlocked, due + RETENTION, RETENTION)
            .unwrap()
            .is_empty()
    );
    // The purge is an ordinary own op: the next sync uploads it.
    let up = a
        .vault
        .upload_request(&mut rng, &a.unlocked)
        .unwrap()
        .unwrap();
    assert_eq!(
        up.records
            .as_slice()
            .iter()
            .filter(|r| matches!(r, Record::Op(_)))
            .count(),
        1
    );
}

/// ADR 0018 §12: "no auto-purge while an unknown-version restore is parked" (§11: "No purge
/// over an unapplied record ... manual or automatic"). The record B holds unapplied here is a
/// restore whose body waits for its item key: A rotated the vault key and restored under a
/// fresh item key at the new epoch, which B, still at the old epoch, cannot open. The rule and
/// the check are the same for a record parked for its schema version (`VaultSync::
/// holds_unapplied` reads the causal layer's waiting records either way).
#[test]
fn no_auto_purge_while_a_restore_is_parked() {
    use super::rotation::{fetch, reauth, settle, signup_with_code};
    use crate::rotation::{RotationLevel, RotationOptions, start_rotation};

    let mut rng = ChaCha20Rng::seed_from_u64(62);
    let mut server = Server::new(63);
    let (mut signed_up, code) = signup_with_code(&mut server, &mut rng);
    let mut a_state = signed_up.device.take().unwrap();
    let sk = secret_key_text(&a_state);
    let vault_id = signed_up.vault_key.vault_id();
    let b = login_and_enrol(&mut server, &mut rng, &sk);
    let authors = Authors::from_account(&b.account).unwrap();
    let mut b_account = b.account;
    let mut a = Dev {
        vault: VaultSync::new(signed_up.vault_key, &signed_up.unlocked, 1).unwrap(),
        unlocked: signed_up.unlocked,
    };
    let mut b = Dev {
        vault: VaultSync::new(b_account.take_vault_key(vault_id).unwrap(), &b.unlocked, 1).unwrap(),
        unlocked: b.unlocked,
    };
    a.sync(&mut server, &mut rng, &authors, T0);
    let item = a.create(&mut rng, "p", T0 + 10);
    a.vault
        .trash_item(&mut rng, &a.unlocked, item, T0 + 20)
        .unwrap();
    a.sync(&mut server, &mut rng, &authors, T0 + 30);
    b.sync(&mut server, &mut rng, &authors, T0 + 40);
    assert_eq!(b.vault.item_lifecycle(item), ItemLifecycle::Trashed);

    // A rotates the vault key, then restores the item under a fresh item key.
    settle(&mut server, &mut rng, &mut a.vault, &a.unlocked);
    let options = RotationOptions {
        level: RotationLevel::Standard,
        revoke: None,
        recovery_code: Some(&code),
        now_ms: T0 + 10_000,
    };
    let login = reauth(&mut server, &mut rng, &sk);
    let pending = start_rotation(
        &mut rng,
        login,
        &a_state,
        &a.unlocked,
        &[&a.vault],
        &options,
    )
    .unwrap();
    server.commit_rotation(pending.commit_request()).unwrap();
    pending
        .finalize(&mut rng, &mut a_state, &mut a.unlocked, &mut [&mut a.vault])
        .unwrap();
    fetch(&server, &mut a.vault);
    a.vault
        .restore_item(&mut rng, &a.unlocked, item, T0 + 20_000)
        .unwrap();
    a.sync(&mut server, &mut rng, &authors, T0 + 20_001);
    assert_eq!(a.vault.item_lifecycle(item), ItemLifecycle::Active);

    // B receives the restore and holds it unapplied: the item still displays Trashed.
    b.vault
        .apply_fetch(
            &authors,
            &server.fetch(&b.vault.fetch_request().unwrap()),
            T0 + 20_002,
        )
        .unwrap();
    assert_eq!(b.vault.item_lifecycle(item), ItemLifecycle::Trashed);
    assert!(b.vault.holds_unapplied(item));
    assert!(!b.vault.is_read_only());

    // Long past the retention period, the parked restore still blocks every purge.
    let late = T0 + 20 + 2 * RETENTION;
    assert!(
        b.vault
            .purge_expired(&mut rng, &b.unlocked, late, RETENTION)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        b.vault
            .purge_item(&mut rng, &b.unlocked, item, late)
            .unwrap_err(),
        ClientError::InvalidEdit
    );
    assert_eq!(b.vault.item_lifecycle(item), ItemLifecycle::Trashed);
    assert!(
        b.vault
            .upload_request(&mut rng, &b.unlocked)
            .unwrap()
            .is_none()
    );
}

#[test]
fn concurrent_auto_purges_converge() {
    let (mut server, mut rng, authors, mut a, mut b) = pair(64);
    let item = a.create(&mut rng, "p", T0 + 10);
    a.vault
        .trash_item(&mut rng, &a.unlocked, item, T0 + 20)
        .unwrap();
    a.sync(&mut server, &mut rng, &authors, T0 + 30);
    b.sync(&mut server, &mut rng, &authors, T0 + 40);

    // Both devices come online after the retention period and purge before they sync.
    let due = T0 + 20 + RETENTION;
    for dev in [&mut a, &mut b] {
        assert_eq!(
            dev.vault
                .purge_expired(&mut rng, &dev.unlocked, due, RETENTION)
                .unwrap(),
            vec![item]
        );
    }
    a.sync(&mut server, &mut rng, &authors, due + 1);
    b.sync(&mut server, &mut rng, &authors, due + 2);
    a.sync(&mut server, &mut rng, &authors, due + 3);
    for dev in [&a, &b] {
        assert_eq!(dev.vault.item_lifecycle(item), ItemLifecycle::Purged);
        assert!(dev.vault.late_edits().is_empty());
    }
    let state = |dev: &Dev| {
        dev.vault
            .merge(item)
            .unwrap()
            .canonical_state()
            .unwrap()
            .unwrap()
            .expose_secret()
            .to_vec()
    };
    assert_eq!(state(&a), state(&b), "one tombstone");
}

#[test]
fn a_late_edit_is_surfaced_and_restored_as_a_new_item() {
    let (mut server, mut rng, authors, mut a, mut b) = pair(66);
    let item = a.create(&mut rng, "p", T0 + 10);
    a.vault
        .trash_item(&mut rng, &a.unlocked, item, T0 + 20)
        .unwrap();
    a.sync(&mut server, &mut rng, &authors, T0 + 30);
    b.sync(&mut server, &mut rng, &authors, T0 + 40);

    // A purges while B, offline, restores the item and edits it.
    a.vault
        .purge_item(&mut rng, &a.unlocked, item, T0 + 50)
        .unwrap();
    b.vault
        .restore_item(&mut rng, &b.unlocked, item, T0 + 51)
        .unwrap();
    b.set_password(&mut rng, item, "late", T0 + 52);
    a.sync(&mut server, &mut rng, &authors, T0 + 60);
    b.sync(&mut server, &mut rng, &authors, T0 + 61);
    a.sync(&mut server, &mut rng, &authors, T0 + 62);

    for dev in [&a, &b] {
        assert_eq!(dev.vault.item_lifecycle(item), ItemLifecycle::Purged);
        let late = dev.vault.late_edits();
        assert_eq!(late.len(), 1);
        assert_eq!(late[0].item, item);
        assert_eq!(late[0].devices, vec![b.unlocked.device_id]);
    }

    // B dismisses the notice: it is not shown again.
    b.vault.dismiss_late_edit(item).unwrap();
    assert!(b.vault.late_edits().is_empty());
    assert_eq!(
        b.vault.dismiss_late_edit(ItemId::from_bytes([7; 16])),
        Err(ClientError::UnknownItem)
    );

    // A restores the late values as a new item, of a type the user confirms.
    assert_eq!(
        a.vault
            .restore_late_edit(&mut rng, &a.unlocked, item, ItemType::SECURE_NOTE, T0 + 70)
            .unwrap_err(),
        ClientError::InvalidEdit,
        "a note has no password"
    );
    assert_eq!(
        a.vault
            .restore_late_edit(
                &mut rng,
                &a.unlocked,
                item,
                ItemType::VAULT_SETTINGS,
                T0 + 70
            )
            .unwrap_err(),
        ClientError::InvalidEdit
    );
    let new_item = a
        .vault
        .restore_late_edit(&mut rng, &a.unlocked, item, ItemType::LOGIN, T0 + 71)
        .unwrap();
    assert_ne!(new_item, item);
    assert_eq!(a.vault.item_lifecycle(new_item), ItemLifecycle::Active);
    assert_eq!(a.vault.item_type(new_item), Some(ItemType::LOGIN));
    assert_eq!(
        text(&a.vault.field_value(new_item, LOGIN_PASSWORD).unwrap()),
        "late"
    );
    assert_eq!(a.vault.item_lifecycle(item), ItemLifecycle::Purged);
    assert!(a.vault.late_edits().is_empty());

    // Restoring needs a tombstone.
    assert_eq!(
        a.vault
            .restore_late_edit(&mut rng, &a.unlocked, new_item, ItemType::LOGIN, T0 + 72)
            .unwrap_err(),
        ClientError::UnknownItem
    );
    a.sync(&mut server, &mut rng, &authors, T0 + 80);
    b.sync(&mut server, &mut rng, &authors, T0 + 81);
    assert_eq!(b.vault.item_lifecycle(new_item), ItemLifecycle::Active);
}

#[test]
fn an_edit_that_wins_over_a_concurrent_trash_is_reported() {
    let (mut server, mut rng, authors, mut a, mut b) = pair(68);
    let item = a.create(&mut rng, "p", T0 + 10);
    a.sync(&mut server, &mut rng, &authors, T0 + 20);
    b.sync(&mut server, &mut rng, &authors, T0 + 21);
    assert_eq!(a.vault.trash_conflict(item), None);

    // A trashes while B, offline, edits: Active wins.
    a.vault
        .trash_item(&mut rng, &a.unlocked, item, T0 + 30)
        .unwrap();
    b.set_password(&mut rng, item, "edited", T0 + 31);
    a.sync(&mut server, &mut rng, &authors, T0 + 40);
    b.sync(&mut server, &mut rng, &authors, T0 + 41);
    a.sync(&mut server, &mut rng, &authors, T0 + 42);
    for dev in [&a, &b] {
        assert_eq!(dev.vault.item_lifecycle(item), ItemLifecycle::Active);
        let conflict = dev.vault.trash_conflict(item).unwrap();
        assert_eq!(conflict.trashed_by, a.unlocked.device_id);
        assert_eq!(conflict.edited_by, b.unlocked.device_id);
        assert_eq!(conflict.trashed_at_ms, T0 + 30);
    }

    // The next edit, which saw both, ends the notice.
    a.set_password(&mut rng, item, "after", T0 + 50);
    assert_eq!(a.vault.trash_conflict(item), None);
}

#[test]
fn password_history_is_newest_first_and_capped() {
    let (mut server, mut rng, authors, mut a, mut b) = pair(70);
    let item = a.create(&mut rng, "p0", T0 + 10);
    assert!(a.vault.password_history(item).is_empty());
    a.set_password(&mut rng, item, "p1", T0 + 20);
    a.set_password(&mut rng, item, "p2", T0 + 30);
    let history = a.vault.password_history(item);
    let shown: Vec<(String, Option<u64>, HistorySource)> = history
        .iter()
        .map(|e| (text(&e.value), e.at_ms, e.source))
        .collect();
    assert_eq!(
        shown,
        vec![
            ("p1".to_owned(), Some(T0 + 20), HistorySource::Edited),
            ("p0".to_owned(), Some(T0 + 10), HistorySource::Edited),
        ]
    );
    assert!(!format!("{history:?}").contains("p1"));

    // A cleared password is not a past password.
    let key = SchemaKey::parse(LOGIN_PASSWORD.as_bytes()).unwrap();
    a.vault
        .edit_item(
            &mut rng,
            &a.unlocked,
            item,
            &[FieldEdit {
                key: &key,
                value: &Value::cleared(),
            }],
            T0 + 35,
        )
        .unwrap();
    a.set_password(&mut rng, item, "p3", T0 + 36);
    let texts: Vec<String> = a
        .vault
        .password_history(item)
        .iter()
        .map(|e| text(&e.value))
        .collect();
    assert_eq!(texts, vec!["p2", "p1", "p0"]);

    // Both sides of a conflict land in the history once an edit resolves it.
    a.sync(&mut server, &mut rng, &authors, T0 + 40);
    b.sync(&mut server, &mut rng, &authors, T0 + 41);
    a.set_password(&mut rng, item, "x", T0 + 50);
    b.set_password(&mut rng, item, "y", T0 + 50);
    a.sync(&mut server, &mut rng, &authors, T0 + 60);
    b.sync(&mut server, &mut rng, &authors, T0 + 61);
    a.sync(&mut server, &mut rng, &authors, T0 + 62);
    assert!(a.vault.field_conflicts(item, LOGIN_PASSWORD));
    a.set_password(&mut rng, item, "z", T0 + 70);
    let texts: Vec<String> = a
        .vault
        .password_history(item)
        .iter()
        .map(|e| text(&e.value))
        .collect();
    assert!(texts.contains(&"x".to_owned()) && texts.contains(&"y".to_owned()));
    assert!(texts.contains(&"p3".to_owned()));

    // The merge keeps the newest `HISTORY_LIMIT`.
    for i in 0..60u64 {
        a.set_password(&mut rng, item, &format!("n{i}"), T0 + 100 + i);
    }
    let history = a.vault.password_history(item);
    assert_eq!(history.len(), HISTORY_LIMIT);
    assert_eq!(text(&history[0].value), "n58");

    // A purged item has none.
    a.vault
        .trash_item(&mut rng, &a.unlocked, item, T0 + 200)
        .unwrap();
    assert_eq!(a.vault.password_history(item).len(), HISTORY_LIMIT);
    a.vault
        .purge_item(&mut rng, &a.unlocked, item, T0 + 201)
        .unwrap();
    assert!(a.vault.password_history(item).is_empty());
}

#[test]
fn imported_password_history_is_shown_with_the_edited() {
    let (_server, mut rng, _authors, mut a, _b) = pair(72);
    let item = a.create(&mut rng, "now", T0 + 10);
    let (_, mut writes) = VaultSync::new_element_writes(
        &mut rng,
        LIST_PWHIST,
        vec![
            (ATTR_VALUE, Value::text("imported").unwrap()),
            (ATTR_MS, Value::u64(T0 - 5_000)),
        ],
        None,
    )
    .unwrap();
    let (_, undated) = VaultSync::new_element_writes(
        &mut rng,
        LIST_PWHIST,
        vec![(ATTR_VALUE, Value::text("undated").unwrap())],
        None,
    )
    .unwrap();
    writes.extend(undated);
    let edits: Vec<FieldEdit<'_>> = writes
        .iter()
        .map(|(key, value)| FieldEdit { key, value })
        .collect();
    a.vault
        .edit_item(&mut rng, &a.unlocked, item, &edits, T0 + 20)
        .unwrap();
    a.set_password(&mut rng, item, "newer", T0 + 30);
    let shown: Vec<(String, HistorySource)> = a
        .vault
        .password_history(item)
        .iter()
        .map(|e| (text(&e.value), e.source))
        .collect();
    assert_eq!(
        shown,
        vec![
            ("now".to_owned(), HistorySource::Edited),
            ("imported".to_owned(), HistorySource::Imported),
            ("undated".to_owned(), HistorySource::Imported),
        ]
    );
}
