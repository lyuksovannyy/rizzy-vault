//! `VaultSync::password_history` and `VaultSync::imported_password_history` tests (ADR 0012
//! §5 "Password history is the history of `login.password`"; ADR 0018 §7, §9).

use rizzy_core::item::schema::{ATTR_MS, ATTR_VALUE, LIST_PWHIST};
use rizzy_core::item::value::SortKey;

use super::lists::one_item;
use super::*;
use crate::lists::ElementWrite;

/// Edits `login.password` to `text` at `now_ms`.
fn edit_password(
    vault: &mut VaultSync,
    rng: &mut ChaCha20Rng,
    unlocked: &UnlockedDevice,
    item: ItemId,
    text: &str,
    now_ms: u64,
) {
    let key = SchemaKey::parse(LOGIN_PASSWORD.as_bytes()).unwrap();
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
            now_ms,
        )
        .unwrap();
}

/// The decoded text of a history entry.
fn text_of(value: &Value) -> String {
    match value.decode().unwrap() {
        ValueRef::Text(t) => t.to_owned(),
        other => panic!("expected text, got {other:?}"),
    }
}

#[test]
fn history_after_several_edits_is_newest_first_and_excludes_current() {
    // `one_item` creates the item with `login.password` = "p".
    let (_server, mut rng, mut vault, unlocked, item) = one_item(300);
    edit_password(&mut vault, &mut rng, &unlocked, item, "p1", T0 + 10);
    edit_password(&mut vault, &mut rng, &unlocked, item, "p2", T0 + 20);
    edit_password(&mut vault, &mut rng, &unlocked, item, "p3", T0 + 30);

    assert_eq!(vault.password_history_len(item), 3);
    let history = vault.password_history(item);
    let texts: Vec<String> = history.iter().map(|e| text_of(&e.value)).collect();
    assert_eq!(texts, vec!["p2", "p1", "p"]);
    // Strictly descending `changed_ms`: newest-superseded first.
    assert!(history.is_sorted_by(|a, b| a.changed_ms >= b.changed_ms));
    // The current value is never a history entry.
    assert!(!texts.contains(&"p3".to_owned()));
}

#[test]
fn history_is_capped_at_the_merge_limit() {
    let (_server, mut rng, mut vault, unlocked, item) = one_item(301);
    let edits = rizzy_sync::merge::HISTORY_LIMIT + 10;
    for i in 0..edits {
        edit_password(
            &mut vault,
            &mut rng,
            &unlocked,
            item,
            &format!("p{i}"),
            T0 + 10 + u64::try_from(i).unwrap(),
        );
    }
    assert_eq!(
        vault.password_history_len(item),
        rizzy_sync::merge::HISTORY_LIMIT
    );
    let history = vault.password_history(item);
    assert_eq!(history.len(), rizzy_sync::merge::HISTORY_LIMIT);
    // The most recently superseded value ("p{edits - 2}", since the last edit is current and
    // never enters history) is kept; the oldest ones ("p", "p0", ...) were pruned.
    let newest = text_of(&history[0].value);
    assert_eq!(newest, format!("p{}", edits - 2));
}

#[test]
fn tombstone_has_no_password_history() {
    let (_server, mut rng, mut vault, unlocked, item) = one_item(302);
    edit_password(&mut vault, &mut rng, &unlocked, item, "p1", T0 + 10);
    assert_eq!(vault.password_history_len(item), 1);
    vault
        .trash_item(&mut rng, &unlocked, item, T0 + 20)
        .unwrap();
    vault
        .purge_item(&mut rng, &unlocked, item, T0 + 21)
        .unwrap();
    assert_eq!(vault.item_lifecycle(item), ItemLifecycle::Purged);
    assert_eq!(vault.password_history_len(item), 0);
    assert!(vault.password_history(item).is_empty());
}

#[test]
fn imported_password_history_is_kept_separate_from_the_merge_history() {
    let (_server, mut rng, mut vault, unlocked, item) = one_item(303);
    edit_password(&mut vault, &mut rng, &unlocked, item, "p1", T0 + 10);

    let value = Value::text("old-imported").unwrap();
    let ms = Value::u64(1_600_000_000_000);
    let (_element, writes) = VaultSync::new_element_writes(
        &mut rng,
        LIST_PWHIST,
        vec![(ATTR_VALUE, value), (ATTR_MS, ms)],
        None::<&SortKey>,
    )
    .unwrap();
    let edits: Vec<ElementWrite> = writes;
    let field_edits: Vec<FieldEdit<'_>> = edits
        .iter()
        .map(|(key, value)| FieldEdit { key, value })
        .collect();
    vault
        .edit_item(&mut rng, &unlocked, item, &field_edits, T0 + 30)
        .unwrap();

    // The imported entry does not show up in the merge history, and vice versa. The merge
    // history holds the superseded value ("p", written by `one_item`), not the current one
    // ("p1").
    let merge_history = vault.password_history(item);
    assert_eq!(merge_history.len(), 1);
    assert_eq!(text_of(&merge_history[0].value), "p");

    let imported = vault.imported_password_history(item);
    assert_eq!(imported.len(), 1);
    assert_eq!(text_of(imported[0].value.as_ref().unwrap()), "old-imported");
    assert_eq!(imported[0].changed_ms, Some(1_600_000_000_000));
}
