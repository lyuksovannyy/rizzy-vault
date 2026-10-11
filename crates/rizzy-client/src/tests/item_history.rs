// SPDX-License-Identifier: AGPL-3.0-only

//! `VaultSync::field_history`, `VaultSync::field_history_len`, `VaultSync::item_history` and
//! `VaultSync::restore_field_history` (ROADMAP §4.2 "Item revision history (restore old
//! versions)", M3): the generic, per-field counterpart of `tests/password_history.rs`, which
//! these tests use as their template. ADR 0018 §3 "History" is the history of every field, not
//! only `login.password` (ADR 0012 §5 names `login.password` only as an example); the restore
//! writes the old value back through `VaultSync::edit_item`, "an ordinary carried edit" (ADR
//! 0018 §2 "Flow"), so it syncs and merges exactly like any other edit.

use rizzy_core::item::schema::LOGIN_USERNAME;

use super::lists::one_item;
use super::*;

/// Edits field `key` to `text` at `now_ms`.
fn edit_field(
    vault: &mut VaultSync,
    rng: &mut ChaCha20Rng,
    unlocked: &UnlockedDevice,
    item: ItemId,
    key: &str,
    text: &str,
    now_ms: u64,
) {
    let key = SchemaKey::parse(key.as_bytes()).unwrap();
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
fn field_history_after_several_edits_is_newest_first_and_excludes_current() {
    // `one_item` creates the item with `login.password` = "p"; generalize to a different
    // field to prove the API is not password-specific.
    let (_server, mut rng, mut vault, unlocked, item) = one_item(400);
    edit_field(
        &mut vault,
        &mut rng,
        &unlocked,
        item,
        LOGIN_USERNAME,
        "u1",
        T0 + 10,
    );
    edit_field(
        &mut vault,
        &mut rng,
        &unlocked,
        item,
        LOGIN_USERNAME,
        "u2",
        T0 + 20,
    );

    assert_eq!(vault.field_history_len(item, LOGIN_USERNAME), 1);
    let history = vault.field_history(item, LOGIN_USERNAME);
    let texts: Vec<String> = history.iter().map(|e| text_of(&e.value)).collect();
    assert_eq!(texts, vec!["u1"]);
    assert!(!texts.contains(&"u2".to_owned()));
}

#[test]
fn password_history_is_field_history_of_login_password() {
    // `password_history`/`password_history_len` are the LOGIN_PASSWORD special case of the
    // generic API (module docs): same answer either way.
    let (_server, mut rng, mut vault, unlocked, item) = one_item(401);
    edit_field(
        &mut vault,
        &mut rng,
        &unlocked,
        item,
        LOGIN_PASSWORD,
        "p1",
        T0 + 10,
    );
    let generic = vault.field_history(item, LOGIN_PASSWORD);
    let specific = vault.password_history(item);
    assert_eq!(generic.len(), specific.len());
    assert_eq!(generic.len(), 1);
    assert_eq!(text_of(&generic[0].value), text_of(&specific[0].value));
    assert_eq!(generic[0].dot, specific[0].dot);
    assert_eq!(
        vault.field_history_len(item, LOGIN_PASSWORD),
        vault.password_history_len(item)
    );
}

#[test]
fn item_history_lists_every_field_that_has_history_and_leaves_out_the_rest() {
    // `one_item` writes only `login.password`; `item.type` and `@lifecycle` never gain
    // history here. Editing `login.username` as well as `login.password` should list both,
    // and nothing else.
    let (_server, mut rng, mut vault, unlocked, item) = one_item(402);
    edit_field(
        &mut vault,
        &mut rng,
        &unlocked,
        item,
        LOGIN_PASSWORD,
        "p1",
        T0 + 10,
    );
    edit_field(
        &mut vault,
        &mut rng,
        &unlocked,
        item,
        LOGIN_USERNAME,
        "u1",
        T0 + 20,
    );
    edit_field(
        &mut vault,
        &mut rng,
        &unlocked,
        item,
        LOGIN_USERNAME,
        "u2",
        T0 + 30,
    );

    let history = vault.item_history(item);
    let mut keys: Vec<&str> = history.iter().map(|f| f.key.as_str()).collect();
    keys.sort_unstable();
    assert_eq!(keys, vec![LOGIN_PASSWORD, LOGIN_USERNAME]);

    let password = history
        .iter()
        .find(|f| f.key.as_str() == LOGIN_PASSWORD)
        .unwrap();
    assert_eq!(password.entries.len(), 1);
    assert_eq!(text_of(&password.entries[0].value), "p");

    let username = history
        .iter()
        .find(|f| f.key.as_str() == LOGIN_USERNAME)
        .unwrap();
    assert_eq!(username.entries.len(), 1);
    assert_eq!(text_of(&username.entries[0].value), "u1");
}

#[test]
fn item_history_is_empty_without_any_edit() {
    let (_server, _rng, vault, _unlocked, item) = one_item(403);
    assert!(vault.item_history(item).is_empty());
}

#[test]
fn restoring_a_history_entry_writes_it_back_as_current_and_pushes_the_displaced_value() {
    let (_server, mut rng, mut vault, unlocked, item) = one_item(404);
    edit_field(
        &mut vault,
        &mut rng,
        &unlocked,
        item,
        LOGIN_PASSWORD,
        "p1",
        T0 + 10,
    );
    // History now holds "p" (the value `one_item` wrote). Restore it.
    let dot = vault.field_history(item, LOGIN_PASSWORD)[0].dot;
    vault
        .restore_field_history(&mut rng, &unlocked, item, LOGIN_PASSWORD, dot, T0 + 20)
        .unwrap();

    assert_eq!(
        text_of(&vault.field_value(item, LOGIN_PASSWORD).unwrap()),
        "p"
    );
    // The restore is an ordinary edit under a fresh dot: it neither removes nor deduplicates
    // the entry it copied ("p", still in history under its own, original dot), and it pushes
    // the value it displaced ("p1") into history too. Newest (by hlc) first.
    let history = vault.field_history(item, LOGIN_PASSWORD);
    let texts: Vec<String> = history.iter().map(|e| text_of(&e.value)).collect();
    assert_eq!(texts, vec!["p1", "p"]);
}

#[test]
fn restore_with_a_dot_the_field_does_not_hold_is_refused() {
    let (_server, mut rng, mut vault, unlocked, item) = one_item(405);
    edit_field(
        &mut vault,
        &mut rng,
        &unlocked,
        item,
        LOGIN_PASSWORD,
        "p1",
        T0 + 10,
    );
    let bogus = vault.field_history(item, LOGIN_PASSWORD)[0].dot;
    // Clearing then re-editing removes that entry from history (ADR 0018 §10 "the merge keeps
    // ≤ 50 history entries"; here it is simply superseded and re-pruned is not needed, but the
    // dot still must not resolve against a *different* field).
    let err = vault
        .restore_field_history(&mut rng, &unlocked, item, LOGIN_USERNAME, bogus, T0 + 20)
        .unwrap_err();
    assert_eq!(err, ClientError::UnknownItem);
}

#[test]
fn a_dot_shared_by_two_fields_restores_only_the_named_fields_value() {
    // One op writing two fields puts the *same* dot in both fields' histories (ADR 0018 §4
    // "Uniqueness": a dot appears at most once per field key, across that field's register and
    // history -- across *different* keys it can repeat). A reveal or restore must be scoped by
    // (key, dot), never dot alone.
    let (_server, mut rng, mut vault, unlocked, item) = one_item(406);
    let password_key = SchemaKey::parse(LOGIN_PASSWORD.as_bytes()).unwrap();
    let username_key = SchemaKey::parse(LOGIN_USERNAME.as_bytes()).unwrap();
    let p1 = Value::text("p1").unwrap();
    let u1 = Value::text("u1").unwrap();
    vault
        .edit_item(
            &mut rng,
            &unlocked,
            item,
            &[
                FieldEdit {
                    key: &password_key,
                    value: &p1,
                },
                FieldEdit {
                    key: &username_key,
                    value: &u1,
                },
            ],
            T0 + 10,
        )
        .unwrap();
    // Supersede both so their first values ("p" and the as-yet-unset username) move to
    // history under dots the create op wrote; instead, directly check the shared dot: the one
    // op above wrote both `login.password` = "p1" and `login.username` = "u1". Supersede both
    // again to push "p1"/"u1" into history under one shared dot.
    edit_field(
        &mut vault,
        &mut rng,
        &unlocked,
        item,
        LOGIN_PASSWORD,
        "p2",
        T0 + 20,
    );
    edit_field(
        &mut vault,
        &mut rng,
        &unlocked,
        item,
        LOGIN_USERNAME,
        "u2",
        T0 + 20,
    );

    let password_history = vault.field_history(item, LOGIN_PASSWORD);
    let username_history = vault.field_history(item, LOGIN_USERNAME);
    let shared_dot = password_history
        .iter()
        .find(|e| text_of(&e.value) == "p1")
        .unwrap()
        .dot;
    assert_eq!(
        username_history
            .iter()
            .find(|e| text_of(&e.value) == "u1")
            .unwrap()
            .dot,
        shared_dot,
        "the one op's dot is shared by both fields' history entries"
    );

    // Restoring that dot under `login.password` restores "p1", never touches the username.
    vault
        .restore_field_history(
            &mut rng,
            &unlocked,
            item,
            LOGIN_PASSWORD,
            shared_dot,
            T0 + 30,
        )
        .unwrap();
    assert_eq!(
        text_of(&vault.field_value(item, LOGIN_PASSWORD).unwrap()),
        "p1"
    );
    assert_eq!(
        text_of(&vault.field_value(item, LOGIN_USERNAME).unwrap()),
        "u2"
    );
}

#[test]
fn restore_on_a_trashed_item_is_refused() {
    let (_server, mut rng, mut vault, unlocked, item) = one_item(407);
    edit_field(
        &mut vault,
        &mut rng,
        &unlocked,
        item,
        LOGIN_PASSWORD,
        "p1",
        T0 + 10,
    );
    let dot = vault.field_history(item, LOGIN_PASSWORD)[0].dot;
    vault
        .trash_item(&mut rng, &unlocked, item, T0 + 20)
        .unwrap();
    let err = vault
        .restore_field_history(&mut rng, &unlocked, item, LOGIN_PASSWORD, dot, T0 + 30)
        .unwrap_err();
    assert_eq!(err, ClientError::UnknownItem);
}

#[test]
fn tombstone_has_no_item_history() {
    let (_server, mut rng, mut vault, unlocked, item) = one_item(408);
    edit_field(
        &mut vault,
        &mut rng,
        &unlocked,
        item,
        LOGIN_PASSWORD,
        "p1",
        T0 + 10,
    );
    assert!(!vault.item_history(item).is_empty());
    vault
        .trash_item(&mut rng, &unlocked, item, T0 + 20)
        .unwrap();
    vault
        .purge_item(&mut rng, &unlocked, item, T0 + 21)
        .unwrap();
    assert!(vault.item_history(item).is_empty());
    assert!(vault.field_history(item, LOGIN_PASSWORD).is_empty());
}
