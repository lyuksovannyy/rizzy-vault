//! List order tests (ADR 0018 §6 "List order"; `crate::lists`): moves between neighbours,
//! the rewrite with evenly spaced keys when no key fits, and the split of a large rewrite into
//! consecutive ops.

use rizzy_core::item::schema::{
    ATTR_ORDER, ATTR_VALUE, LIST_FIELD, LIST_PWHIST, LIST_TAG, LIST_URI,
};
use rizzy_core::item::value::SortKey;
use zeroize::Zeroizing;

use super::*;
use crate::lists::{
    ElementWrite, ListMove, ListPlace, MAX_WRITES_PER_OP, OrderPlan, split_order_ops,
};

/// A writer with one Login item.
fn one_item(seed: u64) -> (Server, ChaCha20Rng, VaultSync, UnlockedDevice, ItemId) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut server = Server::new(seed + 1);
    let a = signup(&mut server, &mut rng, DeviceKind::DesktopCli);
    let authors = server.authors();
    let (vault, unlocked, items) = synced_writer(&mut server, &mut rng, a, &authors, 1);
    (server, rng, vault, unlocked, items[0])
}

/// Writes `writes` to `item` in one op.
fn write(
    vault: &mut VaultSync,
    rng: &mut ChaCha20Rng,
    unlocked: &UnlockedDevice,
    item: ItemId,
    writes: &[ElementWrite],
) {
    let edits: Vec<FieldEdit<'_>> = writes
        .iter()
        .map(|(key, value)| FieldEdit { key, value })
        .collect();
    vault
        .edit_item(rng, unlocked, item, &edits, T0 + 1_000)
        .unwrap();
}

/// Adds a URI `text` with the `order` payload `order` (none for `None`); returns its id.
fn add_uri(
    vault: &mut VaultSync,
    rng: &mut ChaCha20Rng,
    unlocked: &UnlockedDevice,
    item: ItemId,
    text: &str,
    order: Option<&[u8]>,
) -> String {
    let order = order.map(|o| SortKey::from_slice(o).unwrap());
    let (element, writes) = VaultSync::new_element_writes(
        rng,
        LIST_URI,
        vec![(ATTR_VALUE, Value::text(text).unwrap())],
        order.as_ref(),
    )
    .unwrap();
    write(vault, rng, unlocked, item, &writes);
    hex_of(element.as_bytes())
}

/// The URIs of `item` in list order.
fn uris(vault: &VaultSync, item: ItemId) -> Vec<String> {
    vault
        .list_elements(item, LIST_URI)
        .iter()
        .map(|e| {
            let value = vault
                .field_value(item, &format!("{LIST_URI}/{}/{ATTR_VALUE}", *e.element))
                .unwrap();
            match value.decode().unwrap() {
                ValueRef::Text(t) => t.to_owned(),
                _ => panic!("text"),
            }
        })
        .collect()
}

/// A move of `element` to `to`.
fn mv(element: &str, to: ListPlace) -> ListMove {
    ListMove {
        element: Zeroizing::new(element.to_owned()),
        to,
    }
}

/// The element id `id` as a place argument.
fn at(id: &str) -> Zeroizing<String> {
    Zeroizing::new(id.to_owned())
}

/// Plans and writes the moves; returns the plan's shape.
fn apply(
    vault: &mut VaultSync,
    rng: &mut ChaCha20Rng,
    unlocked: &UnlockedDevice,
    item: ItemId,
    moves: &[ListMove],
) -> (usize, bool) {
    let OrderPlan {
        writes, rewritten, ..
    } = vault
        .plan_list_order(Some(item), LIST_URI, &[], 0, moves)
        .unwrap();
    let shape = (writes.len(), rewritten);
    write(vault, rng, unlocked, item, &writes);
    shape
}

/// Moves between neighbours: one `order` write per moved element, strictly between its new
/// neighbours, and the refusals.
#[test]
fn elements_move_between_their_neighbours() {
    let (mut server, mut rng, mut vault, unlocked, item) = one_item(70);
    let orders = vault.append_orders(Some(item), LIST_URI, 3).unwrap();
    let ids: Vec<String> = ["a", "b", "c"]
        .iter()
        .zip(&orders)
        .map(|(text, order)| {
            add_uri(
                &mut vault,
                &mut rng,
                &unlocked,
                item,
                text,
                Some(order.as_bytes()),
            )
        })
        .collect();
    let [a, b, c] = [&ids[0], &ids[1], &ids[2]];
    assert_eq!(uris(&vault, item), ["a", "b", "c"]);

    let steps: [(ListMove, [&str; 3]); 4] = [
        (mv(c, ListPlace::First), ["c", "a", "b"]),
        (mv(a, ListPlace::After(at(b))), ["c", "b", "a"]),
        (mv(a, ListPlace::Before(at(c))), ["a", "c", "b"]),
        (mv(a, ListPlace::Last), ["c", "b", "a"]),
    ];
    for (step, expected) in steps {
        let shape = apply(&mut vault, &mut rng, &unlocked, item, &[step]);
        assert_eq!(shape, (1, false));
        assert_eq!(uris(&vault, item), expected);
    }
    // Several moves in one edit run in turn, each written once.
    let moves = [mv(a, ListPlace::First), mv(b, ListPlace::After(at(a)))];
    assert_eq!(
        apply(&mut vault, &mut rng, &unlocked, item, &moves),
        (2, false)
    );
    assert_eq!(uris(&vault, item), ["a", "b", "c"]);

    // Refusals: itself as the neighbour, an unknown or removed element, lists without order.
    let refused = |moves: &[ListMove], removed: &[&str], list: &str| {
        vault
            .plan_list_order(Some(item), list, removed, 0, moves)
            .unwrap_err()
    };
    assert_eq!(
        refused(&[mv(a, ListPlace::Before(at(a)))], &[], LIST_URI),
        ClientError::InvalidEdit
    );
    assert_eq!(
        refused(&[mv(&"ab".repeat(16), ListPlace::First)], &[], LIST_URI),
        ClientError::UnknownItem
    );
    assert_eq!(
        refused(&[mv(a, ListPlace::After(at(b)))], &[b.as_str()], LIST_URI),
        ClientError::UnknownItem
    );
    for list in [LIST_TAG, LIST_PWHIST] {
        assert_eq!(
            refused(&[mv(a, ListPlace::First)], &[], list),
            ClientError::InvalidEdit
        );
    }
    // A custom field list orders too, and an edit with nothing to place writes nothing.
    assert_eq!(
        vault
            .plan_list_order(Some(item), LIST_FIELD, &[], 1, &[])
            .unwrap()
            .new_orders
            .len(),
        1
    );
    let empty = vault
        .plan_list_order(Some(item), LIST_TAG, &[], 0, &[])
        .unwrap();
    assert!(empty.writes.is_empty() && empty.new_orders.is_empty() && !empty.rewritten);

    // Every op is a valid upload the server stores.
    let up = vault.upload_request(&mut rng, &unlocked).unwrap().unwrap();
    let answer = server.upload(&up);
    assert!(
        answer
            .results
            .as_slice()
            .iter()
            .all(|r| matches!(r, UploadResult::Stored))
    );
}

/// ADR 0018 §6: when no key fits between the neighbours, the list's `order` keys are rewritten
/// with evenly spaced keys, every element written, in one op.
#[test]
fn no_room_rewrites_the_list_evenly() {
    let (mut server, mut rng, mut vault, unlocked, item) = one_item(72);
    // Two elements with equal keys: nothing fits between them.
    let x = add_uri(&mut vault, &mut rng, &unlocked, item, "x", Some(&[0x05]));
    let y = add_uri(&mut vault, &mut rng, &unlocked, item, "y", Some(&[0x05]));
    let z = add_uri(&mut vault, &mut rng, &unlocked, item, "z", Some(&[0x09]));
    let (first, second) = if x < y { ("x", "y") } else { ("y", "x") };
    let (first_id, second_id) = if x < y { (&x, &y) } else { (&y, &x) };
    assert_eq!(uris(&vault, item), [first, second, "z"]);
    let plan = vault
        .plan_list_order(
            Some(item),
            LIST_URI,
            &[],
            0,
            &[mv(&z, ListPlace::After(at(first_id)))],
        )
        .unwrap();
    assert!(plan.rewritten);
    assert_eq!(plan.writes.len(), 3, "every element of the list");
    let keys: Vec<Vec<u8>> = plan
        .writes
        .iter()
        .map(|(_, v)| match v.decode().unwrap() {
            ValueRef::SortKey(k) => k.to_vec(),
            _ => panic!("a sort key"),
        })
        .collect();
    assert_eq!(keys, [vec![0x40], vec![0x80], vec![0xC0]]);
    let expected_keys = [
        format!("{LIST_URI}/{first_id}/{ATTR_ORDER}"),
        format!("{LIST_URI}/{z}/{ATTR_ORDER}"),
        format!("{LIST_URI}/{second_id}/{ATTR_ORDER}"),
    ];
    let written: Vec<&str> = plan.writes.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(written, expected_keys);
    let ops = split_order_ops(plan.writes, Vec::new());
    assert_eq!(ops.len(), 1);
    write(&mut vault, &mut rng, &unlocked, item, &ops[0]);
    assert_eq!(uris(&vault, item), [first, "z", second]);
    assert_eq!(vault_order(&vault, item, 1), [0x80]);

    // An element without `order` sorts last; a move after it rewrites the list too.
    let w = add_uri(&mut vault, &mut rng, &unlocked, item, "w", None);
    assert_eq!(uris(&vault, item), [first, "z", second, "w"]);
    let plan = vault
        .plan_list_order(Some(item), LIST_URI, &[], 0, &[mv(&z, ListPlace::Last)])
        .unwrap();
    assert!(plan.rewritten);
    assert_eq!(plan.writes.len(), 4);
    write(&mut vault, &mut rng, &unlocked, item, &plan.writes);
    assert_eq!(uris(&vault, item), [first, second, "w", "z"]);
    // A move before it needs no rewrite: no-order elements are not upper neighbours.
    let plan = vault
        .plan_list_order(
            Some(item),
            LIST_URI,
            &[],
            0,
            &[mv(&w, ListPlace::Before(at(first_id)))],
        )
        .unwrap();
    assert!(!plan.rewritten);
    assert_eq!(plan.writes.len(), 1);

    let up = vault.upload_request(&mut rng, &unlocked).unwrap().unwrap();
    let answer = server.upload(&up);
    assert!(
        answer
            .results
            .as_slice()
            .iter()
            .all(|r| matches!(r, UploadResult::Stored))
    );
}

/// An append above the highest possible key (64 bytes of `0xFF`) rewrites the list, the new
/// element's key included; `append_orders` refuses it and points to the plan.
#[test]
fn an_append_with_no_room_above_rewrites_the_list() {
    let (_server, mut rng, mut vault, unlocked, item) = one_item(74);
    let top = add_uri(
        &mut vault,
        &mut rng,
        &unlocked,
        item,
        "top",
        Some(&[0xFF; 64]),
    );
    assert_eq!(
        vault.append_orders(Some(item), LIST_URI, 1).unwrap_err(),
        ClientError::InvalidEdit
    );
    let plan = vault
        .plan_list_order(Some(item), LIST_URI, &[], 1, &[])
        .unwrap();
    assert!(plan.rewritten);
    assert_eq!(plan.new_orders.len(), 1);
    assert_eq!(plan.new_orders[0].as_bytes(), [0xAA]);
    assert_eq!(plan.writes.len(), 1);
    assert_eq!(
        plan.writes[0].0.as_str(),
        format!("{LIST_URI}/{top}/{ATTR_ORDER}")
    );
    let (_, mut writes) = VaultSync::new_element_writes(
        &mut rng,
        LIST_URI,
        vec![(ATTR_VALUE, Value::text("new").unwrap())],
        Some(&plan.new_orders[0]),
    )
    .unwrap();
    let mut ops = split_order_ops(plan.writes, core::mem::take(&mut writes));
    assert_eq!(ops.len(), 1);
    write(&mut vault, &mut rng, &unlocked, item, &ops.remove(0));
    assert_eq!(uris(&vault, item), ["top", "new"]);
}

/// ADR 0018 §6 "in consecutive ops if one would break §10": a rewrite too large for one op
/// goes first in ops of at most 1,024 writes, the edit's other writes after it.
#[test]
fn a_large_rewrite_is_split_into_consecutive_ops() {
    let order_write = |i: usize| {
        (
            SchemaKey::parse(format!("{LIST_URI}/{i:032x}/{ATTR_ORDER}").as_bytes()).unwrap(),
            Value::sort_key(&SortKey::from_slice(&[1]).unwrap()),
        )
    };
    let rewrite: Vec<ElementWrite> = (0..MAX_WRITES_PER_OP + 76).map(order_write).collect();
    let others = vec![(
        SchemaKey::parse(b"item.name").unwrap(),
        Value::text("n").unwrap(),
    )];
    let ops = split_order_ops(rewrite, others);
    let sizes: Vec<usize> = ops.iter().map(Vec::len).collect();
    assert_eq!(sizes, [MAX_WRITES_PER_OP, 76, 1]);
    assert_eq!(ops[2][0].0.as_str(), "item.name");
    // Small enough: one op, the rewrite first.
    let ops = split_order_ops(vec![order_write(1)], vec![order_write(2)]);
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0].len(), 2);
    assert!(split_order_ops(Vec::new(), Vec::new()).is_empty());
}
