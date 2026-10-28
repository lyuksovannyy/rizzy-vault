// SPDX-License-Identifier: AGPL-3.0-only

//! A paged Fetch that splits a tombstone cover from its recorded purge (ADR 0050 §2, §4;
//! HANDOFF gap 14), through `VaultSync::apply_fetch` against the fake server paging at
//! `Server::page_len` ops: the cover is held across pages, taken by the retry once the purge
//! header arrives, made moot by a later cover, or given up when the response sequence completes
//! without the purge.

use rizzy_sync::causal::{GapCause, Report};
use rizzy_sync::dot::Dot;

use super::*;

/// A writer that created, trashed and purged one item, and uploaded every op and its
/// snapshots (the purge's tombstone among them), with a second, enrolled device's account;
/// the fake server compacts: every op its stored snapshots cover is served bodiless.
fn purged() -> (
    Server,
    VaultSync,
    DeviceId,
    crate::login::Enrolled,
    Authors,
    ItemId,
) {
    let mut rng = ChaCha20Rng::seed_from_u64(50);
    let mut server = Server::new(51);
    let a = signup(&mut server, &mut rng, DeviceKind::DesktopCli);
    let sk = secret_key_text(a.device.as_ref().unwrap());
    let b = login_and_enrol(&mut server, &mut rng, &sk);
    let authors = Authors::from_account(&b.account).unwrap();
    let (mut writer, unlocked, items) = synced_writer(&mut server, &mut rng, a, &authors, 1);
    let device = unlocked.device_id;
    let item = items[0];
    writer
        .trash_item(&mut rng, &unlocked, item, T0 + 10)
        .unwrap();
    writer
        .purge_item(&mut rng, &unlocked, item, T0 + 11)
        .unwrap();
    while let Some(up) = writer.upload_request(&mut rng, &unlocked).unwrap() {
        let answer = server.upload(&up);
        let outcome = writer.apply_upload_response(&answer).unwrap();
        assert!(outcome.rejected.is_empty(), "{outcome:?}");
    }
    assert_eq!(writer.item_lifecycle(item), ItemLifecycle::Purged);
    // The writer's chain: create, trash, purge.
    assert_eq!(writer.next_device_seq(), 4);
    server.compact = true;
    (server, writer, device, b, authors, item)
}

/// A reader on `b`'s vault key, with nothing fetched yet.
fn reader(b: &mut crate::login::Enrolled, writer: &VaultSync) -> VaultSync {
    let key = b.account.take_vault_key(writer.vault_id()).unwrap();
    VaultSync::new(key, &b.unlocked, 1).unwrap()
}

/// ADR 0050 §4, the exact boundary case: page 1 serves create and trash bodiless with the
/// tombstone, whose recorded purge is above the page's cut; page 2 serves the purge with its
/// body (not compacted yet) and no cover. Before ADR 0050 page 1 ended in a gap and the cursor
/// never moved; now the cover is held and the retry after page 2 takes it.
#[test]
fn a_tombstone_cover_split_from_its_purge_is_held_and_then_taken() {
    let (mut server, writer, a, mut b, authors, item) = purged();
    let mut r = reader(&mut b, &writer);
    server.page_len = 2;
    let page1 = server.fetch(&r.fetch_request().unwrap());
    assert!(!page1.complete);
    assert_eq!(page1.ops.as_slice().len(), 2);
    assert!(page1.ops.as_slice().iter().all(|op| op.body.is_none()));
    assert_eq!(page1.covers.as_slice().len(), 1);
    let out = r.apply_fetch(&authors, &page1, T0 + 20).unwrap();
    assert_eq!(out.held_covers, 1, "{out:?}");
    assert_eq!((out.absorbed, out.refused_covers), (0, 0), "{out:?}");
    assert!(out.reports.is_empty(), "{out:?}");
    // The chain and the cursor went past the held headers; nothing of the item settled.
    assert_eq!(r.cursor_of(a), 2);
    assert_eq!(r.holds_for_tests(item), (vec![item], 1, 0));
    assert!(r.merge(item).unwrap().held_claim().is_some());
    assert!(r.merge(item).unwrap().covered().is_empty());
    // Page 2: the purge with its body.
    server.compact = false;
    let page2 = server.fetch(&r.fetch_request().unwrap());
    assert!(page2.complete);
    assert_eq!(page2.ops.as_slice().len(), 1);
    assert!(page2.covers.as_slice().is_empty());
    let out = r.apply_fetch(&authors, &page2, T0 + 21).unwrap();
    assert_eq!(out.held_covers, 0, "{out:?}");
    assert_eq!((out.absorbed, out.refused_covers), (1, 0), "{out:?}");
    assert!(out.reports.is_empty(), "{out:?}");
    assert_eq!(r.cursor_of(a), 3);
    assert_eq!(
        r.merge(item).unwrap().covered(),
        writer.merge(item).unwrap().covered()
    );
    assert_eq!(r.item_lifecycle(item), ItemLifecycle::Purged);
    // The taken cover is held for a healing request like any absorbed one.
    assert_eq!(r.holds_for_tests(item), (vec![], 0, 1));
    assert!(r.merge(item).unwrap().held_claim().is_none());
    // The next Fetch finds nothing new.
    let again = server.fetch(&r.fetch_request().unwrap());
    assert!(again.ops.as_slice().is_empty());
}

/// The same split with the purge compacted too: page 2 brings the purge bodiless with the
/// tombstone again, which the merge takes, and the held cover is moot.
#[test]
fn a_held_cover_a_later_page_takes_again_is_moot() {
    let (mut server, writer, _, mut b, authors, item) = purged();
    let mut r = reader(&mut b, &writer);
    server.page_len = 2;
    let out = r
        .apply_fetch(
            &authors,
            &server.fetch(&r.fetch_request().unwrap()),
            T0 + 20,
        )
        .unwrap();
    assert_eq!(out.held_covers, 1, "{out:?}");
    let page2 = server.fetch(&r.fetch_request().unwrap());
    assert!(page2.complete);
    let out = r.apply_fetch(&authors, &page2, T0 + 21).unwrap();
    assert_eq!((out.absorbed, out.refused_covers), (1, 0), "{out:?}");
    assert!(out.reports.is_empty(), "{out:?}");
    assert_eq!(r.item_lifecycle(item), ItemLifecycle::Purged);
    assert_eq!(r.holds_for_tests(item), (vec![], 0, 1));
    assert!(r.merge(item).unwrap().held_claim().is_none());
}

/// ADR 0050 §4, the regression: the response sequence completes without the recorded purge
/// (here the server lost it). The hold resolves to the same final refusal and gap as before ADR
/// 0050, the cursor drops below the held headers, and the next Fetch serves them again.
#[test]
fn a_hold_the_response_never_resolves_is_reported_when_it_completes() {
    let (mut server, writer, a, mut b, authors, item) = purged();
    server.ops.get_mut(&a.to_bytes()).unwrap().remove(&3);
    let mut r = reader(&mut b, &writer);
    server.page_len = 2;
    let page = server.fetch(&r.fetch_request().unwrap());
    assert!(page.complete);
    let out = r.apply_fetch(&authors, &page, T0 + 20).unwrap();
    assert_eq!(out.held_covers, 1, "{out:?}");
    assert_eq!((out.absorbed, out.refused_covers), (0, 1), "{out:?}");
    let first = Dot::new(a, 1).unwrap();
    assert!(
        out.reports.contains(&Report::Gap {
            device: a,
            after: 0,
            cause: GapCause::Uncovered { dot: first },
        }),
        "{out:?}"
    );
    assert_eq!(r.item_lifecycle(item), ItemLifecycle::Absent);
    assert_eq!(r.holds_for_tests(item), (vec![], 0, 0));
    assert!(r.merge(item).unwrap().held_claim().is_none());
    // The cursor dropped below the lapsed headers: the next Fetch serves them again.
    assert_eq!(r.cursor_of(a), 0);
    let again = server.fetch(&r.fetch_request().unwrap());
    assert_eq!(again.ops.as_slice().len(), 2);
    let out = r.apply_fetch(&authors, &again, T0 + 30).unwrap();
    assert_eq!((out.held_covers, out.refused_covers), (1, 1), "{out:?}");
}

/// ADR 0109 §2 C5: a healing request is refused with [`ClientError::FetchRequired`] while a
/// hold is open in the running `VaultSync`. The derived cursor passes a held link only for
/// the next page of its own sequence; a healing request's cursor is not that cursor, so the
/// range it would build could name a header the device holds no body for.
#[test]
fn adr_0109_c5_healing_request_is_refused_while_a_hold_is_open() {
    let (mut server, writer, _a, mut b, authors, item) = purged();
    let mut r = reader(&mut b, &writer);
    server.page_len = 2;
    // Page 1 opens a hold: the first two bodiless ops arrive with a cover whose recorded
    // purge is above the page's cut (ADR 0050 §4), and `pending_covers` is nonempty.
    let page1 = server.fetch(&r.fetch_request().unwrap());
    assert!(!page1.complete);
    let out = r.apply_fetch(&authors, &page1, T0 + 20).unwrap();
    assert_eq!(out.held_covers, 1, "{out:?}");
    assert_eq!(r.holds_for_tests(item).1, 1, "pending_covers nonempty");
    // No healing is needed yet: with the sequence open and nothing wrong, the request is
    // just `Ok(None)`.
    assert!(r.healing_request().unwrap().is_none());
    // Fake a "server behind" verdict to force `needs_healing` to true mid-sequence. Without
    // the C5 guard, `healing_request` would build its ranges from the derived cursor, which
    // passes the held link only for the next page of this sequence.
    r.set_server_behind_for_tests(true);
    assert!(r.needs_healing());
    assert_eq!(
        r.healing_request().unwrap_err(),
        ClientError::FetchRequired,
        "C5: no healing while a hold is open",
    );
    // The host clears the state the usual way (complete the sequence or load from the cache),
    // and the guard releases.
    r.set_server_behind_for_tests(false);
    server.compact = false;
    let page2 = server.fetch(&r.fetch_request().unwrap());
    assert!(page2.complete);
    let out = r.apply_fetch(&authors, &page2, T0 + 21).unwrap();
    assert_eq!(out.held_covers, 0, "{out:?}");
    assert_eq!(r.holds_for_tests(item).1, 0);
    assert!(r.healing_request().unwrap().is_none(), "no hold, no need");
}
