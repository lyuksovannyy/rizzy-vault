// SPDX-License-Identifier: AGPL-3.0-only

//! ADR 0050 end to end: `rizzy-client` against the real server over HTTP, with a Fetch page
//! budget small enough that every page holds one op (and the covers of its bodiless headers,
//! ADR 0021 §4), after `worker` compacted the item. A tombstone cover then reaches a new device
//! in a page before the header of the Purge it records, on another device's chain: the client
//! holds it across the pages in between and takes it once the purge arrives (ADR 0050 §2).

use chacha20::ChaCha20Rng;
use chacha20::rand_core::SeedableRng as _;
use rizzy_client::items::ItemLifecycle;
use rizzy_server::worker::run_once;

use crate::common::{Server, block_on};
use crate::rotation::{Client, enrol, signup};

#[test]
fn a_new_device_takes_a_tombstone_served_pages_before_its_purge() {
    block_on(async {
        // A budget of one byte: each page takes its first op and that op's covers only.
        let server = Server::start_with_page_bytes(1).await;
        let mut rng = ChaCha20Rng::seed_from_u64(0x50);
        let (up, sk, _) = signup(&server, &mut rng, false).await;
        let mut first = Client::signed_up(&server, up).await;
        let mut second = Client::enrolled(&server, enrol(&server, &mut rng, &sk).await).await;
        first.refresh(&server).await;
        // The writer is the device with the lower id: the server serves its chain first, so
        // the purger's chain, and the purge, come pages after the writer's headers.
        let (writer, purger) = if first.device_id() < second.device_id() {
            (&mut first, &mut second)
        } else {
            (&mut second, &mut first)
        };
        // The create writes the item key's snapshot; the trash follows; both uploaded.
        let item = writer.create(&mut rng, "doomed");
        assert!(writer.sync(&server, &mut rng).await.is_empty());
        writer.trash(&mut rng, item);
        assert!(writer.sync(&server, &mut rng).await.is_empty());
        // The purger learns both and purges: its tombstone records its own purge.
        assert!(purger.sync(&server, &mut rng).await.is_empty());
        purger.purge(&mut rng, item);
        assert!(purger.sync(&server, &mut rng).await.is_empty());
        assert_eq!(purger.lifecycle(item), ItemLifecycle::Purged);
        assert!(writer.sync(&server, &mut rng).await.is_empty());
        // `worker` deletes the body the writer's snapshot and the tombstone both cover.
        let db = &server.services.db;
        let mut leader = db.try_lead_worker().await.unwrap().unwrap();
        let report = run_once(&server.services.api, db, None, &mut leader).await;
        leader.release().await.unwrap();
        assert!(report.bodies_deleted > 0, "{report:?}");

        // A third device fetches page by page.
        let mut reader = Client::enrolled(&server, enrol(&server, &mut rng, &sk).await).await;
        let totals = reader.fetch_counting(&server).await;
        assert!(totals.pages > 2, "{totals:?}");
        assert!(
            totals.held_covers > 0,
            "the tombstone was not held: {totals:?}"
        );
        assert_eq!(totals.refused_covers, 0, "{totals:?}");
        assert!(totals.reports.is_empty(), "{totals:?}");
        assert_eq!(reader.lifecycle(item), ItemLifecycle::Purged);
    });
}
