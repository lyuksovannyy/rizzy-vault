//! The worker on `SQLite` (ADR 0010 §2): the writer lock the database holds makes this process
//! the only writer, so the worker leads at once, stays leading across runs, and runs every step.

use rizzy_server::worker::{RunReport, run_once};
use rizzy_storage::Engine;

use crate::common::{Server, block_on};

#[test]
fn sqlite_worker_leads_and_runs() {
    block_on(async {
        let server = Server::start().await;
        let db = &server.services.db;
        let mut leader = db.try_lead_worker().await.unwrap().unwrap();
        assert_eq!(leader.engine(), Engine::Sqlite);
        for _ in 0..2 {
            let report = run_once(&server.services.api, db, None, &mut leader).await;
            assert_eq!(
                report,
                RunReport::default(),
                "an empty database: nothing to do"
            );
            assert!(!report.leadership_lost);
        }
        assert!(leader.is_held().await.unwrap());
        leader.release().await.unwrap();
    });
}
