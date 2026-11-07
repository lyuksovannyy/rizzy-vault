// SPDX-License-Identifier: AGPL-3.0-only

//! The per-account security event log (ADR 0090 §14 step 3): each flow writes exactly its row
//! with exactly its fields, refusals write nothing (except codes 3 and 21), nothing is written
//! before KE3, the caps, the age purge, the start-up check of the recovery wait, paging and the
//! alert summary. The flow tests run on PostgreSQL too when `RIZZY_TEST_POSTGRES_URL` is set.

use rizzy_core::secret_key::SecretKey;
use rizzy_core::totp::{TotpParams, TotpSecret};
use rizzy_domain_auth::{AuthError, EVENT_RETENTION_MS, EVENTS_PER_CLASS};
use rizzy_proto::account::AccountStateQuery;
use rizzy_proto::security_event::{
    SecurityEventCursor, SecurityEventKind, SecurityEventListRequest,
};
use rizzy_proto::webauthn::{WebauthnCredentialId, WebauthnRemoveRequest};
use rizzy_storage::Database;

use crate::common::{Env, block_on};
use crate::requests::password_change;
use crate::revocation::enrol as enrol_device;
use crate::revocation_window::{device_session, reauth};
use crate::webauthn::{SoftKey, UP, enrol as enrol_key, login_with};

/// 72 h in ms: the default recovery wait.
const WAIT: u64 = 72 * 3_600_000;

/// Actor kinds of ADR 0090 §4.
const OPAQUE: i64 = 1;
const DEVICE: i64 = 2;
const RECOVERY_CODE: i64 = 4;
const SIGN_IN: i64 = 5;
const SERVER: i64 = 8;

/// One stored row, without its id and time.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Ev {
    kind: i64,
    class: i64,
    actor: i64,
    actor_device: Option<Vec<u8>>,
    subject: Option<Vec<u8>>,
    label: Option<String>,
    old: Option<i64>,
    new: Option<i64>,
    seq: Option<i64>,
}

/// A row of `kind` by `actor` with no other field.
fn ev(kind: i64, class: i64, actor: i64) -> Ev {
    Ev {
        kind,
        class,
        actor,
        actor_device: None,
        subject: None,
        label: None,
        old: None,
        new: None,
        seq: None,
    }
}

type Row = (
    i64,
    i64,
    i64,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
);

/// Every row of the table, oldest first. The admin column must always be NULL here.
async fn rows(db: &Database) -> Vec<Ev> {
    let mut tx = db.begin_write().await.unwrap();
    let admin: i64 = rizzy_storage::on_engine!(tx.conn(), |c| sqlx::query_scalar(
        "SELECT COUNT(*) FROM auth_security_events WHERE actor_admin_id IS NOT NULL"
    )
    .fetch_one(&mut *c)
    .await
    .unwrap());
    assert_eq!(admin, 0);
    let all: Vec<Row> = rizzy_storage::on_engine!(tx.conn(), |c| sqlx::query_as(
        "SELECT kind, class, actor_kind, actor_device_id, subject_device_id, label, value_old, \
         value_new, state_seq FROM auth_security_events ORDER BY at_ms, event_id"
    )
    .fetch_all(&mut *c)
    .await
    .unwrap());
    tx.commit().await.unwrap();
    all.into_iter()
        .map(
            |(kind, class, actor, actor_device, subject, label, old, new, seq)| Ev {
                kind,
                class,
                actor,
                actor_device,
                subject,
                label,
                old,
                new,
                seq,
            },
        )
        .collect()
}

/// The rows written since `before` rows existed.
async fn since(db: &Database, before: usize) -> Vec<Ev> {
    rows(db).await.split_off(before)
}

/// Runs one statement with integer and blob binds.
async fn exec(db: &Database, sql: &'static str, blob: &[u8], ints: &[i64]) {
    let mut tx = db.begin_write().await.unwrap();
    rizzy_storage::on_engine!(tx.conn(), |c| {
        let mut q = sqlx::query(sql).bind(blob.to_vec());
        for i in ints {
            q = q.bind(*i);
        }
        q.execute(&mut *c).await.map(|_| ()).unwrap();
    });
    tx.commit().await.unwrap();
}

/// Runs one statement without binds.
async fn exec_plain(db: &Database, sql: &'static str) {
    let mut tx = db.begin_write().await.unwrap();
    rizzy_storage::on_engine!(tx.conn(), |c| sqlx::query(sql)
        .execute(&mut *c)
        .await
        .map(|_| ())
        .unwrap());
    tx.commit().await.unwrap();
}

/// Inserts a row directly: id `n`, `kind`/`class` at `at_ms`, by the server.
async fn insert(db: &Database, account: &[u8], n: u64, at_ms: i64, kind: i64, class: i64) {
    let mut id = [0x77u8; 16];
    id[8..].copy_from_slice(&n.to_be_bytes());
    let mut tx = db.begin_write().await.unwrap();
    rizzy_storage::on_engine!(tx.conn(), |c| sqlx::query(
        "INSERT INTO auth_security_events (event_id, account_id, at_ms, kind, class, actor_kind) \
         VALUES ($1, $2, $3, $4, $5, 8)"
    )
    .bind(id.to_vec())
    .bind(account.to_vec())
    .bind(at_ms)
    .bind(kind)
    .bind(class)
    .execute(&mut *c)
    .await
    .map(|_| ())
    .unwrap());
    tx.commit().await.unwrap();
}

/// The server's TOTP code for `secret` at `now_ms`.
fn code_at(secret: &TotpSecret, now_ms: u64) -> String {
    TotpParams::DEFAULT
        .code_at(secret, now_ms / 1000)
        .unwrap()
        .to_digits()
        .to_string()
}

fn wait_ms() -> i64 {
    i64::try_from(WAIT).unwrap()
}

#[test]
fn signup_and_logins_write_codes_1_and_2_and_failed_logins_nothing() {
    block_on(async {
        let mut env = Env::on_either_engine(9001, |_| {}).await;
        let client = env.signup("ana", "pw").await;
        let mut created = ev(1, 1, SIGN_IN);
        created.new = Some(wait_ms());
        assert_eq!(rows(&env.db).await, vec![created]);

        // A plain login: code 2, second factor 0, no device.
        env.login(&client).await;
        let mut login = ev(2, 1, SIGN_IN);
        login.new = Some(0);
        assert_eq!(since(&env.db, 1).await, vec![login.clone()]);

        // Nothing before KE3 (§3): a wrong password and an unknown name write nothing.
        let sk = &client.secret_key;
        assert!(env.login_as("ana", "wrong", sk, None, None).await.is_err());
        assert!(env.login_as("nobody", "pw", sk, None, None).await.is_err());
        let other = SecretKey::generate(&mut env.rng);
        assert!(env.login_as("ana", "pw", &other, None, None).await.is_err());
        assert_eq!(rows(&env.db).await.len(), 2);

        // A re-authentication from a device session names its device.
        let (_, fresh) = reauth(&mut env, &client, 0).await;
        let mut bound = login;
        bound.actor_device = Some(client.devices[0].id.as_bytes().to_vec());
        assert_eq!(since(&env.db, 2).await, vec![bound]);
        assert!(fresh.device_id.is_some());
    });
}

#[test]
fn totp_writes_17_3_2_and_18_and_a_round_without_a_code_nothing() {
    block_on(async {
        let mut env = Env::on_either_engine(9002, |_| {}).await;
        let client = env.signup("tom", "pw").await;
        let (name, password, sk) = (
            client.name.clone(),
            client.password.clone(),
            &client.secret_key,
        );
        let login = env.login(&client).await;
        let fresh = env.bearer(&login.response.session_token).await;
        let enrolment = env
            .svc
            .totp_enrol_start(&mut env.rng, &fresh, env.now)
            .await
            .unwrap();
        // A refused confirmation writes nothing.
        let before = rows(&env.db).await.len();
        assert!(
            env.svc
                .totp_enrol_confirm(&fresh, 1, "000000", env.now)
                .await
                .is_err()
        );
        assert_eq!(rows(&env.db).await.len(), before);
        env.svc
            .totp_enrol_confirm(&fresh, 1, &code_at(&enrolment.secret, env.now), env.now)
            .await
            .unwrap();
        assert_eq!(since(&env.db, before).await, vec![ev(17, 2, OPAQUE)]);

        // No code: the normal first round writes nothing.
        let n = rows(&env.db).await.len();
        assert!(matches!(
            env.login_as(&name, &password, sk, None, None).await,
            Err(AuthError::SecondFactorRequired)
        ));
        assert_eq!(rows(&env.db).await.len(), n);
        // A wrong code after KE3: code 3, TOTP, committed with the refusal.
        assert!(
            env.login_as(&name, &password, sk, Some("000000"), None)
                .await
                .is_err()
        );
        let mut failed = ev(3, 2, SIGN_IN);
        failed.new = Some(1);
        assert_eq!(since(&env.db, n).await, vec![failed]);
        // The right code: code 2 with TOTP.
        env.tick(30_000);
        let code = code_at(&enrolment.secret, env.now);
        let ok = env
            .login_as(&name, &password, sk, Some(&code), None)
            .await
            .unwrap();
        let mut login = ev(2, 1, SIGN_IN);
        login.new = Some(1);
        assert_eq!(since(&env.db, n + 1).await, vec![login]);

        let fresh = env.bearer(&ok.response.session_token).await;
        env.tick(30_000);
        env.svc
            .totp_disable(&fresh, &code_at(&enrolment.secret, env.now), env.now)
            .await
            .unwrap();
        assert_eq!(since(&env.db, n + 2).await, vec![ev(18, 2, OPAQUE)]);
    });
}

#[test]
fn devices_write_4_5_and_6_and_a_password_change_8() {
    block_on(async {
        let mut env = Env::on_either_engine(9003, |_| {}).await;
        let mut client = env.signup("dev", "pw").await;
        let n = rows(&env.db).await.len();
        let device = enrol_device(&mut env, &mut client).await;
        let new_id = device.id.as_bytes().to_vec();
        client.devices.push(device);
        let all = since(&env.db, n).await;
        let mut enrolled = ev(4, 2, OPAQUE);
        enrolled.subject = Some(new_id.clone());
        enrolled.new = Some(1);
        assert_eq!(all.last(), Some(&enrolled), "{all:?}");

        // A suspension by device 0's fresh re-authentication, then its lifting.
        let (_, fresh) = reauth(&mut env, &client, 0).await;
        let n = rows(&env.db).await.len();
        env.svc
            .suspend_device(&fresh, client.devices[1].id, env.now)
            .await
            .unwrap();
        let mut suspended = ev(5, 1, OPAQUE);
        suspended.actor_device = Some(client.devices[0].id.as_bytes().to_vec());
        suspended.subject = Some(new_id.clone());
        assert_eq!(since(&env.db, n).await, vec![suspended.clone()]);
        // A repeat suspends nothing new and writes nothing.
        env.svc
            .suspend_device(&fresh, client.devices[1].id, env.now)
            .await
            .unwrap();
        assert_eq!(rows(&env.db).await.len(), n + 1);
        env.svc
            .unsuspend_device(&fresh, client.devices[1].id, env.now)
            .await
            .unwrap();
        let mut lifted = suspended;
        lifted.kind = 6;
        lifted.class = 2;
        assert_eq!(since(&env.db, n + 1).await, vec![lifted]);

        // A password change: code 8 with the new state_seq; the server cannot tell the
        // password from the Secret Key (code 8 says both).
        let login = env.login(&client).await;
        let session = env.bearer(&login.response.session_token).await;
        let new_sk = SecretKey::generate(&mut env.rng);
        let (commit, next) = password_change(&mut env, &client, &session, "new-pw", &new_sk).await;
        let n = rows(&env.db).await.len();
        env.svc
            .commit_change_request(&session, commit, env.now)
            .await
            .unwrap();
        let mut changed = ev(8, 2, OPAQUE);
        changed.seq = Some(i64::try_from(next.0.state_seq).unwrap());
        assert_eq!(since(&env.db, n).await, vec![changed]);
    });
}

#[test]
fn recovery_writes_13_14_and_15_and_a_wrong_code_nothing() {
    block_on(async {
        let mut env = Env::on_either_engine(9004, |_| {}).await;
        let client = env.signup("rec", "pw").await;
        let token = client.recovery_token();
        let source = env.source.clone();
        let n = rows(&env.db).await.len();
        // A wrong recovery code writes nothing.
        assert!(
            env.svc
                .recovery_start("rec", &[7; 32], &source, env.now)
                .await
                .is_err()
        );
        assert!(
            env.svc
                .recovery_start("nobody", &token, &source, env.now)
                .await
                .is_err()
        );
        assert_eq!(rows(&env.db).await.len(), n);
        env.svc
            .recovery_start("rec", &token, &source, env.now)
            .await
            .unwrap();
        let mut started = ev(13, 2, RECOVERY_CODE);
        started.new = Some(i64::try_from(env.now + WAIT).unwrap());
        assert_eq!(since(&env.db, n).await, vec![started.clone()]);
        // A repeat opens nothing and writes nothing.
        env.svc
            .recovery_start("rec", &token, &source, env.now)
            .await
            .unwrap();
        assert_eq!(rows(&env.db).await.len(), n + 1);

        // A device cancels it: code 14 by its device session; a second cancel writes nothing.
        let (_, device) = device_session(&mut env, &client, 0).await;
        assert!(env.svc.recovery_cancel(&device, env.now).await.unwrap());
        let mut cancelled = ev(14, 1, DEVICE);
        cancelled.actor_device = Some(client.devices[0].id.as_bytes().to_vec());
        assert_eq!(since(&env.db, n + 1).await, vec![cancelled]);
        assert!(!env.svc.recovery_cancel(&device, env.now).await.unwrap());
        assert_eq!(rows(&env.db).await.len(), n + 2);

        // Started again and released after the wait: each release writes code 15.
        env.svc
            .recovery_start("rec", &token, &source, env.now)
            .await
            .unwrap();
        env.tick(WAIT);
        for _ in 0..2 {
            env.svc
                .recovery_complete(&mut env.rng, "rec", &token, &source, env.now)
                .await
                .unwrap();
        }
        let tail = since(&env.db, n + 3).await;
        assert_eq!(
            tail,
            vec![ev(15, 2, RECOVERY_CODE), ev(15, 2, RECOVERY_CODE)]
        );
    });
}

#[test]
fn ending_sessions_writes_22_and_23_only_when_something_ended() {
    block_on(async {
        let mut env = Env::on_either_engine(9005, |_| {}).await;
        let client = env.signup("ses", "pw").await;
        let a = env.login(&client).await;
        let a = env.bearer(&a.response.session_token).await;
        let b = env.login(&client).await;
        let b = env.bearer(&b.response.session_token).await;
        env.login(&client).await;
        let n = rows(&env.db).await.len();
        env.svc
            .end_session(&a, b.session_id, env.now)
            .await
            .unwrap();
        let mut ended = ev(22, 1, OPAQUE);
        ended.new = Some(1);
        assert_eq!(since(&env.db, n).await, vec![ended]);
        env.svc.end_other_sessions(&a, env.now).await.unwrap();
        let mut others = ev(23, 1, OPAQUE);
        others.new = Some(1);
        assert_eq!(since(&env.db, n + 1).await, vec![others]);
        // Nothing left to end: nothing written. sessions/current/end is never logged.
        env.svc.end_other_sessions(&a, env.now).await.unwrap();
        env.svc.end_current_session(&a, env.now).await.unwrap();
        assert_eq!(rows(&env.db).await.len(), n + 2);
    });
}

#[test]
fn a_refused_counter_writes_a_possible_clone_entry() {
    // ADR 0090 §13 (INV-83's event-log test), with codes 19, 2 and 20 around it: the key stays
    // enrolled after the refusal (its removal below succeeds).
    block_on(async {
        let mut env = Env::on_either_engine(9006, |_| {}).await;
        let client = env.signup("key", "pw").await;
        let login = env.login(&client).await;
        let fresh = env.bearer(&login.response.session_token).await;
        let key = SoftKey::new(&mut env, 3);
        let n = rows(&env.db).await.len();
        enrol_key(&mut env, &fresh, &key, UP, "YubiKey 5C")
            .await
            .unwrap();
        let mut added = ev(19, 2, OPAQUE);
        added.label = Some("YubiKey 5C".into());
        assert_eq!(since(&env.db, n).await, vec![added.clone()]);

        login_with(&mut env, &client, &key, UP, 6).await.unwrap();
        let mut login = ev(2, 1, SIGN_IN);
        login.new = Some(2);
        assert_eq!(since(&env.db, n + 1).await, vec![login]);

        // INV-83's fourth case: code 21 with the stored and the received counter.
        assert!(matches!(
            login_with(&mut env, &client, &key, UP, 3).await,
            Err(AuthError::PossibleClone { .. })
        ));
        let mut clone = ev(21, 2, SIGN_IN);
        clone.label = Some("YubiKey 5C".into());
        clone.old = Some(6);
        clone.new = Some(3);
        assert_eq!(since(&env.db, n + 2).await, vec![clone]);

        // The removal names the removed key; an unknown key writes nothing.
        let response = login_with(&mut env, &client, &key, UP, 7).await.unwrap();
        let fresh = env.bearer(&response.session_token).await;
        let m = rows(&env.db).await.len();
        let unknown = WebauthnRemoveRequest {
            credential_id: WebauthnCredentialId::new(vec![9; 32]).unwrap(),
        };
        assert!(
            env.svc
                .webauthn_remove(&fresh, &unknown, env.now)
                .await
                .is_err()
        );
        assert_eq!(rows(&env.db).await.len(), m);
        let mine = WebauthnRemoveRequest {
            credential_id: WebauthnCredentialId::new(key.cred_id.clone()).unwrap(),
        };
        env.svc
            .webauthn_remove(&fresh, &mine, env.now)
            .await
            .unwrap();
        let mut removed = added;
        removed.kind = 20;
        assert_eq!(since(&env.db, m).await, vec![removed]);
    });
}

#[test]
fn the_cap_trims_its_own_class_and_keeps_the_wait_in_force() {
    block_on(async {
        let mut env = Env::on_either_engine(9007, |_| {}).await;
        let client = env.signup("cap", "pw").await;
        let account = client.account_id.as_bytes().to_vec();
        // The oldest alert is a code 24 (a shortened wait): the newest code 1/24 row, so it
        // stays. Then 499 more alerts and 10 info rows, all older than now.
        exec_plain(&env.db, "DELETE FROM auth_security_events").await;
        insert(&env.db, &account, 1, 1, 24, 2).await;
        for n in 0..500 {
            insert(
                &env.db,
                &account,
                10 + n,
                2 + i64::try_from(n).unwrap(),
                6,
                2,
            )
            .await;
        }
        for n in 0..10 {
            insert(&env.db, &account, 1_000 + n, 1, 22, 1).await;
        }
        // The 502nd alert (a TOTP enrolment) trims the oldest alert that is not exempt.
        let login = env.login(&client).await;
        let fresh = env.bearer(&login.response.session_token).await;
        let enrolment = env
            .svc
            .totp_enrol_start(&mut env.rng, &fresh, env.now)
            .await
            .unwrap();
        env.svc
            .totp_enrol_confirm(&fresh, 1, &code_at(&enrolment.secret, env.now), env.now)
            .await
            .unwrap();
        let all = rows(&env.db).await;
        let alerts: Vec<&Ev> = all.iter().filter(|e| e.class == 2).collect();
        assert_eq!(
            alerts.len(),
            usize::try_from(EVENTS_PER_CLASS).unwrap() + 1,
            "500 newest plus the exempt code 24"
        );
        assert!(alerts.iter().any(|e| e.kind == 24));
        assert_eq!(alerts.iter().filter(|e| e.kind == 6).count(), 499);
        // Info rows are untouched by an alert insert (11: ten plus the login).
        assert_eq!(all.iter().filter(|e| e.class == 1).count(), 11);
    });
}

#[test]
fn the_worker_purges_by_age_and_trims_bulk_rows() {
    block_on(async {
        let mut env = Env::on_either_engine(9008, |_| {}).await;
        let client = env.signup("old", "pw").await;
        let account = client.account_id.as_bytes().to_vec();
        // The signup's code 1 row is the account's only code 1/24 row.
        for n in 0..600 {
            insert(&env.db, &account, 10 + n, 0, 2, 1).await;
        }
        env.tick(EVENT_RETENTION_MS + 1);
        let purged = env.svc.purge_expired(env.now).await.unwrap();
        // Every old row goes except the code 1 row (the wait in force).
        assert_eq!(purged.security_events, 600);
        let left = rows(&env.db).await;
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].kind, 1);
        // Bulk rows above the cap, all young: the purge trims them to 500.
        let now = i64::try_from(env.now).unwrap();
        for n in 0..520 {
            insert(&env.db, &account, 10_000 + n, now, 2, 1).await;
        }
        let purged = env.svc.purge_expired(env.now).await.unwrap();
        assert_eq!(
            purged.security_events, 20,
            "520 + the code 1 row, down to 500 + exempt"
        );
        assert_eq!(rows(&env.db).await.len(), 501);
        assert!(rows(&env.db).await.iter().any(|e| e.kind == 1));
    });
}

#[test]
fn a_recovery_wait_change_writes_one_entry_per_account() {
    // ADR 0090 §13 (INV-69's event-log test), on the configuration path (§6 point 2); the
    // panel and CLI paths land with ADR 0086.
    block_on(async {
        let mut env = Env::on_either_engine(9009, |_| {}).await;
        let a = env.signup("one", "pw").await;
        env.signup("two", "pw").await;
        // Both code 1 rows state the wait in force: nothing to write.
        assert_eq!(env.svc.check_recovery_wait(env.now).await.unwrap(), 0);
        // An account with no code 1/24 row (as after migration 0015): value_old NULL, info.
        exec(
            &env.db,
            "DELETE FROM auth_security_events WHERE account_id = $1",
            a.account_id.as_bytes(),
            &[],
        )
        .await;
        let n = rows(&env.db).await.len();
        assert_eq!(env.svc.check_recovery_wait(env.now).await.unwrap(), 1);
        let mut first = ev(24, 1, SERVER);
        first.new = Some(wait_ms());
        assert_eq!(since(&env.db, n).await, vec![first]);
        // A restart with an unchanged wait writes nothing; a shorter one writes old -> new for
        // every account, as an alert.
        assert_eq!(env.svc.check_recovery_wait(env.now).await.unwrap(), 0);
        let db = env.db.clone();
        env.reopen(db, |c| c.recovery_wait_ms = 3_600_000);
        assert_eq!(env.svc.check_recovery_wait(env.now).await.unwrap(), 2);
        let mut shorter = ev(24, 2, SERVER);
        shorter.old = Some(wait_ms());
        shorter.new = Some(3_600_000);
        assert_eq!(since(&env.db, n + 1).await, vec![shorter.clone(), shorter]);
        // A longer one is info.
        let db = env.db.clone();
        env.reopen(db, |c| c.recovery_wait_ms = WAIT);
        assert_eq!(env.svc.check_recovery_wait(env.now).await.unwrap(), 2);
        assert!(since(&env.db, n + 3).await.iter().all(|e| e.class == 1));
    });
}

#[test]
fn listing_pages_once_through_every_row_and_only_the_callers() {
    block_on(async {
        let mut env = Env::on_either_engine(9010, |_| {}).await;
        let client = env.signup("lst", "pw").await;
        let other = env.signup("oth", "pw").await;
        let account = client.account_id.as_bytes().to_vec();
        // 250 rows, some sharing a time (the id breaks the tie), and one unknown kind.
        for n in 0..250_u64 {
            insert(&env.db, &account, n, i64::try_from(n / 2).unwrap(), 2, 1).await;
        }
        insert(&env.db, &account, 9_999, 300, 999, 2).await;
        let login = env.login(&client).await;
        let session = env.bearer(&login.response.session_token).await;
        let mut seen = Vec::new();
        let mut before = None;
        loop {
            let page = env
                .svc
                .list_security_events(
                    &session,
                    &SecurityEventListRequest {
                        before,
                        limit: Some(100),
                    },
                )
                .await
                .unwrap();
            assert!(page.events.as_slice().len() <= 100);
            seen.extend(page.events.as_slice().iter().cloned());
            let Some(last) = page.events.as_slice().last() else {
                break;
            };
            before = Some(SecurityEventCursor {
                at_ms: last.at_ms,
                event_id: last.event_id,
            });
            if !page.more {
                break;
            }
        }
        // 250 inserted + the signup's code 1 + the login's code 2; the unknown kind skipped.
        assert_eq!(seen.len(), 252);
        let mut keys: Vec<_> = seen
            .iter()
            .map(|e| (e.at_ms, e.event_id.to_bytes()))
            .collect();
        let sorted = {
            let mut k = keys.clone();
            k.sort_unstable_by(|a, b| b.cmp(a));
            k
        };
        assert_eq!(keys, sorted, "newest first, (at_ms, event_id) descending");
        keys.dedup();
        assert_eq!(keys.len(), 252, "each row once");
        assert!(seen.iter().all(|e| e.kind != SecurityEventKind::Unknown));

        // Another account sees only its own rows.
        let theirs = env.login(&other).await;
        let theirs = env.bearer(&theirs.response.session_token).await;
        let page = env
            .svc
            .list_security_events(
                &theirs,
                &SecurityEventListRequest {
                    before: None,
                    limit: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(page.events.as_slice().len(), 2);
        assert!(!page.more);
        // Out-of-range limits are refused.
        for limit in [0, 101] {
            assert!(matches!(
                env.svc
                    .list_security_events(
                        &session,
                        &SecurityEventListRequest {
                            before: None,
                            limit: Some(limit)
                        }
                    )
                    .await,
                Err(AuthError::InvalidRequest)
            ));
        }
    });
}

#[test]
fn the_recovery_session_cannot_list_and_the_summary_shows_recent_alerts() {
    block_on(async {
        let mut env = Env::on_either_engine(9011, |_| {}).await;
        let client = env.signup("sum", "pw").await;
        let token = client.recovery_token();
        let source = env.source.clone();
        let login = env.login(&client).await;
        let session = env.bearer(&login.response.session_token).await;
        let query = AccountStateQuery {
            known_bundle_seq: 1,
            known_settings_seq: 0,
        };
        // Only info rows so far: no summary.
        let view = env
            .svc
            .account_view(&session, query, env.now)
            .await
            .unwrap();
        assert!(view.security_alerts.is_none());
        env.svc
            .recovery_start("sum", &token, &source, env.now)
            .await
            .unwrap();
        env.tick(WAIT);
        let release = env
            .svc
            .recovery_complete(&mut env.rng, "sum", &token, &source, env.now)
            .await
            .unwrap();
        let recovery = env.bearer(&release.session_token).await;
        assert!(matches!(
            env.svc
                .list_security_events(
                    &recovery,
                    &SecurityEventListRequest {
                        before: None,
                        limit: None
                    }
                )
                .await,
            Err(AuthError::Unauthorized)
        ));
        let login = env.login(&client).await;
        let session = env.bearer(&login.response.session_token).await;
        let view = env
            .svc
            .account_view(&session, query, env.now)
            .await
            .unwrap();
        let summary = view.security_alerts.unwrap();
        // Code 13 is exactly 72 h old (outside the window); code 15 is new.
        assert_eq!(summary.count, 1);
        assert_eq!(
            summary.newest_kind,
            SecurityEventKind::RecoverySessionOpened
        );
        assert_eq!(summary.newest_at_ms, env.now);
        env.tick(WAIT);
        let view = env.svc.account_view(&session, query, env.now).await;
        // The session may have expired by now; a fresh login sees no summary either way.
        let _ = view;
        let login = env.login(&client).await;
        let session = env.bearer(&login.response.session_token).await;
        let view = env
            .svc
            .account_view(&session, query, env.now)
            .await
            .unwrap();
        assert!(view.security_alerts.is_none());
    });
}

#[test]
fn a_failed_insert_rolls_back_the_action() {
    block_on(async {
        let mut env = Env::new(9012).await;
        let client = env.signup("rbk", "pw").await;
        let login = env.login(&client).await;
        let session = env.bearer(&login.response.session_token).await;
        let new_sk = SecretKey::generate(&mut env.rng);
        let (commit, _) = password_change(&mut env, &client, &session, "new-pw", &new_sk).await;
        let db = env.db.clone();
        let count = move |sql: &'static str| {
            let db = db.clone();
            async move {
                let mut tx = db.begin_write().await.unwrap();
                let n: i64 = rizzy_storage::on_engine!(tx.conn(), |c| sqlx::query_scalar(sql)
                    .fetch_one(&mut *c)
                    .await
                    .unwrap());
                tx.commit().await.unwrap();
                n
            }
        };
        let state_before = count("SELECT MAX(state_seq) FROM auth_account_states").await;
        let certs_before = count("SELECT COUNT(*) FROM auth_device_certificates").await;
        // Make every insert fail: the action fails closed and leaves nothing behind (§9).
        exec_plain(
            &env.db,
            "CREATE TRIGGER no_events BEFORE INSERT ON auth_security_events \
             BEGIN SELECT RAISE(ABORT, 'no'); END",
        )
        .await;
        assert!(
            env.svc
                .commit_change_request(&session, commit, env.now)
                .await
                .is_err()
        );
        assert_eq!(
            count("SELECT MAX(state_seq) FROM auth_account_states").await,
            state_before
        );
        let device = client.make_device(&mut env.rng, env.now);
        let mut members: Vec<&crate::common::Device> = client.devices.iter().collect();
        members.push(&device);
        let set = client.device_set(&members);
        let next = client.next_state(|s| s.device_set_hash = set);
        let req = rizzy_proto::account::EnrolDeviceRequest {
            device_certificate: crate::common::bytes(device.cert_wire.clone()),
            account_state: crate::common::bytes(next.1.clone()),
        };
        assert!(env.svc.enrol_device(&session, &req, env.now).await.is_err());
        assert_eq!(
            count("SELECT COUNT(*) FROM auth_device_certificates").await,
            certs_before
        );
    });
}
