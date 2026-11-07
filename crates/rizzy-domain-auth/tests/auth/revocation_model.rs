// SPDX-License-Identifier: AGPL-3.0-only

//! The model-based property test of the revocation window ([ADR 0091] §7 test 4).
//!
//! An account with the owner's devices A and B, the stolen device D and a thief who holds the
//! master password and the Secret Key, on SQLite with an injected clock. Each case is up to 40
//! steps (see [`Step`]); a model of the suspensions, revocations, the window and the
//! credentials predicts every answer, and after every step the invariants hold:
//!
//! - **I1**: once D (or the thief's D') is suspended, no session of it exists and it cannot
//!   authenticate (checked on every step for the sessions, in [`Step::DAuth`] for the
//!   authentication).
//! - **I2**: while a window is open, every left-column request from a session not bound to R
//!   is `revocation_pending` and leaves the dump of every backed-up table, the session ids and
//!   the window row as they were; the recovery commit is never frozen.
//! - **I3**: A's revocation commit, attempted in its open window with no recovery since it
//!   opened, commits within 2 attempts.
//! - **I4**: the server's state is the model's after every step, so `state_seq` only grows and
//!   every accepted commit is one the model accepted; of two rotations built on one base
//!   ([`Step::Race`]) exactly one wins.
//! - **I5**: after A's revocation commit with an SK change, the thief's OPAQUE login with the
//!   old SK fails and none of the thief's sessions is live.
//! - **I6**: after the revocation, H of D is the one the suspension returned and the stored
//!   revocation names it as `last_accepted_device_seq`.
//!
//! What this model reduces, against the ADR's list:
//! - A's revocation commit is a **standard** rotation with an SK change (`password_epoch + 1`,
//!   `account_key_epoch + 1`, the revocations), not a full rotation: the full rotation with an
//!   SK change and a new recovery code in one commit is `revocation_window`'s
//!   `sk_change_in_the_revocation_commit`.
//! - "B uploads" and "D's ops uploaded over B's session" are vault-domain requests; the
//!   in-memory vault port has no upload. B's write here is an auth-domain left-column write
//!   (healing step 3 over its device session), and D's ops over another device's session are
//!   `rizzy-server`'s `tests/http/revocation_window.rs` and `rizzy-domain-vault`'s
//!   `tests/vault/window.rs`; I6 is checked at the auth level (H and the revocation's
//!   `last_accepted_device_seq`).
//! - The thief's refused writes are a kind-4 certificate upload, a commit and (before the
//!   suspension) the enrolment of D'; the other left-column entries are
//!   `revocation_window`'s one-per-entry tests.
//! - Every case starts from one prepared account (a copy of its database); the OPAQUE
//!   registrations of the first new Secret Keys, and A's, B's and the thief's sessions for each
//!   of the first [`POOLED`] window lengths the clock may pass, are prepared once with it. Each
//!   OPAQUE login and registration runs Argon2id at the production parameters, which would
//!   make 256 cases very slow; a case logs in live only once a password change or recovery
//!   ended the prepared sessions, or past the prepared window lengths. A thief login refused
//!   against one OPAQUE record is not repeated against the same record.
//! - The clock moves by 1 s or by the whole window; the boundary itself
//!   (`expires_at_ms - 1`, `expires_at_ms`) is `revocation_window`'s
//!   `window_suspend_renewal_and_boundaries`.
//!
//! The case count is proptest's: `PROPTEST_CASES` (256 when unset, ADR 0091 §7 test 4's count
//! per CI run; the nightly property job of 10,000 cases sets it), split over [`THREADS`]
//! runners.
//!
//! [ADR 0091]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0091-revoked-device-rotation-race.md

use std::cell::RefCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use chacha20::ChaCha20Rng;
use chacha20::rand_core::SeedableRng as _;
use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};
use rizzy_core::envelope::purpose::{
    AccountKeyDeviceGrantCtx, AccountKeyRecoveryWrapCtx, AccountKeyServerWrapCtx,
    IdentitySecretKeysCtx, VaultKeySelfGrantCtx,
};
use rizzy_core::kdf::KdfId;
use rizzy_core::keys::{
    AccountKey, GrantSigner, RecoveryWrapKey, VaultKey, device_set_hash,
    seal_account_key_device_grant,
};
use rizzy_core::opaque::{
    ExportKey, PasswordInput, client_registration_finish, client_registration_start,
};
use rizzy_core::secret::SecretArray;
use rizzy_core::secret_key::SecretKey;
use rizzy_core::sign::{AccountState, DeviceRevocation, Verified};
use rizzy_domain_auth::config::REVOCATION_WINDOW_MS;
use rizzy_domain_auth::{
    AuthConfig, AuthError, AuthService, RecoveryUpload, Session, SignupPolicy,
};
use rizzy_proto::auth::RecoveryRegistration;
use rizzy_proto::objects::{
    AccountKeyRecoveryWrap, AccountKeyServerWrap, DeviceGrant, IdentitySecretKeys, VaultSelfGrant,
};
use rizzy_proto::wire::{Fixed, List};
use rizzy_storage::{Database, SqliteOptions, WriterLock};

use crate::common::{Client, Env, Login, SharedVault, TempDir, block_on, bytes, origin, wid};
use crate::revocation::enrol;
use crate::revocation_window::{
    A, B, Change, D, PASSWORD, bare_change, device_session, empty_grants, enrolment, reauth, snap,
    view, web_certificate, window_row,
};

/// The thief's device, once enrolled.
const DP: usize = 3;
/// H of D and of D', as the vault port reports them.
const HEADS: [(usize, u64); 2] = [(D, 7), (DP, 3)];
/// New Secret Keys prepared for the SK changes of a case; more are registered live.
const PREPARED: usize = 4;
/// Fresh sessions prepared per window length the clock may have moved: a case that passes the
/// window more often logs in live.
const POOLED: u64 = 6;

/// One step of a case.
#[derive(Clone, Copy, Debug)]
enum Step {
    /// A suspends D, and D' too when `dprime` and the thief enrolled it.
    ASuspend { dprime: bool },
    /// A commits the revocation of every suspended device with a rotation and an SK change.
    ACommit,
    /// A crashed and resends its stored commit request byte for byte.
    AResend,
    /// B writes: healing step 3 over its device session.
    BWrite,
    /// B commits a standard rotation.
    BRotate,
    /// B, too, starts revoking D.
    BSuspend,
    /// A and B both commit a rotation built on the same state, B's first.
    Race,
    /// D (and D') try device authentication.
    DAuth,
    /// The thief logs in over OPAQUE with the password and the stolen SK.
    ThiefLogin,
    /// The thief tries its refused writes.
    ThiefWrites,
    /// The thief enrols D' before the suspension.
    ThiefEnrolDPrime,
    /// The clock moves a second, or past the window.
    Tick { long: bool },
    /// The owner completes a recovery.
    Recovery,
}

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        4 => any::<bool>().prop_map(|dprime| Step::ASuspend { dprime }),
        2 => Just(Step::ACommit),
        2 => Just(Step::AResend),
        3 => Just(Step::BWrite),
        1 => Just(Step::BRotate),
        1 => Just(Step::BSuspend),
        1 => Just(Step::Race),
        2 => Just(Step::DAuth),
        1 => Just(Step::ThiefLogin),
        3 => Just(Step::ThiefWrites),
        2 => Just(Step::ThiefEnrolDPrime),
        3 => any::<bool>().prop_map(|long| Step::Tick { long }),
        1 => Just(Step::Recovery),
    ]
}

/// The server configuration: no recovery wait, and rate limits no case reaches.
fn model_config(c: &mut AuthConfig) {
    c.recovery_wait_ms = 0;
    for rule in [
        &mut c.rate_limits.login_per_name_source,
        &mut c.rate_limits.login_per_name,
        &mut c.rate_limits.reauth_per_device,
        &mut c.rate_limits.recovery_per_name_source,
        &mut c.rate_limits.recovery_per_name,
    ] {
        rule.max_attempts = 1_000_000;
    }
}

/// An OPAQUE registration of the password under a new Secret Key.
struct Registration {
    secret_key: SecretKey,
    setup_id: u32,
    upload: Vec<u8>,
    export_key: ExportKey,
}

/// Registers the password under a new SK over `session`.
async fn register(env: &mut Env, session: &Session) -> Registration {
    let secret_key = SecretKey::generate(&mut env.rng);
    let pw_in = PasswordInput::derive_for_new_password(PASSWORD, &secret_key).unwrap();
    let (state, m1) = client_registration_start(&mut env.rng, &pw_in).unwrap();
    let (setup_id, m2) = env
        .svc
        .reregister_start(session, &bytes(m1), env.now)
        .await
        .unwrap();
    let reg =
        client_registration_finish(&mut env.rng, state, &pw_in, m2.as_slice(), KdfId::DEFAULT)
            .unwrap();
    Registration {
        secret_key,
        setup_id,
        upload: reg.upload,
        export_key: reg.export_key,
    }
}

/// The prepared account every case starts from.
struct Base {
    env: Env,
    /// Taken by a running case; `None` after a case panicked, which rebuilds the base.
    client: Option<Client>,
    state: (AccountState, Vec<u8>),
    a_dev: Session,
    a_login: Login,
    b_dev: Session,
    b_login: Login,
    /// A's and B's re-authentications and the thief's session, created at
    /// `k * REVOCATION_WINDOW_MS` after the base's clock, for `k < POOLED`: fresh for every
    /// clock value a case reaches before it passes the window `k + 1` times (a case's short
    /// steps add at most 41 s).
    pool: Vec<(Session, Session, Session)>,
    registrations: Vec<Registration>,
}

async fn build_base() -> Base {
    let mut env = Env::with_config(0x0091, model_config).await;
    let mut client = env.signup("model", PASSWORD).await;
    for _ in 0..2 {
        let device = enrol(&mut env, &mut client).await;
        client.devices.push(device);
    }
    env.vault
        .set_head(client.account_id, client.devices[D].id, HEADS[0].1);
    let (_, a_dev) = device_session(&mut env, &client, A).await;
    let (a_login, a_fresh) = reauth(&mut env, &client, A).await;
    let (_, b_dev) = device_session(&mut env, &client, B).await;
    let (b_login, b_fresh) = reauth(&mut env, &client, B).await;
    let thief = env.login(&client).await;
    let thief = env.bearer(&thief.response.session_token).await;
    let mut registrations = Vec::new();
    for _ in 0..PREPARED {
        registrations.push(register(&mut env, &a_fresh).await);
    }
    let start = env.now;
    let mut pool = vec![(a_fresh, b_fresh, thief)];
    for k in 1..POOLED {
        env.now = start + k * REVOCATION_WINDOW_MS;
        let (_, a) = reauth(&mut env, &client, A).await;
        let (_, b) = reauth(&mut env, &client, B).await;
        let thief = env.login(&client).await;
        let thief = env.bearer(&thief.response.session_token).await;
        pool.push((a, b, thief));
    }
    env.now = start;
    Base {
        state: (client.state.clone(), client.state_wire.clone()),
        client: Some(client),
        env,
        a_dev,
        a_login,
        b_dev,
        b_login,
        pool,
        registrations,
    }
}

/// A server over a copy of the base database, at the base's clock.
async fn fork(base: &Base, seed: u64) -> Env {
    let dir = TempDir::new();
    let path = dir.join("case.db");
    base.env.db.vacuum_into(&path).await.unwrap();
    let lock = WriterLock::acquire(&path).unwrap();
    let db = Database::open_sqlite(&SqliteOptions::new(&path), lock)
        .await
        .unwrap();
    base.env
        .secrets
        .check_database(&db, base.env.now)
        .await
        .unwrap()
        .unwrap();
    let mut config = AuthConfig::new(origin());
    config.signup = SignupPolicy::Open;
    model_config(&mut config);
    let vault = Arc::new(base.env.vault.fork());
    let svc = AuthService::new(
        db.clone(),
        base.env.secrets.clone(),
        config,
        SharedVault(vault.clone()),
    )
    .unwrap();
    Env {
        dir,
        db,
        secrets: base.env.secrets.clone(),
        svc,
        vault,
        rng: ChaCha20Rng::seed_from_u64(seed),
        now: base.env.now,
        source: base.env.source.clone(),
        _postgres_turn: None,
    }
}

/// What the model predicts.
#[derive(Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is one independent fact the model tracks, not a state machine"
)]
struct Model {
    suspended: [bool; 4],
    revoked: [bool; 4],
    dprime: bool,
    /// The window: its revoker and expiry.
    window: Option<(usize, u64)>,
    /// A recovery completed since the window opened.
    recovered_since_open: bool,
    /// A's revocation commit changed the SK.
    sk_changed_by_revocation: bool,
    /// The thief's SK is still the account's.
    thief_sk_valid: bool,
    /// A's last commit request and the state it commits.
    last_a: Option<(Change, Vec<u8>)>,
    /// H per device as the suspensions returned it.
    heads: [u64; 4],
}

impl Model {
    /// The revoker of the window open at `now`.
    fn open(&self, now: u64) -> Option<usize> {
        self.window.filter(|w| now < w.1).map(|w| w.0)
    }
}

/// A rotation built on the client's current state and not yet applied to it.
struct Pending {
    change: Change,
    next: (AccountState, Vec<u8>),
    account_key: AccountKey,
    vault_key: VaultKey,
    revocations: Vec<Verified<DeviceRevocation>>,
    secret_key: Option<SecretKey>,
}

/// The pristine keys of the base client, while a case holds replacements.
#[derive(Default)]
struct Undo {
    account_key: Option<AccountKey>,
    vault_key: Option<VaultKey>,
    secret_key: Option<SecretKey>,
    recovery_code: Option<SecretArray<16>>,
}

/// One running case.
struct Case<'b> {
    base: &'b Base,
    env: Env,
    client: Client,
    m: Model,
    undo: Undo,
    /// A's fresh re-authentication: its login (`None`: the base's) and session.
    a: Option<(Option<Login>, Session)>,
    b: Option<(Option<Login>, Session)>,
    a_dev: Option<Session>,
    b_dev: Option<Session>,
    thief: Option<Session>,
    /// Every session the thief ever held.
    thief_history: Vec<Session>,
    /// SK changes so far: the next registration.
    sk_changes: usize,
    /// Registrations made by this case beyond the prepared ones.
    extra: Vec<Registration>,
    /// The base's prepared sessions are live (no password change or recovery yet).
    pool_valid: bool,
    /// The clock the case started at.
    base_now: u64,
    /// The thief's login was refused against the record of this many SK changes.
    thief_refused_at: Option<usize>,
}

impl Case<'_> {
    fn account(&self) -> rizzy_core::ids::AccountId {
        self.client.account_id
    }

    fn present(&self, device: usize) -> bool {
        device < self.client.devices.len()
    }

    /// A's fresh re-authentication, renewed when stale or ended.
    async fn fresh(&mut self, device: usize) -> Session {
        let now = self.env.now;
        let slot = if device == A { &self.a } else { &self.b };
        if slot.as_ref().is_none_or(|(_, s)| !s.is_fresh_opaque(now)) {
            let renewed = if let Some((a, b, _)) = self.pooled() {
                (None, if device == A { a } else { b })
            } else {
                let (login, session) = reauth(&mut self.env, &self.client, device).await;
                (Some(login), session)
            };
            let slot = if device == A {
                &mut self.a
            } else {
                &mut self.b
            };
            *slot = Some(renewed);
        }
        let slot = if device == A { &self.a } else { &self.b };
        slot.as_ref().unwrap().1.clone()
    }

    /// A device session of `device` (A or B), renewed when ended or expired.
    async fn dev(&mut self, device: usize) -> Session {
        let now = self.env.now;
        let slot = if device == A {
            &self.a_dev
        } else {
            &self.b_dev
        };
        if slot.as_ref().is_none_or(|s| s.expires_at_ms <= now) {
            let (_, session) = device_session(&mut self.env, &self.client, device).await;
            let slot = if device == A {
                &mut self.a_dev
            } else {
                &mut self.b_dev
            };
            *slot = Some(session);
        }
        let slot = if device == A {
            &self.a_dev
        } else {
            &self.b_dev
        };
        slot.clone().unwrap()
    }

    /// The prepared sessions fresh at the current clock, while the base's OPAQUE record is
    /// still the account's.
    fn pooled(&self) -> Option<(Session, Session, Session)> {
        if !self.pool_valid {
            return None;
        }
        let k = (self.env.now - self.base_now) / REVOCATION_WINDOW_MS;
        let k = usize::try_from(k).ok()?;
        self.base.pool.get(k).cloned()
    }

    /// The thief's live session, if it holds one.
    fn thief(&self) -> Option<Session> {
        self.thief
            .clone()
            .filter(|s| s.expires_at_ms > self.env.now)
    }

    /// Every OPAQUE and recovery session ended (a password change); with `devices`, every
    /// session (a recovery).
    fn sessions_ended(&mut self, devices: bool) {
        self.pool_valid = false;
        self.a = None;
        self.b = None;
        self.thief = None;
        if devices {
            self.a_dev = None;
            self.b_dev = None;
        }
    }

    /// The index of the next new Secret Key's registration (see [`reg`]): a prepared one, or
    /// one registered now over `session`.
    async fn registration(&mut self, session: &Session) -> usize {
        let i = self.sk_changes;
        self.sk_changes += 1;
        if i >= self.base.registrations.len() {
            let r = register(&mut self.env, session).await;
            self.extra.push(r);
        }
        i
    }

    /// Applies an accepted rotation to the client, keeping the pristine keys.
    fn install(&mut self, p: Pending) {
        let old = core::mem::replace(&mut self.client.account_key, p.account_key);
        self.undo.account_key.get_or_insert(old);
        let old = core::mem::replace(&mut self.client.vault_key, p.vault_key);
        self.undo.vault_key.get_or_insert(old);
        if let Some(sk) = p.secret_key {
            let old = core::mem::replace(&mut self.client.secret_key, sk);
            self.undo.secret_key.get_or_insert(old);
        }
        self.client.revocations.extend(p.revocations);
        self.client.adopt(p.next);
    }

    /// Asserts `outcome` is `revocation_pending` and nothing changed.
    async fn frozen(&self, outcome: Option<AuthError>, before: &crate::revocation_window::Snap) {
        assert!(
            matches!(outcome, Some(AuthError::RevocationPending)),
            "expected revocation_pending, got {outcome:?}"
        );
        assert!(
            snap(&self.env, self.account()).await == *before,
            "a refused request wrote"
        );
    }

    /// Asserts nothing changed since `before`.
    async fn unchanged(&self, before: &crate::revocation_window::Snap) {
        assert!(
            snap(&self.env, self.account()).await == *before,
            "a refused request wrote"
        );
    }

    async fn suspend(&mut self, by: usize, target: usize) {
        let session = self.fresh(by).await;
        let before = snap(&self.env, self.account()).await;
        let now = self.env.now;
        let id = self.client.devices[target].id;
        let outcome = self.env.svc.suspend_device(&session, id, now).await;
        if self.m.revoked[target] {
            assert!(
                matches!(outcome, Err(AuthError::NotFound)),
                "{:?}",
                outcome.err()
            );
            self.unchanged(&before).await;
            return;
        }
        match self.m.open(now) {
            Some(r) if r != by => self.frozen(outcome.err(), &before).await,
            open => {
                let head = outcome.unwrap();
                let expected = HEADS.iter().find(|h| h.0 == target).unwrap().1;
                assert_eq!(head, expected, "I6: H");
                self.m.heads[target] = head;
                self.m.suspended[target] = true;
                if open.is_none() {
                    self.m.recovered_since_open = false;
                }
                self.m.window = Some((by, now + REVOCATION_WINDOW_MS));
            }
        }
    }

    async fn a_commit(&mut self) {
        let targets: Vec<usize> = [D, DP]
            .into_iter()
            .filter(|&t| self.present(t) && self.m.suspended[t] && !self.m.revoked[t])
            .collect();
        if targets.is_empty() {
            return;
        }
        let session = self.fresh(A).await;
        let now = self.env.now;
        let i3 = self.m.open(now) == Some(A) && !self.m.recovered_since_open;
        let mut attempts = 0;
        loop {
            attempts += 1;
            let i = self.registration(&session).await;
            let r = reg(self.base, &self.extra, i);
            let password_epoch = self.client.state.password_epoch + 1;
            let mut p = rotation(
                &mut self.env,
                &self.client,
                &self.m.heads,
                A,
                &r.export_key,
                password_epoch,
                &targets,
            );
            p.change.registration_upload = Some(bytes(r.upload.clone()));
            p.change.setup_id = Some(r.setup_id);
            p.secret_key = Some(copy_sk(&r.secret_key));
            let before = snap(&self.env, self.account()).await;
            let outcome = self.env.svc.commit_change(&session, &p.change, now).await;
            if let Some(r) = self.m.open(now)
                && r != A
            {
                self.frozen(outcome.err(), &before).await;
                return;
            }
            match outcome {
                Ok(()) => {
                    let wire = p.next.1.clone();
                    let committed = core::mem::replace(&mut p.change, bare_change(vec![0]));
                    self.install(p);
                    self.m.last_a = Some((committed, wire));
                    for t in &targets {
                        self.m.revoked[*t] = true;
                    }
                    self.m.window = None;
                    self.m.sk_changed_by_revocation = true;
                    self.m.thief_sk_valid = false;
                    self.sessions_ended(false);
                    return;
                }
                Err(e) => {
                    self.unchanged(&before).await;
                    assert!(
                        !i3 || attempts < 2,
                        "I3: A's revocation in its own window did not commit in 2 attempts: {e:?}"
                    );
                    assert!(attempts < 2, "A's revocation failed twice: {e:?}");
                }
            }
        }
    }

    async fn a_resend(&mut self) {
        let Some((change, wire)) = self.m.last_a.take() else {
            return;
        };
        let session = self.fresh(A).await;
        let before = snap(&self.env, self.account()).await;
        let outcome = self
            .env
            .svc
            .commit_change(&session, &change, self.env.now)
            .await;
        if self.client.state_wire == wire {
            outcome.unwrap();
        } else {
            assert!(outcome.is_err(), "a stale resend was accepted");
        }
        self.unchanged(&before).await;
        self.m.last_a = Some((change, wire));
    }

    async fn b_write(&mut self) {
        let session = self.dev(B).await;
        let before = snap(&self.env, self.account()).await;
        let outcome = self
            .env
            .svc
            .publish_grants(&session, &empty_grants(), self.env.now)
            .await;
        match self.m.open(self.env.now) {
            Some(r) if r != B => self.frozen(outcome.err(), &before).await,
            _ => outcome.unwrap(),
        }
    }

    async fn b_rotate(&mut self) {
        let session = self.fresh(B).await;
        let p = rotation(
            &mut self.env,
            &self.client,
            &self.m.heads,
            B,
            export_of(self.b.as_ref(), &self.base.b_login),
            self.client.state.password_epoch,
            &[],
        );
        let before = snap(&self.env, self.account()).await;
        let outcome = self
            .env
            .svc
            .commit_change(&session, &p.change, self.env.now)
            .await;
        match self.m.open(self.env.now) {
            Some(r) if r != B => self.frozen(outcome.err(), &before).await,
            _ => {
                outcome.unwrap();
                self.install(p);
            }
        }
    }

    async fn race(&mut self) {
        let a = self.fresh(A).await;
        let b = self.fresh(B).await;
        let pe = self.client.state.password_epoch;
        let pa = rotation(
            &mut self.env,
            &self.client,
            &self.m.heads,
            A,
            export_of(self.a.as_ref(), &self.base.a_login),
            pe,
            &[],
        );
        let pb = rotation(
            &mut self.env,
            &self.client,
            &self.m.heads,
            B,
            export_of(self.b.as_ref(), &self.base.b_login),
            pe,
            &[],
        );
        let now = self.env.now;
        let open = self.m.open(now);
        let before = snap(&self.env, self.account()).await;
        let first = self.env.svc.commit_change(&b, &pb.change, now).await;
        let mid = snap(&self.env, self.account()).await;
        let second = self.env.svc.commit_change(&a, &pa.change, now).await;
        // I4: of two commits on one base exactly one wins.
        assert!(
            first.is_ok() != second.is_ok(),
            "{:?} / {:?}",
            first.err(),
            second.err()
        );
        match open {
            Some(A) => {
                assert!(matches!(first, Err(AuthError::RevocationPending)));
                assert!(mid == before);
                self.install(pa);
            }
            Some(_) => {
                assert!(matches!(second, Err(AuthError::RevocationPending)));
                self.install(pb);
            }
            None => {
                assert!(first.is_ok());
                // A second commit at the stored `state_seq` is a fork of it.
                assert!(
                    matches!(second, Err(AuthError::StateFork | AuthError::StateConflict)),
                    "{:?}",
                    second.err()
                );
                self.install(pb);
            }
        }
        if first.is_ok() {
            self.unchanged(&mid).await;
        }
    }

    async fn d_auth(&mut self) {
        for t in [D, DP] {
            if !self.present(t) {
                continue;
            }
            let outcome = self
                .env
                .device_auth(&self.client, &self.client.devices[t])
                .await;
            if self.m.suspended[t] || self.m.revoked[t] {
                assert!(
                    matches!(outcome, Err(AuthError::Unauthorized)),
                    "I1: D authenticated"
                );
            } else {
                outcome.unwrap();
            }
        }
    }

    async fn thief_login(&mut self) {
        if let Some((_, _, thief)) = self.pooled() {
            // The stolen SK is still the account's: the prepared login of this moment.
            assert!(self.m.thief_sk_valid);
            self.thief_history.push(thief.clone());
            self.thief = Some(thief);
            return;
        }
        if self.thief_refused_at == Some(self.sk_changes) {
            // The same login against the same OPAQUE record was already refused this case.
            return;
        }
        let name = self.client.name.clone();
        let sk = self
            .undo
            .secret_key
            .as_ref()
            .unwrap_or(&self.client.secret_key);
        let outcome = self.env.login_as(&name, PASSWORD, sk, None, None).await;
        if self.m.thief_sk_valid {
            let login = outcome.unwrap();
            let session = self.env.bearer(&login.response.session_token).await;
            self.thief_history.push(session.clone());
            self.thief = Some(session);
        } else {
            assert!(
                matches!(outcome, Err(AuthError::Unauthorized)),
                "I5: the stolen SK still logs in"
            );
            self.thief_refused_at = Some(self.sk_changes);
        }
    }

    async fn thief_writes(&mut self) {
        let Some(thief) = self.thief() else { return };
        let now = self.env.now;
        let open = self.m.open(now).is_some();
        let req = web_certificate(&mut self.env, &self.client);
        let before = snap(&self.env, self.account()).await;
        let outcome = self.env.svc.upload_web_certificate(&thief, &req, now).await;
        if open {
            self.frozen(outcome.err(), &before).await;
        } else {
            outcome.unwrap();
        }
        let next = self.client.next_state(|_| {});
        let before = snap(&self.env, self.account()).await;
        let outcome = self
            .env
            .svc
            .commit_change(&thief, &bare_change(next.1.clone()), now)
            .await;
        if open {
            self.frozen(outcome.err(), &before).await;
        } else if outcome.is_ok() {
            self.client.adopt(next);
        } else {
            assert!(!matches!(outcome, Err(AuthError::RevocationPending)));
            self.unchanged(&before).await;
        }
    }

    async fn thief_enrol(&mut self) {
        if self.m.dprime || self.m.suspended[D] || self.m.revoked[D] {
            return;
        }
        let Some(thief) = self.thief().filter(|s| s.is_fresh_opaque(self.env.now)) else {
            return;
        };
        let (device, req, next) = enrolment(&mut self.env, &self.client);
        let before = snap(&self.env, self.account()).await;
        let outcome = self.env.svc.enrol_device(&thief, &req, self.env.now).await;
        if self.m.open(self.env.now).is_some() {
            self.frozen(outcome.err(), &before).await;
            return;
        }
        outcome.unwrap();
        self.env
            .vault
            .set_head(self.client.account_id, device.id, HEADS[1].1);
        self.client.devices.push(device);
        self.client.adopt(next);
        self.m.dprime = true;
    }

    async fn recovery(&mut self) {
        let token = self.client.recovery_token();
        let source = self.env.source.clone();
        let name = self.client.name.clone();
        let now = self.env.now;
        self.env
            .svc
            .recovery_start(&name, &token, &source, now)
            .await
            .unwrap();
        let release = self
            .env
            .svc
            .recovery_complete(&mut self.env.rng, &name, &token, &source, now)
            .await
            .unwrap();
        let session = self.env.bearer(&release.session_token).await;
        let i = self.registration(&session).await;
        let r = reg(self.base, &self.extra, i);
        let (sk, setup_id, upload) = (copy_sk(&r.secret_key), r.setup_id, r.upload.clone());
        let password_epoch = self.client.state.password_epoch + 1;
        let recovery_epoch = self.client.state.recovery_epoch + 1;
        let account_id = self.client.account_id;
        let rng = &mut self.env.rng;
        let e_srv = r
            .export_key
            .server_unlock_key(account_id)
            .unwrap()
            .wrap_account_key(
                rng,
                &AccountKeyServerWrapCtx {
                    account_id,
                    account_key_epoch: self.client.state.account_key_epoch,
                    password_epoch,
                    kdf_id: KdfId::DEFAULT,
                },
                &self.client.account_key,
            )
            .unwrap();
        let code = SecretArray::<16>::generate(rng);
        let e_rec = RecoveryWrapKey::derive(&code)
            .unwrap()
            .wrap_account_key(
                rng,
                &AccountKeyRecoveryWrapCtx {
                    account_id,
                    account_key_epoch: self.client.account_key.epoch(),
                    recovery_epoch,
                },
                &self.client.account_key,
            )
            .unwrap();
        let token_hash = rizzy_core::keys::RecoveryAuthToken::derive(&code)
            .unwrap()
            .server_hash();
        let next = self.client.next_state(|s| {
            s.password_epoch = password_epoch;
            s.recovery_epoch = recovery_epoch;
        });
        let change = Change {
            registration_upload: Some(bytes(upload)),
            setup_id: Some(setup_id),
            account_key_server_wrap: Some(AccountKeyServerWrap {
                account_key_epoch: self.client.state.account_key_epoch,
                password_epoch,
                kdf_id: 1,
                envelope: bytes(e_srv),
            }),
            recovery: RecoveryUpload::Register(RecoveryRegistration {
                recovery_wrap: AccountKeyRecoveryWrap {
                    account_key_epoch: self.client.account_key.epoch(),
                    recovery_epoch,
                    envelope: bytes(e_rec),
                },
                recovery_token_hash: Fixed::from_bytes(token_hash),
            }),
            ..bare_change(next.1.clone())
        };
        // Never frozen (INV-7), whatever window is open.
        self.env
            .svc
            .commit_change(&session, &change, now)
            .await
            .unwrap();
        self.client.adopt(next);
        let old = core::mem::replace(&mut self.client.secret_key, sk);
        self.undo.secret_key.get_or_insert(old);
        let old = core::mem::replace(&mut self.client.recovery_code, code);
        self.undo.recovery_code.get_or_insert(old);
        self.m.window = None;
        self.m.recovered_since_open = true;
        self.m.thief_sk_valid = false;
        self.sessions_ended(true);
    }

    async fn run(&mut self, step: Step) {
        match step {
            Step::ASuspend { dprime } => {
                self.suspend(A, D).await;
                if dprime && self.m.dprime {
                    self.suspend(A, DP).await;
                }
            }
            Step::ACommit => self.a_commit().await,
            Step::AResend => self.a_resend().await,
            Step::BWrite => self.b_write().await,
            Step::BRotate => self.b_rotate().await,
            Step::BSuspend => self.suspend(B, D).await,
            Step::Race => self.race().await,
            Step::DAuth => self.d_auth().await,
            Step::ThiefLogin => self.thief_login().await,
            Step::ThiefWrites => self.thief_writes().await,
            Step::ThiefEnrolDPrime => self.thief_enrol().await,
            Step::Tick { long } => self
                .env
                .tick(if long { REVOCATION_WINDOW_MS } else { 1_000 }),
            Step::Recovery => self.recovery().await,
        }
        self.env.tick(1);
    }

    /// The invariants after every step.
    async fn check(&mut self, step: Step) {
        let now = self.env.now;
        let account = self.account();
        // The window, as the server holds it, is the model's.
        let server = window_row(&self.env, account)
            .await
            .filter(|w| w.is_open(now))
            .map(|w| w.revoker);
        let model = self.m.open(now).map(|r| self.client.devices[r].id);
        assert_eq!(server, model, "the window after {step:?}");
        // I1: no session of a suspended or revoked device.
        let held = session_devices(&self.env).await;
        for t in [D, DP] {
            if self.present(t) && (self.m.suspended[t] || self.m.revoked[t]) {
                let id = self.client.devices[t].id.to_bytes().to_vec();
                assert!(
                    !held.contains(&Some(id)),
                    "I1: a session of a suspended device"
                );
            }
        }
        // I4: the server's state is the model's.
        let observer = self.dev(A).await;
        let seen = view(&self.env, &observer).await.unwrap();
        assert_eq!(
            seen.account_state.as_slice(),
            self.client.state_wire.as_slice(),
            "I4 after {step:?}"
        );
        // I5: after A's revocation with an SK change, no session of the thief is live.
        if self.m.sk_changed_by_revocation {
            // The thief's sessions are the only ones bound to no device in this model.
            assert!(
                !held.contains(&None),
                "I5: a session bound to no device outlived the SK change"
            );
            for s in &self.thief_history {
                assert!(
                    matches!(view(&self.env, s).await, Err(AuthError::Unauthorized)),
                    "I5: a thief session outlived the SK change"
                );
            }
        }
        // I6: H is unchanged and the revocation names it.
        for (t, h) in HEADS {
            if self.present(t) && self.m.revoked[t] {
                let id = self.client.devices[t].id;
                assert_eq!(self.env.vault.head(account, id), h, "I6");
                let named = seen.device_revocations.iter().any(|w| {
                    self.client.revocations.iter().any(|r| {
                        r.statement().device_id == id
                            && r.statement().last_accepted_device_seq == h
                            && DeviceRevocation::verify(
                                w.as_slice(),
                                self.client.identity.signing_key().verifying_key(),
                            )
                            .is_ok_and(|v| v.statement() == r.statement())
                    })
                });
                assert!(named, "I6: the stored revocation does not name H");
            }
        }
    }

    /// Hands the base client back with its pristine keys and state.
    fn restore(mut self) -> Client {
        let mut client = self.client;
        if let Some(k) = self.undo.account_key.take() {
            client.account_key = k;
        }
        if let Some(k) = self.undo.vault_key.take() {
            client.vault_key = k;
        }
        if let Some(k) = self.undo.secret_key.take() {
            client.secret_key = k;
        }
        if let Some(k) = self.undo.recovery_code.take() {
            client.recovery_code = k;
        }
        client.devices.truncate(3);
        client.revocations.clear();
        client.adopt(self.base.state.clone());
        client
    }
}

/// A rotation sent by `sender` revoking `revoke` (at their H in `heads`), with `E_srv'`
/// under `export_key` at `password_epoch`, on the client's current state, granting the new
/// account key to every other unrevoked device; nothing is applied to the client yet.
fn rotation(
    env: &mut Env,
    client: &Client,
    heads: &[u64; 4],
    sender: usize,
    export_key: &ExportKey,
    password_epoch: u32,
    revoke: &[usize],
) -> Pending {
    let now = env.now;
    let rng = &mut env.rng;
    let account_id = client.account_id;
    let account_key = client.account_key.generate_next(rng).unwrap();
    let vault_key = client.vault_key.generate_next(rng).unwrap();
    let epoch = account_key.epoch();
    let e_srv = export_key
        .server_unlock_key(account_id)
        .unwrap()
        .wrap_account_key(
            rng,
            &AccountKeyServerWrapCtx {
                account_id,
                account_key_epoch: epoch,
                password_epoch,
                kdf_id: KdfId::DEFAULT,
            },
            &account_key,
        )
        .unwrap();
    let e_id = account_key
        .wrap_identity_keys(
            rng,
            &IdentitySecretKeysCtx {
                account_id,
                identity_epoch: client.identity.epoch(),
            },
            &client.identity,
        )
        .unwrap();
    let mut revocations = Vec::new();
    let mut wires = Vec::new();
    for &t in revoke {
        let wire = DeviceRevocation {
            account_id,
            device_id: client.devices[t].id,
            last_accepted_device_seq: heads[t],
            revoked_at_ms: now,
        }
        .sign(client.identity.signing_key())
        .unwrap();
        revocations.push(
            DeviceRevocation::verify(&wire, client.identity.signing_key().verifying_key()).unwrap(),
        );
        wires.push(bytes(wire));
    }
    let revoked: Vec<_> = client
        .revocations
        .iter()
        .chain(&revocations)
        .map(|r| r.statement().device_id)
        .collect();
    let sender_device = &client.devices[sender];
    let grants: Vec<DeviceGrant> = client
        .devices
        .iter()
        .enumerate()
        .filter(|(i, d)| *i != sender && !revoked.contains(&d.id))
        .map(|(_, r)| {
            let ctx = AccountKeyDeviceGrantCtx {
                account_id,
                account_key_epoch: epoch,
                sender_device_id: sender_device.id,
                recipient_device_id: r.id,
            };
            let grant = seal_account_key_device_grant(
                rng,
                &ctx,
                &account_key,
                &client.account_key,
                &r.cert,
                GrantSigner::Device(sender_device.keys.signing_key()),
            )
            .unwrap();
            DeviceGrant {
                account_key_epoch: epoch,
                sender_device_id: wid(sender_device.id.to_bytes()),
                recipient_device_id: wid(r.id.to_bytes()),
                key_grant: bytes(grant),
            }
        })
        .collect();
    let self_grant = VaultSelfGrant {
        vault_id: wid(client.vault_id.to_bytes()),
        account_key_epoch: epoch,
        vault_key_epoch: vault_key.epoch(),
        envelope: bytes(
            account_key
                .wrap_vault_key(
                    rng,
                    &VaultKeySelfGrantCtx {
                        account_id,
                        vault_id: client.vault_id,
                        account_key_epoch: epoch,
                        vault_key_epoch: vault_key.epoch(),
                    },
                    &vault_key,
                )
                .unwrap(),
        ),
    };
    let recovery_epoch = client.state.recovery_epoch;
    let e_rec = RecoveryWrapKey::derive(&client.recovery_code)
        .unwrap()
        .wrap_account_key(
            rng,
            &AccountKeyRecoveryWrapCtx {
                account_id,
                account_key_epoch: epoch,
                recovery_epoch,
            },
            &account_key,
        )
        .unwrap();
    let set = device_set_hash(
        account_id,
        client.devices.iter().map(|d| &d.cert),
        client.revocations.iter().chain(&revocations),
    )
    .unwrap();
    let key_id = account_key.key_id().unwrap();
    let next = client.next_state(|s| {
        s.account_key_epoch = epoch;
        s.account_key_id = key_id;
        s.device_set_hash = set;
        s.password_epoch = password_epoch;
    });
    let change = Change {
        account_key_server_wrap: Some(AccountKeyServerWrap {
            account_key_epoch: epoch,
            password_epoch,
            kdf_id: 1,
            envelope: bytes(e_srv),
        }),
        identity_secret_keys: Some(IdentitySecretKeys {
            identity_epoch: client.identity.epoch(),
            envelope: bytes(e_id),
        }),
        recovery: RecoveryUpload::Rewrap(AccountKeyRecoveryWrap {
            account_key_epoch: epoch,
            recovery_epoch,
            envelope: bytes(e_rec),
        }),
        device_revocations: List::new(wires).unwrap(),
        device_grants: List::new(grants).unwrap(),
        vault_rotation: Some(vec![self_grant]),
        ..bare_change(next.1.clone())
    };
    Pending {
        change,
        next,
        account_key,
        vault_key,
        revocations,
        secret_key: None,
    }
}

/// The export key of a re-authentication slot, or the base's login.
fn export_of<'x>(slot: Option<&'x (Option<Login>, Session)>, base: &'x Login) -> &'x ExportKey {
    match slot {
        Some((Some(login), _)) => &login.export_key,
        _ => &base.export_key,
    }
}

/// Registration `i` of a case: prepared in the base, or registered by the case.
fn reg<'x>(base: &'x Base, extra: &'x [Registration], i: usize) -> &'x Registration {
    base.registrations
        .get(i)
        .unwrap_or_else(|| &extra[i - base.registrations.len()])
}

/// A copy of a Secret Key.
fn copy_sk(sk: &SecretKey) -> SecretKey {
    SecretKey::from_slice(sk.expose_secret()).unwrap()
}

/// The device id of every session.
async fn session_devices(env: &Env) -> Vec<Option<Vec<u8>>> {
    let mut tx = env.db.begin_read().await.unwrap();
    let ids: Vec<Option<Vec<u8>>> = rizzy_storage::on_engine!(tx.conn(), |c| {
        sqlx::query_scalar::<_, Option<Vec<u8>>>("SELECT device_id FROM auth_sessions")
            .fetch_all(&mut *c)
            .await
            .unwrap()
    });
    tx.finish().await.unwrap();
    ids
}

/// Runs one case from the base held in `cell` (built on first use, and again after a case
/// that panicked took it with it).
async fn run_case(cell: &RefCell<Option<Base>>, steps: &[Step]) {
    static SEED: AtomicU64 = AtomicU64::new(1);
    let taken = cell.borrow_mut().take();
    let mut base = match taken {
        Some(base) => base,
        None => build_base().await,
    };
    let client = base.client.take().unwrap();
    let env = fork(&base, SEED.fetch_add(1, Ordering::Relaxed)).await;
    let mut case = Case {
        base: &base,
        env,
        client,
        m: Model {
            thief_sk_valid: true,
            ..Model::default()
        },
        undo: Undo::default(),
        a: Some((None, base.pool[0].0.clone())),
        b: Some((None, base.pool[0].1.clone())),
        a_dev: Some(base.a_dev.clone()),
        b_dev: Some(base.b_dev.clone()),
        thief: Some(base.pool[0].2.clone()),
        thief_history: vec![base.pool[0].2.clone()],
        sk_changes: 0,
        extra: Vec::new(),
        pool_valid: true,
        base_now: base.env.now,
        thief_refused_at: None,
    };
    for &step in steps {
        case.run(step).await;
        case.check(step).await;
    }
    let client = case.restore();
    base.client = Some(client);
    *cell.borrow_mut() = Some(base);
}

/// Threads the cases are split over, each with its own base account.
const THREADS: u32 = 4;

/// ADR 0091 §7 test 4: I1–I6 over generated histories. The cases (proptest's count) are split
/// over [`THREADS`] runners, each shrinking its own failures.
#[test]
fn revocation_window_model() {
    let total = Config::default().cases;
    let runners: Vec<_> = (0..THREADS)
        .map(|i| {
            let cases = total / THREADS + u32::from(i < total % THREADS);
            std::thread::spawn(move || {
                let cell = RefCell::new(None);
                let config = Config {
                    cases,
                    failure_persistence: None,
                    ..Config::default()
                };
                let mut runner = TestRunner::new(config);
                let steps = prop::collection::vec(step(), 1..=40);
                runner
                    .run(&steps, |steps| {
                        block_on(run_case(&cell, &steps));
                        Ok(())
                    })
                    .unwrap();
            })
        })
        .collect();
    for runner in runners {
        runner.join().unwrap();
    }
}
