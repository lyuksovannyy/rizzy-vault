//! An enrolled device, opened: the host side of `rizzy-client`'s flows for one account
//! (ADR 0013 §2: "The host feeds in events … The state machine returns effects").
//!
//! [`Device`] ties together the cache file ([`crate::db`]) behind its floors, the transport
//! ([`crate::http`]), the device state and keys, and the vault driver. It does no cryptography
//! and decides nothing about what is verified or written: every check is `rizzy-client`'s, and
//! this module runs the steps in the order the specs fix.
//!
//! # Opening ([`Device::open`]; CRYPTO.md §5.6, §11.3 step 1; [ADR 0026] §4 step 5)
//!
//! The account's lock, the cache rows, `store::load::open` (format, meta rows, the
//! device-state record), then, in stage 2, the stored `register/finish` again (ADR 0026 §2
//! "Signup pending"); the master password; the offline unlock (one Argon2id run); the load,
//! which verifies every row like a server's answer. Nothing so far needs the network: the
//! vault reads offline.
//!
//! # Going online ([`Device::online`]; CRYPTO.md §11.3 step 2)
//!
//! Device authentication (sessions are never stored, ADR 0026 §1); a pending rotation settled
//! (below); the account answer verified against the pin, with its outcomes:
//! - verified: the account objects are written, the authors replaced;
//! - the account key rotated elsewhere: the grants are opened, and the re-wrapped record, the
//!   new state and self-grant and the Fetch at the new epoch are written in **one**
//!   transaction, then the grants are acknowledged (§11.3 step 4.5; ADR 0026 §4 step 3);
//! - the identity keys changed: the new fingerprint is shown and must be confirmed on this
//!   device (§11.3 step 3.2);
//! - a rollback, a fork or an unconfirmed identity change: the alarm is written in the
//!   transaction that detects it, and the device is read-only from then on, across restarts
//!   (ADR 0026 §4 step 4).
//!
//! # Write order (ADR 0026 §4)
//!
//! Every changeset goes through `Device::commit`: the floors, then one transaction. An own
//! op is committed when it is written, and its move to "sent" is committed before the upload
//! that carries it leaves ([`Device::upload`]); an answer's rows are committed before the next
//! request. A rotation's pending record and exact commit body are committed before the commit
//! is sent, and the finalising transaction holds the new record, state, self-grant and wrap
//! set ([`Device::rotate`]).
//!
//! # A pending rotation at start (`Device::settle_pending`; CRYPTO.md §11 "Secrets before
//! commit")
//!
//! "On restart with a pending record, the client fetches `account-state`: if the server holds
//! the new state it finalises, otherwise it resends the same request." The stored body is
//! resent byte for byte over a fresh re-authentication.
//!
//! **The pending record is dropped only on a definite refusal.** "Only after the server
//! acknowledges the commit, finalise the device state and delete the pending record": the
//! record holds the only copy of the new account key (`E_local'`, `E_dev'`), and a rotator
//! receives no grant for its own rotation, so dropping it after a commit the server applied
//! locks this device out for good. So:
//! - an answer that leaves the outcome unknown ([`CliError::refuses_commit`] is false: no
//!   answer, a proxy's error page, `internal`, an unknown code, a rate limit) keeps the record
//!   and the stored body, and the next run settles them by the rule above;
//! - an answer that is a refusal (`state_conflict` after the rebuild rule, `invalid_request`,
//!   `unauthorized`, …) is followed by one more `account-state` fetch. Only if the server
//!   still does not hold the commit's state is the record dropped; the rotation's keys cannot
//!   be rebuilt on a changed account, and the user starts the rotation again.
//!
//! A change of the identity keys in the answer that settles a pending rotation is taken
//! without the confirmation of §11.3 step 3.2 only when it is provably this rotation's own:
//! the served state is the stored commit's state byte for byte, or the served head bundle is
//! the stored commit's bundle byte for byte. Any other identity change (a full rotation by
//! another device after this one's) is shown and confirmed like any other.
//!
//! A pending **password or Secret Key change** (CRYPTO.md §11.5; `credentials`) is settled the
//! same way, except that its pending record unlocks with the new password only, which the
//! settling run asks for, and that a change without a rotation is recognised by the served
//! state or, when that cannot tell, by a login with the pending credentials.
//!
//! # A password or Secret Key change elsewhere (CRYPTO.md §11.3 step 5)
//!
//! When the account answer shows a higher `password_epoch`, the new password (and, if the
//! stored one no longer logs in, the new Secret Key) is asked for, `E_local` is re-created
//! under it with a new salt, and the record is written in the transaction that adopts the
//! answer.
//!
//! # An older copy of the device state (ADR 0026 §4 step 7, owner decision on open question 5)
//!
//! When a Fetch shows the server holding an own dot this file lacks, or an upload is refused
//! as a conflict at an own dot, alarm 4 is written, the device goes read-only, and the only
//! way on is `rv device forget` and a new login. `next_device_seq` never takes the server's
//! unsigned head.
//!
//! [ADR 0026]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0026-client-device-state-and-cache.md

use std::collections::BTreeSet;
use std::path::PathBuf;

use rizzy_client::ClientError;
use rizzy_client::account::{CertifiedDevice, RevokedDevice, VerifiedAccount};
use rizzy_client::credentials::PendingCredentialChange;
use rizzy_client::device::{DeviceState, UnlockedDevice};
use rizzy_client::login::{LoggedIn, LoginInput, start_login};
use rizzy_client::rizzy_proto::account::{AccountStateQuery, AccountView, DeviceGrantsResponse};
use rizzy_client::rizzy_proto::auth::{
    DeviceAuthFinishResponse, DeviceAuthStartResponse, LoginFinishResponse, LoginStartResponse,
};
use rizzy_client::rizzy_proto::change::{
    CommitChangeRequest, DeviceSuspensionRequest, SuspendDeviceResponse,
};
use rizzy_client::rizzy_proto::error::ErrorCode;
use rizzy_client::rizzy_proto::http::paths;
use rizzy_client::rizzy_proto::recovery::RecoveryCancelResponse;
use rizzy_client::rizzy_proto::vault::{FetchResponse, UploadResponse};
use rizzy_client::rizzy_proto::wire::{Id, SessionToken};
use rizzy_client::rotation::{
    ConflictOutcome, PendingRotation, RevokeDevice, RotationDone, RotationLevel, RotationOptions,
    start_rotation,
};
use rizzy_client::session::{DeviceSession, device_auth_finish, device_auth_start};
use rizzy_client::store::floors::Floors;
use rizzy_client::store::load::{self, Loaded};
use rizzy_client::store::record::{DeviceRecord, Stage};
use rizzy_client::store::rows::{Alarm, Changeset, Write};
use rizzy_client::store::{self};
use rizzy_client::sync::{Authors, VaultSync};
use rizzy_client::unlock::{
    account_state_query, apply_device_grants, identity_change_fingerprint, verify_unlock,
};
use rizzy_core::ids::DeviceId;
use rizzy_core::keys::AccountFingerprint;
use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

use crate::db::Db;
use crate::error::CliError;
use crate::http::{Auth, Http};
use crate::paths::{AccountLock, cache_path, check_data_dir, enrolled_accounts, hex};
use crate::sys::{OsRng, now_ms, os_rng};
use crate::ui::Ui;

mod credentials;
pub use credentials::{CredentialChange, CredentialOutcome};

/// What a command runs in: where the local data is, which account, and the user.
pub struct Env<'a> {
    /// The data directory.
    pub data_dir: PathBuf,
    /// `--account`, parsed.
    pub account: Option<[u8; 16]>,
    /// The user.
    pub ui: &'a mut dyn Ui,
}

impl std::fmt::Debug for Env<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Env").finish_non_exhaustive()
    }
}

/// The word the user types to accept a changed identity fingerprint.
const CONFIRM_WORD: &str = "CONFIRM";

/// The most OPAQUE logins one re-authentication tries (a second one carries the TOTP code).
const LOGIN_ATTEMPTS: usize = 2;

/// A copy of a bearer token, for a request sent while its owner is borrowed or consumed.
pub(crate) fn copy_token(token: &SessionToken) -> SessionToken {
    SessionToken::new(Zeroizing::new(*token.expose_secret()))
}

/// The account to open: `--account`, or the only one enrolled in the data directory.
///
/// # Errors
/// [`CliError::NotEnrolled`], [`CliError::SeveralAccounts`], [`CliError::Io`].
pub(crate) fn pick_account(env: &Env<'_>) -> Result<[u8; 16], CliError> {
    let enrolled = enrolled_accounts(&env.data_dir)?;
    match (env.account, enrolled.as_slice()) {
        (Some(account), _) if enrolled.contains(&account) => Ok(account),
        (Some(_), _) | (None, []) => Err(CliError::NotEnrolled),
        (None, [one]) => Ok(*one),
        (None, _) => Err(CliError::SeveralAccounts),
    }
}

/// An OPAQUE login (CRYPTO.md §11.2 steps 1–6), over `device`'s session when there is one (a
/// re-authentication the server binds to the device, §11.6 step 1). If the server asks for the
/// second factor, the code is asked for and the login starts again: the login state is taken
/// once (ADR 0028 "Single use").
///
/// # Errors
/// The flow's and the transport's errors.
pub(crate) async fn opaque_login(
    http: &Http,
    rng: &mut OsRng,
    ui: &mut dyn Ui,
    input: &LoginInput<'_>,
    mut device: Option<(&mut DeviceSession, &UnlockedDevice)>,
) -> Result<LoggedIn, CliError> {
    /// The authentication of a login request: over the device session when there is one.
    fn auth<'a>(device: &'a mut Option<(&mut DeviceSession, &UnlockedDevice)>) -> Auth<'a> {
        match device {
            Some((session, unlocked)) => Auth::Device(session, unlocked),
            None => Auth::None,
        }
    }
    let mut totp: Option<Zeroizing<String>> = None;
    for _ in 0..LOGIN_ATTEMPTS {
        let (started, request) = start_login(rng, input)?;
        let answer: LoginStartResponse = http
            .post(paths::LOGIN_START, &request, auth(&mut device))
            .await?;
        let (awaiting, finish) =
            started.finish(rng, &answer, totp.as_deref().map(String::as_str))?;
        let finished: Result<LoginFinishResponse, CliError> = http
            .post(paths::LOGIN_FINISH, &finish, auth(&mut device))
            .await;
        match finished {
            Ok(response) => return Ok(awaiting.complete(response)?),
            Err(CliError::Server(ErrorCode::SecondFactorRequired)) if totp.is_none() => {
                totp = Some(ui.secret("Two-factor code")?);
            }
            // The server answers a wrong password and an unknown name alike (§5.9).
            Err(CliError::Server(ErrorCode::Unauthorized)) => {
                return Err(CliError::Client(ClientError::WrongPasswordOrSecretKey));
            }
            Err(e) => return Err(e),
        }
    }
    Err(CliError::Server(ErrorCode::SecondFactorRequired))
}

/// An enrolled device, unlocked and loaded (module docs).
pub struct Device {
    /// The account's lock, held for the life of the process.
    lock: AccountLock,
    /// The cache file.
    db: Db,
    /// The floors of what the file holds.
    floors: Floors,
    /// The transport to the device's server.
    http: Http,
    /// The device-state record as the file holds it, pending record included.
    record: DeviceRecord,
    /// The stored commit of a pending rotation.
    pending_commit: Option<Vec<u8>>,
    /// The device state, with the pin.
    state: DeviceState,
    /// The unlocked keys.
    unlocked: UnlockedDevice,
    /// The account's verified certificates, as last loaded or served.
    certificates: Vec<CertifiedDevice>,
    /// The account's verified revocations.
    revocations: Vec<RevokedDevice>,
    /// The authors, for the vault's Fetch.
    authors: Authors,
    /// The personal vault (M1 has one vault per account).
    vault: VaultSync,
    /// The alarms raised.
    alarms: BTreeSet<Alarm>,
    /// The device session of this run, once authenticated.
    session: Option<DeviceSession>,
    /// Whether the account answer was verified in this run.
    refreshed: bool,
    /// The master password, kept for this run's re-authentications and the pending record.
    password: Zeroizing<String>,
    /// The OS CSPRNG.
    rng: OsRng,
}

impl std::fmt::Debug for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Device")
            .field("state", &self.state)
            .field("alarms", &self.alarms)
            .finish_non_exhaustive()
    }
}

impl Device {
    /// Opens the account's cache and unlocks it offline (module docs, "Opening").
    ///
    /// # Errors
    /// [`CliError::NotEnrolled`], [`CliError::SeveralAccounts`], [`CliError::InUse`];
    /// [`ClientError::WrongPasswordOrSecretKey`], [`ClientError::CacheCorrupt`],
    /// [`ClientError::CacheUpdateRequired`] and [`ClientError::LocalUnlockUnavailable`] as
    /// [`CliError::Client`]; the transport's errors when a pending signup is resent.
    pub async fn open(env: &mut Env<'_>) -> Result<Self, CliError> {
        let account = pick_account(env)?;
        // ADR 0026 §3: "directory 0700", also when `rv` did not create it.
        check_data_dir(&env.data_dir)?;
        let lock = AccountLock::acquire(&env.data_dir, &account)?;
        let mut db = Db::open(&cache_path(&env.data_dir, &account)).await?;
        let mut rows = db.read().await?;
        let mut record = load::open(&rows)?;
        let http = Http::new(record.server_origin().as_str())?;
        if record.stage() == Stage::SignupPending {
            // ADR 0026 §2: the stored `register/finish` is resent as it is; the server treats
            // a byte-identical repeat as success, and its answer finalises the record. The
            // floors of a stage-2 file cannot be built (nothing unlocks), and this changeset
            // is the fixed one `finalize_writes` builds.
            let request = rows
                .pending_commit
                .clone()
                .ok_or(ClientError::CacheCorrupt)?;
            env.ui
                .note("Finishing the signup that was interrupted before the server answered…");
            if let Err(e) = http
                .post_bytes_empty(paths::REGISTER_FINISH, request, Auth::None)
                .await
            {
                if e.refuses_commit() {
                    // A byte-identical repeat of a stored signup is a success (§11.1 step 8),
                    // so a refusal means this signup is not registered. The file is not
                    // removed here: removal is `device forget`'s, with its confirmation.
                    env.ui.note(
                        "The server refused the saved signup: no account was created from it, \
                         and its Emergency Kit is void. Remove it with `rv device forget`, then \
                         sign up again.",
                    );
                } else {
                    env.ui.note(
                        "The saved signup is still not finished. Run an rv command again to \
                         finish it; keep the Emergency Kit.",
                    );
                }
                return Err(e);
            }
            db.write(&store::finalize_writes(&record.committed())?)
                .await?;
            rows = db.read().await?;
            record = load::open(&rows)?;
        }
        let password = env.ui.secret("Master password")?;
        let unlocked = record.unlock(&password)?;
        let Loaded {
            device: state,
            account: loaded_account,
            authors,
            vaults,
            alarms,
            floors,
        } = load::load(&rows, &record, &unlocked, now_ms())?;
        let pending_commit = rows.pending_commit.take();
        drop(rows);
        let mut vaults = vaults.into_iter();
        // M1: one personal vault per account (ROADMAP §4.2).
        let (Some(vault), None) = (vaults.next(), vaults.next()) else {
            return Err(CliError::Client(ClientError::CacheCorrupt));
        };
        Ok(Self {
            lock,
            db,
            floors,
            http,
            record,
            pending_commit,
            state,
            unlocked,
            certificates: loaded_account.certificates().to_vec(),
            revocations: loaded_account.revocations().to_vec(),
            authors,
            vault,
            alarms,
            session: None,
            refreshed: false,
            password,
            rng: os_rng(),
        })
    }

    /// Builds the device of a fresh signup or enrolment, whose cache `db` was just created
    /// with `floors`.
    #[expect(
        clippy::too_many_arguments,
        reason = "the parts of a new enrolment, each from another step of the flow"
    )]
    pub(crate) fn enrolled(
        lock: AccountLock,
        db: Db,
        floors: Floors,
        http: Http,
        state: DeviceState,
        unlocked: UnlockedDevice,
        (certificates, revocations, authors): (Vec<CertifiedDevice>, Vec<RevokedDevice>, Authors),
        mut vault: VaultSync,
        password: Zeroizing<String>,
    ) -> Result<Self, CliError> {
        let record = state.record(Stage::Committed)?;
        vault.persist();
        Ok(Self {
            lock,
            db,
            floors,
            http,
            record,
            pending_commit: None,
            state,
            unlocked,
            certificates,
            revocations,
            authors,
            vault,
            alarms: BTreeSet::new(),
            session: None,
            refreshed: false,
            password,
            rng: os_rng(),
        })
    }

    /// The vault, for reads.
    #[must_use]
    pub const fn vault(&self) -> &VaultSync {
        &self.vault
    }

    /// The device state.
    #[must_use]
    pub const fn state(&self) -> &DeviceState {
        &self.state
    }

    /// The account's verified certificates and revocations, as last loaded or served.
    #[must_use]
    pub fn devices(&self) -> (&[CertifiedDevice], &[RevokedDevice]) {
        (&self.certificates, &self.revocations)
    }

    /// The alarms raised.
    #[must_use]
    pub const fn alarms(&self) -> &BTreeSet<Alarm> {
        &self.alarms
    }

    /// Fails with the first alarm, if any is raised: the device is read-only.
    ///
    /// # Errors
    /// [`CliError::Alarm`].
    pub fn check_writable(&self) -> Result<(), CliError> {
        match self.alarms.first() {
            Some(alarm) => Err(CliError::Alarm(*alarm)),
            None => Ok(()),
        }
    }

    /// Runs an edit on the vault with the device's keys and RNG, and commits the rows it
    /// wrote (ADR 0026 §4 step 1) before returning.
    ///
    /// # Errors
    /// [`CliError::Alarm`] when the device is read-only; the edit's error; the commit's.
    pub async fn edit<T>(
        &mut self,
        edit: impl FnOnce(&mut VaultSync, &mut OsRng, &UnlockedDevice, u64) -> Result<T, ClientError>,
    ) -> Result<T, CliError> {
        self.check_writable()?;
        let done = edit(&mut self.vault, &mut self.rng, &self.unlocked, now_ms());
        // Whatever the edit wrote before it failed is written too: the rows are own ops the
        // merge already holds.
        self.flush().await?;
        Ok(done?)
    }

    /// The floors, then one transaction (ADR 0026 §4).
    async fn commit(&mut self, changeset: Changeset) -> Result<(), CliError> {
        if changeset.is_empty() {
            return Ok(());
        }
        self.floors.admit(&changeset)?;
        self.db.write(&changeset).await
    }

    /// Commits what the vault driver journaled.
    async fn flush(&mut self) -> Result<(), CliError> {
        let writes = self.vault.take_writes();
        self.commit(writes).await
    }

    /// Raises `alarm` in `changeset` (ADR 0026 §4 step 4) and makes the vault read-only.
    fn raise(
        &mut self,
        changeset: &mut Changeset,
        alarm: Alarm,
        evidence: &[&[u8]],
    ) -> Result<(), CliError> {
        changeset.push(store::alarm_write(alarm, evidence)?);
        self.alarms.insert(alarm);
        self.vault.set_read_only(true);
        Ok(())
    }

    /// Raises `alarm`, commits it and returns it as the error.
    async fn alarm(&mut self, alarm: Alarm, evidence: &[&[u8]]) -> CliError {
        let mut changeset = Changeset::new();
        if let Err(e) = self.raise(&mut changeset, alarm, evidence) {
            return e;
        }
        match self.commit(changeset).await {
            Ok(()) => CliError::Alarm(alarm),
            Err(e) => e,
        }
    }

    /// Device authentication (CRYPTO.md §5.10): a new session for this run.
    async fn authenticate(&mut self) -> Result<(), CliError> {
        let start: DeviceAuthStartResponse = self
            .http
            .post(
                paths::DEVICE_AUTH_START,
                &device_auth_start(&self.state),
                Auth::None,
            )
            .await?;
        let finish = device_auth_finish(&self.state, &self.unlocked, &start)?;
        let answer: DeviceAuthFinishResponse = self
            .http
            .post(paths::DEVICE_AUTH_FINISH, &finish, Auth::None)
            .await?;
        self.session = Some(DeviceSession::new(&self.state, answer));
        Ok(())
    }

    /// Cancels a pending recovery over the device session (CRYPTO.md §11.9 step 2). Returns
    /// whether one was pending.
    ///
    /// # Errors
    /// The transport's errors; [`ClientError::Internal`] before [`Device::online`].
    pub async fn cancel_recovery(&mut self) -> Result<bool, CliError> {
        let session = self
            .session
            .as_mut()
            .ok_or(CliError::Client(ClientError::Internal))?;
        let answer: RecoveryCancelResponse = self
            .http
            .post_no_body(
                paths::RECOVERY_CANCEL,
                Auth::Device(session, &self.unlocked),
            )
            .await?;
        Ok(answer.cancelled)
    }

    /// `POST path` over the device session, with a JSON answer. A session the server ended (a
    /// rotation ends sessions) is renewed once.
    async fn call<T: Serialize, R: DeserializeOwned>(
        &mut self,
        path: &'static str,
        value: &T,
    ) -> Result<R, CliError> {
        let session = self
            .session
            .as_mut()
            .ok_or(CliError::Client(ClientError::Internal))?;
        let first = self
            .http
            .post(path, value, Auth::Device(session, &self.unlocked))
            .await;
        match first {
            Err(CliError::Server(ErrorCode::Unauthorized)) => {
                self.authenticate().await?;
                let session = self
                    .session
                    .as_mut()
                    .ok_or(CliError::Client(ClientError::Internal))?;
                self.http
                    .post(path, value, Auth::Device(session, &self.unlocked))
                    .await
            }
            other => other,
        }
    }

    /// Goes online (module docs). Does nothing the second time.
    ///
    /// # Errors
    /// [`CliError::Alarm`] when an alarm is raised or detected; the flows' and the transport's
    /// errors.
    pub async fn online(&mut self, ui: &mut dyn Ui) -> Result<(), CliError> {
        if self.refreshed {
            return Ok(());
        }
        // Rollback, fork and an outdated device state end the online life of this file. An
        // unconfirmed identity change is asked about again below.
        if let Some(alarm) = self
            .alarms
            .iter()
            .find(|a| **a != Alarm::UnconfirmedIdentityChange)
        {
            return Err(CliError::Alarm(*alarm));
        }
        if self.session.is_none() {
            self.authenticate().await?;
        }
        if self.record.has_pending() {
            self.settle_pending(ui).await?;
        } else {
            self.refresh(ui).await?;
        }
        self.refreshed = true;
        Ok(())
    }

    /// The account answer over the device session (CRYPTO.md §11.3 step 2.2).
    async fn account_view(&mut self) -> Result<AccountView, CliError> {
        let query = account_state_query(&self.state);
        self.call(paths::ACCOUNT_STATE, &query).await
    }

    /// Fetches and verifies the account answer (module docs, "Going online").
    async fn refresh(&mut self, ui: &mut dyn Ui) -> Result<(), CliError> {
        let view = self.account_view().await?;
        self.apply_view(ui, &view, Changeset::new(), false).await
    }

    /// Verifies `view` against the pin and persists the outcome. `before` holds writes that
    /// must land in the same transaction (a promoted pending record). `own_rotation` says a
    /// change of the identity keys in the answer is provably the one this device's own
    /// pending rotation made ([`Device::own_identity_change`]); only then is it not asked
    /// about.
    async fn apply_view(
        &mut self,
        ui: &mut dyn Ui,
        view: &AccountView,
        before: Changeset,
        own_rotation: bool,
    ) -> Result<(), CliError> {
        let pinned_wire = self.state.pin().state_wire().to_vec();
        let served_wire = view.account_state.as_slice().to_vec();
        // CRYPTO.md §11.3 step 3: a changed identity key is shown and confirmed first.
        let confirmed = match identity_change_fingerprint(&self.state, view) {
            Ok(None) => None,
            Ok(Some(fingerprint)) => {
                if own_rotation || Self::confirm_identity(ui, &fingerprint)? {
                    Some(fingerprint)
                } else {
                    return Err(self
                        .alarm(
                            Alarm::UnconfirmedIdentityChange,
                            &[&pinned_wire, &served_wire],
                        )
                        .await);
                }
            }
            Err(e) => return Err(e.into()),
        };
        let verified = verify_unlock(&mut self.state, &self.unlocked, view, confirmed.as_ref());
        let (account, changeset) = match verified {
            Ok(account) => (account, before),
            // §11.3 step 5: the password or the Secret Key changed elsewhere. `E_local` is
            // re-created under the new password (in memory), the answer verified again, and the
            // record written in the transaction that adopts the answer.
            Err(ClientError::PasswordChangedElsewhere) => {
                Box::pin(self.follow_credential_change(ui)).await?;
                let account =
                    verify_unlock(&mut self.state, &self.unlocked, view, confirmed.as_ref())?;
                self.record = self.state.record(Stage::Committed)?;
                let mut changeset = before;
                changeset.push(store::record_write(&self.record)?);
                (account, changeset)
            }
            Err(ClientError::AccountKeyRotated) => {
                // §11.3 step 4: the grants, the re-wrapped record, then the answer again.
                let session = self
                    .session
                    .as_mut()
                    .ok_or(CliError::Client(ClientError::Internal))?;
                let grants: DeviceGrantsResponse = self
                    .http
                    .get(paths::DEVICES_GRANTS, Auth::Device(session, &self.unlocked))
                    .await?;
                let ack = apply_device_grants(
                    &mut self.rng,
                    &mut self.state,
                    &mut self.unlocked,
                    view,
                    &grants,
                    confirmed.as_ref(),
                )?;
                let account = match verify_unlock(
                    &mut self.state,
                    &self.unlocked,
                    view,
                    confirmed.as_ref(),
                ) {
                    // A rotation together with a credential change (a Secret Key change
                    // rotates by default, CRYPTO.md §11.5): §11.3 step 5 after step 4,
                    // under the delivered key, before anything is written.
                    Err(ClientError::PasswordChangedElsewhere) => {
                        Box::pin(self.follow_credential_change(ui)).await?;
                        verify_unlock(&mut self.state, &self.unlocked, view, confirmed.as_ref())?
                    }
                    other => other?,
                };
                self.record = self.state.record(Stage::Committed)?;
                let mut changeset = before;
                changeset.push(store::record_write(&self.record)?);
                self.adopt(account, changeset, confirmed.is_some()).await?;
                // §11.3 step 4.5: acknowledged only after the re-wrapped objects are written.
                let session = self
                    .session
                    .as_mut()
                    .ok_or(CliError::Client(ClientError::Internal))?;
                self.http
                    .post_empty(
                        paths::DEVICES_GRANTS_ACK,
                        &ack,
                        Auth::Device(session, &self.unlocked),
                    )
                    .await?;
                return Ok(());
            }
            Err(ClientError::Rollback) => {
                return Err(self
                    .alarm(Alarm::Rollback, &[&pinned_wire, &served_wire])
                    .await);
            }
            Err(ClientError::Fork) => {
                return Err(self.alarm(Alarm::Fork, &[&pinned_wire, &served_wire]).await);
            }
            Err(e) => return Err(e.into()),
        };
        self.adopt(account, changeset, confirmed.is_some()).await
    }

    /// Shows a changed identity fingerprint and asks for the user's confirmation.
    fn confirm_identity(
        ui: &mut dyn Ui,
        fingerprint: &AccountFingerprint,
    ) -> Result<bool, CliError> {
        ui.note(
            "The account's identity keys changed: a full key rotation was made on another \
             device. Compare this number with the one another of your devices shows:",
        );
        ui.note(&fingerprint.safety_number());
        ui.note(
            "If you did not rotate, or the numbers differ, do not confirm: this device then \
             stays read-only.",
        );
        let typed = ui.line(&format!(
            "Type {CONFIRM_WORD} to accept the new identity keys"
        ))?;
        Ok(typed == CONFIRM_WORD)
    }

    /// Adopts a verified account answer: its objects, the authors, and the vault key. When
    /// the vault key moved to a new epoch, the Fetch at that epoch joins the same transaction,
    /// so the wraps on disk always open under the vault key on disk.
    async fn adopt(
        &mut self,
        mut account: VerifiedAccount,
        mut changeset: Changeset,
        identity_confirmed: bool,
    ) -> Result<(), CliError> {
        if identity_confirmed && self.alarms.remove(&Alarm::UnconfirmedIdentityChange) {
            changeset.push(Write::ClearAlarm(Alarm::UnconfirmedIdentityChange));
            self.vault.set_read_only(!self.alarms.is_empty());
        }
        changeset.append(store::account_writes(&account));
        self.authors = Authors::from_account(&account)?;
        self.certificates = account.certificates().to_vec();
        self.revocations = account.revocations().to_vec();
        let key = account
            .take_vault_key(self.vault.vault_id())
            .ok_or(ClientError::InvalidServerResponse)?;
        let epoch = self.vault.vault_key_epoch();
        match self.vault.adopt_vault_key(key) {
            Ok(()) => {}
            // ADR 0025 §4: a second vault key at a seen epoch is a fork, and a verified
            // self-grant below the held vault-key epoch is a rollback. Either way the alarm is
            // written in the transaction that detects it (ADR 0026 §4 step 4), and alone: the
            // answer is not adopted, and the floors would refuse its self-grant (a lower
            // epoch, or another key id at the held one) and with it the whole changeset.
            Err(e @ (ClientError::Fork | ClientError::Rollback)) => {
                let alarm = if matches!(e, ClientError::Fork) {
                    Alarm::Fork
                } else {
                    Alarm::Rollback
                };
                return Err(self.alarm(alarm, &[]).await);
            }
            Err(e) => return Err(e.into()),
        }
        if self.vault.vault_key_epoch() != epoch && self.fetch_into(&mut changeset).await? {
            self.raise(&mut changeset, Alarm::DeviceStateOutdated, &[])?;
        }
        self.commit(changeset).await?;
        self.check_writable()
    }

    /// Runs a complete Fetch, collecting its rows into `changeset`. Returns whether the
    /// server holds more of this device's own history than the file (ADR 0026 §4 step 7).
    async fn fetch_into(&mut self, changeset: &mut Changeset) -> Result<bool, CliError> {
        loop {
            let request = self.vault.fetch_request()?;
            let response: FetchResponse = self.call(paths::VAULT_FETCH, &request).await?;
            let outcome = self.vault.apply_fetch(&self.authors, &response, now_ms())?;
            changeset.append(self.vault.take_writes());
            if outcome.own_history_ahead {
                return Ok(true);
            }
            if response.complete {
                return Ok(false);
            }
        }
    }

    /// A complete Fetch (ADR 0012 §7), each page's rows committed before the next request
    /// (ADR 0026 §4 step 2).
    ///
    /// # Errors
    /// [`CliError::Alarm`] for an older copy of the device state; the flows' and transport's.
    pub async fn fetch(&mut self) -> Result<(), CliError> {
        loop {
            let request = self.vault.fetch_request()?;
            let response: FetchResponse = self.call(paths::VAULT_FETCH, &request).await?;
            let outcome = self.vault.apply_fetch(&self.authors, &response, now_ms())?;
            let mut changeset = self.vault.take_writes();
            if outcome.own_history_ahead {
                self.raise(&mut changeset, Alarm::DeviceStateOutdated, &[])?;
            }
            self.commit(changeset).await?;
            self.check_writable()?;
            if response.complete {
                return Ok(());
            }
        }
    }

    /// Uploads everything queued (ADR 0012 §7 "Upload"). A `stale_epoch` answer is followed by
    /// the account answer (the rotation elsewhere), after which the refused ops are re-issued
    /// under the new epoch with their `device_seq` (ADR 0025 §4).
    ///
    /// # Errors
    /// [`CliError::Server`] for a refusal that is not resolved; [`CliError::Alarm`].
    pub async fn upload(&mut self, ui: &mut dyn Ui) -> Result<(), CliError> {
        let mut followed = false;
        loop {
            let request = match self.vault.upload_request(&mut self.rng, &self.unlocked) {
                Ok(Some(request)) => request,
                Ok(None) => {
                    // Snapshots the step wrote but does not send yet are rows too.
                    self.flush().await?;
                    return Ok(());
                }
                Err(ClientError::VaultKeyRotated) if !followed => {
                    followed = true;
                    self.refresh(ui).await?;
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            // ADR 0026 §4 step 1: `own = 3` is committed before the request leaves.
            self.flush().await?;
            let response: UploadResponse = self.call(paths::VAULT_UPLOAD, &request).await?;
            let outcome = self.vault.apply_upload_response(&response)?;
            let mut changeset = self.vault.take_writes();
            if outcome.own_conflict {
                self.raise(&mut changeset, Alarm::DeviceStateOutdated, &[])?;
            }
            self.commit(changeset).await?;
            self.check_writable()?;
            if outcome.rejected.contains(&ErrorCode::StaleEpoch) && !followed {
                followed = true;
                self.refresh(ui).await?;
                continue;
            }
            if let Some(code) = outcome.rejected.first() {
                return Err(CliError::Server(*code));
            }
        }
    }

    /// Online, then Fetch, upload, Fetch: the device holds what the server holds and the
    /// server holds what the device wrote (ADR 0025 §2 step 1).
    ///
    /// # Errors
    /// As [`Device::online`], [`Device::fetch`] and [`Device::upload`].
    pub async fn sync(&mut self, ui: &mut dyn Ui) -> Result<(), CliError> {
        self.online(ui).await?;
        self.fetch().await?;
        self.upload(ui).await?;
        self.fetch().await
    }

    /// A re-authentication over this device's session (CRYPTO.md §11.6 step 1, §11.8 step 0).
    async fn reauth(&mut self, ui: &mut dyn Ui, login_name: &str) -> Result<LoggedIn, CliError> {
        let secret_key = self.record.secret_key_text();
        let origin = self.http.origin().as_str().to_owned();
        let input = LoginInput {
            server_origin: &origin,
            login_name,
            secret_key: &secret_key,
            password: &self.password,
        };
        let session = self
            .session
            .as_mut()
            .ok_or(CliError::Client(ClientError::Internal))?;
        opaque_login(
            &self.http,
            &mut self.rng,
            ui,
            &input,
            Some((session, &self.unlocked)),
        )
        .await
    }

    /// Drops a pending rotation whose commit the server refused for good.
    async fn abandon_pending(&mut self) -> Result<(), CliError> {
        self.record = self.state.record(Stage::Committed)?;
        self.pending_commit = None;
        self.commit(store::finalize_writes(&self.record)?).await
    }

    /// Drops a pending change found at start that the server does not hold (`settle_pending`),
    /// tells the user which credentials and Emergency Kit are the valid ones, and refreshes.
    /// `credential`: it was a master password or Secret Key change, whose kit, if it showed
    /// one, must not be taken for the valid one. `gone`: neither its credentials nor the
    /// previous ones log in any more (they were changed again on another device, which the
    /// refresh then follows).
    async fn drop_unsettled(
        &mut self,
        ui: &mut dyn Ui,
        credential: bool,
        gone: bool,
    ) -> Result<(), CliError> {
        self.abandon_pending().await?;
        ui.note(match (credential, gone) {
            (true, true) => {
                "Neither the credentials of the interrupted change nor the previous ones log in \
                 any more: the master password or the Secret Key was changed again on another \
                 device. The interrupted change is dropped. Keep every Emergency Kit until this \
                 device works again: the next prompts ask for the account's current master \
                 password, and for the Secret Key of its newest kit if needed."
            }
            (false, true) => {
                "The master password or the Secret Key was changed on another device since the \
                 rotation was interrupted; the rotation is dropped. Run it again once this \
                 device follows the change."
            }
            (true, false) => {
                "The server did not take the interrupted change of the master password or \
                 Secret Key (the account changed since): the change was NOT made. The new \
                 Emergency Kit it showed, if any, is void, its Secret Key and any recovery code \
                 on it alike. Your previous master password, Secret Key and Emergency Kit, with \
                 its recovery code, stay the valid ones. Run the command again."
            }
            (false, false) => {
                "The server did not take the interrupted rotation (the account changed since). \
                 Nothing was rotated; run the command again."
            }
        });
        self.refresh(ui).await
    }

    /// Settles a pending rotation found at start (module docs).
    async fn settle_pending(&mut self, ui: &mut dyn Ui) -> Result<(), CliError> {
        let commit = self
            .pending_commit
            .clone()
            .ok_or(ClientError::CacheCorrupt)?;
        // The stored body is parsed back only through `rizzy-proto` (ADR 0026 §3).
        let request: CommitChangeRequest =
            serde_json::from_slice(&commit).map_err(|_| ClientError::CacheCorrupt)?;
        // A password or Secret Key change (CRYPTO.md §11.5): its pending record unlocks with
        // the new password only, and whether the server took it is asked with a login.
        let mut credential = None;
        if self.record.pending_changes_password() {
            ui.note(
                "A change of the master password or Secret Key was interrupted before the \
                 server answered; settling it.",
            );
            let name = ui.line("Login name")?;
            let new_password = ui.secret("The new master password of that change")?;
            credential = Some((name, new_password));
        }
        // The keys the device holds once the commit is applied (one more Argon2id run).
        let pending_unlocked = self.record.unlock_pending(
            credential
                .as_ref()
                .map_or(self.password.as_str(), |(_, p)| p.as_str()),
        )?;
        let promoted = DeviceRecord::parse(&self.record.encode()?)?.promote_pending();
        let mut view = self.account_view().await?;
        let mut applied = self
            .settled(
                ui,
                &request,
                &promoted,
                &pending_unlocked,
                &view,
                credential.as_ref(),
            )
            .await?;
        if !applied {
            ui.note("A key rotation was interrupted before the server answered; sending it again.");
            let name = match &credential {
                Some((name, _)) => name.clone(),
                None => ui.line("Login name")?,
            };
            let reauth = match self.reauth(ui, &name).await {
                Ok(reauth) => reauth,
                // The current credentials no longer log in, and the change was found not
                // applied (for a credential change: its own credentials did not log in
                // either), so they were changed again on another device. The record holds no
                // key the device needs (`credentials` module docs), and keeping it would fail
                // every later run the same way: it is dropped, and the refresh follows the
                // other change (CRYPTO.md §11.3 step 5).
                Err(CliError::Client(ClientError::WrongPasswordOrSecretKey)) => {
                    return self.drop_unsettled(ui, credential.is_some(), true).await;
                }
                Err(e) => return Err(e),
            };
            let sent = self
                .http
                .post_bytes_empty(
                    paths::ACCOUNT_COMMIT,
                    commit,
                    Auth::Bearer(reauth.bearer_token()),
                )
                .await;
            match sent {
                Ok(()) => {
                    view = self.account_view().await?;
                    applied = true;
                }
                // A refusal. The record holds the only copy of the rotation's keys, so what
                // the server holds is read once more before it is dropped (module docs).
                Err(e) if e.refuses_commit() => {
                    view = self.account_view().await?;
                    applied = self
                        .settled(
                            ui,
                            &request,
                            &promoted,
                            &pending_unlocked,
                            &view,
                            credential.as_ref(),
                        )
                        .await?;
                }
                // Unknown outcome (no answer, a proxy's page, `internal`, a rate limit): the
                // pending record stays, and the next run asks again.
                Err(e) => {
                    ui.note(
                        "The interrupted rotation is still not settled; it stays saved, and \
                         the next rv command that goes online tries again.",
                    );
                    return Err(e);
                }
            }
        }
        if !applied {
            // The keys of the rotation died with the process that made them; it cannot be
            // rebuilt on the changed account, only started again.
            return self.drop_unsettled(ui, credential.is_some(), false).await;
        }
        // CRYPTO.md §11 step 5: the pending keys become the device's, in the transaction that
        // also writes the new state.
        self.state = promoted.to_state(self.state.pin().clone())?;
        self.unlocked = pending_unlocked;
        if let Some((_, new_password)) = credential {
            // From here on this device unlocks, and re-authenticates, with the new password.
            self.password = new_password;
        }
        let finalize = store::finalize_writes(&promoted)?;
        self.record = promoted;
        self.pending_commit = None;
        // CRYPTO.md §11.3 step 3.2: only an identity change that is provably this rotation's
        // own skips the confirmation. If the user declines another one, the alarm is written
        // alone; the pending record stays on disk and the next run settles it again.
        let own_identity = Self::own_identity_change(&request, &view);
        self.apply_view(ui, &view, finalize, own_identity).await
    }

    /// Whether a change of the identity keys in `view` is the one the stored commit `request`
    /// made, so that it needs no confirmation on the device that made it: the served state is
    /// the commit's state byte for byte, or the served head bundle (the last of the chain,
    /// which carries the identity keys the fingerprint is computed from) is the commit's new
    /// bundle byte for byte. A commit without a bundle changed no identity key, so any change
    /// the view then shows is someone else's.
    fn own_identity_change(request: &CommitChangeRequest, view: &AccountView) -> bool {
        if view.account_state == request.account_state {
            return true;
        }
        match (&request.bundle, view.bundles.as_slice().last()) {
            (Some(own), Some(head)) => own == head,
            _ => false,
        }
    }

    /// Whether the server's account is built on this device's pending rotation: the served
    /// state is the stored commit's, the pending keys verify the answer, or the account key
    /// moved on from them without a grant to this device at the pending epoch (a rotator
    /// receives none for its own rotation; a device that lost the race does).
    ///
    /// This decides only whether the pending keys become the device's. It proves nothing
    /// about the identity keys in `view` ([`Device::own_identity_change`] does): the grant
    /// list is unsigned, and the view may be a later state than this rotation's.
    async fn pending_applied(
        &mut self,
        request: &CommitChangeRequest,
        promoted: &DeviceRecord,
        pending_unlocked: &UnlockedDevice,
        view: &AccountView,
    ) -> Result<bool, CliError> {
        if view.account_state == request.account_state {
            return Ok(true);
        }
        let mut probe = promoted.to_state(self.state.pin().clone())?;
        let own_identity = identity_change_fingerprint(&probe, view).ok().flatten();
        match verify_unlock(&mut probe, pending_unlocked, view, own_identity.as_ref()) {
            // A later password change elsewhere is reported only after the pending account
            // key verified the answer: the key is this rotation's.
            Ok(_) | Err(ClientError::PasswordChangedElsewhere) => Ok(true),
            Err(ClientError::AccountKeyRotated) => {
                let session = self
                    .session
                    .as_mut()
                    .ok_or(CliError::Client(ClientError::Internal))?;
                let grants: DeviceGrantsResponse = self
                    .http
                    .get(paths::DEVICES_GRANTS, Auth::Device(session, &self.unlocked))
                    .await?;
                let own = self.state.device_id().to_bytes();
                let epoch = pending_unlocked.account_key_epoch();
                Ok(!grants.grants.as_slice().iter().any(|g| {
                    g.recipient_device_id.to_bytes() == own && g.account_key_epoch == epoch
                }))
            }
            Err(_) => Ok(false),
        }
    }

    /// A key rotation (CRYPTO.md §11.6), with the revocation of `revoke` when given (§11.8):
    /// [`Device::begin_rotation`], [`Device::send_rotation`], [`Device::finish_rotation`].
    /// Returns how many items the rotation left unreadable (wrap rows it could not open).
    ///
    /// # Errors
    /// The flows' and the transport's errors; an answer that leaves the commit's outcome
    /// unknown leaves the pending record for the next run to settle, and the user is told.
    pub async fn rotate(
        &mut self,
        ui: &mut dyn Ui,
        login_name: &str,
        level: RotationLevel,
        revoke: Option<DeviceId>,
    ) -> Result<usize, CliError> {
        let mut flight = self.begin_rotation(ui, login_name, level, revoke).await?;
        if let Err(e) = self.send_rotation(&mut flight).await {
            // The stored body is there exactly while a commit is persisted and not settled.
            if self.pending_commit.is_some() && !matches!(e, CliError::Alarm(_)) {
                ui.note(
                    "The rotation is not finished, and whether the server applied it may be \
                     unknown. It stays saved on this device, and the next rv command that goes \
                     online settles it: it finishes the rotation if the server has it, and \
                     sends it again if not.",
                );
            }
            return Err(e);
        }
        Box::pin(self.finish_rotation(ui, flight)).await
    }

    /// The first part of a rotation: the sync, the re-authentication over this device's
    /// session, the suspension of `revoke` (§11.8 step 0, after which the revoker fetches up
    /// to H), and the rotation built on the synced vault. Nothing is written or committed yet.
    ///
    /// # Errors
    /// The flows' and the transport's errors.
    pub async fn begin_rotation(
        &mut self,
        ui: &mut dyn Ui,
        login_name: &str,
        level: RotationLevel,
        revoke: Option<DeviceId>,
    ) -> Result<RotationInFlight, CliError> {
        self.sync(ui).await?;
        let recovery_code = if self.state.pin().state().recovery_enabled {
            Some(ui.secret(
                "Recovery code from your Emergency Kit (it stays valid after the rotation)",
            )?)
        } else {
            None
        };
        let reauth = self.reauth(ui, login_name).await?;
        let token = copy_token(reauth.bearer_token());
        let revoke = match revoke {
            None => None,
            Some(device_id) => {
                // §11.8 step 0: from here on the server refuses the device and returns H.
                let answer: SuspendDeviceResponse = self
                    .http
                    .post(
                        paths::DEVICES_SUSPEND,
                        &DeviceSuspensionRequest {
                            device_id: Id::from_bytes(device_id.to_bytes()),
                        },
                        Auth::Bearer(&token),
                    )
                    .await?;
                // §11.8 step 1: "The revoker fetches up to H".
                self.fetch().await?;
                Some(RevokeDevice {
                    device_id,
                    last_accepted_device_seq: answer.last_accepted_device_seq,
                })
            }
        };
        let options = RotationOptions {
            level,
            revoke,
            recovery_code: recovery_code.as_deref().map(String::as_str),
            now_ms: now_ms(),
        };
        let mut pending = start_rotation(
            &mut self.rng,
            reauth,
            &self.state,
            &self.unlocked,
            &[&self.vault],
            &options,
        )?;
        let pending_record = pending.pending_record(&mut self.rng, &self.state, &self.unlocked)?;
        self.record = self
            .state
            .record(Stage::Committed)?
            .with_pending(pending_record);
        Ok(RotationInFlight {
            pending: Flight::Rotation(Box::new(pending)),
            token,
        })
    }

    /// ADR 0026 §4 step 3: writes the pending record and the exact JSON body of the commit,
    /// in one transaction, **before** the commit is sent, and returns that body. A process
    /// that dies after this call leaves a file the next run settles
    /// (`Device::settle_pending`).
    ///
    /// # Errors
    /// [`CliError::Database`]; [`ClientError::Internal`].
    pub async fn persist_rotation(
        &mut self,
        flight: &RotationInFlight,
    ) -> Result<Vec<u8>, CliError> {
        let body = serde_json::to_vec(flight.pending.commit_request()?)
            .map_err(|_| ClientError::Internal)?;
        self.commit(store::pending_writes(&self.record, &body)?)
            .await?;
        self.pending_commit = Some(body.clone());
        Ok(body)
    }

    /// Sends the commit, with the retry rule of ADR 0025 §2 step 5: on `state_conflict`, a
    /// complete Fetch, the state again, and a rebuilt request (persisted again before it is
    /// sent) or the verdict that the commit already landed.
    ///
    /// When the pending record is dropped and when it stays is the rule of the module docs
    /// ("The pending record is dropped only on a definite refusal").
    ///
    /// # Errors
    /// An error that leaves the outcome unknown ([`CliError::refuses_commit`] is false) leaves
    /// the pending record for the next run to settle. A refusal drops it, once one more
    /// `account-state` fetch shows the server does not hold the commit's state, and is
    /// returned. [`CliError::Alarm`] for a rollback or a fork shown by the state the retry
    /// rule fetched: the alarm is written, the device is read-only, and the pending record
    /// stays (nothing is deleted from a file that is evidence).
    pub async fn send_rotation(&mut self, flight: &mut RotationInFlight) -> Result<(), CliError> {
        loop {
            let body = self.persist_rotation(flight).await?;
            let sent = self
                .http
                .post_bytes_empty(paths::ACCOUNT_COMMIT, body, Auth::Bearer(&flight.token))
                .await;
            match sent {
                Ok(()) => return Ok(()),
                Err(CliError::Server(ErrorCode::StateConflict)) => {
                    self.fetch().await?;
                    let view: AccountView = self
                        .http
                        .post(
                            paths::ACCOUNT_STATE,
                            &flight.pending.state_query(),
                            Auth::Bearer(&flight.token),
                        )
                        .await?;
                    match flight.pending.on_state_conflict(
                        &mut self.rng,
                        &view,
                        &self.unlocked,
                        &[&self.vault],
                    ) {
                        Ok(ConflictOutcome::Resend) => {}
                        Ok(ConflictOutcome::Committed) => return Ok(()),
                        // ADR 0025 §2 step 5, CRYPTO.md §11.3 step 2.5: "go read-only". The
                        // alarm is written in the transaction that detects it (ADR 0026 §4
                        // step 4), with the pinned and the served state as evidence.
                        Err(e @ (ClientError::Rollback | ClientError::Fork)) => {
                            let alarm = if matches!(e, ClientError::Rollback) {
                                Alarm::Rollback
                            } else {
                                Alarm::Fork
                            };
                            let pinned = self.state.pin().state_wire().to_vec();
                            return Err(self
                                .alarm(alarm, &[&pinned, view.account_state.as_slice()])
                                .await);
                        }
                        // The commit was refused (`state_conflict`) and cannot be rebuilt on
                        // the account as it now is: nothing was applied.
                        Err(e) => {
                            self.abandon_pending().await?;
                            return Err(e.into());
                        }
                    }
                }
                // A refusal: the server's state is read once more before the only copy of
                // the rotation's keys is dropped. If that read fails, the record stays.
                Err(e) if e.refuses_commit() => {
                    if self.commit_landed().await? {
                        return Ok(());
                    }
                    self.abandon_pending().await?;
                    return Err(e);
                }
                // Unknown outcome: the pending record stays for the next run to settle.
                Err(e) => return Err(e),
            }
        }
    }

    /// Whether the server's `account-state` is the state of the stored commit, byte for byte:
    /// the commit was applied whatever the answer to it said.
    async fn commit_landed(&mut self) -> Result<bool, CliError> {
        let Some(commit) = &self.pending_commit else {
            return Ok(false);
        };
        let request: CommitChangeRequest =
            serde_json::from_slice(commit).map_err(|_| ClientError::CacheCorrupt)?;
        let view = self.account_view().await?;
        Ok(view.account_state == request.account_state)
    }

    /// CRYPTO.md §11 step 5, after the server acknowledged the commit: the device state is
    /// finalised and the pending record and the stored body removed, in one transaction with
    /// the new state's rows (the state, the device set, the self-grant, the re-wrapped wrap
    /// set); then everything is synced at the new epoch. Returns how many items the rotation
    /// left unreadable.
    ///
    /// # Errors
    /// The flows' and the transport's errors.
    pub async fn finish_rotation(
        &mut self,
        ui: &mut dyn Ui,
        flight: RotationInFlight,
    ) -> Result<usize, CliError> {
        let state_writes = flight.pending.store_writes()?;
        let done = flight.pending.finalize(
            &mut self.rng,
            &mut self.state,
            &mut self.unlocked,
            &mut [&mut self.vault],
        )?;
        self.authors = done.authors;
        self.record = self.state.record(Stage::Committed)?;
        self.pending_commit = None;
        let mut changeset = store::finalize_writes(&self.record)?;
        changeset.append(state_writes);
        changeset.append(self.vault.take_writes());
        self.commit(changeset).await?;
        // The new device set for `device list`, and everything at the new epoch.
        self.refreshed = false;
        self.sync(ui).await?;
        Ok(done.dropped_items.len())
    }

    /// Uploads what this device wrote and the server never acknowledged, byte for byte, before
    /// the device is removed (ADR 0026 §5, owner decision on open question 6). Returns how
    /// many own ops and snapshots are still unacknowledged afterwards.
    ///
    /// # Errors
    /// The transport's errors; the flows'.
    pub async fn upload_unsent(&mut self) -> Result<(usize, usize), CliError> {
        if self.session.is_none() {
            self.authenticate().await?;
        }
        // A restore generation is needed to mark the rows sent; a Fetch gives one.
        let request = self.vault.fetch_request()?;
        let response: FetchResponse = self.call(paths::VAULT_FETCH, &request).await?;
        self.vault.apply_fetch(&self.authors, &response, now_ms())?;
        self.flush().await?;
        while let Some(request) = self.vault.unsent_upload_request()? {
            self.flush().await?;
            let before = self.vault.unacknowledged();
            let response: UploadResponse = self.call(paths::VAULT_UPLOAD, &request).await?;
            self.vault.apply_upload_response(&response)?;
            self.flush().await?;
            if self.vault.unacknowledged() == before {
                // The server takes no more of them (a conflict, a stale epoch): stop.
                break;
            }
        }
        Ok(self.vault.unacknowledged())
    }

    /// Closes the cache and gives back the account id and the lock, for the removal of the
    /// device's files.
    pub(crate) async fn close(self) -> ([u8; 16], AccountLock) {
        let account = self.state.account_id().to_bytes();
        self.db.close().await;
        (account, self.lock)
    }

    /// The account id as the files are named.
    #[must_use]
    pub fn account_hex(&self) -> String {
        hex(self.state.account_id().as_bytes())
    }
}

/// A rotation (or a credential change, which commits the same way) built and not yet
/// finalised ([`Device::begin_rotation`], `Device::change_credentials`): the pending change
/// of the client core, which holds the new keys, and the fresh OPAQUE session's token. Dropping
/// it wipes the keys; a pending record already written stays for the next run to settle.
pub struct RotationInFlight {
    /// The rotation.
    pub(crate) pending: Flight,
    /// The bearer token of the re-authentication.
    pub(crate) token: SessionToken,
}

impl std::fmt::Debug for RotationInFlight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotationInFlight")
            .field("pending", &self.pending)
            .finish_non_exhaustive()
    }
}

/// What a [`RotationInFlight`] commits: a key rotation (CRYPTO.md §11.6, §11.8), or a password
/// or Secret Key change, with or without a rotation (§11.5). Both are one `account/commit` with
/// a pending record, the same retry rule and the same finalisation.
#[derive(Debug)]
pub(crate) enum Flight {
    /// A key rotation.
    Rotation(Box<PendingRotation>),
    /// A credential change.
    Credential(Box<PendingCredentialChange>),
}

impl Flight {
    /// The commit to send.
    fn commit_request(&self) -> Result<&CommitChangeRequest, ClientError> {
        match self {
            Self::Rotation(r) => Ok(r.commit_request()),
            Self::Credential(c) => c.commit_request(),
        }
    }

    /// What to fetch after a `state_conflict`.
    fn state_query(&self) -> AccountStateQuery {
        match self {
            Self::Rotation(r) => r.state_query(),
            Self::Credential(c) => c.state_query(),
        }
    }

    /// The retry rule after a `state_conflict`.
    fn on_state_conflict(
        &mut self,
        rng: &mut OsRng,
        view: &AccountView,
        unlocked: &UnlockedDevice,
        vaults: &[&VaultSync],
    ) -> Result<ConflictOutcome, ClientError> {
        match self {
            Self::Rotation(r) => r.on_state_conflict(rng, view, unlocked, vaults),
            Self::Credential(c) => c.on_state_conflict(rng, view, unlocked, vaults),
        }
    }

    /// The cache writes of the committed state.
    fn store_writes(&self) -> Result<Changeset, ClientError> {
        match self {
            Self::Rotation(r) => r.store_writes(),
            Self::Credential(c) => c.store_writes(),
        }
    }

    /// Finalises the device state after the acknowledgement.
    fn finalize(
        self,
        rng: &mut OsRng,
        state: &mut DeviceState,
        unlocked: &mut UnlockedDevice,
        vaults: &mut [&mut VaultSync],
    ) -> Result<RotationDone, ClientError> {
        match self {
            Self::Rotation(r) => (*r).finalize(rng, state, unlocked, vaults),
            Self::Credential(c) => (*c).finalize(rng, state, unlocked, vaults),
        }
    }
}
