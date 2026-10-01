//! Flow tests against an in-memory fake server built from `rizzy-core` and `rizzy-sync`
//! (ADR 0013 §6: "The `rizzy-client` flows run against a simulated server in plain Rust
//! tests"). The fake plays the server's half of each flow with the real crypto (OPAQUE,
//! signatures, envelopes); it is not `rizzy-server`, which this crate may not depend on
//! (ADR 0016 R6).
//!
//! Each OPAQUE registration, OPAQUE login and local unlock runs one 64 MiB Argon2id.

use std::collections::BTreeMap;

use chacha20::ChaCha20Rng;
use rand_core::{Rng as _, SeedableRng as _};
use rizzy_core::ids::{AccountId, DeviceId, ItemId, SessionId};
use rizzy_core::item::key::FieldKey as SchemaKey;
use rizzy_core::item::schema::{LOGIN_PASSWORD, LOGIN_USERNAME};
use rizzy_core::item::types::ItemType;
use rizzy_core::item::value::{Value, ValueRef};
use rizzy_core::kdf::KdfId;
use rizzy_core::normalize::{LoginName, ServerOrigin};
use rizzy_core::opaque::{
    CredentialIdentifier, OpaqueContext, PasswordFile, RegisteredCredential, ServerLoginState,
    ServerSetup, server_login_finish, server_login_start, server_registration_finish,
    server_registration_start,
};
use rizzy_core::sign::{
    AccountState, DeviceAuth, DeviceCertificate, DeviceKind, DeviceRequest, OpStatement,
    PublicKeyBundle, SnapshotStatement,
};
use rizzy_proto::account::{AccountStateQuery, AccountView, EnrolDeviceRequest};
use rizzy_proto::auth::{
    DeviceAuthFinishRequest, DeviceAuthFinishResponse, DeviceAuthStartRequest,
    DeviceAuthStartResponse, LoginFinishRequest, LoginFinishResponse, LoginStartRequest,
    LoginStartResponse, RegisterFinishRequest, RegisterStartRequest, RegisterStartResponse,
};
use rizzy_proto::objects::{
    AccountKeyServerWrap, AccountSettings, IdentitySecretKeys, ItemKeyWrap as WireItemKeyWrap,
    VaultSelfGrant,
};
use rizzy_proto::vault::{
    FetchRequest, FetchResponse, OpRecord, Record, SeqEntry, SeqVector, SnapshotRecord,
    UploadRequest, UploadResponse, UploadResult,
};
use rizzy_proto::wire::{Bytes, Fixed, Id, List, SessionToken, Text};
use rizzy_sync::dot::Dot;
use rizzy_sync::header::{OpHeader, SnapshotHeader};
use rizzy_sync::merge::ItemLifecycle;
use zeroize::Zeroizing;

use crate::account::{CertifiedDevice, RevokedDevice};
use crate::device::{DeviceState, UnlockedDevice};
use crate::error::ClientError;
use crate::items::FieldEdit;
use crate::login::{LoginInput, start_login};
use crate::session::{DeviceSession, device_auth_finish, device_auth_start};
use crate::signup::{SignedUp, SignupInput, start_signup};
use crate::sync::{Authors, VaultSync};
use crate::unlock::{account_state_query, verify_unlock};

/// The server's canonical origin.
const ORIGIN: &str = "https://vault.example.com";
/// The master password.
const PASSWORD: &str = "correct horse battery staple";
/// 2026-09-29 in ms.
const T0: u64 = 1_790_000_000_000;

/// The account the fake server holds (one per server).
struct Stored {
    /// The account.
    account_id: AccountId,
    /// The OPAQUE record.
    password_file: Vec<u8>,
    /// `E_srv`.
    e_srv: AccountKeyServerWrap,
    /// `E_id`.
    e_id: IdentitySecretKeys,
    /// Every bundle.
    bundles: Vec<Vec<u8>>,
    /// The current state.
    state: Vec<u8>,
    /// Certificates.
    certs: Vec<Vec<u8>>,
    /// Vault self-grants.
    grants: Vec<VaultSelfGrant>,
    /// `ACCOUNT_SETTINGS`, once written.
    settings: Option<AccountSettings>,
}

/// The fake server.
struct Server {
    /// The OPAQUE setup.
    setup: ServerSetup,
    /// The canonical origin.
    origin: ServerOrigin,
    /// The account.
    account: Option<Stored>,
    /// Pending logins.
    logins: Vec<(Id, ServerLoginState)>,
    /// Issued challenges.
    challenges: Vec<[u8; 32]>,
    /// Device sessions: session id → device.
    sessions: Vec<([u8; 16], DeviceId)>,
    /// Stored op records per device, by `device_seq`.
    ops: BTreeMap<[u8; 16], BTreeMap<u64, OpRecord>>,
    /// The current item-key wrap set.
    wraps: Vec<WireItemKeyWrap>,
    /// Stored snapshots, verified on upload, in upload order.
    snapshots: Vec<(SnapshotHeader, SnapshotRecord)>,
    /// The item of every stored op, by device and `device_seq`, for compaction.
    op_items: BTreeMap<([u8; 16], u64), ItemId>,
    /// Serve like a compacted server (ADR 0021): ops a stored snapshot covers go bodiless,
    /// with those snapshots as covers.
    compact: bool,
    /// The restore generation every answer carries.
    generation: [u8; 16],
    /// The pending device grants of rotations (`rotation` tests).
    device_grants: Vec<rizzy_proto::objects::DeviceGrant>,
    /// The next random value.
    rng: ChaCha20Rng,
}

fn bytes<const N: usize>(v: &[u8]) -> Bytes<N> {
    Bytes::from_slice(v).unwrap()
}

impl Server {
    fn new(seed: u64) -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        Self {
            setup: ServerSetup::generate(&mut rng),
            origin: ServerOrigin::parse(ORIGIN).unwrap(),
            account: None,
            logins: Vec::new(),
            challenges: Vec::new(),
            sessions: Vec::new(),
            ops: BTreeMap::new(),
            wraps: Vec::new(),
            snapshots: Vec::new(),
            op_items: BTreeMap::new(),
            compact: false,
            generation: [7; 16],
            device_grants: Vec::new(),
            rng,
        }
    }

    fn stored(&self) -> &Stored {
        self.account.as_ref().unwrap()
    }

    fn register_start(&self, req: &RegisterStartRequest) -> RegisterStartResponse {
        let id =
            CredentialIdentifier::for_account(AccountId::from_bytes(req.account_id.to_bytes()));
        let m2 = server_registration_start(&self.setup, req.registration_request.as_slice(), &id)
            .unwrap();
        RegisterStartResponse {
            registration_response: bytes(&m2),
        }
    }

    fn register_finish(&mut self, account_id: AccountId, req: &RegisterFinishRequest) {
        let file = server_registration_finish(req.registration_upload.as_slice()).unwrap();
        self.account = Some(Stored {
            account_id,
            password_file: file.to_bytes(),
            e_srv: req.account_key_server_wrap.clone(),
            e_id: req.identity_secret_keys.clone(),
            bundles: vec![req.bundle.as_slice().to_vec()],
            state: req.account_state.as_slice().to_vec(),
            certs: vec![req.device_certificate.as_slice().to_vec()],
            grants: vec![req.vault_self_grant.clone()],
            settings: None,
        });
    }

    fn context(&self) -> OpaqueContext {
        OpaqueContext::new(KdfId::DEFAULT, &self.origin)
    }

    fn login_start(&mut self, req: &LoginStartRequest) -> LoginStartResponse {
        let stored = self.stored();
        let record = RegisteredCredential {
            account_id: stored.account_id,
            password_file: PasswordFile::from_bytes(&stored.password_file).unwrap(),
            kdf_id: KdfId::DEFAULT,
        };
        let login = LoginName::parse(req.login_name.as_str()).unwrap();
        let ctx = self.context();
        let start = server_login_start(
            &mut self.rng,
            &self.setup,
            &login,
            Some(record),
            req.ke1.as_slice(),
            &ctx,
        )
        .unwrap();
        let mut id = [0u8; 16];
        self.rng.fill_bytes(&mut id);
        let login_id = Id::from_bytes(id);
        self.logins.push((login_id, start.state));
        LoginStartResponse {
            login_id,
            ke2: bytes(&start.ke2),
            kdf_id: 1,
            server_origin: Text::from_str(ORIGIN).unwrap(),
        }
    }

    fn view(&self) -> AccountView {
        let s = self.stored();
        AccountView {
            account_state: bytes(&s.state),
            bundles: List::new(s.bundles.iter().map(|b| bytes(b)).collect()).unwrap(),
            device_certificates: List::new(s.certs.iter().map(|c| bytes(c)).collect()).unwrap(),
            device_revocations: List::empty(),
            account_settings: s.settings.clone(),
            identity_secret_keys: s.e_id.clone(),
            vault_self_grants: List::new(s.grants.clone()).unwrap(),
        }
    }

    /// The answer to an [`AccountStateQuery`], as the real server builds it: the settings are
    /// left out when the query's `known_settings_seq` is the current one.
    fn view_since(&self, query: &AccountStateQuery) -> AccountView {
        let mut view = self.view();
        if view
            .account_settings
            .as_ref()
            .is_some_and(|s| s.settings_seq == query.known_settings_seq)
        {
            view.account_settings = None;
        }
        view
    }

    fn token(&mut self) -> SessionToken {
        let mut t = Zeroizing::new([0u8; 32]);
        self.rng.fill_bytes(t.as_mut_slice());
        SessionToken::new(t)
    }

    fn login_finish(&mut self, req: &LoginFinishRequest) -> Result<LoginFinishResponse, ()> {
        let at = self
            .logins
            .iter()
            .position(|(id, _)| *id == req.login_id)
            .ok_or(())?;
        let (_, state) = self.logins.swap_remove(at);
        let ctx = self.context();
        server_login_finish(state, req.ke3.as_slice(), &ctx).map_err(|_| ())?;
        Ok(LoginFinishResponse {
            session_token: self.token(),
            account_id: Id::from_bytes(self.stored().account_id.to_bytes()),
            account_key_server_wrap: self.stored().e_srv.clone(),
            account: self.view(),
        })
    }

    fn enrol(&mut self, req: &EnrolDeviceRequest) {
        let s = self.account.as_mut().unwrap();
        s.certs.push(req.device_certificate.as_slice().to_vec());
        s.state = req.account_state.as_slice().to_vec();
    }

    /// The verified authors the fake uses to check uploads.
    fn authors(&self) -> Authors {
        let s = self.stored();
        let bundle = PublicKeyBundle::verify_self_signed(s.bundles.last().unwrap()).unwrap();
        let certs: Vec<CertifiedDevice> = s
            .certs
            .iter()
            .map(|w| CertifiedDevice {
                certificate: DeviceCertificate::verify(w, &bundle.identity_ed25519, 0).unwrap(),
                wire: w.clone(),
            })
            .collect();
        let revs: Vec<RevokedDevice> = Vec::new();
        Authors::from_statements(&certs, &revs).unwrap()
    }

    fn device_auth_start(&mut self, _req: &DeviceAuthStartRequest) -> DeviceAuthStartResponse {
        let mut c = [0u8; 32];
        self.rng.fill_bytes(&mut c);
        self.challenges.push(c);
        DeviceAuthStartResponse {
            challenge: Fixed::from_bytes(c),
        }
    }

    fn device_auth_finish(
        &mut self,
        req: &DeviceAuthFinishRequest,
    ) -> Result<DeviceAuthFinishResponse, ()> {
        let challenge = req.challenge.to_bytes();
        let at = self
            .challenges
            .iter()
            .position(|c| *c == challenge)
            .ok_or(())?;
        self.challenges.swap_remove(at);
        let device_id = DeviceId::from_bytes(req.device_id.to_bytes());
        let authors = self.authors();
        let author = authors
            .entries_for_tests()
            .find(|a| a.status.device == device_id)
            .ok_or(())?;
        let origin = self.origin.clone();
        DeviceAuth {
            server_origin: &origin,
            account_id: AccountId::from_bytes(req.account_id.to_bytes()),
            device_id,
            challenge,
        }
        .verify(req.signature.as_bytes(), &author.verifying_key)
        .map_err(|_| ())?;
        let mut sid = [0u8; 16];
        self.rng.fill_bytes(&mut sid);
        self.sessions.push((sid, device_id));
        Ok(DeviceAuthFinishResponse {
            session_token: self.token(),
            session_id: Id::from_bytes(sid),
        })
    }

    fn heads(&self) -> SeqVector {
        SeqVector::new(
            self.ops
                .iter()
                .filter_map(|(d, chain)| {
                    Some(SeqEntry {
                        device_id: Id::from_bytes(*d),
                        seq: *chain.keys().last()?,
                    })
                })
                .collect(),
        )
        .unwrap()
    }

    fn upload(&mut self, req: &UploadRequest) -> UploadResponse {
        let authors = self.authors();
        let mut results = Vec::new();
        for record in req.records.as_slice() {
            let result = match record {
                Record::Op(op) => {
                    let wire = op.statement.as_slice();
                    let author = authors.signer(wire).unwrap();
                    let verified = OpStatement::verify(wire, &author.verifying_key).unwrap();
                    let header = OpHeader::parse_statement(&verified).unwrap();
                    let chain = self
                        .ops
                        .entry(header.dot.device_id().to_bytes())
                        .or_default();
                    match chain.get(&header.dot.seq()) {
                        Some(held) if held == op => UploadResult::AlreadyStored,
                        Some(_) => UploadResult::Rejected {
                            error: rizzy_proto::error::ErrorCode::RecordConflict,
                        },
                        None => {
                            if let Some(w) = &op.key_wrap {
                                self.wraps.push(WireItemKeyWrap {
                                    item_id: Id::from_bytes(header.item_id.to_bytes()),
                                    item_key_id: w.item_key_id,
                                    vault_key_epoch: header.vault_key_epoch,
                                    envelope: w.envelope.clone(),
                                });
                            }
                            chain.insert(header.dot.seq(), op.clone());
                            self.op_items.insert(
                                (header.dot.device_id().to_bytes(), header.dot.seq()),
                                header.item_id,
                            );
                            UploadResult::Stored
                        }
                    }
                }
                Record::Snapshot(snapshot) => self.store_snapshot(&authors, req, snapshot),
            };
            results.push(result);
        }
        UploadResponse {
            restore_generation: Fixed::from_bytes(self.generation),
            results: List::new(results).unwrap(),
        }
    }

    /// Checks an uploaded snapshot as the server does (ADR 0021 §9): the signature under its
    /// author's certificate, the strict header, the author and vault, the envelope hash, and a
    /// covered VV that claims only dots the server stores. Stores it if new.
    fn store_snapshot(
        &mut self,
        authors: &Authors,
        req: &UploadRequest,
        snapshot: &SnapshotRecord,
    ) -> UploadResult {
        let refused = UploadResult::Rejected {
            error: rizzy_proto::error::ErrorCode::InvalidRequest,
        };
        let wire = snapshot.statement.as_slice();
        let Some(author) = authors.signer(wire) else {
            return refused;
        };
        let Ok(verified) = SnapshotStatement::verify(wire, &author.verifying_key) else {
            return refused;
        };
        let Ok(header) = SnapshotHeader::parse_statement(&verified) else {
            return refused;
        };
        let stored = header.covered.entries().all(|dot| {
            self.ops
                .get(&dot.device_id().to_bytes())
                .and_then(|chain| chain.keys().last())
                .is_some_and(|&head| head >= dot.seq())
        });
        if header.author != author.status.device
            || header.vault_id.to_bytes() != req.vault_id.to_bytes()
            || !verified.matches_envelope(snapshot.envelope.as_slice())
            || !stored
        {
            return refused;
        }
        if self
            .snapshots
            .iter()
            .any(|(h, _)| h.snapshot_id == header.snapshot_id)
        {
            return UploadResult::AlreadyStored;
        }
        self.snapshots.push((header, snapshot.clone()));
        UploadResult::Stored
    }

    /// A healing request as the server takes it (ADR 0021 §9 "Server acceptance"), simplified:
    /// all or nothing; wraps fill rows; each op is verified and stored unless the same
    /// statement is held at its dot (another one refuses the request); a bodiless header needs
    /// a snapshot of the request that covers it; the snapshots then pass the upload checks
    /// against the heads after the request's headers. No stale-epoch check.
    fn heal(
        &mut self,
        req: &rizzy_proto::vault::HealingRequest,
    ) -> Result<rizzy_proto::vault::HealingResponse, ()> {
        let saved = (
            self.ops.clone(),
            self.wraps.clone(),
            self.snapshots.clone(),
            self.op_items.clone(),
        );
        let authors = self.authors();
        let snapshots: Vec<SnapshotHeader> = req
            .records
            .as_slice()
            .iter()
            .filter_map(|r| match r {
                Record::Snapshot(s) => {
                    let wire = s.statement.as_slice();
                    let author = authors.signer(wire)?;
                    let verified = SnapshotStatement::verify(wire, &author.verifying_key).ok()?;
                    SnapshotHeader::parse_statement(&verified).ok()
                }
                Record::Op(_) => None,
            })
            .collect();
        let mut ok = true;
        self.wraps
            .extend(req.item_key_wraps.as_slice().iter().cloned());
        for record in req.records.as_slice() {
            let Record::Op(op) = record else { continue };
            let wire = op.statement.as_slice();
            let Some(author) = authors.signer(wire) else {
                ok = false;
                break;
            };
            let Ok(verified) = OpStatement::verify(wire, &author.verifying_key) else {
                ok = false;
                break;
            };
            let header = OpHeader::parse_statement(&verified).unwrap();
            if op.body.is_none()
                && !snapshots
                    .iter()
                    .any(|s| s.item_id == header.item_id && s.covered.covers(header.dot))
            {
                ok = false;
                break;
            }
            let chain = self
                .ops
                .entry(header.dot.device_id().to_bytes())
                .or_default();
            match chain.get(&header.dot.seq()) {
                Some(held) if held.statement == op.statement => {}
                Some(_) => {
                    ok = false;
                    break;
                }
                None => {
                    if let Some(w) = &op.key_wrap {
                        self.wraps.push(WireItemKeyWrap {
                            item_id: Id::from_bytes(header.item_id.to_bytes()),
                            item_key_id: w.item_key_id,
                            vault_key_epoch: header.vault_key_epoch,
                            envelope: w.envelope.clone(),
                        });
                    }
                    chain.insert(header.dot.seq(), op.clone());
                    self.op_items.insert(
                        (header.dot.device_id().to_bytes(), header.dot.seq()),
                        header.item_id,
                    );
                }
            }
        }
        let as_upload = UploadRequest {
            vault_id: req.vault_id,
            records: List::new(Vec::new()).unwrap(),
        };
        for record in req.records.as_slice() {
            let Record::Snapshot(snapshot) = record else {
                continue;
            };
            if !ok {
                break;
            }
            if let UploadResult::Rejected { .. } =
                self.store_snapshot(&authors, &as_upload, snapshot)
            {
                ok = false;
            }
        }
        if !ok {
            (self.ops, self.wraps, self.snapshots, self.op_items) = saved;
            return Err(());
        }
        Ok(rizzy_proto::vault::HealingResponse {
            restore_generation: Fixed::from_bytes(self.generation),
        })
    }

    fn fetch(&self, req: &FetchRequest) -> FetchResponse {
        let mut ops = Vec::new();
        let mut covers: Vec<SnapshotRecord> = Vec::new();
        for (device, chain) in &self.ops {
            let have = req.cursor.get(&Id::from_bytes(*device));
            for (&seq, record) in chain.range(have + 1..) {
                let mut record = record.clone();
                if self.compact {
                    let item = self.op_items[&(*device, seq)];
                    let dot = Dot::new(DeviceId::from_bytes(*device), seq).unwrap();
                    // Newest cover first (ADR 0021 §4).
                    let cover = self
                        .snapshots
                        .iter()
                        .rev()
                        .find(|(h, _)| h.item_id == item && h.covered.covers(dot));
                    if let Some((_, cover)) = cover {
                        record.body = None;
                        if !covers.contains(cover) {
                            covers.push(cover.clone());
                        }
                    }
                }
                ops.push(record);
            }
        }
        FetchResponse {
            restore_generation: Fixed::from_bytes(self.generation),
            heads: self.heads(),
            ops: List::new(ops).unwrap(),
            covers: List::new(covers).unwrap(),
            item_key_wraps: List::new(self.wraps.clone()).unwrap(),
            complete: true,
        }
    }
}

impl Authors {
    /// Test access to the entries.
    fn entries_for_tests(&self) -> impl Iterator<Item = &crate::sync::Author> {
        self.entries.iter()
    }
}

/// Signs up a durable device (or a web vault for kind 4).
fn signup(server: &mut Server, rng: &mut ChaCha20Rng, kind: DeviceKind) -> SignedUp {
    let input = SignupInput {
        server_origin: ORIGIN,
        login_name: "Alice",
        password: PASSWORD,
        invite: None,
        issue_recovery_code: true,
        device_kind: kind,
        now_ms: T0,
    };
    let (started, request) = start_signup(rng, &input).unwrap();
    let account_id = AccountId::from_bytes(request.account_id.to_bytes());
    let response = server.register_start(&request);
    let mut pending = started.finish(rng, &response).unwrap();
    assert_eq!(
        pending.commit_request().unwrap_err(),
        ClientError::EmergencyKitNotConfirmed
    );
    let kit = pending.emergency_kit();
    assert!(kit.secret_key().starts_with("RV1-"));
    assert!(kit.recovery_code().unwrap().starts_with("RVR1-"));
    let last = kit.secret_key().rsplit('-').next().unwrap().to_owned();
    let wrong: String = last.chars().rev().collect::<String>() + "0";
    assert!(pending.confirm_kit(&wrong).is_err());
    assert_eq!(pending.pending_device().is_some(), kind.is_durable());
    pending.confirm_kit(&last).unwrap();
    server.register_finish(account_id, pending.commit_request().unwrap());
    pending.finalize().unwrap()
}

/// The printed Secret Key of a device state, through the kit's format.
fn secret_key_text(state: &DeviceState) -> String {
    state.secret_key.to_formatted().to_string()
}

/// Device authentication of an unlocked device.
fn device_session(
    server: &mut Server,
    state: &DeviceState,
    unlocked: &UnlockedDevice,
) -> DeviceSession {
    let start = device_auth_start(state);
    let challenge = server.device_auth_start(&start);
    let finish = device_auth_finish(state, unlocked, &challenge).unwrap();
    let answer = server.device_auth_finish(&finish).unwrap();
    DeviceSession::new(state, answer)
}

/// Logs in on a new device and enrols it.
fn login_and_enrol(server: &mut Server, rng: &mut ChaCha20Rng, sk: &str) -> crate::login::Enrolled {
    let input = LoginInput {
        server_origin: ORIGIN,
        login_name: "alice",
        secret_key: sk,
        password: PASSWORD,
    };
    let (started, request) = start_login(rng, &input).unwrap();
    let answer = server.login_start(&request);
    let (awaiting, finish) = started.finish(rng, &answer, None).unwrap();
    let response = server.login_finish(&finish).unwrap();
    let logged_in = awaiting.complete(response).unwrap();
    assert_eq!(logged_in.account().certificates().len(), 1);
    let (pending, enrol) = logged_in
        .enrol(rng, DeviceKind::DesktopCli, T0 + 1000)
        .unwrap();
    server.enrol(&enrol);
    pending.finalize()
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one end-to-end story: signup, login, enrolment, unlock, signing and sync, in order"
)]
fn signup_login_enrol_unlock_and_sync() {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let mut server = Server::new(2);
    let a = signup(&mut server, &mut rng, DeviceKind::DesktopCli);
    let mut a_state = a.device.unwrap();
    let vault_id = a.vault_key.vault_id();
    let sk = secret_key_text(&a_state);

    // A second device logs in and enrols; the state moves to seq 2 with two devices.
    let b = login_and_enrol(&mut server, &mut rng, &sk);
    assert_eq!(b.account.state().state_seq, 2);
    let mut b_account = b.account;
    let b_vault_key = b_account.take_vault_key(vault_id).unwrap();

    // Device A unlocks offline, authenticates and verifies the new state.
    assert_eq!(
        a_state.unlock("wrong password").unwrap_err(),
        ClientError::WrongPasswordOrSecretKey
    );
    let a_unlocked = a_state.unlock(PASSWORD).unwrap();
    let mut a_session = device_session(&mut server, &a_state, &a_unlocked);
    let query = account_state_query(&a_state);
    assert_eq!(query.known_bundle_seq, 1);
    assert_eq!(query.known_settings_seq, 0);
    let a_account =
        verify_unlock(&mut a_state, &a_unlocked, &server.view_since(&query), None).unwrap();
    assert_eq!(a_account.certificates().len(), 2);
    assert_eq!(a_state.pin().state().state_seq, 2);
    assert_eq!(a_account.fingerprint(), b_account.fingerprint());

    // Request signing: the server rebuilds and verifies the statement.
    let sig = a_session
        .sign_request(&a_unlocked, "POST", "/api/v1/vault/upload", b"{}")
        .unwrap();
    assert_eq!(sig.request_counter, 1);
    let (sid, _) = server.sessions[0];
    let origin = ServerOrigin::parse(ORIGIN).unwrap();
    let authors = Authors::from_account(&a_account).unwrap();
    let key = authors
        .entries_for_tests()
        .find(|e| e.status.device == a_state.device_id())
        .unwrap()
        .verifying_key;
    DeviceRequest {
        server_origin: &origin,
        account_id: a_state.account_id(),
        device_id: a_state.device_id(),
        session_id: SessionId::from_bytes(sid),
        request_counter: 1,
        method: "POST",
        path_and_query: "/api/v1/vault/upload",
        body_hash: DeviceRequest::body_hash(b"{}"),
    }
    .verify(sig.signature.as_bytes(), &key)
    .unwrap();
    let next = a_session
        .sign_request(&a_unlocked, "GET", "/api/v1/x", b"")
        .unwrap();
    assert_eq!(next.request_counter, 2);

    // Sync: A creates a login, B sees it, edits it, A sees the edit.
    let mut a_vault = VaultSync::new(a.vault_key, &a_unlocked, 1).unwrap();
    let mut b_vault = VaultSync::new(b_vault_key, &b.unlocked, 1).unwrap();
    // An upload before any server answer is refused: the restore generation is unknown.
    assert_eq!(
        a_vault.upload_request(&mut rng, &a_unlocked).unwrap_err(),
        ClientError::FetchRequired
    );
    let first = a_vault
        .apply_fetch(
            &authors,
            &server.fetch(&a_vault.fetch_request().unwrap()),
            T0 + 1500,
        )
        .unwrap();
    assert_eq!(first.applied, 0);
    let user_key = SchemaKey::parse(LOGIN_USERNAME.as_bytes()).unwrap();
    let pass_key = SchemaKey::parse(LOGIN_PASSWORD.as_bytes()).unwrap();
    let alice = Value::text("alice").unwrap();
    let secret = Value::text("hunter2").unwrap();
    let item = a_vault
        .create_item(
            &mut rng,
            &a_unlocked,
            ItemType::LOGIN,
            &[
                FieldEdit {
                    key: &user_key,
                    value: &alice,
                },
                FieldEdit {
                    key: &pass_key,
                    value: &secret,
                },
            ],
            T0 + 2000,
        )
        .unwrap();
    assert_eq!(a_vault.item_lifecycle(item), ItemLifecycle::Active);
    assert_eq!(a_vault.item_type(item), Some(ItemType::LOGIN));
    let upload = a_vault
        .upload_request(&mut rng, &a_unlocked)
        .unwrap()
        .unwrap();
    let answer = server.upload(&upload);
    let outcome = a_vault.apply_upload_response(&answer).unwrap();
    assert_eq!(outcome.acknowledged, 1);
    // The fresh item key's snapshot (ADR 0018 §10) goes once its op is acknowledged.
    let upload = a_vault
        .upload_request(&mut rng, &a_unlocked)
        .unwrap()
        .unwrap();
    assert!(matches!(upload.records.as_slice(), [Record::Snapshot(_)]));
    let answer = server.upload(&upload);
    assert_eq!(
        a_vault
            .apply_upload_response(&answer)
            .unwrap()
            .snapshots_stored,
        1
    );
    assert!(
        a_vault
            .upload_request(&mut rng, &a_unlocked)
            .unwrap()
            .is_none()
    );

    let b_authors = Authors::from_account(&b_account).unwrap();
    let fetched = b_vault
        .apply_fetch(
            &b_authors,
            &server.fetch(&b_vault.fetch_request().unwrap()),
            T0 + 3000,
        )
        .unwrap();
    assert_eq!(fetched.applied, 1, "{fetched:?}");
    assert!(!fetched.server_behind);
    assert_eq!(b_vault.item_ids(), vec![item]);
    let shown = b_vault.field_value(item, LOGIN_PASSWORD).unwrap();
    assert!(matches!(
        ValueRef::decode(shown.expose_secret()).unwrap(),
        ValueRef::Text("hunter2")
    ));
    assert_eq!(b_vault.field_keys(item).len(), 3);

    let changed = Value::text("correct horse").unwrap();
    b_vault
        .edit_item(
            &mut rng,
            &b.unlocked,
            item,
            &[FieldEdit {
                key: &pass_key,
                value: &changed,
            }],
            T0 + 4000,
        )
        .unwrap();
    let upload = b_vault
        .upload_request(&mut rng, &b.unlocked)
        .unwrap()
        .unwrap();
    // The answer is lost: the server stored the op, but B never heard. B sends the same
    // records again, and "already stored" acknowledges them (ADR 0021 §9).
    let _lost = server.upload(&upload);
    let again = b_vault
        .upload_request(&mut rng, &b.unlocked)
        .unwrap()
        .unwrap();
    assert_eq!(again.records, upload.records);
    let answer = server.upload(&again);
    assert!(!answer.results.as_slice().is_empty());
    assert!(
        answer
            .results
            .as_slice()
            .iter()
            .all(|r| *r == UploadResult::AlreadyStored),
        "{answer:?}"
    );
    let outcome = b_vault.apply_upload_response(&answer).unwrap();
    assert_eq!(outcome.acknowledged, 1);
    assert!(outcome.rejected.is_empty());

    let fetched = a_vault
        .apply_fetch(
            &authors,
            &server.fetch(&a_vault.fetch_request().unwrap()),
            T0 + 5000,
        )
        .unwrap();
    assert_eq!(fetched.applied, 1, "{fetched:?}");
    let shown = a_vault.field_value(item, LOGIN_PASSWORD).unwrap();
    assert!(matches!(
        ValueRef::decode(shown.expose_secret()).unwrap(),
        ValueRef::Text("correct horse")
    ));
    assert!(!a_vault.field_conflicts(item, LOGIN_PASSWORD));

    // Concurrent edits: both kept, shown as a conflict.
    let x = Value::text("x").unwrap();
    let y = Value::text("y").unwrap();
    a_vault
        .edit_item(
            &mut rng,
            &a_unlocked,
            item,
            &[FieldEdit {
                key: &pass_key,
                value: &x,
            }],
            T0 + 6000,
        )
        .unwrap();
    b_vault
        .edit_item(
            &mut rng,
            &b.unlocked,
            item,
            &[FieldEdit {
                key: &pass_key,
                value: &y,
            }],
            T0 + 6000,
        )
        .unwrap();
    for (vault, unlocked) in [(&mut a_vault, &a_unlocked), (&mut b_vault, &b.unlocked)] {
        let up = vault.upload_request(&mut rng, unlocked).unwrap().unwrap();
        let ans = server.upload(&up);
        vault.apply_upload_response(&ans).unwrap();
    }
    a_vault
        .apply_fetch(
            &authors,
            &server.fetch(&a_vault.fetch_request().unwrap()),
            T0 + 7000,
        )
        .unwrap();
    b_vault
        .apply_fetch(
            &b_authors,
            &server.fetch(&b_vault.fetch_request().unwrap()),
            T0 + 7000,
        )
        .unwrap();
    assert!(a_vault.field_conflicts(item, LOGIN_PASSWORD));
    assert!(b_vault.field_conflicts(item, LOGIN_PASSWORD));
    let a_shown = a_vault.field_value(item, LOGIN_PASSWORD).unwrap();
    let b_shown = b_vault.field_value(item, LOGIN_PASSWORD).unwrap();
    assert_eq!(a_shown.expose_secret(), b_shown.expose_secret());

    // Trash, restore, trash, purge.
    assert_eq!(
        a_vault
            .purge_item(&mut rng, &a_unlocked, item, T0 + 8000)
            .unwrap_err(),
        ClientError::UnknownItem
    );
    a_vault
        .trash_item(&mut rng, &a_unlocked, item, T0 + 8000)
        .unwrap();
    assert_eq!(a_vault.item_lifecycle(item), ItemLifecycle::Trashed);
    a_vault
        .restore_item(&mut rng, &a_unlocked, item, T0 + 8001)
        .unwrap();
    assert_eq!(a_vault.item_lifecycle(item), ItemLifecycle::Active);
    a_vault
        .trash_item(&mut rng, &a_unlocked, item, T0 + 8002)
        .unwrap();
    a_vault
        .purge_item(&mut rng, &a_unlocked, item, T0 + 8003)
        .unwrap();
    assert_eq!(a_vault.item_lifecycle(item), ItemLifecycle::Purged);
    let up = a_vault
        .upload_request(&mut rng, &a_unlocked)
        .unwrap()
        .unwrap();
    let ans = server.upload(&up);
    let out = a_vault.apply_upload_response(&ans).unwrap();
    assert_eq!(out.acknowledged, 4);
    b_vault
        .apply_fetch(
            &b_authors,
            &server.fetch(&b_vault.fetch_request().unwrap()),
            T0 + 9000,
        )
        .unwrap();
    assert_eq!(b_vault.item_lifecycle(item), ItemLifecycle::Purged);

    // Read-only refuses writes.
    b_vault.set_read_only(true);
    assert_eq!(
        b_vault
            .create_item(&mut rng, &b.unlocked, ItemType::LOGIN, &[], T0 + 9500)
            .unwrap_err(),
        ClientError::ReadOnly
    );
}

#[test]
fn unlock_detects_rollback_fork_and_hidden_devices() {
    let mut rng = ChaCha20Rng::seed_from_u64(3);
    let mut server = Server::new(4);
    let a = signup(&mut server, &mut rng, DeviceKind::DesktopCli);
    let mut a_state = a.device.unwrap();
    let first_view = server.view();
    let sk = secret_key_text(&a_state);
    let b = login_and_enrol(&mut server, &mut rng, &sk);
    let a_unlocked = a_state.unlock(PASSWORD).unwrap();
    let account = verify_unlock(&mut a_state, &a_unlocked, &server.view(), None).unwrap();
    assert_eq!(a_state.pin().state().state_seq, 2);

    // Rollback: the server serves the signup state again.
    assert_eq!(
        verify_unlock(&mut a_state, &a_unlocked, &first_view, None).unwrap_err(),
        ClientError::Rollback
    );
    // Fork: another state at seq 2, validly signed.
    let mut forked: AccountState = account.state().clone();
    forked.mail_key_epoch = 7;
    let wire = forked.sign(account.identity.signing_key()).unwrap();
    let mut view = server.view();
    view.account_state = bytes(&wire);
    assert_eq!(
        verify_unlock(&mut a_state, &a_unlocked, &view, None).unwrap_err(),
        ClientError::Fork
    );
    // A hidden device: the second certificate withheld.
    let mut view = server.view();
    view.device_certificates =
        List::new(vec![view.device_certificates.as_slice()[0].clone()]).unwrap();
    assert_eq!(
        verify_unlock(&mut a_state, &a_unlocked, &view, None).unwrap_err(),
        ClientError::InvalidServerResponse
    );
    // A tampered signature on the state.
    let mut view = server.view();
    let mut tampered = view.account_state.as_slice().to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    view.account_state = bytes(&tampered);
    assert_eq!(
        verify_unlock(&mut a_state, &a_unlocked, &view, None).unwrap_err(),
        ClientError::InvalidServerResponse
    );
    // Another device's keys are refused.
    assert_eq!(
        verify_unlock(&mut a_state, &b.unlocked, &server.view(), None).unwrap_err(),
        ClientError::InvalidInput
    );
    // The pin did not move.
    assert_eq!(a_state.pin().state().state_seq, 2);
}

#[test]
fn login_refuses_foreign_origin_kdf_and_wrong_password() {
    let mut rng = ChaCha20Rng::seed_from_u64(5);
    let mut server = Server::new(6);
    let a = signup(&mut server, &mut rng, DeviceKind::DesktopCli);
    let sk = secret_key_text(a.device.as_ref().unwrap());
    let input = LoginInput {
        server_origin: ORIGIN,
        login_name: "alice",
        secret_key: &sk,
        password: "not the password",
    };
    // A foreign origin and an unknown kdf_id are refused before stretching.
    let (started, request) = start_login(&mut rng, &input).unwrap();
    let mut answer = server.login_start(&request);
    answer.server_origin = Text::from_str("https://evil.example").unwrap();
    assert_eq!(
        started.finish(&mut rng, &answer, None).unwrap_err(),
        ClientError::OriginMismatch
    );
    let (started, request) = start_login(&mut rng, &input).unwrap();
    let mut answer = server.login_start(&request);
    answer.kdf_id = 9;
    assert_eq!(
        started.finish(&mut rng, &answer, None).unwrap_err(),
        ClientError::KdfNotAllowed
    );
    // A wrong password fails the OPAQUE finish.
    let (started, request) = start_login(&mut rng, &input).unwrap();
    let answer = server.login_start(&request);
    assert_eq!(
        started.finish(&mut rng, &answer, None).unwrap_err(),
        ClientError::WrongPasswordOrSecretKey
    );
    // Malformed input.
    let bad = LoginInput {
        secret_key: "RV1-nope",
        ..input
    };
    assert_eq!(
        start_login(&mut rng, &bad).unwrap_err(),
        ClientError::InvalidInput
    );
}

#[test]
fn web_vault_signup_has_no_device_state() {
    let mut rng = ChaCha20Rng::seed_from_u64(8);
    let mut server = Server::new(9);
    let web = signup(&mut server, &mut rng, DeviceKind::WebEphemeral);
    assert!(web.device.is_none());
    let cert = &web.own_certificate.certificate;
    assert_eq!(cert.device_kind, DeviceKind::WebEphemeral);
    assert!(cert.expires_at_ms > T0);
    // The signed device set is the empty set.
    let empty = rizzy_core::keys::device_set_hash(
        cert.account_id,
        core::iter::empty(),
        core::iter::empty(),
    )
    .unwrap();
    let state = AccountState::verify(
        &server.stored().state,
        &PublicKeyBundle::verify_self_signed(&server.stored().bundles[0])
            .unwrap()
            .identity_ed25519,
        0,
    )
    .unwrap();
    assert_eq!(state.device_set_hash, empty);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one reader story: a withheld wrap, a forged body, an unknown signer, then honest answers"
)]
fn fetch_drops_forged_records() {
    let mut rng = ChaCha20Rng::seed_from_u64(10);
    let mut server = Server::new(11);
    let a = signup(&mut server, &mut rng, DeviceKind::DesktopCli);
    let sk = secret_key_text(a.device.as_ref().unwrap());
    let vault_id = a.vault_key.vault_id();
    let b = login_and_enrol(&mut server, &mut rng, &sk);
    let authors = Authors::from_account(&b.account).unwrap();
    let mut writer = VaultSync::new(a.vault_key, &a.unlocked, 1).unwrap();
    writer
        .apply_fetch(
            &authors,
            &server.fetch(&writer.fetch_request().unwrap()),
            T0,
        )
        .unwrap();
    let key = SchemaKey::parse(LOGIN_USERNAME.as_bytes()).unwrap();
    let v = Value::text("u").unwrap();
    let item = writer
        .create_item(
            &mut rng,
            &a.unlocked,
            ItemType::LOGIN,
            &[FieldEdit {
                key: &key,
                value: &v,
            }],
            T0,
        )
        .unwrap();
    let up = writer
        .upload_request(&mut rng, &a.unlocked)
        .unwrap()
        .unwrap();
    server.upload(&up);
    let mut b_account = b.account;
    let mut reader =
        VaultSync::new(b_account.take_vault_key(vault_id).unwrap(), &b.unlocked, 1).unwrap();

    // The item key's wrap withheld: the body waits for it (CRYPTO.md §11.6 reader rule).
    let mut response = server.fetch(&reader.fetch_request().unwrap());
    let mut ops = response.ops.into_vec();
    ops[0].key_wrap = None;
    response.ops = List::new(ops).unwrap();
    response.item_key_wraps = List::empty();
    let out = reader.apply_fetch(&authors, &response, T0 + 1).unwrap();
    assert_eq!(out.applied, 0, "{out:?}");
    assert_eq!(reader.item_lifecycle(item), ItemLifecycle::Absent);
    // The honest response carries the wrap and releases the waiting body.
    let out = reader
        .apply_fetch(
            &authors,
            &server.fetch(&reader.fetch_request().unwrap()),
            T0 + 2,
        )
        .unwrap();
    assert_eq!(out.applied, 1, "{out:?}");
    assert_eq!(reader.item_lifecycle(item), ItemLifecycle::Active);

    // A second op, served forged.
    let w = Value::text("w").unwrap();
    writer
        .edit_item(
            &mut rng,
            &a.unlocked,
            item,
            &[FieldEdit {
                key: &key,
                value: &w,
            }],
            T0 + 3,
        )
        .unwrap();
    let up = writer
        .upload_request(&mut rng, &a.unlocked)
        .unwrap()
        .unwrap();
    server.upload(&up);

    // A body that does not match the signed hash is rejected, never applied.
    let mut response = server.fetch(&reader.fetch_request().unwrap());
    let mut ops = response.ops.into_vec();
    let mut body = ops[0].body.as_ref().unwrap().as_slice().to_vec();
    body[40] ^= 1;
    ops[0].body = Some(bytes(&body));
    response.ops = List::new(ops).unwrap();
    let out = reader.apply_fetch(&authors, &response, T0 + 4).unwrap();
    assert_eq!(out.applied, 0);

    // An unknown signer is dropped before the chain check.
    let out = reader
        .apply_fetch(
            &Authors::default(),
            &server.fetch(&reader.fetch_request().unwrap()),
            T0 + 5,
        )
        .unwrap();
    assert_eq!(out.applied, 0);
    assert!(out.dropped >= 1);

    // The honest response applies.
    let out = reader
        .apply_fetch(
            &authors,
            &server.fetch(&reader.fetch_request().unwrap()),
            T0 + 6,
        )
        .unwrap();
    assert_eq!(out.applied, 1, "{out:?}");
    let shown = reader.field_value(item, LOGIN_USERNAME).unwrap();
    assert!(matches!(
        ValueRef::decode(shown.expose_secret()).unwrap(),
        ValueRef::Text("w")
    ));
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the rotation the fake server needs is built inline, then the unlock story in order"
)]
fn unlock_after_rotation_opens_device_grants() {
    use rizzy_core::envelope::purpose::{
        AccountKeyDeviceGrantCtx, IdentitySecretKeysCtx, VaultKeySelfGrantCtx,
    };
    use rizzy_core::keys::{GrantSigner, seal_account_key_device_grant};
    use rizzy_proto::account::DeviceGrantsResponse;
    use rizzy_proto::objects::DeviceGrant;

    let mut rng = ChaCha20Rng::seed_from_u64(12);
    let mut server = Server::new(13);
    let a = signup(&mut server, &mut rng, DeviceKind::DesktopCli);
    let mut a_state = a.device.unwrap();
    let vault_id = a.vault_key.vault_id();
    let sk = secret_key_text(&a_state);
    let b = login_and_enrol(&mut server, &mut rng, &sk);
    let mut b_account = b.account;
    let vault_key = b_account.take_vault_key(vault_id).unwrap();
    let account_id = b_account.account_id();

    // Device B rotates the account key (a standard rotation, CRYPTO.md §11.6), granting the new
    // key to device A.
    let old_key = &b.unlocked.account_key;
    let new_key = old_key.generate_next(&mut rng).unwrap();
    let a_cert = b_account
        .certificates()
        .iter()
        .find(|c| c.certificate.device_id == a_state.device_id())
        .unwrap()
        .certificate
        .clone();
    let ctx = AccountKeyDeviceGrantCtx {
        account_id,
        account_key_epoch: 1,
        sender_device_id: b.unlocked.device_id,
        recipient_device_id: a_state.device_id(),
    };
    let grant = seal_account_key_device_grant(
        &mut rng,
        &ctx,
        &new_key,
        old_key,
        &a_cert,
        GrantSigner::Device(b.unlocked.device_keys.signing_key()),
    )
    .unwrap();
    let e_id = new_key
        .wrap_identity_keys(
            &mut rng,
            &IdentitySecretKeysCtx {
                account_id,
                identity_epoch: 0,
            },
            &b_account.identity,
        )
        .unwrap();
    let self_grant = new_key
        .wrap_vault_key(
            &mut rng,
            &VaultKeySelfGrantCtx {
                account_id,
                vault_id,
                account_key_epoch: 1,
                vault_key_epoch: 0,
            },
            &vault_key,
        )
        .unwrap();
    let mut state = b_account.state().clone();
    state.state_seq += 1;
    state.account_key_epoch = 1;
    state.account_key_id = new_key.key_id().unwrap();
    let state_wire = state.sign(b_account.identity.signing_key()).unwrap();
    {
        let s = server.account.as_mut().unwrap();
        s.state = state_wire;
        s.e_id = IdentitySecretKeys {
            identity_epoch: 0,
            envelope: bytes(&e_id),
        };
        s.grants = vec![VaultSelfGrant {
            vault_id: Id::from_bytes(vault_id.to_bytes()),
            account_key_epoch: 1,
            vault_key_epoch: 0,
            envelope: bytes(&self_grant),
        }];
    }
    let grants = DeviceGrantsResponse {
        grants: List::new(vec![DeviceGrant {
            account_key_epoch: 1,
            sender_device_id: Id::from_bytes(b.unlocked.device_id.to_bytes()),
            recipient_device_id: Id::from_bytes(a_state.device_id().to_bytes()),
            key_grant: bytes(&grant),
        }])
        .unwrap(),
    };

    // Device A unlocks with its old key and learns of the rotation.
    let mut a_unlocked = a_state.unlock(PASSWORD).unwrap();
    let view = server.view();
    assert_eq!(
        verify_unlock(&mut a_state, &a_unlocked, &view, None).unwrap_err(),
        ClientError::AccountKeyRotated
    );
    // No grant: refused.
    let empty = DeviceGrantsResponse {
        grants: List::empty(),
    };
    assert_eq!(
        crate::unlock::apply_device_grants(
            &mut rng,
            &mut a_state,
            &mut a_unlocked,
            &view,
            &empty,
            None
        )
        .unwrap_err(),
        ClientError::InvalidServerResponse
    );
    let ack = crate::unlock::apply_device_grants(
        &mut rng,
        &mut a_state,
        &mut a_unlocked,
        &view,
        &grants,
        None,
    )
    .unwrap();
    assert_eq!(ack.account_key_epoch, 1);
    let account = verify_unlock(&mut a_state, &a_unlocked, &view, None).unwrap();
    assert_eq!(account.state().account_key_epoch, 1);
    a_unlocked.forget_unlock_key();
    // E_local was re-wrapped: the next unlock yields the new key directly.
    let again = a_state.unlock(PASSWORD).unwrap();
    assert_eq!(again.account_key.epoch(), 1);
    verify_unlock(&mut a_state, &again, &server.view(), None).unwrap();
}

/// Signs a new `account-state` after `edit` with the identity key of `account` and serves it.
fn serve_state(
    server: &mut Server,
    account: &crate::account::VerifiedAccount,
    base: &AccountState,
    edit: impl FnOnce(&mut AccountState),
) -> AccountState {
    let mut state = base.clone();
    state.state_seq += 1;
    edit(&mut state);
    let wire = state.sign(account.identity.signing_key()).unwrap();
    server.account.as_mut().unwrap().state = wire;
    state
}

#[test]
fn unlock_keeps_settings_the_server_leaves_out() {
    use rizzy_core::envelope::purpose::AccountSettingsCtx;
    use rizzy_core::envelope::seal;
    use rizzy_core::keys::settings_hash;

    let mut rng = ChaCha20Rng::seed_from_u64(14);
    let mut server = Server::new(15);
    let a = signup(&mut server, &mut rng, DeviceKind::DesktopCli);
    let mut a_state = a.device.unwrap();
    let sk = secret_key_text(&a_state);
    let b = login_and_enrol(&mut server, &mut rng, &sk);
    let account_id = b.account.account_id();

    // Device B writes settings: `settings_seq` 1, a new state.
    let write_settings = |rng: &mut ChaCha20Rng, seq: u64| {
        let ctx = AccountSettingsCtx {
            account_id,
            settings_seq: seq,
        };
        let envelope = seal(rng, b.unlocked.account_key.key(), &ctx, b"prefs").unwrap();
        AccountSettings {
            settings_seq: seq,
            envelope: bytes(&envelope),
        }
    };
    let first = write_settings(&mut rng, 1);
    let state = serve_state(&mut server, &b.account, b.account.state(), |s| {
        s.settings_seq = 1;
        s.settings_hash = settings_hash(1, Some(first.envelope.as_slice())).unwrap();
    });
    server.account.as_mut().unwrap().settings = Some(first.clone());

    // The first unlock holds no settings, so it asks for them and pins them.
    let a_unlocked = a_state.unlock(PASSWORD).unwrap();
    let query = account_state_query(&a_state);
    assert_eq!(query.known_settings_seq, 0);
    let view = server.view_since(&query);
    assert!(view.account_settings.is_some());
    let account = verify_unlock(&mut a_state, &a_unlocked, &view, None).unwrap();
    assert_eq!(account.settings(), Some(&first));
    assert_eq!(a_state.pin().settings(), Some(&first));

    // The next unlock: the server leaves the unchanged settings out, and the pinned ones check.
    let query = account_state_query(&a_state);
    assert_eq!(query.known_settings_seq, 1);
    let view = server.view_since(&query);
    assert!(view.account_settings.is_none());
    let account = verify_unlock(&mut a_state, &a_unlocked, &view, None).unwrap();
    assert_eq!(account.settings(), Some(&first));
    assert_eq!(a_state.pin().settings(), Some(&first));

    // Settings changed (seq 2) but the server leaves them out: refused, nothing adopted.
    let second = write_settings(&mut rng, 2);
    serve_state(&mut server, &b.account, &state, |s| {
        s.settings_seq = 2;
        s.settings_hash = settings_hash(2, Some(second.envelope.as_slice())).unwrap();
    });
    server.account.as_mut().unwrap().settings = Some(second.clone());
    let mut view = server.view_since(&query);
    assert_eq!(view.account_settings.as_ref(), Some(&second));
    view.account_settings = None;
    assert_eq!(
        verify_unlock(&mut a_state, &a_unlocked, &view, None).unwrap_err(),
        ClientError::InvalidServerResponse
    );
    assert_eq!(a_state.pin().settings(), Some(&first));
    // The old settings served against the new state: refused too.
    view.account_settings = Some(first.clone());
    assert_eq!(
        verify_unlock(&mut a_state, &a_unlocked, &view, None).unwrap_err(),
        ClientError::InvalidServerResponse
    );
    // Served as the query asks: adopted.
    let account =
        verify_unlock(&mut a_state, &a_unlocked, &server.view_since(&query), None).unwrap();
    assert_eq!(account.settings(), Some(&second));
    assert_eq!(a_state.pin().settings(), Some(&second));
    assert_eq!(account_state_query(&a_state).known_settings_seq, 2);
}

#[test]
fn unlock_requires_a_certificate_of_this_devices_keys() {
    use rizzy_core::keys::{DeviceKeys, device_set_hash};

    let mut rng = ChaCha20Rng::seed_from_u64(16);
    let mut server = Server::new(17);
    let a = signup(&mut server, &mut rng, DeviceKind::DesktopCli);
    let mut a_state = a.device.unwrap();
    let sk = secret_key_text(&a_state);
    let b = login_and_enrol(&mut server, &mut rng, &sk);
    let a_unlocked = a_state.unlock(PASSWORD).unwrap();

    // The identity key certifies other keys under A's device id, and the state commits to
    // that device set: every signature verifies, but the certificate is not A's.
    let other = DeviceKeys::generate(&mut rng).public_keys();
    let mut certs = Vec::new();
    for c in b.account.certificates() {
        let mut cert = c.certificate.statement().clone();
        if cert.device_id == a_state.device_id() {
            cert.device_ed25519 = other.ed25519;
            cert.device_x25519 = other.x25519;
        }
        certs.push(cert.sign(b.account.identity.signing_key()).unwrap());
    }
    let identity = b.account.pin().identity_key();
    let verified: Vec<_> = certs
        .iter()
        .map(|w| DeviceCertificate::verify(w, &identity, 0).unwrap())
        .collect();
    let set =
        device_set_hash(b.account.account_id(), verified.iter(), core::iter::empty()).unwrap();
    serve_state(&mut server, &b.account, b.account.state(), |s| {
        s.device_set_hash = set;
    });
    server.account.as_mut().unwrap().certs = certs;

    // The account answer itself verifies in full.
    let view = server.view();
    crate::account::verify_account_view(
        &view,
        a_state.account_id(),
        &a_unlocked.account_key,
        &crate::account::Anchor::Enrolled {
            pin: a_state.pin(),
            confirmed: None,
        },
    )
    .unwrap();
    let pinned = a_state.pin().state().state_seq;
    // The unlock refuses it: no certificate of this device's keys, and the pin stays.
    assert_eq!(
        verify_unlock(&mut a_state, &a_unlocked, &view, None).unwrap_err(),
        ClientError::InvalidServerResponse
    );
    assert_eq!(a_state.pin().state().state_seq, pinned);
}

/// Device A with `items` acknowledged items, synced against `server`.
fn synced_writer(
    server: &mut Server,
    rng: &mut ChaCha20Rng,
    a: SignedUp,
    authors: &Authors,
    items: usize,
) -> (VaultSync, UnlockedDevice, Vec<ItemId>) {
    let unlocked = a.unlocked;
    let mut vault = VaultSync::new(a.vault_key, &unlocked, 1).unwrap();
    vault
        .apply_fetch(authors, &server.fetch(&vault.fetch_request().unwrap()), T0)
        .unwrap();
    let key = SchemaKey::parse(LOGIN_PASSWORD.as_bytes()).unwrap();
    let value = Value::text("p").unwrap();
    let mut ids = Vec::new();
    for i in 0..items {
        ids.push(
            vault
                .create_item(
                    rng,
                    &unlocked,
                    ItemType::LOGIN,
                    &[FieldEdit {
                        key: &key,
                        value: &value,
                    }],
                    T0 + 1 + u64::try_from(i).unwrap(),
                )
                .unwrap(),
        );
    }
    let up = vault.upload_request(rng, &unlocked).unwrap().unwrap();
    assert!(
        up.records
            .as_slice()
            .iter()
            .all(|r| matches!(r, Record::Op(_)))
    );
    let answer = server.upload(&up);
    assert_eq!(
        vault.apply_upload_response(&answer).unwrap().acknowledged,
        items
    );
    (vault, unlocked, ids)
}

#[test]
fn server_behind_and_restore_generations() {
    let mut rng = ChaCha20Rng::seed_from_u64(18);
    let mut server = Server::new(19);
    let a = signup(&mut server, &mut rng, DeviceKind::DesktopCli);
    let sk = secret_key_text(a.device.as_ref().unwrap());
    let b = login_and_enrol(&mut server, &mut rng, &sk);
    let authors = Authors::from_account(&b.account).unwrap();
    let (mut vault, unlocked, items) = synced_writer(&mut server, &mut rng, a, &authors, 2);
    let own = unlocked.device_id().to_bytes();

    // The server loses A's acknowledged op 2: its head for A is below A's acknowledgement.
    let lost = server.ops.get_mut(&own).unwrap().remove(&2).unwrap();
    let out = vault
        .apply_fetch(
            &authors,
            &server.fetch(&vault.fetch_request().unwrap()),
            T0 + 10,
        )
        .unwrap();
    assert!(out.server_behind);
    assert!(vault.is_read_only());
    assert_eq!(
        vault
            .create_item(&mut rng, &unlocked, ItemType::LOGIN, &[], T0 + 11)
            .unwrap_err(),
        ClientError::ReadOnly
    );
    assert_eq!(
        vault
            .trash_item(&mut rng, &unlocked, items[0], T0 + 11)
            .unwrap_err(),
        ClientError::ReadOnly
    );
    assert!(vault.upload_request(&mut rng, &unlocked).unwrap().is_none());

    // The server has the op again: writable again.
    server.ops.get_mut(&own).unwrap().insert(2, lost);
    let out = vault
        .apply_fetch(
            &authors,
            &server.fetch(&vault.fetch_request().unwrap()),
            T0 + 12,
        )
        .unwrap();
    assert!(!out.server_behind);
    assert!(!vault.is_read_only());
    // The due snapshots go up now; the fake verifies each.
    let up = vault.upload_request(&mut rng, &unlocked).unwrap().unwrap();
    let answer = server.upload(&up);
    let outcome = vault.apply_upload_response(&answer).unwrap();
    assert_eq!(outcome.snapshots_stored, up.records.as_slice().len());
    assert_eq!(outcome.snapshots_discarded, 0);

    // A restore between the send and the answer: op 3 is refused under another generation,
    // so it may have been stored and served before the restore (ADR 0021 §2, §9).
    vault
        .trash_item(&mut rng, &unlocked, items[0], T0 + 13)
        .unwrap();
    let refuse = |up: &UploadRequest, generation: [u8; 16]| UploadResponse {
        restore_generation: Fixed::from_bytes(generation),
        results: List::new(
            up.records
                .as_slice()
                .iter()
                .map(|_| UploadResult::Rejected {
                    error: rizzy_proto::error::ErrorCode::PrevSeqMismatch,
                })
                .collect(),
        )
        .unwrap(),
    };
    let up = vault.upload_request(&mut rng, &unlocked).unwrap().unwrap();
    assert_eq!(up.records.as_slice().len(), 1);
    let outcome = vault.apply_upload_response(&refuse(&up, [9; 16])).unwrap();
    assert_eq!(outcome.acknowledged, 0);
    assert_eq!(outcome.rejected.len(), 1);
    assert!(vault.may_have_been_served(3));

    // Op 4 is sent under generation 9 and refused under 9: never stored, not "maybe served".
    // Op 3 keeps the generation of its first send, so it stays "maybe served".
    vault
        .restore_item(&mut rng, &unlocked, items[0], T0 + 14)
        .unwrap();
    let up = vault.upload_request(&mut rng, &unlocked).unwrap().unwrap();
    assert_eq!(up.records.as_slice().len(), 2);
    vault.apply_upload_response(&refuse(&up, [9; 16])).unwrap();
    assert!(vault.may_have_been_served(3));
    assert!(!vault.may_have_been_served(4));

    // The restored server stores both.
    server.generation = [9; 16];
    let up = vault.upload_request(&mut rng, &unlocked).unwrap().unwrap();
    let answer = server.upload(&up);
    assert_eq!(
        vault.apply_upload_response(&answer).unwrap().acknowledged,
        2
    );
}

/// ADR 0021 §9 "Server behind", "Healing request": a server restored from an older backup is
/// behind both devices. B heals it with what it holds (A's lost ops verbatim, the lost wrap of
/// an item created after the backup), both devices leave read-only, A writes again on top of
/// the healed chain, and a new device reads every item.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one restore story: backup, writes, restore, healing, reads"
)]
fn a_restored_server_is_healed_and_both_devices_leave_read_only() {
    let mut rng = ChaCha20Rng::seed_from_u64(30);
    let mut server = Server::new(31);
    let a = signup(&mut server, &mut rng, DeviceKind::DesktopCli);
    let sk = secret_key_text(a.device.as_ref().unwrap());
    let b = login_and_enrol(&mut server, &mut rng, &sk);
    let authors = Authors::from_account(&b.account).unwrap();
    let vault_id = a.vault_key.vault_id();
    let (mut a_vault, a_unlocked, items) = synced_writer(&mut server, &mut rng, a, &authors, 1);
    let backup = (
        server.ops.clone(),
        server.wraps.clone(),
        server.snapshots.clone(),
        server.op_items.clone(),
    );

    // After the backup: A edits the first item and creates a second one (a fresh item key).
    let key = SchemaKey::parse(LOGIN_PASSWORD.as_bytes()).unwrap();
    let edited = Value::text("edited after the backup").unwrap();
    a_vault
        .edit_item(
            &mut rng,
            &a_unlocked,
            items[0],
            &[FieldEdit {
                key: &key,
                value: &edited,
            }],
            T0 + 10,
        )
        .unwrap();
    let created = Value::text("created after the backup").unwrap();
    let second = a_vault
        .create_item(
            &mut rng,
            &a_unlocked,
            ItemType::LOGIN,
            &[FieldEdit {
                key: &key,
                value: &created,
            }],
            T0 + 11,
        )
        .unwrap();
    let up = a_vault
        .upload_request(&mut rng, &a_unlocked)
        .unwrap()
        .unwrap();
    assert_eq!(
        a_vault
            .apply_upload_response(&server.upload(&up))
            .unwrap()
            .acknowledged,
        2
    );
    let mut b_account = b.account;
    let mut b_vault =
        VaultSync::new(b_account.take_vault_key(vault_id).unwrap(), &b.unlocked, 1).unwrap();
    b_vault
        .apply_fetch(
            &authors,
            &server.fetch(&b_vault.fetch_request().unwrap()),
            T0 + 12,
        )
        .unwrap();
    assert!(!b_vault.needs_healing());

    // The restore: the backup's rows and a new restore generation.
    (server.ops, server.wraps, server.snapshots, server.op_items) = backup;
    server.generation = [0x55; 16];
    let out = b_vault
        .apply_fetch(
            &authors,
            &server.fetch(&b_vault.fetch_request().unwrap()),
            T0 + 13,
        )
        .unwrap();
    assert!(out.server_behind);
    assert!(b_vault.is_read_only());
    assert!(b_vault.needs_healing());

    // B's request: A's two lost ops with their bodies, and the second item's lost wrap.
    let heal = b_vault.healing_request().unwrap().unwrap();
    let ops: Vec<&OpRecord> = heal
        .records
        .as_slice()
        .iter()
        .map(|r| match r {
            Record::Op(op) => op,
            Record::Snapshot(_) => panic!("no cover needed: every body is held"),
        })
        .collect();
    assert_eq!(ops.len(), 2);
    assert!(ops.iter().all(|op| op.body.is_some()));
    assert!(
        heal.item_key_wraps
            .as_slice()
            .iter()
            .any(|w| w.item_id.to_bytes() == second.to_bytes())
    );
    let answer = server.heal(&heal).unwrap();
    let outcome = b_vault.apply_healing_response(&answer).unwrap();
    assert_eq!((outcome.ops, outcome.own_acknowledged), (2, 0));
    let out = b_vault
        .apply_fetch(
            &authors,
            &server.fetch(&b_vault.fetch_request().unwrap()),
            T0 + 14,
        )
        .unwrap();
    assert!(!out.server_behind);
    assert!(!b_vault.is_read_only());
    assert!(!b_vault.needs_healing());

    // A sees the server whole again and writes on top of the healed chain.
    let out = a_vault
        .apply_fetch(
            &authors,
            &server.fetch(&a_vault.fetch_request().unwrap()),
            T0 + 15,
        )
        .unwrap();
    assert!(!out.server_behind);
    a_vault
        .trash_item(&mut rng, &a_unlocked, items[0], T0 + 16)
        .unwrap();
    let up = a_vault
        .upload_request(&mut rng, &a_unlocked)
        .unwrap()
        .unwrap();
    let answer = server.upload(&up);
    assert!(
        answer
            .results
            .as_slice()
            .iter()
            .all(|r| matches!(r, UploadResult::Stored))
    );

    // A fresh replica of B, from nothing, reads both items as A left them.
    let mut b_state = b.device;
    let mut fresh = verify_unlock(&mut b_state, &b.unlocked, &server.view(), None).unwrap();
    let mut c_vault =
        VaultSync::new(fresh.take_vault_key(vault_id).unwrap(), &b.unlocked, 1).unwrap();
    let out = c_vault
        .apply_fetch(
            &authors,
            &server.fetch(&c_vault.fetch_request().unwrap()),
            T0 + 17,
        )
        .unwrap();
    assert!(out.reports.is_empty(), "{:?}", out.reports);
    assert_eq!(c_vault.item_lifecycle(items[0]), ItemLifecycle::Trashed);
    assert_eq!(
        c_vault
            .field_value(second, LOGIN_PASSWORD)
            .unwrap()
            .expose_secret(),
        created.expose_secret()
    );
}

/// A healing request is refused when the server would get a header with neither its body nor
/// a cover, and nothing is built under an alarm (ADR 0021 §9; `heal` module readings).
#[test]
fn healing_is_not_built_under_an_alarm() {
    let mut rng = ChaCha20Rng::seed_from_u64(32);
    let mut server = Server::new(33);
    let a = signup(&mut server, &mut rng, DeviceKind::DesktopCli);
    let authors = server.authors();
    let (mut vault, unlocked, _) = synced_writer(&mut server, &mut rng, a, &authors, 2);
    let own = unlocked.device_id().to_bytes();
    // Before any Fetch answer of the vault was seen there are no heads: Fetch first.
    let lost = server.ops.get_mut(&own).unwrap().remove(&2).unwrap();
    vault
        .apply_fetch(
            &authors,
            &server.fetch(&vault.fetch_request().unwrap()),
            T0 + 10,
        )
        .unwrap();
    assert!(vault.needs_healing());
    vault.set_read_only(true);
    assert_eq!(vault.healing_request().unwrap_err(), ClientError::ReadOnly);
    vault.set_read_only(false);
    // A refusal changes nothing: the same request is built again.
    let first = vault.healing_request().unwrap().unwrap();
    vault.healing_refused();
    let again = vault.healing_request().unwrap().unwrap();
    assert_eq!(first, again);
    assert_eq!(first.records.as_slice(), [Record::Op(lost)]);
}

#[test]
fn fake_server_refuses_forged_snapshots_and_serves_covers() {
    let mut rng = ChaCha20Rng::seed_from_u64(20);
    let mut server = Server::new(21);
    let a = signup(&mut server, &mut rng, DeviceKind::DesktopCli);
    let sk = secret_key_text(a.device.as_ref().unwrap());
    let vault_id = a.vault_key.vault_id();
    let b = login_and_enrol(&mut server, &mut rng, &sk);
    let authors = Authors::from_account(&b.account).unwrap();
    let (mut writer, unlocked, items) = synced_writer(&mut server, &mut rng, a, &authors, 1);
    let item = items[0];

    // The fresh item key's snapshot: the fake verifies it before storing it.
    let up = writer.upload_request(&mut rng, &unlocked).unwrap().unwrap();
    let [Record::Snapshot(snapshot)] = up.records.as_slice() else {
        panic!("expected one snapshot: {up:?}");
    };
    // A tampered signature, envelope or foreign vault is refused.
    let mut forged = snapshot.clone();
    let mut sig = forged.statement.as_slice().to_vec();
    let last = sig.len() - 1;
    sig[last] ^= 1;
    forged.statement = bytes(&sig);
    let mut body = snapshot.clone();
    let mut env = body.envelope.as_slice().to_vec();
    env[40] ^= 1;
    body.envelope = bytes(&env);
    for bad in [forged, body] {
        let req = UploadRequest {
            vault_id: up.vault_id,
            records: List::new(vec![Record::Snapshot(bad)]).unwrap(),
        };
        assert!(matches!(
            server.upload(&req).results.as_slice(),
            [UploadResult::Rejected { .. }]
        ));
    }
    let foreign = UploadRequest {
        vault_id: Id::from_bytes([0xee; 16]),
        records: up.records.clone(),
    };
    assert!(matches!(
        server.upload(&foreign).results.as_slice(),
        [UploadResult::Rejected { .. }]
    ));
    assert!(server.snapshots.is_empty());
    // The honest snapshot is stored.
    let answer = server.upload(&up);
    assert_eq!(
        writer
            .apply_upload_response(&answer)
            .unwrap()
            .snapshots_stored,
        1
    );
    assert_eq!(server.snapshots.len(), 1);

    // A compacted server serves the op bodiless with the snapshot as its cover; a fresh
    // device absorbs the cover and shows the same value.
    server.compact = true;
    let mut b_account = b.account;
    let mut reader =
        VaultSync::new(b_account.take_vault_key(vault_id).unwrap(), &b.unlocked, 1).unwrap();
    let response = server.fetch(&reader.fetch_request().unwrap());
    assert!(response.ops.as_slice().iter().all(|op| op.body.is_none()));
    assert_eq!(response.covers.as_slice().len(), 1);
    let out = reader.apply_fetch(&authors, &response, T0 + 20).unwrap();
    assert_eq!(out.absorbed, 1, "{out:?}");
    assert_eq!(out.refused_covers, 0);
    assert_eq!(reader.item_lifecycle(item), ItemLifecycle::Active);
    let shown = reader.field_value(item, LOGIN_PASSWORD).unwrap();
    let written = writer.field_value(item, LOGIN_PASSWORD).unwrap();
    assert_eq!(shown.expose_secret(), written.expose_secret());
    assert!(matches!(
        ValueRef::decode(shown.expose_secret()).unwrap(),
        ValueRef::Text("p")
    ));
}

mod export;
mod healing;
mod rotation;
mod store;

/// ADR 0018 §6 "List elements", "List order": URIs and custom fields of an existing item are
/// added after the last element, edited by key, and removed by clearing every attribute the
/// item holds, `uri/<id>/match` (never written by M1) left out; tags by their own key.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one item through every list edit, in order"
)]
fn list_elements_are_added_edited_and_removed() {
    use rizzy_core::item::schema::{
        ATTR_KIND, ATTR_LABEL, ATTR_MATCH, ATTR_VALUE, CUSTOM_KIND_HIDDEN, LIST_FIELD, LIST_TAG,
        LIST_URI,
    };
    use rizzy_core::item::tag::tag_key;

    let mut rng = ChaCha20Rng::seed_from_u64(40);
    let mut server = Server::new(41);
    let a = signup(&mut server, &mut rng, DeviceKind::DesktopCli);
    let authors = server.authors();
    let (mut vault, unlocked, items) = synced_writer(&mut server, &mut rng, a, &authors, 1);
    let item = items[0];
    let mut now = T0 + 100;
    let mut write =
        |vault: &mut VaultSync, rng: &mut ChaCha20Rng, writes: &[(SchemaKey, Value)]| {
            let edits: Vec<FieldEdit<'_>> = writes
                .iter()
                .map(|(key, value)| FieldEdit { key, value })
                .collect();
            now += 1;
            vault.edit_item(rng, &unlocked, item, &edits, now)
        };
    let uris = |vault: &VaultSync| -> Vec<String> {
        vault
            .list_elements(item, LIST_URI)
            .iter()
            .map(|e| {
                let value = vault
                    .field_value(
                        item,
                        &format!("{LIST_URI}/{}/{ATTR_VALUE}", e.element.as_str()),
                    )
                    .unwrap();
                match value.decode().unwrap() {
                    ValueRef::Text(t) => t.to_owned(),
                    _ => panic!("text"),
                }
            })
            .collect()
    };

    // Two URIs, then a third after them: list order is insertion order.
    let orders = vault.append_orders(Some(item), LIST_URI, 2).unwrap();
    let mut writes = Vec::new();
    for (uri, order) in ["https://a.example", "https://b.example"]
        .iter()
        .zip(&orders)
    {
        let (_, new) = VaultSync::new_element_writes(
            &mut rng,
            LIST_URI,
            vec![(ATTR_VALUE, Value::text(uri).unwrap())],
            Some(order),
        )
        .unwrap();
        writes.extend(new);
    }
    write(&mut vault, &mut rng, &writes).unwrap();
    let orders = vault.append_orders(Some(item), LIST_URI, 1).unwrap();
    assert!(orders[0].as_bytes() > vault_order(&vault, item, 1).as_slice());
    let (third, new) = VaultSync::new_element_writes(
        &mut rng,
        LIST_URI,
        vec![(ATTR_VALUE, Value::text("https://c.example").unwrap())],
        Some(&orders[0]),
    )
    .unwrap();
    write(&mut vault, &mut rng, &new).unwrap();
    assert_eq!(
        uris(&vault),
        [
            "https://a.example",
            "https://b.example",
            "https://c.example"
        ]
    );

    // Edit the first, remove the second.
    let elements = vault.list_elements(item, LIST_URI);
    let first = elements[0].element.as_str().to_owned();
    let second = elements[1].element.as_str().to_owned();
    let key = SchemaKey::parse(format!("{LIST_URI}/{first}/{ATTR_VALUE}").as_bytes()).unwrap();
    write(
        &mut vault,
        &mut rng,
        &[(key, Value::text("https://a2.example").unwrap())],
    )
    .unwrap();
    let removal = vault
        .element_removal_writes(item, LIST_URI, &second)
        .unwrap();
    assert_eq!(removal.len(), 2, "value and order");
    assert!(removal.iter().all(|(_, v)| v.is_cleared()));
    write(&mut vault, &mut rng, &removal).unwrap();
    assert_eq!(uris(&vault), ["https://a2.example", "https://c.example"]);
    assert_eq!(
        vault
            .element_removal_writes(item, LIST_URI, &second)
            .unwrap_err(),
        ClientError::UnknownItem
    );

    // A `match` written by a newer client is carried, never written by this one: the removal
    // leaves it out and the element still goes.
    let third_hex = hex_of(third.as_bytes());
    let match_key = format!("{LIST_URI}/{third_hex}/{ATTR_MATCH}");
    let match_value = Value::enumeration(1);
    vault
        .write_op(
            &mut rng,
            &unlocked,
            item,
            &crate::sync::OwnChange {
                lifecycle: rizzy_sync::record::Lifecycle::Active,
                writes: &[(match_key.as_str(), match_value.expose_secret())],
            },
            T0 + 500,
        )
        .unwrap();
    let removal = vault
        .element_removal_writes(item, LIST_URI, &third_hex)
        .unwrap();
    assert!(removal.iter().all(|(k, _)| k.as_str() != match_key));
    write(&mut vault, &mut rng, &removal).unwrap();
    assert_eq!(uris(&vault), ["https://a2.example"]);

    // A hidden custom field, then its removal; a tag the same way.
    let orders = vault.append_orders(Some(item), LIST_FIELD, 1).unwrap();
    let (field, new) = VaultSync::new_element_writes(
        &mut rng,
        LIST_FIELD,
        vec![
            (ATTR_LABEL, Value::text("PIN").unwrap()),
            (ATTR_KIND, Value::enumeration(CUSTOM_KIND_HIDDEN)),
            (ATTR_VALUE, Value::text("1234").unwrap()),
        ],
        Some(&orders[0]),
    )
    .unwrap();
    let tag = tag_key("work").unwrap();
    let mut writes = new;
    writes.push((tag_key("work").unwrap(), Value::bool(true)));
    write(&mut vault, &mut rng, &writes).unwrap();
    assert_eq!(vault.list_elements(item, LIST_FIELD).len(), 1);
    assert_eq!(vault.list_elements(item, LIST_TAG).len(), 1);
    let field_hex = hex_of(field.as_bytes());
    let mut removal = vault
        .element_removal_writes(item, LIST_FIELD, &field_hex)
        .unwrap();
    assert_eq!(removal.len(), 4, "label, kind, value and order");
    let tag_element = vault.list_elements(item, LIST_TAG)[0]
        .element
        .as_str()
        .to_owned();
    removal.extend(
        vault
            .element_removal_writes(item, LIST_TAG, &tag_element)
            .unwrap(),
    );
    write(&mut vault, &mut rng, &removal).unwrap();
    assert!(vault.list_elements(item, LIST_FIELD).is_empty());
    assert!(vault.list_elements(item, LIST_TAG).is_empty());
    // The registers stay (ADR 0018 §4), cleared.
    assert!(
        vault
            .field_value(item, tag.as_str())
            .is_some_and(|v| v.is_cleared())
    );

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

/// The `order` payload of the `index`-th URI element of `item`, in list order.
fn vault_order(vault: &VaultSync, item: ItemId, index: usize) -> Vec<u8> {
    use rizzy_core::item::schema::{ATTR_ORDER, LIST_URI};
    let element = &vault.list_elements(item, LIST_URI)[index];
    let value = vault
        .field_value(
            item,
            &format!("{LIST_URI}/{}/{ATTR_ORDER}", element.element.as_str()),
        )
        .unwrap();
    match value.decode().unwrap() {
        ValueRef::SortKey(payload) => payload.to_vec(),
        _ => panic!("a sort key"),
    }
}

/// Lowercase hex of `bytes`.
fn hex_of(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}
