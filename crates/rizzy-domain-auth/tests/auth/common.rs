//! Shared helpers: a real SQLite database in a temporary directory, an in-memory vault port,
//! and a client that runs `rizzy-core`'s client-side functions (the other half of every flow).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use chacha20::ChaCha20Rng;
use chacha20::rand_core::SeedableRng as _;
use rizzy_core::envelope::purpose::{
    AccountKeyRecoveryWrapCtx, AccountKeyServerWrapCtx, IdentitySecretKeysCtx, VaultKeySelfGrantCtx,
};
use rizzy_core::ids::{AccountId, DeviceId, SessionId, VaultId};
use rizzy_core::kdf::KdfId;
use rizzy_core::keys::{
    AccountKey, DeviceKeys, IdentityKeys, RecoveryAuthToken, RecoveryWrapKey, VaultKey,
    device_set_hash,
};
use rizzy_core::normalize::ServerOrigin;
use rizzy_core::opaque::{
    ExportKey, OpaqueContext, PasswordInput, client_login_finish, client_login_start,
    client_registration_finish, client_registration_start,
};
use rizzy_core::secret::SecretArray;
use rizzy_core::secret_key::SecretKey;
use rizzy_core::sign::{
    AccountState, DeviceCertificate, DeviceKind, DeviceRequest, DeviceRevocation, PublicKeyBundle,
    SyncMode, Verified, VerifiedBundle,
};
use rizzy_domain_auth::{
    AuthConfig, AuthError, AuthService, PersonalVault, RequestParts, ServerSecrets, Session,
    SignupPolicy, VaultPort,
};
use rizzy_proto::auth::{
    DeviceAuthFinishRequest, DeviceAuthStartRequest, LoginFinishRequest, LoginFinishResponse,
    LoginStartRequest, RecoveryRegistration, RegisterFinishRequest, RegisterStartRequest,
    RequestSignature, TotpCode,
};
use rizzy_proto::change::VaultRotationUpload;
use rizzy_proto::objects::{
    AccountKeyRecoveryWrap, AccountKeyServerWrap, IdentitySecretKeys, VaultSelfGrant,
};
use rizzy_proto::recovery::RecoveryVault;
use rizzy_proto::vault::SeqVector;
use rizzy_proto::wire::{Bytes, Fixed, Id, List, SessionToken, Text};
use rizzy_storage::{Conn, Database, SqliteOptions, WriteTx, WriterLock};

/// The server's canonical origin in every test.
pub(crate) const ORIGIN: &str = "https://vault.example.com";

/// The first clock value of a test: 2026-09-29, in ms.
pub(crate) const T0: u64 = 1_790_000_000_000;

/// Runs `f` to completion on a current-thread tokio runtime.
pub(crate) fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

/// A temporary directory, removed on drop.
pub(crate) struct TempDir(PathBuf);

impl TempDir {
    /// A new, empty directory under the system temporary directory.
    pub(crate) fn new() -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "rizzy-domain-auth-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    /// `name` inside the directory.
    pub(crate) fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// H per (account, device).
type Heads = HashMap<([u8; 16], [u8; 16]), u64>;

/// The vault domain's side, in memory: personal vaults and their self-grants, and the device
/// heads a test sets.
#[derive(Debug, Default)]
pub(crate) struct TestVault {
    /// Self-grants per account.
    grants: Mutex<HashMap<[u8; 16], Vec<VaultSelfGrant>>>,
    /// H per (account, device).
    heads: Mutex<Heads>,
}

impl TestVault {
    /// Sets H, the highest `device_seq` held from `device`.
    pub(crate) fn set_head(&self, account: AccountId, device: DeviceId, head: u64) {
        self.heads
            .lock()
            .unwrap()
            .insert((account.to_bytes(), device.to_bytes()), head);
    }
}

/// The port the service holds: a shared handle to one [`TestVault`].
#[derive(Debug, Clone)]
pub(crate) struct SharedVault(pub(crate) Arc<TestVault>);

impl core::ops::Deref for SharedVault {
    type Target = TestVault;
    fn deref(&self) -> &TestVault {
        &self.0
    }
}

impl VaultPort for SharedVault {
    type Rotation = Vec<VaultSelfGrant>;

    fn rotation_from_wire(upload: VaultRotationUpload) -> Self::Rotation {
        upload
            .vaults()
            .iter()
            .map(|v| v.self_grant.clone())
            .collect()
    }

    async fn apply_rotation(
        &self,
        _tx: &mut WriteTx,
        account_id: AccountId,
        new_account_key_epoch: u32,
        _new_account_key_id: [u8; 16],
        rotation: &Self::Rotation,
        _now_ms: u64,
    ) -> Result<(), AuthError> {
        if rotation
            .iter()
            .any(|g| g.account_key_epoch != new_account_key_epoch)
        {
            return Err(AuthError::InvalidRequest);
        }
        self.grants
            .lock()
            .unwrap()
            .insert(account_id.to_bytes(), rotation.clone());
        Ok(())
    }

    async fn create_personal_vault(
        &self,
        _tx: &mut WriteTx,
        account_id: AccountId,
        grant: &VaultSelfGrant,
        _now_ms: u64,
    ) -> Result<PersonalVault, AuthError> {
        let mut grants = self.grants.lock().unwrap();
        match grants.get(&account_id.to_bytes()) {
            Some(held) if held.as_slice() == core::slice::from_ref(grant) => {
                Ok(PersonalVault::Identical)
            }
            Some(_) => Ok(PersonalVault::Conflict),
            None => {
                grants.insert(account_id.to_bytes(), vec![grant.clone()]);
                Ok(PersonalVault::Created)
            }
        }
    }

    async fn self_grants(
        &self,
        _conn: Conn<'_>,
        account_id: AccountId,
        account_key_epoch: u32,
    ) -> Result<Vec<VaultSelfGrant>, AuthError> {
        Ok(self
            .grants
            .lock()
            .unwrap()
            .get(&account_id.to_bytes())
            .map(|g| {
                g.iter()
                    .filter(|g| g.account_key_epoch == account_key_epoch)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn recovery_vaults(
        &self,
        _conn: Conn<'_>,
        account_id: AccountId,
    ) -> Result<Vec<RecoveryVault>, AuthError> {
        Ok(self
            .grants
            .lock()
            .unwrap()
            .get(&account_id.to_bytes())
            .map(|grants| {
                grants
                    .iter()
                    .map(|g| RecoveryVault {
                        vault_id: g.vault_id,
                        self_grant: g.clone(),
                        heads: SeqVector::default(),
                        item_key_wraps: List::empty(),
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn device_head(
        &self,
        _conn: Conn<'_>,
        account_id: AccountId,
        device_id: DeviceId,
    ) -> Result<u64, AuthError> {
        Ok(self
            .heads
            .lock()
            .unwrap()
            .get(&(account_id.to_bytes(), device_id.to_bytes()))
            .copied()
            .unwrap_or(0))
    }
}

/// Invites admit exactly the token `"invite:" + login name`.
pub(crate) struct TestInvites;

impl rizzy_domain_auth::InviteVerifier for TestInvites {
    fn admits(&self, token: &str, login_name: &rizzy_core::normalize::LoginName) -> bool {
        token == format!("invite:{}", login_name.as_str())
    }
}

/// One test's server: a real SQLite database, secrets, the service, a seeded RNG, a clock.
pub(crate) struct Env {
    /// Keeps the directory alive.
    pub(crate) dir: TempDir,
    /// The database.
    pub(crate) db: Database,
    /// The secrets.
    pub(crate) secrets: Arc<ServerSecrets>,
    /// The service.
    pub(crate) svc: AuthService<SharedVault>,
    /// The vault port's state.
    pub(crate) vault: Arc<TestVault>,
    /// The test RNG.
    pub(crate) rng: ChaCha20Rng,
    /// The clock, ms.
    pub(crate) now: u64,
    /// The client's source address.
    pub(crate) source: Vec<u8>,
}

/// The origin.
pub(crate) fn origin() -> ServerOrigin {
    ServerOrigin::parse(ORIGIN).unwrap()
}

impl Env {
    /// A new server with open signup and the default configuration, seeded with `seed`.
    pub(crate) async fn new(seed: u64) -> Self {
        Self::with_config(seed, |_| {}).await
    }

    /// A new server; `adjust` edits the configuration (open signup by default).
    pub(crate) async fn with_config(seed: u64, adjust: impl FnOnce(&mut AuthConfig)) -> Self {
        let dir = TempDir::new();
        let path = dir.join("vault.db");
        let lock = WriterLock::acquire(&path).unwrap();
        let db = Database::open_sqlite(&SqliteOptions::new(&path), lock)
            .await
            .unwrap();
        db.migrate().await.unwrap();
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let secrets = Arc::new(ServerSecrets::generate(&mut rng));
        secrets.check_database(&db, T0).await.unwrap().unwrap();
        let mut config = AuthConfig::new(origin());
        config.signup = SignupPolicy::Open;
        adjust(&mut config);
        let vault = Arc::new(TestVault::default());
        let svc = AuthService::new(
            db.clone(),
            secrets.clone(),
            config,
            SharedVault(vault.clone()),
        )
        .unwrap();
        Self {
            dir,
            db,
            secrets,
            svc,
            vault,
            rng,
            now: T0,
            source: b"192.0.2.1".to_vec(),
        }
    }

    /// Replaces the service with one over `db` and the same secrets and vault.
    pub(crate) fn reopen(&mut self, db: Database, adjust: impl FnOnce(&mut AuthConfig)) {
        let mut config = AuthConfig::new(origin());
        config.signup = SignupPolicy::Open;
        adjust(&mut config);
        self.svc = AuthService::new(
            db.clone(),
            self.secrets.clone(),
            config,
            SharedVault(self.vault.clone()),
        )
        .unwrap();
        self.db = db;
    }

    /// Advances the clock.
    pub(crate) fn tick(&mut self, ms: u64) {
        self.now += ms;
    }

    /// The session behind an OPAQUE or recovery bearer token.
    pub(crate) async fn bearer(&self, token: &SessionToken) -> Session {
        self.svc
            .authenticate_request(token.expose_secret(), None, request(b"{}"), self.now)
            .await
            .unwrap()
    }
}

/// The parts of a test request with `body`.
pub(crate) fn request(body: &[u8]) -> RequestParts<'_> {
    RequestParts {
        method: "POST",
        path_and_query: "/api/v1/test",
        body,
    }
}

/// A durable device the client holds.
pub(crate) struct Device {
    /// Its id.
    pub(crate) id: DeviceId,
    /// Its keys.
    pub(crate) keys: DeviceKeys,
    /// Its certificate.
    pub(crate) cert: Verified<DeviceCertificate>,
    /// The certificate's wire form.
    pub(crate) cert_wire: Vec<u8>,
}

/// A device-authenticated session, as the client holds it.
pub(crate) struct DeviceSession {
    /// The bearer token.
    pub(crate) token: SessionToken,
    /// The session id request signatures cover.
    pub(crate) session_id: SessionId,
    /// The next request counter.
    pub(crate) counter: u64,
    /// The answer's `reregister` flag (ADR 0031 point 2).
    pub(crate) reregister: bool,
}

/// The client side of an account: every secret and every signed object it holds.
pub(crate) struct Client {
    /// The login name as typed.
    pub(crate) name: String,
    /// The master password.
    pub(crate) password: String,
    /// The Secret Key.
    pub(crate) secret_key: SecretKey,
    /// The account.
    pub(crate) account_id: AccountId,
    /// The current account key.
    pub(crate) account_key: AccountKey,
    /// The current identity keys.
    pub(crate) identity: IdentityKeys,
    /// The head bundle.
    pub(crate) bundle: VerifiedBundle,
    /// The head bundle's wire form.
    pub(crate) bundle_wire: Vec<u8>,
    /// The current state.
    pub(crate) state: AccountState,
    /// The current state's wire form.
    pub(crate) state_wire: Vec<u8>,
    /// Durable devices, the first is the signup device.
    pub(crate) devices: Vec<Device>,
    /// Revocations the client signed.
    pub(crate) revocations: Vec<Verified<DeviceRevocation>>,
    /// The personal vault.
    pub(crate) vault_id: VaultId,
    /// Its key.
    pub(crate) vault_key: VaultKey,
    /// The current recovery code.
    pub(crate) recovery_code: SecretArray<16>,
}

impl Client {
    /// The recovery auth token of the current code.
    pub(crate) fn recovery_token(&self) -> [u8; 32] {
        *RecoveryAuthToken::derive(&self.recovery_code)
            .unwrap()
            .expose_secret()
    }

    /// A new durable device's keys and certificate under the current identity key.
    pub(crate) fn make_device(&self, rng: &mut ChaCha20Rng, now: u64) -> Device {
        let keys = DeviceKeys::generate(rng);
        let id = DeviceId::generate(rng);
        self.certify(id, keys, DeviceKind::DesktopCli, now, 0)
    }

    /// Signs a certificate for `keys`.
    pub(crate) fn certify(
        &self,
        id: DeviceId,
        keys: DeviceKeys,
        kind: DeviceKind,
        created: u64,
        expires: u64,
    ) -> Device {
        let cert = DeviceCertificate {
            account_id: self.account_id,
            device_id: id,
            identity_epoch: self.identity.epoch(),
            device_ed25519: *keys.signing_key().verifying_key(),
            device_x25519: keys.public_keys().x25519,
            device_kind: kind,
            created_at_ms: created,
            expires_at_ms: expires,
        };
        let cert_wire = cert.sign(self.identity.signing_key()).unwrap();
        let cert = DeviceCertificate::verify(
            &cert_wire,
            self.identity.signing_key().verifying_key(),
            self.identity.epoch(),
        )
        .unwrap();
        Device {
            id,
            keys,
            cert,
            cert_wire,
        }
    }

    /// The device-set hash over `devices` minus the client's revocations.
    pub(crate) fn device_set(&self, devices: &[&Device]) -> [u8; 32] {
        device_set_hash(
            self.account_id,
            devices.iter().map(|d| &d.cert),
            self.revocations.iter(),
        )
        .unwrap()
    }

    /// The next state: `state_seq + 1` with `edit` applied, signed with the identity key.
    pub(crate) fn next_state(
        &self,
        edit: impl FnOnce(&mut AccountState),
    ) -> (AccountState, Vec<u8>) {
        let mut state = self.state.clone();
        state.state_seq += 1;
        edit(&mut state);
        let wire = state.sign(self.identity.signing_key()).unwrap();
        (state, wire)
    }

    /// Adopts a state as the client's current one.
    pub(crate) fn adopt(&mut self, state: (AccountState, Vec<u8>)) {
        self.state = state.0;
        self.state_wire = state.1;
    }
}

/// Wire helpers.
pub(crate) fn bytes<const N: usize>(v: impl Into<Vec<u8>>) -> Bytes<N> {
    Bytes::new(v.into()).unwrap()
}

/// A wire id.
pub(crate) fn wid(bytes: [u8; 16]) -> Id {
    Id::from_bytes(bytes)
}

impl Env {
    /// Signs up a new account with one durable device and a recovery code.
    pub(crate) async fn signup(&mut self, name: &str, password: &str) -> Client {
        self.signup_full(name, password).await.0
    }

    /// As [`Env::signup`], also returning the commit request.
    pub(crate) async fn signup_full(
        &mut self,
        name: &str,
        password: &str,
    ) -> (Client, RegisterFinishRequest) {
        let (client, finish, outcome) = self.signup_across(name, password, None).await;
        outcome.unwrap();
        (client, finish)
    }

    /// As [`Env::signup_full`], restarting the server with `restart` (when given) between
    /// `register_start` and `register_finish` (ADR 0031 point 3's race), and returning the
    /// commit's outcome instead of unwrapping it.
    pub(crate) async fn signup_across(
        &mut self,
        name: &str,
        password: &str,
        restart: Option<ServerSecrets>,
    ) -> (Client, RegisterFinishRequest, Result<(), AuthError>) {
        let rng = &mut self.rng;
        let secret_key = SecretKey::generate(rng);
        let account_id = AccountId::generate(rng);
        let account_key = AccountKey::generate(rng, 0);
        let identity = IdentityKeys::generate(rng, 0);
        let vault_id = VaultId::generate(rng);
        let vault_key = VaultKey::generate(rng, vault_id, 0);
        let recovery_code = SecretArray::<16>::generate(rng);
        let pw_in = PasswordInput::derive_for_new_password(password, &secret_key).unwrap();
        let (reg_state, m1) = client_registration_start(rng, &pw_in).unwrap();
        let start = RegisterStartRequest {
            invite: None,
            login_name: Text::new(name.to_owned()).unwrap(),
            account_id: wid(account_id.to_bytes()),
            registration_request: bytes(m1),
        };
        let m2 = self
            .svc
            .register_start(&start, &self.source, self.now)
            .await
            .unwrap();
        if let Some(secrets) = restart {
            self.restart_with(secrets).await.unwrap();
        }
        let rng = &mut self.rng;
        let reg = client_registration_finish(
            rng,
            reg_state,
            &pw_in,
            m2.registration_response.as_slice(),
            KdfId::DEFAULT,
        )
        .unwrap();
        let bundle = PublicKeyBundle {
            account_id,
            identity_epoch: 0,
            bundle_seq: 1,
            identity_ed25519: *identity.signing_key().verifying_key(),
            identity_x25519: identity.public_keys().x25519,
            mail_x25519: None,
            pq_required: false,
            created_at_ms: self.now,
            prev_bundle_hash: [0; 32],
        };
        let bundle_wire = bundle.sign(identity.signing_key()).unwrap();
        let bundle = PublicKeyBundle::verify_self_signed(&bundle_wire).unwrap();
        let mut client = Client {
            name: name.to_owned(),
            password: password.to_owned(),
            secret_key,
            account_id,
            account_key,
            identity,
            bundle,
            bundle_wire,
            state: dummy_state(account_id),
            state_wire: Vec::new(),
            devices: Vec::new(),
            revocations: Vec::new(),
            vault_id,
            vault_key,
            recovery_code,
        };
        let device = client.make_device(rng, self.now);
        let state = AccountState {
            account_id,
            state_seq: 1,
            identity_epoch: 0,
            account_key_epoch: 0,
            account_key_id: client.account_key.key_id().unwrap(),
            password_epoch: 0,
            kdf_id: KdfId::DEFAULT,
            recovery_epoch: 1,
            recovery_enabled: true,
            sync_mode: SyncMode::Server,
            mail_key_epoch: 0,
            bundle_hash: *client.bundle.hash(),
            device_set_hash: client.device_set(&[&device]),
            settings_seq: 0,
            settings_hash: [0; 32],
        };
        let state_wire = state.sign(client.identity.signing_key()).unwrap();
        client.state = state;
        client.state_wire = state_wire;
        let finish =
            self.finish_request(&client, &reg.upload, m2.setup_id, &reg.export_key, &device);
        client.devices.push(device);
        let outcome = self.svc.register_finish(&finish, self.now).await;
        (client, finish, outcome)
    }

    /// A server restart with `secrets`: the startup check against the database, then a new
    /// service over the same database and vault.
    pub(crate) async fn restart_with(
        &mut self,
        secrets: ServerSecrets,
    ) -> Result<(), rizzy_domain_auth::StartupCheckError> {
        secrets.check_database(&self.db, self.now).await.unwrap()?;
        self.secrets = Arc::new(secrets);
        let db = self.db.clone();
        self.reopen(db, |_| {});
        Ok(())
    }

    /// The signup commit of `client` (§11.1 step 8).
    pub(crate) fn finish_request(
        &mut self,
        client: &Client,
        upload: &[u8],
        setup_id: u32,
        export_key: &ExportKey,
        device: &Device,
    ) -> RegisterFinishRequest {
        let rng = &mut self.rng;
        let account_id = client.account_id;
        let e_srv = export_key
            .server_unlock_key(account_id)
            .unwrap()
            .wrap_account_key(
                rng,
                &AccountKeyServerWrapCtx {
                    account_id,
                    account_key_epoch: 0,
                    password_epoch: 0,
                    kdf_id: KdfId::DEFAULT,
                },
                &client.account_key,
            )
            .unwrap();
        let e_id = client
            .account_key
            .wrap_identity_keys(
                rng,
                &IdentitySecretKeysCtx {
                    account_id,
                    identity_epoch: 0,
                },
                &client.identity,
            )
            .unwrap();
        let grant = self_grant(rng, client);
        let e_rec = recovery_wrap(rng, client, 1);
        RegisterFinishRequest {
            registration_upload: bytes(upload.to_vec()),
            setup_id,
            account_key_server_wrap: AccountKeyServerWrap {
                account_key_epoch: 0,
                password_epoch: 0,
                kdf_id: 1,
                envelope: bytes(e_srv),
            },
            identity_secret_keys: IdentitySecretKeys {
                identity_epoch: 0,
                envelope: bytes(e_id),
            },
            bundle: bytes(client.bundle_wire.clone()),
            account_state: bytes(client.state_wire.clone()),
            vault_self_grant: grant,
            device_certificate: bytes(device.cert_wire.clone()),
            recovery: Some(RecoveryRegistration {
                recovery_wrap: e_rec,
                recovery_token_hash: Fixed::from_bytes(
                    RecoveryAuthToken::derive(&client.recovery_code)
                        .unwrap()
                        .server_hash(),
                ),
            }),
        }
    }
}

/// The self-grant of the client's personal vault under its current account key.
pub(crate) fn self_grant(rng: &mut ChaCha20Rng, client: &Client) -> VaultSelfGrant {
    let envelope = client
        .account_key
        .wrap_vault_key(
            rng,
            &VaultKeySelfGrantCtx {
                account_id: client.account_id,
                vault_id: client.vault_id,
                account_key_epoch: client.account_key.epoch(),
                vault_key_epoch: client.vault_key.epoch(),
            },
            &client.vault_key,
        )
        .unwrap();
    VaultSelfGrant {
        vault_id: wid(client.vault_id.to_bytes()),
        account_key_epoch: client.account_key.epoch(),
        vault_key_epoch: client.vault_key.epoch(),
        envelope: bytes(envelope),
    }
}

/// `E_rec` of the client's current code under its current account key.
pub(crate) fn recovery_wrap(
    rng: &mut ChaCha20Rng,
    client: &Client,
    recovery_epoch: u32,
) -> AccountKeyRecoveryWrap {
    let envelope = RecoveryWrapKey::derive(&client.recovery_code)
        .unwrap()
        .wrap_account_key(
            rng,
            &AccountKeyRecoveryWrapCtx {
                account_id: client.account_id,
                account_key_epoch: client.account_key.epoch(),
                recovery_epoch,
            },
            &client.account_key,
        )
        .unwrap();
    AccountKeyRecoveryWrap {
        account_key_epoch: client.account_key.epoch(),
        recovery_epoch,
        envelope: bytes(envelope),
    }
}

/// A placeholder state, replaced before use.
fn dummy_state(account_id: AccountId) -> AccountState {
    AccountState {
        account_id,
        state_seq: 1,
        identity_epoch: 0,
        account_key_epoch: 0,
        account_key_id: rizzy_core::ids::SymmetricKeyId::from_bytes([0; 16]),
        password_epoch: 0,
        kdf_id: KdfId::DEFAULT,
        recovery_epoch: 0,
        recovery_enabled: false,
        sync_mode: SyncMode::Server,
        mail_key_epoch: 0,
        bundle_hash: [0; 32],
        device_set_hash: [0; 32],
        settings_seq: 0,
        settings_hash: [0; 32],
    }
}

/// What a client gets from an OPAQUE login.
pub(crate) struct Login {
    /// The server's answer.
    pub(crate) response: LoginFinishResponse,
    /// OPAQUE's `export_key`.
    pub(crate) export_key: ExportKey,
}

impl Env {
    /// Runs an OPAQUE login for `name` with `password` and the client's Secret Key.
    pub(crate) async fn login_as(
        &mut self,
        name: &str,
        password: &str,
        secret_key: &SecretKey,
        totp: Option<&str>,
        reauth: Option<&Session>,
    ) -> Result<Login, AuthError> {
        let pw_in = PasswordInput::derive(password, secret_key).unwrap();
        let (state, ke1) = client_login_start(&mut self.rng, &pw_in).unwrap();
        let start = LoginStartRequest {
            login_name: Text::new(name.to_owned()).unwrap(),
            ke1: bytes(ke1),
        };
        let started = self
            .svc
            .login_start(&mut self.rng, &start, &self.source, reauth, self.now)
            .await?;
        let context =
            OpaqueContext::for_login(&origin(), started.kdf_id, started.server_origin.as_str())
                .unwrap();
        // A wrong password fails here on the client (§11.2 step 4); send a garbage KE3 then,
        // as an attacker would, so the server's answer is what the test sees.
        let ke3 = match client_login_finish(
            &mut self.rng,
            state,
            &pw_in,
            started.ke2.as_slice(),
            &context,
        ) {
            Ok(fin) => {
                let response = self
                    .finish_login(started.login_id, fin.ke3, totp, reauth)
                    .await?;
                return Ok(Login {
                    response,
                    export_key: fin.export_key,
                });
            }
            Err(_) => vec![0x42; rizzy_core::opaque::KE3_LEN],
        };
        self.finish_login(started.login_id, ke3, totp, reauth)
            .await?;
        panic!("a garbage KE3 was accepted")
    }

    /// Sends KE3.
    pub(crate) async fn finish_login(
        &mut self,
        login_id: Id,
        ke3: Vec<u8>,
        totp: Option<&str>,
        reauth: Option<&Session>,
    ) -> Result<LoginFinishResponse, AuthError> {
        let finish = LoginFinishRequest {
            login_id,
            ke3: bytes(ke3),
            totp: totp.map(|c| TotpCode::new(c).unwrap()),
        };
        self.svc
            .login_finish(&mut self.rng, &finish, &self.source, reauth, self.now)
            .await
    }

    /// Logs `client` in with its password.
    pub(crate) async fn login(&mut self, client: &Client) -> Login {
        let (name, password) = (client.name.clone(), client.password.clone());
        self.login_as(&name, &password, &client.secret_key, None, None)
            .await
            .unwrap()
    }

    /// Device authentication of `device` (CRYPTO.md §5.10).
    pub(crate) async fn device_auth(
        &mut self,
        client: &Client,
        device: &Device,
    ) -> Result<DeviceSession, AuthError> {
        let start = DeviceAuthStartRequest {
            account_id: wid(client.account_id.to_bytes()),
            device_id: wid(device.id.to_bytes()),
            reconciliation: None,
        };
        let challenge = self
            .svc
            .device_auth_start(&mut self.rng, &start, self.now)
            .await?
            .challenge;
        let origin = origin();
        let signature = rizzy_core::sign::DeviceAuth {
            server_origin: &origin,
            account_id: client.account_id,
            device_id: device.id,
            challenge: challenge.to_bytes(),
        }
        .sign(device.keys.signing_key())
        .unwrap();
        let finish = DeviceAuthFinishRequest {
            account_id: wid(client.account_id.to_bytes()),
            device_id: wid(device.id.to_bytes()),
            challenge,
            signature: Fixed::from_bytes(signature.to_bytes()),
            reconciliation: None,
        };
        let done = self
            .svc
            .device_auth_finish(&mut self.rng, &finish, self.now)
            .await?;
        Ok(DeviceSession {
            token: done.session_token,
            session_id: SessionId::from_bytes(done.session_id.to_bytes()),
            counter: 1,
            reregister: done.reregister,
        })
    }

    /// Sends one signed request over a device session with the session's next counter.
    pub(crate) async fn signed(
        &self,
        client: &Client,
        device: &Device,
        session: &mut DeviceSession,
        body: &[u8],
    ) -> Result<Session, AuthError> {
        let counter = session.counter;
        session.counter += 1;
        self.signed_with(client, device, session, counter, body)
            .await
    }

    /// Sends one signed request with an explicit counter.
    pub(crate) async fn signed_with(
        &self,
        client: &Client,
        device: &Device,
        session: &DeviceSession,
        counter: u64,
        body: &[u8],
    ) -> Result<Session, AuthError> {
        let origin = origin();
        let parts = request(body);
        let signature = DeviceRequest {
            server_origin: &origin,
            account_id: client.account_id,
            device_id: device.id,
            session_id: session.session_id,
            request_counter: counter,
            method: parts.method,
            path_and_query: parts.path_and_query,
            body_hash: DeviceRequest::body_hash(body),
        }
        .sign(device.keys.signing_key())
        .unwrap();
        let signature = RequestSignature {
            request_counter: counter,
            signature: Fixed::from_bytes(signature.to_bytes()),
        };
        self.svc
            .authenticate_request(
                session.token.expose_secret(),
                Some(&signature),
                parts,
                self.now,
            )
            .await
    }
}

/// Polls two futures concurrently on the current task until both finish (`tokio::join!`
/// without its `macros` feature).
pub(crate) async fn join2<A: std::future::Future, B: std::future::Future>(
    a: A,
    b: B,
) -> (A::Output, B::Output) {
    use std::task::Poll;
    let mut a = std::pin::pin!(a);
    let mut b = std::pin::pin!(b);
    let (mut ra, mut rb) = (None, None);
    std::future::poll_fn(|cx| {
        if ra.is_none()
            && let Poll::Ready(v) = a.as_mut().poll(cx)
        {
            ra = Some(v);
        }
        if rb.is_none()
            && let Poll::Ready(v) = b.as_mut().poll(cx)
        {
            rb = Some(v);
        }
        if ra.is_some() && rb.is_some() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
    (ra.unwrap(), rb.unwrap())
}
