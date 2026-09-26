//! Fuzzes the server side of the OPAQUE wrapper (CRYPTO.md §5, §15 item 7). M1, the
//! registration upload, KE1 and KE3 arrive in unauthenticated API bodies (§11.1 step 4, §11.2
//! steps 3 and 5). The stored record, the sealed login state and the server setup come back
//! from the server's own storage; they are fuzzed as defence in depth. No path here runs the
//! KSF.
//!
//! Every input is tried as it is, where a wrong length must be refused before opaque-ke parses
//! it, and resized to each message length, so opaque-ke's own parsers see fuzzed content. The
//! properties: nothing panics; an accepted record, state or setup serialises back to the same
//! bytes and works in a login; the fake-record path answers every KE1 exactly as the
//! real-record path does (§5.9); and no KE3 completes an honest pending login.
//!
//! The client side (M2, KE2) is not here: a well-formed message runs the production Argon2id,
//! and no cheap KSF exists outside `rizzy-core`'s own tests.
#![no_main]

use std::convert::Infallible;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use rand_core::{TryCryptoRng, TryRng};
use rizzy_core::ids::AccountId;
use rizzy_core::kdf::KdfId;
use rizzy_core::normalize::{LoginName, ServerOrigin};
use rizzy_core::opaque::{
    CredentialIdentifier, KE1_LEN, KE2_LEN, KE3_LEN, OpaqueContext, OpaqueError, PasswordFile,
    PasswordInput, REGISTRATION_REQUEST_LEN, REGISTRATION_RESPONSE_LEN, REGISTRATION_UPLOAD_LEN,
    RegisteredCredential, SERVER_LOGIN_STATE_LEN, SERVER_SETUP_LEN, ServerLoginState, ServerSetup,
    client_login_start, client_registration_start, server_login_finish, server_login_start,
    server_registration_finish, server_registration_start,
};
use rizzy_core::secret::SecretBytes;
use rizzy_core::secret_key::SecretKey;

/// Every fixed length the server side parses. Each input is also resized to each of them.
const LENGTHS: [usize; 6] = [
    REGISTRATION_REQUEST_LEN,
    REGISTRATION_UPLOAD_LEN,
    KE1_LEN,
    KE3_LEN,
    SERVER_LOGIN_STATE_LEN,
    SERVER_SETUP_LEN,
];

/// The canonical encoding of the ristretto255 generator (`1·B` in RFC 9496 Appendix A.1, and
/// curve25519-dalek's `RISTRETTO_BASEPOINT_COMPRESSED`): a valid, non-identity element, used as
/// the client public key of the fixture's record.
const RISTRETTO255_GENERATOR: [u8; 32] = [
    0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71, 0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00, 0x51, 0x5f,
    0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d, 0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d, 0x2d, 0x76,
];

/// The randomness the fixture and the server draw (setup, blinds, masking nonces, ephemeral
/// keys). It counts upward, so no draw is all zeros. It is not a CSPRNG: nothing here depends
/// on unpredictability, and a crash must reproduce from its input alone. Like `rizzy-core`'s
/// test `FixedRng`, it is marked `CryptoRng` only so the API accepts it.
struct CountingRng(u8);

impl TryRng for CountingRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for b in dst {
            *b = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}

impl TryCryptoRng for CountingRng {}

/// What every input runs against, built once per process.
struct Fixture {
    setup: ServerSetup,
    context: OpaqueContext,
    login_name: LoginName,
    account_id: AccountId,
    /// An honest M1 and KE1 from a client.
    m1: Vec<u8>,
    ke1: Vec<u8>,
    /// A record that parses: the generator as the client key, a fixed masking key and
    /// envelope.
    record: Vec<u8>,
    /// The honest KE1's pending logins, in their `SERVER_LOGIN_STATE` plaintext form, with
    /// their credential identifiers: the fake-record path and the real-record path.
    pending: [(SecretBytes, CredentialIdentifier); 2],
}

impl Fixture {
    fn credential(&self, password_file: PasswordFile) -> RegisteredCredential {
        credential(self.account_id, password_file)
    }

    fn record(&self) -> PasswordFile {
        PasswordFile::from_bytes(&self.record).expect("the fixture's record parses")
    }
}

/// The found account for a login with `password_file`, under the Context's `kdf_id`.
fn credential(account_id: AccountId, password_file: PasswordFile) -> RegisteredCredential {
    RegisteredCredential {
        account_id,
        password_file,
        kdf_id: KdfId::DEFAULT,
    }
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let mut rng = CountingRng(0);
        let setup = ServerSetup::generate(&mut rng);
        let origin = ServerOrigin::parse("https://vault.example").expect("a canonical origin");
        let context = OpaqueContext::new(KdfId::DEFAULT, &origin);
        let login_name = LoginName::parse("alice").expect("a login name");
        let account_id = AccountId::from_bytes([1; 16]);
        let secret_key = SecretKey::generate(&mut rng);
        let pw_in = PasswordInput::derive("correct horse", &secret_key).expect("pw_in");
        let (_, m1) = client_registration_start(&mut rng, &pw_in).expect("M1");
        let (_, ke1) = client_login_start(&mut rng, &pw_in).expect("KE1");
        let mut record = RISTRETTO255_GENERATOR.to_vec();
        record.resize(REGISTRATION_UPLOAD_LEN, 0x5a);
        let file = PasswordFile::from_bytes(&record).expect("the fixture's record parses");
        let pending = [None, Some(credential(account_id, file))].map(|found| {
            let start = server_login_start(&mut rng, &setup, &login_name, found, &ke1, &context)
                .expect("an honest KE1 is answered");
            (start.state.to_bytes(), start.state.credential_identifier())
        });
        Fixture {
            setup,
            context,
            login_name,
            account_id,
            m1,
            ke1,
            record,
            pending,
        }
    })
}

fn exercise(f: &Fixture, bytes: &[u8]) {
    let mut rng = CountingRng(0);
    let account = CredentialIdentifier::for_account(f.account_id);

    // M1 (§11.1 step 4).
    if let Ok(m2) = server_registration_start(&f.setup, bytes, &account) {
        assert_eq!(bytes.len(), REGISTRATION_REQUEST_LEN);
        assert_eq!(m2.len(), REGISTRATION_RESPONSE_LEN);
    }

    // The registration upload, which is also the stored record: both readers agree, and an
    // accepted one serialises back unchanged and answers an honest KE1.
    let uploaded = server_registration_finish(bytes);
    let stored = PasswordFile::from_bytes(bytes);
    assert_eq!(uploaded.as_ref().err(), stored.as_ref().err());
    if let Ok(file) = uploaded {
        assert_eq!(file.to_bytes(), bytes);
        let start = server_login_start(
            &mut rng,
            &f.setup,
            &f.login_name,
            Some(f.credential(file)),
            &f.ke1,
            &f.context,
        )
        .expect("an accepted record answers an honest KE1");
        assert_eq!(start.ke2.len(), KE2_LEN);
    }

    // KE1 (§11.2 step 3): an unknown login name gets exactly the answer a real account gets,
    // accepted or refused alike (§5.9).
    let fake = server_login_start(&mut rng, &f.setup, &f.login_name, None, bytes, &f.context)
        .map(|start| start.ke2.len());
    let real = server_login_start(
        &mut rng,
        &f.setup,
        &f.login_name,
        Some(f.credential(f.record())),
        bytes,
        &f.context,
    )
    .map(|start| start.ke2.len());
    assert_eq!(fake, real);
    if fake.is_ok() {
        assert_eq!(bytes.len(), KE1_LEN);
        assert_eq!(fake, Ok(KE2_LEN));
    }

    // KE3 (§11.2 step 5) against the honest pending logins: never accepted, and every KE3 of
    // the right length fails as a wrong password does.
    let expected = if bytes.len() == KE3_LEN {
        OpaqueError::InvalidLogin
    } else {
        OpaqueError::MalformedMessage
    };
    for (state, id) in &f.pending {
        let state = ServerLoginState::from_bytes(state.expose_secret(), *id)
            .expect("the fixture's own state");
        assert_eq!(server_login_finish(state, bytes, &f.context), Err(expected));
    }

    // Values the server reads back from its own storage (§5.8, §5.11).
    if let Ok(state) = ServerLoginState::from_bytes(bytes, account) {
        assert_eq!(state.to_bytes().expose_secret(), bytes);
        let ke3 = bytes.get(..KE3_LEN).unwrap_or(bytes);
        let _ = server_login_finish(state, ke3, &f.context);
    }
    if let Ok(setup) = ServerSetup::from_bytes(bytes) {
        assert_eq!(setup.to_bytes().expose_secret(), bytes);
        let _ = setup.public_key_hash();
        assert!(server_registration_start(&setup, &f.m1, &account).is_ok());
        let start = server_login_start(&mut rng, &setup, &f.login_name, None, &f.ke1, &f.context);
        assert!(start.is_ok());
    }
}

fuzz_target!(|data: &[u8]| {
    let f = fixture();
    exercise(f, data);
    for (i, &len) in LENGTHS.iter().enumerate() {
        if len != data.len() && !LENGTHS[..i].contains(&len) {
            let mut resized = data.to_vec();
            resized.resize(len, 0);
            exercise(f, &resized);
        }
    }
});
