use opaque_ke::ksf::Ksf as _;
use proptest::prelude::*;
use sha2::{Digest as _, Sha256};

use super::ksf::test_hooks::ksf_runs;
use super::*;
use crate::envelope::purpose::AccountKeyServerWrapCtx;
use crate::keys::AccountKey;
use crate::test_util::{hex, seeded_rng};

const ORIGIN: &str = "https://vault.example.com";

fn origin() -> ServerOrigin {
    ServerOrigin::parse(ORIGIN).unwrap()
}

/// Cheap test profiles with distinct parameters per id: `0xfff1` runs 2 passes, `0xfff2` 3.
fn cheap(id: u16) -> KdfId {
    KdfId::test_cheap(id, 1 + u32::from(id & 0x000f))
}

fn sk(byte: u8) -> SecretKey {
    SecretKey::from_slice(&[byte; 16]).unwrap()
}

fn pw(password: &str, secret_key: &SecretKey) -> PasswordInput {
    PasswordInput::derive(password, secret_key).unwrap()
}

/// Server-side fixture: a setup and one registered account.
struct Registered {
    setup: ServerSetup,
    account_id: AccountId,
    file: Vec<u8>,
    export_key: ExportKey,
}

fn register(rng: &mut impl CryptoRng, pw_in: &PasswordInput, kdf_id: KdfId) -> Registered {
    let setup = ServerSetup::generate(rng);
    let account_id = AccountId::generate(rng);
    let (state, m1) = client_registration_start(rng, pw_in).unwrap();
    assert_eq!(m1.len(), REGISTRATION_REQUEST_LEN);
    let m2 = server_registration_start(&setup, &m1, &CredentialIdentifier::for_account(account_id))
        .unwrap();
    assert_eq!(m2.len(), REGISTRATION_RESPONSE_LEN);
    let fin = client_registration_finish(rng, state, pw_in, &m2, kdf_id).unwrap();
    let file = server_registration_finish(&fin.upload).unwrap().to_bytes();
    assert_eq!(file.len(), REGISTRATION_UPLOAD_LEN);
    Registered {
        setup,
        account_id,
        file,
        export_key: fin.export_key,
    }
}

/// One login attempt. The client uses `client_ctx`, the server `server_ctx`.
fn login(
    rng: &mut impl CryptoRng,
    reg: &Registered,
    pw_in: &PasswordInput,
    client_ctx: &OpaqueContext,
    server_ctx: &OpaqueContext,
) -> Result<ExportKey, OpaqueError> {
    let name = LoginName::parse("alice").unwrap();
    let (state, ke1) = client_login_start(rng, pw_in)?;
    // The server names `server_ctx`'s kdf_id for this record, honestly or not.
    let record = RegisteredCredential {
        account_id: reg.account_id,
        password_file: PasswordFile::from_bytes(&reg.file)?,
        kdf_id: server_ctx.kdf_id(),
    };
    let start = server_login_start(rng, &reg.setup, &name, Some(record), &ke1, server_ctx)?;
    assert_eq!(start.ke2.len(), KE2_LEN);
    assert_eq!(
        start.state.credential_identifier(),
        CredentialIdentifier::for_account(reg.account_id)
    );
    let fin = client_login_finish(rng, state, pw_in, &start.ke2, client_ctx)?;
    server_login_finish(start.state, &fin.ke3, server_ctx)?;
    Ok(fin.export_key)
}

#[test]
fn message_lengths_for_rizzy_suite_v1() {
    assert_eq!(REGISTRATION_REQUEST_LEN, 32);
    assert_eq!(REGISTRATION_RESPONSE_LEN, 64);
    assert_eq!(REGISTRATION_UPLOAD_LEN, 192);
    assert_eq!(KE1_LEN, 96);
    assert_eq!(KE2_LEN, 320);
    assert_eq!(KE3_LEN, 64);
}

/// The full flow at the real `kdf_id` 1 (two 64 MiB Argon2id runs), with the Context, the
/// §4.3 `server_unlock_key` and `E_srv`, plus a transcript regression hash (CRYPTO.md §15 item
/// 1, tier B: regenerated, with a note, when a pinned crate changes).
#[test]
fn full_round_trip_at_kdf_id_1() {
    let mut rng = seeded_rng(2026);
    let secret_key = SecretKey::generate(&mut rng);
    let pw_in = PasswordInput::derive_for_new_password("correct horse", &secret_key).unwrap();
    let before = ksf_runs().len();

    // Registration, keeping every message for the transcript hash.
    let setup = ServerSetup::generate(&mut rng);
    let account_id = AccountId::generate(&mut rng);
    let (state, m1) = client_registration_start(&mut rng, &pw_in).unwrap();
    let cred = CredentialIdentifier::for_account(account_id);
    let m2 = server_registration_start(&setup, &m1, &cred).unwrap();
    let reg = client_registration_finish(&mut rng, state, &pw_in, &m2, KdfId::DEFAULT).unwrap();
    let file = server_registration_finish(&reg.upload).unwrap();

    // Login, with the Context the client builds from the server's hints.
    let ctx = OpaqueContext::for_login(&origin(), 1, "https://Vault.Example.com/").unwrap();
    assert_eq!(ctx, OpaqueContext::new(KdfId::DEFAULT, &origin()));
    let (state, ke1) = client_login_start(&mut rng, &pw_in).unwrap();
    let name = LoginName::parse("Alice").unwrap();
    let record = RegisteredCredential {
        account_id,
        password_file: file,
        kdf_id: KdfId::DEFAULT,
    };
    let start = server_login_start(&mut rng, &setup, &name, Some(record), &ke1, &ctx).unwrap();
    let fin = client_login_finish(&mut rng, state, &pw_in, &start.ke2, &ctx).unwrap();
    server_login_finish(start.state, &fin.ke3, &ctx).unwrap();

    // One KSF run for registration and one for login, both at kdf_id 1.
    assert_eq!(ksf_runs()[before..], [1, 1]);
    // Registration and login give the same export_key, hence the same server_unlock_key.
    assert_eq!(
        reg.export_key.expose_secret(),
        fin.export_key.expose_secret()
    );
    let at_signup = reg.export_key.server_unlock_key(account_id).unwrap();
    let at_login = fin.export_key.server_unlock_key(account_id).unwrap();
    let account_key = AccountKey::generate(&mut rng, 0);
    let wrap_ctx = AccountKeyServerWrapCtx {
        account_id,
        account_key_epoch: 0,
        password_epoch: 0,
        kdf_id: KdfId::DEFAULT,
    };
    let e_srv = at_signup
        .wrap_account_key(&mut rng, &wrap_ctx, &account_key)
        .unwrap();
    let opened = at_login.unwrap_account_key(&wrap_ctx, &e_srv).unwrap();
    assert_eq!(
        opened.key().expose_secret(),
        account_key.key().expose_secret()
    );

    // Tier B regression vector: SHA-256 over every message and the export_key.
    let mut transcript = Sha256::new();
    for part in [&m1, &m2, &reg.upload, &ke1, &start.ke2, &fin.ke3] {
        transcript.update(part);
    }
    transcript.update(fin.export_key.expose_secret());
    assert_eq!(
        transcript.finalize().to_vec(),
        hex(TRANSCRIPT_SEED_2026_KDF_1),
        "OPAQUE transcript changed: a pinned crate or the wrapper changed behaviour"
    );
}

/// Tier B transcript regression hash for `full_round_trip_at_kdf_id_1` (seeded `ChaCha20Rng`,
/// seed 2026). Generated by this implementation with opaque-ke 4.0.1, argon2 0.6.0,
/// curve25519-dalek 4.1.3, sha2 0.10.9. Not an independent vector.
const TRANSCRIPT_SEED_2026_KDF_1: &str =
    "e62a1d378d9032c7553d0f55a417a0df0a9a19a0c5a8ef54dc66f842fbb2f3a3";

#[test]
fn wrong_password_secret_key_origin_or_kdf_id_fails_like_a_wrong_password() {
    let mut rng = seeded_rng(1);
    let right_sk = sk(1);
    let pw_in = pw("pw", &right_sk);
    let kdf = cheap(0xfff1);
    let reg = register(&mut rng, &pw_in, kdf);
    let ctx = OpaqueContext::new(kdf, &origin());

    // Baseline succeeds, and gives the registration's export_key.
    let key = login(&mut rng, &reg, &pw_in, &ctx, &ctx).unwrap();
    assert_eq!(key.expose_secret(), reg.export_key.expose_secret());

    // Wrong password, wrong Secret Key: the envelope does not open.
    for wrong in [pw("pW", &right_sk), pw("pw", &sk(2)), pw("pw ", &right_sk)] {
        assert_eq!(
            login(&mut rng, &reg, &wrong, &ctx, &ctx).map(|_| ()),
            Err(OpaqueError::InvalidLogin)
        );
    }

    // A relay phish: the client dialled another origin. The server's KE2 MAC covers its own
    // Context, so the client's check fails before it sends KE3.
    let evil = OpaqueContext::new(kdf, &ServerOrigin::parse("https://evil.example").unwrap());
    let other_port = OpaqueContext::new(
        kdf,
        &ServerOrigin::parse("https://vault.example.com:8443").unwrap(),
    );
    let http = OpaqueContext::new(
        kdf,
        &ServerOrigin::parse("http://vault.example.com").unwrap(),
    );
    for client_ctx in [&evil, &other_port, &http] {
        assert_eq!(
            login(&mut rng, &reg, &pw_in, client_ctx, &ctx).map(|_| ()),
            Err(OpaqueError::InvalidLogin)
        );
    }

    // The server names another kdf_id than the record's: the client stretches differently
    // (and the Context differs), so the login fails. The KSF ran with the Context's kdf_id.
    let other_kdf = OpaqueContext::new(cheap(0xfff2), &origin());
    let before = ksf_runs().len();
    assert_eq!(
        login(&mut rng, &reg, &pw_in, &other_kdf, &other_kdf).map(|_| ()),
        Err(OpaqueError::InvalidLogin)
    );
    assert_eq!(ksf_runs()[before..], [0xfff2]);
    // The two sides' Contexts name different kdf_ids.
    assert_eq!(
        login(&mut rng, &reg, &pw_in, &ctx, &other_kdf).map(|_| ()),
        Err(OpaqueError::InvalidLogin)
    );
    assert_eq!(
        login(&mut rng, &reg, &pw_in, &other_kdf, &ctx).map(|_| ()),
        Err(OpaqueError::InvalidLogin)
    );
    // The Context binding alone: another kdf_id with the same Argon2 parameters stretches to
    // the same value and opens the envelope, yet the KE2 check still fails on the kdf_id.
    let same_params = KdfId::test_cheap(0xfff3, kdf.params().t);
    let relabelled = OpaqueContext::new(same_params, &origin());
    assert_eq!(
        login(&mut rng, &reg, &pw_in, &relabelled, &ctx).map(|_| ()),
        Err(OpaqueError::InvalidLogin)
    );
    assert_eq!(
        login(&mut rng, &reg, &pw_in, &ctx, &relabelled).map(|_| ()),
        Err(OpaqueError::InvalidLogin)
    );
    assert!(login(&mut rng, &reg, &pw_in, &relabelled, &relabelled).is_ok());
}

#[test]
fn server_refuses_a_context_for_another_kdf_id_than_the_record() {
    let mut rng = seeded_rng(9);
    let pw_in = pw("pw", &sk(1));
    let reg = register(&mut rng, &pw_in, cheap(0xfff1));
    let (_, ke1) = client_login_start(&mut rng, &pw_in).unwrap();
    let record = RegisteredCredential {
        account_id: reg.account_id,
        password_file: PasswordFile::from_bytes(&reg.file).unwrap(),
        kdf_id: cheap(0xfff1),
    };
    let wrong = OpaqueContext::new(cheap(0xfff2), &origin());
    let name = LoginName::parse("alice").unwrap();
    assert_eq!(
        server_login_start(&mut rng, &reg.setup, &name, Some(record), &ke1, &wrong).map(|_| ()),
        Err(OpaqueError::ContextMismatch)
    );
}

#[test]
fn server_finish_rejects_a_wrong_ke3() {
    let mut rng = seeded_rng(3);
    let pw_in = pw("pw", &sk(1));
    let kdf = cheap(0xfff1);
    let reg = register(&mut rng, &pw_in, kdf);
    let ctx = OpaqueContext::new(kdf, &origin());
    let name = LoginName::parse("alice").unwrap();
    let (state, ke1) = client_login_start(&mut rng, &pw_in).unwrap();
    let record = RegisteredCredential {
        account_id: reg.account_id,
        password_file: PasswordFile::from_bytes(&reg.file).unwrap(),
        kdf_id: cheap(0xfff1),
    };
    let start = server_login_start(&mut rng, &reg.setup, &name, Some(record), &ke1, &ctx).unwrap();
    let fin = client_login_finish(&mut rng, state, &pw_in, &start.ke2, &ctx).unwrap();
    let mut ke3 = fin.ke3.clone();
    ke3[0] ^= 1;
    assert_eq!(
        server_login_finish(start.state, &ke3, &ctx),
        Err(OpaqueError::InvalidLogin)
    );
}

#[test]
fn ksf_default_is_a_refusing_sentinel() {
    use opaque_ke::generic_array::GenericArray;
    use opaque_ke::generic_array::typenum::{U32, U64};

    let sentinel = RizzyArgon2idKsf::default();
    assert_eq!(sentinel.kdf_id(), None);
    let before = ksf_runs().len();
    assert!(matches!(
        sentinel.hash(GenericArray::<u8, U64>::default()),
        Err(InternalError::KsfError)
    ));
    // Only the 64-byte OPAQUE output length is accepted.
    assert!(matches!(
        RizzyArgon2idKsf::new(cheap(0xfff1)).hash(GenericArray::<u8, U32>::default()),
        Err(InternalError::KsfError)
    ));
    assert_eq!(ksf_runs().len(), before, "neither call stretched");

    // Through opaque-ke itself: `ksf: None` makes it fall back to `Default`, which refuses,
    // for registration and for login alike.
    let mut rng = seeded_rng(4);
    let pw_in = pw("pw", &sk(1));
    let setup = ServerSetup::generate(&mut rng);
    let start =
        ClientRegistration::<Suite>::start(&mut OpaqueRng::new(&mut rng), pw_in.expose_secret())
            .unwrap();
    let response =
        ServerRegistration::<Suite>::start(&setup.inner, start.message, &[7; 16]).unwrap();
    let err = start
        .state
        .finish(
            &mut OpaqueRng::new(&mut rng),
            pw_in.expose_secret(),
            response.message,
            ClientRegistrationFinishParameters::default(),
        )
        .map(|_| ())
        .unwrap_err();
    assert!(matches!(
        err,
        ProtocolError::LibraryError(InternalError::KsfError)
    ));
    assert_eq!(OpaqueError::from(err), OpaqueError::KsfFailed);

    let reg = register(&mut rng, &pw_in, cheap(0xfff1));
    let (state, ke1) = client_login_start(&mut rng, &pw_in).unwrap();
    let record = RegisteredCredential {
        account_id: reg.account_id,
        password_file: PasswordFile::from_bytes(&reg.file).unwrap(),
        kdf_id: cheap(0xfff1),
    };
    let ctx = OpaqueContext::new(cheap(0xfff1), &origin());
    let name = LoginName::parse("alice").unwrap();
    let start = server_login_start(&mut rng, &reg.setup, &name, Some(record), &ke1, &ctx).unwrap();
    let ke2 = CredentialResponse::<Suite>::deserialize(&start.ke2).unwrap();
    let err = state
        .inner
        .finish(
            &mut OpaqueRng::new(&mut rng),
            pw_in.expose_secret(),
            ke2,
            ClientLoginFinishParameters::new(Some(ctx.as_bytes()), Identifiers::default(), None),
        )
        .map(|_| ())
        .unwrap_err();
    assert!(matches!(
        err,
        ProtocolError::LibraryError(InternalError::KsfError)
    ));
}

#[test]
fn ksf_is_argon2id_with_a_zero_salt_and_64_byte_output() {
    // CRYPTO.md §5.1: Argon2id(P = oprf_output, S = 16 zero bytes, kdf_id, T = 64). Checked on
    // a cheap profile (32 KiB, t = 2, p = 4) against the reference C Argon2 (argon2-cffi
    // 25.1.0); the kdf_id 1 parameters behind the same function are pinned by
    // kdf::tests::argon2id_kdf_id_1_known_answers, whose 64-byte case is exactly this KSF
    // configuration, and are exercised end to end by `full_round_trip_at_kdf_id_1`.
    use opaque_ke::generic_array::GenericArray;
    use opaque_ke::generic_array::typenum::U64;
    let input = GenericArray::<u8, U64>::clone_from_slice(&[0x5a; 64]);
    let output = RizzyArgon2idKsf::new(cheap(0xfff1)).hash(input).unwrap();
    assert_eq!(
        output.to_vec(),
        hex(
            "bccaa3cc7d90ef050f5e4d78b745b41c88b0ca919ccf645805bfe870d76b7de1
             b8c283e6129d701743e1be216ae8518f77301619192b5dcc762c6153e5b5011e"
        )
    );
}

#[test]
fn context_layout() {
    let ctx = OpaqueContext::new(KdfId::DEFAULT, &origin());
    let mut expected = b"rizzy-vault/v1/opaque/context\x00\x00\x01\x00\x01".to_vec();
    expected.extend_from_slice(&u32::try_from(ORIGIN.len()).unwrap().to_be_bytes());
    expected.extend_from_slice(ORIGIN.as_bytes());
    assert_eq!(ctx.as_bytes(), expected);
    assert_eq!(ctx.kdf_id(), KdfId::DEFAULT);
    assert!(!format!("{ctx:?}").contains("vault"));
}

#[test]
fn login_hints_are_checked_before_any_stretching() {
    let before = ksf_runs().len();
    for kdf in [0u16, 2, 3, u16::MAX] {
        assert_eq!(
            OpaqueContext::for_login(&origin(), kdf, ORIGIN),
            Err(LoginHintError::KdfNotAllowed(KdfError::NotAllowed {
                kdf_id: kdf
            }))
        );
    }
    for served in [
        "https://evil.example",
        "https://vault.example.com:8443",
        "http://vault.example.com",
        "not an origin",
        "",
    ] {
        assert_eq!(
            OpaqueContext::for_login(&origin(), 1, served),
            Err(LoginHintError::OriginMismatch),
            "{served}"
        );
    }
    assert!(OpaqueContext::for_login(&origin(), 1, "HTTPS://vault.example.com:443/").is_ok());
    assert_eq!(ksf_runs().len(), before);
}

#[test]
fn fake_record_path() {
    let mut rng = seeded_rng(5);
    let pw_in = pw("pw", &sk(1));
    let kdf = cheap(0xfff1);
    let reg = register(&mut rng, &pw_in, kdf);
    let ctx = OpaqueContext::new(kdf, &origin());
    let unknown = LoginName::parse("Mallory@Example.com").unwrap();

    // The same code path, with no record: a full-length KE2 and a sealable state.
    let (state, ke1) = client_login_start(&mut rng, &pw_in).unwrap();
    let fake = server_login_start(&mut rng, &reg.setup, &unknown, None, &ke1, &ctx).unwrap();
    assert_eq!(fake.ke2.len(), KE2_LEN);
    assert_eq!(
        fake.state.credential_identifier(),
        CredentialIdentifier::fake(&unknown)
    );
    assert_eq!(fake.state.to_bytes().len(), SERVER_LOGIN_STATE_LEN);
    // The client cannot tell it from a wrong password.
    assert_eq!(
        client_login_finish(&mut rng, state, &pw_in, &fake.ke2, &ctx).map(|_| ()),
        Err(OpaqueError::InvalidLogin)
    );
    // Any KE3 fails on the server.
    assert_eq!(
        server_login_finish(fake.state, &[0u8; KE3_LEN], &ctx),
        Err(OpaqueError::InvalidLogin)
    );

    // Deterministic: the same name and KE1 give the same OPRF evaluation (the first 32 bytes of
    // KE2), so repeated probes get consistent answers; another name gives another one.
    let again = server_login_start(&mut rng, &reg.setup, &unknown, None, &ke1, &ctx).unwrap();
    assert_eq!(fake.ke2[..32], again.ke2[..32]);
    assert_ne!(
        fake.ke2[32..],
        again.ke2[32..],
        "the rest is freshly random"
    );
    let same_name = LoginName::parse("mallory@example.com").unwrap();
    let third = server_login_start(&mut rng, &reg.setup, &same_name, None, &ke1, &ctx).unwrap();
    assert_eq!(fake.ke2[..32], third.ke2[..32]);
    let other = LoginName::parse("eve").unwrap();
    let fourth = server_login_start(&mut rng, &reg.setup, &other, None, &ke1, &ctx).unwrap();
    assert_ne!(fake.ke2[..32], fourth.ke2[..32]);

    // A real record under the name ignores the fake id: its credential identifier is the
    // account id, and the login succeeds.
    let record = RegisteredCredential {
        account_id: reg.account_id,
        password_file: PasswordFile::from_bytes(&reg.file).unwrap(),
        kdf_id: cheap(0xfff1),
    };
    let (state, ke1) = client_login_start(&mut rng, &pw_in).unwrap();
    let real =
        server_login_start(&mut rng, &reg.setup, &unknown, Some(record), &ke1, &ctx).unwrap();
    assert_eq!(
        real.state.credential_identifier(),
        CredentialIdentifier::for_account(reg.account_id)
    );
    let fin = client_login_finish(&mut rng, state, &pw_in, &real.ke2, &ctx).unwrap();
    server_login_finish(real.state, &fin.ke3, &ctx).unwrap();
}

#[test]
fn fake_derivations_known_answers() {
    // Independent: Python hashlib and hmac, written from CRYPTO.md §4.3.
    let name = LoginName::parse("Alice@Example.com").unwrap();
    assert_eq!(
        CredentialIdentifier::fake(&name).as_bytes().to_vec(),
        hex("634340e76c985d9c271f19bf81d3c1db")
    );
    let enum_key = EnumKey::from_slice(&[0x42; 32]).unwrap();
    assert_eq!(
        enum_key.fake_kdf_selector(&name),
        Ok(15_504_708_438_194_591_919)
    );
    assert_ne!(
        enum_key.fake_kdf_selector(&LoginName::parse("bob").unwrap()),
        enum_key.fake_kdf_selector(&name)
    );
    assert!(EnumKey::from_slice(&[0; 31]).is_err());
    assert_eq!(format!("{enum_key:?}"), "EnumKey([REDACTED])");
}

#[test]
fn password_input_known_answers() {
    // Independent: Python cryptography HKDF and unicodedata NFC, from CRYPTO.md §5.2.
    let secret_key = SecretKey::from_slice(&(0u8..16).collect::<Vec<_>>()).unwrap();
    assert_eq!(
        pw("correct horse battery staple", &secret_key)
            .expose_secret()
            .to_vec(),
        hex("208da9182340563966cd9f79e69cda25825ce350dce1d8251edbc525efb9491f")
    );
    let composed = pw("caf\u{e9}", &secret_key);
    let decomposed = pw("cafe\u{301}", &secret_key);
    assert_eq!(composed.expose_secret(), decomposed.expose_secret());
    assert_eq!(
        composed.expose_secret().to_vec(),
        hex("30a5b6fda734a32efc1746b11c2e6881ce33b043af82781c9259378eb481bf3b")
    );
    // The Secret Key matters.
    assert_ne!(
        pw("correct horse battery staple", &sk(0)).expose_secret(),
        pw("correct horse battery staple", &secret_key).expose_secret()
    );
    // New passwords reject unassigned code points; login never does.
    assert_eq!(
        PasswordInput::derive_for_new_password("pw\u{0378}", &secret_key).map(|_| ()),
        Err(KdfError::UnassignedCodePoint)
    );
    assert!(PasswordInput::derive("pw\u{0378}", &secret_key).is_ok());
    assert_eq!(format!("{composed:?}"), "PasswordInput([REDACTED])");
}

#[test]
fn server_state_serialisation() {
    let mut rng = seeded_rng(6);
    let pw_in = pw("pw", &sk(1));
    let kdf = cheap(0xfff1);
    let reg = register(&mut rng, &pw_in, kdf);

    // The setup survives the secrets file, and logins still work with the restored copy.
    let bytes = reg.setup.to_bytes();
    assert_eq!(bytes.len(), SERVER_SETUP_LEN);
    let restored = ServerSetup::from_bytes(bytes.expose_secret()).unwrap();
    assert_eq!(restored.public_key_hash(), reg.setup.public_key_hash());
    assert_ne!(
        ServerSetup::generate(&mut rng).public_key_hash(),
        reg.setup.public_key_hash()
    );
    let reg = Registered {
        setup: restored,
        ..reg
    };
    let ctx = OpaqueContext::new(kdf, &origin());
    assert!(login(&mut rng, &reg, &pw_in, &ctx, &ctx).is_ok());

    // The login state survives SERVER_LOGIN_STATE storage between KE2 and KE3.
    let name = LoginName::parse("alice").unwrap();
    let (state, ke1) = client_login_start(&mut rng, &pw_in).unwrap();
    let record = RegisteredCredential {
        account_id: reg.account_id,
        password_file: PasswordFile::from_bytes(&reg.file).unwrap(),
        kdf_id: cheap(0xfff1),
    };
    let start = server_login_start(&mut rng, &reg.setup, &name, Some(record), &ke1, &ctx).unwrap();
    let stored = start.state.to_bytes();
    assert_eq!(stored.len(), SERVER_LOGIN_STATE_LEN);
    let cred = start.state.credential_identifier();
    drop(start.state);
    let fin = client_login_finish(&mut rng, state, &pw_in, &start.ke2, &ctx).unwrap();
    let state = ServerLoginState::from_bytes(stored.expose_secret(), cred).unwrap();
    server_login_finish(state, &fin.ke3, &ctx).unwrap();

    // Debug never shows key material.
    for text in [
        format!("{:?}", reg.setup),
        format!("{:?}", PasswordFile::from_bytes(&reg.file).unwrap()),
        format!("{:?}", reg.export_key),
    ] {
        assert!(text.contains("[REDACTED]"), "{text}");
    }
}

#[test]
fn malformed_inputs_are_rejected_without_panics() {
    let mut rng = seeded_rng(7);
    let pw_in = pw("pw", &sk(1));
    let kdf = cheap(0xfff1);
    let reg = register(&mut rng, &pw_in, kdf);
    let ctx = OpaqueContext::new(kdf, &origin());
    let name = LoginName::parse("alice").unwrap();
    let cred = CredentialIdentifier::for_account(reg.account_id);

    let (_, m1) = client_registration_start(&mut rng, &pw_in).unwrap();
    let (_, ke1) = client_login_start(&mut rng, &pw_in).unwrap();
    for len in [0, 1, 31, 33, 95, 97, 200] {
        let junk = vec![0x5a; len];
        assert_eq!(
            server_registration_start(&reg.setup, &junk, &cred),
            Err(OpaqueError::MalformedMessage)
        );
        assert_eq!(
            server_registration_finish(&junk).map(|_| ()),
            Err(OpaqueError::MalformedMessage)
        );
        assert_eq!(
            server_login_start(&mut rng, &reg.setup, &name, None, &junk, &ctx).map(|_| ()),
            Err(OpaqueError::MalformedMessage)
        );
        assert_eq!(
            PasswordFile::from_bytes(&junk).map(|_| ()).unwrap_err(),
            OpaqueError::MalformedMessage
        );
        assert!(ServerSetup::from_bytes(&junk).is_err());
        assert!(ServerLoginState::from_bytes(&junk, cred).is_err());
    }
    // Right length, but not a valid group element (all 0xff is not a canonical encoding).
    assert_eq!(
        server_registration_start(&reg.setup, &[0xff; REGISTRATION_REQUEST_LEN], &cred),
        Err(OpaqueError::MalformedMessage)
    );
    assert!(server_registration_start(&reg.setup, &m1, &cred).is_ok());
    let mut bad_ke1 = ke1.clone();
    bad_ke1[..32].fill(0xff);
    assert!(server_login_start(&mut rng, &reg.setup, &name, None, &bad_ke1, &ctx).is_err());

    // Client side: truncated or extended server messages never reach the KSF.
    let before = ksf_runs().len();
    for len in [0, 63, 65, 319, 321] {
        let (state, _) = client_registration_start(&mut rng, &pw_in).unwrap();
        assert_eq!(
            client_registration_finish(&mut rng, state, &pw_in, &vec![1; len], kdf).map(|_| ()),
            Err(OpaqueError::MalformedMessage)
        );
        let (state, _) = client_login_start(&mut rng, &pw_in).unwrap();
        assert_eq!(
            client_login_finish(&mut rng, state, &pw_in, &vec![1; len], &ctx).map(|_| ()),
            Err(OpaqueError::MalformedMessage)
        );
    }
    assert_eq!(ksf_runs().len(), before);

    // A server that reflects the client's blinded element is caught.
    let (state, m1) = client_registration_start(&mut rng, &pw_in).unwrap();
    let mut reflected = m1.clone();
    reflected.extend_from_slice(&[0u8; 32]);
    let honest = server_registration_start(&reg.setup, &m1, &cred).unwrap();
    reflected[32..].copy_from_slice(&honest[32..]);
    assert_eq!(
        client_registration_finish(&mut rng, state, &pw_in, &reflected, kdf).map(|_| ()),
        Err(OpaqueError::Protocol)
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn server_parsers_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..400)) {
        let mut rng = seeded_rng(8);
        let setup = ServerSetup::generate(&mut rng);
        let ctx = OpaqueContext::new(cheap(0xfff1), &origin());
        let name = LoginName::parse("alice").unwrap();
        let cred = CredentialIdentifier::for_account(AccountId::from_bytes([1; 16]));
        let _ = server_registration_start(&setup, &bytes, &cred);
        let _ = server_registration_finish(&bytes);
        let _ = server_login_start(&mut rng, &setup, &name, None, &bytes, &ctx);
        let _ = PasswordFile::from_bytes(&bytes);
        let _ = ServerSetup::from_bytes(&bytes);
        let _ = ServerLoginState::from_bytes(&bytes, cred);
        // Fixed-length random inputs reach opaque-ke's own parsers.
        let mut fixed = bytes.clone();
        fixed.resize(KE1_LEN, 0);
        let _ = server_login_start(&mut rng, &setup, &name, None, &fixed, &ctx);
        fixed.resize(REGISTRATION_UPLOAD_LEN, 0);
        let _ = server_registration_finish(&fixed);
        fixed.resize(SERVER_SETUP_LEN, 0);
        let _ = ServerSetup::from_bytes(&fixed);
    }
}
