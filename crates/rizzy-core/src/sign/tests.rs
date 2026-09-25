//! Signature tests: RFC 8032 through the wrappers, `verify_strict` behaviour, the container,
//! independent known answers for every statement, a round trip and a bit-flip tamper test per
//! statement, the structural rules of each statement, and the bundle chain rules.
//!
//! Known answers marked "independent" were computed with a separate Python implementation
//! written from CRYPTO.md (Python `cryptography` 50.0.1 Ed25519, `hashlib`), not from this code.

use super::bundle::FLAG_PQ_REQUIRED;
use super::statements::{
    OP_HEADER_MAX_LEN, OP_HEADER_MIN_LEN, SNAPSHOT_HEADER_MIN_LEN, WEB_CERT_MAX_LIFETIME_MS,
};
use super::*;
use crate::envelope::Purpose;
use crate::hpke::{HpkePublicKey, HpkeSecretKey};
use crate::ids::{AccountId, DeviceId, SessionId, SymmetricKeyId};
use crate::kdf::KdfId;
use crate::keys::IdentityPublicKeys;
use crate::labels;
use crate::test_util::{hex, seeded_rng};

// ---------------------------------------------------------------------------------------------
// Fixtures (the same values as the independent computation)
// ---------------------------------------------------------------------------------------------

const CREATED: u64 = 1_700_000_000_000;

fn account() -> AccountId {
    AccountId::from_bytes([0x0a; 16])
}

fn device() -> DeviceId {
    DeviceId::from_bytes([0x0e; 16])
}

fn identity() -> IdentitySigningKey {
    IdentitySigningKey::from_seed(&[0x66; 32])
}

fn device_key() -> DeviceSigningKey {
    DeviceSigningKey::from_seed(&[0x88; 32])
}

fn sender_key() -> DeviceSigningKey {
    DeviceSigningKey::from_seed(&[0x55; 32])
}

fn x25519(byte: u8) -> HpkePublicKey {
    *HpkeSecretKey::from_x25519_bytes(&[byte; 32])
        .unwrap()
        .public_key()
}

fn cert() -> DeviceCertificate {
    DeviceCertificate {
        account_id: account(),
        device_id: device(),
        identity_epoch: 0,
        device_ed25519: *device_key().verifying_key(),
        device_x25519: x25519(0x33),
        device_kind: DeviceKind::DesktopCli,
        created_at_ms: CREATED,
        expires_at_ms: 0,
    }
}

fn first_bundle() -> PublicKeyBundle {
    PublicKeyBundle {
        account_id: account(),
        identity_epoch: 0,
        bundle_seq: 1,
        identity_ed25519: *identity().verifying_key(),
        identity_x25519: x25519(0x77),
        mail_x25519: None,
        pq_required: false,
        created_at_ms: CREATED,
        prev_bundle_hash: [0; 32],
    }
}

fn state() -> AccountState {
    AccountState {
        account_id: account(),
        state_seq: 1,
        identity_epoch: 0,
        account_key_epoch: 0,
        account_key_id: SymmetricKeyId::from_bytes(hex(PREV_AK_KEY_ID).try_into().unwrap()),
        password_epoch: 0,
        kdf_id: KdfId::DEFAULT,
        recovery_epoch: 1,
        recovery_enabled: true,
        sync_mode: SyncMode::Server,
        mail_key_epoch: 0,
        bundle_hash: hex(BUNDLE_HASH).try_into().unwrap(),
        device_set_hash: hex(DEVICE_SET_HASH_ONE).try_into().unwrap(),
        settings_seq: 0,
        settings_hash: [0; 32],
    }
}

fn op_header() -> Vec<u8> {
    (0u8..97).collect()
}

/// Signs `body` under `label` directly, bypassing the statement types' checks, to build
/// statements a conforming writer would never produce.
fn raw_wire<R: SignerRole>(label: labels::Label, body: &[u8], key: &SigningKey<R>) -> Vec<u8> {
    let container = key.sign_message(&signed_message(label, body)).unwrap();
    encode_wire(body, &[container]).unwrap()
}

/// Every single-bit flip anywhere in `wire` is rejected, and every truncation too, without a
/// panic. `verify` returns whether the statement was accepted.
fn assert_every_bit_is_bound(wire: &[u8], verify: impl Fn(&[u8]) -> bool) {
    assert!(verify(wire), "the untouched statement verifies");
    for i in 0..wire.len() * 8 {
        let mut bad = wire.to_vec();
        bad[i / 8] ^= 1 << (i % 8);
        assert!(!verify(&bad), "bit {i} (byte {})", i / 8);
    }
    for n in 0..wire.len() {
        assert!(!verify(&wire[..n]), "prefix {n}");
    }
    let mut longer = wire.to_vec();
    longer.push(0);
    assert!(!verify(&longer), "trailing byte");
}

// Independent known answers.
const PREV_AK_KEY_ID: &str = "3961f732bceb9056d953baad8dbfaecf";
const BUNDLE_HASH: &str = "c04d5fdc185ef66a9f88948e5afcad05732fdea031a04319a2e38b1dea7bd4fe";
const DEVICE_SET_HASH_ONE: &str =
    "8a76dc093c66172b62b36d0303d15d95472a80de28805b40170c4d2b09e02b6e";
const BUNDLE_WIRE: &str = "0000009200010a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a00000000000000000000000102010000002034b4d9043156cb6dcf0beb0a2949b7559c940d2bcb6dbe8c53a9b30278e3a74602000000201cf579aba45a10ba1d1ef06d91fca2aa9ed0a1150515653155405d0b18cb9a67000000018bcfe5680000000000000000000000000000000000000000000000000000000000000000000101ad996d67a9c99ad23034d63f7d371aa1931b87adaf0e52ad2bd662d96890379cb599bb9ee46ac485a3928290fe9189b7c558c6bb9f681bc0fad32129d25e503ec93ad0c7638b154d9a86d3a463fcf80b";
const CERT_WIRE: &str = "0000007700010a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e00000000b2491d9502ae28630a2bacb2e0c74510ffcdd328c334ff3e1393e75b2d31e7dc7b0d47d93427f8311160781c7c733fd89f88970aef490d8aa0ee19a4cb8a1b14010000018bcfe5680000000000000000000101ad996d67a9c99ad23034d63f7d371aa193cba5c815682ac0f8ead5e782cd34fbe535f54c93339188a15ad3a585a1b14131124b01e93ed384adf56145ed705bd2a9b5b80a1ce4e5a17c2ae8161e169c0d";
const STATE_WIRE: &str = "000000aa00010a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a000000000000000100000000000000003961f732bceb9056d953baad8dbfaecf00000000000100000001010100000000c04d5fdc185ef66a9f88948e5afcad05732fdea031a04319a2e38b1dea7bd4fe8a76dc093c66172b62b36d0303d15d95472a80de28805b40170c4d2b09e02b6e000000000000000000000000000000000000000000000000000000000000000000000000000000000101ad996d67a9c99ad23034d63f7d371aa19d9977da0b13adbcdc2feb03734c632c7045fded717604bf82fff9641fb6bdd22e1d113161dedc61406d350e782be8eb6b537ba49da1ef3a1091940913feb809";
const OP_WIRE: &str = "000000a7000100000061000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f601b4aa51c2da05becf8c63270438c833327d5b28b7006438c85053a5c607d5f241dd3df8a4e08ac1ddd42d3ef5e7414217eaac0ac9a9f714aa86c0a877c2f166a01018b4f02d8c0c813226bd2f5ab5c54e8cdaaa5b57c21e1e1c64d279b19639758185b45f9ddbe8fa3785bb88493b10a550705c66922d419f223839c4b9c2ebb072dce7cf6d7a216f014755660895ae09109";
const OP_WIRE_NOWRAP: &str = "000000a7000100000061000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f601b4aa51c2da05becf8c63270438c833327d5b28b7006438c85053a5c607d5f24000000000000000000000000000000000000000000000000000000000000000001018b4f02d8c0c813226bd2f5ab5c54e8cd8c8b15215dc10acd2cdb3364e4d1317019cf28290979770b281c646e221d3f15684015772c4b8850b679ce5eda3ad393765c47a389a66a6a3e6104dd93427700";
/// The device-grant envelope of the HPKE known answer (`hpke` tests).
const DEVICE_GRANT_ENVELOPE: &str = "0112cfc73380bda7467f0b0fa7b309c67b7686e76b8dd088dabf46d94d4820a251861376de69c3a36f2e53f8bffcdb519e008af61a94cfae79e703dad5b2b8bd10f7ec486c68920bdee3ef0a4f2c6fffdecb5ae7f9f8b8318632e6fa830e56af4a72";
const KEY_GRANT_WIRE: &str = "0000008a000100048b4f02d8c0c813226bd2f5ab5c54e8cdcfc73380bda7467f0b0fa7b309c67b76000000620112cfc73380bda7467f0b0fa7b309c67b7686e76b8dd088dabf46d94d4820a251861376de69c3a36f2e53f8bffcdb519e008af61a94cfae79e703dad5b2b8bd10f7ec486c68920bdee3ef0a4f2c6fffdecb5ae7f9f8b8318632e6fa830e56af4a7201018b4f02d8c0c813226bd2f5ab5c54e8cdf09cf8d2c2eade4f6bfed14a55468fb995267fdd05bb16884187b6e9f40213eff4e71275b6f58851979039130339250ddd6bcd359a4c0371b7e2cc3aaf530b01";
const DEVICE_AUTH_CONTAINER: &str = "0101e0f805f5eb8d09a48be91ca1e27455a3e92d41c927db6b42f37bd8ebf923ccf38b36324fe2e5a5abcac89c5a6fb89fd9db1c033e4efe11a02365c2b659c263af77f14ad816c8f6ecee1bdee58235c607";
const DEVICE_REQUEST_CONTAINER: &str = "0101e0f805f5eb8d09a48be91ca1e27455a3dcd5aee16ff96a8c9d42017f636b077567fc560e279488e22ad300d12e8707d0102fc2e4e5a9a99e6525e51ee8d45d0762f8fbb3494e57177c650fcedfc22707";

// ---------------------------------------------------------------------------------------------
// RFC 8032 and verify_strict (CRYPTO.md §10.2, §15 item 2)
// ---------------------------------------------------------------------------------------------

/// RFC 8032 §7.1 tests 1–3, through [`SigningKey`] and [`VerifyingKey`]. The values were also
/// re-derived independently (Ed25519 is deterministic).
#[test]
fn rfc8032_section_7_1_through_the_wrappers() {
    let cases = [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
    ];
    for (sk, pk, msg, sig) in cases {
        let key = DeviceSigningKey::from_seed(&hex(sk).try_into().unwrap());
        assert_eq!(
            key.verifying_key().as_bytes().as_slice(),
            hex(pk).as_slice()
        );
        let container = key.sign_message(&hex(msg)).unwrap();
        assert_eq!(container.signature().as_slice(), hex(sig).as_slice());
        assert_eq!(container.signer_key_id(), &key.key_id());
        let public = DeviceVerifyingKey::from_bytes(&hex(pk).try_into().unwrap()).unwrap();
        public.verify_container(&hex(msg), &container).unwrap();
        assert_eq!(
            public.verify_container(b"another message", &container),
            Err(VerifyError::BadSignature)
        );
        let mut seed = [0u8; 32];
        key.write_seed(&mut seed);
        assert_eq!(seed.as_slice(), hex(sk).as_slice());
    }
}

/// `verify_strict` rejects a malleated signature (`s + ℓ`), and key parsing rejects small-order
/// and non-canonically encoded keys.
#[test]
fn strict_verification_and_strict_keys() {
    let key = DeviceSigningKey::from_seed(&[0x21; 32]);
    let container = key.sign_message(b"message").unwrap();
    // ℓ = 2^252 + 27742317777372353535851937790883648493, little-endian.
    let ell = hex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
    let mut malleated = *container.signature();
    let mut carry = 0u16;
    for (s, l) in malleated[32..].iter_mut().zip(&ell) {
        let sum = u16::from(*s) + u16::from(*l) + carry;
        *s = sum.to_le_bytes()[0];
        carry = sum >> 8;
    }
    let mut bytes = container.to_bytes();
    bytes[18..].copy_from_slice(&malleated);
    let malleated = SignatureContainer::from_bytes(&bytes).unwrap();
    assert_eq!(
        key.verifying_key().verify_container(b"message", &malleated),
        Err(VerifyError::BadSignature)
    );

    // The identity point (small order) is a weak key.
    let mut identity_point = [0u8; 32];
    identity_point[0] = 1;
    assert_eq!(
        DeviceVerifyingKey::from_bytes(&identity_point).map(|_| ()),
        Err(ParseError::InvalidValue)
    );
    // Non-canonical encodings y = p + k of points that are not weak: decompression accepts
    // them, this module does not.
    let mut found = 0;
    for k in 0u8..19 {
        for sign in [0x00u8, 0x80] {
            let mut enc = [0xffu8; 32];
            enc[0] = 0xed + k;
            enc[31] = 0x7f | sign;
            if let Ok(point) = ed25519_dalek::VerifyingKey::from_bytes(&enc)
                && !point.is_weak()
            {
                found += 1;
                assert_eq!(
                    DeviceVerifyingKey::from_bytes(&enc).map(|_| ()),
                    Err(ParseError::InvalidValue),
                    "k = {k}"
                );
            }
        }
    }
    assert!(found > 0, "the test found non-canonical encodings to try");
}

#[test]
fn roles_have_their_own_key_types_and_ids() {
    let seed = [0x31; 32];
    let as_identity = IdentitySigningKey::from_seed(&seed);
    let as_device = DeviceSigningKey::from_seed(&seed);
    assert_eq!(
        as_identity.verifying_key().as_bytes(),
        as_device.verifying_key().as_bytes()
    );
    assert_eq!(
        as_identity.key_id(),
        PublicKeyId::derive(
            KeyType::IdentityEd25519,
            as_identity.verifying_key().as_bytes()
        )
    );
    assert_eq!(
        as_device.key_id(),
        PublicKeyId::derive(KeyType::DeviceEd25519, as_device.verifying_key().as_bytes())
    );
    assert_ne!(as_identity.key_id(), as_device.key_id());
    // A device container never verifies under the same key bytes in the identity role.
    let container = as_device.sign_message(b"m").unwrap();
    assert_eq!(
        as_identity
            .verifying_key()
            .verify_container(b"m", &container),
        Err(VerifyError::WrongSigner)
    );
    // Generation uses the injected RNG; Debug never shows the seed.
    let a = IdentitySigningKey::generate(&mut seeded_rng(1));
    let b = IdentitySigningKey::generate(&mut seeded_rng(1));
    assert_eq!(a.verifying_key(), b.verifying_key());
    let text = format!("{a:?}");
    assert!(text.contains("[REDACTED]") && text.contains("Identity"));
    let mut seed = [0u8; 32];
    a.write_seed(&mut seed);
    assert!(!text.contains(&format!("{:02x}{:02x}{:02x}", seed[0], seed[1], seed[2])));
}

#[test]
fn signature_container_layout_and_rejections() {
    let container = device_key().sign_message(b"m").unwrap();
    let bytes = container.to_bytes();
    assert_eq!(bytes.len(), 82);
    assert_eq!(&bytes[..2], &[0x01, 0x01]);
    assert_eq!(&bytes[2..18], device_key().key_id().as_bytes());
    assert_eq!(SignatureContainer::from_bytes(&bytes).unwrap(), container);
    for (index, value) in [
        (0usize, 0x00u8),
        (0, 0x02),
        (1, 0x00),
        (1, SIG_ALG_RESERVED_HYBRID),
    ] {
        let mut bad = bytes;
        bad[index] = value;
        assert_eq!(
            SignatureContainer::from_bytes(&bad),
            Err(VerifyError::UnsupportedVersion),
            "byte {index} = {value:#04x}"
        );
    }
    assert!(matches!(
        SignatureContainer::from_bytes(&bytes[..81]),
        Err(VerifyError::Malformed(_))
    ));
    assert!(matches!(
        SignatureContainer::from_bytes(&[bytes.as_slice(), &[0]].concat()),
        Err(VerifyError::Malformed(_))
    ));
}

#[test]
fn framing_is_label_nul_version_body() {
    let message = signed_message(labels::SIG_OP, b"body");
    assert_eq!(message, b"rizzy-vault/v1/sig/op\x00\x00\x01body".to_vec());
    // A statement signed under one type never verifies as another.
    let revocation = DeviceRevocation {
        account_id: account(),
        device_id: device(),
        last_accepted_device_seq: 5,
        revoked_at_ms: CREATED,
    };
    let body = revocation.encode_body().unwrap();
    let wrong_label = raw_wire(labels::SIG_DEVICE_CERTIFICATE, &body, &identity());
    assert_eq!(
        DeviceRevocation::verify(&wrong_label, identity().verifying_key()).map(|_| ()),
        Err(VerifyError::BadSignature)
    );
    // An unknown statement version is rejected.
    let good = revocation.sign(&identity()).unwrap();
    let mut v2 = good.clone();
    v2[5] = 2;
    assert_eq!(
        DeviceRevocation::verify(&v2, identity().verifying_key()).map(|_| ()),
        Err(VerifyError::UnsupportedVersion)
    );
    // Two containers where one is expected.
    let doubled = [good.as_slice(), &good[good.len() - CONTAINER_LEN..]].concat();
    assert!(DeviceRevocation::verify(&doubled, identity().verifying_key()).is_err());
}

// ---------------------------------------------------------------------------------------------
// device-certificate
// ---------------------------------------------------------------------------------------------

#[test]
fn device_certificate_known_answer_round_trip_and_tamper() {
    let wire = cert().sign(&identity()).unwrap();
    assert_eq!(wire, hex(CERT_WIRE));
    let verified = DeviceCertificate::verify(&wire, identity().verifying_key(), 0).unwrap();
    assert_eq!(verified.statement(), &cert());
    assert!(verified.in_device_set());
    assert_every_bit_is_bound(&wire, |w| {
        DeviceCertificate::verify(w, identity().verifying_key(), 0).is_ok()
    });
    // The identity epoch is the verifier's, and the key must be the identity key.
    assert_eq!(
        DeviceCertificate::verify(&wire, identity().verifying_key(), 1).map(|_| ()),
        Err(VerifyError::Mismatch)
    );
    let other = IdentitySigningKey::from_seed(&[0x67; 32]);
    assert_eq!(
        DeviceCertificate::verify(&wire, other.verifying_key(), 0).map(|_| ()),
        Err(VerifyError::WrongSigner)
    );
}

#[test]
fn device_certificate_kind_4_expiry_rule() {
    let web = DeviceCertificate {
        device_kind: DeviceKind::WebEphemeral,
        expires_at_ms: CREATED + WEB_CERT_MAX_LIFETIME_MS,
        ..cert()
    };
    assert_eq!(WEB_CERT_MAX_LIFETIME_MS, 43_200_000);
    let wire = web.sign(&identity()).unwrap();
    let verified = DeviceCertificate::verify(&wire, identity().verifying_key(), 0).unwrap();
    assert!(!verified.in_device_set());
    // HLC read as milliseconds (top 48 bits) ≤ expires_at_ms.
    let expires = web.expires_at_ms;
    assert!(verified.permits_hlc((expires << 16) | 0xffff));
    assert!(verified.permits_hlc(CREATED << 16));
    assert!(!verified.permits_hlc((expires + 1) << 16));
    // Durable certificate without expiry: any HLC.
    assert!(cert().permits_hlc(u64::MAX));

    let invalid = [
        DeviceCertificate {
            expires_at_ms: 0,
            ..web.clone()
        },
        DeviceCertificate {
            expires_at_ms: CREATED + WEB_CERT_MAX_LIFETIME_MS + 1,
            ..web.clone()
        },
        DeviceCertificate {
            expires_at_ms: CREATED,
            ..web.clone()
        },
        DeviceCertificate {
            created_at_ms: u64::MAX - 1,
            expires_at_ms: u64::MAX,
            ..web.clone()
        },
        // Any certificate that expires before it is created.
        DeviceCertificate {
            expires_at_ms: CREATED - 1,
            ..cert()
        },
    ];
    for bad in invalid {
        assert_eq!(
            bad.sign(&identity()).map(|_| ()),
            Err(SignError::Encode(EncodeError::InvalidField)),
            "{bad:?}"
        );
        // Validly signed by hand, it is still rejected by the reader.
        let mut body = cert().encode_body().unwrap();
        body[100] = bad.device_kind.to_u8();
        body[101..109].copy_from_slice(&bad.created_at_ms.to_be_bytes());
        body[109..117].copy_from_slice(&bad.expires_at_ms.to_be_bytes());
        let wire = raw_wire(labels::SIG_DEVICE_CERTIFICATE, &body, &identity());
        assert_eq!(
            DeviceCertificate::verify(&wire, identity().verifying_key(), 0).map(|_| ()),
            Err(VerifyError::Malformed(ParseError::InvalidValue)),
            "{bad:?}"
        );
    }
    // device_kind outside 1–4.
    for kind in [0u8, 5, 0xff] {
        let mut body = cert().encode_body().unwrap();
        body[100] = kind;
        let wire = raw_wire(labels::SIG_DEVICE_CERTIFICATE, &body, &identity());
        assert!(DeviceCertificate::verify(&wire, identity().verifying_key(), 0).is_err());
    }
    // A weak device key inside a certificate.
    let mut body = cert().encode_body().unwrap();
    body[36..68].copy_from_slice(&{
        let mut p = [0u8; 32];
        p[0] = 1;
        p
    });
    let wire = raw_wire(labels::SIG_DEVICE_CERTIFICATE, &body, &identity());
    assert!(DeviceCertificate::verify(&wire, identity().verifying_key(), 0).is_err());
}

// ---------------------------------------------------------------------------------------------
// device-revocation
// ---------------------------------------------------------------------------------------------

#[test]
fn device_revocation_round_trip_and_tamper() {
    let revocation = DeviceRevocation {
        account_id: account(),
        device_id: device(),
        last_accepted_device_seq: 41,
        revoked_at_ms: CREATED,
    };
    let wire = revocation.sign(&identity()).unwrap();
    let verified = DeviceRevocation::verify(&wire, identity().verifying_key()).unwrap();
    assert_eq!(*verified, revocation);
    assert!(verified.permits_device_seq(41));
    assert!(!verified.permits_device_seq(42));
    assert_every_bit_is_bound(&wire, |w| {
        DeviceRevocation::verify(w, identity().verifying_key()).is_ok()
    });
    // A revocation signed only by a superseded identity key is rejected under the current one.
    let new_identity = IdentitySigningKey::from_seed(&[0x67; 32]);
    assert!(DeviceRevocation::verify(&wire, new_identity.verifying_key()).is_err());
}

// ---------------------------------------------------------------------------------------------
// account-state
// ---------------------------------------------------------------------------------------------

#[test]
fn account_state_known_answer_round_trip_and_tamper() {
    let wire = state().sign(&identity()).unwrap();
    assert_eq!(wire, hex(STATE_WIRE));
    let verified = AccountState::verify(&wire, identity().verifying_key(), 0).unwrap();
    assert_eq!(verified.statement(), &state());
    assert_every_bit_is_bound(&wire, |w| {
        AccountState::verify(w, identity().verifying_key(), 0).is_ok()
    });
    assert_eq!(
        AccountState::verify(&wire, identity().verifying_key(), 1).map(|_| ()),
        Err(VerifyError::Mismatch)
    );
}

#[test]
fn account_state_field_rules() {
    // Offsets in the 168-byte body.
    let good = state().encode_body().unwrap();
    assert_eq!(good.len(), 168);
    let cases: [(&str, usize, &[u8]); 9] = [
        ("state_seq 0", 16, &[0; 8]),
        ("kdf_id 0", 52, &[0, 0]),
        ("kdf_id 2 (reserved)", 52, &[0, 2]),
        ("recovery_enabled 2", 58, &[2]),
        ("recovery enabled with epoch 0", 54, &[0, 0, 0, 0]),
        ("sync_mode 0", 59, &[0]),
        ("sync_mode 3", 59, &[3]),
        (
            "settings_seq 1 with a zero hash",
            128,
            &[0, 0, 0, 0, 0, 0, 0, 1],
        ),
        ("settings_seq 0 with a hash", 136, &[1]),
    ];
    for (name, offset, value) in cases {
        let mut body = good.clone();
        body[offset..offset + value.len()].copy_from_slice(value);
        let wire = raw_wire(labels::SIG_ACCOUNT_STATE, &body, &identity());
        assert_eq!(
            AccountState::verify(&wire, identity().verifying_key(), 0).map(|_| ()),
            Err(VerifyError::Malformed(ParseError::InvalidValue)),
            "{name}"
        );
    }
    // The writer refuses the same states.
    let bad_states = [
        AccountState {
            state_seq: 0,
            ..state()
        },
        AccountState {
            recovery_epoch: 0,
            ..state()
        },
        AccountState {
            settings_seq: 1,
            ..state()
        },
        AccountState {
            settings_hash: [1; 32],
            ..state()
        },
    ];
    for bad in bad_states {
        assert!(bad.sign(&identity()).is_err());
    }
    // Recovery disabled with epoch 0 (the user opted out at signup) and On-device mode are
    // valid.
    let ok = AccountState {
        recovery_enabled: false,
        recovery_epoch: 0,
        sync_mode: SyncMode::OnDevice,
        settings_seq: 3,
        settings_hash: [9; 32],
        ..state()
    };
    let wire = ok.sign(&identity()).unwrap();
    assert_eq!(
        *AccountState::verify(&wire, identity().verifying_key(), 0).unwrap(),
        ok
    );
}

#[test]
fn account_state_compare_and_swap_rules() {
    let base = state();
    // Only state_seq and device_set_hash changed: re-apply.
    let reapply = AccountState {
        state_seq: 2,
        device_set_hash: [7; 32],
        ..state()
    };
    assert_eq!(base.cas_retry(&reapply), CasRetry::Reapply);
    assert_eq!(base.cas_retry(&base), CasRetry::Reapply);
    // Anything else changed: restart.
    let restart: Vec<AccountState> = vec![
        AccountState {
            account_id: AccountId::from_bytes([1; 16]),
            ..reapply.clone()
        },
        AccountState {
            identity_epoch: 1,
            ..reapply.clone()
        },
        AccountState {
            account_key_epoch: 1,
            ..reapply.clone()
        },
        AccountState {
            account_key_id: SymmetricKeyId::from_bytes([1; 16]),
            ..reapply.clone()
        },
        AccountState {
            password_epoch: 1,
            ..reapply.clone()
        },
        AccountState {
            recovery_epoch: 2,
            ..reapply.clone()
        },
        AccountState {
            recovery_enabled: false,
            ..reapply.clone()
        },
        AccountState {
            sync_mode: SyncMode::OnDevice,
            ..reapply.clone()
        },
        AccountState {
            mail_key_epoch: 1,
            ..reapply.clone()
        },
        AccountState {
            bundle_hash: [1; 32],
            ..reapply.clone()
        },
        AccountState {
            settings_seq: 1,
            settings_hash: [1; 32],
            ..reapply.clone()
        },
    ];
    for current in &restart {
        assert_eq!(base.cas_retry(current), CasRetry::Restart, "{current:?}");
    }
    // Same state_seq, other content: a fork of the signed state.
    let fork = AccountState {
        password_epoch: 1,
        ..state()
    };
    assert_eq!(base.cas_retry(&fork), CasRetry::Restart);
    // Older than the base: rollback.
    let newer = AccountState {
        state_seq: 5,
        ..state()
    };
    assert_eq!(newer.cas_retry(&base), CasRetry::Rollback);
    // Persisted-value rollback checks.
    assert!(!base.is_rollback(1, 0));
    assert!(base.is_rollback(2, 0));
    assert!(base.is_rollback(1, 1));
}

// ---------------------------------------------------------------------------------------------
// op and snapshot
// ---------------------------------------------------------------------------------------------

#[test]
fn op_statement_known_answers_and_hashed_form() {
    let env = b"op envelope bytes";
    let wrap = b"item key wrap bytes";
    let with_wrap = OpStatement::new(&op_header(), env, Some(wrap)).unwrap();
    let wire = with_wrap.sign(&sender_key()).unwrap();
    assert_eq!(wire, hex(OP_WIRE));
    let no_wrap = OpStatement::new(&op_header(), env, None).unwrap();
    let wire0 = no_wrap.sign(&sender_key()).unwrap();
    assert_eq!(wire0, hex(OP_WIRE_NOWRAP));

    let verified = OpStatement::verify(&wire, sender_key().verifying_key()).unwrap();
    assert_eq!(verified.header(), op_header().as_slice());
    assert_eq!(
        verified.header_hash(),
        <[u8; 32]>::from(sha2::Sha256::digest(op_header()))
    );
    assert!(verified.matches_envelope(env));
    assert!(!verified.matches_envelope(b"other envelope"));
    assert!(verified.matches_wrap(wrap));
    assert!(!verified.matches_wrap(b"another wrap"));
    let verified0 = OpStatement::verify(&wire0, sender_key().verifying_key()).unwrap();
    assert_eq!(verified0.wrap_hash(), None);
    assert!(!verified0.matches_wrap(wrap));
    assert!(!verified0.matches_wrap(&[]));

    for w in [&wire, &wire0] {
        assert_every_bit_is_bound(w, |w| {
            OpStatement::verify(w, sender_key().verifying_key()).is_ok()
        });
    }
    // Signed by another device: rejected.
    assert_eq!(
        OpStatement::verify(&wire, device_key().verifying_key()).map(|_| ()),
        Err(VerifyError::WrongSigner)
    );
    // An op statement never verifies as a snapshot statement.
    assert!(SnapshotStatement::verify(&wire, sender_key().verifying_key()).is_err());
}

#[test]
fn record_header_bounds() {
    let header = vec![1u8; OP_HEADER_MIN_LEN];
    assert!(OpStatement::new(&header[..OP_HEADER_MIN_LEN - 1], b"e", None).is_err());
    assert!(OpStatement::new(&header, b"e", None).is_ok());
    assert!(OpStatement::new(&vec![1u8; OP_HEADER_MAX_LEN + 1], b"e", None).is_err());
    assert!(OpStatement::new(&vec![1u8; OP_HEADER_MAX_LEN], b"e", None).is_ok());
    let snap = vec![2u8; SNAPSHOT_HEADER_MIN_LEN];
    assert!(SnapshotStatement::new(&snap[..SNAPSHOT_HEADER_MIN_LEN - 1], b"e", None).is_err());
    let statement = SnapshotStatement::new(&snap, b"snapshot envelope", Some(b"w")).unwrap();
    let wire = statement.sign(&device_key()).unwrap();
    let verified = SnapshotStatement::verify(&wire, device_key().verifying_key()).unwrap();
    assert_eq!(*verified, statement);
    assert!(verified.matches_envelope(b"snapshot envelope") && verified.matches_wrap(b"w"));
    assert_every_bit_is_bound(&wire, |w| {
        SnapshotStatement::verify(w, device_key().verifying_key()).is_ok()
    });
    // A too-short header signed by hand is rejected by the reader.
    let mut body = Vec::new();
    crate::encoding::put_bytes(&mut body, &snap[..10]).unwrap();
    body.extend_from_slice(&[3; 64]);
    let short = raw_wire(labels::SIG_SNAPSHOT, &body, &device_key());
    assert!(SnapshotStatement::verify(&short, device_key().verifying_key()).is_err());
}

// ---------------------------------------------------------------------------------------------
// key-grant
// ---------------------------------------------------------------------------------------------

#[test]
fn key_grant_known_answer_round_trip_and_tamper() {
    let envelope = hex(DEVICE_GRANT_ENVELOPE);
    let wire = KeyGrant::sign(Purpose::AccountKeyDeviceGrant, &sender_key(), &envelope).unwrap();
    assert_eq!(wire, hex(KEY_GRANT_WIRE));
    let verified = KeyGrant::verify(&wire, sender_key().verifying_key()).unwrap();
    assert_eq!(verified.purpose(), Purpose::AccountKeyDeviceGrant);
    assert_eq!(verified.sender_key_id(), &sender_key().key_id());
    assert_eq!(verified.recipient_key_id().as_bytes(), &envelope[2..18]);
    assert_eq!(verified.envelope(), envelope.as_slice());
    assert_every_bit_is_bound(&wire, |w| {
        KeyGrant::verify(w, sender_key().verifying_key()).is_ok()
    });
    // Another sender key: rejected. An identity key over the same bytes: rejected too.
    assert_eq!(
        KeyGrant::verify(&wire, device_key().verifying_key()).map(|_| ()),
        Err(VerifyError::WrongSigner)
    );
    let as_identity = IdentitySigningKey::from_seed(&[0x55; 32]);
    assert!(KeyGrant::verify(&wire, as_identity.verifying_key()).is_err());
    // A kind-4 client's grant is signed by the identity key.
    let by_identity =
        KeyGrant::sign(Purpose::AccountKeyDeviceGrant, &identity(), &envelope).unwrap();
    assert!(KeyGrant::verify(&by_identity, identity().verifying_key()).is_ok());
}

#[test]
fn key_grant_structural_rules() {
    let envelope = hex(DEVICE_GRANT_ENVELOPE);
    // Only the signed-grant purposes, with an HPKE envelope of that purpose's mode.
    for purpose in [
        Purpose::ItemOp,
        Purpose::VaultKeyMemberGrant,
        Purpose::MailMessage,
    ] {
        assert!(
            KeyGrant::sign(purpose, &sender_key(), &envelope).is_err(),
            "{}",
            purpose.name()
        );
    }
    let mut base_mode = envelope.clone();
    base_mode[1] = 0x10;
    assert!(KeyGrant::sign(Purpose::AccountKeyDeviceGrant, &sender_key(), &base_mode).is_err());
    let symmetric = [&[0x01u8, 0x01][..], &[0u8; 120]].concat();
    assert!(KeyGrant::sign(Purpose::AccountKeyDeviceGrant, &sender_key(), &symmetric).is_err());

    // Hand-built bodies: recipient id not the envelope's, sender id not the signer's.
    let body = |purpose: u16, sender: &PublicKeyId, recipient: &[u8]| {
        let mut body = purpose.to_be_bytes().to_vec();
        body.extend_from_slice(sender.as_bytes());
        body.extend_from_slice(recipient);
        crate::encoding::put_bytes(&mut body, &envelope).unwrap();
        body
    };
    let wrong_recipient = raw_wire(
        labels::SIG_KEY_GRANT,
        &body(0x0004, &sender_key().key_id(), &[9; 16]),
        &sender_key(),
    );
    assert_eq!(
        KeyGrant::verify(&wrong_recipient, sender_key().verifying_key()).map(|_| ()),
        Err(VerifyError::Malformed(ParseError::InvalidValue))
    );
    let wrong_sender = raw_wire(
        labels::SIG_KEY_GRANT,
        &body(0x0004, &device_key().key_id(), &envelope[2..18]),
        &sender_key(),
    );
    assert_eq!(
        KeyGrant::verify(&wrong_sender, sender_key().verifying_key()).map(|_| ()),
        Err(VerifyError::WrongSigner)
    );
    let unknown_purpose = raw_wire(
        labels::SIG_KEY_GRANT,
        &body(0x0999, &sender_key().key_id(), &envelope[2..18]),
        &sender_key(),
    );
    assert!(KeyGrant::verify(&unknown_purpose, sender_key().verifying_key()).is_err());
}

// ---------------------------------------------------------------------------------------------
// device-auth and device-request
// ---------------------------------------------------------------------------------------------

fn auth() -> DeviceAuth<'static> {
    DeviceAuth {
        server_origin: "https://vault.example",
        account_id: account(),
        device_id: device(),
        challenge: [0xcc; 32],
    }
}

fn request() -> DeviceRequest<'static> {
    DeviceRequest {
        server_origin: "https://vault.example",
        account_id: account(),
        device_id: device(),
        session_id: SessionId::from_bytes([0x5e; 16]),
        request_counter: 7,
        method: "POST",
        path_and_query: "/api/v1/ops?vault=1",
        body_hash: DeviceRequest::body_hash(b"{\"ops\":[]}"),
    }
}

#[test]
fn device_auth_known_answer_and_bindings() {
    let container = auth().sign(&device_key()).unwrap();
    assert_eq!(
        container.to_bytes().as_slice(),
        hex(DEVICE_AUTH_CONTAINER).as_slice()
    );
    let bytes = container.to_bytes();
    let pk = *device_key().verifying_key();
    auth().verify(&bytes, &pk).unwrap();
    // The origin binding: a signature for server A does not verify at server B.
    let at_b = DeviceAuth {
        server_origin: "https://evil.example",
        ..auth()
    };
    assert_eq!(at_b.verify(&bytes, &pk), Err(VerifyError::BadSignature));
    let others = [
        DeviceAuth {
            account_id: AccountId::from_bytes([1; 16]),
            ..auth()
        },
        DeviceAuth {
            device_id: DeviceId::from_bytes([1; 16]),
            ..auth()
        },
        DeviceAuth {
            challenge: [0xcd; 32],
            ..auth()
        },
    ];
    for other in others {
        assert!(other.verify(&bytes, &pk).is_err(), "{other:?}");
    }
    assert_every_bit_is_bound(&bytes, |c| auth().verify(c, &pk).is_ok());
    assert!(
        DeviceAuth {
            server_origin: "",
            ..auth()
        }
        .sign(&device_key())
        .is_err()
    );
}

#[test]
fn device_request_known_answer_and_bindings() {
    let container = request().sign(&device_key()).unwrap();
    assert_eq!(
        container.to_bytes().as_slice(),
        hex(DEVICE_REQUEST_CONTAINER).as_slice()
    );
    let bytes = container.to_bytes();
    let pk = *device_key().verifying_key();
    request().verify(&bytes, &pk).unwrap();
    let others = [
        DeviceRequest {
            server_origin: "https://vault.example:8443",
            ..request()
        },
        DeviceRequest {
            session_id: SessionId::from_bytes([1; 16]),
            ..request()
        },
        DeviceRequest {
            request_counter: 8,
            ..request()
        },
        DeviceRequest {
            method: "GET",
            ..request()
        },
        DeviceRequest {
            path_and_query: "/api/v1/ops?vault=2",
            ..request()
        },
        DeviceRequest {
            body_hash: DeviceRequest::body_hash(b"{}"),
            ..request()
        },
        // Moving bytes between the length-prefixed fields changes the message.
        DeviceRequest {
            method: "POST/api",
            path_and_query: "/v1/ops?vault=1",
            ..request()
        },
    ];
    for other in others {
        assert!(other.verify(&bytes, &pk).is_err(), "{other:?}");
    }
    assert_every_bit_is_bound(&bytes, |c| request().verify(c, &pk).is_ok());
}

// ---------------------------------------------------------------------------------------------
// public-key-bundle and the chain (§10.2, §10.3)
// ---------------------------------------------------------------------------------------------

fn successor(
    prev: &VerifiedBundle,
    identity_epoch: u32,
    identity: &IdentitySigningKey,
    identity_x25519: HpkePublicKey,
    mail: Option<HpkePublicKey>,
) -> PublicKeyBundle {
    PublicKeyBundle {
        account_id: prev.account_id,
        identity_epoch,
        bundle_seq: prev.bundle_seq + 1,
        identity_ed25519: *identity.verifying_key(),
        identity_x25519,
        mail_x25519: mail,
        pq_required: false,
        created_at_ms: prev.created_at_ms + 1,
        prev_bundle_hash: *prev.hash(),
    }
}

fn pinned_first() -> VerifiedBundle {
    PublicKeyBundle::verify_self_signed(&first_bundle().sign(&identity()).unwrap()).unwrap()
}

#[test]
fn first_bundle_known_answer_round_trip_and_tamper() {
    let wire = first_bundle().sign(&identity()).unwrap();
    assert_eq!(wire, hex(BUNDLE_WIRE));
    let verified = PublicKeyBundle::verify_self_signed(&wire).unwrap();
    assert_eq!(verified.bundle(), &first_bundle());
    assert_eq!(verified.hash().as_slice(), hex(BUNDLE_HASH).as_slice());
    assert!(!verified.has_predecessor_signature());
    assert_eq!(
        verified.identity_public_keys(),
        IdentityPublicKeys {
            ed25519: *identity().verifying_key(),
            x25519: x25519(0x77),
        }
    );
    assert_every_bit_is_bound(&wire, |w| PublicKeyBundle::verify_self_signed(w).is_ok());
    // Only the identity key inside the bundle may self-sign it.
    let other = IdentitySigningKey::from_seed(&[0x67; 32]);
    assert_eq!(first_bundle().sign(&other), Err(SignError::WrongKey));
    // The state commits to it.
    assert!(state().matches_bundle(&verified));
    assert!(
        !AccountState {
            identity_epoch: 1,
            ..state()
        }
        .matches_bundle(&verified)
    );
}

#[test]
fn bundle_structural_rules() {
    // Body offsets with two keys: n at 28, first entry type at 29 (len 30..34, key 34..66),
    // second entry type at 66 (len 67..71, key 71..103), flags 103, created 104..112,
    // prev 112..144.
    let good = first_bundle().encode_body().unwrap();
    assert_eq!(good.len(), 144);
    let check = |body: &[u8], name: &str| {
        let wire = raw_wire(labels::SIG_PUBLIC_KEY_BUNDLE, body, &identity());
        assert!(
            matches!(
                PublicKeyBundle::verify_self_signed(&wire),
                Err(VerifyError::Malformed(_))
            ),
            "{name}"
        );
    };
    let mut body = good.clone();
    body[29] = 0x02;
    body[66] = 0x01;
    check(&body, "unsorted entries");
    let mut body = good.clone();
    body[66] = 0x01;
    check(&body, "duplicate key type");
    let mut body = good.clone();
    body[66] = 0x05;
    check(&body, "device key type in a bundle");
    let mut body = good.clone();
    body[66] = 0x10;
    check(&body, "reserved PQ key type");
    let mut body = good.clone();
    body[28] = 1;
    check(&body, "one entry only (and trailing bytes)");
    let mut body = good.clone();
    body[103] = 0x02;
    check(&body, "reserved flag bit");
    let mut body = good.clone();
    body[70] = 31;
    check(&body, "31-byte key");
    let mut body = good.clone();
    body[20..28].copy_from_slice(&0u64.to_be_bytes());
    check(&body, "bundle_seq 0");
    let mut body = good.clone();
    body[143] = 1;
    check(&body, "first bundle with a predecessor hash");
    let mut body = good.clone();
    body[20..28].copy_from_slice(&2u64.to_be_bytes());
    check(&body, "later bundle without a predecessor hash");
    let mut body = good.clone();
    body[16..20].copy_from_slice(&1u32.to_be_bytes());
    check(&body, "first bundle with identity_epoch 1");
    // A missing identity X25519 key: n = 1 and the second entry removed.
    let mut body = good[..66].to_vec();
    body[28] = 1;
    body.extend_from_slice(&good[103..]);
    check(&body, "missing identity X25519 key");

    // The writer refuses the same values.
    for bad in [
        PublicKeyBundle {
            bundle_seq: 0,
            ..first_bundle()
        },
        PublicKeyBundle {
            prev_bundle_hash: [1; 32],
            ..first_bundle()
        },
        PublicKeyBundle {
            identity_epoch: 1,
            ..first_bundle()
        },
    ] {
        assert!(bad.sign(&identity()).is_err(), "{bad:?}");
    }
    // pq_required round-trips.
    let pq = PublicKeyBundle {
        pq_required: true,
        ..first_bundle()
    };
    let verified = PublicKeyBundle::verify_self_signed(&pq.sign(&identity()).unwrap()).unwrap();
    assert!(verified.pq_required);
    assert_eq!(FLAG_PQ_REQUIRED, 1);
}

#[test]
fn a_silent_successor_keeps_both_identity_keys() {
    let pinned = pinned_first();
    let next = successor(&pinned, 0, &identity(), x25519(0x77), Some(x25519(0x44)));
    let wire = next.sign(&identity()).unwrap();
    let (verified, step) = pinned.verify_successor(&wire).unwrap();
    assert_eq!(step, BundleStep::Silent);
    assert_eq!(verified.mail_x25519, Some(x25519(0x44)));
    // The same bundle again is unchanged.
    assert_eq!(
        verified.verify_successor(&wire).unwrap().1,
        BundleStep::Unchanged
    );
    // Keeping the keys under a new identity_epoch is inconsistent.
    let bumped = successor(&pinned, 1, &identity(), x25519(0x77), None);
    assert_eq!(
        pinned
            .verify_successor(&bumped.sign(&identity()).unwrap())
            .map(|_| ()),
        Err(BundleChainError::IdentityEpochMismatch)
    );
    // A second signature on a bundle that keeps its keys is rejected.
    let old = IdentitySigningKey::from_seed(&[0x68; 32]);
    let doubled = next
        .sign_identity_change(&identity(), &old)
        .unwrap_or_default();
    assert!(doubled.is_empty(), "sign_identity_change refuses epoch 0");
    let body = next.encode_body().unwrap();
    let message = signed_message(labels::SIG_PUBLIC_KEY_BUNDLE, &body);
    let first = identity().sign_message(&message).unwrap();
    let second = old.sign_message(&message).unwrap();
    let doubled = encode_wire(&body, &[first, second]).unwrap();
    assert!(pinned.verify_successor(&doubled).is_err());
}

#[test]
fn an_identity_change_needs_both_signatures() {
    let pinned = pinned_first();
    let new_identity = IdentitySigningKey::from_seed(&[0x67; 32]);
    let next = successor(&pinned, 1, &new_identity, x25519(0x78), None);

    // Both signatures, the new key's first: accepted, and reported as an identity change.
    let wire = next
        .sign_identity_change(&new_identity, &identity())
        .unwrap();
    let standalone = PublicKeyBundle::verify_self_signed(&wire).unwrap();
    assert!(standalone.has_predecessor_signature());
    let (verified, step) = pinned.verify_successor(&wire).unwrap();
    assert_eq!(step, BundleStep::IdentityChanged);
    assert_eq!(verified.identity_ed25519, *new_identity.verifying_key());
    assert_every_bit_is_bound(&wire, |w| pinned.verify_successor(w).is_ok());

    // Only the self-signature: rejected.
    let only_self = next.sign(&new_identity).unwrap();
    assert_eq!(
        pinned.verify_successor(&only_self).map(|_| ()),
        Err(BundleChainError::IdentityChangeNotSigned)
    );
    // The second signature by some other key (an attacker's): rejected.
    let attacker = IdentitySigningKey::from_seed(&[0x69; 32]);
    let by_attacker = next.sign_identity_change(&new_identity, &attacker).unwrap();
    assert_eq!(
        pinned.verify_successor(&by_attacker).map(|_| ()),
        Err(BundleChainError::IdentityChangeNotSigned)
    );
    // The containers in the wrong order: the first is not the self-signature.
    let (body_part, containers) = wire.split_at(wire.len() - 2 * CONTAINER_LEN);
    let swapped = [
        body_part,
        &containers[CONTAINER_LEN..],
        &containers[..CONTAINER_LEN],
    ]
    .concat();
    assert_eq!(
        pinned.verify_successor(&swapped).map(|_| ()),
        Err(BundleChainError::Invalid(VerifyError::WrongSigner))
    );
    // Changing only the X25519 key is an identity change too.
    let x_only = successor(&pinned, 0, &identity(), x25519(0x79), None);
    assert_eq!(
        pinned
            .verify_successor(&x_only.sign(&identity()).unwrap())
            .map(|_| ()),
        Err(BundleChainError::IdentityEpochMismatch)
    );
    // New keys without identity_epoch + 1.
    let skipped = successor(&pinned, 2, &new_identity, x25519(0x78), None);
    assert_eq!(
        pinned
            .verify_successor(
                &skipped
                    .sign_identity_change(&new_identity, &identity())
                    .unwrap()
            )
            .map(|_| ()),
        Err(BundleChainError::IdentityEpochMismatch)
    );
    // The writer refuses a "change" to the same key, or signing with a key not in the bundle.
    assert_eq!(
        next.sign_identity_change(&new_identity, &new_identity),
        Err(SignError::WrongKey)
    );
    assert_eq!(
        next.sign_identity_change(&identity(), &new_identity),
        Err(SignError::WrongKey)
    );
}

#[test]
fn rollback_fork_gap_and_account_mismatch() {
    let pinned = pinned_first();
    let b2 = successor(&pinned, 0, &identity(), x25519(0x77), Some(x25519(0x44)));
    let b2_wire = b2.sign(&identity()).unwrap();
    let (v2, _) = pinned.verify_successor(&b2_wire).unwrap();

    // Rollback: the older bundle offered after the newer one is pinned.
    let b1_wire = first_bundle().sign(&identity()).unwrap();
    assert_eq!(
        v2.verify_successor(&b1_wire).map(|_| ()),
        Err(BundleChainError::Rollback)
    );
    // Fork: another bundle with the same bundle_seq.
    let b2_other = PublicKeyBundle {
        mail_x25519: Some(x25519(0x45)),
        ..b2.clone()
    };
    assert_eq!(
        v2.verify_successor(&b2_other.sign(&identity()).unwrap())
            .map(|_| ()),
        Err(BundleChainError::Fork)
    );
    // Fork: the next position, but naming another predecessor.
    let b3_forked = PublicKeyBundle {
        bundle_seq: 3,
        prev_bundle_hash: [0x5a; 32],
        ..b2.clone()
    };
    assert_eq!(
        v2.verify_successor(&b3_forked.sign(&identity()).unwrap())
            .map(|_| ()),
        Err(BundleChainError::Fork)
    );
    // Gap: skipping a position.
    let b4 = PublicKeyBundle {
        bundle_seq: 4,
        ..b3_forked.clone()
    };
    assert_eq!(
        v2.verify_successor(&b4.sign(&identity()).unwrap())
            .map(|_| ()),
        Err(BundleChainError::Gap)
    );
    // Another account.
    let other_account = PublicKeyBundle {
        account_id: AccountId::from_bytes([0x0b; 16]),
        ..b2.clone()
    };
    assert_eq!(
        pinned
            .verify_successor(&other_account.sign(&identity()).unwrap())
            .map(|_| ()),
        Err(BundleChainError::AccountMismatch)
    );
}

#[test]
fn a_chain_is_walked_in_order() {
    let pinned = pinned_first();
    let b2 = successor(&pinned, 0, &identity(), x25519(0x77), Some(x25519(0x44)));
    let b2_wire = b2.sign(&identity()).unwrap();
    let (v2, _) = pinned.verify_successor(&b2_wire).unwrap();
    let new_identity = IdentitySigningKey::from_seed(&[0x67; 32]);
    let b3 = successor(&v2, 1, &new_identity, x25519(0x78), Some(x25519(0x44)));
    let b3_wire = b3.sign_identity_change(&new_identity, &identity()).unwrap();
    let (v3, _) = v2.verify_successor(&b3_wire).unwrap();
    let b4 = successor(&v3, 1, &new_identity, x25519(0x78), None);
    let b4_wire = b4.sign(&new_identity).unwrap();

    let (last, changed) = pinned
        .verify_chain(&[&b2_wire, &b3_wire, &b4_wire])
        .unwrap();
    assert!(changed);
    assert_eq!(last.bundle_seq, 4);
    assert_eq!(last.identity_ed25519, *new_identity.verifying_key());
    let (_, changed) = pinned.verify_chain(&[&b2_wire]).unwrap();
    assert!(!changed);
    // Out of order: a gap at the first step.
    assert_eq!(
        pinned.verify_chain(&[&b3_wire, &b2_wire]).map(|_| ()),
        Err(BundleChainError::Gap)
    );
    // After the change, the old identity key signs nothing that verifies: a bundle that keeps
    // the new keys but is self-signed with the old key is rejected.
    let forged = successor(&v3, 1, &identity(), x25519(0x78), None);
    assert!(
        v3.verify_successor(&forged.sign(&identity()).unwrap())
            .is_err()
    );
}

proptest::proptest! {
    #[test]
    fn statement_parsers_never_panic(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..400)) {
        let id = *identity().verifying_key();
        let dev = *device_key().verifying_key();
        let _ = PublicKeyBundle::verify_self_signed(&bytes);
        let _ = DeviceCertificate::verify(&bytes, &id, 0);
        let _ = DeviceRevocation::verify(&bytes, &id);
        let _ = AccountState::verify(&bytes, &id, 0);
        let _ = OpStatement::verify(&bytes, &dev);
        let _ = SnapshotStatement::verify(&bytes, &dev);
        let _ = KeyGrant::verify(&bytes, &dev);
        let _ = SignatureContainer::from_bytes(&bytes);
        let _ = auth().verify(&bytes, &dev);
        let _ = pinned_first().verify_successor(&bytes);
    }
}
