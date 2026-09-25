//! HPKE tests: RFC 7748 and RFC 9180 vectors through this module's code, independent known
//! answers for the device grant, round trips in both modes, mode separation, and the negative
//! tests of CRYPTO.md §15 item 4 for HPKE purposes.
//!
//! The known answers marked "independent" were computed with a separate Python implementation
//! written from CRYPTO.md and RFC 9180 (Python `cryptography` 50.0.1 for X25519 and
//! ChaCha20-Poly1305, `hmac`/`hashlib` for HKDF, the RFC 9180 key schedule by hand). That
//! implementation first reproduced the RFC 9180 A.2.1 and A.2.2 vectors.

use super::*;
use crate::envelope::purpose::{AccountKeyDeviceGrantCtx, VaultKeyMemberGrantCtx};
use crate::envelope::{Context, Purpose};
use crate::ids::{AccountId, DeviceId, VaultId};
use crate::test_util::{FixedRng, hex, seeded_rng};

fn arr32(text: &str) -> [u8; 32] {
    hex(text).try_into().unwrap()
}

fn account() -> AccountId {
    AccountId::from_bytes([0x0a; 16])
}

fn grant_ctx() -> AccountKeyDeviceGrantCtx {
    AccountKeyDeviceGrantCtx {
        account_id: account(),
        account_key_epoch: 1,
        sender_device_id: DeviceId::from_bytes([0x0d; 16]),
        recipient_device_id: DeviceId::from_bytes([0x0e; 16]),
    }
}

fn member_ctx() -> VaultKeyMemberGrantCtx {
    VaultKeyMemberGrantCtx {
        vault_id: VaultId::from_bytes([0x0f; 16]),
        vault_key_epoch: 3,
        granter_account_id: account(),
        grantee_account_id: AccountId::from_bytes([0x0b; 16]),
    }
}

fn recipient() -> HpkeSecretKey {
    HpkeSecretKey::from_x25519_bytes(&[0x33; 32]).unwrap()
}

fn previous_key() -> AccountKey {
    AccountKey::from_key(Key32::from_slice(&[0x11; 32]).unwrap(), 0)
}

fn psk() -> HpkePsk {
    HpkePsk::device_grant(&previous_key(), &grant_ctx()).unwrap()
}

fn sealed_grant() -> Vec<u8> {
    seal_psk(
        &mut seeded_rng(1),
        recipient().public_key(),
        &psk(),
        &grant_ctx(),
        &[0x22; 32],
    )
    .unwrap()
}

/// Counts HPKE openings during `f`.
fn hpke_opens_during<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let before = test_hooks::hpke_opens();
    let out = f();
    (out, test_hooks::hpke_opens() - before)
}

/// Builds an envelope by hand with any algorithm byte and mode, bypassing the typed API.
fn raw_envelope<C: Context>(
    alg: AlgId,
    key_type: KeyType,
    recipient: &HpkePublicKey,
    psk: Option<(&[u8], &[u8])>,
    ctx: &C,
    plaintext: &[u8],
) -> Vec<u8> {
    let header = header(alg, &recipient.key_id(key_type));
    let aad = build_aad(&header, ctx);
    let mut body = plaintext.to_vec();
    let (enc, tag) = raw_seal_in_place(
        &mut seeded_rng(9),
        recipient,
        psk,
        &info(C::PURPOSE),
        &aad,
        &mut body,
    )
    .unwrap();
    [header.as_slice(), &enc, &body, &tag].concat()
}

// ---------------------------------------------------------------------------------------------
// Upstream vectors (CRYPTO.md §15 item 2)
// ---------------------------------------------------------------------------------------------

/// RFC 7748 §6.1: the public keys through [`HpkeSecretKey`], and the shared secret through
/// this module's open path.
#[test]
fn rfc7748_section_6_1_through_the_wrapper() {
    let alice = HpkeSecretKey::from_x25519_bytes(&arr32(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    ))
    .unwrap();
    let bob = HpkeSecretKey::from_x25519_bytes(&arr32(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    ))
    .unwrap();
    assert_eq!(
        alice.public_key().as_bytes(),
        &arr32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    );
    assert_eq!(
        bob.public_key().as_bytes(),
        &arr32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    );
    // An HPKE Base envelope whose ephemeral key is Alice's key, sealed to Bob by the
    // independent implementation (which checked K = 4a5d9d5b…161742 first). Bob's key opens it
    // here only if X25519(b, A) is RFC 7748's K.
    let ct = hex("7482ac52719920f7e83ecf5e6bbd7796ccfd30716f8c0e212b335ba00cadbf09d66c4659");
    let (body, tag) = ct.split_at(ct.len() - 16);
    let mut body = body.to_vec();
    raw_open_in_place(
        &bob,
        None,
        alice.public_key().as_bytes(),
        b"rfc7748",
        b"aad",
        &mut body,
        tag.try_into().unwrap(),
    )
    .unwrap();
    assert_eq!(body, b"RFC 7748 section 6.1");
}

/// One RFC 9180 test vector for our suite (KEM 0x20, KDF 1, AEAD 3), sequence number 0.
struct Rfc9180Vector {
    ikm_r: &'static str,
    ikm_e: &'static str,
    sk_rm: &'static str,
    pk_rm: &'static str,
    enc: &'static str,
    psk: &'static str,
    psk_id: &'static str,
    ct: &'static str,
}

const RFC9180_INFO: &str = "4f6465206f6e2061204772656369616e2055726e";
const RFC9180_AAD: &str = "436f756e742d30";
const RFC9180_PT: &str = "4265617574792069732074727574682c20747275746820626561757479";

/// RFC 9180 A.2.1 (Base) and A.2.2 (PSK): DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
/// `ChaCha20Poly1305`. Taken from the CFRG `test-vectors.json` of draft-irtf-cfrg-hpke.
const RFC9180_VECTORS: [Rfc9180Vector; 2] = [
    Rfc9180Vector {
        ikm_r: "1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df",
        ikm_e: "909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b",
        sk_rm: "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
        pk_rm: "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",
        enc: "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
        psk: "",
        psk_id: "",
        ct: "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28",
    },
    Rfc9180Vector {
        ikm_r: "26b923eade72941c8a85b09986cdfa3f1296852261adedc52d58d2930269812b",
        ikm_e: "35706a0b09fb26fb45c39c2f5079c709c7cf98e43afa973f14d88ece7e29c2e3",
        sk_rm: "77d114e0212be51cb1d76fa99dd41cfd4d0166b08caa09074430a6c59ef17879",
        pk_rm: "13640af826b722fc04feaa4de2f28fbd5ecc03623b317834e7ff4120dbe73062",
        enc: "2261299c3f40a9afc133b969a97f05e95be2c514e54f3de26cbe5644ac735b04",
        psk: "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82",
        psk_id: "456e6e796e20447572696e206172616e204d6f726961",
        ct: "4a177f9c0d6f15cfdf533fb65bf84aecdc6ab16b8b85b4cf65a370e07fc1d78d28fb073214525276f4a89608ff",
    },
];

#[test]
fn rfc9180_vectors_through_the_envelope_code() {
    for v in RFC9180_VECTORS {
        // Key generation is RFC 9180 DeriveKeyPair over the injected bytes.
        let generated = HpkeSecretKey::generate_x25519(&mut FixedRng::new(&hex(v.ikm_r)));
        assert_eq!(generated.public_key().as_bytes(), &arr32(v.pk_rm));
        let mut sk = [0u8; 32];
        generated.write_secret(&mut sk);
        assert_eq!(sk, arr32(v.sk_rm));

        let (psk, psk_id) = (hex(v.psk), hex(v.psk_id));
        let parts = (!psk.is_empty()).then_some((psk.as_slice(), psk_id.as_slice()));
        let mut body = hex(RFC9180_PT);
        let (enc, tag) = raw_seal_in_place(
            &mut FixedRng::new(&hex(v.ikm_e)),
            generated.public_key(),
            parts,
            &hex(RFC9180_INFO),
            &hex(RFC9180_AAD),
            &mut body,
        )
        .unwrap();
        assert_eq!(enc, arr32(v.enc));
        assert_eq!([body.as_slice(), &tag].concat(), hex(v.ct));

        let recipient = HpkeSecretKey::from_x25519_bytes(&arr32(v.sk_rm)).unwrap();
        raw_open_in_place(
            &recipient,
            parts,
            &enc,
            &hex(RFC9180_INFO),
            &hex(RFC9180_AAD),
            &mut body,
            &tag,
        )
        .unwrap();
        assert_eq!(body, hex(RFC9180_PT));
    }
}

// ---------------------------------------------------------------------------------------------
// Known answers for our envelope (CRYPTO.md §15 item 1, inline until the vector files land)
// ---------------------------------------------------------------------------------------------

const DEVICE_GRANT_PSK: &str = "3a4534c8df763b1f1d70d8410b0be7bd5175f5eafb7bbcdd2a00af8e3094d611";
/// Independent: `ACCOUNT_KEY_DEVICE_GRANT` for account 0x0a…, epoch 1, sender 0x0d…,
/// recipient 0x0e… (X25519 secret 0x33…), previous key 0x11…, new key 0x22…, ephemeral IKM
/// 0x44….
pub(crate) const DEVICE_GRANT_ENVELOPE: &str = "0112cfc73380bda7467f0b0fa7b309c67b7686e76b8dd088dabf46d94d4820a251861376de69c3a36f2e53f8bffcdb519e008af61a94cfae79e703dad5b2b8bd10f7ec486c68920bdee3ef0a4f2c6fffdecb5ae7f9f8b8318632e6fa830e56af4a72";

#[test]
fn device_grant_psk_known_answer() {
    let psk = psk();
    assert_eq!(psk.purpose(), Purpose::AccountKeyDeviceGrant);
    assert_eq!(psk.secret().expose_secret(), &arr32(DEVICE_GRANT_PSK));
    assert_eq!(
        psk_id_label(Purpose::AccountKeyDeviceGrant)
            .unwrap()
            .as_bytes(),
        b"rizzy-vault/v1/hpke-psk/device-grant"
    );
    // The PSK comes from the key of the epoch just before the grant's.
    let wrong_epoch = AccountKey::from_key(Key32::from_slice(&[0x11; 32]).unwrap(), 1);
    assert_eq!(
        HpkePsk::device_grant(&wrong_epoch, &grant_ctx()).map(|_| ()),
        Err(EncryptError::ContextMismatch)
    );
}

#[test]
fn device_grant_envelope_known_answer() {
    let envelope = seal_psk(
        &mut FixedRng::new(&[0x44; 32]),
        recipient().public_key(),
        &psk(),
        &grant_ctx(),
        &[0x22; 32],
    )
    .unwrap();
    assert_eq!(envelope, hex(DEVICE_GRANT_ENVELOPE));
    let opened = open_psk(&recipient(), &psk(), &grant_ctx(), &envelope).unwrap();
    assert_eq!(opened.expose_secret(), &[0x22; 32]);
}

/// §9.2 names `single_shot_seal_with_rng` and `single_shot_open`; this module uses their
/// in-place forms. Both directions give the same bytes.
#[test]
fn in_place_calls_match_the_calls_named_in_crypto_md() {
    let ours = seal_psk(
        &mut FixedRng::new(&[0x44; 32]),
        recipient().public_key(),
        &psk(),
        &grant_ctx(),
        &[0x22; 32],
    )
    .unwrap();

    let psk = psk();
    let (psk_bytes, psk_id) = psk.parts().unwrap();
    let bundle = PskBundle::new(psk_bytes, psk_id).unwrap();
    let pk_r = X25519PublicKey::from_bytes(recipient().public_key().as_bytes()).unwrap();
    let header = &ours[..HEADER_LEN];
    let aad = build_aad(header.try_into().unwrap(), &grant_ctx());
    let info = info(Purpose::AccountKeyDeviceGrant);
    let (enc, ct) =
        hpke::single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeS::Psk(bundle),
            &pk_r,
            &info,
            &[0x22; 32],
            &aad,
            &mut FixedRng::new(&[0x44; 32]),
        )
        .unwrap();
    assert_eq!([header, enc.to_bytes().as_slice(), &ct].concat(), ours);

    let SecretInner::X25519(sk_r) = &recipient().secret;
    let encapped = X25519EncappedKey::from_bytes(&ours[HEADER_LEN..HEADER_LEN + ENC_LEN]).unwrap();
    let pt = hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Psk(bundle),
        sk_r,
        &encapped,
        &info,
        &ours[HEADER_LEN + ENC_LEN..],
        &aad,
    )
    .unwrap();
    assert_eq!(pt, [0x22; 32]);
}

// ---------------------------------------------------------------------------------------------
// Layout and round trips
// ---------------------------------------------------------------------------------------------

#[test]
fn psk_mode_layout_is_crypto_md_9_2() {
    let envelope = sealed_grant();
    assert_eq!(envelope.len(), HPKE_OVERHEAD + 32);
    assert_eq!(HPKE_OVERHEAD, 66);
    assert_eq!(&envelope[..2], &[0x01, 0x12]);
    // The header names the recipient device's X25519 key, with key type 0x05.
    let id = PublicKeyId::derive(KeyType::DeviceX25519, recipient().public_key().as_bytes());
    assert_eq!(&envelope[2..18], id.as_bytes());
    let parsed = parse::parse(&envelope).unwrap();
    assert!(matches!(parsed, EnvelopeRef::Hpke(e) if e.alg_id() == AlgId::HpkePskX25519));
    assert_eq!(parsed.to_vec(), envelope);
}

#[test]
fn psk_mode_round_trips_and_is_randomised() {
    let a = sealed_grant();
    let b = seal_psk(
        &mut seeded_rng(2),
        recipient().public_key(),
        &psk(),
        &grant_ctx(),
        &[0x22; 32],
    )
    .unwrap();
    assert_ne!(a, b, "a fresh ephemeral key per envelope");
    for envelope in [a, b] {
        let pt = open_psk(&recipient(), &psk(), &grant_ctx(), &envelope).unwrap();
        assert_eq!(pt.expose_secret(), &[0x22; 32]);
    }
}

#[test]
fn base_mode_round_trips_with_the_purpose_recipient_type() {
    let grantee = HpkeSecretKey::generate_x25519(&mut seeded_rng(3));
    let envelope = seal_base(
        &mut seeded_rng(4),
        grantee.public_key(),
        &member_ctx(),
        &[0x5c; 32],
    )
    .unwrap();
    assert_eq!(&envelope[..2], &[0x01, 0x10]);
    // VAULT_KEY_MEMBER_GRANT goes to the grantee's identity X25519 key (0x02).
    let id = grantee.public_key().key_id(KeyType::IdentityX25519);
    assert_eq!(&envelope[2..18], id.as_bytes());
    let pt = open_base(&grantee, &member_ctx(), &envelope).unwrap();
    assert_eq!(pt.expose_secret(), &[0x5c; 32]);
}

#[test]
fn generated_keys_come_from_the_injected_rng() {
    let a = HpkeSecretKey::generate_x25519(&mut seeded_rng(5));
    let b = HpkeSecretKey::generate_x25519(&mut seeded_rng(5));
    let c = HpkeSecretKey::generate_x25519(&mut seeded_rng(6));
    assert_eq!(a.public_key(), b.public_key());
    assert_ne!(a.public_key(), c.public_key());
    assert_eq!(a.kem(), Kem::X25519HkdfSha256);
    assert_eq!(Kem::X25519HkdfSha256.id(), 0x0020);
    // The secret round-trips through its 32 bytes.
    let mut bytes = [0u8; 32];
    a.write_secret(&mut bytes);
    let again = HpkeSecretKey::from_x25519_bytes(&bytes).unwrap();
    assert_eq!(again.public_key(), a.public_key());
    let text = format!("{a:?} {:?}", psk());
    assert!(text.contains("[REDACTED]"));
    assert!(!text.contains(&format!("{:02x}{:02x}", bytes[0], bytes[1])));
}

// ---------------------------------------------------------------------------------------------
// Mode separation (§9.5 rule 2)
// ---------------------------------------------------------------------------------------------

// Compile-time: the device-grant context is a PSK context and not a Base context, and the
// member-grant context the reverse, so `seal_base`/`open_base` cannot take a PSK purpose.
trait DoesNotImpl {
    const IMPLS: bool = false;
}
impl<T: ?Sized> DoesNotImpl for T {}
struct ProbeBase<T: ?Sized>(core::marker::PhantomData<T>);
impl<T: HpkeBaseContext> ProbeBase<T> {
    const IMPLS: bool = true;
}
struct ProbePsk<T: ?Sized>(core::marker::PhantomData<T>);
impl<T: HpkePskContext> ProbePsk<T> {
    const IMPLS: bool = true;
}
const _: () = {
    assert!(<ProbePsk<AccountKeyDeviceGrantCtx>>::IMPLS);
    assert!(!<ProbeBase<AccountKeyDeviceGrantCtx>>::IMPLS);
    assert!(<ProbeBase<VaultKeyMemberGrantCtx>>::IMPLS);
    assert!(!<ProbePsk<VaultKeyMemberGrantCtx>>::IMPLS);
};

#[test]
fn a_psk_purpose_never_accepts_base_mode() {
    let rcpt = recipient();
    // A well-formed Base-mode envelope for the device-grant purpose, made by hand.
    let base = raw_envelope(
        AlgId::HpkeBaseX25519,
        KeyType::DeviceX25519,
        rcpt.public_key(),
        None,
        &grant_ctx(),
        &[0x22; 32],
    );
    let (result, opens) = hpke_opens_during(|| open_psk(&rcpt, &psk(), &grant_ctx(), &base));
    assert_eq!(result.map(|_| ()), Err(DecryptError));
    assert_eq!(opens, 0, "rejected by the allow-list before any crypto");

    // A PSK envelope relabelled as Base mode: rejected before any crypto as well.
    let mut relabelled = sealed_grant();
    relabelled[1] = AlgId::HpkeBaseX25519.to_u8();
    let (result, opens) = hpke_opens_during(|| open_psk(&rcpt, &psk(), &grant_ctx(), &relabelled));
    assert_eq!(result.map(|_| ()), Err(DecryptError));
    assert_eq!(opens, 0);
}

#[test]
fn a_base_purpose_never_accepts_psk_mode() {
    let grantee = HpkeSecretKey::generate_x25519(&mut seeded_rng(3));
    let psk_envelope = raw_envelope(
        AlgId::HpkePskX25519,
        KeyType::IdentityX25519,
        grantee.public_key(),
        Some((&[7u8; 32], b"some psk id")),
        &member_ctx(),
        &[0x5c; 32],
    );
    let (result, opens) = hpke_opens_during(|| open_base(&grantee, &member_ctx(), &psk_envelope));
    assert_eq!(result.map(|_| ()), Err(DecryptError));
    assert_eq!(opens, 0);

    let mut relabelled = seal_base(
        &mut seeded_rng(4),
        grantee.public_key(),
        &member_ctx(),
        &[1; 32],
    )
    .unwrap();
    relabelled[1] = AlgId::HpkePskX25519.to_u8();
    let (result, opens) = hpke_opens_during(|| open_base(&grantee, &member_ctx(), &relabelled));
    assert_eq!(result.map(|_| ()), Err(DecryptError));
    assert_eq!(opens, 0);
}

#[test]
fn symmetric_and_reserved_algorithms_are_rejected_before_crypto() {
    let rcpt = recipient();
    for alg in [0x01u8, 0x02, 0x03, 0x11, 0x13, 0x00, 0xff] {
        let mut envelope = sealed_grant();
        envelope[1] = alg;
        let (result, opens) =
            hpke_opens_during(|| open_psk(&rcpt, &psk(), &grant_ctx(), &envelope));
        assert_eq!(result.map(|_| ()), Err(DecryptError), "alg {alg:#04x}");
        assert_eq!(opens, 0);
    }
}

#[test]
fn registry_psk_labels_and_recipient_types_follow_the_modes() {
    for purpose in Purpose::ALL {
        let family = purpose.encrypt_alg().family();
        assert_eq!(
            psk_id_label(purpose).is_some(),
            family == crate::envelope::AlgFamily::HpkePsk,
            "{}",
            purpose.name()
        );
        assert_eq!(
            purpose.hpke_recipient_key_type().is_some(),
            suite(purpose.encrypt_alg()).is_some(),
            "{}",
            purpose.name()
        );
        // Every algorithm on an HPKE purpose's allow-list has the purpose's mode.
        if let Some((_, mode)) = suite(purpose.encrypt_alg()) {
            for alg in purpose.client_decrypt_allow_list() {
                assert_eq!(
                    suite(*alg).map(|(_, m)| m),
                    Some(mode),
                    "{}",
                    purpose.name()
                );
            }
        }
    }
    // The four PSK labels are distinct.
    let labels: std::collections::HashSet<_> = Purpose::ALL
        .into_iter()
        .filter_map(psk_id_label)
        .map(Label::as_str)
        .collect();
    assert_eq!(labels.len(), 4);
}

// ---------------------------------------------------------------------------------------------
// Negative tests (§9.5, §15 item 4)
// ---------------------------------------------------------------------------------------------

#[test]
fn another_recipient_key_fails_at_the_key_id_before_crypto() {
    let envelope = sealed_grant();
    let other = HpkeSecretKey::generate_x25519(&mut seeded_rng(7));
    let (result, opens) = hpke_opens_during(|| open_psk(&other, &psk(), &grant_ctx(), &envelope));
    assert_eq!(result.map(|_| ()), Err(DecryptError));
    assert_eq!(opens, 0);
}

#[test]
fn a_wrong_psk_or_context_field_fails() {
    let envelope = sealed_grant();
    let rcpt = recipient();
    // A PSK from another previous account key.
    let other_prev = AccountKey::from_key(Key32::from_slice(&[0x12; 32]).unwrap(), 0);
    let wrong_psk = HpkePsk::device_grant(&other_prev, &grant_ctx()).unwrap();
    assert!(open_psk(&rcpt, &wrong_psk, &grant_ctx(), &envelope).is_err());
    // Every context field is bound (through the AAD, and for the PSK fields also the PSK).
    let mut contexts = Vec::new();
    let base = grant_ctx();
    contexts.push(AccountKeyDeviceGrantCtx {
        account_id: AccountId::from_bytes([0x0b; 16]),
        ..base
    });
    contexts.push(AccountKeyDeviceGrantCtx {
        account_key_epoch: 2,
        ..base
    });
    contexts.push(AccountKeyDeviceGrantCtx {
        sender_device_id: DeviceId::from_bytes([0x0c; 16]),
        ..base
    });
    contexts.push(AccountKeyDeviceGrantCtx {
        recipient_device_id: DeviceId::from_bytes([0x0c; 16]),
        ..base
    });
    for ctx in contexts {
        // The PSK the reader derives for that context; the epoch case needs the key before it.
        let prev = AccountKey::from_key(
            Key32::from_slice(&[0x11; 32]).unwrap(),
            ctx.account_key_epoch - 1,
        );
        let reader_psk = HpkePsk::device_grant(&prev, &ctx).unwrap();
        assert!(
            open_psk(&rcpt, &reader_psk, &ctx, &envelope).is_err(),
            "{ctx:?}"
        );
        // Also with the sealer's PSK: the AAD alone rejects it.
        assert!(open_psk(&rcpt, &psk(), &ctx, &envelope).is_err(), "{ctx:?}");
    }
}

#[test]
fn every_single_bit_flip_is_rejected() {
    let envelope = sealed_grant();
    let rcpt = recipient();
    for i in 0..envelope.len() * 8 {
        let mut bad = envelope.clone();
        bad[i / 8] ^= 1 << (i % 8);
        assert!(
            open_psk(&rcpt, &psk(), &grant_ctx(), &bad).is_err(),
            "bit {i}"
        );
    }
}

#[test]
fn truncation_and_extension_never_panic() {
    let envelope = sealed_grant();
    let rcpt = recipient();
    for n in 0..envelope.len() {
        let (result, opens) =
            hpke_opens_during(|| open_psk(&rcpt, &psk(), &grant_ctx(), &envelope[..n]));
        assert!(result.is_err(), "prefix {n}");
        assert_eq!(
            opens, 0,
            "a fixed-size purpose checks its exact length first"
        );
    }
    let mut longer = envelope.clone();
    longer.push(0);
    let (result, opens) = hpke_opens_during(|| open_psk(&rcpt, &psk(), &grant_ctx(), &longer));
    assert!(result.is_err());
    assert_eq!(opens, 0);
}

#[test]
fn seal_enforces_the_purpose_plaintext_size_and_the_psk_purpose() {
    let pk = *recipient().public_key();
    for len in [0usize, 31, 33, 64] {
        assert_eq!(
            seal_psk(&mut seeded_rng(1), &pk, &psk(), &grant_ctx(), &vec![0; len]).map(|_| ()),
            Err(EncryptError::InvalidPlaintextLength),
            "{len}"
        );
    }
    // A small-order recipient key gives the all-zero shared secret and is refused.
    assert_eq!(
        seal_psk(
            &mut seeded_rng(1),
            &HpkePublicKey::x25519([0; 32]),
            &psk(),
            &grant_ctx(),
            &[0; 32]
        )
        .map(|_| ()),
        Err(EncryptError::InvalidPublicKey)
    );
}

#[test]
fn a_purpose_mismatch_between_psk_and_context_is_refused() {
    // Only the device-grant PSK exists in M1; forge one with another purpose to show the check.
    let forged = HpkePsk {
        purpose: Purpose::PasswordVerifierGrant,
        psk: Key32::from_slice(psk().secret().expose_secret()).unwrap(),
    };
    assert_eq!(
        seal_psk(
            &mut seeded_rng(1),
            recipient().public_key(),
            &forged,
            &grant_ctx(),
            &[0; 32]
        )
        .map(|_| ()),
        Err(EncryptError::ContextMismatch)
    );
    let (result, opens) =
        hpke_opens_during(|| open_psk(&recipient(), &forged, &grant_ctx(), &sealed_grant()));
    assert_eq!(result.map(|_| ()), Err(DecryptError));
    assert_eq!(opens, 0);
}

proptest::proptest! {
    #[test]
    fn open_never_panics_on_arbitrary_input(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..200)) {
        let _ = open_psk(&recipient(), &psk(), &grant_ctx(), &bytes);
        let _ = open_base(&recipient(), &member_ctx(), &bytes);
    }
}
