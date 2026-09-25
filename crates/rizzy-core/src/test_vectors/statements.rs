//! `statements.json`: every signed statement of CRYPTO.md §10.2 and the §9.3 container.
//!
//! The vectors tell one account's story, so the statements refer to each other: signup (the
//! first bundle, certificates, the first `account-state`), a standard rotation after a
//! revocation, a full rotation (a two-signature bundle, re-issued certificates and revocation,
//! a state signed by the new identity key), then a silent bundle update and a settings change.
//! The rotation states keep `settings_seq = 0` (§11.6 step 3, §15 item 1).
//!
//! The `op` and `snapshot` vectors sign opaque header bytes of a valid length: the canonical
//! op and snapshot headers are ADR 0012 §3's, and `rizzy-sync` does not encode them yet.

use chacha20::ChaCha20Rng;
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};

use super::{Obj, Vector, arr, boolean, bytes, num, opt_bytes, random, random_vec, text, u64_of};
use crate::encoding::{put_str, put_u64};
use crate::envelope::Purpose;
use crate::envelope::purpose::AccountKeyDeviceGrantCtx;
use crate::hpke::{self, HpkePsk, HpkePublicKey, HpkeSecretKey};
use crate::ids::{AccountId, DeviceId, PublicKeyId, SessionId, SymmetricKeyId};
use crate::kdf::KdfId;
use crate::keys::{AccountKey, device_set_hash};
use crate::labels::{self, Label};
use crate::secret::Key32;
use crate::sign::{
    AccountState, DeviceAuth, DeviceCertificate, DeviceKind, DeviceRequest, DeviceRevocation,
    DeviceSigningKey, IdentitySigningKey, KeyGrant, OpStatement, PublicKeyBundle,
    SignatureContainer, SnapshotStatement, SyncMode, Verified, signed_message, split_wire,
};

const KIND: &str = "statement";

fn vector(name: &str, index: usize, inputs: Obj) -> Vector {
    Vector::build(compute, KIND, name, index, inputs)
}

const T0: u64 = 1_780_000_000_000;
const HOUR: u64 = 3_600_000;

/// A device of the story: its seeds and certificate fields.
struct Device {
    id: [u8; 16],
    seed: [u8; 32],
    x25519_secret: [u8; 32],
    kind: DeviceKind,
    created: u64,
    expires: u64,
}

impl Device {
    fn new(rng: &mut ChaCha20Rng, kind: DeviceKind, created: u64, expires: u64) -> Self {
        Self {
            id: random(rng),
            seed: random(rng),
            x25519_secret: super::envelopes::x25519_secret(rng),
            kind,
            created,
            expires,
        }
    }

    fn signing(&self) -> DeviceSigningKey {
        DeviceSigningKey::from_seed(&self.seed)
    }

    fn x25519_public(&self) -> [u8; 32] {
        *HpkeSecretKey::from_x25519_bytes(&self.x25519_secret)
            .expect("a key")
            .public_key()
            .as_bytes()
    }

    fn certificate(&self, account: &[u8; 16], identity_seed: &[u8; 32], epoch: u32) -> Obj {
        Obj::new()
            .bytes("signer_seed", identity_seed)
            .bytes("account_id", account)
            .bytes("device_id", &self.id)
            .num("identity_epoch", epoch)
            .bytes(
                "device_ed25519_public_key",
                self.signing().verifying_key().as_bytes(),
            )
            .bytes("device_x25519_public_key", &self.x25519_public())
            .num("device_kind", u32::from(self.kind.to_u8()))
            .u64("created_at_ms", self.created)
            .u64("expires_at_ms", self.expires)
    }
}

/// `{key, key_id}` of a random account key: only the id goes into a state.
fn account_key_id(rng: &mut ChaCha20Rng) -> [u8; 16] {
    let key = Key32::generate(rng);
    *key.key_id().expect("key id").as_bytes()
}

fn identity_x25519(rng: &mut ChaCha20Rng) -> [u8; 32] {
    *HpkeSecretKey::generate_x25519(rng).public_key().as_bytes()
}

/// The device-set hash of the certificates (wire form) under `identity_seed`.
fn set_hash(
    account: &[u8; 16],
    identity_seed: &[u8; 32],
    epoch: u32,
    certs: &[&Vector],
    revocations: &[&Vector],
) -> [u8; 32] {
    let vk = *IdentitySigningKey::from_seed(identity_seed).verifying_key();
    let certs: Vec<Verified<DeviceCertificate>> = certs
        .iter()
        .map(|v| DeviceCertificate::verify(&bytes(&v.outputs, "wire"), &vk, epoch).expect("cert"))
        .collect();
    let revocations: Vec<Verified<DeviceRevocation>> = revocations
        .iter()
        .map(|v| DeviceRevocation::verify(&bytes(&v.outputs, "wire"), &vk).expect("revocation"))
        .collect();
    device_set_hash(AccountId::from_bytes(*account), &certs, &revocations).expect("a set")
}

#[expect(
    clippy::too_many_lines,
    reason = "one linear story; splitting it would scatter the cross-references"
)]
pub(super) fn generate(rng: &mut ChaCha20Rng) -> Vec<Vector> {
    let account: [u8; 16] = random(rng);
    let id0: [u8; 32] = random(rng);
    let id1: [u8; 32] = random(rng);
    let (x0, x1) = (identity_x25519(rng), identity_x25519(rng));
    let desktop = Device::new(rng, DeviceKind::DesktopCli, T0, 0);
    let web = Device::new(rng, DeviceKind::WebEphemeral, T0 + HOUR, T0 + 13 * HOUR);
    let extension = Device::new(rng, DeviceKind::Extension, T0 + 2 * HOUR, 0);
    let mobile = Device::new(rng, DeviceKind::Mobile, T0 + 3 * HOUR, 0);

    // Signup.
    let bundle1 = vector(
        "public-key-bundle",
        0,
        Obj::new()
            .bytes("signer_seed", &id0)
            .null("previous_signer_seed")
            .bytes("account_id", &account)
            .num("identity_epoch", 0)
            .u64("bundle_seq", 1)
            .bytes("identity_x25519_public_key", &x0)
            .null("mail_x25519_public_key")
            .bool("pq_required", false)
            .u64("created_at_ms", T0)
            .bytes("prev_bundle_hash", &[0; 32]),
    );
    let cert_desktop = vector(
        "device-certificate",
        0,
        desktop.certificate(&account, &id0, 0),
    );
    let cert_web = vector("device-certificate", 1, web.certificate(&account, &id0, 0));
    let cert_extension = vector(
        "device-certificate",
        2,
        extension.certificate(&account, &id0, 0),
    );
    let cert_mobile = vector(
        "device-certificate",
        3,
        mobile.certificate(&account, &id0, 0),
    );
    let state = |seq: u64,
                 signer: &[u8; 32],
                 identity_epoch: u32,
                 account_key_epoch: u32,
                 key_id: &[u8; 16],
                 recovery_epoch: u32,
                 bundle_hash: &[u8],
                 device_set: &[u8; 32],
                 settings: (u64, [u8; 32])| {
        Obj::new()
            .bytes("signer_seed", signer)
            .bytes("account_id", &account)
            .u64("state_seq", seq)
            .num("identity_epoch", identity_epoch)
            .num("account_key_epoch", account_key_epoch)
            .bytes("account_key_id", key_id)
            .num("password_epoch", 0)
            .num("kdf_id", 1)
            .num("recovery_epoch", recovery_epoch)
            .bool("recovery_enabled", true)
            .num("sync_mode", 1)
            .num("mail_key_epoch", 0)
            .bytes("bundle_hash", bundle_hash)
            .bytes("device_set_hash", device_set)
            .u64("settings_seq", settings.0)
            .bytes("settings_hash", &settings.1)
    };
    let h1 = bytes(&bundle1.outputs, "bundle_hash");
    let signup_set = set_hash(&account, &id0, 0, &[&cert_desktop, &cert_web], &[]);
    let state_signup = vector(
        "account-state",
        0,
        state(
            1,
            &id0,
            0,
            0,
            &account_key_id(rng),
            1,
            &h1,
            &signup_set,
            (0, [0; 32]),
        ),
    );

    // Standard rotation after revoking the extension: new account key, new recovery code,
    // same identity key.
    let revocation = vector(
        "device-revocation",
        0,
        Obj::new()
            .bytes("signer_seed", &id0)
            .bytes("account_id", &account)
            .bytes("device_id", &extension.id)
            .u64("last_accepted_device_seq", 118)
            .u64("revoked_at_ms", T0 + 30 * HOUR),
    );
    let rotated_set = set_hash(
        &account,
        &id0,
        0,
        &[&cert_desktop, &cert_extension, &cert_mobile, &cert_web],
        &[&revocation],
    );
    let state_standard = vector(
        "account-state",
        1,
        state(
            5,
            &id0,
            0,
            1,
            &account_key_id(rng),
            2,
            &h1,
            &rotated_set,
            (0, [0; 32]),
        ),
    );

    // Full rotation: a bundle signed by both identity keys, re-issued certificates and
    // revocation, a state signed by the new key.
    let bundle2 = vector(
        "public-key-bundle",
        1,
        Obj::new()
            .bytes("signer_seed", &id1)
            .bytes("previous_signer_seed", &id0)
            .bytes("account_id", &account)
            .num("identity_epoch", 1)
            .u64("bundle_seq", 2)
            .bytes("identity_x25519_public_key", &x1)
            .null("mail_x25519_public_key")
            .bool("pq_required", false)
            .u64("created_at_ms", T0 + 40 * HOUR)
            .bytes("prev_bundle_hash", &h1),
    );
    let h2 = bytes(&bundle2.outputs, "bundle_hash");
    let cert_desktop1 = vector(
        "device-certificate",
        4,
        desktop.certificate(&account, &id1, 1),
    );
    let cert_mobile1 = vector(
        "device-certificate",
        5,
        mobile.certificate(&account, &id1, 1),
    );
    let revocation1 = vector(
        "device-revocation",
        1,
        Obj::new()
            .bytes("signer_seed", &id1)
            .bytes("account_id", &account)
            .bytes("device_id", &extension.id)
            .u64("last_accepted_device_seq", 118)
            .u64("revoked_at_ms", T0 + 30 * HOUR),
    );
    let full_set = set_hash(
        &account,
        &id1,
        1,
        &[&cert_desktop1, &cert_mobile1],
        &[&revocation1],
    );
    let state_full = vector(
        "account-state",
        2,
        state(
            6,
            &id1,
            1,
            2,
            &account_key_id(rng),
            3,
            &h2,
            &full_set,
            (0, [0; 32]),
        ),
    );

    // A silent bundle update (same identity keys, pq_required set), then settings.
    let bundle3 = vector(
        "public-key-bundle",
        2,
        Obj::new()
            .bytes("signer_seed", &id1)
            .null("previous_signer_seed")
            .bytes("account_id", &account)
            .num("identity_epoch", 1)
            .u64("bundle_seq", 3)
            .bytes("identity_x25519_public_key", &x1)
            .null("mail_x25519_public_key")
            .bool("pq_required", true)
            .u64("created_at_ms", T0 + 50 * HOUR)
            .bytes("prev_bundle_hash", &h2),
    );
    let h3 = bytes(&bundle3.outputs, "bundle_hash");
    let settings_envelope = random_vec(rng, 160);
    let settings_hash: [u8; 32] = Sha256::digest(&settings_envelope).into();
    let key_id = account_key_id(rng);
    let state_settings = vector(
        "account-state",
        3,
        state(
            7,
            &id1,
            1,
            2,
            &key_id,
            3,
            &h3,
            &full_set,
            (1, settings_hash),
        ),
    );

    // Records and grants by the desktop device.
    let dev_seed = desktop.seed;
    let record = |header_len: usize, wrap: bool, rng: &mut ChaCha20Rng| {
        let obj = Obj::new()
            .bytes("signer_seed", &dev_seed)
            .bytes("canonical_header", &random_vec(rng, header_len))
            .bytes("envelope", &random_vec(rng, 90 + 256));
        if wrap {
            obj.bytes("item_key_wrap", &random_vec(rng, 90 + 37))
        } else {
            obj.null("item_key_wrap")
        }
    };
    let op_wrap = vector("op", 0, record(97 + 2 * 24, true, rng));
    let op_plain = vector("op", 1, record(97, false, rng));
    let snapshot = vector("snapshot", 0, record(73 + 24, true, rng));

    let grant_envelope = |rng: &mut ChaCha20Rng, sender: &[u8; 16], recipient: &Device| {
        let ctx = AccountKeyDeviceGrantCtx {
            account_id: AccountId::from_bytes(account),
            account_key_epoch: 1,
            sender_device_id: DeviceId::from_bytes(*sender),
            recipient_device_id: DeviceId::from_bytes(recipient.id),
        };
        let previous = AccountKey::generate(rng, 0);
        let psk = HpkePsk::device_grant(&previous, &ctx).expect("psk");
        let pk = HpkePublicKey::x25519(recipient.x25519_public());
        let new_account_key = random::<32>(rng);
        hpke::seal_psk(rng, &pk, &psk, &ctx, &new_account_key).expect("seal")
    };
    let env = grant_envelope(rng, &desktop.id, &mobile);
    let grant_device = vector(
        "key-grant",
        0,
        Obj::new()
            .bytes("signer_seed", &dev_seed)
            .text("signer_role", "device")
            .num("purpose", u32::from(Purpose::AccountKeyDeviceGrant.id()))
            .bytes("envelope", &env),
    );
    let env = grant_envelope(rng, &web.id, &mobile);
    let grant_web = vector(
        "key-grant",
        1,
        Obj::new()
            .bytes("signer_seed", &id0)
            .text("signer_role", "identity")
            .num("purpose", u32::from(Purpose::AccountKeyDeviceGrant.id()))
            .bytes("envelope", &env),
    );

    let auth = vector(
        "device-auth",
        0,
        Obj::new()
            .bytes("signer_seed", &dev_seed)
            .text("server_origin", "https://vault.example.com")
            .bytes("account_id", &account)
            .bytes("device_id", &desktop.id)
            .bytes("challenge", &random::<32>(rng)),
    );
    let request = vector(
        "device-request",
        0,
        Obj::new()
            .bytes("signer_seed", &dev_seed)
            .text("server_origin", "https://vault.example.com")
            .bytes("account_id", &account)
            .bytes("device_id", &desktop.id)
            .bytes("session_id", &random::<16>(rng))
            .u64("request_counter", 42)
            .text("method", "POST")
            .text("path_and_query", "/api/v1/vaults/sync?cursor=17")
            .bytes("request_body", br#"{"ops":[]}"#),
    );

    vec![
        bundle1,
        bundle2,
        bundle3,
        cert_desktop,
        cert_web,
        cert_extension,
        cert_mobile,
        cert_desktop1,
        cert_mobile1,
        revocation,
        revocation1,
        state_signup,
        state_standard,
        state_full,
        state_settings,
        op_wrap,
        op_plain,
        snapshot,
        grant_device,
        grant_web,
        auth,
        request,
    ]
}

/// The bundles form a chain (first → identity change → silent update), and every state names
/// one of them.
pub(super) fn check_file(vectors: &[Vector]) {
    let wires: Vec<Vec<u8>> = vectors
        .iter()
        .filter(|v| v.name == "public-key-bundle")
        .map(|v| bytes(&v.outputs, "wire"))
        .collect();
    let (first, rest) = wires.split_first().expect("bundles");
    let pinned = PublicKeyBundle::verify_self_signed(first).expect("first bundle");
    let rest: Vec<&[u8]> = rest.iter().map(Vec::as_slice).collect();
    let (last, identity_changed) = pinned.verify_chain(&rest).expect("a valid chain");
    assert!(identity_changed);
    assert_eq!(last.bundle().bundle_seq, 3);
    let hashes: Vec<Vec<u8>> = vectors
        .iter()
        .filter(|v| v.name == "public-key-bundle")
        .map(|v| bytes(&v.outputs, "bundle_hash"))
        .collect();
    for v in vectors.iter().filter(|v| v.name == "account-state") {
        assert!(
            hashes.contains(&bytes(&v.inputs, "bundle_hash")),
            "{}",
            v.id
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------------------------

/// The outputs of a single-signer statement: the parts of its §9.6 wire form, and the signed
/// message rebuilt from the §10.2 framing.
fn single_outputs(
    label: Label,
    wire: &[u8],
    signer_public_key: &[u8; 32],
    signer_key_id: PublicKeyId,
    message_hash: &[u8; 32],
) -> Obj {
    let (body, containers) = split_wire(wire, usize::MAX).expect("a wire statement");
    let message = signed_message(label, body);
    // LABEL("sig/<type>") ‖ 0x00 ‖ u16(1) ‖ body, from the text.
    let mut framed = label.as_bytes().to_vec();
    framed.extend_from_slice(&[0x00, 0x00, 0x01]);
    framed.extend_from_slice(body);
    assert_eq!(message, framed);
    assert_eq!(<[u8; 32]>::from(Sha256::digest(&message)), *message_hash);
    let container = SignatureContainer::from_bytes(containers).expect("one container");
    assert_eq!(*container.signer_key_id(), signer_key_id);
    Obj::new()
        .bytes("signer_public_key", signer_public_key)
        .bytes("signer_key_id", signer_key_id.as_bytes())
        .bytes("body", body)
        .bytes("signed_message", &message)
        .bytes("message_hash", message_hash)
        .bytes("container", containers)
        .bytes("wire", wire)
}

fn seed(m: &Map<String, Value>) -> [u8; 32] {
    arr(m, "signer_seed")
}

fn account(m: &Map<String, Value>) -> AccountId {
    AccountId::from_bytes(arr(m, "account_id"))
}

#[expect(
    clippy::too_many_lines,
    reason = "one match arm per statement type, each short"
)]
#[expect(
    clippy::single_match_else,
    reason = "the two arms build different signature layouts; a match reads clearer"
)]
pub(super) fn compute(name: &str, m: &Map<String, Value>) -> Map<String, Value> {
    match name {
        "public-key-bundle" => {
            let key = IdentitySigningKey::from_seed(&seed(m));
            let bundle = PublicKeyBundle {
                account_id: account(m),
                identity_epoch: num(m, "identity_epoch"),
                bundle_seq: u64_of(m, "bundle_seq"),
                identity_ed25519: *key.verifying_key(),
                identity_x25519: HpkePublicKey::x25519(arr(m, "identity_x25519_public_key")),
                mail_x25519: opt_bytes(m, "mail_x25519_public_key")
                    .map(|k| HpkePublicKey::x25519(k.try_into().expect("32 bytes"))),
                pq_required: boolean(m, "pq_required"),
                created_at_ms: u64_of(m, "created_at_ms"),
                prev_bundle_hash: arr(m, "prev_bundle_hash"),
            };
            let previous = opt_bytes(m, "previous_signer_seed")
                .map(|s| IdentitySigningKey::from_seed(&s.try_into().expect("a 32-byte seed")));
            let wire = match &previous {
                None => bundle.sign(&key),
                Some(prev) => bundle.sign_identity_change(&key, prev),
            }
            .expect("sign");
            let verified = PublicKeyBundle::verify_self_signed(&wire).expect("verify");
            assert_eq!(*verified.bundle(), bundle);
            assert_eq!(verified.has_predecessor_signature(), previous.is_some());
            let (body, containers) = split_wire(&wire, usize::MAX).expect("wire");
            let message = signed_message(labels::SIG_PUBLIC_KEY_BUNDLE, body);
            assert_eq!(<[u8; 32]>::from(Sha256::digest(&message)), *verified.hash());
            // Two containers for an identity change, the new key's first (§9.6).
            let first = SignatureContainer::from_bytes(containers.get(..82).expect("one"))
                .expect("container");
            assert_eq!(*first.signer_key_id(), key.key_id());
            let mut out = Obj::new()
                .bytes(
                    "identity_ed25519_public_key",
                    key.verifying_key().as_bytes(),
                )
                .bytes("signer_key_id", key.key_id().as_bytes());
            out = match &previous {
                Some(prev) => {
                    let second = SignatureContainer::from_bytes(containers.get(82..).expect("two"))
                        .expect("container");
                    assert_eq!(*second.signer_key_id(), prev.key_id());
                    out.bytes("previous_signer_key_id", prev.key_id().as_bytes())
                }
                None => {
                    assert_eq!(containers.len(), 82);
                    out.null("previous_signer_key_id")
                }
            };
            out.bytes("body", body)
                .bytes("signed_message", &message)
                .bytes("bundle_hash", verified.hash())
                .bytes("containers", containers)
                .bytes("wire", &wire)
                .done()
        }
        "device-certificate" => {
            let key = IdentitySigningKey::from_seed(&seed(m));
            let cert = DeviceCertificate {
                account_id: account(m),
                device_id: DeviceId::from_bytes(arr(m, "device_id")),
                identity_epoch: num(m, "identity_epoch"),
                device_ed25519: crate::sign::DeviceVerifyingKey::from_bytes(&arr(
                    m,
                    "device_ed25519_public_key",
                ))
                .expect("an Ed25519 key"),
                device_x25519: HpkePublicKey::x25519(arr(m, "device_x25519_public_key")),
                device_kind: DeviceKind::from_u8(num(m, "device_kind")).expect("a kind"),
                created_at_ms: u64_of(m, "created_at_ms"),
                expires_at_ms: u64_of(m, "expires_at_ms"),
            };
            let wire = cert.sign(&key).expect("sign");
            let verified =
                DeviceCertificate::verify(&wire, key.verifying_key(), cert.identity_epoch)
                    .expect("verify");
            assert_eq!(*verified, cert);
            single_outputs(
                labels::SIG_DEVICE_CERTIFICATE,
                &wire,
                key.verifying_key().as_bytes(),
                key.key_id(),
                verified.message_hash(),
            )
            .done()
        }
        "device-revocation" => {
            let key = IdentitySigningKey::from_seed(&seed(m));
            let revocation = DeviceRevocation {
                account_id: account(m),
                device_id: DeviceId::from_bytes(arr(m, "device_id")),
                last_accepted_device_seq: u64_of(m, "last_accepted_device_seq"),
                revoked_at_ms: u64_of(m, "revoked_at_ms"),
            };
            let wire = revocation.sign(&key).expect("sign");
            let verified = DeviceRevocation::verify(&wire, key.verifying_key()).expect("verify");
            assert_eq!(*verified, revocation);
            single_outputs(
                labels::SIG_DEVICE_REVOCATION,
                &wire,
                key.verifying_key().as_bytes(),
                key.key_id(),
                verified.message_hash(),
            )
            .done()
        }
        "account-state" => {
            let key = IdentitySigningKey::from_seed(&seed(m));
            let state = AccountState {
                account_id: account(m),
                state_seq: u64_of(m, "state_seq"),
                identity_epoch: num(m, "identity_epoch"),
                account_key_epoch: num(m, "account_key_epoch"),
                account_key_id: SymmetricKeyId::from_bytes(arr(m, "account_key_id")),
                password_epoch: num(m, "password_epoch"),
                kdf_id: KdfId::from_u16(num(m, "kdf_id")).expect("an allowed kdf_id"),
                recovery_epoch: num(m, "recovery_epoch"),
                recovery_enabled: boolean(m, "recovery_enabled"),
                sync_mode: SyncMode::from_u8(num(m, "sync_mode")).expect("a sync mode"),
                mail_key_epoch: num(m, "mail_key_epoch"),
                bundle_hash: arr(m, "bundle_hash"),
                device_set_hash: arr(m, "device_set_hash"),
                settings_seq: u64_of(m, "settings_seq"),
                settings_hash: arr(m, "settings_hash"),
            };
            let wire = state.sign(&key).expect("sign");
            let verified = AccountState::verify(&wire, key.verifying_key(), state.identity_epoch)
                .expect("verify");
            assert_eq!(*verified, state);
            single_outputs(
                labels::SIG_ACCOUNT_STATE,
                &wire,
                key.verifying_key().as_bytes(),
                key.key_id(),
                verified.message_hash(),
            )
            .done()
        }
        "op" | "snapshot" => record(name, m),
        "key-grant" => {
            let envelope = bytes(m, "envelope");
            let purpose = Purpose::from_id(num(m, "purpose")).expect("a purpose");
            let (wire, pk, id, hash) = match text(m, "signer_role") {
                "device" => {
                    let key = DeviceSigningKey::from_seed(&seed(m));
                    let wire = KeyGrant::sign(purpose, &key, &envelope).expect("sign");
                    let v = KeyGrant::verify(&wire, key.verifying_key()).expect("verify");
                    assert_eq!(v.envelope(), envelope);
                    (
                        wire,
                        *key.verifying_key().as_bytes(),
                        key.key_id(),
                        *v.message_hash(),
                    )
                }
                "identity" => {
                    let key = IdentitySigningKey::from_seed(&seed(m));
                    let wire = KeyGrant::sign(purpose, &key, &envelope).expect("sign");
                    let v = KeyGrant::verify(&wire, key.verifying_key()).expect("verify");
                    assert_eq!(v.envelope(), envelope);
                    (
                        wire,
                        *key.verifying_key().as_bytes(),
                        key.key_id(),
                        *v.message_hash(),
                    )
                }
                other => panic!("signer_role {other}"),
            };
            // §10.1: u16(purpose) ‖ sender key id ‖ recipient key id ‖ bytes(hpke_envelope),
            // the recipient key id being the envelope header's.
            let mut body = purpose.id().to_be_bytes().to_vec();
            body.extend_from_slice(id.as_bytes());
            body.extend_from_slice(envelope.get(2..18).expect("a header"));
            crate::encoding::put_bytes(&mut body, &envelope).expect("encode");
            let out = single_outputs(labels::SIG_KEY_GRANT, &wire, &pk, id, &hash);
            assert_eq!(bytes(&out.0, "body"), body);
            out.done()
        }
        "device-auth" => {
            let key = DeviceSigningKey::from_seed(&seed(m));
            let auth = DeviceAuth {
                server_origin: text(m, "server_origin"),
                account_id: account(m),
                device_id: DeviceId::from_bytes(arr(m, "device_id")),
                challenge: arr(m, "challenge"),
            };
            let container = auth.sign(&key).expect("sign").to_bytes();
            auth.verify(&container, key.verifying_key())
                .expect("verify");
            // §5.10: str(server_origin) ‖ account_id ‖ device_id ‖ challenge.
            let mut body = Vec::new();
            put_str(&mut body, auth.server_origin).expect("encode");
            body.extend_from_slice(auth.account_id.as_bytes());
            body.extend_from_slice(auth.device_id.as_bytes());
            body.extend_from_slice(&auth.challenge);
            detached_outputs(labels::SIG_DEVICE_AUTH, &body, &key, &container)
        }
        "device-request" => {
            let key = DeviceSigningKey::from_seed(&seed(m));
            let body_hash = DeviceRequest::body_hash(&bytes(m, "request_body"));
            let request = DeviceRequest {
                server_origin: text(m, "server_origin"),
                account_id: account(m),
                device_id: DeviceId::from_bytes(arr(m, "device_id")),
                session_id: SessionId::from_bytes(arr(m, "session_id")),
                request_counter: u64_of(m, "request_counter"),
                method: text(m, "method"),
                path_and_query: text(m, "path_and_query"),
                body_hash,
            };
            let container = request.sign(&key).expect("sign").to_bytes();
            request
                .verify(&container, key.verifying_key())
                .expect("verify");
            // §10.2: str(server_origin) ‖ account_id ‖ device_id ‖ session_id ‖
            // u64 request_counter ‖ str(method) ‖ str(path_and_query) ‖ SHA-256(body).
            let mut body = Vec::new();
            put_str(&mut body, request.server_origin).expect("encode");
            body.extend_from_slice(request.account_id.as_bytes());
            body.extend_from_slice(request.device_id.as_bytes());
            body.extend_from_slice(request.session_id.as_bytes());
            put_u64(&mut body, request.request_counter);
            put_str(&mut body, request.method).expect("encode");
            put_str(&mut body, request.path_and_query).expect("encode");
            body.extend_from_slice(&body_hash);
            let mut out = detached_outputs(labels::SIG_DEVICE_REQUEST, &body, &key, &container);
            out.extend(Obj::new().bytes("request_body_hash", &body_hash).done());
            out
        }
        other => panic!("unknown statement vector {other}"),
    }
}

/// `op` and `snapshot`: the hashed record statements.
fn record(name: &str, m: &Map<String, Value>) -> Map<String, Value> {
    let key = DeviceSigningKey::from_seed(&seed(m));
    let header = bytes(m, "canonical_header");
    let envelope = bytes(m, "envelope");
    let wrap = opt_bytes(m, "item_key_wrap");
    let (wire, hash, label) = if name == "op" {
        let st = OpStatement::new(&header, &envelope, wrap.as_deref()).expect("statement");
        let wire = st.sign(&key).expect("sign");
        let v = OpStatement::verify(&wire, key.verifying_key()).expect("verify");
        assert_eq!(*v, st);
        assert!(v.matches_envelope(&envelope));
        assert_eq!(
            wrap.as_deref().is_some_and(|w| v.matches_wrap(w)),
            wrap.is_some()
        );
        (wire, *v.message_hash(), labels::SIG_OP)
    } else {
        let st = SnapshotStatement::new(&header, &envelope, wrap.as_deref()).expect("statement");
        let wire = st.sign(&key).expect("sign");
        let v = SnapshotStatement::verify(&wire, key.verifying_key()).expect("verify");
        assert_eq!(*v, st);
        assert!(v.matches_envelope(&envelope));
        (wire, *v.message_hash(), labels::SIG_SNAPSHOT)
    };
    let envelope_hash: [u8; 32] = Sha256::digest(&envelope).into();
    let wrap_hash: [u8; 32] = wrap.as_ref().map_or([0; 32], |w| Sha256::digest(w).into());
    // bytes(header) ‖ SHA-256(envelope) ‖ SHA-256(wrap) or 32 zero bytes.
    let mut body = Vec::new();
    crate::encoding::put_bytes(&mut body, &header).expect("encode");
    body.extend_from_slice(&envelope_hash);
    body.extend_from_slice(&wrap_hash);
    let out = single_outputs(
        label,
        &wire,
        key.verifying_key().as_bytes(),
        key.key_id(),
        &hash,
    );
    assert_eq!(bytes(&out.0, "body"), body);
    out.bytes("envelope_hash", &envelope_hash)
        .bytes("wrap_hash", &wrap_hash)
        .done()
}

/// `device-auth` and `device-request` travel as a bare container over a message the verifier
/// rebuilds; the vector gives that message and the container.
fn detached_outputs(
    label: Label,
    body: &[u8],
    key: &DeviceSigningKey,
    container: &[u8; 82],
) -> Map<String, Value> {
    let message = signed_message(label, body);
    // The container verifies over the message rebuilt from the text.
    let parsed = SignatureContainer::from_bytes(container).expect("container");
    key.verifying_key()
        .verify_container(&message, &parsed)
        .expect("the rebuilt message is the signed one");
    Obj::new()
        .bytes("signer_public_key", key.verifying_key().as_bytes())
        .bytes("signer_key_id", key.key_id().as_bytes())
        .bytes("body", body)
        .bytes("signed_message", &message)
        .bytes("container", container)
        .done()
}
