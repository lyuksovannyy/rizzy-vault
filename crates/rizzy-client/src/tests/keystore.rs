// SPDX-License-Identifier: AGPL-3.0-only

//! Device-state record version 2 ([ADR 0057] §5): known-answer vectors of a record with `E_ks`
//! and forward envelopes and at the `forward_count` boundary, the canonical form, the
//! `has_ks = 1 ⇒ has_local = 1` rule and the platform gate (INV-81) under both
//! `keystore_capable` values, in the parser and in the floors, and the v1 → v2 upgrade; and the
//! lifecycle with real keys against the fake server (CRYPTO.md §5.6 step 3, §11.3 step 4.3):
//! enabling, the keystore unlock, rotations crossed by keystore unlocks up to the eighth forward
//! envelope and the refused ninth, the password unlock that follows and collapses the chain,
//! with and without the keystore secret attached, and disabling.
//!
//! [ADR 0057]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0057-device-state-v2-keystore.md

use proptest::prelude::*;
use rizzy_core::secret_key::SecretKey;
use rizzy_core::sign::DeviceKind;

use super::*;
use crate::device::{ForwardWrap, KeystoreWrap, LocalWrap, MAX_FORWARD_COUNT};
use crate::store::floors::Floors;
use crate::store::record::{DeviceRecord, MAX_DEVICE_STATE_LEN, RECORD_VERSION, Stage};
use crate::store::rows::{Changeset, Write};

/// A symmetric envelope's bytes, enough for the parser: the header and a minimal body.
fn envelope(fill: u8) -> Vec<u8> {
    let mut out = vec![0x01, 0x01];
    out.extend(core::iter::repeat_n(fill, 88));
    out
}

/// The record of the vectors: the fixed fields of the ADR 0026 vectors, `E_local` at
/// account-key epoch 7, `E_ks` (if any) at the end of the chain, and `forward` envelopes
/// `7 → 8 → … → 7 + forward`.
fn ks_record(has_local: bool, has_ks: bool, forward: u32) -> DeviceRecord {
    DeviceRecord {
        stage: Stage::Committed,
        server_origin: ServerOrigin::parse(ORIGIN).unwrap(),
        account_id: AccountId::from_bytes([0xa1; 16]),
        device_id: DeviceId::from_bytes([0xd2; 16]),
        device_kind: DeviceKind::DesktopCli,
        secret_key: SecretKey::from_slice(&[0x11; 16]).unwrap(),
        device_salt: [0x22; 16],
        kdf_id: KdfId::DEFAULT,
        device_keys_wrap: envelope(0x33),
        local_wrap: has_local.then(|| LocalWrap {
            envelope: envelope(0x44),
            account_key_epoch: 7,
            password_epoch: 3,
        }),
        keystore_wrap: has_ks.then(|| KeystoreWrap {
            envelope: envelope(0x88),
            account_key_epoch: 7 + forward,
        }),
        forward: (0..forward)
            .map(|i| ForwardWrap {
                envelope: envelope(0x90 + u8::try_from(i).unwrap()),
                from_account_key_epoch: 7 + i,
                to_account_key_epoch: 8 + i,
            })
            .collect(),
        pending: None,
    }
}

/// The vector bytes, written out field by field from ADR 0057 §2.
fn ks_bytes(has_local: bool, has_ks: bool, forward: u32) -> Vec<u8> {
    let bytes_of = |out: &mut Vec<u8>, x: &[u8]| {
        out.extend_from_slice(&u32::try_from(x.len()).unwrap().to_be_bytes());
        out.extend_from_slice(x);
    };
    let mut out = vec![0x00, 0x02, 0x01];
    bytes_of(&mut out, ORIGIN.as_bytes());
    out.extend_from_slice(&[0xa1; 16]);
    out.extend_from_slice(&[0xd2; 16]);
    out.push(1);
    out.extend_from_slice(&[0x11; 16]);
    out.extend_from_slice(&[0x22; 16]);
    out.extend_from_slice(&[0x00, 0x01]);
    bytes_of(&mut out, &envelope(0x33));
    if has_local {
        out.push(1);
        out.extend_from_slice(&[0, 0, 0, 7, 0, 0, 0, 3]);
        bytes_of(&mut out, &envelope(0x44));
    } else {
        out.push(0);
    }
    if has_ks {
        out.push(1);
        out.extend_from_slice(&(7 + forward).to_be_bytes());
        bytes_of(&mut out, &envelope(0x88));
    } else {
        out.push(0);
    }
    out.push(u8::try_from(forward).unwrap());
    for i in 0..forward {
        out.extend_from_slice(&(7 + i).to_be_bytes());
        out.extend_from_slice(&(8 + i).to_be_bytes());
        bytes_of(&mut out, &envelope(0x90 + u8::try_from(i).unwrap()));
    }
    out.push(0);
    out
}

/// ADR 0057 §5: a v2 record with `has_ks = 1` and forward envelopes, and the boundary at 8,
/// against bytes written out from the grammar; each parses back to itself on a keystore-capable
/// host (one state, one encoding) and is refused as corrupt on any other (INV-81).
#[test]
fn v2_record_vectors() {
    for (has_ks, forward) in [(true, 1), (true, 2), (true, 8), (false, 2), (false, 8)] {
        let record = ks_record(true, has_ks, forward);
        let encoded = record.encode().unwrap();
        assert_eq!(
            hex_of(&encoded),
            hex_of(&ks_bytes(true, has_ks, forward)),
            "{has_ks} {forward}"
        );
        let parsed = DeviceRecord::parse(&encoded, true).unwrap();
        assert_eq!(parsed.has_keystore(), has_ks);
        assert_eq!(parsed.forward_count(), usize::try_from(forward).unwrap());
        assert_eq!(parsed.encode().unwrap().as_slice(), encoded.as_slice());
        // The gate only concerns `has_ks`: a forward chain alone parses everywhere.
        assert_eq!(
            DeviceRecord::parse(&encoded, false).map(|r| r.forward_count()),
            if has_ks {
                Err(ClientError::CacheCorrupt)
            } else {
                Ok(usize::try_from(forward).unwrap())
            }
        );
    }
    // Fixed here so that a layout change cannot pass by changing encoder and helper together:
    // the length of the one-forward vector and the bytes around `has_ks`.
    let one = ks_record(true, true, 1).encode().unwrap();
    assert_eq!(
        one.len(),
        3 + 29 + 16 + 16 + 1 + 16 + 16 + 2 + 94 + (1 + 8 + 94) + (1 + 4 + 94) + 1 + (8 + 94) + 1
    );
    let ks_at = 3 + 29 + 16 + 16 + 1 + 16 + 16 + 2 + 94 + 1 + 8 + 94;
    assert_eq!(hex_of(&one[ks_at..ks_at + 9]), "01000000080000005a");
    let count_at = ks_at + 1 + 4 + 94;
    assert_eq!(hex_of(&one[count_at..count_at + 9]), "010000000700000008");
    assert_eq!(one[one.len() - 1], 0);
    assert_eq!(RECORD_VERSION, 2);
    assert_eq!(MAX_FORWARD_COUNT, 8);
}

/// ADR 0057 §2: `forward_count` 9 is refused before any entry is read, under both gate values;
/// the encoder refuses to write it.
#[test]
fn nine_forward_envelopes_are_refused() {
    let mut nine = ks_bytes(true, false, 8);
    // Patch the count to 9 and append a ninth entry before the pending flag.
    let count_at = nine.len() - 1 - 8 * (8 + 4 + 90) - 1;
    assert_eq!(nine[count_at], 8);
    nine[count_at] = 9;
    let pending = nine.pop().unwrap();
    nine.extend_from_slice(&15u32.to_be_bytes());
    nine.extend_from_slice(&16u32.to_be_bytes());
    nine.extend_from_slice(&90u32.to_be_bytes());
    nine.extend_from_slice(&envelope(0x99));
    nine.push(pending);
    for capable in [false, true] {
        assert_eq!(
            DeviceRecord::parse(&nine, capable).unwrap_err(),
            ClientError::CacheCorrupt
        );
    }
    // 255 with no entries behind it is refused the same way.
    let mut many = ks_bytes(true, false, 0);
    let at = many.len() - 2;
    many[at] = 0xff;
    assert_eq!(
        DeviceRecord::parse(&many, true).unwrap_err(),
        ClientError::CacheCorrupt
    );
    let mut record = ks_record(true, false, 8);
    record.forward.push(ForwardWrap {
        envelope: envelope(0x99),
        from_account_key_epoch: 15,
        to_account_key_epoch: 16,
    });
    assert_eq!(record.encode().unwrap_err(), ClientError::Internal);
    // A full record still fits ADR 0026 §2's bound.
    assert!(ks_bytes(true, true, 8).len() <= MAX_DEVICE_STATE_LEN);
}

/// ADR 0057 §2: `has_ks = 1` requires `has_local = 1`; flags outside 0/1, a truncated `[ks]`
/// or forward entry, a non-envelope `E_ks` and a trailing byte are refused.
#[test]
fn v2_refusals() {
    for capable in [false, true] {
        assert_eq!(
            DeviceRecord::parse(&ks_bytes(false, true, 0), capable).unwrap_err(),
            ClientError::CacheCorrupt
        );
    }
    assert_eq!(
        ks_record(false, true, 0).encode().unwrap_err(),
        ClientError::Internal
    );
    let good = ks_bytes(true, true, 2);
    assert!(DeviceRecord::parse(&good, true).is_ok());
    let ks_at = 3 + 29 + 16 + 16 + 1 + 16 + 16 + 2 + 94 + 1 + 8 + 94;
    let mut flag = good.clone();
    flag[ks_at] = 2;
    assert!(DeviceRecord::parse(&flag, true).is_err());
    // `E_ks` that is not a symmetric envelope.
    let mut not_envelope = good.clone();
    not_envelope[ks_at + 1 + 4 + 4] = 0x02;
    assert!(DeviceRecord::parse(&not_envelope, true).is_err());
    let mut trailing = good.clone();
    trailing.push(0);
    assert!(DeviceRecord::parse(&trailing, true).is_err());
    for cut in 1..good.len() {
        assert!(
            DeviceRecord::parse(&good[..cut], true).is_err(),
            "cut {cut}"
        );
    }
    // A pending flag outside 0/1 after the forward entries.
    let mut pending = good;
    let last = pending.len() - 1;
    pending[last] = 2;
    assert!(DeviceRecord::parse(&pending, true).is_err());
}

/// ADR 0057 §3: a v1 record reads as `has_ks = 0`, `forward_count = 0` and is written back as
/// version 2: the same bytes with the version raised and the two new zero bytes in place.
#[test]
fn v1_records_are_read_and_written_as_v2() {
    let v2 = ks_bytes(true, false, 0);
    // The v1 form: version 1, without the `has_ks` and `forward_count` bytes.
    let mut v1 = v2.clone();
    v1[1] = 1;
    let at = v1.len() - 3;
    v1.drain(at..at + 2);
    assert_eq!(v1.len() + 2, v2.len());
    for capable in [false, true] {
        let record = DeviceRecord::parse(&v1, capable).unwrap();
        assert!(!record.has_keystore());
        assert_eq!(record.forward_count(), 0);
        assert_eq!(hex_of(&record.encode().unwrap()), hex_of(&v2));
    }
    // A v1 record has no `has_ks`: one more byte where v2 has it is trailing data.
    let mut v1_with_flag = v1.clone();
    v1_with_flag.insert(at, 0);
    assert!(DeviceRecord::parse(&v1_with_flag, true).is_err());
    // Version 3 is "update required"; version 0 corrupt.
    let mut v3 = v2.clone();
    v3[1] = 3;
    assert_eq!(
        DeviceRecord::parse(&v3, true).unwrap_err(),
        ClientError::CacheUpdateRequired
    );
    let mut v0 = v2;
    v0[1] = 0;
    assert_eq!(
        DeviceRecord::parse(&v0, true).unwrap_err(),
        ClientError::CacheCorrupt
    );
}

/// INV-81 in the floors: a written record with `has_ks = 1` is admitted only after the host
/// turned the gate on; a record without `E_ks` is admitted either way.
#[test]
fn floors_apply_the_platform_gate() {
    let write = |has_ks: bool| crate::store::create_writes(&ks_record(true, has_ks, 1)).unwrap();
    let mut floors = Floors::empty();
    assert_eq!(floors.admit(&write(true)), Err(ClientError::Internal));
    assert!(floors.admit(&write(false)).is_ok());
    // A later write of a record with `E_ks` is refused too, one without it admitted.
    let mut later = Changeset::new();
    later.push(Write::DeviceState(
        ks_record(true, true, 1).encode().unwrap(),
    ));
    assert_eq!(floors.admit(&later), Err(ClientError::Internal));
    let mut later = Changeset::new();
    later.push(Write::DeviceState(
        ks_record(true, false, 2).encode().unwrap(),
    ));
    assert!(floors.admit(&later).is_ok());
    let mut capable = Floors::empty();
    capable.set_keystore_capable(true);
    assert!(capable.admit(&write(true)).is_ok());
}

/// The `Debug` form shows flags and counts, never envelope bytes or the Secret Key.
#[test]
fn v2_debug_is_redacted() {
    let shown = format!("{:?}", ks_record(true, true, 2));
    assert!(shown.contains("has_ks: true"));
    assert!(shown.contains("forward_count: 2"));
    assert!(!shown.contains("136"), "{shown}");
    assert!(!shown.contains("17, 17"), "{shown}");
}

proptest! {
    /// Round trip: any combination of the v2 fields encodes, parses (on a capable host) and
    /// encodes again to the same bytes.
    #[test]
    fn v2_round_trip(
        has_local in any::<bool>(),
        has_ks in any::<bool>(),
        forward in 0u32..=8,
        ks_epoch in any::<u32>(),
        epochs in proptest::collection::vec((any::<u32>(), any::<u32>()), 8),
        fill in any::<u8>(),
    ) {
        let mut record = ks_record(has_local, has_ks && has_local, forward);
        if let Some(ks) = record.keystore_wrap.as_mut() {
            ks.account_key_epoch = ks_epoch;
            ks.envelope = envelope(fill);
        }
        for (step, (from, to)) in record.forward.iter_mut().zip(epochs) {
            step.from_account_key_epoch = from;
            step.to_account_key_epoch = to;
        }
        let encoded = record.encode().unwrap();
        prop_assert!(encoded.len() <= MAX_DEVICE_STATE_LEN);
        let parsed = DeviceRecord::parse(&encoded, true).unwrap();
        prop_assert_eq!(parsed.encode().unwrap().to_vec(), encoded.to_vec());
        prop_assert_eq!(
            DeviceRecord::parse(&encoded, false).is_ok(),
            !(has_ks && has_local)
        );
    }

    /// Any one flipped byte of a v2 record with `E_ks` and a chain parses to a record that
    /// encodes back to the flipped bytes, or is refused; never a panic.
    #[test]
    fn v2_flipped_bytes_stay_canonical(at in 0usize..1000, bit in 0u8..8) {
        let mut bytes = ks_bytes(true, true, 3);
        let at = at % bytes.len();
        bytes[at] ^= 1 << bit;
        for capable in [false, true] {
            if let Ok(record) = DeviceRecord::parse(&bytes, capable) {
                prop_assert_eq!(record.encode().unwrap().to_vec(), bytes.clone());
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The lifecycle with real keys (CRYPTO.md §5.6 step 3, §11.3 step 4.3; ADR 0057 §2)
// ---------------------------------------------------------------------------------------------

use rizzy_core::envelope::purpose::{
    AccountKeyDeviceGrantCtx, IdentitySecretKeysCtx, VaultKeySelfGrantCtx,
};
use rizzy_core::ids::VaultId;
use rizzy_core::keys::{GrantSigner, VaultKey, seal_account_key_device_grant};
use rizzy_proto::account::DeviceGrantsResponse;
use rizzy_proto::objects::DeviceGrant;

use crate::unlock::apply_device_grants;

/// Device B, which rotates the account key and grants each new key to device A.
struct Rotator {
    account: crate::account::VerifiedAccount,
    /// B's keys; `account_key` is replaced at each rotation.
    unlocked: UnlockedDevice,
    vault_key: VaultKey,
    state: AccountState,
    /// The grants A has not applied yet, oldest first.
    grants: Vec<DeviceGrant>,
}

impl Rotator {
    fn new(server: &mut Server, rng: &mut ChaCha20Rng, sk: &str, vault_id: VaultId) -> Self {
        let b = login_and_enrol(server, rng, sk);
        let mut account = b.account;
        let vault_key = account.take_vault_key(vault_id).unwrap();
        let state = account.state().clone();
        Self {
            account,
            unlocked: b.unlocked,
            vault_key,
            state,
            grants: Vec::new(),
        }
    }

    /// One standard rotation (CRYPTO.md §11.6) granting the new key to `a`; serves the new
    /// state, `E_id` and self-grant.
    fn rotate(&mut self, server: &mut Server, rng: &mut ChaCha20Rng, a: &DeviceState) {
        let account_id = self.account.account_id();
        let new_key = self.unlocked.account_key.generate_next(rng).unwrap();
        let epoch = new_key.epoch();
        let a_cert = self
            .account
            .certificates()
            .iter()
            .find(|c| c.certificate.device_id == a.device_id())
            .unwrap()
            .certificate
            .clone();
        let grant = seal_account_key_device_grant(
            rng,
            &AccountKeyDeviceGrantCtx {
                account_id,
                account_key_epoch: epoch,
                sender_device_id: self.unlocked.device_id,
                recipient_device_id: a.device_id(),
            },
            &new_key,
            &self.unlocked.account_key,
            &a_cert,
            GrantSigner::Device(self.unlocked.device_keys.signing_key()),
        )
        .unwrap();
        let e_id = new_key
            .wrap_identity_keys(
                rng,
                &IdentitySecretKeysCtx {
                    account_id,
                    identity_epoch: 0,
                },
                &self.account.identity,
            )
            .unwrap();
        let self_grant = new_key
            .wrap_vault_key(
                rng,
                &VaultKeySelfGrantCtx {
                    account_id,
                    vault_id: self.vault_key.vault_id(),
                    account_key_epoch: epoch,
                    vault_key_epoch: 0,
                },
                &self.vault_key,
            )
            .unwrap();
        self.state.state_seq += 1;
        self.state.account_key_epoch = epoch;
        self.state.account_key_id = new_key.key_id().unwrap();
        let wire = self
            .state
            .sign(self.account.identity.signing_key())
            .unwrap();
        let s = server.account.as_mut().unwrap();
        s.state = wire;
        s.e_id = IdentitySecretKeys {
            identity_epoch: 0,
            envelope: bytes(&e_id),
        };
        s.grants = vec![VaultSelfGrant {
            vault_id: Id::from_bytes(self.vault_key.vault_id().to_bytes()),
            account_key_epoch: epoch,
            vault_key_epoch: 0,
            envelope: bytes(&self_grant),
        }];
        self.grants.push(DeviceGrant {
            account_key_epoch: epoch,
            sender_device_id: Id::from_bytes(self.unlocked.device_id.to_bytes()),
            recipient_device_id: Id::from_bytes(a.device_id().to_bytes()),
            key_grant: bytes(&grant),
        });
        self.unlocked.account_key = new_key;
    }

    /// The grants A has not applied yet.
    fn pending(&self) -> DeviceGrantsResponse {
        DeviceGrantsResponse {
            grants: List::new(self.grants.clone()).unwrap(),
        }
    }
}

/// The online part after an unlock (CRYPTO.md §11.3 steps 2–4): verify; on a rotation apply the
/// grants and verify again. Returns the result of applying the grants, if any were needed.
fn online(
    rng: &mut ChaCha20Rng,
    server: &Server,
    b: &mut Rotator,
    state: &mut DeviceState,
    unlocked: &mut UnlockedDevice,
) -> Option<Result<(), ClientError>> {
    let view = server.view();
    match verify_unlock(state, unlocked, &view, None) {
        Ok(_) => None,
        Err(ClientError::AccountKeyRotated) => {
            let applied = apply_device_grants(rng, state, unlocked, &view, &b.pending(), None);
            Some(applied.map(|_ack| {
                b.grants.clear();
                verify_unlock(state, unlocked, &view, None).unwrap();
            }))
        }
        Err(e) => panic!("{e:?}"),
    }
}

/// A copy of a device state, through its record (the state is not `Clone`).
fn copy_state(state: &DeviceState) -> DeviceState {
    let bytes = state.record(Stage::Committed).unwrap().encode().unwrap();
    DeviceRecord::parse(&bytes, true)
        .unwrap()
        .to_state(state.pin().clone())
        .unwrap()
}

fn record_bytes(state: &DeviceState) -> Vec<u8> {
    state
        .record(Stage::Committed)
        .unwrap()
        .encode()
        .unwrap()
        .to_vec()
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one story: enable, cross eight rotations by keystore unlock, refuse the ninth, collapse"
)]
fn keystore_unlock_lifecycle() {
    let mut rng = ChaCha20Rng::seed_from_u64(57);
    let mut server = Server::new(5757);
    let a = signup(&mut server, &mut rng, DeviceKind::DesktopCli);
    let mut state = a.device.unwrap();
    let sk = secret_key_text(&state);
    let mut b = Rotator::new(&mut server, &mut rng, &sk, a.vault_key.vault_id());

    // Without `E_ks` there is no keystore unlock.
    assert!(!state.has_keystore());
    assert_eq!(
        state.unlock_keystore(&[0; 32]).unwrap_err(),
        ClientError::KeystoreUnlockUnavailable
    );

    // Enable after a password unlock (CRYPTO.md §4.2): the secret is returned, never stored.
    let mut unlocked = state.unlock(PASSWORD).unwrap();
    online(&mut rng, &server, &mut b, &mut state, &mut unlocked);
    let secret = state.enable_keystore(&mut rng, &unlocked).unwrap();
    let secret = secret.expose_secret().to_vec();
    assert!(state.has_keystore());
    let bytes = record_bytes(&state);
    assert!(
        !bytes.windows(secret.len()).any(|w| w == secret.as_slice()),
        "INV-82: the secret is not in the record"
    );
    assert_eq!(
        DeviceRecord::parse(&bytes, false).unwrap_err(),
        ClientError::CacheCorrupt,
        "INV-81"
    );
    let record = DeviceRecord::parse(&bytes, true).unwrap();
    assert!(record.has_keystore());
    // The keystore unlock: no Argon2id, the same keys as the password unlock.
    let ks = record.unlock_keystore(&secret).unwrap();
    assert_eq!(ks.account_key_epoch(), 0);
    assert!(ks.has_keystore_secret());
    assert_eq!(
        ks.account_key.key().expose_secret(),
        unlocked.account_key.key().expose_secret()
    );
    // A wrong or short secret.
    assert_eq!(
        state.unlock_keystore(&[0x5a; 32]).unwrap_err(),
        ClientError::KeystoreUnlockUnavailable
    );
    assert_eq!(
        state.unlock_keystore(&secret[..31]).unwrap_err(),
        ClientError::InvalidInput
    );
    // Keys of another device cannot enable it.
    assert_eq!(
        state.enable_keystore(&mut rng, &b.unlocked).unwrap_err(),
        ClientError::InvalidInput
    );

    // Eight rotations, each crossed by a keystore unlock: E_ks and E_dev move to the new key,
    // E_local stays at epoch 0, and the forward chain grows by one (§11.3 step 4.3).
    for n in 1..=8u32 {
        b.rotate(&mut server, &mut rng, &state);
        let mut ks = state.unlock_keystore(&secret).unwrap();
        assert_eq!(ks.account_key_epoch(), n - 1);
        assert_eq!(
            online(&mut rng, &server, &mut b, &mut state, &mut ks),
            Some(Ok(()))
        );
        assert_eq!(ks.account_key_epoch(), n);
        assert_eq!(state.forward_count(), usize::try_from(n).unwrap());
        assert_eq!(state.local_wrap.account_key_epoch, 0);
        let again = state.unlock_keystore(&secret).unwrap();
        assert_eq!(again.account_key_epoch(), n);
    }
    // The record of a full chain round-trips and a password unlock from it follows all eight
    // forward envelopes to the newest key (§5.6 step 3).
    let full = record_bytes(&state);
    let record = DeviceRecord::parse(&full, true).unwrap();
    assert_eq!(record.forward_count(), 8);
    assert_eq!(record.encode().unwrap().as_slice(), full.as_slice());
    let followed = record.unlock(PASSWORD).unwrap();
    assert_eq!(followed.account_key_epoch(), 8);
    assert_eq!(
        followed.account_key.key().expose_secret(),
        b.unlocked.account_key.key().expose_secret()
    );

    // A ninth rotation crossed by a keystore unlock is refused (owner answer 2): nothing changes,
    // nothing is acknowledged, the grants stay to be fetched.
    b.rotate(&mut server, &mut rng, &state);
    let mut ks = state.unlock_keystore(&secret).unwrap();
    assert_eq!(
        online(&mut rng, &server, &mut b, &mut state, &mut ks),
        Some(Err(ClientError::KeystoreUnlockUnavailable))
    );
    assert_eq!(record_bytes(&state), full);
    assert_eq!(b.grants.len(), 1);

    // The password unlock that follows: without the keystore secret, E_local and E_dev move to
    // epoch 9, the chain is deleted, and E_ks is deleted with it (it cannot be re-wrapped).
    let mut without = copy_state(&state);
    let mut pw = without.unlock(PASSWORD).unwrap();
    assert_eq!(pw.account_key_epoch(), 8);
    let mut b_copy_grants = b.grants.clone();
    assert_eq!(
        online(&mut rng, &server, &mut b, &mut without, &mut pw),
        Some(Ok(()))
    );
    assert_eq!(without.forward_count(), 0);
    assert!(!without.has_keystore());
    assert_eq!(without.local_wrap.account_key_epoch, 9);
    assert_eq!(without.unlock(PASSWORD).unwrap().account_key_epoch(), 9);

    // With the secret attached (a second presence check), E_ks is re-wrapped instead.
    b.grants.append(&mut b_copy_grants);
    let mut pw = state.unlock(PASSWORD).unwrap();
    pw.attach_keystore_secret(&secret).unwrap();
    assert_eq!(
        pw.attach_keystore_secret(&secret[..16]).unwrap_err(),
        ClientError::InvalidInput
    );
    assert_eq!(
        online(&mut rng, &server, &mut b, &mut state, &mut pw),
        Some(Ok(()))
    );
    assert_eq!(state.forward_count(), 0);
    assert!(state.has_keystore());
    assert_eq!(
        state.unlock_keystore(&secret).unwrap().account_key_epoch(),
        9
    );
    assert_eq!(state.unlock(PASSWORD).unwrap().account_key_epoch(), 9);
    pw.forget_unlock_key();
    assert!(!pw.has_keystore_secret());

    // One more rotation crossed by a keystore unlock, then a password unlock with no rotation:
    // the chain is collapsed after the answer verified (§11.3 step 4.3, "At the next password
    // unlock").
    b.rotate(&mut server, &mut rng, &state);
    let mut ks = state.unlock_keystore(&secret).unwrap();
    assert_eq!(
        online(&mut rng, &server, &mut b, &mut state, &mut ks),
        Some(Ok(()))
    );
    assert_eq!(state.forward_count(), 1);
    // A keystore unlock cannot collapse: it has no local unlock key.
    assert_eq!(
        state.collapse_forward(&mut rng, &ks).unwrap_err(),
        ClientError::InvalidInput
    );
    let mut pw = state.unlock(PASSWORD).unwrap();
    assert_eq!(pw.account_key_epoch(), 10);
    assert_eq!(online(&mut rng, &server, &mut b, &mut state, &mut pw), None);
    assert!(state.collapse_forward(&mut rng, &pw).unwrap());
    assert!(!state.collapse_forward(&mut rng, &pw).unwrap());
    assert_eq!(state.forward_count(), 0);
    assert_eq!(state.local_wrap.account_key_epoch, 10);
    assert_eq!(state.unlock(PASSWORD).unwrap().account_key_epoch(), 10);

    // Disabling deletes E_ks only; a live chain stays (ADR 0057 §2).
    b.rotate(&mut server, &mut rng, &state);
    let mut ks = state.unlock_keystore(&secret).unwrap();
    online(&mut rng, &server, &mut b, &mut state, &mut ks);
    assert_eq!(state.forward_count(), 1);
    state.disable_keystore();
    assert!(!state.has_keystore());
    assert_eq!(state.forward_count(), 1);
    let bytes = record_bytes(&state);
    let record = DeviceRecord::parse(&bytes, false).unwrap();
    assert_eq!(record.forward_count(), 1);
    assert_eq!(record.unlock(PASSWORD).unwrap().account_key_epoch(), 11);
    assert_eq!(
        record.unlock_keystore(&secret).unwrap_err(),
        ClientError::KeystoreUnlockUnavailable
    );
}

/// A damaged forward envelope or a broken chain is `CacheCorrupt` after the password opened
/// `E_local` (ADR 0026 §5 (d)); a wrong password stays `WrongPasswordOrSecretKey`.
#[test]
fn a_damaged_forward_chain_is_corrupt() {
    let mut rng = ChaCha20Rng::seed_from_u64(5758);
    let mut server = Server::new(5759);
    let a = signup(&mut server, &mut rng, DeviceKind::DesktopCli);
    let mut state = a.device.unwrap();
    let sk = secret_key_text(&state);
    let mut b = Rotator::new(&mut server, &mut rng, &sk, a.vault_key.vault_id());
    let unlocked = state.unlock(PASSWORD).unwrap();
    let secret = state.enable_keystore(&mut rng, &unlocked).unwrap();
    b.rotate(&mut server, &mut rng, &state);
    let mut ks = state.unlock_keystore(secret.expose_secret()).unwrap();
    online(&mut rng, &server, &mut b, &mut state, &mut ks)
        .unwrap()
        .unwrap();
    let good = record_bytes(&state);
    // The last byte of the forward envelope (before `pending = 0`).
    let mut flipped = good.clone();
    let at = flipped.len() - 2;
    flipped[at] ^= 1;
    let record = DeviceRecord::parse(&flipped, true).unwrap();
    assert_eq!(
        record.unlock(PASSWORD).unwrap_err(),
        ClientError::CacheCorrupt
    );
    assert_eq!(
        record.unlock("not the password").unwrap_err(),
        ClientError::WrongPasswordOrSecretKey
    );
    // The chain no longer starting at `E_local`'s epoch.
    let mut broken = copy_state(&state);
    broken.forward[0].from_account_key_epoch = 5;
    assert_eq!(
        broken.unlock(PASSWORD).unwrap_err(),
        ClientError::CacheCorrupt
    );
    // The keystore path does not read the chain.
    assert_eq!(
        record
            .unlock_keystore(secret.expose_secret())
            .unwrap()
            .account_key_epoch(),
        1
    );
}
