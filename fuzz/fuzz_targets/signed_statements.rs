//! Fuzzes the signature container and the signed-statement parsers (CRYPTO.md §9.3, §9.6,
//! §10.2, §15 item 7): they never panic and never allocate in proportion to a length field.
//! Every statement decoder runs before its signature check, so arbitrary input reaches it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_core::sign::{
    AccountState, DeviceAuth, DeviceCertificate, DeviceRequest, DeviceRevocation,
    DeviceVerifyingKey, IdentityVerifyingKey, KeyGrant, OpStatement, PublicKeyBundle,
    SignatureContainer, SnapshotStatement,
};

/// RFC 8032 §7.1 test 1 public key: a valid, canonical, non-weak Ed25519 key.
const PUBLIC_KEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

fuzz_target!(|data: &[u8]| {
    let identity = IdentityVerifyingKey::from_bytes(&PUBLIC_KEY).expect("valid key");
    let device = DeviceVerifyingKey::from_bytes(&PUBLIC_KEY).expect("valid key");
    let _ = SignatureContainer::from_bytes(data);
    if let Ok(bundle) = PublicKeyBundle::verify_self_signed(data) {
        let _ = bundle.verify_successor(data);
    }
    let _ = DeviceCertificate::verify(data, &identity, 0);
    let _ = DeviceRevocation::verify(data, &identity);
    let _ = AccountState::verify(data, &identity, 0);
    let _ = OpStatement::verify(data, &device);
    let _ = SnapshotStatement::verify(data, &device);
    let _ = KeyGrant::verify(data, &device);
    let _ = KeyGrant::verify(data, &identity);
    if data.len() >= 32 {
        let (head, container) = data.split_at(32);
        let auth = DeviceAuth {
            server_origin: "https://vault.example",
            account_id: rizzy_core::ids::AccountId::from_bytes([1; 16]),
            device_id: rizzy_core::ids::DeviceId::from_bytes([2; 16]),
            challenge: head.try_into().expect("32 bytes"),
        };
        let _ = auth.verify(container, &device);
        let request = DeviceRequest {
            server_origin: "https://vault.example",
            account_id: auth.account_id,
            device_id: auth.device_id,
            session_id: rizzy_core::ids::SessionId::from_bytes([3; 16]),
            request_counter: 1,
            method: "GET",
            path_and_query: "/",
            body_hash: head.try_into().expect("32 bytes"),
        };
        let _ = request.verify(container, &device);
    }
});
