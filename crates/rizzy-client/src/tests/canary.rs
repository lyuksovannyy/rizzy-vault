// SPDX-License-Identifier: AGPL-3.0-only

//! The key-byte half of the INV-15 canary (threat model INV-15: the account key, vault keys,
//! item keys and private keys never leave a client unencrypted) and the envelope canary of
//! CRYPTO.md §15 item 5 ("the `E_dev`, `E_local`, `E_ks` and `ACCOUNT_KEY_FORWARD` envelope
//! bytes never appear in any request body or server row").
//!
//! These bytes live inside `rizzy-client`'s and `rizzy-core`'s types, which no host can read,
//! so the black-box canary of `rizzy-cli`'s end-to-end tests cannot name them. This one runs
//! inside the crate, over the fake server of the parent module, whose handlers record every
//! request and answer as the JSON body a transport would carry ([`Server::wire`]); everything
//! the fake stores comes from those requests, so its "rows" are in the haystack too.
//!
//! The flow: a signup with a recovery code, a login and enrolment on a second device, device
//! authentication, item writes, uploads and Fetches, a web-vault login, a standard rotation
//! committed by the first device and followed by the second through its grant, and writes
//! after it. The secrets, collected along the way: every account key, vault key and item key
//! either device held, `E_dev` and `E_local` of both devices before and after the rotation,
//! the Secret Key, `pw_in` and the recovery code. Each is searched for raw, as hex and as base64
//! at any alignment ([`forms`]).
//!
//! Not covered, and why:
//! - **The private keys** (identity and device Ed25519 and X25519): `rizzy-core` lets their
//!   seeds out only through a crate-private function, into the `E_id` and `E_dev` plaintext,
//!   and its test hooks exist only in its own test build. Reaching them here would need a new
//!   accessor in `rizzy-core` (a security boundary), so this test does not; `E_dev`, which
//!   wraps the device keys, is searched for instead.
//! - **The local and server unlock keys:** the same, `rizzy-core`'s `key_for_tests` is
//!   `cfg(test)` there.
//! - **`E_ks` and `ACCOUNT_KEY_FORWARD`:** not built yet (CRYPTO.md, M3/M7 keystore unlock).

use rizzy_core::opaque::PasswordInput;
use rizzy_core::secret_key::RecoveryCode;
use rizzy_proto::account::DeviceGrantsResponse;

use super::rotation::{fetch, reauth, settle, signup_with_code};
use super::*;
use crate::rotation::{RotationLevel, RotationOptions, start_rotation};
use crate::unlock::apply_device_grants;

/// The secrets of one device state: its Secret Key, `pw_in` (under [`PASSWORD`]), `E_local`
/// and `E_dev`.
fn device_secrets(label: &str, state: &DeviceState, out: &mut Vec<(String, Vec<u8>)>) {
    let pw_in = PasswordInput::derive(PASSWORD, &state.secret_key).unwrap();
    out.push((
        format!("{label}: the Secret Key"),
        state.secret_key.expose_secret().to_vec(),
    ));
    out.push((format!("{label}: pw_in"), pw_in.expose_secret().to_vec()));
    out.push((
        format!("{label}: E_local"),
        state.local_wrap.envelope.clone(),
    ));
    out.push((format!("{label}: E_dev"), state.device_keys_wrap.clone()));
}

/// The account key of an unlocked device.
fn account_key(label: &str, unlocked: &UnlockedDevice, out: &mut Vec<(String, Vec<u8>)>) {
    out.push((
        format!("{label}: the account key"),
        unlocked.account_key.key().expose_secret().to_vec(),
    ));
}

/// The vault key and every item key a vault holds.
fn vault_keys(label: &str, vault: &VaultSync, out: &mut Vec<(String, Vec<u8>)>) {
    for (i, key) in vault.key_bytes_for_tests().into_iter().enumerate() {
        let what = if i == 0 {
            "the vault key"
        } else {
            "an item key"
        };
        out.push((format!("{label}: {what} ({i})"), key));
    }
}

/// INV-15 and CRYPTO.md §15 item 5 (module docs).
///
/// ETH class: none. Key material leaving the client is not one of the threat model's §5 classes.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one story through every flow the fake serves, then one search"
)]
fn canary_key_bytes_and_device_envelopes_never_reach_the_server() {
    let mut rng = ChaCha20Rng::seed_from_u64(1515);
    let mut server = Server::new(1516);
    let mut secrets: Vec<(String, Vec<u8>)> = Vec::new();

    // Signup with a recovery code; a second device logs in and enrols.
    let (mut a, code) = signup_with_code(&mut server, &mut rng);
    let mut a_state = a.device.take().unwrap();
    let sk = secret_key_text(&a_state);
    device_secrets("A at signup", &a_state, &mut secrets);
    account_key("A at signup", &a.unlocked, &mut secrets);
    secrets.push((
        "the recovery code".into(),
        RecoveryCode::parse(&code).unwrap().expose_secret().to_vec(),
    ));
    let b = login_and_enrol(&mut server, &mut rng, &sk);
    device_secrets("B at enrolment", &b.device, &mut secrets);

    // A writes two items and syncs, with device authentication.
    let authors = server.authors();
    let (mut vault, mut a_unlocked, items) = synced_writer(&mut server, &mut rng, a, &authors, 2);
    let _session = device_session(&mut server, &a_state, &a_unlocked);
    settle(&mut server, &mut rng, &mut vault, &a_unlocked);
    vault_keys("A before the rotation", &vault, &mut secrets);

    // A web-vault login (kind 4), which opens `E_srv` in memory.
    let _web = web_login(&mut server, &mut rng, &sk);

    // A standard rotation by A, keeping the recovery code.
    let options = RotationOptions {
        level: RotationLevel::Standard,
        revoke: None,
        recovery_code: Some(&code),
        now_ms: T0 + 10_000,
    };
    let login = reauth(&mut server, &mut rng, &sk);
    let pending =
        start_rotation(&mut rng, login, &a_state, &a_unlocked, &[&vault], &options).unwrap();
    server.commit_rotation(pending.commit_request()).unwrap();
    pending
        .finalize(&mut rng, &mut a_state, &mut a_unlocked, &mut [&mut vault])
        .unwrap();
    fetch(&server, &mut vault);
    // A writes again: the writer rule makes a fresh item key at the new epoch.
    let key = SchemaKey::parse(LOGIN_PASSWORD.as_bytes()).unwrap();
    let value = Value::text("after the rotation").unwrap();
    vault
        .edit_item(
            &mut rng,
            &a_unlocked,
            items[0],
            &[FieldEdit {
                key: &key,
                value: &value,
            }],
            T0 + 20_000,
        )
        .unwrap();
    settle(&mut server, &mut rng, &mut vault, &a_unlocked);
    device_secrets("A after the rotation", &a_state, &mut secrets);
    account_key("A after the rotation", &a_unlocked, &mut secrets);
    vault_keys("A after the rotation", &vault, &mut secrets);

    // B follows through its grant and reads every item.
    let mut b_state = b.device;
    let mut b_unlocked = b_state.unlock(PASSWORD).unwrap();
    account_key("B before following", &b_unlocked, &mut secrets);
    let view = server.view();
    let grants = DeviceGrantsResponse {
        grants: List::new(
            server
                .device_grants
                .iter()
                .filter(|g| g.recipient_device_id.to_bytes() == b_state.device_id().to_bytes())
                .cloned()
                .collect(),
        )
        .unwrap(),
    };
    server.capture(serde_json::to_vec(&grants));
    apply_device_grants(
        &mut rng,
        &mut b_state,
        &mut b_unlocked,
        &view,
        &grants,
        None,
    )
    .unwrap();
    let mut b_account = verify_unlock(&mut b_state, &b_unlocked, &view, None).unwrap();
    let vault_id = b_account.vault_ids().next().unwrap();
    let mut b_vault =
        VaultSync::new(b_account.take_vault_key(vault_id).unwrap(), &b_unlocked, 1).unwrap();
    fetch(&server, &mut b_vault);
    assert!(b_vault.field_value(items[1], LOGIN_PASSWORD).is_some());
    device_secrets("B after following", &b_state, &mut secrets);
    account_key("B after following", &b_unlocked, &mut secrets);
    vault_keys("B after following", &b_vault, &mut secrets);

    let wire = server.wire.borrow().clone();
    // Positive controls: the haystack holds the server's view, and the search finds an
    // envelope that is meant to reach the server (`E_srv`) in it, so an empty search cannot
    // pass.
    assert!(wire.len() > 30, "{} bodies", wire.len());
    let e_srv = server.stored().e_srv.envelope.as_slice().to_vec();
    assert!(
        forms(&e_srv)
            .iter()
            .any(|f| wire.iter().any(|body| contains(body, f)))
    );
    assert!(secrets.len() > 20, "{} secrets", secrets.len());

    for (label, secret) in &secrets {
        for form in forms(secret) {
            for (i, body) in wire.iter().enumerate() {
                assert!(
                    !contains(body, &form),
                    "{label} is in body {i} the server saw (one of its forms)"
                );
            }
        }
    }
}

/// Whether `haystack` contains `needle`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Lowercase hex of `bytes`.
fn to_hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        write!(out, "{b:02x}").unwrap();
        out
    })
}

/// The base64 alphabet of RFC 4648 §4.
const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The base64url alphabet of RFC 4648 §5.
const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Unpadded base64 of `bytes` in `alphabet` ([`STANDARD`] or [`URL`]).
fn base64(alphabet: &[u8; 64], bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in bytes.chunks(3) {
        let mut word = [0u8; 3];
        word[..chunk.len()].copy_from_slice(chunk);
        let n = (u32::from(word[0]) << 16) | (u32::from(word[1]) << 8) | u32::from(word[2]);
        for i in 0..=chunk.len() {
            let index = usize::try_from((n >> (18 - 6 * i)) & 63).unwrap();
            out.push(alphabet[index]);
        }
    }
    out
}

/// Every form of `secret` the canary searches for: raw, lower- and upper-case hex, and base64
/// in the standard and URL alphabets at each of the three byte alignments, so that the secret
/// is found inside a longer encoded value too, padded or not.
fn forms(secret: &[u8]) -> Vec<Vec<u8>> {
    let hex = to_hex(secret);
    let mut out = vec![
        secret.to_vec(),
        hex.to_ascii_uppercase().into_bytes(),
        hex.into_bytes(),
    ];
    for shift in 0..3 {
        let mut shifted = vec![0u8; shift];
        shifted.extend_from_slice(secret);
        // The characters that encode only bits of the secret.
        let (start, end) = ((8 * shift).div_ceil(6), 8 * shifted.len() / 6);
        for alphabet in [STANDARD, URL] {
            out.push(base64(alphabet, &shifted)[start..end].to_vec());
        }
    }
    assert!(out.iter().all(|f| f.len() >= 8), "a needle too short");
    out
}

/// The search finds a secret in every form, inside longer values, and nothing else (a positive
/// control: a search that silently matched nothing would let the canary pass forever).
#[test]
fn the_canary_search_finds_every_form() {
    // RFC 4648 §10.
    assert_eq!(base64(STANDARD, b"foobar"), b"Zm9vYmFy");
    assert_eq!(base64(STANDARD, b"fooba"), b"Zm9vYmE");
    assert_eq!(base64(STANDARD, b"foob"), b"Zm9vYg");
    assert_eq!(base64(URL, &[0xfb, 0xff]), b"-_8");
    let secret = [0x3cu8; 32];
    for shift in 0..3 {
        let mut value = vec![0xa5u8; shift];
        value.extend_from_slice(&secret);
        value.extend_from_slice(&[0x5a; 5]);
        let hex = to_hex(&value);
        let mut padded = base64(STANDARD, &value);
        while !padded.len().is_multiple_of(4) {
            padded.push(b'=');
        }
        for haystack in [
            value.clone(),
            hex.to_ascii_uppercase().into_bytes(),
            hex.into_bytes(),
            padded,
            base64(URL, &value),
        ] {
            let haystack = [b"{\"x\":\"".as_slice(), &haystack, b"\"}"].concat();
            assert!(forms(&secret).iter().any(|f| contains(&haystack, f)));
        }
    }
    assert!(
        !forms(&secret)
            .iter()
            .any(|f| contains(b"{\"x\":\"nothing to see here\"}", f))
    );
}
