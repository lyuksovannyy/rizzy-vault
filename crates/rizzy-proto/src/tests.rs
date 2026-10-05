//! Message-level tests: known-answer JSON for representative messages, serde round trips of
//! every message type, rejection of unknown and oversize fields in requests, tolerance of
//! unknown fields in responses, and redacted `Debug` output of messages that carry secrets.
//!
//! The known-answer strings are written from RFC 4648 §10's base64 test vectors ("f" → `Zg`,
//! "fo" → `Zm8`, "foo" → `Zm9v`, "foob" → `Zm9vYg`, "foobar" → `Zm9vYmFy`) and from all-zero
//! and all-0xff bytes (`A…` and `_…`), not from this crate's encoder.

use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

use crate::account::{
    AccountStateQuery, AccountView, AckDeviceGrantsRequest, DeviceGrantsResponse,
    EnrolDeviceRequest, PublishAccountStateRequest, PublishBundlesRequest, PublishGrantsRequest,
    UploadWebDeviceCertificateRequest,
};
use crate::auth::{
    DeviceAuthFinishRequest, DeviceAuthFinishResponse, DeviceAuthStartRequest,
    DeviceAuthStartResponse, InviteToken, LoginFinishRequest, LoginFinishResponse, LoginName,
    LoginStartRequest, LoginStartResponse, Reconciliation, RecoveryRegistration,
    RegisterFinishRequest, RegisterStartRequest, RegisterStartResponse, ServerOrigin, TotpCode,
};
use crate::change::{
    CommitChangeRequest, DeviceSuspensionRequest, ReregisterStartRequest, ReregisterStartResponse,
    RetiredSecretKey, SuspendDeviceResponse, VaultRotation, VaultRotationUpload, WrapLocator,
};
use crate::error::ErrorCode;
use crate::objects::{
    AccountKeyRecoveryWrap, AccountKeyServerWrap, AccountSettings, DeviceGrant, IdentitySecretKeys,
    ItemKeyWrap, VaultSelfGrant,
};
use crate::recovery::{
    RecoveryAuthToken, RecoveryCancelResponse, RecoveryCompleteResponse, RecoveryRequest,
    RecoveryStartResponse, RecoveryVault,
};
use crate::totp::{
    TotpDisableRequest, TotpEnrolConfirmRequest, TotpEnrolStartResponse, TotpSecretBytes,
};
use crate::vault::{
    FetchRequest, FetchResponse, HealingRequest, HealingResponse, OpRecord, Record, RecordKeyWrap,
    SeqEntry, SeqVector, SnapshotRecord, UploadRequest, UploadResponse, UploadResult,
};
use crate::wire::{Bytes, Fixed, Id, List, SessionToken, WireError};

/// 22 characters: the base64url text of 16 zero bytes.
const ZERO_ID: &str = "AAAAAAAAAAAAAAAAAAAAAA";

/// Serialises `value`, parses the text back, serialises again, and checks that the two texts
/// agree: every type has one JSON form per value. Returns the text.
fn round_trip<T: Serialize + DeserializeOwned>(value: &T) -> String {
    let text = serde_json::to_string(value).unwrap();
    let parsed: T = serde_json::from_str(&text).unwrap();
    assert_eq!(serde_json::to_string(&parsed).unwrap(), text);
    text
}

/// A byte value from a slice.
fn b<const MAX: usize>(bytes: &[u8]) -> Bytes<MAX> {
    Bytes::from_slice(bytes).unwrap()
}

/// A list from a vector.
fn l<T, const MAX: usize>(items: Vec<T>) -> List<T, MAX> {
    List::new(items).unwrap()
}

/// An id filled with `byte`.
fn id(byte: u8) -> Id {
    Id::from_bytes([byte; 16])
}

/// A sample account view.
fn account_view() -> AccountView {
    AccountView {
        account_state: b(b"state"),
        bundles: l(vec![b(b"bundle-1"), b(b"bundle-2")]),
        device_certificates: l(vec![b(b"cert")]),
        device_revocations: List::empty(),
        account_settings: Some(AccountSettings {
            settings_seq: 2,
            envelope: b(b"settings"),
        }),
        identity_secret_keys: IdentitySecretKeys {
            identity_epoch: 0,
            envelope: b(b"e_id"),
        },
        vault_self_grants: l(vec![vault_self_grant()]),
    }
}

/// A sample vault self-grant.
fn vault_self_grant() -> VaultSelfGrant {
    VaultSelfGrant {
        vault_id: id(3),
        account_key_epoch: 0,
        vault_key_epoch: 0,
        envelope: b(b"grant"),
    }
}

/// A sample device grant.
fn device_grant() -> DeviceGrant {
    DeviceGrant {
        account_key_epoch: 1,
        sender_device_id: id(4),
        recipient_device_id: id(5),
        key_grant: b(b"key-grant"),
    }
}

/// A sample item-key wrap-set row.
fn item_key_wrap() -> ItemKeyWrap {
    ItemKeyWrap {
        item_id: id(6),
        item_key_id: id(7),
        vault_key_epoch: 0,
        envelope: b(b"wrap"),
    }
}

/// Sample records: a full op, a bodiless header, a snapshot with a wrap.
fn records() -> Vec<Record> {
    vec![
        Record::Op(OpRecord {
            statement: b(b"op-1"),
            body: Some(b(b"body")),
            key_wrap: Some(RecordKeyWrap {
                item_key_id: id(7),
                envelope: b(b"wrap"),
            }),
        }),
        Record::Op(OpRecord {
            statement: b(b"op-2"),
            body: None,
            key_wrap: None,
        }),
        Record::Snapshot(SnapshotRecord {
            statement: b(b"snap"),
            envelope: b(b"snapshot"),
            key_wrap: None,
        }),
    ]
}

/// A cursor with two entries.
fn cursor() -> SeqVector {
    SeqVector::new(vec![
        SeqEntry {
            device_id: id(1),
            seq: 3,
        },
        SeqEntry {
            device_id: id(2),
            seq: 1,
        },
    ])
    .unwrap()
}

#[test]
fn known_answer_login_start() {
    let request = LoginStartRequest {
        login_name: LoginName::from_str("alice").unwrap(),
        ke1: b(b"foobar"),
    };
    let json = r#"{"login_name":"alice","ke1":"Zm9vYmFy"}"#;
    assert_eq!(round_trip(&request), json);
    assert_eq!(
        serde_json::from_str::<LoginStartRequest>(json).unwrap(),
        request
    );
}

#[test]
fn known_answer_device_auth_finish() {
    let request = DeviceAuthFinishRequest {
        account_id: id(0),
        device_id: id(0xff),
        challenge: Fixed::from_bytes([0; 32]),
        signature: Fixed::from_bytes([0; 82]),
        reconciliation: None,
    };
    let json = format!(
        r#"{{"account_id":"{ZERO_ID}","device_id":"{}_w","challenge":"{}","signature":"{}"}}"#,
        "_".repeat(20),
        "A".repeat(43),
        "A".repeat(110),
    );
    assert_eq!(round_trip(&request), json);
}

#[test]
fn known_answer_upload() {
    let request = UploadRequest {
        vault_id: id(0),
        records: l(vec![
            Record::Op(OpRecord {
                statement: b(b"foo"),
                body: Some(b(b"foobar")),
                key_wrap: None,
            }),
            Record::Snapshot(SnapshotRecord {
                statement: b(b"fo"),
                envelope: b(b"f"),
                key_wrap: Some(RecordKeyWrap {
                    item_key_id: id(0),
                    envelope: b(b"foob"),
                }),
            }),
        ]),
    };
    let json = format!(
        concat!(
            r#"{{"vault_id":"{z}","records":["#,
            r#"{{"op":{{"statement":"Zm9v","body":"Zm9vYmFy"}}}},"#,
            r#"{{"snapshot":{{"statement":"Zm8","envelope":"Zg","key_wrap":{{"item_key_id":"{z}","envelope":"Zm9vYg"}}}}}}"#,
            r#"]}}"#
        ),
        z = ZERO_ID
    );
    assert_eq!(round_trip(&request), json);

    let response = UploadResponse {
        restore_generation: Fixed::from_bytes([0; 16]),
        results: l(vec![
            UploadResult::Stored,
            UploadResult::AlreadyStored,
            UploadResult::Rejected {
                error: ErrorCode::StaleEpoch,
            },
            UploadResult::NotProcessed,
        ]),
    };
    let json = format!(
        concat!(
            r#"{{"restore_generation":"{}","results":["#,
            r#"{{"result":"stored"}},{{"result":"already_stored"}},"#,
            r#"{{"result":"rejected","error":"stale_epoch"}},{{"result":"not_processed"}}]}}"#
        ),
        ZERO_ID
    );
    assert_eq!(round_trip(&response), json);
}

#[test]
fn known_answer_fetch_request() {
    let request = FetchRequest {
        vault_id: id(0),
        cursor: SeqVector::new(vec![SeqEntry {
            device_id: id(0),
            seq: 3,
        }])
        .unwrap(),
        wraps_after_epoch: None,
    };
    let json =
        format!(r#"{{"vault_id":"{ZERO_ID}","cursor":[{{"device_id":"{ZERO_ID}","seq":3}}]}}"#);
    assert_eq!(round_trip(&request), json);
}

#[test]
fn every_auth_message_round_trips() {
    round_trip(&RegisterStartResponse {
        registration_response: b(b"m2"),
        setup_id: 2,
    });
    round_trip(&RegisterFinishRequest {
        registration_upload: b(b"upload"),
        setup_id: 1,
        account_key_server_wrap: AccountKeyServerWrap {
            account_key_epoch: 0,
            password_epoch: 0,
            kdf_id: 1,
            envelope: b(b"e_srv"),
        },
        identity_secret_keys: IdentitySecretKeys {
            identity_epoch: 0,
            envelope: b(b"e_id"),
        },
        bundle: b(b"bundle"),
        account_state: b(b"state"),
        vault_self_grant: vault_self_grant(),
        device_certificate: b(b"cert"),
        recovery: Some(RecoveryRegistration {
            recovery_wrap: AccountKeyRecoveryWrap {
                account_key_epoch: 0,
                recovery_epoch: 1,
                envelope: b(b"e_rec"),
            },
            recovery_token_hash: Fixed::from_bytes([8; 32]),
        }),
    });
    round_trip(&LoginStartResponse {
        login_id: id(9),
        ke2: b(b"ke2"),
        kdf_id: 1,
        server_origin: ServerOrigin::from_str("https://vault.example").unwrap(),
    });
    round_trip(&DeviceAuthStartRequest {
        account_id: id(1),
        device_id: id(2),
        reconciliation: Some(Reconciliation {
            device_certificate: b(b"cert"),
            account_state: b(b"state"),
            bundles: l(vec![b(b"bundle")]),
            device_certificates: l(vec![b(b"cert")]),
            device_revocations: l(vec![]),
        }),
    });
    round_trip(&DeviceAuthStartResponse {
        challenge: Fixed::from_bytes([1; 32]),
    });
}

#[test]
fn every_account_and_vault_message_round_trips() {
    round_trip(&AccountStateQuery {
        known_bundle_seq: 1,
        known_settings_seq: 0,
    });
    round_trip(&account_view());
    round_trip(&EnrolDeviceRequest {
        device_certificate: b(b"cert"),
        account_state: b(b"state"),
    });
    round_trip(&UploadWebDeviceCertificateRequest {
        device_certificate: b(b"cert"),
    });
    round_trip(&DeviceGrantsResponse {
        grants: l(vec![device_grant()]),
    });
    round_trip(&AckDeviceGrantsRequest {
        account_key_epoch: 1,
    });
    round_trip(&PublishBundlesRequest {
        bundles: l(vec![b(b"bundle")]),
    });
    round_trip(&PublishAccountStateRequest {
        account_state: b(b"state"),
        device_certificates: l(vec![b(b"cert")]),
        device_revocations: l(vec![b(b"revocation")]),
        identity_secret_keys: None,
        account_settings: None,
    });
    round_trip(&PublishGrantsRequest {
        vault_self_grants: l(vec![vault_self_grant()]),
        device_grants: l(vec![device_grant()]),
    });
    round_trip(&UploadRequest {
        vault_id: id(3),
        records: l(records()),
    });
    round_trip(&FetchRequest {
        vault_id: id(3),
        cursor: cursor(),
        wraps_after_epoch: Some(0),
    });
    round_trip(&FetchResponse {
        restore_generation: Fixed::from_bytes([2; 16]),
        heads: cursor(),
        ops: l(vec![OpRecord {
            statement: b(b"op"),
            body: None,
            key_wrap: None,
        }]),
        covers: l(vec![SnapshotRecord {
            statement: b(b"snap"),
            envelope: b(b"snapshot"),
            key_wrap: None,
        }]),
        item_key_wraps: l(vec![item_key_wrap()]),
        complete: true,
    });
    round_trip(&HealingRequest {
        vault_id: id(3),
        item_key_wraps: l(vec![item_key_wrap()]),
        records: l(records()),
        self_grant: None,
    });
    round_trip(&HealingResponse {
        restore_generation: Fixed::from_bytes([2; 16]),
    });
}

#[test]
fn messages_with_secrets_round_trip() {
    let register = RegisterStartRequest {
        invite: Some(InviteToken::new("invite-7Qx").unwrap()),
        login_name: LoginName::from_str("Alice@Example.org").unwrap(),
        account_id: id(1),
        registration_request: b(b"m1"),
    };
    round_trip(&register);
    let finish = LoginFinishRequest {
        login_id: id(2),
        ke3: b(b"ke3"),
        totp: Some(TotpCode::new("123456").unwrap()),
    };
    let text = round_trip(&finish);
    assert!(text.contains(r#""totp":"123456""#));
    let response = LoginFinishResponse {
        session_token: SessionToken::new(Zeroizing::new([0xff; 32])),
        account_id: id(1),
        account_key_server_wrap: AccountKeyServerWrap {
            account_key_epoch: 0,
            password_epoch: 0,
            kdf_id: 1,
            envelope: b(b"e_srv"),
        },
        account: account_view(),
        reregister: true,
    };
    round_trip(&response);
    round_trip(&DeviceAuthFinishResponse {
        session_token: SessionToken::new(Zeroizing::new([1; 32])),
        session_id: id(4),
        reregister: false,
    });
}

#[test]
fn debug_output_never_shows_secrets() {
    let register = RegisterStartRequest {
        invite: Some(InviteToken::new("INVITE-SECRET").unwrap()),
        login_name: LoginName::from_str("alice@example.org").unwrap(),
        account_id: id(1),
        registration_request: b(b"OPAQUE-M1"),
    };
    let finish = LoginFinishRequest {
        login_id: id(2),
        ke3: b(b"OPAQUE-KE3"),
        totp: Some(TotpCode::new("987654").unwrap()),
    };
    let response = DeviceAuthFinishResponse {
        session_token: SessionToken::new(Zeroizing::new([0xab; 32])),
        session_id: id(4),
        reregister: false,
    };
    let token_text = response.session_token.to_b64url();
    let shown = format!("{register:?} {finish:?} {response:?}");
    for secret in [
        "INVITE-SECRET",
        "alice",
        "OPAQUE",
        "987654",
        token_text.as_str(),
        "abababab",
    ] {
        assert!(!shown.contains(secret), "{secret} in {shown}");
    }
}

#[test]
fn requests_reject_unknown_fields() {
    // CRYPTO.md §11.1 step 8: no field can carry E_dev; an unknown field fails the request.
    let finish = serde_json::to_value(RegisterFinishRequest {
        registration_upload: b(b"upload"),
        setup_id: 1,
        account_key_server_wrap: AccountKeyServerWrap {
            account_key_epoch: 0,
            password_epoch: 0,
            kdf_id: 1,
            envelope: b(b"e_srv"),
        },
        identity_secret_keys: IdentitySecretKeys {
            identity_epoch: 0,
            envelope: b(b"e_id"),
        },
        bundle: b(b"bundle"),
        account_state: b(b"state"),
        vault_self_grant: vault_self_grant(),
        device_certificate: b(b"cert"),
        recovery: None,
    })
    .unwrap();
    assert!(serde_json::from_value::<RegisterFinishRequest>(finish.clone()).is_ok());
    let mut with_e_dev = finish.clone();
    with_e_dev["e_dev"] = "Zm9v".into();
    assert!(serde_json::from_value::<RegisterFinishRequest>(with_e_dev).is_err());
    // Nested objects of a request reject unknown fields too.
    let mut nested = finish;
    nested["vault_self_grant"]["e_dev"] = "Zm9v".into();
    assert!(serde_json::from_value::<RegisterFinishRequest>(nested).is_err());

    // `H_rec` is not a field of `E_rec`'s type, so a response reusing it cannot carry `H_rec`.
    let wrap = serde_json::to_value(AccountKeyRecoveryWrap {
        account_key_epoch: 0,
        recovery_epoch: 1,
        envelope: b(b"e_rec"),
    })
    .unwrap();
    assert!(wrap.get("recovery_token_hash").is_none());
    let mut with_h_rec = wrap;
    with_h_rec["recovery_token_hash"] = "A".repeat(43).into();
    assert!(serde_json::from_value::<AccountKeyRecoveryWrap>(with_h_rec).is_err());

    let base = format!(r#""vault_id":"{ZERO_ID}","cursor":[]"#);
    assert!(serde_json::from_str::<FetchRequest>(&format!("{{{base}}}")).is_ok());
    assert!(serde_json::from_str::<FetchRequest>(&format!(r#"{{{base},"x":1}}"#)).is_err());
    // Missing and duplicate fields.
    assert!(serde_json::from_str::<LoginStartRequest>(r#"{"login_name":"alice"}"#).is_err());
    assert!(
        serde_json::from_str::<LoginStartRequest>(
            r#"{"login_name":"alice","ke1":"Zg","ke1":"Zg"}"#
        )
        .is_err()
    );
    // An unknown record kind.
    let upload = format!(r#"{{"vault_id":"{ZERO_ID}","records":[{{"relay":{{}}}}]}}"#);
    assert!(serde_json::from_str::<UploadRequest>(&upload).is_err());
}

#[test]
fn responses_ignore_unknown_fields() {
    let mut value = serde_json::to_value(FetchResponse {
        restore_generation: Fixed::from_bytes([2; 16]),
        heads: SeqVector::default(),
        ops: List::empty(),
        covers: List::empty(),
        item_key_wraps: List::empty(),
        complete: false,
    })
    .unwrap();
    value["added_later"] = serde_json::json!({"a": [1, 2]});
    assert!(serde_json::from_value::<FetchResponse>(value).is_ok());
    let mut view = serde_json::to_value(account_view()).unwrap();
    view["added_later"] = true.into();
    assert!(serde_json::from_value::<AccountView>(view).is_ok());
}

#[test]
fn oversize_fields_are_rejected() {
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    let json = |ke1: &[u8]| {
        format!(
            r#"{{"login_name":"alice","ke1":"{}"}}"#,
            Base64UrlUnpadded::encode_string(ke1)
        )
    };
    assert!(serde_json::from_str::<LoginStartRequest>(&json(&[0; 512])).is_ok());
    assert!(serde_json::from_str::<LoginStartRequest>(&json(&[0; 513])).is_err());
    assert!(serde_json::from_str::<LoginStartRequest>(&json(&[])).is_err());

    let name = |n: usize| format!(r#"{{"login_name":"{}","ke1":"Zg"}}"#, "a".repeat(n));
    assert!(serde_json::from_str::<LoginStartRequest>(&name(254)).is_ok());
    assert!(serde_json::from_str::<LoginStartRequest>(&name(255)).is_err());

    // A count limit: 1,025 bundles.
    let bundles = vec!["\"Zg\""; 1025].join(",");
    let publish = format!(r#"{{"bundles":[{bundles}]}}"#);
    assert!(serde_json::from_str::<PublishBundlesRequest>(&publish).is_err());
    let bundles = vec!["\"Zg\""; 1024].join(",");
    let publish = format!(r#"{{"bundles":[{bundles}]}}"#);
    assert!(serde_json::from_str::<PublishBundlesRequest>(&publish).is_ok());

    // An account statement over 1 KiB.
    let state = Base64UrlUnpadded::encode_string(&[0; 1025]);
    let enrol = format!(r#"{{"device_certificate":"Zg","account_state":"{state}"}}"#);
    assert!(serde_json::from_str::<EnrolDeviceRequest>(&enrol).is_err());

    // The kind-4 certificate upload carries one bounded certificate and nothing else.
    let web = |cert: &str, extra: &str| format!(r#"{{"device_certificate":"{cert}"{extra}}}"#);
    let at_limit = Base64UrlUnpadded::encode_string(&[0; 1024]);
    assert!(serde_json::from_str::<UploadWebDeviceCertificateRequest>(&web(&at_limit, "")).is_ok());
    assert!(serde_json::from_str::<UploadWebDeviceCertificateRequest>(&web(&state, "")).is_err());
    assert!(
        serde_json::from_str::<UploadWebDeviceCertificateRequest>(&web(
            "Zg",
            r#","account_state":"Zg""#
        ))
        .is_err()
    );

    // A signature container must be exactly 82 bytes.
    let sig = |n: usize| {
        format!(
            r#"{{"account_id":"{ZERO_ID}","device_id":"{ZERO_ID}","challenge":"{}","signature":"{}"}}"#,
            "A".repeat(43),
            Base64UrlUnpadded::encode_string(&vec![0; n])
        )
    };
    assert!(serde_json::from_str::<DeviceAuthFinishRequest>(&sig(82)).is_ok());
    assert!(serde_json::from_str::<DeviceAuthFinishRequest>(&sig(81)).is_err());
    assert!(serde_json::from_str::<DeviceAuthFinishRequest>(&sig(83)).is_err());
}

#[test]
fn seq_vectors_are_canonical() {
    let entry = |d: u8, seq: u64| SeqEntry {
        device_id: id(d),
        seq,
    };
    assert!(SeqVector::new(vec![entry(1, 1), entry(2, 5)]).is_ok());
    assert_eq!(
        SeqVector::new(vec![entry(2, 1), entry(1, 1)]),
        Err(WireError::NotCanonical)
    );
    assert_eq!(
        SeqVector::new(vec![entry(1, 1), entry(1, 2)]),
        Err(WireError::NotCanonical)
    );
    assert_eq!(
        SeqVector::new(vec![entry(1, 0)]),
        Err(WireError::NotCanonical)
    );
    let v = cursor();
    assert_eq!(v.get(&id(1)), 3);
    assert_eq!(v.get(&id(2)), 1);
    assert_eq!(v.get(&id(9)), 0);

    let zero =
        format!(r#"{{"vault_id":"{ZERO_ID}","cursor":[{{"device_id":"{ZERO_ID}","seq":0}}]}}"#);
    assert!(serde_json::from_str::<FetchRequest>(&zero).is_err());
    let twice = format!(
        r#"{{"vault_id":"{ZERO_ID}","cursor":[{{"device_id":"{ZERO_ID}","seq":1}},{{"device_id":"{ZERO_ID}","seq":2}}]}}"#
    );
    assert!(serde_json::from_str::<FetchRequest>(&twice).is_err());
}

/// A sample commit: a password change with a new recovery code.
fn commit_change() -> CommitChangeRequest {
    CommitChangeRequest {
        account_state: b(b"state"),
        registration_upload: Some(b(b"upload")),
        setup_id: Some(2),
        account_key_server_wrap: Some(AccountKeyServerWrap {
            account_key_epoch: 0,
            password_epoch: 1,
            kdf_id: 1,
            envelope: b(b"e_srv"),
        }),
        recovery: Some(RecoveryRegistration {
            recovery_wrap: AccountKeyRecoveryWrap {
                account_key_epoch: 0,
                recovery_epoch: 2,
                envelope: b(b"e_rec"),
            },
            recovery_token_hash: Fixed::from_bytes([8; 32]),
        }),
        account_settings: None,
        device_certificates: l(vec![b(b"cert")]),
        device_revocations: List::empty(),
        ..bare_commit(b"state")
    }
}

#[test]
fn known_answer_change_recovery_and_totp() {
    let suspend = DeviceSuspensionRequest { device_id: id(0) };
    assert_eq!(
        round_trip(&suspend),
        format!(r#"{{"device_id":"{ZERO_ID}"}}"#)
    );
    assert_eq!(
        round_trip(&SuspendDeviceResponse {
            last_accepted_device_seq: 7
        }),
        r#"{"last_accepted_device_seq":7}"#
    );
    let commit = CommitChangeRequest {
        account_state: b(b"foobar"),
        registration_upload: None,
        setup_id: None,
        account_key_server_wrap: None,
        recovery: None,
        account_settings: Some(AccountSettings {
            settings_seq: 1,
            envelope: b(b"foo"),
        }),
        device_certificates: List::empty(),
        device_revocations: List::empty(),
        ..bare_commit(b"foobar")
    };
    assert_eq!(
        round_trip(&commit),
        concat!(
            r#"{"account_state":"Zm9vYmFy","account_settings":{"settings_seq":1,"envelope":"Zm9v"},"#,
            r#""device_certificates":[],"device_revocations":[]}"#
        )
    );
    let recovery = RecoveryRequest {
        login_name: LoginName::from_str("alice").unwrap(),
        recovery_auth_token: RecoveryAuthToken::new(Zeroizing::new([0; 32])),
    };
    assert_eq!(
        round_trip(&recovery),
        format!(
            r#"{{"login_name":"alice","recovery_auth_token":"{}"}}"#,
            "A".repeat(43)
        )
    );
    let confirm = TotpEnrolConfirmRequest {
        totp_credential_seq: 1,
        code: TotpCode::new("123456").unwrap(),
    };
    assert_eq!(
        round_trip(&confirm),
        r#"{"totp_credential_seq":1,"code":"123456"}"#
    );
    let enrol = TotpEnrolStartResponse {
        totp_credential_seq: 1,
        secret: TotpSecretBytes::new(Zeroizing::new([0xff; 20])),
    };
    assert_eq!(
        round_trip(&enrol),
        // 20 bytes of 0xff: 26 full characters, then `8` (the last 4 bits are zero).
        format!(
            r#"{{"totp_credential_seq":1,"secret":"{}8"}}"#,
            "_".repeat(26)
        )
    );
}

#[test]
fn every_change_recovery_and_totp_message_round_trips() {
    round_trip(&ReregisterStartRequest {
        registration_request: b(b"m1"),
    });
    round_trip(&ReregisterStartResponse {
        registration_response: b(b"m2"),
        setup_id: 2,
    });
    round_trip(&commit_change());
    round_trip(&RecoveryStartResponse {
        available_at_ms: 1_790_000_000_000,
    });
    round_trip(&RecoveryCancelResponse { cancelled: true });
    round_trip(&RecoveryCompleteResponse {
        session_token: SessionToken::new(Zeroizing::new([3; 32])),
        account_id: id(1),
        recovery_wrap: AccountKeyRecoveryWrap {
            account_key_epoch: 0,
            recovery_epoch: 1,
            envelope: b(b"e_rec"),
        },
        account: account_view(),
        vaults: l(vec![recovery_vault()]),
    });
    round_trip(&TotpDisableRequest {
        code: TotpCode::new("000000").unwrap(),
    });
}

#[test]
fn change_recovery_and_totp_requests_are_strict() {
    // No field can carry a device-only secret, a new Secret Key, a recovery code or a key.
    let commit = serde_json::to_value(commit_change()).unwrap();
    assert!(serde_json::from_value::<CommitChangeRequest>(commit.clone()).is_ok());
    for field in [
        "e_dev",
        "secret_key",
        "recovery_code",
        "account_key",
        "vault_key",
    ] {
        let mut extra = commit.clone();
        extra[field] = "Zm9v".into();
        assert!(
            serde_json::from_value::<CommitChangeRequest>(extra).is_err(),
            "{field}"
        );
    }
    let mut nested = commit.clone();
    nested["recovery"]["recovery_wrap"]["e_dev"] = "Zm9v".into();
    assert!(serde_json::from_value::<CommitChangeRequest>(nested).is_err());
    // The device lists are required, and bounded.
    let mut missing = commit;
    missing
        .as_object_mut()
        .unwrap()
        .remove("device_revocations");
    assert!(serde_json::from_value::<CommitChangeRequest>(missing).is_err());
    let certs = vec!["\"Zg\""; 4097].join(",");
    let over = format!(
        r#"{{"account_state":"Zg","device_certificates":[{certs}],"device_revocations":[]}}"#
    );
    assert!(serde_json::from_str::<CommitChangeRequest>(&over).is_err());

    // The recovery auth token is exactly 32 bytes; the name follows §2.
    let recovery = |name: &str, token: &str| {
        format!(r#"{{"login_name":"{name}","recovery_auth_token":"{token}"}}"#)
    };
    let token = "A".repeat(43);
    assert!(serde_json::from_str::<RecoveryRequest>(&recovery("ivy", &token)).is_ok());
    assert!(serde_json::from_str::<RecoveryRequest>(&recovery("ivy", &"A".repeat(42))).is_err());
    assert!(serde_json::from_str::<RecoveryRequest>(&recovery("ivy", &"A".repeat(44))).is_err());
    assert!(serde_json::from_str::<RecoveryRequest>(&recovery("i y", &token)).is_err());
    assert!(
        serde_json::from_str::<RecoveryRequest>(&format!(
            r#"{{"login_name":"ivy","recovery_auth_token":"{token}","code":"x"}}"#
        ))
        .is_err()
    );
    assert!(
        serde_json::from_str::<DeviceSuspensionRequest>(&format!(
            r#"{{"device_id":"{ZERO_ID}","account_id":"{ZERO_ID}"}}"#
        ))
        .is_err()
    );
    assert!(
        serde_json::from_str::<TotpEnrolConfirmRequest>(
            r#"{"totp_credential_seq":1,"code":"12345a"}"#
        )
        .is_err()
    );
    assert!(serde_json::from_str::<TotpDisableRequest>(r#"{"code":"123456789"}"#).is_err());
}

#[test]
fn change_recovery_and_totp_debug_output_never_shows_secrets() {
    let recovery = RecoveryRequest {
        login_name: LoginName::from_str("alice@example.org").unwrap(),
        recovery_auth_token: RecoveryAuthToken::new(Zeroizing::new([0xcd; 32])),
    };
    let token_text = recovery.recovery_auth_token.to_b64url();
    let enrol = TotpEnrolStartResponse {
        totp_credential_seq: 1,
        secret: TotpSecretBytes::new(Zeroizing::new([0xef; 20])),
    };
    let secret_text = enrol.secret.to_b64url();
    let complete = RecoveryCompleteResponse {
        session_token: SessionToken::new(Zeroizing::new([0xab; 32])),
        account_id: id(1),
        recovery_wrap: AccountKeyRecoveryWrap {
            account_key_epoch: 0,
            recovery_epoch: 1,
            envelope: b(b"E-REC-BYTES"),
        },
        account: account_view(),
        vaults: List::empty(),
    };
    let session_text = complete.session_token.to_b64url();
    let confirm = TotpEnrolConfirmRequest {
        totp_credential_seq: 1,
        code: TotpCode::new("987654").unwrap(),
    };
    let shown = format!("{recovery:?} {enrol:?} {complete:?} {confirm:?}");
    for secret in [
        "alice",
        token_text.as_str(),
        secret_text.as_str(),
        session_text.as_str(),
        "987654",
        "cdcdcd",
        "efefef",
        "ababab",
    ] {
        assert!(!shown.contains(secret), "{secret} in {shown}");
    }
}

/// A commit with only its required fields and `state`.
fn bare_commit(state: &[u8]) -> CommitChangeRequest {
    CommitChangeRequest {
        account_state: b(state),
        registration_upload: None,
        setup_id: None,
        account_key_server_wrap: None,
        recovery: None,
        account_settings: None,
        device_certificates: List::empty(),
        device_revocations: List::empty(),
        bundle: None,
        identity_secret_keys: None,
        retired_secret_keys: List::empty(),
        device_grants: List::empty(),
        recovery_rewrap: None,
        vault_rotation: None,
    }
}

/// A sample self-grant of vault `vault`.
fn self_grant(vault: u8) -> VaultSelfGrant {
    VaultSelfGrant {
        vault_id: id(vault),
        account_key_epoch: 1,
        vault_key_epoch: 1,
        envelope: b(b"grant"),
    }
}

/// A sample wrap-set row at epoch 1.
fn wrap(item: u8) -> ItemKeyWrap {
    ItemKeyWrap {
        item_id: id(item),
        item_key_id: id(item.wrapping_add(100)),
        vault_key_epoch: 1,
        envelope: b(b"wrap"),
    }
}

/// A sample vault half of vault `vault`.
fn vault_rotation(vault: u8) -> VaultRotation {
    VaultRotation {
        self_grant: self_grant(vault),
        cursor: SeqVector::new(vec![SeqEntry {
            device_id: id(1),
            seq: 3,
        }])
        .unwrap(),
        item_key_wraps: l(vec![wrap(1)]),
        dropped: l(vec![WrapLocator {
            item_id: id(2),
            item_key_id: id(102),
        }]),
    }
}

/// A sample vault of a recovery answer.
fn recovery_vault() -> RecoveryVault {
    RecoveryVault {
        vault_id: id(4),
        self_grant: self_grant(4),
        heads: SeqVector::default(),
        item_key_wraps: l(vec![wrap(1)]),
    }
}

/// A sample full rotation with every rotation field.
fn rotation_commit() -> CommitChangeRequest {
    CommitChangeRequest {
        account_key_server_wrap: Some(AccountKeyServerWrap {
            account_key_epoch: 1,
            password_epoch: 0,
            kdf_id: 1,
            envelope: b(b"e_srv"),
        }),
        bundle: Some(b(b"bundle")),
        identity_secret_keys: Some(IdentitySecretKeys {
            identity_epoch: 1,
            envelope: b(b"e_id"),
        }),
        retired_secret_keys: l(vec![RetiredSecretKey {
            retired_key_id: id(9),
            envelope: b(b"retired"),
        }]),
        device_grants: l(vec![DeviceGrant {
            account_key_epoch: 1,
            sender_device_id: id(1),
            recipient_device_id: id(2),
            key_grant: b(b"grant"),
        }]),
        recovery_rewrap: Some(AccountKeyRecoveryWrap {
            account_key_epoch: 1,
            recovery_epoch: 1,
            envelope: b(b"e_rec"),
        }),
        vault_rotation: Some(
            VaultRotationUpload::new(vec![vault_rotation(3), vault_rotation(4)]).unwrap(),
        ),
        ..bare_commit(b"state")
    }
}

#[test]
fn rotation_fields_round_trip_and_are_left_out_when_absent() {
    let text = round_trip(&rotation_commit());
    for field in [
        "\"bundle\"",
        "\"identity_secret_keys\"",
        "\"retired_secret_keys\"",
        "\"device_grants\"",
        "\"recovery_rewrap\"",
        "\"vault_rotation\"",
        "\"cursor\"",
        "\"dropped\"",
    ] {
        assert!(text.contains(field), "{field}");
    }
    // A commit without a rotation sends none of them (additive fields, ADR 0025 §1).
    let plain = round_trip(&bare_commit(b"foo"));
    assert_eq!(
        plain,
        r#"{"account_state":"Zm9v","device_certificates":[],"device_revocations":[]}"#
    );
    // Empty lists sent explicitly parse, and serialise without them.
    let explicit = r#"{"account_state":"Zm9v","device_certificates":[],"device_revocations":[],"device_grants":[],"retired_secret_keys":[]}"#;
    let parsed: CommitChangeRequest = serde_json::from_str(explicit).unwrap();
    assert_eq!(serde_json::to_string(&parsed).unwrap(), plain);
}

#[test]
fn vault_rotation_is_ordered_bounded_and_strict() {
    // Strictly ascending by vault id: a duplicate or a wrong order is refused both ways.
    assert_eq!(
        VaultRotationUpload::new(vec![vault_rotation(4), vault_rotation(3)]),
        Err(WireError::NotCanonical)
    );
    assert_eq!(
        VaultRotationUpload::new(vec![vault_rotation(3), vault_rotation(3)]),
        Err(WireError::NotCanonical)
    );
    let good = serde_json::to_value(rotation_commit()).unwrap();
    let mut swapped = good.clone();
    swapped["vault_rotation"]["vaults"]
        .as_array_mut()
        .unwrap()
        .reverse();
    assert!(serde_json::from_value::<CommitChangeRequest>(swapped).is_err());
    // Unknown fields are refused at every level of the vault half.
    for path in [
        &["vault_rotation"][..],
        &["vault_rotation", "vaults", "0"],
        &["vault_rotation", "vaults", "0", "self_grant"],
        &["vault_rotation", "vaults", "0", "item_key_wraps", "0"],
        &["vault_rotation", "vaults", "0", "dropped", "0"],
        &["retired_secret_keys", "0"],
    ] {
        let mut extra = good.clone();
        let mut at = &mut extra;
        for key in path {
            at = match key.parse::<usize>() {
                Ok(i) => &mut at[i],
                Err(_) => &mut at[*key],
            };
        }
        at["vault_key"] = "Zm9v".into();
        assert!(
            serde_json::from_value::<CommitChangeRequest>(extra).is_err(),
            "{path:?}"
        );
    }
    // A cursor must be canonical.
    let mut zero = good.clone();
    zero["vault_rotation"]["vaults"][0]["cursor"][0]["seq"] = 0.into();
    assert!(serde_json::from_value::<CommitChangeRequest>(zero).is_err());
    // At most 16 retired keys.
    let mut many = good;
    let one = many["retired_secret_keys"][0].clone();
    many["retired_secret_keys"] = serde_json::Value::Array(vec![one; 17]);
    assert!(serde_json::from_value::<CommitChangeRequest>(many).is_err());
}

#[test]
fn recovery_complete_carries_vaults_and_ignores_unknown_fields() {
    let complete = RecoveryCompleteResponse {
        session_token: SessionToken::new(Zeroizing::new([3; 32])),
        account_id: id(1),
        recovery_wrap: AccountKeyRecoveryWrap {
            account_key_epoch: 0,
            recovery_epoch: 1,
            envelope: b(b"e_rec"),
        },
        account: account_view(),
        vaults: l(vec![recovery_vault()]),
    };
    let mut value = serde_json::to_value(&complete).unwrap();
    value["vaults"][0]["later"] = 1.into();
    value["later"] = 1.into();
    let parsed: RecoveryCompleteResponse = serde_json::from_value(value).unwrap();
    assert_eq!(parsed.vaults.as_slice(), complete.vaults.as_slice());
}

#[test]
fn setup_fields_of_adr_0031() {
    // `reregister` is additive: an answer without it reads as `false` (ADR 0031 point 2).
    let response = DeviceAuthFinishResponse {
        session_token: SessionToken::new(Zeroizing::new([1; 32])),
        session_id: id(4),
        reregister: true,
    };
    let mut json = serde_json::to_value(&response).unwrap();
    assert_eq!(json["reregister"], true);
    json.as_object_mut().unwrap().remove("reregister");
    let back: DeviceAuthFinishResponse = serde_json::from_value(json).unwrap();
    assert!(!back.reregister);
    // The echoed `setup_id` travels with the upload and is absent without one (point 3).
    let with = serde_json::to_value(commit_change()).unwrap();
    assert_eq!(with["setup_id"], 2);
    let without = serde_json::to_value(bare_commit(b"state")).unwrap();
    assert!(without.get("setup_id").is_none());
    assert_eq!(
        serde_json::to_string(&crate::error::ErrorResponse::new(ErrorCode::SetupRetired)).unwrap(),
        r#"{"error":"setup_retired"}"#
    );
}

#[test]
fn healing_fields_of_adr_0032() {
    // Step 2 carries `E_id` and the settings as optional fields: absent when `None`, and an
    // older request without them still parses (ADR 0032 §2).
    let bare = PublishAccountStateRequest {
        account_state: b(b"state"),
        device_certificates: l(vec![b(b"cert")]),
        device_revocations: List::empty(),
        identity_secret_keys: None,
        account_settings: None,
    };
    let json = serde_json::to_value(&bare).unwrap();
    assert!(json.get("identity_secret_keys").is_none());
    assert!(json.get("account_settings").is_none());
    let full = PublishAccountStateRequest {
        identity_secret_keys: Some(IdentitySecretKeys {
            identity_epoch: 1,
            envelope: b(b"e_id"),
        }),
        account_settings: Some(AccountSettings {
            settings_seq: 2,
            envelope: b(b"settings"),
        }),
        ..bare
    };
    round_trip(&full);
    // Step 3b: a healing request with a self-grant and no records (§2); `self_grant` is absent
    // when `None`.
    let step_3b = HealingRequest {
        vault_id: id(3),
        item_key_wraps: l(vec![item_key_wrap()]),
        records: List::empty(),
        self_grant: Some(vault_self_grant()),
    };
    round_trip(&step_3b);
    let plain = HealingRequest {
        self_grant: None,
        ..step_3b
    };
    assert!(
        serde_json::to_value(&plain)
            .unwrap()
            .get("self_grant")
            .is_none()
    );
    // The new `409` code (ADR 0028 item 3 as ADR 0032 amends it).
    assert_eq!(
        serde_json::to_string(&crate::error::ErrorResponse::new(
            ErrorCode::CredentialsStale
        ))
        .unwrap(),
        r#"{"error":"credentials_stale"}"#
    );
}
