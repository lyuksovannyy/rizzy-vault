// SPDX-License-Identifier: AGPL-3.0-only

//! Known answers and parsing rules of ADR 0090 §7 (§14 step 1). The known-answer strings are
//! written from all-zero and all-0xff ids (`A…` and `_…`), not from this crate's encoder.

use std::fmt::Write as _;

use super::*;

const ZERO: &str = "AAAAAAAAAAAAAAAAAAAAAA";
const FF: &str = "_____________________w";

fn id(n: u8) -> Id {
    Id::from_bytes([n; 16])
}

/// The ADR's §3 table, in code order.
const NAMES: [&str; 27] = [
    "account_created",
    "password_login",
    "second_factor_failed",
    "device_enrolled",
    "device_suspended",
    "device_unsuspended",
    "device_revoked",
    "credentials_changed",
    "account_key_rotated",
    "identity_rotated",
    "recovery_code_changed",
    "recovery_disabled",
    "recovery_started",
    "recovery_cancelled",
    "recovery_session_opened",
    "recovery_completed",
    "totp_enabled",
    "totp_disabled",
    "security_key_added",
    "security_key_removed",
    "security_key_possible_clone",
    "session_ended",
    "other_sessions_ended",
    "recovery_wait_changed",
    "account_disabled",
    "account_enabled",
    "second_factor_reset_by_admin",
];

/// The §3 classes, in code order (code 24 for a longer wait).
const ALERT: [bool; 27] = [
    false, false, true, true, false, true, false, true, false, false, true, true, true, false,
    true, true, true, true, true, true, true, false, false, false, true, true, true,
];

#[test]
fn every_kind_has_its_code_name_and_class() {
    assert_eq!(SecurityEventKind::ALL.len(), 27);
    for (i, kind) in SecurityEventKind::ALL.iter().enumerate() {
        let code = u16::try_from(i + 1).unwrap();
        assert_eq!(kind.code(), Some(code));
        assert_eq!(SecurityEventKind::from_code(code), Some(*kind));
        assert_eq!(
            serde_json::to_string(kind).unwrap(),
            format!("\"{}\"", NAMES[i])
        );
        let class = kind.class(Some(10), Some(20));
        assert_eq!(class == SecurityEventClass::Alert, ALERT[i], "{}", NAMES[i]);
    }
    assert_eq!(SecurityEventKind::from_code(0), None);
    assert_eq!(SecurityEventKind::from_code(28), None);
    assert_eq!(SecurityEventKind::Unknown.code(), None);
    // Code 24 is an alert only when the wait got shorter.
    let wait = SecurityEventKind::RecoveryWaitChanged;
    assert_eq!(wait.class(Some(20), Some(10)), SecurityEventClass::Alert);
    assert_eq!(wait.class(Some(10), Some(10)), SecurityEventClass::Info);
    assert_eq!(wait.class(None, Some(10)), SecurityEventClass::Info);
}

#[test]
fn actor_kinds_and_classes_have_their_codes() {
    let names = [
        "opaque_session",
        "device_session",
        "recovery_session",
        "recovery_code",
        "sign_in",
        "admin_panel",
        "operator_cli",
        "server",
    ];
    assert_eq!(SecurityEventActorKind::ALL.len(), names.len());
    for (i, kind) in SecurityEventActorKind::ALL.iter().enumerate() {
        let code = u8::try_from(i + 1).unwrap();
        assert_eq!(kind.code(), Some(code));
        assert_eq!(SecurityEventActorKind::from_code(code), Some(*kind));
        assert_eq!(
            serde_json::to_string(kind).unwrap(),
            format!("\"{}\"", names[i])
        );
    }
    assert_eq!(SecurityEventActorKind::from_code(9), None);
    assert_eq!(SecurityEventClass::Info.code(), Some(1));
    assert_eq!(SecurityEventClass::Alert.code(), Some(2));
    assert_eq!(SecurityEventClass::from_code(3), None);
}

#[test]
fn known_answer_request() {
    let req = SecurityEventListRequest {
        before: Some(SecurityEventCursor {
            at_ms: 7,
            event_id: id(0xff),
        }),
        limit: Some(100),
    };
    let text = format!(r#"{{"before":{{"at_ms":7,"event_id":"{FF}"}},"limit":100}}"#);
    assert_eq!(serde_json::to_string(&req).unwrap(), text);
    assert_eq!(
        serde_json::from_str::<SecurityEventListRequest>(&text).unwrap(),
        req
    );
    let empty = SecurityEventListRequest {
        before: None,
        limit: None,
    };
    assert_eq!(serde_json::to_string(&empty).unwrap(), "{}");
    assert_eq!(
        serde_json::from_str::<SecurityEventListRequest>("{}").unwrap(),
        empty
    );
}

#[test]
fn requests_are_strict() {
    let parse = |s: &str| serde_json::from_str::<SecurityEventListRequest>(s);
    assert!(parse(r#"{"limit":1}"#).is_ok());
    assert!(parse(r#"{"limit":0}"#).is_err());
    assert!(parse(r#"{"limit":101}"#).is_err());
    assert!(parse(r#"{"limit":-1}"#).is_err());
    assert!(parse(r#"{"limit":4294967296}"#).is_err());
    assert!(parse(r#"{"limit":null}"#).is_err());
    assert!(parse(r#"{"account_id":"AAAAAAAAAAAAAAAAAAAAAA"}"#).is_err());
    assert!(
        parse(&format!(
            r#"{{"before":{{"at_ms":1,"event_id":"{ZERO}","x":1}}}}"#
        ))
        .is_err()
    );
    assert!(parse(r#"{"before":{"at_ms":1}}"#).is_err());
}

fn view(kind: SecurityEventKind) -> SecurityEventView {
    SecurityEventView {
        event_id: id(0),
        at_ms: 1,
        kind,
        class: kind.class(None, None),
        actor: SecurityEventActor {
            kind: SecurityEventActorKind::SignIn,
            device_id: None,
        },
        subject_device_id: None,
        label: None,
        value_old: None,
        value_new: None,
        state_seq: None,
    }
}

#[test]
fn known_answer_response_with_every_kind() {
    let mut events: Vec<SecurityEventView> =
        SecurityEventKind::ALL.iter().map(|k| view(*k)).collect();
    events[20] = SecurityEventView {
        event_id: id(0xff),
        at_ms: 1_761_400_000_000,
        kind: SecurityEventKind::SecurityKeyPossibleClone,
        class: SecurityEventClass::Alert,
        actor: SecurityEventActor {
            kind: SecurityEventActorKind::DeviceSession,
            device_id: Some(id(0)),
        },
        subject_device_id: Some(id(0xff)),
        label: Some(WebauthnLabel::new("YubiKey 5C".into()).unwrap()),
        value_old: Some(41),
        value_new: Some(12),
        state_seq: Some(3),
    };
    let response = SecurityEventListResponse {
        events: List::new(events).unwrap(),
        more: true,
    };
    let mut expected = String::from(r#"{"events":["#);
    for (i, name) in NAMES.iter().enumerate() {
        if i > 0 {
            expected.push(',');
        }
        if i == 20 {
            expected.push_str(&format!(
                concat!(
                    r#"{{"event_id":"{FF}","at_ms":1761400000000,"kind":"security_key_possible_clone","#,
                    r#""class":"alert","actor":{{"kind":"device_session","device_id":"{ZERO}"}},"#,
                    r#""subject_device_id":"{FF}","label":"YubiKey 5C","value_old":41,"value_new":12,"#,
                    r#""state_seq":3}}"#
                ),
                FF = FF,
                ZERO = ZERO
            ));
        } else {
            let class = if ALERT[i] { "alert" } else { "info" };
            write!(
                expected,
                r#"{{"event_id":"{ZERO}","at_ms":1,"kind":"{name}","class":"{class}","actor":{{"kind":"sign_in"}}}}"#
            )
            .unwrap();
        }
    }
    expected.push_str(r#"],"more":true}"#);
    assert_eq!(serde_json::to_string(&response).unwrap(), expected);
    assert_eq!(
        serde_json::from_str::<SecurityEventListResponse>(&expected).unwrap(),
        response
    );
}

#[test]
fn known_answer_summary() {
    let summary = SecurityAlertSummary {
        count: 2,
        newest_event_id: id(0),
        newest_at_ms: 5,
        newest_kind: SecurityEventKind::DeviceEnrolled,
    };
    let text = format!(
        r#"{{"count":2,"newest_event_id":"{ZERO}","newest_at_ms":5,"newest_kind":"device_enrolled"}}"#
    );
    assert_eq!(serde_json::to_string(&summary).unwrap(), text);
    assert_eq!(
        serde_json::from_str::<SecurityAlertSummary>(&text).unwrap(),
        summary
    );
}

#[test]
fn responses_tolerate_unknown_values_and_fields() {
    let text = format!(
        r#"{{"events":[{{"event_id":"{ZERO}","at_ms":1,"kind":"from_the_future","class":"critical","actor":{{"kind":"robot","x":1}},"y":2}}],"more":false,"z":3}}"#
    );
    let parsed = serde_json::from_str::<SecurityEventListResponse>(&text).unwrap();
    let event = &parsed.events.as_slice()[0];
    assert_eq!(event.kind, SecurityEventKind::Unknown);
    assert_eq!(event.class, SecurityEventClass::Unknown);
    assert_eq!(event.actor.kind, SecurityEventActorKind::Unknown);
    let summary = format!(
        r#"{{"count":1,"newest_event_id":"{ZERO}","newest_at_ms":1,"newest_kind":"nope"}}"#
    );
    assert_eq!(
        serde_json::from_str::<SecurityAlertSummary>(&summary)
            .unwrap()
            .newest_kind,
        SecurityEventKind::Unknown
    );
}

#[test]
fn a_list_above_the_limit_fails_to_parse() {
    let one = format!(
        r#"{{"event_id":"{ZERO}","at_ms":1,"kind":"password_login","class":"info","actor":{{"kind":"sign_in"}}}}"#
    );
    let list = |n: usize| {
        format!(
            r#"{{"events":[{}],"more":false}}"#,
            vec![one.as_str(); n].join(",")
        )
    };
    assert!(serde_json::from_str::<SecurityEventListResponse>(&list(100)).is_ok());
    assert!(serde_json::from_str::<SecurityEventListResponse>(&list(101)).is_err());
    // A label above 64 bytes is refused, as everywhere else.
    let long = format!(
        r#"{{"events":[{{"event_id":"{ZERO}","at_ms":1,"kind":"security_key_added","class":"alert","actor":{{"kind":"sign_in"}},"label":"{}"}}],"more":false}}"#,
        "x".repeat(65)
    );
    assert!(serde_json::from_str::<SecurityEventListResponse>(&long).is_err());
}
