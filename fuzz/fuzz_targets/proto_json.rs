//! Fuzzes the `/api/v1` types of `rizzy-proto` on arbitrary JSON bytes: every request type the
//! server parses from a client, and every response type a client parses from a server the
//! threat model does not trust (ADR 0002 point 3; threat model §7.6 "D", A2). None may panic,
//! and none may allocate past its type's limits, whatever lengths the input announces.
//!
//! What runs on each input:
//!
//! - The first byte picks one message type; the rest is parsed as that type with
//!   `serde_json::from_slice`. When it parses, serialising it and parsing the result again
//!   must give the same JSON text twice: one JSON form per accepted value, so the limits and
//!   canonical-form checks hold for everything the type admits.
//! - The whole input, read as UTF-8, is parsed as a `Rizzy-Client` header value
//!   ([`ClientHeader::parse`]); an accepted value must print back to exactly the input.
//!
//! Part of CRYPTO.md §15 item 7 for the API body parsers (CLAUDE.md: untrusted API bodies get a
//! fuzz target).
//!
//! ```text
//! cargo +nightly fuzz run proto_json
//! ```
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_proto::account::{
    AccountStateQuery, AccountView, AckDeviceGrantsRequest, DeviceGrantsResponse,
    EnrolDeviceRequest, PublishAccountStateRequest, PublishBundlesRequest, PublishGrantsRequest,
    UploadWebDeviceCertificateRequest,
};
use rizzy_proto::auth::{
    DeviceAuthFinishRequest, DeviceAuthFinishResponse, DeviceAuthStartRequest,
    DeviceAuthStartResponse, LoginFinishRequest, LoginFinishResponse, LoginStartRequest,
    LoginStartResponse, RegisterFinishRequest, RegisterStartRequest, RegisterStartResponse,
};
use rizzy_proto::change::{
    CommitChangeRequest, DeviceSuspensionRequest, ReregisterStartRequest, ReregisterStartResponse,
    SuspendDeviceResponse,
};
use rizzy_proto::error::ErrorResponse;
use rizzy_proto::meta::{ClientHeader, MetaResponse};
use rizzy_proto::recovery::{
    RecoveryCancelResponse, RecoveryCompleteResponse, RecoveryRequest, RecoveryStartResponse,
};
use rizzy_proto::totp::{TotpDisableRequest, TotpEnrolConfirmRequest, TotpEnrolStartResponse};
use rizzy_proto::vault::{
    FetchRequest, FetchResponse, HealingRequest, HealingResponse, UploadRequest, UploadResponse,
};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Parses `json` as `T`; when it parses, checks that serialising is stable across a second
/// parse.
fn check<T: Serialize + DeserializeOwned>(json: &[u8]) {
    let Ok(value) = serde_json::from_slice::<T>(json) else {
        return;
    };
    let first = serde_json::to_string(&value).expect("an accepted value serialises");
    let again: T = serde_json::from_str(&first).expect("a serialised value parses");
    let second = serde_json::to_string(&again).expect("an accepted value serialises");
    assert_eq!(first, second);
}

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = core::str::from_utf8(data) {
        if let Ok(header) = ClientHeader::parse(text) {
            assert_eq!(header.to_string(), text);
        }
    }
    let Some((&selector, json)) = data.split_first() else {
        return;
    };
    match selector % 40 {
        // Requests.
        0 => check::<RegisterStartRequest>(json),
        1 => check::<RegisterFinishRequest>(json),
        2 => check::<LoginStartRequest>(json),
        3 => check::<LoginFinishRequest>(json),
        4 => check::<DeviceAuthStartRequest>(json),
        5 => check::<DeviceAuthFinishRequest>(json),
        6 => check::<AccountStateQuery>(json),
        7 => check::<EnrolDeviceRequest>(json),
        8 => check::<AckDeviceGrantsRequest>(json),
        9 => check::<PublishBundlesRequest>(json),
        10 => check::<PublishAccountStateRequest>(json),
        11 => check::<PublishGrantsRequest>(json),
        12 => check::<UploadRequest>(json),
        13 => check::<FetchRequest>(json),
        14 => check::<HealingRequest>(json),
        27 => check::<UploadWebDeviceCertificateRequest>(json),
        // Responses.
        15 => check::<ErrorResponse>(json),
        16 => check::<MetaResponse>(json),
        17 => check::<RegisterStartResponse>(json),
        18 => check::<LoginStartResponse>(json),
        19 => check::<LoginFinishResponse>(json),
        20 => check::<DeviceAuthStartResponse>(json),
        21 => check::<DeviceAuthFinishResponse>(json),
        22 => check::<AccountView>(json),
        23 => check::<DeviceGrantsResponse>(json),
        24 => check::<UploadResponse>(json),
        25 => check::<FetchResponse>(json),
        26 => check::<HealingResponse>(json),
        // Requests of the account changes, recovery and TOTP.
        28 => check::<ReregisterStartRequest>(json),
        29 => check::<CommitChangeRequest>(json),
        30 => check::<DeviceSuspensionRequest>(json),
        31 => check::<RecoveryRequest>(json),
        32 => check::<TotpEnrolConfirmRequest>(json),
        33 => check::<TotpDisableRequest>(json),
        // Their responses.
        34 => check::<ReregisterStartResponse>(json),
        35 => check::<SuspendDeviceResponse>(json),
        36 => check::<RecoveryStartResponse>(json),
        37 => check::<RecoveryCancelResponse>(json),
        38 => check::<RecoveryCompleteResponse>(json),
        _ => check::<TotpEnrolStartResponse>(json),
    }
});
