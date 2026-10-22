// SPDX-License-Identifier: AGPL-3.0-only

//! Unit tests of the CXF payload codec.

use super::*;

#[test]
fn payload_round_trips_and_checks_its_version() {
    let payload = encode_cxf_payload(b"{}").unwrap();
    assert_eq!(payload.expose_secret(), b"\x00\x02\x00\x00\x00\x02{}");
    assert_eq!(parse_cxf_payload(payload.expose_secret()).unwrap(), b"{}");
    for bad in [
        &b"\x00\x01\x00\x00\x00\x02{}"[..],
        b"\x00\x02\x00\x00\x00\x03{}",
        b"\x00\x02\x00\x00\x00\x01{}",
        b"\x00",
        b"",
    ] {
        assert_eq!(
            parse_cxf_payload(bad).unwrap_err(),
            ClientError::InvalidExportFile
        );
    }
}
