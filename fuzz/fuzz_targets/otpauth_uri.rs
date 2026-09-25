//! Fuzzes the otpauth URI and Base32 secret parsers (CRYPTO.md §11.15, §15 item 7): never
//! panic, and an accepted URI formats to one that parses to the same secret and parameters.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_core::totp::{OtpAuthUri, TotpSecret};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    if let Ok(uri) = OtpAuthUri::parse(text) {
        let again = OtpAuthUri::parse(&uri.to_uri()).expect("a formatted URI parses");
        assert_eq!(again.secret().expose_secret(), uri.secret().expose_secret());
        assert_eq!(again.kind(), uri.kind());
        assert_eq!(again.algorithm(), uri.algorithm());
        assert_eq!(again.digits(), uri.digits());
        assert_eq!(again.label(), uri.label());
        assert_eq!(again.issuer(), uri.issuer());
    }
    if let Ok(secret) = TotpSecret::from_base32(text) {
        let again = TotpSecret::from_base32(&secret.to_base32()).expect("canonical Base32 parses");
        assert_eq!(again.expose_secret(), secret.expose_secret());
    }
});
