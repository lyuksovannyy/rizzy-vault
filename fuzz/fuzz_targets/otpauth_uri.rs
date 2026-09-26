//! Fuzzes the otpauth URI and Base32 secret parsers (CRYPTO.md §11.15, §15 item 7): never
//! panic, and an accepted URI formats to one of at most `MAX_URI_LEN` bytes that parses to the
//! same secret and parameters and formats identically again. The parser's label and issuer
//! limits make that hold for every accepted URI, so a failed reparse is a real bug.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_core::totp::{MAX_URI_LEN, OtpAuthUri, TotpSecret};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    if let Ok(uri) = OtpAuthUri::parse(text) {
        let formatted = uri.to_uri();
        assert!(
            formatted.len() <= MAX_URI_LEN,
            "to_uri stays within MAX_URI_LEN"
        );
        let again = OtpAuthUri::parse(&formatted).expect("a formatted URI parses");
        assert_eq!(again.secret().expose_secret(), uri.secret().expose_secret());
        assert_eq!(again.kind(), uri.kind());
        assert_eq!(again.algorithm(), uri.algorithm());
        assert_eq!(again.digits(), uri.digits());
        assert_eq!(again.label(), uri.label());
        assert_eq!(again.issuer(), uri.issuer());
        assert!(
            *again.to_uri() == *formatted,
            "the formatted form is canonical"
        );
    }
    if let Ok(secret) = TotpSecret::from_base32(text) {
        let canonical = secret.to_base32();
        let again = TotpSecret::from_base32(&canonical).expect("canonical Base32 parses");
        assert_eq!(again.expose_secret(), secret.expose_secret());
        assert!(
            *again.to_base32() == *canonical,
            "Base32 output is canonical"
        );
    }
});
