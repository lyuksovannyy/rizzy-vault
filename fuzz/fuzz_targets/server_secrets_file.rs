//! Fuzzes `rizzy-server`'s secrets file reader (`rizzy_server::secrets_file::parse`, CRYPTO.md
//! §5.11 contents in this build's layout). The file sits on the operator's secrets mount; a
//! damaged file must be refused without a panic, and an error must never carry the file's
//! contents.
//!
//! For each input, none may panic, and an accepted file serialises to a file that parses back
//! to the same serialisation (one canonical output per accepted value).
//!
//! ```text
//! cargo +nightly fuzz run server_secrets_file
//! ```
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_server::secrets_file::{parse, serialize};

fuzz_target!(|data: &[u8]| {
    match parse(data) {
        Ok(secrets) => {
            let out = serialize(&secrets).expect("an accepted file serialises");
            let again = parse(&out).expect("a written file parses");
            assert_eq!(
                serialize(&again).expect("serialises").as_slice(),
                out.as_slice()
            );
        }
        Err(e) => {
            // Errors name a field or a rule, never a value.
            assert!(e.to_string().len() < 200);
        }
    }
});
