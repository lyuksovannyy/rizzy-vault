//! Fuzzes `rizzy-server`'s configuration file parser (`rizzy_server::config::parse_file`) and
//! the validation over it (`Config::from_sources`). The file is written by an operator, but a
//! damaged or hostile file must still be refused without a panic.
//!
//! For each input read as UTF-8 (lossily), none may panic, and an accepted file names only
//! known settings, each once; building a configuration from it either succeeds or fails with
//! a `ConfigError`, whose text never contains the database URL's value.
//!
//! ```text
//! cargo +nightly fuzz run server_config
//! ```
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_server::config::{Config, KEYS, Sources, parse_file};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let Ok(settings) = parse_file(&text) else {
        return;
    };
    assert!(settings.keys().all(|k| KEYS.contains(k)));
    let no_env = |_: &str| None;
    let url = settings
        .get(rizzy_server::config::DATABASE_URL)
        .cloned()
        .unwrap_or_default();
    match Config::from_sources(&Sources {
        file: settings,
        env: &no_env,
        roles_flag: None,
    }) {
        Ok(config) => {
            let _ = config.check_serve();
            if url.len() > 12 {
                assert!(!format!("{config:?}").contains(&url));
            }
        }
        Err(e) => {
            if url.len() > 12 {
                assert!(!e.to_string().contains(&url));
            }
        }
    }
});
