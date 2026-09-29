//! Structured logging with an allow-list of fields (threat model INV-48, §7.13; ADR 0010).
//!
//! **What a log line can hold.** One JSON object per line on stderr, with `ts_ms`, `level`,
//! `event` and the fields of the call. The event name and every field name are `&'static str`
//! written in this crate's source, and a field value is one of [`Field`]'s kinds:
//! - an integer or a fixed `&'static str` from the source;
//! - [`Field::Error`]: the `Display` of an error type whose docs promise it carries no value
//!   (`rizzy_domain_auth::AuthError`, `rizzy_domain_vault::VaultError` and its reports,
//!   `rizzy_storage::Error`, this crate's own errors), each call site reviewed as such.
//!
//! There is no field kind for request or response bodies, headers, tokens, keys, OPAQUE
//! messages, envelopes, statements, login names or paths, and no free-form string: a value that
//! is not an integer or a source constant can only come in through an error's `Display`. So no
//! caller can log a secret by passing it in (INV-48), and the list of what the server logs is
//! the list of `log::` call sites. IP addresses are not logged at all in M1, though `THREAT_MODEL`
//! §3.4 would allow them.
//!
//! **Level.** Set once at startup ([`init`]); lines below it are dropped. The default is
//! [`Level::Info`]. A failed write to stderr is ignored: logging never stops the server.

use core::fmt;
use std::io::Write as _;
use std::sync::OnceLock;

use serde_json::{Map, Value};

use crate::sys::now_ms;

/// A log level, most severe first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// The server cannot do what it must.
    Error,
    /// Something is wrong but the server goes on.
    Warn,
    /// Normal operation: startup, shutdown, one line per request, worker runs.
    Info,
    /// More detail about the same events.
    Debug,
}

impl Level {
    /// The name in log lines and in `RIZZY_LOG_LEVEL`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }

    /// Parses `error`, `warn`, `info` or `debug`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "error" => Some(Self::Error),
            "warn" => Some(Self::Warn),
            "info" => Some(Self::Info),
            "debug" => Some(Self::Debug),
            _ => None,
        }
    }
}

/// One field of a log line. See the module docs for what each kind may carry.
pub enum Field<'a> {
    /// An integer: a count, a duration, a status code, a port.
    U64(&'static str, u64),
    /// A constant from this crate's source: a role, a method, a route template, an outcome.
    Str(&'static str, &'static str),
    /// The `Display` of an error type documented to carry no value (module docs).
    Error(&'static str, &'a dyn fmt::Display),
}

impl fmt::Debug for Field<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::U64(k, v) => write!(f, "{k}={v}"),
            Self::Str(k, v) => write!(f, "{k}={v}"),
            Self::Error(k, v) => write!(f, "{k}={v}"),
        }
    }
}

/// The level in force; unset means [`Level::Info`].
static LEVEL: OnceLock<Level> = OnceLock::new();

/// Sets the level once, at startup. A second call is ignored.
pub fn init(level: Level) {
    let _already_set = LEVEL.set(level);
}

/// Whether lines at `level` are written.
#[must_use]
pub fn enabled(level: Level) -> bool {
    level <= *LEVEL.get().unwrap_or(&Level::Info)
}

/// The JSON text of one line: `ts_ms`, `level`, `event`, then `fields` in order. A field that
/// repeats a name overwrites the earlier one.
#[must_use]
pub fn render(ts_ms: u64, level: Level, event: &'static str, fields: &[Field<'_>]) -> String {
    let mut line = Map::new();
    line.insert("ts_ms".to_owned(), Value::from(ts_ms));
    line.insert("level".to_owned(), Value::from(level.name()));
    line.insert("event".to_owned(), Value::from(event));
    for field in fields {
        let (key, value) = match field {
            Field::U64(k, v) => (*k, Value::from(*v)),
            Field::Str(k, v) => (*k, Value::from(*v)),
            Field::Error(k, v) => (*k, Value::from(v.to_string())),
        };
        line.insert(key.to_owned(), value);
    }
    Value::Object(line).to_string()
}

/// Writes one line at `level`, if enabled.
pub fn log(level: Level, event: &'static str, fields: &[Field<'_>]) {
    if !enabled(level) {
        return;
    }
    let mut text = render(now_ms(), level, event, fields);
    text.push('\n');
    // A failed write (a closed stderr) must not stop the server.
    let _ignored = std::io::stderr().lock().write_all(text.as_bytes());
}

/// [`log`] at [`Level::Error`].
pub fn error(event: &'static str, fields: &[Field<'_>]) {
    log(Level::Error, event, fields);
}

/// [`log`] at [`Level::Warn`].
pub fn warn(event: &'static str, fields: &[Field<'_>]) {
    log(Level::Warn, event, fields);
}

/// [`log`] at [`Level::Info`].
pub fn info(event: &'static str, fields: &[Field<'_>]) {
    log(Level::Info, event, fields);
}

/// [`log`] at [`Level::Debug`].
pub fn debug(event: &'static str, fields: &[Field<'_>]) {
    log(Level::Debug, event, fields);
}

#[cfg(test)]
mod tests {
    //! The line format and the level filter.

    use super::*;

    #[test]
    fn a_line_is_one_json_object_with_the_allowed_fields() {
        let err = crate::config::ConfigError::Missing("RIZZY_ORIGIN");
        let line = render(
            7,
            Level::Warn,
            "startup_refused",
            &[
                Field::U64("status", 503),
                Field::Str("role", "api"),
                Field::Error("error", &err),
            ],
        );
        let parsed: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["ts_ms"], 7);
        assert_eq!(parsed["level"], "warn");
        assert_eq!(parsed["event"], "startup_refused");
        assert_eq!(parsed["status"], 503);
        assert_eq!(parsed["role"], "api");
        assert_eq!(parsed["error"], err.to_string());
        assert!(!line.contains('\n'));
    }

    #[test]
    fn levels_order_and_parse() {
        assert!(Level::Error < Level::Debug);
        for level in [Level::Error, Level::Warn, Level::Info, Level::Debug] {
            assert_eq!(Level::parse(level.name()), Some(level));
        }
        assert_eq!(Level::parse("trace"), None);
    }
}
