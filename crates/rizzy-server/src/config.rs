//! The server configuration: a file and environment variables ([ADR 0010] §1, §4).
//!
//! [ADR 0010] names `--roles` / `RIZZY_ROLES`, a data volume, a separate read-only secrets mount
//! and the listeners, and no configuration format. So the reading here is the smallest one that
//! covers them, and it is this crate's pre-v1.0 choice (reported to the owner):
//!
//! - **Settings are `RIZZY_*` names** ([`KEYS`]). Each can come from the environment or from a
//!   configuration file; the environment wins over the file, and `--roles` on the command line
//!   wins over both for the roles.
//! - **The file** is named by `--config <path>` or `RIZZY_CONFIG`. It holds `NAME=value` lines,
//!   the same names as the environment; blank lines and lines starting with `#` are skipped;
//!   there is no quoting, escaping or interpolation. An unknown name, a repeated name or a line
//!   without `=` is refused, so a misspelt setting never passes silently. The file is read with
//!   a size limit ([`MAX_CONFIG_FILE_LEN`]) and parsed without panics (fuzz target
//!   `server_config`).
//! - **No secret on the command line** (threat model §7.5, INV-56 for `rv`, applied to the
//!   server too): the only flags are `--roles` and `--config`. The database URL, which can
//!   carry the `PostgreSQL` password, comes only from the environment or the file, and
//!   [`Config`]'s `Debug` leaves it out.
//!
//! Every value has a default except the canonical origin, which the `api` and `worker` roles
//! require (both build the auth domain, which binds the origin into OPAQUE and every
//! device signature).
//!
//! [ADR 0010]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0010-server-shape.md

use core::fmt;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rizzy_domain_auth::types::ServerOrigin;
use zeroize::Zeroizing;

use crate::log::Level;

/// The roles (ADR 0010 §1).
pub const ROLES: &str = "RIZZY_ROLES";
/// The configuration file.
pub const CONFIG: &str = "RIZZY_CONFIG";
/// The server's canonical origin (CRYPTO.md §2 `server_origin`), required by `api` and `worker`.
pub const ORIGIN: &str = "RIZZY_ORIGIN";
/// The public listener of `api` and `web`.
pub const LISTEN: &str = "RIZZY_LISTEN";
/// The data volume: the `SQLite` file and its pre-migration copy (ADR 0010 §4).
pub const DATA_DIR: &str = "RIZZY_DATA_DIR";
/// A `postgres://` URL; without it the database is `SQLite` in the data directory (ADR 0011
/// point 1).
pub const DATABASE_URL: &str = "RIZZY_DATABASE_URL";
/// The secrets file, on its own read-only mount (ADR 0010 §4).
pub const SECRETS_FILE: &str = "RIZZY_SECRETS_FILE";
/// `closed` (the default) or `open` (CRYPTO.md §5.9).
pub const SIGNUP: &str = "RIZZY_SIGNUP";
/// Comma-separated IP addresses of the reverse proxies whose `X-Forwarded-For` is trusted
/// (threat model §7.6 "S", §7.14).
pub const TRUSTED_PROXIES: &str = "RIZZY_TRUSTED_PROXIES";
/// `error`, `warn`, `info` (the default) or `debug`.
pub const LOG_LEVEL: &str = "RIZZY_LOG_LEVEL";
/// Seconds between two worker runs.
pub const WORKER_INTERVAL_SECS: &str = "RIZZY_WORKER_INTERVAL_SECS";
/// The body-size limit of the vault upload and healing requests, in bytes.
pub const MAX_UPLOAD_BYTES: &str = "RIZZY_MAX_UPLOAD_BYTES";

/// Every setting name the file and the environment accept.
pub const KEYS: &[&str] = &[
    ROLES,
    ORIGIN,
    LISTEN,
    DATA_DIR,
    DATABASE_URL,
    SECRETS_FILE,
    SIGNUP,
    TRUSTED_PROXIES,
    LOG_LEVEL,
    WORKER_INTERVAL_SECS,
    MAX_UPLOAD_BYTES,
];

/// The largest configuration file read: 64 KiB.
pub const MAX_CONFIG_FILE_LEN: usize = 64 * 1024;

/// The default listener: loopback only, an unprivileged port (ADR 0010 §4). A container sets
/// `RIZZY_LISTEN=0.0.0.0:8080` behind its reverse proxy.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:8080";

/// The default data directory, the container's data volume.
pub const DEFAULT_DATA_DIR: &str = "/data";

/// The default secrets file, on the separate secrets mount (ADR 0010 §4: "a second volume at
/// `/run/rizzy-secrets`").
pub const DEFAULT_SECRETS_FILE: &str = "/run/rizzy-secrets/secrets.json";

/// The `SQLite` file's name inside the data directory.
pub const SQLITE_FILE_NAME: &str = "rizzy-vault.sqlite3";

/// The pre-migration copy's name inside the data directory (ADR 0011 point 9).
pub const PRE_MIGRATION_COPY_NAME: &str = "rizzy-vault.sqlite3.pre-migration";

/// The default worker interval: one minute.
pub const DEFAULT_WORKER_INTERVAL: Duration = Duration::from_secs(60);

/// The default, and the smallest allowed, upload body limit: 32 MiB. One upload must fit at
/// least one record of the largest size the wire admits, an op statement near its 1.5 MiB
/// limit with a 16 MiB envelope, about 24.5 MiB as base64url JSON
/// (`rizzy_proto::limits::MAX_OP_STATEMENT_LEN`, `MAX_ENVELOPE_LEN`).
pub const DEFAULT_MAX_UPLOAD_BYTES: usize = 32 * 1024 * 1024;

/// The largest upload body limit an operator may set: 256 MiB.
pub const MAX_MAX_UPLOAD_BYTES: usize = 256 * 1024 * 1024;

/// A role of the binary (ADR 0010 §1). Only the M1 roles exist in this build.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    /// OPAQUE, sessions, devices, vault and op log.
    Api,
    /// The web vault's static assets.
    Web,
    /// Scheduled deletion and compaction.
    Worker,
}

impl Role {
    /// The role's name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Api => "api",
            Self::Web => "web",
            Self::Worker => "worker",
        }
    }
}

/// The roles one process runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Roles {
    /// `api`.
    pub api: bool,
    /// `web`.
    pub web: bool,
    /// `worker`.
    pub worker: bool,
}

impl Roles {
    /// The M1 default: `api,web,worker` (ADR 0010 §1; `notify` joins in M3).
    pub const DEFAULT: Self = Self {
        api: true,
        web: true,
        worker: true,
    };

    /// Parses a comma-separated role list.
    ///
    /// `notify` and `icons` (M3) and `smtp` (M6) are refused: this build has no such role.
    /// When they exist, ADR 0010 §2's isolation checks (`smtp` and `icons` run alone, see no
    /// database setting and no secrets file) belong here.
    ///
    /// # Errors
    /// [`ConfigError::Invalid`] for an empty list, an empty entry or an unknown name;
    /// [`ConfigError::RoleNotInThisBuild`] for a later milestone's role.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let mut roles = Self {
            api: false,
            web: false,
            worker: false,
        };
        for name in text.split(',').map(str::trim) {
            match name {
                "api" => roles.api = true,
                "web" => roles.web = true,
                "worker" => roles.worker = true,
                "notify" => return Err(ConfigError::RoleNotInThisBuild("notify")),
                "icons" => return Err(ConfigError::RoleNotInThisBuild("icons")),
                "smtp" => return Err(ConfigError::RoleNotInThisBuild("smtp")),
                _ => return Err(ConfigError::Invalid(ROLES)),
            }
        }
        Ok(roles)
    }

    /// Whether any role needs the database and the secrets (`api`, `worker`).
    #[must_use]
    pub const fn need_database(self) -> bool {
        self.api || self.worker
    }

    /// Whether any role serves HTTP (`api`, `web`).
    #[must_use]
    pub const fn need_listener(self) -> bool {
        self.api || self.web
    }

    /// The role names, for the startup log line.
    #[must_use]
    pub fn names(self) -> &'static str {
        match (self.api, self.web, self.worker) {
            (true, true, true) => "api,web,worker",
            (true, true, false) => "api,web",
            (true, false, true) => "api,worker",
            (true, false, false) => "api",
            (false, true, true) => "web,worker",
            (false, true, false) => "web",
            (false, false, true) => "worker",
            (false, false, false) => "",
        }
    }
}

/// Where the database is.
pub enum DatabaseConfig {
    /// `SQLite` at this path (the default: [`SQLITE_FILE_NAME`] in the data directory).
    Sqlite(PathBuf),
    /// `PostgreSQL` at this URL. The URL can carry the password; it is wiped on drop and never
    /// printed.
    Postgres(Zeroizing<String>),
}

impl fmt::Debug for DatabaseConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(path) => f.debug_tuple("Sqlite").field(path).finish(),
            Self::Postgres(_) => f.write_str("Postgres([REDACTED])"),
        }
    }
}

/// Who may sign up (CRYPTO.md §5.9). Invite-only signup needs an admin who issues invites,
/// which is the M3 admin API; until then an operator chooses between closed and open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignupMode {
    /// Nobody signs up (the default).
    Closed,
    /// Anyone signs up, rate-limited per source, per (name, source) and per name.
    Open,
}

/// The validated configuration.
#[derive(Debug)]
pub struct Config {
    /// The roles this process runs.
    pub roles: Roles,
    /// The canonical origin; `None` only when neither `api` nor `worker` runs.
    pub origin: Option<ServerOrigin>,
    /// The public listener.
    pub listen: SocketAddr,
    /// The data directory.
    pub data_dir: PathBuf,
    /// The database.
    pub database: DatabaseConfig,
    /// The secrets file.
    pub secrets_file: PathBuf,
    /// The signup mode.
    pub signup: SignupMode,
    /// The trusted reverse proxies.
    pub trusted_proxies: Vec<IpAddr>,
    /// The log level.
    pub log_level: Level,
    /// The time between worker runs.
    pub worker_interval: Duration,
    /// The upload body limit.
    pub max_upload_bytes: usize,
}

/// A configuration the server refuses. `Display` names the setting, never its value (the
/// database URL can carry a password).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigError {
    /// A required setting is missing.
    Missing(&'static str),
    /// A setting's value is not valid.
    Invalid(&'static str),
    /// A setting's value is not valid UTF-8.
    NotUtf8(&'static str),
    /// The role belongs to a later milestone.
    RoleNotInThisBuild(&'static str),
    /// The configuration file names a setting that does not exist.
    UnknownSetting,
    /// The configuration file names a setting twice.
    RepeatedSetting(&'static str),
    /// A configuration file line has no `=`.
    MalformedLine,
    /// The configuration file is larger than [`MAX_CONFIG_FILE_LEN`].
    FileTooLarge,
    /// The configuration file could not be read, or is not UTF-8.
    FileUnreadable,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(key) => write!(f, "{key} is required"),
            Self::Invalid(key) => write!(f, "{key} has an invalid value"),
            Self::NotUtf8(key) => write!(f, "{key} is not valid UTF-8"),
            Self::RoleNotInThisBuild(role) => {
                write!(f, "the {role} role is not available in this build")
            }
            Self::UnknownSetting => f.write_str("the configuration file names an unknown setting"),
            Self::RepeatedSetting(key) => {
                write!(f, "the configuration file sets {key} more than once")
            }
            Self::MalformedLine => f.write_str("a configuration file line has no '='"),
            Self::FileTooLarge => f.write_str("the configuration file is too large"),
            Self::FileUnreadable => {
                f.write_str("the configuration file cannot be read or is not UTF-8")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// Parses a configuration file's text into its settings (module docs for the format).
///
/// # Errors
/// [`ConfigError::FileTooLarge`], [`ConfigError::MalformedLine`],
/// [`ConfigError::UnknownSetting`], [`ConfigError::RepeatedSetting`].
pub fn parse_file(text: &str) -> Result<BTreeMap<&'static str, String>, ConfigError> {
    if text.len() > MAX_CONFIG_FILE_LEN {
        return Err(ConfigError::FileTooLarge);
    }
    let mut settings = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, value) = line.split_once('=').ok_or(ConfigError::MalformedLine)?;
        let name = name.trim();
        let key = KEYS
            .iter()
            .copied()
            .find(|k| *k == name)
            .ok_or(ConfigError::UnknownSetting)?;
        if key == CONFIG {
            return Err(ConfigError::UnknownSetting);
        }
        if settings.insert(key, value.trim().to_owned()).is_some() {
            return Err(ConfigError::RepeatedSetting(key));
        }
    }
    Ok(settings)
}

/// Reads the configuration file at `path`, at most [`MAX_CONFIG_FILE_LEN`] bytes.
///
/// # Errors
/// [`ConfigError::FileUnreadable`] and the errors of [`parse_file`].
pub fn read_file(path: &Path) -> Result<BTreeMap<&'static str, String>, ConfigError> {
    let bytes = crate::fsutil::read_limited(path, MAX_CONFIG_FILE_LEN).map_err(|e| match e {
        crate::fsutil::ReadError::TooLarge => ConfigError::FileTooLarge,
        crate::fsutil::ReadError::Io(_) => ConfigError::FileUnreadable,
    })?;
    let text = String::from_utf8(bytes.to_vec()).map_err(|_| ConfigError::FileUnreadable)?;
    // The file may hold the database URL; wipe the copy once it is parsed.
    let text = Zeroizing::new(text);
    parse_file(&text)
}

/// Where the settings come from: the environment over the file.
pub struct Sources<'a> {
    /// The configuration file's settings, if any.
    pub file: BTreeMap<&'static str, String>,
    /// Reads one environment variable.
    pub env: &'a dyn Fn(&str) -> Option<OsString>,
    /// `--roles` from the command line.
    pub roles_flag: Option<String>,
}

impl fmt::Debug for Sources<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sources")
            .field("file_settings", &self.file.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl Sources<'_> {
    /// The value of `key`: the environment if set, else the file.
    fn get(&self, key: &'static str) -> Result<Option<String>, ConfigError> {
        if let Some(value) = (self.env)(key) {
            return value
                .into_string()
                .map(Some)
                .map_err(|_| ConfigError::NotUtf8(key));
        }
        Ok(self.file.get(key).cloned())
    }
}

impl Config {
    /// Builds and validates the configuration from `sources`.
    ///
    /// # Errors
    /// [`ConfigError`] for a missing origin (with `api`), a value that does not parse, or a
    /// later milestone's role.
    pub fn from_sources(sources: &Sources<'_>) -> Result<Self, ConfigError> {
        let roles = match &sources.roles_flag {
            Some(flag) => Roles::parse(flag)?,
            None => match sources.get(ROLES)? {
                Some(text) => Roles::parse(&text)?,
                None => Roles::DEFAULT,
            },
        };
        let origin = match sources.get(ORIGIN)? {
            Some(text) => {
                Some(ServerOrigin::parse(&text).map_err(|_| ConfigError::Invalid(ORIGIN))?)
            }
            None => None,
        };
        let listen = sources
            .get(LISTEN)?
            .unwrap_or_else(|| DEFAULT_LISTEN.to_owned())
            .parse::<SocketAddr>()
            .map_err(|_| ConfigError::Invalid(LISTEN))?;
        let data_dir = PathBuf::from(
            sources
                .get(DATA_DIR)?
                .unwrap_or_else(|| DEFAULT_DATA_DIR.to_owned()),
        );
        let database = match sources.get(DATABASE_URL)?.map(Zeroizing::new) {
            Some(url) if url.is_empty() => return Err(ConfigError::Invalid(DATABASE_URL)),
            Some(url) => {
                if !(url.starts_with("postgres://") || url.starts_with("postgresql://")) {
                    return Err(ConfigError::Invalid(DATABASE_URL));
                }
                DatabaseConfig::Postgres(url)
            }
            None => DatabaseConfig::Sqlite(data_dir.join(SQLITE_FILE_NAME)),
        };
        let secrets_file = PathBuf::from(
            sources
                .get(SECRETS_FILE)?
                .unwrap_or_else(|| DEFAULT_SECRETS_FILE.to_owned()),
        );
        let signup = match sources.get(SIGNUP)?.as_deref() {
            None | Some("closed") => SignupMode::Closed,
            Some("open") => SignupMode::Open,
            Some(_) => return Err(ConfigError::Invalid(SIGNUP)),
        };
        let trusted_proxies = match sources.get(TRUSTED_PROXIES)? {
            None => Vec::new(),
            Some(text) if text.trim().is_empty() => Vec::new(),
            Some(text) => text
                .split(',')
                .map(|a| a.trim().parse::<IpAddr>())
                .collect::<Result<_, _>>()
                .map_err(|_| ConfigError::Invalid(TRUSTED_PROXIES))?,
        };
        let log_level = match sources.get(LOG_LEVEL)? {
            None => Level::Info,
            Some(text) => Level::parse(&text).ok_or(ConfigError::Invalid(LOG_LEVEL))?,
        };
        let worker_interval = match sources.get(WORKER_INTERVAL_SECS)? {
            None => DEFAULT_WORKER_INTERVAL,
            Some(text) => match text.parse::<u64>() {
                Ok(secs @ 1..=86_400) => Duration::from_secs(secs),
                _ => return Err(ConfigError::Invalid(WORKER_INTERVAL_SECS)),
            },
        };
        let max_upload_bytes = match sources.get(MAX_UPLOAD_BYTES)? {
            None => DEFAULT_MAX_UPLOAD_BYTES,
            Some(text) => match text.parse::<usize>() {
                Ok(n) if (DEFAULT_MAX_UPLOAD_BYTES..=MAX_MAX_UPLOAD_BYTES).contains(&n) => n,
                _ => return Err(ConfigError::Invalid(MAX_UPLOAD_BYTES)),
            },
        };
        Ok(Self {
            roles,
            origin,
            listen,
            data_dir,
            database,
            secrets_file,
            signup,
            trusted_proxies,
            log_level,
            worker_interval,
            max_upload_bytes,
        })
    }

    /// Checks what serving needs beyond parsing: an origin when `api` or `worker` runs (the
    /// admin subcommands need none).
    ///
    /// # Errors
    /// [`ConfigError::Missing`] for the origin.
    pub const fn check_serve(&self) -> Result<(), ConfigError> {
        if self.origin.is_none() && self.roles.need_database() {
            return Err(ConfigError::Missing(ORIGIN));
        }
        Ok(())
    }

    /// The pre-migration copy's path (ADR 0011 point 9).
    #[must_use]
    pub fn pre_migration_copy(&self) -> PathBuf {
        self.data_dir.join(PRE_MIGRATION_COPY_NAME)
    }
}

#[cfg(test)]
mod tests {
    //! The file format, the precedence and the refusals.

    use super::*;

    fn env_of(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<OsString> {
        move |key| {
            pairs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| OsString::from(*v))
        }
    }

    #[test]
    fn file_format() {
        let parsed = parse_file(
            "# comment\n\nRIZZY_ORIGIN = https://vault.example.com\nRIZZY_SIGNUP=open\n",
        )
        .unwrap();
        assert_eq!(parsed[ORIGIN], "https://vault.example.com");
        assert_eq!(parsed[SIGNUP], "open");
        assert_eq!(parse_file("RIZZY_NOPE=1"), Err(ConfigError::UnknownSetting));
        assert_eq!(
            parse_file("RIZZY_CONFIG=/x"),
            Err(ConfigError::UnknownSetting)
        );
        assert_eq!(
            parse_file("RIZZY_SIGNUP=open\nRIZZY_SIGNUP=closed"),
            Err(ConfigError::RepeatedSetting(SIGNUP))
        );
        assert_eq!(parse_file("RIZZY_SIGNUP"), Err(ConfigError::MalformedLine));
        let big = "#".repeat(MAX_CONFIG_FILE_LEN + 1);
        assert_eq!(parse_file(&big), Err(ConfigError::FileTooLarge));
    }

    #[test]
    fn environment_wins_over_the_file_and_the_flag_over_both() {
        let env = env_of(&[(SIGNUP, "open"), (ROLES, "web")]);
        let mut file = BTreeMap::new();
        file.insert(SIGNUP, "closed".to_owned());
        file.insert(ORIGIN, "https://vault.example.com".to_owned());
        let sources = Sources {
            file,
            env: &env,
            roles_flag: None,
        };
        let config = Config::from_sources(&sources).unwrap();
        assert_eq!(config.signup, SignupMode::Open);
        assert_eq!(config.roles, Roles::parse("web").unwrap());
        let flagged = Sources {
            roles_flag: Some("api".to_owned()),
            ..sources
        };
        assert!(Config::from_sources(&flagged).unwrap().roles.api);
    }

    #[test]
    fn defaults_and_refusals() {
        let env = env_of(&[(ORIGIN, "https://vault.example.com")]);
        let sources = Sources {
            file: BTreeMap::new(),
            env: &env,
            roles_flag: None,
        };
        let config = Config::from_sources(&sources).unwrap();
        assert_eq!(config.roles, Roles::DEFAULT);
        assert_eq!(config.signup, SignupMode::Closed);
        assert_eq!(config.listen.to_string(), DEFAULT_LISTEN);
        assert!(matches!(config.database, DatabaseConfig::Sqlite(_)));

        let none = env_of(&[]);
        let no_origin = Sources {
            file: BTreeMap::new(),
            env: &none,
            roles_flag: None,
        };
        assert_eq!(
            Config::from_sources(&no_origin)
                .unwrap()
                .check_serve()
                .unwrap_err(),
            ConfigError::Missing(ORIGIN)
        );
        // `web` alone needs no origin.
        let web = Sources {
            roles_flag: Some("web".to_owned()),
            ..no_origin
        };
        let web = Config::from_sources(&web).unwrap();
        assert!(web.origin.is_none());
        assert!(web.check_serve().is_ok());

        for (roles, err) in [
            ("smtp", ConfigError::RoleNotInThisBuild("smtp")),
            ("api,icons", ConfigError::RoleNotInThisBuild("icons")),
            ("", ConfigError::Invalid(ROLES)),
            ("api,,web", ConfigError::Invalid(ROLES)),
        ] {
            assert_eq!(Roles::parse(roles), Err(err), "{roles}");
        }
    }

    #[test]
    fn the_database_url_is_never_printed() {
        let env = env_of(&[
            (ORIGIN, "https://vault.example.com"),
            (DATABASE_URL, "postgres://user:hunter2@db.example.com/v"),
        ]);
        let sources = Sources {
            file: BTreeMap::new(),
            env: &env,
            roles_flag: None,
        };
        let config = Config::from_sources(&sources).unwrap();
        assert!(!format!("{config:?}").contains("hunter2"));
        let bad = env_of(&[
            (ORIGIN, "https://vault.example.com"),
            (DATABASE_URL, "mysql://user:hunter2@db"),
        ]);
        let err = Config::from_sources(&Sources {
            file: BTreeMap::new(),
            env: &bad,
            roles_flag: None,
        })
        .unwrap_err();
        assert!(!err.to_string().contains("hunter2"));
    }
}
