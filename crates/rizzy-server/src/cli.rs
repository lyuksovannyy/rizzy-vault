//! The `rizzy-vault` command line.
//!
//! ```text
//! rizzy-vault [serve] [--roles <list>] [--config <file>]
//! rizzy-vault migrate [--config <file>]
//! rizzy-vault secrets init [--config <file>]
//! rizzy-vault secrets rotate [--data-key] [--config <file>]
//! rizzy-vault backup-secrets --out <file> --passphrase-file <file|-> [--config <file>]
//! rizzy-vault -h | --help
//! rizzy-vault -V | --version
//! ```
//!
//! With no subcommand the server runs the roles of `--roles`, `RIZZY_ROLES`, or the default
//! `api,web,worker` (ADR 0010 §1). No flag takes a secret (threat model §7.5 and INV-56, applied
//! to the server): the database URL and every other setting come from the environment or the
//! configuration file ([`crate::config`]), the backup passphrase from a file or standard input.
//!
//! Arguments are read with `args_os`, so an argument that is not UTF-8 is a usage error, never
//! a panic. Exit codes: 0 success, 1 a runtime failure, 2 a usage or configuration error.
//! Messages go to stderr through `write!` on a locked handle (never `println!`, which would
//! panic on a closed pipe) and name what failed, never a value.

use std::ffi::{OsStr, OsString};
use std::io::{self, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;

use crate::admin::{self, Rotate};
use crate::config::{self, Config, Sources};
use crate::server;

/// The help text, printed on `--help` (stdout) and on a usage error (stderr).
pub const USAGE: &str = "\
rizzy-vault — self-hosted end-to-end encrypted password manager server

USAGE:
    rizzy-vault [serve] [--roles <list>] [--config <file>]
    rizzy-vault migrate [--config <file>]
    rizzy-vault secrets init [--config <file>]
    rizzy-vault secrets rotate [--data-key] [--config <file>]
    rizzy-vault backup-secrets --out <file> --passphrase-file <file|-> [--config <file>]

OPTIONS:
    --roles <list>    Roles to run: api, web, worker (default: all three; or RIZZY_ROLES)
    --config <file>   Configuration file of NAME=value lines (or RIZZY_CONFIG)
    -h, --help        Print this help
    -V, --version     Print version

Settings come from RIZZY_* environment variables or the configuration file: RIZZY_ORIGIN,
RIZZY_LISTEN, RIZZY_DATA_DIR, RIZZY_DATABASE_URL, RIZZY_SECRETS_FILE, RIZZY_SIGNUP,
RIZZY_TRUSTED_PROXIES, RIZZY_LOG_LEVEL, RIZZY_WORKER_INTERVAL_SECS, RIZZY_MAX_UPLOAD_BYTES.
";

/// A parsed command line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// `-h`, `--help`.
    Help,
    /// `-V`, `--version`.
    Version,
    /// Run the server.
    Serve {
        /// `--roles`.
        roles: Option<String>,
        /// `--config`.
        config: Option<PathBuf>,
    },
    /// `migrate`.
    Migrate {
        /// `--config`.
        config: Option<PathBuf>,
    },
    /// `secrets init`.
    SecretsInit {
        /// `--config`.
        config: Option<PathBuf>,
    },
    /// `secrets rotate [--data-key]`.
    SecretsRotate {
        /// `--data-key`.
        data_key: bool,
        /// `--config`.
        config: Option<PathBuf>,
    },
    /// `backup-secrets`.
    BackupSecrets {
        /// `--out`.
        out: PathBuf,
        /// `--passphrase-file`.
        passphrase_file: PathBuf,
        /// `--config`.
        config: Option<PathBuf>,
    },
}

/// A command line that does not parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UsageError;

/// The flags a subcommand accepts after its name.
#[derive(Default)]
struct Flags {
    /// `--roles`.
    roles: Option<String>,
    /// `--config`.
    config: Option<PathBuf>,
    /// `--data-key`.
    data_key: bool,
    /// `--out`.
    out: Option<PathBuf>,
    /// `--passphrase-file`.
    passphrase_file: Option<PathBuf>,
}

/// Which flags a subcommand accepts.
#[derive(Clone, Copy)]
struct Allowed {
    /// `--roles`.
    roles: bool,
    /// `--data-key`.
    data_key: bool,
    /// `--out` and `--passphrase-file`.
    backup: bool,
}

/// Parses the flags in `args` that `allowed` admits; each at most once.
fn flags(args: &[OsString], allowed: Allowed) -> Result<Flags, UsageError> {
    let mut out = Flags::default();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.to_str().ok_or(UsageError)? {
            "--config" if out.config.is_none() => {
                out.config = Some(PathBuf::from(it.next().ok_or(UsageError)?));
            }
            "--roles" if allowed.roles && out.roles.is_none() => {
                let value = it.next().and_then(|v| v.to_str()).ok_or(UsageError)?;
                out.roles = Some(value.to_owned());
            }
            "--data-key" if allowed.data_key && !out.data_key => out.data_key = true,
            "--out" if allowed.backup && out.out.is_none() => {
                out.out = Some(PathBuf::from(it.next().ok_or(UsageError)?));
            }
            "--passphrase-file" if allowed.backup && out.passphrase_file.is_none() => {
                out.passphrase_file = Some(PathBuf::from(it.next().ok_or(UsageError)?));
            }
            _ => return Err(UsageError),
        }
    }
    Ok(out)
}

/// Parses the arguments after the program name.
///
/// # Errors
/// [`UsageError`] for anything but the forms of the module docs.
pub fn parse(args: &[OsString]) -> Result<Command, UsageError> {
    let first = args
        .first()
        .map(|a| a.to_str().ok_or(UsageError))
        .transpose()?;
    let none = Allowed {
        roles: false,
        data_key: false,
        backup: false,
    };
    match (
        first,
        args.get(1).map(OsString::as_os_str).and_then(OsStr::to_str),
    ) {
        (Some("-h" | "--help"), _) if args.len() == 1 => Ok(Command::Help),
        (Some("-V" | "--version"), _) if args.len() == 1 => Ok(Command::Version),
        (None | Some("--roles" | "--config"), _) => {
            let f = flags(
                args,
                Allowed {
                    roles: true,
                    ..none
                },
            )?;
            Ok(Command::Serve {
                roles: f.roles,
                config: f.config,
            })
        }
        (Some("serve"), _) => {
            let f = flags(
                args.get(1..).unwrap_or_default(),
                Allowed {
                    roles: true,
                    ..none
                },
            )?;
            Ok(Command::Serve {
                roles: f.roles,
                config: f.config,
            })
        }
        (Some("migrate"), _) => {
            let f = flags(args.get(1..).unwrap_or_default(), none)?;
            Ok(Command::Migrate { config: f.config })
        }
        (Some("secrets"), Some("init")) => {
            let f = flags(args.get(2..).unwrap_or_default(), none)?;
            Ok(Command::SecretsInit { config: f.config })
        }
        (Some("secrets"), Some("rotate")) => {
            let f = flags(
                args.get(2..).unwrap_or_default(),
                Allowed {
                    data_key: true,
                    ..none
                },
            )?;
            Ok(Command::SecretsRotate {
                data_key: f.data_key,
                config: f.config,
            })
        }
        (Some("backup-secrets"), _) => {
            let f = flags(
                args.get(1..).unwrap_or_default(),
                Allowed {
                    backup: true,
                    ..none
                },
            )?;
            Ok(Command::BackupSecrets {
                out: f.out.ok_or(UsageError)?,
                passphrase_file: f.passphrase_file.ok_or(UsageError)?,
                config: f.config,
            })
        }
        _ => Err(UsageError),
    }
}

/// Writes `message` and a newline to stderr, ignoring a closed stderr.
fn eprint_line(message: &str) {
    let _ignored = writeln!(io::stderr().lock(), "rizzy-vault: {message}");
}

/// Writes `message` and a newline to stdout; `false` if stdout is closed.
fn print_line(message: &str) -> bool {
    writeln!(io::stdout().lock(), "{message}").is_ok()
}

/// Loads the configuration: the file of `--config` or `RIZZY_CONFIG`, the environment over it,
/// `--roles` over both.
fn load_config(
    path: Option<PathBuf>,
    roles: Option<String>,
) -> Result<Config, config::ConfigError> {
    let env = |key: &str| std::env::var_os(key);
    let path = path.or_else(|| env(config::CONFIG).map(PathBuf::from));
    let file = match path {
        Some(path) => config::read_file(&path)?,
        None => std::collections::BTreeMap::new(),
    };
    Config::from_sources(&Sources {
        file,
        env: &env,
        roles_flag: roles,
    })
}

/// A multi-threaded tokio runtime.
fn runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
}

/// The process entry point (module docs).
#[must_use]
pub fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let Ok(command) = parse(&args) else {
        let _ignored = write!(io::stderr().lock(), "{USAGE}");
        return ExitCode::from(2);
    };
    let (config_path, roles) = match &command {
        Command::Help => {
            return if write!(io::stdout().lock(), "{USAGE}").is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            };
        }
        Command::Version => {
            return if print_line(&format!("rizzy-vault {}", env!("CARGO_PKG_VERSION"))) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            };
        }
        Command::Serve { roles, config } => (config.clone(), roles.clone()),
        Command::Migrate { config }
        | Command::SecretsInit { config }
        | Command::SecretsRotate { config, .. }
        | Command::BackupSecrets { config, .. } => (config.clone(), None),
    };
    let config = match load_config(config_path, roles) {
        Ok(config) if !matches!(command, Command::Serve { .. }) => config,
        Ok(config) => match config.check_serve() {
            Ok(()) => config,
            Err(e) => {
                eprint_line(&format!("configuration: {e}"));
                return ExitCode::from(2);
            }
        },
        Err(e) => {
            eprint_line(&format!("configuration: {e}"));
            return ExitCode::from(2);
        }
    };
    let outcome: Result<String, String> = match command {
        Command::Help | Command::Version => Ok(String::new()),
        Command::Serve { .. } => match runtime() {
            Ok(rt) => rt
                .block_on(server::serve(config))
                .map(|()| String::new())
                .map_err(|e| e.to_string()),
            Err(e) => Err(format!("cannot start the runtime: {}", e.kind())),
        },
        Command::Migrate { .. } => match runtime() {
            Ok(rt) => rt
                .block_on(admin::migrate(&config))
                .map(str::to_owned)
                .map_err(|e| e.to_string()),
            Err(e) => Err(format!("cannot start the runtime: {}", e.kind())),
        },
        Command::SecretsInit { .. } => admin::secrets_init(&config)
            .map(|()| "secrets file written".to_owned())
            .map_err(|e| e.to_string()),
        Command::SecretsRotate { data_key, .. } => {
            let what = if data_key {
                Rotate::DataKey
            } else {
                Rotate::Setup
            };
            admin::secrets_rotate(&config, what)
                .map(|id| match what {
                    Rotate::Setup => {
                        format!("new OPAQUE setup {id} added; new registrations use it")
                    }
                    Rotate::DataKey => format!("new data key {id} added and marked current"),
                })
                .map_err(|e| e.to_string())
        }
        Command::BackupSecrets {
            out,
            passphrase_file,
            ..
        } => admin::backup_secrets(&config, &out, &passphrase_file)
            .map(|()| "secrets backup written; store it apart from the database backups".to_owned())
            .map_err(|e| e.to_string()),
    };
    match outcome {
        Ok(message) if message.is_empty() => ExitCode::SUCCESS,
        Ok(message) => {
            if print_line(&message) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(message) => {
            eprint_line(&message);
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    //! The command-line grammar.

    use super::*;

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    #[test]
    fn commands() {
        assert_eq!(
            parse(&args(&[])),
            Ok(Command::Serve {
                roles: None,
                config: None
            })
        );
        assert_eq!(
            parse(&args(&["--roles", "api,web", "--config", "/etc/rv"])),
            Ok(Command::Serve {
                roles: Some("api,web".to_owned()),
                config: Some(PathBuf::from("/etc/rv"))
            })
        );
        assert_eq!(
            parse(&args(&["serve", "--roles", "web"])),
            Ok(Command::Serve {
                roles: Some("web".to_owned()),
                config: None
            })
        );
        assert_eq!(
            parse(&args(&["secrets", "rotate", "--data-key"])),
            Ok(Command::SecretsRotate {
                data_key: true,
                config: None
            })
        );
        assert_eq!(
            parse(&args(&[
                "backup-secrets",
                "--out",
                "b.json",
                "--passphrase-file",
                "-"
            ])),
            Ok(Command::BackupSecrets {
                out: PathBuf::from("b.json"),
                passphrase_file: PathBuf::from("-"),
                config: None
            })
        );
        assert_eq!(parse(&args(&["--version"])), Ok(Command::Version));
    }

    #[test]
    fn refusals() {
        for bad in [
            &["--version", "x"][..],
            &["--roles"],
            &["--roles", "api", "--roles", "web"],
            &["migrate", "--roles", "api"],
            &["secrets"],
            &["secrets", "init", "--data-key"],
            &["backup-secrets", "--out", "b.json"],
            &["backup", "x"],
            &["restore", "x"],
            &["--database-url", "postgres://u:p@h/d"],
        ] {
            assert_eq!(parse(&args(bad)), Err(UsageError), "{bad:?}");
        }
    }
}
