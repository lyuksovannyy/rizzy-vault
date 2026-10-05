//! The `rizzy-vault` command line.
//!
//! ```text
//! rizzy-vault [serve] [--roles <list>] [--config <file>]
//! rizzy-vault migrate [--config <file>]
//! rizzy-vault secrets init [--config <file>]
//! rizzy-vault secrets rotate [--data-key] [--config <file>]
//! rizzy-vault secrets retire-setups [--grace-days <n>] [--config <file>]
//! rizzy-vault backup-secrets --out <file> --passphrase-file <file|-> [--config <file>]
//! rizzy-vault backup --out <file|-> [--config <file>]
//! rizzy-vault restore --in <file|-> [--config <file>]
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
//!
//! Before anything else, [`main`] disables core dumps ([`crate::coredump`], threat model INV-60,
//! ADR 0024) and exits 1 if that fails, for every command, `--help` and `--version` included.

use std::ffi::{OsStr, OsString};
use std::io::{self, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;

use crate::admin::{self, Rotate};
use crate::config::{self, Config, Sources};
use crate::coredump;
use crate::server;
use rizzy_domain_auth::retirement::{DAY_MS, DEFAULT_GRACE_DAYS, MAX_GRACE_DAYS};

/// The help text, printed on `--help` (stdout) and on a usage error (stderr).
pub const USAGE: &str = "\
rizzy-vault — self-hosted end-to-end encrypted password manager server

USAGE:
    rizzy-vault [serve] [--roles <list>] [--config <file>]
    rizzy-vault migrate [--config <file>]
    rizzy-vault secrets init [--config <file>]
    rizzy-vault secrets rotate [--data-key] [--config <file>]
    rizzy-vault secrets retire-setups [--grace-days <n>] [--config <file>]
    rizzy-vault backup-secrets --out <file> --passphrase-file <file|-> [--config <file>]
    rizzy-vault backup --out <file|-> [--config <file>]
    rizzy-vault restore --in <file|-> [--config <file>]

OPTIONS:
    --roles <list>    Roles to run: api, web, worker (default: all three; or RIZZY_ROLES)
    --config <file>   Configuration file of NAME=value lines (or RIZZY_CONFIG)
    --grace-days <n>  retire-setups: days since a setup's successor was recorded (default 90,
                      0 to 3650; 0 retires at once)
    -h, --help        Print this help
    -V, --version     Print version

Settings come from RIZZY_* environment variables or the configuration file: RIZZY_ORIGIN,
RIZZY_LISTEN, RIZZY_DATA_DIR, RIZZY_DATABASE_URL, RIZZY_SECRETS_FILE, RIZZY_SIGNUP,
RIZZY_TRUSTED_PROXIES, RIZZY_LOG_LEVEL, RIZZY_WORKER_INTERVAL_SECS, RIZZY_MAX_UPLOAD_BYTES,
RIZZY_RECOVERY_WAIT_HOURS.
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
    /// `secrets retire-setups [--grace-days N]` (ADR 0031 points 4–5).
    SecretsRetireSetups {
        /// `--grace-days`, or the default 90.
        grace_days: u32,
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
    /// `backup` (ADR 0023 §6).
    Backup {
        /// `--out`: a file, or `-` for stdout.
        out: PathBuf,
        /// `--config`.
        config: Option<PathBuf>,
    },
    /// `restore` (ADR 0023 §5, §6).
    Restore {
        /// `--in`: a file, or `-` for stdin.
        input: PathBuf,
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
    /// `--in`.
    input: Option<PathBuf>,
    /// `--grace-days`.
    grace_days: Option<u32>,
}

/// Which flags a subcommand accepts.
#[derive(Clone, Copy)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "one independent flag per command-line option"
)]
struct Allowed {
    /// `--roles`.
    roles: bool,
    /// `--data-key`.
    data_key: bool,
    /// `--out`.
    out: bool,
    /// `--passphrase-file`.
    passphrase_file: bool,
    /// `--in`.
    input: bool,
    /// `--grace-days`.
    grace_days: bool,
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
            "--out" if allowed.out && out.out.is_none() => {
                out.out = Some(PathBuf::from(it.next().ok_or(UsageError)?));
            }
            "--passphrase-file" if allowed.passphrase_file && out.passphrase_file.is_none() => {
                out.passphrase_file = Some(PathBuf::from(it.next().ok_or(UsageError)?));
            }
            "--in" if allowed.input && out.input.is_none() => {
                out.input = Some(PathBuf::from(it.next().ok_or(UsageError)?));
            }
            "--grace-days" if allowed.grace_days && out.grace_days.is_none() => {
                let value = it.next().and_then(|v| v.to_str()).ok_or(UsageError)?;
                out.grace_days = Some(grace_days(value)?);
            }
            _ => return Err(UsageError),
        }
    }
    Ok(out)
}

/// No flag but `--config`.
const NONE: Allowed = Allowed {
    roles: false,
    data_key: false,
    out: false,
    passphrase_file: false,
    input: false,
    grace_days: false,
};

/// Parses `secrets <sub>` with the arguments after `sub`.
fn parse_secrets(sub: &str, rest: &[OsString]) -> Result<Command, UsageError> {
    match sub {
        "init" => Ok(Command::SecretsInit {
            config: flags(rest, NONE)?.config,
        }),
        "rotate" => {
            let f = flags(
                rest,
                Allowed {
                    data_key: true,
                    ..NONE
                },
            )?;
            Ok(Command::SecretsRotate {
                data_key: f.data_key,
                config: f.config,
            })
        }
        "retire-setups" => {
            let f = flags(
                rest,
                Allowed {
                    grace_days: true,
                    ..NONE
                },
            )?;
            Ok(Command::SecretsRetireSetups {
                grace_days: f.grace_days.unwrap_or(DEFAULT_GRACE_DAYS),
                config: f.config,
            })
        }
        _ => Err(UsageError),
    }
}

/// Parses the arguments after the program name.
///
/// # Errors
/// [`UsageError`] for anything but the forms of the module docs.
pub fn parse(args: &[OsString]) -> Result<Command, UsageError> {
    /// `serve`'s flags.
    const SERVE: Allowed = Allowed {
        roles: true,
        ..NONE
    };
    let first = args
        .first()
        .map(|a| a.to_str().ok_or(UsageError))
        .transpose()?;
    // The arguments from position `from` on.
    let rest = |from: usize| args.get(from..).unwrap_or_default();
    match (
        first,
        args.get(1).map(OsString::as_os_str).and_then(OsStr::to_str),
    ) {
        (Some("-h" | "--help"), _) if args.len() == 1 => Ok(Command::Help),
        (Some("-V" | "--version"), _) if args.len() == 1 => Ok(Command::Version),
        (None | Some("--roles" | "--config"), _) => {
            let f = flags(args, SERVE)?;
            Ok(Command::Serve {
                roles: f.roles,
                config: f.config,
            })
        }
        (Some("serve"), _) => {
            let f = flags(rest(1), SERVE)?;
            Ok(Command::Serve {
                roles: f.roles,
                config: f.config,
            })
        }
        (Some("migrate"), _) => Ok(Command::Migrate {
            config: flags(rest(1), NONE)?.config,
        }),
        (Some("secrets"), Some(sub)) => parse_secrets(sub, rest(2)),
        (Some("backup-secrets"), _) => {
            let f = flags(
                rest(1),
                Allowed {
                    out: true,
                    passphrase_file: true,
                    ..NONE
                },
            )?;
            Ok(Command::BackupSecrets {
                out: f.out.ok_or(UsageError)?,
                passphrase_file: f.passphrase_file.ok_or(UsageError)?,
                config: f.config,
            })
        }
        (Some("backup"), _) => {
            let f = flags(rest(1), Allowed { out: true, ..NONE })?;
            Ok(Command::Backup {
                out: f.out.ok_or(UsageError)?,
                config: f.config,
            })
        }
        (Some("restore"), _) => {
            let f = flags(
                rest(1),
                Allowed {
                    input: true,
                    ..NONE
                },
            )?;
            Ok(Command::Restore {
                input: f.input.ok_or(UsageError)?,
                config: f.config,
            })
        }
        _ => Err(UsageError),
    }
}

/// `--grace-days`: decimal digits only, 0 to [`MAX_GRACE_DAYS`] (ADR 0031 point 4).
fn grace_days(text: &str) -> Result<u32, UsageError> {
    if text.is_empty() || text.len() > 4 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(UsageError);
    }
    text.parse::<u32>()
        .ok()
        .filter(|days| *days <= MAX_GRACE_DAYS)
        .ok_or(UsageError)
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
        None => config::Settings::new(),
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
    // First, before the command line, the configuration or any secret (INV-60, ADR 0024).
    if let Err(e) = coredump::disable() {
        eprint_line(&e.to_string());
        return ExitCode::FAILURE;
    }
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
        | Command::SecretsRetireSetups { config, .. }
        | Command::BackupSecrets { config, .. }
        | Command::Backup { config, .. }
        | Command::Restore { config, .. } => (config.clone(), None),
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
        Command::SecretsRotate { data_key, .. } => run_secrets_rotate(&config, data_key),
        Command::SecretsRetireSetups { grace_days, .. } => {
            return run_retire_setups(&config, grace_days);
        }
        Command::BackupSecrets {
            out,
            passphrase_file,
            ..
        } => admin::backup_secrets(&config, &out, &passphrase_file)
            .map(|()| "secrets backup written; store it apart from the database backups".to_owned())
            .map_err(|e| e.to_string()),
        Command::Backup { out, .. } => return run_backup(&config, &out),
        Command::Restore { input, .. } => return run_restore(&config, &input),
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

/// `secrets rotate [--data-key]`: adds a new OPAQUE setup, or a new current data key, and
/// returns the line to print.
fn run_secrets_rotate(config: &Config, data_key: bool) -> Result<String, String> {
    let what = if data_key {
        Rotate::DataKey
    } else {
        Rotate::Setup
    };
    let rt = runtime().map_err(|e| format!("cannot start the runtime: {}", e.kind()))?;
    rt.block_on(admin::secrets_rotate(config, what))
        .map(|rotated| rotation_message(what, &rotated))
        .map_err(|e| e.to_string())
}

/// The line `secrets rotate` prints: the new id, and for `--data-key` what happens to the old
/// keys (CRYPTO.md §5.11 "Rotation"). Ids are not secret.
fn rotation_message(what: Rotate, rotated: &admin::Rotated) -> String {
    let id = rotated.id;
    match what {
        Rotate::Setup => format!("new OPAQUE setup {id} added; new registrations use it"),
        Rotate::DataKey => {
            let dropped = if rotated.dropped_data_keys.is_empty() {
                String::new()
            } else {
                let ids: Vec<String> = rotated
                    .dropped_data_keys
                    .iter()
                    .map(u32::to_string)
                    .collect();
                format!(
                    "; dropped data key(s) {}, which no row names any more",
                    ids.join(", ")
                )
            };
            format!(
                "new data key {id} added and marked current; the worker re-seals the 2FA \
                 secrets under it when the server runs{dropped}. Make a new secrets backup"
            )
        }
    }
}

/// `secrets retire-setups`: the report of ADR 0031 point 5 on stdout (ids, times and counts
/// only, no account names), or the failure on stderr.
fn run_retire_setups(config: &Config, grace_days: u32) -> ExitCode {
    let rt = match runtime() {
        Ok(rt) => rt,
        Err(e) => {
            eprint_line(&format!("cannot start the runtime: {}", e.kind()));
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(admin::secrets_retire_setups(config, grace_days)) {
        Ok(report) => {
            if print_line(&retirement_message(&report)) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(e) => admin_failure(&e),
    }
}

/// The lines `secrets retire-setups` prints (ADR 0031 point 5): per selected setup its id, its
/// successor time and the records that still name it, the cost of `--grace-days 0`, what was
/// removed from the secrets file, and the reminder to make a new secrets backup.
#[must_use]
pub fn retirement_message(report: &admin::RetiredSetups) -> String {
    let mut lines = Vec::new();
    for setup in &report.selected {
        let age_days = report
            .now_ms
            .saturating_sub(setup.successor_at_ms)
            .checked_div(DAY_MS)
            .unwrap_or(0);
        lines.push(format!(
            "setup {}: successor recorded at {} ms since the Unix epoch ({age_days} days ago); \
             {} account record(s) still on it",
            setup.setup_id, setup.successor_at_ms, setup.records
        ));
    }
    let on_retired: u64 = report.selected.iter().map(|s| s.records).sum();
    if !report.selected.is_empty() {
        let ids: Vec<String> = report
            .selected
            .iter()
            .map(|s| s.setup_id.to_string())
            .collect();
        lines.push(format!(
            "retired OPAQUE setup(s) {} (grace period {} days)",
            ids.join(", "),
            report.grace_days
        ));
        if on_retired > 0 {
            lines.push(format!(
                "{on_retired} account(s) lose password login at the next server start: they log in \
                 through an enrolled device, which moves them to the current setup, or with their \
                 recovery code{}",
                if report.grace_days == 0 {
                    " (--grace-days 0: retired at once, without a grace period)"
                } else {
                    ""
                }
            ));
        }
    }
    if report.removed.is_empty() {
        if report.selected.is_empty() {
            lines.push("no OPAQUE setup to retire; the secrets file is unchanged".to_owned());
        }
    } else {
        let ids: Vec<String> = report.removed.iter().map(u32::to_string).collect();
        lines.push(format!(
            "removed OPAQUE setup(s) {} from the secrets file; they stop being accepted at the \
             next server start. Make a new secrets backup: an old one still holds them",
            ids.join(", ")
        ));
    }
    lines.join("\n")
}

/// The exit code of a failed admin command: 2 for a usage error, 1 otherwise.
fn admin_failure(e: &admin::AdminError) -> ExitCode {
    eprint_line(&e.to_string());
    if e.is_usage() {
        ExitCode::from(2)
    } else {
        ExitCode::FAILURE
    }
}

/// `backup`. Every message goes to stderr, since stdout may carry the file (`--out -`); the
/// SHA-256 is printed for the operator to record (ADR 0023 §2).
fn run_backup(config: &Config, out: &std::path::Path) -> ExitCode {
    let rt = match runtime() {
        Ok(rt) => rt,
        Err(e) => {
            eprint_line(&format!("cannot start the runtime: {}", e.kind()));
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(admin::backup(config, out)) {
        Ok(summary) => {
            eprint_line(&format!(
                "database backup written: {} bytes, SHA-256 {}. Record the digest; encrypt the \
                 file at rest and store it apart from the secrets backup",
                summary.len,
                summary.digest_hex()
            ));
            ExitCode::SUCCESS
        }
        Err(e) => admin_failure(&e),
    }
}

/// `restore`: the report and the INV-59 notice on stdout (ADR 0023 §5 step 6).
fn run_restore(config: &Config, input: &std::path::Path) -> ExitCode {
    let rt = match runtime() {
        Ok(rt) => rt,
        Err(e) => {
            eprint_line(&format!("cannot start the runtime: {}", e.kind()));
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(admin::restore(config, input)) {
        Ok(report) => {
            let message = format!(
                "restored {} rows; {} accounts are in a reconciliation epoch under a new restore \
                 generation.\n{}",
                report.rows,
                report.accounts_in_reconciliation,
                admin::RESTORE_NOTICE
            );
            if print_line(&message) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(e) => admin_failure(&e),
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
        assert_eq!(
            parse(&args(&["secrets", "retire-setups"])),
            Ok(Command::SecretsRetireSetups {
                grace_days: 90,
                config: None
            })
        );
        for (text, days) in [("0", 0), ("3650", 3650), ("007", 7)] {
            assert_eq!(
                parse(&args(&["secrets", "retire-setups", "--grace-days", text])),
                Ok(Command::SecretsRetireSetups {
                    grace_days: days,
                    config: None
                })
            );
        }
        assert_eq!(
            parse(&args(&["backup", "--out", "-"])),
            Ok(Command::Backup {
                out: PathBuf::from("-"),
                config: None
            })
        );
        assert_eq!(
            parse(&args(&[
                "restore",
                "--config",
                "/etc/rv",
                "--in",
                "db.rvbackup"
            ])),
            Ok(Command::Restore {
                input: PathBuf::from("db.rvbackup"),
                config: Some(PathBuf::from("/etc/rv"))
            })
        );
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
            &["backup"],
            &["backup", "--in", "f"],
            &["backup", "--out", "a", "--out", "b"],
            &["backup", "--out", "f", "--passphrase-file", "p"],
            &["restore"],
            &["restore", "--out", "f"],
            &["restore", "--in"],
            &["backup-secrets", "--in", "f", "--passphrase-file", "p"],
            &["restore", "x"],
            &["secrets", "retire-setups", "--grace-days"],
            &["secrets", "retire-setups", "--grace-days", "3651"],
            &["secrets", "retire-setups", "--grace-days", "-1"],
            &["secrets", "retire-setups", "--grace-days", "+5"],
            &[
                "secrets",
                "retire-setups",
                "--grace-days",
                "1",
                "--grace-days",
                "2",
            ],
            &["secrets", "retire-setups", "--data-key"],
            &["secrets", "rotate", "--grace-days", "1"],
            &["--database-url", "postgres://u:p@h/d"],
        ] {
            assert_eq!(parse(&args(bad)), Err(UsageError), "{bad:?}");
        }
    }
}
