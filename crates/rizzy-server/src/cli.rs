// SPDX-License-Identifier: AGPL-3.0-only

//! The `rizzy-vault` command line.
//!
//! ```text
//! rizzy-vault [serve] [--roles <list>] [--config <file>]
//! rizzy-vault migrate [--config <file>]
//! rizzy-vault secrets init [--config <file>]
//! rizzy-vault secrets rotate [--data-key | --backup-key] [--config <file>]
//! rizzy-vault secrets retire-setups [--grace-days <n>] [--config <file>]
//! rizzy-vault secrets restore --in <file|-> --passphrase-file <file|-> [--config <file>]
//! rizzy-vault secrets invalidate [--confirm] [--config <file>]
//! rizzy-vault backup-secrets --out <file> --passphrase-file <file|-> [--config <file>]
//! rizzy-vault backup --out <file|-> [--encrypt] [--config <file>]
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
use rizzy_domain_auth::invalidation::LossCase;
use rizzy_domain_auth::retirement::{DAY_MS, DEFAULT_GRACE_DAYS, MAX_GRACE_DAYS};

/// The help text, printed on `--help` (stdout) and on a usage error (stderr).
pub const USAGE: &str = "\
rizzy-vault — self-hosted end-to-end encrypted password manager server

USAGE:
    rizzy-vault [serve] [--roles <list>] [--config <file>]
    rizzy-vault migrate [--config <file>]
    rizzy-vault secrets init [--config <file>]
    rizzy-vault secrets rotate [--data-key | --backup-key] [--config <file>]
    rizzy-vault secrets retire-setups [--grace-days <n>] [--config <file>]
    rizzy-vault secrets restore --in <file|-> --passphrase-file <file|-> [--config <file>]
    rizzy-vault secrets invalidate [--confirm] [--config <file>]
    rizzy-vault backup-secrets --out <file> --passphrase-file <file|-> [--config <file>]
    rizzy-vault backup --out <file|-> [--encrypt] [--config <file>]
    rizzy-vault restore --in <file|-> [--config <file>]

OPTIONS:
    --roles <list>    Roles to run: api, web, worker (default: these three), or icons, which
                      runs alone (or RIZZY_ROLES)
    --config <file>   Configuration file of NAME=value lines (or RIZZY_CONFIG)
    --grace-days <n>  retire-setups: days since a setup's successor was recorded (default 90,
                      0 to 3650; 0 retires at once)
    --data-key        secrets rotate: a new current data key instead of a new OPAQUE setup
    --backup-key      secrets rotate: a new current backup key, for backup --encrypt
    --encrypt         backup: seal the file under the secrets file's current backup key
                      (format version 2); restore opens it with the same secrets file
    --confirm         secrets invalidate: carry it out; without it, only report what it
                      would discard
    -h, --help        Print this help
    -V, --version     Print version

Settings come from RIZZY_* environment variables or the configuration file (named by
--config or RIZZY_CONFIG, never by the file itself): RIZZY_ROLES, RIZZY_ORIGIN, RIZZY_LISTEN,
RIZZY_ADMIN_LISTEN, RIZZY_DATA_DIR, RIZZY_DATABASE_URL, RIZZY_SECRETS_FILE, RIZZY_SIGNUP,
RIZZY_TRUSTED_PROXIES, RIZZY_LOG_LEVEL, RIZZY_WORKER_INTERVAL_SECS, RIZZY_MAX_UPLOAD_BYTES,
RIZZY_RECOVERY_WAIT_HOURS, RIZZY_ACCOUNT_QUOTA_BYTES.
The icons role reads RIZZY_BREACH_CHECK (off or on), RIZZY_ICON_CACHE_DIR,
RIZZY_ICON_CACHE_TTL_SECS and RIZZY_ICON_CACHE_MAX_BYTES.
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
    /// `secrets rotate [--data-key | --backup-key]`.
    SecretsRotate {
        /// `--data-key`.
        data_key: bool,
        /// `--backup-key` (ADR 0071). Never together with `--data-key`.
        backup_key: bool,
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
    /// `secrets restore` (ADR 0047).
    SecretsRestore {
        /// `--in`: a file, or `-` for stdin.
        input: PathBuf,
        /// `--passphrase-file`: a file, or `-` for stdin (never both from stdin).
        passphrase_file: PathBuf,
        /// `--config`.
        config: Option<PathBuf>,
    },
    /// `secrets invalidate [--confirm]` (ADR 0047).
    SecretsInvalidate {
        /// `--confirm`.
        confirm: bool,
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
    /// `backup` (ADR 0023 §6; `--encrypt`, ADR 0071).
    Backup {
        /// `--out`: a file, or `-` for stdout.
        out: PathBuf,
        /// `--encrypt`: format version 2 under the current backup key.
        encrypt: bool,
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
#[expect(
    clippy::struct_excessive_bools,
    reason = "one independent flag per command-line option"
)]
struct Flags {
    /// `--roles`.
    roles: Option<String>,
    /// `--config`.
    config: Option<PathBuf>,
    /// `--data-key`.
    data_key: bool,
    /// `--backup-key`.
    backup_key: bool,
    /// `--encrypt`.
    encrypt: bool,
    /// `--out`.
    out: Option<PathBuf>,
    /// `--passphrase-file`.
    passphrase_file: Option<PathBuf>,
    /// `--in`.
    input: Option<PathBuf>,
    /// `--grace-days`.
    grace_days: Option<u32>,
    /// `--confirm`.
    confirm: bool,
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
    /// `--backup-key`.
    backup_key: bool,
    /// `--encrypt`.
    encrypt: bool,
    /// `--out`.
    out: bool,
    /// `--passphrase-file`.
    passphrase_file: bool,
    /// `--in`.
    input: bool,
    /// `--grace-days`.
    grace_days: bool,
    /// `--confirm`.
    confirm: bool,
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
            "--backup-key" if allowed.backup_key && !out.backup_key => out.backup_key = true,
            "--encrypt" if allowed.encrypt && !out.encrypt => out.encrypt = true,
            "--confirm" if allowed.confirm && !out.confirm => out.confirm = true,
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
    backup_key: false,
    encrypt: false,
    out: false,
    passphrase_file: false,
    input: false,
    grace_days: false,
    confirm: false,
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
                    backup_key: true,
                    ..NONE
                },
            )?;
            // One secret per rotation.
            if f.data_key && f.backup_key {
                return Err(UsageError);
            }
            Ok(Command::SecretsRotate {
                data_key: f.data_key,
                backup_key: f.backup_key,
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
        "restore" => {
            let f = flags(
                rest,
                Allowed {
                    input: true,
                    passphrase_file: true,
                    ..NONE
                },
            )?;
            let (Some(input), Some(passphrase_file)) = (f.input, f.passphrase_file) else {
                return Err(UsageError);
            };
            // Standard input carries one of the two at most.
            if input.as_os_str() == "-" && passphrase_file.as_os_str() == "-" {
                return Err(UsageError);
            }
            Ok(Command::SecretsRestore {
                input,
                passphrase_file,
                config: f.config,
            })
        }
        "invalidate" => {
            let f = flags(
                rest,
                Allowed {
                    confirm: true,
                    ..NONE
                },
            )?;
            Ok(Command::SecretsInvalidate {
                confirm: f.confirm,
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
            let f = flags(
                rest(1),
                Allowed {
                    out: true,
                    encrypt: true,
                    ..NONE
                },
            )?;
            Ok(Command::Backup {
                out: f.out.ok_or(UsageError)?,
                encrypt: f.encrypt,
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

/// Success if the output was written, a runtime failure otherwise (a closed stdout).
fn written(ok: bool) -> ExitCode {
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
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
        Command::Help => return written(write!(io::stdout().lock(), "{USAGE}").is_ok()),
        Command::Version => {
            return written(print_line(&format!(
                "rizzy-vault {}",
                env!("CARGO_PKG_VERSION")
            )));
        }
        Command::Serve { roles, config } => (config.clone(), roles.clone()),
        Command::Migrate { config }
        | Command::SecretsInit { config }
        | Command::SecretsRotate { config, .. }
        | Command::SecretsRetireSetups { config, .. }
        | Command::SecretsRestore { config, .. }
        | Command::SecretsInvalidate { config, .. }
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
        Command::SecretsRotate {
            data_key,
            backup_key,
            ..
        } => run_secrets_rotate(&config, data_key, backup_key),
        Command::SecretsRetireSetups { grace_days, .. } => {
            return run_retire_setups(&config, grace_days);
        }
        Command::SecretsRestore {
            input,
            passphrase_file,
            ..
        } => return run_secrets_restore(&config, &input, &passphrase_file),
        Command::SecretsInvalidate { confirm, .. } => {
            return run_secrets_invalidate(&config, confirm);
        }
        Command::BackupSecrets {
            out,
            passphrase_file,
            ..
        } => admin::backup_secrets(&config, &out, &passphrase_file)
            .map(|()| "secrets backup written; store it apart from the database backups".to_owned())
            .map_err(|e| e.to_string()),
        Command::Backup { out, encrypt, .. } => return run_backup(&config, &out, encrypt),
        Command::Restore { input, .. } => return run_restore(&config, &input),
    };
    match outcome {
        Ok(message) if message.is_empty() => ExitCode::SUCCESS,
        Ok(message) => written(print_line(&message)),
        Err(message) => {
            eprint_line(&message);
            ExitCode::FAILURE
        }
    }
}

/// `secrets rotate [--data-key | --backup-key]`: adds a new OPAQUE setup, a new current data
/// key or a new current backup key, and returns the line to print.
fn run_secrets_rotate(config: &Config, data_key: bool, backup_key: bool) -> Result<String, String> {
    let what = if data_key {
        Rotate::DataKey
    } else if backup_key {
        Rotate::BackupKey
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
        Rotate::BackupKey => format!(
            "new backup key {id} added and marked current; `backup --encrypt` seals under it, \
             and the older backup keys stay so their backups remain restorable. Make a new \
             secrets backup: without the secrets file no encrypted backup can be restored"
        ),
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

/// `secrets restore` (ADR 0047): the report on stdout, or the failure on stderr.
fn run_secrets_restore(
    config: &Config,
    input: &std::path::Path,
    passphrase_file: &std::path::Path,
) -> ExitCode {
    let rt = match runtime() {
        Ok(rt) => rt,
        Err(e) => {
            eprint_line(&format!("cannot start the runtime: {}", e.kind()));
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(admin::secrets_restore(config, input, passphrase_file)) {
        Ok(restored) => {
            if print_line(&secrets_restore_message(&restored)) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(e) => admin_failure(&e),
    }
}

/// The lines `secrets restore` prints (ADR 0047 step 4): what was written, and every setup the
/// database's records name that the restored file lacks (ids and counts only).
#[must_use]
pub fn secrets_restore_message(restored: &admin::SecretsRestored) -> String {
    let mut lines = vec![if restored.created {
        "secrets file restored from the backup (created)".to_owned()
    } else {
        "secrets file restored from the backup (replaced)".to_owned()
    }];
    if restored.database_empty {
        lines.push(
            "the database is empty, so there was nothing to check the backup against; restore \
             the database backup next (`rizzy-vault restore`), which checks it"
                .to_owned(),
        );
    }
    for (setup_id, records) in &restored.missing_setups {
        lines.push(format!(
            "OPAQUE setup {setup_id} is not in this backup: {records} account record(s) on it \
             lose password login and log in through an enrolled device or with their recovery \
             code"
        ));
    }
    lines.join("\n")
}

/// `secrets invalidate [--confirm]` (ADR 0047): the report on stdout; without `--confirm`,
/// the diagnosis on stderr with exit code 2; a refusal or failure on stderr with exit code 1.
fn run_secrets_invalidate(config: &Config, confirm: bool) -> ExitCode {
    let rt = match runtime() {
        Ok(rt) => rt,
        Err(e) => {
            eprint_line(&format!("cannot start the runtime: {}", e.kind()));
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(admin::secrets_invalidate(config, confirm)) {
        Ok(done) => {
            if print_line(&secrets_invalidate_message(&done)) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(e) => admin_failure(&e),
    }
}

/// The lines `secrets invalidate --confirm` prints (ADR 0047 step 8): counts only, no names.
#[must_use]
pub fn secrets_invalidate_message(done: &admin::SecretsInvalidated) -> String {
    match done {
        admin::SecretsInvalidated::MarkerCleared { setup_id } => format!(
            "an earlier `secrets invalidate` had already written the secrets file (OPAQUE setup \
             {setup_id}); its leftover marker is cleared, nothing else changed"
        ),
        admin::SecretsInvalidated::Invalidated { outcome, resumed } => {
            let mut lines = Vec::new();
            if *resumed {
                lines.push("resumed an interrupted `secrets invalidate`".to_owned());
            }
            lines.push(format!(
                "{}: every OPAQUE setup is retired; new OPAQUE setup {} written to the secrets \
                 file",
                match outcome.case {
                    LossCase::SetupOnly => "setup-only loss",
                    LossCase::Whole => "whole loss",
                },
                outcome.setup_id
            ));
            lines.push(format!(
                "{} account(s) need to re-register their password: they log in through an \
                 enrolled device or with their recovery code, which moves them to the new setup",
                outcome.accounts
            ));
            lines.push(format!(
                "{} TOTP enrolment(s) to redo",
                outcome.totp_rows_deleted
            ));
            if outcome.case == LossCase::Whole {
                lines.push(
                    "no bootstrap token was made, and encrypted database backups sealed under \
                     the lost backup keys cannot be restored"
                        .to_owned(),
                );
            }
            lines.push(
                "Make a new secrets backup and a new database backup: older ones no longer \
                 match"
                    .to_owned(),
            );
            lines.join("\n")
        }
    }
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
fn run_backup(config: &Config, out: &std::path::Path, encrypt: bool) -> ExitCode {
    let rt = match runtime() {
        Ok(rt) => rt,
        Err(e) => {
            eprint_line(&format!("cannot start the runtime: {}", e.kind()));
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(admin::backup(config, out, encrypt)) {
        Ok(summary) => {
            eprint_line(&backup_message(&summary));
            ExitCode::SUCCESS
        }
        Err(e) => admin_failure(&e),
    }
}

/// The line `backup` prints on stderr: for a plain backup its length and SHA-256 (ADR 0023
/// §2); for an encrypted one its length, chunk count and backup key id, which are in its clear
/// header (ADR 0071; it has no outer digest).
fn backup_message(summary: &admin::BackupSummary) -> String {
    match summary.encrypted {
        None => format!(
            "database backup written: {} bytes, SHA-256 {}. Record the digest; encrypt the \
             file at rest and store it apart from the secrets backup",
            summary.len,
            summary.digest_hex()
        ),
        Some(e) => format!(
            "encrypted database backup written (format version 2): {} bytes in {} chunk(s), \
             sealed under backup key {}. Restoring it needs the secrets file that holds this \
             key: store the file apart from the secrets file and its backup",
            summary.len, e.chunk_count, e.backup_key_id
        ),
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

    use std::collections::BTreeSet;

    use super::*;

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    /// Every `"RIZZY_*"` string literal in `config.rs` outside its test module: the names
    /// the server reads, read from the source so a name added there without a help line fails.
    fn names_config_reads() -> BTreeSet<&'static str> {
        const SOURCE: &str = include_str!("config.rs");
        let code = SOURCE.split("#[cfg(test)]").next().unwrap();
        code.match_indices("\"RIZZY_")
            .filter_map(|(at, _)| {
                let rest = &code[at + 1..];
                let literal = &rest[..rest.find('"')?];
                literal
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
                    .then_some(literal)
            })
            .collect()
    }

    #[test]
    fn help_lists_every_setting_config_reads() {
        let read = names_config_reads();
        // The literals are exactly the file-and-environment names plus RIZZY_CONFIG.
        let declared: BTreeSet<&str> = config::KEYS
            .iter()
            .copied()
            .chain([config::CONFIG])
            .collect();
        assert_eq!(read, declared);
        let words: BTreeSet<&str> = USAGE
            .split(|c: char| !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
            .collect();
        for name in &read {
            assert!(words.contains(name), "--help does not name {name}");
        }
        assert!(
            USAGE.contains("icons"),
            "--help does not name the icons role"
        );
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
                backup_key: false,
                config: None
            })
        );
        assert_eq!(
            parse(&args(&["secrets", "rotate", "--backup-key"])),
            Ok(Command::SecretsRotate {
                data_key: false,
                backup_key: true,
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
                encrypt: false,
                config: None
            })
        );
        assert_eq!(
            parse(&args(&["backup", "--encrypt", "--out", "db.rvbackup"])),
            Ok(Command::Backup {
                out: PathBuf::from("db.rvbackup"),
                encrypt: true,
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

    /// `secrets restore` and `secrets invalidate` (ADR 0047); their refusals are in
    /// `refusals`.
    #[test]
    fn secrets_operator_commands() {
        for (input, passphrase) in [("s.json", "-"), ("-", "p"), ("s.json", "p")] {
            assert_eq!(
                parse(&args(&[
                    "secrets",
                    "restore",
                    "--passphrase-file",
                    passphrase,
                    "--in",
                    input
                ])),
                Ok(Command::SecretsRestore {
                    input: PathBuf::from(input),
                    passphrase_file: PathBuf::from(passphrase),
                    config: None
                })
            );
        }
        for (list, confirm) in [
            (&["secrets", "invalidate"][..], false),
            (&["secrets", "invalidate", "--confirm"], true),
        ] {
            assert_eq!(
                parse(&args(list)),
                Ok(Command::SecretsInvalidate {
                    confirm,
                    config: None
                })
            );
        }
        assert_eq!(
            parse(&args(&[
                "secrets",
                "invalidate",
                "--config",
                "/etc/rv",
                "--confirm"
            ])),
            Ok(Command::SecretsInvalidate {
                confirm: true,
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
            &["secrets", "rotate", "--data-key", "--backup-key"],
            &["secrets", "rotate", "--backup-key", "--backup-key"],
            &["secrets", "init", "--backup-key"],
            &["backup", "--out", "f", "--encrypt", "--encrypt"],
            &["backup", "--out", "f", "--backup-key"],
            &["restore", "--in", "f", "--encrypt"],
            &[
                "backup-secrets",
                "--out",
                "b",
                "--passphrase-file",
                "p",
                "--encrypt",
            ],
            &["--database-url", "postgres://u:p@h/d"],
            // ADR 0047: both flags required, stdin for one of them at most, no other flag.
            &["secrets", "restore"],
            &["secrets", "restore", "--in", "s.json"],
            &["secrets", "restore", "--passphrase-file", "p"],
            &["secrets", "restore", "--in", "-", "--passphrase-file", "-"],
            &[
                "secrets",
                "restore",
                "--in",
                "s",
                "--passphrase-file",
                "p",
                "--confirm",
            ],
            &[
                "secrets",
                "restore",
                "--in",
                "s",
                "--passphrase-file",
                "p",
                "--out",
                "o",
            ],
            &[
                "secrets",
                "restore",
                "--in",
                "s",
                "--in",
                "t",
                "--passphrase-file",
                "p",
            ],
            &["secrets", "restore", "--in", "s", "--passphrase-file"],
            &["secrets", "restore", "s.json"],
            &["secrets", "invalidate", "--confirm", "--confirm"],
            &["secrets", "invalidate", "--force"],
            &["secrets", "invalidate", "--confirm=yes"],
            &["secrets", "invalidate", "yes"],
            &["secrets", "invalidate", "--grace-days", "0"],
            &["secrets", "invalidate", "--data-key"],
            &["secrets", "rotate", "--confirm"],
            &["secrets", "retire-setups", "--confirm"],
            &["restore", "--in", "f", "--confirm"],
            &["secrets", "invalidat"],
        ] {
            assert_eq!(parse(&args(bad)), Err(UsageError), "{bad:?}");
        }
    }
}
