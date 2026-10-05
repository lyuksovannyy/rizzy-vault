//! The `rv` command line.
//!
//! No argument is ever a secret (threat model INV-56): passwords, the Secret Key, recovery
//! codes, invite tokens and the values of concealed item fields are read from the terminal
//! without echo, or from standard input ([`crate::ui`]). An option that would take one does not
//! exist, and `--field` refuses a key the item schema conceals.
//!
//! Arguments are read with `args_os` by `main`, so an argument that is not UTF-8 is a usage
//! error, never a panic. [`parse`] is a pure function over the arguments after the program
//! name.

use std::ffi::OsString;
use std::path::PathBuf;

use crate::error::CliError;

/// The help text, printed on `--help` (stdout) and on a usage error (stderr).
pub const USAGE: &str = "\
rv — rizzy-vault command-line client

USAGE:
    rv signup --server <url> --name <login> [--no-recovery-code] [--invite]
    rv login --server <url> --name <login>
    rv unlock
    rv sync
    rv item list [--trash]
    rv item show <item> [--reveal]
    rv item create --type <type> [--field <key>=<value>]... [--secret <key>]...
                   [--uri <uri>]... [--tag <name>]... [<custom field>]...
    rv item edit <item> [--field <key>=<value>]... [--secret <key>]... [--clear <key>]...
                   [--tag <name>]... [--untag <name>]... [--uri <uri>]...
                   [--set-uri <id>=<uri>]... [--remove-uri <id>]... [<custom field>]...
                   [--set-custom <id>=<value>]... [--set-custom-secret <id>]...
                   [--remove-custom <id>]... [--move-uri <id>=<place>]...
                   [--move-custom <id>=<place>]...
    rv item trash <item> | restore <item> | purge <item>
    rv generate [--length <n>] [--no-symbols] [--no-ambiguous] | [--words <n>]
    rv totp <item>
    rv export --out <file> [--format encrypted|json|csv]
    rv import --in <file> --format <format>
    rv device list
    rv device revoke <device> --name <login> [--standard]
    rv device forget
    rv rotate --name <login> [--full]
    rv recovery start --server <url> --name <login>
    rv recovery complete --server <url> --name <login> [--skip-rotation]
    rv recovery cancel
    rv password --name <login> [--rotate]
    rv secret-key --name <login> [--skip-rotation | --full-rotation]
    rv 2fa enable --name <login> | disable --name <login>

OPTIONS:
    --account <id>   The account (hex id) when several are enrolled here
    --ca-file <path> A PEM file of the private CA that issued the server's certificate; it
                     replaces the public roots (also RIZZY_CLI_CA_FILE)
    -h, --help       Print this help
    -V, --version    Print version

<item> and <device> are hex ids or unique prefixes of one, as the list commands print them.
<custom field> is --custom <label>=<text>, --custom-secret <label> (a hidden field; its value
is asked for) or --custom-bool <label>=true|false. <id> is a URI's or custom field's element
id as `item show` prints it in the field's key (uri/<id>/value), or a unique prefix of one.
<place> is first, last, before:<id> or after:<id>.
<type> is login, note, card, identity, ssh-key, api-credential, software-license, wifi,
bank-account or passkey. Field keys are the item schema's (item.name, item.notes,
login.username, login.password, login.totp, card.number, …).
Import formats: bitwarden-json, 1pux, keepass-xml, csv, chrome-csv, firefox-csv, rizzy-json,
rizzy-encrypted.

SECRETS are never taken from the command line or the environment. rv asks for them on the
terminal without echo; when standard input is not a terminal it reads them from it, one per
line, in the order it asks. `--secret <key>` asks for a field's value that way.

LOCAL DATA lives in $RIZZY_CLI_DATA_DIR, or the platform's local data directory
(~/.local/share/rizzy-vault, ~/Library/Application Support/rizzy-vault, %LOCALAPPDATA%\\rizzy-vault).
It holds this device's Secret Key and encrypted vault cache: keep it OUT of backups and
file-sync tools.
";

/// What an export writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportFormat {
    /// The encrypted export (CRYPTO.md §11.14).
    Encrypted,
    /// Plaintext JSON (ADR 0027 §3).
    Json,
    /// Plaintext CSV (ADR 0027 §4).
    Csv,
}

/// What an import reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportFormat {
    /// Bitwarden's unencrypted JSON export.
    BitwardenJson,
    /// 1Password's 1PUX archive.
    OnePux,
    /// `KeePass`'s XML export.
    KeePassXml,
    /// A generic CSV with a header row.
    Csv,
    /// Chrome's password CSV.
    ChromeCsv,
    /// Firefox's password CSV.
    FirefoxCsv,
    /// Our own plaintext JSON export.
    RizzyJson,
    /// Our own encrypted export.
    RizzyEncrypted,
}

/// The field changes of `item create` and `item edit`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FieldArgs {
    /// `--field key=value`: fields that are not concealed.
    pub fields: Vec<(String, String)>,
    /// `--secret key`: fields whose value is asked for.
    pub secrets: Vec<String>,
    /// `--clear key` (edit only).
    pub clear: Vec<String>,
    /// `--uri uri`: a new URI.
    pub uris: Vec<String>,
    /// `--set-uri id=uri` (edit only).
    pub uri_set: Vec<(String, String)>,
    /// `--remove-uri id` (edit only).
    pub uri_remove: Vec<String>,
    /// `--move-uri id=place` (edit only): `first`, `last`, `before:<id>` or `after:<id>`.
    pub uri_move: Vec<(String, String)>,
    /// `--custom label=text`: a new text custom field.
    pub custom: Vec<(String, String)>,
    /// `--custom-secret label`: a new hidden custom field, its value asked for.
    pub custom_secret: Vec<String>,
    /// `--custom-bool label=true|false`: a new boolean custom field.
    pub custom_bool: Vec<(String, String)>,
    /// `--set-custom id=value` (edit only): a custom field that is not hidden.
    pub custom_set: Vec<(String, String)>,
    /// `--set-custom-secret id` (edit only): a custom field's value, asked for.
    pub custom_set_secret: Vec<String>,
    /// `--remove-custom id` (edit only).
    pub custom_remove: Vec<String>,
    /// `--move-custom id=place` (edit only), places as for `--move-uri`.
    pub custom_move: Vec<(String, String)>,
    /// `--tag name`.
    pub tags: Vec<String>,
    /// `--untag name` (edit only).
    pub untag: Vec<String>,
}

/// The options of `rv generate`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Generate {
    /// A character password.
    Characters {
        /// The length.
        length: usize,
        /// Whether symbols are used.
        symbols: bool,
        /// Whether look-alike characters are left out.
        no_ambiguous: bool,
    },
    /// A passphrase of this many words.
    Words(usize),
}

/// A parsed command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// `-h`, `--help`.
    Help,
    /// `-V`, `--version`.
    Version,
    /// `signup`.
    Signup {
        /// `--server`.
        server: String,
        /// `--name`.
        name: String,
        /// Not `--no-recovery-code`.
        recovery_code: bool,
        /// `--invite`: ask for an invite token.
        invite: bool,
    },
    /// `login`.
    Login {
        /// `--server`.
        server: String,
        /// `--name`.
        name: String,
    },
    /// `unlock`.
    Unlock,
    /// `sync`.
    Sync,
    /// `item list`.
    ItemList {
        /// `--trash`: the trashed items instead of the active ones.
        trash: bool,
    },
    /// `item show`.
    ItemShow {
        /// The item.
        item: String,
        /// `--reveal`: print concealed values.
        reveal: bool,
    },
    /// `item create`.
    ItemCreate {
        /// `--type`.
        item_type: String,
        /// The fields.
        fields: FieldArgs,
    },
    /// `item edit`.
    ItemEdit {
        /// The item.
        item: String,
        /// The changes.
        fields: FieldArgs,
    },
    /// `item trash`.
    ItemTrash(String),
    /// `item restore`.
    ItemRestore(String),
    /// `item purge`.
    ItemPurge(String),
    /// `generate`.
    Generate(Generate),
    /// `totp`.
    Totp(String),
    /// `export`.
    Export {
        /// `--out`.
        out: PathBuf,
        /// `--format`.
        format: ExportFormat,
    },
    /// `import`.
    Import {
        /// `--in`.
        input: PathBuf,
        /// `--format`.
        format: ImportFormat,
    },
    /// `device list`.
    DeviceList,
    /// `device revoke`.
    DeviceRevoke {
        /// The device.
        device: String,
        /// `--name`: the login name, for the re-authentication.
        name: String,
        /// `--standard`: a standard rotation instead of the full one.
        standard: bool,
    },
    /// `device forget`.
    DeviceForget,
    /// `rotate`.
    Rotate {
        /// `--name`.
        name: String,
        /// `--full`.
        full: bool,
    },
    /// `recovery start`.
    RecoveryStart {
        /// `--server`.
        server: String,
        /// `--name`.
        name: String,
    },
    /// `recovery complete`.
    RecoveryComplete {
        /// `--server`.
        server: String,
        /// `--name`.
        name: String,
        /// Not `--skip-rotation`: rotate the account and vault keys (the default).
        rotate: bool,
    },
    /// `recovery cancel`.
    RecoveryCancel,
    /// `password`: a new master password (CRYPTO.md §11.5).
    Password {
        /// `--name`: the login name, for the re-authentication.
        name: String,
        /// `--rotate`: also rotate the account key and the vault keys.
        rotate: bool,
    },
    /// `secret-key`: a new Secret Key (CRYPTO.md §11.5).
    SecretKey {
        /// `--name`.
        name: String,
        /// Not `--skip-rotation`: rotate the account and vault keys (the default).
        rotate: bool,
        /// `--full-rotation`: the rotation also replaces the identity keys ("the kit was
        /// stolen").
        full: bool,
    },
    /// `2fa enable` or `2fa disable`.
    TwoFactor {
        /// `--name`.
        name: String,
        /// `enable` rather than `disable`.
        enable: bool,
    },
}

/// A command with the options every command shares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invocation {
    /// `--account`.
    pub account: Option<String>,
    /// `--ca-file`: the private CA file whose certificates replace the public roots for
    /// `https://` servers (ADR 0030 Decision 4). Read only when a command dials one.
    pub ca_file: Option<PathBuf>,
    /// The command.
    pub command: Command,
}

/// A usage error with `what` went wrong.
fn usage(what: impl Into<String>) -> CliError {
    CliError::Usage(what.into())
}

/// The arguments not yet read.
struct Args {
    /// The remaining arguments, in order.
    rest: std::vec::IntoIter<String>,
}

impl Args {
    /// The next argument, if any.
    fn next(&mut self) -> Option<String> {
        self.rest.next()
    }

    /// The value of option `name`.
    fn value(&mut self, name: &str) -> Result<String, CliError> {
        self.next()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| usage(format!("{name} needs a value")))
    }

    /// The next argument as a positional `what`.
    fn positional(&mut self, what: &str) -> Result<String, CliError> {
        match self.next() {
            Some(v) if !v.starts_with('-') && !v.is_empty() => Ok(v),
            _ => Err(usage(format!("{what} is missing"))),
        }
    }

    /// Fails if an argument is left.
    fn done(&mut self) -> Result<(), CliError> {
        match self.next() {
            None => Ok(()),
            Some(extra) => Err(unknown(&extra)),
        }
    }
}

/// The longest option name an "unknown option" message repeats.
const MAX_ECHOED_OPTION_LEN: usize = 32;

/// The error for an argument no command takes. The argument itself is not echoed unless it is
/// an option name: a mistyped positional could be a secret typed in the wrong place.
///
/// Only the name is ever repeated, never a value: `--password=hunter2` is cut at the first
/// `=`, and what is left is echoed only if it has the shape of `rv`'s own option names (`--`,
/// a lower-case ASCII letter, then lower-case letters and `-`, at most
/// [`MAX_ECHOED_OPTION_LEN`] bytes). Anything else is reported without a byte of it (threat
/// model INV-56; [`CliError::Usage`] is the one error that carries text the caller typed).
fn unknown(argument: &str) -> CliError {
    let name = argument.split_once('=').map_or(argument, |(name, _)| name);
    let is_option_name = name.len() <= MAX_ECHOED_OPTION_LEN
        && name.strip_prefix("--").is_some_and(|rest| {
            rest.starts_with(|c: char| c.is_ascii_lowercase())
                && rest.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
        });
    if is_option_name {
        usage(format!("unknown option {name}"))
    } else {
        usage("unexpected argument")
    }
}

/// A required option's value.
fn required(value: Option<String>, name: &str) -> Result<String, CliError> {
    value.ok_or_else(|| usage(format!("{name} is required")))
}

/// Parses the arguments after the program name.
///
/// # Errors
/// [`CliError::Usage`].
pub fn parse(arguments: Vec<OsString>) -> Result<Invocation, CliError> {
    let mut strings = Vec::with_capacity(arguments.len());
    for argument in arguments {
        strings.push(
            argument
                .into_string()
                .map_err(|_| usage("an argument is not valid UTF-8"))?,
        );
    }
    // `--account` and `--ca-file` may come anywhere; take them out first.
    let (mut account, mut ca_file) = (None, None);
    let mut rest = Vec::with_capacity(strings.len());
    let mut iter = strings.into_iter();
    while let Some(argument) = iter.next() {
        if argument == "--account" {
            account = Some(
                iter.next()
                    .filter(|v| !v.is_empty())
                    .ok_or_else(|| usage("--account needs a value"))?,
            );
        } else if argument == "--ca-file" {
            ca_file = Some(PathBuf::from(
                iter.next()
                    .filter(|v| !v.is_empty())
                    .ok_or_else(|| usage("--ca-file needs a value"))?,
            ));
        } else {
            rest.push(argument);
        }
    }
    let mut args = Args {
        rest: rest.into_iter(),
    };
    let command = match args.next().as_deref() {
        Some("-h" | "--help") => Command::Help,
        Some("-V" | "--version") => Command::Version,
        Some("signup") => signup(&mut args)?,
        Some("login") => {
            let (server, name) = server_and_name(&mut args)?;
            Command::Login { server, name }
        }
        Some("unlock") => Command::Unlock,
        Some("sync") => Command::Sync,
        Some("item") => item(&mut args)?,
        Some("generate") => generate(&mut args)?,
        Some("totp") => Command::Totp(args.positional("the item")?),
        Some("export") => export(&mut args)?,
        Some("import") => import(&mut args)?,
        Some("device") => device(&mut args)?,
        Some("rotate") => {
            let (mut name, mut full) = (None, false);
            while let Some(option) = args.next() {
                match option.as_str() {
                    "--name" => name = Some(args.value("--name")?),
                    "--full" => full = true,
                    other => return Err(unknown(other)),
                }
            }
            Command::Rotate {
                name: required(name, "--name")?,
                full,
            }
        }
        Some("recovery") => match args.next().as_deref() {
            Some("start") => {
                let (server, name) = server_and_name(&mut args)?;
                Command::RecoveryStart { server, name }
            }
            Some("complete") => {
                let (mut server, mut name, mut rotate) = (None, None, true);
                while let Some(option) = args.next() {
                    match option.as_str() {
                        "--server" => server = Some(args.value("--server")?),
                        "--name" => name = Some(args.value("--name")?),
                        "--skip-rotation" => rotate = false,
                        other => return Err(unknown(other)),
                    }
                }
                Command::RecoveryComplete {
                    server: required(server, "--server")?,
                    name: required(name, "--name")?,
                    rotate,
                }
            }
            Some("cancel") => Command::RecoveryCancel,
            _ => return Err(usage("recovery needs start, complete or cancel")),
        },
        Some(word @ ("password" | "secret-key" | "2fa")) => account_command(&mut args, word)?,
        Some(other) => return Err(unknown(other)),
        None => return Err(usage("no command")),
    };
    args.done()?;
    Ok(Invocation {
        account,
        ca_file,
        command,
    })
}

/// `--server` and `--name`, both required, in any order.
fn server_and_name(args: &mut Args) -> Result<(String, String), CliError> {
    let (mut server, mut name) = (None, None);
    while let Some(option) = args.next() {
        match option.as_str() {
            "--server" => server = Some(args.value("--server")?),
            "--name" => name = Some(args.value("--name")?),
            other => return Err(unknown(other)),
        }
    }
    Ok((required(server, "--server")?, required(name, "--name")?))
}

/// `password`, `secret-key` and `2fa …` (`word`).
fn account_command(args: &mut Args, word: &str) -> Result<Command, CliError> {
    Ok(match word {
        "password" => {
            let (name, rotate) = name_and_flag(args, "--rotate")?;
            Command::Password { name, rotate }
        }
        "secret-key" => secret_key_command(args)?,
        _ => {
            let enable = match args.next().as_deref() {
                Some("enable") => true,
                Some("disable") => false,
                _ => return Err(usage("2fa needs enable or disable")),
            };
            let (name, _) = name_and_flag(args, "")?;
            Command::TwoFactor { name, enable }
        }
    })
}

/// `secret-key`: `--name`, and at most one of `--skip-rotation` and `--full-rotation`, in any
/// order.
fn secret_key_command(args: &mut Args) -> Result<Command, CliError> {
    let (mut name, mut skip, mut full) = (None, false, false);
    while let Some(option) = args.next() {
        match option.as_str() {
            "--name" => name = Some(args.value("--name")?),
            "--skip-rotation" => skip = true,
            "--full-rotation" => full = true,
            other => return Err(unknown(other)),
        }
    }
    if skip && full {
        return Err(usage(
            "--skip-rotation and --full-rotation contradict each other",
        ));
    }
    Ok(Command::SecretKey {
        name: required(name, "--name")?,
        rotate: !skip,
        full,
    })
}

/// `--name`, required, and the optional flag `flag` (none when empty), in any order.
fn name_and_flag(args: &mut Args, flag: &str) -> Result<(String, bool), CliError> {
    let (mut name, mut set) = (None, false);
    while let Some(option) = args.next() {
        match option.as_str() {
            "--name" => name = Some(args.value("--name")?),
            other if !flag.is_empty() && other == flag => set = true,
            other => return Err(unknown(other)),
        }
    }
    Ok((required(name, "--name")?, set))
}

/// `signup`.
fn signup(args: &mut Args) -> Result<Command, CliError> {
    let (mut server, mut name, mut recovery_code, mut invite) = (None, None, true, false);
    while let Some(option) = args.next() {
        match option.as_str() {
            "--server" => server = Some(args.value("--server")?),
            "--name" => name = Some(args.value("--name")?),
            "--no-recovery-code" => recovery_code = false,
            "--invite" => invite = true,
            other => return Err(unknown(other)),
        }
    }
    Ok(Command::Signup {
        server: required(server, "--server")?,
        name: required(name, "--name")?,
        recovery_code,
        invite,
    })
}

/// `item …`.
fn item(args: &mut Args) -> Result<Command, CliError> {
    match args.next().as_deref() {
        Some("list") => {
            let trash = match args.next().as_deref() {
                None => false,
                Some("--trash") => true,
                Some(other) => return Err(unknown(other)),
            };
            Ok(Command::ItemList { trash })
        }
        Some("show") => {
            let item = args.positional("the item")?;
            let reveal = match args.next().as_deref() {
                None => false,
                Some("--reveal") => true,
                Some(other) => return Err(unknown(other)),
            };
            Ok(Command::ItemShow { item, reveal })
        }
        Some("create") => {
            let mut item_type = None;
            let fields = field_args(args, true, &mut item_type)?;
            Ok(Command::ItemCreate {
                item_type: required(item_type, "--type")?,
                fields,
            })
        }
        Some("edit") => {
            let item = args.positional("the item")?;
            let fields = field_args(args, false, &mut None)?;
            Ok(Command::ItemEdit { item, fields })
        }
        Some("trash") => Ok(Command::ItemTrash(args.positional("the item")?)),
        Some("restore") => Ok(Command::ItemRestore(args.positional("the item")?)),
        Some("purge") => Ok(Command::ItemPurge(args.positional("the item")?)),
        _ => Err(usage(
            "item needs list, show, create, edit, trash, restore or purge",
        )),
    }
}

/// The field options of `item create` (`create`) or `item edit`.
fn field_args(
    args: &mut Args,
    create: bool,
    item_type: &mut Option<String>,
) -> Result<FieldArgs, CliError> {
    let mut fields = FieldArgs::default();
    while let Some(option) = args.next() {
        match option.as_str() {
            "--type" if create => *item_type = Some(args.value("--type")?),
            "--field" => {
                let pair = args.value("--field")?;
                let (key, value) = pair
                    .split_once('=')
                    .ok_or_else(|| usage("--field takes <key>=<value>"))?;
                fields.fields.push((key.to_owned(), value.to_owned()));
            }
            "--secret" => fields.secrets.push(args.value("--secret")?),
            "--tag" => fields.tags.push(args.value("--tag")?),
            "--uri" => fields.uris.push(args.value("--uri")?),
            "--custom" => fields
                .custom
                .push(pair(args, "--custom", "<label>=<text>")?),
            "--custom-secret" => fields.custom_secret.push(args.value("--custom-secret")?),
            "--custom-bool" => {
                fields
                    .custom_bool
                    .push(pair(args, "--custom-bool", "<label>=true|false")?);
            }
            "--set-uri" if !create => fields.uri_set.push(pair(args, "--set-uri", "<id>=<uri>")?),
            "--remove-uri" if !create => fields.uri_remove.push(args.value("--remove-uri")?),
            "--move-uri" if !create => {
                fields
                    .uri_move
                    .push(pair(args, "--move-uri", "<id>=<place>")?);
            }
            "--move-custom" if !create => {
                fields
                    .custom_move
                    .push(pair(args, "--move-custom", "<id>=<place>")?);
            }
            "--set-custom" if !create => {
                fields
                    .custom_set
                    .push(pair(args, "--set-custom", "<id>=<value>")?);
            }
            "--set-custom-secret" if !create => fields
                .custom_set_secret
                .push(args.value("--set-custom-secret")?),
            "--remove-custom" if !create => {
                fields.custom_remove.push(args.value("--remove-custom")?);
            }
            "--clear" if !create => fields.clear.push(args.value("--clear")?),
            "--untag" if !create => fields.untag.push(args.value("--untag")?),
            other => return Err(unknown(other)),
        }
    }
    Ok(fields)
}

/// The value of `option` split at its first `=`: `<a>=<b>` as `form` names it.
fn pair(args: &mut Args, option: &str, form: &str) -> Result<(String, String), CliError> {
    let text = args.value(option)?;
    let (a, b) = text
        .split_once('=')
        .ok_or_else(|| usage(format!("{option} takes {form}")))?;
    Ok((a.to_owned(), b.to_owned()))
}

/// `generate`.
fn generate(args: &mut Args) -> Result<Command, CliError> {
    let (mut length, mut symbols, mut no_ambiguous, mut words) = (20usize, true, false, None);
    let number = |text: String, name: &str| {
        text.parse::<usize>()
            .map_err(|_| usage(format!("{name} takes a number")))
    };
    while let Some(option) = args.next() {
        match option.as_str() {
            "--length" => length = number(args.value("--length")?, "--length")?,
            "--words" => words = Some(number(args.value("--words")?, "--words")?),
            "--no-symbols" => symbols = false,
            "--no-ambiguous" => no_ambiguous = true,
            other => return Err(unknown(other)),
        }
    }
    Ok(Command::Generate(match words {
        Some(words) => Generate::Words(words),
        None => Generate::Characters {
            length,
            symbols,
            no_ambiguous,
        },
    }))
}

/// `export`.
fn export(args: &mut Args) -> Result<Command, CliError> {
    let (mut out, mut format) = (None, ExportFormat::Encrypted);
    while let Some(option) = args.next() {
        match option.as_str() {
            "--out" => out = Some(args.value("--out")?),
            "--format" => {
                format = match args.value("--format")?.as_str() {
                    "encrypted" => ExportFormat::Encrypted,
                    "json" => ExportFormat::Json,
                    "csv" => ExportFormat::Csv,
                    _ => return Err(usage("--format takes encrypted, json or csv")),
                }
            }
            other => return Err(unknown(other)),
        }
    }
    Ok(Command::Export {
        out: PathBuf::from(required(out, "--out")?),
        format,
    })
}

/// `import`.
fn import(args: &mut Args) -> Result<Command, CliError> {
    let (mut input, mut format) = (None, None);
    while let Some(option) = args.next() {
        match option.as_str() {
            "--in" => input = Some(args.value("--in")?),
            "--format" => {
                format = Some(match args.value("--format")?.as_str() {
                    "bitwarden-json" => ImportFormat::BitwardenJson,
                    "1pux" => ImportFormat::OnePux,
                    "keepass-xml" => ImportFormat::KeePassXml,
                    "csv" => ImportFormat::Csv,
                    "chrome-csv" => ImportFormat::ChromeCsv,
                    "firefox-csv" => ImportFormat::FirefoxCsv,
                    "rizzy-json" => ImportFormat::RizzyJson,
                    "rizzy-encrypted" => ImportFormat::RizzyEncrypted,
                    _ => return Err(usage("unknown import format")),
                });
            }
            other => return Err(unknown(other)),
        }
    }
    Ok(Command::Import {
        input: PathBuf::from(required(input, "--in")?),
        format: format.ok_or_else(|| usage("--format is required"))?,
    })
}

/// `device …`.
fn device(args: &mut Args) -> Result<Command, CliError> {
    match args.next().as_deref() {
        Some("list") => Ok(Command::DeviceList),
        Some("forget") => Ok(Command::DeviceForget),
        Some("revoke") => {
            let device = args.positional("the device")?;
            let (mut name, mut standard) = (None, false);
            while let Some(option) = args.next() {
                match option.as_str() {
                    "--name" => name = Some(args.value("--name")?),
                    "--standard" => standard = true,
                    other => return Err(unknown(other)),
                }
            }
            Ok(Command::DeviceRevoke {
                device,
                name: required(name, "--name")?,
                standard,
            })
        }
        _ => Err(usage("device needs list, revoke or forget")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(line: &str) -> Result<Invocation, CliError> {
        parse(line.split_whitespace().map(OsString::from).collect())
    }

    fn command(line: &str) -> Command {
        parsed(line).unwrap().command
    }

    #[test]
    fn commands_parse() {
        assert_eq!(command("--help"), Command::Help);
        assert_eq!(command("-V"), Command::Version);
        assert_eq!(
            command("signup --name alice --server https://v.example --no-recovery-code"),
            Command::Signup {
                server: "https://v.example".to_owned(),
                name: "alice".to_owned(),
                recovery_code: false,
                invite: false,
            }
        );
        assert_eq!(
            command("item list --trash"),
            Command::ItemList { trash: true }
        );
        assert_eq!(
            command("item show ab12 --reveal"),
            Command::ItemShow {
                item: "ab12".to_owned(),
                reveal: true
            }
        );
        let Command::ItemCreate { item_type, fields } = command(
            "item create --type login --field item.name=Mail --secret login.password --uri https://m.example --tag work",
        ) else {
            panic!("item create");
        };
        assert_eq!(item_type, "login");
        assert_eq!(fields.fields, [("item.name".to_owned(), "Mail".to_owned())]);
        assert_eq!(fields.secrets, ["login.password"]);
        assert_eq!(fields.uris, ["https://m.example"]);
        assert_eq!(fields.tags, ["work"]);
        assert_eq!(
            command("generate --length 32 --no-symbols"),
            Command::Generate(Generate::Characters {
                length: 32,
                symbols: false,
                no_ambiguous: false
            })
        );
        assert_eq!(
            command("generate --words 5"),
            Command::Generate(Generate::Words(5))
        );
        assert_eq!(
            command("export --out f.rvx"),
            Command::Export {
                out: PathBuf::from("f.rvx"),
                format: ExportFormat::Encrypted
            }
        );
        assert_eq!(
            command("import --format 1pux --in a.1pux"),
            Command::Import {
                input: PathBuf::from("a.1pux"),
                format: ImportFormat::OnePux
            }
        );
        assert_eq!(
            command("device revoke ab --name alice"),
            Command::DeviceRevoke {
                device: "ab".to_owned(),
                name: "alice".to_owned(),
                standard: false
            }
        );
        assert_eq!(command("recovery cancel"), Command::RecoveryCancel);
        let with_account = parsed("sync --account 00ff").unwrap();
        assert_eq!(with_account.account.as_deref(), Some("00ff"));
        assert_eq!(with_account.command, Command::Sync);
        assert_eq!(with_account.ca_file, None);
        let with_ca =
            parsed("--ca-file /etc/rv/ca.pem login --server https://v.example --name a").unwrap();
        assert_eq!(
            with_ca.ca_file.as_deref(),
            Some(std::path::Path::new("/etc/rv/ca.pem"))
        );
        assert!(matches!(with_ca.command, Command::Login { .. }));
        assert!(matches!(parsed("sync --ca-file"), Err(CliError::Usage(_))));
    }

    #[test]
    fn usage_errors_never_echo_a_positional() {
        for line in [
            "",
            "frobnicate",
            "signup --name a",
            "item",
            "item show",
            "item create --type login --remove-uri ab",
            "item create --field novalue --type login",
            "generate --length many",
            "export",
            "export --out f --format xml",
            "import --in f",
            "sync extra",
            "device revoke ab",
            "--account",
        ] {
            assert!(matches!(parsed(line), Err(CliError::Usage(_))), "{line}");
        }
        // An unexpected positional (it could be a secret typed in the wrong place) is not
        // repeated in the message; an unknown option name is.
        let CliError::Usage(message) = parsed("unlock hunter2").unwrap_err() else {
            panic!("usage");
        };
        assert!(!message.contains("hunter2"), "{message}");
        let CliError::Usage(message) = parsed("unlock --password").unwrap_err() else {
            panic!("usage");
        };
        assert!(message.contains("--password"), "{message}");
        // A value glued to an unknown option is never repeated, only the option's name; and
        // an argument that is not an option name at all is not repeated in any part.
        let CliError::Usage(message) = parsed("unlock --password=hunter2").unwrap_err() else {
            panic!("usage");
        };
        assert_eq!(message, "unknown option --password");
        for secret in [
            "unlock -hunter2",
            "unlock --=hunter2",
            "unlock --Hunter2",
            "unlock --hunterhunterhunterhunterhunterhunter",
            "unlock -12345678",
        ] {
            let CliError::Usage(message) = parsed(secret).unwrap_err() else {
                panic!("usage");
            };
            assert_eq!(message, "unexpected argument", "{secret}");
        }
    }

    #[test]
    fn account_commands_parse() {
        assert_eq!(
            command("password --name alice --rotate"),
            Command::Password {
                name: "alice".to_owned(),
                rotate: true
            }
        );
        assert_eq!(
            command("secret-key --skip-rotation --name alice"),
            Command::SecretKey {
                name: "alice".to_owned(),
                rotate: false,
                full: false
            }
        );
        assert_eq!(
            command("secret-key --full-rotation --name alice"),
            Command::SecretKey {
                name: "alice".to_owned(),
                rotate: true,
                full: true
            }
        );
        assert_eq!(
            command("2fa disable --name alice"),
            Command::TwoFactor {
                name: "alice".to_owned(),
                enable: false
            }
        );
        for line in [
            "password",
            "password --name alice --skip-rotation",
            "secret-key --name alice --rotate",
            "secret-key --name alice --skip-rotation --full-rotation",
            "secret-key --full-rotation",
            "2fa --name alice",
            "2fa enable",
            "2fa enable --name alice 123456",
        ] {
            assert!(matches!(parsed(line), Err(CliError::Usage(_))), "{line}");
        }
    }
}
