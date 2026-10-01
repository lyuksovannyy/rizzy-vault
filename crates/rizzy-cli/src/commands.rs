//! The `rv` commands (ROADMAP §4.2: "CLI client (`rv`) — list, get, add, generate, copy
//! TOTP", with import, export, devices and rotation).
//!
//! [`run`] takes a parsed [`Invocation`] and an [`Env`] and does one command. Everything the
//! user types or reads goes through [`Env::ui`], so the end-to-end tests run the same code with
//! scripted answers.
//!
//! # What runs offline
//!
//! `item list`, `item show`, `totp`, `export` and `generate` need no network: the cache is
//! unlocked and loaded, and that is all (ROADMAP §4.2 "Offline read access"). `rv sync` brings
//! the cache up to date. A command that writes (`item create/edit/trash/restore/purge`,
//! `import`) commits the new ops to the cache first and then syncs; if the server cannot be
//! reached the ops stay queued, the command says so and still succeeds, and the next sync
//! uploads them.
//!
//! # Secrets (threat model INV-56)
//!
//! - **In:** never from the command line. `--field` refuses a key the schema conceals;
//!   `--secret <key>` asks for the value.
//! - **Out:** `item show` prints a concealed field as `********` unless `--reveal` is given.
//!   `generate` and `totp` print what they were asked for. `signup`, `secret-key` and
//!   `recovery complete` print the Emergency Kit once, `2fa enable` the 2FA secret once.
//!   Nothing else prints a secret, and no error or note ever does.
//!   Copying to the clipboard instead of printing (INV-56's default for a terminal) is not in
//!   this build (reported): it needs a platform clipboard crate.
//!
//! # Removing this device (`device forget`; ADR 0026 §5)
//!
//! "The only recovery is 'remove this device'." The command uploads the own ops the server
//! never acknowledged, byte for byte, when the cache unlocks and loads; says what would be
//! lost; asks for the word `FORGET`; and deletes the account's files. It is refused while a
//! rollback, fork or identity alarm is raised (the file is the evidence), and allowed under
//! the "device state outdated" alarm, whose only resolution it is. When the cache does not
//! load or the password is not at hand, the unsent edits cannot be verified: they are
//! discarded, after the same warning and confirmation. The alarm rule holds in that case too:
//! the alarm rows are cleartext and are read without unlocking (`refuse_under_alarm`), so a
//! mistyped password never removes a file that is evidence.

use std::path::Path;

use rizzy_client::ClientError;
use rizzy_client::export::plaintext::{
    PLAINTEXT_EXPORT_PHRASE, PLAINTEXT_EXPORT_WARNING, PlaintextExportAck, csv_export_warning,
};
use rizzy_client::items::{FieldEdit, FieldKey, ItemId, ItemLifecycle, ItemType, Value};
use rizzy_client::rizzy_import::{self, Format};
use rizzy_client::rotation::RotationLevel;
use rizzy_client::signup::DeviceKind;
use rizzy_client::store::rows::Alarm;
use rizzy_client::sync::VaultSync;
use rizzy_core::generator::{
    CharacterOptions, ClassRule, PassphraseOptions, generate_passphrase, generate_password,
};
use rizzy_core::ids::DeviceId;
use rizzy_core::item::key::ElementId;
use rizzy_core::item::order::evenly_spaced;
use rizzy_core::item::schema::{
    ATTR_ORDER, ATTR_VALUE, Concealment, Expected, ITEM_NAME, KeyClass, LIST_URI, LOGIN_TOTP,
    classify,
};
use rizzy_core::item::tag::{tag_key, tag_name};
use rizzy_core::item::value::ValueRef;
use rizzy_core::totp::{OtpAuthUri, TotpParams, TotpSecret};
use zeroize::Zeroizing;

use crate::account;
use crate::args::{Command, ExportFormat, FieldArgs, Generate, ImportFormat, Invocation, USAGE};
use crate::db::Db;
use crate::device::{CredentialChange, Device, Env, pick_account};
use crate::enrol;
use crate::error::{CliError, alarm_text};
use crate::paths::{AccountLock, cache_path, hex, read_limited, unhex, write_new_file};
use crate::recover;
use crate::sys::{now_ms, os_rng};
use crate::ui::Ui;

/// The word that confirms `device forget`.
const FORGET_WORD: &str = "FORGET";

/// What `item show` prints in place of a concealed value.
const CONCEALED: &str = "********";

/// The largest file an import reads: the largest input any importer accepts (a 1PUX archive).
const MAX_IMPORT_FILE_LEN: usize = rizzy_import::limits::MAX_ARCHIVE_LEN;

/// Runs one command.
///
/// # Errors
/// [`CliError`]; its `Display` is what the user reads.
#[expect(clippy::too_many_lines, reason = "one arm per command")]
pub async fn run(invocation: Invocation, env: &mut Env<'_>) -> Result<(), CliError> {
    if let Some(account) = &invocation.account {
        env.account = Some(
            unhex::<16>(account)
                .ok_or_else(|| CliError::Usage("--account takes a hex id".into()))?,
        );
    }
    match invocation.command {
        Command::Help => env.ui.print(USAGE.trim_end()),
        Command::Version => env.ui.print(concat!("rv ", env!("CARGO_PKG_VERSION"))),
        Command::Signup {
            server,
            name,
            recovery_code,
            invite,
        } => {
            let device =
                Box::pin(enrol::signup(env, &server, &name, recovery_code, invite)).await?;
            env.ui.note(&format!(
                "Signed up. This device is enrolled as account {}.",
                device.account_hex()
            ));
            Ok(())
        }
        Command::Login { server, name } => {
            let device = Box::pin(enrol::login(env, &server, &name)).await?;
            env.ui.note(&format!(
                "Logged in. This device is enrolled as account {}; {} items.",
                device.account_hex(),
                visible_items(device.vault(), false).len()
            ));
            Ok(())
        }
        Command::Unlock => Box::pin(unlock(env)).await,
        Command::Sync => {
            let mut device = Device::open(env).await?;
            device.sync(env.ui).await?;
            env.ui.note(&format!(
                "Synced; {} items.",
                visible_items(device.vault(), false).len()
            ));
            Ok(())
        }
        Command::ItemList { trash } => {
            let device = Device::open(env).await?;
            item_list(&device, env.ui, trash)
        }
        Command::ItemShow { item, reveal } => {
            let device = Device::open(env).await?;
            item_show(&device, env.ui, &item, reveal)
        }
        Command::ItemCreate { item_type, fields } => {
            Box::pin(item_create(env, &item_type, &fields)).await
        }
        Command::ItemEdit { item, fields } => Box::pin(item_edit(env, &item, &fields)).await,
        Command::ItemTrash(item) => {
            Box::pin(lifecycle(env, &item, |vault, rng, unlocked, item, now| {
                vault.trash_item(rng, unlocked, item, now)
            }))
            .await
        }
        Command::ItemRestore(item) => {
            Box::pin(lifecycle(env, &item, |vault, rng, unlocked, item, now| {
                vault.restore_item(rng, unlocked, item, now)
            }))
            .await
        }
        Command::ItemPurge(item) => {
            Box::pin(lifecycle(env, &item, |vault, rng, unlocked, item, now| {
                vault.purge_item(rng, unlocked, item, now)
            }))
            .await
        }
        Command::Generate(options) => generate(env.ui, options),
        Command::Totp(item) => {
            let device = Device::open(env).await?;
            totp(&device, env.ui, &item)
        }
        Command::Export { out, format } => export(env, &out, format).await,
        Command::Import { input, format } => Box::pin(import(env, &input, format)).await,
        Command::DeviceList => Box::pin(device_list(env)).await,
        Command::DeviceRevoke {
            device,
            name,
            standard,
        } => Box::pin(device_revoke(env, &device, &name, standard)).await,
        Command::DeviceForget => device_forget(env).await,
        Command::Rotate { name, full } => {
            let mut device = Device::open(env).await?;
            let level = if full {
                RotationLevel::Full
            } else {
                RotationLevel::Standard
            };
            let dropped = Box::pin(device.rotate(env.ui, &name, level, None)).await?;
            report_rotation(env.ui, dropped);
            Ok(())
        }
        Command::RecoveryStart { server, name } => recover::start(env, &server, &name).await,
        Command::RecoveryComplete {
            server,
            name,
            rotate,
        } => Box::pin(recover::complete(env, &server, &name, rotate)).await,
        Command::RecoveryCancel => Box::pin(recover::cancel(env)).await,
        Command::Password { name, rotate } => {
            Box::pin(account::change(
                env,
                &name,
                CredentialChange::Password { rotate },
            ))
            .await
        }
        Command::SecretKey { name, rotate } => {
            Box::pin(account::change(
                env,
                &name,
                CredentialChange::SecretKey { rotate },
            ))
            .await
        }
        Command::TwoFactor { name, enable } => {
            Box::pin(account::two_factor(env, &name, enable)).await
        }
    }
}

/// What a rotation did, for the user.
fn report_rotation(ui: &mut dyn Ui, dropped: usize) {
    ui.note("The account key and the vault key were rotated.");
    if dropped > 0 {
        ui.note(&format!(
            "{dropped} item keys could not be opened and were dropped: those items are no \
             longer readable on any device."
        ));
    }
}

/// The items a list shows: active ones, or trashed ones, without the vault-settings item.
fn visible_items(vault: &VaultSync, trash: bool) -> Vec<ItemId> {
    let wanted = if trash {
        ItemLifecycle::Trashed
    } else {
        ItemLifecycle::Active
    };
    vault
        .item_ids()
        .into_iter()
        .filter(|item| {
            vault.item_lifecycle(*item) == wanted
                && vault.item_type(*item) != Some(ItemType::VAULT_SETTINGS)
        })
        .collect()
}

/// The item a hex id or a unique prefix of one names, among the active and trashed items.
fn resolve_item(vault: &VaultSync, text: &str) -> Result<ItemId, CliError> {
    let wanted = text.to_ascii_lowercase();
    if wanted.is_empty() || !wanted.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(CliError::BadInput(
            "an item is named by its hex id or a prefix of it",
        ));
    }
    let mut matches = vault.item_ids().into_iter().filter(|item| {
        hex(item.as_bytes()).starts_with(&wanted)
            && matches!(
                vault.item_lifecycle(*item),
                ItemLifecycle::Active | ItemLifecycle::Trashed
            )
    });
    match (matches.next(), matches.next()) {
        (Some(item), None) => Ok(item),
        (None, _) => Err(CliError::Client(ClientError::UnknownItem)),
        (Some(_), Some(_)) => Err(CliError::BadInput("several items start with that id")),
    }
}

/// The name of an item type, as `--type` takes it.
fn type_name(item_type: Option<ItemType>) -> &'static str {
    TYPES
        .iter()
        .find(|(_, t)| Some(*t) == item_type)
        .map_or("unknown", |(name, _)| name)
}

/// The item types `--type` names.
const TYPES: [(&str, ItemType); 10] = [
    ("login", ItemType::LOGIN),
    ("note", ItemType::SECURE_NOTE),
    ("card", ItemType::CARD),
    ("identity", ItemType::IDENTITY),
    ("ssh-key", ItemType::SSH_KEY),
    ("api-credential", ItemType::API_CREDENTIAL),
    ("software-license", ItemType::SOFTWARE_LICENSE),
    ("wifi", ItemType::WIFI),
    ("bank-account", ItemType::BANK_ACCOUNT),
    ("passkey", ItemType::PASSKEY),
];

/// A displayed value as text for the terminal. Bytes and sort keys are described, not dumped.
fn show_value(value: &Value) -> Zeroizing<String> {
    Zeroizing::new(match value.decode() {
        Ok(ValueRef::Text(text)) => text.to_owned(),
        Ok(ValueRef::Bool(flag)) => flag.to_string(),
        Ok(ValueRef::U64(number)) => number.to_string(),
        Ok(ValueRef::Enum(number)) => number.to_string(),
        Ok(ValueRef::Bytes(bytes)) => format!("({} bytes)", bytes.len()),
        Ok(ValueRef::SortKey(key)) => format!("(order {})", hex(key)),
        Ok(ValueRef::Cleared) => String::new(),
        Err(_) => "(a value this version cannot show)".to_owned(),
    })
}

/// The text of a field, if it holds a text.
fn text_field(vault: &VaultSync, item: ItemId, key: &str) -> Option<Zeroizing<String>> {
    let value = vault.field_value(item, key)?;
    match value.decode() {
        Ok(ValueRef::Text(text)) => Some(Zeroizing::new(text.to_owned())),
        _ => None,
    }
}

/// Whether a field's value is concealed unless `--reveal` is given: what the schema conceals,
/// and, to be safe, every key this build does not know.
fn concealed(key: &FieldKey) -> bool {
    match classify(key.as_key()) {
        KeyClass::Known(spec) => spec.concealment != Concealment::Shown,
        _ => true,
    }
}

/// `unlock`: the offline unlock, then the online part; prints where the device stands.
async fn unlock(env: &mut Env<'_>) -> Result<(), CliError> {
    let mut device = Device::open(env).await?;
    let online = device.online(env.ui).await;
    let state = device.state();
    env.ui
        .print(&format!("account:  {}", device.account_hex()))?;
    env.ui
        .print(&format!("device:   {}", hex(state.device_id().as_bytes())))?;
    env.ui
        .print(&format!("server:   {}", state.server_origin().as_str()))?;
    env.ui.print(&format!(
        "items:    {}",
        visible_items(device.vault(), false).len()
    ))?;
    for alarm in device.alarms() {
        env.ui.print(&format!("ALARM:    {}", alarm_text(*alarm)))?;
    }
    match online {
        Ok(()) => env.ui.print("online:   yes, the account state verified"),
        Err(CliError::Network) => env
            .ui
            .print("online:   no, the server was not reached; the local copy is unlocked"),
        Err(e) => Err(e),
    }
}

/// `item list`.
fn item_list(device: &Device, ui: &mut dyn Ui, trash: bool) -> Result<(), CliError> {
    let vault = device.vault();
    for item in visible_items(vault, trash) {
        let name = text_field(vault, item, ITEM_NAME).unwrap_or_default();
        ui.print(&format!(
            "{}  {:<16}  {}",
            hex(item.as_bytes()),
            type_name(vault.item_type(item)),
            name.as_str()
        ))?;
    }
    Ok(())
}

/// `item show`.
fn item_show(device: &Device, ui: &mut dyn Ui, item: &str, reveal: bool) -> Result<(), CliError> {
    let vault = device.vault();
    let item = resolve_item(vault, item)?;
    ui.print(&format!("id:    {}", hex(item.as_bytes())))?;
    ui.print(&format!("type:  {}", type_name(vault.item_type(item))))?;
    if vault.item_lifecycle(item) == ItemLifecycle::Trashed {
        ui.print("state: in the trash")?;
    }
    for key in vault.field_keys(item) {
        let Ok(parsed) = FieldKey::parse(key.as_bytes()) else {
            continue;
        };
        let Some(value) = vault.field_value(item, &key) else {
            continue;
        };
        if value.is_cleared() {
            continue;
        }
        // A tag is its name, not a hex key.
        let label = match tag_name(parsed.as_key()) {
            Ok(name) => Zeroizing::new(format!("tag {}", name.as_str())),
            Err(_) => Zeroizing::new(key.as_str().to_owned()),
        };
        let shown = if concealed(&parsed) && !reveal {
            Zeroizing::new(CONCEALED.to_owned())
        } else {
            show_value(&value)
        };
        let conflict = if vault.field_conflicts(item, &key) {
            "  (conflicting values; this is the one shown everywhere)"
        } else {
            ""
        };
        let line = Zeroizing::new(format!("{}: {}{conflict}", label.as_str(), shown.as_str()));
        ui.print(&line)?;
    }
    Ok(())
}

/// The encoded value of `text` for `key`, as the schema expects it.
fn encode_value(key: &FieldKey, text: &str) -> Result<Value, CliError> {
    let bad = CliError::BadInput("the value does not fit the field");
    let KeyClass::Known(spec) = classify(key.as_key()) else {
        return Err(CliError::BadInput("not a field this version can write"));
    };
    match spec.expected {
        Expected::Text | Expected::CustomFieldValue => Value::text(text).map_err(|_| bad),
        Expected::Bool => match text {
            "true" | "yes" => Ok(Value::bool(true)),
            "false" | "no" => Ok(Value::bool(false)),
            _ => Err(bad),
        },
        Expected::U64 => text.parse().map(Value::u64).map_err(|_| bad),
        Expected::Enum => text.parse().map(Value::enumeration).map_err(|_| bad),
        _ => Err(CliError::BadInput("not a field this version can write")),
    }
}

/// The writes `--field`, `--secret`, `--clear`, `--tag`, `--untag` and `--uri` ask for.
fn collect_writes(ui: &mut dyn Ui, fields: &FieldArgs) -> Result<Vec<(FieldKey, Value)>, CliError> {
    let parse_key = |text: &str| {
        FieldKey::parse(text.as_bytes()).map_err(|_| CliError::BadInput("not a field key"))
    };
    let mut writes = Vec::new();
    for (key, value) in &fields.fields {
        let key = parse_key(key)?;
        if concealed(&key) {
            // INV-56: a concealed value never comes from the command line.
            return Err(CliError::Usage(
                "this field is concealed: use --secret <key> and type its value when asked".into(),
            ));
        }
        let value = encode_value(&key, value)?;
        writes.push((key, value));
    }
    for key in &fields.secrets {
        let parsed = parse_key(key)?;
        let typed = ui.secret(&format!("Value of {key}"))?;
        let value = encode_value(&parsed, &typed)?;
        writes.push((parsed, value));
    }
    for key in &fields.clear {
        writes.push((parse_key(key)?, Value::cleared()));
    }
    let tag = |name: &str| tag_key(name).map_err(|_| CliError::BadInput("not a tag name"));
    for name in &fields.tags {
        writes.push((tag(name)?, Value::bool(true)));
    }
    for name in &fields.untag {
        writes.push((tag(name)?, Value::cleared()));
    }
    if !fields.uris.is_empty() {
        let mut rng = os_rng();
        let orders =
            evenly_spaced(fields.uris.len()).map_err(|_| CliError::BadInput("too many URIs"))?;
        for (uri, order) in fields.uris.iter().zip(orders) {
            let id = ElementId::generate(&mut rng);
            let bad = |_| CliError::BadInput("not a URI this version can write");
            writes.push((
                id.key(LIST_URI, ATTR_VALUE).map_err(bad)?,
                Value::text(uri).map_err(|_| CliError::BadInput("the URI is too long"))?,
            ));
            writes.push((
                id.key(LIST_URI, ATTR_ORDER).map_err(bad)?,
                Value::sort_key(&order),
            ));
        }
    }
    Ok(writes)
}

/// Syncs after a local write; an unreachable server leaves the ops queued and is not an error.
async fn sync_after_write(device: &mut Device, ui: &mut dyn Ui) -> Result<(), CliError> {
    match device.sync(ui).await {
        Ok(()) => Ok(()),
        Err(CliError::Network) => {
            ui.note(
                "Saved on this device. The server was not reached; `rv sync` will upload the \
                 change.",
            );
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// `item create`.
async fn item_create(
    env: &mut Env<'_>,
    type_text: &str,
    fields: &FieldArgs,
) -> Result<(), CliError> {
    let item_type = TYPES
        .iter()
        .find(|(name, _)| *name == type_text)
        .map(|(_, t)| *t)
        .ok_or_else(|| CliError::Usage("unknown item type".into()))?;
    let mut device = Device::open(env).await?;
    let writes = collect_writes(env.ui, fields)?;
    let item = device
        .edit(|vault, rng, unlocked, now| {
            let edits: Vec<FieldEdit<'_>> = writes
                .iter()
                .map(|(key, value)| FieldEdit { key, value })
                .collect();
            vault.create_item(rng, unlocked, item_type, &edits, now)
        })
        .await?;
    env.ui.print(&hex(item.as_bytes()))?;
    sync_after_write(&mut device, env.ui).await
}

/// `item edit`.
async fn item_edit(env: &mut Env<'_>, item: &str, fields: &FieldArgs) -> Result<(), CliError> {
    let mut device = Device::open(env).await?;
    let item = resolve_item(device.vault(), item)?;
    let writes = collect_writes(env.ui, fields)?;
    if writes.is_empty() {
        return Err(CliError::Usage("nothing to change".into()));
    }
    device
        .edit(|vault, rng, unlocked, now| {
            let edits: Vec<FieldEdit<'_>> = writes
                .iter()
                .map(|(key, value)| FieldEdit { key, value })
                .collect();
            vault.edit_item(rng, unlocked, item, &edits, now)
        })
        .await?;
    sync_after_write(&mut device, env.ui).await
}

/// `item trash`, `item restore`, `item purge`.
async fn lifecycle(
    env: &mut Env<'_>,
    item: &str,
    op: impl FnOnce(
        &mut VaultSync,
        &mut crate::sys::OsRng,
        &rizzy_client::device::UnlockedDevice,
        ItemId,
        u64,
    ) -> Result<(), ClientError>,
) -> Result<(), CliError> {
    let mut device = Device::open(env).await?;
    let item = resolve_item(device.vault(), item)?;
    device
        .edit(|vault, rng, unlocked, now| op(vault, rng, unlocked, item, now))
        .await?;
    sync_after_write(&mut device, env.ui).await
}

/// `generate`: the generator of `rizzy-core` (CRYPTO.md §12.1), printed because that is what
/// the command is for.
fn generate(ui: &mut dyn Ui, options: Generate) -> Result<(), CliError> {
    let mut rng = os_rng();
    let bad = |_| CliError::Usage("the generator options are not valid".into());
    let generated = match options {
        Generate::Characters {
            length,
            symbols,
            no_ambiguous,
        } => generate_password(
            &mut rng,
            &CharacterOptions {
                length,
                symbols: if symbols {
                    ClassRule::Required
                } else {
                    ClassRule::Excluded
                },
                exclude_ambiguous: no_ambiguous,
                ..CharacterOptions::default()
            },
        )
        .map_err(bad)?,
        Generate::Words(words) => generate_passphrase(
            &mut rng,
            &PassphraseOptions {
                words,
                ..PassphraseOptions::default()
            },
        )
        .map_err(bad)?,
    };
    ui.note(&format!("{:.0} bits of entropy", generated.entropy_bits()));
    ui.print(generated.expose_secret())
}

/// `totp`: the current code of an item's `login.totp`, which holds an `otpauth://` URI or a
/// bare Base32 secret (then SHA-1, 6 digits, 30 s; CRYPTO.md §11.15).
fn totp(device: &Device, ui: &mut dyn Ui, item: &str) -> Result<(), CliError> {
    let vault = device.vault();
    let item = resolve_item(vault, item)?;
    let bad = || CliError::BadInput("the item's one-time-code secret is not valid");
    let stored = text_field(vault, item, LOGIN_TOTP)
        .ok_or(CliError::BadInput("the item has no one-time-code secret"))?;
    let (params, secret) = if stored.starts_with("otpauth://") {
        let uri = OtpAuthUri::parse(&stored).map_err(|_| bad())?;
        let params = uri.totp_params().ok_or(CliError::BadInput(
            "the item's code is counter-based, not time-based",
        ))?;
        let secret = TotpSecret::from_slice(uri.secret().expose_secret()).map_err(|_| bad())?;
        (params, secret)
    } else {
        // The UI strips spaces before parsing (§11.15 "Base32 secrets").
        let compact = Zeroizing::new(stored.replace(' ', ""));
        (
            TotpParams::DEFAULT,
            TotpSecret::from_base32(&compact).map_err(|_| bad())?,
        )
    };
    let seconds = now_ms() / 1000;
    let code = params.code_at(&secret, seconds).map_err(|_| bad())?;
    let period = u64::from(params.period.get());
    ui.note(&format!("valid for {} s", period - seconds % period));
    ui.print(&code.to_digits())
}

/// `export` (ADR 0027 §5; CRYPTO.md §11.14): the cache as it is, to a new file.
async fn export(env: &mut Env<'_>, out: &Path, format: ExportFormat) -> Result<(), CliError> {
    // Nothing is derived or typed for a path that cannot be written: the check the final
    // `create_new` makes again.
    if out.symlink_metadata().is_ok() {
        return Err(CliError::FileExists);
    }
    let device = Device::open(env).await?;
    let vault = device.vault();
    let blockers = vault.export_blockers();
    if !blockers.is_empty() {
        for item in blockers {
            env.ui.note(&format!(
                "item {} is too large to export; duplicate it as a new item first",
                hex(item.as_bytes())
            ));
        }
        return Err(CliError::Client(ClientError::ExportOversizeItems));
    }
    match format {
        ExportFormat::Encrypted => {
            let password = env
                .ui
                .secret("Export password (not your master password)")?;
            let again = env.ui.secret("Export password, again")?;
            if *password != *again {
                return Err(CliError::BadInput("the two passwords differ"));
            }
            let mut rng = os_rng();
            let exported = vault.export_encrypted(&mut rng, &password, now_ms())?;
            write_new_file(out, &exported.file)?;
            env.ui
                .note(&format!("Exported {} items, encrypted.", exported.items));
            if !exported.unresolved.is_empty() {
                env.ui.note(&format!(
                    "{} items hold conflicting values; the export holds the merged state.",
                    exported.unresolved.len()
                ));
            }
            Ok(())
        }
        ExportFormat::Json | ExportFormat::Csv => {
            // ADR 0027 §5: the warning, then the phrase typed at a terminal; no flag skips it.
            env.ui.note(PLAINTEXT_EXPORT_WARNING);
            if format == ExportFormat::Csv {
                let loss = vault.csv_export_loss()?;
                env.ui.note(&csv_export_warning(loss.items_losing_data()));
            }
            let typed = env
                .ui
                .typed(&format!("Type {PLAINTEXT_EXPORT_PHRASE} to write the file"))?;
            let ack = PlaintextExportAck::from_typed_phrase(&typed)?;
            let plaintext = if format == ExportFormat::Json {
                vault.export_plaintext_json(ack, now_ms())?
            } else {
                vault.export_plaintext_csv(ack)?
            };
            write_new_file(out, plaintext.expose_secret())?;
            env.ui
                .note("Written, unencrypted. Delete the file as soon as you have used it.");
            Ok(())
        }
    }
}

/// `import`: every `rizzy-import` format, and our own encrypted export.
async fn import(env: &mut Env<'_>, input: &Path, format: ImportFormat) -> Result<(), CliError> {
    let file = Zeroizing::new(read_limited(input, MAX_IMPORT_FILE_LEN)?);
    let mut device = Device::open(env).await?;
    let foreign = match format {
        ImportFormat::BitwardenJson => Some(Format::BitwardenJson),
        ImportFormat::OnePux => Some(Format::OnePux),
        ImportFormat::KeePassXml => Some(Format::KeePassXml),
        ImportFormat::Csv => Some(Format::GenericCsv),
        ImportFormat::ChromeCsv => Some(Format::ChromeCsv),
        ImportFormat::FirefoxCsv => Some(Format::FirefoxCsv),
        ImportFormat::RizzyJson => Some(Format::RizzyPlaintextJson),
        ImportFormat::RizzyEncrypted => None,
    };
    if let Some(format) = foreign {
        let mut rng = os_rng();
        let parsed = rizzy_import::import(format, &file, &mut rng).map_err(CliError::Import)?;
        let done = device
            .edit(|vault, rng, unlocked, now| vault.import_items(rng, unlocked, &parsed.items, now))
            .await?;
        // Counts and positions only (INV-48): never a name or a value of the file.
        env.ui.note(&format!(
            "Imported {} items; {} skipped; {} entries with warnings.",
            done.imported.len(),
            done.skipped.len() + parsed.counts.skipped_items,
            parsed.warnings.len()
        ));
        let counts = parsed.counts;
        if counts.collapsed_conflicts + counts.dropped_history + counts.dropped_fields > 0 {
            env.ui.note(&format!(
                "{} conflicts collapsed, {} history entries and {} fields not carried.",
                counts.collapsed_conflicts, counts.dropped_history, counts.dropped_fields
            ));
        }
    } else {
        let password = env.ui.secret("Export password")?;
        let done = device
            .edit(|vault, rng, unlocked, now| {
                vault.import_encrypted(rng, unlocked, &file, &password, now)
            })
            .await?;
        env.ui.note(&format!(
            "Imported {} items; {} skipped; {} conflicts collapsed, {} history entries and {} \
             fields not carried.",
            done.imported.len(),
            done.skipped_items,
            done.collapsed_fields,
            done.history_not_carried,
            done.fields_not_carried
        ));
    }
    sync_after_write(&mut device, env.ui).await
}

/// The name of a device kind.
const fn kind_name(kind: DeviceKind) -> &'static str {
    match kind {
        DeviceKind::DesktopCli => "desktop/cli",
        DeviceKind::WebEphemeral => "web (ephemeral)",
        _ => "device",
    }
}

/// `device list`: the signed device set, from the server when it is reachable, else as last
/// verified.
async fn device_list(env: &mut Env<'_>) -> Result<(), CliError> {
    let mut device = Device::open(env).await?;
    match device.online(env.ui).await {
        Ok(()) => {}
        Err(CliError::Network) => env
            .ui
            .note("The server was not reached; this is the device set as last verified."),
        Err(e) => return Err(e),
    }
    let own = device.state().device_id();
    let (certificates, revocations) = device.devices();
    for entry in certificates {
        let certificate = &entry.certificate;
        if !certificate.in_device_set() {
            continue;
        }
        let revoked = revocations
            .iter()
            .any(|r| r.revocation.device_id == certificate.device_id);
        let note = match (certificate.device_id == own, revoked) {
            (_, true) => "  revoked",
            (true, false) => "  this device",
            (false, false) => "",
        };
        env.ui.print(&format!(
            "{}  {:<16}  enrolled {}{note}",
            hex(certificate.device_id.as_bytes()),
            kind_name(certificate.device_kind),
            certificate.created_at_ms / 1000,
        ))?;
    }
    Ok(())
}

/// `device revoke` (CRYPTO.md §11.8): suspension, then the revocation and a rotation in one
/// commit. Full by default (a lost or stolen device); `--standard` for one wiped and handed on.
async fn device_revoke(
    env: &mut Env<'_>,
    device_text: &str,
    login_name: &str,
    standard: bool,
) -> Result<(), CliError> {
    let mut device = Device::open(env).await?;
    device.online(env.ui).await?;
    let wanted = device_text.to_ascii_lowercase();
    if wanted.is_empty() || !wanted.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(CliError::BadInput(
            "a device is named by its hex id or a prefix of it",
        ));
    }
    let own = device.state().device_id();
    let target: DeviceId = {
        let (certificates, revocations) = device.devices();
        let mut matches = certificates.iter().filter(|c| {
            c.certificate.in_device_set()
                && hex(c.certificate.device_id.as_bytes()).starts_with(&wanted)
                && !revocations
                    .iter()
                    .any(|r| r.revocation.device_id == c.certificate.device_id)
        });
        match (matches.next(), matches.next()) {
            (Some(one), None) => one.certificate.device_id,
            (None, _) => return Err(CliError::BadInput("no such device, or already revoked")),
            _ => return Err(CliError::BadInput("several devices start with that id")),
        }
    };
    if target == own {
        return Err(CliError::BadInput(
            "this is the device you are using; revoke it from another device, or run `rv device forget`",
        ));
    }
    env.ui.note(
        "Revocation protects future data only: what the device already holds stays readable \
         to whoever holds it.",
    );
    let level = if standard {
        RotationLevel::Standard
    } else {
        RotationLevel::Full
    };
    let dropped = Box::pin(device.rotate(env.ui, login_name, level, Some(target))).await?;
    env.ui.note("The device was revoked.");
    report_rotation(env.ui, dropped);
    Ok(())
}

/// Deletes the files of `account` in the data directory. The lock is held until they are gone.
fn delete_account_files(
    env: &Env<'_>,
    account: &[u8; 16],
    lock: AccountLock,
) -> Result<(), CliError> {
    let cache = cache_path(&env.data_dir, account);
    let mut journal = cache.clone().into_os_string();
    journal.push("-journal");
    let removed = std::fs::remove_file(&cache);
    // A rollback journal exists only after a crash inside a transaction.
    let _ = std::fs::remove_file(journal);
    drop(lock);
    let _ = std::fs::remove_file(env.data_dir.join(format!("{}.lock", hex(account))));
    removed.map_err(crate::error::io_error("cannot delete the local data"))
}

/// Refuses the removal of a cache that did not open while it holds an alarm other than
/// "device state outdated" (ADR 0026 §5: "While an alarm is active the app refuses removal and
/// names the alarm"; the owner's decision on open question 5 allows removal under alarm 4
/// only). The alarm rows are read without unlocking ([`Db::alarm_keys`]).
///
/// An alarm row whose key is no alarm this build knows is refused too: it may be an alarm of
/// a newer `rv`, and deleting evidence is not undone (the conservative reading; reported).
/// Only a file that cannot be read as a cache at all (§5 (a)) holds no alarm to keep.
///
/// # Errors
/// [`CliError::Alarm`]; [`CliError::BadInput`] for an unknown alarm; [`CliError::InUse`].
async fn refuse_under_alarm(cache: &Path) -> Result<(), CliError> {
    let mut db = match Db::open(cache).await {
        Ok(db) => db,
        Err(CliError::InUse) => return Err(CliError::InUse),
        // Not a database: nothing in it is an alarm.
        Err(_) => return Ok(()),
    };
    let keys = db.alarm_keys().await;
    db.close().await;
    let keys = match keys {
        Ok(keys) => keys,
        Err(CliError::InUse) => return Err(CliError::InUse),
        // No such table: not a cache.
        Err(_) => return Ok(()),
    };
    for key in keys {
        let alarm = match key.as_slice() {
            [byte] => Alarm::from_u8(*byte),
            _ => None,
        };
        match alarm {
            Some(Alarm::DeviceStateOutdated) => {}
            Some(alarm) => return Err(CliError::Alarm(alarm)),
            None => {
                return Err(CliError::BadInput(
                    "the local data holds an alarm this version of rv does not know; it is \
                     not removed (use a newer rv)",
                ));
            }
        }
    }
    Ok(())
}

/// `device forget` (module docs).
async fn device_forget(env: &mut Env<'_>) -> Result<(), CliError> {
    let account = pick_account(env)?;
    let opened = Device::open(env).await;
    let (lock, unsent) = match opened {
        Ok(mut device) => {
            // The file is the evidence of these alarms: it is not removed while one is raised.
            if let Some(alarm) = device
                .alarms()
                .iter()
                .find(|a| **a != Alarm::DeviceStateOutdated)
            {
                return Err(CliError::Alarm(*alarm));
            }
            let unsent = if let Ok(left) = device.upload_unsent().await {
                left
            } else {
                env.ui
                    .note("The edits the server never acknowledged could not be uploaded now.");
                device.vault().unacknowledged()
            };
            let (_, lock) = device.close().await;
            (lock, Some(unsent))
        }
        Err(CliError::InUse) => return Err(CliError::InUse),
        Err(CliError::NoTerminal | CliError::InputEnded) => return Err(CliError::NoTerminal),
        Err(e) => {
            // The cache does not unlock or load: its unsent edits cannot be verified, so
            // they cannot be uploaded (ADR 0026 §5).
            env.ui
                .note(&format!("The local data could not be opened: {e}"));
            let lock = AccountLock::acquire(&env.data_dir, &account)?;
            // The alarm rule holds here too: a mistyped password must not be a way to delete
            // the evidence. Alarm rows are cleartext, so they are read without any key.
            refuse_under_alarm(&cache_path(&env.data_dir, &account)).await?;
            (lock, None)
        }
    };
    match unsent {
        Some((0, 0)) => env
            .ui
            .note("Every change made on this device is on the server."),
        Some((ops, snapshots)) => env.ui.note(&format!(
            "{ops} changes and {snapshots} snapshots made on this device are NOT on the server \
             and will be lost."
        )),
        None => env.ui.note(
            "Changes made on this device that never reached the server, if any, will be lost.",
        ),
    }
    env.ui.note(
        "This removes the device's keys and vault copy from this computer. To use rv here \
         again you log in anew, with your Secret Key. Revoke the old device from another \
         device afterwards (`rv device list`, `rv device revoke`).",
    );
    let typed = env
        .ui
        .line(&format!("Type {FORGET_WORD} to remove this device"))?;
    if typed != FORGET_WORD {
        return Err(CliError::BadInput("not confirmed; nothing was removed"));
    }
    delete_account_files(env, &account, lock)?;
    env.ui.note("Removed.");
    Ok(())
}
