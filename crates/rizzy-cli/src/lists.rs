//! The list options of `item create` and `item edit`: URIs and custom fields (ADR 0018 §6
//! "List elements", §7 `uri/…`, `field/…`; the writes are `rizzy_client::lists`'s).
//!
//! | Option | Writes |
//! |---|---|
//! | `--uri <uri>` | a new URI element: `value`, and `order` after the list's last element |
//! | `--set-uri <id>=<uri>` (edit) | the element's `value` |
//! | `--remove-uri <id>` (edit) | Cleared to each attribute of the element the item holds |
//! | `--custom <label>=<text>` | a new text custom field: `label`, `kind` 1, `value`, `order` |
//! | `--custom-secret <label>` | a new hidden custom field (`kind` 2); the value is asked for |
//! | `--custom-bool <label>=true\|false` | a new boolean custom field (`kind` 3) |
//! | `--set-custom <id>=<value>` (edit) | the field's `value`; refused for a hidden field |
//! | `--set-custom-secret <id>` (edit) | the field's `value`, asked for |
//! | `--remove-custom <id>` (edit) | Cleared to each attribute of the field the item holds |
//!
//! `<id>` is an element id as `item show` prints it in the field's key (`uri/<id>/value`), or a
//! unique prefix of one. Every write of one command goes into one op with the command's other
//! field writes.
//!
//! **Secrets (INV-56).** A hidden custom field's value never comes from the command line:
//! `--custom-secret` and `--set-custom-secret` ask for it. A field whose kind displays as hidden
//! (hidden, or a kind this version does not know) refuses `--set-custom`. Labels and URIs are
//! shown fields (ADR 0018 §7).

use rizzy_client::items::{FieldKey, ItemId, Value};
use rizzy_client::sync::VaultSync;
use rizzy_core::item::schema::{
    ATTR_KIND, ATTR_LABEL, ATTR_VALUE, CUSTOM_KIND_BOOLEAN, CUSTOM_KIND_HIDDEN, CUSTOM_KIND_TEXT,
    CustomFieldKind, LIST_FIELD, LIST_URI,
};

use crate::args::FieldArgs;
use crate::error::CliError;
use crate::sys::os_rng;
use crate::ui::Ui;

/// A field write.
type FieldWrite = (FieldKey, Value);

/// A Text value of user input.
fn text(input: &str) -> Result<Value, CliError> {
    Value::text(input).map_err(|_| CliError::BadInput("the value is too long"))
}

/// A Bool value of `true`/`yes` or `false`/`no`.
fn boolean(input: &str) -> Result<Value, CliError> {
    match input {
        "true" | "yes" => Ok(Value::bool(true)),
        "false" | "no" => Ok(Value::bool(false)),
        _ => Err(CliError::BadInput("a boolean field takes true or false")),
    }
}

/// The full element id of `list` of `item` that `prefix` names, among the elements the item
/// displays.
fn resolve(vault: &VaultSync, item: ItemId, list: &str, prefix: &str) -> Result<String, CliError> {
    let wanted = prefix.to_ascii_lowercase();
    if wanted.is_empty() || !wanted.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(CliError::BadInput(
            "an element is named by its hex id or a prefix of it",
        ));
    }
    let elements = vault.list_elements(item, list);
    let mut matches = elements
        .iter()
        .filter(|e| e.element.as_str().starts_with(&wanted));
    match (matches.next(), matches.next()) {
        (Some(element), None) => Ok(element.element.as_str().to_owned()),
        (None, _) => Err(CliError::BadInput(
            "the item has no such URI or custom field",
        )),
        (Some(_), Some(_)) => Err(CliError::BadInput("several elements start with that id")),
    }
}

/// The key of `attribute` of element `element` (full hex id) of `list`.
fn element_key(list: &str, element: &str, attribute: &str) -> Result<FieldKey, CliError> {
    FieldKey::parse(format!("{list}/{element}/{attribute}").as_bytes())
        .map_err(|_| CliError::BadInput("not an element of this version"))
}

/// The kind a custom field displays.
fn custom_kind(vault: &VaultSync, item: ItemId, element: &str) -> CustomFieldKind {
    let key = format!("{LIST_FIELD}/{element}/{ATTR_KIND}");
    let value = vault.field_value(item, &key);
    CustomFieldKind::from_displayed(value.as_ref().and_then(|v| v.decode().ok()))
}

/// The writes of the list options in `fields`, for a new item (`item` is `None`) or an
/// existing one. Asks for the values of hidden custom fields.
///
/// # Errors
/// [`CliError::Usage`] for an edit-only option on a new item; [`CliError::BadInput`] for an
/// element that does not resolve or a value that does not fit; the client's errors.
pub(crate) fn list_writes(
    ui: &mut dyn Ui,
    vault: &VaultSync,
    item: Option<ItemId>,
    fields: &FieldArgs,
) -> Result<Vec<FieldWrite>, CliError> {
    let mut rng = os_rng();
    let mut writes = Vec::new();
    // New URIs.
    let orders = vault.append_orders(item, LIST_URI, fields.uris.len())?;
    for (uri, order) in fields.uris.iter().zip(&orders) {
        let (_, new) = VaultSync::new_element_writes(
            &mut rng,
            LIST_URI,
            vec![(ATTR_VALUE, text(uri)?)],
            Some(order),
        )?;
        writes.extend(new);
    }
    // New custom fields, in the order given: text, hidden, boolean.
    let mut custom: Vec<(&str, u16, Value)> = Vec::new();
    for (label, value) in &fields.custom {
        custom.push((label, CUSTOM_KIND_TEXT, text(value)?));
    }
    for label in &fields.custom_secret {
        let typed = ui.secret(&format!("Value of the hidden field {label}"))?;
        custom.push((label, CUSTOM_KIND_HIDDEN, text(&typed)?));
    }
    for (label, value) in &fields.custom_bool {
        custom.push((label, CUSTOM_KIND_BOOLEAN, boolean(value)?));
    }
    let orders = vault.append_orders(item, LIST_FIELD, custom.len())?;
    for ((label, kind, value), order) in custom.into_iter().zip(&orders) {
        let (_, new) = VaultSync::new_element_writes(
            &mut rng,
            LIST_FIELD,
            vec![
                (ATTR_LABEL, text(label)?),
                (ATTR_KIND, Value::enumeration(kind)),
                (ATTR_VALUE, value),
            ],
            Some(order),
        )?;
        writes.extend(new);
    }
    let edits_elements = !fields.uri_set.is_empty()
        || !fields.uri_remove.is_empty()
        || !fields.custom_set.is_empty()
        || !fields.custom_set_secret.is_empty()
        || !fields.custom_remove.is_empty();
    let Some(item) = item else {
        if edits_elements {
            return Err(CliError::Usage(
                "--set-… and --remove-… change an existing item: use item edit".into(),
            ));
        }
        return Ok(writes);
    };
    for (prefix, uri) in &fields.uri_set {
        let element = resolve(vault, item, LIST_URI, prefix)?;
        writes.push((element_key(LIST_URI, &element, ATTR_VALUE)?, text(uri)?));
    }
    for prefix in &fields.uri_remove {
        let element = resolve(vault, item, LIST_URI, prefix)?;
        writes.extend(vault.element_removal_writes(item, LIST_URI, &element)?);
    }
    for (prefix, value) in &fields.custom_set {
        let element = resolve(vault, item, LIST_FIELD, prefix)?;
        let kind = custom_kind(vault, item, &element);
        if kind.displays_as_hidden() {
            // INV-56: a concealed value never comes from the command line.
            return Err(CliError::Usage(
                "this custom field is hidden: use --set-custom-secret <id> and type its value \
                 when asked"
                    .into(),
            ));
        }
        let value = if kind == CustomFieldKind::Boolean {
            boolean(value)?
        } else {
            text(value)?
        };
        writes.push((element_key(LIST_FIELD, &element, ATTR_VALUE)?, value));
    }
    for prefix in &fields.custom_set_secret {
        let element = resolve(vault, item, LIST_FIELD, prefix)?;
        let typed = ui.secret("Value of the hidden field")?;
        let value = if custom_kind(vault, item, &element) == CustomFieldKind::Boolean {
            boolean(&typed)?
        } else {
            text(&typed)?
        };
        writes.push((element_key(LIST_FIELD, &element, ATTR_VALUE)?, value));
    }
    for prefix in &fields.custom_remove {
        let element = resolve(vault, item, LIST_FIELD, prefix)?;
        writes.extend(vault.element_removal_writes(item, LIST_FIELD, &element)?);
    }
    Ok(writes)
}
