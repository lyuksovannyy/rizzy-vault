//! The list options of `item create` and `item edit`: URIs and custom fields (ADR 0018 §6
//! "List elements", "List order", §7 `uri/…`, `field/…`; the writes are `rizzy_client::lists`'s).
//!
//! | Option | Writes |
//! |---|---|
//! | `--uri <uri>` | a new URI element: `value`, and `order` after the list's last element |
//! | `--set-uri <id>=<uri>` (edit) | the element's `value` |
//! | `--remove-uri <id>` (edit) | Cleared to each attribute of the element the item holds |
//! | `--move-uri <id>=<place>` (edit) | the element's `order`, between its new neighbours |
//! | `--custom <label>=<text>` | a new text custom field: `label`, `kind` 1, `value`, `order` |
//! | `--custom-secret <label>` | a new hidden custom field (`kind` 2); the value is asked for |
//! | `--custom-bool <label>=true\|false` | a new boolean custom field (`kind` 3) |
//! | `--set-custom <id>=<value>` (edit) | the field's `value`; refused for a hidden field |
//! | `--set-custom-secret <id>` (edit) | the field's `value`, asked for |
//! | `--remove-custom <id>` (edit) | Cleared to each attribute of the field the item holds |
//! | `--move-custom <id>=<place>` (edit) | the field's `order`, between its new neighbours |
//!
//! `<id>` is an element id as `item show` prints it in the field's key (`uri/<id>/value`), or a
//! unique prefix of one; `item show` also prints each list's element ids in list order
//! (`order of uri: …`). `<place>` is `first`, `last`, `before:<id>` or `after:<id>`. Moves of
//! one list run in the order given, after that command's removals and additions (new
//! elements go after the last element). Every write of one command goes into one op with the
//! command's other field writes, except when no `order` key fits between the new neighbours:
//! then the list's `order` keys are rewritten with evenly spaced keys (ADR 0018 §6), in the
//! same op while it fits the 1,024-write limit and in consecutive ops before it otherwise
//! (`rizzy_client::lists::split_order_ops`). Tags and password history have no `order` in
//! ADR 0018 §7, so they have no move option.
//!
//! **Secrets (INV-56).** A hidden custom field's value never comes from the command line:
//! `--custom-secret` and `--set-custom-secret` ask for it. A field whose kind displays as hidden
//! (hidden, or a kind this version does not know) refuses `--set-custom`. Labels and URIs are
//! shown fields (ADR 0018 §7).

use rizzy_client::items::{FieldKey, ItemId, Value};
use rizzy_client::lists::{ListMove, ListPlace, OrderPlan};
use rizzy_client::sync::VaultSync;
use rizzy_core::item::schema::{
    ATTR_KIND, ATTR_LABEL, ATTR_VALUE, CUSTOM_KIND_BOOLEAN, CUSTOM_KIND_HIDDEN, CUSTOM_KIND_TEXT,
    CustomFieldKind, LIST_FIELD, LIST_URI,
};
use rizzy_core::item::value::SortKey;
use zeroize::Zeroizing;

use crate::args::FieldArgs;
use crate::error::CliError;
use crate::sys::os_rng;
use crate::ui::Ui;

/// A field write.
type FieldWrite = (FieldKey, Value);

/// The writes of the list options of one command.
pub(crate) struct ListWrites {
    /// Writes for the command's op.
    pub(crate) writes: Vec<FieldWrite>,
    /// The `order` writes of rewritten lists, which may go in ops of their own before it
    /// (`rizzy_client::lists::split_order_ops`).
    pub(crate) rewrite: Vec<FieldWrite>,
}

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

/// The moves of `list` that `moves` (`<id>=<place>` pairs) ask for. An element the same
/// command removes cannot be moved or be a neighbour.
fn resolve_moves(
    vault: &VaultSync,
    item: ItemId,
    list: &str,
    moves: &[(String, String)],
    removed: &[String],
) -> Result<Vec<ListMove>, CliError> {
    let element = |prefix: &str| -> Result<Zeroizing<String>, CliError> {
        let full = resolve(vault, item, list, prefix)?;
        if removed.contains(&full) {
            return Err(CliError::BadInput(
                "this command removes that element, so it has no place to move to or by",
            ));
        }
        Ok(Zeroizing::new(full))
    };
    let mut out = Vec::with_capacity(moves.len());
    for (id, place) in moves {
        let to = match place.as_str() {
            "first" => ListPlace::First,
            "last" => ListPlace::Last,
            other => match other.split_once(':') {
                Some(("before", neighbour)) => ListPlace::Before(element(neighbour)?),
                Some(("after", neighbour)) => ListPlace::After(element(neighbour)?),
                _ => {
                    return Err(CliError::Usage(
                        "a place is first, last, before:<id> or after:<id>".into(),
                    ));
                }
            },
        };
        out.push(ListMove {
            element: element(id)?,
            to,
        });
    }
    Ok(out)
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

/// The order of one list's edit, with `rizzy_client::lists`'s plan, its existing elements'
/// `order` writes sorted into `out`.
fn plan(
    vault: &VaultSync,
    item: Option<ItemId>,
    list: &str,
    removed: &[String],
    added: usize,
    moves: &[ListMove],
    out: &mut ListWrites,
) -> Result<Vec<SortKey>, CliError> {
    let removed: Vec<&str> = removed.iter().map(String::as_str).collect();
    let OrderPlan {
        new_orders,
        writes,
        rewritten,
    } = vault.plan_list_order(item, list, &removed, added, moves)?;
    if rewritten {
        out.rewrite.extend(writes);
    } else {
        out.writes.extend(writes);
    }
    Ok(new_orders)
}

/// The edits of existing elements in `fields`: values set and elements removed.
fn element_edits(
    ui: &mut dyn Ui,
    vault: &VaultSync,
    item: ItemId,
    fields: &FieldArgs,
    removed: (&[String], &[String]),
    writes: &mut Vec<FieldWrite>,
) -> Result<(), CliError> {
    for (prefix, uri) in &fields.uri_set {
        let element = resolve(vault, item, LIST_URI, prefix)?;
        writes.push((element_key(LIST_URI, &element, ATTR_VALUE)?, text(uri)?));
    }
    for element in removed.0 {
        writes.extend(vault.element_removal_writes(item, LIST_URI, element)?);
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
    for element in removed.1 {
        writes.extend(vault.element_removal_writes(item, LIST_FIELD, element)?);
    }
    Ok(())
}

/// The writes of the list options in `fields`, for a new item (`item` is `None`) or an
/// existing one. Asks for the values of hidden custom fields.
///
/// # Errors
/// [`CliError::Usage`] for an edit-only option on a new item or a malformed place;
/// [`CliError::BadInput`] for an element that does not resolve or a value that does not fit;
/// the client's errors.
pub(crate) fn list_writes(
    ui: &mut dyn Ui,
    vault: &VaultSync,
    item: Option<ItemId>,
    fields: &FieldArgs,
) -> Result<ListWrites, CliError> {
    let edits_elements = !fields.uri_set.is_empty()
        || !fields.uri_remove.is_empty()
        || !fields.uri_move.is_empty()
        || !fields.custom_set.is_empty()
        || !fields.custom_set_secret.is_empty()
        || !fields.custom_remove.is_empty()
        || !fields.custom_move.is_empty();
    if item.is_none() && edits_elements {
        return Err(CliError::Usage(
            "--set-…, --remove-… and --move-… change an existing item: use item edit".into(),
        ));
    }
    // The elements this command removes and the moves it asks for, by full id.
    let mut removed_uris = Vec::new();
    let mut removed_fields = Vec::new();
    let mut uri_moves = Vec::new();
    let mut field_moves = Vec::new();
    if let Some(item) = item {
        for prefix in &fields.uri_remove {
            removed_uris.push(resolve(vault, item, LIST_URI, prefix)?);
        }
        for prefix in &fields.custom_remove {
            removed_fields.push(resolve(vault, item, LIST_FIELD, prefix)?);
        }
        uri_moves = resolve_moves(vault, item, LIST_URI, &fields.uri_move, &removed_uris)?;
        field_moves = resolve_moves(
            vault,
            item,
            LIST_FIELD,
            &fields.custom_move,
            &removed_fields,
        )?;
    }
    let mut out = ListWrites {
        writes: Vec::new(),
        rewrite: Vec::new(),
    };
    let mut rng = os_rng();
    // New URIs.
    let orders = plan(
        vault,
        item,
        LIST_URI,
        &removed_uris,
        fields.uris.len(),
        &uri_moves,
        &mut out,
    )?;
    for (uri, order) in fields.uris.iter().zip(&orders) {
        let (_, new) = VaultSync::new_element_writes(
            &mut rng,
            LIST_URI,
            vec![(ATTR_VALUE, text(uri)?)],
            Some(order),
        )?;
        out.writes.extend(new);
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
    let orders = plan(
        vault,
        item,
        LIST_FIELD,
        &removed_fields,
        custom.len(),
        &field_moves,
        &mut out,
    )?;
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
        out.writes.extend(new);
    }
    if let Some(item) = item {
        element_edits(
            ui,
            vault,
            item,
            fields,
            (&removed_uris, &removed_fields),
            &mut out.writes,
        )?;
    }
    Ok(out)
}
