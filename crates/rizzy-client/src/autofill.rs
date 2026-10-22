// SPDX-License-Identifier: AGPL-3.0-only

//! Custom-field autocomplete ids and autocomplete-driven autofill ([ADR 0076] §2–§5).
//!
//! - **Writer checks W1–W5** (§2.3, [`check_custom_fields`]): every write path that can set or
//!   keep a custom field runs them, so every client enforces them identically. Create, edit
//!   (and so conflict "pick one" and "keep both", and history restore, which edit) and import
//!   call them; the errors are typed codes that never echo the id or the label.
//! - **Merge-made duplicates** (§2.5, [`VaultSync::custom_field_autofill`]): of the fields that
//!   display a given fillable id, only the first in list order (`order`, then element id) fills;
//!   the editor marks the others as shadowed and names the winner.
//! - **The fill plan** (§4.2–§4.3, [`VaultSync::custom_fill_offer`], [`VaultSync::fill_plan`]):
//!   the disclosure an offer shows (Display Names and a concealed flag, never values), and the
//!   values one fill click sends: username and password narrowed by `only`, the current TOTP
//!   code (never the secret), and custom values by exact token match, with role precedence.
//! - **The save plan** (§5.3–§5.4, [`VaultSync::custom_save_plan`]): which captured custom
//!   fields a save dialog offers to add or update, and its defaults. A save never sets or
//!   changes the id of an existing field.
//!
//! **What W5 exempts.** A write that removes a field (the field no longer exists after it), and
//! a write that touches only a field's `order` (a move, or a list rewrite that renumbers fields
//! the user did not edit: `order` is a layout attribute, ADR 0018 §6, so it is not an edit of
//! the field's content). An import keeps a source field's empty name (§2.4, owner answer 4)
//! unless the field also carries an autocomplete id, which a label-less field cannot hold.
//!
//! **What "sets an id" means for W3.** A write of a non-empty id that differs from the id the
//! field displays now. A write that leaves an existing merge-made duplicate in place is not
//! refused, so an unrelated edit never locks the item (§2.3 W3).
//!
//! [ADR 0076]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0076-autocomplete-driven-autofill.md

use core::fmt;

use rizzy_core::ids::ItemId;
use rizzy_core::item::autocomplete::{AutocompleteIdError, check_autocomplete_id};
use rizzy_core::item::key::FieldKeyRef;
use rizzy_core::item::order::{ListEntry, compare_list_entries, element_exists};
use rizzy_core::item::schema::{
    ATTR_AUTOCOMPLETE, ATTR_KIND, ATTR_LABEL, ATTR_ORDER, ATTR_VALUE, CustomFieldKind, LIST_FIELD,
    LOGIN_PASSWORD, LOGIN_TOTP, LOGIN_USERNAME,
};
use rizzy_core::item::types::ItemType;
use rizzy_core::item::value::{Value, ValueRef};
use rizzy_core::totp::{OtpAuthUri, TotpParams, TotpSecret};
use zeroize::Zeroizing;

use crate::error::ClientError;
use crate::items::ItemLifecycle;
use crate::sync::VaultSync;

/// The longest value that fills, in UTF-16 code units (ADR 0076 §4.3, the extension's
/// `MAX_FIELD_VALUE_LEN`).
pub const MAX_FILL_VALUE_UTF16: usize = 4096;

/// The most custom tokens one fill scope or offer holds (ADR 0076 §4.1, §4.4).
pub const MAX_CUSTOM_TOKENS: usize = 16;

/// The most custom fields one submitted form reports (ADR 0076 §5.1).
pub const MAX_CAPTURED_FIELDS: usize = 8;

/// Which write path runs [`check_custom_fields`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckMode {
    /// A create op or an edit op of the user (and the conflict and history paths, which edit).
    Write,
    /// An import (ADR 0027): a label-less field without an autocomplete id is kept (§2.4).
    Import,
}

/// One custom field: every attribute it displays, as encoded values.
struct FieldState {
    /// The element id, as the key's hex digits.
    element: Zeroizing<String>,
    /// Each attribute with its displayed encoded value; Cleared values are kept (empty).
    attributes: Vec<(Zeroizing<String>, Value)>,
}

impl FieldState {
    /// The displayed value of `attribute`, if the field has a register of it.
    fn get(&self, attribute: &str) -> Option<&Value> {
        self.attributes
            .iter()
            .find(|(a, _)| a.as_str() == attribute)
            .map(|(_, v)| v)
    }

    /// Sets the displayed value of `attribute` (an op's write).
    fn set(&mut self, attribute: &str, value: Value) {
        match self
            .attributes
            .iter_mut()
            .find(|(a, _)| a.as_str() == attribute)
        {
            Some((_, v)) => *v = value,
            None => self
                .attributes
                .push((Zeroizing::new(attribute.to_owned()), value)),
        }
    }

    /// Whether the field exists: a content attribute displays a non-empty value (ADR 0018 §6).
    fn exists(&self) -> bool {
        element_exists(
            self.attributes
                .iter()
                .map(|(a, v)| (Some(a.as_str()), v.expose_secret())),
        )
    }

    /// The kind the field displays; absent or malformed reads as unknown.
    fn kind(&self) -> CustomFieldKind {
        CustomFieldKind::from_displayed(self.get(ATTR_KIND).and_then(|v| v.decode().ok()))
    }

    /// The displayed Text of `attribute`, if it is a non-empty Text.
    fn text(&self, attribute: &str) -> Option<&str> {
        match self.get(attribute)?.decode() {
            Ok(ValueRef::Text(text)) if !text.is_empty() => Some(text),
            _ => None,
        }
    }

    /// The Display Name, if it holds a non-whitespace character (§2.3 W5).
    fn label(&self) -> Option<&str> {
        self.text(ATTR_LABEL).filter(|l| !l.trim().is_empty())
    }

    /// The displayed autocomplete id, any Text (valid or not).
    fn autocomplete(&self) -> Option<&str> {
        self.text(ATTR_AUTOCOMPLETE)
    }

    /// The id this field fills under, if it may fill at all (§4.3 without the value and the
    /// list-order conditions): it exists, its kind is text or hidden, it has a Display Name, and
    /// its id passes the grammar and is not reserved.
    fn fillable_id(&self) -> Option<&str> {
        if !self.exists() || !matches!(self.kind(), CustomFieldKind::Text | CustomFieldKind::Hidden)
        {
            return None;
        }
        self.label()?;
        self.autocomplete()
            .filter(|id| check_autocomplete_id(id.as_bytes()).is_ok())
    }

    /// The value that fills, if it is a non-empty Text of at most 4096 UTF-16 units (§4.3).
    fn fill_value(&self) -> Option<&str> {
        self.text(ATTR_VALUE)
            .filter(|v| v.encode_utf16().count() <= MAX_FILL_VALUE_UTF16)
    }
}

/// Puts `fields` in list order (`order`, then element id; ADR 0018 §6), keeping only those that
/// exist.
fn in_list_order(mut fields: Vec<FieldState>) -> Vec<FieldState> {
    fields.retain(FieldState::exists);
    fields.sort_by(|a, b| {
        compare_list_entries(
            &ListEntry {
                order: a.get(ATTR_ORDER).map(Value::expose_secret),
                element: &a.element,
            },
            &ListEntry {
                order: b.get(ATTR_ORDER).map(Value::expose_secret),
                element: &b.element,
            },
        )
    });
    fields
}

/// The index of the field that fills `id` among `ordered` (list order), if any (§2.5).
fn winner_index(ordered: &[FieldState], id: &str) -> Option<usize> {
    ordered.iter().position(|f| f.fillable_id() == Some(id))
}

/// The W1/W2 client error of a core id error.
fn map_id_error(e: AutocompleteIdError) -> ClientError {
    match e {
        AutocompleteIdError::Invalid => ClientError::AutocompleteInvalid,
        AutocompleteIdError::Reserved => ClientError::AutocompleteReserved,
    }
}

/// Runs the ADR 0076 §2.3 writer checks W1–W5 on one op's `writes` against `current`, the
/// item's custom fields before the op (none for a new item). Writes that are not custom-field
/// attributes are ignored; keys and value types are [`rizzy_core::item::schema::check_write`]'s.
///
/// # Errors
/// [`ClientError::AutocompleteInvalid`] (W1), [`ClientError::AutocompleteReserved`] (W2),
/// [`ClientError::AutocompleteDuplicate`] (W3), [`ClientError::AutocompleteKind`] (W4),
/// [`ClientError::LabelRequired`] (W5); [`ClientError::InvalidEdit`] for an autocomplete id
/// that is not Text.
fn check_fields(
    current: Vec<FieldState>,
    writes: &[(&str, &[u8])],
    mode: CheckMode,
) -> Result<(), ClientError> {
    let mut after = current;
    let mut touched: Vec<Touched> = Vec::new();
    for (key, value) in writes {
        let Ok(parsed) = FieldKeyRef::parse(key.as_bytes()) else {
            continue;
        };
        let (Some(LIST_FIELD), Some(element), Some(attribute)) =
            (parsed.list(), parsed.element(), parsed.attribute())
        else {
            continue;
        };
        let Ok(value) = Value::copy_from_encoded(value) else {
            continue;
        };
        let index = if let Some(i) = after.iter().position(|f| f.element.as_str() == element) {
            i
        } else {
            after.push(FieldState {
                element: Zeroizing::new(element.to_owned()),
                attributes: Vec::new(),
            });
            after.len() - 1
        };
        let entry = if let Some(i) = touched.iter().position(|t| t.element.as_str() == element) {
            i
        } else {
            touched.push(Touched {
                element: Zeroizing::new(element.to_owned()),
                content: false,
                id: false,
                kind: false,
                newly_set: None,
            });
            touched.len() - 1
        };
        let before_id = after
            .get(index)
            .and_then(|f| f.autocomplete().map(|s| Zeroizing::new(s.to_owned())));
        let Some(t) = touched.get_mut(entry) else {
            return Err(ClientError::Internal);
        };
        t.content |= attribute != ATTR_ORDER;
        t.kind |= attribute == ATTR_KIND;
        if attribute == ATTR_AUTOCOMPLETE && !value.is_cleared() {
            let Ok(ValueRef::Text(id)) = value.decode() else {
                return Err(ClientError::InvalidEdit);
            };
            // W1, W2.
            check_autocomplete_id(id.as_bytes()).map_err(map_id_error)?;
            t.id = true;
            if t.newly_set.is_none() && before_id.as_deref().map(String::as_str) != Some(id) {
                t.newly_set = Some(Zeroizing::new(id.to_owned()));
            }
        }
        if let Some(field) = after.get_mut(index) {
            field.set(attribute, value);
        }
    }
    for t in &touched {
        let Some(field) = after
            .iter()
            .find(|f| f.element.as_str() == t.element.as_str())
        else {
            return Err(ClientError::Internal);
        };
        if !field.exists() {
            // A removal: nothing to check.
            continue;
        }
        // W3: an id the write sets must not be displayed by another existing field.
        if let Some(id) = &t.newly_set
            && field.autocomplete() == Some(id.as_str())
            && after.iter().any(|other| {
                other.element.as_str() != t.element.as_str()
                    && other.exists()
                    && other.autocomplete() == Some(id.as_str())
            })
        {
            return Err(ClientError::AutocompleteDuplicate);
        }
        // W4: an id only on a text or hidden field.
        if (t.id || t.kind)
            && field.autocomplete().is_some()
            && !matches!(
                field.kind(),
                CustomFieldKind::Text | CustomFieldKind::Hidden
            )
        {
            return Err(ClientError::AutocompleteKind);
        }
        // W5: the Display Name.
        let exempt = mode == CheckMode::Import && field.autocomplete().is_none();
        if t.content && !exempt && field.label().is_none() {
            return Err(ClientError::LabelRequired);
        }
    }
    Ok(())
}

/// What one op writes to one custom field, for [`check_fields`].
struct Touched {
    /// The element id.
    element: Zeroizing<String>,
    /// An attribute other than `order` was written (W5 applies).
    content: bool,
    /// A non-empty autocomplete id was written (W4 applies).
    id: bool,
    /// The kind was written (W4 applies).
    kind: bool,
    /// The id the op sets, if it differs from the one displayed before (W3 applies).
    newly_set: Option<Zeroizing<String>>,
}

/// [`check_fields`] for a new item (create or import): no current fields. Pure, so the import
/// preview and its fuzz target run it too.
///
/// # Errors
/// As [`check_fields`].
pub fn check_custom_fields(writes: &[(&str, &[u8])], mode: CheckMode) -> Result<(), ClientError> {
    check_fields(Vec::new(), writes, mode)
}

/// Why a custom field's autocomplete id does or does not fill (ADR 0076 §2.5, §3, §4.3), for
/// the editor.
#[derive(Clone, PartialEq, Eq)]
pub enum AutofillState {
    /// No id.
    None,
    /// The field fills under its id.
    Fills,
    /// The id breaks the grammar (W1's error).
    Invalid,
    /// The id is reserved (W2's error).
    Reserved,
    /// The field is boolean or of an unknown kind (W4's error).
    WrongKind,
    /// The field has no Display Name ("Unnamed field"): it never fills (§2.4).
    Unnamed,
    /// Another field of the item, earlier in list order, fills the same id (§2.5). Holds the
    /// winner's element id.
    Shadowed(Zeroizing<String>),
}

impl fmt::Debug for AutofillState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::None => "None",
            Self::Fills => "Fills",
            Self::Invalid => "Invalid",
            Self::Reserved => "Reserved",
            Self::WrongKind => "WrongKind",
            Self::Unnamed => "Unnamed",
            Self::Shadowed(_) => "Shadowed([REDACTED])",
        })
    }
}

/// One custom field of [`VaultSync::custom_field_autofill`].
pub struct CustomFieldAutofill {
    /// The element id (hex).
    pub element: Zeroizing<String>,
    /// What the field's id does.
    pub state: AutofillState,
}

impl fmt::Debug for CustomFieldAutofill {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustomFieldAutofill")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// One custom field an offer discloses (ADR 0076 §4.1): its Display Name and whether it is
/// hidden, never its value.
pub struct CustomOffer {
    /// The page token it fills (lowercase, exact).
    pub token: Zeroizing<String>,
    /// The element id the offer records for the token.
    pub element: Zeroizing<String>,
    /// The Display Name.
    pub label: Zeroizing<String>,
    /// `true` for a hidden field: the row says "(hidden)".
    pub concealed: bool,
}

impl fmt::Debug for CustomOffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustomOffer")
            .field("concealed", &self.concealed)
            .finish_non_exhaustive()
    }
}

/// The narrowing of one fill (ADR 0076 §4.1 `only`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FillOnly {
    /// An identifier-first step: the username only.
    Username,
    /// A password-only step: the password only.
    Password,
    /// A TOTP-only step: the code only.
    Totp,
}

/// A custom token the offer resolved, with the element it recorded for it.
pub struct CustomChoice {
    /// The page token.
    pub token: Zeroizing<String>,
    /// The element id the offer recorded.
    pub element: Zeroizing<String>,
}

impl fmt::Debug for CustomChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CustomChoice([REDACTED])")
    }
}

/// What one fill click asks for, taken from the long-lived context's own offer record, never
/// from the page (ADR 0076 §4.2).
#[derive(Debug)]
pub struct FillRequest<'a> {
    /// The step's narrowing.
    pub only: Option<FillOnly>,
    /// The step also has a TOTP target.
    pub totp: bool,
    /// The custom tokens the offer disclosed.
    pub custom: &'a [CustomChoice],
    /// The custom token the step's username target carries, if any.
    pub username_token: Option<&'a str>,
    /// The custom token the step's password target carries, if any.
    pub password_token: Option<&'a str>,
}

/// The values one fill sends to the content script (ADR 0076 §4.2, §4.4). Wiped on drop;
/// `Debug` shows which members are present only.
#[derive(Default)]
pub struct FillPlan {
    /// `login.username`.
    pub username: Option<Zeroizing<String>>,
    /// `login.password`.
    pub password: Option<Zeroizing<String>>,
    /// The current TOTP code, 6–8 digits. Never the secret.
    pub totp: Option<Zeroizing<String>>,
    /// Custom values by token, in the order the offer listed them.
    pub custom: Vec<(Zeroizing<String>, Zeroizing<String>)>,
}

impl fmt::Debug for FillPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FillPlan")
            .field("username", &self.username.is_some())
            .field("password", &self.password.is_some())
            .field("totp", &self.totp.is_some())
            .field("custom", &self.custom.len())
            .finish()
    }
}

impl FillPlan {
    /// `true` when nothing would be filled.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.username.is_none()
            && self.password.is_none()
            && self.totp.is_none()
            && self.custom.is_empty()
    }
}

/// A TOTP code at one instant (CRYPTO.md §11.15). The secret never leaves [`VaultSync`].
pub struct TotpNow {
    /// The code's digits.
    pub code: Zeroizing<String>,
    /// The period in seconds.
    pub period_s: u64,
    /// Seconds left in the current period.
    pub valid_for_s: u64,
}

impl fmt::Debug for TotpNow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpNow")
            .field("period_s", &self.period_s)
            .field("valid_for_s", &self.valid_for_s)
            .finish_non_exhaustive()
    }
}

/// One custom field a submitted form captured (ADR 0076 §5.1).
#[derive(Clone, Copy)]
pub struct CapturedField<'a> {
    /// The page token.
    pub token: &'a str,
    /// The typed value.
    pub value: &'a str,
    /// `true` for a `type=password` input.
    pub masked: bool,
}

impl fmt::Debug for CapturedField<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapturedField")
            .field("masked", &self.masked)
            .finish_non_exhaustive()
    }
}

/// What a save-dialog row does (ADR 0076 §5.3).
#[derive(Clone, PartialEq, Eq)]
pub enum SaveRowKind {
    /// "Add custom field <Display Name>": a new field, its id the token.
    Add,
    /// "Update <Display Name>": a new value for this existing field (element id).
    Update(Zeroizing<String>),
}

impl fmt::Debug for SaveRowKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Add => "Add",
            Self::Update(_) => "Update([REDACTED])",
        })
    }
}

/// One save-dialog row (ADR 0076 §5.3).
pub struct SaveRow {
    /// The index of the captured field the row is for.
    pub index: usize,
    /// Add or update.
    pub kind: SaveRowKind,
    /// The Display Name: the token for a new field (editable), the field's own for an update.
    pub label: Zeroizing<String>,
    /// The new field is hidden, or the updated one is: the row says "(hidden)".
    pub concealed: bool,
    /// The row's default: checked for a new text field only.
    pub checked: bool,
}

impl fmt::Debug for SaveRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SaveRow")
            .field("index", &self.index)
            .field("kind", &self.kind)
            .field("concealed", &self.concealed)
            .field("checked", &self.checked)
            .finish_non_exhaustive()
    }
}

/// The current code of a `login.totp` value: an `otpauth://totp` URI or a bare Base32 secret
/// (then SHA-1, 6 digits, 30 s; CRYPTO.md §11.15). `None` for an HOTP URI or anything invalid.
fn totp_at(stored: &str, now_ms: u64) -> Option<TotpNow> {
    let (params, secret) = if stored.starts_with("otpauth://") {
        let uri = OtpAuthUri::parse(stored).ok()?;
        let params = uri.totp_params()?;
        let secret = TotpSecret::from_slice(uri.secret().expose_secret()).ok()?;
        (params, secret)
    } else {
        // The UI strips spaces before parsing (§11.15 "Base32 secrets").
        let compact = Zeroizing::new(stored.replace(' ', ""));
        (TotpParams::DEFAULT, TotpSecret::from_base32(&compact).ok()?)
    };
    let seconds = now_ms / 1000;
    let code = params.code_at(&secret, seconds).ok()?;
    let period = u64::from(params.period.get());
    Some(TotpNow {
        code: code.to_digits(),
        period_s: period,
        valid_for_s: period - seconds % period,
    })
}

impl VaultSync {
    /// The item's custom fields, every attribute with its displayed value, not filtered or
    /// ordered.
    fn custom_field_states(&self, item: ItemId) -> Vec<FieldState> {
        let mut out: Vec<FieldState> = Vec::new();
        for key in self.field_keys(item) {
            let Ok(parsed) = FieldKeyRef::parse(key.as_bytes()) else {
                continue;
            };
            let (Some(LIST_FIELD), Some(element), Some(attribute)) =
                (parsed.list(), parsed.element(), parsed.attribute())
            else {
                continue;
            };
            let value = self
                .field_value(item, key.as_str())
                .unwrap_or_else(Value::cleared);
            match out.iter_mut().find(|f| f.element.as_str() == element) {
                Some(field) => field.set(attribute, value),
                None => out.push(FieldState {
                    element: Zeroizing::new(element.to_owned()),
                    attributes: vec![(Zeroizing::new(attribute.to_owned()), value)],
                }),
            }
        }
        out
    }

    /// Runs W1–W5 (ADR 0076 §2.3) on an edit op's `writes` to `item`.
    ///
    /// # Errors
    /// As [`check_custom_fields`].
    pub(crate) fn check_custom_field_edit(
        &self,
        item: ItemId,
        writes: &[(&str, &[u8])],
    ) -> Result<(), ClientError> {
        if !writes.iter().any(|(k, _)| is_field_key(k)) {
            return Ok(());
        }
        check_fields(self.custom_field_states(item), writes, CheckMode::Write)
    }

    /// What each of the item's custom fields' autocomplete id does, in list order (ADR 0076
    /// §2.4–§2.5, §3): for the editor's inline errors and the "also used by" warning, which
    /// names the winner ([`AutofillState::Shadowed`]).
    #[must_use]
    pub fn custom_field_autofill(&self, item: ItemId) -> Vec<CustomFieldAutofill> {
        let ordered = in_list_order(self.custom_field_states(item));
        let mut out = Vec::with_capacity(ordered.len());
        for (i, field) in ordered.iter().enumerate() {
            let state = match field.autocomplete() {
                None => AutofillState::None,
                Some(id) => match check_autocomplete_id(id.as_bytes()) {
                    Err(AutocompleteIdError::Invalid) => AutofillState::Invalid,
                    Err(AutocompleteIdError::Reserved) => AutofillState::Reserved,
                    Ok(())
                        if !matches!(
                            field.kind(),
                            CustomFieldKind::Text | CustomFieldKind::Hidden
                        ) =>
                    {
                        AutofillState::WrongKind
                    }
                    Ok(()) if field.label().is_none() => AutofillState::Unnamed,
                    Ok(()) => match winner_index(&ordered, id) {
                        Some(w) if w != i => ordered.get(w).map_or(AutofillState::Fills, |win| {
                            AutofillState::Shadowed(win.element.clone())
                        }),
                        _ => AutofillState::Fills,
                    },
                },
            };
            out.push(CustomFieldAutofill {
                element: field.element.clone(),
                state,
            });
        }
        out
    }

    /// Whether the item is an Active Login whose `login.totp` holds a valid time-based secret
    /// (ADR 0076 §1.3 rule (g), §4.1 `hasTotp`). An HOTP URI is not.
    #[must_use]
    pub fn has_time_based_totp(&self, item: ItemId) -> bool {
        self.totp_now(item, 0).is_some()
    }

    /// The current TOTP code of the item's `login.totp` at `now_ms` (CRYPTO.md §11.15), current
    /// step only, no look-ahead. `None` when it has no valid time-based secret. The secret never
    /// leaves this call.
    #[must_use]
    pub fn totp_now(&self, item: ItemId, now_ms: u64) -> Option<TotpNow> {
        let value = self.field_value(item, LOGIN_TOTP)?;
        let stored = match value.decode() {
            Ok(ValueRef::Text(text)) if !text.is_empty() => Zeroizing::new(text.to_owned()),
            _ => return None,
        };
        totp_at(&stored, now_ms)
    }

    /// The custom fields an offer for `tokens` (the page's custom tokens, lowercase, document
    /// order) discloses for `item` (ADR 0076 §4.1, §4.3): per token, the field that fills it, if
    /// its value qualifies. Tokens that are invalid, reserved or repeated are skipped; at most
    /// 16 are read. Values are never returned.
    #[must_use]
    pub fn custom_fill_offer(&self, item: ItemId, tokens: &[&str]) -> Vec<CustomOffer> {
        if !self.is_active_login(item) {
            return Vec::new();
        }
        let ordered = in_list_order(self.custom_field_states(item));
        let mut seen: Vec<&str> = Vec::new();
        let mut out = Vec::new();
        for token in tokens.iter().take(MAX_CUSTOM_TOKENS) {
            if seen.contains(token) || check_autocomplete_id(token.as_bytes()).is_err() {
                continue;
            }
            seen.push(token);
            let Some(field) = winner_index(&ordered, token).and_then(|w| ordered.get(w)) else {
                continue;
            };
            if field.fill_value().is_none() {
                continue;
            }
            let Some(label) = field.label() else {
                continue;
            };
            out.push(CustomOffer {
                token: Zeroizing::new((*token).to_owned()),
                element: field.element.clone(),
                label: Zeroizing::new(label.to_owned()),
                concealed: field.kind() == CustomFieldKind::Hidden,
            });
        }
        out
    }

    /// The values one fill click sends (ADR 0076 §4.2): username and password narrowed by
    /// `only`, the TOTP code if asked for and the item has one, and each custom value whose
    /// recorded element still fills its token (re-checked now: a field edited since the offer
    /// is dropped if it no longer qualifies). A role target that carries a token that resolved
    /// gets the custom value, and the role value is not sent.
    ///
    /// # Errors
    /// [`ClientError::UnknownItem`] unless `item` is an Active Login.
    pub fn fill_plan(
        &self,
        item: ItemId,
        request: &FillRequest<'_>,
        now_ms: u64,
    ) -> Result<FillPlan, ClientError> {
        if !self.is_active_login(item) {
            return Err(ClientError::UnknownItem);
        }
        let ordered = in_list_order(self.custom_field_states(item));
        let mut plan = FillPlan::default();
        for choice in request.custom.iter().take(MAX_CUSTOM_TOKENS) {
            if plan
                .custom
                .iter()
                .any(|(t, _)| t.as_str() == choice.token.as_str())
            {
                continue;
            }
            let Some(field) = winner_index(&ordered, &choice.token).and_then(|w| ordered.get(w))
            else {
                continue;
            };
            if field.element.as_str() != choice.element.as_str() {
                continue;
            }
            if let Some(value) = field.fill_value() {
                plan.custom
                    .push((choice.token.clone(), Zeroizing::new(value.to_owned())));
            }
        }
        let resolved = |token: Option<&str>| {
            token.is_some_and(|t| plan.custom.iter().any(|(c, _)| c.as_str() == t))
        };
        let want_username = matches!(request.only, None | Some(FillOnly::Username))
            && !resolved(request.username_token);
        let want_password = matches!(request.only, None | Some(FillOnly::Password))
            && !resolved(request.password_token);
        let want_totp = request.totp || request.only == Some(FillOnly::Totp);
        let text = |key: &str| {
            self.field_value(item, key).and_then(|v| match v.decode() {
                Ok(ValueRef::Text(t)) if !t.is_empty() => Some(Zeroizing::new(t.to_owned())),
                _ => None,
            })
        };
        if want_username {
            plan.username = text(LOGIN_USERNAME);
        }
        if want_password {
            plan.password = text(LOGIN_PASSWORD);
        }
        if want_totp {
            plan.totp = self.totp_now(item, now_ms).map(|t| t.code);
        }
        Ok(plan)
    }

    /// The save-dialog rows for the custom fields a submitted form captured (ADR 0076 §5.3):
    /// for a new item (`item` `None`) or an update of `item`. A token that is invalid, reserved
    /// or repeated, an empty value or one over 4096 UTF-16 units gives no row; at most 8 are
    /// read. On an update: no field with the token gives an "add" row; the field that fills it
    /// with a different value gives an "update" row; an equal value, or a token only a field
    /// that cannot fill holds (adding would duplicate the id, and a save never changes an
    /// existing id, §5.4), gives none.
    #[must_use]
    pub fn custom_save_plan(
        &self,
        item: Option<ItemId>,
        captured: &[CapturedField<'_>],
    ) -> Vec<SaveRow> {
        let ordered = match item {
            Some(item) if self.is_active_login(item) => {
                in_list_order(self.custom_field_states(item))
            }
            Some(_) => return Vec::new(),
            None => Vec::new(),
        };
        let mut seen: Vec<&str> = Vec::new();
        let mut rows = Vec::new();
        for (index, field) in captured.iter().enumerate().take(MAX_CAPTURED_FIELDS) {
            if seen.contains(&field.token)
                || check_autocomplete_id(field.token.as_bytes()).is_err()
                || field.value.is_empty()
                || field.value.encode_utf16().count() > MAX_FILL_VALUE_UTF16
            {
                continue;
            }
            seen.push(field.token);
            if let Some(existing) = winner_index(&ordered, field.token).and_then(|w| ordered.get(w))
            {
                if existing.text(ATTR_VALUE) == Some(field.value) {
                    continue;
                }
                let Some(label) = existing.label() else {
                    continue;
                };
                rows.push(SaveRow {
                    index,
                    kind: SaveRowKind::Update(existing.element.clone()),
                    label: Zeroizing::new(label.to_owned()),
                    concealed: existing.kind() == CustomFieldKind::Hidden,
                    checked: false,
                });
            } else {
                if ordered
                    .iter()
                    .any(|f| f.autocomplete() == Some(field.token))
                {
                    continue;
                }
                rows.push(SaveRow {
                    index,
                    kind: SaveRowKind::Add,
                    label: Zeroizing::new(field.token.to_owned()),
                    concealed: field.masked,
                    checked: !field.masked,
                });
            }
        }
        rows
    }

    /// Whether `item` is an Active Login: the only items that fill.
    fn is_active_login(&self, item: ItemId) -> bool {
        self.item_lifecycle(item) == ItemLifecycle::Active
            && self.item_type(item) == Some(ItemType::LOGIN)
    }
}

/// `true` if `key` is an attribute of a custom field.
fn is_field_key(key: &str) -> bool {
    FieldKeyRef::parse(key.as_bytes())
        .is_ok_and(|k| k.list() == Some(LIST_FIELD) && k.attribute().is_some())
}

#[cfg(test)]
mod tests;
