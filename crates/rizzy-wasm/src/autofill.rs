// SPDX-License-Identifier: AGPL-3.0-only

//! Autocomplete-driven autofill bindings ([ADR 0076] §2.5, §4, §5; ADR 0013 §3 rules 3 and 6):
//! one coarse call per user action, over [`rizzy_client::autofill`].
//!
//! | Call | What crosses to JavaScript |
//! |---|---|
//! | `custom_field_autofill` (`Session.customFieldAutofill`, `DeviceSession.customFieldAutofill`) | per custom field: its element id, what its autocomplete id does, and for a shadowed one the winner's id and Display Name (the editor shows both anyway) |
//! | `autofill_offer` (`DeviceSession.autofillOffer`) | whether the item fills a TOTP code, and per page token the Display Name, the concealed flag and the element id the offer records. Never a value |
//! | `fill_plan` (`DeviceSession.fillPlan`) | the values of one fill click: username, password, the current TOTP code (never the secret), custom values by token |
//! | `save_plan` (`DeviceSession.customSavePlan`) | the save dialog's rows: kind, element id, Display Name, flags. Never a value |
//!
//! [ADR 0076]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0076-autocomplete-driven-autofill.md

use core::fmt;

use rizzy_client::ClientError;
use rizzy_client::autofill::{
    AutofillState, CapturedField, CustomChoice, FillOnly, FillRequest, SaveRowKind,
};
use rizzy_client::rizzy_core::item::schema::{ATTR_LABEL, LIST_FIELD};
use rizzy_client::rizzy_core::item::value::ValueRef;
use rizzy_client::sync::VaultSync;
use wasm_bindgen::prelude::wasm_bindgen;
use zeroize::Zeroizing;

use crate::error::{CoreError, CoreResult};
use crate::items::{item_in, visible_item};

/// What one custom field's autocomplete id does (ADR 0076 §2.4–§2.5, §3), for the editor.
#[wasm_bindgen]
pub struct CustomFieldAutofillView {
    /// The element id, hex.
    element: String,
    /// `none`, `fills`, `invalid`, `reserved`, `wrong_kind`, `unnamed` or `shadowed`.
    state: &'static str,
    /// For `shadowed`: the element id of the field that fills the id instead.
    winner: Option<String>,
    /// For `shadowed`: that field's Display Name.
    winner_label: Option<Zeroizing<String>>,
}

impl fmt::Debug for CustomFieldAutofillView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustomFieldAutofillView")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

#[wasm_bindgen]
impl CustomFieldAutofillView {
    /// The element id, hex.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn element(&self) -> String {
        self.element.clone()
    }

    /// What the id does: `none`, `fills`, `invalid` (W1), `reserved` (W2), `wrong_kind` (W4),
    /// `unnamed` (no Display Name) or `shadowed` (§2.5).
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn state(&self) -> String {
        self.state.to_owned()
    }

    /// For `shadowed`: the winner's element id.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn winner(&self) -> Option<String> {
        self.winner.clone()
    }

    /// For `shadowed`: the winner's Display Name.
    #[wasm_bindgen(getter, js_name = winnerLabel)]
    #[must_use]
    pub fn winner_label(&self) -> Option<String> {
        self.winner_label.as_ref().map(|l| l.as_str().to_owned())
    }
}

/// The displayed Text of `field/<element>/label`, if any.
fn label_of(
    vault: &VaultSync,
    item: rizzy_client::items::ItemId,
    element: &str,
) -> Option<Zeroizing<String>> {
    let value = vault.field_value(item, &format!("{LIST_FIELD}/{element}/{ATTR_LABEL}"))?;
    match value.decode() {
        Ok(ValueRef::Text(text)) => Some(Zeroizing::new(text.to_owned())),
        _ => None,
    }
}

/// [`VaultSync::custom_field_autofill`] for a visible item.
///
/// # Errors
/// `invalid_input` for an id that is not 32 hex digits; `unknown_item`.
pub(crate) fn custom_field_autofill(
    vault: &VaultSync,
    id: &str,
) -> CoreResult<Vec<CustomFieldAutofillView>> {
    let item = visible_item(vault, id)?;
    Ok(vault
        .custom_field_autofill(item)
        .into_iter()
        .map(|f| {
            let (state, winner) = match f.state {
                AutofillState::None => ("none", None),
                AutofillState::Fills => ("fills", None),
                AutofillState::Invalid => ("invalid", None),
                AutofillState::Reserved => ("reserved", None),
                AutofillState::WrongKind => ("wrong_kind", None),
                AutofillState::Unnamed => ("unnamed", None),
                AutofillState::Shadowed(winner) => ("shadowed", Some(winner)),
            };
            let winner_label = winner.as_ref().and_then(|w| label_of(vault, item, w));
            CustomFieldAutofillView {
                element: f.element.as_str().to_owned(),
                state,
                winner: winner.map(|w| w.as_str().to_owned()),
                winner_label,
            }
        })
        .collect())
}

/// One custom field an offer discloses (ADR 0076 §4.1).
#[wasm_bindgen]
pub struct CustomOfferView {
    /// The page token.
    token: String,
    /// The element id the offer records.
    element: String,
    /// The Display Name.
    label: Zeroizing<String>,
    /// A hidden field.
    concealed: bool,
}

impl fmt::Debug for CustomOfferView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustomOfferView")
            .field("concealed", &self.concealed)
            .finish_non_exhaustive()
    }
}

#[wasm_bindgen]
impl CustomOfferView {
    /// The page token it fills.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn token(&self) -> String {
        self.token.clone()
    }

    /// The element id the offer records for the token (kept in the long-lived context).
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn element(&self) -> String {
        self.element.clone()
    }

    /// The Display Name.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn label(&self) -> String {
        self.label.as_str().to_owned()
    }

    /// A hidden field: the row says "(hidden)".
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn concealed(&self) -> bool {
        self.concealed
    }
}

/// What a fill of one item would include (ADR 0076 §4.1), values never included.
#[wasm_bindgen]
#[derive(Debug)]
pub struct AutofillOffer {
    /// The item holds a valid time-based secret.
    fills_totp: bool,
    /// The custom fields, in the order of the page tokens.
    custom: Vec<CustomOfferView>,
}

#[wasm_bindgen]
impl AutofillOffer {
    /// The item can fill a TOTP code (`hasTotp`, ADR 0076 §1.3 rule (g)).
    #[wasm_bindgen(getter, js_name = fillsTotp)]
    #[must_use]
    pub fn fills_totp(&self) -> bool {
        self.fills_totp
    }

    /// The custom fields it would fill.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn custom(&self) -> Vec<CustomOfferView> {
        self.custom
            .iter()
            .map(|c| CustomOfferView {
                token: c.token.clone(),
                element: c.element.clone(),
                label: c.label.clone(),
                concealed: c.concealed,
            })
            .collect()
    }
}

/// The offer for an Active item and the page's custom `tokens`.
///
/// # Errors
/// `invalid_input` for an id that is not 32 hex digits.
pub(crate) fn autofill_offer(
    vault: &VaultSync,
    id: &str,
    tokens: &[String],
) -> CoreResult<AutofillOffer> {
    let item = item_in(vault, id)?;
    let tokens: Vec<&str> = tokens.iter().map(String::as_str).collect();
    let custom = vault
        .custom_fill_offer(item, &tokens)
        .into_iter()
        .map(|c| CustomOfferView {
            token: c.token.as_str().to_owned(),
            element: c.element.as_str().to_owned(),
            label: c.label,
            concealed: c.concealed,
        })
        .collect();
    Ok(AutofillOffer {
        fills_totp: vault.has_time_based_totp(item),
        custom,
    })
}

/// The values one fill click sends (ADR 0076 §4.4 `FillValues`). Wiped when freed.
#[wasm_bindgen]
pub struct FillValues {
    /// `login.username`.
    username: Option<Zeroizing<String>>,
    /// `login.password`.
    password: Option<Zeroizing<String>>,
    /// The current TOTP code.
    totp: Option<Zeroizing<String>>,
    /// Custom tokens, parallel to [`FillValues::custom_values`].
    custom_tokens: Vec<String>,
    /// Custom values.
    custom_values: Vec<Zeroizing<String>>,
}

impl fmt::Debug for FillValues {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FillValues")
            .field("custom", &self.custom_tokens.len())
            .finish_non_exhaustive()
    }
}

#[wasm_bindgen]
impl FillValues {
    /// `login.username`, if sent.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn username(&self) -> Option<String> {
        self.username.as_ref().map(|v| v.as_str().to_owned())
    }

    /// `login.password`, if sent.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn password(&self) -> Option<String> {
        self.password.as_ref().map(|v| v.as_str().to_owned())
    }

    /// The current TOTP code, if sent.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn totp(&self) -> Option<String> {
        self.totp.as_ref().map(|v| v.as_str().to_owned())
    }

    /// The custom tokens, parallel to [`FillValues::custom_values`].
    #[wasm_bindgen(getter, js_name = customTokens)]
    #[must_use]
    pub fn custom_tokens(&self) -> Vec<String> {
        self.custom_tokens.clone()
    }

    /// The custom values.
    #[wasm_bindgen(getter, js_name = customValues)]
    #[must_use]
    pub fn custom_values(&self) -> Vec<String> {
        self.custom_values
            .iter()
            .map(|v| v.as_str().to_owned())
            .collect()
    }
}

/// The `only` narrowing as JavaScript names it.
fn only_of(only: Option<&str>) -> CoreResult<Option<FillOnly>> {
    match only {
        None => Ok(None),
        Some("username") => Ok(Some(FillOnly::Username)),
        Some("password") => Ok(Some(FillOnly::Password)),
        Some("totp") => Ok(Some(FillOnly::Totp)),
        Some(_) => Err(ClientError::InvalidInput.into()),
    }
}

/// One fill's request, as the long-lived context's offer record holds it.
pub(crate) struct FillArgs<'a> {
    /// The narrowing.
    pub(crate) only: Option<&'a str>,
    /// The step also has a TOTP target.
    pub(crate) totp: bool,
    /// The recorded custom tokens.
    pub(crate) tokens: &'a [String],
    /// The element ids recorded for them, parallel.
    pub(crate) elements: &'a [String],
    /// The username target's custom token.
    pub(crate) username_token: Option<&'a str>,
    /// The password target's custom token.
    pub(crate) password_token: Option<&'a str>,
}

impl fmt::Debug for FillArgs<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FillArgs")
            .field("only", &self.only)
            .field("totp", &self.totp)
            .finish_non_exhaustive()
    }
}

/// [`VaultSync::fill_plan`] for one fill click.
///
/// # Errors
/// `invalid_input` for a bad id, a bad `only` or token and element lists of different
/// lengths; `unknown_item` unless the item is an Active Login.
pub(crate) fn fill_plan(
    vault: &VaultSync,
    id: &str,
    args: &FillArgs<'_>,
    now_ms: u64,
) -> CoreResult<FillValues> {
    let item = item_in(vault, id)?;
    if args.tokens.len() != args.elements.len() {
        return Err(ClientError::InvalidInput.into());
    }
    let custom: Vec<CustomChoice> = args
        .tokens
        .iter()
        .zip(args.elements)
        .map(|(token, element)| CustomChoice {
            token: Zeroizing::new(token.clone()),
            element: Zeroizing::new(element.clone()),
        })
        .collect();
    let request = FillRequest {
        only: only_of(args.only)?,
        totp: args.totp,
        custom: &custom,
        username_token: args.username_token,
        password_token: args.password_token,
    };
    let plan = vault.fill_plan(item, &request, now_ms)?;
    let (custom_tokens, custom_values) = plan
        .custom
        .into_iter()
        .map(|(token, value)| (token.as_str().to_owned(), value))
        .unzip();
    Ok(FillValues {
        username: plan.username,
        password: plan.password,
        totp: plan.totp,
        custom_tokens,
        custom_values,
    })
}

/// One save-dialog row (ADR 0076 §5.3). No value.
#[wasm_bindgen]
pub struct SaveRowView {
    /// The index of the captured field.
    index: u32,
    /// `add` or `update`.
    kind: &'static str,
    /// For `update`: the field's element id.
    element: Option<String>,
    /// The Display Name (the token for a new field, editable).
    label: Zeroizing<String>,
    /// "(hidden)".
    concealed: bool,
    /// The row's default.
    checked: bool,
}

impl fmt::Debug for SaveRowView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SaveRowView")
            .field("index", &self.index)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

#[wasm_bindgen]
impl SaveRowView {
    /// The index of the captured field the row is for.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn index(&self) -> u32 {
        self.index
    }

    /// `add` or `update`.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn kind(&self) -> String {
        self.kind.to_owned()
    }

    /// For `update`: the existing field's element id.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn element(&self) -> Option<String> {
        self.element.clone()
    }

    /// The Display Name.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn label(&self) -> String {
        self.label.as_str().to_owned()
    }

    /// A hidden field.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn concealed(&self) -> bool {
        self.concealed
    }

    /// Checked by default.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn checked(&self) -> bool {
        self.checked
    }
}

/// [`VaultSync::custom_save_plan`] for a new item (`id` `None`) or an update.
///
/// # Errors
/// `invalid_input` for a bad id or lists of different lengths.
pub(crate) fn save_plan(
    vault: &VaultSync,
    id: Option<&str>,
    tokens: &[String],
    values: &[Zeroizing<String>],
    masked: &[u8],
) -> CoreResult<Vec<SaveRowView>> {
    let item = id.map(|id| item_in(vault, id)).transpose()?;
    if tokens.len() != values.len() || tokens.len() != masked.len() {
        return Err(ClientError::InvalidInput.into());
    }
    let captured: Vec<CapturedField<'_>> = tokens
        .iter()
        .zip(values)
        .zip(masked)
        .map(|((token, value), masked)| CapturedField {
            token,
            value: value.as_str(),
            masked: *masked != 0,
        })
        .collect();
    vault
        .custom_save_plan(item, &captured)
        .into_iter()
        .map(|row| {
            let (kind, element) = match row.kind {
                SaveRowKind::Add => ("add", None),
                SaveRowKind::Update(element) => ("update", Some(element.as_str().to_owned())),
            };
            Ok(SaveRowView {
                index: u32::try_from(row.index)
                    .map_err(|_| CoreError::from(ClientError::Internal))?,
                kind,
                element,
                label: row.label,
                concealed: row.concealed,
                checked: row.checked,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_is_one_of_three_names() {
        assert_eq!(only_of(None).unwrap(), None);
        assert_eq!(only_of(Some("username")).unwrap(), Some(FillOnly::Username));
        assert_eq!(only_of(Some("password")).unwrap(), Some(FillOnly::Password));
        assert_eq!(only_of(Some("totp")).unwrap(), Some(FillOnly::Totp));
        for bad in ["", "TOTP", "custom", "username "] {
            assert_eq!(only_of(Some(bad)).unwrap_err().code(), "invalid_input");
        }
    }

    #[test]
    fn debug_output_shows_no_value_or_name() {
        let values = FillValues {
            username: Some(Zeroizing::new("alice".to_owned())),
            password: Some(Zeroizing::new("hunter2".to_owned())),
            totp: Some(Zeroizing::new("123456".to_owned())),
            custom_tokens: vec!["member".to_owned()],
            custom_values: vec![Zeroizing::new("M-1".to_owned())],
        };
        let offer = CustomOfferView {
            token: "member".to_owned(),
            element: "00".repeat(16),
            label: Zeroizing::new("Member no.".to_owned()),
            concealed: true,
        };
        let row = SaveRowView {
            index: 0,
            kind: "add",
            element: None,
            label: Zeroizing::new("Member no.".to_owned()),
            concealed: false,
            checked: true,
        };
        let view = CustomFieldAutofillView {
            element: "00".repeat(16),
            state: "shadowed",
            winner: Some("11".repeat(16)),
            winner_label: Some(Zeroizing::new("Member no.".to_owned())),
        };
        let text = format!("{values:?} {offer:?} {row:?} {view:?}");
        for secret in ["alice", "hunter2", "123456", "M-1", "Member", "member"] {
            assert!(!text.contains(secret), "{secret} in {text}");
        }
        assert_eq!(values.custom_values(), ["M-1"]);
        assert_eq!(view.winner_label().as_deref(), Some("Member no."));
    }
}
