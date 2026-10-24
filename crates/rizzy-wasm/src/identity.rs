// SPDX-License-Identifier: AGPL-3.0-only

//! The identity generator for JavaScript ([ADR 0079] §3, §10): the web vault's "New identity"
//! form opens pre-filled from [`generate_identity`] (`generateIdentity`), redraws one field
//! and its dependents with [`regenerate_identity_field`] (`regenerateIdentityField`), and
//! lists the bundled countries ([`identity_countries`]) and the age presets ([`age_presets`])
//! in `rizzy-client`'s order. The leaf passes the platform's local date; randomness is the OS
//! RNG. A generated identity is not a secret (ADR 0079 §2), so it is held as plain strings.
//!
//! Every option arrives from JavaScript and is untrusted (ADR 0013 §3 rule 8): each is checked
//! by `rizzy-client` and a refusal throws an `identity_*` code ([`identity_error`]).
//!
//! [ADR 0079]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0079-identity-generator.md

use rizzy_client::identity_gen::{
    self, AgeRange, CivilDate, CountryCode, EmailDomain, EmailStyle, GeneratedIdentity,
    IdentityDefaults, IdentityField, IdentityGenError, IdentityOptions, SexChoice,
};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::error::CoreError;
use crate::rng::os_rng;

/// An option string that is not one of its allowed values (`male`, `female`, `random`;
/// `name`, `nickname`), or a date that is not a calendar date.
pub const IDENTITY_INVALID_OPTION: &str = "identity_invalid_option";

/// The stable `identity_*` code of a refusal. Codes never change meaning.
///
/// | Refusal | Code |
/// |---|---|
/// | country not bundled | `identity_unsupported_country` |
/// | age range outside `18 <= min <= max <= 99` | `identity_age_range` |
/// | email domain not LDH A-label syntax | `identity_email_domain` |
/// | email domain with non-ASCII characters (enter its `xn--` form) | `identity_email_domain_not_ascii` |
/// | today too early for the range | `identity_date` |
/// | not a generated field key | `identity_unknown_field` |
/// | the bundled data failed to parse (a build defect) | `identity_data` |
/// | RNG failure | `identity_rng_failure` |
/// | an option string outside its values | [`IDENTITY_INVALID_OPTION`] |
#[must_use]
pub const fn identity_error(e: IdentityGenError) -> CoreError {
    CoreError::new(match e {
        IdentityGenError::UnsupportedCountry => "identity_unsupported_country",
        IdentityGenError::AgeRange => "identity_age_range",
        IdentityGenError::EmailDomain => "identity_email_domain",
        IdentityGenError::EmailDomainNotAscii => "identity_email_domain_not_ascii",
        IdentityGenError::Date => "identity_date",
        IdentityGenError::UnknownField => "identity_unknown_field",
        IdentityGenError::Data(_) => "identity_data",
        IdentityGenError::Rng => "identity_rng_failure",
    })
}

/// A generated identity, held for redrawing one field. Its values are plain text.
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct IdentityDraft {
    /// The generator's output and draw state.
    inner: GeneratedIdentity,
}

#[wasm_bindgen]
impl IdentityDraft {
    /// The keys of the filled fields, in `rizzy-client`'s order (`identity.sex` first).
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn keys(&self) -> Vec<String> {
        self.inner
            .fields()
            .into_iter()
            .map(|(k, _)| k.to_owned())
            .collect()
    }

    /// The value of the field `key`, if it is filled.
    #[must_use]
    pub fn value(&self, key: &str) -> Option<String> {
        IdentityField::from_key(key)
            .ok()
            .and_then(|f| self.inner.get(f))
            .map(str::to_owned)
    }

    /// The default item name, "First Last" (ADR 0079 §3).
    #[wasm_bindgen(getter, js_name = itemName)]
    #[must_use]
    pub fn item_name(&self) -> String {
        self.inner.item_name()
    }
}

/// One age preset (ADR 0079 §3): a stable id and its bounds; clients localize the label.
#[wasm_bindgen]
#[derive(Clone, Copy, Debug)]
pub struct AgePresetView {
    /// The preset.
    preset: identity_gen::AgePreset,
}

#[wasm_bindgen]
impl AgePresetView {
    /// The stable id, for example `18-27` or `any`.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn id(&self) -> String {
        self.preset.id.to_owned()
    }

    /// The youngest age.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn min(&self) -> u8 {
        self.preset.min
    }

    /// The oldest age.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn max(&self) -> u8 {
        self.preset.max
    }
}

/// One bundled country: its ISO code and CLDR English name.
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct IdentityCountryView {
    /// The ISO 3166-1 alpha-2 code.
    code: String,
    /// The English name.
    name: String,
}

#[wasm_bindgen]
impl IdentityCountryView {
    /// The ISO 3166-1 alpha-2 code, upper case.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn code(&self) -> String {
        self.code.clone()
    }

    /// The CLDR English name.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn name(&self) -> String {
        self.name.clone()
    }
}

/// The age presets, in display order (ADR 0079 §3).
#[wasm_bindgen(js_name = agePresets)]
#[must_use]
pub fn age_presets() -> Vec<AgePresetView> {
    identity_gen::age_presets()
        .iter()
        .map(|&preset| AgePresetView { preset })
        .collect()
}

/// The bundled countries, in code order.
///
/// # Errors
/// `identity_data` if the bundled data does not parse.
#[wasm_bindgen(js_name = identityCountries)]
pub fn identity_countries() -> Result<Vec<IdentityCountryView>, CoreError> {
    let data =
        identity_gen::embedded_data().map_err(|e| identity_error(IdentityGenError::Data(e)))?;
    Ok(data
        .countries()
        .iter()
        .map(|c| IdentityCountryView {
            code: c.code().to_owned(),
            name: c.name().to_owned(),
        })
        .collect())
}

/// Checks an age range (ADR 0079 §3, §10: the custom-range and exact-age inputs).
///
/// # Errors
/// `identity_age_range` outside `18 <= min <= max <= 99`.
#[wasm_bindgen(js_name = checkAgeRange)]
pub fn check_age_range(min: u8, max: u8) -> Result<(), CoreError> {
    AgeRange::new(min, max).map(|_| ()).map_err(identity_error)
}

/// Checks an email domain and returns it lower-cased (ADR 0079 §3, §8).
///
/// # Errors
/// `identity_email_domain` or `identity_email_domain_not_ascii`.
#[wasm_bindgen(js_name = normalizeEmailDomain)]
pub fn normalize_email_domain(domain: &str) -> Result<String, CoreError> {
    EmailDomain::parse(domain)
        .map(|d| d.as_str().to_owned())
        .map_err(identity_error)
}

/// The sex option from its string.
///
/// # Errors
/// [`IDENTITY_INVALID_OPTION`].
pub fn sex_choice(text: &str) -> Result<SexChoice, CoreError> {
    match text {
        "male" => Ok(SexChoice::Male),
        "female" => Ok(SexChoice::Female),
        "random" => Ok(SexChoice::Random),
        _ => Err(CoreError::new(IDENTITY_INVALID_OPTION)),
    }
}

/// The sex option's string.
#[must_use]
pub const fn sex_choice_name(sex: SexChoice) -> &'static str {
    match sex {
        SexChoice::Male => "male",
        SexChoice::Female => "female",
        SexChoice::Random => "random",
    }
}

/// The email style from its string.
///
/// # Errors
/// [`IDENTITY_INVALID_OPTION`].
pub fn email_style(text: &str) -> Result<EmailStyle, CoreError> {
    match text {
        "name" => Ok(EmailStyle::NameAndBirthday),
        "nickname" => Ok(EmailStyle::Nickname),
        _ => Err(CoreError::new(IDENTITY_INVALID_OPTION)),
    }
}

/// The email style's string.
#[must_use]
pub const fn email_style_name(style: EmailStyle) -> &'static str {
    match style {
        EmailStyle::NameAndBirthday => "name",
        EmailStyle::Nickname => "nickname",
    }
}

/// The options from what JavaScript passes. An empty domain means none.
///
/// # Errors
/// As [`sex_choice`], [`email_style`], and the `identity_*` codes of each check.
pub fn identity_options(
    sex: &str,
    country: &str,
    age_min: u8,
    age_max: u8,
    style: &str,
    domain: Option<&str>,
) -> Result<IdentityOptions, CoreError> {
    let mut options = IdentityOptions::new(CountryCode::parse(country).map_err(identity_error)?);
    options.sex = sex_choice(sex)?;
    options.age = AgeRange::new(age_min, age_max).map_err(identity_error)?;
    options.email_style = email_style(style)?;
    options.email_domain = match domain {
        None | Some("") => None,
        Some(d) => Some(EmailDomain::parse(d).map_err(identity_error)?),
    };
    Ok(options)
}

/// Today's civil date from the platform's local date.
fn today(year: i32, month: u8, day: u8) -> Result<CivilDate, CoreError> {
    CivilDate::new(year, month, day).ok_or(CoreError::new(IDENTITY_INVALID_OPTION))
}

/// Draws a new identity (ADR 0079 §3, §4) with title and phone on (Open questions 4 and 5).
///
/// `sex` is `male`, `female` or `random`; `email_style` is `name` or `nickname`;
/// `email_domain` empty or absent means none (the email stays empty, §8); `year`, `month`,
/// `day` are today's local date.
///
/// # Errors
/// The `identity_*` codes ([`identity_error`], [`IDENTITY_INVALID_OPTION`]).
#[wasm_bindgen(js_name = generateIdentity)]
#[expect(
    clippy::too_many_arguments,
    reason = "the flat argument list is the wasm-bindgen signature; JavaScript passes plain values"
)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "wasm-bindgen passes an optional string by value"
)]
pub fn generate_identity(
    sex: &str,
    country: &str,
    age_min: u8,
    age_max: u8,
    email_style: &str,
    email_domain: Option<String>,
    year: i32,
    month: u8,
    day: u8,
) -> Result<IdentityDraft, CoreError> {
    let options = identity_options(
        sex,
        country,
        age_min,
        age_max,
        email_style,
        email_domain.as_deref(),
    )?;
    let data =
        identity_gen::embedded_data().map_err(|e| identity_error(IdentityGenError::Data(e)))?;
    let inner =
        identity_gen::generate_identity(&mut os_rng(), data, &options, today(year, month, day)?)
            .map_err(identity_error)?;
    Ok(IdentityDraft { inner })
}

/// Redraws the field `field_key` of `current` and its dependents with these options
/// (ADR 0079 §4): the picker changes and the per-field Regenerate buttons. The result holds
/// every field; the form writes only those the user has not edited, plus `field_key` itself.
///
/// # Errors
/// As [`generate_identity`], and `identity_unknown_field`.
#[wasm_bindgen(js_name = regenerateIdentityField)]
#[expect(
    clippy::too_many_arguments,
    reason = "the flat argument list is the wasm-bindgen signature; JavaScript passes plain values"
)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "wasm-bindgen passes an optional string by value"
)]
pub fn regenerate_identity_field(
    current: &IdentityDraft,
    field_key: &str,
    sex: &str,
    country: &str,
    age_min: u8,
    age_max: u8,
    email_style: &str,
    email_domain: Option<String>,
    year: i32,
    month: u8,
    day: u8,
) -> Result<IdentityDraft, CoreError> {
    let field = IdentityField::from_key(field_key).map_err(identity_error)?;
    let options = identity_options(
        sex,
        country,
        age_min,
        age_max,
        email_style,
        email_domain.as_deref(),
    )?;
    let data =
        identity_gen::embedded_data().map_err(|e| identity_error(IdentityGenError::Data(e)))?;
    let inner = identity_gen::regenerate_field(
        &mut os_rng(),
        data,
        &options,
        today(year, month, day)?,
        field,
        &current.inner,
    )
    .map_err(identity_error)?;
    Ok(IdentityDraft { inner })
}

/// The account's identity generator defaults (`ACCOUNT_SETTINGS` tag `0x0004`, ADR 0079 Open
/// question 7) as JavaScript reads them.
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct IdentityDefaultsView {
    /// The defaults.
    inner: IdentityDefaults,
}

impl IdentityDefaultsView {
    /// Wraps the decoded defaults.
    pub(crate) const fn new(inner: IdentityDefaults) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen]
impl IdentityDefaultsView {
    /// `male`, `female` or `random`.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn sex(&self) -> String {
        sex_choice_name(self.inner.sex).to_owned()
    }

    /// The default country, if set.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn country(&self) -> Option<String> {
        self.inner.country.map(|c| c.as_str().to_owned())
    }

    /// The last-used age range's lower bound.
    #[wasm_bindgen(getter, js_name = ageMin)]
    #[must_use]
    pub fn age_min(&self) -> u8 {
        self.inner.age.min()
    }

    /// The last-used age range's upper bound.
    #[wasm_bindgen(getter, js_name = ageMax)]
    #[must_use]
    pub fn age_max(&self) -> u8 {
        self.inner.age.max()
    }

    /// `name` or `nickname`.
    #[wasm_bindgen(getter, js_name = emailStyle)]
    #[must_use]
    pub fn email_style(&self) -> String {
        email_style_name(self.inner.email_style).to_owned()
    }

    /// The email domain for generated identities, if set.
    #[wasm_bindgen(getter, js_name = emailDomain)]
    #[must_use]
    pub fn email_domain(&self) -> Option<String> {
        self.inner
            .email_domain
            .as_ref()
            .map(|d| d.as_str().to_owned())
    }
}

/// The defaults from what JavaScript passes; an empty country or domain means none.
///
/// # Errors
/// As [`identity_options`].
pub fn identity_defaults(
    sex: &str,
    country: Option<&str>,
    age_min: u8,
    age_max: u8,
    style: &str,
    domain: Option<&str>,
) -> Result<IdentityDefaults, CoreError> {
    Ok(IdentityDefaults {
        sex: sex_choice(sex)?,
        country: match country {
            None | Some("") => None,
            Some(c) => Some(CountryCode::parse(c).map_err(identity_error)?),
        },
        age: AgeRange::new(age_min, age_max).map_err(identity_error)?,
        email_style: email_style(style)?,
        email_domain: match domain {
            None | Some("") => None,
            Some(d) => Some(EmailDomain::parse(d).map_err(identity_error)?),
        },
    })
}
