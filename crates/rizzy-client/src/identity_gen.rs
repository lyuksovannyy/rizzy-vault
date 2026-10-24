// SPDX-License-Identifier: AGPL-3.0-only

//! The identity generator: a new identity, pre-filled ([ADR 0079]).
//!
//! [`generate_identity`] draws a synthetic identity for a country from the bundled data
//! ([`data`], [`embedded_data`]); [`regenerate_field`] redraws one field and the fields that
//! depend on it. Both are pure and sans-I/O: the caller passes its CSPRNG and today's civil
//! date (the leaf reads the platform clock), and the output is a list of `(field key, text)`
//! pairs for the ordinary create op. Nothing is written until the user saves (ADR 0079 §3).
//!
//! - **The draws** follow ADR 0079 §4 in its normative order, each with the password
//!   generator's uniform index ([`rizzy_core::generator::uniform`], CRYPTO.md §12.1), so the
//!   known-answer vectors pin every output for a given RNG stream, data version, options and date.
//! - **Not constant-time.** A generated identity is shown to the user at once and is not a
//!   secret (ADR 0079 §2), so values are read by plain indexing.
//! - **Never generated:** `identity.ssn`, `identity.passport_number`, `identity.drivers_license`
//!   (ADR 0079 §3). Middle name, company and address lines 2–3 stay empty.
//! - **Age.** A preset ([`AGE_PRESETS`]), a custom range and an exact age all reach the generator
//!   as one [`AgeRange`]; the completed age today is always inside it (§4 step 4).
//! - **Email.** Until masked email exists (M6) the domain is the user's own, and with none set
//!   `identity.email` is left empty (§8). The username, the nickname, is always filled.
//!
//! [ADR 0079]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0079-identity-generator.md

use core::fmt;

use rand_core::CryptoRng;
use rizzy_core::generator::{uniform, wordlist};
use rizzy_core::item::schema::{
    IDENTITY_ADDRESS1, IDENTITY_BIRTHDAY, IDENTITY_CITY, IDENTITY_COUNTRY, IDENTITY_EMAIL,
    IDENTITY_FIRST_NAME, IDENTITY_LAST_NAME, IDENTITY_PHONE, IDENTITY_POSTAL_CODE, IDENTITY_SEX,
    IDENTITY_SEX_FEMALE, IDENTITY_SEX_MALE, IDENTITY_STATE, IDENTITY_TITLE, IDENTITY_USERNAME,
};

pub mod data;
mod date;
mod defaults;
mod embedded;
#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code indexes fixtures; a panic there fails the test, which CLAUDE.md allows"
)]
mod tests;

pub use data::{Country, IdentityData, IdentityDataError};
pub use date::{CivilDate, MAX_YEAR, MIN_YEAR};
pub use defaults::{IdentityDefaults, TAG_IDENTITY_DEFAULTS};
pub use embedded::{NAME, VERSION, embedded_data};

use data::{Name, Surnames};

/// The youngest age an [`AgeRange`] may hold (ADR 0079 §3).
pub const MIN_AGE: u8 = 18;
/// The oldest age an [`AgeRange`] may hold (ADR 0079 §3).
pub const MAX_AGE: u8 = 99;
/// The longest email domain accepted, in bytes (ADR 0079 §3).
pub const MAX_DOMAIN_LEN: usize = 253;
/// The longest email local part generated, in octets (RFC 5321 §4.5.3.1.1).
pub const MAX_LOCAL_PART_LEN: usize = 64;
/// The longest age text [`AgeRange::parse`] reads.
const MAX_AGE_TEXT_LEN: usize = 16;

/// Why the generator refused. Carries no user data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityGenError {
    /// The country is not in the bundled data.
    UnsupportedCountry,
    /// The age range is outside `18 <= min <= max <= 99`, or its text is not a preset id,
    /// `MIN-MAX` or `N`.
    AgeRange,
    /// The email domain is not LDH A-label syntax (two or more labels of 1–63 bytes, at most
    /// 253 bytes in all).
    EmailDomain,
    /// The email domain has non-ASCII characters: enter its `xn--` form (no IDNA here).
    EmailDomainNotAscii,
    /// Today's date is too early for the age range.
    Date,
    /// The field name is not one the generator fills.
    UnknownField,
    /// The bundled data did not parse (a build defect).
    Data(IdentityDataError),
    /// The RNG failed (the uniform index ran out of draws).
    Rng,
}

impl fmt::Display for IdentityGenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedCountry => f.write_str("the country is not supported"),
            Self::AgeRange => f.write_str("the age range must be within 18 to 99, minimum first"),
            Self::EmailDomain => f.write_str("the email domain is not a valid domain name"),
            Self::EmailDomainNotAscii => {
                f.write_str("enter the email domain in its ASCII (xn--) form")
            }
            Self::Date => f.write_str("today's date is out of range"),
            Self::UnknownField => f.write_str("the field is not a generated identity field"),
            Self::Data(e) => write!(f, "{e}"),
            Self::Rng => f.write_str("the random number generator failed"),
        }
    }
}

impl core::error::Error for IdentityGenError {}

impl From<IdentityDataError> for IdentityGenError {
    fn from(e: IdentityDataError) -> Self {
        Self::Data(e)
    }
}

// --- options ----------------------------------------------------------------------------------

/// A generated identity's sex (ADR 0079 §1: stored as `male` or `female`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Sex {
    /// `male`.
    Male,
    /// `female`.
    Female,
}

impl Sex {
    /// The stored value, `male` or `female`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Male => IDENTITY_SEX_MALE,
            Self::Female => IDENTITY_SEX_FEMALE,
        }
    }

    /// Parses `male` or `female` (exactly).
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            IDENTITY_SEX_MALE => Some(Self::Male),
            IDENTITY_SEX_FEMALE => Some(Self::Female),
            _ => None,
        }
    }
}

/// The sex option: one of the two, or a draw (ADR 0079 §4 step 1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum SexChoice {
    /// Always male.
    Male,
    /// Always female.
    Female,
    /// `uniform(2)`: 0 is male, 1 is female.
    #[default]
    Random,
}

impl From<Sex> for SexChoice {
    fn from(sex: Sex) -> Self {
        match sex {
            Sex::Male => Self::Male,
            Sex::Female => Self::Female,
        }
    }
}

/// How the email local part is built (ADR 0079 §4 step 10).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum EmailStyle {
    /// `first` sep `last` suffix, the suffix from the birthday.
    #[default]
    NameAndBirthday,
    /// The nickname (the username).
    Nickname,
}

/// An age range in completed years, `18 <= min <= max <= 99` (ADR 0079 §3). A preset, a
/// custom range and an exact age `n` (as `[n, n]`) are all this one pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AgeRange {
    /// The youngest age.
    min: u8,
    /// The oldest age.
    max: u8,
}

impl AgeRange {
    /// The range `[min, max]`.
    ///
    /// # Errors
    /// [`IdentityGenError::AgeRange`] outside `18 <= min <= max <= 99`.
    pub const fn new(min: u8, max: u8) -> Result<Self, IdentityGenError> {
        if MIN_AGE <= min && min <= max && max <= MAX_AGE {
            Ok(Self { min, max })
        } else {
            Err(IdentityGenError::AgeRange)
        }
    }

    /// The exact age `n`, as `[n, n]`.
    ///
    /// # Errors
    /// [`IdentityGenError::AgeRange`] outside 18–99.
    pub const fn exact(n: u8) -> Result<Self, IdentityGenError> {
        Self::new(n, n)
    }

    /// Parses `rv`'s `--age`: a preset `id` ([`AGE_PRESETS`]), `MIN-MAX`, or `N` (an exact
    /// age). Reads at most 16 bytes; decimal digits only, no sign.
    ///
    /// # Errors
    /// [`IdentityGenError::AgeRange`] for anything else or out of bounds.
    pub fn parse(text: &str) -> Result<Self, IdentityGenError> {
        if text.len() > MAX_AGE_TEXT_LEN {
            return Err(IdentityGenError::AgeRange);
        }
        if let Some(p) = AGE_PRESETS.iter().find(|p| p.id == text) {
            return Ok(p.range());
        }
        let number = |t: &str| -> Result<u8, IdentityGenError> {
            if t.is_empty() || t.len() > 3 || !t.bytes().all(|b| b.is_ascii_digit()) {
                return Err(IdentityGenError::AgeRange);
            }
            t.parse().map_err(|_| IdentityGenError::AgeRange)
        };
        match text.split_once('-') {
            Some((min, max)) => Self::new(number(min)?, number(max)?),
            None => Self::exact(number(text)?),
        }
    }

    /// The youngest age.
    #[must_use]
    pub const fn min(self) -> u8 {
        self.min
    }

    /// The oldest age.
    #[must_use]
    pub const fn max(self) -> u8 {
        self.max
    }

    /// The first preset with these bounds, if any (ADR 0079 §10: how a remembered range reopens).
    #[must_use]
    pub fn preset(self) -> Option<&'static AgePreset> {
        AGE_PRESETS
            .iter()
            .find(|p| p.min == self.min && p.max == self.max)
    }
}

impl Default for AgeRange {
    /// The first-time default, the preset `18-27` (ADR 0079 §3).
    fn default() -> Self {
        AGE_PRESETS[0].range()
    }
}

/// One age preset of ADR 0079 §3: a stable `id` (the English label is localized by clients).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AgePreset {
    /// The stable id, for example `18-27` or `any`.
    pub id: &'static str,
    /// The youngest age.
    pub min: u8,
    /// The oldest age.
    pub max: u8,
}

impl AgePreset {
    /// The preset's range. Every preset is valid (pinned by a test).
    #[must_use]
    pub const fn range(&self) -> AgeRange {
        AgeRange {
            min: self.min,
            max: self.max,
        }
    }
}

/// An [`AgePreset`] (for the const list).
const fn preset(id: &'static str, min: u8, max: u8) -> AgePreset {
    AgePreset { id, min, max }
}

/// The age presets, in display order (ADR 0079 §3): the owner's 18–27 (the first-time default)
/// and 28+ (28–65), the nine five-year presets of `AliasVault`, and its "Random", 21–65.
/// Every client shows this list in this order.
pub const AGE_PRESETS: [AgePreset; 12] = [
    preset("18-27", 18, 27),
    preset("28-65", 28, 65),
    preset("21-25", 21, 25),
    preset("26-30", 26, 30),
    preset("31-35", 31, 35),
    preset("36-40", 36, 40),
    preset("41-45", 41, 45),
    preset("46-50", 46, 50),
    preset("51-55", 51, 55),
    preset("56-60", 56, 60),
    preset("61-65", 61, 65),
    preset("any", 21, 65),
];

/// [`AGE_PRESETS`] as a slice (the bindings' `age_presets()`).
#[must_use]
pub fn age_presets() -> &'static [AgePreset] {
    &AGE_PRESETS
}

/// A validated email domain: LDH A-label syntax, two or more labels of 1–63 bytes, at most 253
/// bytes, lower-cased (ADR 0079 §3). No IDNA: a U-label is refused.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EmailDomain(String);

impl EmailDomain {
    /// Validates and lower-cases `text`.
    ///
    /// # Errors
    /// [`IdentityGenError::EmailDomainNotAscii`] for any non-ASCII byte,
    /// [`IdentityGenError::EmailDomain`] for any other violation.
    pub fn parse(text: &str) -> Result<Self, IdentityGenError> {
        if !text.is_ascii() {
            return Err(IdentityGenError::EmailDomainNotAscii);
        }
        if text.is_empty() || text.len() > MAX_DOMAIN_LEN {
            return Err(IdentityGenError::EmailDomain);
        }
        let lower = text.to_ascii_lowercase();
        let mut labels = 0usize;
        for label in lower.split('.') {
            let ok = (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
            if !ok {
                return Err(IdentityGenError::EmailDomain);
            }
            labels += 1;
        }
        if labels < 2 {
            return Err(IdentityGenError::EmailDomain);
        }
        Ok(Self(lower))
    }

    /// The domain, lower case.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An ISO 3166-1 alpha-2 code, upper case. Whether the data has it is checked when generating.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CountryCode([u8; 2]);

impl CountryCode {
    /// Two ASCII letters, in any case.
    ///
    /// # Errors
    /// [`IdentityGenError::UnsupportedCountry`] otherwise.
    pub fn parse(text: &str) -> Result<Self, IdentityGenError> {
        match text.as_bytes() {
            [a, b] if a.is_ascii_alphabetic() && b.is_ascii_alphabetic() => {
                Ok(Self([a.to_ascii_uppercase(), b.to_ascii_uppercase()]))
            }
            _ => Err(IdentityGenError::UnsupportedCountry),
        }
    }

    /// The code, upper case.
    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.0).unwrap_or_default()
    }
}

/// Everything the generator takes besides the RNG, the data and today (ADR 0079 §3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityOptions {
    /// Male, female or a draw.
    pub sex: SexChoice,
    /// The country; must be in the data.
    pub country: CountryCode,
    /// The age range.
    pub age: AgeRange,
    /// The email local part's style.
    pub email_style: EmailStyle,
    /// The user's email domain; none means `identity.email` stays empty (ADR 0079 §8).
    pub email_domain: Option<EmailDomain>,
    /// Fill `identity.title` from the sex (Open question 4, accepted).
    pub title: bool,
    /// Fill `identity.phone` from fictional ranges where the country has one (Open question 5).
    pub phone: bool,
}

impl IdentityOptions {
    /// The defaults for `country`: a drawn sex, 18–27, name and birthday, no domain, a title
    /// and a phone.
    #[must_use]
    pub fn new(country: CountryCode) -> Self {
        Self {
            sex: SexChoice::Random,
            country,
            age: AgeRange::default(),
            email_style: EmailStyle::NameAndBirthday,
            email_domain: None,
            title: true,
            phone: true,
        }
    }
}

/// A field the generator fills, by its ADR 0018 §7 key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IdentityField {
    /// `identity.sex`.
    Sex,
    /// `identity.title` (derived from the sex; no draw of its own).
    Title,
    /// `identity.first_name`.
    FirstName,
    /// `identity.last_name`.
    LastName,
    /// `identity.birthday`.
    Birthday,
    /// `identity.username` (the nickname).
    Username,
    /// `identity.email`.
    Email,
    /// `identity.phone`.
    Phone,
    /// `identity.address1`.
    Address1,
    /// `identity.city`.
    City,
    /// `identity.state`.
    State,
    /// `identity.postal_code`.
    PostalCode,
    /// `identity.country`.
    Country,
}

impl IdentityField {
    /// Every generated field, in the order [`GeneratedIdentity::fields`] lists them.
    pub const ALL: [Self; 13] = [
        Self::Sex,
        Self::Title,
        Self::FirstName,
        Self::LastName,
        Self::Birthday,
        Self::Username,
        Self::Email,
        Self::Phone,
        Self::Address1,
        Self::City,
        Self::State,
        Self::PostalCode,
        Self::Country,
    ];

    /// The field key.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::Sex => IDENTITY_SEX,
            Self::Title => IDENTITY_TITLE,
            Self::FirstName => IDENTITY_FIRST_NAME,
            Self::LastName => IDENTITY_LAST_NAME,
            Self::Birthday => IDENTITY_BIRTHDAY,
            Self::Username => IDENTITY_USERNAME,
            Self::Email => IDENTITY_EMAIL,
            Self::Phone => IDENTITY_PHONE,
            Self::Address1 => IDENTITY_ADDRESS1,
            Self::City => IDENTITY_CITY,
            Self::State => IDENTITY_STATE,
            Self::PostalCode => IDENTITY_POSTAL_CODE,
            Self::Country => IDENTITY_COUNTRY,
        }
    }

    /// The field with this key.
    ///
    /// # Errors
    /// [`IdentityGenError::UnknownField`] for any other key.
    pub fn from_key(key: &str) -> Result<Self, IdentityGenError> {
        Self::ALL
            .into_iter()
            .find(|f| f.key() == key)
            .ok_or(IdentityGenError::UnknownField)
    }
}

// --- output -----------------------------------------------------------------------------------

/// A generated identity: the values, plus what [`regenerate_field`] needs to redraw one field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneratedIdentity {
    /// `identity.country`.
    country: CountryCode,
    /// `identity.sex`.
    sex: Sex,
    /// `identity.title`, if titles are on.
    title: Option<String>,
    /// `identity.first_name`: display and ascii forms.
    first: (String, String),
    /// `identity.last_name`: display and ascii forms.
    last: (String, String),
    /// The birthday.
    birthday: CivilDate,
    /// `identity.birthday`, `YYYY-MM-DD`.
    birthday_text: String,
    /// `identity.username`, the nickname of §4 step 9.
    nickname: String,
    /// `identity.email`, only with a domain.
    email: Option<String>,
    /// `identity.phone`, only from fictional ranges.
    phone: Option<String>,
    /// `identity.address1`.
    address1: String,
    /// `identity.city`.
    city: String,
    /// The city's index in the country's list (for its paired subdivision).
    city_index: usize,
    /// The subdivision's index in the country's list (for its postcode patterns).
    subdivision: usize,
    /// `identity.state`, the subdivision's written form.
    state: String,
    /// `identity.postal_code`.
    postal_code: String,
}

impl GeneratedIdentity {
    /// The `(field key, value)` pairs, in [`IdentityField::ALL`] order; a field left empty
    /// (no title, email or phone) is absent.
    #[must_use]
    pub fn fields(&self) -> Vec<(&'static str, String)> {
        IdentityField::ALL
            .into_iter()
            .filter_map(|f| self.get(f).map(|v| (f.key(), v.to_owned())))
            .collect()
    }

    /// One field's value, if it is filled.
    #[must_use]
    pub fn get(&self, field: IdentityField) -> Option<&str> {
        match field {
            IdentityField::Sex => Some(self.sex.as_str()),
            IdentityField::Title => self.title.as_deref(),
            IdentityField::FirstName => Some(&self.first.0),
            IdentityField::LastName => Some(&self.last.0),
            IdentityField::Birthday => Some(&self.birthday_text),
            IdentityField::Username => Some(&self.nickname),
            IdentityField::Email => self.email.as_deref(),
            IdentityField::Phone => self.phone.as_deref(),
            IdentityField::Address1 => Some(&self.address1),
            IdentityField::City => Some(&self.city),
            IdentityField::State => Some(&self.state),
            IdentityField::PostalCode => Some(&self.postal_code),
            IdentityField::Country => Some(self.country.as_str()),
        }
    }

    /// The sex.
    #[must_use]
    pub const fn sex(&self) -> Sex {
        self.sex
    }

    /// The birthday.
    #[must_use]
    pub const fn birthday(&self) -> CivilDate {
        self.birthday
    }

    /// The country.
    #[must_use]
    pub const fn country(&self) -> CountryCode {
        self.country
    }

    /// The default item name, "First Last" (ADR 0079 §3: the editor's default, not a field).
    #[must_use]
    pub fn item_name(&self) -> String {
        format!("{} {}", self.first.0, self.last.0)
    }
}

// --- generation -------------------------------------------------------------------------------

/// The draw steps of ADR 0079 §4, as bits, run in this order. Step 6 is split into the city
/// draw and the subdivision draw so that one of them can be redrawn alone.
type Steps = u16;
/// Step 1, sex.
const S_SEX: Steps = 1 << 1;
/// Step 2, first name.
const S_FIRST: Steps = 1 << 2;
/// Step 3, last name.
const S_LAST: Steps = 1 << 3;
/// Step 4, birthday.
const S_BIRTHDAY: Steps = 1 << 4;
/// Step 5, street and number.
const S_STREET: Steps = 1 << 5;
/// Step 6, the city draw.
const S_CITY: Steps = 1 << 6;
/// Step 6, the subdivision draw (or the city's paired one).
const S_SUBDIVISION: Steps = 1 << 7;
/// Step 7, postcode.
const S_POSTCODE: Steps = 1 << 8;
/// Step 8, phone.
const S_PHONE: Steps = 1 << 9;
/// Step 9, nickname.
const S_NICKNAME: Steps = 1 << 10;
/// Step 10, email local part and address.
const S_EMAIL: Steps = 1 << 11;
/// The title has no draw: it follows the sex.
const S_TITLE: Steps = 1 << 12;
/// Every step: a new identity.
const ALL_STEPS: Steps = S_SEX
    | S_FIRST
    | S_LAST
    | S_BIRTHDAY
    | S_STREET
    | S_CITY
    | S_SUBDIVISION
    | S_POSTCODE
    | S_PHONE
    | S_NICKNAME
    | S_EMAIL
    | S_TITLE;
/// Changing the country redraws every step except the birthday and the nickname (§4).
const COUNTRY_STEPS: Steps = ALL_STEPS & !(S_BIRTHDAY | S_NICKNAME);

/// The email local part's separators (§4 step 10), indexed by `uniform(3)`.
const SEPARATORS: [&str; 3] = [".", "_", ""];

/// Draws a new identity (ADR 0079 §3, §4).
///
/// # Errors
/// [`IdentityGenError::UnsupportedCountry`] if `options.country` is not in `data`,
/// [`IdentityGenError::Date`] if `today` is too early for the age range,
/// [`IdentityGenError::Rng`] if the RNG fails.
pub fn generate_identity<R: CryptoRng + ?Sized>(
    rng: &mut R,
    data: &IdentityData<'_>,
    options: &IdentityOptions,
    today: CivilDate,
) -> Result<GeneratedIdentity, IdentityGenError> {
    let country = data
        .country(options.country.as_str())
        .ok_or(IdentityGenError::UnsupportedCountry)?;
    birthday_bounds(options.age, today)?;
    let mut id = GeneratedIdentity {
        country: options.country,
        sex: Sex::Male,
        title: None,
        first: (String::new(), String::new()),
        last: (String::new(), String::new()),
        birthday: today,
        birthday_text: String::new(),
        nickname: String::new(),
        email: None,
        phone: None,
        address1: String::new(),
        city: String::new(),
        city_index: 0,
        subdivision: 0,
        state: String::new(),
        postal_code: String::new(),
    };
    run(rng, country, options, today, ALL_STEPS, &mut id)?;
    Ok(id)
}

/// Redraws `field` and the fields that depend on it (ADR 0079 §4, "Regenerating one field"),
/// keeping every other value of `current`. A picker change is a call with the new option:
/// the sex picker redraws [`IdentityField::Sex`], the country picker [`IdentityField::Country`],
/// the age picker [`IdentityField::Birthday`], the email style or domain [`IdentityField::Email`].
///
/// The dependents: first name, last name or birthday → the email; sex → the first name, a
/// sex-split last name, the title, and so the email; country → every field except the
/// birthday and the username. In the nickname email style the username and the email share
/// step 9, so redrawing either redraws both. A city paired with a subdivision carries it, and
/// a new subdivision redraws the postcode where the data has per-subdivision patterns. If
/// `options.country` is not `current`'s country, the country's steps are redrawn as well.
/// The result holds every field; the caller writes only those the user has not edited, plus
/// `field` itself (ADR 0079 §10).
///
/// # Errors
/// As [`generate_identity`].
pub fn regenerate_field<R: CryptoRng + ?Sized>(
    rng: &mut R,
    data: &IdentityData<'_>,
    options: &IdentityOptions,
    today: CivilDate,
    field: IdentityField,
    current: &GeneratedIdentity,
) -> Result<GeneratedIdentity, IdentityGenError> {
    let country = data
        .country(options.country.as_str())
        .ok_or(IdentityGenError::UnsupportedCountry)?;
    birthday_bounds(options.age, today)?;
    let split = matches!(country.last, Surnames::Split { .. });
    let nickname_email = options.email_style == EmailStyle::Nickname;
    let same_country = options.country == current.country;
    let paired = same_country
        && country
            .cities
            .get(current.city_index)
            .is_some_and(|c| c.subdivision.is_some());
    let mut steps = match field {
        IdentityField::Sex => S_SEX | S_FIRST | S_TITLE | S_EMAIL | if split { S_LAST } else { 0 },
        IdentityField::Title => S_TITLE,
        IdentityField::FirstName => S_FIRST | S_EMAIL,
        IdentityField::LastName => S_LAST | S_EMAIL,
        IdentityField::Birthday => S_BIRTHDAY | S_EMAIL,
        IdentityField::Username | IdentityField::Email if nickname_email => S_NICKNAME | S_EMAIL,
        IdentityField::Username => S_NICKNAME,
        IdentityField::Email => S_EMAIL,
        IdentityField::Phone => S_PHONE,
        IdentityField::Address1 => S_STREET,
        IdentityField::City => S_CITY,
        IdentityField::State if paired => S_CITY | S_SUBDIVISION,
        IdentityField::State => S_SUBDIVISION,
        IdentityField::PostalCode => S_POSTCODE,
        IdentityField::Country => COUNTRY_STEPS,
    };
    if !same_country {
        steps |= COUNTRY_STEPS;
    }
    let mut id = current.clone();
    id.country = options.country;
    run(rng, country, options, today, steps, &mut id)?;
    Ok(id)
}

/// The day numbers `lo..=hi` of every birthday whose completed age today is in the range
/// (§4 step 4): `hi` is today minus `min` years, `lo` is today minus `max + 1` years plus a
/// day, and 29 February minus years is 28 February in a common year.
fn birthday_bounds(age: AgeRange, today: CivilDate) -> Result<(i64, i64), IdentityGenError> {
    let hi = today
        .minus_years(u16::from(age.min()))
        .ok_or(IdentityGenError::Date)?;
    let before = today
        .minus_years(u16::from(age.max()) + 1)
        .ok_or(IdentityGenError::Date)?;
    Ok((before.days() + 1, hi.days()))
}

/// `uniform(n)` as a `usize`.
fn draw<R: CryptoRng + ?Sized>(rng: &mut R, n: usize) -> Result<usize, IdentityGenError> {
    let n = u32::try_from(n).map_err(|_| IdentityGenError::Rng)?;
    let i = uniform(rng, n).map_err(|_| IdentityGenError::Rng)?;
    usize::try_from(i).map_err(|_| IdentityGenError::Rng)
}

/// A uniform element of a non-empty list.
fn pick<'l, T, R: CryptoRng + ?Sized>(
    rng: &mut R,
    list: &'l [T],
) -> Result<&'l T, IdentityGenError> {
    let i = draw(rng, list.len())?;
    list.get(i).ok_or(IdentityGenError::Rng)
}

/// A pattern with each `#` replaced by `uniform(10)` and each `?` by `uniform(26)` over A–Z
/// (§4 steps 7 and 8), left to right.
fn fill<R: CryptoRng + ?Sized>(rng: &mut R, pattern: &str) -> Result<String, IdentityGenError> {
    let mut out = String::with_capacity(pattern.len());
    for c in pattern.chars() {
        match c {
            '#' => out.push(nth_char(b"0123456789", draw(rng, 10)?)?),
            '?' => out.push(nth_char(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ", draw(rng, 26)?)?),
            other => out.push(other),
        }
    }
    Ok(out)
}

/// `alphabet[i]` as a `char`.
fn nth_char(alphabet: &[u8], i: usize) -> Result<char, IdentityGenError> {
    alphabet
        .get(i)
        .map(|&b| char::from(b))
        .ok_or(IdentityGenError::Rng)
}

/// Copies a drawn name into its slot.
fn set_name(slot: &mut (String, String), name: &Name<'_>) {
    slot.0.clear();
    slot.0.push_str(name.display);
    slot.1.clear();
    slot.1.push_str(name.ascii);
}

/// Sets the subdivision and `identity.state`.
fn set_subdivision(id: &mut GeneratedIdentity, country: &Country<'_>, index: usize) {
    id.subdivision = index;
    id.state = country
        .subdivisions
        .get(index)
        .map(|s| s.written.to_owned())
        .unwrap_or_default();
}

/// `ascii(first) sep ascii(last) suffix`, cut from the last-name end to 64 octets (§4 step 10).
fn name_local_part(first: &str, last: &str, sep: &str, suffix: &str) -> String {
    let room = MAX_LOCAL_PART_LEN.saturating_sub(first.len() + sep.len() + suffix.len());
    // The ascii forms are ASCII, so every byte index is a character boundary.
    let last = last.get(..room.min(last.len())).unwrap_or_default();
    let first = first
        .get(..MAX_LOCAL_PART_LEN.min(first.len()))
        .unwrap_or_default();
    format!("{first}{sep}{last}{suffix}")
}

/// Runs the selected steps of §4 in order on `id`.
fn run<R: CryptoRng + ?Sized>(
    rng: &mut R,
    country: &Country<'_>,
    options: &IdentityOptions,
    today: CivilDate,
    steps: Steps,
    id: &mut GeneratedIdentity,
) -> Result<(), IdentityGenError> {
    let on = |s: Steps| steps & s != 0;
    // 1. Sex.
    if on(S_SEX) {
        id.sex = match options.sex {
            SexChoice::Male => Sex::Male,
            SexChoice::Female => Sex::Female,
            SexChoice::Random => draw_sex(rng)?,
        };
    }
    // 2. First name.
    if on(S_FIRST) {
        let list = match id.sex {
            Sex::Male => &country.first_male,
            Sex::Female => &country.first_female,
        };
        set_name(&mut id.first, pick(rng, list)?);
    }
    // 3. Last name, by sex where the country's surnames are split.
    if on(S_LAST) {
        let list = match (&country.last, id.sex) {
            (Surnames::Shared(all), _) => all,
            (Surnames::Split { male, .. }, Sex::Male) => male,
            (Surnames::Split { female, .. }, Sex::Female) => female,
        };
        set_name(&mut id.last, pick(rng, list)?);
    }
    // 4. Birthday: uniform over every date whose completed age today is in [min, max].
    if on(S_BIRTHDAY) {
        let (lo, hi) = birthday_bounds(options.age, today)?;
        let span = usize::try_from(hi - lo + 1).map_err(|_| IdentityGenError::Date)?;
        let offset = i64::try_from(draw(rng, span)?).map_err(|_| IdentityGenError::Date)?;
        id.birthday = CivilDate::from_days(lo + offset).ok_or(IdentityGenError::Date)?;
        id.birthday_text = id.birthday.to_string();
    }
    // 5. Street and house number, formatted by the country's pattern.
    if on(S_STREET) {
        let street = pick(rng, &country.streets)?;
        let (lo, hi) = country.number;
        let span = usize::from(hi - lo) + 1;
        let number = usize::from(lo) + draw(rng, span)?;
        id.address1 = country
            .address
            .replace("{street}", street)
            .replace("{number}", &number.to_string());
    }
    // 6. City, then its paired subdivision or a separate subdivision draw.
    let old_subdivision = id.subdivision;
    if on(S_CITY) {
        let i = draw(rng, country.cities.len())?;
        let city = country.cities.get(i).ok_or(IdentityGenError::Rng)?;
        id.city_index = i;
        id.city.clear();
        id.city.push_str(city.name);
        if let Some(s) = city.subdivision {
            set_subdivision(id, country, s);
        }
    }
    if on(S_SUBDIVISION) {
        let paired = country
            .cities
            .get(id.city_index)
            .and_then(|c| c.subdivision);
        let s = match paired {
            Some(s) => s,
            None => draw(rng, country.subdivisions.len())?,
        };
        set_subdivision(id, country, s);
    }
    // 7. Postcode: the subdivision's patterns if the data has them, else the country's. A new
    // subdivision redraws it where per-subdivision patterns exist.
    let per_subdivision = country.subdivisions.iter().any(|s| !s.postcodes.is_empty());
    if on(S_POSTCODE) || (per_subdivision && id.subdivision != old_subdivision) {
        let pattern = pick(rng, country.postcode_patterns(id.subdivision))?;
        id.postal_code = fill(rng, pattern)?;
    }
    // 8. Phone, only from fictional ranges (§7).
    if on(S_PHONE) {
        id.phone = if options.phone && country.has_phone() {
            let pattern = pick(rng, &country.phones)?;
            Some(fill(rng, pattern)?)
        } else {
            None
        };
    }
    // 9. Nickname: two EFF words and two digits.
    if on(S_NICKNAME) {
        id.nickname = draw_nickname(rng)?;
    }
    // 10. Email: the local part, and the address only if a domain is known (§8). The name
    // style draws its separator and suffix even without a domain, so the stream does not
    // depend on whether one is set.
    if on(S_EMAIL) {
        id.email = draw_email(rng, options, id)?;
    }
    // The title follows the sex (Open question 4).
    if on(S_TITLE) {
        id.title = options.title.then(|| {
            match id.sex {
                Sex::Male => country.title_male,
                Sex::Female => country.title_female,
            }
            .to_owned()
        });
    }
    Ok(())
}

/// §4 step 1 for a random sex: `uniform(2)`, 0 is male and 1 is female.
fn draw_sex<R: CryptoRng + ?Sized>(rng: &mut R) -> Result<Sex, IdentityGenError> {
    Ok(if draw(rng, 2)? == 0 {
        Sex::Male
    } else {
        Sex::Female
    })
}

/// §4 step 9: two EFF words, each `uniform(7776)`, joined, then `uniform(100)` as two digits.
fn draw_nickname<R: CryptoRng + ?Sized>(rng: &mut R) -> Result<String, IdentityGenError> {
    let mut word = || -> Result<&'static str, IdentityGenError> {
        let i =
            u32::try_from(draw(rng, wordlist::WORD_COUNT)?).map_err(|_| IdentityGenError::Rng)?;
        wordlist::word(i).ok_or(IdentityGenError::Rng)
    };
    let (first, second) = (word()?, word()?);
    let digits = draw(rng, 100)?;
    Ok(format!("{first}{second}{digits:02}"))
}

/// §4 step 10: the local part, and the address only if a domain is known (§8). The name style
/// draws its separator and suffix even without a domain, so the stream does not depend on
/// whether one is set.
fn draw_email<R: CryptoRng + ?Sized>(
    rng: &mut R,
    options: &IdentityOptions,
    id: &GeneratedIdentity,
) -> Result<Option<String>, IdentityGenError> {
    let local = match options.email_style {
        EmailStyle::NameAndBirthday => {
            let sep = SEPARATORS.get(draw(rng, 3)?).copied().unwrap_or_default();
            let b = id.birthday;
            let suffix = match draw(rng, 3)? {
                0 => format!("{:04}", b.year()),
                1 => format!("{:02}", b.year().rem_euclid(100)),
                _ => format!("{:02}{:02}", b.day(), b.month()),
            };
            name_local_part(&id.first.1, &id.last.1, sep, &suffix)
        }
        EmailStyle::Nickname => id.nickname.clone(),
    };
    Ok(options
        .email_domain
        .as_ref()
        .map(|d| format!("{local}@{}", d.as_str())))
}
