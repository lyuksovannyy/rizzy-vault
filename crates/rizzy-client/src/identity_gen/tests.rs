// SPDX-License-Identifier: AGPL-3.0-only

//! ADR 0079 §12: the generator's property tests, uniformity smoke test, preset pins and parser
//! tests on a synthetic fixture; the known-answer vectors and data tests on the embedded file.

use std::collections::BTreeSet;

use chacha20::ChaCha20Rng;
use proptest::prelude::*;
use rand_core::SeedableRng as _;

use super::data::{self, IdentityDataError, MAX_DATA_LEN};
use super::*;

// --- a synthetic fixture in the data format ---------------------------------------------------

/// `count` distinct letter-only words `<stem><two letters>`, sorted.
fn words(stem: &str, count: usize) -> Vec<String> {
    let mut out: Vec<String> = (0..count)
        .map(|i| {
            let a = char::from(b'a' + u8::try_from(i / 26).unwrap());
            let b = char::from(b'a' + u8::try_from(i % 26).unwrap());
            format!("{stem}{a}{b}")
        })
        .collect();
    out.sort();
    out
}

fn names(stem: &str, count: usize) -> String {
    let mut out = String::new();
    for w in words(stem, count) {
        out.push_str(&w);
        out.push('|');
        out.push_str(&w.to_ascii_lowercase());
        out.push('\n');
    }
    out
}

fn list(stem: &str, count: usize) -> String {
    words(stem, count).into_iter().map(|w| w + "\n").collect()
}

/// Three countries: DE (name-first address, shared surnames, no phone), SE (split surnames),
/// US (number-first, per-subdivision postcodes, a phone range, a long surname).
pub(super) fn fixture() -> String {
    let mut s = String::from(data::HEADER);
    s.push('\n');
    s.push_str("@country DE\n@name Germany\n@title.male Herr\n@title.female Frau\n");
    s.push_str("@address {street} {number}\n@number 1 199\n@postcode #####\n");
    s.push_str("[first.female]\n");
    s.push_str(&names("Anna", 60));
    s.push_str("[first.male]\n");
    let mut male = names("Jan", 59);
    male.push_str("Jürgen|juergen\n");
    s.push_str(&male);
    s.push_str("[last]\n");
    s.push_str(&names("Muell", 60));
    s.push_str("[street]\n");
    s.push_str(&list("Hauptstrasse", 50));
    s.push_str("[city]\n");
    s.push_str(&list("Berlin", 50));
    s.push_str("[subdivision]\nDE-BE|Berlin\nDE-BY|Bayern\n");
    s.push_str("@country SE\n@name Sweden\n@title.male Herr\n@title.female Fru\n");
    s.push_str("@address {street} {number}\n@number 1 99\n@postcode ### ##\n");
    s.push_str("[first.female]\n");
    s.push_str(&names("Karin", 50));
    s.push_str("[first.male]\n");
    s.push_str(&names("Lars", 50));
    s.push_str("[last.female]\n");
    s.push_str(&names("Skaa", 50));
    s.push_str("[last.male]\n");
    s.push_str(&names("Skib", 50));
    s.push_str("[street]\n");
    s.push_str(&list("Storgatan", 50));
    s.push_str("[city]\n");
    s.push_str(&list("Uppsala", 50));
    s.push_str("[subdivision]\nSE-AB|Stockholms laen\n");
    s.push_str("@country US\n@name United States\n@title.male Mr\n@title.female Ms\n");
    s.push_str("@address {number} {street}\n@number 100 9999\n@postcode #####\n");
    s.push_str("@phone +1 202 555 01##\n");
    s.push_str("[first.female]\n");
    s.push_str(&names("Abigailmaryelizabethjo", 50));
    s.push_str("[first.male]\n");
    s.push_str(&names("Bob", 50));
    s.push_str("[last]\n");
    s.push_str(&names("Wolfeschlegelsteinhausenber", 50));
    s.push_str("[street]\n");
    s.push_str(&list("Main Street", 50));
    s.push_str("[city]\n");
    let mut cities: Vec<String> = words("Springfield", 49)
        .into_iter()
        .map(|w| w + "|US-CA")
        .collect();
    cities.push("Zanesville".to_owned());
    cities.sort();
    for c in cities {
        s.push_str(&c);
        s.push('\n');
    }
    s.push_str("[subdivision]\nUS-CA|CA\nUS-NY|NY\n");
    s.push_str("[postcode]\nUS-CA|900##\nUS-CA|961##\nUS-NY|100##\n");
    s
}

fn fixture_data(text: &str) -> IdentityData<'_> {
    data::parse(text.as_bytes()).unwrap()
}

fn date(y: i32, m: u8, d: u8) -> CivilDate {
    CivilDate::new(y, m, d).unwrap()
}

fn options(country: &str) -> IdentityOptions {
    IdentityOptions::new(CountryCode::parse(country).unwrap())
}

/// Whether `value` is `pattern` filled: `#` a digit, `?` an upper-case letter, else literal.
pub(super) fn matches_pattern(value: &str, pattern: &str) -> bool {
    value.len() == pattern.len()
        && value.bytes().zip(pattern.bytes()).all(|(v, p)| match p {
            b'#' => v.is_ascii_digit(),
            b'?' => v.is_ascii_uppercase(),
            _ => v == p,
        })
}

/// RFC 5321 local part as §4 step 10 constrains it.
pub(super) fn local_part_ok(local: &str) -> bool {
    !local.is_empty()
        && local.len() <= MAX_LOCAL_PART_LEN
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

const GENERATED_KEYS: [&str; 13] = [
    "identity.sex",
    "identity.title",
    "identity.first_name",
    "identity.last_name",
    "identity.birthday",
    "identity.username",
    "identity.email",
    "identity.phone",
    "identity.address1",
    "identity.city",
    "identity.state",
    "identity.postal_code",
    "identity.country",
];

/// The §12 invariants every generated identity keeps.
pub(super) fn check_identity(
    data: &IdentityData<'_>,
    o: &IdentityOptions,
    today: CivilDate,
    id: &GeneratedIdentity,
) {
    let country = data.country(o.country.as_str()).unwrap();
    let fields = id.fields();
    for (k, _) in &fields {
        assert!(GENERATED_KEYS.contains(k), "{k}");
    }
    for never in [
        "identity.ssn",
        "identity.passport_number",
        "identity.drivers_license",
    ] {
        assert!(fields.iter().all(|(k, _)| *k != never));
    }
    let age = id.birthday().age_on(today).unwrap();
    assert!(
        (u32::from(o.age.min())..=u32::from(o.age.max())).contains(&age),
        "{age}"
    );
    let birthday = id.get(IdentityField::Birthday).unwrap();
    assert_eq!(CivilDate::parse(birthday), Some(id.birthday()));
    match (&o.email_domain, id.get(IdentityField::Email)) {
        (None, email) => assert_eq!(email, None),
        (Some(d), Some(email)) => {
            let (local, domain) = email.rsplit_once('@').unwrap();
            assert_eq!(domain, d.as_str());
            assert!(local_part_ok(local), "{local}");
            if o.email_style == EmailStyle::Nickname {
                assert_eq!(Some(local), id.get(IdentityField::Username));
            }
        }
        (Some(_), None) => panic!("no email with a domain"),
    }
    let postcode = id.get(IdentityField::PostalCode).unwrap();
    assert!(
        country
            .all_postcode_patterns()
            .any(|p| matches_pattern(postcode, p)),
        "{postcode}"
    );
    let state = id.get(IdentityField::State).unwrap();
    assert!(country.subdivision_names().any(|s| s == state), "{state}");
    assert_eq!(id.get(IdentityField::Country), Some(country.code()));
    assert_eq!(
        id.get(IdentityField::Sex).and_then(Sex::parse),
        Some(id.sex())
    );
    match o.sex {
        SexChoice::Male => assert_eq!(id.sex(), Sex::Male),
        SexChoice::Female => assert_eq!(id.sex(), Sex::Female),
        SexChoice::Random => {}
    }
    assert_eq!(id.get(IdentityField::Title).is_some(), o.title);
    assert_eq!(
        id.get(IdentityField::Phone).is_some(),
        o.phone && country.has_phone()
    );
    let username = id.get(IdentityField::Username).unwrap();
    assert!(local_part_ok(username), "{username}");
    for (k, v) in &fields {
        assert!(!v.is_empty(), "{k}");
    }
}

// --- presets, options, dates ------------------------------------------------------------------

/// ADR 0079 §12 "Preset list test": the twelve ids, bounds and order of §3.
#[test]
fn age_presets_are_adr_0079s_list() {
    let got: Vec<(&str, u8, u8)> = age_presets().iter().map(|p| (p.id, p.min, p.max)).collect();
    assert_eq!(
        got,
        [
            ("18-27", 18, 27),
            ("28-65", 28, 65),
            ("21-25", 21, 25),
            ("26-30", 26, 30),
            ("31-35", 31, 35),
            ("36-40", 36, 40),
            ("41-45", 41, 45),
            ("46-50", 46, 50),
            ("51-55", 51, 55),
            ("56-60", 56, 60),
            ("61-65", 61, 65),
            ("any", 21, 65),
        ]
    );
    for p in age_presets() {
        assert_eq!(AgeRange::new(p.min, p.max), Ok(p.range()), "{}", p.id);
        assert_eq!(AgeRange::parse(p.id), Ok(p.range()), "{}", p.id);
    }
    assert_eq!(AgeRange::default(), AgeRange::new(18, 27).unwrap());
}

/// ADR 0079 §3 and §10: the three age modes and their bounds.
#[test]
fn age_ranges_parse_and_validate() {
    assert_eq!(AgeRange::parse("28"), AgeRange::exact(28));
    assert_eq!(AgeRange::parse("18-27"), AgeRange::new(18, 27));
    assert_eq!(AgeRange::parse("30-44"), AgeRange::new(30, 44));
    assert_eq!(AgeRange::parse("any"), AgeRange::new(21, 65));
    assert_eq!(
        AgeRange::parse("28-65").unwrap().preset().unwrap().id,
        "28-65"
    );
    assert_eq!(AgeRange::new(30, 44).unwrap().preset(), None);
    for bad in [
        "",
        "17",
        "100",
        "27-18",
        "17-20",
        "18-100",
        "-",
        "18-",
        "-27",
        "+20",
        " 20",
        "20 ",
        "2a",
        "18--27",
        "0x20",
        "any ",
        "ANY",
        "99999999999999999",
    ] {
        assert_eq!(
            AgeRange::parse(bad),
            Err(IdentityGenError::AgeRange),
            "{bad:?}"
        );
    }
    assert_eq!(
        AgeRange::new(18, 99).map(|r| (r.min(), r.max())),
        Ok((18, 99))
    );
    assert_eq!(AgeRange::new(17, 20), Err(IdentityGenError::AgeRange));
    assert_eq!(AgeRange::exact(99).map(AgeRange::max), Ok(99));
    assert_eq!(AgeRange::exact(100), Err(IdentityGenError::AgeRange));
}

/// ADR 0079 §3: LDH A-label syntax, lower-cased; U-labels refused with their own error.
#[test]
fn email_domains_validate() {
    assert_eq!(
        EmailDomain::parse("Example.COM").unwrap().as_str(),
        "example.com"
    );
    assert!(EmailDomain::parse("xn--bcher-kva.example").is_ok());
    assert!(EmailDomain::parse("a.b").is_ok());
    let long_label = "a".repeat(63);
    assert!(EmailDomain::parse(&format!("{long_label}.com")).is_ok());
    assert_eq!(
        EmailDomain::parse(&format!("a{long_label}.com")),
        Err(IdentityGenError::EmailDomain)
    );
    let max = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert_eq!(max.len(), 253);
    assert!(EmailDomain::parse(&max).is_ok());
    assert_eq!(
        EmailDomain::parse(&format!("{max}e")),
        Err(IdentityGenError::EmailDomain)
    );
    for bad in [
        "", "com", ".com", "a..com", "a.com.", "-a.com", "a-.com", "a_b.com", "a b.com", "a@b.com",
    ] {
        assert_eq!(
            EmailDomain::parse(bad),
            Err(IdentityGenError::EmailDomain),
            "{bad:?}"
        );
    }
    assert_eq!(
        EmailDomain::parse("bücher.example"),
        Err(IdentityGenError::EmailDomainNotAscii)
    );
}

#[test]
fn country_codes_and_fields_parse() {
    assert_eq!(CountryCode::parse("de").unwrap().as_str(), "DE");
    for bad in ["", "D", "DEU", "D1", "ÄÖ"] {
        assert_eq!(
            CountryCode::parse(bad),
            Err(IdentityGenError::UnsupportedCountry)
        );
    }
    for f in IdentityField::ALL {
        assert_eq!(IdentityField::from_key(f.key()), Ok(f));
    }
    assert_eq!(
        IdentityField::from_key("identity.ssn"),
        Err(IdentityGenError::UnknownField)
    );
}

/// The day arithmetic round-trips over the supported years and agrees with `age_on`.
#[test]
fn civil_dates_round_trip() {
    let first = date(MIN_YEAR, 1, 1).days();
    let last = date(MAX_YEAR, 12, 31).days();
    let mut prev: Option<CivilDate> = None;
    for d in first..=last {
        let c = CivilDate::from_days(d).unwrap();
        assert_eq!(c.days(), d);
        if let Some(p) = prev {
            assert!(p < c);
        }
        prev = Some(c);
    }
    assert_eq!(date(1970, 1, 1).days(), 0);
    assert_eq!(CivilDate::from_days(first - 1), None);
    assert_eq!(CivilDate::from_days(last + 1), None);
    assert_eq!(CivilDate::parse("2024-02-29"), Some(date(2024, 2, 29)));
    for bad in [
        "2023-02-29",
        "2024-13-01",
        "2024-00-10",
        "24-02-29",
        "2024/02/29",
        "2024-2-29",
        "0999-01-01",
    ] {
        assert_eq!(CivilDate::parse(bad), None, "{bad}");
    }
    assert_eq!(date(2024, 2, 29).minus_years(1), Some(date(2023, 2, 28)));
    assert_eq!(date(2024, 2, 29).minus_years(4), Some(date(2020, 2, 29)));
    assert_eq!(date(2000, 2, 29).age_on(date(2027, 2, 28)), Some(26));
    assert_eq!(date(2000, 2, 29).age_on(date(2027, 3, 1)), Some(27));
    assert_eq!(date(2000, 2, 29).age_on(date(2028, 2, 29)), Some(28));
    assert_eq!(date(2008, 10, 23).to_string(), "2008-10-23");
}

/// ADR 0079 §4 step 4 and §12: an exact age spans exactly 365 or 366 dates, all of that age.
#[test]
fn an_exact_age_spans_one_year_of_dates() {
    for today in [
        date(2026, 10, 23),
        date(2028, 2, 29),
        date(2027, 2, 28),
        date(2027, 3, 1),
        date(2024, 1, 1),
    ] {
        for n in [18u8, 28, 99] {
            let (lo, hi) = birthday_bounds(AgeRange::exact(n).unwrap(), today).unwrap();
            let span = hi - lo + 1;
            assert!(span == 365 || span == 366, "{today} {n}: {span}");
            for d in [lo, hi] {
                let b = CivilDate::from_days(d).unwrap();
                assert_eq!(b.age_on(today), Some(u32::from(n)), "{today} {b}");
            }
            for d in [lo - 1, hi + 1] {
                let b = CivilDate::from_days(d).unwrap();
                assert_ne!(b.age_on(today), Some(u32::from(n)), "{today} {b}");
            }
        }
    }
}

#[test]
fn a_too_early_today_is_refused() {
    let text = fixture();
    let data = fixture_data(&text);
    let mut o = options("DE");
    o.age = AgeRange::new(18, 99).unwrap();
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    assert_eq!(
        generate_identity(&mut rng, &data, &o, date(1050, 1, 1)),
        Err(IdentityGenError::Date)
    );
    o.country = CountryCode::parse("FR").unwrap();
    assert_eq!(
        generate_identity(&mut rng, &data, &o, date(2026, 10, 23)),
        Err(IdentityGenError::UnsupportedCountry)
    );
}

#[test]
fn a_long_local_part_is_cut_from_the_last_name_end() {
    let first = "a".repeat(32);
    let last = "b".repeat(32);
    let local = name_local_part(&first, &last, ".", "1998");
    assert_eq!(local.len(), 64);
    assert!(local.starts_with(&format!("{first}.")));
    assert!(local.ends_with("b1998"));
    assert_eq!(
        name_local_part("anna", "mueller", "", "98"),
        "annamueller98"
    );
}

/// No domain: the email stays empty and the username is still filled (ADR 0079 §8).
#[test]
fn without_a_domain_the_email_stays_empty() {
    let text = fixture();
    let data = fixture_data(&text);
    let o = options("US");
    let id = generate_identity(
        &mut ChaCha20Rng::seed_from_u64(5),
        &data,
        &o,
        date(2026, 10, 23),
    )
    .unwrap();
    assert_eq!(id.get(IdentityField::Email), None);
    assert!(id.get(IdentityField::Username).is_some());
    assert!(id.fields().iter().all(|(k, _)| *k != "identity.email"));
}

// --- the parser -------------------------------------------------------------------------------

#[test]
fn the_fixture_parses() {
    let text = fixture();
    let data = fixture_data(&text);
    let codes: Vec<&str> = data.countries().iter().map(Country::code).collect();
    assert_eq!(codes, ["DE", "SE", "US"]);
    assert_eq!(data.country("US").unwrap().name(), "United States");
    assert!(data.country("US").unwrap().has_phone());
    assert!(!data.country("DE").unwrap().has_phone());
}

/// Mutations of a valid file are refused with an error, never a panic.
#[test]
fn malformed_data_is_refused() {
    let text = fixture();
    let replace = |from: &str, to: &str| text.replacen(from, to, 1);
    let cases: Vec<String> = vec![
        String::new(),
        text.trim_end().to_owned(),
        replace("# identity-data v1", "# identity-data v2"),
        replace("@name Germany", "@name Germany!"),
        replace("@name Germany\n", ""),
        replace("@country SE", "@country AA"),
        replace("@country SE", "@country DE"),
        replace("@country SE", "@country se"),
        replace("@number 1 199", "@number 0 199"),
        replace("@number 1 199", "@number 200 199"),
        replace("@number 1 199", "@number 1 99999"),
        replace("@address {street} {number}", "@address {street}"),
        replace(
            "@address {street} {number}",
            "@address {street} {number} {number}",
        ),
        replace("@postcode #####", "@postcode ##*##"),
        replace("@phone +1 202 555 01##", "@phone +1 202 555 0100"),
        replace("Annaab|annaab", "Annaab|Annaab"),
        replace("Annaab|annaab", "Annaab|-annaab"),
        replace("Annaab|annaab", "Annaab"),
        replace("Annaab|annaab", "Anna1b|annaab"),
        replace("Annaab|annaab", "Annaac|annaac"),
        replace("[first.male]", "[first.other]"),
        replace("[street]", "[city]"),
        replace("DE-BY|Bayern", "FR-BY|Bayern"),
        replace("DE-BY|Bayern", "DE-BYXX|Bayern"),
        replace("US-NY|100##", "US-TX|100##"),
        replace("US-CA|961##", "US-CA|900##"),
        replace("Zanesville", "Zanesville|US-TX"),
        replace("\n[subdivision]\nSE-AB|Stockholms laen\n", "\n"),
        format!("{text}\n"),
        format!("{text}stray\n"),
        text.replace('\n', "\r\n"),
        format!("{}\n", "x".repeat(MAX_DATA_LEN)),
    ];
    for (i, case) in cases.iter().enumerate() {
        assert!(data::parse(case.as_bytes()).is_err(), "case {i}");
    }
    // A short list: drop 26 names, leaving 34 in the female list.
    let short: String = text
        .lines()
        .filter(|l| !l.starts_with("Annaa"))
        .flat_map(|l| [l, "\n"])
        .collect();
    assert!(matches!(
        data::parse(short.as_bytes()),
        Err(IdentityDataError::Incomplete(_) | IdentityDataError::Line(_))
    ));
    assert_eq!(data::parse(&[0xff, 0xfe]), Err(IdentityDataError::NotUtf8));
    let header_only = format!("{}\n", data::HEADER);
    assert_eq!(
        data::parse(header_only.as_bytes()),
        Err(IdentityDataError::Empty)
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// The parser never panics on arbitrary bytes or on a corrupted valid file.
    #[test]
    fn the_parser_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..2048),
                               at in any::<prop::sample::Index>(),
                               byte in any::<u8>()) {
        let _ = data::parse(&bytes);
        let mut text = fixture().into_bytes();
        let i = at.index(text.len());
        text[i] = byte;
        let _ = data::parse(&text);
        text.truncate(i);
        let _ = data::parse(&text);
    }
}

// --- generator properties ---------------------------------------------------------------------

fn arb_options() -> impl Strategy<Value = IdentityOptions> {
    (
        prop::sample::select(vec!["DE", "SE", "US"]),
        prop::sample::select(vec![SexChoice::Male, SexChoice::Female, SexChoice::Random]),
        (18u8..=99, 0u8..=81),
        any::<bool>(),
        prop::option::of(prop::sample::select(vec![
            "example.com",
            "mail.example.org",
        ])),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(
            |(c, sex, (min, extra), nickname, domain, title, phone)| IdentityOptions {
                sex,
                country: CountryCode::parse(c).unwrap(),
                age: AgeRange::new(min, min.saturating_add(extra).min(MAX_AGE)).unwrap(),
                email_style: if nickname {
                    EmailStyle::Nickname
                } else {
                    EmailStyle::NameAndBirthday
                },
                email_domain: domain.map(|d| EmailDomain::parse(d).unwrap()),
                title,
                phone,
            },
        )
}

fn arb_today() -> impl Strategy<Value = CivilDate> {
    (date(1970, 1, 1).days()..=date(2199, 12, 31).days())
        .prop_map(|d| CivilDate::from_days(d).unwrap())
}

/// The fields a field's regeneration may change (ADR 0079 §4).
fn dependents(field: IdentityField, o: &IdentityOptions, split: bool) -> BTreeSet<&'static str> {
    use IdentityField as F;
    let mut keys: Vec<F> = match field {
        F::Sex => vec![F::Sex, F::FirstName, F::Title, F::Email],
        F::FirstName | F::LastName | F::Birthday => vec![field, F::Email],
        F::Username | F::Email if o.email_style == EmailStyle::Nickname => {
            vec![F::Username, F::Email]
        }
        F::City | F::State => vec![F::City, F::State, F::PostalCode],
        F::Country => IdentityField::ALL
            .into_iter()
            .filter(|f| !matches!(f, F::Birthday | F::Username))
            .collect(),
        other => vec![other],
    };
    if field == F::Sex && split {
        keys.push(F::LastName);
    }
    keys.into_iter().map(F::key).collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// ADR 0079 §12 properties, for any seed, option set and today from 1970 to 2199.
    #[test]
    fn generated_identities_keep_the_invariants(seed in any::<u64>(), o in arb_options(), today in arb_today()) {
        let text = fixture();
        let data = fixture_data(&text);
        let id = generate_identity(&mut ChaCha20Rng::seed_from_u64(seed), &data, &o, today).unwrap();
        check_identity(&data, &o, today, &id);
        // Determinism: the same seed gives the same output.
        let again = generate_identity(&mut ChaCha20Rng::seed_from_u64(seed), &data, &o, today).unwrap();
        prop_assert_eq!(&again, &id);
    }

    /// An exact age gives exactly that age.
    #[test]
    fn an_exact_age_is_kept(seed in any::<u64>(), n in 18u8..=99, today in arb_today()) {
        let text = fixture();
        let data = fixture_data(&text);
        let mut o = options("DE");
        o.age = AgeRange::exact(n).unwrap();
        let id = generate_identity(&mut ChaCha20Rng::seed_from_u64(seed), &data, &o, today).unwrap();
        prop_assert_eq!(id.birthday().age_on(today), Some(u32::from(n)));
    }

    /// Every preset keeps its age in its bounds.
    #[test]
    fn every_preset_keeps_its_bounds(seed in any::<u64>(), p in prop::sample::select(AGE_PRESETS.to_vec()), today in arb_today()) {
        let text = fixture();
        let data = fixture_data(&text);
        let mut o = options("US");
        o.age = p.range();
        let id = generate_identity(&mut ChaCha20Rng::seed_from_u64(seed), &data, &o, today).unwrap();
        let age = id.birthday().age_on(today).unwrap();
        prop_assert!((u32::from(p.min)..=u32::from(p.max)).contains(&age));
    }

    /// `regenerate_field` changes only that field and its dependents, and keeps the invariants.
    #[test]
    fn regeneration_changes_only_the_field_and_its_dependents(
        seed in any::<u64>(),
        o in arb_options(),
        today in arb_today(),
        field in prop::sample::select(IdentityField::ALL.to_vec()),
        new_country in prop::sample::select(vec!["DE", "SE", "US"]),
    ) {
        let text = fixture();
        let data = fixture_data(&text);
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let before = generate_identity(&mut rng, &data, &o, today).unwrap();
        let mut o2 = o.clone();
        if field == IdentityField::Country {
            o2.country = CountryCode::parse(new_country).unwrap();
        }
        let after = regenerate_field(&mut rng, &data, &o2, today, field, &before).unwrap();
        check_identity(&data, &o2, today, &after);
        let split = matches!(data.country(o2.country.as_str()).unwrap().last, data::Surnames::Split { .. });
        let allowed = dependents(field, &o2, split);
        for f in IdentityField::ALL {
            if before.get(f) != after.get(f) {
                prop_assert!(allowed.contains(f.key()), "{:?} changed {:?}", field, f);
            }
        }
    }
}

/// ADR 0079 §12 "Uniformity smoke test": χ² on the sex draw and on the birthday's day of the
/// year, 100k draws each, through the generator's own steps; deterministic and fast.
#[test]
fn sex_and_birthday_draws_are_uniform() {
    let text = fixture();
    let data = fixture_data(&text);
    let country = data.country("DE").unwrap();
    let mut o = options("DE");
    // 82 whole years of dates: every day of the year except 29 February appears 82 times.
    o.age = AgeRange::new(18, 99).unwrap();
    let today = date(2026, 10, 23);
    let mut rng = ChaCha20Rng::seed_from_u64(0x0079);
    let mut id = generate_identity(&mut rng, &data, &o, today).unwrap();
    let draws = 100_000;
    let mut sex = [0u64; 2];
    let mut days = vec![0u64; 366];
    for _ in 0..draws {
        run(&mut rng, country, &o, today, S_SEX | S_BIRTHDAY, &mut id).unwrap();
        sex[usize::from(id.sex() == Sex::Female)] += 1;
        let b = id.birthday();
        if (b.month(), b.day()) != (2, 29) {
            let doy =
                usize::try_from(date(2025, b.month(), b.day()).days() - date(2025, 1, 1).days())
                    .unwrap();
            days[doy] += 1;
        }
    }
    let chi = |counts: &[u64]| -> f64 {
        #[expect(
            clippy::cast_precision_loss,
            reason = "test statistics on small counts"
        )]
        let total = counts.iter().sum::<u64>() as f64;
        #[expect(
            clippy::cast_precision_loss,
            reason = "test statistics on small counts"
        )]
        let expected = total / counts.len() as f64;
        counts
            .iter()
            .map(|&c| {
                #[expect(
                    clippy::cast_precision_loss,
                    reason = "test statistics on small counts"
                )]
                let d = c as f64 - expected;
                d * d / expected
            })
            .sum()
    };
    // Critical values at p = 0.0001: 15.14 for 1 degree of freedom, about 470 for 364.
    assert!(chi(&sex) < 15.14, "sex chi-square {}", chi(&sex));
    let x2 = chi(&days[..365]);
    assert!(x2 < 470.0, "day-of-year chi-square {x2}");
}

// --- the synced defaults, ACCOUNT_SETTINGS tag 0x0004 (Open question 7) ----------------------

/// The layout of Open question 7, byte for byte, and its reject rule.
#[test]
fn identity_defaults_encode_to_the_open_question_7_layout() {
    use crate::settings::AccountSettingsRecord;

    let d = IdentityDefaults {
        sex: SexChoice::Female,
        country: Some(CountryCode::parse("de").unwrap()),
        age: AgeRange::exact(28).unwrap(),
        email_style: EmailStyle::Nickname,
        email_domain: Some(EmailDomain::parse("Mail.Example").unwrap()),
    };
    let bytes = d.encode().unwrap();
    let mut want = vec![2, b'D', b'E', 28, 28, 2, 0, 0, 0, 12];
    want.extend_from_slice(b"mail.example");
    assert_eq!(bytes, want);
    assert_eq!(IdentityDefaults::decode(&bytes), Some(d));
    let first = IdentityDefaults::default().encode().unwrap();
    assert_eq!(first, [0, 0, 0, 18, 27, 1, 0, 0, 0, 0]);
    assert_eq!(
        IdentityDefaults::decode(&first),
        Some(IdentityDefaults::default())
    );
    assert_eq!(TAG_IDENTITY_DEFAULTS, 0x0004);

    let bad: Vec<Vec<u8>> = vec![
        vec![],
        vec![3, 0, 0, 18, 27, 1, 0, 0, 0, 0],
        vec![0, b'd', b'e', 18, 27, 1, 0, 0, 0, 0],
        vec![0, b'D', 0, 18, 27, 1, 0, 0, 0, 0],
        vec![0, 0, 0, 17, 27, 1, 0, 0, 0, 0],
        vec![0, 0, 0, 30, 27, 1, 0, 0, 0, 0],
        vec![0, 0, 0, 18, 100, 1, 0, 0, 0, 0],
        vec![0, 0, 0, 18, 27, 0, 0, 0, 0, 0],
        vec![0, 0, 0, 18, 27, 3, 0, 0, 0, 0],
        vec![0, 0, 0, 18, 27, 1, 0, 0, 0],
        vec![0, 0, 0, 18, 27, 1, 0, 0, 0, 0, 0],
        [vec![0, 0, 0, 18, 27, 1, 0, 0, 0, 3], b"com".to_vec()].concat(),
        [vec![0, 0, 0, 18, 27, 1, 0, 0, 0, 5], b"A.com".to_vec()].concat(),
        [vec![0, 0, 0, 18, 27, 1, 0, 0, 0, 1], vec![0xff]].concat(),
    ];
    for (i, b) in bad.iter().enumerate() {
        assert_eq!(IdentityDefaults::decode(b), None, "case {i}");
    }

    // Inside a record: decoded as a recognised tag, re-encoded byte for byte, and a violation
    // inside it rejects the whole record (ADR 0042 §2).
    let mut record = vec![0, 1, 0, 1, 0x00, 0x04];
    record.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
    record.extend_from_slice(&bytes);
    let decoded = AccountSettingsRecord::decode(&record).unwrap();
    assert_eq!(
        decoded.identity_defaults(),
        IdentityDefaults::decode(&bytes).as_ref()
    );
    assert_eq!(decoded.unknown_tags().count(), 0);
    assert_eq!(decoded.encode().unwrap().as_slice(), record.as_slice());
    let mut broken = record.clone();
    let last = broken.len() - 1;
    broken[last] = b'-';
    assert_eq!(
        AccountSettingsRecord::decode(&broken),
        Err(crate::ClientError::InvalidServerResponse)
    );
}

// --- the embedded data (ADR 0079 §5, §12 "Data tests") ----------------------------------------

/// The v1 country set of Open question 6.
const V1_COUNTRIES: [&str; 13] = [
    "AT", "AU", "CA", "CH", "DE", "ES", "FR", "GB", "IE", "IT", "NL", "SE", "US",
];

/// The embedded file parses, is within the 384 KiB budget, holds exactly the v1 countries, and
/// keeps the content rules (the parser enforces the per-entry rules; checked again here).
#[test]
fn the_embedded_data_parses_within_its_budget() {
    assert_eq!((NAME, VERSION), ("identity-data", 1));
    let raw = embedded::RAW;
    assert!(raw.len() <= MAX_DATA_LEN, "{} bytes", raw.len());
    let data = embedded_data().unwrap();
    let codes: Vec<&str> = data.countries().iter().map(Country::code).collect();
    assert_eq!(codes, V1_COUNTRIES);
    for c in data.countries() {
        let lists: [(&str, usize); 4] = [
            ("first.female", c.first_female.len()),
            ("first.male", c.first_male.len()),
            ("street", c.streets.len()),
            ("city", c.cities.len()),
        ];
        for (name, len) in lists {
            assert!(len >= data::MIN_LIST, "{} {name}: {len}", c.code());
        }
        let names = c
            .first_female
            .iter()
            .chain(&c.first_male)
            .chain(match &c.last {
                data::Surnames::Shared(all) => all.iter().chain([].iter()),
                data::Surnames::Split { female, male } => female.iter().chain(male.iter()),
            });
        for n in names {
            assert!(
                data::display(n.display) && data::ascii(n.ascii),
                "{}",
                n.display
            );
        }
        for p in c.all_postcode_patterns() {
            assert!(data::postcode(p), "{p}");
        }
        assert!(!c.subdivisions.is_empty());
        // Titles are the sex-derived ones of Open question 4.
        assert!(!c.title_male.is_empty() && !c.title_female.is_empty());
    }
}

/// ADR 0079 §12: one vector pins the data file's SHA-256 and `VERSION`. A data change is a new
/// `VERSION` with new known-answer vectors (§4 "Determinism").
#[test]
fn the_embedded_data_is_pinned() {
    // `client_data_hash` is SHA-256 of its input; used here only as a test digest.
    let digest = rizzy_core::passkey::client_data_hash(embedded::RAW.as_bytes());
    let hex = digest.iter().fold(String::new(), |mut s, b| {
        s.push(char::from(b"0123456789abcdef"[usize::from(b >> 4)]));
        s.push(char::from(b"0123456789abcdef"[usize::from(b & 15)]));
        s
    });
    assert_eq!((hex.as_str(), VERSION), (DATA_V1_SHA256, 1));
}

/// Every country generates, with every field the ADR fills, over many seeds.
#[test]
fn every_bundled_country_generates() {
    let data = embedded_data().unwrap();
    let today = date(2026, 10, 23);
    for code in V1_COUNTRIES {
        for seed in 0..40 {
            let mut o = options(code);
            o.email_domain = Some(EmailDomain::parse("example.org").unwrap());
            o.email_style = if seed % 2 == 0 {
                EmailStyle::NameAndBirthday
            } else {
                EmailStyle::Nickname
            };
            let id =
                generate_identity(&mut ChaCha20Rng::seed_from_u64(seed), data, &o, today).unwrap();
            check_identity(data, &o, today, &id);
        }
    }
}

// --- known-answer vectors (ADR 0079 §12) ------------------------------------------------------

/// One known-answer vector: the options, the seed and today, and the exact output pairs.
struct Kat {
    seed: u64,
    country: &'static str,
    sex: SexChoice,
    style: EmailStyle,
    domain: Option<&'static str>,
    age: (u8, u8),
    today: (i32, u8, u8),
    expected: &'static [(&'static str, &'static str)],
}

impl Kat {
    fn options(&self) -> IdentityOptions {
        IdentityOptions {
            sex: self.sex,
            country: CountryCode::parse(self.country).unwrap(),
            age: AgeRange::new(self.age.0, self.age.1).unwrap(),
            email_style: self.style,
            email_domain: self.domain.map(|d| EmailDomain::parse(d).unwrap()),
            title: true,
            phone: true,
        }
    }

    fn run(&self) -> GeneratedIdentity {
        let (y, m, d) = self.today;
        generate_identity(
            &mut ChaCha20Rng::seed_from_u64(self.seed),
            embedded_data().unwrap(),
            &self.options(),
            date(y, m, d),
        )
        .unwrap()
    }
}

/// Prints the vectors' current outputs, for a reviewed data or draw change (run with
/// `--ignored --nocapture`).
#[test]
#[ignore = "prints the vectors for a reviewed update; not a check"]
fn print_known_answer_vectors() {
    for kat in KATS {
        println!("seed {} {}:", kat.seed, kat.country);
        for (k, v) in kat.run().fields() {
            println!("    (\"{k}\", \"{v}\"),");
        }
    }
}

#[test]
fn known_answer_vectors() {
    for kat in KATS {
        let got = kat.run().fields();
        let got: Vec<(&str, &str)> = got.iter().map(|(k, v)| (*k, v.as_str())).collect();
        assert_eq!(got, kat.expected, "seed {} {}", kat.seed, kat.country);
    }
}

/// SHA-256 of `identity-data-v1.txt`, as `data/identity/SOURCES.md` records it.
const DATA_V1_SHA256: &str = "a4738097349e9f0aaaef6ca251c449e7dccb90b8290077aac70f48a7a30a42c7";
/// The vectors: DE, US, FR, GB and AU, both sexes, both email styles, a domain and none, the
/// presets 18–27 and 28+, a custom range, the exact age 28 (also on 29 February 2028), and a
/// 29 February birthday.
const KATS: &[Kat] = &[
    Kat {
        seed: 1,
        country: "DE",
        sex: SexChoice::Female,
        style: EmailStyle::NameAndBirthday,
        domain: Some("example.org"),
        age: (18, 27),
        today: (2026, 10, 23),
        expected: &[
            ("identity.sex", "female"),
            ("identity.title", "Frau"),
            ("identity.first_name", "Charleen"),
            ("identity.last_name", "Giesa"),
            ("identity.birthday", "2005-06-18"),
            ("identity.username", "preseasoncilantro21"),
            ("identity.email", "charleen.giesa05@example.org"),
            ("identity.phone", "+49 176 04069026"),
            ("identity.address1", "Neuenhausgasse 663"),
            ("identity.city", "Stralsund"),
            ("identity.state", "Hessen"),
            ("identity.postal_code", "14595"),
            ("identity.country", "DE"),
        ],
    },
    Kat {
        seed: 2,
        country: "DE",
        sex: SexChoice::Male,
        style: EmailStyle::Nickname,
        domain: Some("example.org"),
        age: (28, 65),
        today: (2026, 10, 23),
        expected: &[
            ("identity.sex", "male"),
            ("identity.title", "Herr"),
            ("identity.first_name", "Yves"),
            ("identity.last_name", "Freisen"),
            ("identity.birthday", "1973-10-12"),
            ("identity.username", "arrivedeceiver26"),
            ("identity.email", "arrivedeceiver26@example.org"),
            ("identity.phone", "+49 221 4710597"),
            ("identity.address1", "Grüner Weg 828"),
            ("identity.city", "Braunschweig"),
            ("identity.state", "Saarland"),
            ("identity.postal_code", "48859"),
            ("identity.country", "DE"),
        ],
    },
    Kat {
        seed: 3,
        country: "US",
        sex: SexChoice::Female,
        style: EmailStyle::Nickname,
        domain: Some("mail.example"),
        age: (30, 44),
        today: (2026, 10, 23),
        expected: &[
            ("identity.sex", "female"),
            ("identity.title", "Ms"),
            ("identity.first_name", "Maribel"),
            ("identity.last_name", "Shields"),
            ("identity.birthday", "1991-12-23"),
            ("identity.username", "manhuntastonish35"),
            ("identity.email", "manhuntastonish35@mail.example"),
            ("identity.phone", "+1 512-555-0199"),
            ("identity.address1", "1501 Koby Falls"),
            ("identity.city", "Stamford"),
            ("identity.state", "VT"),
            ("identity.postal_code", "05414"),
            ("identity.country", "US"),
        ],
    },
    Kat {
        seed: 4,
        country: "US",
        sex: SexChoice::Male,
        style: EmailStyle::NameAndBirthday,
        domain: Some("mail.example"),
        age: (28, 28),
        today: (2026, 10, 23),
        expected: &[
            ("identity.sex", "male"),
            ("identity.title", "Mr"),
            ("identity.first_name", "Akeem"),
            ("identity.last_name", "Denesik"),
            ("identity.birthday", "1997-11-17"),
            ("identity.username", "scoffdawdler50"),
            ("identity.email", "akeemdenesik97@mail.example"),
            ("identity.phone", "+1 212-555-0114"),
            ("identity.address1", "3902 Jackson Street"),
            ("identity.city", "Rancho Palos Verdes"),
            ("identity.state", "RI"),
            ("identity.postal_code", "02920"),
            ("identity.country", "US"),
        ],
    },
    Kat {
        seed: 5,
        country: "FR",
        sex: SexChoice::Female,
        style: EmailStyle::NameAndBirthday,
        domain: Some("example.net"),
        age: (21, 25),
        today: (2026, 10, 23),
        expected: &[
            ("identity.sex", "female"),
            ("identity.title", "Mme"),
            ("identity.first_name", "Francia"),
            ("identity.last_name", "Jean"),
            ("identity.birthday", "2001-10-01"),
            ("identity.username", "morphinecorrosive02"),
            ("identity.email", "francia.jean2001@example.net"),
            ("identity.address1", "6650 Avenue des Saussaies"),
            ("identity.city", "Montpellier"),
            ("identity.state", "Corse"),
            ("identity.postal_code", "49091"),
            ("identity.country", "FR"),
        ],
    },
    Kat {
        seed: 6,
        country: "FR",
        sex: SexChoice::Male,
        style: EmailStyle::Nickname,
        domain: None,
        age: (21, 65),
        today: (2026, 10, 23),
        expected: &[
            ("identity.sex", "male"),
            ("identity.title", "M."),
            ("identity.first_name", "Émeric"),
            ("identity.last_name", "Brun"),
            ("identity.birthday", "1974-10-17"),
            ("identity.username", "eradicatedetector74"),
            ("identity.address1", "9627 Boulevard de Paris"),
            ("identity.city", "Le Mans"),
            ("identity.state", "Pays de la Loire"),
            ("identity.postal_code", "05689"),
            ("identity.country", "FR"),
        ],
    },
    Kat {
        seed: 7,
        country: "GB",
        sex: SexChoice::Random,
        style: EmailStyle::NameAndBirthday,
        domain: Some("example.org"),
        age: (28, 28),
        today: (2028, 2, 29),
        expected: &[
            ("identity.sex", "female"),
            ("identity.title", "Ms"),
            ("identity.first_name", "Imelda"),
            ("identity.last_name", "Stamm"),
            ("identity.birthday", "1999-12-04"),
            ("identity.username", "recycledgainfully42"),
            ("identity.email", "imelda_stamm0412@example.org"),
            ("identity.phone", "+44 113 496 0724"),
            ("identity.address1", "372 Yasmeen Meadows"),
            ("identity.city", "Nicolas-under-Dietrich"),
            ("identity.state", "Wales"),
            ("identity.postal_code", "DT8 1IH"),
            ("identity.country", "GB"),
        ],
    },
    // A 29 February birthday: the exact age 22 on 2026-10-23 spans 2003-10-24..=2004-10-23.
    Kat {
        seed: 2,
        country: "AU",
        sex: SexChoice::Random,
        style: EmailStyle::NameAndBirthday,
        domain: Some("example.com"),
        age: (22, 22),
        today: (2026, 10, 23),
        expected: &[
            ("identity.sex", "male"),
            ("identity.title", "Mr"),
            ("identity.first_name", "Nate"),
            ("identity.last_name", "Lockman"),
            ("identity.birthday", "2004-02-29"),
            ("identity.username", "jobcompanion41"),
            ("identity.email", "natelockman2004@example.com"),
            ("identity.address1", "7996 Jerde Terrace"),
            ("identity.city", "Bartolettifort"),
            ("identity.state", "SA"),
            ("identity.postal_code", "4885"),
            ("identity.country", "AU"),
        ],
    },
];

/// Finds the first seed whose AU identity with the exact age 22 on 2026-10-23 is born on
/// 29 February 2004 (for the vector below; run with `--ignored --nocapture`).
#[test]
#[ignore = "a search helper for the 29 February birthday vector; not a check"]
fn find_a_29_february_birthday_seed() {
    let data = embedded_data().unwrap();
    let mut o = options("AU");
    o.age = AgeRange::exact(22).unwrap();
    o.email_domain = Some(EmailDomain::parse("example.com").unwrap());
    for seed in 0..100_000u64 {
        let id = generate_identity(
            &mut ChaCha20Rng::seed_from_u64(seed),
            data,
            &o,
            date(2026, 10, 23),
        )
        .unwrap();
        if id.birthday() == date(2004, 2, 29) {
            println!("seed {seed}");
            return;
        }
    }
}
