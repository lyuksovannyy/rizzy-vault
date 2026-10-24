// SPDX-License-Identifier: AGPL-3.0-only

//! Tests of `cargo xtask identity-data`: sampling, content rules, the writer, the validator,
//! `SOURCES.md` parsing, and a whole run (write, then `--check`) on a tiny fixture checkout.

use std::fs;
use std::path::{Path, PathBuf};

use super::{
    BEGIN, CLDR, Cities, Country, CountryData, END, FAKER, Form, HEADER, Last, Level, Limits,
    OUTPUT, SOURCES, SplitMix64, TRANSLIT, country, display_ok, hex_sha256, manifest, phone_ok,
    postcode_ok, render, run_with, sample, title_ok, validate,
};

/// The committed table, so the fixture run uses the real rules.
const TABLE: &str = include_str!("../../../../data/identity/translit.txt");

/// A fresh scratch directory under the OS temp dir (the pattern of the other xtask tests).
fn scratch_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "rizzy-xtask-identity-test-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// Writes `text` to `root/rel`, creating directories.
fn put(root: &Path, rel: &str, text: &str) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

#[test]
fn splitmix64_matches_the_reference_output() {
    // Vigna's splitmix64.c from state 0: the first output is 0xe220a8397b1dcdaf.
    let mut g = SplitMix64(0);
    assert_eq!(g.next_u64(), 0xe220_a839_7b1d_cdaf);
    assert_eq!(g.next_u64(), 0x6e78_9e6a_a1b9_65f4);
}

#[test]
fn below_stays_in_range() {
    let mut g = SplitMix64::for_label("x");
    assert_eq!(g.below(0), 0);
    assert_eq!(g.below(1), 0);
    for _ in 0..1000 {
        assert!(g.below(7) < 7);
    }
}

#[test]
fn sampling_is_deterministic_per_label() {
    let items: Vec<u32> = (0..100).collect();
    let a = sample(items.clone(), 10, "DE/first.female");
    assert_eq!(a, sample(items.clone(), 10, "DE/first.female"));
    assert_ne!(a, sample(items.clone(), 10, "DE/first.male"));
    assert_eq!(a.len(), 10);
    let mut unique = a.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), 10);
    assert_eq!(sample(items.clone(), 100, "x"), items);
    assert_eq!(sample(items.clone(), 200, "x"), items);
}

#[test]
fn content_rules() {
    for ok in [
        "Anna",
        "Jürgen",
        "O'Brien",
        "Anne-Marie",
        "Val de Loire",
        "Łukasz",
        "Ödön",
    ] {
        assert!(display_ok(ok), "{ok}");
    }
    for bad in [
        "",
        "Bahnhofstr.",
        "St. Gallen",
        "Biel/Bienne",
        "Anna ",
        " Anna",
        "A  B",
        "-Anna",
        "Anna'",
        "1st Street",
        "Αθήνα",
        "Ana\u{301}",
        "a×b",
        &"a".repeat(41),
    ] {
        assert!(!display_ok(bad), "{bad:?}");
    }
    assert!(postcode_ok("A## ?#??") && postcode_ok("#####-####") && postcode_ok("T#? #?#"));
    assert!(
        !postcode_ok("")
            && !postcode_ok("a####")
            && !postcode_ok("#*##")
            && !postcode_ok(&"#".repeat(17))
    );
    assert!(phone_ok("+44 7700 900###") && phone_ok("+1 (212) 555-01##"));
    assert!(
        !phone_ok("+44 7700 900000") && !phone_ok("+44 7700 900#x#") && !phone_ok(&"#".repeat(25))
    );
    assert!(title_ok("Sig.ra") && title_ok("Prof. Dr") && !title_ok("") && !title_ok("Hr1"));
}

/// A small country for writer and validator tests.
fn sample_country() -> CountryData {
    CountryData {
        code: "XA".into(),
        name: "Testland".into(),
        title_male: "Mr".into(),
        title_female: "Ms".into(),
        address: "{number} {street}".into(),
        number: (1, 99),
        postcodes: vec!["##".into(), "?#".into()],
        phones: vec!["+1 555-01##".into()],
        first_female: vec![("Anna".into(), "anna".into())],
        first_male: vec![("Max".into(), "max".into())],
        last: Last::Split(
            vec![("Nowak".into(), "nowak".into())],
            vec![("Kowal".into(), "kowal".into())],
        ),
        streets: vec!["Main Street".into()],
        cities: vec!["Springfield".into()],
        subdivisions: vec![("XA-1".into(), "One".into()), ("XA-B".into(), "Bee".into())],
        sub_postcodes: vec![("XA-1".into(), "1#".into()), ("XA-B".into(), "2#".into())],
    }
}

#[test]
fn the_writer_follows_the_format_contract() {
    let text = render(&[sample_country()]);
    let want = format!(
        "{HEADER}\n@country XA\n@name Testland\n@title.male Mr\n@title.female Ms\n@address \
         {{number}} {{street}}\n@number 1 99\n@postcode ##\n@postcode ?#\n@phone +1 555-01##\n\
         [first.female]\nAnna|anna\n[first.male]\nMax|max\n[last.female]\nNowak|nowak\n\
         [last.male]\nKowal|kowal\n[street]\nMain Street\n[city]\nSpringfield\n[subdivision]\n\
         XA-1|One\nXA-B|Bee\n[postcode]\nXA-1|1#\nXA-B|2#\n"
    );
    assert_eq!(text, want);
    validate(&text, 1).unwrap();
    assert!(validate(&text, 2).is_err(), "lists under the minimum");
}

#[test]
fn the_validator_rejects_broken_files() {
    let good = render(&[sample_country()]);
    let mut two = sample_country();
    two.code = "XB".into();
    two.subdivisions = vec![("XB-1".into(), "One".into())];
    two.sub_postcodes = Vec::new();
    two.last = Last::One(vec![("Nowak".into(), "nowak".into())]);
    validate(&render(&[sample_country(), two.clone()]), 1).unwrap();
    assert!(
        validate(&render(&[two, sample_country()]), 1).is_err(),
        "country order"
    );
    let cases: Vec<(&str, String)> = vec![
        ("no final LF", good.trim_end().to_owned()),
        ("blank line", good.replace("[street]\n", "[street]\n\n")),
        (
            "trailing space",
            good.replace("Main Street", "Main Street "),
        ),
        ("comment", good.replace("[city]\n", "[city]\n# x\n")),
        ("header", good.replace("do not edit", "edit")),
        ("tab", good.replace("Main Street", "Main\tStreet")),
        ("CR", good.replace("[city]\n", "[city]\r\n")),
        ("missing directive", good.replace("@number 1 99\n", "")),
        ("bad number", good.replace("@number 1 99", "@number 0 99")),
        (
            "bad address",
            good.replace("{number} {street}", "{number} {street} {street}"),
        ),
        ("bad ascii", good.replace("Anna|anna", "Anna|Anna")),
        ("no ascii", good.replace("Anna|anna", "Anna")),
        ("bad display", good.replace("Main Street", "Main St.")),
        (
            "unsorted",
            good.replace("Main Street\n", "Main Street\nAvenue\n"),
        ),
        (
            "duplicate",
            good.replace("Main Street\n", "Main Street\nMain Street\n"),
        ),
        (
            "unsorted postcode",
            good.replace("@postcode ##\n@postcode ?#", "@postcode ?#\n@postcode ##"),
        ),
        ("unknown code", good.replace("XA-B|2#", "XA-C|2#")),
        ("foreign code", good.replace("XA-B|Bee", "XB-B|Bee")),
        ("long line", good.replace("Main Street", &"A".repeat(201))),
        ("bad phone", good.replace("+1 555-01##", "+1 555-0100")),
        ("stray line", format!("{good}stray\n")),
    ];
    for (what, text) in cases {
        assert!(validate(&text, 1).is_err(), "accepted: {what}");
    }
    let mut big = good.clone();
    while big.len() <= super::MAX_OUTPUT {
        big.push_str(&good[HEADER.len() + 1..]);
    }
    assert!(validate(&big, 1).is_err(), "over the budget");
}

#[test]
fn manifest_parsing() {
    let sha = "a".repeat(64);
    let good = format!(
        "prose\n```identity-data-inputs\nfaker src/x.ts {sha}\ncldr common/y.xml {sha}\n```\n"
    );
    let m = manifest(&good).unwrap();
    assert_eq!(m.len(), 2);
    assert_eq!(m[&("faker".to_owned(), "src/x.ts".to_owned())], sha);
    for bad in [
        "no block\n".to_owned(),
        good.replace("\n```\n", "\n"),
        format!("{good}{good}"),
        good.replace("faker src/x.ts", "npm src/x.ts"),
        good.replace("faker src/x.ts", "faker /etc/x.ts"),
        good.replace("faker src/x.ts", "faker src/../x.ts"),
        good.replace("faker src/x.ts", "faker src//x.ts"),
        good.replacen(&sha, &"A".repeat(64), 1),
        good.replacen(&sha, "abc", 1),
        good.replace("cldr common/y.xml", "faker src/x.ts"),
        good.replace("faker src/x.ts ", "faker src/x.ts  "),
    ] {
        assert!(manifest(&bad).is_err(), "accepted {bad:?}");
    }
}

/// The fixture: one country (DE through `de` → `en`), with entries every rule touches.
fn fixture(root: &Path) -> (PathBuf, PathBuf) {
    let faker = root.join("faker");
    let cldr = root.join("cldr");
    put(
        &faker,
        "src/locale/de.ts",
        "/*\n * generated\n */\nimport { Faker } from '../faker';\nimport base from '../locales/base';\nimport de from '../locales/de';\nimport en from '../locales/en';\n\nexport const faker = new Faker({\n  locale: [de, en, base],\n});\n",
    );
    put(
        &faker,
        "src/locales/de/person/first_name.ts",
        "export default {\n  generic: ['Kim'],\n  female: ['Anna', 'Jürgen-Anne', 'Anna', 'Zoë'],\n  male: ['Max', 'Jörg', 'Ab.'],\n};\n",
    );
    put(
        &faker,
        "src/locales/de/person/last_name.ts",
        "export default {\n  generic: [\n    // a comment\n    'Müller',\n    'Weiß',\n    'Łoś',\n  ],\n};\n",
    );
    put(
        &faker,
        "src/locales/de/location/building_number.ts",
        "export default ['###', '##', '##a'];\n",
    );
    put(
        &faker,
        "src/locales/de/location/street_address.ts",
        "export default {\n  normal: '{{location.street}} {{location.buildingNumber}}',\n  full: '{{location.street}} {{location.buildingNumber}} {{location.secondaryAddress}}',\n};\n",
    );
    put(
        &faker,
        "src/locales/de/location/street_pattern.ts",
        "export default ['{{location.street_name}}'];\n",
    );
    put(
        &faker,
        "src/locales/de/location/street_name.ts",
        "export default ['Hauptstraße', 'Bahnhofstr.', 'Ringweg'];\n",
    );
    put(
        &faker,
        "src/locales/de/location/city_name.ts",
        "export default ['München', 'Berlin', 'Biel/Bienne'];\n",
    );
    put(
        &faker,
        "src/locales/en/location/postcode.ts",
        "export default ['#####'];\n",
    );
    put(
        &cldr,
        "common/main/en.xml",
        "<ldml>\n\t\t\t<territory type=\"DE\">Germany</territory>\n</ldml>\n",
    );
    put(
        &cldr,
        "common/supplemental/subdivisions.xml",
        "<supplementalData>\n\t\t<subgroup type=\"DE\" contains=\"deby debe\"/>\n</supplementalData>\n",
    );
    put(
        &cldr,
        "common/subdivisions/de.xml",
        "<ldml>\n\t\t\t<subdivision type=\"debe\">Berlin</subdivision>\n\t\t\t<subdivision type=\"deby\" draft=\"contributed\">Bayern</subdivision>\n</ldml>\n",
    );
    (faker, cldr)
}

/// The fixture's one country.
const FIXTURE_COUNTRIES: &[Country] = &[country(
    "DE",
    "de",
    "de",
    Cities::Names("de"),
    ("Herr", "Frau"),
    &["+49 30 23125###"],
)];

/// Small caps so the sampler runs on the female names.
const FIXTURE_LIMITS: Limits = Limits {
    first: 10,
    last: 10,
    street: 10,
    city: 10,
    min_list: 1,
};

/// The input block for every file under the two fixture checkouts.
fn block(faker: &Path, cldr: &Path) -> String {
    let mut lines = Vec::new();
    for (id, root) in [(FAKER.id, faker), (CLDR.id, cldr)] {
        let mut stack = vec![root.to_owned()];
        while let Some(dir) = stack.pop() {
            for e in fs::read_dir(&dir).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    // The manifest names files with `/` on every platform, as the tool reads them.
                    let rel = p
                        .strip_prefix(root)
                        .unwrap()
                        .components()
                        .map(|c| c.as_os_str().to_str().unwrap())
                        .collect::<Vec<_>>()
                        .join("/");
                    lines.push(format!("{id} {rel} {}", hex_sha256(&fs::read(&p).unwrap())));
                }
            }
        }
    }
    lines.sort();
    format!("```identity-data-inputs\n{}\n```\n", lines.join("\n"))
}

#[test]
fn a_fixture_run_writes_then_checks() {
    let root = scratch_dir("run");
    let (faker, cldr) = fixture(&root);
    let repo = root.join("repo");
    put(&repo, TRANSLIT, TABLE);
    put(&repo, OUTPUT, "");
    let hand = format!(
        "# Provenance\n\n{}\n{BEGIN}\n{END}\nafter\n",
        block(&faker, &cldr)
    );
    put(&repo, SOURCES, &hand);
    let paths = (faker.as_path(), cldr.as_path());

    let err = run_with(FIXTURE_COUNTRIES, FIXTURE_LIMITS, &repo, paths, true).unwrap_err();
    assert!(err.contains("out of date"), "{err}");
    let report = run_with(FIXTURE_COUNTRIES, FIXTURE_LIMITS, &repo, paths, false).unwrap();
    assert!(report.contains("written"), "{report}");
    let output = fs::read_to_string(repo.join(OUTPUT)).unwrap();
    let want = format!(
        "{HEADER}\n@country DE\n@name Germany\n@title.male Herr\n@title.female Frau\n@address \
         {{street}} {{number}}\n@number 1 999\n@postcode #####\n@phone +49 30 23125###\n\
         [first.female]\nAnna|anna\nJürgen-Anne|juergen-anne\nZoë|zoe\n[first.male]\nJörg|joerg\n\
         Max|max\n[last]\nMüller|mueller\nWeiß|weiss\nŁoś|los\n[street]\nHauptstraße\nRingweg\n\
         [city]\nBerlin\nMünchen\n[subdivision]\nDE-BE|Berlin\nDE-BY|Bayern\n"
    );
    assert_eq!(output, want);
    let sources = fs::read_to_string(repo.join(SOURCES)).unwrap();
    assert!(sources.starts_with("# Provenance\n"));
    assert!(sources.ends_with(&format!("{END}\nafter\n")));
    assert!(sources.contains(&hex_sha256(want.as_bytes())));
    assert!(sources.contains("| DE/street |"));
    assert!(
        sources.contains("DE/first.male | src/locales/de/person/first_name.ts | all | 3 | 1 |")
    );

    let ok = run_with(FIXTURE_COUNTRIES, FIXTURE_LIMITS, &repo, paths, true).unwrap();
    assert!(ok.contains("current"), "{ok}");
    // One changed byte in either committed file fails the check.
    put(&repo, OUTPUT, &output.replace("Ringweg", "Ringwef"));
    assert!(run_with(FIXTURE_COUNTRIES, FIXTURE_LIMITS, &repo, paths, true).is_err());
    put(&repo, OUTPUT, &output);
    put(
        &repo,
        SOURCES,
        &sources.replace("Generated report", "Generated Report"),
    );
    assert!(run_with(FIXTURE_COUNTRIES, FIXTURE_LIMITS, &repo, paths, true).is_err());
    put(&repo, SOURCES, &sources);
    run_with(FIXTURE_COUNTRIES, FIXTURE_LIMITS, &repo, paths, true).unwrap();

    // A changed upstream file fails verification before anything is written.
    put(
        &faker,
        "src/locales/de/location/street_name.ts",
        "export default ['Ringweg', 'Neuweg'];\n",
    );
    let err = run_with(FIXTURE_COUNTRIES, FIXTURE_LIMITS, &repo, paths, false).unwrap_err();
    assert!(
        err.contains("SHA-256 mismatch: faker src/locales/de/location/street_name.ts"),
        "{err}"
    );
    assert_eq!(fs::read_to_string(repo.join(OUTPUT)).unwrap(), output);
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn unlisted_and_unread_files_fail() {
    let root = scratch_dir("manifest");
    let (faker, cldr) = fixture(&root);
    let repo = root.join("repo");
    put(&repo, TRANSLIT, TABLE);
    put(&repo, OUTPUT, "");
    let full = block(&faker, &cldr);
    let paths = (faker.as_path(), cldr.as_path());

    let missing: String = full
        .lines()
        .filter(|l| !l.contains("city_name.ts"))
        .flat_map(|l| [l, "\n"])
        .collect();
    put(&repo, SOURCES, &format!("{missing}{BEGIN}\n{END}\n"));
    let err = run_with(FIXTURE_COUNTRIES, FIXTURE_LIMITS, &repo, paths, false).unwrap_err();
    assert!(
        err.contains("not listed: faker src/locales/de/location/city_name.ts"),
        "{err}"
    );
    assert!(err.contains("nothing was written"), "{err}");

    let extra = full.replace(
        "\n```",
        &format!(
            "\nfaker src/locales/de/location/unused.ts {}\n```",
            "0".repeat(64)
        ),
    );
    put(&repo, SOURCES, &format!("{extra}{BEGIN}\n{END}\n"));
    let err = run_with(FIXTURE_COUNTRIES, FIXTURE_LIMITS, &repo, paths, false).unwrap_err();
    assert!(
        err.contains("listed but not read: faker src/locales/de/location/unused.ts"),
        "{err}"
    );
    assert_eq!(fs::read_to_string(repo.join(OUTPUT)).unwrap(), "");

    put(&repo, SOURCES, &full);
    let err = run_with(FIXTURE_COUNTRIES, FIXTURE_LIMITS, &repo, paths, false).unwrap_err();
    assert!(err.contains("GENERATED"), "{err}");
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn the_v1_country_table_is_consistent() {
    let codes: Vec<&str> = super::COUNTRIES.iter().map(|c| c.code).collect();
    assert_eq!(
        codes,
        [
            "AT", "AU", "CA", "CH", "DE", "ES", "FR", "GB", "IE", "IT", "NL", "SE", "US"
        ]
    );
    for c in super::COUNTRIES {
        assert!(
            title_ok(c.title_male) && title_ok(c.title_female),
            "{}",
            c.code
        );
        assert!(
            c.phones.len() <= 16 && c.phones.iter().all(|p| phone_ok(p)),
            "{}",
            c.code
        );
        assert_eq!(c.german, ["AT", "CH", "DE"].contains(&c.code), "{}", c.code);
        assert_eq!(
            c.form == Form::Code,
            ["AU", "CA", "US"].contains(&c.code),
            "{}",
            c.code
        );
        assert_eq!(c.level == Level::Children, c.code == "IE", "{}", c.code);
    }
}
