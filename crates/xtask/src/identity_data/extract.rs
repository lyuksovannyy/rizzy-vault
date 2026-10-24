// SPDX-License-Identifier: AGPL-3.0-only

//! Extraction: from the verified upstream files to one [`CountryData`] per country, with the
//! report of every drop and decision ([`CountryReport`]).
//!
//! Each faker key is read from the first locale of the country's chain that has the file (faker
//! merges locales key by key the same way). Code-built faker files are accepted only in the exact
//! shapes below ([`GB_POSTCODE`], [`FR_POSTCODE`], [`NL_POSTCODE`], [`CA_BY_STATE`]).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use super::ts::{self, Capture, Literal, Value};
use super::{
    CLDR, Cities, Country, CountryData, CountryReport, FAKER, Form, Inputs, Last, Level, Limits,
    ListReport, MAX_PHONES, MAX_POSTCODES, MAX_SUB_POSTCODES, MAX_SUBDIVISIONS, SplitMix64,
    Translit, cldr, display_ok, normalize, phone_ok, postcode_ok, sample, title_ok,
};

/// faker's GB postcode file (`en_GB/location/postcode.ts`): every district prefix with each
/// suffix, plus the London prefixes with the extra-letter suffix.
const GB_POSTCODE: &str = "const suffixes = $strs; const londonExtraLetterSuffixes = $strs; \
    const londonPrefixes = $strs; const prefixes = $strs; export default [ ...[...prefixes, \
    ...londonPrefixes].flatMap((prefix) => suffixes.map((suffix) => prefix + suffix)), \
    ...londonPrefixes.flatMap((prefix) => londonExtraLetterSuffixes.map((suffix) => prefix + \
    suffix)), ];";

/// faker's FR postcode file (`fr/location/postcode.ts`): two-digit metropolitan departments and
/// three-digit overseas prefixes.
const FR_POSTCODE: &str = "const range = (start: number, end: number): number[] => \
    Array.from({ length: end - start + 1 }, (_, index) => start + index); const metropolitan = \
    range($num, $num).map((department) => `${department.toString().padStart(2, '0')}###`); \
    const overseas = [...range($num, $num), $num, ...range($num, $num)].map((territory) => \
    `${territory}##`); export default [...metropolitan, ...overseas];";

/// faker's NL postcode file (`nl/location/postcode.ts`): four digits and two letters, minus three
/// letter pairs.
const NL_POSTCODE: &str = "const digitPrefixes = $strs; const letters = $strs; const \
    forbiddenLetterPairs = new Set($strs); const letterPairs = letters.flatMap((first) => \
    letters.map((second) => first + second).filter((pair) => !forbiddenLetterPairs.has(pair))); \
    export default digitPrefixes.flatMap((prefix) => letterPairs.map((pair) => \
    `${prefix} ${pair}`));";

/// faker's CA postcode-by-province file (`en_CA/location/postcode_by_state.ts`).
const CA_BY_STATE: &str = "const suffix = $str; export default $obj;";

/// The one suffix regex [`CA_BY_STATE`] may use, and the pattern it maps to: `?` is uniform over
/// A–Z (ADR 0079 §4 step 7), so the six letters the regex excludes can appear.
const CA_SUFFIX: (&str, &str) = (
    "[0-9][ABCEGHJ-NPRSTVW-Z] [0-9][ABCEGHJ-NPRSTVW-Z][0-9]",
    "#? #?#",
);

/// The pattern references the expander knows.
const REFS: &[&str] = &[
    "location.city_prefix",
    "location.city_suffix",
    "location.city_infix",
    "location.city_name",
    "location.street_name",
    "location.street_suffix",
    "location.street_prefix",
    "location.street_name_part",
    "location.common_street_suffix",
    "person.firstName",
    "person.lastName",
];

/// The CLDR inputs shared by every country.
struct Cldr {
    /// `common/main/en.xml`.
    main: String,
    /// The subdivision containment.
    containment: BTreeMap<String, Vec<String>>,
    /// Subdivision names by language, read on first use.
    names: BTreeMap<String, BTreeMap<String, String>>,
}

/// Compiles every country.
///
/// # Errors
///
/// On the first extraction error.
pub(super) fn all(
    inputs: &mut Inputs,
    countries: &[Country],
    limits: Limits,
    table: &Translit,
) -> Result<(Vec<CountryData>, Vec<CountryReport>), String> {
    let main = inputs.read(&CLDR, "common/main/en.xml")?;
    let sup = inputs.read(&CLDR, "common/supplemental/subdivisions.xml")?;
    let mut shared = Cldr {
        main,
        containment: cldr::containment(&sup)?,
        names: BTreeMap::new(),
    };
    let mut data = Vec::new();
    let mut reports = Vec::new();
    for c in countries {
        let (d, r) = country(inputs, &mut shared, c, limits, table)
            .map_err(|e| format!("identity-data: {}: {e}", c.code))?;
        data.push(d);
        reports.push(r);
    }
    Ok((data, reports))
}

/// faker access through one country's locale chain.
struct Faker<'a> {
    /// The reader.
    inputs: &'a mut Inputs,
    /// The chain, most specific first.
    chain: Vec<String>,
}

impl Faker<'_> {
    /// The first locale whose `src/locales/<locale>/<key>.ts` exists, and that path.
    fn resolve(&self, key: &str) -> Option<(String, String)> {
        self.chain.iter().find_map(|l| {
            let path = format!("src/locales/{l}/{key}.ts");
            self.inputs.exists(&FAKER, &path).then(|| (l.clone(), path))
        })
    }

    /// Reads `key` through the chain: (locale, path, text).
    fn read(&mut self, key: &str) -> Result<(String, String, String), String> {
        let (locale, path) = self
            .resolve(key)
            .ok_or_else(|| format!("no locale in {:?} has {key}", self.chain))?;
        let text = self.inputs.read(&FAKER, &path)?;
        Ok((locale, path, text))
    }

    /// Reads `key` as a literal file.
    fn literal(&mut self, key: &str) -> Result<(String, String, Literal), String> {
        let (locale, path, text) = self.read(key)?;
        let lit = ts::parse_default(&text).map_err(|e| format!("{path}: {e}"))?;
        Ok((locale, path, lit))
    }

    /// Reads `key` as a plain string list.
    fn list(&mut self, key: &str) -> Result<(String, Vec<String>), String> {
        match self.literal(key)? {
            (_, path, Literal::List(l)) => Ok((path, l)),
            (_, path, Literal::Object(_)) => Err(format!("{path}: expected a list")),
        }
    }
}

/// Splits a `{ generic?, female?, male? }` object into its lists.
fn sexed(path: &str, obj: Vec<(String, Value)>) -> Result<BTreeMap<String, Vec<String>>, String> {
    let mut out = BTreeMap::new();
    for (k, v) in obj {
        match (k.as_str(), v) {
            ("generic" | "female" | "male", Value::List(l)) => {
                out.insert(k, l);
            }
            _ => return Err(format!("{path}: unexpected key or value {k:?}")),
        }
    }
    Ok(out)
}

/// One country.
fn country(
    inputs: &mut Inputs,
    shared: &mut Cldr,
    c: &Country,
    limits: Limits,
    table: &Translit,
) -> Result<(CountryData, CountryReport), String> {
    let entry = format!("src/locale/{}.ts", c.locale);
    let chain =
        ts::locale_chain(&inputs.read(&FAKER, &entry)?).map_err(|e| format!("{entry}: {e}"))?;
    if chain.first().map(String::as_str) != Some(c.locale) {
        return Err(format!(
            "{entry}: the chain does not start with {}",
            c.locale
        ));
    }
    let mut rep = CountryReport {
        code: c.code.to_owned(),
        ..CountryReport::default()
    };
    rep.notes.push(format!(
        "faker locale chain ({entry}): {}",
        chain.join(" → ")
    ));
    let mut f = Faker { inputs, chain };
    let names = names(&mut f, c, limits, table, &mut rep)?;
    let (number, address) = number_and_address(&mut f, &mut rep)?;
    let mut pools = Pools::new(&names);
    let streets = streets(&mut f, c, limits, &mut pools, &mut rep)?;
    let cities = cities(&mut f, c, limits, &mut pools, &mut rep)?;
    let subdivisions = subdivisions(f.inputs, shared, c, &mut rep)?;
    let sub_postcodes = if c.by_state {
        by_state(&mut f, c, &subdivisions, &mut rep)?
    } else {
        Vec::new()
    };
    let postcodes = if c.postcode_from_states {
        let set: BTreeSet<String> = sub_postcodes.iter().map(|(_, p)| p.clone()).collect();
        rep.notes.push(format!(
            "@postcode: the union of the {} per-subdivision patterns (faker's own postcode file \
             for this locale is not read)",
            set.len()
        ));
        set.into_iter().collect()
    } else {
        postcodes(&mut f, &mut rep)?
    };
    if postcodes.is_empty() || postcodes.len() > MAX_POSTCODES {
        return Err(format!("{} postcode patterns", postcodes.len()));
    }
    let name = cldr::territory_name(&shared.main, c.code)?;
    if !display_ok(&name) {
        return Err(format!("territory name {name:?} breaks the display rule"));
    }
    for t in [c.title_male, c.title_female] {
        if !title_ok(t) {
            return Err(format!("title {t:?} breaks the title rule"));
        }
    }
    let phones: BTreeSet<String> = c.phones.iter().map(|&p| p.to_owned()).collect();
    if phones.len() != c.phones.len()
        || phones.len() > MAX_PHONES
        || !phones.iter().all(|p| phone_ok(p))
    {
        return Err("malformed phone patterns".to_owned());
    }
    let data = CountryData {
        code: c.code.to_owned(),
        name,
        title_male: c.title_male.to_owned(),
        title_female: c.title_female.to_owned(),
        address,
        number,
        postcodes,
        phones: phones.into_iter().collect(),
        first_female: names.first_female,
        first_male: names.first_male,
        last: names.last,
        streets,
        cities,
        subdivisions,
        sub_postcodes,
    };
    Ok((data, rep))
}

/// The person lists of one country, and the raw pools patterns draw from.
struct Names {
    /// `[first.female]`.
    first_female: Vec<(String, String)>,
    /// `[first.male]`.
    first_male: Vec<(String, String)>,
    /// `[last]` or the split lists.
    last: Last,
    /// Every first name that passes the display rule (female, male, then generic), for
    /// `{{person.firstName}}`.
    first_pool: Vec<String>,
    /// Every last name that passes the display rule, for `{{person.lastName}}`.
    last_pool: Vec<String>,
}

/// Normalizes, checks and de-duplicates display forms; counts go to `rep`.
fn clean(raw: &[String], rep: &mut ListReport) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for r in raw {
        let d = normalize(r);
        if !display_ok(&d) {
            rep.dropped_rule += 1;
        } else if !seen.insert(d.clone()) {
            rep.duplicates += 1;
        } else {
            out.push(d);
        }
    }
    out
}

/// Builds a capped, sorted name list with ascii forms.
fn name_list(
    raw: &[String],
    label: &str,
    from: &str,
    cap: usize,
    min: usize,
    (table, german): (&Translit, bool),
    rep: &mut CountryReport,
) -> Result<Vec<(String, String)>, String> {
    let mut lr = ListReport {
        label: label.to_owned(),
        from: from.to_owned(),
        upstream: raw.len(),
        ..ListReport::default()
    };
    let mut kept = Vec::new();
    for d in clean(raw, &mut lr) {
        match table.ascii(&d, german) {
            Some(a) => kept.push((d, a)),
            None => lr.dropped_ascii += 1,
        }
    }
    lr.method = method(kept.len(), cap);
    let mut out = sample(kept, cap, label);
    out.sort();
    lr.written = out.len();
    rep.lists.push(lr);
    if out.len() < min {
        return Err(format!("{label}: {} entries, fewer than {min}", out.len()));
    }
    Ok(out)
}

/// "all" or "sample N of M".
fn method(len: usize, cap: usize) -> String {
    if len > cap {
        format!("fixed-seed sample of {cap} from {len}")
    } else {
        "all".to_owned()
    }
}

/// First and last names.
fn names(
    f: &mut Faker<'_>,
    c: &Country,
    limits: Limits,
    table: &Translit,
    rep: &mut CountryReport,
) -> Result<Names, String> {
    let tr = (table, c.german);
    let (_, path, lit) = f.literal("person/first_name")?;
    let Literal::Object(obj) = lit else {
        return Err(format!("{path}: first names are not split by sex"));
    };
    let first = sexed(&path, obj)?;
    let (Some(female), Some(male)) = (first.get("female"), first.get("male")) else {
        return Err(format!("{path}: no female and male lists"));
    };
    let generic = first.get("generic").cloned().unwrap_or_default();
    if !generic.is_empty() {
        rep.notes.push(format!(
            "first names: the sex-specific lists only; faker's {} generic (unisex) entries in \
             {path} are not used for [first.*], only inside street and city patterns",
            generic.len()
        ));
    }
    let code = c.code;
    let first_female = name_list(
        female,
        &format!("{code}/first.female"),
        &path,
        limits.first,
        limits.min_list,
        tr,
        rep,
    )?;
    let first_male = name_list(
        male,
        &format!("{code}/first.male"),
        &path,
        limits.first,
        limits.min_list,
        tr,
        rep,
    )?;
    let mut scratch = ListReport::default();
    let all_first: Vec<String> = female.iter().chain(male).chain(&generic).cloned().collect();
    let first_pool = clean(&all_first, &mut scratch);

    let (_, path, lit) = f.literal("person/last_name")?;
    let lists = match lit {
        Literal::List(l) => BTreeMap::from([("generic".to_owned(), l)]),
        Literal::Object(obj) => sexed(&path, obj)?,
    };
    let (last, raw_last) = match (lists.get("generic"), lists.get("female"), lists.get("male")) {
        (Some(g), None, None) => (
            Last::One(name_list(
                g,
                &format!("{code}/last"),
                &path,
                limits.last,
                limits.min_list,
                tr,
                rep,
            )?),
            g.clone(),
        ),
        (None, Some(fe), Some(ma)) => (
            Last::Split(
                name_list(
                    fe,
                    &format!("{code}/last.female"),
                    &path,
                    limits.last,
                    limits.min_list,
                    tr,
                    rep,
                )?,
                name_list(
                    ma,
                    &format!("{code}/last.male"),
                    &path,
                    limits.last,
                    limits.min_list,
                    tr,
                    rep,
                )?,
            ),
            fe.iter().chain(ma).cloned().collect(),
        ),
        _ => return Err(format!("{path}: unexpected last-name keys")),
    };
    let last_pool = clean(&raw_last, &mut scratch);
    rep.notes.push(format!(
        "last names: the plain list in {path}; faker's last_name_pattern (occasional double \
         names) is not applied"
    ));
    Ok(Names {
        first_female,
        first_male,
        last,
        first_pool,
        last_pool,
    })
}

/// `@number` from `location/building_number` and `@address` from `location/street_address`.
fn number_and_address(
    f: &mut Faker<'_>,
    rep: &mut CountryReport,
) -> Result<((u32, u32), String), String> {
    let (path, numbers) = f.list("location/building_number")?;
    let mut digits = 0;
    let mut first_sep = None;
    let mut skipped = Vec::new();
    for e in &numbers {
        let (sep, t) = match (e.strip_prefix(", "), e.strip_prefix(' ')) {
            (Some(t), _) => (", ", t),
            (None, Some(t)) => (" ", t),
            (None, None) => ("", e.as_str()),
        };
        if t == "s/n." {
            skipped.push(e.trim().to_owned());
            continue;
        }
        let hashes = t.bytes().take_while(|&b| b == b'#').count();
        if hashes == 0 || !["", "a", "b", "c", " I", " II", " III"].contains(&&t[hashes..]) {
            return Err(format!("{path}: unexpected building number {e:?}"));
        }
        first_sep.get_or_insert(sep);
        digits = digits.max(hashes);
    }
    let hi = 10u32
        .checked_pow(u32::try_from(digits).map_err(|_| "too many digits".to_owned())?)
        .map_or(9999, |p| (p - 1).min(9999));
    let number = (1, hi);
    rep.notes.push(format!(
        "@number 1 {hi}: from {path} {numbers:?}: the most '#' is {digits}, capped at 9999; letter \
         and roman suffixes are not generated{}",
        if skipped.is_empty() {
            String::new()
        } else {
            format!("; skipped {skipped:?}")
        }
    ));
    let (_, path, lit) = f.literal("location/street_address")?;
    let Literal::Object(obj) = lit else {
        return Err(format!("{path}: expected an object"));
    };
    let normal = obj
        .iter()
        .find_map(|(k, v)| match (k.as_str(), v) {
            ("normal", Value::Str(s)) => Some(s.clone()),
            _ => None,
        })
        .ok_or_else(|| format!("{path}: no normal pattern"))?;
    if obj.len() != 2
        || !obj
            .iter()
            .any(|(k, v)| k == "full" && matches!(v, Value::Str(_)))
    {
        return Err(format!("{path}: expected exactly normal and full"));
    }
    let address = match (normal.as_str(), first_sep) {
        ("{{location.buildingNumber}} {{location.street}}", _) => "{number} {street}".to_owned(),
        ("{{location.street}} {{location.buildingNumber}}", _) => "{street} {number}".to_owned(),
        ("{{location.street}}{{location.buildingNumber}}", Some(sep @ (", " | " "))) => {
            format!("{{street}}{sep}{{number}}")
        }
        _ => return Err(format!("{path}: unexpected address pattern {normal:?}")),
    };
    rep.notes.push(format!(
        "@address {address}: from {path} normal = {normal:?}{}",
        if normal.contains("}}{{") {
            " (the separator is the first numeric building-number entry's)"
        } else {
            ""
        }
    ));
    Ok((number, address))
}

/// One piece of a faker pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Piece {
    /// A single space between two references.
    Space,
    /// A `{{namespace.key}}` reference.
    Ref(String),
}

/// Parses a pattern: references from [`REFS`], separated by nothing or one space.
fn parse_pattern(p: &str) -> Result<Vec<Piece>, String> {
    let mut out = Vec::new();
    let mut rest = p;
    while !rest.is_empty() {
        if let Some(r) = rest.strip_prefix("{{") {
            let end = r
                .find("}}")
                .ok_or_else(|| format!("unterminated reference in {p:?}"))?;
            let name = &r[..end];
            if !REFS.contains(&name) {
                return Err(format!("unknown reference {name:?} in {p:?}"));
            }
            out.push(Piece::Ref(name.to_owned()));
            rest = &r[end + 2..];
        } else if let Some(r) = rest.strip_prefix(' ') {
            if !matches!(out.last(), Some(Piece::Ref(_))) || !r.starts_with("{{") {
                return Err(format!("unexpected literal text in {p:?}"));
            }
            out.push(Piece::Space);
            rest = r;
        } else {
            return Err(format!("unexpected literal text in {p:?}"));
        }
    }
    if out.is_empty() {
        return Err("empty pattern".to_owned());
    }
    Ok(out)
}

/// The value lists pattern references draw from.
struct Pools {
    /// Reference → (source path, entries).
    lists: BTreeMap<String, (String, Vec<String>)>,
}

impl Pools {
    /// Starts with the two person pools.
    fn new(names: &Names) -> Self {
        let mut lists = BTreeMap::new();
        lists.insert(
            "person.firstName".to_owned(),
            ("the first-name pool".to_owned(), names.first_pool.clone()),
        );
        lists.insert(
            "person.lastName".to_owned(),
            ("the last-name pool".to_owned(), names.last_pool.clone()),
        );
        Self { lists }
    }

    /// The list for `name`, reading `location/<key>` on first use.
    fn get(&mut self, f: &mut Faker<'_>, name: &str) -> Result<&(String, Vec<String>), String> {
        if !self.lists.contains_key(name) {
            let key = name
                .strip_prefix("location.")
                .ok_or_else(|| format!("no pool for {name}"))?;
            let (path, raw) = f.list(&format!("location/{key}"))?;
            let cleaned: Vec<String> = raw.iter().map(|s| normalize(s)).collect();
            if cleaned.is_empty() {
                return Err(format!("{path} is empty"));
            }
            self.lists.insert(name.to_owned(), (path, cleaned));
        }
        self.lists
            .get(name)
            .ok_or_else(|| format!("no pool for {name}"))
    }
}

/// Expands patterns with [`SplitMix64::for_label`] until `cap` unique entries pass the display
/// rule or `cap * 64` draws are spent.
fn expand(
    f: &mut Faker<'_>,
    patterns: &[Vec<Piece>],
    pools: &mut Pools,
    cap: usize,
    lr: &mut ListReport,
) -> Result<Vec<String>, String> {
    let mut lists: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for p in patterns.iter().flatten() {
        if let Piece::Ref(name) = p {
            let (_, l) = pools.get(f, name)?;
            lists.insert(name.clone(), l.clone());
        }
    }
    let mut rng = SplitMix64::for_label(&lr.label);
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    let mut draws = 0;
    while out.len() < cap && draws < cap * 64 {
        draws += 1;
        let mut s = String::new();
        for piece in &patterns[rng.below(patterns.len())] {
            match piece {
                Piece::Space => s.push(' '),
                Piece::Ref(name) => {
                    let l = lists
                        .get(name)
                        .ok_or_else(|| format!("no pool for {name}"))?;
                    s.push_str(&l[rng.below(l.len())]);
                }
            }
        }
        let s = normalize(&s);
        if !display_ok(&s) {
            lr.dropped_rule += 1;
        } else if seen.insert(s.clone()) {
            out.push(s);
        } else {
            lr.duplicates += 1;
        }
    }
    lr.upstream = draws;
    Ok(out)
}

/// A plain or pattern-built list (streets or cities), capped and sorted.
fn place_list(
    f: &mut Faker<'_>,
    (pattern_key, list_key, extra): (Option<&str>, &str, Option<(&str, &str)>),
    label: &str,
    (cap, min): (usize, usize),
    pools: &mut Pools,
    rep: &mut CountryReport,
) -> Result<Vec<String>, String> {
    let mut lr = ListReport {
        label: label.to_owned(),
        ..ListReport::default()
    };
    let mut direct = Some(list_key.to_owned());
    let mut patterns = Vec::new();
    if let Some(key) = pattern_key {
        let (path, raw) = f.list(key)?;
        patterns = raw
            .iter()
            .map(|p| parse_pattern(p))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("{path}: {e}"))?;
        direct = match patterns.as_slice() {
            [p] => match p.as_slice() {
                [Piece::Ref(r)] => r.strip_prefix("location.").map(str::to_owned),
                _ => None,
            },
            _ => None,
        };
        lr.from = path;
    }
    if extra.is_some() && direct.is_none() {
        return Err(format!(
            "{label}: an extra list needs a single-reference pattern"
        ));
    }
    let mut out = if let Some(key) = direct {
        let (path, mut raw) = f.list(&format!("location/{key}"))?;
        lr.from = if lr.from.is_empty() {
            path
        } else {
            format!("{} → {path}", lr.from)
        };
        if let Some((locale, without)) = extra {
            let path = format!("src/locales/{locale}/location/{key}.ts");
            let text = f.inputs.read(&FAKER, &path)?;
            let Literal::List(more) =
                ts::parse_default(&text).map_err(|e| format!("{path}: {e}"))?
            else {
                return Err(format!("{path}: expected a list"));
            };
            let _ = write!(lr.from, " + {path} without entries containing {without:?}");
            raw.extend(more.into_iter().filter(|s| !s.contains(without)));
        }
        lr.upstream = raw.len();
        let kept = clean(&raw, &mut lr);
        lr.method = method(kept.len(), cap);
        sample(kept, cap, label)
    } else {
        lr.method = format!("pattern expansion, {} patterns (synthetic)", patterns.len());
        expand(f, &patterns, pools, cap, &mut lr)?
    };
    out.sort();
    lr.written = out.len();
    rep.lists.push(lr);
    if out.len() < min {
        return Err(format!("{label}: {} entries, fewer than {min}", out.len()));
    }
    Ok(out)
}

/// `[street]` from `location/street_pattern`.
fn streets(
    f: &mut Faker<'_>,
    c: &Country,
    limits: Limits,
    pools: &mut Pools,
    rep: &mut CountryReport,
) -> Result<Vec<String>, String> {
    if let Some((locale, without)) = c.extra_streets {
        rep.notes.push(format!(
            "streets: faker's {} street_name list is under the {}-entry minimum, so {locale}'s \
             street_name entries without {without:?} are appended (Swiss Standard German \
             spells ss, not ß): a reported deviation from faker's own chain",
            c.locale, limits.min_list
        ));
    }
    place_list(
        f,
        (
            Some("location/street_pattern"),
            "street_name",
            c.extra_streets,
        ),
        &format!("{}/street", c.code),
        (limits.street, limits.min_list),
        pools,
        rep,
    )
}

/// `[city]`: faker's real city list, or its city pattern expanded.
fn cities(
    f: &mut Faker<'_>,
    c: &Country,
    limits: Limits,
    pools: &mut Pools,
    rep: &mut CountryReport,
) -> Result<Vec<String>, String> {
    let label = format!("{}/city", c.code);
    match c.cities {
        Cities::Names(locale) => {
            let resolved = f.resolve("location/city_name").map(|(l, _)| l);
            if resolved.as_deref() != Some(locale) {
                return Err(format!(
                    "city_name resolves to {resolved:?}, expected {locale}"
                ));
            }
            rep.notes.push(format!(
                "cities: real names, faker {locale}/location/city_name.ts (the locale's \
                 city_pattern is not used)"
            ));
            place_list(
                f,
                (None, "city_name", None),
                &label,
                (limits.city, limits.min_list),
                pools,
                rep,
            )
        }
        Cities::Pattern => {
            let (path, raw) = f.list("location/city_pattern")?;
            if raw.iter().any(|p| p.contains("city_name")) {
                return Err(format!(
                    "{path} references city_name; configure Cities::Names"
                ));
            }
            rep.notes.push(format!(
                "cities: SYNTHETIC. faker has no real city list for this locale; {path} is \
                 expanded with the fixed seed (ADR 0079 §7 asks for real city names: reported \
                 deviation)"
            ));
            place_list(
                f,
                (Some("location/city_pattern"), "city_name", None),
                &label,
                (limits.city, limits.min_list),
                pools,
                rep,
            )
        }
    }
}

/// `[subdivision]` from CLDR.
fn subdivisions(
    inputs: &mut Inputs,
    shared: &mut Cldr,
    c: &Country,
    rep: &mut CountryReport,
) -> Result<Vec<(String, String)>, String> {
    let top = shared
        .containment
        .get(c.code)
        .ok_or_else(|| format!("no CLDR containment for {}", c.code))?
        .clone();
    for ex in c.exclude {
        if !top.iter().any(|t| t == ex) {
            return Err(format!("excluded {ex} is not a top-level subdivision"));
        }
    }
    let kept: Vec<String> = top
        .iter()
        .filter(|t| !c.exclude.contains(&t.as_str()))
        .cloned()
        .collect();
    let ids: Vec<String> = match c.level {
        Level::Top => kept,
        Level::Children => {
            let mut v = Vec::new();
            for g in &kept {
                v.extend(
                    shared
                        .containment
                        .get(g)
                        .ok_or_else(|| format!("{g} has no members"))?
                        .iter()
                        .cloned(),
                );
            }
            v
        }
    };
    if c.form == Form::Name && !shared.names.contains_key(c.lang) {
        let path = format!("common/subdivisions/{}.xml", c.lang);
        let text = inputs.read(&CLDR, &path)?;
        shared.names.insert(
            c.lang.to_owned(),
            cldr::subdivision_names(&text).map_err(|e| format!("{path}: {e}"))?,
        );
    }
    let mut out = Vec::new();
    let mut dropped = Vec::new();
    for id in &ids {
        let code = cldr::iso_code(c.code, id)?;
        let form = match c.form {
            Form::Code => code[3..].to_owned(),
            Form::Name => normalize(
                shared
                    .names
                    .get(c.lang)
                    .and_then(|n| n.get(id))
                    .ok_or_else(|| format!("no {} name for {id}", c.lang))?,
            ),
        };
        if display_ok(&form) {
            out.push((code, form));
        } else {
            dropped.push(format!("{code} {form:?}"));
        }
    }
    out.sort();
    let forms: BTreeSet<&str> = out.iter().map(|(_, f)| f.as_str()).collect();
    let codes: BTreeSet<&str> = out.iter().map(|(c, _)| c.as_str()).collect();
    if out.is_empty()
        || out.len() > MAX_SUBDIVISIONS
        || forms.len() != out.len()
        || codes.len() != out.len()
    {
        return Err(format!(
            "{} subdivisions, or a repeated code or form",
            out.len()
        ));
    }
    rep.notes.push(format!(
        "subdivisions: {} written ({}: {} candidates under CLDR's {} top-level entries{}); \
         written form: {}{}",
        out.len(),
        match c.level {
            Level::Top => "the top-level ISO 3166-2 entries of the CLDR containment",
            Level::Children => "the members of each top-level ISO 3166-2 entry",
        },
        ids.len(),
        top.len(),
        if c.exclude.is_empty() {
            String::new()
        } else {
            format!(", after excluding {:?}", c.exclude)
        },
        match c.form {
            Form::Code => "the ISO 3166-2 suffix (postal custom)".to_owned(),
            Form::Name => format!("the CLDR {} name", c.lang),
        },
        if dropped.is_empty() {
            String::new()
        } else {
            format!("; dropped by the display rule: {}", dropped.join(", "))
        },
    ));
    Ok(out)
}

/// Expands faker's `*` (letter or digit), which ADR 0079 §4 step 7 does not have, into every
/// `#`/`?` combination: the same set of outputs.
fn expand_stars(p: &str) -> Result<Vec<String>, String> {
    let stars = p.matches('*').count();
    if stars > 4 {
        return Err(format!("{p:?}: more than four '*'"));
    }
    let mut out = Vec::new();
    for mask in 0..(1u32 << stars) {
        let mut k = 0;
        let s: String = p
            .chars()
            .map(|ch| {
                if ch == '*' {
                    let bit = mask >> k & 1;
                    k += 1;
                    if bit == 0 { '#' } else { '?' }
                } else {
                    ch
                }
            })
            .collect();
        out.push(s);
    }
    Ok(out)
}

/// The country's `@postcode` patterns from `location/postcode`.
fn postcodes(f: &mut Faker<'_>, rep: &mut CountryReport) -> Result<Vec<String>, String> {
    let (_, path, text) = f.read("location/postcode")?;
    let mut note = String::new();
    let raw: Vec<String> = if let Ok(Literal::List(l)) = ts::parse_default(&text) {
        let mut v = Vec::new();
        for p in &l {
            v.extend(expand_stars(p)?);
        }
        if l.iter().any(|p| p.contains('*')) {
            " ('*' = letter or digit expanded into every '#'/'?' combination: the same outputs \
             as faker, other weights)"
                .clone_into(&mut note);
        }
        v
    } else if let Ok(caps) = ts::match_template(&text, GB_POSTCODE) {
        let [
            Capture::Strs(suffixes),
            Capture::Strs(extra),
            Capture::Strs(london),
            Capture::Strs(prefixes),
        ] = caps.as_slice()
        else {
            return Err(format!("{path}: unexpected captures"));
        };
        let mut v = Vec::new();
        for p in prefixes.iter().chain(london) {
            v.extend(suffixes.iter().map(|s| format!("{p}{s}")));
        }
        for p in london {
            v.extend(extra.iter().map(|s| format!("{p}{s}")));
        }
        " (faker's district shape, expanded 1:1)".clone_into(&mut note);
        v
    } else if let Ok(caps) = ts::match_template(&text, FR_POSTCODE) {
        fr_postcodes(&path, &caps)?
    } else if let Ok(caps) = ts::match_template(&text, NL_POSTCODE) {
        let [
            Capture::Strs(digits),
            Capture::Strs(letters),
            Capture::Strs(forbidden),
        ] = caps.as_slice()
        else {
            return Err(format!("{path}: unexpected captures"));
        };
        let az: Vec<String> = ('A'..='Z').map(String::from).collect();
        if *letters != az {
            return Err(format!("{path}: the letters are not A-Z"));
        }
        note = format!(
            " (compressed to one '?? ' pattern per digit prefix; '?' is uniform over A-Z, so the \
             pairs {forbidden:?} that faker excludes can appear)"
        );
        digits.iter().map(|d| format!("{d} ??")).collect()
    } else {
        return Err(format!(
            "{path}: neither a plain list nor one of the accepted code shapes (GB, FR, NL)"
        ));
    };
    let set: BTreeSet<String> = raw.into_iter().collect();
    if let Some(bad) = set.iter().find(|p| !postcode_ok(p)) {
        return Err(format!("{path}: postcode pattern {bad:?} breaks the rule"));
    }
    rep.notes.push(format!(
        "@postcode: {} pattern(s) from {path}{note}",
        set.len()
    ));
    Ok(set.into_iter().collect())
}

/// The FR shape: `range(a, b)` two-digit departments, then three-digit overseas prefixes.
fn fr_postcodes(path: &str, caps: &[Capture]) -> Result<Vec<String>, String> {
    let nums: Vec<u64> = caps
        .iter()
        .map(|c| match c {
            Capture::Num(n) => Ok(*n),
            _ => Err(format!("{path}: unexpected captures")),
        })
        .collect::<Result<_, _>>()?;
    let [
        metro_lo,
        metro_hi,
        over_lo,
        over_hi,
        single,
        last_lo,
        last_hi,
    ] = nums.as_slice()
    else {
        return Err(format!("{path}: unexpected captures"));
    };
    if !(1..=99).contains(metro_lo) || metro_lo > metro_hi || *metro_hi > 99 {
        return Err(format!("{path}: metropolitan range {metro_lo}..{metro_hi}"));
    }
    let mut patterns: Vec<String> = (*metro_lo..=*metro_hi)
        .map(|n| format!("{n:02}###"))
        .collect();
    for n in (*over_lo..=*over_hi)
        .chain([*single])
        .chain(*last_lo..=*last_hi)
    {
        if !(100..=999).contains(&n) {
            return Err(format!("{path}: overseas prefix {n}"));
        }
        patterns.push(format!("{n}##"));
    }
    Ok(patterns)
}

/// The `[postcode]` lines from `location/postcode_by_state` (US `number.int` ranges, or the CA
/// province letters).
fn by_state(
    f: &mut Faker<'_>,
    c: &Country,
    subdivisions: &[(String, String)],
    rep: &mut CountryReport,
) -> Result<Vec<(String, String)>, String> {
    let (_, path, text) = f.read("location/postcode_by_state")?;
    let mut per_key: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let note;
    if let Ok(Literal::Object(obj)) = ts::parse_default(&text) {
        for (k, v) in obj {
            let values = match v {
                Value::Str(s) => vec![s],
                Value::List(l) => l,
                Value::Template(_) => return Err(format!("{path}: template value for {k}")),
            };
            let set = per_key.entry(k.clone()).or_default();
            for s in values {
                set.extend(zip_prefixes(&s).map_err(|e| format!("{path}: {k}: {e}"))?);
            }
        }
        note = "number.int ranges widened to their 3-digit prefixes (\"995##\" covers 99500-99599 \
                even where faker's range starts at 99501)";
    } else {
        let caps = ts::match_template(&text, CA_BY_STATE).map_err(|e| format!("{path}: {e}"))?;
        let [Capture::Str(suffix), Capture::Obj(obj)] = caps.as_slice() else {
            return Err(format!("{path}: unexpected captures"));
        };
        if suffix != CA_SUFFIX.0 {
            return Err(format!("{path}: unexpected suffix regex {suffix:?}"));
        }
        for (k, v) in obj {
            let Value::Template(raw) = v else {
                return Err(format!("{path}: {k} is not a template"));
            };
            let inner = raw
                .strip_prefix("{{helpers.fromRegExp(")
                .and_then(|r| r.strip_suffix("${suffix})}}"))
                .ok_or_else(|| format!("{path}: {k}: unexpected template {raw:?}"))?;
            let letters = inner
                .strip_prefix('[')
                .and_then(|r| r.strip_suffix(']'))
                .unwrap_or(inner);
            if letters.is_empty() || !letters.bytes().all(|b| b.is_ascii_uppercase()) {
                return Err(format!("{path}: {k}: unexpected first letter {inner:?}"));
            }
            let set = per_key.entry(k.clone()).or_default();
            set.extend(letters.chars().map(|l| format!("{l}{}", CA_SUFFIX.1)));
        }
        note = "first letter per province from the regex; the regex's other letters, which \
                exclude D F I O Q U, become '?' (uniform over A-Z, ADR 0079 §4 step 7)";
    }
    let codes = super::code_set(subdivisions);
    let mut out = Vec::new();
    let mut skipped = Vec::new();
    for (k, set) in per_key {
        let code = format!("{}-{k}", c.code);
        if codes.contains(code.as_str()) {
            out.extend(set.into_iter().map(|p| (code.clone(), p)));
        } else {
            skipped.push(code);
        }
    }
    for (code, _) in subdivisions {
        if !out.iter().any(|(c2, _)| c2 == code) {
            return Err(format!("{path}: no postcode for {code}"));
        }
    }
    if out.len() > MAX_SUB_POSTCODES || out.iter().any(|(_, p)| !postcode_ok(p)) {
        return Err(format!(
            "{path}: {} per-subdivision patterns, or a bad one",
            out.len()
        ));
    }
    out.sort();
    rep.notes.push(format!(
        "[postcode]: {} lines from {path}; {note}{}",
        out.len(),
        if skipped.is_empty() {
            String::new()
        } else {
            format!(
                "; keys outside the subdivision list skipped: {}",
                skipped.join(", ")
            )
        }
    ));
    Ok(out)
}

/// The 3-digit ZIP prefixes of `0*{{number.int({"min": A,"max": B})}}`, as `ddd##` patterns.
fn zip_prefixes(s: &str) -> Result<Vec<String>, String> {
    let zeros = s.bytes().take_while(|&b| b == b'0').count();
    let inner = s[zeros..]
        .strip_prefix("{{number.int({\"min\": ")
        .and_then(|r| r.strip_suffix("})}}"))
        .ok_or_else(|| format!("unexpected value {s:?}"))?;
    let (lo, hi) = inner
        .split_once(",\"max\": ")
        .ok_or_else(|| format!("unexpected value {s:?}"))?;
    let parse = |t: &str| {
        if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("unexpected number in {s:?}"));
        }
        t.parse::<u32>().map_err(|e| format!("{s:?}: {e}"))
    };
    let (lo, hi) = (parse(lo)?, parse(hi)?);
    let width = u32::try_from(5usize.saturating_sub(zeros)).map_err(|_| "width".to_owned())?;
    if width == 0 || lo > hi || lo < 10u32.pow(width - 1) || hi >= 10u32.pow(width) {
        return Err(format!(
            "{s:?} does not give {width}-digit numbers after {zeros} zeros"
        ));
    }
    let pad = "0".repeat(zeros);
    let mut out = Vec::new();
    for block in lo / 100..=hi / 100 {
        let zip = format!("{pad}{}", (block * 100).max(lo));
        let p = format!("{}##", &zip[..3]);
        if !out.contains(&p) {
            out.push(p);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{Piece, expand_stars, fr_postcodes, parse_pattern, zip_prefixes};
    use crate::identity_data::ts::{Capture, match_template};

    #[test]
    fn patterns_accept_references_and_single_spaces_only() {
        assert_eq!(
            parse_pattern("{{person.firstName}} {{location.street_suffix}}").unwrap(),
            vec![
                Piece::Ref("person.firstName".into()),
                Piece::Space,
                Piece::Ref("location.street_suffix".into())
            ]
        );
        assert!(parse_pattern("{{location.city_prefix}}{{location.city_suffix}}").is_ok());
        for bad in [
            "{{person.jobTitle}}",
            "{{location.street_name}}  {{location.street_suffix}}",
            " {{location.street_name}}",
            "{{location.street_name}} ",
            "St. {{location.street_name}}",
            "{{location.street_name}}-{{location.street_suffix}}",
            "{{location.street_name",
            "{{number.int({\"min\": 1})}}",
            "",
        ] {
            assert!(parse_pattern(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn stars_expand_to_both_symbols() {
        assert_eq!(
            expand_stars("A## **").unwrap(),
            vec!["A## ##", "A## ?#", "A## #?", "A## ??"]
        );
        assert_eq!(expand_stars("####").unwrap(), vec!["####"]);
        assert!(expand_stars("*****").is_err());
    }

    #[test]
    fn zip_ranges_widen_to_prefixes() {
        assert_eq!(
            zip_prefixes("{{number.int({\"min\": 99501,\"max\": 99750})}}").unwrap(),
            vec!["995##", "996##", "997##"]
        );
        assert_eq!(
            zip_prefixes("0{{number.int({\"min\": 6390,\"max\": 6390})}}").unwrap(),
            vec!["063##"]
        );
        assert_eq!(
            zip_prefixes("00{{number.int({\"min\": 601,\"max\": 799})}}").unwrap(),
            vec!["006##", "007##"]
        );
        for bad in [
            "{{number.int({\"min\": 601,\"max\": 799})}}",
            "0{{number.int({\"min\": 60001,\"max\": 60002})}}",
            "{{number.int({\"min\": 9,\"max\": 1})}}",
            "{{number.int({ \"min\": 10000,\"max\": 10001})}}",
            "{{helpers.fromRegExp([0-9]{5})}}",
        ] {
            assert!(zip_prefixes(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn the_fr_shape_is_matched_exactly() {
        let src = "// note\nconst range = (start: number, end: number): number[] =>\n  \
                   Array.from({ length: end - start + 1 }, (_, index) => start + index);\n\nconst \
                   metropolitan = range(1, 3).map(\n  (department) => \
                   `${department.toString().padStart(2, '0')}###`\n);\n\nconst overseas = \
                   [...range(971, 972), 984, ...range(986, 986)].map(\n  (territory) => \
                   `${territory}##`\n);\n\nexport default [...metropolitan, ...overseas];\n";
        let caps = match_template(src, super::FR_POSTCODE).unwrap();
        assert_eq!(caps.len(), 7);
        assert_eq!(
            fr_postcodes("fr", &caps).unwrap(),
            vec![
                "01###", "02###", "03###", "971##", "972##", "984##", "986##"
            ]
        );
        assert!(match_template(&src.replace("###`", "##`"), super::FR_POSTCODE).is_err());
        assert!(fr_postcodes("fr", &[Capture::Num(1)]).is_err());
    }
}
