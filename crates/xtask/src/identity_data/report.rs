// SPDX-License-Identifier: AGPL-3.0-only

//! The generated part of [`super::SOURCES`]: output size and SHA-256, the verified input files
//! with their upstream URLs, the sampling rule, every list's counts and every country's
//! derivations. Everything outside the markers is written by hand and kept as it is.

use std::fmt::Write as _;

use super::{
    BEGIN, CLDR, Country, CountryReport, END, FAKER, Inputs, Limits, MAX_OUTPUT, OUTPUT, SEED,
    Upstream, hex_sha256,
};

/// The upstream of a manifest source id.
fn upstream(id: &str) -> &'static Upstream {
    if id == FAKER.id { &FAKER } else { &CLDR }
}

/// Renders the generated section, markers included.
pub(super) fn render(
    inputs: &Inputs,
    output: &str,
    sizes: &[(String, usize)],
    reports: &[CountryReport],
    limits: Limits,
    countries: &[Country],
) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "{BEGIN}\n\n## Generated report\n");
    let _ = writeln!(
        s,
        "- Output: `{OUTPUT}`, {} bytes of the {MAX_OUTPUT}-byte budget.\n- Output SHA-256: \
         `{}`\n",
        output.len(),
        hex_sha256(output.as_bytes())
    );
    s.push_str("| Country | Bytes | Phone patterns |\n|---|---:|---:|\n");
    for (code, size) in sizes {
        let phones = countries
            .iter()
            .find(|c| c.code == code)
            .map_or(0, |c| c.phones.len());
        let _ = writeln!(s, "| {code} | {size} | {phones} |");
    }
    s.push_str(
        "\n### Verified input files\n\nEach file was checked against the input block above \
                before the output was written.\n\n| Upstream | Tag | Commit | Path | SHA-256 | \
                Licence |\n|---|---|---|---|---|---|\n",
    );
    for (id, path, sha) in inputs.verified() {
        let u = upstream(id);
        let _ = writeln!(
            s,
            "| {id} | {} | `{}` | [{path}]({}/blob/{}/{path}) | `{sha}` | {} |",
            u.tag, u.commit, u.repo, u.tag, u.licence
        );
    }
    let _ = writeln!(
        s,
        "\n### Sampling and expansion\n\n- Generator: SplitMix64, seeded per list with \
         `{SEED:#018x}` XOR the 64-bit FNV-1a hash of the list label (for example \
         `DE/first.female`).\n- Caps: {} first names per sex, {} last names (per sex where \
         split), {} streets, {} cities, every subdivision. faker's lists are alphabetical, not \
         frequency-ordered, so a list over its cap keeps a partial Fisher-Yates sample (uniform \
         index by rejection) of that size.\n- Pattern lists: a pattern is drawn uniformly, then \
         each reference uniformly from its list, until the cap is reached or 64 × cap draws are \
         spent; entries that break the display rule or repeat are discarded and counted.\n- \
         Every list is written in ascending byte order; no list may have fewer than {} \
         entries.\n",
        limits.first, limits.last, limits.street, limits.city, limits.min_list
    );
    s.push_str(
        "### Lists\n\n\"Upstream\" is the number of upstream entries, or of pattern draws. \
         Dropped: by the display rule, or because the ascii form failed (an unmapped character \
         or an over-long result).\n\n| List | From | Method | Upstream | Dropped (rule) | \
         Dropped (ascii) | Duplicates | Written |\n|---|---|---|---:|---:|---:|---:|---:|\n",
    );
    for r in reports {
        for l in &r.lists {
            let _ = writeln!(
                s,
                "| {} | {} | {} | {} | {} | {} | {} | {} |",
                l.label,
                l.from,
                l.method,
                l.upstream,
                l.dropped_rule,
                l.dropped_ascii,
                l.duplicates,
                l.written
            );
        }
    }
    s.push_str("\n### Per-country derivations\n");
    for (r, c) in reports.iter().zip(countries) {
        let _ = writeln!(
            s,
            "\n#### {}\n\n- titles: {} / {}\n- transliteration: {}",
            r.code,
            c.title_male,
            c.title_female,
            if c.german {
                "[de] over [general]"
            } else {
                "[general]"
            }
        );
        for n in &r.notes {
            let _ = writeln!(s, "- {n}");
        }
        if c.phones.is_empty() {
            s.push_str("- @phone: none (no regulator citation verified)\n");
        } else {
            let _ = writeln!(s, "- @phone: {} patterns (citation above)", c.phones.len());
        }
    }
    let _ = write!(s, "\n{END}\n");
    s
}

/// Replaces the generated section of `sources` with `generated`.
///
/// # Errors
///
/// When the markers are missing, repeated or out of order.
pub(super) fn splice(sources: &str, generated: &str) -> Result<String, String> {
    let begin = sources
        .find(BEGIN)
        .ok_or("SOURCES.md has no BEGIN GENERATED marker")?;
    let end = sources
        .find(END)
        .ok_or("SOURCES.md has no END GENERATED marker")?;
    if sources.matches(BEGIN).count() != 1 || sources.matches(END).count() != 1 || end < begin {
        return Err("SOURCES.md: malformed generated markers".to_owned());
    }
    let after = sources[end + END.len()..]
        .strip_prefix('\n')
        .unwrap_or(&sources[end + END.len()..]);
    Ok(format!("{}{generated}{after}", &sources[..begin]))
}

#[cfg(test)]
mod tests {
    use super::{BEGIN, END, splice};

    #[test]
    fn splice_keeps_the_hand_written_parts() {
        let src = format!("# Title\n\nprose\n\n{BEGIN}\nold\n{END}\ntail\n");
        let gen_ = format!("{BEGIN}\nnew\n{END}\n");
        assert_eq!(
            splice(&src, &gen_).unwrap(),
            format!("# Title\n\nprose\n\n{BEGIN}\nnew\n{END}\ntail\n")
        );
        assert!(splice("no markers", &gen_).is_err());
        assert!(splice(&format!("{END}\n{BEGIN}\n"), &gen_).is_err());
        assert!(splice(&format!("{src}{BEGIN}\n"), &gen_).is_err());
    }
}
