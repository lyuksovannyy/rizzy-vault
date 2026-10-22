// SPDX-License-Identifier: AGPL-3.0-only

//! The M3 design-token pipeline (ADR 0014 §5, ADR 0019 §13, ROADMAP §4.5): reads the one
//! platform-neutral token source, [`SOURCE`], and generates the web CSS ([`CSS_OUTPUT`], the
//! only generated file an app in this repository imports) plus one file per other toolkit
//! ADR 0019 §13 names: Swift, Kotlin for Compose, a XAML resource dictionary and a QML singleton
//! ([`SWIFT_OUTPUT`], [`KOTLIN_OUTPUT`], [`XAML_OUTPUT`], [`QML_OUTPUT`]).
//!
//! No client in this repository consumes the four non-CSS files yet — the native clients live in
//! their own repositories and hold no Rust (ADR 0019 §6). They are generated and committed here
//! so `--check` catches drift today, and so the release workflow can ship them as the "Token
//! bundle" (ADR 0019 §7) once those repositories exist. Their colour tokens use each language's
//! native colour type (a lossless, standard conversion); their spacing, type-size, radius and
//! shadow tokens keep the web source's own CSS unit (`rem`/`px`) as a string, because converting
//! `rem`/`px` to that platform's point/dp system is a design decision for that client's own ADR,
//! not one this change makes.
//!
//! `cargo xtask generate-tokens` parses the source ([`parse`]), runs the WCAG AA contrast check
//! over every declared pair ([`check_contrast`]) and, only if every pair passes, writes all five
//! files. `cargo xtask generate-tokens --check` does the same but never writes: a contrast
//! failure is still reported, and otherwise every generated file's would-be bytes are compared
//! against what is already on disk, with every path that differs reported as stale.
//!
//! # The source format
//!
//! [`SOURCE`] is a JSON object with exactly six top-level keys:
//!
//! - `color`: `{ "light": {...}, "dark": {...} }`, each an object with exactly [`COLOR_KEYS`] as
//!   keys and a `#rrggbb` string value.
//! - `contrast-pairs`: an array of `{ "fg": <colour key>, "bg": <colour key>, "min-ratio": N }`.
//!   `fg` and `bg` must each name a key from [`COLOR_KEYS`]; ADR 0014 §5 says the check "covers
//!   the declared pairs only" — `--color-border` is the one pair the current source leaves
//!   undeclared (its own contrast is far below even the 3:1 floor against every background it is
//!   used with, but it is a decorative 1px rule, not one of the pairs ADR 0014 §5's own tokens.css
//!   comment named as declared, and changing its colour to pass is a design call for the owner,
//!   not an edit this change makes).
//! - `spacing`, `type`, `radius`: an object with exactly [`SPACING_KEYS`], [`TYPE_KEYS`] or
//!   [`RADIUS_KEYS`] as keys and a non-empty, single-line string value.
//! - `shadow`: `{ "light": {...}, "dark": {...} }`, each an object with exactly [`SHADOW_KEYS`]
//!   as keys and a non-empty, single-line string value. Shadow tokens are new in this change
//!   (ROADMAP §4.5 asks the one data file to cover "color incl. light/dark, spacing, type,
//!   radius, shadow"); nothing consumes `--shadow-1`/`--shadow-2` yet.
//!
//! Every reader here fails closed, like every other `xtask` reader ([`mod@crate::metadata`],
//! [`crate::manifest`]): a missing key, an extra key (catches a typo silently turning into "this
//! key is just missing, defaulted"), a value of the wrong JSON type, or a contrast pair naming a
//! colour key that does not exist in [`COLOR_KEYS`] is an error, never a silent default or skip.
//!
//! # Contrast
//!
//! [`contrast_ratio`] is the plain WCAG 2 relative-luminance formula. A pair's `min-ratio` is
//! `4.5` for normal text or `3.0` for large text/UI components (WCAG AA); the source file encodes
//! whichever applies per declared pair, so the check in [`check_contrast`] needs no separate
//! text-size classification. A `min-ratio` below [`WCAG_AA_FLOOR`] (3:1, the lowest ratio WCAG
//! 2 AA accepts for anything: SC 1.4.3 large text, SC 1.4.11 non-text) is a parse error, so a
//! pair can never be declared into passing below AA; a stricter ratio (AAA's 7:1) is allowed.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

use serde_json::{Map, Value};

/// The platform-neutral token source, relative to the workspace root (module docs).
pub(crate) const SOURCE: &str = "packages/ui/tokens/tokens.json";

/// The generated web CSS: the file `apps/web` and `apps/extension` import by path
/// (`@rizzy-vault/ui/tokens.css`, `packages/ui/package.json`'s `exports`). Replaces the M1
/// hand-written file, keeping every custom property name (ADR 0014 §5).
pub(crate) const CSS_OUTPUT: &str = "packages/ui/src/tokens.css";

/// The generated Swift token file (ADR 0019 §13, §2 "Platforms and toolkits": macOS/iOS).
pub(crate) const SWIFT_OUTPUT: &str = "packages/ui/tokens/generated/Tokens.swift";

/// The generated Kotlin (Compose) token file (ADR 0019 §13, §2: Android).
pub(crate) const KOTLIN_OUTPUT: &str = "packages/ui/tokens/generated/Tokens.kt";

/// The generated XAML resource dictionary (ADR 0019 §13, §2: Windows/WinUI 3).
pub(crate) const XAML_OUTPUT: &str = "packages/ui/tokens/generated/Tokens.xaml";

/// The generated QML singleton (ADR 0019 §13, §2: Linux/Qt 6 Quick).
pub(crate) const QML_OUTPUT: &str = "packages/ui/tokens/generated/Tokens.qml";

/// Every output this command writes, in the order it writes and checks them.
const OUTPUTS: [&str; 5] = [
    CSS_OUTPUT,
    SWIFT_OUTPUT,
    KOTLIN_OUTPUT,
    XAML_OUTPUT,
    QML_OUTPUT,
];

/// Colour token keys, in declaration order (the order every generated file lists them in). Both
/// themes, and every contrast pair's `fg`/`bg`, use exactly this key set.
pub(crate) const COLOR_KEYS: &[&str] = &[
    "bg",
    "surface",
    "border",
    "text",
    "text-muted",
    "accent",
    "on-accent",
    "danger",
    "on-danger",
    "warning-bg",
    "warning-text",
    "focus",
];

/// Spacing token keys (`--space-<key>`), in declaration order.
const SPACING_KEYS: &[&str] = &["1", "2", "3", "4", "6", "8"];

/// Type token keys (`--<key>`, the key itself already spelling out the property name), in
/// declaration order.
const TYPE_KEYS: &[&str] = &[
    "font-body",
    "font-mono",
    "font-size-small",
    "font-size-body",
    "font-size-title",
];

/// Radius token keys (`--radius-<key>`), in declaration order.
const RADIUS_KEYS: &[&str] = &["1", "2"];

/// Shadow token keys (`--shadow-<key>`), in declaration order.
const SHADOW_KEYS: &[&str] = &["1", "2"];

/// The lowest `min-ratio` a declared pair may ask for (module docs, "Contrast"): WCAG 2 AA's
/// 3:1, which applies to large text (SC 1.4.3) and to UI components and focus indicators
/// (SC 1.4.11). Normal text needs 4.5:1, which the source declares per pair.
pub(crate) const WCAG_AA_FLOOR: f64 = 3.0;

/// One declared WCAG AA contrast pair (module docs, "The source format").
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ContrastPair {
    /// The foreground colour key (text, or a control like the focus outline).
    pub(crate) fg: String,
    /// The background colour key it is checked against.
    pub(crate) bg: String,
    /// `4.5` (normal text) or `3.0` (large text/UI), WCAG AA.
    pub(crate) min_ratio: f64,
}

/// An ordered list of (key, value) string pairs, in a group's declared key order
/// ([`COLOR_KEYS`] and friends).
pub(crate) type Props = Vec<(String, String)>;

/// The fully parsed and validated token source (module docs).
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Tokens {
    /// Light-theme colours, keyed by [`COLOR_KEYS`].
    pub(crate) color_light: Props,
    /// Dark-theme colours, keyed by [`COLOR_KEYS`].
    pub(crate) color_dark: Props,
    /// Spacing values, keyed by [`SPACING_KEYS`].
    pub(crate) spacing: Props,
    /// Type values, keyed by [`TYPE_KEYS`].
    pub(crate) type_: Props,
    /// Radius values, keyed by [`RADIUS_KEYS`].
    pub(crate) radius: Props,
    /// Light-theme shadows, keyed by [`SHADOW_KEYS`].
    pub(crate) shadow_light: Props,
    /// Dark-theme shadows, keyed by [`SHADOW_KEYS`].
    pub(crate) shadow_dark: Props,
    /// Every declared contrast pair, checked in both themes.
    pub(crate) contrast_pairs: Vec<ContrastPair>,
}

impl Tokens {
    /// The value for `key` in a colour group ([`Self::color_light`]/[`Self::color_dark`]), or
    /// `""` if absent. [`parse`] guarantees every [`COLOR_KEYS`] entry is present, and
    /// [`parse_contrast_pairs`] rejects any `fg`/`bg` outside [`COLOR_KEYS`], so the fallback
    /// never fires on data this module produced.
    fn color<'a>(palette: &'a Props, key: &str) -> &'a str {
        palette
            .iter()
            .find(|(k, _)| k == key)
            .map_or("", |(_, v)| v.as_str())
    }
}

/// Checks that `map`'s keys are exactly `expected` (as a set): neither missing a key `expected`
/// names, nor holding one it does not (module docs, "fails closed").
///
/// # Errors
///
/// Returns a message naming `context` and every missing or unexpected key, sorted.
fn check_keys(map: &Map<String, Value>, expected: &[&str], context: &str) -> Result<(), String> {
    let expected_set: BTreeSet<&str> = expected.iter().copied().collect();
    let found: BTreeSet<&str> = map.keys().map(String::as_str).collect();
    let missing: Vec<&str> = expected_set.difference(&found).copied().collect();
    if !missing.is_empty() {
        return Err(format!("{context}: missing key(s) {missing:?}"));
    }
    let extra: Vec<&str> = found.difference(&expected_set).copied().collect();
    if !extra.is_empty() {
        return Err(format!("{context}: unexpected key(s) {extra:?}"));
    }
    Ok(())
}

/// Reads an object whose keys are exactly `keys`, as [`Props`] in `keys`' order.
///
/// # Errors
///
/// Returns a message when `value` is not an object, [`check_keys`] rejects its keys, or any
/// value is not a JSON string.
fn require_object(value: &Value, keys: &[&str], context: &str) -> Result<Props, String> {
    let Value::Object(map) = value else {
        return Err(format!("{context}: expected an object"));
    };
    check_keys(map, keys, context)?;
    let mut out = Vec::with_capacity(keys.len());
    for key in keys {
        let Some(Value::String(s)) = map.get(*key) else {
            return Err(format!("{context}.{key}: expected a string"));
        };
        out.push(((*key).to_owned(), s.clone()));
    }
    Ok(out)
}

/// Whether `s` is a `#rrggbb` colour (lowercase or uppercase hex digits).
pub(crate) fn is_hex_color(s: &str) -> bool {
    s.len() == 7 && s.starts_with('#') && s[1..].chars().all(|c| c.is_ascii_hexdigit())
}

/// Checks every value in `props` is [`is_hex_color`].
///
/// # Errors
///
/// Returns a message naming the first offending key.
fn validate_hex_colors(props: &Props, context: &str) -> Result<(), String> {
    for (key, value) in props {
        if !is_hex_color(value) {
            return Err(format!(
                "{context}.{key}: {value:?} is not a `#rrggbb` colour"
            ));
        }
    }
    Ok(())
}

/// Checks every value in `props` is non-empty and holds no line break (module docs: the CSS and
/// per-toolkit renderers emit these as one-line declarations).
///
/// # Errors
///
/// Returns a message naming the first offending key.
fn validate_single_line(props: &Props, context: &str) -> Result<(), String> {
    for (key, value) in props {
        if value.is_empty() || value.contains(['\n', '\r']) {
            return Err(format!(
                "{context}.{key}: must be a non-empty, single-line value, found {value:?}"
            ));
        }
    }
    Ok(())
}

/// Reads a `{ "light": {...}, "dark": {...} }` group ([`color`][Value::Object] or `shadow`).
///
/// # Errors
///
/// Returns a message when `value` is not an object, it does not have exactly `light` and `dark`,
/// or either side fails [`require_object`].
fn require_theme_pair(
    value: &Value,
    keys: &[&str],
    context: &str,
) -> Result<(Props, Props), String> {
    let Value::Object(map) = value else {
        return Err(format!("{context}: expected an object"));
    };
    check_keys(map, &["light", "dark"], context)?;
    let light = require_object(
        map.get("light")
            .ok_or_else(|| format!("{context}.light: missing"))?,
        keys,
        &format!("{context}.light"),
    )?;
    let dark = require_object(
        map.get("dark")
            .ok_or_else(|| format!("{context}.dark: missing"))?,
        keys,
        &format!("{context}.dark"),
    )?;
    Ok((light, dark))
}

/// Reads the `contrast-pairs` array (module docs, "The source format").
///
/// # Errors
///
/// Returns a message when `value` is not an array, an entry is not an object with exactly
/// `fg`/`bg`/`min-ratio`, `fg`/`bg` is not a string naming a [`COLOR_KEYS`] entry, `min-ratio` is
/// not a number of at least [`WCAG_AA_FLOOR`], or any of this is malformed in the entry's index.
fn parse_contrast_pairs(value: &Value, context: &str) -> Result<Vec<ContrastPair>, String> {
    let Value::Array(items) = value else {
        return Err(format!("{context}: expected an array"));
    };
    let mut out = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let entry_context = format!("{context}[{i}]");
        let Value::Object(obj) = item else {
            return Err(format!("{entry_context}: expected an object"));
        };
        check_keys(obj, &["fg", "bg", "min-ratio"], &entry_context)?;
        let Some(Value::String(fg)) = obj.get("fg") else {
            return Err(format!("{entry_context}.fg: expected a string"));
        };
        let Some(Value::String(bg)) = obj.get("bg") else {
            return Err(format!("{entry_context}.bg: expected a string"));
        };
        let Some(min_ratio) = obj.get("min-ratio").and_then(Value::as_f64) else {
            return Err(format!("{entry_context}.min-ratio: expected a number"));
        };
        if !COLOR_KEYS.contains(&fg.as_str()) {
            return Err(format!("{entry_context}.fg: unknown colour key {fg:?}"));
        }
        if !COLOR_KEYS.contains(&bg.as_str()) {
            return Err(format!("{entry_context}.bg: unknown colour key {bg:?}"));
        }
        if min_ratio.is_nan() || min_ratio < WCAG_AA_FLOOR {
            return Err(format!(
                "{entry_context}.min-ratio: must be at least {WCAG_AA_FLOOR} (WCAG AA), found {min_ratio}"
            ));
        }
        out.push(ContrastPair {
            fg: fg.clone(),
            bg: bg.clone(),
            min_ratio,
        });
    }
    Ok(out)
}

/// Parses and validates [`SOURCE`]'s contents (module docs, "The source format" and "fails
/// closed").
///
/// # Errors
///
/// Returns a message for invalid JSON, or the first validation failure found.
pub(crate) fn parse(text: &str) -> Result<Tokens, String> {
    let value: Value =
        serde_json::from_str(text).map_err(|e| format!("{SOURCE}: invalid JSON: {e}"))?;
    let Value::Object(top) = &value else {
        return Err(format!("{SOURCE}: expected a top-level object"));
    };
    check_keys(
        top,
        &[
            "color",
            "contrast-pairs",
            "spacing",
            "type",
            "radius",
            "shadow",
        ],
        SOURCE,
    )?;

    let color = top
        .get("color")
        .ok_or_else(|| format!("{SOURCE}.color: missing"))?;
    let (color_light, color_dark) =
        require_theme_pair(color, COLOR_KEYS, &format!("{SOURCE}.color"))?;
    validate_hex_colors(&color_light, &format!("{SOURCE}.color.light"))?;
    validate_hex_colors(&color_dark, &format!("{SOURCE}.color.dark"))?;

    let spacing = require_object(
        top.get("spacing")
            .ok_or_else(|| format!("{SOURCE}.spacing: missing"))?,
        SPACING_KEYS,
        &format!("{SOURCE}.spacing"),
    )?;
    validate_single_line(&spacing, &format!("{SOURCE}.spacing"))?;

    let type_ = require_object(
        top.get("type")
            .ok_or_else(|| format!("{SOURCE}.type: missing"))?,
        TYPE_KEYS,
        &format!("{SOURCE}.type"),
    )?;
    validate_single_line(&type_, &format!("{SOURCE}.type"))?;

    let radius = require_object(
        top.get("radius")
            .ok_or_else(|| format!("{SOURCE}.radius: missing"))?,
        RADIUS_KEYS,
        &format!("{SOURCE}.radius"),
    )?;
    validate_single_line(&radius, &format!("{SOURCE}.radius"))?;

    let shadow = top
        .get("shadow")
        .ok_or_else(|| format!("{SOURCE}.shadow: missing"))?;
    let (shadow_light, shadow_dark) =
        require_theme_pair(shadow, SHADOW_KEYS, &format!("{SOURCE}.shadow"))?;
    validate_single_line(&shadow_light, &format!("{SOURCE}.shadow.light"))?;
    validate_single_line(&shadow_dark, &format!("{SOURCE}.shadow.dark"))?;

    let contrast_pairs = parse_contrast_pairs(
        top.get("contrast-pairs")
            .ok_or_else(|| format!("{SOURCE}.contrast-pairs: missing"))?,
        &format!("{SOURCE}.contrast-pairs"),
    )?;

    Ok(Tokens {
        color_light,
        color_dark,
        spacing,
        type_,
        radius,
        shadow_light,
        shadow_dark,
        contrast_pairs,
    })
}

/// One sRGB channel (0-255) to linear light, the WCAG 2 relative-luminance formula's first step.
fn srgb_to_linear(channel: u8) -> f64 {
    let c = f64::from(channel) / 255.0;
    if c <= 0.040_45 {
        c / 12.92
    } else {
        ((c + 0.055) / 1.055).powf(2.4)
    }
}

/// The relative luminance of a `#rrggbb` colour. The caller guarantees `hex` is
/// [`is_hex_color`]; a channel that somehow fails to parse reads as `0` rather than panicking
/// (CLAUDE.md bans `unwrap`/`expect`/`panic!` outside tests), which cannot happen on validated
/// input.
fn relative_luminance(hex: &str) -> f64 {
    let channel = |range: std::ops::Range<usize>| {
        hex.get(range)
            .and_then(|s| u8::from_str_radix(s, 16).ok())
            .unwrap_or(0)
    };
    let r = channel(1..3);
    let g = channel(3..5);
    let b = channel(5..7);
    0.2126 * srgb_to_linear(r) + 0.7152 * srgb_to_linear(g) + 0.0722 * srgb_to_linear(b)
}

/// The WCAG 2 contrast ratio between two `#rrggbb` colours: `(lighter + 0.05) / (darker + 0.05)`
/// over their relative luminances. Always >= 1.0; symmetric in its two arguments.
pub(crate) fn contrast_ratio(a: &str, b: &str) -> f64 {
    let la = relative_luminance(a);
    let lb = relative_luminance(b);
    let (lighter, darker) = if la >= lb { (la, lb) } else { (lb, la) };
    (lighter + 0.05) / (darker + 0.05)
}

/// Checks every declared contrast pair in both themes (module docs, "Contrast").
///
/// Returns one message per failing (theme, pair), sorted by theme then declaration order; empty
/// when every pair passes.
pub(crate) fn check_contrast(tokens: &Tokens) -> Vec<String> {
    let mut out = Vec::new();
    for (theme, palette) in [("light", &tokens.color_light), ("dark", &tokens.color_dark)] {
        for pair in &tokens.contrast_pairs {
            let fg = Tokens::color(palette, &pair.fg);
            let bg = Tokens::color(palette, &pair.bg);
            let ratio = contrast_ratio(fg, bg);
            if ratio < pair.min_ratio {
                out.push(format!(
                    "{theme} theme: --color-{} ({fg}) on --color-{} ({bg}) is {ratio:.2}:1, needs \
                     >= {}:1 (WCAG AA, ADR 0014 §5)",
                    pair.fg, pair.bg, pair.min_ratio
                ));
            }
        }
    }
    out
}

/// `kebab-case` to `camelCase` (`"text-muted"` -> `"textMuted"`, `"bg"` -> `"bg"`), used for
/// Swift/Kotlin/QML identifiers.
fn kebab_to_camel(s: &str) -> String {
    let mut out = String::new();
    for (i, part) in s.split('-').enumerate() {
        if i == 0 {
            out.push_str(part);
        } else {
            let mut chars = part.chars();
            if let Some(first) = chars.next() {
                out.extend(first.to_uppercase());
                out.push_str(chars.as_str());
            }
        }
    }
    out
}

/// `kebab-case` to `PascalCase` (`"text-muted"` -> `"TextMuted"`), used for XAML `x:Key`s.
fn kebab_to_pascal(s: &str) -> String {
    let camel = kebab_to_camel(s);
    let mut chars = camel.chars();
    chars
        .next()
        .map(|first| first.to_uppercase().collect::<String>() + chars.as_str())
        .unwrap_or_default()
}

/// A `#rrggbb` string's channels as `(r, g, b)`. The caller guarantees [`is_hex_color`].
fn hex_channels(hex: &str) -> (u8, u8, u8) {
    let channel = |range: std::ops::Range<usize>| {
        hex.get(range)
            .and_then(|s| u8::from_str_radix(s, 16).ok())
            .unwrap_or(0)
    };
    (channel(1..3), channel(3..5), channel(5..7))
}

/// `#rrggbb` as a Kotlin `0xFFrrggbb` ARGB literal (opaque).
fn kotlin_color_literal(hex: &str) -> String {
    let (r, g, b) = hex_channels(hex);
    format!("0xFF{r:02X}{g:02X}{b:02X}")
}

/// Appends one `--name: value;` declaration at `indent`.
fn push_decl(out: &mut String, indent: &str, name: &str, value: &str) {
    let _ = writeln!(out, "{indent}--{name}: {value};");
}

/// Appends every colour and shadow custom property for one theme, at `indent` (module docs: the
/// two groups that vary by theme).
fn push_theme_vars(out: &mut String, colors: &Props, shadows: &Props, indent: &str) {
    for (key, value) in colors {
        push_decl(out, indent, &format!("color-{key}"), value);
    }
    let _ = writeln!(out);
    for (key, value) in shadows {
        push_decl(out, indent, &format!("shadow-{key}"), value);
    }
}

/// Joins `items` as English prose: `"a"`, `"a and b"` or `"a, b and c"` (no Oxford comma, matching
/// this module's hand-written prose). Empty input yields `""`.
fn and_join(items: &[String]) -> String {
    match items.len() {
        0 => String::new(),
        1 => items[0].clone(),
        _ => {
            let last = &items[items.len() - 1];
            let rest = &items[..items.len() - 1];
            format!("{} and {last}", rest.join(", "))
        }
    }
}

/// Splits `text` on spaces, like [`str::split_whitespace`], except a space inside a parenthesised
/// group (`(--color-x, --color-y)`) never splits: the whole group, including the space after its
/// internal comma, comes back as one token. [`wrap_comment`] uses this so word-wrap can never
/// break a contrast pair across two lines, which would make it unfindable as one substring.
fn atomic_words(text: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();
    for ch in text.chars() {
        match ch {
            ' ' if depth == 0 => {
                if !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }
            }
            '(' => {
                depth += 1;
                current.push(ch);
            }
            ')' => {
                depth -= 1;
                current.push(ch);
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

/// Greedy word-wrap: breaks `text` into lines of at most `width` columns ([`atomic_words`]'
/// tokens, so a parenthesised contrast pair is never split across lines — a single token longer
/// than `width` still gets its own line), joined by `"\n   "` to match this file's existing
/// three-space continuation-line style. Deterministic for a given `text`/`width`, so the
/// generated file's bytes are stable and `--check` round-trips.
fn wrap_comment(text: &str, width: usize) -> String {
    let mut lines: Vec<String> = Vec::new();
    let mut current = String::new();
    for word in atomic_words(text) {
        let candidate_len = if current.is_empty() {
            word.len()
        } else {
            current.len() + 1 + word.len()
        };
        if !current.is_empty() && candidate_len > width {
            lines.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(&word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines.join("\n   ")
}

/// Builds the generated CSS header's "Colour: ..." paragraph from `tokens.contrast_pairs` itself
/// (never a string literal — the SSOT violation a review found: the paragraph used to be a fixed
/// literal with no connection to the data `check_contrast` actually validates, so it silently
/// went stale the moment `contrast-pairs` changed, and nothing — not `--check`, not CI — could
/// catch it, since the same literal text was reproduced identically on every run). Every
/// [`COLOR_KEYS`] entry absent from every pair's `fg`/`bg` is named as undeclared, also derived,
/// for the same reason.
fn contrast_pairs_paragraph(tokens: &Tokens) -> String {
    let pairs: Vec<String> = tokens
        .contrast_pairs
        .iter()
        .map(|p| format!("(--color-{}, --color-{})", p.fg, p.bg))
        .collect();
    let declared: BTreeSet<&str> = tokens
        .contrast_pairs
        .iter()
        .flat_map(|p| [p.fg.as_str(), p.bg.as_str()])
        .collect();
    let undeclared: Vec<String> = COLOR_KEYS
        .iter()
        .filter(|key| !declared.contains(*key))
        .map(|key| format!("--color-{key}"))
        .collect();
    let undeclared_sentence = if undeclared.is_empty() {
        "Every colour key appears in at least one declared pair.".to_owned()
    } else {
        let verb = if undeclared.len() == 1 { "is" } else { "are" };
        format!(
            "{} {verb} not declared and not checked.",
            and_join(&undeclared)
        )
    };
    if pairs.is_empty() {
        format!(
            "Colour: no WCAG AA pairs are declared, so `cargo xtask generate-tokens` checks \
             none (ADR 0014 §5; it covers the declared pairs only). {undeclared_sentence}"
        )
    } else {
        format!(
            "Colour: the WCAG AA pairs `cargo xtask generate-tokens` checks (ADR 0014 §5; it \
             covers the declared pairs only) are {}. {undeclared_sentence}",
            and_join(&pairs)
        )
    }
}

/// Renders [`CSS_OUTPUT`] from `tokens`: the same selectors and custom property names as the M1
/// hand-written file (ADR 0014 §5), plus the new `--shadow-*` properties.
pub(crate) fn render_css(tokens: &Tokens) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "/* SPDX-License-Identifier: AGPL-3.0-only */");
    let _ = writeln!(out);
    let colour_paragraph = wrap_comment(&contrast_pairs_paragraph(tokens), 88);
    let _ = writeln!(
        out,
        "/* GENERATED FILE — do not edit by hand. Source: {SOURCE}; regenerate with\n   \
         `cargo xtask generate-tokens` (ADR 0014 §5, ADR 0019 §13). `cargo xtask\n   \
         generate-tokens --check` fails CI if this file is stale. Every custom property name is\n   \
         kept from the M1 hand-written set, so nothing that reads this file changes.\n\n   \
         {colour_paragraph} */"
    );
    let _ = writeln!(out);
    let _ = writeln!(out, ":root {{");
    let _ = writeln!(out, "  color-scheme: light dark;");
    let _ = writeln!(out);
    for (key, value) in &tokens.color_light {
        push_decl(&mut out, "  ", &format!("color-{key}"), value);
    }
    let _ = writeln!(out);
    for (key, value) in &tokens.spacing {
        push_decl(&mut out, "  ", &format!("space-{key}"), value);
    }
    let _ = writeln!(out);
    for (key, value) in &tokens.type_ {
        push_decl(&mut out, "  ", key, value);
    }
    let _ = writeln!(out);
    for (key, value) in &tokens.radius {
        push_decl(&mut out, "  ", &format!("radius-{key}"), value);
    }
    let _ = writeln!(out);
    for (key, value) in &tokens.shadow_light {
        push_decl(&mut out, "  ", &format!("shadow-{key}"), value);
    }
    let _ = writeln!(out, "}}");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "/* The theme choice: \"system\" follows `prefers-color-scheme` below with no attribute\n   \
         set; \"light\"/\"dark\" is forced by `data-theme` on the document root regardless of the\n   \
         system scheme (apps/web/src/theme.ts). */"
    );
    let _ = writeln!(out, "@media (prefers-color-scheme: dark) {{");
    let _ = writeln!(out, "  :root:not([data-theme=\"light\"]) {{");
    push_theme_vars(&mut out, &tokens.color_dark, &tokens.shadow_dark, "    ");
    let _ = writeln!(out, "  }}");
    let _ = writeln!(out, "}}");
    let _ = writeln!(out);
    let _ = writeln!(out, ":root[data-theme=\"dark\"] {{");
    push_theme_vars(&mut out, &tokens.color_dark, &tokens.shadow_dark, "  ");
    let _ = writeln!(out, "}}");
    out
}

/// A shared header for every per-toolkit generated file: `comment(line)` wraps each line in that
/// language's comment syntax.
fn generated_header(comment: impl Fn(&str) -> String) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{}",
        comment("GENERATED FILE — do not edit by hand. Source: packages/ui/tokens/tokens.json;")
    );
    let _ = writeln!(
        out,
        "{}",
        comment("regenerate with `cargo xtask generate-tokens` (ADR 0014 §5, ADR 0019 §13).")
    );
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "{}",
        comment("No client in this repository consumes this file yet (ADR 0019 §6); it exists so")
    );
    let _ = writeln!(
        out,
        "{}",
        comment("the release workflow can ship it in the token bundle (ADR 0019 §7) once that")
    );
    let _ = writeln!(out, "{}", comment("client repository exists."));
    out
}

/// Renders [`SWIFT_OUTPUT`].
pub(crate) fn render_swift(tokens: &Tokens) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "// SPDX-License-Identifier: AGPL-3.0-only");
    let _ = writeln!(out);
    let _ = write!(out, "{}", generated_header(|l| format!("// {l}")));
    let _ = writeln!(out);
    let _ = writeln!(out, "import Foundation");
    let _ = writeln!(out, "import SwiftUI");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "/// Design tokens generated from the platform-neutral source (ADR 0014 §5)."
    );
    let _ = writeln!(out, "public enum RizzyTokens {{");
    let _ = writeln!(out, "    public struct ColorPalette {{");
    for key in COLOR_KEYS {
        let _ = writeln!(out, "        public let {}: Color", kebab_to_camel(key));
    }
    let _ = writeln!(out, "    }}");
    let _ = writeln!(out);
    for (name, palette) in [("light", &tokens.color_light), ("dark", &tokens.color_dark)] {
        let fields = COLOR_KEYS
            .iter()
            .map(|key| {
                format!(
                    "{}: Color(hex: \"{}\")",
                    kebab_to_camel(key),
                    Tokens::color(palette, key)
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(out, "    public static let {name} = ColorPalette({fields})");
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "    // Spacing, type and radius keep the web source's own CSS unit as a string (module"
    );
    let _ = writeln!(
        out,
        "    // docs on `generate-tokens` in crates/xtask/src/tokens.rs)."
    );
    for (key, value) in &tokens.spacing {
        let _ = writeln!(out, "    public static let space{key} = \"{value}\"");
    }
    for (key, value) in &tokens.type_ {
        let _ = writeln!(
            out,
            "    public static let {} = \"{}\"",
            kebab_to_camel(key),
            value.replace('"', "\\\"")
        );
    }
    for (key, value) in &tokens.radius {
        let _ = writeln!(out, "    public static let radius{key} = \"{value}\"");
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "    public struct ShadowPalette {{");
    for key in SHADOW_KEYS {
        let _ = writeln!(out, "        public let shadow{key}: String");
    }
    let _ = writeln!(out, "    }}");
    for (name, shadows) in [
        ("Light", &tokens.shadow_light),
        ("Dark", &tokens.shadow_dark),
    ] {
        let fields = SHADOW_KEYS
            .iter()
            .map(|key| format!("shadow{key}: \"{}\"", Tokens::color(shadows, key)))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            out,
            "    public static let shadow{name} = ShadowPalette({fields})"
        );
    }
    let _ = writeln!(out, "}}");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "/// Builds a `Color` from a `#rrggbb` string; the source only emits that form."
    );
    let _ = writeln!(out, "extension Color {{");
    let _ = writeln!(out, "    init(hex: String) {{");
    let _ = writeln!(
        out,
        "        let digits = hex.trimmingCharacters(in: CharacterSet(charactersIn: \"#\"))"
    );
    let _ = writeln!(out, "        var value: UInt64 = 0");
    let _ = writeln!(out, "        Scanner(string: digits).scanHexInt64(&value)");
    let _ = writeln!(
        out,
        "        self.init(red: Double((value & 0xFF0000) >> 16) / 255,\n                  \
         green: Double((value & 0x00FF00) >> 8) / 255,\n                  \
         blue: Double(value & 0x0000FF) / 255)"
    );
    let _ = writeln!(out, "    }}");
    let _ = writeln!(out, "}}");
    out
}

/// Renders [`KOTLIN_OUTPUT`].
pub(crate) fn render_kotlin(tokens: &Tokens) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "// SPDX-License-Identifier: AGPL-3.0-only");
    let _ = writeln!(out);
    let _ = write!(out, "{}", generated_header(|l| format!("// {l}")));
    let _ = writeln!(out);
    let _ = writeln!(out, "package com.rizzyvault.tokens");
    let _ = writeln!(out);
    let _ = writeln!(out, "import androidx.compose.ui.graphics.Color");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "/** Design tokens generated from the platform-neutral source (ADR 0014 §5). */"
    );
    let _ = writeln!(out, "object RizzyTokens {{");
    let _ = writeln!(out, "    data class ColorPalette(");
    for key in COLOR_KEYS {
        let _ = writeln!(out, "        val {}: Color,", kebab_to_camel(key));
    }
    let _ = writeln!(out, "    )");
    let _ = writeln!(out);
    for (name, palette) in [("light", &tokens.color_light), ("dark", &tokens.color_dark)] {
        let fields = COLOR_KEYS
            .iter()
            .map(|key| {
                format!(
                    "{} = Color({})",
                    kebab_to_camel(key),
                    kotlin_color_literal(Tokens::color(palette, key))
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(out, "    val {name} = ColorPalette({fields})");
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "    // Spacing, type and radius keep the web source's own CSS unit as a string (module"
    );
    let _ = writeln!(
        out,
        "    // docs on `generate-tokens` in crates/xtask/src/tokens.rs)."
    );
    for (key, value) in &tokens.spacing {
        let _ = writeln!(out, "    const val space{key} = \"{value}\"");
    }
    for (key, value) in &tokens.type_ {
        let _ = writeln!(
            out,
            "    const val {} = \"{}\"",
            kebab_to_camel(key),
            value.replace('"', "\\\"")
        );
    }
    for (key, value) in &tokens.radius {
        let _ = writeln!(out, "    const val radius{key} = \"{value}\"");
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "    data class ShadowPalette(");
    for key in SHADOW_KEYS {
        let _ = writeln!(out, "        val shadow{key}: String,");
    }
    let _ = writeln!(out, "    )");
    for (name, shadows) in [
        ("Light", &tokens.shadow_light),
        ("Dark", &tokens.shadow_dark),
    ] {
        let fields = SHADOW_KEYS
            .iter()
            .map(|key| format!("shadow{key} = \"{}\"", Tokens::color(shadows, key)))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(out, "    val shadow{name} = ShadowPalette({fields})");
    }
    let _ = writeln!(out, "}}");
    out
}

/// Renders [`XAML_OUTPUT`].
pub(crate) fn render_xaml(tokens: &Tokens) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "<!-- SPDX-License-Identifier: AGPL-3.0-only -->");
    let _ = writeln!(out);
    let _ = write!(out, "{}", generated_header(|l| format!("<!-- {l} -->")));
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "<ResourceDictionary\n    xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\"\n    xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\">"
    );
    let _ = writeln!(out, "  <ResourceDictionary.ThemeDictionaries>");
    for (name, palette) in [("Light", &tokens.color_light), ("Dark", &tokens.color_dark)] {
        let _ = writeln!(out, "    <ResourceDictionary x:Key=\"{name}\">");
        for key in COLOR_KEYS {
            let pascal = kebab_to_pascal(key);
            let value = Tokens::color(palette, key);
            let _ = writeln!(out, "      <Color x:Key=\"Color{pascal}\">{value}</Color>");
            let _ = writeln!(
                out,
                "      <SolidColorBrush x:Key=\"Brush{pascal}\" Color=\"{{StaticResource Color{pascal}}}\" />"
            );
        }
        let _ = writeln!(out, "    </ResourceDictionary>");
    }
    let _ = writeln!(
        out,
        "    <!-- HighContrast intentionally left empty: WinUI then leaves the system theme brushes -->"
    );
    let _ = writeln!(
        out,
        "    <!-- untouched (ADR 0019 §13's documented alternative), instead of a SystemColors -->"
    );
    let _ = writeln!(
        out,
        "    <!-- mapping invented here that no WinUI build in this repository can verify. -->"
    );
    let _ = writeln!(out, "    <ResourceDictionary x:Key=\"HighContrast\" />");
    let _ = writeln!(out, "  </ResourceDictionary.ThemeDictionaries>");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "  <!-- Spacing, type and radius keep the web source's own CSS unit as a string resource -->"
    );
    let _ = writeln!(
        out,
        "  <!-- (module docs on `generate-tokens` in crates/xtask/src/tokens.rs). -->"
    );
    for (key, value) in &tokens.spacing {
        let _ = writeln!(out, "  <x:String x:Key=\"Space{key}\">{value}</x:String>");
    }
    for (key, value) in &tokens.type_ {
        let _ = writeln!(
            out,
            "  <x:String x:Key=\"{}\">{}</x:String>",
            kebab_to_pascal(key),
            xml_escape(value)
        );
    }
    for (key, value) in &tokens.radius {
        let _ = writeln!(out, "  <x:String x:Key=\"Radius{key}\">{value}</x:String>");
    }
    for (name, shadows) in [
        ("Light", &tokens.shadow_light),
        ("Dark", &tokens.shadow_dark),
    ] {
        for key in SHADOW_KEYS {
            let value = Tokens::color(shadows, key);
            let _ = writeln!(
                out,
                "  <x:String x:Key=\"Shadow{name}{key}\">{}</x:String>",
                xml_escape(value)
            );
        }
    }
    let _ = writeln!(out, "</ResourceDictionary>");
    out
}

/// Escapes `&`, `<` and `>` for XML text content.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Renders [`QML_OUTPUT`].
pub(crate) fn render_qml(tokens: &Tokens) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "// SPDX-License-Identifier: AGPL-3.0-only");
    let _ = writeln!(out);
    let _ = write!(out, "{}", generated_header(|l| format!("// {l}")));
    let _ = writeln!(out);
    let _ = writeln!(out, "pragma Singleton");
    let _ = writeln!(out, "import QtQml 2.15");
    let _ = writeln!(out);
    let _ = writeln!(out, "QtObject {{");
    for (name, palette) in [("light", &tokens.color_light), ("dark", &tokens.color_dark)] {
        let _ = writeln!(out, "    readonly property QtObject {name}: QtObject {{");
        for key in COLOR_KEYS {
            let _ = writeln!(
                out,
                "        readonly property color {}: \"{}\"",
                kebab_to_camel(key),
                Tokens::color(palette, key)
            );
        }
        let _ = writeln!(out, "    }}");
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "    // Spacing, type and radius keep the web source's own CSS unit as a string (module"
    );
    let _ = writeln!(
        out,
        "    // docs on `generate-tokens` in crates/xtask/src/tokens.rs)."
    );
    for (key, value) in &tokens.spacing {
        let _ = writeln!(out, "    readonly property string space{key}: \"{value}\"");
    }
    for (key, value) in &tokens.type_ {
        let _ = writeln!(
            out,
            "    readonly property string {}: \"{}\"",
            kebab_to_camel(key),
            value.replace('"', "\\\"")
        );
    }
    for (key, value) in &tokens.radius {
        let _ = writeln!(out, "    readonly property string radius{key}: \"{value}\"");
    }
    let _ = writeln!(out);
    for (name, shadows) in [
        ("shadowLight", &tokens.shadow_light),
        ("shadowDark", &tokens.shadow_dark),
    ] {
        let _ = writeln!(out, "    readonly property QtObject {name}: QtObject {{");
        for key in SHADOW_KEYS {
            let _ = writeln!(
                out,
                "        readonly property string shadow{key}: \"{}\"",
                Tokens::color(shadows, key)
            );
        }
        let _ = writeln!(out, "    }}");
    }
    let _ = writeln!(out, "}}");
    out
}

/// Renders the one output at `path` from `tokens`, matching `path` against the five named
/// constants (`str` supports constant patterns).
///
/// The `_` arm is unreachable in practice, never in principle: every caller in this module only
/// ever passes a path from [`OUTPUTS`], which is built from exactly these five constants, but the
/// compiler cannot prove a `match` on `&str` exhaustive over an arbitrary set of constants, so an
/// arm is required to compile. `tests::render_output_covers_every_outputs_path` is the actual
/// exhaustiveness guarantee: it fails loudly (an empty file, asserted non-empty) if a future
/// `OUTPUTS` entry is added here without a matching arm, rather than writing that empty file
/// silently the way `run`'s `write` branch would otherwise do.
fn render_one(path: &str, tokens: &Tokens) -> String {
    match path {
        CSS_OUTPUT => render_css(tokens),
        SWIFT_OUTPUT => render_swift(tokens),
        KOTLIN_OUTPUT => render_kotlin(tokens),
        XAML_OUTPUT => render_xaml(tokens),
        QML_OUTPUT => render_qml(tokens),
        _ => String::new(),
    }
}

/// Renders every [`OUTPUTS`] file from `tokens`, paired with its path, in [`OUTPUTS`]' order.
fn render_all(tokens: &Tokens) -> [(&'static str, String); OUTPUTS.len()] {
    let mut out: [(&'static str, String); OUTPUTS.len()] = Default::default();
    for (slot, path) in out.iter_mut().zip(OUTPUTS) {
        *slot = (path, render_one(path, tokens));
    }
    out
}

/// `cargo xtask generate-tokens` (`write = true`) or `cargo xtask generate-tokens --check`
/// (`write = false`): reads and parses [`SOURCE`], runs [`check_contrast`], and either writes
/// every [`OUTPUTS`] file or reports every one that is stale (module docs).
///
/// # Errors
///
/// Returns a message when [`SOURCE`] cannot be read or parsed, when any contrast pair fails,
/// when `write` and a file cannot be written, or when `!write` and at least one output is stale.
pub(crate) fn run(root: &Path, write: bool) -> Result<String, String> {
    let text =
        std::fs::read_to_string(root.join(SOURCE)).map_err(|e| format!("reading {SOURCE}: {e}"))?;
    let tokens = parse(&text)?;
    let violations = check_contrast(&tokens);
    if !violations.is_empty() {
        let mut message = String::new();
        for v in &violations {
            let _ = writeln!(message, "error: {v}");
        }
        let _ = write!(
            message,
            "generate-tokens: {} contrast violation(s) below WCAG AA over the declared token \
             pairs ({SOURCE})",
            violations.len()
        );
        return Err(message);
    }
    let outputs = render_all(&tokens);
    if write {
        for (path, content) in &outputs {
            let full = root.join(path);
            if let Some(dir) = full.parent() {
                std::fs::create_dir_all(dir)
                    .map_err(|e| format!("creating {}: {e}", dir.display()))?;
            }
            std::fs::write(&full, content).map_err(|e| format!("writing {path}: {e}"))?;
        }
        Ok(format!(
            "generate-tokens: wrote {} file(s) from {SOURCE} (ADR 0014 §5, ADR 0019 §13)",
            outputs.len()
        ))
    } else {
        let mut stale = Vec::new();
        for (path, content) in &outputs {
            let existing = std::fs::read_to_string(root.join(path)).unwrap_or_default();
            if &existing != content {
                stale.push(*path);
            }
        }
        if stale.is_empty() {
            Ok(format!(
                "generate-tokens --check: ok ({} generated file(s) match {SOURCE}; ADR 0014 §5, \
                 ADR 0019 §13)",
                outputs.len()
            ))
        } else {
            let mut message = String::new();
            for path in &stale {
                let _ = writeln!(
                    message,
                    "error: {path} is stale; run `cargo xtask generate-tokens` to regenerate it"
                );
            }
            let _ = write!(
                message,
                "generate-tokens --check: {} of {} generated file(s) do not match {SOURCE}",
                stale.len(),
                outputs.len()
            );
            Err(message)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal but fully valid source document, used as the baseline every malformed-input
    /// test mutates one field of.
    fn valid_json() -> serde_json::Value {
        serde_json::json!({
            "color": {
                "light": {
                    "bg": "#f7f7f8", "surface": "#ffffff", "border": "#c9cad1", "text": "#17181c",
                    "text-muted": "#4d505b", "accent": "#2f4fd6", "on-accent": "#ffffff",
                    "danger": "#b3261e", "on-danger": "#ffffff", "warning-bg": "#fff4d6",
                    "warning-text": "#4a3500", "focus": "#2f4fd6",
                },
                "dark": {
                    "bg": "#121317", "surface": "#1c1d23", "border": "#3b3d47", "text": "#ececf1",
                    "text-muted": "#b4b6c2", "accent": "#8fa6ff", "on-accent": "#0b1030",
                    "danger": "#ffb4ab", "on-danger": "#410002", "warning-bg": "#3a2c00",
                    "warning-text": "#ffe08a", "focus": "#8fa6ff",
                },
            },
            "contrast-pairs": [
                { "fg": "text", "bg": "bg", "min-ratio": 4.5 },
                { "fg": "focus", "bg": "bg", "min-ratio": 3.0 },
            ],
            "spacing": { "1": "0.25rem", "2": "0.5rem", "3": "0.75rem", "4": "1rem", "6": "1.5rem", "8": "2rem" },
            "type": {
                "font-body": "system-ui", "font-mono": "ui-monospace",
                "font-size-small": "0.875rem", "font-size-body": "1rem", "font-size-title": "1.375rem",
            },
            "radius": { "1": "4px", "2": "8px" },
            "shadow": {
                "light": { "1": "0 1px 2px rgba(0,0,0,0.12)", "2": "0 4px 12px rgba(0,0,0,0.16)" },
                "dark": { "1": "0 1px 2px rgba(0,0,0,0.4)", "2": "0 4px 16px rgba(0,0,0,0.55)" },
            },
        })
    }

    #[test]
    fn contrast_ratio_known_answers() {
        assert!((contrast_ratio("#ffffff", "#000000") - 21.0).abs() < 1e-9);
        assert!((contrast_ratio("#000000", "#ffffff") - 21.0).abs() < 1e-9);
        assert!((contrast_ratio("#ffffff", "#ffffff") - 1.0).abs() < 1e-9);
        // The classic boundary example: #777 on white is ~4.48:1 (just under 4.5:1).
        let ratio = contrast_ratio("#777777", "#ffffff");
        assert!((4.47..4.49).contains(&ratio), "{ratio}");
    }

    #[test]
    fn contrast_ratio_matches_current_token_pairs() {
        // The six pairs ADR 0014 §5's own tokens.css comment declares, light theme, computed
        // independently of the generator (a regression guard: a future token edit that breaks
        // one of these is caught by `check_contrast`, but this test catches a mistake in
        // `contrast_ratio`/`relative_luminance` itself, against hand-checked values).
        assert!((contrast_ratio("#17181c", "#f7f7f8") - 16.57).abs() < 0.05);
        assert!((contrast_ratio("#ffffff", "#2f4fd6") - 6.54).abs() < 0.05);
    }

    #[test]
    fn is_hex_color_accepts_and_rejects() {
        assert!(is_hex_color("#17181c"));
        assert!(is_hex_color("#FFFFFF"));
        assert!(!is_hex_color("17181c"));
        assert!(!is_hex_color("#17181"));
        assert!(!is_hex_color("#17181cx"));
        assert!(!is_hex_color("#gggggg"));
    }

    #[test]
    fn kebab_to_camel_and_pascal() {
        assert_eq!(kebab_to_camel("bg"), "bg");
        assert_eq!(kebab_to_camel("text-muted"), "textMuted");
        assert_eq!(kebab_to_camel("on-accent"), "onAccent");
        assert_eq!(kebab_to_pascal("text-muted"), "TextMuted");
        assert_eq!(kebab_to_pascal("bg"), "Bg");
    }

    #[test]
    fn parse_accepts_the_valid_document() {
        let tokens = parse(&valid_json().to_string()).unwrap();
        assert_eq!(tokens.color_light.len(), COLOR_KEYS.len());
        assert_eq!(tokens.color_dark.len(), COLOR_KEYS.len());
        assert_eq!(Tokens::color(&tokens.color_light, "bg"), "#f7f7f8");
        assert_eq!(tokens.contrast_pairs.len(), 2);
        assert!((tokens.contrast_pairs[0].min_ratio - 4.5).abs() < 1e-9);
    }

    #[test]
    fn parse_rejects_invalid_json() {
        let err = parse("not json").unwrap_err();
        assert!(err.contains("invalid JSON"), "{err}");
    }

    #[test]
    fn parse_rejects_a_missing_color_key() {
        let mut doc = valid_json();
        doc["color"]["light"].as_object_mut().unwrap().remove("bg");
        let err = parse(&doc.to_string()).unwrap_err();
        assert!(err.contains("missing key"), "{err}");
        assert!(err.contains("bg"), "{err}");
    }

    #[test]
    fn parse_rejects_an_extra_color_key() {
        let mut doc = valid_json();
        doc["color"]["light"]
            .as_object_mut()
            .unwrap()
            .insert("extra".to_owned(), serde_json::json!("#000000"));
        let err = parse(&doc.to_string()).unwrap_err();
        assert!(err.contains("unexpected key"), "{err}");
        assert!(err.contains("extra"), "{err}");
    }

    #[test]
    fn parse_rejects_a_non_string_value() {
        let mut doc = valid_json();
        doc["color"]["light"]["bg"] = serde_json::json!(123);
        let err = parse(&doc.to_string()).unwrap_err();
        assert!(err.contains("expected a string"), "{err}");
    }

    #[test]
    fn parse_rejects_a_non_hex_color() {
        let mut doc = valid_json();
        doc["color"]["light"]["bg"] = serde_json::json!("not-a-color");
        let err = parse(&doc.to_string()).unwrap_err();
        assert!(err.contains("not a `#rrggbb` colour"), "{err}");
    }

    #[test]
    fn parse_rejects_an_empty_spacing_value() {
        let mut doc = valid_json();
        doc["spacing"]["1"] = serde_json::json!("");
        let err = parse(&doc.to_string()).unwrap_err();
        assert!(err.contains("non-empty"), "{err}");
    }

    #[test]
    fn parse_rejects_a_multiline_value() {
        let mut doc = valid_json();
        doc["type"]["font-body"] = serde_json::json!("a\nb");
        let err = parse(&doc.to_string()).unwrap_err();
        assert!(err.contains("single-line"), "{err}");
    }

    #[test]
    fn parse_rejects_a_contrast_pair_naming_an_unknown_color_key() {
        let mut doc = valid_json();
        doc["contrast-pairs"][0]["fg"] = serde_json::json!("not-a-color-key");
        let err = parse(&doc.to_string()).unwrap_err();
        assert!(err.contains("unknown colour key"), "{err}");
    }

    #[test]
    fn parse_rejects_a_non_positive_min_ratio() {
        let mut doc = valid_json();
        doc["contrast-pairs"][0]["min-ratio"] = serde_json::json!(0);
        let err = parse(&doc.to_string()).unwrap_err();
        assert!(err.contains("must be at least 3 (WCAG AA)"), "{err}");
    }

    #[test]
    fn parse_rejects_a_min_ratio_below_wcag_aa() {
        // A pair cannot be declared into passing below AA: 2.9:1 is under the 3:1 floor.
        let mut doc = valid_json();
        doc["contrast-pairs"][1]["min-ratio"] = serde_json::json!(2.9);
        let err = parse(&doc.to_string()).unwrap_err();
        assert!(err.contains("contrast-pairs[1].min-ratio"), "{err}");
        assert!(err.contains("must be at least 3 (WCAG AA)"), "{err}");
    }

    #[test]
    fn parse_accepts_a_stricter_than_aa_min_ratio() {
        let mut doc = valid_json();
        doc["contrast-pairs"][0]["min-ratio"] = serde_json::json!(7.0);
        let tokens = parse(&doc.to_string()).unwrap();
        assert!((tokens.contrast_pairs[0].min_ratio - 7.0).abs() < 1e-9);
    }

    #[test]
    fn parse_rejects_an_unexpected_top_level_key() {
        let mut doc = valid_json();
        doc.as_object_mut()
            .unwrap()
            .insert("extra".to_owned(), serde_json::json!({}));
        let err = parse(&doc.to_string()).unwrap_err();
        assert!(err.contains("unexpected key"), "{err}");
    }

    #[test]
    fn check_contrast_passes_the_real_m1_palette() {
        let tokens = parse(&include_source_fixture()).unwrap();
        assert_eq!(check_contrast(&tokens), Vec::<String>::new());
    }

    #[test]
    fn check_contrast_flags_a_failing_pair() {
        let mut doc = valid_json();
        // bg and surface are the same colour: text on it should still pass easily, but flip the
        // pair to compare a colour against itself (ratio 1:1) to force a clean failure.
        doc["contrast-pairs"] = serde_json::json!([
            { "fg": "bg", "bg": "bg", "min-ratio": 4.5 },
        ]);
        let tokens = parse(&doc.to_string()).unwrap();
        let violations = check_contrast(&tokens);
        assert_eq!(violations.len(), 2, "{violations:?}"); // light theme + dark theme
        assert!(violations[0].contains("1.00:1"), "{violations:?}");
    }

    #[test]
    fn check_contrast_fails_just_below_aa_and_passes_just_above() {
        // #777777 on white is 4.48:1, just under AA's 4.5:1 for text; #767676 is 4.54:1, just over
        // it. Both themes get the same pair, so a failure is reported once per theme.
        let mut doc = valid_json();
        for theme in ["light", "dark"] {
            doc["color"][theme]["surface"] = serde_json::json!("#ffffff");
            doc["color"][theme]["text-muted"] = serde_json::json!("#777777");
        }
        doc["contrast-pairs"] = serde_json::json!([
            { "fg": "text-muted", "bg": "surface", "min-ratio": 4.5 },
        ]);
        let tokens = parse(&doc.to_string()).unwrap();
        let violations = check_contrast(&tokens);
        assert_eq!(violations.len(), 2, "{violations:?}");
        assert!(violations[0].contains("4.48:1"), "{violations:?}");

        for theme in ["light", "dark"] {
            doc["color"][theme]["text-muted"] = serde_json::json!("#767676");
        }
        let tokens = parse(&doc.to_string()).unwrap();
        assert_eq!(check_contrast(&tokens), Vec::<String>::new());
    }

    #[test]
    fn check_contrast_holds_ui_pairs_to_three_to_one() {
        // #949494 on white is 3.03:1 (passes 3:1); #959595 is 2.99:1 (fails), WCAG SC 1.4.11.
        let mut doc = valid_json();
        for theme in ["light", "dark"] {
            doc["color"][theme]["bg"] = serde_json::json!("#ffffff");
            doc["color"][theme]["focus"] = serde_json::json!("#959595");
        }
        doc["contrast-pairs"] = serde_json::json!([
            { "fg": "focus", "bg": "bg", "min-ratio": 3.0 },
        ]);
        let tokens = parse(&doc.to_string()).unwrap();
        assert_eq!(check_contrast(&tokens).len(), 2);
        for theme in ["light", "dark"] {
            doc["color"][theme]["focus"] = serde_json::json!("#949494");
        }
        let tokens = parse(&doc.to_string()).unwrap();
        assert_eq!(check_contrast(&tokens), Vec::<String>::new());
    }

    #[test]
    fn render_css_keeps_every_m1_custom_property_name() {
        // The exact 25 names the M1 hand-written file declared (ADR 0014 §5's "keeping the
        // property names where possible"), written out as literals rather than derived from
        // `COLOR_KEYS`/`SPACING_KEYS`/`TYPE_KEYS`/`RADIUS_KEYS`: a future rename of one of those
        // constants must not make this test silently track it. apps/web and apps/extension read
        // these by name, so a rename here is the exact drift this generator must never produce.
        const M1_NAMES: &[&str] = &[
            "--color-bg",
            "--color-surface",
            "--color-border",
            "--color-text",
            "--color-text-muted",
            "--color-accent",
            "--color-on-accent",
            "--color-danger",
            "--color-on-danger",
            "--color-warning-bg",
            "--color-warning-text",
            "--color-focus",
            "--space-1",
            "--space-2",
            "--space-3",
            "--space-4",
            "--space-6",
            "--space-8",
            "--font-body",
            "--font-mono",
            "--font-size-small",
            "--font-size-body",
            "--font-size-title",
            "--radius-1",
            "--radius-2",
        ];
        let tokens = parse(&valid_json().to_string()).unwrap();
        let css = render_css(&tokens);
        assert!(css.starts_with("/* SPDX-License-Identifier: AGPL-3.0-only */\n"));
        for name in M1_NAMES {
            assert!(css.contains(&format!("{name}:")), "{name}\n{css}");
        }
        assert_eq!(M1_NAMES.len(), 25);
        // The new, additive shadow tokens (ROADMAP §4.5): not part of the M1 contract above, but
        // still generated.
        assert!(css.contains("--shadow-1:"));
        assert!(css.contains("--shadow-2:"));
        assert!(css.contains("--space-1: 0.25rem;"));
        assert!(css.contains("--radius-1: 4px;"));
        assert!(css.contains("--font-body: system-ui;"));
        assert!(css.contains(":root {"));
        assert!(css.contains("@media (prefers-color-scheme: dark) {"));
        assert!(css.contains(":root[data-theme=\"dark\"] {"));
    }

    #[test]
    fn render_css_header_lists_every_real_contrast_pair() {
        // Regression guard for the SSOT violation review found: the header's "WCAG AA pairs"
        // sentence used to be a string literal, completely disconnected from
        // `tokens.contrast_pairs`. This reads the real, committed source and checks every pair it
        // declares is actually named in the generated header, so a future edit to
        // `contrast-pairs` that the header's text does not follow fails here instead of the
        // generated file silently going stale forever (the bug `--check` could never catch,
        // because the same literal text was reproduced identically on every run).
        let tokens = parse(&include_source_fixture()).unwrap();
        let css = render_css(&tokens);
        for pair in &tokens.contrast_pairs {
            assert!(
                css.contains(&format!("--color-{}, --color-{}", pair.fg, pair.bg)),
                "{pair:?}\n{css}"
            );
        }
    }

    #[test]
    fn render_css_header_contrast_list_tracks_declared_pairs_not_a_literal() {
        // `valid_json()` declares only (text, bg) and (focus, bg) — fewer, and different, pairs
        // than the real tokens.json's set. Asserting both the presence of what IS declared and
        // the absence of a pair that is NOT is the asymmetry that catches a hardcoded literal: a
        // literal copy of the real file's header would contain the absent pair too.
        let tokens = parse(&valid_json().to_string()).unwrap();
        let css = render_css(&tokens);
        assert!(css.contains("--color-text, --color-bg"), "{css}");
        assert!(css.contains("--color-focus, --color-bg"), "{css}");
        assert!(!css.contains("--color-on-accent, --color-accent"), "{css}");
        assert!(!css.contains("--color-on-danger, --color-danger"), "{css}");
    }

    #[test]
    fn contrast_pairs_paragraph_handles_zero_declared_pairs() {
        // `parse_contrast_pairs` accepts an empty array, so `and_join(&[])` (`""`) is reachable
        // here, not just a theoretical input. Naively formatting "...only) are {list}." would
        // render "...only) are ." with a dangling "are" and no object — this is the edge case
        // that must read as a sentence instead.
        let mut doc = valid_json();
        doc["contrast-pairs"] = serde_json::json!([]);
        let tokens = parse(&doc.to_string()).unwrap();
        let paragraph = contrast_pairs_paragraph(&tokens);
        assert!(!paragraph.contains("are ."), "{paragraph}");
        assert!(
            paragraph.contains("no WCAG AA pairs are declared"),
            "{paragraph}"
        );
    }

    #[test]
    fn contrast_pairs_paragraph_is_built_from_the_declared_pairs() {
        // Exact match, pinning the helper's whole output (this file's own idiom: see
        // `render_css_keeps_every_m1_custom_property_name`'s literal `M1_NAMES`). A substring
        // check against the *rendered CSS* can pass vacuously — `--color-danger` and
        // `--color-border` both already appear in the file's `:root` block regardless of what
        // this paragraph says — so this asserts directly against [`contrast_pairs_paragraph`]'s
        // return value, where no `:root` block can make the assertion pass by accident.
        // `valid_json()` declares only (text, bg) and (focus, bg), so every other `COLOR_KEYS`
        // entry, in `COLOR_KEYS`' own order, must be named as undeclared.
        let tokens = parse(&valid_json().to_string()).unwrap();
        assert_eq!(
            contrast_pairs_paragraph(&tokens),
            "Colour: the WCAG AA pairs `cargo xtask generate-tokens` checks (ADR 0014 §5; it \
             covers the declared pairs only) are (--color-text, --color-bg) and (--color-focus, \
             --color-bg). --color-surface, --color-border, --color-text-muted, --color-accent, \
             --color-on-accent, --color-danger, --color-on-danger, --color-warning-bg and \
             --color-warning-text are not declared and not checked."
        );
    }

    #[test]
    fn render_output_covers_every_outputs_path() {
        // The actual exhaustiveness guarantee for `render_one`'s match (module docs there): every
        // path `OUTPUTS` can hand it renders to something non-empty, so a future output added to
        // `OUTPUTS` without a matching arm fails this test instead of silently writing an empty
        // file.
        let tokens = parse(&valid_json().to_string()).unwrap();
        for path in OUTPUTS {
            assert!(!render_one(path, &tokens).is_empty(), "{path}");
        }
    }

    #[test]
    fn render_swift_contains_every_color_field_and_hex_value() {
        let tokens = parse(&valid_json().to_string()).unwrap();
        let swift = render_swift(&tokens);
        assert!(swift.starts_with("// SPDX-License-Identifier: AGPL-3.0-only\n"));
        assert!(swift.contains("textMuted: Color"));
        assert!(swift.contains("Color(hex: \"#f7f7f8\")"));
        assert!(swift.contains("public static let space1 = \"0.25rem\""));
    }

    #[test]
    fn render_kotlin_contains_argb_literals() {
        let tokens = parse(&valid_json().to_string()).unwrap();
        let kotlin = render_kotlin(&tokens);
        assert!(kotlin.starts_with("// SPDX-License-Identifier: AGPL-3.0-only\n"));
        // #f7f7f8 opaque -> 0xFFF7F7F8.
        assert!(kotlin.contains("0xFFF7F7F8"), "{kotlin}");
    }

    #[test]
    fn render_xaml_is_well_formed_and_leaves_high_contrast_empty() {
        let tokens = parse(&valid_json().to_string()).unwrap();
        let xaml = render_xaml(&tokens);
        assert!(xaml.starts_with("<!-- SPDX-License-Identifier: AGPL-3.0-only -->\n"));
        assert!(xaml.contains("x:Key=\"ColorBg\">#f7f7f8</Color>"));
        assert!(xaml.contains("<ResourceDictionary.ThemeDictionaries>"));
        assert!(xaml.contains("</ResourceDictionary.ThemeDictionaries>"));
        assert!(xaml.contains("x:Key=\"Light\">"));
        assert!(xaml.contains("x:Key=\"Dark\">"));
        assert!(xaml.contains("x:Key=\"HighContrast\" />"));
        assert!(xaml.trim_end().ends_with("</ResourceDictionary>"));
    }

    #[test]
    fn render_qml_declares_a_singleton_with_both_themes() {
        let tokens = parse(&valid_json().to_string()).unwrap();
        let qml = render_qml(&tokens);
        assert!(qml.starts_with("// SPDX-License-Identifier: AGPL-3.0-only\n"));
        assert!(qml.contains("pragma Singleton"));
        assert!(qml.contains("property QtObject light: QtObject"));
        assert!(qml.contains("property QtObject dark: QtObject"));
        assert!(qml.contains("property color bg: \"#f7f7f8\""));
    }

    /// A fresh scratch directory under the OS temp dir, removed by the caller (the same pattern
    /// as `psl_check::tests::scratch_dir` and `ext_manifest`'s and `equivalence_list`'s own
    /// copies).
    fn scratch_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rizzy-xtask-tokens-test-{name}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
        ));
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        dir
    }

    #[test]
    fn run_rejects_a_contrast_failure_without_writing() {
        let dir = scratch_dir("contrast-failure");
        let mut doc = valid_json();
        doc["contrast-pairs"] = serde_json::json!([{ "fg": "bg", "bg": "bg", "min-ratio": 4.5 }]);
        let source_dir = dir.join("packages/ui/tokens");
        std::fs::create_dir_all(&source_dir).unwrap();
        std::fs::write(source_dir.join("tokens.json"), doc.to_string()).unwrap();
        let err = run(&dir, true).unwrap_err();
        assert!(err.contains("contrast violation"), "{err}");
        assert!(!dir.join(CSS_OUTPUT).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_write_then_check_round_trips() {
        let dir = scratch_dir("round-trip");
        let source_dir = dir.join("packages/ui/tokens");
        std::fs::create_dir_all(&source_dir).unwrap();
        std::fs::write(source_dir.join("tokens.json"), valid_json().to_string()).unwrap();
        run(&dir, true).unwrap();
        for output in OUTPUTS {
            assert!(dir.join(output).exists(), "{output}");
        }
        let ok = run(&dir, false).unwrap();
        assert!(ok.contains("ok"), "{ok}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_check_reports_a_stale_file() {
        let dir = scratch_dir("stale");
        let source_dir = dir.join("packages/ui/tokens");
        std::fs::create_dir_all(&source_dir).unwrap();
        std::fs::write(source_dir.join("tokens.json"), valid_json().to_string()).unwrap();
        run(&dir, true).unwrap();
        std::fs::write(dir.join(CSS_OUTPUT), "stale\n").unwrap();
        let err = run(&dir, false).unwrap_err();
        assert!(err.contains(CSS_OUTPUT), "{err}");
        assert!(err.contains("stale"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Reads the real, committed source file at the workspace root, for
    /// [`check_contrast_passes_the_real_m1_palette`]. `CARGO_MANIFEST_DIR` is `crates/xtask`.
    fn include_source_fixture() -> String {
        let here = Path::new(env!("CARGO_MANIFEST_DIR"));
        let root = here.parent().and_then(Path::parent).unwrap_or(here);
        std::fs::read_to_string(root.join(SOURCE)).unwrap()
    }
}
