// SPDX-License-Identifier: AGPL-3.0-only

//! `cargo xtask check-deps`'s source-URL base check (ADR 0106 §2, implementation step 4): the
//! root manifest's `[workspace.package] repository` is the base `rizzy-server` derives its
//! default `/api/meta` `source_url` from (`CARGO_PKG_REPOSITORY`; every member inherits the
//! field). It must satisfy `rizzy_proto::meta::SourceUrl`'s grammar, have no query or fragment
//! and not end in `/` (`SourceUrl::is_base`), so a bad value fails CI rather than leaving a
//! build without a default. A missing or unreadable field fails too.

use rizzy_proto::meta::SourceUrl;

use crate::manifest::{self, Manifest, TomlValue};

/// The checked key of the root `Cargo.toml`.
const KEY: &str = "workspace.package.repository";

/// Runs the check on the root manifest.
///
/// # Errors
/// What is wrong with the field.
pub(crate) fn check(workspace_manifest: &Manifest) -> Result<(), String> {
    let entries: Vec<(&str, &str)> = workspace_manifest.under(KEY).collect();
    let value = match entries.as_slice() {
        [(k, v)] if *k == KEY => manifest::parse_value(v).ok(),
        _ => None,
    };
    let Some(TomlValue::Str(repository)) = value else {
        return Err(format!(
            "the root Cargo.toml must set `{KEY}` to one string: it is the base of the \
             server's default source URL (ADR 0106 §2)"
        ));
    };
    if SourceUrl::parse(&repository)
        .ok()
        .is_some_and(|url| url.is_base())
    {
        Ok(())
    } else {
        Err(format!(
            "`{KEY}` = {repository:?} is not a valid source URL base (ADR 0106 §1–§2): an \
             https:// URL of at most 2048 bytes with a plain host[:port], no query or fragment \
             and no trailing `/`"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn of(text: &str) -> Result<(), String> {
        check(&Manifest::parse(text))
    }

    #[test]
    fn the_committed_workspace_manifest_passes() {
        assert_eq!(of(include_str!("../../../Cargo.toml")), Ok(()));
    }

    #[test]
    fn a_bad_or_missing_repository_fails() {
        assert!(of("[workspace.package]\nrepository = \"https://github.com/o/r\"\n").is_ok());
        for bad in [
            "[workspace.package]\nversion = \"0.0.0\"\n",
            "[workspace.package]\nrepository = \"http://github.com/o/r\"\n",
            "[workspace.package]\nrepository = \"https://github.com/o/r/\"\n",
            "[workspace.package]\nrepository = \"https://github.com/o/r?x\"\n",
            "[workspace.package]\nrepository = \"https://github.com/o/r#x\"\n",
            "[workspace.package]\nrepository = \"git@github.com:o/r\"\n",
            "[workspace.package]\nrepository = 5\n",
        ] {
            assert!(of(bad).is_err(), "{bad}");
        }
    }
}
