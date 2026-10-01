//! The password generator (CRYPTO.md §12.1; ROADMAP §4.2 "generate"), as `rv generate` offers
//! it: characters or words, drawn from the CSPRNG in Rust. No session is needed.

use core::fmt;

use rizzy_client::ClientError;
use rizzy_client::rizzy_core::generator::{
    CharacterOptions, ClassRule, PassphraseOptions, generate_passphrase, generate_password,
};
use wasm_bindgen::prelude::wasm_bindgen;
use zeroize::Zeroizing;

use crate::error::CoreError;
use crate::rng::os_rng;

/// A generated password or passphrase and its entropy. The value is wiped when freed.
#[wasm_bindgen]
pub struct Generated {
    /// The value.
    value: Zeroizing<String>,
    /// `log2` of the space it was drawn from, uniformly.
    entropy_bits: f64,
}

impl fmt::Debug for Generated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Generated")
            .field("entropy_bits", &self.entropy_bits)
            .finish_non_exhaustive()
    }
}

#[wasm_bindgen]
impl Generated {
    /// The password or passphrase. A secret.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn value(&self) -> String {
        self.value.as_str().to_owned()
    }

    /// Its entropy in bits, for the UI.
    #[wasm_bindgen(getter, js_name = entropyBits)]
    #[must_use]
    pub fn entropy_bits(&self) -> f64 {
        self.entropy_bits
    }
}

/// A password of `length` characters from lowercase, uppercase and digits (each required),
/// with symbols required or left out, and ambiguous characters left out if asked.
///
/// # Errors
/// `invalid_input` for options the generator refuses (such as a length below the number of
/// required classes).
#[wasm_bindgen(js_name = generatePassword)]
pub fn generate_password_js(
    length: usize,
    symbols: bool,
    exclude_ambiguous: bool,
) -> Result<Generated, CoreError> {
    let generated = generate_password(
        &mut os_rng(),
        &CharacterOptions {
            length,
            symbols: if symbols {
                ClassRule::Required
            } else {
                ClassRule::Excluded
            },
            exclude_ambiguous,
            ..CharacterOptions::default()
        },
    )
    .map_err(|_| ClientError::InvalidInput)?;
    Ok(Generated {
        value: Zeroizing::new(generated.expose_secret().to_owned()),
        entropy_bits: generated.entropy_bits(),
    })
}

/// A passphrase of `words` words from the generator's word list, separated by `.`.
///
/// # Errors
/// `invalid_input` for a word count the generator refuses.
#[wasm_bindgen(js_name = generatePassphrase)]
pub fn generate_passphrase_js(words: usize) -> Result<Generated, CoreError> {
    let generated = generate_passphrase(
        &mut os_rng(),
        &PassphraseOptions {
            words,
            ..PassphraseOptions::default()
        },
    )
    .map_err(|_| ClientError::InvalidInput)?;
    Ok(Generated {
        value: Zeroizing::new(generated.expose_secret().to_owned()),
        entropy_bits: generated.entropy_bits(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwords_and_passphrases_are_generated() {
        let password = generate_password_js(24, true, true).unwrap();
        assert_eq!(password.value().len(), 24);
        assert!(password.entropy_bits() > 100.0);
        let phrase = generate_passphrase_js(6).unwrap();
        assert_eq!(phrase.value().split('.').count(), 6);
        assert!(generate_password_js(0, true, false).is_err());
        assert!(!format!("{password:?}").contains(&password.value()));
    }
}
