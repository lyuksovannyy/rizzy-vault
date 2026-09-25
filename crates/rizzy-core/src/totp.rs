//! HOTP and TOTP (CRYPTO.md §11.15; RFC 4226, RFC 6238).
//!
//! One implementation serves both uses: codes for items that hold a TOTP secret, and the
//! server's own 2FA (§5.10). Neither kind of TOTP ever feeds key derivation.
//!
//! - **Allow-lists.** Algorithm SHA1, SHA256 or SHA512 (HMAC from `hmac` over `sha1` or `sha2`);
//!   digits 6–8; period 1–300 s, default 30. Anything else is rejected, never clamped.
//! - **No clock.** `rizzy-core` reads no clock (ADR 0016 R1): callers pass the Unix time or the
//!   time step.
//! - **otpauth URIs** ([`OtpAuthUri`]). The secret is RFC 4648 Base32 (not the Crockford alphabet
//!   of §7), parsed case-insensitively with optional padding.
//! - **Server verification** ([`TotpParams::verify`]) accepts the current time step or one step
//!   either side, rejects any step at or below the last step it accepted for the credential, and
//!   compares codes with `ct_eq`.
//! - **Secrets** live in zeroizing buffers ([`TotpSecret`]). Base32 decoding and encoding of the
//!   secret, and the RFC 4226 dynamic truncation, use no secret-indexed lookups (§12.3).

use core::fmt;

use hmac::{Hmac, KeyInit, Mac};
use rand_core::CryptoRng;
use subtle::{ConditionallySelectable as _, ConstantTimeEq as _};
use zeroize::{Zeroize as _, Zeroizing};

use crate::secret::SecretBytes;
use crate::secret_key::in_range;

/// Shortest accepted secret, in bytes.
pub const MIN_SECRET_LEN: usize = 1;
/// Longest accepted secret, in bytes (1024 bits, the HMAC-SHA-512 block size).
pub const MAX_SECRET_LEN: usize = 128;
/// Length of a secret the server generates for its own 2FA: 160 bits, as RFC 4226 §4 R6
/// recommends.
pub const GENERATED_SECRET_LEN: usize = 20;
/// Longest otpauth URI the parser looks at, in bytes.
pub const MAX_URI_LEN: usize = 4096;

/// Why a TOTP value or URI was rejected, or a code did not verify. Carries no secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TotpError {
    /// The algorithm is not SHA1, SHA256 or SHA512.
    UnsupportedAlgorithm,
    /// The number of digits is not 6, 7 or 8.
    InvalidDigits,
    /// The period is not 1–300 seconds.
    InvalidPeriod,
    /// The HOTP counter is not a decimal `u64`.
    InvalidCounter,
    /// The secret is not canonical RFC 4648 Base32, or its length is outside
    /// [`MIN_SECRET_LEN`]..=[`MAX_SECRET_LEN`] bytes.
    InvalidSecret,
    /// The URI is malformed: wrong scheme or type, bad percent-encoding, not ASCII, too long.
    InvalidUri,
    /// A required URI parameter (`secret`, or `counter` for HOTP) is missing.
    MissingParameter,
    /// A URI parameter this parser reads appears more than once.
    DuplicateParameter,
    /// The submitted code is malformed, wrong, outside the ±1 step window, or a replay.
    CodeRejected,
    /// An internal primitive failed. Unreachable.
    Internal,
}

impl fmt::Display for TotpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedAlgorithm => "TOTP algorithm must be SHA1, SHA256 or SHA512",
            Self::InvalidDigits => "TOTP digits must be 6, 7 or 8",
            Self::InvalidPeriod => "TOTP period must be 1 to 300 seconds",
            Self::InvalidCounter => "invalid HOTP counter",
            Self::InvalidSecret => "invalid TOTP secret",
            Self::InvalidUri => "invalid otpauth URI",
            Self::MissingParameter => "otpauth URI lacks a required parameter",
            Self::DuplicateParameter => "otpauth URI repeats a parameter",
            Self::CodeRejected => "code rejected",
            Self::Internal => "internal TOTP error",
        })
    }
}

impl core::error::Error for TotpError {}

/// The HMAC hash (RFC 6238 §1.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// HMAC-SHA-1, the RFC 4226 default and what most otpauth URIs use.
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

impl Algorithm {
    /// The name as written in otpauth URIs.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }

    /// Parses an otpauth `algorithm` value, case-insensitively.
    ///
    /// # Errors
    /// [`TotpError::UnsupportedAlgorithm`] for anything but SHA1, SHA256 and SHA512.
    pub fn from_name(name: &str) -> Result<Self, TotpError> {
        [Self::Sha1, Self::Sha256, Self::Sha512]
            .into_iter()
            .find(|a| a.name().eq_ignore_ascii_case(name))
            .ok_or(TotpError::UnsupportedAlgorithm)
    }

    const fn mac_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }
}

/// The number of digits of a code: 6, 7 or 8.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Digits(u8);

impl Digits {
    /// 6 digits, the RFC 4226 default.
    pub const DEFAULT: Self = Self(6);

    /// Checks the allow-list.
    ///
    /// # Errors
    /// [`TotpError::InvalidDigits`] outside 6–8.
    pub const fn new(digits: u8) -> Result<Self, TotpError> {
        match digits {
            6..=8 => Ok(Self(digits)),
            _ => Err(TotpError::InvalidDigits),
        }
    }

    /// The number of digits.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }

    const fn modulus(self) -> u32 {
        match self.0 {
            6 => 1_000_000,
            7 => 10_000_000,
            _ => 100_000_000,
        }
    }
}

/// The TOTP time step in seconds: 1–300.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Period(u32);

impl Period {
    /// 30 seconds, the RFC 6238 default.
    pub const DEFAULT: Self = Self(30);

    /// Checks the allow-list.
    ///
    /// # Errors
    /// [`TotpError::InvalidPeriod`] outside 1–300.
    pub const fn new(seconds: u32) -> Result<Self, TotpError> {
        match seconds {
            1..=300 => Ok(Self(seconds)),
            _ => Err(TotpError::InvalidPeriod),
        }
    }

    /// The period in seconds.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// A HOTP/TOTP shared secret, wiped on drop.
pub struct TotpSecret {
    bytes: SecretBytes,
}

impl TotpSecret {
    /// Draws a new 20-byte secret from the injected CSPRNG, for the server's own 2FA.
    #[must_use]
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut bytes = Zeroizing::new(vec![0u8; GENERATED_SECRET_LEN]);
        rng.fill_bytes(&mut bytes);
        Self {
            bytes: SecretBytes::from_zeroizing(bytes),
        }
    }

    /// Takes a raw secret (for example one opened from `SERVER_TOTP_SECRET` or item data).
    ///
    /// # Errors
    /// [`TotpError::InvalidSecret`] if the length is outside the allowed range.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, TotpError> {
        if !(MIN_SECRET_LEN..=MAX_SECRET_LEN).contains(&bytes.len()) {
            return Err(TotpError::InvalidSecret);
        }
        Ok(Self {
            bytes: SecretBytes::copy_from_slice(bytes),
        })
    }

    /// Parses RFC 4648 Base32, case-insensitively, with or without `=` padding.
    ///
    /// Strict: if padding is present it must be complete and correct; the unpadded length must
    /// be a valid Base32 length; the unused trailing bits must be zero, so every secret has one
    /// accepted spelling per case; no spaces or other characters.
    ///
    /// # Errors
    /// [`TotpError::InvalidSecret`].
    pub fn from_base32(text: &str) -> Result<Self, TotpError> {
        Ok(Self {
            bytes: base32_decode(text)?,
        })
    }

    /// The unpadded, uppercase RFC 4648 Base32 form, in a buffer wiped on drop.
    #[must_use]
    pub fn to_base32(&self) -> Zeroizing<String> {
        base32_encode(self.bytes.expose_secret())
    }

    /// The raw secret bytes.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        self.bytes.expose_secret()
    }
}

impl fmt::Debug for TotpSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TotpSecret([REDACTED])")
    }
}

/// A one-time code. It is a short-lived credential: `Debug` is redacted and the value is wiped
/// on drop.
pub struct OtpCode {
    value: u32,
    digits: Digits,
}

impl OtpCode {
    /// The code as exactly `digits` decimal digits, zero-padded, in a buffer wiped on drop.
    ///
    /// The digits come from integer division by public powers of ten; that the division time of
    /// a CPU might vary with the code's value is an accepted, local-only residual.
    #[must_use]
    pub fn to_digits(&self) -> Zeroizing<String> {
        let mut out = Zeroizing::new(String::with_capacity(usize::from(self.digits.get())));
        let mut divisor = self.digits.modulus() / 10;
        while divisor > 0 {
            let d = (self.value / divisor) % 10;
            out.push(char::from(b'0' + u8::try_from(d).unwrap_or(0)));
            divisor /= 10;
        }
        out
    }

    /// The number of digits.
    #[must_use]
    pub const fn digits(&self) -> Digits {
        self.digits
    }

    /// Whether `submitted` is this code, compared in constant time. The submission must be
    /// exactly `digits` ASCII digits.
    #[must_use]
    pub fn matches(&self, submitted: &str) -> bool {
        parse_code(submitted, self.digits).is_some_and(|v| bool::from(v.ct_eq(&self.value)))
    }
}

impl Drop for OtpCode {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl fmt::Debug for OtpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OtpCode([REDACTED])")
    }
}

/// HOTP (RFC 4226): the code for `counter`.
///
/// # Errors
/// [`TotpError::Internal`] (unreachable).
pub fn hotp(
    secret: &TotpSecret,
    algorithm: Algorithm,
    digits: Digits,
    counter: u64,
) -> Result<OtpCode, TotpError> {
    let mut buf = Zeroizing::new([0u8; 64]);
    let mac = buf
        .get_mut(..algorithm.mac_len())
        .ok_or(TotpError::Internal)?;
    let key = secret.expose_secret();
    let msg = counter.to_be_bytes();
    match algorithm {
        Algorithm::Sha1 => hmac_into::<Hmac<sha1::Sha1>>(key, &msg, mac)?,
        Algorithm::Sha256 => hmac_into::<Hmac<sha2::Sha256>>(key, &msg, mac)?,
        Algorithm::Sha512 => hmac_into::<Hmac<sha2::Sha512>>(key, &msg, mac)?,
    }
    let mut word = dynamic_truncation(mac);
    let value = word % digits.modulus();
    word.zeroize();
    Ok(OtpCode { value, digits })
}

fn hmac_into<M: Mac + KeyInit>(key: &[u8], msg: &[u8], out: &mut [u8]) -> Result<(), TotpError> {
    let mut mac = <M as KeyInit>::new_from_slice(key).map_err(|_| TotpError::Internal)?;
    mac.update(msg);
    let mut tag = mac.finalize().into_bytes();
    let copied = if tag.len() == out.len() {
        out.copy_from_slice(&tag);
        Ok(())
    } else {
        Err(TotpError::Internal)
    };
    tag.as_mut_slice().zeroize();
    copied
}

/// RFC 4226 §5.3 dynamic truncation, without indexing by the secret-derived offset: every
/// possible 4-byte window is read and the one at the offset is selected in constant time.
fn dynamic_truncation(mac: &[u8]) -> u32 {
    let offset = u32::from(mac.last().copied().unwrap_or(0) & 0x0f);
    let mut word = 0u32;
    for (o, window) in (0u32..16).zip(mac.windows(4)) {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(window);
        let candidate = u32::from_be_bytes(bytes);
        word.conditional_assign(&candidate, o.ct_eq(&offset));
    }
    word & 0x7fff_ffff
}

/// Parses exactly `digits` ASCII digits. The submitted code is attacker-chosen, so its format is
/// checked with ordinary branches; the comparison with the expected code is constant-time.
fn parse_code(submitted: &str, digits: Digits) -> Option<u32> {
    let bytes = submitted.as_bytes();
    if bytes.len() != usize::from(digits.get()) || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(
        bytes
            .iter()
            .fold(0u32, |acc, b| acc * 10 + u32::from(b - b'0')),
    )
}

/// TOTP parameters (RFC 6238): algorithm, digits and period, each from its allow-list.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TotpParams {
    /// The HMAC hash.
    pub algorithm: Algorithm,
    /// The number of digits.
    pub digits: Digits,
    /// The time step.
    pub period: Period,
}

impl TotpParams {
    /// SHA1, 6 digits, 30 s: the defaults, and the parameters of the server's own 2FA.
    pub const DEFAULT: Self = Self {
        algorithm: Algorithm::Sha1,
        digits: Digits::DEFAULT,
        period: Period::DEFAULT,
    };

    /// The time step `T = floor(unix_seconds / period)` (RFC 6238 §4.2, `T0 = 0`). The caller
    /// supplies the time; `rizzy-core` reads no clock.
    #[must_use]
    pub fn time_step(&self, unix_seconds: u64) -> u64 {
        unix_seconds / u64::from(self.period.0)
    }

    /// The code for time step `step`.
    ///
    /// # Errors
    /// [`TotpError::Internal`] (unreachable).
    pub fn code_at_step(&self, secret: &TotpSecret, step: u64) -> Result<OtpCode, TotpError> {
        hotp(secret, self.algorithm, self.digits, step)
    }

    /// The code at Unix time `unix_seconds`.
    ///
    /// # Errors
    /// [`TotpError::Internal`] (unreachable).
    pub fn code_at(&self, secret: &TotpSecret, unix_seconds: u64) -> Result<OtpCode, TotpError> {
        self.code_at_step(secret, self.time_step(unix_seconds))
    }

    /// Server-side verification (CRYPTO.md §11.15).
    ///
    /// Accepts `submitted` if it is the code of `current_step - 1`, `current_step` or
    /// `current_step + 1`, and that step is above `last_accepted_step`, the step this credential
    /// last accepted (`None` if it never did). Returns the accepted step, which the caller stores
    /// as the new `last_accepted_step` in the same transaction.
    ///
    /// Readings, chosen to fail closed:
    /// - **Replays.** A step at or below the last accepted one is rejected, not only the equal
    ///   step, so an older code that was never used cannot be accepted after a newer one
    ///   (RFC 6238 §5.2).
    /// - **Several matches.** All three candidates are always computed and compared in constant
    ///   time. If two steps have the same code, the highest one is accepted, so the same code
    ///   string cannot be replayed in the next step.
    ///
    /// # Errors
    /// [`TotpError::CodeRejected`] for a malformed, wrong, out-of-window or replayed code.
    pub fn verify(
        &self,
        secret: &TotpSecret,
        submitted: &str,
        current_step: u64,
        last_accepted_step: Option<u64>,
    ) -> Result<u64, TotpError> {
        let parsed = parse_code(submitted, self.digits);
        let steps = [
            current_step.checked_sub(1),
            Some(current_step),
            current_step.checked_add(1),
        ];
        let mut candidates: [Option<(u64, OtpCode)>; 3] = [const { None }; 3];
        for (slot, step) in candidates.iter_mut().zip(steps) {
            if let Some(step) = step {
                *slot = Some((step, self.code_at_step(secret, step)?));
            }
        }
        let accepted = select_step(
            candidates
                .iter()
                .flatten()
                .map(|(step, code)| (*step, code.value)),
            parsed.unwrap_or(0),
            last_accepted_step,
        );
        match (parsed, accepted) {
            (Some(_), Some(step)) => Ok(step),
            _ => Err(TotpError::CodeRejected),
        }
    }
}

/// Picks the highest eligible step whose expected code equals `submitted`, comparing every
/// candidate in constant time. Which steps are eligible (above `last_accepted_step`) depends only
/// on public state.
fn select_step(
    candidates: impl Iterator<Item = (u64, u32)>,
    submitted: u32,
    last_accepted_step: Option<u64>,
) -> Option<u64> {
    let mut matched = subtle::Choice::from(0);
    let mut accepted = 0u64;
    for (step, expected) in candidates {
        let eligible = last_accepted_step.is_none_or(|last| step > last);
        let hit = expected.ct_eq(&submitted) & subtle::Choice::from(u8::from(eligible));
        // Candidates arrive in increasing step order, so the last hit is the highest.
        accepted.conditional_assign(&step, hit);
        matched |= hit;
    }
    bool::from(matched).then_some(accepted)
}

impl Default for TotpParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The OTP type of an otpauth URI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OtpKind {
    /// `otpauth://totp/…`, with its period.
    Totp {
        /// The time step.
        period: Period,
    },
    /// `otpauth://hotp/…`, with its counter.
    Hotp {
        /// The next counter value.
        counter: u64,
    },
}

/// A parsed `otpauth://` URI (the Key Uri Format used by authenticator apps).
///
/// Readings, chosen to fail closed:
/// - The URI must be ASCII (non-ASCII text must be percent-encoded) and at most
///   [`MAX_URI_LEN`] bytes; a fragment is rejected.
/// - The scheme and type (`totp`, `hotp`) are case-insensitive; parameter names are the
///   lowercase names `secret`, `issuer`, `algorithm`, `digits`, `period` and `counter`.
/// - Parameters this parser does not read (such as `image`) are ignored, as is `period` on a
///   HOTP URI and `counter` on a TOTP URI. A parameter it reads may appear only once.
/// - Percent-escapes must be `%` and two hex digits and decode to UTF-8. In the query, `+` means
///   a space (form encoding); in the label it is a literal `+`.
/// - Numbers are plain decimal without sign or leading zeros (`0` itself is allowed for the
///   counter).
pub struct OtpAuthUri {
    kind: OtpKind,
    label: String,
    issuer: Option<String>,
    algorithm: Algorithm,
    digits: Digits,
    secret: TotpSecret,
}

impl OtpAuthUri {
    /// Builds a TOTP URI, for example for the server's 2FA enrolment QR code.
    #[must_use]
    pub fn new_totp(
        label: String,
        issuer: Option<String>,
        params: TotpParams,
        secret: TotpSecret,
    ) -> Self {
        Self {
            kind: OtpKind::Totp {
                period: params.period,
            },
            label,
            issuer,
            algorithm: params.algorithm,
            digits: params.digits,
            secret,
        }
    }

    /// Parses an otpauth URI.
    ///
    /// # Errors
    /// A [`TotpError`] naming the problem.
    pub fn parse(uri: &str) -> Result<Self, TotpError> {
        if uri.len() > MAX_URI_LEN || !uri.is_ascii() || uri.contains('#') {
            return Err(TotpError::InvalidUri);
        }
        let (scheme, rest) = uri.split_once("://").ok_or(TotpError::InvalidUri)?;
        if !scheme.eq_ignore_ascii_case("otpauth") {
            return Err(TotpError::InvalidUri);
        }
        let (kind_text, rest) = rest.split_once('/').ok_or(TotpError::InvalidUri)?;
        let is_totp = if kind_text.eq_ignore_ascii_case("totp") {
            true
        } else if kind_text.eq_ignore_ascii_case("hotp") {
            false
        } else {
            return Err(TotpError::InvalidUri);
        };
        let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
        let label = percent_decode(label, false)?;

        let mut secret = None;
        let mut issuer = None;
        let mut algorithm = None;
        let mut digits = None;
        let mut period = None;
        let mut counter = None;
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let slot = match key {
                "secret" => &mut secret,
                "issuer" => &mut issuer,
                "algorithm" => &mut algorithm,
                "digits" => &mut digits,
                "period" => &mut period,
                "counter" => &mut counter,
                _ => continue,
            };
            if slot.is_some() {
                return Err(TotpError::DuplicateParameter);
            }
            *slot = Some(value);
        }

        let secret_text = percent_decode_secret(secret.ok_or(TotpError::MissingParameter)?)?;
        let secret = TotpSecret::from_base32(&secret_text)?;
        let issuer = issuer.map(|v| percent_decode(v, true)).transpose()?;
        let algorithm = match algorithm {
            Some(v) => Algorithm::from_name(&percent_decode(v, true)?)?,
            None => Algorithm::Sha1,
        };
        let digits = match digits {
            Some(v) => Digits::new(
                u8::try_from(parse_decimal(v, 1).ok_or(TotpError::InvalidDigits)?)
                    .map_err(|_| TotpError::InvalidDigits)?,
            )?,
            None => Digits::DEFAULT,
        };
        let kind = if is_totp {
            let period = match period {
                Some(v) => Period::new(
                    u32::try_from(parse_decimal(v, 3).ok_or(TotpError::InvalidPeriod)?)
                        .map_err(|_| TotpError::InvalidPeriod)?,
                )?,
                None => Period::DEFAULT,
            };
            OtpKind::Totp { period }
        } else {
            let text = counter.ok_or(TotpError::MissingParameter)?;
            let counter = parse_decimal(text, 20).ok_or(TotpError::InvalidCounter)?;
            OtpKind::Hotp { counter }
        };
        Ok(Self {
            kind,
            label,
            issuer,
            algorithm,
            digits,
            secret,
        })
    }

    /// Formats the URI. Label and issuer are percent-encoded (everything but RFC 3986
    /// unreserved characters), the secret is unpadded uppercase Base32. The result holds the
    /// secret, so it is wiped on drop.
    #[must_use]
    pub fn to_uri(&self) -> Zeroizing<String> {
        let mut out = Zeroizing::new(String::with_capacity(
            64 + 3 * self.label.len()
                + 3 * self.issuer.as_ref().map_or(0, String::len)
                + 2 * self.secret.expose_secret().len(),
        ));
        out.push_str(match self.kind {
            OtpKind::Totp { .. } => "otpauth://totp/",
            OtpKind::Hotp { .. } => "otpauth://hotp/",
        });
        percent_encode_into(&mut out, &self.label);
        out.push_str("?secret=");
        out.push_str(&self.secret.to_base32());
        if let Some(issuer) = &self.issuer {
            out.push_str("&issuer=");
            percent_encode_into(&mut out, issuer);
        }
        out.push_str("&algorithm=");
        out.push_str(self.algorithm.name());
        out.push_str("&digits=");
        out.push_str(&self.digits.get().to_string());
        match self.kind {
            OtpKind::Totp { period } => {
                out.push_str("&period=");
                out.push_str(&period.get().to_string());
            }
            OtpKind::Hotp { counter } => {
                out.push_str("&counter=");
                out.push_str(&counter.to_string());
            }
        }
        out
    }

    /// TOTP or HOTP, with the period or counter.
    #[must_use]
    pub const fn kind(&self) -> OtpKind {
        self.kind
    }

    /// The decoded label (often `Issuer:account`).
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The decoded `issuer` parameter, if present.
    #[must_use]
    pub fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    /// The HMAC hash.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// The number of digits.
    #[must_use]
    pub const fn digits(&self) -> Digits {
        self.digits
    }

    /// The shared secret.
    #[must_use]
    pub const fn secret(&self) -> &TotpSecret {
        &self.secret
    }

    /// The TOTP parameters, or `None` for a HOTP URI.
    #[must_use]
    pub const fn totp_params(&self) -> Option<TotpParams> {
        match self.kind {
            OtpKind::Totp { period } => Some(TotpParams {
                algorithm: self.algorithm,
                digits: self.digits,
                period,
            }),
            OtpKind::Hotp { .. } => None,
        }
    }
}

/// Redacts the secret, and also the label and issuer: for an item's TOTP they are decrypted
/// item data (an account name, an e-mail address), which never goes to logs.
impl fmt::Debug for OtpAuthUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OtpAuthUri")
            .field("kind", &self.kind)
            .field("label", &"[REDACTED]")
            .field("issuer", &self.issuer.as_ref().map(|_| "[REDACTED]"))
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("secret", &self.secret)
            .finish()
    }
}

/// Plain decimal of at most `max_digits` digits, no sign, no leading zero (except `0`).
fn parse_decimal(text: &str, max_digits: usize) -> Option<u64> {
    let ok = !text.is_empty()
        && text.len() <= max_digits
        && text.bytes().all(|b| b.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'));
    if ok { text.parse().ok() } else { None }
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Strict percent-decoding into UTF-8. `plus_is_space` applies form encoding (query values).
fn percent_decode(text: &str, plus_is_space: bool) -> Result<String, TotpError> {
    let mut out = Zeroizing::new(Vec::with_capacity(text.len()));
    let mut bytes = text.bytes();
    while let Some(b) = bytes.next() {
        match b {
            b'%' => {
                let hi = bytes
                    .next()
                    .and_then(hex_value)
                    .ok_or(TotpError::InvalidUri)?;
                let lo = bytes
                    .next()
                    .and_then(hex_value)
                    .ok_or(TotpError::InvalidUri)?;
                out.push((hi << 4) | lo);
            }
            b'+' if plus_is_space => out.push(b' '),
            _ => out.push(b),
        }
    }
    // The capacity covers the decoded length, so nothing was reallocated. On a UTF-8 error the
    // bytes (possibly part of a secret) are wiped rather than dropped.
    String::from_utf8(core::mem::take(&mut *out)).map_err(|e| {
        e.into_bytes().zeroize();
        TotpError::InvalidUri
    })
}

/// Percent-decodes the secret value into a wiped buffer. Base32 never needs escapes, but `=`
/// padding is sometimes written `%3D`.
fn percent_decode_secret(text: &str) -> Result<Zeroizing<String>, TotpError> {
    let decoded = Zeroizing::new(percent_decode(text, false)?);
    Ok(decoded)
}

fn percent_encode_into(out: &mut String, text: &str) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            // Labels and issuers are public; indexing by their bytes is fine.
            out.push('%');
            out.push(char::from(HEX[usize::from(b >> 4)]));
            out.push(char::from(HEX[usize::from(b & 0x0f)]));
        }
    }
}

/// RFC 4648 Base32 character → 5-bit value, case-insensitive, with arithmetic only.
fn base32_value(b: u8) -> (u8, bool) {
    let c = b ^ (in_range(b, b'a', b'z') & 0x20);
    let letter = in_range(c, b'A', b'Z');
    let digit = in_range(c, b'2', b'7');
    let value = (letter & c.wrapping_sub(b'A')) | (digit & c.wrapping_sub(b'2').wrapping_add(26));
    (value, (letter | digit) != 0)
}

/// 5-bit value → RFC 4648 Base32 character (`A`–`Z`, `2`–`7`), with arithmetic only.
fn base32_char(v: u8) -> u8 {
    let v = v & 0x1f;
    // 'A' + v for v < 26; '2' + (v - 26) = 'A' + v - 41 for v >= 26.
    b'A'.wrapping_add(v)
        .wrapping_sub(in_range(v, 26, 31) & 0x29)
}

fn base32_decode(text: &str) -> Result<SecretBytes, TotpError> {
    let bytes = text.as_bytes();
    let data_len = bytes.iter().position(|b| *b == b'=').unwrap_or(bytes.len());
    let (data, pad) = bytes.split_at(data_len);
    let expected_pad = match data_len % 8 {
        0 => 0,
        2 => 6,
        4 => 4,
        5 => 3,
        7 => 1,
        _ => return Err(TotpError::InvalidSecret),
    };
    if !pad.is_empty() && (pad.len() != expected_pad || pad.iter().any(|b| *b != b'=')) {
        return Err(TotpError::InvalidSecret);
    }
    let out_len = data_len * 5 / 8;
    if !(MIN_SECRET_LEN..=MAX_SECRET_LEN).contains(&out_len) {
        return Err(TotpError::InvalidSecret);
    }

    let mut out = Zeroizing::new(Vec::with_capacity(out_len));
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut valid = true;
    for &b in data {
        let (value, ok) = base32_value(b);
        valid &= ok;
        acc = (acc << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).unwrap_or(0));
            acc &= (1 << bits) - 1;
        }
    }
    let trailing_zero = acc == 0;
    acc.zeroize();
    if !valid || !trailing_zero || out.len() != out_len {
        return Err(TotpError::InvalidSecret);
    }
    Ok(SecretBytes::from_zeroizing(out))
}

fn base32_encode(bytes: &[u8]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(bytes.len().div_ceil(5) * 8));
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(base32_char(
                u8::try_from((acc >> bits) & 0x1f).unwrap_or(0),
            )));
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(base32_char(
            u8::try_from((acc << (5 - bits)) & 0x1f).unwrap_or(0),
        )));
    }
    acc.zeroize();
    out
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::test_util::{hex, seeded_rng};

    const SEED_SHA1: &[u8] = b"12345678901234567890";
    const SEED_SHA256: &[u8] = b"12345678901234567890123456789012";
    const SEED_SHA512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

    fn secret(bytes: &[u8]) -> TotpSecret {
        TotpSecret::from_slice(bytes).unwrap()
    }

    #[test]
    fn rfc2202_hmac_sha1() {
        for (key, data, expected) in [
            (
                vec![0x0b; 20],
                b"Hi There".to_vec(),
                "b617318655057264e28bc0b6fb378c8ef146be00",
            ),
            (
                b"Jefe".to_vec(),
                b"what do ya want for nothing?".to_vec(),
                "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
            ),
            (
                vec![0xaa; 80],
                b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
                "aa4ae5e15272d00e95705637ce8a3b55ed402112",
            ),
        ] {
            let mut out = [0u8; 20];
            hmac_into::<Hmac<sha1::Sha1>>(&key, &data, &mut out).unwrap();
            assert_eq!(out.to_vec(), hex(expected));
        }
    }

    /// RFC 4226 Appendix D: HMAC values, truncated values and 6-digit codes for counters 0–9.
    #[test]
    fn rfc4226_appendix_d() {
        let vectors: [(&str, u32, &str); 10] = [
            (
                "cc93cf18508d94934c64b65d8ba7667fb7cde4b0",
                1_284_755_224,
                "755224",
            ),
            (
                "75a48a19d4cbe100644e8ac1397eea747a2d33ab",
                1_094_287_082,
                "287082",
            ),
            (
                "0bacb7fa082fef30782211938bc1c5e70416ff44",
                137_359_152,
                "359152",
            ),
            (
                "66c28227d03a2d5529262ff016a1e6ef76557ece",
                1_726_969_429,
                "969429",
            ),
            (
                "a904c900a64b35909874b33e61c5938a8e15ed1c",
                1_640_338_314,
                "338314",
            ),
            (
                "a37e783d7b7233c083d4f62926c7a25f238d0316",
                868_254_676,
                "254676",
            ),
            (
                "bc9cd28561042c83f219324d3c607256c03272ae",
                1_918_287_922,
                "287922",
            ),
            (
                "a4fb960c0bc06e1eabb804e5b397cdc4b45596fa",
                82_162_583,
                "162583",
            ),
            (
                "1b3c89f65e6c9e883012052823443f048b4332db",
                673_399_871,
                "399871",
            ),
            (
                "1637409809a679dc698207310c8c7fc07290d9e5",
                645_520_489,
                "520489",
            ),
        ];
        let s = secret(SEED_SHA1);
        for (counter, (mac_hex, truncated, code)) in (0u64..).zip(vectors) {
            let mut mac = [0u8; 20];
            hmac_into::<Hmac<sha1::Sha1>>(SEED_SHA1, &counter.to_be_bytes(), &mut mac).unwrap();
            assert_eq!(mac.to_vec(), hex(mac_hex), "counter {counter}");
            assert_eq!(dynamic_truncation(&mac), truncated);
            let otp = hotp(&s, Algorithm::Sha1, Digits::DEFAULT, counter).unwrap();
            assert_eq!(otp.to_digits().as_str(), code);
            assert!(otp.matches(code));
        }
    }

    /// RFC 6238 Appendix B: 8-digit codes for SHA1, SHA256 and SHA512 at six times.
    #[test]
    fn rfc6238_appendix_b() {
        let vectors: [(u64, u64, [&str; 3]); 6] = [
            (59, 1, ["94287082", "46119246", "90693936"]),
            (
                1_111_111_109,
                37_037_036,
                ["07081804", "68084774", "25091201"],
            ),
            (
                1_111_111_111,
                37_037_037,
                ["14050471", "67062674", "99943326"],
            ),
            (
                1_234_567_890,
                41_152_263,
                ["89005924", "91819424", "93441116"],
            ),
            (
                2_000_000_000,
                66_666_666,
                ["69279037", "90698825", "38618901"],
            ),
            (
                20_000_000_000,
                666_666_666,
                ["65353130", "77737706", "47863826"],
            ),
        ];
        let algs = [
            (Algorithm::Sha1, SEED_SHA1),
            (Algorithm::Sha256, SEED_SHA256),
            (Algorithm::Sha512, SEED_SHA512),
        ];
        for (time, step, codes) in vectors {
            for ((algorithm, seed), code) in algs.into_iter().zip(codes) {
                let params = TotpParams {
                    algorithm,
                    digits: Digits::new(8).unwrap(),
                    period: Period::DEFAULT,
                };
                assert_eq!(params.time_step(time), step, "T at {time}");
                let otp = params.code_at(&secret(seed), time).unwrap();
                assert_eq!(otp.to_digits().as_str(), code, "{algorithm:?} at {time}");
            }
        }
    }

    #[test]
    fn allow_lists_reject_never_clamp() {
        for d in [0u8, 5, 9, 10, 255] {
            assert_eq!(Digits::new(d), Err(TotpError::InvalidDigits));
        }
        for d in 6..=8 {
            assert_eq!(Digits::new(d).unwrap().get(), d);
        }
        for p in [0u32, 301, 3600, u32::MAX] {
            assert_eq!(Period::new(p), Err(TotpError::InvalidPeriod));
        }
        assert_eq!(Period::new(1).unwrap().get(), 1);
        assert_eq!(Period::new(300).unwrap().get(), 300);
        for name in ["SHA1", "sha256", "Sha512"] {
            assert!(Algorithm::from_name(name).is_ok());
        }
        for name in ["MD5", "SHA-1", "SHA384", "SHA3-256", ""] {
            assert_eq!(
                Algorithm::from_name(name),
                Err(TotpError::UnsupportedAlgorithm)
            );
        }
        assert!(TotpSecret::from_slice(&[]).is_err());
        assert!(TotpSecret::from_slice(&[0; MAX_SECRET_LEN + 1]).is_err());
    }

    #[test]
    fn codes_are_zero_padded_and_compared_strictly() {
        let code = OtpCode {
            value: 42,
            digits: Digits::DEFAULT,
        };
        assert_eq!(code.to_digits().as_str(), "000042");
        assert!(code.matches("000042"));
        for bad in [
            "42", "0000042", " 000042", "000042 ", "00004２", "-00042", "+00042", "",
        ] {
            assert!(!code.matches(bad), "{bad:?}");
        }
        assert_eq!(format!("{code:?}"), "OtpCode([REDACTED])");
    }

    #[test]
    fn server_verification_window_and_replay() {
        let s = secret(SEED_SHA1);
        let p = TotpParams::DEFAULT;
        let now = 1_111_111_111u64;
        let step = p.time_step(now);
        let code = |st: u64| p.code_at_step(&s, st).unwrap().to_digits();

        // Current step and one either side are accepted, and the accepted step is returned.
        for st in [step - 1, step, step + 1] {
            assert_eq!(p.verify(&s, &code(st), step, None), Ok(st));
        }
        // Two steps away is rejected.
        for st in [step - 2, step + 2] {
            assert_eq!(
                p.verify(&s, &code(st), step, None),
                Err(TotpError::CodeRejected)
            );
        }
        // Replay: the same step, or an older one, after it was accepted.
        let accepted = p.verify(&s, &code(step), step, None).unwrap();
        assert_eq!(
            p.verify(&s, &code(step), step, Some(accepted)),
            Err(TotpError::CodeRejected)
        );
        assert_eq!(
            p.verify(&s, &code(step - 1), step, Some(accepted)),
            Err(TotpError::CodeRejected)
        );
        // A newer step is still fine.
        assert_eq!(
            p.verify(&s, &code(step + 1), step, Some(accepted)),
            Ok(step + 1)
        );
        // Wrong or malformed codes.
        let wrong = format!(
            "{:06}",
            (code(step).parse::<u32>().unwrap() + 1) % 1_000_000
        );
        for bad in [wrong.as_str(), "12345", "1234567", "abcdef", ""] {
            assert_eq!(
                p.verify(&s, bad, step, None),
                Err(TotpError::CodeRejected),
                "{bad}"
            );
        }
        // Step 0 has no predecessor; no underflow.
        assert_eq!(p.verify(&s, &code(0), 0, None), Ok(0));
        assert_eq!(p.verify(&s, &code(u64::MAX), u64::MAX, None), Ok(u64::MAX));
    }

    #[test]
    fn verification_prefers_the_highest_matching_step() {
        // Two neighbouring steps with the same code (about 1 in 10^6 per pair): the highest
        // eligible one is accepted, so the same string cannot be replayed one step later.
        let same = [(9, 123_456), (10, 123_456), (11, 654_321)];
        assert_eq!(select_step(same.into_iter(), 123_456, None), Some(10));
        assert_eq!(select_step(same.into_iter(), 123_456, Some(10)), None);
        assert_eq!(select_step(same.into_iter(), 123_456, Some(9)), Some(10));
        let all = [(9, 7), (10, 7), (11, 7)];
        assert_eq!(select_step(all.into_iter(), 7, Some(9)), Some(11));
        assert_eq!(select_step(all.into_iter(), 8, None), None);
        assert_eq!(select_step([].into_iter(), 7, None), None);
    }

    #[test]
    fn rfc4648_base32_vectors() {
        for (plain, encoded) in [
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            let s = TotpSecret::from_slice(plain.as_bytes()).unwrap();
            assert_eq!(s.to_base32().as_str(), encoded);
            assert_eq!(
                TotpSecret::from_base32(encoded).unwrap().expose_secret(),
                plain.as_bytes()
            );
            let lower = encoded.to_ascii_lowercase();
            assert_eq!(
                TotpSecret::from_base32(&lower).unwrap().expose_secret(),
                plain.as_bytes()
            );
            let padded = format!("{encoded}{}", "=".repeat((8 - encoded.len() % 8) % 8));
            assert_eq!(
                TotpSecret::from_base32(&padded).unwrap().expose_secret(),
                plain.as_bytes()
            );
        }
        for c in 0..32u8 {
            assert_eq!(base32_value(base32_char(c)), (c, true));
        }
        for b in 0..=255u8 {
            let valid = b.is_ascii_alphabetic() || (b'2'..=b'7').contains(&b);
            assert_eq!(base32_value(b).1, valid, "{b:#04x}");
        }
    }

    #[test]
    fn base32_rejections() {
        for bad in [
            "",
            "M",
            "MZX",
            "MZXW6Y",
            "MZXW6YTBO", // impossible lengths
            "MY=",
            "MY======= ",
            "MY=====",
            "MY======M",
            "M=Y=====", // bad padding
            "MZ",
            "MZXR", // non-zero trailing bits ("MY" and "MZXQ" are canonical)
            "MZXW 6YTB",
            "MZXW-6YTB",
            "MZXW1YTB",
            "MZXW8YTB",
            "MZXWéYTB", // bad characters
            "========",
        ] {
            assert!(TotpSecret::from_base32(bad).is_err(), "{bad:?}");
        }
        let too_long = "A".repeat((MAX_SECRET_LEN + 5) * 8 / 5);
        assert!(TotpSecret::from_base32(&too_long).is_err());
    }

    #[test]
    fn otpauth_parsing() {
        let uri = "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME+Co&algorithm=SHA256&digits=7&period=60&image=https%3A%2F%2Fx";
        let parsed = OtpAuthUri::parse(uri).unwrap();
        assert_eq!(parsed.label(), "ACME Co:john.doe@email.com");
        assert_eq!(parsed.issuer(), Some("ACME Co"));
        assert_eq!(parsed.algorithm(), Algorithm::Sha256);
        assert_eq!(parsed.digits().get(), 7);
        assert_eq!(
            parsed.kind(),
            OtpKind::Totp {
                period: Period::new(60).unwrap()
            }
        );
        assert_eq!(parsed.secret().expose_secret().len(), 20);
        let debug = format!("{parsed:?}");
        assert!(!debug.contains("HXDM") && !debug.contains("john") && !debug.contains("ACME"));

        let minimal = OtpAuthUri::parse("OTPAUTH://TOTP/x?secret=gezdgnbvgy3tqojq").unwrap();
        assert_eq!(minimal.totp_params(), Some(TotpParams::DEFAULT));
        assert_eq!(minimal.secret().expose_secret(), b"1234567890");

        let hotp_uri = OtpAuthUri::parse("otpauth://hotp/x?secret=GEZDGNBV&counter=0").unwrap();
        assert_eq!(hotp_uri.kind(), OtpKind::Hotp { counter: 0 });
        assert_eq!(hotp_uri.totp_params(), None);
        let padded = OtpAuthUri::parse("otpauth://totp/x?secret=MY%3D%3D%3D%3D%3D%3D").unwrap();
        assert_eq!(padded.secret().expose_secret(), b"f");
    }

    #[test]
    fn otpauth_rejections() {
        use TotpError as E;
        for (uri, err) in [
            ("otpauth://totp/x", E::MissingParameter),
            ("otpauth://totp/x?issuer=a", E::MissingParameter),
            ("otpauth://hotp/x?secret=GEZDGNBV", E::MissingParameter),
            (
                "otpauth://totp/x?secret=GEZDGNBV&secret=GEZDGNBV",
                E::DuplicateParameter,
            ),
            (
                "otpauth://totp/x?secret=GEZDGNBV&digits=6&digits=6",
                E::DuplicateParameter,
            ),
            (
                "otpauth://totp/x?secret=GEZDGNBV&algorithm=MD5",
                E::UnsupportedAlgorithm,
            ),
            (
                "otpauth://totp/x?secret=GEZDGNBV&digits=10",
                E::InvalidDigits,
            ),
            (
                "otpauth://totp/x?secret=GEZDGNBV&digits=5",
                E::InvalidDigits,
            ),
            (
                "otpauth://totp/x?secret=GEZDGNBV&digits=06",
                E::InvalidDigits,
            ),
            ("otpauth://totp/x?secret=GEZDGNBV&digits=", E::InvalidDigits),
            (
                "otpauth://totp/x?secret=GEZDGNBV&period=0",
                E::InvalidPeriod,
            ),
            (
                "otpauth://totp/x?secret=GEZDGNBV&period=301",
                E::InvalidPeriod,
            ),
            (
                "otpauth://totp/x?secret=GEZDGNBV&period=030",
                E::InvalidPeriod,
            ),
            (
                "otpauth://totp/x?secret=GEZDGNBV&period=-1",
                E::InvalidPeriod,
            ),
            (
                "otpauth://hotp/x?secret=GEZDGNBV&counter=01",
                E::InvalidCounter,
            ),
            (
                "otpauth://hotp/x?secret=GEZDGNBV&counter=18446744073709551616",
                E::InvalidCounter,
            ),
            ("otpauth://totp/x?secret=GEZDGNB1", E::InvalidSecret),
            ("otpauth://totp/x?secret=", E::InvalidSecret),
            ("otpauth://totp/x?secret", E::InvalidSecret),
            ("otpauth://totp/x?secret=GEZD%20GNBV", E::InvalidSecret),
            ("https://totp/x?secret=GEZDGNBV", E::InvalidUri),
            ("otpauth://steam/x?secret=GEZDGNBV", E::InvalidUri),
            ("otpauth:/totp/x?secret=GEZDGNBV", E::InvalidUri),
            ("otpauth://totp?secret=GEZDGNBV", E::InvalidUri),
            ("otpauth://totp/x%ZZ?secret=GEZDGNBV", E::InvalidUri),
            ("otpauth://totp/x%C3?secret=GEZDGNBV", E::InvalidUri),
            ("otpauth://totp/x?secret=GEZDGNBV#frag", E::InvalidUri),
            ("otpauth://totp/é?secret=GEZDGNBV", E::InvalidUri),
        ] {
            assert_eq!(OtpAuthUri::parse(uri).map(|_| ()), Err(err), "{uri}");
        }
        let long = format!("otpauth://totp/{}?secret=GEZDGNBV", "a".repeat(MAX_URI_LEN));
        assert_eq!(OtpAuthUri::parse(&long).map(|_| ()), Err(E::InvalidUri));
    }

    #[test]
    fn otpauth_format_round_trip() {
        let s = TotpSecret::generate(&mut seeded_rng(4));
        let raw = s.expose_secret().to_vec();
        let uri = OtpAuthUri::new_totp(
            "Rizzy Vault:alice@example.com".into(),
            Some("Rizzy Vault+".into()),
            TotpParams::DEFAULT,
            s,
        );
        let text = uri.to_uri();
        assert!(text.starts_with("otpauth://totp/Rizzy%20Vault%3Aalice%40example.com?secret="));
        let back = OtpAuthUri::parse(&text).unwrap();
        assert_eq!(back.label(), "Rizzy Vault:alice@example.com");
        assert_eq!(back.issuer(), Some("Rizzy Vault+"));
        assert_eq!(back.secret().expose_secret(), raw.as_slice());
        assert_eq!(back.totp_params(), Some(TotpParams::DEFAULT));
    }

    proptest! {
        #[test]
        fn otpauth_parser_never_panics(input in "\\PC{0,120}") {
            let _ = OtpAuthUri::parse(&input);
        }

        #[test]
        fn otpauth_query_fuzz(q in "[a-z0-9=&%+A-Z]{0,80}", kind in "(totp|hotp|TOTP)") {
            let uri = format!("otpauth://{kind}/l?{q}");
            if let Ok(parsed) = OtpAuthUri::parse(&uri) {
                let again = OtpAuthUri::parse(&parsed.to_uri()).unwrap();
                prop_assert_eq!(again.secret().expose_secret(), parsed.secret().expose_secret());
                prop_assert_eq!(again.kind(), parsed.kind());
            }
        }

        #[test]
        fn base32_round_trips(bytes in proptest::collection::vec(any::<u8>(), 1..=MAX_SECRET_LEN)) {
            let s = TotpSecret::from_slice(&bytes).unwrap();
            let text = s.to_base32();
            let back = TotpSecret::from_base32(&text).unwrap();
            prop_assert_eq!(back.expose_secret(), bytes.as_slice());
        }

        #[test]
        fn base32_never_panics(input in "[A-Za-z0-9=]{0,64}") {
            let _ = TotpSecret::from_base32(&input);
        }
    }
}
