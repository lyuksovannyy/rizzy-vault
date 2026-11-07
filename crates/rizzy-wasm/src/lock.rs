// SPDX-License-Identifier: AGPL-3.0-only

//! The vault lock settings of [ADR 0110] §1–§4 and §6 point 1, as `rizzy-client`'s
//! [`lock_settings`](rizzy_client::lock_settings) has them: one parser for every client (§3
//! point 3), the encoder, the extension's migration, the bounding rule, and the lock timer.
//!
//! - [`parse_lock_settings`] (`parseLockSettings`) reads the text stored under
//!   `rizzy.lock_settings`; a missing (`null`/`undefined`) or broken record is the defaults. It
//!   never throws.
//! - [`LockSettings`] is a valid value: its constructor throws `invalid_input` for an idle
//!   time outside the list; [`LockSettings::encode`] is the text to store.
//! - [`lock_settings_from_legacy_minutes`] (`lockSettingsFromLegacyMinutes`) is §3 point 5's
//!   migration of the extension's `rizzy.auto_lock_minutes` integer.
//! - [`LockTimer`] is the sans-I/O timer: the host passes both clocks (`performance.now()` and
//!   `Date.now()`, whole milliseconds, as `bigint`) and gets `"idle"`, `"sleep"` or `undefined`.
//! - [`lock_settings_limits`] (`lockSettingsLimits`) gives the keys, the list and the timings.
//!
//! [ADR 0110]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0110-passkey-user-verification.md

use rizzy_client::ClientError;
use rizzy_client::lock_settings::{
    self as ls, ClockReading, LockReason, LockSettings as Settings, LockTimer as Timer, UnlockedBy,
};
use wasm_bindgen::prelude::*;

use crate::error::CoreError;

/// One device's lock settings (ADR 0110 §1); always valid.
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockSettings {
    /// The settings.
    inner: Settings,
}

#[wasm_bindgen]
impl LockSettings {
    /// The settings the UI chose.
    ///
    /// # Errors
    /// `invalid_input` when `idle_minutes` is not one of 1, 2, 5, 10, 15, 30, 60, 240.
    #[wasm_bindgen(constructor)]
    pub fn new(auto_lock: bool, idle_minutes: u16, lock_on_sleep: bool) -> Result<Self, CoreError> {
        Settings::new(auto_lock, idle_minutes, lock_on_sleep)
            .map(|inner| Self { inner })
            .ok_or_else(|| ClientError::InvalidInput.into())
    }

    /// The master toggle.
    #[wasm_bindgen(getter, js_name = autoLock)]
    #[must_use]
    pub fn auto_lock(&self) -> bool {
        self.inner.auto_lock()
    }

    /// The idle time, in minutes.
    #[wasm_bindgen(getter, js_name = idleMinutes)]
    #[must_use]
    pub fn idle_minutes(&self) -> u16 {
        self.inner.idle_minutes()
    }

    /// Always `true` today (ADR 0110 §4.1).
    #[wasm_bindgen(getter, js_name = lockOnRestart)]
    #[must_use]
    pub fn lock_on_restart(&self) -> bool {
        self.inner.lock_on_restart()
    }

    /// The sleep (and screen-lock) switch.
    #[wasm_bindgen(getter, js_name = lockOnSleep)]
    #[must_use]
    pub fn lock_on_sleep(&self) -> bool {
        self.inner.lock_on_sleep()
    }

    /// The canonical record text to store under `rizzy.lock_settings`.
    #[must_use]
    pub fn encode(&self) -> String {
        self.inner.encode()
    }

    /// Whether the policy is bounding (ADR 0110 §6 point 1) for a session last unlocked by
    /// master password (`true`) or otherwise (`false`).
    #[wasm_bindgen(js_name = isBounding)]
    #[must_use]
    pub fn is_bounding(&self, unlocked_by_master_password: bool) -> bool {
        self.inner.is_bounding(if unlocked_by_master_password {
            UnlockedBy::MasterPassword
        } else {
            UnlockedBy::Other
        })
    }
}

/// Reads the stored record; `null`/`undefined` or a broken record is the defaults (ADR 0110 §3
/// point 3).
#[wasm_bindgen(js_name = parseLockSettings)]
#[must_use]
pub fn parse_lock_settings(record: Option<String>) -> LockSettings {
    LockSettings {
        inner: record.map_or(Settings::DEFAULT, |text| Settings::parse(text.as_bytes())),
    }
}

/// The settings migrated from the extension's `rizzy.auto_lock_minutes` (ADR 0110 §3 point 5).
/// The caller passes a stored integer only, clamped to `0..=u32::MAX`.
#[wasm_bindgen(js_name = lockSettingsFromLegacyMinutes)]
#[must_use]
pub fn lock_settings_from_legacy_minutes(minutes: u32) -> LockSettings {
    LockSettings {
        inner: Settings::from_legacy_minutes(u64::from(minutes)),
    }
}

/// The record's keys, the idle list and the timings of ADR 0110.
#[wasm_bindgen]
#[derive(Clone, Copy, Debug)]
pub struct LockSettingsLimits;

#[wasm_bindgen]
impl LockSettingsLimits {
    /// `rizzy.lock_settings`.
    #[wasm_bindgen(getter, js_name = storageKey)]
    #[must_use]
    pub fn storage_key(&self) -> String {
        ls::LOCK_SETTINGS_KEY.to_owned()
    }

    /// `rizzy.auto_lock_minutes`, the extension's key that is migrated.
    #[wasm_bindgen(getter, js_name = legacyStorageKey)]
    #[must_use]
    pub fn legacy_storage_key(&self) -> String {
        ls::LEGACY_AUTO_LOCK_MINUTES_KEY.to_owned()
    }

    /// The longest record read, in bytes.
    #[wasm_bindgen(getter, js_name = maxRecordLength)]
    #[must_use]
    pub fn max_record_length(&self) -> usize {
        ls::MAX_LOCK_SETTINGS_LEN
    }

    /// The idle values, in minutes, in display order.
    #[wasm_bindgen(getter, js_name = idleMinutes)]
    #[must_use]
    pub fn idle_minutes(&self) -> Vec<u16> {
        ls::IDLE_MINUTES.to_vec()
    }

    /// The default idle time, in minutes.
    #[wasm_bindgen(getter, js_name = defaultIdleMinutes)]
    #[must_use]
    pub fn default_idle_minutes(&self) -> u16 {
        ls::DEFAULT_IDLE_MINUTES
    }

    /// The longest bounding idle time, in minutes.
    #[wasm_bindgen(getter, js_name = uvPolicyMaxIdleMinutes)]
    #[must_use]
    pub fn uv_policy_max_idle_minutes(&self) -> u16 {
        ls::UV_POLICY_MAX_IDLE_MINUTES
    }

    /// The turn-off dialog's delay, in milliseconds.
    #[wasm_bindgen(getter, js_name = confirmDelayMs)]
    #[must_use]
    pub fn confirm_delay_ms(&self) -> u32 {
        small(ls::LOCK_DISABLE_CONFIRM_DELAY_MS)
    }

    /// The lock timer's tick, in milliseconds.
    #[wasm_bindgen(getter, js_name = sleepTickMs)]
    #[must_use]
    pub fn sleep_tick_ms(&self) -> u32 {
        small(ls::SLEEP_TICK_MS)
    }

    /// The wall-clock gap that counts as a sleep, in milliseconds.
    #[wasm_bindgen(getter, js_name = sleepGapMs)]
    #[must_use]
    pub fn sleep_gap_ms(&self) -> u32 {
        small(ls::SLEEP_GAP_MS)
    }
}

/// A timing constant as a `u32` (they are all far below it).
fn small(ms: u64) -> u32 {
    u32::try_from(ms).unwrap_or(u32::MAX)
}

/// The lock settings' bounds and timings ([`LockSettingsLimits`]).
#[wasm_bindgen(js_name = lockSettingsLimits)]
#[must_use]
pub fn lock_settings_limits() -> LockSettingsLimits {
    LockSettingsLimits
}

/// The lock timer of one unlocked session (ADR 0110 §4.2–§4.3; module docs).
#[wasm_bindgen]
#[derive(Clone, Copy, Debug)]
pub struct LockTimer {
    /// The timer.
    inner: Timer,
}

/// A reading of the host's clocks.
const fn reading(monotonic_ms: u64, wall_ms: u64) -> ClockReading {
    ClockReading {
        monotonic_ms,
        wall_ms,
    }
}

/// The reason's name for JavaScript.
fn reason(r: Option<LockReason>) -> Option<String> {
    r.map(|r| {
        match r {
            LockReason::Idle => "idle",
            LockReason::Sleep => "sleep",
        }
        .to_owned()
    })
}

#[wasm_bindgen]
impl LockTimer {
    /// A timer started at unlock, which counts as the last input.
    #[wasm_bindgen(constructor)]
    #[must_use]
    pub fn new(settings: &LockSettings, monotonic_ms: u64, wall_ms: u64) -> Self {
        Self {
            inner: Timer::new(settings.inner, reading(monotonic_ms, wall_ms)),
        }
    }

    /// Records user input.
    pub fn input(&mut self, monotonic_ms: u64, wall_ms: u64) {
        self.inner.input(reading(monotonic_ms, wall_ms));
    }

    /// One tick: `"sleep"`, `"idle"` or `undefined`.
    pub fn tick(&mut self, monotonic_ms: u64, wall_ms: u64) -> Option<String> {
        reason(self.inner.tick(reading(monotonic_ms, wall_ms)))
    }

    /// Applies new settings and re-checks the idle deadline at once: `"idle"` or `undefined`.
    #[wasm_bindgen(js_name = setSettings)]
    pub fn set_settings(
        &mut self,
        settings: &LockSettings,
        monotonic_ms: u64,
        wall_ms: u64,
    ) -> Option<String> {
        reason(
            self.inner
                .set_settings(settings.inner, reading(monotonic_ms, wall_ms)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bindings_carry_the_client_rules() {
        let d = parse_lock_settings(None);
        assert!(d.auto_lock() && d.lock_on_restart() && d.lock_on_sleep());
        assert_eq!(d.idle_minutes(), 5);
        assert_eq!(parse_lock_settings(Some("{".into())), d);
        let s = LockSettings::new(false, 15, false).unwrap();
        assert_eq!(parse_lock_settings(Some(s.encode())), s);
        assert_eq!(
            LockSettings::new(true, 3, true).unwrap_err().as_str(),
            "invalid_input"
        );
        assert_eq!(lock_settings_from_legacy_minutes(180).idle_minutes(), 60);
        assert_eq!(lock_settings_from_legacy_minutes(15).idle_minutes(), 15);
        assert!(d.is_bounding(true));
        assert!(!d.is_bounding(false));
        assert!(!LockSettings::new(true, 10, true).unwrap().is_bounding(true));
        let l = lock_settings_limits();
        assert_eq!(l.storage_key(), "rizzy.lock_settings");
        assert_eq!(l.idle_minutes(), [1, 2, 5, 10, 15, 30, 60, 240]);
        assert_eq!(
            (l.confirm_delay_ms(), l.sleep_tick_ms(), l.sleep_gap_ms()),
            (5_000, 10_000, 120_000)
        );

        let one = LockSettings::new(true, 1, true).unwrap();
        let mut t = LockTimer::new(&one, 0, 1_000_000);
        assert_eq!(t.tick(10_000, 1_010_000), None);
        assert_eq!(t.tick(10_000, 1_130_000).as_deref(), Some("sleep"));
        t.input(20_000, 1_140_000);
        assert_eq!(t.tick(80_000, 1_150_000).as_deref(), Some("idle"));
        let off = LockSettings::new(false, 1, true).unwrap();
        assert_eq!(t.set_settings(&off, 90_000, 1_160_000), None);
        assert_eq!(
            t.set_settings(&one, 90_000, 1_160_000).as_deref(),
            Some("idle")
        );
    }
}
