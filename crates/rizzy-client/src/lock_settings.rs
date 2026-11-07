// SPDX-License-Identifier: AGPL-3.0-only

//! The vault lock settings of [ADR 0110] §1–§4 and §6: the one per-device record every client
//! reads ([`LockSettings`]), the lock timer that applies it ([`LockTimer`]), and the "bounding"
//! rule that ties `UV` to it ([`LockSettings::is_bounding`]).
//!
//! # The record (ADR 0110 §3)
//!
//! Per device, local only, never synced or sent to the server, not secret and not encrypted.
//! One key on every client, [`LOCK_SETTINGS_KEY`], whose value is a JSON text of at most
//! [`MAX_LOCK_SETTINGS_LEN`] bytes:
//!
//! ```json
//! {"v":1,"auto_lock":true,"idle_minutes":5,"lock_on_restart":true,"lock_on_sleep":true}
//! ```
//!
//! The record is untrusted input (anything with access to the store can rewrite it), so
//! [`LockSettings::parse`] never fails: a text longer than 256 bytes, not JSON, not an object,
//! `v` other than exactly `1`, a missing field or one of the wrong type, or an `idle_minutes`
//! outside [`IDLE_MINUTES`] means the **defaults** (locking on, 5 minutes, restart on, sleep
//! on). Unknown extra fields are ignored. A duplicated member counts by its first occurrence
//! (`rizzy-import`'s JSON reader, whose bounds and strictness this reuses). `lock_on_restart`
//! is read as `true` whatever it says, and always written as `true` (§4.1: no client can keep a
//! vault unlocked across a restart until an Accepted ADR defines key storage that survives one),
//! so a broken or rewritten record never weakens locking below what the user chose in the UI.
//!
//! [`LockSettings::encode`] writes the one canonical text above. What parses encodes to a text
//! that parses to the same settings (the fuzz target `client_lock_settings` checks it).
//!
//! **Migration** (§3 point 5, the extension only): [`LockSettings::from_legacy_minutes`] turns
//! the integer of the code-only key [`LEGACY_AUTO_LOCK_MINUTES_KEY`] into a v1 record: locking
//! on, the largest [`IDLE_MINUTES`] value not above it (at least 1, so a saved value that is in
//! the list is kept as is: 15 stays 15), both switches on.
//!
//! # The lock timer (ADR 0110 §4.2–§4.3)
//!
//! Sans-I/O: the host passes every [`ClockReading`] (its monotonic clock and its wall clock, in
//! milliseconds) and acts on the [`LockReason`] it gets back. It calls [`LockTimer::tick`] every
//! [`SLEEP_TICK_MS`], [`LockTimer::input`] on user input and [`LockTimer::set_settings`] on a
//! settings change.
//!
//! - **Idle** (§4.3): the deadline is N minutes after the last input, checked against **both**
//!   clocks; either one passing it locks. A wall clock that went back counts as no time passed
//!   on that clock (the monotonic one still counts).
//! - **Sleep** (§4.2 point 2): a tick that sees the wall clock moved forward by at least
//!   [`SLEEP_GAP_MS`] since the previous tick means the device slept (or the clock jumped), and
//!   locks when `lock_on_sleep` is on. A backward jump resets the baseline and does not lock.
//! - **Off** (§1 point 2, §4.3 point 3): with the master toggle off, nothing locks. Input is
//!   still recorded, so turning locking on re-checks the deadline against the real time since
//!   the last input (§1 point 3) and a vault idle for longer than N locks at once.
//!
//! # Bounding (ADR 0110 §6 point 1)
//!
//! The policy is bounding if and only if automatic locking is on, `idle_minutes` is at most
//! [`UV_POLICY_MAX_IDLE_MINUTES`] (1, 2 or 5), and the session's last unlock was by master
//! password. The sleep and restart options do not enter the rule (§6 point 3).
//!
//! [ADR 0110]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0110-passkey-user-verification.md

use rizzy_import::json::{self, Json};

/// The storage key of the record on every client (ADR 0110 §3 point 2): `localStorage` in the
/// web vault, `storage.local` in the extension, the app's local preferences natively.
pub const LOCK_SETTINGS_KEY: &str = "rizzy.lock_settings";

/// The extension's code-only key of its previous idle setting, which the first read migrates
/// and removes (ADR 0110 §3 point 5).
pub const LEGACY_AUTO_LOCK_MINUTES_KEY: &str = "rizzy.auto_lock_minutes";

/// The longest record text read, in bytes (ADR 0110 §3 point 2); a longer one means the
/// defaults.
pub const MAX_LOCK_SETTINGS_LEN: usize = 256;

/// The record format this code reads and writes (`"v":1`, ADR 0110 §3 point 4).
pub const LOCK_SETTINGS_VERSION: u16 = 1;

/// The values of "Lock after N minutes idle", in minutes, in display order (ADR 0110 §1). No
/// free entry; anything longer is "off".
pub const IDLE_MINUTES: [u16; 8] = [1, 2, 5, 10, 15, 30, 60, 240];

/// The default idle time, in minutes (ADR 0110 §1, the owner's 5 minutes).
pub const DEFAULT_IDLE_MINUTES: u16 = 5;

/// The longest idle time at which the lock policy still bounds `UV` (ADR 0110 §6 point 1, the
/// owner's answer to Open question 1).
pub const UV_POLICY_MAX_IDLE_MINUTES: u16 = 5;

/// How long the turn-off dialog keeps Confirm disabled, in milliseconds of the monotonic clock
/// (ADR 0110 §2 point 3).
pub const LOCK_DISABLE_CONFIRM_DELAY_MS: u64 = 5_000;

/// The lock timer's tick, in milliseconds (ADR 0110 §4.2 point 2).
pub const SLEEP_TICK_MS: u64 = 10_000;

/// The forward wall-clock jump between two ticks that counts as a sleep, in milliseconds
/// (ADR 0110 §4.2 points 2–3).
pub const SLEEP_GAP_MS: u64 = 120_000;

/// Milliseconds in a minute.
const MS_PER_MINUTE: u64 = 60_000;

/// One device's lock settings (ADR 0110 §1). Always valid: `idle_minutes` is one of
/// [`IDLE_MINUTES`]. `lock_on_restart` is not a field: it is `true` on every client today
/// ([`LockSettings::lock_on_restart`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LockSettings {
    /// The master toggle.
    auto_lock: bool,
    /// One of [`IDLE_MINUTES`].
    idle_minutes: u16,
    /// The sleep (and screen-lock) switch.
    lock_on_sleep: bool,
}

impl Default for LockSettings {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// How the current unlocked session was unlocked, for [`LockSettings::is_bounding`] (ADR 0110
/// §6 point 4: only a master-password unlock counts).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnlockedBy {
    /// The local unlock with the master password, or the master-password OPAQUE login.
    MasterPassword,
    /// Anything else: a keystore-gated unlock, a recovery-code flow.
    Other,
}

impl LockSettings {
    /// The defaults (ADR 0110 §1): locking on, 5 minutes, restart on, sleep on.
    pub const DEFAULT: Self = Self {
        auto_lock: true,
        idle_minutes: DEFAULT_IDLE_MINUTES,
        lock_on_sleep: true,
    };

    /// The settings the UI chose, or `None` when `idle_minutes` is not one of [`IDLE_MINUTES`].
    #[must_use]
    pub fn new(auto_lock: bool, idle_minutes: u16, lock_on_sleep: bool) -> Option<Self> {
        IDLE_MINUTES.contains(&idle_minutes).then_some(Self {
            auto_lock,
            idle_minutes,
            lock_on_sleep,
        })
    }

    /// The master toggle, "Lock the vault automatically".
    #[must_use]
    pub const fn auto_lock(&self) -> bool {
        self.auto_lock
    }

    /// "Lock after N minutes idle": one of [`IDLE_MINUTES`].
    #[must_use]
    pub const fn idle_minutes(&self) -> u16 {
        self.idle_minutes
    }

    /// The idle time in milliseconds.
    #[must_use]
    pub const fn idle_ms(&self) -> u64 {
        // At most 240 × 60 000: no overflow.
        self.idle_minutes as u64 * MS_PER_MINUTE
    }

    /// "Lock when the browser/app restarts": `true` on every client today (ADR 0110 §4.1).
    #[must_use]
    pub const fn lock_on_restart(&self) -> bool {
        true
    }

    /// "Lock when the computer sleeps or hibernates" (screen lock included, where reported).
    #[must_use]
    pub const fn lock_on_sleep(&self) -> bool {
        self.lock_on_sleep
    }

    /// The same settings with the master toggle set to `auto_lock`; the sub-options keep their
    /// values (ADR 0110 §1 point 2).
    #[must_use]
    pub const fn with_auto_lock(self, auto_lock: bool) -> Self {
        Self { auto_lock, ..self }
    }

    /// Whether the lock policy bounds the unlocked time enough for the unlock to count as user
    /// verification (ADR 0110 §6 point 1; module docs).
    #[must_use]
    pub const fn is_bounding(&self, unlocked_by: UnlockedBy) -> bool {
        self.auto_lock
            && self.idle_minutes <= UV_POLICY_MAX_IDLE_MINUTES
            && matches!(unlocked_by, UnlockedBy::MasterPassword)
    }

    /// Reads a record; anything broken means [`LockSettings::DEFAULT`] (module docs).
    #[must_use]
    pub fn parse(record: &[u8]) -> Self {
        Self::parse_strict(record).unwrap_or(Self::DEFAULT)
    }

    /// Reads a record, or `None` when it is broken and [`LockSettings::parse`] would give the
    /// defaults. For tests and the fuzz target; hosts call [`LockSettings::parse`].
    #[must_use]
    pub fn parse_strict(record: &[u8]) -> Option<Self> {
        if record.len() > MAX_LOCK_SETTINGS_LEN {
            return None;
        }
        let root = json::parse(record, MAX_LOCK_SETTINGS_LEN).ok()?;
        root.members()?;
        if small_integer(root.get("v")?)? != LOCK_SETTINGS_VERSION {
            return None;
        }
        let auto_lock = root.get("auto_lock")?.as_bool()?;
        let idle_minutes = small_integer(root.get("idle_minutes")?)?;
        // Read for its type only: `false` is read as `true` (ADR 0110 §3 point 3, §4.1).
        root.get("lock_on_restart")?.as_bool()?;
        let lock_on_sleep = root.get("lock_on_sleep")?.as_bool()?;
        Self::new(auto_lock, idle_minutes, lock_on_sleep)
    }

    /// The canonical record text (module docs); `lock_on_restart` is always `true`.
    #[must_use]
    pub fn encode(&self) -> String {
        format!(
            "{{\"v\":{LOCK_SETTINGS_VERSION},\"auto_lock\":{},\"idle_minutes\":{},\"lock_on_restart\":true,\"lock_on_sleep\":{}}}",
            self.auto_lock, self.idle_minutes, self.lock_on_sleep
        )
    }

    /// The v1 settings migrated from the extension's `rizzy.auto_lock_minutes` integer (ADR 0110
    /// §3 point 5): locking on, the largest [`IDLE_MINUTES`] value not above `minutes` (at
    /// least 1), both switches on.
    #[must_use]
    pub fn from_legacy_minutes(minutes: u64) -> Self {
        let idle_minutes = IDLE_MINUTES
            .iter()
            .copied()
            .filter(|&m| u64::from(m) <= minutes)
            .max()
            .unwrap_or(IDLE_MINUTES[0]);
        Self {
            auto_lock: true,
            idle_minutes,
            lock_on_sleep: true,
        }
    }
}

/// A JSON number written as plain digits that fits a `u16`; anything else (a string, a
/// fraction, an exponent, a sign, a larger value) is `None`.
fn small_integer(value: &Json) -> Option<u16> {
    match value {
        Json::Number(text) if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) => {
            text.parse().ok()
        }
        _ => None,
    }
}

/// One reading of the host's two clocks, in milliseconds: the monotonic one
/// (`performance.now()` or the platform's equivalent, which may stop while the device sleeps)
/// and the wall clock (`Date.now()`, milliseconds since the Unix epoch).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockReading {
    /// The monotonic clock.
    pub monotonic_ms: u64,
    /// The wall clock.
    pub wall_ms: u64,
}

/// Why the lock timer locks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockReason {
    /// No input for the idle time (ADR 0110 §4.3).
    Idle,
    /// A wall-clock gap of at least [`SLEEP_GAP_MS`] between two ticks (ADR 0110 §4.2 point 2).
    Sleep,
}

/// The lock timer of one unlocked session (module docs). Start it at unlock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockTimer {
    /// The settings in force.
    settings: LockSettings,
    /// The last user input (the unlock counts as one).
    last_input: ClockReading,
    /// The wall clock at the previous tick: the sleep-gap baseline.
    previous_tick_wall_ms: u64,
}

impl LockTimer {
    /// A timer that counts the unlock at `now` as the last input.
    #[must_use]
    pub const fn new(settings: LockSettings, now: ClockReading) -> Self {
        Self {
            settings,
            last_input: now,
            previous_tick_wall_ms: now.wall_ms,
        }
    }

    /// The settings in force.
    #[must_use]
    pub const fn settings(&self) -> LockSettings {
        self.settings
    }

    /// The last input, as recorded.
    #[must_use]
    pub const fn last_input(&self) -> ClockReading {
        self.last_input
    }

    /// Records user input at `now`: the idle deadline restarts.
    pub const fn input(&mut self, now: ClockReading) {
        self.last_input = now;
    }

    /// Applies new settings at once (ADR 0110 §1 points 3 and 5): the idle deadline is
    /// re-checked against the time since the last input, and the sleep baseline restarts at
    /// `now`, so switching sleep detection on starts it rather than looking back.
    pub const fn set_settings(
        &mut self,
        settings: LockSettings,
        now: ClockReading,
    ) -> Option<LockReason> {
        self.settings = settings;
        self.previous_tick_wall_ms = now.wall_ms;
        self.idle_due(now)
    }

    /// One tick, every [`SLEEP_TICK_MS`]: a sleep gap since the previous tick, then the idle
    /// deadline. The baseline moves to `now` whatever the clock did (a backward jump resets it).
    pub const fn tick(&mut self, now: ClockReading) -> Option<LockReason> {
        let previous = self.previous_tick_wall_ms;
        self.previous_tick_wall_ms = now.wall_ms;
        if self.settings.auto_lock
            && self.settings.lock_on_sleep
            && now.wall_ms >= previous
            && now.wall_ms - previous >= SLEEP_GAP_MS
        {
            return Some(LockReason::Sleep);
        }
        self.idle_due(now)
    }

    /// The idle deadline alone, by either clock (module docs).
    #[must_use]
    pub const fn idle_due(&self, now: ClockReading) -> Option<LockReason> {
        if !self.settings.auto_lock {
            return None;
        }
        let idle = self.settings.idle_ms();
        let by_monotonic = now
            .monotonic_ms
            .saturating_sub(self.last_input.monotonic_ms);
        let by_wall = now.wall_ms.saturating_sub(self.last_input.wall_ms);
        if by_monotonic >= idle || by_wall >= idle {
            Some(LockReason::Idle)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests;
