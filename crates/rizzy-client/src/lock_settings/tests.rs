// SPDX-License-Identifier: AGPL-3.0-only

//! Tests of ADR 0110's lock settings record, the lock timer and the bounding rule
//! (Implementation plan, steps 1 and 3; INV-127's parser tests).

use super::*;

const DEFAULT_TEXT: &str =
    r#"{"v":1,"auto_lock":true,"idle_minutes":5,"lock_on_restart":true,"lock_on_sleep":true}"#;

fn settings(auto_lock: bool, idle_minutes: u16, lock_on_sleep: bool) -> LockSettings {
    LockSettings::new(auto_lock, idle_minutes, lock_on_sleep).unwrap()
}

#[test]
fn the_default_record_round_trips_byte_for_byte() {
    assert_eq!(LockSettings::DEFAULT.encode(), DEFAULT_TEXT);
    assert_eq!(
        LockSettings::parse_strict(DEFAULT_TEXT.as_bytes()),
        Some(LockSettings::DEFAULT)
    );
    assert_eq!(LockSettings::default(), LockSettings::DEFAULT);
    let d = LockSettings::DEFAULT;
    assert!(d.auto_lock() && d.lock_on_restart() && d.lock_on_sleep());
    assert_eq!(d.idle_minutes(), 5);
    assert_eq!(d.idle_ms(), 300_000);
}

#[test]
fn every_valid_value_round_trips() {
    for &m in &IDLE_MINUTES {
        for auto_lock in [false, true] {
            for sleep in [false, true] {
                let s = settings(auto_lock, m, sleep);
                let text = s.encode();
                assert!(text.len() <= MAX_LOCK_SETTINGS_LEN);
                assert_eq!(LockSettings::parse_strict(text.as_bytes()), Some(s));
            }
        }
    }
}

#[test]
fn a_broken_record_means_the_defaults() {
    let off = r#"{"v":1,"auto_lock":false,"idle_minutes":15,"lock_on_restart":true,"lock_on_sleep":false}"#;
    let padded = format!("{off}{}", " ".repeat(MAX_LOCK_SETTINGS_LEN - off.len()));
    assert_eq!(padded.len(), 256);
    assert_eq!(
        LockSettings::parse(padded.as_bytes()),
        settings(false, 15, false)
    );
    let too_long = format!("{padded} ");
    assert_eq!(too_long.len(), 257);
    let field = |name: &str, value: &str| {
        let mut parts = vec![
            ("v", "1"),
            ("auto_lock", "false"),
            ("idle_minutes", "15"),
            ("lock_on_restart", "true"),
            ("lock_on_sleep", "false"),
        ];
        for part in &mut parts {
            if part.0 == name {
                part.1 = value;
            }
        }
        let body: Vec<String> = parts
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, v)| format!("\"{k}\":{v}"))
            .collect();
        format!("{{{}}}", body.join(",")).into_bytes()
    };
    let mut cases: Vec<Vec<u8>> = vec![
        too_long.into_bytes(),
        field("v", "2"),
        field("v", "0"),
        field("v", "1.0"),
        field("v", "\"1\""),
        field("v", ""),
        field("idle_minutes", "3"),
        field("idle_minutes", "0"),
        field("idle_minutes", "65551"),
        field("idle_minutes", "99999999999999999999"),
        field("idle_minutes", "15.0"),
        field("idle_minutes", "1.5e1"),
        field("idle_minutes", "-15"),
        field("idle_minutes", "\"15\""),
        field("idle_minutes", "null"),
        field("idle_minutes", ""),
        field("auto_lock", "\"no\""),
        field("auto_lock", "1"),
        field("auto_lock", ""),
        field("lock_on_restart", "null"),
        field("lock_on_restart", ""),
        field("lock_on_sleep", "0"),
        field("lock_on_sleep", "[]"),
        field("lock_on_sleep", ""),
        br#"[{"v":1,"auto_lock":false,"idle_minutes":15,"lock_on_restart":true,"lock_on_sleep":false}]"#.to_vec(),
        br#"{"v":1,"auto_lock":false,"idle_minutes":15,"lock_on_restart":true,"lock_on_sleep":false,}"#.to_vec(),
        br#"{"v":1,"auto_lock":false,"idle_minutes":15,"lock_on_restart":true,"lock_on_sleep":false} x"#.to_vec(),
        b"\"v\"".to_vec(),
        b"null".to_vec(),
        b"".to_vec(),
        b"15".to_vec(),
        b"{}".to_vec(),
    ];
    // Invalid UTF-8 inside a string member and as a value.
    let mut bad = field("lock_on_sleep", "false");
    bad.splice(1..1, b"\"\xff\":1,".iter().copied());
    cases.push(bad);
    let mut bad = field("lock_on_sleep", "false");
    bad.push(0xff);
    cases.push(bad);
    for case in &cases {
        assert_eq!(
            LockSettings::parse_strict(case),
            None,
            "{}",
            String::from_utf8_lossy(case)
        );
        assert_eq!(LockSettings::parse(case), LockSettings::DEFAULT);
    }
    // The helper itself builds a valid record when nothing is changed.
    assert_eq!(
        LockSettings::parse_strict(&field("v", "1")),
        Some(settings(false, 15, false))
    );
}

#[test]
fn restart_false_reads_true_and_unknown_fields_are_ignored() {
    let text = r#"{ "lock_on_sleep" : false, "extra": [1, {"x": null}], "idle_minutes": 240,
        "lock_on_restart": false, "auto_lock": true, "v": 1 }"#;
    let s = LockSettings::parse_strict(text.as_bytes()).unwrap();
    assert_eq!(s, settings(true, 240, false));
    assert!(s.lock_on_restart());
    assert_eq!(
        s.encode(),
        r#"{"v":1,"auto_lock":true,"idle_minutes":240,"lock_on_restart":true,"lock_on_sleep":false}"#
    );
}

#[test]
fn new_accepts_only_the_list() {
    for m in 0..=300_u16 {
        assert_eq!(
            LockSettings::new(true, m, true).is_some(),
            IDLE_MINUTES.contains(&m),
            "{m}"
        );
    }
    assert_eq!(
        settings(true, 10, false).with_auto_lock(false),
        settings(false, 10, false)
    );
}

#[test]
fn the_legacy_minutes_migrate_to_the_largest_value_not_above() {
    for (old, new) in [
        (0, 1),
        (1, 1),
        (2, 2),
        (3, 2),
        (5, 5),
        (9, 5),
        (10, 10),
        (15, 15),
        (16, 15),
        (59, 30),
        (60, 60),
        (180, 60),
        (239, 60),
        (240, 240),
        (u64::MAX, 240),
    ] {
        assert_eq!(
            LockSettings::from_legacy_minutes(old),
            settings(true, new, true),
            "{old}"
        );
    }
}

#[test]
fn bounding_needs_locking_on_five_minutes_at_most_and_a_master_password_unlock() {
    for &m in &IDLE_MINUTES {
        for sleep in [false, true] {
            assert_eq!(
                settings(true, m, sleep).is_bounding(UnlockedBy::MasterPassword),
                m <= 5,
                "{m}"
            );
            assert!(!settings(true, m, sleep).is_bounding(UnlockedBy::Other));
            assert!(!settings(false, m, sleep).is_bounding(UnlockedBy::MasterPassword));
        }
    }
    assert!(LockSettings::DEFAULT.is_bounding(UnlockedBy::MasterPassword));
    assert_eq!(UV_POLICY_MAX_IDLE_MINUTES, 5);
}

fn at(monotonic_ms: u64, wall_ms: u64) -> ClockReading {
    ClockReading {
        monotonic_ms,
        wall_ms,
    }
}

const WALL: u64 = 1_800_000_000_000;

#[test]
fn the_idle_deadline_fires_by_either_clock() {
    let s = settings(true, 1, false);
    // Monotonic: 59 999 ms is not idle, 60 000 is.
    let mut t = LockTimer::new(s, at(1_000, WALL));
    assert_eq!(t.tick(at(60_999, WALL + 50_000)), None);
    assert_eq!(t.tick(at(61_000, WALL + 55_000)), Some(LockReason::Idle));
    // Wall: a monotonic clock that stopped (asleep) does not hide the time.
    let mut t = LockTimer::new(s, at(1_000, WALL));
    assert_eq!(t.tick(at(1_000, WALL + 59_999)), None);
    assert_eq!(t.tick(at(1_000, WALL + 60_000)), Some(LockReason::Idle));
    // Input restarts the deadline on both clocks.
    let mut t = LockTimer::new(s, at(0, WALL));
    t.input(at(50_000, WALL + 50_000));
    assert_eq!(t.last_input(), at(50_000, WALL + 50_000));
    assert_eq!(t.tick(at(100_000, WALL + 100_000)), None);
    assert_eq!(t.tick(at(110_000, WALL + 110_000)), Some(LockReason::Idle));
    // A wall clock that went back counts as no time on that clock; the monotonic one counts.
    let mut t = LockTimer::new(s, at(0, WALL));
    assert_eq!(t.tick(at(10_000, WALL - 3_600_000)), None);
    assert_eq!(t.tick(at(60_000, WALL - 3_590_000)), Some(LockReason::Idle));
}

#[test]
fn a_wall_gap_of_120_seconds_locks_with_sleep_on_only() {
    let start = at(0, WALL);
    // 120 s locks with sleep on (idle 5 minutes is not yet due by the monotonic clock).
    let mut t = LockTimer::new(settings(true, 5, true), start);
    assert_eq!(t.tick(at(10_000, WALL + 10_000)), None);
    assert_eq!(t.tick(at(10_000, WALL + 130_000)), Some(LockReason::Sleep));
    // Exactly 120 s since the previous tick locks.
    let mut t = LockTimer::new(settings(true, 5, true), start);
    assert_eq!(t.tick(at(10_000, WALL + 120_000)), Some(LockReason::Sleep));
    // 119 s does not.
    let mut t = LockTimer::new(settings(true, 5, true), start);
    assert_eq!(t.tick(at(10_000, WALL + 119_999)), None);
    // With sleep off, 120 s does not.
    let mut t = LockTimer::new(settings(true, 5, false), start);
    assert_eq!(t.tick(at(10_000, WALL + 120_000)), None);
    // A backward jump does not lock and resets the baseline.
    let mut t = LockTimer::new(settings(true, 5, true), start);
    assert_eq!(t.tick(at(10_000, WALL - 600_000)), None);
    assert_eq!(t.tick(at(20_000, WALL - 590_000)), None);
    assert_eq!(t.tick(at(30_000, WALL - 470_000)), Some(LockReason::Sleep));
    // The gap is per tick, not since the start.
    let mut t = LockTimer::new(settings(true, 240, true), start);
    for i in 1..=30 {
        assert_eq!(t.tick(at(i * 10_000, WALL + i * 10_000)), None);
    }
}

#[test]
fn with_locking_off_nothing_locks() {
    let mut t = LockTimer::new(settings(false, 1, true), at(0, WALL));
    assert_eq!(t.tick(at(10_000_000, WALL + 10_000_000)), None);
    assert_eq!(t.tick(at(20_000_000, WALL + 20_000_000)), None);
    assert_eq!(t.idle_due(at(20_000_000, WALL + 20_000_000)), None);
}

#[test]
fn a_settings_change_rechecks_the_deadline_at_once() {
    let mut t = LockTimer::new(settings(false, 5, true), at(0, WALL));
    assert_eq!(t.tick(at(400_000, WALL + 400_000)), None);
    // Turning locking on after 400 s idle with 5 minutes locks immediately (§1 point 3).
    assert_eq!(
        t.set_settings(settings(true, 5, true), at(400_000, WALL + 400_000)),
        Some(LockReason::Idle)
    );
    // A longer N does not lock; a shorter one re-checks at once.
    let mut t = LockTimer::new(settings(true, 10, true), at(0, WALL));
    assert_eq!(
        t.set_settings(settings(true, 15, true), at(200_000, WALL + 200_000)),
        None
    );
    assert_eq!(t.settings(), settings(true, 15, true));
    assert_eq!(
        t.set_settings(settings(true, 2, true), at(200_000, WALL + 200_000)),
        Some(LockReason::Idle)
    );
    // Switching sleep on starts detection now: an earlier gap does not count.
    let mut t = LockTimer::new(settings(true, 240, false), at(0, WALL));
    assert_eq!(
        t.set_settings(settings(true, 240, true), at(0, WALL + 500_000)),
        None
    );
    assert_eq!(t.tick(at(10_000, WALL + 510_000)), None);
}

#[test]
fn the_constants_are_the_adrs() {
    assert_eq!(LOCK_SETTINGS_KEY, "rizzy.lock_settings");
    assert_eq!(LEGACY_AUTO_LOCK_MINUTES_KEY, "rizzy.auto_lock_minutes");
    assert_eq!(MAX_LOCK_SETTINGS_LEN, 256);
    assert_eq!(IDLE_MINUTES, [1, 2, 5, 10, 15, 30, 60, 240]);
    assert_eq!(LOCK_DISABLE_CONFIRM_DELAY_MS, 5_000);
    assert_eq!(SLEEP_TICK_MS, 10_000);
    assert_eq!(SLEEP_GAP_MS, 120_000);
}
