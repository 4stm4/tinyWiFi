//! Weekly internet-access schedule.
//!
//! Each day has an optional window during which internet is **on**.
//! Outside the window (or when the day is inactive) internet is blocked.
//!
//! Enforcement uses a dedicated nftables chain `schedule` inside
//! `inet filter`. The chain is empty when internet is allowed;
//! when blocked a single `drop` rule is present.
//! The static nftables config must include this chain and a jump to it
//! from the `forward` chain.

use std::process::Command;

use serde::{Deserialize, Serialize};

pub const SCHEDULE_PATH: &str = "/etc/tinywifi/schedule.json";

/// One day's allowed window. `from` and `to` are "HH:MM" strings.
/// Internet is ON inside [from, to); blocked outside.
/// If `from == to` the whole day is blocked (active=true with zero-length window).
/// Overnight window is supported: `from > to` means ON spans midnight.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DayWindow {
    /// Whether this day's restriction is active. If false: internet always on.
    #[serde(default)]
    pub active: bool,
    /// Time internet turns ON, "HH:MM".
    #[serde(default = "default_from")]
    pub from: String,
    /// Time internet turns OFF, "HH:MM".
    #[serde(default = "default_to")]
    pub to: String,
}

fn default_from() -> String { "07:00".into() }
fn default_to()   -> String { "22:00".into() }

/// Weekly schedule. Index 0=Mon … 6=Sun.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schedule {
    /// Master switch: if false the schedule has no effect.
    #[serde(default)]
    pub enabled: bool,
    /// Per-day windows, Monday first.
    pub days: [DayWindow; 7],
}

impl Default for Schedule {
    fn default() -> Self {
        Self {
            enabled: false,
            days: Default::default(),
        }
    }
}

impl Schedule {
    pub fn load() -> Self {
        let Ok(text) = std::fs::read_to_string(SCHEDULE_PATH) else {
            return Self::default();
        };
        serde_json::from_str(&text).unwrap_or_default()
    }

    pub fn save(&self) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("serialize schedule: {e}"))?;
        std::fs::write(SCHEDULE_PATH, json)
            .map_err(|e| format!("write {SCHEDULE_PATH}: {e}"))?;
        Ok(())
    }

    /// Returns true if internet should be blocked right now.
    pub fn should_block_now(&self) -> bool {
        if !self.enabled { return false; }
        let (weekday, hour, minute) = local_time();
        let window = &self.days[weekday as usize];
        if !window.active { return false; }
        let current = hour * 60 + minute;
        let from = parse_hhmm(&window.from).unwrap_or(0);
        let to   = parse_hhmm(&window.to).unwrap_or(1440);
        if from == to {
            return true; // whole day blocked
        }
        if from < to {
            // Normal window: ON during [from, to)
            !(from <= current && current < to)
        } else {
            // Overnight: ON spans midnight → [from..1440) + [0..to)
            // Blocked during [to, from)
            to <= current && current < from
        }
    }
}

// ── nftables enforcement ──────────────────────────────────────────────────────

/// Returns true if internet is currently blocked by the schedule chain.
pub fn is_inet_blocked() -> bool {
    let Ok(out) = Command::new("nft")
        .args(["list", "chain", "inet", "filter", "schedule"])
        .output()
    else {
        return false;
    };
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines().any(|l| l.trim() == "drop")
}

/// Block internet for LAN clients via the schedule chain.
pub fn inet_block() -> Result<(), String> {
    if is_inet_blocked() { return Ok(()); }
    nft(&["add", "rule", "inet", "filter", "schedule", "drop"])
}

/// Unblock internet: flush the schedule chain.
pub fn inet_unblock() -> Result<(), String> {
    if !is_inet_blocked() { return Ok(()); }
    nft(&["flush", "chain", "inet", "filter", "schedule"])
}

/// Apply or remove the block based on the current schedule state.
/// Returns true if the nft state changed.
pub fn apply_schedule(schedule: &Schedule) -> Result<bool, String> {
    let want_block = schedule.should_block_now();
    let is_blocked = is_inet_blocked();
    if want_block == is_blocked { return Ok(false); }
    if want_block { inet_block()?; } else { inet_unblock()?; }
    Ok(true)
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn nft(args: &[&str]) -> Result<(), String> {
    let out = Command::new("nft").args(args).output()
        .map_err(|e| format!("nft: {e}"))?;
    if out.status.success() { return Ok(()); }
    Err(format!("nft {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim()))
}

fn parse_hhmm(s: &str) -> Option<u32> {
    let (h, m) = s.split_once(':')?;
    Some(h.trim().parse::<u32>().ok()? * 60 + m.trim().parse::<u32>().ok()?)
}

/// Returns (weekday 0=Mon…6=Sun, hour, minute) in local time.
fn local_time() -> (u8, u32, u32) {
    let Ok(out) = Command::new("date").args(["+%u %H %M"]).output() else {
        return (0, 0, 0);
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let mut it = text.split_whitespace();
    let wd = it.next().and_then(|s| s.parse::<u8>().ok()).unwrap_or(1).saturating_sub(1);
    let h  = it.next().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
    let m  = it.next().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
    (wd, h, m)
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn window(active: bool, from: &str, to: &str) -> DayWindow {
        DayWindow { active, from: from.into(), to: to.into() }
    }

    fn sched_with_day(day: usize, w: DayWindow) -> Schedule {
        let mut s = Schedule::default();
        s.enabled = true;
        s.days[day] = w;
        s
    }

    fn mins_to_blocked(s: &Schedule, weekday: u8, h: u32, m: u32) -> bool {
        if !s.enabled { return false; }
        let window = &s.days[weekday as usize];
        if !window.active { return false; }
        let current = h * 60 + m;
        let from = parse_hhmm(&window.from).unwrap_or(0);
        let to   = parse_hhmm(&window.to).unwrap_or(1440);
        if from == to { return true; }
        if from < to {
            !(from <= current && current < to)
        } else {
            to <= current && current < from
        }
    }

    #[test]
    fn disabled_never_blocks() {
        let s = Schedule::default(); // enabled=false
        assert!(!mins_to_blocked(&s, 0, 23, 0));
    }

    #[test]
    fn inactive_day_never_blocks() {
        let s = sched_with_day(0, window(false, "07:00", "22:00"));
        assert!(!mins_to_blocked(&s, 0, 3, 0));
    }

    #[test]
    fn normal_window_blocks_outside() {
        let s = sched_with_day(0, window(true, "07:00", "22:00"));
        assert!(mins_to_blocked(&s, 0, 6, 59),  "before window");
        assert!(!mins_to_blocked(&s, 0, 7, 0),  "at start");
        assert!(!mins_to_blocked(&s, 0, 14, 0), "midday");
        assert!(!mins_to_blocked(&s, 0, 21, 59),"before end");
        assert!(mins_to_blocked(&s, 0, 22, 0),  "at end");
        assert!(mins_to_blocked(&s, 0, 23, 30), "after end");
    }

    #[test]
    fn overnight_window() {
        // ON from 22:00 to 06:00 next day
        let s = sched_with_day(0, window(true, "22:00", "06:00"));
        assert!(!mins_to_blocked(&s, 0, 22, 0), "at start overnight");
        assert!(!mins_to_blocked(&s, 0, 0, 0),  "midnight");
        assert!(!mins_to_blocked(&s, 0, 5, 59), "before end overnight");
        assert!(mins_to_blocked(&s, 0, 6, 0),   "at end overnight");
        assert!(mins_to_blocked(&s, 0, 14, 0),  "midday blocked");
    }

    #[test]
    fn whole_day_blocked() {
        let s = sched_with_day(0, window(true, "00:00", "00:00"));
        assert!(mins_to_blocked(&s, 0, 0, 0));
        assert!(mins_to_blocked(&s, 0, 12, 0));
    }
}
