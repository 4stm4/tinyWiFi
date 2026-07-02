//! Visibility toggles for optional nav items (Radar/Monitor, AdBlock).
//! Persisted as JSON so it survives restarts; both default to visible so
//! existing installs see no change. When a feature is turned off, its page
//! and API routes 404 (see `require_feature` in main.rs) — the underlying
//! service (e.g. adblock's DNS blocklist) keeps running if it was already
//! enabled, it's just unreachable from the UI until turned back on.

use serde::{Deserialize, Serialize};

pub const FEATURES_FILE: &str = "/etc/tinywifi/features.json";

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Features {
    #[serde(default = "default_true")]
    pub adblock: bool,
    #[serde(default = "default_true")]
    pub monitor: bool,
}

fn default_true() -> bool {
    true
}

impl Default for Features {
    fn default() -> Self {
        Features { adblock: true, monitor: true }
    }
}

/// Falls back to all-enabled if the file is absent or unreadable, so a
/// missing/corrupt file never hides a page unexpectedly.
pub fn read() -> Features {
    std::fs::read_to_string(FEATURES_FILE)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn write(features: &Features) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(features).expect("Features always serializes");
    std::fs::write(FEATURES_FILE, json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_both_enabled() {
        let f = Features::default();
        assert!(f.adblock);
        assert!(f.monitor);
    }

    #[test]
    fn missing_field_defaults_to_enabled() {
        // Configs written before this feature existed have neither key.
        let f: Features = serde_json::from_str("{}").unwrap();
        assert!(f.adblock);
        assert!(f.monitor);
    }

    #[test]
    fn roundtrips_through_json() {
        let f = Features { adblock: false, monitor: true };
        let json = serde_json::to_string(&f).unwrap();
        let back: Features = serde_json::from_str(&json).unwrap();
        assert!(!back.adblock);
        assert!(back.monitor);
    }
}
