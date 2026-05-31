//! Reader for `hostapd.conf`.
//!
//! The file is kept as an ordered list of lines so unknown directives, blank
//! lines and comments survive a read/write round-trip. Only the handful of
//! known Wi-Fi keys are interpreted into [`WifiConfig`]; editing lands in a
//! later milestone.

use std::io;
use std::path::Path;

use serde::Serialize;

use crate::file::{file_exists, file_readable};

const KEY_INTERFACE: &str = "interface";
const KEY_SSID: &str = "ssid";
const KEY_PASSPHRASE: &str = "wpa_passphrase";
const KEY_COUNTRY: &str = "country_code";
const KEY_CHANNEL: &str = "channel";
const KEY_HW_MODE: &str = "hw_mode";

/// One physical line of the config.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Line {
    /// Blank line, comment, or anything that is not a `key=value` pair.
    Raw(String),
    /// A parsed `key=value` directive.
    Pair { key: String, value: String },
}

/// The whole config, preserving original ordering and unknown content.
#[derive(Debug, Clone)]
pub struct HostapdConf {
    lines: Vec<Line>,
    trailing_newline: bool,
}

/// The known Wi-Fi fields, as read from the config. Fields are optional so a
/// missing directive is represented as `None` rather than guessed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WifiConfig {
    pub interface: Option<String>,
    pub ssid: Option<String>,
    pub wpa_passphrase: Option<String>,
    pub country_code: Option<String>,
    pub channel: Option<u16>,
    pub hw_mode: Option<String>,
}

impl HostapdConf {
    /// Parse config text. Never fails: lines it cannot interpret are kept verbatim.
    pub fn parse(content: &str) -> Self {
        let trailing_newline = content.ends_with('\n');
        let lines = content
            .lines()
            .map(|line| {
                let trimmed = line.trim_start();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    return Line::Raw(line.to_string());
                }
                match line.split_once('=') {
                    Some((key, value)) => Line::Pair {
                        key: key.trim().to_string(),
                        value: value.to_string(),
                    },
                    None => Line::Raw(line.to_string()),
                }
            })
            .collect();
        HostapdConf {
            lines,
            trailing_newline,
        }
    }

    /// Read and parse the config at `path`, checking availability first.
    pub fn from_path(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        if !file_exists(path) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("hostapd config not found: {}", path.display()),
            ));
        }
        if !file_readable(path) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("hostapd config not readable: {}", path.display()),
            ));
        }
        Ok(Self::parse(&std::fs::read_to_string(path)?))
    }

    /// Set a directive: update the first matching `key=value` line in place,
    /// or append a new one if the key is absent. Unknown lines are untouched.
    pub fn set(&mut self, key: &str, value: &str) {
        for line in &mut self.lines {
            if let Line::Pair { key: k, value: v } = line {
                if k == key {
                    *v = value.to_string();
                    return;
                }
            }
        }
        self.lines.push(Line::Pair {
            key: key.to_string(),
            value: value.to_string(),
        });
        self.trailing_newline = true;
    }

    /// Apply edited Wi-Fi settings to the known keys.
    pub fn apply(&mut self, settings: &crate::wifi::WifiSettings) {
        self.set(KEY_SSID, &settings.ssid);
        self.set(KEY_PASSPHRASE, &settings.passphrase);
        self.set(KEY_COUNTRY, &settings.country_code);
        self.set(KEY_CHANNEL, &settings.channel.to_string());
    }

    /// Value of the first directive with this key, if present.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.lines.iter().find_map(|line| match line {
            Line::Pair { key: k, value } if k == key => Some(value.as_str()),
            _ => None,
        })
    }

    /// Extract the known Wi-Fi fields into a [`WifiConfig`].
    pub fn wifi_config(&self) -> WifiConfig {
        WifiConfig {
            interface: self.get(KEY_INTERFACE).map(str::to_string),
            ssid: self.get(KEY_SSID).map(str::to_string),
            wpa_passphrase: self.get(KEY_PASSPHRASE).map(str::to_string),
            country_code: self.get(KEY_COUNTRY).map(str::to_string),
            channel: self.get(KEY_CHANNEL).and_then(|v| v.trim().parse().ok()),
            hw_mode: self.get(KEY_HW_MODE).map(str::to_string),
        }
    }
}

impl std::fmt::Display for HostapdConf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, line) in self.lines.iter().enumerate() {
            if i > 0 {
                writeln!(f)?;
            }
            match line {
                Line::Raw(s) => write!(f, "{s}")?,
                Line::Pair { key, value } => write!(f, "{key}={value}")?,
            }
        }
        if self.trailing_newline {
            writeln!(f)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL_CONFIG: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../configs/hostapd.conf"));

    #[test]
    fn reads_known_fields_from_real_config() {
        let conf = HostapdConf::parse(REAL_CONFIG);
        let wifi = conf.wifi_config();
        assert_eq!(wifi.interface.as_deref(), Some("wlan0"));
        assert_eq!(wifi.ssid.as_deref(), Some("4STM4-TinyWifi"));
        assert_eq!(wifi.wpa_passphrase.as_deref(), Some("tinywifi123"));
        assert_eq!(wifi.country_code.as_deref(), Some("GB"));
        assert_eq!(wifi.channel, Some(6));
        assert_eq!(wifi.hw_mode.as_deref(), Some("g"));
    }

    #[test]
    fn round_trips_without_losing_content() {
        let conf = HostapdConf::parse(REAL_CONFIG);
        assert_eq!(conf.to_string(), REAL_CONFIG);
    }

    #[test]
    fn preserves_comments_and_unknown_lines() {
        let input = "# header comment\ninterface=wlan0\n\nsome_unknown_directive=1\nssid=Test\n";
        let conf = HostapdConf::parse(input);
        assert_eq!(conf.to_string(), input);
        assert_eq!(conf.get("some_unknown_directive"), Some("1"));
        assert_eq!(conf.wifi_config().ssid.as_deref(), Some("Test"));
    }

    #[test]
    fn missing_keys_are_none() {
        let conf = HostapdConf::parse("interface=wlan0\n");
        let wifi = conf.wifi_config();
        assert_eq!(wifi.interface.as_deref(), Some("wlan0"));
        assert_eq!(wifi.ssid, None);
        assert_eq!(wifi.channel, None);
    }

    #[test]
    fn set_updates_in_place_and_preserves_layout() {
        let input = "# comment\ninterface=wlan0\nssid=Old\nchannel=6\n";
        let mut conf = HostapdConf::parse(input);
        conf.set("ssid", "New");
        conf.set("channel", "11");
        assert_eq!(conf.to_string(), "# comment\ninterface=wlan0\nssid=New\nchannel=11\n");
    }

    #[test]
    fn set_appends_missing_key() {
        let mut conf = HostapdConf::parse("interface=wlan0\n");
        conf.set("country_code", "GB");
        assert_eq!(conf.to_string(), "interface=wlan0\ncountry_code=GB\n");
    }
}
