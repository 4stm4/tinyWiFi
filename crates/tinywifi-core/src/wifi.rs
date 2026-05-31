//! Editing Wi-Fi settings: validation, plus the guarded save flow
//! (check -> validate -> backup -> write -> restart -> verify -> rollback).

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::file::{backup, file_exists, file_writable, restore_backup};
use crate::hostapd::HostapdConf;
use crate::interface::interface_exists;
use crate::service::{service_restart, service_running, ServiceError};

/// The systemd unit that serves the access point.
const HOSTAPD_SERVICE: &str = "hostapd";

/// 5 GHz channels accepted in addition to the 2.4 GHz range 1..=14.
const CHANNELS_5GHZ: &[u16] = &[
    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165,
];

/// The user-editable Wi-Fi fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WifiSettings {
    pub ssid: String,
    pub passphrase: String,
    pub country_code: String,
    pub channel: u16,
}

/// Why a Wi-Fi update could not be applied.
#[derive(Debug)]
pub enum WifiError {
    /// Config file does not exist.
    NotFound(PathBuf),
    /// Config file exists but is not writable.
    NotWritable(PathBuf),
    /// One or more fields failed validation.
    Validation(Vec<String>),
    /// The configured AP interface is missing.
    InterfaceMissing(String),
    /// Filesystem error while reading/writing/backing up.
    Io(io::Error),
    /// systemctl could not restart the service.
    Service(ServiceError),
    /// Service restarted but did not come up; config was rolled back.
    RolledBack,
}

impl fmt::Display for WifiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WifiError::NotFound(p) => write!(f, "hostapd config not found: {}", p.display()),
            WifiError::NotWritable(p) => {
                write!(f, "hostapd config not writable: {}", p.display())
            }
            WifiError::Validation(errs) => write!(f, "invalid settings: {}", errs.join("; ")),
            WifiError::InterfaceMissing(i) => write!(f, "interface '{i}' does not exist"),
            WifiError::Io(e) => write!(f, "filesystem error: {e}"),
            WifiError::Service(e) => write!(f, "{e}"),
            WifiError::RolledBack => {
                write!(f, "hostapd failed to start with new config; rolled back")
            }
        }
    }
}

impl std::error::Error for WifiError {}

fn is_valid_channel(channel: u16) -> bool {
    (1..=14).contains(&channel) || CHANNELS_5GHZ.contains(&channel)
}

impl WifiSettings {
    /// Validate all fields, collecting every problem rather than stopping at
    /// the first. Returns `Ok` only when the settings are safe to write.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        match self.ssid.len() {
            1..=32 => {}
            _ => errors.push("SSID must be 1-32 characters".to_string()),
        }
        match self.passphrase.len() {
            8..=63 => {}
            _ => errors.push("password must be 8-63 characters".to_string()),
        }
        if self.country_code.len() != 2
            || !self.country_code.chars().all(|c| c.is_ascii_alphabetic())
        {
            errors.push("country must be a 2-letter code".to_string());
        }
        if !is_valid_channel(self.channel) {
            errors.push(format!("channel {} is not a valid Wi-Fi channel", self.channel));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Apply new Wi-Fi settings to `path` and restart hostapd.
///
/// Sequence: confirm the file exists and is writable, validate the settings,
/// confirm the AP interface exists, back up the file, write the changes, then
/// restart hostapd and verify it is running. If the restart fails or the
/// service does not come up, the backup is restored and hostapd restarted on
/// the old config before returning an error.
pub fn update_wifi(path: impl AsRef<Path>, settings: &WifiSettings) -> Result<(), WifiError> {
    let path = path.as_ref();

    if !file_exists(path) {
        return Err(WifiError::NotFound(path.to_path_buf()));
    }
    settings.validate().map_err(WifiError::Validation)?;
    if !file_writable(path) {
        return Err(WifiError::NotWritable(path.to_path_buf()));
    }

    let mut conf = HostapdConf::from_path(path).map_err(WifiError::Io)?;
    if let Some(iface) = conf.wifi_config().interface {
        if !interface_exists(&iface) {
            return Err(WifiError::InterfaceMissing(iface));
        }
    }

    backup(path).map_err(WifiError::Io)?;
    conf.apply(settings);
    std::fs::write(path, conf.to_string()).map_err(WifiError::Io)?;

    match service_restart(HOSTAPD_SERVICE) {
        Ok(()) if service_running(HOSTAPD_SERVICE) => Ok(()),
        Ok(()) => {
            rollback(path);
            Err(WifiError::RolledBack)
        }
        Err(e) => {
            rollback(path);
            Err(WifiError::Service(e))
        }
    }
}

fn rollback(path: &Path) {
    let _ = restore_backup(path);
    let _ = service_restart(HOSTAPD_SERVICE);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> WifiSettings {
        WifiSettings {
            ssid: "TinyWifi".to_string(),
            passphrase: "tinywifi123".to_string(),
            country_code: "GB".to_string(),
            channel: 6,
        }
    }

    #[test]
    fn accepts_valid_settings() {
        assert!(valid().validate().is_ok());
    }

    #[test]
    fn rejects_short_ssid_and_password() {
        let s = WifiSettings {
            ssid: String::new(),
            passphrase: "short".to_string(),
            ..valid()
        };
        let errs = s.validate().unwrap_err();
        assert_eq!(errs.len(), 2);
    }

    #[test]
    fn rejects_bad_country_and_channel() {
        let s = WifiSettings {
            country_code: "GBR".to_string(),
            channel: 200,
            ..valid()
        };
        let errs = s.validate().unwrap_err();
        assert_eq!(errs.len(), 2);
    }

    #[test]
    fn accepts_5ghz_channel() {
        let s = WifiSettings {
            channel: 36,
            ..valid()
        };
        assert!(s.validate().is_ok());
    }

    #[test]
    fn update_refuses_missing_file() {
        let err = update_wifi("/nonexistent/hostapd.conf", &valid()).unwrap_err();
        assert!(matches!(err, WifiError::NotFound(_)));
    }

    #[test]
    fn update_validates_before_touching_disk() {
        // Even with a real file, invalid settings must fail before any write.
        let bad = WifiSettings {
            channel: 999,
            ..valid()
        };
        let err = update_wifi(
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../configs/hostapd.conf"),
            &bad,
        )
        .unwrap_err();
        assert!(matches!(err, WifiError::Validation(_)));
    }
}
