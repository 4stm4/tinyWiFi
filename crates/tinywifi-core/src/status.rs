//! Aggregated system status, the single struct the web UI and display read
//! from. Every field is derived through the guarded checks in [`crate::file`],
//! [`crate::interface`] and [`crate::service`], so collecting status never
//! panics when a service, file or interface is absent.

use std::path::Path;

use serde::Serialize;

use crate::file::{file_exists, file_readable};
use crate::interface::{interface_exists, interface_has_ip};
use crate::service::{service_status, ServiceStatus};

/// Whether the DHCP leases file can be read right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LeasesStatus {
    Available,
    Unavailable,
}

/// State of a network interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum InterfaceStatus {
    /// Interface exists and has an IPv4 address.
    Up,
    /// Interface exists but has no IPv4 address.
    Down,
    /// No such interface.
    Missing,
}

/// Top-level snapshot rendered on the dashboard and the display.
#[derive(Debug, Clone, Serialize)]
pub struct SystemStatus {
    pub hostapd: ServiceStatus,
    pub nanodhcp: ServiceStatus,
    pub leases: LeasesStatus,
    pub wlan0: InterfaceStatus,
}

fn leases_status(path: impl AsRef<Path>) -> LeasesStatus {
    if file_exists(&path) && file_readable(&path) {
        LeasesStatus::Available
    } else {
        LeasesStatus::Unavailable
    }
}

fn interface_status(name: &str) -> InterfaceStatus {
    if !interface_exists(name) {
        InterfaceStatus::Missing
    } else if interface_has_ip(name) {
        InterfaceStatus::Up
    } else {
        InterfaceStatus::Down
    }
}

impl SystemStatus {
    /// Collect a fresh snapshot. `iface` is the AP interface (e.g. `wlan0`)
    /// and `leases_file` is the path to the DHCP leases JSON.
    pub fn collect(iface: &str, leases_file: impl AsRef<Path>) -> Self {
        SystemStatus {
            hostapd: service_status("hostapd"),
            nanodhcp: service_status("nanodhcp"),
            leases: leases_status(leases_file),
            wlan0: interface_status(iface),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_to_expected_shape() {
        let status = SystemStatus {
            hostapd: ServiceStatus::Running,
            nanodhcp: ServiceStatus::Running,
            leases: LeasesStatus::Available,
            wlan0: InterfaceStatus::Up,
        };
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "hostapd": "running",
                "nanodhcp": "running",
                "leases": "available",
                "wlan0": "up"
            })
        );
    }

    #[test]
    fn missing_leases_file_is_unavailable() {
        assert_eq!(
            leases_status("/nonexistent/tinywifi/leases.json"),
            LeasesStatus::Unavailable
        );
    }
}
