//! Shared core for TinyWifi: service/file/interface checks, config parsing,
//! and the data model used by the web UI and the display daemon.
//!
//! Project rule: always check service/file/interface availability *before*
//! reading, restarting, or rendering data.

pub mod file;
pub mod hostapd;
pub mod interface;
pub mod nanodhcp;
pub mod service;
pub mod status;
pub mod wifi;

pub use hostapd::{HostapdConf, WifiConfig};
pub use nanodhcp::{DhcpConfig, DhcpError};
pub use service::{
    service_exists, service_reload_or_restart, service_restart, service_running, service_start,
    service_status, service_stop, ServiceError, ServiceStatus,
};
pub use status::{InterfaceStatus, LeasesStatus, SystemStatus};
pub use wifi::{update_wifi, WifiError, WifiSettings};

/// Crate version, surfaced in the dashboard and on the display.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        assert!(!VERSION.is_empty());
    }
}
