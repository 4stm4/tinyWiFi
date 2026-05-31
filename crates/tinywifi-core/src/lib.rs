//! Shared core for TinyWifi: service/file/interface checks, config parsing,
//! and the data model used by the web UI and the display daemon.
//!
//! Project rule: always check service/file/interface availability *before*
//! reading, restarting, or rendering data.

pub mod file;
pub mod interface;
pub mod service;
pub mod status;

pub use service::{
    service_exists, service_reload_or_restart, service_restart, service_running, service_start,
    service_status, ServiceError, ServiceStatus,
};
pub use status::{InterfaceStatus, LeasesStatus, SystemStatus};

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
