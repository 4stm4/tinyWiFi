//! Shared core for TinyWifi: service/file/interface checks, config parsing,
//! and the data model used by the web UI and the display daemon.
//!
//! Project rule: always check service/file/interface availability *before*
//! reading, restarting, or rendering data.

pub mod amnezia;
pub mod config;
pub mod file;
pub mod hostapd;
pub mod interface;
pub mod leases;
pub mod metrics;
pub mod nanodhcp;
pub mod safety;
pub mod service;
pub mod status;
pub mod wifi;

pub use amnezia::{
    awg_binary, import_tunnel, parse_awg_show, parse_conf as parse_awg_conf, scan_tunnels,
    tunnel_down, tunnel_up, AwgInterface, AwgPeer, AwgShowIface, AwgTunnel,
    AwgTunnelStatus, ImportError, AWG_CONF_DIR,
};
pub use config::{ConfigError, TinywifiConfig};
pub use hostapd::{HostapdConf, WifiConfig};
pub use interface::{has_default_route, interface_exists, interface_has_ip, interface_ipv4};
pub use leases::{Lease, LeaseStatus, LeasesReport, LeasesState};
pub use metrics::{load_average, memory, uptime_secs, Memory};
pub use nanodhcp::{stage_dhcp, update_dhcp, DhcpConfig, DhcpError, DhcpSettings, DhcpUpdateError};
pub use safety::{discard_backup, revert, wait_until_running, AutoRevert};
pub use service::{
    service_exists, service_reload_or_restart, service_restart, service_running, service_start,
    service_status, service_stop, ServiceError, ServiceStatus,
};
pub use status::{InterfaceStatus, LeasesStatus, SystemStatus};
pub use wifi::{stage_wifi, update_wifi, WifiError, WifiSettings};

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
