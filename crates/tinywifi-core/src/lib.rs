//! Shared core for TinyWifi: service/file/interface checks, config parsing,
//! and the data model used by the web UI and the display daemon.
//!
//! Project rule: always check service/file/interface availability *before*
//! reading, restarting, or rendering data.

pub mod amnezia;
pub mod wan;
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
pub mod acl;
pub mod wifi;

pub use amnezia::{
    awg_binary, import_tunnel, load_bypass_list, parse_awg_show, parse_conf as parse_awg_conf,
    save_bypass_list, scan_tunnels, strip_to_wg_conf, tunnel_down, tunnel_up, AwgInterface,
    AwgPeer, AwgShowIface, AwgTunnel, AwgTunnelStatus, ImportError, AWG_CONF_DIR,
    VPN_BYPASS_PATH,
};
pub use config::{ConfigError, TinywifiConfig};
pub use hostapd::{HostapdConf, WifiConfig};
pub use interface::{has_default_route, interface_exists, interface_has_ip, interface_ipv4};
pub use leases::{Lease, LeaseStatus, LeasesReport, LeasesState};
pub use metrics::{hostname, iface_traffic, kernel_version, load_average, memory, ntp_servers, uptime_secs, Memory};
pub use nanodhcp::{
    add_static_lease, list_static_leases, remove_static_lease, stage_dhcp, update_dhcp, DhcpConfig,
    DhcpError, DhcpSettings, DhcpUpdateError, StaticLease, StaticLeaseError,
};
pub use safety::{discard_backup, revert, wait_until_running, AutoRevert};
pub use service::{
    service_exists, service_reload_or_restart, service_restart, service_running, service_start,
    service_status, service_stop, ServiceError, ServiceStatus,
};
pub use status::{InterfaceStatus, LeasesStatus, SystemStatus};
pub use wan::{
    apply_wan, wan_candidates, wan_status, IfaceState, WanConfig, WanMode, WanStatus,
    WAN_CONF_PATH,
};
pub use acl::{AclMode, AclState, ACL_STATE_FILE};
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
