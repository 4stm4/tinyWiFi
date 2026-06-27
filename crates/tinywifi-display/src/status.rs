use std::net::Ipv4Addr;

use tinywifi_core::leases::{LeaseStatus, LeasesReport};
use tinywifi_core::{
    has_default_route, interface_ipv4, metrics, HostapdConf, TinywifiConfig,
};

/// The condensed status shown on the device's small screen. Every field is
/// optional or has a safe default so a missing service/file degrades the line
/// rather than crashing the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayStatus {
    pub ssid: Option<String>,
    pub ip: Option<Ipv4Addr>,
    pub clients: usize,
    pub wan: bool,
    pub ram_used_percent: Option<u8>,
    pub uptime_secs: Option<u64>,
}

impl DisplayStatus {
    /// Returns true when all fields except `uptime_secs` are equal.
    pub fn eq_except_uptime(&self, other: &Self) -> bool {
        self.ssid == other.ssid
            && self.ip == other.ip
            && self.clients == other.clients
            && self.wan == other.wan
            && self.ram_used_percent == other.ram_used_percent
    }

    /// Gather a fresh snapshot via core's guarded readers.
    pub fn collect(config: &TinywifiConfig) -> Self {
        let iface = HostapdConf::from_path(&config.paths.hostapd_conf)
            .ok()
            .and_then(|c| c.wifi_config().interface)
            .unwrap_or_else(|| "wlan0".to_string());

        let ssid = HostapdConf::from_path(&config.paths.hostapd_conf)
            .ok()
            .and_then(|c| c.wifi_config().ssid);

        let clients = LeasesReport::read(&config.paths.leases_file)
            .leases
            .iter()
            .filter(|l| l.status == LeaseStatus::Active)
            .count();

        DisplayStatus {
            ssid,
            ip: interface_ipv4(&iface),
            clients,
            wan: has_default_route(),
            ram_used_percent: metrics::memory().map(|m| m.used_percent()),
            uptime_secs: metrics::uptime_secs(),
        }
    }
}
