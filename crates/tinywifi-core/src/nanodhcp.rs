//! Reader for the nanodhcp TOML config (`/etc/nanodhcp/nanodhcp.conf`).
//!
//! Parses into [`DhcpConfig`] and offers structural validation (address
//! ranges and subnet). Interface existence is checked separately by callers
//! that act on the system, so reading stays side-effect free.

use std::fmt;
use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::file::{file_exists, file_readable};

/// The known nanodhcp settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhcpConfig {
    pub interface: String,
    pub range_start: Ipv4Addr,
    pub range_end: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
    pub lease_time: u64,
    pub leases_file: String,
}

/// Why the DHCP config could not be loaded.
#[derive(Debug)]
pub enum DhcpError {
    NotFound(PathBuf),
    NotReadable(PathBuf),
    Parse(String),
    Io(io::Error),
}

impl fmt::Display for DhcpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DhcpError::NotFound(p) => write!(f, "nanodhcp config not found: {}", p.display()),
            DhcpError::NotReadable(p) => {
                write!(f, "nanodhcp config not readable: {}", p.display())
            }
            DhcpError::Parse(e) => write!(f, "invalid nanodhcp config: {e}"),
            DhcpError::Io(e) => write!(f, "filesystem error: {e}"),
        }
    }
}

impl std::error::Error for DhcpError {}

impl DhcpConfig {
    /// Parse TOML text. Invalid IPs and missing keys surface as `Parse`.
    pub fn parse(content: &str) -> Result<Self, DhcpError> {
        toml::from_str(content).map_err(|e| DhcpError::Parse(e.message().to_string()))
    }

    /// Read and parse the config at `path`, checking availability first.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, DhcpError> {
        let path = path.as_ref();
        if !file_exists(path) {
            return Err(DhcpError::NotFound(path.to_path_buf()));
        }
        if !file_readable(path) {
            return Err(DhcpError::NotReadable(path.to_path_buf()));
        }
        let content = std::fs::read_to_string(path).map_err(DhcpError::Io)?;
        Self::parse(&content)
    }

    /// Structural validation: the pool must be ordered and the gateway must
    /// share the pool's /24. Collects every problem found.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if u32::from(self.range_start) > u32::from(self.range_end) {
            errors.push(format!(
                "range_start {} must not be greater than range_end {}",
                self.range_start, self.range_end
            ));
        }

        let net = |ip: Ipv4Addr| {
            let o = ip.octets();
            [o[0], o[1], o[2]]
        };
        if net(self.gateway) != net(self.range_start) || net(self.gateway) != net(self.range_end) {
            errors.push(format!(
                "gateway {} must be in the same /24 subnet as the DHCP range",
                self.gateway
            ));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL_CONFIG: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../configs/nanodhcp.conf"));

    #[test]
    fn reads_real_config() {
        let cfg = DhcpConfig::from_path(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../configs/nanodhcp.conf"
        ))
        .unwrap();
        assert_eq!(cfg.interface, "wlan0");
        assert_eq!(cfg.range_start, Ipv4Addr::new(192, 168, 44, 100));
        assert_eq!(cfg.range_end, Ipv4Addr::new(192, 168, 44, 200));
        assert_eq!(cfg.gateway, Ipv4Addr::new(192, 168, 44, 1));
        assert_eq!(cfg.dns, vec![Ipv4Addr::new(192, 168, 44, 1), Ipv4Addr::new(1, 1, 1, 1)]);
        assert_eq!(cfg.lease_time, 86400);
        assert_eq!(cfg.leases_file, "/var/lib/nanodhcp/leases.json");
    }

    #[test]
    fn real_config_is_valid() {
        assert!(DhcpConfig::parse(REAL_CONFIG).unwrap().validate().is_ok());
    }

    #[test]
    fn rejects_inverted_range() {
        let cfg = DhcpConfig {
            range_start: Ipv4Addr::new(192, 168, 44, 200),
            range_end: Ipv4Addr::new(192, 168, 44, 100),
            ..DhcpConfig::parse(REAL_CONFIG).unwrap()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_gateway_outside_subnet() {
        let cfg = DhcpConfig {
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            ..DhcpConfig::parse(REAL_CONFIG).unwrap()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_invalid_ip() {
        let bad = "interface = \"wlan0\"\nrange_start = \"not-an-ip\"\nrange_end = \"192.168.44.200\"\ngateway = \"192.168.44.1\"\ndns = []\nlease_time = 100\nleases_file = \"/x\"\n";
        assert!(matches!(DhcpConfig::parse(bad), Err(DhcpError::Parse(_))));
    }
}
