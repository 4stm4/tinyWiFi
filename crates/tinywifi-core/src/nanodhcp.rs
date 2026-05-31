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

use crate::file::{backup, file_exists, file_readable, file_writable};
use crate::safety::{discard_backup, revert, wait_until_running};
use crate::service::{service_restart, ServiceError};

/// The systemd unit that serves DHCP.
const NANODHCP_SERVICE: &str = "nanodhcp";

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

    /// Overwrite the editable fields from `settings`, keeping `interface` and
    /// `leases_file` as they are.
    pub fn apply(&mut self, settings: &DhcpSettings) {
        self.gateway = settings.gateway;
        self.range_start = settings.range_start;
        self.range_end = settings.range_end;
        self.dns = settings.dns.clone();
        self.lease_time = settings.lease_time;
    }

    /// Serialize back to TOML text.
    pub fn to_toml(&self) -> Result<String, DhcpError> {
        toml::to_string(self).map_err(|e| DhcpError::Parse(e.to_string()))
    }

    /// Structural validation: the pool must be ordered, the gateway must
    /// share the pool's /24, and the lease time must be positive. Collects
    /// every problem found.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.lease_time == 0 {
            errors.push("lease_time must be greater than 0".to_string());
        }

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

/// The user-editable DHCP fields. `interface` and `leases_file` are not
/// editable here and are preserved from the existing config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhcpSettings {
    /// The LAN IP / gateway address handed to clients.
    pub gateway: Ipv4Addr,
    pub range_start: Ipv4Addr,
    pub range_end: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
    pub lease_time: u64,
}

/// Why a DHCP update could not be applied.
#[derive(Debug)]
pub enum DhcpUpdateError {
    /// Config could not be loaded (missing/unreadable/unparseable).
    Load(DhcpError),
    /// Config exists but is not writable.
    NotWritable(PathBuf),
    /// One or more fields failed validation.
    Validation(Vec<String>),
    /// Filesystem error while backing up or writing.
    Io(io::Error),
    /// systemctl could not restart the service.
    Service(ServiceError),
    /// Service restarted but did not come up; config was rolled back.
    RolledBack,
}

impl fmt::Display for DhcpUpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DhcpUpdateError::Load(e) => write!(f, "{e}"),
            DhcpUpdateError::NotWritable(p) => {
                write!(f, "nanodhcp config not writable: {}", p.display())
            }
            DhcpUpdateError::Validation(errs) => {
                write!(f, "invalid settings: {}", errs.join("; "))
            }
            DhcpUpdateError::Io(e) => write!(f, "filesystem error: {e}"),
            DhcpUpdateError::Service(e) => write!(f, "{e}"),
            DhcpUpdateError::RolledBack => {
                write!(f, "nanodhcp failed to start with new config; rolled back")
            }
        }
    }
}

impl std::error::Error for DhcpUpdateError {}

/// Apply new DHCP settings to `path` and restart nanodhcp, committing the
/// change once the service comes up (the `.bak` is discarded).
///
/// Sequence: load the current config (which checks it exists and is
/// readable), merge the edits, validate, confirm the file is writable, back
/// it up, write the new TOML, restart nanodhcp and verify it is running. If
/// the restart fails or the service does not come up, the backup is restored
/// and nanodhcp restarted on the old config before returning an error.
pub fn update_dhcp(path: impl AsRef<Path>, settings: &DhcpSettings) -> Result<(), DhcpUpdateError> {
    apply_dhcp(path.as_ref(), settings, Commit::Now)
}

/// Like [`update_dhcp`], but keeps the `.bak` after a successful restart so the
/// caller can still revert. Used by the web UI's confirm-or-auto-revert flow.
/// The caller must eventually commit ([`discard_backup`]) or revert
/// ([`revert`]).
pub fn stage_dhcp(path: impl AsRef<Path>, settings: &DhcpSettings) -> Result<(), DhcpUpdateError> {
    apply_dhcp(path.as_ref(), settings, Commit::Hold)
}

/// Whether to discard the backup after the service comes up cleanly.
#[derive(Clone, Copy)]
enum Commit {
    Now,
    Hold,
}

fn apply_dhcp(
    path: &Path,
    settings: &DhcpSettings,
    commit: Commit,
) -> Result<(), DhcpUpdateError> {
    let mut config = DhcpConfig::from_path(path).map_err(DhcpUpdateError::Load)?;
    config.apply(settings);
    config.validate().map_err(DhcpUpdateError::Validation)?;

    if !file_writable(path) {
        return Err(DhcpUpdateError::NotWritable(path.to_path_buf()));
    }

    let toml = config.to_toml().map_err(DhcpUpdateError::Load)?;
    backup(path).map_err(DhcpUpdateError::Io)?;
    std::fs::write(path, toml).map_err(DhcpUpdateError::Io)?;

    match service_restart(NANODHCP_SERVICE) {
        Ok(()) if wait_until_running(NANODHCP_SERVICE) => {
            if let Commit::Now = commit {
                discard_backup(path);
            }
            Ok(())
        }
        Ok(()) => {
            revert(path, NANODHCP_SERVICE);
            Err(DhcpUpdateError::RolledBack)
        }
        Err(e) => {
            revert(path, NANODHCP_SERVICE);
            Err(DhcpUpdateError::Service(e))
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

    fn settings() -> DhcpSettings {
        DhcpSettings {
            gateway: Ipv4Addr::new(192, 168, 50, 1),
            range_start: Ipv4Addr::new(192, 168, 50, 50),
            range_end: Ipv4Addr::new(192, 168, 50, 150),
            dns: vec![Ipv4Addr::new(8, 8, 8, 8)],
            lease_time: 3600,
        }
    }

    #[test]
    fn apply_preserves_interface_and_leases_file() {
        let mut cfg = DhcpConfig::parse(REAL_CONFIG).unwrap();
        cfg.apply(&settings());
        assert_eq!(cfg.interface, "wlan0");
        assert_eq!(cfg.leases_file, "/var/lib/nanodhcp/leases.json");
        assert_eq!(cfg.gateway, Ipv4Addr::new(192, 168, 50, 1));
        assert_eq!(cfg.lease_time, 3600);
    }

    #[test]
    fn apply_then_serialize_round_trips() {
        let mut cfg = DhcpConfig::parse(REAL_CONFIG).unwrap();
        cfg.apply(&settings());
        let reparsed = DhcpConfig::parse(&cfg.to_toml().unwrap()).unwrap();
        assert_eq!(cfg, reparsed);
    }

    #[test]
    fn rejects_zero_lease_time() {
        let cfg = DhcpConfig {
            lease_time: 0,
            ..DhcpConfig::parse(REAL_CONFIG).unwrap()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn update_refuses_missing_file() {
        let err = update_dhcp("/nonexistent/nanodhcp.conf", &settings()).unwrap_err();
        assert!(matches!(err, DhcpUpdateError::Load(DhcpError::NotFound(_))));
    }

    #[test]
    fn update_validates_before_touching_disk() {
        let bad = DhcpSettings {
            range_start: Ipv4Addr::new(192, 168, 50, 200),
            range_end: Ipv4Addr::new(192, 168, 50, 50),
            ..settings()
        };
        let err = update_dhcp(
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../configs/nanodhcp.conf"),
            &bad,
        )
        .unwrap_err();
        assert!(matches!(err, DhcpUpdateError::Validation(_)));
    }
}
