//! Reader/editor for the nanodhcp config (`/etc/nanodhcp/nanodhcp.conf`).
//!
//! The on-device format is line-oriented `key=value` (not TOML), so the file
//! is kept line-preserving — like [`crate::hostapd`] — and unknown keys
//! (`server_ip`, `subnet`, …) survive a round-trip when we edit the pool or
//! DNS. [`DhcpConfig`] is the typed view the API and validation work with;
//! its field names map onto the file's keys via the `K_*` constants.

use std::fmt;
use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::file::{backup, file_exists, file_readable, file_writable};
use crate::safety::{discard_backup, revert, wait_until_running};
use crate::service::{service_restart, ServiceError};

/// The systemd unit / init script that serves DHCP.
const NANODHCP_SERVICE: &str = "nanodhcp";

// File keys mapped onto [`DhcpConfig`] fields.
const K_STATIC: &str = "static";
const K_INTERFACE: &str = "interface";
const K_RANGE_START: &str = "pool_start";
const K_RANGE_END: &str = "pool_end";
const K_GATEWAY: &str = "router";
const K_DNS: &str = "dns";
const K_LEASE_TIME: &str = "lease_time";
const K_LEASES_FILE: &str = "lease_file";

/// A line in the config: either passed through verbatim (blank/comment/
/// unknown) or a recognised `key=value` pair.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Line {
    Raw(String),
    Pair { key: String, value: String },
}

/// Line-preserving view of the config file. Edits update or append pairs and
/// leave everything else untouched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpConf {
    lines: Vec<Line>,
}

impl DhcpConf {
    /// Parse text into lines. `key=value` (optionally spaced, optionally
    /// quoted values) becomes a pair; anything else is preserved verbatim.
    pub fn parse(content: &str) -> Self {
        let lines = content
            .lines()
            .map(|line| {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    return Line::Raw(line.to_string());
                }
                match line.split_once('=') {
                    Some((key, value)) => Line::Pair {
                        key: key.trim().to_string(),
                        value: unquote(value.trim()).to_string(),
                    },
                    None => Line::Raw(line.to_string()),
                }
            })
            .collect();
        DhcpConf { lines }
    }

    /// Read and parse the file, checking availability first (project rule).
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, DhcpError> {
        let path = path.as_ref();
        if !file_exists(path) {
            return Err(DhcpError::NotFound(path.to_path_buf()));
        }
        if !file_readable(path) {
            return Err(DhcpError::NotReadable(path.to_path_buf()));
        }
        let content = std::fs::read_to_string(path).map_err(DhcpError::Io)?;
        Ok(Self::parse(&content))
    }

    /// The value for `key`, if present.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.lines.iter().find_map(|line| match line {
            Line::Pair { key: k, value } if k == key => Some(value.as_str()),
            _ => None,
        })
    }

    /// Set `key` to `value`, updating it in place or appending if new.
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
    }

    /// All values for `key` (supports repeatable keys like `static=`).
    pub fn get_all(&self, key: &str) -> Vec<&str> {
        self.lines
            .iter()
            .filter_map(|line| match line {
                Line::Pair { key: k, value } if k == key => Some(value.as_str()),
                _ => None,
            })
            .collect()
    }

    /// Remove a single `key=value` line whose value equals `value`.
    pub fn remove_where(&mut self, key: &str, value: &str) {
        self.lines.retain(|line| !matches!(line, Line::Pair { key: k, value: v } if k == key && v == value));
    }

    /// Append a new `key=value` line (does not check for duplicates).
    pub fn append(&mut self, key: &str, value: &str) {
        self.lines.push(Line::Pair {
            key: key.to_string(),
            value: value.to_string(),
        });
    }
}

impl fmt::Display for DhcpConf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for line in &self.lines {
            match line {
                Line::Raw(s) => writeln!(f, "{s}")?,
                Line::Pair { key, value } => writeln!(f, "{key}={value}")?,
            }
        }
        Ok(())
    }
}

fn unquote(s: &str) -> &str {
    let b = s.as_bytes();
    if b.len() >= 2 && (b[0] == b'"' || b[0] == b'\'') && b[b.len() - 1] == b[0] {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// The typed view of the known nanodhcp settings.
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

fn require<'a>(conf: &'a DhcpConf, key: &str) -> Result<&'a str, DhcpError> {
    conf.get(key)
        .ok_or_else(|| DhcpError::Parse(format!("missing key '{key}'")))
}

fn parse_ip(conf: &DhcpConf, key: &str) -> Result<Ipv4Addr, DhcpError> {
    require(conf, key)?
        .parse()
        .map_err(|_| DhcpError::Parse(format!("'{key}' is not a valid IPv4 address")))
}

fn parse_dns(value: &str) -> Result<Vec<Ipv4Addr>, DhcpError> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse()
                .map_err(|_| DhcpError::Parse(format!("'{s}' in dns is not a valid IPv4 address")))
        })
        .collect()
}

impl DhcpConfig {
    /// Build the typed view from a parsed file.
    pub fn from_conf(conf: &DhcpConf) -> Result<Self, DhcpError> {
        let lease_time = require(conf, K_LEASE_TIME)?
            .parse()
            .map_err(|_| DhcpError::Parse("'lease_time' is not a number".to_string()))?;
        Ok(DhcpConfig {
            interface: require(conf, K_INTERFACE)?.to_string(),
            range_start: parse_ip(conf, K_RANGE_START)?,
            range_end: parse_ip(conf, K_RANGE_END)?,
            gateway: parse_ip(conf, K_GATEWAY)?,
            dns: conf.get(K_DNS).map(parse_dns).transpose()?.unwrap_or_default(),
            lease_time,
            leases_file: conf
                .get(K_LEASES_FILE)
                .unwrap_or("/var/lib/nanodhcp/leases")
                .to_string(),
        })
    }

    /// Parse the typed view from text.
    pub fn parse(content: &str) -> Result<Self, DhcpError> {
        Self::from_conf(&DhcpConf::parse(content))
    }

    /// Read and parse the typed view from `path`, checking availability first.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, DhcpError> {
        Self::from_conf(&DhcpConf::from_path(path)?)
    }

    /// Structural validation: the pool must be ordered, the gateway must share
    /// the pool's /24, and the lease time must be positive. Collects every
    /// problem found.
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

/// A static DHCP binding: `static=name,mac,ip` in nanodhcp.conf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticLease {
    pub name: String,
    pub mac: String,
    pub ip: Ipv4Addr,
}

impl StaticLease {
    fn to_conf_value(&self) -> String {
        format!("{},{},{}", self.name, self.mac.to_lowercase(), self.ip)
    }

    fn parse(value: &str) -> Option<Self> {
        let mut parts = value.splitn(3, ',');
        let name = parts.next()?.trim().to_string();
        let mac = parts.next()?.trim().to_lowercase();
        let ip: Ipv4Addr = parts.next()?.trim().parse().ok()?;
        Some(StaticLease { name, mac, ip })
    }
}

/// Error type for static lease operations.
#[derive(Debug)]
pub enum StaticLeaseError {
    Load(DhcpError),
    NotWritable(PathBuf),
    DuplicateMac(String),
    DuplicateIp(Ipv4Addr),
    NotFound(String),
    Io(io::Error),
}

impl fmt::Display for StaticLeaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StaticLeaseError::Load(e) => write!(f, "{e}"),
            StaticLeaseError::NotWritable(p) => write!(f, "not writable: {}", p.display()),
            StaticLeaseError::DuplicateMac(m) => write!(f, "MAC {m} already has a static lease"),
            StaticLeaseError::DuplicateIp(ip) => write!(f, "IP {ip} already has a static lease"),
            StaticLeaseError::NotFound(m) => write!(f, "no static lease for MAC {m}"),
            StaticLeaseError::Io(e) => write!(f, "filesystem error: {e}"),
        }
    }
}

impl std::error::Error for StaticLeaseError {}

/// Return all static leases from the config file.
pub fn list_static_leases(path: impl AsRef<Path>) -> Result<Vec<StaticLease>, DhcpError> {
    let conf = DhcpConf::from_path(path)?;
    Ok(conf
        .get_all(K_STATIC)
        .into_iter()
        .filter_map(StaticLease::parse)
        .collect())
}

/// Add a new static lease, writing the config and restarting nanodhcp.
pub fn add_static_lease(path: impl AsRef<Path>, lease: &StaticLease) -> Result<(), StaticLeaseError> {
    let path = path.as_ref();
    let mut conf = DhcpConf::from_path(path).map_err(StaticLeaseError::Load)?;
    let existing: Vec<StaticLease> = conf
        .get_all(K_STATIC)
        .into_iter()
        .filter_map(StaticLease::parse)
        .collect();

    let mac = lease.mac.to_lowercase();
    if existing.iter().any(|l| l.mac == mac) {
        return Err(StaticLeaseError::DuplicateMac(mac));
    }
    if existing.iter().any(|l| l.ip == lease.ip) {
        return Err(StaticLeaseError::DuplicateIp(lease.ip));
    }
    if !file_writable(path) {
        return Err(StaticLeaseError::NotWritable(path.to_path_buf()));
    }

    conf.append(K_STATIC, &lease.to_conf_value());
    std::fs::write(path, conf.to_string()).map_err(StaticLeaseError::Io)?;
    let _ = service_restart(NANODHCP_SERVICE);
    Ok(())
}

/// Remove a static lease by MAC address, writing the config and restarting nanodhcp.
pub fn remove_static_lease(path: impl AsRef<Path>, mac: &str) -> Result<(), StaticLeaseError> {
    let path = path.as_ref();
    let mut conf = DhcpConf::from_path(path).map_err(StaticLeaseError::Load)?;
    let mac_lc = mac.to_lowercase();

    let target = conf
        .get_all(K_STATIC)
        .into_iter()
        .find_map(|v| StaticLease::parse(v).filter(|l| l.mac == mac_lc))
        .ok_or_else(|| StaticLeaseError::NotFound(mac_lc.clone()))?;

    if !file_writable(path) {
        return Err(StaticLeaseError::NotWritable(path.to_path_buf()));
    }

    conf.remove_where(K_STATIC, &target.to_conf_value());
    std::fs::write(path, conf.to_string()).map_err(StaticLeaseError::Io)?;
    let _ = service_restart(NANODHCP_SERVICE);
    Ok(())
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

fn join_dns(dns: &[Ipv4Addr]) -> String {
    dns.iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(",")
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
    /// The init system could not restart the service.
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
/// Sequence: load the current config (checking it exists and is readable),
/// merge the edits into the known keys (preserving everything else), validate,
/// confirm the file is writable, back it up, write it, restart nanodhcp and
/// verify it is running. On failure the backup is restored and nanodhcp
/// restarted on the old config before returning an error.
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

fn apply_dhcp(path: &Path, settings: &DhcpSettings, commit: Commit) -> Result<(), DhcpUpdateError> {
    let mut conf = DhcpConf::from_path(path).map_err(DhcpUpdateError::Load)?;
    conf.set(K_GATEWAY, &settings.gateway.to_string());
    conf.set(K_RANGE_START, &settings.range_start.to_string());
    conf.set(K_RANGE_END, &settings.range_end.to_string());
    conf.set(K_DNS, &join_dns(&settings.dns));
    conf.set(K_LEASE_TIME, &settings.lease_time.to_string());

    let view = DhcpConfig::from_conf(&conf).map_err(DhcpUpdateError::Load)?;
    view.validate().map_err(DhcpUpdateError::Validation)?;

    if !file_writable(path) {
        return Err(DhcpUpdateError::NotWritable(path.to_path_buf()));
    }

    backup(path).map_err(DhcpUpdateError::Io)?;
    std::fs::write(path, conf.to_string()).map_err(DhcpUpdateError::Io)?;

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

    fn real() -> DhcpConfig {
        DhcpConfig::parse(REAL_CONFIG).unwrap()
    }

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
        assert_eq!(cfg.leases_file, "/var/lib/nanodhcp/leases");
    }

    #[test]
    fn real_config_is_valid() {
        assert!(real().validate().is_ok());
    }

    #[test]
    fn tolerates_quoted_and_spaced_values() {
        let cfg = DhcpConfig::parse(
            "interface = \"wlan0\"\npool_start = 192.168.44.100\npool_end=192.168.44.200\nrouter='192.168.44.1'\ndns = 1.1.1.1\nlease_time = 600\nlease_file = /x\n",
        )
        .unwrap();
        assert_eq!(cfg.interface, "wlan0");
        assert_eq!(cfg.gateway, Ipv4Addr::new(192, 168, 44, 1));
        assert_eq!(cfg.dns, vec![Ipv4Addr::new(1, 1, 1, 1)]);
        assert_eq!(cfg.lease_time, 600);
    }

    #[test]
    fn rejects_inverted_range() {
        let cfg = DhcpConfig {
            range_start: Ipv4Addr::new(192, 168, 44, 200),
            range_end: Ipv4Addr::new(192, 168, 44, 100),
            ..real()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_gateway_outside_subnet() {
        let cfg = DhcpConfig {
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            ..real()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_zero_lease_time() {
        let cfg = DhcpConfig {
            lease_time: 0,
            ..real()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_invalid_ip() {
        let bad = "interface=wlan0\npool_start=not-an-ip\npool_end=192.168.44.200\nrouter=192.168.44.1\nlease_time=100\nlease_file=/x\n";
        assert!(matches!(DhcpConfig::parse(bad), Err(DhcpError::Parse(_))));
    }

    #[test]
    fn rejects_missing_required_key() {
        let bad = "interface=wlan0\npool_end=192.168.44.200\nrouter=192.168.44.1\nlease_time=100\n";
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
    fn edit_preserves_unknown_keys_and_interface() {
        let mut conf = DhcpConf::parse(REAL_CONFIG);
        let s = settings();
        conf.set(K_GATEWAY, &s.gateway.to_string());
        conf.set(K_RANGE_START, &s.range_start.to_string());
        let out = conf.to_string();
        // Unknown keys preserved.
        assert!(out.contains("server_ip=192.168.44.1"));
        assert!(out.contains("subnet=192.168.44.0/24"));
        assert!(out.contains("subnet_mask=255.255.255.0"));
        // Interface untouched, edits applied under file's key names.
        assert!(out.contains("interface=wlan0"));
        assert!(out.contains("router=192.168.50.1"));
        assert!(out.contains("pool_start=192.168.50.50"));
        // Round-trips back into the typed view.
        let reparsed = DhcpConfig::parse(&out).unwrap();
        assert_eq!(reparsed.gateway, s.gateway);
        assert_eq!(reparsed.range_start, s.range_start);
        assert_eq!(reparsed.interface, "wlan0");
    }

    #[test]
    fn update_refuses_missing_file() {
        let err = update_dhcp("/nonexistent/nanodhcp.conf", &settings()).unwrap_err();
        assert!(matches!(err, DhcpUpdateError::Load(DhcpError::NotFound(_))));
    }

    #[test]
    fn static_lease_roundtrip() {
        let lease = StaticLease {
            name: "laptop".to_string(),
            mac: "AA:BB:CC:DD:EE:FF".to_string(),
            ip: Ipv4Addr::new(192, 168, 44, 50),
        };
        let parsed = StaticLease::parse(&lease.to_conf_value()).unwrap();
        assert_eq!(parsed.mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(parsed.ip, lease.ip);
        assert_eq!(parsed.name, "laptop");
    }

    #[test]
    fn static_lease_crud_in_memory() {
        let mut conf = DhcpConf::parse(REAL_CONFIG);
        assert!(conf.get_all(K_STATIC).is_empty());

        conf.append(K_STATIC, "pc,aa:bb:cc:00:00:01,192.168.44.51");
        conf.append(K_STATIC, "tv,aa:bb:cc:00:00:02,192.168.44.52");
        let leases: Vec<_> = conf.get_all(K_STATIC).into_iter().filter_map(StaticLease::parse).collect();
        assert_eq!(leases.len(), 2);
        assert_eq!(leases[0].name, "pc");

        conf.remove_where(K_STATIC, "pc,aa:bb:cc:00:00:01,192.168.44.51");
        let leases: Vec<_> = conf.get_all(K_STATIC).into_iter().filter_map(StaticLease::parse).collect();
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].name, "tv");

        let out = conf.to_string();
        assert!(out.contains("static=tv,aa:bb:cc:00:00:02,192.168.44.52"));
        assert!(!out.contains("static=pc"));
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
