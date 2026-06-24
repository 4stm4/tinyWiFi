//! Reader/editor for the nanodns config (`/etc/nanodns/config`).
//!
//! Same line-preserving `key=value` format as nanodhcp.  The only editable
//! sections are the local zone (`domain`), upstream resolvers (`upstream=`,
//! repeatable), and static A-records (`record=name,type,value,ttl`,
//! repeatable).  All other keys (listen, router_name, lease_file, cache…)
//! survive a round-trip unchanged.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::file::{file_exists, file_readable, file_writable};
use crate::service::service_restart;

const NANODNS_SERVICE: &str = "nanodns";

const K_DOMAIN: &str = "domain";
const K_UPSTREAM: &str = "upstream";
const K_RECORD: &str = "record";

// ── Line-preserving config parser ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
enum Line {
    Raw(String),
    Pair { key: String, value: String },
}

/// Line-preserving view of the nanodns config.  Edits update or append pairs
/// and leave comments, blanks, and unknown keys untouched.
#[derive(Debug, Clone)]
pub struct NanoDnsConf {
    lines: Vec<Line>,
}

impl NanoDnsConf {
    pub fn parse(content: &str) -> Self {
        let lines = content
            .lines()
            .map(|line| {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    return Line::Raw(line.to_string());
                }
                match line.split_once('=') {
                    Some((k, v)) => Line::Pair {
                        key: k.trim().to_string(),
                        value: v.trim().to_string(),
                    },
                    None => Line::Raw(line.to_string()),
                }
            })
            .collect();
        NanoDnsConf { lines }
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, DnsError> {
        let path = path.as_ref();
        if !file_exists(path) {
            return Err(DnsError::NotFound(path.to_path_buf()));
        }
        if !file_readable(path) {
            return Err(DnsError::NotReadable(path.to_path_buf()));
        }
        let content = std::fs::read_to_string(path).map_err(DnsError::Io)?;
        Ok(Self::parse(&content))
    }

    /// First value for `key`.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.lines.iter().find_map(|l| match l {
            Line::Pair { key: k, value } if k == key => Some(value.as_str()),
            _ => None,
        })
    }

    /// Set (or append) a single-value key.
    pub fn set(&mut self, key: &str, value: &str) {
        for l in &mut self.lines {
            if let Line::Pair { key: k, value: v } = l {
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

    /// All values for a repeatable key.
    pub fn get_all(&self, key: &str) -> Vec<&str> {
        self.lines
            .iter()
            .filter_map(|l| match l {
                Line::Pair { key: k, value } if k == key => Some(value.as_str()),
                _ => None,
            })
            .collect()
    }

    /// Remove all lines matching `key`.
    pub fn remove_all(&mut self, key: &str) {
        self.lines
            .retain(|l| !matches!(l, Line::Pair { key: k, .. } if k == key));
    }

    /// Remove the first `key=value` line whose value equals `value`.
    pub fn remove_where(&mut self, key: &str, value: &str) {
        let mut removed = false;
        self.lines.retain(|l| {
            if !removed {
                if let Line::Pair { key: k, value: v } = l {
                    if k == key && v == value {
                        removed = true;
                        return false;
                    }
                }
            }
            true
        });
    }

    /// Append a new `key=value` line.
    pub fn append(&mut self, key: &str, value: &str) {
        self.lines.push(Line::Pair {
            key: key.to_string(),
            value: value.to_string(),
        });
    }
}

impl fmt::Display for NanoDnsConf {
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

// ── Types ─────────────────────────────────────────────────────────────────────

/// User-editable DNS settings (zone name and upstream resolvers).
/// All other config keys are preserved on every write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NanoDnsSettings {
    pub domain: String,
    pub upstreams: Vec<String>,
}

impl Default for NanoDnsSettings {
    fn default() -> Self {
        NanoDnsSettings {
            domain: "lan".to_string(),
            upstreams: vec!["1.1.1.1:53".to_string(), "8.8.8.8:53".to_string()],
        }
    }
}

/// A static DNS record (`record=name,type,value,ttl` in nanodns config).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: String,
    pub value: String,
    pub ttl: u32,
}

impl DnsRecord {
    fn to_conf_value(&self) -> String {
        format!("{},{},{},{}", self.name, self.rtype, self.value, self.ttl)
    }

    fn parse(raw: &str) -> Option<Self> {
        let mut parts = raw.splitn(4, ',');
        let name = parts.next()?.trim().to_string();
        let rtype = parts.next()?.trim().to_uppercase();
        let value = parts.next()?.trim().to_string();
        let ttl: u32 = parts.next()?.trim().parse().ok()?;
        Some(DnsRecord { name, rtype, value, ttl })
    }
}

// ── Error types ───────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum DnsError {
    NotFound(PathBuf),
    NotReadable(PathBuf),
    Io(io::Error),
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsError::NotFound(p) => write!(f, "nanodns config not found: {}", p.display()),
            DnsError::NotReadable(p) => write!(f, "nanodns config not readable: {}", p.display()),
            DnsError::Io(e) => write!(f, "filesystem error: {e}"),
        }
    }
}

impl std::error::Error for DnsError {}

#[derive(Debug)]
pub enum DnsRecordError {
    Load(DnsError),
    NotWritable(PathBuf),
    DuplicateName(String),
    NotFound(String),
    Io(io::Error),
}

impl fmt::Display for DnsRecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsRecordError::Load(e) => write!(f, "{e}"),
            DnsRecordError::NotWritable(p) => write!(f, "not writable: {}", p.display()),
            DnsRecordError::DuplicateName(n) => write!(f, "record '{n}' already exists"),
            DnsRecordError::NotFound(n) => write!(f, "no record named '{n}'"),
            DnsRecordError::Io(e) => write!(f, "filesystem error: {e}"),
        }
    }
}

impl std::error::Error for DnsRecordError {}

// ── Public API ────────────────────────────────────────────────────────────────

/// Return the current zone settings from the config file.
pub fn get_dns_settings(path: impl AsRef<Path>) -> Result<NanoDnsSettings, DnsError> {
    let conf = NanoDnsConf::from_path(path)?;
    Ok(NanoDnsSettings {
        domain: conf.get(K_DOMAIN).unwrap_or("lan").to_string(),
        upstreams: conf.get_all(K_UPSTREAM).into_iter().map(String::from).collect(),
    })
}

/// Write zone settings to the config file and restart nanodns.
/// All other config keys are preserved.
pub fn update_dns_settings(path: impl AsRef<Path>, settings: &NanoDnsSettings) -> Result<(), DnsError> {
    let path = path.as_ref();
    let mut conf = NanoDnsConf::from_path(path)?;
    if !file_writable(path) {
        return Err(DnsError::NotFound(path.to_path_buf()));
    }
    conf.set(K_DOMAIN, &settings.domain);
    conf.remove_all(K_UPSTREAM);
    for up in &settings.upstreams {
        conf.append(K_UPSTREAM, up);
    }
    std::fs::write(path, conf.to_string()).map_err(DnsError::Io)?;
    let _ = service_restart(NANODNS_SERVICE);
    Ok(())
}

/// Return all static DNS records from the config file.
pub fn list_dns_records(path: impl AsRef<Path>) -> Result<Vec<DnsRecord>, DnsError> {
    let conf = NanoDnsConf::from_path(path)?;
    Ok(conf.get_all(K_RECORD).into_iter().filter_map(DnsRecord::parse).collect())
}

/// Add a static DNS record and restart nanodns.
pub fn add_dns_record(path: impl AsRef<Path>, record: &DnsRecord) -> Result<(), DnsRecordError> {
    let path = path.as_ref();
    let mut conf = NanoDnsConf::from_path(path).map_err(DnsRecordError::Load)?;
    let name_lc = record.name.to_lowercase();
    let exists = conf.get_all(K_RECORD).into_iter()
        .filter_map(DnsRecord::parse)
        .any(|r| r.name.to_lowercase() == name_lc && r.rtype == record.rtype);
    if exists {
        return Err(DnsRecordError::DuplicateName(record.name.clone()));
    }
    if !file_writable(path) {
        return Err(DnsRecordError::NotWritable(path.to_path_buf()));
    }
    conf.append(K_RECORD, &record.to_conf_value());
    std::fs::write(path, conf.to_string()).map_err(DnsRecordError::Io)?;
    let _ = service_restart(NANODNS_SERVICE);
    Ok(())
}

/// Remove a static DNS record by name (and type) and restart nanodns.
pub fn remove_dns_record(path: impl AsRef<Path>, name: &str, rtype: &str) -> Result<(), DnsRecordError> {
    let path = path.as_ref();
    let mut conf = NanoDnsConf::from_path(path).map_err(DnsRecordError::Load)?;
    let name_lc = name.to_lowercase();
    let rtype_uc = rtype.to_uppercase();
    let target = conf.get_all(K_RECORD).into_iter()
        .filter_map(DnsRecord::parse)
        .find(|r| r.name.to_lowercase() == name_lc && r.rtype == rtype_uc)
        .ok_or_else(|| DnsRecordError::NotFound(name.to_string()))?;
    if !file_writable(path) {
        return Err(DnsRecordError::NotWritable(path.to_path_buf()));
    }
    conf.remove_where(K_RECORD, &target.to_conf_value());
    std::fs::write(path, conf.to_string()).map_err(DnsRecordError::Io)?;
    let _ = service_restart(NANODNS_SERVICE);
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const REAL_CONFIG: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../configs/nanodns.conf"));

    #[test]
    fn reads_real_config() {
        let conf = NanoDnsConf::parse(REAL_CONFIG);
        assert_eq!(conf.get(K_DOMAIN), Some("lan"));
        let ups = conf.get_all(K_UPSTREAM);
        assert!(ups.contains(&"1.1.1.1:53"));
        assert!(ups.contains(&"8.8.8.8:53"));
        let recs: Vec<DnsRecord> = conf.get_all(K_RECORD).into_iter().filter_map(DnsRecord::parse).collect();
        assert_eq!(recs.len(), 2);
        assert!(recs.iter().any(|r| r.name == "admin.lan" && r.value == "192.168.44.1"));
    }

    #[test]
    fn record_roundtrip() {
        let r = DnsRecord { name: "test.lan".into(), rtype: "A".into(), value: "10.0.0.5".into(), ttl: 120 };
        let parsed = DnsRecord::parse(&r.to_conf_value()).unwrap();
        assert_eq!(parsed.name, "test.lan");
        assert_eq!(parsed.rtype, "A");
        assert_eq!(parsed.value, "10.0.0.5");
        assert_eq!(parsed.ttl, 120);
    }

    #[test]
    fn update_settings_preserves_other_keys() {
        let mut conf = NanoDnsConf::parse(REAL_CONFIG);
        conf.set(K_DOMAIN, "home");
        conf.remove_all(K_UPSTREAM);
        conf.append(K_UPSTREAM, "9.9.9.9:53");
        let out = conf.to_string();
        assert!(out.contains("domain=home"));
        assert!(out.contains("upstream=9.9.9.9:53"));
        assert!(!out.contains("1.1.1.1"));
        assert!(out.contains("listen=0.0.0.0:53"));
        assert!(out.contains("lease_file="));
    }

    #[test]
    fn record_crud_in_memory() {
        let mut conf = NanoDnsConf::parse(REAL_CONFIG);
        let initial = conf.get_all(K_RECORD).len();

        conf.append(K_RECORD, "mypc.lan,A,192.168.44.50,60");
        assert_eq!(conf.get_all(K_RECORD).len(), initial + 1);

        conf.remove_where(K_RECORD, "mypc.lan,A,192.168.44.50,60");
        assert_eq!(conf.get_all(K_RECORD).len(), initial);
    }
}
