//! Reader for the nanodhcp leases file (`/var/lib/nanodhcp/leases.json`).
//!
//! Guards before reading: the file must exist and be readable, and the
//! nanodhcp service state decides whether the data is fresh. The report
//! distinguishes active / stale / empty / error so the UI can render each
//! case without crashing on a missing or malformed file.

use std::net::Ipv4Addr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::file::{file_exists, file_readable};
use crate::service::service_running;

const NANODHCP_SERVICE: &str = "nanodhcp";

/// Per-lease validity relative to the current time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LeaseStatus {
    Active,
    Expired,
}

/// Overall freshness of the leases data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LeasesState {
    /// nanodhcp is running and leases are present.
    Active,
    /// Leases are present but nanodhcp is not running (data may be stale).
    Stale,
    /// No leases (file absent or empty list).
    Empty,
    /// File unreadable or JSON malformed.
    Error,
}

/// One DHCP lease as exposed to the UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Lease {
    pub hostname: Option<String>,
    pub mac: String,
    pub ip: Ipv4Addr,
    /// Unix timestamp (seconds) when the lease was granted.
    pub lease_start: u64,
    /// Unix timestamp (seconds) when the lease expires.
    pub lease_expires: u64,
    pub status: LeaseStatus,
}

/// What the leases file looks like on disk, before status is computed.
#[derive(Debug, Clone, Deserialize)]
struct RawLease {
    hostname: Option<String>,
    mac: String,
    ip: Ipv4Addr,
    lease_start: u64,
    lease_expires: u64,
}

/// The result of reading the leases file.
#[derive(Debug, Clone, Serialize)]
pub struct LeasesReport {
    pub state: LeasesState,
    pub leases: Vec<Lease>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl LeasesReport {
    fn empty() -> Self {
        LeasesReport {
            state: LeasesState::Empty,
            leases: Vec::new(),
            error: None,
        }
    }

    fn error(message: impl Into<String>) -> Self {
        LeasesReport {
            state: LeasesState::Error,
            leases: Vec::new(),
            error: Some(message.into()),
        }
    }

    /// Read and classify the leases file at `path`, using the live nanodhcp
    /// service state and the current time.
    pub fn read(path: impl AsRef<Path>) -> Self {
        Self::read_at(path, now_unix(), service_running(NANODHCP_SERVICE))
    }

    fn read_at(path: impl AsRef<Path>, now: u64, running: bool) -> Self {
        let path = path.as_ref();
        if !file_exists(path) {
            return Self::empty();
        }
        if !file_readable(path) {
            return Self::error(format!("leases file not readable: {}", path.display()));
        }
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => return Self::error(format!("failed to read leases file: {e}")),
        };
        match parse_leases(&content, now) {
            Ok(leases) => LeasesReport {
                state: classify(running, leases.len()),
                leases,
                error: None,
            },
            Err(e) => Self::error(e),
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Decide overall freshness from service state and lease count.
fn classify(running: bool, lease_count: usize) -> LeasesState {
    if lease_count == 0 {
        LeasesState::Empty
    } else if running {
        LeasesState::Active
    } else {
        LeasesState::Stale
    }
}

/// Parse leases JSON, computing each lease's status against `now`.
pub fn parse_leases(content: &str, now: u64) -> Result<Vec<Lease>, String> {
    let raw: Vec<RawLease> =
        serde_json::from_str(content).map_err(|e| format!("invalid leases JSON: {e}"))?;
    Ok(raw
        .into_iter()
        .map(|r| Lease {
            hostname: r.hostname,
            mac: r.mac,
            ip: r.ip,
            lease_start: r.lease_start,
            lease_expires: r.lease_expires,
            status: if r.lease_expires > now {
                LeaseStatus::Active
            } else {
                LeaseStatus::Expired
            },
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    const SAMPLE: &str = r#"[
        {"hostname": "phone", "mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.44.100", "lease_start": 1000, "lease_expires": 2000},
        {"hostname": null, "mac": "aa:bb:cc:dd:ee:02", "ip": "192.168.44.101", "lease_start": 1000, "lease_expires": 5000}
    ]"#;

    fn tmp_path(tag: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("tinywifi_leases_{tag}_{nanos}"))
    }

    #[test]
    fn computes_per_lease_status_against_now() {
        let leases = parse_leases(SAMPLE, 3000).unwrap();
        assert_eq!(leases.len(), 2);
        // expires 2000 <= now 3000 -> expired
        assert_eq!(leases[0].status, LeaseStatus::Expired);
        // expires 5000 > now 3000 -> active
        assert_eq!(leases[1].status, LeaseStatus::Active);
        assert_eq!(leases[1].hostname, None);
    }

    #[test]
    fn invalid_json_is_an_error() {
        assert!(parse_leases("{not json", 0).is_err());
    }

    #[test]
    fn classify_covers_the_matrix() {
        assert_eq!(classify(true, 3), LeasesState::Active);
        assert_eq!(classify(false, 3), LeasesState::Stale);
        assert_eq!(classify(true, 0), LeasesState::Empty);
        assert_eq!(classify(false, 0), LeasesState::Empty);
    }

    #[test]
    fn missing_file_reports_empty() {
        let report = LeasesReport::read_at("/nonexistent/leases.json", 0, true);
        assert_eq!(report.state, LeasesState::Empty);
        assert!(report.leases.is_empty());
        assert!(report.error.is_none());
    }

    #[test]
    fn present_leases_with_running_service_are_active() {
        let p = tmp_path("active");
        std::fs::write(&p, SAMPLE).unwrap();
        let report = LeasesReport::read_at(&p, 3000, true);
        assert_eq!(report.state, LeasesState::Active);
        assert_eq!(report.leases.len(), 2);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn present_leases_with_stopped_service_are_stale() {
        let p = tmp_path("stale");
        std::fs::write(&p, SAMPLE).unwrap();
        let report = LeasesReport::read_at(&p, 3000, false);
        assert_eq!(report.state, LeasesState::Stale);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn malformed_file_reports_error() {
        let p = tmp_path("bad");
        std::fs::write(&p, "{not json").unwrap();
        let report = LeasesReport::read_at(&p, 0, true);
        assert_eq!(report.state, LeasesState::Error);
        assert!(report.error.is_some());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn empty_array_reports_empty() {
        let p = tmp_path("emptyarr");
        std::fs::write(&p, "[]").unwrap();
        let report = LeasesReport::read_at(&p, 0, true);
        assert_eq!(report.state, LeasesState::Empty);
        std::fs::remove_file(&p).ok();
    }
}
