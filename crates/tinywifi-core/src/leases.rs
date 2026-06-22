//! Reader for the nanodhcp leases file (`/var/lib/nanodhcp/leases`).
//!
//! File format — one lease per line, space-separated:
//!   `<mac> <ip> <hostname> <expiry_unix_secs>`
//!
//! Guards before reading: the file must exist and be readable, and the
//! nanodhcp service state decides whether the data is fresh. The report
//! distinguishes active / stale / empty / error so the UI can render each
//! case without crashing on a missing or malformed file.

use std::net::Ipv4Addr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

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
    /// File unreadable.
    Error,
}

/// One DHCP lease as exposed to the UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Lease {
    pub hostname: Option<String>,
    pub mac: String,
    pub ip: Ipv4Addr,
    /// Unix timestamp (seconds) when the lease expires.
    pub lease_expires: u64,
    pub status: LeaseStatus,
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
        let leases = parse_leases(&content, now);
        LeasesReport {
            state: classify(running, leases.len()),
            leases,
            error: None,
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

/// Parse the nanodhcp leases file: `<mac> <ip> <hostname> <expiry_unix_secs>`.
/// Malformed or empty lines are silently skipped.
pub fn parse_leases(content: &str, now: u64) -> Vec<Lease> {
    content
        .lines()
        .filter_map(|line| parse_line(line.trim(), now))
        .collect()
}

fn parse_line(line: &str, now: u64) -> Option<Lease> {
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut fields = line.splitn(4, ' ');
    let mac = fields.next()?.to_string();
    let ip: Ipv4Addr = fields.next()?.parse().ok()?;
    let hostname_raw = fields.next()?;
    let hostname = if hostname_raw.is_empty() || hostname_raw == "*" {
        None
    } else {
        Some(hostname_raw.to_string())
    };
    let lease_expires: u64 = fields
        .next()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    Some(Lease {
        hostname,
        mac,
        ip,
        lease_expires,
        status: if lease_expires > now {
            LeaseStatus::Active
        } else {
            LeaseStatus::Expired
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    // Format: mac ip hostname expiry_unix_secs
    const SAMPLE: &str = "\
aa:bb:cc:dd:ee:01 192.168.44.100 phone 2000\n\
aa:bb:cc:dd:ee:02 192.168.44.101 * 5000\n";

    fn tmp_path(tag: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("tinywifi_leases_{tag}_{nanos}"))
    }

    #[test]
    fn computes_per_lease_status_against_now() {
        let leases = parse_leases(SAMPLE, 3000);
        assert_eq!(leases.len(), 2);
        // expires 2000 <= now 3000 -> expired
        assert_eq!(leases[0].status, LeaseStatus::Expired);
        assert_eq!(leases[0].hostname.as_deref(), Some("phone"));
        // expires 5000 > now 3000 -> active; hostname "*" -> None
        assert_eq!(leases[1].status, LeaseStatus::Active);
        assert_eq!(leases[1].hostname, None);
    }

    #[test]
    fn real_nanodhcp_format_parses() {
        let input = "a2:f0:b8:05:cf:72 192.168.44.10 4stm4-11 86585\n\
                     66:85:fd:b7:4d:08 192.168.44.11 Macmini 86644\n";
        let leases = parse_leases(input, 0);
        assert_eq!(leases.len(), 2);
        assert_eq!(leases[0].mac, "a2:f0:b8:05:cf:72");
        assert_eq!(leases[0].ip, "192.168.44.10".parse::<Ipv4Addr>().unwrap());
        assert_eq!(leases[0].hostname.as_deref(), Some("4stm4-11"));
        assert_eq!(leases[0].lease_expires, 86585);
    }

    #[test]
    fn malformed_lines_are_skipped() {
        let input = "not-a-line\naa:bb:cc:dd:ee:01 192.168.44.100 host 9999\nbad\n";
        let leases = parse_leases(input, 0);
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].mac, "aa:bb:cc:dd:ee:01");
    }

    #[test]
    fn comment_lines_are_skipped() {
        let input = "# comment\naa:bb:cc:dd:ee:01 192.168.44.100 host 9999\n";
        let leases = parse_leases(input, 0);
        assert_eq!(leases.len(), 1);
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
        let report = LeasesReport::read_at("/nonexistent/leases", 0, true);
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
    fn empty_file_reports_empty() {
        let p = tmp_path("emptyfile");
        std::fs::write(&p, "").unwrap();
        let report = LeasesReport::read_at(&p, 0, true);
        assert_eq!(report.state, LeasesState::Empty);
        std::fs::remove_file(&p).ok();
    }
}
