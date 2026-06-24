//! Host metrics read from `/proc`: uptime, memory and load average.
//! Each reader returns `None` when the source is unavailable so the dashboard
//! can show "unknown" instead of failing.

use serde::Serialize;

/// Memory totals, in kibibytes, as reported by `/proc/meminfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Memory {
    pub total_kb: u64,
    pub available_kb: u64,
}

impl Memory {
    pub fn used_kb(&self) -> u64 {
        self.total_kb.saturating_sub(self.available_kb)
    }

    pub fn used_percent(&self) -> u8 {
        if self.total_kb == 0 {
            return 0;
        }
        ((self.used_kb() as f64 / self.total_kb as f64) * 100.0).round() as u8
    }
}

/// Seconds since boot, from `/proc/uptime`.
pub fn uptime_secs() -> Option<u64> {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|c| parse_uptime(&c))
}

/// Memory totals, from `/proc/meminfo`.
pub fn memory() -> Option<Memory> {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|c| parse_meminfo(&c))
}

/// The 1/5/15-minute load averages, from `/proc/loadavg`.
pub fn load_average() -> Option<[f64; 3]> {
    std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|c| parse_loadavg(&c))
}

/// RX and TX byte counters for `iface`, from `/sys/class/net/<iface>/statistics/`.
pub fn iface_traffic(iface: &str) -> Option<(u64, u64)> {
    let read_stat = |name: &str| -> Option<u64> {
        std::fs::read_to_string(format!("/sys/class/net/{iface}/statistics/{name}"))
            .ok()?
            .trim()
            .parse()
            .ok()
    };
    Some((read_stat("rx_bytes")?, read_stat("tx_bytes")?))
}

/// Device hostname, from `/proc/sys/kernel/hostname`.
pub fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Kernel release string, from `/proc/sys/kernel/osrelease`.
pub fn kernel_version() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// NTP server lines from `/etc/openntpd/ntpd.conf` (`servers` / `server` directives).
pub fn ntp_servers() -> Vec<String> {
    std::fs::read_to_string("/etc/openntpd/ntpd.conf")
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let t = line.trim();
            if t.starts_with("servers ") || t.starts_with("server ") {
                t.splitn(2, ' ').nth(1).map(str::trim).map(String::from)
            } else {
                None
            }
        })
        .collect()
}

fn parse_uptime(content: &str) -> Option<u64> {
    content
        .split_whitespace()
        .next()?
        .parse::<f64>()
        .ok()
        .map(|s| s as u64)
}

fn meminfo_field(content: &str, key: &str) -> Option<u64> {
    content
        .lines()
        .find(|line| line.starts_with(key))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|n| n.parse().ok())
}

fn parse_meminfo(content: &str) -> Option<Memory> {
    Some(Memory {
        total_kb: meminfo_field(content, "MemTotal:")?,
        available_kb: meminfo_field(content, "MemAvailable:")?,
    })
}

fn parse_loadavg(content: &str) -> Option<[f64; 3]> {
    let mut it = content.split_whitespace();
    Some([
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_uptime() {
        assert_eq!(parse_uptime("12345.67 9876.54\n"), Some(12345));
        assert_eq!(parse_uptime(""), None);
    }

    #[test]
    fn parses_meminfo() {
        let sample = "MemTotal:        4000000 kB\nMemFree:  100000 kB\nMemAvailable:    3000000 kB\n";
        let mem = parse_meminfo(sample).unwrap();
        assert_eq!(mem.total_kb, 4_000_000);
        assert_eq!(mem.available_kb, 3_000_000);
        assert_eq!(mem.used_kb(), 1_000_000);
        assert_eq!(mem.used_percent(), 25);
    }

    #[test]
    fn meminfo_missing_field_is_none() {
        assert!(parse_meminfo("MemTotal: 100 kB\n").is_none());
    }

    #[test]
    fn parses_loadavg() {
        assert_eq!(
            parse_loadavg("0.15 0.25 0.35 1/234 5678\n"),
            Some([0.15, 0.25, 0.35])
        );
        assert_eq!(parse_loadavg("0.1 0.2\n"), None);
    }
}
