//! Ad/tracker blocking via nanodns block_file.
//!
//! Downloads blocklists in hosts format, converts to nanodns domain list
//! (one domain per line), writes to BLOCKLIST_PATH.  nanodns hot-reloads
//! by mtime — no restart needed.

use std::io::{BufRead, Write};
use std::path::Path;
use std::time::SystemTime;

use serde::Serialize;

use crate::nanodns::{get_dns_settings, update_dns_settings};

pub const BLOCKLIST_PATH: &str = "/etc/nanodns/blocklist";

/// Bundled blocklist sources.
pub const SOURCES: &[(&str, &str)] = &[
    (
        "StevenBlack",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    ),
];

#[derive(Debug, Clone, Serialize)]
pub struct AdblockStatus {
    pub enabled: bool,
    pub domain_count: usize,
    /// Unix timestamp of blocklist file modification, None if file missing.
    pub last_updated: Option<u64>,
    pub block_response: String,
}

// ── Status ────────────────────────────────────────────────────────────────────

pub fn adblock_status(conf_path: &Path) -> AdblockStatus {
    let settings = get_dns_settings(conf_path).unwrap_or_default();
    let enabled = settings.block_file.is_some();
    let domain_count = count_domains(BLOCKLIST_PATH);
    let last_updated = std::fs::metadata(BLOCKLIST_PATH)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_secs());
    AdblockStatus {
        enabled,
        domain_count,
        last_updated,
        block_response: settings.block_response,
    }
}

// ── Enable / Disable ──────────────────────────────────────────────────────────

pub fn adblock_enable(conf_path: &Path) -> Result<(), String> {
    let mut settings = get_dns_settings(conf_path)
        .map_err(|e| e.to_string())?;
    settings.block_file = Some(BLOCKLIST_PATH.to_string());
    update_dns_settings(conf_path, &settings).map_err(|e| e.to_string())
}

pub fn adblock_disable(conf_path: &Path) -> Result<(), String> {
    let mut settings = get_dns_settings(conf_path)
        .map_err(|e| e.to_string())?;
    settings.block_file = None;
    update_dns_settings(conf_path, &settings).map_err(|e| e.to_string())
}

pub fn adblock_set_response(conf_path: &Path, response: &str) -> Result<(), String> {
    let mut settings = get_dns_settings(conf_path)
        .map_err(|e| e.to_string())?;
    settings.block_response = response.to_string();
    update_dns_settings(conf_path, &settings).map_err(|e| e.to_string())
}

// ── Blocklist update ──────────────────────────────────────────────────────────

/// Download all bundled sources, merge, deduplicate, write to BLOCKLIST_PATH.
/// Returns number of domains written.
pub fn update_blocklist() -> Result<usize, String> {
    let mut domains: std::collections::HashSet<String> = std::collections::HashSet::new();

    for (name, url) in SOURCES {
        match fetch_url(url) {
            Ok(body) => {
                let count_before = domains.len();
                parse_hosts_into(&body, &mut domains);
                let added = domains.len() - count_before;
                let _ = added; // logged implicitly via total
                let _ = name;
            }
            Err(e) => return Err(format!("Failed to fetch {name}: {e}")),
        }
    }

    write_blocklist(BLOCKLIST_PATH, &domains)?;
    Ok(domains.len())
}

fn fetch_url(url: &str) -> Result<String, String> {
    let out = std::process::Command::new("wget")
        .args(["-qO-", "--timeout=30", url])
        .output()
        .map_err(|e| format!("wget: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "wget exit {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    String::from_utf8(out.stdout).map_err(|e| e.to_string())
}

/// Parse a standard hosts file and collect unique domains into `set`.
/// Lines: `0.0.0.0 domain.com` or `# comment` or blank.
fn parse_hosts_into(body: &str, set: &mut std::collections::HashSet<String>) {
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        // Skip the IP column
        let ip = parts.next().unwrap_or("");
        // Only process sinkhole entries (0.0.0.0 or 127.0.0.1)
        if ip != "0.0.0.0" && ip != "127.0.0.1" {
            continue;
        }
        if let Some(domain) = parts.next() {
            let d = domain.to_lowercase();
            // Skip localhost and bare IPs
            if d == "localhost" || d.chars().all(|c| c.is_ascii_digit() || c == '.') {
                continue;
            }
            set.insert(d);
        }
    }
}

fn write_blocklist(path: &str, domains: &std::collections::HashSet<String>) -> Result<(), String> {
    // Ensure parent dir exists
    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut sorted: Vec<&String> = domains.iter().collect();
    sorted.sort();

    let mut f = std::fs::File::create(path).map_err(|e| e.to_string())?;
    for d in sorted {
        writeln!(f, "{d}").map_err(|e| e.to_string())?;
    }
    Ok(())
}

// ── Custom rules ──────────────────────────────────────────────────────────────

/// Add a single domain to the blocklist file (appends; nanodns hot-reloads).
pub fn add_custom_block(domain: &str) -> Result<(), String> {
    let domain = domain.trim().to_lowercase();
    if domain.is_empty() {
        return Err("Empty domain".to_string());
    }
    // Check for duplicates
    let existing = read_blocklist_lines();
    if existing.iter().any(|l| l == &domain) {
        return Ok(()); // already there
    }
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(BLOCKLIST_PATH)
        .map_err(|e| e.to_string())?;
    writeln!(f, "{domain}").map_err(|e| e.to_string())
}

/// Remove a single domain from the blocklist file.
pub fn remove_custom_block(domain: &str) -> Result<(), String> {
    let domain = domain.trim().to_lowercase();
    let lines = read_blocklist_lines();
    let filtered: Vec<String> = lines.into_iter().filter(|l| l != &domain).collect();
    let mut f = std::fs::File::create(BLOCKLIST_PATH).map_err(|e| e.to_string())?;
    for l in filtered {
        writeln!(f, "{l}").map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn read_blocklist_lines() -> Vec<String> {
    let Ok(f) = std::fs::File::open(BLOCKLIST_PATH) else { return Vec::new() };
    std::io::BufReader::new(f)
        .lines()
        .flatten()
        .map(|l| l.trim().to_lowercase())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

pub fn count_domains(path: &str) -> usize {
    let Ok(f) = std::fs::File::open(path) else { return 0 };
    std::io::BufReader::new(f)
        .lines()
        .flatten()
        .filter(|l| {
            let l = l.trim();
            !l.is_empty() && !l.starts_with('#')
        })
        .count()
}
