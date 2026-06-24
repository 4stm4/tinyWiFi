//! WiFi monitor mode: detect secondary adapter, enable/disable monitor mode,
//! run passive scan (beacons + probe requests via iw).

use std::process::Command;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct MonitorAdapter {
    pub iface: String,
    pub phy: String,
    pub driver: String,
    pub supports_monitor: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MonitorState {
    Off,
    On,
}

#[derive(Debug, Clone, Serialize)]
pub struct MonitorStatus {
    pub state: MonitorState,
    pub adapter: Option<MonitorAdapter>,
    /// Most recently scanned access points (from iw dev scan dump).
    pub scan: Vec<ScannedAp>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScannedAp {
    pub bssid: String,
    pub ssid: String,
    pub channel: u8,
    pub signal: i32,
}

// ── Global state ──────────────────────────────────────────────────────────────

/// Shared monitor state — persisted in memory only, resets on daemon restart.
#[derive(Default)]
struct Inner {
    state: MonitorState,
    iface: Option<String>,
    scan: Vec<ScannedAp>,
}

impl Default for MonitorState {
    fn default() -> Self { MonitorState::Off }
}

#[derive(Clone)]
pub struct MonitorHandle(Arc<Mutex<Inner>>);

impl MonitorHandle {
    pub fn new() -> Self {
        MonitorHandle(Arc::new(Mutex::new(Inner::default())))
    }
}

impl Default for MonitorHandle {
    fn default() -> Self { Self::new() }
}

// ── Interface detection ───────────────────────────────────────────────────────

/// The AP interface name used by hostapd. We exclude it from candidates.
const AP_IFACE: &str = "wlan0";

/// Find secondary wireless interfaces (not the AP iface) and probe capabilities.
pub fn detect_monitor_adapter() -> Option<MonitorAdapter> {
    let rd = std::fs::read_dir("/sys/class/net").ok()?;
    let candidates: Vec<String> = rd
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.starts_with("wlan") && n != AP_IFACE)
        .collect();

    for iface in candidates {
        if let Some(adapter) = probe_adapter(&iface) {
            return Some(adapter);
        }
    }
    None
}

fn probe_adapter(iface: &str) -> Option<MonitorAdapter> {
    // Find phy for this interface
    let phy_path = format!("/sys/class/net/{iface}/phy80211/name");
    let phy = std::fs::read_to_string(&phy_path)
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "phy1".to_string());

    // Read driver via uevent or modalias
    let driver = read_driver(iface);

    // Check monitor mode support via iw phy info
    let supports = check_monitor_support(&phy);

    Some(MonitorAdapter { iface: iface.to_string(), phy, driver, supports_monitor: supports })
}

fn read_driver(iface: &str) -> String {
    let driver_path = format!("/sys/class/net/{iface}/device/driver");
    std::fs::read_link(&driver_path)
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_else(|| "unknown".to_string())
}

fn check_monitor_support(phy: &str) -> bool {
    let out = Command::new("iw").args(["phy", phy, "info"]).output();
    match out {
        Ok(o) => {
            let text = String::from_utf8_lossy(&o.stdout);
            text.contains("monitor")
        }
        Err(_) => false,
    }
}

// ── Enable / Disable ──────────────────────────────────────────────────────────

pub fn enable_monitor(handle: &MonitorHandle) -> Result<String, String> {
    let adapter = detect_monitor_adapter()
        .ok_or_else(|| "Нет доступного WiFi адаптера для мониторинга".to_string())?;

    if !adapter.supports_monitor {
        return Err(format!("Адаптер {} не поддерживает monitor mode", adapter.iface));
    }

    let iface = adapter.iface.clone();

    // Bring interface down, set monitor mode, bring back up
    run("ip", &["link", "set", &iface, "down"])?;
    run("iw", &["dev", &iface, "set", "type", "monitor"])?;
    run("ip", &["link", "set", &iface, "up"])?;

    let mut inner = handle.0.lock().unwrap();
    inner.state = MonitorState::On;
    inner.iface = Some(iface.clone());

    // Trigger first scan immediately
    drop(inner);
    refresh_scan(handle);

    Ok(iface)
}

pub fn disable_monitor(handle: &MonitorHandle) -> Result<(), String> {
    let iface = {
        let inner = handle.0.lock().unwrap();
        inner.iface.clone()
    };

    if let Some(ref iface) = iface {
        let _ = run("ip", &["link", "set", iface, "down"]);
        let _ = run("iw", &["dev", iface, "set", "type", "managed"]);
        let _ = run("ip", &["link", "set", iface, "up"]);
    }

    let mut inner = handle.0.lock().unwrap();
    inner.state = MonitorState::Off;
    inner.iface = None;
    inner.scan.clear();

    Ok(())
}

// ── Scanning ──────────────────────────────────────────────────────────────────

/// Refresh scan results from `iw dev <iface> scan dump`.
pub fn refresh_scan(handle: &MonitorHandle) {
    let iface = {
        let inner = handle.0.lock().unwrap();
        inner.iface.clone()
    };
    let Some(iface) = iface else { return };

    // Trigger a new scan
    let _ = Command::new("iw").args(["dev", &iface, "scan", "trigger"]).output();

    // Read cached scan results (dump doesn't wait for scan to finish)
    let out = Command::new("iw").args(["dev", &iface, "scan", "dump"]).output();
    let aps = match out {
        Ok(o) if o.status.success() => parse_iw_scan(&String::from_utf8_lossy(&o.stdout)),
        _ => Vec::new(),
    };

    let mut inner = handle.0.lock().unwrap();
    if inner.state == MonitorState::On {
        inner.scan = aps;
    }
}

fn parse_iw_scan(text: &str) -> Vec<ScannedAp> {
    let mut aps = Vec::new();
    let mut bssid = String::new();
    let mut ssid = String::new();
    let mut channel: u8 = 0;
    let mut signal: i32 = 0;

    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("BSS ") && line.contains(':') {
            if !bssid.is_empty() {
                aps.push(ScannedAp { bssid: bssid.clone(), ssid: ssid.clone(), channel, signal });
            }
            bssid = line[4..].split(' ').next().unwrap_or("").to_string();
            ssid.clear();
            channel = 0;
            signal = 0;
        } else if line.starts_with("SSID:") {
            ssid = line[5..].trim().to_string();
        } else if line.starts_with("DS Parameter set: channel") {
            channel = line.split_whitespace().last().unwrap_or("0").parse().unwrap_or(0);
        } else if line.starts_with("signal:") {
            // "signal: -65.00 dBm"
            signal = line.split_whitespace().nth(1).unwrap_or("0")
                .parse::<f32>().unwrap_or(0.0) as i32;
        }
    }
    if !bssid.is_empty() {
        aps.push(ScannedAp { bssid, ssid, channel, signal });
    }
    aps
}

// ── Status ────────────────────────────────────────────────────────────────────

pub fn monitor_status(handle: &MonitorHandle) -> MonitorStatus {
    let inner = handle.0.lock().unwrap();
    let adapter = if inner.state == MonitorState::On {
        inner.iface.as_ref().and_then(|i| probe_adapter(i))
    } else {
        detect_monitor_adapter()
    };
    MonitorStatus {
        state: inner.state.clone(),
        adapter,
        scan: inner.scan.clone(),
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn run(prog: &str, args: &[&str]) -> Result<(), String> {
    let out = Command::new(prog)
        .args(args)
        .output()
        .map_err(|e| format!("{prog}: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}
