//! WAN interface detection, status, and configuration.
//!
//! Scans /sys/class/net for candidate WAN interfaces (not lo, wlan*, wg*),
//! reads current IP/gateway/DNS from the kernel, and applies DHCP or static
//! config via busybox ip + udhcpc.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

pub const WAN_CONF_PATH: &str = "/etc/tinywifi/wan.conf";

// ── Data model ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum WanMode {
    #[default]
    Dhcp,
    Static,
}

/// Persisted WAN config (what the user chose).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WanConfig {
    pub interface: String,
    pub mode: WanMode,
    /// Only used when mode = Static.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,   // "1.2.3.4/24"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<Vec<String>>,
}

/// Live status of a WAN interface (read from kernel).
#[derive(Debug, Clone, Serialize)]
pub struct WanStatus {
    pub interface: String,
    pub state: IfaceState,
    pub address: Option<String>,
    pub gateway: Option<String>,
    pub dns: Vec<String>,
    /// true if 8.8.8.8 is reachable (1-packet ping).
    pub online: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum IfaceState {
    Up,
    Down,
    Missing,
}

// ── Interface scanning ───────────────────────────────────────────────────────

/// List interfaces that are plausible WAN candidates:
/// exclude lo, wlan*, wg*, br*, and any interface named wlan.
pub fn wan_candidates() -> Vec<String> {
    let Ok(rd) = std::fs::read_dir("/sys/class/net") else { return Vec::new(); };
    let mut names: Vec<String> = rd
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| {
            n != "lo"
                && !n.starts_with("wlan")
                && !n.starts_with("wg")
                && !n.starts_with("br")
                && !n.starts_with("dummy")
        })
        .collect();
    names.sort();
    names
}

// ── Status reading ───────────────────────────────────────────────────────────

/// Read live status of the given interface from the kernel.
pub fn wan_status(iface: &str) -> WanStatus {
    let state = iface_state(iface);
    let address = iface_address(iface);
    let gateway = default_gateway_via(iface);
    let dns = read_dns();
    let online = if state == IfaceState::Up {
        ping_ok("8.8.8.8")
    } else {
        false
    };
    WanStatus { interface: iface.to_string(), state, address, gateway, dns, online }
}

fn iface_state(iface: &str) -> IfaceState {
    let path = PathBuf::from(format!("/sys/class/net/{iface}"));
    if !path.exists() { return IfaceState::Missing; }
    let oper = std::fs::read_to_string(path.join("operstate")).unwrap_or_default();
    if oper.trim() == "up" { IfaceState::Up } else { IfaceState::Down }
}

fn iface_address(iface: &str) -> Option<String> {
    let out = Command::new("ip")
        .args(["addr", "show", iface])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("inet ") {
            return rest.split_whitespace().next().map(|s| s.to_string());
        }
    }
    None
}

fn default_gateway_via(iface: &str) -> Option<String> {
    let out = Command::new("ip").args(["route", "show"]).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if line.starts_with("default") && line.contains(&format!("dev {iface}")) {
            for (i, word) in line.split_whitespace().enumerate() {
                if word == "via" {
                    if let Some(gw) = line.split_whitespace().nth(i + 1) {
                        return Some(gw.to_string());
                    }
                }
            }
        }
    }
    None
}

fn read_dns() -> Vec<String> {
    let content = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    content
        .lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver "))
        .map(|s| s.split_whitespace().next().unwrap_or("").to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn ping_ok(host: &str) -> bool {
    Command::new("ping")
        .args(["-c1", "-W2", host])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ── Config persistence ────────────────────────────────────────────────────────

impl WanConfig {
    pub fn load() -> Option<Self> {
        let text = std::fs::read_to_string(WAN_CONF_PATH).ok()?;
        parse_wan_conf(&text)
    }

    pub fn save(&self) -> std::io::Result<()> {
        if let Some(parent) = Path::new(WAN_CONF_PATH).parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(WAN_CONF_PATH, self.to_conf())
    }

    fn to_conf(&self) -> String {
        let mut s = format!(
            "interface={}\nmode={}\n",
            self.interface,
            match self.mode { WanMode::Dhcp => "dhcp", WanMode::Static => "static" },
        );
        if let Some(a) = &self.address { s.push_str(&format!("address={a}\n")); }
        if let Some(g) = &self.gateway { s.push_str(&format!("gateway={g}\n")); }
        if let Some(dns) = &self.dns { s.push_str(&format!("dns={}\n", dns.join(","))); }
        s
    }
}

fn parse_wan_conf(text: &str) -> Option<WanConfig> {
    let mut iface: Option<String> = None;
    let mut mode = WanMode::Dhcp;
    let mut address: Option<String> = None;
    let mut gateway: Option<String> = None;
    let mut dns: Option<Vec<String>> = None;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        if let Some((k, v)) = line.split_once('=') {
            match k.trim() {
                "interface" => { iface = Some(v.trim().to_string()); }
                "mode" => {
                    mode = if v.trim() == "static" { WanMode::Static } else { WanMode::Dhcp };
                }
                "address" => { address = Some(v.trim().to_string()); }
                "gateway" => { gateway = Some(v.trim().to_string()); }
                "dns" => {
                    dns = Some(v.trim().split(',').map(|s| s.trim().to_string()).collect());
                }
                _ => {}
            }
        }
    }
    Some(WanConfig { interface: iface?, mode, address, gateway, dns })
}

// ── Apply ─────────────────────────────────────────────────────────────────────

/// Apply the WAN config: bring up the interface and configure networking.
pub fn apply_wan(cfg: &WanConfig) -> Result<(), String> {
    let iface = &cfg.interface;

    // Make sure module is loaded for USB adapters
    let _ = Command::new("modprobe").arg("r8152").output();

    // Bring interface up
    run("ip", &["link", "set", iface, "up"])?;

    match cfg.mode {
        WanMode::Dhcp => apply_dhcp(iface),
        WanMode::Static => apply_static(cfg),
    }
}

fn apply_dhcp(iface: &str) -> Result<(), String> {
    // Kill any existing udhcpc for this interface
    let _ = Command::new("killall").args(["udhcpc"]).output();
    std::thread::sleep(std::time::Duration::from_millis(300));

    let out = Command::new("udhcpc")
        .args(["-i", iface, "-t", "15", "-n", "-q"])
        .output()
        .map_err(|e| format!("udhcpc: {e}"))?;

    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string()
            .or_else_empty(|| String::from_utf8_lossy(&out.stdout).trim().to_string()))
    }
}

fn apply_static(cfg: &WanConfig) -> Result<(), String> {
    let iface = &cfg.interface;
    let addr = cfg.address.as_deref().ok_or("address is required for static mode")?;
    let gw = cfg.gateway.as_deref().ok_or("gateway is required for static mode")?;

    // Validate
    let (ip_part, _) = addr.split_once('/').ok_or("address must be in CIDR notation (x.x.x.x/n)")?;
    ip_part.parse::<Ipv4Addr>().map_err(|_| "invalid IP address")?;
    gw.parse::<Ipv4Addr>().map_err(|_| "invalid gateway")?;

    run("ip", &["addr", "flush", "dev", iface])?;
    run("ip", &["addr", "add", addr, "dev", iface])?;
    // Remove any existing default route and add new one
    let _ = Command::new("ip").args(["route", "del", "default"]).output();
    run("ip", &["route", "add", "default", "via", gw, "dev", iface])?;

    // Write resolv.conf
    if let Some(dns_list) = &cfg.dns {
        let content: String = dns_list
            .iter()
            .filter(|d| !d.is_empty())
            .map(|d| format!("nameserver {d}\n"))
            .collect();
        if !content.is_empty() {
            std::fs::write("/etc/resolv.conf", content)
                .map_err(|e| format!("resolv.conf: {e}"))?;
        }
    }

    Ok(())
}

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

trait OrElseEmpty {
    fn or_else_empty(self, f: impl FnOnce() -> String) -> String;
}
impl OrElseEmpty for String {
    fn or_else_empty(self, f: impl FnOnce() -> String) -> String {
        if self.is_empty() { f() } else { self }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dhcp_conf() {
        let text = "interface=eth0\nmode=dhcp\n";
        let cfg = parse_wan_conf(text).unwrap();
        assert_eq!(cfg.interface, "eth0");
        assert_eq!(cfg.mode, WanMode::Dhcp);
        assert!(cfg.address.is_none());
    }

    #[test]
    fn parse_static_conf() {
        let text = "interface=eth0\nmode=static\naddress=192.168.1.2/24\ngateway=192.168.1.1\ndns=8.8.8.8,1.1.1.1\n";
        let cfg = parse_wan_conf(text).unwrap();
        assert_eq!(cfg.mode, WanMode::Static);
        assert_eq!(cfg.address.as_deref(), Some("192.168.1.2/24"));
        assert_eq!(cfg.gateway.as_deref(), Some("192.168.1.1"));
        assert_eq!(cfg.dns.as_ref().unwrap(), &["8.8.8.8", "1.1.1.1"]);
    }

    #[test]
    fn roundtrip_conf() {
        let cfg = WanConfig {
            interface: "eth0".into(),
            mode: WanMode::Static,
            address: Some("10.0.0.2/24".into()),
            gateway: Some("10.0.0.1".into()),
            dns: Some(vec!["1.1.1.1".into()]),
        };
        let text = cfg.to_conf();
        let back = parse_wan_conf(&text).unwrap();
        assert_eq!(back.interface, "eth0");
        assert_eq!(back.address.as_deref(), Some("10.0.0.2/24"));
    }

    #[test]
    fn wan_candidates_excludes_lo_and_wlan() {
        // On a host without /sys/class/net this returns empty — that's fine.
        let candidates = wan_candidates();
        assert!(!candidates.contains(&"lo".to_string()));
        for c in &candidates {
            assert!(!c.starts_with("wlan"));
            assert!(!c.starts_with("wg"));
        }
    }

    #[test]
    fn missing_interface_key_returns_none() {
        let text = "mode=dhcp\n"; // no interface=
        assert!(parse_wan_conf(text).is_none());
    }
}
