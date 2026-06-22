//! AmneziaWG detection, config parsing, and tunnel management.
//!
//! Detects the `awg` binary and reads `*.conf` files from the standard
//! config directory (`/etc/amnezia/amneziawg/`).  Parses WireGuard INI
//! format extended with AmneziaWG obfuscation keys (Jc, Jmin, Jmax,
//! S1, S2, H1–H4).  Tunnel status comes from `awg show`.
//!
//! All operations degrade gracefully: missing binary → status Missing,
//! missing config dir → empty list, failed `awg show` → status Down.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;

/// Standard config directory on embedded images.
pub const AWG_CONF_DIR: &str = "/etc/amnezia/amneziawg";

const BIN_DIRS: &[&str] = &[
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
];

// ── Data model ──────────────────────────────────────────────────────────────

/// Typed view of a `[Interface]` section.
#[derive(Debug, Clone, Serialize, Default)]
pub struct AwgInterface {
    /// One or more `Address = x.x.x.x/n` values.
    pub addresses: Vec<String>,
    pub listen_port: Option<u16>,
    pub dns: Vec<String>,
    // AmneziaWG obfuscation parameters
    pub jc: Option<u32>,
    pub jmin: Option<u32>,
    pub jmax: Option<u32>,
    pub s1: Option<u32>,
    pub s2: Option<u32>,
    pub h1: Option<u32>,
    pub h2: Option<u32>,
    pub h3: Option<u32>,
    pub h4: Option<u32>,
}

/// Typed view of a `[Peer]` section.
#[derive(Debug, Clone, Serialize)]
pub struct AwgPeer {
    pub public_key: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive: Option<u32>,
    pub has_preshared_key: bool,
}

/// A parsed tunnel config + runtime status.
#[derive(Debug, Clone, Serialize)]
pub struct AwgTunnel {
    /// Interface name derived from the filename, e.g. `awg0`.
    pub name: String,
    pub config_path: PathBuf,
    pub iface: AwgInterface,
    pub peers: Vec<AwgPeer>,
    /// Runtime status: requires kernel module + running interface.
    pub status: AwgTunnelStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AwgTunnelStatus {
    /// Interface is up and responding to `awg show`.
    Up,
    /// Config exists but interface is not active.
    Down,
    /// `awg` binary not found.
    Missing,
}

/// One peer as reported by `awg show`.
#[derive(Debug, Clone, Serialize, Default)]
pub struct AwgShowPeer {
    pub public_key: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    /// Unix timestamp of latest successful handshake (0 = never).
    pub latest_handshake: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// One interface as reported by `awg show`.
#[derive(Debug, Clone, Serialize)]
pub struct AwgShowIface {
    pub name: String,
    pub public_key: Option<String>,
    pub listen_port: Option<u16>,
    pub peers: Vec<AwgShowPeer>,
}

// ── Binary detection ─────────────────────────────────────────────────────────

/// Returns the path to the `awg` binary, or `None` if not installed.
pub fn awg_binary() -> Option<PathBuf> {
    // Check $PATH first
    if let Ok(p) = std::env::var("PATH") {
        for dir in p.split(':') {
            let candidate = PathBuf::from(dir).join("awg");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    for dir in BIN_DIRS {
        let candidate = PathBuf::from(dir).join("awg");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

// ── Config parsing ───────────────────────────────────────────────────────────

/// Parse an AmneziaWG / WireGuard INI config file.
pub fn parse_conf(content: &str) -> (AwgInterface, Vec<AwgPeer>) {
    let mut iface = AwgInterface::default();
    let mut peers: Vec<AwgPeer> = Vec::new();

    #[derive(PartialEq)]
    enum Section { None, Interface, Peer }
    let mut current = Section::None;
    let mut peer_buf: Option<PeerBuf> = None;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.eq_ignore_ascii_case("[Interface]") {
            if let Some(pb) = peer_buf.take() { peers.push(pb.finish()); }
            current = Section::Interface;
            continue;
        }
        if line.eq_ignore_ascii_case("[Peer]") {
            if let Some(pb) = peer_buf.take() { peers.push(pb.finish()); }
            current = Section::Peer;
            peer_buf = Some(PeerBuf::default());
            continue;
        }
        let (key, val) = match line.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => continue,
        };
        match current {
            Section::Interface => apply_iface_key(&mut iface, key, val),
            Section::Peer => {
                if let Some(pb) = peer_buf.as_mut() {
                    pb.apply(key, val);
                }
            }
            Section::None => {}
        }
    }
    if let Some(pb) = peer_buf.take() { peers.push(pb.finish()); }
    (iface, peers)
}

fn apply_iface_key(iface: &mut AwgInterface, key: &str, val: &str) {
    match key {
        "Address" => {
            for part in val.split(',') {
                let s = part.trim().to_string();
                if !s.is_empty() { iface.addresses.push(s); }
            }
        }
        "ListenPort" => { iface.listen_port = val.parse().ok(); }
        "DNS" => {
            for part in val.split(',') {
                let s = part.trim().to_string();
                if !s.is_empty() { iface.dns.push(s); }
            }
        }
        "Jc"   => { iface.jc   = val.parse().ok(); }
        "Jmin" => { iface.jmin = val.parse().ok(); }
        "Jmax" => { iface.jmax = val.parse().ok(); }
        "S1"   => { iface.s1   = val.parse().ok(); }
        "S2"   => { iface.s2   = val.parse().ok(); }
        "H1"   => { iface.h1   = val.parse().ok(); }
        "H2"   => { iface.h2   = val.parse().ok(); }
        "H3"   => { iface.h3   = val.parse().ok(); }
        "H4"   => { iface.h4   = val.parse().ok(); }
        _ => {}
    }
}

#[derive(Default)]
struct PeerBuf {
    public_key: String,
    endpoint: Option<String>,
    allowed_ips: Vec<String>,
    persistent_keepalive: Option<u32>,
    has_preshared_key: bool,
}

impl PeerBuf {
    fn apply(&mut self, key: &str, val: &str) {
        match key {
            "PublicKey"          => { self.public_key = val.to_string(); }
            "Endpoint"           => { self.endpoint = Some(val.to_string()); }
            "AllowedIPs"         => {
                for part in val.split(',') {
                    let s = part.trim().to_string();
                    if !s.is_empty() { self.allowed_ips.push(s); }
                }
            }
            "PersistentKeepalive" => { self.persistent_keepalive = val.parse().ok(); }
            "PresharedKey"       => { self.has_preshared_key = true; }
            _ => {}
        }
    }
    fn finish(self) -> AwgPeer {
        AwgPeer {
            public_key: self.public_key,
            endpoint: self.endpoint,
            allowed_ips: self.allowed_ips,
            persistent_keepalive: self.persistent_keepalive,
            has_preshared_key: self.has_preshared_key,
        }
    }
}

/// Read a single `*.conf` file, returning a tunnel.
pub fn read_tunnel(path: &Path, status: AwgTunnelStatus) -> Option<AwgTunnel> {
    let name = path.file_stem()?.to_string_lossy().to_string();
    let content = std::fs::read_to_string(path).ok()?;
    let (iface, peers) = parse_conf(&content);
    Some(AwgTunnel {
        name,
        config_path: path.to_path_buf(),
        iface,
        peers,
        status,
    })
}

// ── awg show ─────────────────────────────────────────────────────────────────

/// Run `awg show` and parse output into a map keyed by interface name.
pub fn awg_show() -> Vec<AwgShowIface> {
    let bin = match awg_binary() {
        Some(b) => b,
        None => return Vec::new(),
    };
    let out = Command::new(&bin).arg("show").output();
    let stdout = match out {
        Ok(o) if o.status.success() || !o.stdout.is_empty() => {
            String::from_utf8_lossy(&o.stdout).to_string()
        }
        _ => return Vec::new(),
    };
    parse_awg_show(&stdout)
}

/// Parse `awg show` text output.
pub fn parse_awg_show(text: &str) -> Vec<AwgShowIface> {
    let mut result: Vec<AwgShowIface> = Vec::new();
    let mut current_iface: Option<AwgShowIface> = None;
    let mut current_peer: Option<AwgShowPeer> = None;

    for line in text.lines() {
        if line.is_empty() { continue; }

        if !line.starts_with(' ') && !line.starts_with('\t') {
            // top-level: "interface: name" or "peer: pubkey"
            if let Some(name) = line.strip_prefix("interface: ") {
                if let Some(p) = current_peer.take() {
                    if let Some(i) = current_iface.as_mut() { i.peers.push(p); }
                }
                if let Some(i) = current_iface.take() { result.push(i); }
                current_iface = Some(AwgShowIface {
                    name: name.trim().to_string(),
                    public_key: None,
                    listen_port: None,
                    peers: Vec::new(),
                });
            } else if let Some(pk) = line.strip_prefix("peer: ") {
                if let Some(p) = current_peer.take() {
                    if let Some(i) = current_iface.as_mut() { i.peers.push(p); }
                }
                current_peer = Some(AwgShowPeer {
                    public_key: pk.trim().to_string(),
                    ..Default::default()
                });
            }
        } else {
            let line = line.trim();
            if let Some(kv) = line.split_once(": ") {
                let (k, v) = (kv.0.trim(), kv.1.trim());
                if let Some(ref mut peer) = current_peer {
                    match k {
                        "endpoint" => { peer.endpoint = Some(v.to_string()); }
                        "allowed ips" => {
                            for part in v.split(", ") {
                                peer.allowed_ips.push(part.trim().to_string());
                            }
                        }
                        "latest handshake" => {
                            peer.latest_handshake = parse_handshake_age(v);
                        }
                        "transfer" => { parse_transfer(v, peer); }
                        _ => {}
                    }
                } else if let Some(ref mut iface) = current_iface {
                    match k {
                        "public key" => { iface.public_key = Some(v.to_string()); }
                        "listening port" => { iface.listen_port = v.parse().ok(); }
                        _ => {}
                    }
                }
            }
        }
    }
    if let Some(p) = current_peer.take() {
        if let Some(i) = current_iface.as_mut() { i.peers.push(p); }
    }
    if let Some(i) = current_iface.take() { result.push(i); }
    result
}

/// Parse "N minutes, M seconds ago" → approximate unix timestamp of handshake.
fn parse_handshake_age(s: &str) -> u64 {
    if s == "0 seconds ago" || s.contains("Never") { return 0; }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut secs: u64 = 0;
    for part in s.trim_end_matches(" ago").split(", ") {
        let part = part.trim();
        if let Some(n) = part.strip_suffix(" seconds").or_else(|| part.strip_suffix(" second")) {
            secs += n.trim().parse::<u64>().unwrap_or(0);
        } else if let Some(n) = part.strip_suffix(" minutes").or_else(|| part.strip_suffix(" minute")) {
            secs += n.trim().parse::<u64>().unwrap_or(0) * 60;
        } else if let Some(n) = part.strip_suffix(" hours").or_else(|| part.strip_suffix(" hour")) {
            secs += n.trim().parse::<u64>().unwrap_or(0) * 3600;
        } else if let Some(n) = part.strip_suffix(" days").or_else(|| part.strip_suffix(" day")) {
            secs += n.trim().parse::<u64>().unwrap_or(0) * 86400;
        }
    }
    now.saturating_sub(secs)
}

/// Parse "X KiB received, Y KiB sent" into bytes.
fn parse_transfer(s: &str, peer: &mut AwgShowPeer) {
    for part in s.split(", ") {
        if let Some(rx) = part.strip_suffix(" received") {
            peer.rx_bytes = parse_bytes(rx.trim());
        } else if let Some(tx) = part.strip_suffix(" sent") {
            peer.tx_bytes = parse_bytes(tx.trim());
        }
    }
}

fn parse_bytes(s: &str) -> u64 {
    if let Some((n, unit)) = s.rsplit_once(' ') {
        let n: f64 = n.parse().unwrap_or(0.0);
        let mult = match unit {
            "B" => 1.0,
            "KiB" => 1024.0,
            "MiB" => 1024.0 * 1024.0,
            "GiB" => 1024.0 * 1024.0 * 1024.0,
            _ => 1.0,
        };
        return (n * mult) as u64;
    }
    0
}

// ── Scanning ─────────────────────────────────────────────────────────────────

/// Scan `dir` for `*.conf` files and return parsed tunnels with runtime status.
pub fn scan_tunnels(dir: impl AsRef<Path>) -> Vec<AwgTunnel> {
    let dir = dir.as_ref();
    let has_binary = awg_binary().is_some();
    let active = if has_binary { awg_show() } else { Vec::new() };
    let active_names: std::collections::HashSet<String> =
        active.iter().map(|i| i.name.clone()).collect();

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let mut tunnels: Vec<AwgTunnel> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("conf") { continue; }
        let status = if !has_binary {
            AwgTunnelStatus::Missing
        } else {
            let name = path.file_stem().unwrap_or_default().to_string_lossy().to_string();
            if active_names.contains(&name) { AwgTunnelStatus::Up } else { AwgTunnelStatus::Down }
        };
        if let Some(t) = read_tunnel(&path, status) {
            tunnels.push(t);
        }
    }
    tunnels.sort_by(|a, b| a.name.cmp(&b.name));
    tunnels
}

// ── Tunnel lifecycle ──────────────────────────────────────────────────────────

/// Bring up a tunnel: `ip link add <name> type amneziawg` → `awg setconf` → addrs → `ip link set up`.
pub fn tunnel_up(tunnel: &AwgTunnel) -> Result<(), String> {
    let name = &tunnel.name;
    let conf = tunnel.config_path.display().to_string();

    run_cmd("ip", &["link", "add", name, "type", "amneziawg"])?;
    run_cmd(
        awg_binary()
            .as_deref()
            .unwrap_or(Path::new("awg"))
            .to_str()
            .unwrap_or("awg"),
        &["setconf", name, &conf],
    )?;
    for addr in &tunnel.iface.addresses {
        run_cmd("ip", &["addr", "add", addr, "dev", name])?;
    }
    run_cmd("ip", &["link", "set", name, "up"])
}

/// Bring down a tunnel: `ip link set <name> down` → `ip link del <name>`.
pub fn tunnel_down(name: &str) -> Result<(), String> {
    let _ = run_cmd("ip", &["link", "set", name, "down"]);
    run_cmd("ip", &["link", "del", name])
}

fn run_cmd(prog: &str, args: &[&str]) -> Result<(), String> {
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_CONF: &str = "\
[Interface]
PrivateKey = CJcwdFUmUTE65cyzhlzEQEMyFctL74qkyDM4oh/oNHY=
Address = 10.8.0.1/24
ListenPort = 51820
Jc = 4
Jmin = 40
Jmax = 70
S1 = 0
S2 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4

[Peer]
PublicKey = m/sRfpbAcfCiPeunu/sZBpxJFb5xaEvlD27+ZtWV3zA=
AllowedIPs = 10.8.0.2/32
PersistentKeepalive = 25
";

    #[test]
    fn parses_interface_fields() {
        let (iface, _) = parse_conf(SAMPLE_CONF);
        assert_eq!(iface.addresses, vec!["10.8.0.1/24"]);
        assert_eq!(iface.listen_port, Some(51820));
        assert_eq!(iface.jc, Some(4));
        assert_eq!(iface.jmin, Some(40));
        assert_eq!(iface.jmax, Some(70));
        assert_eq!(iface.s1, Some(0));
        assert_eq!(iface.h1, Some(1));
        assert_eq!(iface.h4, Some(4));
    }

    #[test]
    fn parses_peer_fields() {
        let (_, peers) = parse_conf(SAMPLE_CONF);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].public_key, "m/sRfpbAcfCiPeunu/sZBpxJFb5xaEvlD27+ZtWV3zA=");
        assert_eq!(peers[0].allowed_ips, vec!["10.8.0.2/32"]);
        assert_eq!(peers[0].persistent_keepalive, Some(25));
        assert!(!peers[0].has_preshared_key);
    }

    #[test]
    fn multiple_peers() {
        let conf = format!(
            "{SAMPLE_CONF}\n[Peer]\nPublicKey = AAAA\nAllowedIPs = 10.8.0.3/32\nPresharedKey = secret\n"
        );
        let (_, peers) = parse_conf(&conf);
        assert_eq!(peers.len(), 2);
        assert!(peers[1].has_preshared_key);
    }

    #[test]
    fn comment_and_blank_lines_skipped() {
        let conf = "# this is a comment\n\n[Interface]\n# another\nListenPort = 1234\n";
        let (iface, _) = parse_conf(conf);
        assert_eq!(iface.listen_port, Some(1234));
    }

    const SHOW_OUTPUT: &str = "\
interface: awg0
  public key: PUBKEY0==
  private key: (hidden)
  listening port: 51820

peer: PEERKEY==
  endpoint: 1.2.3.4:51820
  allowed ips: 10.8.0.2/32
  latest handshake: 2 minutes, 5 seconds ago
  transfer: 1.50 KiB received, 512 B sent
";

    #[test]
    fn parses_awg_show_interface() {
        let ifaces = parse_awg_show(SHOW_OUTPUT);
        assert_eq!(ifaces.len(), 1);
        let i = &ifaces[0];
        assert_eq!(i.name, "awg0");
        assert_eq!(i.public_key.as_deref(), Some("PUBKEY0=="));
        assert_eq!(i.listen_port, Some(51820));
        assert_eq!(i.peers.len(), 1);
    }

    #[test]
    fn parses_awg_show_peer() {
        let ifaces = parse_awg_show(SHOW_OUTPUT);
        let peer = &ifaces[0].peers[0];
        assert_eq!(peer.public_key, "PEERKEY==");
        assert_eq!(peer.endpoint.as_deref(), Some("1.2.3.4:51820"));
        assert_eq!(peer.allowed_ips, vec!["10.8.0.2/32"]);
        assert!(peer.latest_handshake > 0);
        assert_eq!(peer.rx_bytes, 1536); // 1.50 KiB
        assert_eq!(peer.tx_bytes, 512);
    }

    #[test]
    fn empty_show_output_gives_empty_vec() {
        assert!(parse_awg_show("").is_empty());
    }

    #[test]
    fn parse_bytes_units() {
        assert_eq!(parse_bytes("1.50 KiB"), 1536);
        assert_eq!(parse_bytes("512 B"), 512);
        assert_eq!(parse_bytes("1.00 MiB"), 1048576);
    }
}
