//! AmneziaWG detection, config parsing, tunnel management, and import.
//!
//! Detects the `awg` binary and reads `*.conf` files from the standard
//! config directory (`/etc/amnezia/amneziawg/`).  Parses WireGuard INI
//! format extended with AmneziaWG obfuscation keys (Jc, Jmin, Jmax,
//! S1–S4, H1–H4, I1–I5).  Tunnel status comes from `awg show`.
//!
//! Import supports two formats:
//!  - Raw `[Interface]` / `[Peer]` `.conf` text
//!  - `vpn://` URI: base64url → skip 4-byte length → zlib → JSON
//!
//! All operations degrade gracefully: missing binary → status Missing,
//! missing config dir → empty list, failed `awg show` → status Down.

use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine as _;
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
    // AmneziaWG obfuscation parameters (junk traffic)
    pub jc: Option<u32>,
    pub jmin: Option<u32>,
    pub jmax: Option<u32>,
    // Split-tunnel obfuscation sizes
    pub s1: Option<u32>,
    pub s2: Option<u32>,
    pub s3: Option<u32>,
    pub s4: Option<u32>,
    // Magic header values (may be ranges like "123-456")
    pub h1: Option<String>,
    pub h2: Option<String>,
    pub h3: Option<String>,
    pub h4: Option<String>,
    // DNS injection templates (I1–I5, may be empty)
    pub i1: Option<String>,
    pub i2: Option<String>,
    pub i3: Option<String>,
    pub i4: Option<String>,
    pub i5: Option<String>,
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
        "S3"   => { iface.s3   = val.parse().ok(); }
        "S4"   => { iface.s4   = val.parse().ok(); }
        // H1-H4 can be plain numbers or ranges like "123-456"
        "H1"   => { iface.h1   = Some(val.to_string()); }
        "H2"   => { iface.h2   = Some(val.to_string()); }
        "H3"   => { iface.h3   = Some(val.to_string()); }
        "H4"   => { iface.h4   = Some(val.to_string()); }
        // I1-I5: DNS injection templates, can be empty strings
        "I1"   => { iface.i1   = Some(val.to_string()); }
        "I2"   => { iface.i2   = Some(val.to_string()); }
        "I3"   => { iface.i3   = Some(val.to_string()); }
        "I4"   => { iface.i4   = Some(val.to_string()); }
        "I5"   => { iface.i5   = Some(val.to_string()); }
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

// ── Import ───────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum ImportError {
    /// Not a recognised format.
    UnknownFormat,
    /// base64 / zlib / JSON decode error.
    Decode(String),
    /// Could not write the resulting config file.
    Write(std::io::Error),
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportError::UnknownFormat => write!(f, "unrecognised format (expected [Interface] or vpn://)"),
            ImportError::Decode(e) => write!(f, "decode error: {e}"),
            ImportError::Write(e) => write!(f, "write error: {e}"),
        }
    }
}

/// Import a tunnel config from either:
/// - a raw `[Interface]` / `[Peer]` `.conf` string, or
/// - a `vpn://` URI (base64url → skip 4 bytes → zlib → JSON).
///
/// Writes the resulting `.conf` to `<conf_dir>/<name>.conf`.
/// Returns the path that was written.
pub fn import_tunnel(
    input: &str,
    name: &str,
    conf_dir: impl AsRef<Path>,
) -> Result<PathBuf, ImportError> {
    let conf_text = if input.trim_start().starts_with("[Interface]") {
        input.to_string()
    } else if let Some(uri) = input.trim().strip_prefix("vpn://") {
        decode_vpn_uri(uri)?
    } else {
        return Err(ImportError::UnknownFormat);
    };

    std::fs::create_dir_all(conf_dir.as_ref())
        .map_err(ImportError::Write)?;

    let safe_name: String = name
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    let path = conf_dir.as_ref().join(format!("{safe_name}.conf"));
    std::fs::write(&path, &conf_text).map_err(ImportError::Write)?;
    Ok(path)
}

/// Decode a `vpn://` payload: base64url → skip 4-byte length prefix → zlib decompress → JSON.
/// Returns the `.conf` text.
fn decode_vpn_uri(uri: &str) -> Result<String, ImportError> {
    use flate2::read::ZlibDecoder;
    use std::io::Read as _;

    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(uri)
        .map_err(|e| ImportError::Decode(format!("base64: {e}")))?;

    if raw.len() < 4 {
        return Err(ImportError::Decode("payload too short".into()));
    }
    // First 4 bytes are big-endian uncompressed length — skip them.
    let compressed = &raw[4..];

    let mut decoder = ZlibDecoder::new(compressed);
    let mut json_str = String::new();
    decoder
        .read_to_string(&mut json_str)
        .map_err(|e| ImportError::Decode(format!("zlib: {e}")))?;

    extract_conf_from_json(&json_str)
}

/// Pull the `.conf` text out of the AmneziaVPN JSON envelope and fill DNS placeholders.
fn extract_conf_from_json(json_str: &str) -> Result<String, ImportError> {
    let root: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| ImportError::Decode(format!("json: {e}")))?;

    // Navigate containers[0].awg
    let awg = root
        .get("containers")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("awg"))
        .ok_or_else(|| ImportError::Decode("missing containers[0].awg".into()))?;

    // last_config is a JSON string inside the awg object
    let last_config_str = awg
        .get("last_config")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ImportError::Decode("missing awg.last_config".into()))?;

    let last_config: serde_json::Value = serde_json::from_str(last_config_str)
        .map_err(|e| ImportError::Decode(format!("last_config json: {e}")))?;

    let conf_template = last_config
        .get("config")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ImportError::Decode("missing last_config.config".into()))?;

    // Fill DNS placeholders from the awg object's dns1/dns2 or from the root
    let dns1 = awg.get("dns1").and_then(|v| v.as_str())
        .or_else(|| root.get("dns1").and_then(|v| v.as_str()))
        .unwrap_or("1.1.1.1");
    let dns2 = awg.get("dns2").and_then(|v| v.as_str())
        .or_else(|| root.get("dns2").and_then(|v| v.as_str()))
        .unwrap_or("1.0.0.1");

    let conf = conf_template
        .replace("$PRIMARY_DNS", dns1)
        .replace("$SECONDARY_DNS", dns2);

    Ok(conf)
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
        assert_eq!(iface.h1.as_deref(), Some("1"));
        assert_eq!(iface.h4.as_deref(), Some("4"));
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

    const FULL_CONF: &str = "\
[Interface]
PrivateKey = HD05E6Alo0+bCqe1R8sso7kXIZmcB8GGhoPJnESxts4=
Address = 10.8.1.7/32
DNS = 1.1.1.1, 1.0.0.1
Jc = 5
Jmin = 10
Jmax = 50
S1 = 64
S2 = 50
S3 = 33
S4 = 6
H1 = 644456937-947561569
H2 = 1227333105-1274069595
H3 = 2083103156-2109834062
H4 = 2143087149-2147361817
I1 = <r 2><b 0x858000>
I2 =
I3 =
I4 =
I5 =

[Peer]
PublicKey = yjSWAm97rHwDZL0yIOR3XmLxU33qyacMWObFkJSvKkQ=
PresharedKey = VUgvZskXT51mo67krBdD5f6G9WjjxCP1jfUup3BH8Ks=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 156.67.62.126:46089
PersistentKeepalive = 25
";

    #[test]
    fn parses_s3_s4_fields() {
        let (iface, _) = parse_conf(FULL_CONF);
        assert_eq!(iface.s3, Some(33));
        assert_eq!(iface.s4, Some(6));
    }

    #[test]
    fn parses_h_as_range_string() {
        let (iface, _) = parse_conf(FULL_CONF);
        assert_eq!(iface.h1.as_deref(), Some("644456937-947561569"));
        assert_eq!(iface.h4.as_deref(), Some("2143087149-2147361817"));
    }

    #[test]
    fn parses_i_fields() {
        let (iface, _) = parse_conf(FULL_CONF);
        assert!(iface.i1.as_deref().unwrap_or("").starts_with("<r 2>"));
        assert_eq!(iface.i2.as_deref(), Some(""));
        assert_eq!(iface.i5.as_deref(), Some(""));
    }

    #[test]
    fn parses_preshared_key_flag() {
        let (_, peers) = parse_conf(FULL_CONF);
        assert!(peers[0].has_preshared_key);
    }

    #[test]
    fn import_raw_conf_writes_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = import_tunnel(FULL_CONF, "test0", dir.path()).unwrap();
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("[Interface]"));
        assert!(content.contains("Jc = 5"));
    }

    #[test]
    fn import_vpn_uri_decodes_and_writes() {
        let uri = "vpn://AAALR3jatVbrbuI4FP7fp0Bo_k3LxHHiJNV0JCi9AC0w0As7zQiFxLQpkGSSQKFVpX2VfYWV9j26b7THdhqCMD-60oRLTr7z-Vzscxy_7JXgKrthkDp-QOOkfFi64xi7XnKJs5yne1BvglxxjgAvE03TdGJh48DSDJ0gkMv7ErLKyEhVDYwxUvQDpBqaQizd0qV0zOiqYgIXg80DFSmWiWGEKqVrnI40rJgG0iygawYmyESGjN7gkX-NS-q3r6OSsjR1U4ELZT9xEWIRTFwyhqw0BYM8Jp6S81xFcYtjICcHbprm6SY2sPFN6pjPglSDd2q0nRp9l6bpMo10ZpszZ8mVilzrB3yhpNp-tuJSnbrbap8nh7FUx9MjMtXUSdIhFOnYZxVYfrEDBttQeDY827LSs8v7OUsVLGnNFXlY8KTFVuRpGU9WZQVeI4vuN5dX0WOWaRHC25C2DelbUNMVUHGGWMlkqLIB-0E2xUW4n69OEVQlBvpZkBgXwSxMUsCc6TR8ot7QjxKmvBO40CkV_vmyNizww0MGCeRnbsmd-jRIG57wcTMxT2_aNESDk6qPrU5wabaqpHaJzrVrtTNtjxfPt2cPqD4faEeFcIQRiOY9-4pZQRVzmxHF_mI4oauM9zkdPT4o5i99pfeuPJU-dxCpzW5qTv0UGf7ZA-4dDz7fX1hXTxJv0Xy0NvV_A-e9JEzcNYKUxmPHpT9tO6h6XkyTpHRUes_mC1YBr7f7gH3q9hqX1d4fQ3jcL33qnxx32vXsGUhdSNNJaYuu2PiPZGkHTRfG6EyAauLuuewsGczkPgIJagkkNccwSFA1IGlMC8K5oG1vCKBi4-S7ACiZKXnrg5JZl_e7HTSYx9_d5OCGRc_uOLtr2V0Xd_jedSmN2Sp256Op74p1WD32b6szy4jPn-o_LpRVo9PDg9nF8hrjXyvHvbztjE4nzf6iNfl-xNeQJg9OTD0x-ub6fvEjmQyudDQLiTGJa15dH5Mz6_bxcXncRY_j63mEa-dmK2Gjq6JBG11WQXlH7pd4E9rBSeBFoR-kbB10UiFGhagVpJJDjSgmW6IunEH8JIU6b1EaOVN_QdnMswUqlO9DmKRtZ0azdipaKrBm6TwjYKOIR7kP6CMaDbmXbEsv7nZRGKcM5rGt0WRSaL-PzM7ackLjBY03O_lDywTb2asdyF6VLGj2juRBSwlxmIZuOB0u2DSE_CUvPUol81FA06EjNgRxFuA7gvTNnsZOkDDnQ-6A0edeVN4gvm6OWx87GduZBfTZdw7glKmuh73uiW1bnFM9Onbm0_R457icl7ixH6VZem9_vf3z759vf7P_Es5JQcJPMajCPwVYnFB58ebwe8lxVbHgynuve_8Bn-G69w";
        let dir = tempfile::tempdir().unwrap();
        let path = import_tunnel(uri, "awg1", dir.path()).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("[Interface]"), "no [Interface] in: {content}");
        assert!(content.contains("Jc"), "no Jc in conf");
        // DNS placeholders must be filled
        assert!(!content.contains("$PRIMARY_DNS"), "DNS placeholder not filled");
    }

    #[test]
    fn import_unknown_format_is_error() {
        let dir = tempfile::tempdir().unwrap();
        let result = import_tunnel("garbage data", "x", dir.path());
        assert!(matches!(result, Err(ImportError::UnknownFormat)));
    }
}
