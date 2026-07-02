//! Loader for the main TinyWifi config (`/etc/tinywifi/tinywifi.toml`),
//! shared by the web UI and the display daemon.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::file::{file_exists, file_readable};

/// Default on-device location of the config.
pub const DEFAULT_PATH: &str = "/etc/tinywifi/tinywifi.toml";

#[derive(Debug, Clone, Deserialize)]
pub struct TinywifiConfig {
    pub web: WebConfig,
    pub display: DisplayConfig,
    pub paths: Paths,
    pub services: Services,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WebConfig {
    /// HTTPS address the web server binds to, e.g. `0.0.0.0:443`.
    pub listen: String,
    /// Plain-HTTP address that redirects to `listen`, e.g. `0.0.0.0:80`.
    /// Defaulted so existing configs without this field still parse.
    #[serde(default = "default_http_redirect_listen")]
    pub http_redirect_listen: String,
}

fn default_http_redirect_listen() -> String {
    "0.0.0.0:80".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct DisplayConfig {
    /// How often the display refreshes, in seconds.
    pub refresh_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Paths {
    pub hostapd_conf: PathBuf,
    pub nanodhcp_conf: PathBuf,
    pub nanodns_conf: PathBuf,
    pub leases_file: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Services {
    pub hostapd: String,
    pub nanodhcp: String,
    pub nanodns: String,
    pub web: String,
    pub display: String,
}

#[derive(Debug)]
pub enum ConfigError {
    NotFound(PathBuf),
    NotReadable(PathBuf),
    Parse(String),
    Io(io::Error),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::NotFound(p) => write!(f, "config not found: {}", p.display()),
            ConfigError::NotReadable(p) => write!(f, "config not readable: {}", p.display()),
            ConfigError::Parse(e) => write!(f, "invalid config: {e}"),
            ConfigError::Io(e) => write!(f, "filesystem error: {e}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl TinywifiConfig {
    pub fn parse(content: &str) -> Result<Self, ConfigError> {
        toml::from_str(content).map_err(|e| ConfigError::Parse(e.message().to_string()))
    }

    /// Read and parse the config at `path`, checking availability first.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        if !file_exists(path) {
            return Err(ConfigError::NotFound(path.to_path_buf()));
        }
        if !file_readable(path) {
            return Err(ConfigError::NotReadable(path.to_path_buf()));
        }
        let content = std::fs::read_to_string(path).map_err(ConfigError::Io)?;
        Self::parse(&content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL_CONFIG: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../configs/tinywifi.toml"));

    #[test]
    fn reads_real_config() {
        let cfg = TinywifiConfig::parse(REAL_CONFIG).unwrap();
        assert_eq!(cfg.web.listen, "0.0.0.0:8443");
        assert_eq!(cfg.web.http_redirect_listen, "0.0.0.0:8080");
        assert_eq!(cfg.display.refresh_secs, 10);
        assert_eq!(cfg.paths.nanodhcp_conf, PathBuf::from("/etc/nanodhcp/nanodhcp.conf"));
        assert_eq!(cfg.paths.nanodns_conf, PathBuf::from("/etc/nanodns/config"));
        assert_eq!(cfg.paths.leases_file, PathBuf::from("/var/lib/nanodhcp/leases"));
        assert_eq!(cfg.services.hostapd, "hostapd");
        assert_eq!(cfg.services.nanodns, "nanodns");
        assert_eq!(cfg.services.display, "tinywifi-display");
    }

    /// Configs written before TLS support was added lack `http_redirect_listen`;
    /// they must still parse instead of failing to boot.
    #[test]
    fn web_config_without_http_redirect_listen_uses_default() {
        let toml = REAL_CONFIG.replace(
            "http_redirect_listen = \"0.0.0.0:8080\"\n",
            "",
        );
        let cfg = TinywifiConfig::parse(&toml).unwrap();
        assert_eq!(cfg.web.http_redirect_listen, "0.0.0.0:80");
    }
}
