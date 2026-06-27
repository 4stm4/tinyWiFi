mod epaper;
mod render;
mod status;

use std::path::PathBuf;
use std::time::Duration;

use tinywifi_core::config::{self, DisplayConfig, Paths, Services, TinywifiConfig, WebConfig};

use crate::epaper::EpaperRenderer;
use crate::render::{ConsoleRenderer, Renderer};
use crate::status::DisplayStatus;

fn config_path() -> String {
    if let Ok(p) = std::env::var("TINYWIFI_CONFIG") {
        return p;
    }
    if std::path::Path::new(config::DEFAULT_PATH).exists() {
        return config::DEFAULT_PATH.to_string();
    }
    "configs/tinywifi.toml".to_string()
}

/// On-device defaults used when the config can't be read, so the display keeps
/// running (in degraded form) instead of exiting.
fn default_config() -> TinywifiConfig {
    TinywifiConfig {
        web: WebConfig {
            listen: "0.0.0.0:8080".to_string(),
        },
        display: DisplayConfig { refresh_secs: 10 },
        paths: Paths {
            hostapd_conf: PathBuf::from("/etc/hostapd/hostapd.conf"),
            nanodhcp_conf: PathBuf::from("/etc/nanodhcp/nanodhcp.conf"),
            nanodns_conf: PathBuf::from("/etc/nanodns/config"),
            leases_file: PathBuf::from("/var/lib/nanodhcp/leases.json"),
        },
        services: Services {
            hostapd: "hostapd".to_string(),
            nanodhcp: "nanodhcp".to_string(),
            nanodns: "nanodns".to_string(),
            web: "tinywifi-web".to_string(),
            display: "tinywifi-display".to_string(),
        },
    }
}

fn main() {
    let path = config_path();
    let config = TinywifiConfig::from_path(&path).unwrap_or_else(|e| {
        eprintln!("tinywifi-display: config unavailable ({e}); using defaults");
        default_config()
    });

    let interval = Duration::from_secs(config.display.refresh_secs.max(1));

    let mut renderer: Box<dyn Renderer> = match EpaperRenderer::open() {
        Ok(r) => {
            println!("tinywifi-display {}: Waveshare 2.13\" e-paper ready", tinywifi_core::VERSION);
            Box::new(r)
        }
        Err(e) => {
            eprintln!("tinywifi-display {}: e-paper unavailable ({e}), using console", tinywifi_core::VERSION);
            Box::new(ConsoleRenderer)
        }
    };

    loop {
        if renderer.is_available() {
            let status = DisplayStatus::collect(&config);
            if let Err(e) = renderer.render(&status) {
                eprintln!("tinywifi-display: render error: {e}");
            }
        } else {
            eprintln!("tinywifi-display: screen unavailable, skipping frame");
        }
        std::thread::sleep(interval);
    }
}
