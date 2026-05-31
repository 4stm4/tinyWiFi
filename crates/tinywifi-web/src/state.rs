use std::sync::Arc;

use tinywifi_core::{HostapdConf, TinywifiConfig};

/// Shared, cheaply-cloneable application state.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<TinywifiConfig>,
}

impl AppState {
    pub fn new(config: TinywifiConfig) -> Self {
        AppState {
            config: Arc::new(config),
        }
    }

    /// The AP interface, read from hostapd.conf, defaulting to `wlan0` if the
    /// config is unavailable or omits it.
    pub fn ap_interface(&self) -> String {
        HostapdConf::from_path(&self.config.paths.hostapd_conf)
            .ok()
            .and_then(|c| c.wifi_config().interface)
            .unwrap_or_else(|| "wlan0".to_string())
    }
}
