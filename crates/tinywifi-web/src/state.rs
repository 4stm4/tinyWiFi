use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tinywifi_core::{AutoRevert, HostapdConf, MonitorHandle, TinywifiConfig};

use crate::auth;

/// Armed auto-reverts awaiting confirmation, keyed by area (`"wifi"`,
/// `"dhcp"`). Arming a new change for a key replaces (and cancels) the
/// previous pending one.
pub type PendingReverts = Arc<Mutex<HashMap<&'static str, AutoRevert>>>;

/// Shared, cheaply-cloneable application state.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<TinywifiConfig>,
    pub pending: PendingReverts,
    pub sessions: auth::Sessions,
    pub login_attempts: auth::LoginAttempts,
    pub monitor: MonitorHandle,
}

impl AppState {
    pub fn new(config: TinywifiConfig) -> Self {
        AppState {
            config: Arc::new(config),
            pending: Arc::new(Mutex::new(HashMap::new())),
            sessions: auth::new_sessions(),
            login_attempts: auth::new_login_attempts(),
            monitor: MonitorHandle::new(),
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
