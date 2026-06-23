//! Client MAC-address access control list (ACL).
//!
//! Three modes:
//!   - Disabled  — no filtering, all clients welcome.
//!   - Whitelist — only MACs in the list may associate.
//!   - Blacklist — MACs in the list are refused.
//!
//! Persisted to `/var/lib/tinywifi/acl.json`; applied by writing a hostapd
//! MAC file, updating `hostapd.conf`, and restarting the service.

use std::path::Path;

use serde::{Deserialize, Serialize};

pub const ACL_STATE_FILE: &str = "/var/lib/tinywifi/acl.json";
pub const HOSTAPD_ACCEPT_FILE: &str = "/etc/hostapd/hostapd.accept";
pub const HOSTAPD_DENY_FILE: &str = "/etc/hostapd/hostapd.deny";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AclMode {
    #[default]
    Disabled,
    Whitelist,
    Blacklist,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AclState {
    #[serde(default)]
    pub mode: AclMode,
    #[serde(default)]
    pub macs: Vec<String>,
}

impl AclState {
    pub fn load() -> Self {
        let path = Path::new(ACL_STATE_FILE);
        if !path.exists() {
            return Self::default();
        }
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return Self::default(),
        };
        serde_json::from_str(&content).unwrap_or_default()
    }

    pub fn save(&self) -> Result<(), String> {
        let path = Path::new(ACL_STATE_FILE);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create dir {}: {e}", parent.display()))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("serialize acl: {e}"))?;
        std::fs::write(path, json).map_err(|e| format!("write {ACL_STATE_FILE}: {e}"))
    }

    pub fn normalize_mac(mac: &str) -> String {
        mac.trim().to_lowercase()
    }

    pub fn add(&mut self, mac: &str) {
        let mac = Self::normalize_mac(mac);
        if !mac.is_empty() && !self.macs.contains(&mac) {
            self.macs.push(mac);
        }
    }

    pub fn remove(&mut self, mac: &str) {
        let mac = Self::normalize_mac(mac);
        self.macs.retain(|m| m != &mac);
    }

    /// Apply ACL to hostapd: write MAC file, update conf, restart service.
    pub fn apply(&self, hostapd_conf_path: &Path, service: &str) -> Result<(), String> {
        use crate::hostapd::HostapdConf;
        use crate::service::service_restart;

        // Write / clear MAC list files
        match self.mode {
            AclMode::Whitelist => {
                write_mac_file(HOSTAPD_ACCEPT_FILE, &self.macs)?;
                std::fs::remove_file(HOSTAPD_DENY_FILE).ok();
            }
            AclMode::Blacklist => {
                write_mac_file(HOSTAPD_DENY_FILE, &self.macs)?;
                std::fs::remove_file(HOSTAPD_ACCEPT_FILE).ok();
            }
            AclMode::Disabled => {
                std::fs::remove_file(HOSTAPD_ACCEPT_FILE).ok();
                std::fs::remove_file(HOSTAPD_DENY_FILE).ok();
            }
        }

        // Update hostapd.conf
        let mut conf = HostapdConf::from_path(hostapd_conf_path)
            .map_err(|e| e.to_string())?;
        match self.mode {
            AclMode::Whitelist => {
                conf.set("macaddr_acl", "1");
                conf.set("accept_mac_file", HOSTAPD_ACCEPT_FILE);
                conf.remove_key("deny_mac_file");
            }
            AclMode::Blacklist => {
                conf.set("macaddr_acl", "0");
                conf.set("deny_mac_file", HOSTAPD_DENY_FILE);
                conf.remove_key("accept_mac_file");
            }
            AclMode::Disabled => {
                conf.set("macaddr_acl", "0");
                conf.remove_key("accept_mac_file");
                conf.remove_key("deny_mac_file");
            }
        }
        std::fs::write(hostapd_conf_path, conf.to_string())
            .map_err(|e| format!("write hostapd.conf: {e}"))?;

        service_restart(service).map_err(|e| e.to_string())
    }
}

fn write_mac_file(path: &str, macs: &[String]) -> Result<(), String> {
    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create dir {}: {e}", parent.display()))?;
    }
    let content = macs.join("\n") + if macs.is_empty() { "" } else { "\n" };
    std::fs::write(path, content).map_err(|e| format!("write {path}: {e}"))
}
