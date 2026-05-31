//! systemd service checks and lifecycle actions.
//!
//! Project rule: never start/restart a unit without first confirming it
//! exists. The lifecycle helpers enforce this and return [`ServiceError`]
//! instead of silently failing.

use std::fmt;
use std::io;
use std::process::Command;

/// Outcome of inspecting a single service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceStatus {
    /// Unit exists and is active.
    Running,
    /// Unit exists but is not active.
    Stopped,
    /// No such unit on the host.
    Missing,
    /// Could not determine status (systemctl unavailable, etc.).
    Error,
}

/// Why a lifecycle action could not be carried out.
#[derive(Debug)]
pub enum ServiceError {
    /// The unit does not exist, so the action was not attempted.
    NotFound(String),
    /// systemctl ran but reported failure.
    CommandFailed { name: String, stderr: String },
    /// systemctl could not be invoked at all.
    Io(io::Error),
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceError::NotFound(name) => write!(f, "service '{name}' not found"),
            ServiceError::CommandFailed { name, stderr } => {
                write!(f, "systemctl action on '{name}' failed: {}", stderr.trim())
            }
            ServiceError::Io(e) => write!(f, "failed to run systemctl: {e}"),
        }
    }
}

impl std::error::Error for ServiceError {}

impl From<io::Error> for ServiceError {
    fn from(e: io::Error) -> Self {
        ServiceError::Io(e)
    }
}

fn unit(name: &str) -> String {
    if name.contains('.') {
        name.to_string()
    } else {
        format!("{name}.service")
    }
}

/// True if systemd has a unit loaded under this name.
pub fn service_exists(name: &str) -> bool {
    match Command::new("systemctl")
        .args(["show", "-p", "LoadState", "--value", &unit(name)])
        .output()
    {
        Ok(out) => String::from_utf8_lossy(&out.stdout).trim() == "loaded",
        Err(_) => false,
    }
}

/// True if the unit is currently active.
pub fn service_running(name: &str) -> bool {
    match Command::new("systemctl")
        .args(["is-active", "--quiet", &unit(name)])
        .status()
    {
        Ok(status) => status.success(),
        Err(_) => false,
    }
}

/// Combined status: missing / running / stopped, or error if systemctl fails.
pub fn service_status(name: &str) -> ServiceStatus {
    match Command::new("systemctl")
        .args(["show", "-p", "LoadState", "--value", &unit(name)])
        .output()
    {
        Ok(out) => {
            let load_state = String::from_utf8_lossy(&out.stdout);
            match load_state.trim() {
                "loaded" => {
                    if service_running(name) {
                        ServiceStatus::Running
                    } else {
                        ServiceStatus::Stopped
                    }
                }
                "not-found" => ServiceStatus::Missing,
                _ => ServiceStatus::Error,
            }
        }
        Err(_) => ServiceStatus::Error,
    }
}

fn run_action(action: &str, name: &str) -> Result<(), ServiceError> {
    if !service_exists(name) {
        return Err(ServiceError::NotFound(name.to_string()));
    }
    let out = Command::new("systemctl")
        .args([action, &unit(name)])
        .output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(ServiceError::CommandFailed {
            name: name.to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
}

/// `systemctl start` the unit (checks existence first).
pub fn service_start(name: &str) -> Result<(), ServiceError> {
    run_action("start", name)
}

/// `systemctl restart` the unit (checks existence first).
pub fn service_restart(name: &str) -> Result<(), ServiceError> {
    run_action("restart", name)
}

/// `systemctl reload-or-restart` the unit (checks existence first).
pub fn service_reload_or_restart(name: &str) -> Result<(), ServiceError> {
    run_action("reload-or-restart", name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_name_gets_service_suffix() {
        assert_eq!(unit("hostapd"), "hostapd.service");
        assert_eq!(unit("nanodhcp.service"), "nanodhcp.service");
    }

    #[test]
    fn bogus_service_is_missing_and_not_running() {
        let name = "tinywifi-bogus-unit-xyz";
        assert!(!service_exists(name));
        assert!(!service_running(name));
    }

    #[test]
    fn lifecycle_refuses_missing_unit() {
        let err = service_start("tinywifi-bogus-unit-xyz").unwrap_err();
        assert!(matches!(err, ServiceError::NotFound(_)));
    }

    #[test]
    fn status_serializes_lowercase() {
        let json = serde_json::to_string(&ServiceStatus::Running).unwrap();
        assert_eq!(json, "\"running\"");
    }
}
