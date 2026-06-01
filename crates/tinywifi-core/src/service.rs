//! Service checks and lifecycle actions, abstracted over the host's init
//! system so the same code works on a systemd box and on the Buildroot/busybox
//! netOS image (SysV-style `/etc/init.d` scripts).
//!
//! Project rule: never start/restart a unit without first confirming it can be
//! managed. The lifecycle helpers enforce this and return [`ServiceError`]
//! instead of silently failing.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// Directories searched for service executables (status fallback) and the
/// SysV init scripts directory.
const BIN_DIRS: &[&str] = &[
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
];
const INIT_D: &str = "/etc/init.d";
/// `/proc/<pid>/comm` is truncated to 15 bytes by the kernel.
const COMM_MAX: usize = 15;

/// Outcome of inspecting a single service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceStatus {
    /// Running (active unit / live process).
    Running,
    /// Installed but not running.
    Stopped,
    /// Not installed on the host.
    Missing,
    /// Could not determine status.
    Error,
}

/// Why a lifecycle action could not be carried out.
#[derive(Debug)]
pub enum ServiceError {
    /// The service cannot be managed here (no unit / init script), so the
    /// action was not attempted.
    NotFound(String),
    /// The init system ran but reported failure.
    CommandFailed { name: String, stderr: String },
    /// The init command could not be invoked at all.
    Io(io::Error),
    /// No supported way to manage services on this host.
    Unsupported,
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceError::NotFound(name) => write!(f, "service '{name}' not found"),
            ServiceError::CommandFailed { name, stderr } => {
                write!(f, "action on '{name}' failed: {}", stderr.trim())
            }
            ServiceError::Io(e) => write!(f, "failed to run init command: {e}"),
            ServiceError::Unsupported => {
                write!(f, "no supported service manager on this host")
            }
        }
    }
}

impl std::error::Error for ServiceError {}

impl From<io::Error> for ServiceError {
    fn from(e: io::Error) -> Self {
        ServiceError::Io(e)
    }
}

/// Which init system manages services on this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Backend {
    /// systemd (`systemctl`).
    Systemd,
    /// SysV-style `/etc/init.d` scripts (Buildroot/busybox).
    SysVInit,
    /// No manager: status by process scan, lifecycle unsupported.
    Proc,
}

fn detect_backend() -> Backend {
    if which("systemctl").is_some() {
        Backend::Systemd
    } else if Path::new(INIT_D).is_dir() {
        Backend::SysVInit
    } else {
        Backend::Proc
    }
}

fn backend() -> Backend {
    static BACKEND: OnceLock<Backend> = OnceLock::new();
    *BACKEND.get_or_init(detect_backend)
}

/// Locate an executable named `name` in the standard binary directories or on
/// `$PATH`.
fn which(name: &str) -> Option<PathBuf> {
    for dir in BIN_DIRS {
        let p = Path::new(dir).join(name);
        if p.is_file() {
            return Some(p);
        }
    }
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':').filter(|d| !d.is_empty()) {
            let p = Path::new(dir).join(name);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

/// Find the `/etc/init.d` script for `name`. An exact filename match wins; the
/// run-level-prefixed form (`S10nanodhcp` for `nanodhcp`) is the fallback, so a
/// dedicated `nanodhcp` control script takes precedence over a boot stub.
fn init_script(name: &str) -> Option<PathBuf> {
    let entries = std::fs::read_dir(INIT_D).ok()?;
    let mut prefixed = None;
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let file = file_name.to_string_lossy();
        if file == name {
            return Some(entry.path());
        }
        if prefixed.is_none() && strip_rc_prefix(&file) == name {
            prefixed = Some(entry.path());
        }
    }
    prefixed
}

fn strip_rc_prefix(file: &str) -> &str {
    let b = file.as_bytes();
    if b.len() > 3 && (b[0] == b'S' || b[0] == b'K') && b[1].is_ascii_digit() && b[2].is_ascii_digit()
    {
        &file[3..]
    } else {
        file
    }
}

/// True if a running process matches `name` by its command name. Checks
/// `/proc/<pid>/comm` (handling the kernel's 15-byte truncation) and the
/// basename of `/proc/<pid>/cmdline`'s first argument.
fn process_running(name: &str) -> bool {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let pid = file_name.to_string_lossy();
        if !pid.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        if proc_matches(&entry.path(), name) {
            return true;
        }
    }
    false
}

fn proc_matches(proc_dir: &Path, name: &str) -> bool {
    if let Ok(comm) = std::fs::read_to_string(proc_dir.join("comm")) {
        let comm = comm.trim();
        if comm == name || (name.len() > COMM_MAX && comm == &name[..COMM_MAX]) {
            return true;
        }
    }
    if let Ok(cmdline) = std::fs::read(proc_dir.join("cmdline")) {
        if let Some(arg0) = cmdline.split(|&b| b == 0).next().filter(|a| !a.is_empty()) {
            let arg0 = String::from_utf8_lossy(arg0);
            if Path::new(arg0.as_ref())
                .file_name()
                .is_some_and(|base| base.to_string_lossy() == name)
            {
                return true;
            }
        }
    }
    false
}

fn unit(name: &str) -> String {
    if name.contains('.') {
        name.to_string()
    } else {
        format!("{name}.service")
    }
}

fn systemd_load_state(name: &str) -> Option<String> {
    let out = Command::new("systemctl")
        .args(["show", "-p", "LoadState", "--value", &unit(name)])
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// True if the service can be managed on this host (systemd unit loaded, init
/// script present, or — for status only — a known executable exists).
pub fn service_exists(name: &str) -> bool {
    match backend() {
        Backend::Systemd => systemd_load_state(name).as_deref() == Some("loaded"),
        Backend::SysVInit => init_script(name).is_some() || which(name).is_some(),
        Backend::Proc => which(name).is_some(),
    }
}

/// True if the service is currently running.
pub fn service_running(name: &str) -> bool {
    match backend() {
        Backend::Systemd => Command::new("systemctl")
            .args(["is-active", "--quiet", &unit(name)])
            .status()
            .map(|s| s.success())
            .unwrap_or(false),
        _ => process_running(name),
    }
}

/// Combined status: running / stopped / missing, or error if it can't be told.
pub fn service_status(name: &str) -> ServiceStatus {
    match backend() {
        Backend::Systemd => match systemd_load_state(name).as_deref() {
            Some("loaded") => {
                if service_running(name) {
                    ServiceStatus::Running
                } else {
                    ServiceStatus::Stopped
                }
            }
            Some("not-found") => ServiceStatus::Missing,
            Some(_) => ServiceStatus::Error,
            None => ServiceStatus::Error,
        },
        _ => {
            if process_running(name) {
                ServiceStatus::Running
            } else if init_script(name).is_some() || which(name).is_some() {
                ServiceStatus::Stopped
            } else {
                ServiceStatus::Missing
            }
        }
    }
}

fn run_action(action: &str, name: &str) -> Result<(), ServiceError> {
    if !service_exists(name) {
        return Err(ServiceError::NotFound(name.to_string()));
    }
    let out = match backend() {
        Backend::Systemd => Command::new("systemctl").args([action, &unit(name)]).output()?,
        Backend::SysVInit => {
            let script = init_script(name).ok_or_else(|| ServiceError::NotFound(name.to_string()))?;
            Command::new(&script).arg(action).output()?
        }
        Backend::Proc => return Err(ServiceError::Unsupported),
    };
    if out.status.success() {
        Ok(())
    } else {
        Err(ServiceError::CommandFailed {
            name: name.to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
}

/// Start the service (checks it can be managed first).
pub fn service_start(name: &str) -> Result<(), ServiceError> {
    run_action("start", name)
}

/// Stop the service (checks it can be managed first).
pub fn service_stop(name: &str) -> Result<(), ServiceError> {
    run_action("stop", name)
}

/// Restart the service (checks it can be managed first).
pub fn service_restart(name: &str) -> Result<(), ServiceError> {
    run_action("restart", name)
}

/// Reload-or-restart the service. SysV scripts have no reload-or-restart verb,
/// so it maps to `restart` there; systemd uses the native verb.
pub fn service_reload_or_restart(name: &str) -> Result<(), ServiceError> {
    match backend() {
        Backend::Systemd => run_action("reload-or-restart", name),
        _ => run_action("restart", name),
    }
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
    fn strips_runlevel_prefix() {
        assert_eq!(strip_rc_prefix("S10nanodhcp"), "nanodhcp");
        assert_eq!(strip_rc_prefix("K90foo"), "foo");
        assert_eq!(strip_rc_prefix("rcS"), "rcS");
        assert_eq!(strip_rc_prefix("hostapd"), "hostapd");
    }

    #[test]
    fn bogus_service_is_missing_and_not_running() {
        let name = "tinywifi-bogus-unit-xyz";
        assert!(!service_exists(name));
        assert!(!service_running(name));
        assert_eq!(service_status(name), ServiceStatus::Missing);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detects_a_live_process() {
        // The test runner itself is alive; match it by its own comm.
        let comm = std::fs::read_to_string("/proc/self/comm").unwrap();
        assert!(process_running(comm.trim()));
    }

    #[test]
    fn lifecycle_refuses_unmanageable_unit() {
        let err = service_start("tinywifi-bogus-unit-xyz").unwrap_err();
        assert!(matches!(
            err,
            ServiceError::NotFound(_) | ServiceError::Unsupported
        ));
    }

    #[test]
    fn status_serializes_lowercase() {
        let json = serde_json::to_string(&ServiceStatus::Running).unwrap();
        assert_eq!(json, "\"running\"");
    }
}
