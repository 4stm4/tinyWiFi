//! Network interface checks. Backed by `/sys/class/net` for existence and the
//! `ip` tool for address presence, so they work on the Pi's Linux rootfs.

use std::path::Path;
use std::process::Command;

/// True if a network interface with this name exists on the host.
pub fn interface_exists(name: &str) -> bool {
    Path::new("/sys/class/net").join(name).exists()
}

/// True if the interface exists and currently has an IPv4 address assigned.
pub fn interface_has_ip(name: &str) -> bool {
    if !interface_exists(name) {
        return false;
    }
    match Command::new("ip")
        .args(["-o", "-4", "addr", "show", name])
        .output()
    {
        Ok(out) => !out.stdout.is_empty(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn loopback_exists() {
        assert!(interface_exists("lo"));
    }

    #[test]
    fn bogus_interface_does_not_exist() {
        assert!(!interface_exists("definitely-not-an-iface0"));
        assert!(!interface_has_ip("definitely-not-an-iface0"));
    }
}
