//! Network interface checks. Backed by `/sys/class/net` for existence and the
//! `ip` tool for address presence, so they work on the Pi's Linux rootfs.

use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Command;

/// True if a network interface with this name exists on the host.
pub fn interface_exists(name: &str) -> bool {
    Path::new("/sys/class/net").join(name).exists()
}

/// True if the interface exists and currently has an IPv4 address assigned.
pub fn interface_has_ip(name: &str) -> bool {
    interface_ipv4(name).is_some()
}

/// The first IPv4 address assigned to the interface, if any.
pub fn interface_ipv4(name: &str) -> Option<Ipv4Addr> {
    if !interface_exists(name) {
        return None;
    }
    let out = Command::new("ip")
        .args(["-o", "-4", "addr", "show", name])
        .output()
        .ok()?;
    parse_ipv4(&String::from_utf8_lossy(&out.stdout))
}

/// True if the host has a default route (a usable WAN/uplink).
pub fn has_default_route() -> bool {
    match Command::new("ip").args(["route", "show", "default"]).output() {
        Ok(out) => !out.stdout.trim_ascii().is_empty(),
        Err(_) => false,
    }
}

/// Extract the address from `ip -o -4 addr show` output (the token after `inet`,
/// with its CIDR suffix stripped).
fn parse_ipv4(output: &str) -> Option<Ipv4Addr> {
    let mut tokens = output.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "inet" {
            return tokens.next()?.split('/').next()?.parse().ok();
        }
    }
    None
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
        assert_eq!(interface_ipv4("definitely-not-an-iface0"), None);
    }

    #[test]
    fn parses_ipv4_from_ip_output() {
        let line = "3: wlan0    inet 192.168.44.1/24 brd 192.168.44.255 scope global wlan0\\       valid_lft forever";
        assert_eq!(parse_ipv4(line), Some(Ipv4Addr::new(192, 168, 44, 1)));
        assert_eq!(parse_ipv4(""), None);
        assert_eq!(parse_ipv4("2: eth0    no address here"), None);
    }
}
