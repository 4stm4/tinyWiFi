use std::io;

use crate::status::DisplayStatus;

/// A target the status frame can be drawn to. The console implementation is
/// used today; a real screen driver can implement the same trait later and
/// report availability through [`Renderer::is_available`].
pub trait Renderer {
    /// Whether the screen is present and ready. The daemon skips drawing (and
    /// logs a degraded state) when this is false.
    fn is_available(&self) -> bool {
        true
    }

    /// Draw a pre-formatted frame.
    fn render(&mut self, frame: &str) -> io::Result<()>;
}

/// Writes frames to stdout. Stands in for the hardware screen for now.
pub struct ConsoleRenderer;

impl Renderer for ConsoleRenderer {
    fn render(&mut self, frame: &str) -> io::Result<()> {
        println!("{frame}");
        Ok(())
    }
}

fn opt<T: std::fmt::Display>(value: Option<T>) -> String {
    value.map(|v| v.to_string()).unwrap_or_else(|| "—".to_string())
}

fn short_uptime(secs: u64) -> String {
    let (d, h, m) = (secs / 86400, (secs % 86400) / 3600, (secs % 3600) / 60);
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else {
        format!("{m}m")
    }
}

/// Format the status into the lines shown on screen.
/// Lines starting with "---" are rendered as horizontal separators by EpaperRenderer.
pub fn format_frame(status: &DisplayStatus) -> String {
    let ram = status
        .ram_used_percent
        .map(|p| format!("{p}%"))
        .unwrap_or_else(|| "—".to_string());
    let up = status
        .uptime_secs
        .map(short_uptime)
        .unwrap_or_else(|| "—".to_string());
    format!(
        "TinyWifi\n\
         ---\n\
         SSID: {ssid}\n\
         IP:   {ip}\n\
         ---\n\
         Clients: {clients}\n\
         WAN:     {wan}\n\
         ---\n\
         RAM: {ram}\n\
         Up:  {up}",
        ssid = opt(status.ssid.clone()),
        ip = opt(status.ip.map(|a| a.to_string())),
        clients = status.clients,
        wan = if status.wan { "OK" } else { "NO" },
        ram = ram,
        up = up,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn formats_full_status() {
        let s = DisplayStatus {
            ssid: Some("MyNet".to_string()),
            ip: Some(Ipv4Addr::new(192, 168, 44, 1)),
            clients: 3,
            wan: true,
            ram_used_percent: Some(30),
            uptime_secs: Some(90061), // 1d 1h ...
        };
        let frame = format_frame(&s);
        assert!(frame.contains("SSID: MyNet"));
        assert!(frame.contains("IP:   192.168.44.1"));
        assert!(frame.contains("Clients: 3"));
        assert!(frame.contains("WAN:     OK"));
        assert!(frame.contains("RAM: 30%"));
        assert!(frame.contains("Up:  1d 1h"));
    }

    #[test]
    fn degrades_missing_fields() {
        let s = DisplayStatus {
            ssid: None,
            ip: None,
            clients: 0,
            wan: false,
            ram_used_percent: None,
            uptime_secs: None,
        };
        let frame = format_frame(&s);
        assert!(frame.contains("SSID: —"));
        assert!(frame.contains("IP:   —"));
        assert!(frame.contains("WAN:     NO"));
        assert!(frame.contains("RAM: —"));
        assert!(frame.contains("Up: —"));
    }
}
