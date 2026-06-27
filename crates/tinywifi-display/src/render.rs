use std::io;

use crate::status::DisplayStatus;

pub trait Renderer {
    fn is_available(&self) -> bool {
        true
    }

    fn render(&mut self, status: &DisplayStatus) -> io::Result<()>;
}

pub struct ConsoleRenderer;

impl Renderer for ConsoleRenderer {
    fn render(&mut self, s: &DisplayStatus) -> io::Result<()> {
        let ram = s.ram_used_percent.map(|p| format!("{p}%")).unwrap_or_else(|| "—".into());
        let up  = s.uptime_secs.map(short_uptime).unwrap_or_else(|| "—".into());
        println!(
            "TinyWifi | SSID: {} | IP: {} | Clients: {} | WAN: {} | RAM: {} | Up: {}",
            s.ssid.as_deref().unwrap_or("—"),
            s.ip.map(|a| a.to_string()).as_deref().unwrap_or("—"),
            s.clients,
            if s.wan { "OK" } else { "NO" },
            ram, up,
        );
        Ok(())
    }
}

pub fn short_uptime(secs: u64) -> String {
    let (d, h, m) = (secs / 86400, (secs % 86400) / 3600, (secs % 3600) / 60);
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else {
        format!("{m}m")
    }
}
