use std::fmt::Display;

use axum::extract::State;
use axum::response::{Html, Redirect};

use tinywifi_core::leases::{LeaseStatus, LeasesReport};
use tinywifi_core::metrics::{self, Memory};
use tinywifi_core::{interface_ipv4, HostapdConf, SystemStatus};

use crate::state::AppState;

const NAV: &[(&str, &str)] = &[
    ("/dashboard", "Dashboard"),
    ("/wifi", "Wi-Fi"),
    ("/dhcp", "DHCP"),
    ("/leases", "Leases"),
    ("/system", "System"),
];

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn layout(title: &str, body: &str) -> Html<String> {
    let nav = NAV
        .iter()
        .map(|(href, label)| format!("<a href=\"{href}\">{label}</a>"))
        .collect::<Vec<_>>()
        .join(" ");
    Html(format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>TinyWifi — {title}</title>\n\
         <style>\n\
         body{{font-family:system-ui,sans-serif;margin:0;padding:1rem;max-width:40rem}}\n\
         nav{{display:flex;gap:.75rem;flex-wrap:wrap;margin-bottom:1rem;\
         border-bottom:1px solid #ccc;padding-bottom:.5rem}}\n\
         nav a{{text-decoration:none}}\n\
         table{{border-collapse:collapse;width:100%}}\n\
         td,th{{text-align:left;padding:.25rem .5rem;border-bottom:1px solid #eee}}\n\
         </style>\n</head>\n<body>\n<nav>{nav}</nav>\n<h1>{title}</h1>\n{body}\n</body>\n</html>\n"
    ))
}

pub async fn index() -> Redirect {
    Redirect::to("/dashboard")
}

fn opt<T: Display>(value: Option<T>) -> String {
    value.map(|v| v.to_string()).unwrap_or_else(|| "—".to_string())
}

fn fmt_uptime(secs: u64) -> String {
    let (d, h, m) = (secs / 86400, (secs % 86400) / 3600, (secs % 3600) / 60);
    if d > 0 {
        format!("{d}d {h}h {m}m")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else {
        format!("{m}m")
    }
}

fn fmt_memory(m: Memory) -> String {
    format!(
        "{} / {} MB ({}%)",
        m.used_kb() / 1024,
        m.total_kb / 1024,
        m.used_percent()
    )
}

fn fmt_load(l: [f64; 3]) -> String {
    format!("{:.2} {:.2} {:.2}", l[0], l[1], l[2])
}

fn row(label: &str, value: &str) -> String {
    format!("<tr><th>{}</th><td>{}</td></tr>\n", escape(label), value)
}

pub async fn dashboard(State(st): State<AppState>) -> Html<String> {
    let iface = st.ap_interface();
    let status = SystemStatus::collect(&iface, &st.config.paths.leases_file);
    let ssid = HostapdConf::from_path(&st.config.paths.hostapd_conf)
        .ok()
        .and_then(|c| c.wifi_config().ssid);
    let ip = interface_ipv4(&iface);
    let report = LeasesReport::read(&st.config.paths.leases_file);
    let clients = report
        .leases
        .iter()
        .filter(|l| l.status == LeaseStatus::Active)
        .count();

    let mut body = String::from("<table>\n");
    body.push_str(&row("Wi-Fi (hostapd)", &format!("{:?}", status.hostapd)));
    body.push_str(&row("SSID", &escape(&opt(ssid))));
    body.push_str(&row(
        &format!("{iface} IP"),
        &escape(&opt(ip.map(|a| a.to_string()))),
    ));
    body.push_str(&row(&iface, &format!("{:?}", status.wlan0)));
    body.push_str(&row("DHCP (nanodhcp)", &format!("{:?}", status.nanodhcp)));
    body.push_str(&row("Clients", &clients.to_string()));
    body.push_str(&row("Leases", &format!("{:?}", report.state)));
    body.push_str(&row("Uptime", &opt(metrics::uptime_secs().map(fmt_uptime))));
    body.push_str(&row("RAM", &opt(metrics::memory().map(fmt_memory))));
    body.push_str(&row("Load", &opt(metrics::load_average().map(fmt_load))));
    body.push_str("</table>\n<p><a href=\"/api/status\">/api/status</a></p>");

    layout("Dashboard", &body)
}

pub async fn wifi() -> Html<String> {
    layout(
        "Wi-Fi",
        "<p>Edit SSID, password, country and channel.</p>\
         <p>API: <a href=\"/api/wifi\">GET /api/wifi</a>, POST /api/wifi</p>",
    )
}

pub async fn dhcp() -> Html<String> {
    layout(
        "DHCP",
        "<p>Edit the DHCP pool, gateway, DNS and lease time.</p>\
         <p>API: <a href=\"/api/dhcp\">GET /api/dhcp</a>, POST /api/dhcp</p>",
    )
}

pub async fn leases() -> Html<String> {
    layout(
        "Leases",
        "<p>Connected DHCP clients.</p>\
         <p>API: <a href=\"/api/leases\">GET /api/leases</a></p>",
    )
}

pub async fn system() -> Html<String> {
    layout(
        "System",
        "<p>Restart services and reboot the device.</p>\
         <p>API: <a href=\"/api/services\">GET /api/services</a></p>",
    )
}
