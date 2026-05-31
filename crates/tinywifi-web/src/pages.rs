use axum::extract::State;
use axum::response::{Html, Redirect};

use tinywifi_core::SystemStatus;

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

pub async fn dashboard(State(st): State<AppState>) -> Html<String> {
    let iface = st.ap_interface();
    let status = SystemStatus::collect(&iface, &st.config.paths.leases_file);
    let body = format!(
        "<table>\n\
         <tr><th>Wi-Fi (hostapd)</th><td>{:?}</td></tr>\n\
         <tr><th>DHCP (nanodhcp)</th><td>{:?}</td></tr>\n\
         <tr><th>Leases</th><td>{:?}</td></tr>\n\
         <tr><th>{}</th><td>{:?}</td></tr>\n\
         </table>\n\
         <p><a href=\"/api/status\">/api/status</a></p>",
        status.hostapd,
        status.nanodhcp,
        status.leases,
        escape(&iface),
        status.wlan0,
    );
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
