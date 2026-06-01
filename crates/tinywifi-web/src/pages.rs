use std::fmt::Display;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::response::{Html, Redirect};

use tinywifi_core::file::file_exists;
use tinywifi_core::leases::{LeaseStatus, LeasesReport};
use tinywifi_core::metrics::{self, Memory};
use tinywifi_core::{
    interface_ipv4, service_status, DhcpConfig, HostapdConf, ServiceStatus, SystemStatus,
};

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
         label{{display:block;margin:.7rem 0 .2rem;font-weight:600}}\n\
         input{{width:100%;max-width:22rem;padding:.4rem;box-sizing:border-box;font-size:1rem}}\n\
         form button{{margin-top:1rem;padding:.5rem 1.2rem;font-size:1rem}}\n\
         .hint{{color:#666;font-size:.85rem;margin:.2rem 0}}\n\
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

/// Shared client-side helpers: POST a JSON form and report the result, plus the
/// per-page field collectors.
const FORM_SCRIPT: &str = "\
<script>\n\
async function twSave(url, payload, btn){\n\
  const out = document.getElementById('result');\n\
  btn.disabled = true; out.style.color=''; out.textContent = 'Сохранение…';\n\
  try {\n\
    const r = await fetch(url, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});\n\
    let j = {}; try { j = await r.json(); } catch(e) {}\n\
    if (r.ok) { out.style.color='green'; out.textContent='Сохранено ✓'; setTimeout(function(){location.reload();}, 900); }\n\
    else { out.style.color='red'; out.textContent='Ошибка ' + r.status + ': ' + (j.error || r.statusText); }\n\
  } catch(e) { out.style.color='red'; out.textContent='Сбой запроса: ' + e; }\n\
  btn.disabled = false;\n\
}\n\
function val(id){ return document.getElementById(id).value; }\n\
function twWifi(btn){ twSave('/api/wifi', {\n\
  ssid: val('ssid'), passphrase: val('passphrase'),\n\
  country_code: val('country'), channel: parseInt(val('channel'),10)\n\
}, btn); }\n\
function twDhcp(btn){ twSave('/api/dhcp', {\n\
  gateway: val('gateway'), range_start: val('range_start'), range_end: val('range_end'),\n\
  dns: val('dns').split(',').map(function(s){return s.trim();}).filter(function(s){return s;}),\n\
  lease_time: parseInt(val('lease_time'),10)\n\
}, btn); }\n\
</script>\n";

fn fmt_expiry(expires: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if expires > now {
        format!("через {}", fmt_uptime(expires - now))
    } else {
        "истёк".to_string()
    }
}

pub async fn wifi(State(st): State<AppState>) -> Html<String> {
    let body = match HostapdConf::from_path(&st.config.paths.hostapd_conf) {
        Ok(conf) => {
            let w = conf.wifi_config();
            let iface = w.interface.unwrap_or_else(|| "wlan0".to_string());
            format!(
                "<form onsubmit=\"return false\">\n\
                 <p class=\"hint\">Интерфейс: {iface}</p>\n\
                 <label for=\"ssid\">SSID</label>\
                 <input id=\"ssid\" value=\"{ssid}\" maxlength=\"32\">\n\
                 <label for=\"passphrase\">Пароль (8–63 символа)</label>\
                 <input id=\"passphrase\" value=\"{pass}\" minlength=\"8\" maxlength=\"63\">\n\
                 <label for=\"country\">Страна (2 буквы)</label>\
                 <input id=\"country\" value=\"{country}\" maxlength=\"2\">\n\
                 <label for=\"channel\">Канал</label>\
                 <input id=\"channel\" type=\"number\" value=\"{channel}\" min=\"1\" max=\"165\">\n\
                 <button onclick=\"twWifi(this)\">Сохранить</button>\n\
                 <p id=\"result\" role=\"status\"></p>\n\
                 </form>\n{FORM_SCRIPT}",
                iface = escape(&iface),
                ssid = escape(&w.ssid.unwrap_or_default()),
                pass = escape(&w.wpa_passphrase.unwrap_or_default()),
                country = escape(&w.country_code.unwrap_or_default()),
                channel = w.channel.map(|c| c.to_string()).unwrap_or_default(),
            )
        }
        Err(e) => format!(
            "<p>Конфиг hostapd недоступен: {}</p>",
            escape(&e.to_string())
        ),
    };
    layout("Wi-Fi", &body)
}

pub async fn dhcp(State(st): State<AppState>) -> Html<String> {
    let body = match DhcpConfig::from_path(&st.config.paths.nanodhcp_conf) {
        Ok(c) => format!(
            "<form onsubmit=\"return false\">\n\
             <p class=\"hint\">Интерфейс: {iface}</p>\n\
             <label for=\"gateway\">Шлюз (router)</label>\
             <input id=\"gateway\" value=\"{gw}\">\n\
             <label for=\"range_start\">Начало пула</label>\
             <input id=\"range_start\" value=\"{rs}\">\n\
             <label for=\"range_end\">Конец пула</label>\
             <input id=\"range_end\" value=\"{re}\">\n\
             <label for=\"dns\">DNS (через запятую)</label>\
             <input id=\"dns\" value=\"{dns}\">\n\
             <label for=\"lease_time\">Аренда, секунд</label>\
             <input id=\"lease_time\" type=\"number\" value=\"{lt}\" min=\"1\">\n\
             <button onclick=\"twDhcp(this)\">Сохранить</button>\n\
             <p id=\"result\" role=\"status\"></p>\n\
             </form>\n{FORM_SCRIPT}",
            iface = escape(&c.interface),
            gw = escape(&c.gateway.to_string()),
            rs = escape(&c.range_start.to_string()),
            re = escape(&c.range_end.to_string()),
            dns = escape(
                &c.dns
                    .iter()
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            lt = c.lease_time,
        ),
        Err(e) => format!(
            "<p>Конфиг nanodhcp недоступен: {}</p>",
            escape(&e.to_string())
        ),
    };
    layout("DHCP", &body)
}

pub async fn leases(State(st): State<AppState>) -> Html<String> {
    let report = LeasesReport::read(&st.config.paths.leases_file);
    let mut body = format!("<p>Состояние: <strong>{:?}</strong></p>\n", report.state);
    if let Some(err) = &report.error {
        body.push_str(&format!(
            "<p style=\"color:red\">{}</p>\n",
            escape(err)
        ));
    }
    if report.leases.is_empty() {
        body.push_str("<p>Активных клиентов нет.</p>\n");
    } else {
        body.push_str(
            "<table>\n<tr><th>Хост</th><th>MAC</th><th>IP</th><th>Статус</th><th>Истекает</th></tr>\n",
        );
        for l in &report.leases {
            body.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{:?}</td><td>{}</td></tr>\n",
                escape(l.hostname.as_deref().unwrap_or("—")),
                escape(&l.mac),
                escape(&l.ip.to_string()),
                l.status,
                escape(&fmt_expiry(l.lease_expires)),
            ));
        }
        body.push_str("</table>\n");
    }
    body.push_str("<p><a href=\"/api/leases\">/api/leases</a></p>");
    layout("Leases", &body)
}

const SYSTEM_SCRIPT: &str = "\
<p id=\"result\" role=\"status\"></p>\n\
<script>\n\
async function act(url, btn, confirmMsg){\n\
  if(confirmMsg && !confirm(confirmMsg)) return;\n\
  const out = document.getElementById('result');\n\
  btn.disabled = true; out.textContent = 'Working…';\n\
  try {\n\
    const r = await fetch(url, {method:'POST'});\n\
    let j = {}; try { j = await r.json(); } catch(e) {}\n\
    out.textContent = r.ok ? ('OK: ' + url) : ('Error ' + r.status + ': ' + (j.error||r.statusText));\n\
    if(r.ok) setTimeout(function(){ location.reload(); }, 1000);\n\
  } catch(e){ out.textContent = 'Request failed: ' + e; }\n\
  btn.disabled = false;\n\
}\n\
</script>\n";

pub async fn system(State(st): State<AppState>) -> Html<String> {
    let s = &st.config.services;
    let p = &st.config.paths;
    let items: [(&str, &str, Option<&std::path::Path>); 4] = [
        ("Wi-Fi (hostapd)", &s.hostapd, Some(p.hostapd_conf.as_path())),
        ("DHCP (nanodhcp)", &s.nanodhcp, Some(p.nanodhcp_conf.as_path())),
        ("Web UI", &s.web, None),
        ("Display", &s.display, None),
    ];

    let mut body = String::from("<table>\n<tr><th>Service</th><th>Status</th><th></th></tr>\n");
    for (label, unit, config) in items {
        let status = service_status(unit);
        let missing_config = config.map(|c| !file_exists(c)).unwrap_or(false);
        let mut status_cell = format!("{status:?}");
        if missing_config {
            status_cell.push_str(" <em>(config missing)</em>");
        }
        let disabled = if status == ServiceStatus::Missing {
            " disabled"
        } else {
            ""
        };
        let button = format!(
            "<button onclick=\"act('/api/services/{}/restart', this)\"{}>Restart</button>",
            escape(unit),
            disabled
        );
        body.push_str(&format!(
            "<tr><th>{}</th><td>{}</td><td>{}</td></tr>\n",
            escape(label),
            status_cell,
            button
        ));
    }
    body.push_str("</table>\n");
    body.push_str(
        "<h2>Device</h2>\n\
         <button onclick=\"act('/api/system/reboot', this, 'Reboot the device?')\">Reboot</button>\n",
    );
    body.push_str(SYSTEM_SCRIPT);

    layout("System", &body)
}
