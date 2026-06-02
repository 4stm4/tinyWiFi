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

/// Wi-Fi signal glyph for the brand wordmark; inherits `--accent` via
/// `currentColor` from `.topbar__brand .mark`.
const BRAND_MARK: &str = "<svg width=\"20\" height=\"20\" viewBox=\"0 0 100 100\" fill=\"none\" \
stroke=\"currentColor\" stroke-width=\"7\" stroke-linecap=\"round\">\
<path d=\"M22 44a40 40 0 0 1 56 0\" opacity=\".4\"/>\
<path d=\"M34 56a24 24 0 0 1 32 0\" opacity=\".75\"/>\
<circle cx=\"50\" cy=\"70\" r=\"5\" fill=\"currentColor\" stroke=\"none\"/></svg>";

/// Render a status enum's `Debug` name as a colored Nervum status pill.
/// Covers `ServiceStatus`, `InterfaceStatus`, `LeasesStatus`, `LeaseStatus`
/// and `LeasesState`.
fn pill(text: &str) -> String {
    let kind = match text {
        "Running" | "Up" | "Active" | "Available" => "ok",
        "Stale" | "Down" => "drift",
        "Error" => "failed",
        // Stopped, Missing, Empty, Unavailable, Expired
        _ => "muted",
    };
    format!(
        "<span class=\"pill pill--{kind}\"><span class=\"dot\"></span>{}</span>",
        escape(text)
    )
}

fn layout(title: &str, active: &str, body: &str) -> Html<String> {
    let nav = NAV
        .iter()
        .map(|(href, label)| {
            let cls = if *href == active {
                "tw-nav__item is-active"
            } else {
                "tw-nav__item"
            };
            format!("<a class=\"{cls}\" href=\"{href}\">{label}</a>")
        })
        .collect::<Vec<_>>()
        .join("");
    Html(format!(
        "<!DOCTYPE html>\n<html lang=\"ru\" data-theme=\"dark\">\n<head>\n\
         <meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>TinyWifi — {title}</title>\n\
         <link rel=\"stylesheet\" href=\"/style.css\">\n\
         </head>\n<body>\n\
         <header class=\"tw-top\">\n\
         <div class=\"topbar__brand\"><span class=\"mark\">{BRAND_MARK}</span>\
         <span class=\"name\">tiny<b>wifi</b></span></div>\n\
         <nav class=\"tw-nav\">{nav}</nav>\n\
         </header>\n\
         <main class=\"page\">\n\
         <div class=\"page__head\"><h1 class=\"page__title\">{title}</h1></div>\n\
         {body}\n\
         </main>\n</body>\n</html>\n"
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

    let mut body = String::from("<table class=\"tbl\"><tbody>\n");
    body.push_str(&row("Wi-Fi (hostapd)", &pill(&format!("{:?}", status.hostapd))));
    body.push_str(&row("SSID", &escape(&opt(ssid))));
    body.push_str(&row(
        &format!("{iface} IP"),
        &escape(&opt(ip.map(|a| a.to_string()))),
    ));
    body.push_str(&row(&iface, &pill(&format!("{:?}", status.wlan0))));
    body.push_str(&row(
        "DHCP (nanodhcp)",
        &pill(&format!("{:?}", status.nanodhcp)),
    ));
    body.push_str(&row("Clients", &clients.to_string()));
    body.push_str(&row("Leases", &pill(&format!("{:?}", report.state))));
    body.push_str(&row("Uptime", &opt(metrics::uptime_secs().map(fmt_uptime))));
    body.push_str(&row("RAM", &opt(metrics::memory().map(fmt_memory))));
    body.push_str(&row("Load", &opt(metrics::load_average().map(fmt_load))));
    body.push_str("</tbody></table>\n<p><a href=\"/api/status\">/api/status</a></p>");

    layout("Dashboard", "/dashboard", &body)
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
                "<section class=\"card\"><div class=\"card__body\">\n\
                 <div class=\"callout\"><div class=\"body\">Интерфейс: <b>{iface}</b></div></div>\n\
                 <form onsubmit=\"return false\">\n\
                 <div class=\"form-grid\">\n\
                 <div class=\"field field--full\"><label for=\"ssid\">SSID</label>\
                 <input id=\"ssid\" value=\"{ssid}\" maxlength=\"32\"></div>\n\
                 <div class=\"field field--full\"><label for=\"passphrase\">Пароль (8–63 символа)</label>\
                 <input id=\"passphrase\" value=\"{pass}\" minlength=\"8\" maxlength=\"63\"></div>\n\
                 <div class=\"field\"><label for=\"country\">Страна (2 буквы)</label>\
                 <input id=\"country\" value=\"{country}\" maxlength=\"2\"></div>\n\
                 <div class=\"field\"><label for=\"channel\">Канал</label>\
                 <input id=\"channel\" type=\"number\" value=\"{channel}\" min=\"1\" max=\"165\"></div>\n\
                 </div>\n\
                 <div class=\"form-actions\">\
                 <button class=\"btn btn--primary\" onclick=\"twWifi(this)\">Сохранить</button>\
                 <span id=\"result\" class=\"note\" role=\"status\"></span></div>\n\
                 </form>\n</div></section>\n{FORM_SCRIPT}",
                iface = escape(&iface),
                ssid = escape(&w.ssid.unwrap_or_default()),
                pass = escape(&w.wpa_passphrase.unwrap_or_default()),
                country = escape(&w.country_code.unwrap_or_default()),
                channel = w.channel.map(|c| c.to_string()).unwrap_or_default(),
            )
        }
        Err(e) => format!(
            "<div class=\"callout\" style=\"border-color:var(--status-failed)\">\
             <div class=\"body\">Конфиг hostapd недоступен: {}</div></div>",
            escape(&e.to_string())
        ),
    };
    layout("Wi-Fi", "/wifi", &body)
}

pub async fn dhcp(State(st): State<AppState>) -> Html<String> {
    let body = match DhcpConfig::from_path(&st.config.paths.nanodhcp_conf) {
        Ok(c) => format!(
            "<section class=\"card\"><div class=\"card__body\">\n\
             <div class=\"callout\"><div class=\"body\">Интерфейс: <b>{iface}</b></div></div>\n\
             <form onsubmit=\"return false\">\n\
             <div class=\"form-grid\">\n\
             <div class=\"field field--full\"><label for=\"gateway\">Шлюз (router)</label>\
             <input id=\"gateway\" value=\"{gw}\"></div>\n\
             <div class=\"field\"><label for=\"range_start\">Начало пула</label>\
             <input id=\"range_start\" value=\"{rs}\"></div>\n\
             <div class=\"field\"><label for=\"range_end\">Конец пула</label>\
             <input id=\"range_end\" value=\"{re}\"></div>\n\
             <div class=\"field field--full\"><label for=\"dns\">DNS (через запятую)</label>\
             <input id=\"dns\" value=\"{dns}\"></div>\n\
             <div class=\"field\"><label for=\"lease_time\">Аренда, секунд</label>\
             <input id=\"lease_time\" type=\"number\" value=\"{lt}\" min=\"1\"></div>\n\
             </div>\n\
             <div class=\"form-actions\">\
             <button class=\"btn btn--primary\" onclick=\"twDhcp(this)\">Сохранить</button>\
             <span id=\"result\" class=\"note\" role=\"status\"></span></div>\n\
             </form>\n</div></section>\n{FORM_SCRIPT}",
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
            "<div class=\"callout\" style=\"border-color:var(--status-failed)\">\
             <div class=\"body\">Конфиг nanodhcp недоступен: {}</div></div>",
            escape(&e.to_string())
        ),
    };
    layout("DHCP", "/dhcp", &body)
}

pub async fn leases(State(st): State<AppState>) -> Html<String> {
    let report = LeasesReport::read(&st.config.paths.leases_file);
    let mut body = format!("<p>Состояние: {}</p>\n", pill(&format!("{:?}", report.state)));
    if let Some(err) = &report.error {
        body.push_str(&format!(
            "<div class=\"callout\" style=\"border-color:var(--status-failed)\">\
             <div class=\"body\">{}</div></div>\n",
            escape(err)
        ));
    }
    if report.leases.is_empty() {
        body.push_str("<div class=\"empty\">Активных клиентов нет.</div>\n");
    } else {
        body.push_str(
            "<table class=\"tbl\">\n<thead><tr><th>Хост</th><th>MAC</th><th>IP</th>\
             <th>Статус</th><th>Истекает</th></tr></thead>\n<tbody>\n",
        );
        for l in &report.leases {
            body.push_str(&format!(
                "<tr><td class=\"col-host\">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                escape(l.hostname.as_deref().unwrap_or("—")),
                escape(&l.mac),
                escape(&l.ip.to_string()),
                pill(&format!("{:?}", l.status)),
                escape(&fmt_expiry(l.lease_expires)),
            ));
        }
        body.push_str("</tbody></table>\n");
    }
    body.push_str("<p><a href=\"/api/leases\">/api/leases</a></p>");
    layout("Leases", "/leases", &body)
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

    let mut body = String::from(
        "<table class=\"tbl\">\n<thead><tr><th>Сервис</th><th>Статус</th><th></th></tr></thead>\n<tbody>\n",
    );
    for (label, unit, config) in items {
        let status = service_status(unit);
        let missing_config = config.map(|c| !file_exists(c)).unwrap_or(false);
        let mut status_cell = pill(&format!("{status:?}"));
        if missing_config {
            status_cell.push_str(" <span class=\"tag\">config missing</span>");
        }
        let disabled = if status == ServiceStatus::Missing {
            " disabled"
        } else {
            ""
        };
        let button = format!(
            "<button class=\"btn btn--ghost btn--sm\" \
             onclick=\"act('/api/services/{}/restart', this)\"{}>Restart</button>",
            escape(unit),
            disabled
        );
        body.push_str(&format!(
            "<tr><td class=\"col-host\">{}</td><td>{}</td><td class=\"num\">{}</td></tr>\n",
            escape(label),
            status_cell,
            button
        ));
    }
    body.push_str("</tbody></table>\n");
    body.push_str(
        "<h2>Устройство</h2>\n\
         <div class=\"danger-zone\">\
         <div class=\"body\"><div class=\"t\">Перезагрузка устройства</div>\
         <div class=\"d\">Перезапустит точку доступа; клиенты ненадолго отключатся.</div></div>\
         <button class=\"btn btn--danger\" \
         onclick=\"act('/api/system/reboot', this, 'Reboot the device?')\">Reboot</button>\
         </div>\n",
    );
    body.push_str(SYSTEM_SCRIPT);

    layout("System", "/system", &body)
}
