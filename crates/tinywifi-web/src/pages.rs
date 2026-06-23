use std::fmt::Display;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::response::{Html, Redirect};

use tinywifi_core::file::file_exists;
use tinywifi_core::leases::{LeaseStatus, LeasesReport};
use tinywifi_core::{AclMode, AclState};
use tinywifi_core::metrics;
use tinywifi_core::{
    scan_tunnels, wan_candidates, wan_status, AwgTunnelStatus, IfaceState,
    WanConfig, WanMode, AWG_CONF_DIR,
    interface_ipv4, service_status, DhcpConfig, HostapdConf, ServiceStatus, SystemStatus,
};

use crate::state::AppState;

/// Top navigation: (href, Russian label). The English page name is passed by
/// each handler and drives the document `<title>` and the page-head eyebrow.
const NAV: &[(&str, &str)] = &[
    ("/dashboard", "Панель"),
    ("/wifi", "Wi-Fi"),
    ("/dhcp", "DHCP"),
    ("/leases", "Клиенты"),
    ("/wan", "WAN"),
    ("/vpn", "VPN"),
    ("/system", "Система"),
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

/// Theme switch glyph — a half-filled "contrast" disc that reads the same in
/// either theme.
const THEME_ICON: &str = "<svg width=\"17\" height=\"17\" viewBox=\"0 0 24 24\" fill=\"none\" \
stroke=\"currentColor\" stroke-width=\"2\"><circle cx=\"12\" cy=\"12\" r=\"9\"/>\
<path d=\"M12 3a9 9 0 0 0 0 18z\" fill=\"currentColor\" stroke=\"none\"/></svg>";

// Compact line icons (stroke = currentColor) for the dashboard tiles and the
// leases table. Kept tiny on purpose — this is an embedded operator panel.
const ICO_CLIENTS: &str = "<svg width=\"16\" height=\"16\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><circle cx=\"9\" cy=\"8\" r=\"3\"/><path d=\"M3 20a6 6 0 0 1 12 0M16 6a3 3 0 0 1 0 6M21 20a6 6 0 0 0-5-5.9\"/></svg>";
const ICO_RAM: &str = "<svg width=\"16\" height=\"16\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><rect x=\"4\" y=\"7\" width=\"16\" height=\"10\" rx=\"1\"/><path d=\"M8 7V5M12 7V5M16 7V5M8 21v-4M16 21v-4\"/></svg>";
const ICO_UPTIME: &str = "<svg width=\"16\" height=\"16\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M12 7v5l3 2\"/></svg>";
const ICO_LOAD: &str = "<svg width=\"16\" height=\"16\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"M3 12h4l3 7 4-14 3 7h4\"/></svg>";
const ICO_DEVICE: &str = "<svg width=\"15\" height=\"15\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><rect x=\"4\" y=\"4\" width=\"16\" height=\"12\" rx=\"1\"/><path d=\"M9 20h6M12 16v4\"/></svg>";

/// Theme toggle + early-restore wiring. The inline restore runs in `<head>` so
/// the stored theme is applied before first paint (no flash).
const THEME_SCRIPT: &str = "<script>\n\
function twToggleTheme(){var d=document.documentElement;\
var n=d.dataset.theme==='light'?'dark':'light';d.dataset.theme=n;\
try{localStorage.setItem('tw-theme',n);}catch(e){}}\n\
</script>\n";

/// A 3-bar signal indicator. Real RSSI is not in the lease data, so the level
/// is derived from lease validity: full for active, a single bar for expired.
fn sig(active: bool) -> String {
    let on = if active { 3 } else { 1 };
    let bars: String = [5_i32, 8, 11]
        .iter()
        .enumerate()
        .map(|(i, h)| {
            let cls = if i < on { " class=\"on\"" } else { "" };
            format!("<i{cls} style=\"height:{h}px\"></i>")
        })
        .collect();
    format!("<span class=\"sig\">{bars}</span>")
}

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

fn layout(title: &str, en: &str, active: &str, body: &str) -> Html<String> {
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
         <script>try{{var t=localStorage.getItem('tw-theme');if(t)document.documentElement.dataset.theme=t;}}catch(e){{}}</script>\n\
         <title>TinyWifi — {en}</title>\n\
         <link rel=\"stylesheet\" href=\"/style.css\">\n\
         </head>\n<body>\n\
         <header class=\"tw-top\">\n\
         <div class=\"topbar__brand\"><span class=\"mark\">{BRAND_MARK}</span>\
         <span class=\"name\">tiny<b>wifi</b></span></div>\n\
         <nav class=\"tw-nav\">{nav}</nav>\n\
         <button class=\"theme-toggle\" onclick=\"twToggleTheme()\" title=\"Тема\" \
         aria-label=\"Переключить тему\" style=\"margin-left:auto\">{THEME_ICON}</button>\n\
         </header>\n\
         <main class=\"page\">\n\
         <div class=\"page__head\">\
         <h1 class=\"page__title\"><span class=\"en\">{en}</span>{title}</h1></div>\n\
         {body}\n\
         {THEME_SCRIPT}\
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

fn row(label: &str, value: &str) -> String {
    format!("<tr><th>{}</th><td>{}</td></tr>\n", escape(label), value)
}

/// One dashboard stat tile. `value` may contain markup (e.g. a `.unit` span);
/// `label` and `meta` are escaped.
fn tile(ico: &str, label: &str, value: &str, meta: &str) -> String {
    format!(
        "<div class=\"tile\">\
         <div class=\"tile__top\"><span class=\"tile__label\">{lab}</span>\
         <span class=\"tile__ico\">{ico}</span></div>\
         <div class=\"tile__value\">{value}</div>\
         <div class=\"tile__meta\">{met}</div></div>",
        lab = escape(label),
        met = escape(meta),
    )
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

    // Stat tiles (big numbers).
    let mem = metrics::memory();
    let ram_value = mem
        .as_ref()
        .map(|m| format!("{}<span class=\"unit\">%</span>", m.used_percent()))
        .unwrap_or_else(|| "—".to_string());
    let ram_meta = mem
        .map(|m| format!("{} / {} MB", m.used_kb() / 1024, m.total_kb / 1024))
        .unwrap_or_default();
    let up_value = metrics::uptime_secs()
        .map(fmt_uptime)
        .unwrap_or_else(|| "—".to_string());
    let load = metrics::load_average();
    let load_value = load
        .map(|l| format!("{:.2}", l[0]))
        .unwrap_or_else(|| "—".to_string());
    let load_meta = load
        .map(|l| format!("{:.2} · {:.2}", l[1], l[2]))
        .unwrap_or_default();

    let mut body = String::from("<div class=\"tiles\">");
    body.push_str(&tile(
        ICO_CLIENTS,
        "Clients · Клиенты",
        &clients.to_string(),
        "активные",
    ));
    body.push_str(&tile(ICO_RAM, "RAM · Память", &ram_value, &ram_meta));
    body.push_str(&tile(
        ICO_UPTIME,
        "Uptime · Аптайм",
        &up_value,
        "с перезагрузки",
    ));
    body.push_str(&tile(ICO_LOAD, "Load · Нагрузка", &load_value, &load_meta));
    body.push_str("</div>\n");

    // Network / service status.
    body.push_str("<h2>Состояние</h2>\n<table class=\"tbl\"><tbody>\n");
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
    body.push_str(&row("Leases", &pill(&format!("{:?}", report.state))));
    body.push_str("</tbody></table>\n<p><a href=\"/api/status\">/api/status</a></p>");

    layout("Сводка", "Dashboard", "/dashboard", &body)
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
                 <div class=\"field field--full\"><label for=\"ssid\">SSID <span class=\"en\">network name</span></label>\
                 <input id=\"ssid\" value=\"{ssid}\" maxlength=\"32\"></div>\n\
                 <div class=\"field field--full\"><label for=\"passphrase\">Пароль <span class=\"en\">passphrase</span></label>\
                 <input id=\"passphrase\" value=\"{pass}\" minlength=\"8\" maxlength=\"63\">\
                 <div class=\"hint\">8–63 символа</div></div>\n\
                 <div class=\"field\"><label for=\"country\">Страна <span class=\"en\">country</span></label>\
                 <input id=\"country\" value=\"{country}\" maxlength=\"2\">\
                 <div class=\"hint\">2 буквы, ISO-3166</div></div>\n\
                 <div class=\"field\"><label for=\"channel\">Канал <span class=\"en\">channel</span></label>\
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
    layout("Точка доступа", "Wi-Fi", "/wifi", &body)
}

pub async fn dhcp(State(st): State<AppState>) -> Html<String> {
    let body = match DhcpConfig::from_path(&st.config.paths.nanodhcp_conf) {
        Ok(c) => format!(
            "<section class=\"card\"><div class=\"card__body\">\n\
             <div class=\"callout\"><div class=\"body\">Интерфейс: <b>{iface}</b></div></div>\n\
             <form onsubmit=\"return false\">\n\
             <div class=\"form-grid\">\n\
             <div class=\"field field--full\"><label for=\"gateway\">Шлюз <span class=\"en\">gateway</span></label>\
             <input id=\"gateway\" value=\"{gw}\"></div>\n\
             <div class=\"field\"><label for=\"range_start\">Начало пула <span class=\"en\">pool start</span></label>\
             <input id=\"range_start\" value=\"{rs}\"></div>\n\
             <div class=\"field\"><label for=\"range_end\">Конец пула <span class=\"en\">pool end</span></label>\
             <input id=\"range_end\" value=\"{re}\"></div>\n\
             <div class=\"field field--full\"><label for=\"dns\">DNS <span class=\"en\">resolvers</span></label>\
             <input id=\"dns\" value=\"{dns}\"><div class=\"hint\">через запятую</div></div>\n\
             <div class=\"field\"><label for=\"lease_time\">Аренда <span class=\"en\">lease</span></label>\
             <input id=\"lease_time\" type=\"number\" value=\"{lt}\" min=\"1\"><div class=\"hint\">секунд</div></div>\n\
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
    layout("Выдача адресов", "DHCP", "/dhcp", &body)
}

pub async fn leases(State(st): State<AppState>) -> Html<String> {
    let report = LeasesReport::read(&st.config.paths.leases_file);
    let acl = AclState::load();
    let blocked: std::collections::HashSet<String> = acl.macs.iter().cloned().collect();

    let mut body = String::new();

    // ACL control panel
    let mode_cls = match acl.mode { AclMode::Disabled => "ok", AclMode::Whitelist => "warn", AclMode::Blacklist => "failed" };
    let mode_label = match acl.mode { AclMode::Disabled => "Открытый", AclMode::Whitelist => "Белый список", AclMode::Blacklist => "Чёрный список" };
    let mac_list_html = if acl.macs.is_empty() {
        String::new()
    } else {
        let items: String = acl.macs.iter().map(|m| format!(
            "<span style=\"margin-right:.5rem\">{m}              <button style=\"font-size:.75rem;padding:.1rem .35rem\"              onclick=\"aclUnblock(\'{m}\')\">✕</button></span>",
        )).collect();
        format!("<div style=\"margin-top:.8rem;font-size:.85rem\"><strong>Список ({n}):</strong><br>{items}</div>",
            n = acl.macs.len())
    };
    body.push_str(&format!(
        "<div class=\"card\" style=\"margin-bottom:1.2rem\">         <div class=\"card-title\">Управление доступом          <span class=\"pill pill-{cls}\">{lbl}</span></div>         <div style=\"display:flex;gap:.6rem;flex-wrap:wrap;margin-top:.6rem\">           <button onclick=\"aclSetMode(\'disabled\')\">Открытый</button>           <button onclick=\"aclSetMode(\'whitelist\')\">Белый список</button>           <button onclick=\"aclSetMode(\'blacklist\')\">Чёрный список</button>         </div>{mac_list}</div>",
        cls = mode_cls, lbl = mode_label, mac_list = mac_list_html,
    ));

    // Clients table
    body.push_str(&format!("<p>Состояние: {}</p>\n", pill(&format!("{:?}", report.state))));
    if let Some(err) = &report.error {
        body.push_str(&format!(
            "<div class=\"callout\" style=\"border-color:var(--status-failed)\"><div class=\"body\">{}</div></div>\n",
            escape(err)
        ));
    }
    if report.leases.is_empty() {
        body.push_str("<div class=\"empty\">Активных клиентов нет.</div>\n");
    } else {
        body.push_str(
            "<table class=\"tbl\">\n<thead><tr><th>Хост</th><th>MAC</th><th>IP</th>             <th>Сигнал</th><th>Статус</th><th>Истекает</th><th></th></tr></thead>\n<tbody>\n",
        );
        for l in &report.leases {
            let active = l.status == LeaseStatus::Active;
            let is_blocked = blocked.contains(&AclState::normalize_mac(&l.mac));
            let btn = if is_blocked {
                format!(
                    "<button onclick=\"aclUnblock(\'{mac}\')\"                     style=\"background:var(--status-ok);color:#fff\">Разблокировать</button>",
                    mac = escape(&l.mac))
            } else {
                format!(
                    "<button onclick=\"aclBlock(\'{mac}\')\"                     style=\"background:var(--status-failed);color:#fff\">Блок</button>",
                    mac = escape(&l.mac))
            };
            body.push_str(&format!(
                "<tr><td class=\"col-host\"><span class=\"dev-ico\">{ico}</span>{host}</td>                 <td>{mac}</td><td>{ip}</td><td>{sig}</td><td>{st}</td><td>{exp}</td><td>{btn}</td></tr>\n",
                ico  = ICO_DEVICE,
                host = escape(l.hostname.as_deref().unwrap_or("—")),
                mac  = escape(&l.mac),
                ip   = escape(&l.ip.to_string()),
                sig  = sig(active),
                st   = pill(&format!("{:?}", l.status)),
                exp  = escape(&fmt_expiry(l.lease_expires)),
            ));
        }
        body.push_str("</tbody></table>\n");
    }

    body.push_str(r#"
<script>
async function aclBlock(mac){
  const r=await fetch('/api/acl/block',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mac})});
  if(r.ok)location.reload();else alert('Ошибка: '+(await r.text()));
}
async function aclUnblock(mac){
  const r=await fetch('/api/acl/unblock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mac})});
  if(r.ok)location.reload();else alert('Ошибка: '+(await r.text()));
}
async function aclSetMode(mode){
  const cur=await(await fetch('/api/acl')).json();
  const r=await fetch('/api/acl',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mode,macs:cur.macs||[]})});
  if(r.ok)location.reload();else alert('Ошибка: '+(await r.text()));
}
</script>"#);

    layout("Клиенты", "Leases", "/leases", &body)
}

pub async fn wan(_st: State<AppState>) -> Html<String> {
    let candidates = wan_candidates();
    let saved = WanConfig::load();

    // Active interface: saved config or first candidate
    let active_iface = saved
        .as_ref()
        .map(|c| c.interface.clone())
        .or_else(|| candidates.first().cloned())
        .unwrap_or_else(|| "eth0".to_string());

    let status = wan_status(&active_iface);
    let mode = saved.as_ref().map(|c| c.mode).unwrap_or(WanMode::Dhcp);

    let online_pill = if status.online {
        pill("Up")
    } else {
        pill("Down")
    };
    let state_pill = match status.state {
        IfaceState::Up      => pill("Up"),
        IfaceState::Down    => pill("Down"),
        IfaceState::Missing => pill("Missing"),
    };

    let mut body = String::new();

    // Status card
    body.push_str("<section class=\"card\" style=\"margin-bottom:1rem\"><div class=\"card__body\">\n");
    body.push_str("<h2 style=\"margin:0 0 .75rem\">Состояние</h2>\n");
    body.push_str("<table class=\"tbl\"><tbody>\n");
    body.push_str(&row("Интерфейс", &escape(&active_iface)));
    body.push_str(&row("Канал", &state_pill));
    body.push_str(&row("Адрес", &escape(status.address.as_deref().unwrap_or("—"))));
    body.push_str(&row("Шлюз",  &escape(status.gateway.as_deref().unwrap_or("—"))));
    body.push_str(&row("DNS", &escape(&if status.dns.is_empty() { "—".into() } else { status.dns.join(", ") })));
    body.push_str(&format!("<tr><th>Интернет</th><td>{online_pill}</td></tr>\n"));
    body.push_str("</tbody></table>\n");
    body.push_str("</div></section>\n");

    // Config card
    // Interface selector options
    let iface_options: String = candidates
        .iter()
        .map(|n| {
            let sel = if n == &active_iface { " selected" } else { "" };
            format!("<option value=\"{n}\"{sel}>{n}</option>")
        })
        .collect();

    let (dhcp_sel, static_sel) = match mode {
        WanMode::Dhcp   => (" selected", ""),
        WanMode::Static => ("", " selected"),
    };

    let static_addr = saved.as_ref().and_then(|c| c.address.clone()).unwrap_or_default();
    let static_gw   = saved.as_ref().and_then(|c| c.gateway.clone()).unwrap_or_default();
    let static_dns  = saved.as_ref()
        .and_then(|c| c.dns.as_ref())
        .map(|d| d.join(", "))
        .unwrap_or_default();

    body.push_str(&format!(
        "<section class=\"card\"><div class=\"card__body\">\n\
         <h2 style=\"margin:0 0 .75rem\">Настройка</h2>\n\
         <form onsubmit=\"return false\">\n\
         <div class=\"form-grid\">\n\
         <div class=\"field\"><label for=\"wan-iface\">Интерфейс <span class=\"en\">interface</span></label>\
         <select id=\"wan-iface\" onchange=\"wanModeToggle()\">{iface_options}</select></div>\n\
         <div class=\"field\"><label for=\"wan-mode\">Режим <span class=\"en\">mode</span></label>\
         <select id=\"wan-mode\" onchange=\"wanModeToggle()\">\
         <option value=\"dhcp\"{dhcp_sel}>DHCP (авто)</option>\
         <option value=\"static\"{static_sel}>Static (ручной)</option>\
         </select></div>\n\
         </div>\n\
         <div id=\"wan-static\" style=\"display:none\">\n\
         <div class=\"form-grid\">\n\
         <div class=\"field\"><label for=\"wan-addr\">Адрес <span class=\"en\">address/prefix</span></label>\
         <input id=\"wan-addr\" value=\"{static_addr}\" placeholder=\"192.168.1.2/24\"></div>\n\
         <div class=\"field\"><label for=\"wan-gw\">Шлюз <span class=\"en\">gateway</span></label>\
         <input id=\"wan-gw\" value=\"{static_gw}\" placeholder=\"192.168.1.1\"></div>\n\
         <div class=\"field field--full\"><label for=\"wan-dns\">DNS</label>\
         <input id=\"wan-dns\" value=\"{static_dns}\" placeholder=\"8.8.8.8, 1.1.1.1\">\
         <div class=\"hint\">через запятую</div></div>\n\
         </div>\n\
         </div>\n\
         <div class=\"form-actions\">\
         <button class=\"btn btn--primary\" onclick=\"wanSave(this)\">Применить</button>\
         <span id=\"wan-result\" class=\"note\" role=\"status\"></span>\
         </div>\n\
         </form>\n</div></section>\n",
    ));

    body.push_str("<p><a href=\"/api/wan\">/api/wan</a></p>\n");
    body.push_str(WAN_SCRIPT);

    layout("Интернет", "WAN", "/wan", &body)
}

const WAN_SCRIPT: &str = "\
<script>\n\
function wanModeToggle(){\n\
  var m=document.getElementById('wan-mode').value;\n\
  document.getElementById('wan-static').style.display=m==='static'?'':'none';\n\
}\n\
wanModeToggle();\n\
async function wanSave(btn){\n\
  var out=document.getElementById('wan-result');\n\
  btn.disabled=true; out.style.color=''; out.textContent='Применяю…';\n\
  var payload={\n\
    interface:document.getElementById('wan-iface').value,\n\
    mode:document.getElementById('wan-mode').value,\n\
    address:document.getElementById('wan-addr')?.value||null,\n\
    gateway:document.getElementById('wan-gw')?.value||null,\n\
    dns:document.getElementById('wan-dns')?.value.split(',').map(function(s){return s.trim();}).filter(Boolean)||null\n\
  };\n\
  try{\n\
    var r=await fetch('/api/wan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});\n\
    var j={}; try{j=await r.json();}catch(e){}\n\
    if(r.ok){out.style.color='green';out.textContent='Применено ✓';setTimeout(function(){location.reload();},1200);}\n\
    else{out.style.color='red';out.textContent='Ошибка: '+(j.error||r.statusText);}\n\
  }catch(e){out.style.color='red';out.textContent='Сбой: '+e;}\n\
  btn.disabled=false;\n\
}\n\
</script>\n";

pub async fn vpn(_st: State<AppState>) -> Html<String> {
    use tinywifi_core::load_bypass_list;
    let tunnels = scan_tunnels(AWG_CONF_DIR);
    let bypass = load_bypass_list();

    let mut body = String::new();

    // ── Section 1: Tunnel list ─────────────────────────────────────────────
    body.push_str("<section class=\"card\" style=\"margin-bottom:1rem\"><div class=\"card__body\">\n");
    body.push_str("<h2 style=\"margin:0 0 1rem\">Мои туннели</h2>\n");

    if tunnels.is_empty() {
        body.push_str("<div class=\"empty\" style=\"margin:.5rem 0 1rem\">Нет туннелей. Добавьте ниже.</div>\n");
    } else {
        body.push_str("<div style=\"display:flex;flex-direction:column;gap:.5rem;margin-bottom:1rem\">\n");
        for t in &tunnels {
            let is_up = t.status == AwgTunnelStatus::Up;
            let endpoint = t.peers.first()
                .and_then(|p| p.endpoint.as_deref())
                .unwrap_or("—");
            let dot_color = if is_up { "var(--status-ok)" } else { "var(--text-muted)" };
            body.push_str(&format!(
                "<div style=\"display:flex;align-items:center;gap:.75rem;padding:.6rem .75rem;\
                 background:var(--surface-2);border-radius:6px\">\
                 <span style=\"width:8px;height:8px;border-radius:50%;background:{dot_color};flex-shrink:0\"></span>\
                 <div style=\"flex:1;min-width:0\">\
                 <div style=\"font-weight:600\">{name}</div>\
                 <div style=\"font-size:.75rem;color:var(--text-muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap\">{ep}</div>\
                 </div>\
                 <div id=\"vpn-result-{n}\" class=\"note\" role=\"status\" style=\"font-size:.8rem\"></div>\
                 {btn}\
                 </div>\n",
                dot_color = dot_color,
                name = escape(&t.name),
                ep = escape(endpoint),
                n = escape(&t.name),
                btn = if is_up {
                    format!("<button class=\"btn btn--ghost btn--sm\" onclick=\"vpnAct('/api/vpn/{n}/down',this)\">Отключить</button>",
                        n = escape(&t.name))
                } else {
                    format!("<button class=\"btn btn--primary btn--sm\" onclick=\"vpnAct('/api/vpn/{n}/up',this)\">Подключить</button>",
                        n = escape(&t.name))
                },
            ));
        }
        body.push_str("</div>\n");
    }

    // Toggle button to show/hide import form
    body.push_str(
        "<button class=\"btn btn--ghost btn--sm\" onclick=\"vpnToggleImport()\" id=\"vpn-add-btn\">\
         + Добавить туннель\
         </button>\n\
         <div id=\"vpn-import-form\" style=\"display:none;margin-top:.75rem\">\n\
         <div class=\"field\" style=\"margin-bottom:.5rem\">\
         <label for=\"vpn-name\">Имя туннеля</label>\
         <input id=\"vpn-name\" value=\"awg0\" maxlength=\"32\" placeholder=\"awg0\">\
         </div>\
         <div class=\"field\" style=\"margin-bottom:.5rem\">\
         <label for=\"vpn-import-text\">Конфиг <span class=\"en\">(.conf или vpn://...)</span></label>\
         <textarea id=\"vpn-import-text\" rows=\"7\" \
         style=\"width:100%;box-sizing:border-box;font-family:monospace;font-size:.8rem;\
         resize:vertical;background:var(--surface-1);color:var(--text);\
         border:1px solid var(--border);border-radius:4px;padding:.5rem\" \
         placeholder=\"[Interface]\nPrivateKey = ...\n\nили vpn://AAALR...\"></textarea>\
         </div>\
         <div class=\"form-actions\">\
         <button class=\"btn btn--primary\" onclick=\"vpnImport(this)\">Импортировать</button>\
         <button class=\"btn btn--ghost\" onclick=\"vpnToggleImport()\">Отмена</button>\
         <span id=\"vpn-import-result\" class=\"note\" role=\"status\"></span>\
         </div>\
         </div>\n"
    );
    body.push_str("</div></section>\n");

    // ── Section 2: Bypass list ─────────────────────────────────────────────
    body.push_str("<section class=\"card\"><div class=\"card__body\">\n");
    body.push_str(
        "<h2 style=\"margin:0 0 .4rem\">Обход VPN</h2>\
         <p style=\"margin:0 0 .75rem;font-size:.85rem;color:var(--text-muted)\">\
         Адреса и сети, которые всегда идут напрямую (не через туннель).\
         </p>\n"
    );

    // Bypass entries list
    body.push_str("<div id=\"bypass-list\">\n");
    if bypass.is_empty() {
        body.push_str("<div class=\"empty\" style=\"margin:.5rem 0\">Нет исключений — весь трафик через VPN.</div>\n");
    }
    for entry in &bypass {
        body.push_str(&format!(
            "<div style=\"display:flex;align-items:center;gap:.5rem;margin-bottom:.4rem\">\
             <code style=\"flex:1;font-size:.85rem\">{entry}</code>\
             <button class=\"btn btn--ghost btn--sm\" onclick=\"bypassRemove(this,'{entry}')\">✕</button>\
             </div>\n",
            entry = escape(entry),
        ));
    }
    body.push_str("</div>\n");

    // Add entry form
    body.push_str(
        "<div style=\"display:flex;gap:.5rem;margin-top:.5rem\" id=\"bypass-add-row\">\
         <input id=\"bypass-input\" placeholder=\"1.2.3.4 или 192.168.0.0/16\" \
         style=\"flex:1\" onkeydown=\"if(event.key==='Enter')bypassAdd()\">\
         <button class=\"btn btn--primary btn--sm\" onclick=\"bypassAdd()\">Добавить</button>\
         </div>\
         <span id=\"bypass-result\" class=\"note\" role=\"status\" style=\"display:block;margin-top:.4rem\"></span>\n"
    );
    body.push_str("</div></section>\n");

    body.push_str(VPN_SCRIPT);
    layout("Туннели", "VPN", "/vpn", &body)
}

const VPN_SCRIPT: &str = "\
<script>\n\
var _bypassEntries = Array.from(document.querySelectorAll('#bypass-list code')).map(function(e){return e.textContent.trim();});\n\
\n\
function vpnToggleImport(){\n\
  var f=document.getElementById('vpn-import-form');\n\
  f.style.display=f.style.display==='none'?'':'none';\n\
}\n\
\n\
async function vpnImport(btn){\n\
  var out=document.getElementById('vpn-import-result');\n\
  var name=document.getElementById('vpn-name').value.trim();\n\
  var config=document.getElementById('vpn-import-text').value.trim();\n\
  if(!name||!config){out.style.color='red';out.textContent='Заполните имя и конфиг';return;}\n\
  btn.disabled=true;out.style.color='';out.textContent='Импорт…';\n\
  try{\n\
    var r=await fetch('/api/vpn',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,config})});\n\
    var j={};try{j=await r.json();}catch(e){}\n\
    if(r.ok){out.style.color='green';out.textContent='Добавлен ✓';setTimeout(function(){location.reload();},700);}\n\
    else{out.style.color='red';out.textContent='Ошибка: '+(j.error||r.statusText);}\n\
  }catch(e){out.style.color='red';out.textContent='Сбой: '+e;}\n\
  btn.disabled=false;\n\
}\n\
\n\
async function vpnAct(url,btn){\n\
  var parts=url.split('/');var name=parts[parts.length-2];\n\
  var out=document.getElementById('vpn-result-'+name);\n\
  btn.disabled=true;\n\
  if(out){out.style.color='';out.textContent='…';}\n\
  try{\n\
    var r=await fetch(url,{method:'POST'});\n\
    var j={};try{j=await r.json();}catch(e){}\n\
    if(r.ok){if(out)out.textContent='';setTimeout(function(){location.reload();},600);}\n\
    else{if(out){out.style.color='red';out.textContent=j.error||r.statusText;}}\n\
  }catch(e){\n\
    if(out){out.style.color='red';out.textContent='Сбой: '+e;}\n\
  }\n\
  btn.disabled=false;\n\
}\n\
\n\
async function bypassSave(entries){\n\
  var out=document.getElementById('bypass-result');\n\
  try{\n\
    var r=await fetch('/api/vpn/bypass',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({entries:entries})});\n\
    if(r.ok){out.style.color='green';out.textContent='Сохранено ✓';setTimeout(function(){out.textContent='';},2000);}\n\
    else{var j={};try{j=await r.json();}catch(e){}out.style.color='red';out.textContent='Ошибка: '+(j.error||r.statusText);}\n\
  }catch(e){out.style.color='red';out.textContent='Сбой: '+e;}\n\
}\n\
\n\
function bypassAdd(){\n\
  var inp=document.getElementById('bypass-input');\n\
  var val=inp.value.trim();\n\
  if(!val)return;\n\
  if(_bypassEntries.indexOf(val)>=0){inp.value='';return;}\n\
  _bypassEntries.push(val);\n\
  inp.value='';\n\
  bypassSave(_bypassEntries);\n\
  var list=document.getElementById('bypass-list');\n\
  var empties=list.querySelectorAll('.empty');\n\
  empties.forEach(function(e){e.remove();});\n\
  var div=document.createElement('div');\n\
  div.style.cssText='display:flex;align-items:center;gap:.5rem;margin-bottom:.4rem';\n\
  div.innerHTML='<code style=\"flex:1;font-size:.85rem\">'+val+'</code>'\n\
    +'<button class=\"btn btn--ghost btn--sm\" onclick=\"bypassRemove(this,\\''+val+'\\')\" >✕</button>';\n\
  list.appendChild(div);\n\
}\n\
\n\
function bypassRemove(btn,entry){\n\
  _bypassEntries=_bypassEntries.filter(function(e){return e!==entry;});\n\
  btn.parentElement.remove();\n\
  bypassSave(_bypassEntries);\n\
}\n\
</script>\n";

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

    layout("Система", "System", "/system", &body)
}
