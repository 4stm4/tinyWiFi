use std::path::PathBuf;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use tinywifi_core::{
    apply_wan, discard_backup, import_tunnel, leases::LeasesReport, load_bypass_list, revert,
    save_bypass_list, scan_tunnels, service_restart, service_status, stage_dhcp, stage_wifi,
    tunnel_down, tunnel_up, update_dhcp, update_wifi, wan_candidates, wan_status, AutoRevert,
    AwgTunnel, AwgTunnelStatus, DhcpConfig, DhcpSettings, DhcpUpdateError, HostapdConf,
    SystemStatus, WanConfig, WanStatus, WifiConfig, WifiError, WifiSettings, AWG_CONF_DIR,
};

use crate::state::AppState;

/// Bounds on the confirm window: long enough to reconnect to a new Wi-Fi,
/// short enough that a lockout self-heals quickly.
const MIN_HOLD_SECS: u64 = 5;
const MAX_HOLD_SECS: u64 = 600;

/// Optional `?hold=<secs>` on an update: apply the change but auto-revert it
/// after `secs` unless a matching `/confirm` arrives first.
#[derive(Deserialize)]
pub struct HoldParams {
    pub hold: Option<u64>,
}

/// A JSON error response with an HTTP status.
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        ApiError {
            status,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

type ApiResult<T> = Result<Json<T>, ApiError>;

fn ok() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

fn pending(secs: u64) -> Json<Value> {
    Json(json!({ "status": "pending", "confirm_within": secs }))
}

/// Arm (or replace) the auto-revert for `key`. After `secs` the staged config
/// is restored and the service restarted, unless `/confirm` cancels it first.
fn arm_revert(st: &AppState, key: &'static str, path: PathBuf, service: String, secs: u64) {
    let guard = AutoRevert::arm(Duration::from_secs(secs), move || {
        revert(&path, &service);
        discard_backup(&path);
    });
    // Dropping any previous guard for this key cancels its timer.
    st.pending.lock().unwrap().insert(key, guard);
}

/// Confirm a staged change: cancel the timer and discard the retained backup.
/// Reports whether a pending change existed and whether it was confirmed in
/// time or had already auto-reverted.
fn confirm_pending(st: &AppState, key: &'static str, path: &std::path::Path) -> Json<Value> {
    let guard = st.pending.lock().unwrap().remove(key);
    match guard {
        Some(g) if g.confirm() => {
            discard_backup(path);
            Json(json!({ "status": "confirmed" }))
        }
        Some(_) => Json(json!({ "status": "already_reverted" })),
        None => Json(json!({ "status": "no_pending" })),
    }
}

pub async fn status(State(st): State<AppState>) -> Json<SystemStatus> {
    Json(SystemStatus::collect(
        &st.ap_interface(),
        &st.config.paths.leases_file,
    ))
}

pub async fn wifi_get(State(st): State<AppState>) -> ApiResult<WifiConfig> {
    let conf = HostapdConf::from_path(&st.config.paths.hostapd_conf)
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(conf.wifi_config()))
}

pub async fn wifi_post(
    State(st): State<AppState>,
    Query(q): Query<HoldParams>,
    Json(settings): Json<WifiSettings>,
) -> Result<Json<Value>, ApiError> {
    let path = st.config.paths.hostapd_conf.clone();
    match q.hold {
        Some(secs) => {
            stage_wifi(&path, &settings).map_err(wifi_error)?;
            let secs = secs.clamp(MIN_HOLD_SECS, MAX_HOLD_SECS);
            arm_revert(&st, "wifi", path, st.config.services.hostapd.clone(), secs);
            Ok(pending(secs))
        }
        None => {
            update_wifi(&path, &settings).map_err(wifi_error)?;
            Ok(ok())
        }
    }
}

pub async fn wifi_confirm(State(st): State<AppState>) -> Json<Value> {
    confirm_pending(&st, "wifi", &st.config.paths.hostapd_conf)
}

pub async fn dhcp_get(State(st): State<AppState>) -> ApiResult<DhcpConfig> {
    let conf = DhcpConfig::from_path(&st.config.paths.nanodhcp_conf)
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(conf))
}

pub async fn dhcp_post(
    State(st): State<AppState>,
    Query(q): Query<HoldParams>,
    Json(settings): Json<DhcpSettings>,
) -> Result<Json<Value>, ApiError> {
    let path = st.config.paths.nanodhcp_conf.clone();
    match q.hold {
        Some(secs) => {
            stage_dhcp(&path, &settings).map_err(dhcp_error)?;
            let secs = secs.clamp(MIN_HOLD_SECS, MAX_HOLD_SECS);
            arm_revert(&st, "dhcp", path, st.config.services.nanodhcp.clone(), secs);
            Ok(pending(secs))
        }
        None => {
            update_dhcp(&path, &settings).map_err(dhcp_error)?;
            Ok(ok())
        }
    }
}

pub async fn dhcp_confirm(State(st): State<AppState>) -> Json<Value> {
    confirm_pending(&st, "dhcp", &st.config.paths.nanodhcp_conf)
}

pub async fn leases(State(st): State<AppState>) -> Json<LeasesReport> {
    Json(LeasesReport::read(&st.config.paths.leases_file))
}

pub async fn services(State(st): State<AppState>) -> Json<Value> {
    let s = &st.config.services;
    let mut map = serde_json::Map::new();
    for name in [&s.hostapd, &s.nanodhcp, &s.web, &s.display] {
        map.insert(name.clone(), json!(service_status(name)));
    }
    Json(Value::Object(map))
}

pub async fn service_restart_handler(
    State(st): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let s = &st.config.services;
    let known = [&s.hostapd, &s.nanodhcp, &s.web, &s.display];
    if !known.iter().any(|k| **k == name) {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            format!("unknown service '{name}'"),
        ));
    }
    service_restart(&name)
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(ok())
}

pub async fn reboot() -> Result<Json<Value>, ApiError> {
    let out = std::process::Command::new("systemctl")
        .arg("reboot")
        .output()
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if out.status.success() {
        Ok(ok())
    } else {
        Err(ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ))
    }
}

#[derive(serde::Deserialize)]
pub struct VpnImportBody {
    /// Tunnel name (e.g. "awg0"). Written as `<name>.conf`.
    pub name: String,
    /// Raw `[Interface]...` text or full `vpn://...` URI.
    pub config: String,
}

pub async fn vpn_import(
    Json(body): Json<VpnImportBody>,
) -> Result<Json<Value>, ApiError> {
    let name = body.name.trim();
    if name.is_empty() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "name is required"));
    }
    import_tunnel(&body.config, name, AWG_CONF_DIR)
        .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok(ok())
}

// ── WAN ──────────────────────────────────────────────────────────────────────

#[derive(serde::Serialize)]
pub struct WanGetResponse {
    pub candidates: Vec<String>,
    pub config: Option<WanConfig>,
    pub status: Option<WanStatus>,
}

pub async fn wan_get(_st: State<AppState>) -> Json<WanGetResponse> {
    let candidates = wan_candidates();
    let config = WanConfig::load();
    let status = config
        .as_ref()
        .map(|c| wan_status(&c.interface))
        .or_else(|| candidates.first().map(|i| wan_status(i)));
    Json(WanGetResponse { candidates, config, status })
}

pub async fn wan_post(Json(body): Json<WanConfig>) -> Result<Json<Value>, ApiError> {
    body.save()
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    apply_wan(&body)
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(ok())
}

pub async fn vpn_list(_st: State<AppState>) -> Json<Vec<AwgTunnel>> {
    Json(scan_tunnels(AWG_CONF_DIR))
}

pub async fn vpn_up(Path(name): Path<String>) -> Result<Json<Value>, ApiError> {
    let tunnels = scan_tunnels(AWG_CONF_DIR);
    let tunnel = find_tunnel(&tunnels, &name)?;
    tunnel_up(tunnel).map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(ok())
}

pub async fn vpn_down(Path(name): Path<String>) -> Result<Json<Value>, ApiError> {
    let tunnels = scan_tunnels(AWG_CONF_DIR);
    let tunnel = find_tunnel(&tunnels, &name)?;
    if tunnel.status != AwgTunnelStatus::Up {
        return Err(ApiError::new(StatusCode::CONFLICT, format!("tunnel '{name}' is not up")));
    }
    tunnel_down(&name).map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(ok())
}

fn find_tunnel<'a>(tunnels: &'a [AwgTunnel], name: &str) -> Result<&'a AwgTunnel, ApiError> {
    tunnels
        .iter()
        .find(|t| t.name == name)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, format!("tunnel '{name}' not found")))
}

// ── VPN bypass list ───────────────────────────────────────────────────────────

pub async fn vpn_bypass_get() -> Json<Vec<String>> {
    Json(load_bypass_list())
}

#[derive(serde::Deserialize)]
pub struct BypassBody {
    pub entries: Vec<String>,
}

pub async fn vpn_bypass_post(Json(body): Json<BypassBody>) -> Result<Json<Value>, ApiError> {
    save_bypass_list(&body.entries)
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(ok())
}

fn wifi_error(e: WifiError) -> ApiError {
    let status = match e {
        WifiError::Validation(_) => StatusCode::BAD_REQUEST,
        WifiError::NotFound(_) => StatusCode::NOT_FOUND,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    ApiError::new(status, e.to_string())
}

fn dhcp_error(e: DhcpUpdateError) -> ApiError {
    let status = match e {
        DhcpUpdateError::Validation(_) => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    ApiError::new(status, e.to_string())
}

// ── ACL ───────────────────────────────────────────────────────────────────────

use tinywifi_core::{AclMode, AclState};

pub async fn acl_get(State(st): State<AppState>) -> Json<AclState> {
    Json(AclState::load())
}

#[derive(serde::Deserialize)]
pub struct AclBody {
    pub mode: AclMode,
    pub macs: Vec<String>,
}

pub async fn acl_post(
    State(st): State<AppState>,
    Json(body): Json<AclBody>,
) -> Result<Json<Value>, ApiError> {
    let mut state = AclState { mode: body.mode, macs: body.macs };
    state.macs = state.macs.iter().map(|m| AclState::normalize_mac(m)).collect();
    state.save().map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    state
        .apply(&st.config.paths.hostapd_conf, &st.config.services.hostapd)
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(ok())
}

#[derive(serde::Deserialize)]
pub struct AclMacBody {
    pub mac: String,
}

/// Add a MAC to the blacklist (quick block from leases page).
pub async fn acl_block(
    State(st): State<AppState>,
    Json(body): Json<AclMacBody>,
) -> Result<Json<Value>, ApiError> {
    let mut state = AclState::load();
    if state.mode == AclMode::Disabled {
        state.mode = AclMode::Blacklist;
    }
    state.add(&body.mac);
    state.save().map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    state
        .apply(&st.config.paths.hostapd_conf, &st.config.services.hostapd)
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(ok())
}

/// Remove a MAC from the list (unblock).
pub async fn acl_unblock(
    State(st): State<AppState>,
    Json(body): Json<AclMacBody>,
) -> Result<Json<Value>, ApiError> {
    let mut state = AclState::load();
    state.remove(&body.mac);
    state.save().map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    state
        .apply(&st.config.paths.hostapd_conf, &st.config.services.hostapd)
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(ok())
}
