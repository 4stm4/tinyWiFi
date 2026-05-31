use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

use tinywifi_core::{
    leases::LeasesReport, service_restart, service_status, update_dhcp, update_wifi, DhcpConfig,
    DhcpSettings, DhcpUpdateError, HostapdConf, SystemStatus, WifiConfig, WifiError, WifiSettings,
};

use crate::state::AppState;

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
    Json(settings): Json<WifiSettings>,
) -> Result<Json<Value>, ApiError> {
    update_wifi(&st.config.paths.hostapd_conf, &settings).map_err(wifi_error)?;
    Ok(ok())
}

pub async fn dhcp_get(State(st): State<AppState>) -> ApiResult<DhcpConfig> {
    let conf = DhcpConfig::from_path(&st.config.paths.nanodhcp_conf)
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(conf))
}

pub async fn dhcp_post(
    State(st): State<AppState>,
    Json(settings): Json<DhcpSettings>,
) -> Result<Json<Value>, ApiError> {
    update_dhcp(&st.config.paths.nanodhcp_conf, &settings).map_err(dhcp_error)?;
    Ok(ok())
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
