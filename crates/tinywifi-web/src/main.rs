mod api;
mod assets;
mod pages;
mod state;

#[cfg(test)]
mod tests;

use std::process::ExitCode;

use axum::routing::{get, post};
use axum::Router;
use tinywifi_core::config::{self, TinywifiConfig};

use crate::state::AppState;

/// Resolve the config path: `$TINYWIFI_CONFIG`, else the on-device default,
/// else the in-repo copy for local development.
fn config_path() -> String {
    if let Ok(p) = std::env::var("TINYWIFI_CONFIG") {
        return p;
    }
    if std::path::Path::new(config::DEFAULT_PATH).exists() {
        return config::DEFAULT_PATH.to_string();
    }
    "configs/tinywifi.toml".to_string()
}

fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(pages::index))
        .route("/style.css", get(assets::style_css))
        .route("/fonts/:name", get(assets::font))
        .route("/dashboard", get(pages::dashboard))
        .route("/wifi", get(pages::wifi))
        .route("/dhcp", get(pages::dhcp))
        .route("/leases", get(pages::leases))
        .route("/system", get(pages::system))
        .route("/vpn", get(pages::vpn))
        .route("/api/vpn", get(api::vpn_list).post(api::vpn_import))
        .route("/api/vpn/:name/up", post(api::vpn_up))
        .route("/api/vpn/:name/down", post(api::vpn_down))
        .route("/api/status", get(api::status))
        .route("/api/wifi", get(api::wifi_get).post(api::wifi_post))
        .route("/api/wifi/confirm", post(api::wifi_confirm))
        .route("/api/dhcp", get(api::dhcp_get).post(api::dhcp_post))
        .route("/api/dhcp/confirm", post(api::dhcp_confirm))
        .route("/api/leases", get(api::leases))
        .route("/api/services", get(api::services))
        .route(
            "/api/services/:name/restart",
            post(api::service_restart_handler),
        )
        .route("/api/system/reboot", post(api::reboot))
        .with_state(state)
}

#[tokio::main]
async fn main() -> ExitCode {
    let path = config_path();
    let config = match TinywifiConfig::from_path(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("tinywifi-web: failed to load config from {path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let listen = config.web.listen.clone();
    let app = build_router(AppState::new(config));

    let listener = match tokio::net::TcpListener::bind(&listen).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("tinywifi-web: failed to bind {listen}: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!("tinywifi-web {} listening on {listen}", tinywifi_core::VERSION);
    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        eprintln!("tinywifi-web: server error: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
