mod api;
mod assets;
mod auth;
mod pages;
mod state;

#[cfg(test)]
mod tests;

use std::process::ExitCode;

use axum::middleware;
use axum::response::{IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::Router;
use tinywifi_core::config::{self, TinywifiConfig};

use crate::state::AppState;

fn config_path() -> String {
    if let Ok(p) = std::env::var("TINYWIFI_CONFIG") {
        return p;
    }
    if std::path::Path::new(config::DEFAULT_PATH).exists() {
        return config::DEFAULT_PATH.to_string();
    }
    "configs/tinywifi.toml".to_string()
}

/// Middleware: redirect to /login unless the request carries a valid session.
async fn require_auth(
    axum::extract::State(st): axum::extract::State<AppState>,
    request: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    if let Some(token) = auth::extract_session_cookie(request.headers()) {
        if auth::session_valid(&st.sessions, &token) {
            return next.run(request).await;
        }
    }
    Redirect::to("/login").into_response()
}

fn build_router(state: AppState) -> Router {
    // Public routes — no auth required.
    let public = Router::new()
        .route("/login", get(pages::login).post(api::login_post))
        .route("/logout", post(api::logout_post))
        .route("/style.css", get(assets::style_css))
        .route("/fonts/:name", get(assets::font));

    // Protected routes — all require a valid session cookie.
    let protected = Router::new()
        .route("/", get(pages::index))
        .route("/dashboard", get(pages::dashboard))
        .route("/wifi", get(pages::wifi))
        .route("/dhcp", get(pages::dhcp))
        .route("/leases", get(pages::leases))
        .route("/system", get(pages::system))
        .route("/wan", get(pages::wan))
        .route("/api/wan", get(api::wan_get).post(api::wan_post))
        .route("/vpn", get(pages::vpn))
        .route("/api/vpn", get(api::vpn_list).post(api::vpn_import))
        .route("/api/vpn/:name/up", post(api::vpn_up))
        .route("/api/vpn/:name/down", post(api::vpn_down))
        .route("/api/vpn/bypass", get(api::vpn_bypass_get).post(api::vpn_bypass_post))
        .route("/api/status", get(api::status))
        .route("/api/traffic", get(api::traffic))
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
        .route("/api/auth/password", post(api::change_password))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_auth,
        ));

    Router::new()
        .merge(public)
        .merge(protected)
        .with_state(state)
}

#[tokio::main]
async fn main() -> ExitCode {
    auth::init();

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
