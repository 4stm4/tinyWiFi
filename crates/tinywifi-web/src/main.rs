mod api;
mod assets;
mod auth;
mod pages;
mod state;
mod tls;

#[cfg(test)]
mod tests;

use std::process::ExitCode;

use std::net::SocketAddr;
use std::time::Duration;

use axum::extract::State;
use axum::http::{header, Uri};
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
        .route("/dns", get(pages::dns))
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
        .route("/api/dhcp/static", get(api::static_leases_get).post(api::static_leases_post))
        .route("/api/dhcp/static/:mac", axum::routing::delete(api::static_leases_delete))
        .route("/api/acl", get(api::acl_get).post(api::acl_post))
        .route("/api/acl/block", post(api::acl_block))
        .route("/api/acl/unblock", post(api::acl_unblock))
        .route("/api/dns", get(api::dns_get).post(api::dns_settings_post))
        .route("/api/dns/records", post(api::dns_records_post).delete(api::dns_records_delete))
        .route("/api/services", get(api::services))
        .route(
            "/api/services/:name/restart",
            post(api::service_restart_handler),
        )
        .route("/api/system/reboot", post(api::reboot))
        .route("/api/auth/password", post(api::change_password))
        .route("/monitor", get(pages::monitor))
        .route("/api/monitor", get(api::monitor_get).post(api::monitor_post))
        .route("/api/monitor/detect", get(api::monitor_detect))
        .route("/adblock", get(pages::adblock))
        .route("/api/adblock", get(api::adblock_get).post(api::adblock_post))
        .route("/api/adblock/update", post(api::adblock_update))
        .route("/api/adblock/custom", post(api::adblock_custom_add).delete(api::adblock_custom_remove))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_auth,
        ));

    Router::new()
        .merge(public)
        .merge(protected)
        .with_state(state)
}

/// Redirects every plain-HTTP request to the same path on HTTPS.
async fn redirect_to_https(State(https_port): State<u16>, headers: axum::http::HeaderMap, uri: Uri) -> impl IntoResponse {
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h))
        .unwrap_or("tinywifi.local");
    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    Redirect::permanent(&format!("https://{host}:{https_port}{path}"))
}

#[tokio::main]
async fn main() -> ExitCode {
    auth::init();
    if let Err(e) = tls::init() {
        eprintln!("tinywifi-web: failed to set up TLS certificate: {e}");
        return ExitCode::FAILURE;
    }

    let path = config_path();
    let config = match TinywifiConfig::from_path(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("tinywifi-web: failed to load config from {path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let https_listen = config.web.listen.clone();
    let http_listen = config.web.http_redirect_listen.clone();

    let https_addr: SocketAddr = match https_listen.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("tinywifi-web: invalid web.listen {https_listen:?}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let http_addr: SocketAddr = match http_listen.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("tinywifi-web: invalid web.http_redirect_listen {http_listen:?}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let rustls_config = match tls::rustls_config().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("tinywifi-web: failed to load TLS certificate: {e}");
            return ExitCode::FAILURE;
        }
    };

    let app = build_router(AppState::new(config));
    let redirect_app = Router::new()
        .fallback(redirect_to_https)
        .with_state(https_addr.port());

    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        shutdown_handle.graceful_shutdown(Some(Duration::from_secs(5)));
    });

    println!(
        "tinywifi-web {} listening on https://{https_addr} (http://{http_addr} redirects)",
        tinywifi_core::VERSION
    );

    let https_server = axum_server::bind_rustls(https_addr, rustls_config)
        .handle(handle.clone())
        .serve(app.into_make_service_with_connect_info::<SocketAddr>());
    let http_server = axum_server::bind(http_addr)
        .handle(handle)
        .serve(redirect_app.into_make_service());

    let (https_res, http_res) = tokio::join!(https_server, http_server);
    if let Err(e) = https_res {
        eprintln!("tinywifi-web: https server error: {e}");
        return ExitCode::FAILURE;
    }
    if let Err(e) = http_res {
        eprintln!("tinywifi-web: http redirect server error: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
