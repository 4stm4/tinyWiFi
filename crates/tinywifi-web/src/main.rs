mod api;
mod assets;
mod auth;
mod pages;
mod ratelimit;
mod state;
mod tls;

#[cfg(test)]
mod tests;

use std::process::ExitCode;

use std::net::SocketAddr;
use std::time::Duration;

use axum::extract::{ConnectInfo, State};
use axum::http::{header, Request, Response, Uri};
use axum::middleware;
use axum::response::{IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::Router;
use tinywifi_core::config::{self, TinywifiConfig};
use tower_http::trace::TraceLayer;
use tracing::Span;

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

/// Middleware: rejects with 429 once an IP exceeds its request budget.
/// Applies to the whole app, on top of login's own brute-force ban — this
/// one is about spam/automation, not credential guessing specifically.
/// `ConnectInfo` is only present when served via
/// `into_make_service_with_connect_info` (absent in the test harness, which
/// drives the router directly via `tower::ServiceExt::oneshot`), so a
/// missing one skips the check rather than rejecting the request.
async fn rate_limit(
    axum::extract::State(st): axum::extract::State<AppState>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    request: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    if let Some(ConnectInfo(addr)) = connect_info {
        if ratelimit::is_rate_limited(&st.rate_limiter, addr.ip()) {
            tracing::warn!(ip = %addr.ip(), "rate limit exceeded");
            return (axum::http::StatusCode::TOO_MANY_REQUESTS, "too many requests").into_response();
        }
    }
    next.run(request).await
}

fn build_router(state: AppState) -> Router {
    // Public routes — no auth required.
    let public = Router::new()
        .route("/health", get(api::health))
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
        .layer(middleware::from_fn_with_state(state.clone(), rate_limit))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(request_span)
                .on_response(log_response),
        )
        .with_state(state)
}

/// One span per request, tagged with the client IP when available (only
/// present when served via `into_make_service_with_connect_info`).
fn request_span<B>(req: &Request<B>) -> Span {
    let ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());
    tracing::info_span!("http", method = %req.method(), path = %req.uri().path(), ip = tracing::field::debug(ip))
}

fn log_response<B>(response: &Response<B>, latency: Duration, _span: &Span) {
    tracing::info!(status = %response.status(), latency_ms = latency.as_millis(), "request completed");
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

/// Reads `RUST_LOG` (standard `tracing` convention); defaults to `info` so
/// admin actions and request audit logs show up without extra config.
fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

#[tokio::main]
async fn main() -> ExitCode {
    init_logging();

    auth::init();
    if let Err(e) = tls::init() {
        tracing::error!("failed to set up TLS certificate: {e}");
        return ExitCode::FAILURE;
    }

    let path = config_path();
    let config = match TinywifiConfig::from_path(&path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("failed to load config from {path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let https_listen = config.web.listen.clone();
    let http_listen = config.web.http_redirect_listen.clone();

    let https_addr: SocketAddr = match https_listen.parse() {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("invalid web.listen {https_listen:?}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let http_addr: SocketAddr = match http_listen.parse() {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("invalid web.http_redirect_listen {http_listen:?}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let rustls_config = match tls::rustls_config().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("failed to load TLS certificate: {e}");
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

    tracing::info!(
        version = tinywifi_core::VERSION,
        "listening on https://{https_addr} (http://{http_addr} redirects)"
    );

    let https_server = axum_server::bind_rustls(https_addr, rustls_config)
        .handle(handle.clone())
        .serve(app.into_make_service_with_connect_info::<SocketAddr>());
    let http_server = axum_server::bind(http_addr)
        .handle(handle)
        .serve(redirect_app.into_make_service());

    let (https_res, http_res) = tokio::join!(https_server, http_server);
    if let Err(e) = https_res {
        tracing::error!("https server error: {e}");
        return ExitCode::FAILURE;
    }
    if let Err(e) = http_res {
        tracing::error!("http redirect server error: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
