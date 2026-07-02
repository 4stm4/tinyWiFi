//! Integration tests for the HTTP layer. They drive the real [`build_router`]
//! through `tower`'s `oneshot` (no sockets) against temporary config files, so
//! the handlers, extractors and core readers are exercised end to end.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use tinywifi_core::config::{
    DisplayConfig, Paths, Services, TinywifiConfig, WebConfig,
};

use crate::build_router;
use crate::state::AppState;
use crate::auth;

const HOSTAPD: &str = "\
interface=wlan0
driver=nl80211
ssid=TestNet
hw_mode=g
channel=6
country_code=US
wpa=2
wpa_passphrase=secret12
";

const NANODHCP: &str = "\
interface=wlan0
server_ip=192.168.44.1
subnet=192.168.44.0/24
pool_start=192.168.44.100
pool_end=192.168.44.200
router=192.168.44.1
dns=192.168.44.1,1.1.1.1
lease_time=86400
lease_file=/var/lib/nanodhcp/leases
";

/// A temp dir holding hostapd/nanodhcp configs plus the matching `AppState`.
/// The dir is kept alive for as long as the returned guard lives. Carries a
/// pre-authenticated session token since every `/api/*` and page route is
/// behind `require_auth`.
struct Fixture {
    _dir: tempfile::TempDir,
    state: AppState,
    session: String,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let hostapd = dir.path().join("hostapd.conf");
    let nanodhcp = dir.path().join("nanodhcp.conf");
    std::fs::write(&hostapd, HOSTAPD).unwrap();
    std::fs::write(&nanodhcp, NANODHCP).unwrap();

    let config = TinywifiConfig {
        web: WebConfig {
            listen: "127.0.0.1:0".to_string(),
            http_redirect_listen: "127.0.0.1:0".to_string(),
        },
        display: DisplayConfig { refresh_secs: 5 },
        paths: Paths {
            hostapd_conf: hostapd,
            nanodhcp_conf: nanodhcp,
            // Deliberately absent so nanodns/leases degrade to "empty".
            nanodns_conf: dir.path().join("nanodns-absent"),
            leases_file: dir.path().join("leases-absent"),
        },
        services: Services {
            hostapd: "hostapd".to_string(),
            nanodhcp: "nanodhcp".to_string(),
            nanodns: "nanodns".to_string(),
            web: "tinywifi-web".to_string(),
            display: "tinywifi-display".to_string(),
        },
    };

    let state = AppState::new(config);
    let session = auth::session_create(&state.sessions);

    Fixture {
        _dir: dir,
        state,
        session,
    }
}

async fn send(f: &Fixture, method: &str, uri: &str, body: Option<&str>) -> (StatusCode, String) {
    let router = build_router(f.state.clone());
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", format!("{}={}", auth::SESSION_COOKIE, f.session));
    let req = match body {
        Some(b) => builder
            .header("content-type", "application/json")
            .body(Body::from(b.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

#[tokio::test]
async fn status_endpoint_returns_shape() {
    let f = fixture();
    let (status, body) = send(&f, "GET", "/api/status", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("\"hostapd\""), "body: {body}");
    assert!(body.contains("\"wlan0\""), "body: {body}");
}

#[tokio::test]
async fn wifi_get_reads_real_config() {
    let f = fixture();
    let (status, body) = send(&f, "GET", "/api/wifi", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("\"ssid\":\"TestNet\""), "body: {body}");
    assert!(body.contains("\"channel\":6"), "body: {body}");
}

#[tokio::test]
async fn dhcp_get_parses_key_value_config() {
    let f = fixture();
    let (status, body) = send(&f, "GET", "/api/dhcp", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("\"range_start\":\"192.168.44.100\""), "body: {body}");
    assert!(body.contains("\"gateway\":\"192.168.44.1\""), "body: {body}");
}

#[tokio::test]
async fn leases_degrade_to_empty_when_file_absent() {
    let f = fixture();
    let (status, body) = send(&f, "GET", "/api/leases", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("\"state\":\"empty\""), "body: {body}");
}

#[tokio::test]
async fn services_lists_all_four() {
    let f = fixture();
    let (status, body) = send(&f, "GET", "/api/services", None).await;
    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    let obj = json.as_object().unwrap();
    assert_eq!(obj.len(), 4, "body: {body}");
    assert!(obj.contains_key("hostapd"));
    assert!(obj.contains_key("tinywifi-display"));
}

#[tokio::test]
async fn dashboard_renders_html_with_ssid() {
    let f = fixture();
    let (status, body) = send(&f, "GET", "/dashboard", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("<title>TinyWifi — Dashboard</title>"), "body head: {}", &body[..body.len().min(200)]);
    assert!(body.contains("TestNet"), "expected SSID in dashboard");
}

#[tokio::test]
async fn index_redirects_to_dashboard() {
    let f = fixture();
    let (status, _) = send(&f, "GET", "/", None).await;
    assert!(
        status == StatusCode::SEE_OTHER || status.is_redirection(),
        "status: {status}"
    );
}

#[tokio::test]
async fn wifi_confirm_with_nothing_pending() {
    let f = fixture();
    let (status, body) = send(&f, "POST", "/api/wifi/confirm", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("\"no_pending\""), "body: {body}");
}

#[tokio::test]
async fn wifi_post_invalid_settings_is_rejected() {
    let f = fixture();
    // Empty SSID and a too-short password fail validation before any disk or
    // service interaction, so this must be a clean 400.
    let bad = r#"{"ssid":"","passphrase":"short","country_code":"US","channel":6}"#;
    let (status, body) = send(&f, "POST", "/api/wifi", Some(bad)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
}

#[tokio::test]
async fn unknown_route_is_404() {
    let f = fixture();
    let (status, _) = send(&f, "GET", "/api/nope", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
