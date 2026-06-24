//! Session management and password hashing for the web UI.
//!
//! Single-admin model: one password stored as an argon2id PHC hash in
//! AUTH_FILE. Sessions are in-memory tokens with 24-hour TTL; they reset on
//! every server restart, which is fine for an embedded device.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::password_hash::SaltString;
use argon2::{Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier};

pub const SESSION_COOKIE: &str = "tw_sess";
pub const AUTH_FILE: &str = "/etc/tinywifi/auth";
/// Marker created on init, removed when the user changes the password.
const DEFAULT_MARKER: &str = "/etc/tinywifi/auth.default";
const DEFAULT_PASSWORD: &str = "admin";
const SESSION_TTL: Duration = Duration::from_secs(86400);

/// Brute-force protection: max failed attempts before IP is banned.
const MAX_ATTEMPTS: u32 = 10;
/// Window over which failed attempts are counted.
const ATTEMPT_WINDOW: Duration = Duration::from_secs(60);
/// How long a banned IP is locked out.
const BAN_DURATION: Duration = Duration::from_secs(300);

pub type Sessions = Arc<Mutex<HashMap<String, Instant>>>;

pub(crate) struct AttemptState {
    count: u32,
    window_start: Instant,
    banned_until: Option<Instant>,
}

/// Per-IP login attempt tracker. In-memory; resets on server restart.
pub type LoginAttempts = Arc<Mutex<HashMap<IpAddr, AttemptState>>>;

pub fn new_sessions() -> Sessions {
    Arc::new(Mutex::new(HashMap::new()))
}

pub fn new_login_attempts() -> LoginAttempts {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Returns true if this IP is currently banned.
pub fn is_banned(attempts: &LoginAttempts, ip: IpAddr) -> bool {
    let map = attempts.lock().unwrap();
    match map.get(&ip) {
        Some(s) => s.banned_until.map_or(false, |t| t > Instant::now()),
        None => false,
    }
}

/// Record a failed login attempt. Bans the IP after MAX_ATTEMPTS in the window.
pub fn record_failure(attempts: &LoginAttempts, ip: IpAddr) {
    let mut map = attempts.lock().unwrap();
    let now = Instant::now();
    let entry = map.entry(ip).or_insert(AttemptState {
        count: 0,
        window_start: now,
        banned_until: None,
    });
    // Reset window if it has expired.
    if now.duration_since(entry.window_start) >= ATTEMPT_WINDOW {
        entry.count = 0;
        entry.window_start = now;
    }
    entry.count += 1;
    if entry.count >= MAX_ATTEMPTS {
        entry.banned_until = Some(now + BAN_DURATION);
        entry.count = 0;
        entry.window_start = now;
    }
}

/// Clear the attempt counter for an IP after a successful login.
pub fn record_success(attempts: &LoginAttempts, ip: IpAddr) {
    attempts.lock().unwrap().remove(&ip);
}

/// Generate a random 32-byte hex token and add it to the session store.
pub fn session_create(sessions: &Sessions) -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    sessions
        .lock()
        .unwrap()
        .insert(token.clone(), Instant::now());
    token
}

pub fn session_valid(sessions: &Sessions, token: &str) -> bool {
    let mut map = sessions.lock().unwrap();
    match map.get(token) {
        Some(t) if t.elapsed() < SESSION_TTL => true,
        Some(_) => {
            map.remove(token);
            false
        }
        None => false,
    }
}

pub fn session_remove(sessions: &Sessions, token: &str) {
    sessions.lock().unwrap().remove(token);
}

// Lightweight params for embedded hardware (Pi-class).
// Default argon2 uses m=65536 KiB (64 MB) which stalls QEMU guests.
// 8 MB / 2 iterations is still strong for a local-only admin interface.
fn argon2_params() -> Params {
    Params::new(8192, 2, 1, None).expect("valid argon2 params")
}

fn argon2() -> Argon2<'static> {
    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, argon2_params())
}

pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    argon2()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    // Verification uses the params embedded in the PHC string.
    // Use default() so it can handle any stored params (including old m=65536).
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// After a successful login, re-hash with lightweight params if the stored
/// hash was created with heavy defaults (m_cost > our 8 MiB target).
pub fn maybe_upgrade_hash(password: &str) {
    let Some(hash) = read_hash() else { return };
    let Ok(parsed) = PasswordHash::new(&hash) else { return };
    let heavy = Params::try_from(&parsed)
        .map(|p| p.m_cost() > 8192)
        .unwrap_or(false);
    if heavy {
        if let Ok(new_hash) = hash_password(password) {
            let _ = write_hash(&new_hash);
        }
    }
}

pub fn read_hash() -> Option<String> {
    std::fs::read_to_string(AUTH_FILE)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn write_hash(hash: &str) -> std::io::Result<()> {
    std::fs::write(AUTH_FILE, format!("{hash}\n"))
}

/// True when the device is still running the default "admin" password.
pub fn is_default_password() -> bool {
    std::path::Path::new(DEFAULT_MARKER).exists()
}

fn clear_default_marker() {
    let _ = std::fs::remove_file(DEFAULT_MARKER);
}

/// Called at server startup: creates AUTH_FILE with the default password hash
/// if the file does not yet exist, and leaves a marker so the UI can warn.
pub fn init() {
    if !std::path::Path::new(AUTH_FILE).exists() {
        if let Ok(hash) = hash_password(DEFAULT_PASSWORD) {
            if write_hash(&hash).is_ok() {
                let _ = std::fs::write(DEFAULT_MARKER, "");
            }
        }
    }
}

/// Called after a successful password change; removes the default-password marker.
pub fn on_password_changed() {
    clear_default_marker();
}

/// Extract the session token from a `Cookie` request header.
pub fn extract_session_cookie(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            s.split(';').find_map(|part| {
                part.trim()
                    .strip_prefix(&format!("{SESSION_COOKIE}="))
                    .map(str::to_string)
            })
        })
}
