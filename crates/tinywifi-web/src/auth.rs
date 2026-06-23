//! Session management and password hashing for the web UI.
//!
//! Single-admin model: one password stored as an argon2id PHC hash in
//! AUTH_FILE. Sessions are in-memory tokens with 24-hour TTL; they reset on
//! every server restart, which is fine for an embedded device.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};

pub const SESSION_COOKIE: &str = "tw_sess";
pub const AUTH_FILE: &str = "/etc/tinywifi/auth";
/// Marker created on init, removed when the user changes the password.
const DEFAULT_MARKER: &str = "/etc/tinywifi/auth.default";
const DEFAULT_PASSWORD: &str = "admin";
const SESSION_TTL: Duration = Duration::from_secs(86400);

pub type Sessions = Arc<Mutex<HashMap<String, Instant>>>;

pub fn new_sessions() -> Sessions {
    Arc::new(Mutex::new(HashMap::new()))
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

pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .ok()
        .map(|h| {
            Argon2::default()
                .verify_password(password.as_bytes(), &h)
                .is_ok()
        })
        .unwrap_or(false)
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
