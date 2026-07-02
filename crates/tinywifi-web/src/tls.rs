//! TLS certificate management for the web UI.
//!
//! Single self-signed certificate, generated on first boot and reused
//! afterwards. Mirrors auth.rs's init-on-first-run pattern: a marker file
//! lets the UI warn that the certificate isn't CA-signed.

use std::path::Path;

pub const CERT_FILE: &str = "/etc/tinywifi/tls/cert.pem";
pub const KEY_FILE: &str = "/etc/tinywifi/tls/key.pem";
/// Marker left alongside the cert so the UI can warn it's self-signed.
const SELF_SIGNED_MARKER: &str = "/etc/tinywifi/tls/self-signed";

/// Ensures a certificate/key pair exists at CERT_FILE/KEY_FILE, generating a
/// self-signed one (10-year validity) if missing, and installs `ring` as the
/// process-wide rustls crypto provider. Call once at startup, before
/// building the rustls config.
pub fn init() -> std::io::Result<()> {
    // axum-server's "tls-rustls-no-provider" feature (chosen to avoid the
    // aws-lc-rs default, which needs cmake/a C++ toolchain that isn't
    // available on the build host) requires the caller to install a
    // provider explicitly; ignore the error if one is already installed.
    let _ = rustls::crypto::ring::default_provider().install_default();
    init_at(CERT_FILE, KEY_FILE, SELF_SIGNED_MARKER)
}

fn init_at(cert_path: &str, key_path: &str, marker_path: &str) -> std::io::Result<()> {
    if Path::new(cert_path).exists() && Path::new(key_path).exists() {
        return Ok(());
    }
    let names = vec!["tinywifi.local".to_string(), "localhost".to_string()];
    let generated = rcgen::generate_simple_self_signed(names)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    if let Some(dir) = Path::new(cert_path).parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(cert_path, generated.cert.pem())?;
    std::fs::write(key_path, generated.signing_key.serialize_pem())?;
    std::fs::write(marker_path, "")?;
    Ok(())
}

/// True when the current certificate is self-signed (not CA-issued), so the
/// UI can show a "not verified" notice.
pub fn is_self_signed() -> bool {
    Path::new(SELF_SIGNED_MARKER).exists()
}

/// Loads the rustls server config from CERT_FILE/KEY_FILE. `init()` must
/// have run first so the files exist.
pub async fn rustls_config() -> std::io::Result<axum_server::tls_rustls::RustlsConfig> {
    axum_server::tls_rustls::RustlsConfig::from_pem_file(CERT_FILE, KEY_FILE).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_cert_and_key_on_first_run() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        let marker = dir.path().join("self-signed");
        init_at(
            cert.to_str().unwrap(),
            key.to_str().unwrap(),
            marker.to_str().unwrap(),
        )
        .unwrap();
        assert!(cert.exists());
        assert!(key.exists());
        assert!(marker.exists());
    }

    #[test]
    fn is_idempotent_and_does_not_regenerate() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        let marker = dir.path().join("self-signed");
        let paths = (cert.to_str().unwrap(), key.to_str().unwrap(), marker.to_str().unwrap());
        init_at(paths.0, paths.1, paths.2).unwrap();
        let first = std::fs::read_to_string(&cert).unwrap();
        init_at(paths.0, paths.1, paths.2).unwrap();
        let second = std::fs::read_to_string(&cert).unwrap();
        assert_eq!(first, second);
    }
}
