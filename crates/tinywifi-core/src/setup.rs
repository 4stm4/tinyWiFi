//! First-boot admin password: a random secret generated once by
//! `tinywifi-web` and shown on-screen by `tinywifi-display` until the admin
//! changes it. Kept here (rather than in `tinywifi-web`) since both crates
//! need to agree on the file path without depending on each other.

use rand::Rng;

/// Plaintext of the generated password, readable by the display daemon.
/// Removed once the admin sets their own password.
pub const INITIAL_PASSWORD_FILE: &str = "/etc/tinywifi/auth.initial-password";

/// Excludes visually ambiguous characters (0/O, 1/l/I) so it's easy to
/// transcribe from a small e-paper screen.
const CHARSET: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz";
const LENGTH: usize = 10;

/// Generate a random password for first boot.
pub fn generate_initial_password() -> String {
    let mut rng = rand::thread_rng();
    (0..LENGTH)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

/// Persist the plaintext so the display daemon can show it.
pub fn write_initial_password(password: &str) -> std::io::Result<()> {
    std::fs::write(INITIAL_PASSWORD_FILE, password)
}

/// Read the pending initial password, if the admin hasn't changed it yet.
pub fn read_initial_password() -> Option<String> {
    std::fs::read_to_string(INITIAL_PASSWORD_FILE)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Called once the admin sets their own password: the plaintext must not
/// linger on disk any longer than necessary.
pub fn clear_initial_password() {
    let _ = std::fs::remove_file(INITIAL_PASSWORD_FILE);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_password_has_expected_length_and_charset() {
        let pw = generate_initial_password();
        assert_eq!(pw.len(), LENGTH);
        assert!(pw.bytes().all(|b| CHARSET.contains(&b)));
    }

    #[test]
    fn two_generated_passwords_differ() {
        // Not a strict guarantee, but a collision here would indicate a
        // broken RNG rather than bad luck (56^10 possibilities).
        assert_ne!(generate_initial_password(), generate_initial_password());
    }
}
