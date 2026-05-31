//! Filesystem availability checks. Always run these before reading or
//! writing a config so callers can degrade gracefully instead of panicking.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

/// True if the path exists and is a regular file.
pub fn file_exists(path: impl AsRef<Path>) -> bool {
    path.as_ref().is_file()
}

/// The `.bak` sibling path used for backups (e.g. `foo.conf` -> `foo.conf.bak`).
pub fn backup_path(path: impl AsRef<Path>) -> PathBuf {
    let mut name = OsString::from(path.as_ref().as_os_str());
    name.push(".bak");
    PathBuf::from(name)
}

/// Copy `path` to its `.bak` sibling. Returns the backup path.
pub fn backup(path: impl AsRef<Path>) -> std::io::Result<PathBuf> {
    let bak = backup_path(&path);
    fs::copy(&path, &bak)?;
    Ok(bak)
}

/// Restore `path` from its `.bak` sibling.
pub fn restore_backup(path: impl AsRef<Path>) -> std::io::Result<()> {
    let bak = backup_path(&path);
    fs::copy(&bak, &path)?;
    Ok(())
}

/// True if the file can be opened for reading right now.
pub fn file_readable(path: impl AsRef<Path>) -> bool {
    fs::File::open(path).is_ok()
}

/// True if the existing file can be opened for writing. Does not create the
/// file and does not truncate it, so it is safe to call as a probe.
pub fn file_writable(path: impl AsRef<Path>) -> bool {
    fs::OpenOptions::new().write(true).open(path).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_path(tag: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("tinywifi_{tag}_{nanos}"))
    }

    #[test]
    fn existing_file_is_readable_and_writable() {
        let p = tmp_path("rw");
        let mut f = fs::File::create(&p).unwrap();
        writeln!(f, "hello").unwrap();
        drop(f);

        assert!(file_exists(&p));
        assert!(file_readable(&p));
        assert!(file_writable(&p));

        fs::remove_file(&p).ok();
    }

    #[test]
    fn missing_file_fails_all_checks() {
        let p = tmp_path("missing");
        assert!(!file_exists(&p));
        assert!(!file_readable(&p));
        assert!(!file_writable(&p));
    }

    #[test]
    fn backup_and_restore_round_trip() {
        let p = tmp_path("bak");
        fs::write(&p, "original").unwrap();
        let bak = backup(&p).unwrap();
        assert_eq!(bak, backup_path(&p));
        assert!(file_exists(&bak));

        fs::write(&p, "changed").unwrap();
        restore_backup(&p).unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "original");

        fs::remove_file(&p).ok();
        fs::remove_file(&bak).ok();
    }

    #[cfg(unix)]
    #[test]
    fn readonly_file_is_not_writable() {
        use std::os::unix::fs::PermissionsExt;
        let p = tmp_path("ro");
        fs::File::create(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o444)).unwrap();

        assert!(file_readable(&p));
        assert!(!file_writable(&p));

        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).ok();
        fs::remove_file(&p).ok();
    }
}
