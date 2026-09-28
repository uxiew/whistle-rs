//! Files and directories only their owner can read.
//!
//! What the storage directory holds is not public: the root CA's private key
//! (with it, anyone can forge a certificate every client of this proxy trusts),
//! captured sessions (cookies and `Authorization` headers, verbatim), and values
//! that often hold tokens. Everything was written with the process umask —
//! `root.key` came out `0644` — so any other account on the machine could read
//! the key and the traffic.
//!
//! On Unix, files are created `0600` and directories `0700`. A directory that
//! already existed is left alone unless it is one of this proxy's own
//! (`certs/`, `rules/`, `sessions/`), which [`tighten`] narrows on startup: a
//! `--dir` pointed at an existing shared directory is the operator's choice,
//! not ours to chmod. Elsewhere these are the plain `std::fs` calls.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

/// Create `dir` and its parents; a directory this call creates is `0700`.
pub fn create_dir(dir: &Path) -> io::Result<()> {
    let existed = dir.is_dir();
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    if !existed {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    let _ = existed;
    Ok(())
}

/// Replace `path`'s contents; the file is `0600` afterwards, even if it existed
/// with a wider mode.
pub fn write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)?;
    // `mode` applies only when the file is created; an old one keeps its bits.
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)
}

/// Open `path` for appending, creating it `0600`.
pub fn open_append(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options.open(path)?;
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

/// Narrow an existing file to `0600` or directory to `0700`. For this proxy's
/// own files, written by versions that did not restrict them. Missing is fine.
pub fn tighten(path: &Path) {
    #[cfg(unix)]
    if let Ok(meta) = fs::metadata(path) {
        let mode = if meta.is_dir() { 0o700 } else { 0o600 };
        if meta.permissions().mode() & 0o777 != mode
            && let Err(e) = fs::set_permissions(path, fs::Permissions::from_mode(mode))
        {
            tracing::warn!("could not restrict {}: {e}", path.display());
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).expect("metadata").permissions().mode() & 0o777
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "whistle-rs-private-fs-{}-{name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn a_new_directory_and_file_are_the_owners_alone() {
        let dir = scratch("new").join("a").join("b");
        create_dir(&dir).expect("create");
        assert_eq!(mode(&dir), 0o700);
        let file = dir.join("secret");
        write(&file, b"x").expect("write");
        assert_eq!(mode(&file), 0o600);
        let appended = dir.join("log");
        open_append(&appended).expect("append");
        assert_eq!(mode(&appended), 0o600);
    }

    /// An old, world-readable file is narrowed when it is written again.
    #[test]
    fn rewriting_a_wide_file_narrows_it() {
        let dir = scratch("rewrite");
        fs::create_dir_all(&dir).expect("dir");
        let file = dir.join("values.json");
        fs::write(&file, b"{}").expect("seed");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).expect("chmod");
        write(&file, b"{\"a\":1}").expect("write");
        assert_eq!(mode(&file), 0o600);
        assert_eq!(fs::read(&file).expect("read"), b"{\"a\":1}");
        let log = dir.join("log");
        fs::write(&log, b"").expect("seed");
        fs::set_permissions(&log, fs::Permissions::from_mode(0o644)).expect("chmod");
        open_append(&log).expect("append");
        assert_eq!(mode(&log), 0o600);
    }

    /// A directory the operator already had is theirs; ours are tightened.
    #[test]
    fn an_existing_directory_is_left_alone_unless_tightened() {
        let dir = scratch("existing");
        fs::create_dir_all(&dir).expect("dir");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).expect("chmod");
        create_dir(&dir).expect("create");
        assert_eq!(mode(&dir), 0o755);
        tighten(&dir);
        assert_eq!(mode(&dir), 0o700);
        tighten(&dir.join("missing")); // not an error
    }
}
