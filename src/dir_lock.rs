//! One process at a time on a storage directory.
//!
//! Every instance holds the whole of its rule groups, values and switches in
//! memory and writes the whole of them back on each save. Two instances on one
//! directory therefore overwrite each other: a group created in one is gone
//! from `groups.json` the moment the other saves, and nothing says so. Their
//! histories also land in the same file under the same session ids. Upstream's
//! `w2 start` refuses a second instance on a storage directory; this does the
//! same for every start, since there is no daemon here to do it.
//!
//! The lock is the operating system's (`flock` on Unix, `LockFileEx` on
//! Windows), not the file's existence. It goes when the process does, however
//! it goes — `kill -9` and a crash included — so there is never a stale lock to
//! delete by hand. Deleting the file while an instance holds it does **not**
//! release it on Unix: the next instance locks a new file of the same name and
//! both run, which is the thing this exists to stop.

use std::fs::{File, OpenOptions, TryLockError};
use std::io;
use std::path::{Path, PathBuf};

/// The file whose lock is the directory's.
const LOCK: &str = "lock";
/// What the holder says about itself, for the message the next one prints.
/// Not the lock file: on Windows nobody else can read a locked file.
const OWNER: &str = "lock.owner";

/// The directory, held. Dropping it — or the process ending — releases it.
#[derive(Debug)]
pub struct DirLock {
    _file: File,
    dir: PathBuf,
}

/// Why [`DirLock::acquire`] did not get the directory.
#[derive(Debug)]
pub enum LockError {
    /// Another process holds it. `owner` is what that process recorded about
    /// itself, if it got that far.
    Held { dir: PathBuf, owner: Option<String> },
    /// The lock could not be taken or tested at all — a filesystem without
    /// locks, say. Nothing is known about other instances.
    Unavailable { dir: PathBuf, error: io::Error },
}

impl std::fmt::Display for LockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LockError::Held { dir, owner } => {
                write!(f, "{} is in use by another whistle-rs", dir.display())?;
                if let Some(owner) = owner {
                    write!(f, " ({owner})")?;
                }
                // What to do instead is the caller's to say: the binary and an
                // embedding program have different ways to name a directory.
                write!(
                    f,
                    ". Two instances on one directory overwrite each other's rule \
                     groups, values and history"
                )
            }
            LockError::Unavailable { dir, error } => write!(
                f,
                "cannot lock {} ({error}); nothing stops a second whistle-rs from \
                 using it at the same time",
                dir.display()
            ),
        }
    }
}

impl std::error::Error for LockError {}

impl DirLock {
    /// Take `dir` for this process, which must already exist. Fails at once
    /// rather than waiting: the other instance may run for days.
    pub fn acquire(dir: &Path) -> Result<DirLock, LockError> {
        let unavailable = |error| LockError::Unavailable {
            dir: dir.to_path_buf(),
            error,
        };
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.join(LOCK))
            .map_err(unavailable)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                let owner = std::fs::read_to_string(dir.join(OWNER))
                    .ok()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty());
                return Err(LockError::Held {
                    dir: dir.to_path_buf(),
                    owner,
                });
            }
            Err(TryLockError::Error(e)) => return Err(unavailable(e)),
        }
        let lock = DirLock {
            _file: file,
            dir: dir.to_path_buf(),
        };
        // At once, so a previous holder's line is never shown for this one.
        lock.record(None);
        Ok(lock)
    }

    /// Say who holds the directory: this process, and where it listens once
    /// that is known.
    pub fn record(&self, listening: Option<&str>) {
        let mut line = format!("pid {}", std::process::id());
        if let Some(addr) = listening {
            line.push_str(&format!(", listening on {addr}"));
        }
        // A plain write, not `private_fs::write`: nothing here is secret, and
        // that one's `fsync` takes long enough on macOS (~10 ms) for the next
        // instance to look in between and find no line at all.
        if let Err(e) = std::fs::write(self.dir.join(OWNER), line) {
            tracing::debug!("cannot write {}: {e}", self.dir.join(OWNER).display());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("whistle-rs-dir-lock-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    #[test]
    fn a_held_directory_is_refused_and_says_who_holds_it() {
        let dir = scratch("held");
        let first = DirLock::acquire(&dir).expect("first takes it");
        first.record(Some("http://127.0.0.1:8899"));
        // A second handle in the same process stands in for a second process:
        // `flock` and `LockFileEx` locks belong to the open file, not the pid.
        let second = DirLock::acquire(&dir).expect_err("second is refused");
        let text = second.to_string();
        assert!(
            matches!(&second, LockError::Held { owner: Some(o), .. }
                if o == &format!("pid {}, listening on http://127.0.0.1:8899", std::process::id())),
            "{second:?}"
        );
        assert!(text.contains(&dir.display().to_string()), "{text}");
        drop(first);
        DirLock::acquire(&dir).expect("free again once the holder lets go");
    }

    #[test]
    fn another_directory_is_unaffected() {
        let (a, b) = (scratch("one"), scratch("two"));
        let _a = DirLock::acquire(&a).expect("a");
        DirLock::acquire(&b).expect("b is its own directory");
    }
}
