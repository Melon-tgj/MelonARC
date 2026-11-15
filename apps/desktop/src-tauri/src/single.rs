//! One shell per data directory.
//!
//! Two windows would mean two supervisors, two children and two writers on the
//! same `api-token`, so the second instance stops before it does anything. The
//! lock is a real file lock (`File::try_lock`, stable since Rust 1.89) rather
//! than a pid file: the kernel drops it when the process dies, so a crash never
//! leaves a lock that has to be cleaned up by hand.
//!
//! Bringing the existing window to the front needs a window-management plugin,
//! which this stage does not add; the second launch simply exits and says why on
//! stderr.
//!
//! A lock that cannot be taken because the *file* cannot be opened is not a
//! second instance: it is a permissions problem, and refusing to start over it
//! would be worse than running without the protection. That case warns and
//! continues.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::path::Path;

use crate::settings::LOCK_FILE;

/// Take the lock, or exit when another instance already holds it.
///
/// The returned handle must stay alive for the whole process: dropping the file
/// releases the lock.
pub fn acquire(data_dir: &Path) -> Option<File> {
    let path = data_dir.join(LOCK_FILE);

    if let Err(error) = fs::create_dir_all(data_dir) {
        eprintln!(
            "melonarc-desktop: warning: cannot create {}: {error}; starting without the single-instance lock",
            data_dir.display()
        );
        return None;
    }

    let file = match OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) => {
            eprintln!(
                "melonarc-desktop: warning: cannot open {}: {error}; starting without the single-instance lock",
                path.display()
            );
            return None;
        }
    };

    match file.try_lock() {
        Ok(()) => Some(file),
        Err(TryLockError::WouldBlock) => {
            eprintln!(
                "melonarc-desktop: another window is already running for {}; this launch stops here",
                data_dir.display()
            );
            std::process::exit(0);
        }
        Err(TryLockError::Error(error)) => {
            eprintln!(
                "melonarc-desktop: warning: cannot lock {}: {error}; starting anyway",
                path.display()
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lock_file_is_created_inside_the_data_directory() {
        let dir = std::env::temp_dir().join(format!(
            "melonarc-single-instance-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);

        let held = acquire(&dir);
        assert!(held.is_some(), "a fresh directory has no owner");
        assert!(dir.join(LOCK_FILE).is_file(), "the lock file is on disk");

        drop(held);
        let _ = fs::remove_dir_all(&dir);
    }
}
