//! On-disk path resolution for NGSM-owned artifacts.
//!
//! All paths live under `%ProgramData%\NGSM\` on Windows. Tests set
//! `NGSM_PROGRAM_DATA_DIR` to a per-test tempdir to stay hermetic — the
//! env var override is honored on every platform.

use std::path::PathBuf;

/// Number of rotated event-log backups retained on disk
/// (`events.log.1` .. `events.log.N`). Used by the supervisor's rotation
/// logic and by the GUI reader's path enumeration to stay in sync — any
/// change to retention depth flows from this single source.
pub const BACKUP_RETENTION_COUNT: u8 = 4;

/// Returns the NGSM data directory, creating it if missing.
///
/// Resolution order:
/// 1. `NGSM_PROGRAM_DATA_DIR` env var (tests + advanced overrides).
/// 2. `%ProgramData%\NGSM` on Windows (env var `ProgramData`, always set
///    by the OS).
/// 3. Hard error otherwise — we don't have a sensible non-Windows
///    fallback yet, and the supervisor only runs on Windows.
pub fn ngsm_program_data() -> std::io::Result<PathBuf> {
    let base = if let Ok(override_dir) = std::env::var("NGSM_PROGRAM_DATA_DIR") {
        PathBuf::from(override_dir)
    } else if let Ok(pd) = std::env::var("ProgramData") {
        PathBuf::from(pd).join("NGSM")
    } else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "neither NGSM_PROGRAM_DATA_DIR nor ProgramData is set",
        ));
    };
    std::fs::create_dir_all(&base)?;
    Ok(base)
}

/// Returns the path to the active event log file.
pub fn events_log() -> std::io::Result<PathBuf> {
    Ok(ngsm_program_data()?.join("events.log"))
}

/// Returns the path to the rotated (one-back) event log file.
pub fn events_log_backup() -> std::io::Result<PathBuf> {
    Ok(ngsm_program_data()?.join("events.log.1"))
}

/// Returns the path to backup file `n` (1..=BACKUP_RETENTION_COUNT). Index
/// 1 is the most-recent backup (the one events.log gets renamed to on the
/// next rotation); the highest index is the oldest backup we retain.
pub fn events_log_backup_n(n: u8) -> std::io::Result<PathBuf> {
    if !(1..=BACKUP_RETENTION_COUNT).contains(&n) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "events_log_backup_n: n must be 1..={BACKUP_RETENTION_COUNT}, got {n}"
            ),
        ));
    }
    Ok(ngsm_program_data()?.join(format!("events.log.{n}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// All paths tests mutate the process-wide `NGSM_PROGRAM_DATA_DIR`
    /// env var. Rust runs them on multiple threads by default, so the
    /// reads + writes race. Serialise them on this lock.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Build an isolated tempdir, lock the process env, and set
    /// `NGSM_PROGRAM_DATA_DIR` to it. Returns the guard + tempdir so the
    /// caller can keep both alive for the duration of the test.
    fn isolate() -> (std::sync::MutexGuard<'static, ()>, tempfile::TempDir) {
        let guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("NGSM_PROGRAM_DATA_DIR", dir.path());
        (guard, dir)
    }

    #[test]
    fn ngsm_program_data_returns_override_and_creates_it() {
        let (_g, dir) = isolate();
        let nested = dir.path().join("does_not_exist_yet");
        std::env::set_var("NGSM_PROGRAM_DATA_DIR", &nested);
        let resolved = ngsm_program_data().unwrap();
        assert_eq!(resolved, nested);
        assert!(resolved.exists());
    }

    #[test]
    fn events_log_lives_under_program_data() {
        let (_g, _dir) = isolate();
        let log = events_log().unwrap();
        assert!(log.ends_with("events.log"));
        assert!(log.parent().unwrap().exists());
    }

    #[test]
    fn events_log_backup_lives_under_program_data() {
        let (_g, _dir) = isolate();
        let bak = events_log_backup().unwrap();
        assert!(bak.ends_with("events.log.1"));
        assert!(bak.parent().unwrap().exists());
    }

    #[test]
    fn events_log_backup_n_returns_indexed_files() {
        let (_g, _dir) = isolate();
        let b1 = events_log_backup_n(1).unwrap();
        let b4 = events_log_backup_n(4).unwrap();
        assert!(b1.ends_with("events.log.1"));
        assert!(b4.ends_with("events.log.4"));
    }

    #[test]
    fn events_log_backup_n_rejects_out_of_range() {
        let (_g, _dir) = isolate();
        assert!(events_log_backup_n(0).is_err());
        assert!(events_log_backup_n(5).is_err());
    }

    #[test]
    fn events_log_backup_n_matches_legacy_helper_for_n_1() {
        let (_g, _dir) = isolate();
        assert_eq!(
            events_log_backup_n(1).unwrap(),
            events_log_backup().unwrap()
        );
    }
}
