//! On-disk path resolution for NGSM-owned artifacts.
//!
//! All paths live under `%ProgramData%\NGSM\` on Windows. Tests set
//! `NGSM_PROGRAM_DATA_DIR` to a per-test tempdir to stay hermetic — the
//! env var override is honored on every platform.

use std::path::PathBuf;

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
    if !base.exists() {
        std::fs::create_dir_all(&base)?;
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an isolated tempdir and set `NGSM_PROGRAM_DATA_DIR` to it.
    /// Returns the tempdir so the caller can keep it alive for the test
    /// (it's removed on drop).
    fn isolate() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("NGSM_PROGRAM_DATA_DIR", dir.path());
        dir
    }

    #[test]
    fn ngsm_program_data_returns_override_and_creates_it() {
        let dir = isolate();
        let nested = dir.path().join("does_not_exist_yet");
        std::env::set_var("NGSM_PROGRAM_DATA_DIR", &nested);
        let resolved = ngsm_program_data().unwrap();
        assert_eq!(resolved, nested);
        assert!(resolved.exists());
    }

    #[test]
    fn events_log_lives_under_program_data() {
        let _dir = isolate();
        let log = events_log().unwrap();
        assert!(log.ends_with("events.log"));
        assert!(log.parent().unwrap().exists());
    }

    #[test]
    fn events_log_backup_lives_under_program_data() {
        let _dir = isolate();
        let bak = events_log_backup().unwrap();
        assert!(bak.ends_with("events.log.1"));
    }
}
