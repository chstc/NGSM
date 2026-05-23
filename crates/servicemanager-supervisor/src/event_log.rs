//! Append-only JSON Lines event log shared across all NGSM supervisor
//! processes.
//!
//! Each call to [`EventWriter::log`] (or its convenience wrappers) opens
//! the log with `create + append`, formats one [`EventRecord`] as JSON,
//! writes it with a single `write_all`, and closes the handle. On NTFS,
//! a single `write_all` of less than ~4 KiB to a file opened with
//! `FILE_APPEND_DATA` is atomic across processes — interleaved records
//! from concurrent supervisors are never torn.
//!
//! Failures (disk full, missing ACL, rotation race) are reported to
//! stderr and swallowed. Service supervision MUST NOT depend on the log
//! being writable.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use servicemanager_core::events::{EventKind, EventRecord, StopReason};
use servicemanager_core::paths;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Rotation threshold for `events.log`. Single backup at `events.log.1`.
pub(crate) const ROTATION_THRESHOLD_BYTES: u64 = 1024 * 1024;

/// One writer per supervisor process. Holds the service name so callers
/// don't pass it on every event.
pub(crate) struct EventWriter {
    service: String,
}

impl EventWriter {
    pub fn for_service(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    pub fn started(&self, pid: u32) {
        self.log(EventRecord {
            ts: now_rfc3339(),
            service: self.service.clone(),
            event: EventKind::Started,
            pid: Some(pid),
            exit_code: None,
            lived_ms: None,
            delay_ms: None,
            reason: None,
        });
    }

    pub fn restarted(&self, pid: u32, delay_ms: u64) {
        self.log(EventRecord {
            ts: now_rfc3339(),
            service: self.service.clone(),
            event: EventKind::Restarted,
            pid: Some(pid),
            exit_code: None,
            lived_ms: None,
            delay_ms: Some(delay_ms),
            reason: None,
        });
    }

    pub fn child_exited(&self, exit_code: i32, lived_ms: u64) {
        self.log(EventRecord {
            ts: now_rfc3339(),
            service: self.service.clone(),
            event: EventKind::ChildExited,
            pid: None,
            exit_code: Some(exit_code),
            lived_ms: Some(lived_ms),
            delay_ms: None,
            reason: None,
        });
    }

    pub fn throttled(&self, delay_ms: u64) {
        self.log(EventRecord {
            ts: now_rfc3339(),
            service: self.service.clone(),
            event: EventKind::Throttled,
            pid: None,
            exit_code: None,
            lived_ms: None,
            delay_ms: Some(delay_ms),
            reason: None,
        });
    }

    pub fn stopped(&self, reason: StopReason) {
        self.log(EventRecord {
            ts: now_rfc3339(),
            service: self.service.clone(),
            event: EventKind::Stopped,
            pid: None,
            exit_code: None,
            lived_ms: None,
            delay_ms: None,
            reason: Some(reason),
        });
    }

    /// Best-effort append. All errors are reported on stderr (so they
    /// land in the per-service stderr log when the supervisor is running
    /// under SCM) and swallowed.
    pub fn log(&self, record: EventRecord) {
        if let Err(e) = self.try_log(record) {
            eprintln!("[supervisor:{}] event log write failed: {e}", self.service);
        }
    }

    fn try_log(&self, record: EventRecord) -> std::io::Result<()> {
        let path = paths::events_log()?;
        let mut line = serde_json::to_string(&record)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        line.push('\n');
        append_one(&path, line.as_bytes())?;
        // The record is already on disk; rotation failure is a housekeeping
        // problem, not a write failure. Log and continue.
        if let Err(e) = maybe_rotate(&path) {
            eprintln!(
                "[supervisor:{}] event log rotation failed (ignored): {e}",
                self.service
            );
        }
        Ok(())
    }
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| String::from("1970-01-01T00:00:00Z"))
}

fn append_one(path: &PathBuf, bytes: &[u8]) -> std::io::Result<()> {
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    f.write_all(bytes)
}

/// On Windows: serialize rotation across all supervisor processes using a
/// named mutex. Re-check file size after acquiring the lock; if a peer
/// already rotated, skip.
///
/// On non-Windows (e.g. Linux CI): keep the original single-check behavior.
fn maybe_rotate(active: &PathBuf) -> std::io::Result<()> {
    // Fast path: skip the mutex overhead if we are clearly under threshold.
    let size = match std::fs::metadata(active) {
        Ok(m) => m.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if size < ROTATION_THRESHOLD_BYTES {
        return Ok(());
    }

    #[cfg(windows)]
    {
        rotate_with_mutex(active)
    }

    #[cfg(not(windows))]
    {
        let backup = paths::events_log_backup()?;
        std::fs::rename(active, &backup)
    }
}

/// Windows-only: acquire `Global\NGSM-events-log-rotate`, re-check size, rename.
#[cfg(windows)]
fn rotate_with_mutex(active: &PathBuf) -> std::io::Result<()> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject};

    // 1 000 ms timeout so a stuck peer doesn't stall supervision indefinitely.
    const TIMEOUT_MS: u32 = 1_000;

    // Encode the name as a null-terminated UTF-16 string.
    let name_wide: Vec<u16> = "Global\\NGSM-events-log-rotate\0".encode_utf16().collect();

    // SAFETY: name_wide is a valid null-terminated UTF-16 string. We pass
    // NULL for security attributes (default) and FALSE for bInitialOwner.
    let mutex: HANDLE = unsafe {
        CreateMutexW(None, false, PCWSTR(name_wide.as_ptr())).map_err(std::io::Error::other)?
    };

    // RAII guard — releases and closes the mutex handle on drop.
    struct MutexGuard(HANDLE);
    impl Drop for MutexGuard {
        fn drop(&mut self) {
            unsafe {
                // Ignore errors: if the handle is invalid there's nothing we
                // can do, and panicking inside Drop is worse.
                let _ = ReleaseMutex(self.0);
                let _ = CloseHandle(self.0);
            }
        }
    }

    let wait_result = unsafe { WaitForSingleObject(mutex, TIMEOUT_MS) };

    // WAIT_ABANDONED means the previous owner died while holding the lock;
    // we still own it now, so treat it like WAIT_OBJECT_0.
    if wait_result != WAIT_OBJECT_0 && wait_result != WAIT_ABANDONED {
        // Timeout or error — skip rotation; the next write will retry.
        unsafe {
            let _ = CloseHandle(mutex);
        }
        eprintln!(
            "[supervisor] event log rotation skipped: could not acquire rotation mutex \
             (WaitForSingleObject returned {wait_result:?})"
        );
        return Ok(());
    }

    // We own the mutex; the guard will release it on scope exit.
    let _guard = MutexGuard(mutex);

    // Re-check: a peer may have already rotated while we were waiting.
    let size = match std::fs::metadata(active) {
        Ok(m) => m.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if size < ROTATION_THRESHOLD_BYTES {
        return Ok(());
    }

    let backup = paths::events_log_backup()?;
    std::fs::rename(active, &backup)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Tests in this module touch the same env var (`NGSM_PROGRAM_DATA_DIR`)
    /// and the same on-disk artifacts, so they serialize on this mutex.
    /// (Cargo runs each test crate's tests in one binary, multithreaded.)
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn isolate() -> (std::sync::MutexGuard<'static, ()>, tempfile::TempDir) {
        let guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("NGSM_PROGRAM_DATA_DIR", dir.path());
        (guard, dir)
    }

    fn read_lines() -> Vec<String> {
        let path = paths::events_log().unwrap();
        if !path.exists() {
            return Vec::new();
        }
        let raw = std::fs::read_to_string(&path).unwrap();
        raw.lines().map(|l| l.to_string()).collect()
    }

    #[test]
    fn started_appends_one_parseable_line() {
        let (_g, _dir) = isolate();
        let w = EventWriter::for_service("Foo");
        w.started(1234);
        let lines = read_lines();
        assert_eq!(lines.len(), 1);
        let rec: EventRecord = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(rec.event, EventKind::Started);
        assert_eq!(rec.service, "Foo");
        assert_eq!(rec.pid, Some(1234));
    }

    #[test]
    fn each_event_kind_writes_a_distinct_record() {
        let (_g, _dir) = isolate();
        let w = EventWriter::for_service("Bar");
        w.started(10);
        w.child_exited(1, 800);
        w.throttled(1500);
        w.restarted(20, 1500);
        w.stopped(StopReason::ScmStop);
        let lines = read_lines();
        assert_eq!(lines.len(), 5);
        let kinds: Vec<EventKind> = lines
            .iter()
            .map(|l| serde_json::from_str::<EventRecord>(l).unwrap().event)
            .collect();
        assert_eq!(
            kinds,
            vec![
                EventKind::Started,
                EventKind::ChildExited,
                EventKind::Throttled,
                EventKind::Restarted,
                EventKind::Stopped,
            ]
        );
    }

    #[test]
    fn concurrent_writers_produce_intact_lines() {
        let (_g, _dir) = isolate();
        let threads: Vec<_> = (0..8)
            .map(|t| {
                std::thread::spawn(move || {
                    let w = EventWriter::for_service(format!("svc{t}"));
                    for i in 0..100 {
                        w.started(i);
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let lines = read_lines();
        assert_eq!(lines.len(), 800);
        // Every line is independently parseable — no torn writes.
        for l in &lines {
            serde_json::from_str::<EventRecord>(l)
                .unwrap_or_else(|e| panic!("bad line {l:?}: {e}"));
        }
    }

    #[test]
    fn write_past_threshold_rotates_to_backup() {
        let (_g, dir) = isolate();
        // Seed the active file just over the threshold so the very next
        // append triggers rotation.
        let active = paths::events_log().unwrap();
        std::fs::write(&active, vec![b'x'; (ROTATION_THRESHOLD_BYTES + 1) as usize]).unwrap();

        let w = EventWriter::for_service("RotateMe");
        w.started(42);

        let backup = paths::events_log_backup().unwrap();
        assert!(backup.exists(), "backup file should exist after rotation");
        // The active file was renamed to .1, so the post-rotation
        // events.log either does not exist (next writer recreates it)
        // or is small. Either way, the rotated backup contains the
        // pre-rotation bytes and the new event line.
        let backup_bytes = std::fs::read(&backup).unwrap();
        assert!(backup_bytes.len() > ROTATION_THRESHOLD_BYTES as usize);
        // The new record is in the *renamed* file (the writer's append
        // happened before maybe_rotate noticed the size).
        let backup_str = String::from_utf8_lossy(&backup_bytes);
        assert!(backup_str.contains(r#""event":"started""#));
        let _ = dir; // keep tempdir alive
    }

    #[test]
    fn write_after_rotation_creates_fresh_active_file() {
        let (_g, _dir) = isolate();
        let active = paths::events_log().unwrap();
        std::fs::write(&active, vec![b'x'; (ROTATION_THRESHOLD_BYTES + 1) as usize]).unwrap();
        let w = EventWriter::for_service("Foo");
        w.started(1); // triggers rotation
                      // Active is now missing or empty; the next write must recreate it.
        w.started(2);
        assert!(active.exists(), "events.log must exist after second write");
        let body = std::fs::read_to_string(&active).unwrap();
        assert!(body.contains(r#""pid":2"#));
    }

    #[test]
    fn write_failure_does_not_panic() {
        let (_g, _dir) = isolate();
        // Point at a path under a directory that does not and cannot be
        // created (a file masquerading as a directory).
        let bogus = std::env::temp_dir().join("ngsm-test-bogus-file");
        std::fs::write(&bogus, b"i am a file, not a dir").unwrap();
        std::env::set_var("NGSM_PROGRAM_DATA_DIR", &bogus);
        let w = EventWriter::for_service("Foo");
        w.started(1); // must not panic
                      // Cleanup
        let _ = std::fs::remove_file(&bogus);
    }

    #[test]
    fn concurrent_rotations_do_not_clobber_backup() {
        let (_g, _dir) = isolate();
        // Pre-seed backup with sentinel content
        std::fs::write(paths::events_log_backup().unwrap(), b"BACKUP_SENTINEL\n").unwrap();
        // Seed active over threshold
        let active = paths::events_log().unwrap();
        std::fs::write(&active, vec![b'x'; (ROTATION_THRESHOLD_BYTES + 1) as usize]).unwrap();

        // Many concurrent writers all triggering rotation
        let threads: Vec<_> = (0..16)
            .map(|i| {
                std::thread::spawn(move || {
                    let w = EventWriter::for_service(format!("svc{i}"));
                    w.started(i);
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }

        // Backup must still contain the pre-seeded sentinel — only one
        // rotation should have actually run (or zero if all writers
        // raced past the re-check; the file might still be >threshold
        // with new records appended, that's fine — we just need to prove
        // the original backup wasn't overwritten).
        let backup_path = paths::events_log_backup().unwrap();
        if backup_path.exists() {
            let backup_body = std::fs::read(&backup_path).unwrap();
            // Either no rotation happened (backup still is the sentinel)
            // OR exactly one rotation happened (backup is the old active
            // which contained the 1MB+ of 'x' bytes — the sentinel is
            // gone because rotation replaced backup with old active).
            // What we MUST NOT see: an active that's small AND a backup
            // that contains neither the sentinel nor 1MB+ of 'x' —
            // that would mean a clobber.
            let is_sentinel = backup_body == b"BACKUP_SENTINEL\n";
            let is_rotated_old_active = backup_body.len() >= ROTATION_THRESHOLD_BYTES as usize
                && backup_body
                    .iter()
                    .take(ROTATION_THRESHOLD_BYTES as usize)
                    .all(|b| *b == b'x');
            assert!(
                is_sentinel || is_rotated_old_active,
                "backup file was clobbered: len={}, first_bytes={:?}",
                backup_body.len(),
                &backup_body[..backup_body.len().min(40)]
            );
        }
    }
}
