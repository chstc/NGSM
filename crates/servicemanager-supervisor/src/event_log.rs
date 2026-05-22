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
pub const ROTATION_THRESHOLD_BYTES: u64 = 1024 * 1024;

/// One writer per supervisor process. Holds the service name so callers
/// don't pass it on every event.
pub struct EventWriter {
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
        maybe_rotate(&path)?;
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

fn maybe_rotate(active: &PathBuf) -> std::io::Result<()> {
    let size = match std::fs::metadata(active) {
        Ok(m) => m.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if size < ROTATION_THRESHOLD_BYTES {
        return Ok(());
    }
    let backup = paths::events_log_backup()?;
    // `rename` overwrites the destination on Windows when both are on
    // the same volume, which is always true here (same directory).
    std::fs::rename(active, &backup)?;
    Ok(())
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
}
