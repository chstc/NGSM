//! Append-only JSON Lines event log shared across all NGSM supervisor
//! processes.
//!
//! Append and rotation share one destination-scoped interprocess lock.
//!
//! Failures (disk full, missing ACL, rotation race) are reported to
//! stderr and swallowed. Service supervision MUST NOT depend on the log
//! being writable.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use crate::diagnostics;

#[cfg(all(test, windows))]
#[path = "event_log_tests_windows.rs"]
mod windows_tests;
use servicemanager_core::events::{EventKind, EventRecord, StopReason};
use servicemanager_core::paths;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Rotation threshold for `events.log`. Bumped to 8 MiB for v0.3 so the
/// retained history (4 backups × 8 MiB ≈ 32 MiB) covers 30 days of typical
/// supervisor activity without hand-holding.
pub(crate) const ROTATION_THRESHOLD_BYTES: u64 = 8 * 1024 * 1024;

/// One writer per supervisor process. Holds the service name so callers
/// don't pass it on every event.
pub(crate) struct EventWriter {
    service: String,
    diagnostic: diagnostics::Reporter,
}

impl EventWriter {
    #[cfg(test)]
    pub fn for_service(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            diagnostic: diagnostics::reporter().clone(),
        }
    }

    pub(crate) fn with_diagnostics(
        service: impl Into<String>,
        diagnostic: diagnostics::Reporter,
    ) -> Self {
        Self {
            service: service.into(),
            diagnostic,
        }
    }

    #[cfg(test)]
    pub fn started(&self, pid: u32) {
        self.started_at(pid, now_rfc3339());
    }

    pub(crate) fn started_at(&self, pid: u32, ts: String) {
        self.log(EventRecord {
            ts,
            service: self.service.clone(),
            event: EventKind::Started,
            pid: Some(pid),
            exit_code: None,
            lived_ms: None,
            delay_ms: None,
            reason: None,
        });
    }

    #[cfg(test)]
    pub fn restarted(&self, pid: u32, delay_ms: u64) {
        self.restarted_at(pid, delay_ms, now_rfc3339());
    }

    pub(crate) fn restarted_at(&self, pid: u32, delay_ms: u64, ts: String) {
        self.log(EventRecord {
            ts,
            service: self.service.clone(),
            event: EventKind::Restarted,
            pid: Some(pid),
            exit_code: None,
            lived_ms: None,
            delay_ms: Some(delay_ms),
            reason: None,
        });
    }

    #[cfg(test)]
    pub fn child_exited(&self, exit_code: i32, lived_ms: u64) {
        self.child_exited_at(exit_code, lived_ms, now_rfc3339());
    }

    pub(crate) fn child_exited_at(&self, exit_code: i32, lived_ms: u64, ts: String) {
        self.log(EventRecord {
            ts,
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

    /// Best-effort append. Failure diagnostics use the independent host sink.
    pub fn log(&self, record: EventRecord) {
        if let Err(e) = self.try_log(record) {
            self.diagnostic
                .report(&self.service, "event log write", &e.to_string());
        }
    }

    fn try_log(&self, record: EventRecord) -> std::io::Result<()> {
        let path = paths::events_log()?;
        let mut line = serde_json::to_string(&record)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        line.push('\n');
        with_event_log_write_lock(&path, || {
            append_one(&path, line.as_bytes())?;
            // The record is already on disk; rotation failure is a housekeeping
            // problem, not a write failure. Log and continue.
            if let Err(e) = maybe_rotate(&path) {
                self.diagnostic
                    .report(&self.service, "event log rotation", &e.to_string());
            }
            Ok(())
        })
    }
}

pub(crate) fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| String::from("1970-01-01T00:00:00Z"))
}

fn append_one(path: &PathBuf, bytes: &[u8]) -> std::io::Result<()> {
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    f.write_all(bytes)
}

/// Serialize each event-log append/rotation cycle so concurrent writers never
/// split records or rotate a file another writer is actively appending to.
#[cfg(windows)]
fn with_event_log_write_lock<F>(path: &std::path::Path, f: F) -> std::io::Result<()>
where
    F: FnOnce() -> std::io::Result<()>,
{
    let _guard = EventLock::acquire(path, 5_000)?;
    f()
}

#[cfg(windows)]
const EVENT_MUTEX_SDDL: &str =
    "D:P(A;;0x00100001;;;SY)(A;;0x00100001;;;BA)(A;;0x00100001;;;SU)(A;;0x00100001;;;OW)";

#[cfg(windows)]
fn mutex_name(path: &std::path::Path) -> std::io::Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("event log has no parent"))?;
    let canonical = std::fs::canonicalize(parent)?.join(
        path.file_name()
            .ok_or_else(|| std::io::Error::other("event log has no filename"))?,
    );
    let mut hash = 0xcbf29ce484222325u64;
    for word in canonical.as_os_str().encode_wide() {
        for byte in word.to_le_bytes() {
            hash = (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3);
        }
    }
    Ok(format!("Global\\NGSM-events-{hash:016x}\0")
        .encode_utf16()
        .collect())
}

#[cfg(windows)]
fn create_event_mutex(
    path: &std::path::Path,
    descriptor: &str,
    access: u32,
) -> std::io::Result<windows::Win32::Foundation::HANDLE> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
    };
    use windows::Win32::System::Threading::CreateMutexExW;

    let name = mutex_name(path)?;
    let descriptor: Vec<u16> = descriptor.encode_utf16().chain(Some(0)).collect();
    let mut security = PSECURITY_DESCRIPTOR::default();
    // SAFETY: the SDDL input is terminated and security receives a LocalAlloc allocation.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(descriptor.as_ptr()),
            SDDL_REVISION_1,
            &mut security,
            None,
        )
    }
    .map_err(std::io::Error::other)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security.0,
        bInheritHandle: false.into(),
    };
    // SAFETY: attributes and the descriptor remain alive throughout creation/opening.
    let result = unsafe { CreateMutexExW(Some(&attributes), PCWSTR(name.as_ptr()), 0, access) };
    // SAFETY: the converted descriptor is one LocalAlloc allocation, freed exactly once.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(security.0)));
    }
    result.map_err(|error| std::io::Error::from_raw_os_error(error.code().0 & 0xffff))
}

#[cfg(windows)]
struct EventLock(windows::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl EventLock {
    fn acquire(path: &std::path::Path, timeout_ms: u32) -> std::io::Result<Self> {
        use windows::Win32::Foundation::{
            CloseHandle, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT,
        };
        use windows::Win32::System::Threading::WaitForSingleObject;
        // SYNCHRONIZE | MUTEX_MODIFY_STATE; never request MUTEX_ALL_ACCESS.
        let handle = create_event_mutex(path, EVENT_MUTEX_SDDL, 0x0010_0001)?;
        // SAFETY: handle is the live mutex just created/opened.
        let result = unsafe { WaitForSingleObject(handle, timeout_ms) };
        if result == WAIT_OBJECT_0 || result == WAIT_ABANDONED {
            Ok(Self(handle))
        } else {
            let error = if result == WAIT_TIMEOUT {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "event log mutex timed out")
            } else {
                std::io::Error::last_os_error()
            };
            // SAFETY: acquisition failed; close without releasing an unowned mutex.
            unsafe {
                let _ = CloseHandle(handle);
            }
            Err(error)
        }
    }
}

#[cfg(windows)]
impl Drop for EventLock {
    fn drop(&mut self) {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::ReleaseMutex;
        // SAFETY: this thread owns the mutex, and this guard owns its handle.
        unsafe {
            let _ = ReleaseMutex(self.0);
            let _ = CloseHandle(self.0);
        }
    }
}

#[cfg(not(windows))]
fn with_event_log_write_lock<F>(_path: &std::path::Path, f: F) -> std::io::Result<()>
where
    F: FnOnce() -> std::io::Result<()>,
{
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    f()
}

/// Called while holding the same lock as the preceding append.
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

    // Shift: events.log.(N-1) → events.log.N, ..., events.log.1 → events.log.2,
    // then active events.log → events.log.1. The oldest backup (.N) is removed
    // first because Windows rename refuses to overwrite an existing target.
    let oldest = paths::events_log_backup_n(paths::BACKUP_RETENTION_COUNT)?;
    if let Err(e) = std::fs::remove_file(&oldest) {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(e);
        }
    }
    for i in (1..paths::BACKUP_RETENTION_COUNT).rev() {
        let from = paths::events_log_backup_n(i)?;
        let to = paths::events_log_backup_n(i + 1)?;
        if !from.exists() {
            continue;
        }
        std::fs::rename(&from, &to)?;
    }
    let dest_1 = paths::events_log_backup_n(1)?;
    std::fs::rename(active, &dest_1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn isolate() -> (std::sync::MutexGuard<'static, ()>, tempfile::TempDir) {
        let guard = crate::TEST_PROGRAM_DATA_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
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
        let bogus = _dir.path().join("ngsm-test-bogus-file");
        std::fs::write(&bogus, b"i am a file, not a dir").unwrap();
        std::env::set_var("NGSM_PROGRAM_DATA_DIR", &bogus);
        let w = EventWriter::for_service("Foo");
        w.started(1); // must not panic
                      // Cleanup
        let _ = std::fs::remove_file(&bogus);
    }

    #[test]
    fn second_rotation_overwrites_existing_backup() {
        let (_g, _dir) = isolate();
        // Pre-seed backup AND active over threshold.
        std::fs::write(paths::events_log_backup().unwrap(), b"old\n").unwrap();
        let active = paths::events_log().unwrap();
        std::fs::write(&active, vec![b'x'; (ROTATION_THRESHOLD_BYTES + 1) as usize]).unwrap();

        let w = EventWriter::for_service("Foo");
        w.started(42); // triggers rotation; the existing backup must be replaced

        let backup = paths::events_log_backup().unwrap();
        assert!(backup.exists(), "backup should still exist (just replaced)");
        let body = std::fs::read(&backup).unwrap();
        // The backup should now be the OLD active file (1MB+ of 'x'), not
        // the original "old\n" sentinel.
        assert!(
            body.len() > ROTATION_THRESHOLD_BYTES as usize,
            "backup should be the rotated old active"
        );
        assert_ne!(
            &body[..3],
            b"old",
            "backup should no longer be the pre-seeded sentinel"
        );
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

    #[test]
    fn rotation_shifts_existing_backups_and_drops_oldest() {
        let (_g, _dir) = isolate();
        // Pre-seed all four backups with distinct sentinel content.
        std::fs::write(paths::events_log_backup_n(1).unwrap(), b"BAK1\n").unwrap();
        std::fs::write(paths::events_log_backup_n(2).unwrap(), b"BAK2\n").unwrap();
        std::fs::write(paths::events_log_backup_n(3).unwrap(), b"BAK3\n").unwrap();
        std::fs::write(paths::events_log_backup_n(4).unwrap(), b"BAK4_OLDEST\n").unwrap();
        // Seed active over threshold.
        let active = paths::events_log().unwrap();
        std::fs::write(&active, vec![b'x'; (ROTATION_THRESHOLD_BYTES + 1) as usize]).unwrap();

        let w = EventWriter::for_service("Shifter");
        w.started(7);

        // After rotation: oldest backup is gone; .1..=.4 are the prior .0..=.3.
        let b1 = std::fs::read(paths::events_log_backup_n(1).unwrap()).unwrap();
        let b2 = std::fs::read(paths::events_log_backup_n(2).unwrap()).unwrap();
        let b3 = std::fs::read(paths::events_log_backup_n(3).unwrap()).unwrap();
        let b4 = std::fs::read(paths::events_log_backup_n(4).unwrap()).unwrap();
        // .1 is the rotated old active (1MB+ of 'x' followed by the new event).
        assert!(b1.len() > ROTATION_THRESHOLD_BYTES as usize);
        assert_eq!(&b2[..], b"BAK1\n");
        assert_eq!(&b3[..], b"BAK2\n");
        assert_eq!(&b4[..], b"BAK3\n");
        // The previous BAK4_OLDEST is gone (replaced).
        assert!(!b4.starts_with(b"BAK4_OLDEST"));
    }
}
