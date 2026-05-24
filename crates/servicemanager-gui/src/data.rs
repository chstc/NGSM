//! Background worker for the UI thread.
//!
//! Win32 calls (SCM enumerate, registry read, install, etc.) can take
//! tens to hundreds of milliseconds; running them on the UI thread would
//! freeze the frame. We send `Job`s to a worker and post `JobResult`s
//! back, calling a `wake` callback after each so the UI drains them promptly.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, SyncSender};
use std::sync::Arc;
use std::thread;

use servicemanager_core::ServiceDefinition;
use servicemanager_win32::{enumerate_descendants, query_service, ProcessInfo};

// Re-export the canonical spec types from ops so that other GUI modules that
// import `crate::data::InstallSpec` / `EditSpec` / `RecoverySpec` keep working
// without touching their import paths.
pub use servicemanager_ops::{EditSpec, InstallSpec, RecoverySpec};

/// A unit of work the UI hands to the worker thread.
pub enum Job {
    Refresh,
    /// `token` identifies the modal operation that submitted this install so
    /// the UI can drop a stale result whose modal was cancelled or replaced.
    Install {
        spec: InstallSpec,
        token: u64,
    },
    /// `token` identifies the modal operation that submitted this edit so the
    /// UI can drop a stale result whose modal was cancelled or replaced.
    Edit {
        spec: EditSpec,
        token: u64,
    },
    Start(String),
    Stop(String),
    Restart(String),
    Pause(String),
    Continue(String),
    Rotate(String),
    Remove(String),
    Processes(String),
    ReadLog {
        service: String,
        stderr: bool,
    },
    SaveRecovery(RecoverySpec),
}

/// A result the worker posts back to the UI.
pub enum JobResult {
    Services {
        defs: Vec<ServiceDefinition>,
        /// Per-service managed-config read failures (access denied, corrupt
        /// values, ...). The rows are still shown; these are surfaced as a
        /// status-bar warning instead of being silently dropped.
        warnings: Vec<String>,
        /// Most-recent supervisor-recorded events, newest first. Populated
        /// every Refresh tick from the on-disk event log.
        events: Vec<servicemanager_core::EventRecord>,
        /// Dashboard metrics computed against the last 30 days of events.
        metrics: crate::metrics::DashboardMetrics,
    },
    Processes {
        service: String,
        processes: Vec<ProcessInfo>,
    },
    /// A privileged action ran (e.g. `Install`). Stash the success message;
    /// the UI shows it in the status bar.
    Acted(String),
    /// A tail of a service's stdout/stderr log.
    Log {
        service: String,
        stderr: bool,
        status: String,
        lines: Vec<String>,
    },
    /// Outcome of a `SaveRecovery` job — routed to the Recovery view's own
    /// status line. `Ok` carries the success message, `Err` the failure.
    RecoverySaved(Result<String, String>),
    /// Outcome of an `Install` job — routed back to the Install dialog. The
    /// `token` echoes the submitting modal's operation id so a stale result
    /// (cancelled / replaced before the worker finished) can be dropped.
    Installed {
        token: u64,
        result: Result<String, String>,
    },
    /// Outcome of an `Edit` job — routed back to the Edit dialog. The
    /// `token` echoes the submitting modal's operation id so a stale result
    /// (cancelled / replaced before the worker finished) can be dropped.
    Edited {
        token: u64,
        result: Result<String, String>,
    },
    Error(String),
}

/// Maximum number of jobs held in the worker queue. 16 is plenty for any
/// realistic UI burst; it prevents stale auto-refresh ticks from piling up.
const JOB_CHANNEL_CAP: usize = 16;

/// Error returned by [`JobSender::send`].
///
/// Does not carry the rejected `Job` to keep the variant size small — `Job`
/// can contain large payloads (specs, strings) and clippy's `result_large_err`
/// lint would fire if the error variant propagated those.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobSendError {
    /// The worker queue is full (back-pressure from a slow worker).
    Full,
    /// The worker thread has exited and the receiver is gone.
    Disconnected,
}

impl fmt::Display for JobSendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JobSendError::Full => write!(f, "job queue full"),
            JobSendError::Disconnected => write!(f, "worker thread disconnected"),
        }
    }
}

/// A clonable sender that coalesces `Job::Refresh` requests and delivers jobs
/// to the bounded worker queue without blocking the UI thread.
#[derive(Clone)]
pub struct JobSender {
    inner: SyncSender<Job>,
    /// Set to `true` when a `Refresh` is queued; cleared to `false` when the
    /// worker starts handling it. Prevents N identical Refresh jobs from
    /// stacking up during rapid auto-refresh ticks.
    pending_refresh: Arc<AtomicBool>,
}

impl JobSender {
    /// Try to send `job` to the worker. Returns [`JobSendError`] if the
    /// channel is full or disconnected. Never blocks the caller.
    ///
    /// A `Job::Refresh` is silently dropped (returns `Ok`) when one is already
    /// pending — the in-flight refresh will pick up the latest state when it
    /// runs.
    pub fn send(&self, job: Job) -> Result<(), JobSendError> {
        let is_refresh = matches!(job, Job::Refresh);
        if is_refresh && self.pending_refresh.swap(true, Ordering::AcqRel) {
            // swap returns the previous value; if it was already true there is
            // already a pending Refresh — discard this duplicate.
            return Ok(());
        }
        match self.inner.try_send(job) {
            Ok(()) => Ok(()),
            Err(e) => {
                if is_refresh {
                    // try_send failed — un-mark the pending flag so a future
                    // Refresh attempt isn't silently coalesced into oblivion.
                    self.pending_refresh.store(false, Ordering::Release);
                }
                Err(match e {
                    std::sync::mpsc::TrySendError::Full(_) => JobSendError::Full,
                    std::sync::mpsc::TrySendError::Disconnected(_) => JobSendError::Disconnected,
                })
            }
        }
    }
}

/// Spawn the worker thread. Returns the `JobSender`; results land on
/// `result_tx`. The worker calls `wake` after each result so the UI thread
/// can drain and apply them.
pub fn spawn_worker(result_tx: Sender<JobResult>, wake: Box<dyn Fn() + Send>) -> JobSender {
    let (job_tx, job_rx) = std::sync::mpsc::sync_channel::<Job>(JOB_CHANNEL_CAP);
    let pending_refresh = Arc::new(AtomicBool::new(false));
    let pending_refresh_worker = Arc::clone(&pending_refresh);
    thread::spawn(move || worker_loop(job_rx, result_tx, wake, pending_refresh_worker));
    JobSender {
        inner: job_tx,
        pending_refresh,
    }
}

fn worker_loop(
    rx: Receiver<Job>,
    tx: Sender<JobResult>,
    wake: Box<dyn Fn() + Send>,
    pending_refresh: Arc<AtomicBool>,
) {
    while let Ok(job) = rx.recv() {
        if matches!(job, Job::Refresh) {
            // Clear the flag now so the UI can enqueue the next Refresh as
            // soon as this one starts executing (rather than after it finishes).
            pending_refresh.store(false, Ordering::Release);
        }
        let result = execute(job);
        // Intentionally ignore the send result: if the UI-thread receiver has
        // been dropped (window closed) there is nothing useful the worker can
        // do — just keep draining until `rx.recv()` returns `Err` and exits.
        let _ = tx.send(result);
        wake();
    }
}

#[cfg(test)]
mod job_sender_tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn refresh_coalescing_skips_duplicate() {
        let (tx, _rx) = mpsc::sync_channel::<Job>(16);
        let pending = Arc::new(AtomicBool::new(false));
        let sender = JobSender {
            inner: tx,
            pending_refresh: Arc::clone(&pending),
        };

        // First Refresh: flag transitions false→true, job enqueued.
        sender.send(Job::Refresh).unwrap();
        assert!(pending.load(Ordering::Acquire), "flag should be set");

        // Second Refresh while flag is still true: silently dropped.
        sender.send(Job::Refresh).unwrap();

        // Simulate the worker clearing the flag.
        pending.store(false, Ordering::Release);

        // Now a third Refresh should be accepted again.
        sender.send(Job::Refresh).unwrap();
        assert!(pending.load(Ordering::Acquire), "flag should be set again");
    }

    #[test]
    fn refresh_send_failure_clears_pending_flag_so_future_refresh_can_retry() {
        // Bound channel of size 1, fill it with a non-Refresh job, then try
        // Refresh — try_send must fail with Full. After that failure, the
        // pending_refresh flag MUST be back to false so the next Refresh
        // attempt is not silently coalesced into oblivion.
        let (tx, rx) = mpsc::sync_channel::<Job>(1);
        let pending = Arc::new(AtomicBool::new(false));
        let sender = JobSender {
            inner: tx,
            pending_refresh: Arc::clone(&pending),
        };

        // Fill the channel with one non-Refresh job.
        sender.send(Job::Start("svc".into())).unwrap();

        // Refresh should fail Full and leave pending=false.
        let err = sender.send(Job::Refresh).unwrap_err();
        assert_eq!(err, JobSendError::Full);
        assert!(
            !pending.load(Ordering::Acquire),
            "pending_refresh must be cleared after a failed Refresh send"
        );

        // Drain the channel and confirm a second Refresh attempt now succeeds.
        let _ = rx.recv().unwrap();
        sender.send(Job::Refresh).unwrap();
        assert!(pending.load(Ordering::Acquire));
    }
}

fn execute(job: Job) -> JobResult {
    match job {
        Job::Refresh => match servicemanager_ops::list_services() {
            Ok((defs, mut warnings)) => {
                let now = time::OffsetDateTime::now_utc();
                let since = now - time::Duration::days(30);
                let (events_window, read_failed) = match crate::event_log_reader::read_since(since)
                {
                    Ok(v) => (v, false),
                    Err(e) => {
                        warnings.push(format!("event log unreadable: {e} — availability unknown"));
                        (Vec::new(), true)
                    }
                };
                let mut metrics = crate::metrics::compute_metrics(&defs, &events_window, now);
                if read_failed {
                    metrics.availability_unknown = true;
                }
                JobResult::Services {
                    defs,
                    warnings,
                    events: crate::event_log_reader::read_recent(50),
                    metrics,
                }
            }
            Err(e) => JobResult::Error(format!("enumerate: {e}")),
        },
        Job::Install { spec, token } => JobResult::Installed {
            token,
            result: servicemanager_ops::install(spec),
        },
        Job::Edit { spec, token } => JobResult::Edited {
            token,
            result: servicemanager_ops::edit(spec),
        },
        Job::Start(n) => match servicemanager_ops::start(&n) {
            Ok(msg) => JobResult::Acted(msg),
            Err(e) => JobResult::Error(format!("{n}: {e}")),
        },
        Job::Stop(n) => match servicemanager_ops::stop(&n) {
            Ok(msg) => JobResult::Acted(msg),
            Err(e) => JobResult::Error(format!("{n}: {e}")),
        },
        Job::Pause(n) => match servicemanager_ops::pause(&n) {
            Ok(msg) => JobResult::Acted(msg),
            Err(e) => JobResult::Error(format!("{n}: {e}")),
        },
        Job::Continue(n) => match servicemanager_ops::continue_service(&n) {
            Ok(msg) => JobResult::Acted(msg),
            Err(e) => JobResult::Error(format!("{n}: {e}")),
        },
        Job::Rotate(n) => match servicemanager_ops::rotate(&n) {
            Ok(msg) => JobResult::Acted(msg),
            Err(e) => JobResult::Error(e),
        },
        Job::Restart(n) => match servicemanager_ops::restart(&n, 30_000) {
            Ok(msg) => JobResult::Acted(msg),
            Err(e) => JobResult::Error(e),
        },
        // GUI always purges managed config and never force-natives.
        Job::Remove(n) => match servicemanager_ops::remove(&n, false, true) {
            Ok(msg) => JobResult::Acted(msg),
            Err(e) => JobResult::Error(e),
        },
        Job::Processes(n) => match processes(&n) {
            Ok(r) => r,
            Err(e) => JobResult::Error(e),
        },
        Job::ReadLog { service, stderr } => read_log(&service, stderr),
        Job::SaveRecovery(spec) => {
            JobResult::RecoverySaved(servicemanager_ops::save_recovery(spec))
        }
    }
}

fn processes(name: &str) -> Result<JobResult, String> {
    let snap = query_service(name).map_err(|e| e.to_string())?;
    let pid = snap
        .runtime
        .as_ref()
        .and_then(|r| r.pid)
        .ok_or_else(|| format!("service '{name}' is not running"))?;
    let descendants = enumerate_descendants(pid).map_err(|e| e.to_string())?;
    Ok(JobResult::Processes {
        service: name.to_string(),
        processes: descendants,
    })
}

/// Read the tail of a managed service's stdout or stderr log file.
fn read_log(service: &str, stderr: bool) -> JobResult {
    let which = if stderr { "stderr" } else { "stdout" };
    let log = |status: String, lines: Vec<String>| JobResult::Log {
        service: service.to_string(),
        stderr,
        status,
        lines,
    };
    let cfg = match servicemanager_registry::read_managed_config(service) {
        Ok(Some(c)) => c,
        Ok(None) => {
            return log(
                format!("'{service}' is not an NGSM-managed service."),
                Vec::new(),
            )
        }
        Err(e) => return log(format!("Cannot read '{service}' config: {e}"), Vec::new()),
    };
    let path = if stderr {
        cfg.io.stderr.as_ref().map(|s| s.path.clone())
    } else {
        cfg.io.stdout.as_ref().map(|s| s.path.clone())
    };
    let Some(path) = path else {
        return log(
            format!("No {which} log is configured for '{service}'."),
            Vec::new(),
        );
    };
    match tail_file(&path) {
        Ok(lines) => log(
            format!("{which}  ·  {path}  ·  {} lines", lines.len()),
            lines,
        ),
        Err(e) => log(format!("Cannot read {which} log '{path}': {e}"), Vec::new()),
    }
}

/// Read the last ~64 KiB of a file and return up to its last 400 lines.
///
/// Decodes as UTF-8 by default. If the file starts with a UTF-16 BOM
/// (`FF FE` or `FE FF`) the tail is decoded as UTF-16 with the
/// appropriate endianness, aligned to the BOM. A UTF-8 BOM
/// (`EF BB BF`) is recognised but does not change behavior.
fn tail_file(path: &str) -> std::io::Result<Vec<String>> {
    use std::io::{Read, Seek, SeekFrom};
    const TAIL: u64 = 64 * 1024;
    let mut f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();

    // Peek the first 4 bytes to detect a BOM. Encoding is determined
    // by what we find at byte 0.
    let mut head = [0u8; 4];
    let head_read = {
        let n_to_read = (len.min(4)) as usize;
        if n_to_read > 0 {
            f.seek(SeekFrom::Start(0))?;
            f.read_exact(&mut head[..n_to_read])?;
        }
        n_to_read
    };
    let encoding = detect_encoding(&head[..head_read]);

    // Compute the tail start. For UTF-16 align to a 2-byte boundary
    // (relative to the file start) so we don't slice mid-code-unit.
    let mut tail_start = len.saturating_sub(TAIL);
    if matches!(encoding, TailEncoding::Utf16Le | TailEncoding::Utf16Be) && tail_start % 2 != 0 {
        tail_start += 1;
    }
    let partial = tail_start > 0;

    f.seek(SeekFrom::Start(tail_start))?;
    let mut buf = Vec::with_capacity(TAIL as usize);
    f.read_to_end(&mut buf)?;

    let text = decode_tail(&buf, encoding);
    let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
    // A mid-file seek leaves the first line truncated — drop it.
    if partial && !lines.is_empty() {
        lines.remove(0);
    }
    let extra = lines.len().saturating_sub(400);
    if extra > 0 {
        lines.drain(0..extra);
    }
    Ok(lines)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TailEncoding {
    Utf8,
    Utf16Le,
    Utf16Be,
}

fn detect_encoding(head: &[u8]) -> TailEncoding {
    if head.len() >= 2 && head[0] == 0xFF && head[1] == 0xFE {
        TailEncoding::Utf16Le
    } else if head.len() >= 2 && head[0] == 0xFE && head[1] == 0xFF {
        TailEncoding::Utf16Be
    } else {
        TailEncoding::Utf8
    }
}

fn decode_tail(buf: &[u8], encoding: TailEncoding) -> String {
    match encoding {
        TailEncoding::Utf8 => String::from_utf8_lossy(buf).into_owned(),
        TailEncoding::Utf16Le => {
            // Truncate to a whole code-unit count.
            let n = (buf.len() / 2) * 2;
            let codes: Vec<u16> = buf[..n]
                .chunks_exact(2)
                .map(|p| u16::from_le_bytes([p[0], p[1]]))
                .collect();
            String::from_utf16_lossy(&codes)
        }
        TailEncoding::Utf16Be => {
            let n = (buf.len() / 2) * 2;
            let codes: Vec<u16> = buf[..n]
                .chunks_exact(2)
                .map(|p| u16::from_be_bytes([p[0], p[1]]))
                .collect();
            String::from_utf16_lossy(&codes)
        }
    }
}

#[cfg(test)]
mod tail_tests {
    use super::*;
    use std::io::Write;

    fn write_temp(bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(bytes).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn tail_decodes_utf8_without_bom() {
        let f = write_temp(b"hello\nworld\n");
        let lines = tail_file(f.path().to_str().unwrap()).unwrap();
        assert_eq!(lines, vec!["hello".to_string(), "world".to_string()]);
    }

    #[test]
    fn tail_decodes_utf8_with_bom() {
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(b"hello\nworld\n");
        let f = write_temp(&bytes);
        let lines = tail_file(f.path().to_str().unwrap()).unwrap();
        // The first "line" includes the BOM chars at the start; the
        // line content after that is still ASCII.
        assert!(lines.iter().any(|l| l.contains("hello")));
        assert!(lines.iter().any(|l| l.contains("world")));
    }

    #[test]
    fn tail_decodes_utf16_le_with_bom() {
        // "hi\n" in UTF-16 LE with BOM
        let mut bytes = vec![0xFF, 0xFE];
        for ch in "hi\n".chars() {
            let mut units = [0u16; 2];
            let s = ch.encode_utf16(&mut units);
            for u in s {
                bytes.extend_from_slice(&u.to_le_bytes());
            }
        }
        let f = write_temp(&bytes);
        let lines = tail_file(f.path().to_str().unwrap()).unwrap();
        assert!(
            lines.iter().any(|l| l.contains("hi")),
            "expected 'hi' in {lines:?}"
        );
    }

    #[test]
    fn tail_decodes_utf16_be_with_bom() {
        let mut bytes = vec![0xFE, 0xFF];
        for ch in "hi\n".chars() {
            let mut units = [0u16; 2];
            let s = ch.encode_utf16(&mut units);
            for u in s {
                bytes.extend_from_slice(&u.to_be_bytes());
            }
        }
        let f = write_temp(&bytes);
        let lines = tail_file(f.path().to_str().unwrap()).unwrap();
        assert!(
            lines.iter().any(|l| l.contains("hi")),
            "expected 'hi' in {lines:?}"
        );
    }
}
