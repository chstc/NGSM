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

use servicemanager_core::{Error as CoreError, Result as CoreResult, ServiceDefinition};
use servicemanager_win32::{enumerate_descendants, query_service, ProcessInfo};

use crate::requests::{LogTarget, ModalTarget, RecoveryTarget, Request};

// Re-export the canonical spec types from ops so that other GUI modules that
// import `crate::data::InstallSpec` / `EditSpec` / `RecoverySpec` keep working
// without touching their import paths.
pub use servicemanager_ops::{EditSpec, InstallSpec, RecoverySpec};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionKind {
    Start,
    Stop,
    Restart,
    Pause,
    Continue,
    Rotate,
    Remove,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionTarget {
    pub service: String,
    pub kind: ActionKind,
}

/// A unit of work the UI hands to the worker thread.
pub enum Job {
    Refresh,
    Install {
        spec: InstallSpec,
        request: Request<ModalTarget>,
    },
    Edit {
        spec: EditSpec,
        request: Request<ModalTarget>,
    },
    Action(Request<ActionTarget>),
    Processes(Request<ModalTarget>),
    ReadLog(Request<LogTarget>),
    ReadRecovery(Request<RecoveryTarget>),
    SaveRecovery {
        spec: RecoverySpec,
        request: Request<RecoveryTarget>,
    },
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
        request: Request<ModalTarget>,
        result: CoreResult<Vec<ProcessInfo>>,
    },
    /// A privileged action ran (e.g. `Install`). Stash the success message;
    /// the UI shows it in the status bar.
    Acted {
        request: Request<ActionTarget>,
        result: CoreResult<String>,
    },
    /// A tail of a service's stdout/stderr log.
    Log {
        request: Request<LogTarget>,
        status: String,
        lines: Vec<String>,
    },
    /// Outcome of a `SaveRecovery` job — routed to the Recovery view's own
    /// status line. `Ok` carries the success message, `Err` the failure.
    RecoverySaved {
        request: Request<RecoveryTarget>,
        result: CoreResult<String>,
    },
    RecoveryLoaded {
        request: Request<RecoveryTarget>,
        result: CoreResult<RecoverySpec>,
    },
    Installed {
        request: Request<ModalTarget>,
        result: CoreResult<String>,
    },
    Edited {
        request: Request<ModalTarget>,
        result: CoreResult<String>,
    },
    ScanError(CoreError),
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

#[cfg(test)]
pub(crate) fn test_channel(capacity: usize) -> (JobSender, Receiver<Job>) {
    let (inner, receiver) = std::sync::mpsc::sync_channel(capacity);
    (
        JobSender {
            inner,
            pending_refresh: Arc::new(AtomicBool::new(false)),
        },
        receiver,
    )
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
        sender
            .send(Job::Action(Request {
                id: 1,
                target: ActionTarget {
                    service: "svc".into(),
                    kind: ActionKind::Start,
                },
            }))
            .unwrap();

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
            Err(e) => JobResult::ScanError(CoreError::other(format!("enumerate: {e}"))),
        },
        Job::Install { spec, request } => JobResult::Installed {
            request,
            result: servicemanager_ops::install(spec),
        },
        Job::Edit { spec, request } => JobResult::Edited {
            request,
            result: servicemanager_ops::edit(spec),
        },
        Job::Action(request) => {
            let name = &request.target.service;
            let result = match request.target.kind {
                ActionKind::Start => servicemanager_ops::start(name),
                ActionKind::Stop => servicemanager_ops::stop(name),
                ActionKind::Restart => servicemanager_ops::restart(name, 30_000),
                ActionKind::Pause => servicemanager_ops::pause(name),
                ActionKind::Continue => servicemanager_ops::continue_service(name),
                ActionKind::Rotate => servicemanager_ops::rotate(name),
                // GUI always purges managed config and never force-natives.
                ActionKind::Remove => servicemanager_ops::remove(name, false, true),
            };
            JobResult::Acted { request, result }
        }
        Job::Processes(request) => {
            let result = processes(&request.target.service);
            JobResult::Processes { request, result }
        }
        Job::ReadLog(request) => read_log(request),
        Job::ReadRecovery(request) => {
            let result = servicemanager_ops::read_recovery(&request.target.service);
            JobResult::RecoveryLoaded { request, result }
        }
        Job::SaveRecovery { spec, request } => JobResult::RecoverySaved {
            request,
            result: servicemanager_ops::save_recovery(spec),
        },
    }
}

fn processes(name: &str) -> CoreResult<Vec<ProcessInfo>> {
    let snap = query_service(name)?;
    let pid = snap
        .runtime
        .as_ref()
        .and_then(|r| r.pid)
        .ok_or_else(|| CoreError::other(format!("service '{name}' is not running")))?;
    enumerate_descendants(pid)
}

/// Read the tail of a managed service's stdout or stderr log file.
fn read_log(request: Request<LogTarget>) -> JobResult {
    let service = request.target.service.as_str();
    let stderr = request.target.stderr;
    let which = if stderr { "stderr" } else { "stdout" };
    let log = |status: String, lines: Vec<String>| JobResult::Log {
        request: request.clone(),
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
    let field = if stderr { "AppStderr" } else { "AppStdout" };
    if log_needs_service_environment(&cfg, field, &path) {
        return log(
            format!(
                "{which} uses service-environment references. The GUI cannot safely \
                 resolve another service account's environment; open the resolved \
                 log path instead. Configured path: {path}"
            ),
            Vec::new(),
        );
    }
    match tail_file(&path) {
        Ok(lines) => log(
            format!("{which}  ·  {path}  ·  {} lines", lines.len()),
            lines,
        ),
        Err(e) => log(format!("Cannot read {which} log '{path}': {e}"), Vec::new()),
    }
}

fn log_needs_service_environment(
    config: &servicemanager_core::ManagedApplicationConfig,
    field: &str,
    path: &str,
) -> bool {
    if !config.is_expandable_string(field) {
        return false;
    }
    let mut signs = path.match_indices('%');
    while let Some((start, _)) = signs.next() {
        if let Some((end, _)) = signs.next() {
            if end > start + 1 {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod log_context_tests {
    use super::*;

    #[test]
    fn only_marked_paths_with_real_references_require_the_service_environment() {
        let config = servicemanager_core::ManagedApplicationConfig {
            expandable_strings: ["AppStdout".into()].into(),
            ..Default::default()
        };
        assert!(log_needs_service_environment(
            &config,
            "AppStdout",
            r"%HOME%\out.log"
        ));
        assert!(!log_needs_service_environment(
            &config,
            "AppStderr",
            r"%HOME%\out.log"
        ));
        for path in [
            r"C:\logs\out.log",
            r"C:\100%ready.log",
            r"C:\100%%.log",
            r"C:\%%prefix%tail",
        ] {
            assert!(!log_needs_service_environment(&config, "AppStdout", path));
        }
    }
}

/// Read the last ~64 KiB of a file and return up to its last 400 lines.
///
/// Decodes as UTF-8 by default. If the file starts with a UTF-16 BOM
/// (`FF FE` or `FE FF`) the tail is decoded as UTF-16 with the
/// appropriate endianness, aligned to the BOM. A UTF-8 BOM
/// (`EF BB BF`) is recognised but does not change behavior.
fn tail_file(path: &str) -> std::io::Result<Vec<String>> {
    let mut f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    tail_reader(&mut f, len)
}

fn tail_reader(
    reader: &mut (impl std::io::Read + std::io::Seek),
    len: u64,
) -> std::io::Result<Vec<String>> {
    use std::io::{Read, SeekFrom};
    const TAIL: u64 = 64 * 1024;
    reader.seek(SeekFrom::Start(0))?;
    let mut head = Vec::new();
    reader.by_ref().take(len.min(4)).read_to_end(&mut head)?;
    let encoding = detect_encoding(&head);
    let tail = crate::bounded_log::read_tail(
        reader,
        len,
        TAIL,
        matches!(encoding, TailEncoding::Utf16Le | TailEncoding::Utf16Be),
    )?;

    let text = decode_tail(&tail.bytes, encoding);
    let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
    // A mid-file seek leaves the first line truncated — drop it.
    if tail.partial && !lines.is_empty() {
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
        let mut f = tempfile::NamedTempFile::new_in(".").unwrap();
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

    #[test]
    fn application_tail_is_bounded_for_growing_unterminated_input() {
        for len in [10, 128 * 1024] {
            let mut reader = crate::bounded_log::tests::GrowingReader::default();
            let lines = tail_reader(&mut reader, len).unwrap();
            assert_eq!(reader.read, len.min(4) + len.min(64 * 1024));
            assert!(lines.len() <= 1);
        }
    }

    #[test]
    fn application_tail_handles_empty_truncated_and_four_hundred_lines() {
        use std::io::Cursor;
        assert!(tail_reader(&mut Cursor::new(b""), 0).unwrap().is_empty());
        assert_eq!(
            tail_reader(&mut Cursor::new(b"short\n"), 40).unwrap(),
            ["short"]
        );
        let bytes = (0..600)
            .map(|i| format!("line {i}\n"))
            .collect::<String>()
            .into_bytes();
        let len = bytes.len() as u64;
        let lines = tail_reader(&mut Cursor::new(bytes), len).unwrap();
        assert_eq!(lines.len(), 400);
        assert_eq!(lines[0], "line 200");
        assert_eq!(lines[399], "line 599");
    }

    #[test]
    fn large_utf16_tail_preserves_code_unit_alignment() {
        use std::io::Cursor;
        for encoding in [TailEncoding::Utf16Le, TailEncoding::Utf16Be] {
            let mut bytes = match encoding {
                TailEncoding::Utf16Le => vec![0xff, 0xfe],
                _ => vec![0xfe, 0xff],
            };
            for unit in ("prefix\n".repeat(10_000) + "last \u{1f600}\n").encode_utf16() {
                bytes.extend_from_slice(&match encoding {
                    TailEncoding::Utf16Le => unit.to_le_bytes(),
                    _ => unit.to_be_bytes(),
                });
            }
            let len = bytes.len() as u64;
            let lines = tail_reader(&mut Cursor::new(bytes), len).unwrap();
            assert_eq!(lines.last().unwrap(), "last \u{1f600}");
            assert_eq!(lines.len(), 400);
        }
    }
}
