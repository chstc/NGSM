//! Background worker for the UI thread.
//!
//! Win32 calls (SCM enumerate, registry read, install, etc.) can take
//! tens to hundreds of milliseconds; running them on the UI thread would
//! freeze the frame. We send `Job`s to a worker and post `JobResult`s
//! back, calling a `wake` callback after each so the UI drains them promptly.

use std::sync::mpsc::{Receiver, Sender};
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
    Install(InstallSpec),
    Edit(EditSpec),
    Start(String),
    Stop(String),
    Restart(String),
    Pause(String),
    Continue(String),
    Rotate(String),
    Remove(String),
    Processes(String),
    ReadLog { service: String, stderr: bool },
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
    /// Outcome of an `Install` job — routed back to the Install dialog.
    Installed(Result<String, String>),
    /// Outcome of an `Edit` job — routed back to the Edit dialog.
    Edited(Result<String, String>),
    Error(String),
}

/// Spawn the worker thread. Returns the job sender; results land on
/// `result_tx`. The worker calls `wake` after each result so the UI thread
/// can drain and apply them.
pub fn spawn_worker(result_tx: Sender<JobResult>, wake: Box<dyn Fn() + Send>) -> Sender<Job> {
    let (job_tx, job_rx) = std::sync::mpsc::channel::<Job>();
    thread::spawn(move || worker_loop(job_rx, result_tx, wake));
    job_tx
}

fn worker_loop(rx: Receiver<Job>, tx: Sender<JobResult>, wake: Box<dyn Fn() + Send>) {
    while let Ok(job) = rx.recv() {
        let result = execute(job);
        let _ = tx.send(result);
        wake();
    }
}

fn execute(job: Job) -> JobResult {
    match job {
        Job::Refresh => match servicemanager_ops::list_services() {
            Ok((defs, warnings)) => JobResult::Services {
                defs,
                warnings,
                events: crate::event_log_reader::read_recent(50),
            },
            Err(e) => JobResult::Error(format!("enumerate: {e}")),
        },
        Job::Install(spec) => JobResult::Installed(servicemanager_ops::install(spec)),
        Job::Edit(spec) => JobResult::Edited(servicemanager_ops::edit(spec)),
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
        Job::Restart(n) => match servicemanager_ops::restart(&n) {
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
