//! Log rotation: offline rotation helper, online [`RotationSink`], and the
//! pipe-reader thread that feeds the sink.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use servicemanager_core::{IoStream, LogRotationConfig};
use time::format_description::FormatItem;
use time::macros::format_description;
use time::OffsetDateTime;

use crate::SupervisorError;

const STAMP_FMT: &[FormatItem<'_>] =
    format_description!("[year][month][day]-[hour][minute][second]");

/// Offline rotation: if rotation is enabled and the existing log file is
/// over the configured size or older than the configured seconds, rename it
/// to `<stem>.<YYYYMMDD-HHMMSS>[.<ext>]`. Failures are logged but never
/// propagated — a missing rotation must not block service start.
pub(crate) fn maybe_rotate(path: &Path, rotation: &LogRotationConfig) {
    if rotation.enabled != Some(true) {
        return;
    }
    let metadata = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return, // file does not exist yet — nothing to rotate
    };
    let size = metadata.len();
    let age = metadata.modified().ok().and_then(|t| t.elapsed().ok());

    let mut should_rotate = false;
    if let Some(threshold) = rotation.bytes {
        if threshold > 0 && size >= threshold {
            should_rotate = true;
        }
    }
    if let (Some(secs), Some(age)) = (rotation.seconds, age) {
        if secs > 0 && age.as_secs() >= secs as u64 {
            should_rotate = true;
        }
    }
    if !should_rotate {
        return;
    }

    let rotated = build_rotated_name(path);
    if let Err(e) = std::fs::rename(path, &rotated) {
        eprintln!(
            "[supervisor] rotate {} -> {} failed: {e}",
            path.display(),
            rotated.display()
        );
    }
}

/// Pick a rotated log file name that does not already exist.
///
/// The base name is `<stem>.<YYYYMMDD-HHMMSS>[.<ext>]`. Because the stamp is
/// only second-resolution, two rotations within the same second would
/// otherwise collide and the second rename would silently clobber the first;
/// a `-<n>` counter is appended until a free name is found.
pub(crate) fn build_rotated_name(path: &Path) -> PathBuf {
    let now = OffsetDateTime::now_utc();
    let stamp_str = now
        .format(&STAMP_FMT)
        .unwrap_or_else(|_| String::from("19700101-000000"));

    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "log".to_string());
    let ext = path
        .extension()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();

    let make = |suffix: &str| -> PathBuf {
        let name = match (ext.is_empty(), suffix.is_empty()) {
            (true, true) => format!("{stem}.{stamp_str}"),
            (false, true) => format!("{stem}.{stamp_str}.{ext}"),
            (true, false) => format!("{stem}.{stamp_str}{suffix}"),
            (false, false) => format!("{stem}.{stamp_str}{suffix}.{ext}"),
        };
        path.with_file_name(name)
    };

    let first = make("");
    if !first.exists() {
        return first;
    }
    for n in 1..=9999 {
        let candidate = make(&format!("-{n}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    first
}

/// Owns the destination log file when online rotation is enabled. Each
/// write goes through the mutex so the supervisor's `Rotate` thread can
/// safely swap the underlying file out without racing the reader.
pub struct RotationSink {
    state: Mutex<RotationState>,
}

struct RotationState {
    path: PathBuf,
    file: File,
    bytes_in_current: u64,
    opened_at: Instant,
    config: LogRotationConfig,
}

impl RotationSink {
    pub(crate) fn open(
        stream: &IoStream,
        config: LogRotationConfig,
    ) -> Result<Self, SupervisorError> {
        let path = PathBuf::from(&stream.path);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    eprintln!("[supervisor] cannot create log dir {parent:?}: {e}");
                }
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| SupervisorError::OpenLog(path.clone(), e))?;
        let bytes_in_current = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self {
            state: Mutex::new(RotationState {
                path,
                file,
                bytes_in_current,
                opened_at: Instant::now(),
                config,
            }),
        })
    }

    pub(crate) fn write(&self, buf: &[u8]) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        state.file.write_all(buf)?;
        state.bytes_in_current = state.bytes_in_current.saturating_add(buf.len() as u64);
        if state.should_rotate() {
            // A rotation failure is recoverable: `rotate()` always leaves the
            // real log reopened, so writes keep flowing. Log it but do not
            // propagate — propagating would break the pipe-reader loop and
            // permanently stop copying this stream.
            if let Err(e) = state.rotate() {
                eprintln!("[supervisor] online log rotation failed (continuing): {e}");
            }
        }
        Ok(())
    }

    pub(crate) fn force_rotate(&self) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        state.rotate()
    }
}

impl RotationState {
    fn should_rotate(&self) -> bool {
        if let Some(threshold) = self.config.bytes {
            if threshold > 0 && self.bytes_in_current >= threshold {
                return true;
            }
        }
        if let Some(secs) = self.config.seconds {
            if secs > 0 && self.opened_at.elapsed().as_secs() >= secs as u64 {
                return true;
            }
        }
        false
    }

    fn rotate(&mut self) -> io::Result<()> {
        let rotated = build_rotated_name(&self.path);
        // Flush the current file before rename — required on Windows.
        self.file.sync_all().ok();
        let scratch = scratch_path(&self.path);
        // Point `self.file` at a scratch file so the OS releases the real log
        // handle, then rename the log aside.
        let rename_result = (|| -> io::Result<()> {
            let tmp = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&scratch)
                .or_else(|_| File::create(&scratch))?;
            let _ = std::mem::replace(&mut self.file, tmp);
            std::fs::rename(&self.path, &rotated)
        })();
        // Reopen the real log file regardless of whether the rename
        // succeeded, so the stream never gets stuck writing to the scratch
        // file. A failed rotation is thus recoverable — writes simply
        // continue to the (un-rotated) log.
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.bytes_in_current = self.file.metadata().map(|m| m.len()).unwrap_or(0);
        self.opened_at = Instant::now();
        let _ = std::fs::remove_file(&scratch);
        rename_result
    }
}

/// Scratch path used as a placeholder while the old log handle is released
/// for the rename. Kept in the log file's *own* directory so rotation does
/// not depend on the process temp directory being writable, on the same
/// volume, or sharing the log directory's ACLs.
fn scratch_path(log_path: &Path) -> PathBuf {
    let name = format!(".ngsm-rotate-scratch-{}.tmp", std::process::id());
    match log_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        Some(dir) => dir.join(name),
        None => PathBuf::from(name),
    }
}

/// Reader thread that streams a child's stdio into a [`RotationSink`].
/// Exits when the pipe reports EOF (i.e. the child closed its end).
pub(crate) fn pipe_reader_loop(
    service_name: String,
    label: String,
    mut reader: os_pipe::PipeReader,
    sink: Arc<RotationSink>,
) {
    let mut buf = vec![0u8; 8 * 1024];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if let Err(e) = sink.write(&buf[..n]) {
                    eprintln!("[supervisor:{service_name}] sink-write {label} failed: {e}");
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
}
