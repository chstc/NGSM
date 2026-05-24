//! Log rotation: offline rotation helper, online [`RotationSink`], and the
//! pipe-reader thread that feeds the sink.

use std::collections::HashMap;
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

/// Normalize a configured log path into a stable dedup key.
///
/// The two configured streams may target *the same* underlying file written
/// with two different but equivalent path strings (different case on Windows,
/// mixed `/` vs `\`, a trailing dot, etc.). If the file has not yet been
/// created we cannot `canonicalize` it, so this falls back to a string-level
/// normalization that is safe to compute pre-creation:
///
/// * On Windows: lowercase the path and convert `/` to `\`. NTFS / FAT are
///   case-insensitive, so equivalent paths fold to the same key.
/// * Elsewhere: return the path unchanged (POSIX is case-sensitive).
fn dedup_key(path: &str) -> String {
    if cfg!(windows) {
        path.replace('/', "\\").to_ascii_lowercase()
    } else {
        path.to_string()
    }
}

/// Output of [`dedup_sinks`]: per-stream sink handle plus the deduplicated
/// `Vec` of unique underlying sinks.
pub(crate) type DedupSinks = (
    Option<Arc<RotationSink>>,
    Option<Arc<RotationSink>>,
    Vec<Arc<RotationSink>>,
);

/// Build at most one [`RotationSink`] per unique log path, sharing the
/// resulting `Arc` between `stdout` and `stderr` when they target the same
/// file. Two independent sinks would each own a separate file handle, byte
/// counter, and rotation state; if both streams write to the same path the
/// second sink would silently race the first on every rotation
/// (misplaced records, failed renames, inaccurate byte thresholds).
///
/// Returns `(stdout_sink, stderr_sink, unique_sinks)`. `unique_sinks` is the
/// deduplicated list the caller must keep alive (pushed into
/// `Supervisor::sinks`) so on-demand `Rotate` operates on each underlying
/// sink exactly once.
pub(crate) fn dedup_sinks(
    stdout: Option<&IoStream>,
    stderr: Option<&IoStream>,
    config: &LogRotationConfig,
) -> Result<DedupSinks, SupervisorError> {
    let mut by_key: HashMap<String, Arc<RotationSink>> = HashMap::new();
    let mut unique: Vec<Arc<RotationSink>> = Vec::new();

    let mut resolve =
        |maybe: Option<&IoStream>| -> Result<Option<Arc<RotationSink>>, SupervisorError> {
            let Some(stream) = maybe else { return Ok(None) };
            let key = dedup_key(&stream.path);
            if let Some(existing) = by_key.get(&key) {
                return Ok(Some(Arc::clone(existing)));
            }
            let sink = Arc::new(RotationSink::open(stream, config.clone())?);
            by_key.insert(key, Arc::clone(&sink));
            unique.push(Arc::clone(&sink));
            Ok(Some(sink))
        };

    let out = resolve(stdout)?;
    let err = resolve(stderr)?;
    Ok((out, err, unique))
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn stream(path: &Path) -> IoStream {
        IoStream {
            path: path.to_string_lossy().into_owned(),
            share_mode: None,
            creation_disposition: None,
            flags_and_attributes: None,
            copy_and_truncate: None,
        }
    }

    fn rotation_at(bytes: u64) -> LogRotationConfig {
        LogRotationConfig {
            enabled: Some(true),
            online: Some(1),
            bytes: Some(bytes),
            ..Default::default()
        }
    }

    #[test]
    fn dedup_returns_distinct_sinks_for_distinct_paths() {
        let dir = tempdir().unwrap();
        let out_path = dir.path().join("out.log");
        let err_path = dir.path().join("err.log");
        let cfg = LogRotationConfig::default();

        let (out, err, unique) =
            dedup_sinks(Some(&stream(&out_path)), Some(&stream(&err_path)), &cfg).unwrap();

        let out = out.expect("stdout sink");
        let err = err.expect("stderr sink");
        assert!(
            !Arc::ptr_eq(&out, &err),
            "distinct paths must not share a sink"
        );
        assert_eq!(unique.len(), 2, "two unique sinks expected");
    }

    #[test]
    fn dedup_shares_sink_when_stdout_and_stderr_match() {
        let dir = tempdir().unwrap();
        let shared = dir.path().join("combined.log");
        let cfg = LogRotationConfig::default();

        let (out, err, unique) =
            dedup_sinks(Some(&stream(&shared)), Some(&stream(&shared)), &cfg).unwrap();

        let out = out.expect("stdout sink");
        let err = err.expect("stderr sink");
        assert!(
            Arc::ptr_eq(&out, &err),
            "identical paths must share the same Arc<RotationSink>"
        );
        assert_eq!(
            unique.len(),
            1,
            "only one underlying sink should be tracked for rotation"
        );
    }

    #[test]
    #[cfg(windows)]
    fn dedup_folds_windows_case_and_separator_variants() {
        let dir = tempdir().unwrap();
        let canonical = dir.path().join("combined.log");
        // Force a string-level mismatch that is path-equivalent on Windows:
        // lowercase the parent and swap one separator. Both must dedup.
        let raw = canonical.to_string_lossy().into_owned();
        let twisted = raw.replace('\\', "/").to_uppercase();
        let cfg = LogRotationConfig::default();

        let a = IoStream {
            path: raw,
            share_mode: None,
            creation_disposition: None,
            flags_and_attributes: None,
            copy_and_truncate: None,
        };
        let b = IoStream {
            path: twisted,
            share_mode: None,
            creation_disposition: None,
            flags_and_attributes: None,
            copy_and_truncate: None,
        };
        let (out, err, unique) = dedup_sinks(Some(&a), Some(&b), &cfg).unwrap();
        let out = out.unwrap();
        let err = err.unwrap();
        assert!(Arc::ptr_eq(&out, &err));
        assert_eq!(unique.len(), 1);
    }

    #[test]
    fn same_path_stdout_stderr_share_sink_state() {
        // Regression for finding #11: when stdout and stderr point at the
        // same log file, the second writer must observe rotations performed
        // by the first writer (same handle, same byte counter, same state).
        // Two independent sinks would each keep an old handle, so the second
        // writer would race the first and silently lose records.
        let dir = tempdir().unwrap();
        let shared = dir.path().join("shared.log");

        // Threshold at 8 bytes so a single 16-byte write triggers rotation.
        let cfg = rotation_at(8);
        let (out, err, unique) =
            dedup_sinks(Some(&stream(&shared)), Some(&stream(&shared)), &cfg).unwrap();
        let out = out.unwrap();
        let err = err.unwrap();
        assert!(Arc::ptr_eq(&out, &err), "must share the same sink");
        assert_eq!(unique.len(), 1);

        // First writer crosses the threshold and triggers a rotation. After
        // this, `shared.log` exists fresh and the rotated file sits alongside.
        out.write(b"AAAAAAAAAAAAAAAA").unwrap();

        // List rotated siblings *before* the second writer runs so the count
        // is unambiguous.
        let rotated_before: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let n = e.file_name();
                let n = n.to_string_lossy();
                n.starts_with("shared.") && n != "shared.log"
            })
            .collect();
        assert_eq!(
            rotated_before.len(),
            1,
            "first write should have produced exactly one rotated file"
        );

        // Second writer reuses the SAME sink (shared Arc), so its write goes
        // to the post-rotation `shared.log`, not to a stale handle pointing
        // at the rotated file.
        err.write(b"BB").unwrap();

        let post_rotation = std::fs::read(&shared).unwrap();
        assert_eq!(
            post_rotation, b"BB",
            "second writer's bytes must land in the post-rotation file"
        );

        // The rotated file must still hold *only* the first writer's bytes.
        let rotated_path = rotated_before[0].path();
        let rotated = std::fs::read(&rotated_path).unwrap();
        assert_eq!(
            rotated, b"AAAAAAAAAAAAAAAA",
            "rotated file should contain the pre-rotation bytes only"
        );

        // And no new rotation should have been triggered by the 2-byte write.
        let rotated_after: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let n = e.file_name();
                let n = n.to_string_lossy();
                n.starts_with("shared.") && n != "shared.log"
            })
            .collect();
        assert_eq!(rotated_after.len(), 1);
    }
}
