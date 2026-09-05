//! One rotation owner per actual file. A missing handle is a recoverable
//! reopen state, never a successful write into disposable scratch storage.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use servicemanager_core::{IoStream, LogRotationConfig};
use time::format_description::FormatItem;
use time::macros::format_description;
use time::OffsetDateTime;

use crate::SupervisorError;

const STAMP_FMT: &[FormatItem<'_>] =
    format_description!("[year][month][day]-[hour][minute][second]");

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
    rotation_queued: AtomicBool,
    identity: FileIdentity,
    options: IoStream,
    canonical: PathBuf,
}

struct RotationState {
    path: PathBuf,
    file: Option<File>,
    bytes_in_current: u64,
    opened_at: Instant,
    config: LogRotationConfig,
    stream: IoStream,
    io: Arc<dyn RotationIo>,
}

pub(crate) trait RotationIo: Send + Sync {
    fn reopen(&self, path: &Path, stream: &IoStream) -> io::Result<File>;
    fn rename(&self, path: &Path, archive: &Path) -> io::Result<()>;
    fn write(&self, file: &mut File, bytes: &[u8]) -> io::Result<usize> {
        file.write(bytes)
    }
    fn copy_archive(
        &self,
        path: &Path,
        archive: &Path,
        cancelled: &dyn Fn() -> bool,
    ) -> io::Result<()> {
        let mut source = File::open(path)?;
        let mut destination = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(archive)?;
        let result = (|| {
            let mut buffer = [0u8; 64 * 1024];
            loop {
                if cancelled() {
                    return Err(io::ErrorKind::Interrupted.into());
                }
                let count = source.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                destination.write_all(&buffer[..count])?;
            }
            destination.sync_all()
        })();
        if let Err(error) = result {
            drop(destination);
            let _ = std::fs::remove_file(archive);
            return Err(error);
        }
        Ok(())
    }
}

fn log_path_text(path: &Path) -> io::Result<&str> {
    path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "canonical log path contains invalid Unicode and cannot be reopened losslessly",
        )
    })
}

pub(crate) struct FileIo;
impl RotationIo for FileIo {
    fn reopen(&self, path: &Path, stream: &IoStream) -> io::Result<File> {
        let mut stream = stream.clone();
        stream.path = log_path_text(path)?.to_owned();
        // Creation disposition is a one-time launch instruction, never a reason
        // to retruncate or reject the existing log during error recovery.
        stream.creation_disposition = Some(4);
        open_output(&stream)
    }

    fn rename(&self, path: &Path, archive: &Path) -> io::Result<()> {
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            use windows::core::PCWSTR;
            use windows::Win32::Storage::FileSystem::{MoveFileExW, MOVE_FILE_FLAGS};
            let source: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            let target: Vec<u16> = archive.as_os_str().encode_wide().chain(Some(0)).collect();
            // SAFETY: both paths are terminated. Omitting REPLACE_EXISTING protects archives.
            unsafe {
                MoveFileExW(
                    PCWSTR(source.as_ptr()),
                    PCWSTR(target.as_ptr()),
                    MOVE_FILE_FLAGS(0),
                )
            }
            .map_err(io::Error::other)
        }
        #[cfg(not(windows))]
        {
            std::fs::hard_link(path, archive)?;
            std::fs::remove_file(path)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileIdentity(u64, u64);

fn identity(file: &File) -> io::Result<(FileIdentity, u64)> {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Storage::FileSystem::{
            GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        };
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: file owns the handle and info is a valid output structure.
        unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut info) }
            .map_err(io::Error::other)?;
        Ok((
            FileIdentity(
                u64::from(info.dwVolumeSerialNumber),
                (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
            ),
            u64::from(info.nNumberOfLinks),
        ))
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        Ok((
            FileIdentity(metadata.dev(), metadata.ino()),
            metadata.nlink(),
        ))
    }
}

fn existing_identity(path: &Path) -> io::Result<Option<(FileIdentity, u64)>> {
    let mut options = OpenOptions::new();
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.access_mode(0);
    }
    #[cfg(not(windows))]
    options.read(true);
    match options.open(path) {
        Ok(file) => Ok(Some(identity(&file)?)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn same_options(left: &IoStream, right: &IoStream) -> bool {
    let flags = |value: Option<u32>| value.filter(|&value| value != 0).unwrap_or(0x80);
    left.share_mode.unwrap_or(7) == right.share_mode.unwrap_or(7)
        && left.creation_disposition.unwrap_or(4) == right.creation_disposition.unwrap_or(4)
        && flags(left.flags_and_attributes) == flags(right.flags_and_attributes)
        && left.copy_and_truncate.unwrap_or(false) == right.copy_and_truncate.unwrap_or(false)
}

pub(crate) fn validate_output(stream: &IoStream, rotation: &LogRotationConfig) -> io::Result<()> {
    let path = stream.path.strip_prefix("\\\\?\\").unwrap_or(&stream.path);
    let after_drive = if path.as_bytes().get(1) == Some(&b':') {
        &path[2..]
    } else {
        path
    };
    if after_drive.contains(':') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "alternate data stream log paths are unsupported; use a regular file",
        ));
    }
    validate_open_options(stream)?;
    if stream
        .creation_disposition
        .is_some_and(|mode| !(1..=5).contains(&mode))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid output creation disposition",
        ));
    }
    if matches!(stream.creation_disposition, Some(2 | 5))
        && (rotation.enabled == Some(true) || stream.copy_and_truncate == Some(true))
    {
        return Err(io::Error::new(io::ErrorKind::InvalidInput,
            "destructive creation dispositions cannot be combined with log rotation/CopyAndTruncate"));
    }
    Ok(())
}

fn validate_open_options(stream: &IoStream) -> io::Result<()> {
    if stream.share_mode.is_some_and(|mode| mode & !7 != 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported stream sharing bits",
        ));
    }
    let unsupported = 0x4000_0000 | 0x2000_0000 | 0x0400_0000 | 0x0020_0000;
    if stream.flags_and_attributes.unwrap_or(0) & unsupported != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput,
            "overlapped, unbuffered, delete-on-close and open-reparse-point stream flags are unsupported"));
    }
    Ok(())
}

fn apply_open_options(options: &mut OpenOptions, stream: &IoStream) {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(stream.share_mode.unwrap_or(7));
        options.attributes(0);
        options.custom_flags(stream.flags_and_attributes.unwrap_or(0x80));
    }
    #[cfg(not(windows))]
    let _ = (options, stream);
}

pub(crate) fn open_output(stream: &IoStream) -> io::Result<File> {
    validate_open_options(stream)?;
    let path = Path::new(&stream.path);
    if matches!(stream.creation_disposition.unwrap_or(4), 1 | 2 | 4) {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut options = OpenOptions::new();
    match stream.creation_disposition.unwrap_or(4) {
        1 => {
            options.append(true).create_new(true);
        }
        2 => {
            options.write(true).create(true).truncate(true);
        }
        3 => {
            options.append(true);
        }
        4 => {
            options.append(true).create(true);
        }
        5 => {
            options.write(true).truncate(true);
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid stream creation disposition",
            ))
        }
    }
    apply_open_options(&mut options, stream);
    options.open(path)
}

pub(crate) fn validate_input(stream: &IoStream) -> io::Result<()> {
    validate_open_options(stream)?;
    if stream.creation_disposition.is_some_and(|mode| mode != 3)
        || stream.copy_and_truncate == Some(true)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "stdin supports only read-only OPEN_EXISTING, without CopyAndTruncate",
        ));
    }
    Ok(())
}

pub(crate) fn open_input(stream: &IoStream) -> io::Result<File> {
    validate_input(stream)?;
    let mut options = OpenOptions::new();
    options.read(true);
    apply_open_options(&mut options, stream);
    options.open(&stream.path)
}

impl RotationSink {
    pub(crate) fn open(
        stream: &IoStream,
        config: LogRotationConfig,
    ) -> Result<Self, SupervisorError> {
        Self::open_with_io(stream, config, Arc::new(FileIo))
    }

    pub(crate) fn open_with_io(
        stream: &IoStream,
        config: LogRotationConfig,
        io: Arc<dyn RotationIo>,
    ) -> Result<Self, SupervisorError> {
        let path = PathBuf::from(&stream.path);
        validate_output(stream, &config)?;
        let file = open_output(stream).map_err(|e| SupervisorError::OpenLog(path.clone(), e))?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(SupervisorError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "output redirection currently requires a regular file",
            )));
        }
        let (identity, links) = identity(&file)?;
        if links > 1 && config.enabled == Some(true) {
            return Err(SupervisorError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "rotation of hard-linked log files is unsupported",
            )));
        }
        let canonical = std::fs::canonicalize(&path)?;
        log_path_text(&canonical)?;
        let bytes_in_current = metadata.len();
        Ok(Self {
            state: Mutex::new(RotationState {
                path: canonical.clone(),
                file: Some(file),
                bytes_in_current,
                opened_at: Instant::now(),
                config,
                stream: stream.clone(),
                io,
            }),
            rotation_queued: AtomicBool::new(false),
            identity,
            options: stream.clone(),
            canonical,
        })
    }

    #[cfg(test)]
    pub(crate) fn write(&self, buf: &[u8]) -> io::Result<()> {
        let mut remaining = buf;
        while !remaining.is_empty() {
            let n = self.write_some(remaining, &|| false)?;
            if n == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            remaining = &remaining[n..];
        }
        if self.due(false)? {
            self.force_rotate()?;
        }
        Ok(())
    }

    pub(crate) fn write_some(
        &self,
        bytes: &[u8],
        cancelled: &dyn Fn() -> bool,
    ) -> io::Result<usize> {
        let mut state = self.lock(cancelled)?;
        if state.file.is_none() {
            let file = state.io.reopen(&state.path, &state.stream)?;
            state.bytes_in_current = file.metadata()?.len();
            state.opened_at = Instant::now();
            state.file = Some(file);
        }
        let io = Arc::clone(&state.io);
        let n = io.write(state.file.as_mut().unwrap(), bytes)?;
        state.bytes_in_current = state.bytes_in_current.saturating_add(n as u64);
        Ok(n)
    }

    fn lock(&self, cancelled: &dyn Fn() -> bool) -> io::Result<MutexGuard<'_, RotationState>> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if cancelled() {
                return Err(io::ErrorKind::Interrupted.into());
            }
            match self.state.try_lock() {
                Ok(guard) => return Ok(guard),
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    return Err(io::Error::other("log sink state poisoned"))
                }
                Err(std::sync::TryLockError::WouldBlock) => {}
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "log sink is busy"));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    pub(crate) fn child_stdio(&self) -> io::Result<std::process::Stdio> {
        let state = self.lock(&|| false)?;
        Ok(std::process::Stdio::from(
            state
                .file
                .as_ref()
                .ok_or_else(|| io::Error::other("log is awaiting recovery"))?
                .try_clone()?,
        ))
    }

    pub(crate) fn due(&self, offline: bool) -> io::Result<bool> {
        let state = self.lock(&|| false)?;
        if offline {
            let metadata = std::fs::metadata(&state.path)?;
            let age = metadata
                .modified()
                .ok()
                .and_then(|t| t.elapsed().ok())
                .unwrap_or_default();
            Ok(state.should_rotate_for(metadata.len(), age))
        } else {
            Ok(state.should_rotate())
        }
    }

    pub(crate) fn has_data(&self) -> io::Result<bool> {
        Ok(self.lock(&|| false)?.bytes_in_current > 0)
    }

    pub(crate) fn queue_rotation(&self) -> bool {
        !self.rotation_queued.swap(true, Ordering::AcqRel)
    }

    pub(crate) fn rotation_handled(&self) {
        self.rotation_queued.store(false, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn force_rotate(&self) -> io::Result<()> {
        self.rotate(&|| false).map(|_| ())
    }

    pub(crate) fn rotate(&self, cancelled: &dyn Fn() -> bool) -> io::Result<Option<PathBuf>> {
        let mut state = self.lock(cancelled)?;
        if state.bytes_in_current == 0 {
            return Ok(None);
        }
        let result = state.rotate(cancelled);
        self.rotation_handled();
        result
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
    // Diagnose all options before a destructive initial open can affect either stream.
    for stream in [stdout, stderr].into_iter().flatten() {
        validate_output(stream, config)?;
    }
    if let (Some(out), Some(err)) = (stdout, stderr) {
        if let (Some((out_id, links)), Some((err_id, _))) = (
            existing_identity(Path::new(&out.path))?,
            existing_identity(Path::new(&err.path))?,
        ) {
            if out_id == err_id {
                if !same_options(out, err) {
                    return Err(SupervisorError::Io(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "stdout/stderr sharing one file have conflicting open/rotation options",
                    )));
                }
                if links > 1
                    && std::fs::canonicalize(&out.path)? != std::fs::canonicalize(&err.path)?
                {
                    return Err(SupervisorError::Io(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "distinct hard-link log aliases cannot share a destination",
                    )));
                }
            }
        }
    }
    let mut unique: Vec<Arc<RotationSink>> = Vec::new();

    let mut resolve =
        |maybe: Option<&IoStream>| -> Result<Option<Arc<RotationSink>>, SupervisorError> {
            let Some(stream) = maybe else { return Ok(None) };
            validate_output(stream, config)?;
            if let Some((key, links)) = existing_identity(Path::new(&stream.path))? {
                if let Some(existing) = unique.iter().find(|sink| sink.identity == key) {
                    if !same_options(&existing.options, stream) {
                        return Err(SupervisorError::Io(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "stdout/stderr sharing one file have conflicting open/rotation options",
                        )));
                    }
                    let canonical = std::fs::canonicalize(&stream.path)?;
                    if canonical != existing.canonical && links > 1 {
                        return Err(SupervisorError::Io(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "distinct hard-link log aliases cannot share a rotation destination",
                        )));
                    }
                    return Ok(Some(Arc::clone(existing)));
                }
            }
            let sink = Arc::new(RotationSink::open(stream, config.clone())?);
            unique.push(Arc::clone(&sink));
            Ok(Some(sink))
        };

    let out = resolve(stdout)?;
    let err = resolve(stderr)?;
    Ok((out, err, unique))
}

impl RotationState {
    fn should_rotate(&self) -> bool {
        self.should_rotate_for(self.bytes_in_current, self.opened_at.elapsed())
    }

    fn should_rotate_for(&self, bytes: u64, age: Duration) -> bool {
        if self.config.enabled != Some(true) || bytes == 0 {
            return false;
        }
        if let Some(threshold) = self.config.bytes {
            if threshold > 0 && bytes >= threshold {
                return true;
            }
        }
        if let Some(secs) = self.config.seconds {
            if secs > 0 && age.as_secs() >= secs as u64 {
                return true;
            }
        }
        false
    }

    fn rotate(&mut self, cancelled: &dyn Fn() -> bool) -> io::Result<Option<PathBuf>> {
        let rotated = build_rotated_name(&self.path);
        if cancelled() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        if let Some(file) = &self.file {
            file.sync_all()?;
        }
        drop(self.file.take());
        let rotate_result = if self.stream.copy_and_truncate == Some(true) {
            self.copy_and_truncate(&rotated, cancelled)
        } else if cancelled() {
            Err(io::ErrorKind::Interrupted.into())
        } else {
            self.io.rename(&self.path, &rotated)
        };
        if cancelled() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let reopen = self.io.reopen(&self.path, &self.stream);
        match reopen {
            Ok(file) => {
                self.bytes_in_current = file.metadata()?.len();
                self.file = Some(file);
                if rotate_result.is_ok() {
                    self.opened_at = Instant::now();
                }
            }
            Err(e) => {
                // Future write_some calls retry the active destination. No write
                // can succeed until a real destination handle is available.
                return Err(e);
            }
        }
        rotate_result.map(|_| Some(rotated))
    }

    fn copy_and_truncate(&self, archive: &Path, cancelled: &dyn Fn() -> bool) -> io::Result<()> {
        self.io.copy_archive(&self.path, archive, cancelled)?;
        if cancelled() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let mut options = OpenOptions::new();
        options.write(true);
        apply_open_options(&mut options, &self.stream);
        // The complete archive is durable before the original file is shortened.
        options.open(&self.path)?.set_len(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_only_output_modes_do_not_create_missing_parent_directories() {
        let directory = tempfile::tempdir().unwrap();
        for disposition in [3, 5] {
            let parent = directory.path().join(format!("missing-{disposition}"));
            let mut output = stream(&parent.join("output.log"));
            output.creation_disposition = Some(disposition);
            assert!(open_output(&output).is_err());
            assert!(
                !parent.exists(),
                "existing-only opening must not create directories"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn canonical_log_paths_are_never_reopened_with_lossy_unicode() {
        use std::os::windows::ffi::OsStringExt;
        let invalid = PathBuf::from(std::ffi::OsString::from_wide(&[b'x' as u16, 0xd800]));
        assert_eq!(
            log_path_text(&invalid).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let valid = Path::new("C:\\logs\\literal-\u{fffd}.log");
        assert_eq!(
            log_path_text(valid).unwrap(),
            "C:\\logs\\literal-\u{fffd}.log"
        );
    }
    use std::io::{Read, Seek, SeekFrom};
    use std::sync::atomic::AtomicUsize;
    use tempfile::tempdir;

    struct FaultIo {
        reopen_failures: AtomicUsize,
        rename_failure: AtomicBool,
        copy_failure: AtomicBool,
    }
    impl FaultIo {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                reopen_failures: AtomicUsize::new(0),
                rename_failure: AtomicBool::new(false),
                copy_failure: AtomicBool::new(false),
            })
        }
    }
    impl RotationIo for FaultIo {
        fn reopen(&self, path: &Path, stream: &IoStream) -> io::Result<File> {
            if self
                .reopen_failures
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "injected reopen failure",
                ));
            }
            FileIo.reopen(path, stream)
        }
        fn rename(&self, path: &Path, archive: &Path) -> io::Result<()> {
            if self.rename_failure.load(Ordering::Acquire) {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "injected rename failure",
                ))
            } else {
                FileIo.rename(path, archive)
            }
        }
        fn copy_archive(
            &self,
            path: &Path,
            archive: &Path,
            cancelled: &dyn Fn() -> bool,
        ) -> io::Result<()> {
            if self.copy_failure.load(Ordering::Acquire) {
                Err(io::Error::other("injected archive copy failure"))
            } else {
                FileIo.copy_archive(path, archive, cancelled)
            }
        }
    }

    fn stream(path: &Path) -> IoStream {
        IoStream {
            path: path.to_string_lossy().into_owned(),
            share_mode: None,
            creation_disposition: None,
            flags_and_attributes: None,
            copy_and_truncate: None,
        }
    }

    #[test]
    fn dot_segment_aliases_share_one_active_rotation_destination() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("shared.log");
        let alias = dir.path().join(".").join("shared.log");
        let stdout = stream(&path);
        let stderr = stream(&alias);
        let config = LogRotationConfig {
            enabled: Some(true),
            online: Some(1),
            ..Default::default()
        };
        let (out, err, unique) = dedup_sinks(Some(&stdout), Some(&stderr), &config).unwrap();
        let out = out.unwrap();
        let err = err.unwrap();
        assert_eq!(
            unique.len(),
            1,
            "one physical log must have one rotation owner"
        );
        assert!(Arc::ptr_eq(&out, &err));
        out.write(b"before rotation\n").unwrap();
        out.force_rotate().unwrap();
        err.write(b"after rotation\n").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"after rotation\n");
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
    fn failed_reopen_never_acknowledges_scratch_writes_and_recovers_without_loss() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("output.log");
        let faults = FaultIo::new();
        let sink =
            RotationSink::open_with_io(&stream(&path), rotation_at(0), faults.clone()).unwrap();
        assert_eq!(sink.write_some(b"before", &|| false).unwrap(), 6);
        faults.reopen_failures.store(2, Ordering::Release);
        assert!(sink.rotate(&|| false).is_err());
        assert!(sink.write_some(b"after", &|| false).is_err());
        assert_eq!(sink.write_some(b"after", &|| false).unwrap(), 5);
        assert_eq!(std::fs::read(&path).unwrap(), b"after");
        let archives: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|entry| entry != &path)
            .collect();
        assert_eq!(archives.len(), 1);
        assert_eq!(std::fs::read(&archives[0]).unwrap(), b"before");
        assert!(!archives[0]
            .file_name()
            .unwrap()
            .to_string_lossy()
            .contains("scratch"));
    }

    #[test]
    fn failed_rename_and_failed_reopen_preserve_the_original_log() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("output.log");
        let faults = FaultIo::new();
        let sink =
            RotationSink::open_with_io(&stream(&path), rotation_at(0), faults.clone()).unwrap();
        sink.write_some(b"before", &|| false).unwrap();
        faults.rename_failure.store(true, Ordering::Release);
        faults.reopen_failures.store(1, Ordering::Release);
        assert!(sink.rotate(&|| false).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"before");
        sink.write_some(b"after", &|| false).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"beforeafter");
    }

    #[test]
    fn copy_and_truncate_preserves_file_identity_and_archives_before_truncation() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("output.log");
        std::fs::write(&path, b"original").unwrap();
        let mut configured = stream(&path);
        configured.copy_and_truncate = Some(true);
        let faults = FaultIo::new();
        let sink = RotationSink::open_with_io(&configured, rotation_at(0), faults.clone()).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
        faults.copy_failure.store(true, Ordering::Release);
        assert!(sink.rotate(&|| false).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
        faults.copy_failure.store(false, Ordering::Release);
        let mut retained_reader = File::open(&path).unwrap();
        let original_identity = identity(&retained_reader).unwrap().0;
        let archive = sink.rotate(&|| false).unwrap().unwrap();
        assert_eq!(std::fs::read(archive).unwrap(), b"original");
        sink.write_some(b"new", &|| false).unwrap();
        assert_eq!(
            identity(&File::open(&path).unwrap()).unwrap().0,
            original_identity
        );
        retained_reader.seek(SeekFrom::Start(0)).unwrap();
        let mut read = Vec::new();
        retained_reader.read_to_end(&mut read).unwrap();
        assert_eq!(read, b"new");
    }

    #[test]
    fn conflicting_alias_options_hard_links_and_streams_are_rejected_before_reuse() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("out.log");
        let out = stream(&path);
        let mut err = out.clone();
        err.share_mode = Some(0);
        assert!(dedup_sinks(Some(&out), Some(&err), &rotation_at(0)).is_err());
        let alias = dir.path().join("hard.log");
        std::fs::hard_link(&path, &alias).unwrap();
        assert!(RotationSink::open(&out, rotation_at(0)).is_err());
        let alternate = stream(&PathBuf::from(format!("{}:alternate", path.display())));
        assert!(RotationSink::open(&alternate, rotation_at(0)).is_err());
    }

    #[test]
    fn output_creation_disposition_and_sharing_are_honored_but_stdin_is_read_only() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("out.log");
        let mut configured = stream(&path);
        configured.creation_disposition = Some(3);
        assert!(
            open_output(&configured).is_err(),
            "OPEN_EXISTING must not create output"
        );
        assert!(!path.exists());
        configured.creation_disposition = Some(1);
        drop(open_output(&configured).unwrap());
        assert!(
            open_output(&configured).is_err(),
            "CREATE_NEW must not append an existing file"
        );
        configured.creation_disposition = None;
        configured.share_mode = Some(0);
        let file = open_output(&configured).unwrap();
        #[cfg(windows)]
        assert!(
            File::open(&path).is_err(),
            "configured exclusive sharing must be effective"
        );
        drop(file);
        configured.creation_disposition = Some(2);
        assert!(
            open_input(&configured).is_err(),
            "stdin cannot truncate/create"
        );
        configured.creation_disposition = Some(3);
        configured.share_mode = None;
        drop(open_input(&configured).unwrap());
        configured.flags_and_attributes = Some(0x4000_0000);
        assert!(
            open_output(&configured).is_err(),
            "overlapped stdio requires a different I/O implementation"
        );
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
