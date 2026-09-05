//! Owned, bounded pipe drainage. Storage failures apply backpressure instead
//! of disconnecting a live child's pipe; only committed prefixes are removed.

use std::io::{self, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc::Sender, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::diagnostics;
use crate::rotation::RotationSink;
use crate::SupervisorMessage;

const BUFFER_LIMIT: usize = 64 * 1024;
const RETRY_DELAY: Duration = Duration::from_millis(100);

#[derive(Default, Debug)]
pub(crate) struct ReaderStats {
    pub(crate) written: u64,
    pub(crate) dropped: u64,
}

pub(crate) struct ReaderTask {
    handle: Option<JoinHandle<io::Result<ReaderStats>>>,
    cancelled: Arc<AtomicBool>,
    drain_deadline: Arc<Mutex<Option<Instant>>>,
}

impl ReaderTask {
    pub(crate) fn spawn(
        service: String,
        label: String,
        reader: os_pipe::PipeReader,
        sink: Arc<RotationSink>,
        tx: Sender<SupervisorMessage>,
        generation: u64,
        diagnostic: diagnostics::Reporter,
    ) -> io::Result<Self> {
        let cancelled = Arc::new(AtomicBool::new(false));
        let drain_deadline = Arc::new(Mutex::new(None));
        let worker_cancelled = Arc::clone(&cancelled);
        let worker_deadline = Arc::clone(&drain_deadline);
        let handle = thread::Builder::new()
            .name(format!("ngsm-{label}"))
            .spawn(move || {
                let context = ReaderContext {
                    service,
                    label,
                    cancelled: worker_cancelled,
                    drain_deadline: worker_deadline,
                    tx,
                    generation,
                    diagnostic,
                };
                let result = copy_pipe(reader, sink, &context);
                if let Err(error) = &result {
                    context.diagnostic.report(
                        &context.service,
                        &format!("{} generation={}", context.label, context.generation),
                        &error.to_string(),
                    );
                    let _ = context
                        .tx
                        .send(SupervisorMessage::ReaderFailed(context.generation));
                }
                result
            })?;
        Ok(Self {
            handle: Some(handle),
            cancelled,
            drain_deadline,
        })
    }

    pub(crate) fn finish(&mut self, deadline: Instant) -> io::Result<ReaderStats> {
        *self
            .drain_deadline
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(deadline);
        while self.handle.as_ref().is_some_and(|h| !h.is_finished()) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        if self.handle.as_ref().is_some_and(|h| !h.is_finished()) {
            self.cancel();
            let cancel_deadline = Instant::now() + Duration::from_millis(500);
            while self.handle.as_ref().is_some_and(|h| !h.is_finished())
                && Instant::now() < cancel_deadline
            {
                thread::sleep(Duration::from_millis(5));
            }
        }
        if self.handle.as_ref().is_some_and(|h| !h.is_finished()) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "output I/O did not cancel; the host must exit without starting another generation",
            ));
        }
        match self.handle.take() {
            Some(handle) => handle
                .join()
                .map_err(|_| io::Error::other("output reader panicked"))?,
            None => Ok(ReaderStats::default()),
        }
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        #[cfg(windows)]
        if let Some(handle) = &self.handle {
            use std::os::windows::io::AsRawHandle;
            use windows::Win32::Foundation::HANDLE;
            use windows::Win32::System::IO::CancelSynchronousIo;
            // SAFETY: the join handle pins this reader thread. It is never a foreign thread.
            unsafe {
                let _ = CancelSynchronousIo(HANDLE(handle.as_raw_handle()));
            }
        }
    }
}

impl Drop for ReaderTask {
    fn drop(&mut self) {
        // Exceptional cleanup (including unwinding) still interrupts our own I/O.
        // A failed bounded finish is fatal to this supervisor: no next generation is allowed.
        self.cancel();
    }
}

struct ReaderContext {
    service: String,
    label: String,
    cancelled: Arc<AtomicBool>,
    drain_deadline: Arc<Mutex<Option<Instant>>>,
    tx: Sender<SupervisorMessage>,
    generation: u64,
    diagnostic: diagnostics::Reporter,
}

fn copy_pipe(
    mut reader: os_pipe::PipeReader,
    sink: Arc<RotationSink>,
    context: &ReaderContext,
) -> io::Result<ReaderStats> {
    let ReaderContext {
        service,
        label,
        cancelled,
        drain_deadline,
        tx,
        generation,
        diagnostic,
    } = context;
    let mut pending = Vec::with_capacity(BUFFER_LIMIT);
    let mut offset = 0;
    let mut stats = ReaderStats::default();
    let mut eof = false;
    let mut retry_at = Instant::now();
    let mut last_diagnostic = None;
    let mut buffer = [0u8; 8192];
    loop {
        if eof && pending.is_empty() {
            return Ok(stats);
        }
        let expired = drain_deadline
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some_and(|deadline| Instant::now() >= deadline);
        if cancelled.load(Ordering::Acquire) || expired {
            stats.dropped += (pending.len() - offset) as u64;
            diagnostic.report(
                service,
                &format!("{label} generation={generation}"),
                &format!(
                    "drain deadline: {} buffered bytes lost; unread pipe data may remain",
                    stats.dropped
                ),
            );
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "output drain incomplete ({} buffered bytes lost)",
                    stats.dropped
                ),
            ));
        }
        if offset < pending.len() && Instant::now() >= retry_at {
            let written = sink
                .write_some(&pending[offset..], &|| cancelled.load(Ordering::Acquire))
                .and_then(|count| {
                    if count == 0 {
                        Err(io::ErrorKind::WriteZero.into())
                    } else {
                        Ok(count)
                    }
                });
            match written {
                Ok(n) => {
                    offset += n;
                    stats.written += n as u64;
                    if offset == pending.len() {
                        pending.clear();
                        offset = 0;
                    }
                    if sink.due(false).unwrap_or(false)
                        && sink.queue_rotation()
                        && tx.send(SupervisorMessage::AutoRotate(*generation)).is_err()
                    {
                        sink.rotation_handled();
                    }
                }
                Err(error) => {
                    if last_diagnostic
                        .is_none_or(|last: Instant| last.elapsed() >= Duration::from_secs(5))
                    {
                        diagnostic.report(
                            service,
                            &format!("{label} generation={generation}"),
                            &format!(
                                "write failed; retaining pipe/backpressure and retrying: {error}"
                            ),
                        );
                        last_diagnostic = Some(Instant::now());
                    }
                    retry_at = Instant::now() + RETRY_DELAY;
                }
            }
        }
        if eof && pending.is_empty() {
            return Ok(stats);
        }
        if !eof && pending.len() - offset < BUFFER_LIMIT {
            if offset > 0 {
                pending.drain(..offset);
                offset = 0;
            }
            let capacity = buffer.len().min(BUFFER_LIMIT - pending.len());
            match available(&reader) {
                Ok(Some(0)) => {}
                Ok(available) => {
                    let count = available.map_or(capacity, |n| n.min(capacity));
                    match reader.read(&mut buffer[..count]) {
                        Ok(0) => eof = true,
                        Ok(n) => pending.extend_from_slice(&buffer[..n]),
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => eof = true,
                        Err(e) => return Err(io::Error::new(e.kind(), format!(
                            "pipe read failed: {e}; {} buffered bytes lost; unread data may remain",
                            pending.len() - offset,
                        ))),
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::BrokenPipe => eof = true,
                Err(e) => return Err(io::Error::new(e.kind(), format!(
                    "pipe availability query failed: {e}; {} buffered bytes lost; unread data may remain",
                    pending.len() - offset,
                ))),
            }
        }
        if pending.is_empty() || Instant::now() < retry_at || eof {
            thread::sleep(Duration::from_millis(5));
        }
    }
}

fn available(reader: &os_pipe::PipeReader) -> io::Result<Option<usize>> {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::System::Pipes::PeekNamedPipe;
        let mut available = 0u32;
        // SAFETY: this worker exclusively owns the reading handle and available is writable.
        unsafe {
            PeekNamedPipe(
                HANDLE(reader.as_raw_handle()),
                None,
                0,
                None,
                Some(&mut available),
                None,
            )
        }
        .map_err(|error| io::Error::from_raw_os_error(error.code().0 & 0xffff))?;
        Ok(Some(available as usize))
    }
    #[cfg(not(windows))]
    {
        let _ = reader;
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rotation::{FileIo, RotationIo};
    use servicemanager_core::{IoStream, LogRotationConfig};
    use std::collections::VecDeque;
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;
    use std::sync::{mpsc, Condvar};

    enum WriteStep {
        Prefix(usize),
        Fail,
    }
    struct FlakyIo {
        steps: Mutex<VecDeque<WriteStep>>,
        unavailable: AtomicBool,
    }
    impl RotationIo for FlakyIo {
        fn reopen(&self, path: &Path, stream: &IoStream) -> io::Result<File> {
            FileIo.reopen(path, stream)
        }
        fn rename(&self, path: &Path, archive: &Path) -> io::Result<()> {
            FileIo.rename(path, archive)
        }
        fn write(&self, file: &mut File, bytes: &[u8]) -> io::Result<usize> {
            if self.unavailable.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "injected storage outage",
                ));
            }
            match self.steps.lock().unwrap().pop_front() {
                Some(WriteStep::Prefix(count)) => file.write(&bytes[..bytes.len().min(count)]),
                Some(WriteStep::Fail) => {
                    Err(io::Error::other("injected partial-write follow-up failure"))
                }
                None => file.write(bytes),
            }
        }
    }

    struct Recording(Arc<Mutex<Vec<diagnostics::Diagnostic>>>);
    impl diagnostics::DiagnosticSink for Recording {
        fn write(&mut self, record: &diagnostics::Diagnostic) -> io::Result<()> {
            self.0.lock().unwrap().push(record.clone());
            Ok(())
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
    fn real_pipe_retries_partial_writes_without_duplicate_prefixes_or_broken_pipe() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("output.log");
        let faults = Arc::new(FlakyIo {
            steps: Mutex::new(VecDeque::from([
                WriteStep::Prefix(3),
                WriteStep::Fail,
                WriteStep::Prefix(2),
                WriteStep::Fail,
            ])),
            unavailable: AtomicBool::new(false),
        });
        let sink = Arc::new(
            RotationSink::open_with_io(&stream(&path), LogRotationConfig::default(), faults)
                .unwrap(),
        );
        let (reader, mut writer) = os_pipe::pipe().unwrap();
        let (tx, _rx) = mpsc::channel();
        let records = Arc::new(Mutex::new(Vec::new()));
        let reporter = diagnostics::Reporter::new(Recording(Arc::clone(&records)));
        let mut task = ReaderTask::spawn(
            "PipeFixture".into(),
            "stdout".into(),
            reader,
            sink,
            tx,
            7,
            reporter.clone(),
        )
        .unwrap();
        let expected = b"ABCDEFGHIJKL0123456789\n".repeat(2048);
        let payload = expected.clone();
        let (sent, delivered) = mpsc::channel();
        let producer = thread::spawn(move || {
            let _ = sent.send(writer.write_all(&payload));
        });
        delivered
            .recv_timeout(Duration::from_secs(3))
            .expect("pipe producer must remain responsive")
            .expect("recoverable storage failures must not break the child's pipe");
        producer.join().unwrap();
        let stats = task
            .finish(Instant::now() + Duration::from_secs(2))
            .unwrap();
        assert_eq!(stats.written, expected.len() as u64);
        assert_eq!(stats.dropped, 0);
        assert_eq!(std::fs::read(path).unwrap(), expected);
        assert!(reporter.flush(Duration::from_secs(1)));
        assert!(records
            .lock()
            .unwrap()
            .iter()
            .any(|record| record.operation.contains("generation=7")
                && record.message.contains("retaining pipe")));
    }

    #[test]
    fn bounded_backpressure_recovers_after_storage_becomes_available() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("output.log");
        let faults = Arc::new(FlakyIo {
            steps: Mutex::new(VecDeque::new()),
            unavailable: AtomicBool::new(true),
        });
        let sink = Arc::new(
            RotationSink::open_with_io(
                &stream(&path),
                LogRotationConfig::default(),
                faults.clone(),
            )
            .unwrap(),
        );
        let (reader, mut writer) = os_pipe::pipe().unwrap();
        let (tx, _rx) = mpsc::channel();
        let reporter = diagnostics::Reporter::new(Recording(Arc::new(Mutex::new(Vec::new()))));
        let mut task = ReaderTask::spawn(
            "Backpressure".into(),
            "stdout".into(),
            reader,
            sink,
            tx,
            1,
            reporter,
        )
        .unwrap();
        let payload = vec![b'Z'; BUFFER_LIMIT * 3];
        let expected = payload.clone();
        let (sent, delivered) = mpsc::channel();
        let producer = thread::spawn(move || {
            let _ = sent.send(writer.write_all(&payload));
        });
        thread::sleep(Duration::from_millis(30));
        assert!(
            !producer.is_finished(),
            "bounded storage outage should backpressure, not drop/disconnect"
        );
        faults.unavailable.store(false, Ordering::Release);
        delivered
            .recv_timeout(Duration::from_secs(3))
            .expect("backpressure must recover")
            .unwrap();
        producer.join().unwrap();
        let stats = task
            .finish(Instant::now() + Duration::from_secs(2))
            .unwrap();
        assert_eq!(stats.written, expected.len() as u64);
        assert_eq!(std::fs::read(path).unwrap(), expected);
    }

    #[test]
    fn stalled_output_has_bounded_cancellation_and_an_explicit_fatal_drain_result() {
        struct BlockingIo {
            entered: mpsc::Sender<()>,
            release: (Mutex<bool>, Condvar),
        }
        impl RotationIo for BlockingIo {
            fn reopen(&self, path: &Path, stream: &IoStream) -> io::Result<File> {
                FileIo.reopen(path, stream)
            }
            fn rename(&self, path: &Path, archive: &Path) -> io::Result<()> {
                FileIo.rename(path, archive)
            }
            fn write(&self, file: &mut File, bytes: &[u8]) -> io::Result<usize> {
                let _ = self.entered.send(());
                let (lock, changed) = &self.release;
                let mut released = lock.lock().unwrap();
                while !*released {
                    released = changed.wait(released).unwrap();
                }
                file.write(bytes)
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let (entered, waiting) = mpsc::channel();
        let io = Arc::new(BlockingIo {
            entered,
            release: (Mutex::new(false), Condvar::new()),
        });
        let sink = Arc::new(
            RotationSink::open_with_io(
                &stream(&dir.path().join("blocked.log")),
                LogRotationConfig::default(),
                io.clone(),
            )
            .unwrap(),
        );
        let (reader, mut writer) = os_pipe::pipe().unwrap();
        let (tx, _rx) = mpsc::channel();
        let reporter = diagnostics::Reporter::new(Recording(Arc::new(Mutex::new(Vec::new()))));
        let mut task = ReaderTask::spawn(
            "Stalled".into(),
            "stdout".into(),
            reader,
            sink,
            tx,
            1,
            reporter,
        )
        .unwrap();
        writer.write_all(b"tail").unwrap();
        drop(writer);
        waiting.recv_timeout(Duration::from_secs(1)).unwrap();
        let started = Instant::now();
        let result = task.finish(Instant::now() + Duration::from_millis(20));
        *io.release.0.lock().unwrap() = true;
        io.release.1.notify_all();
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
        if let Ok(stats) = task.finish(Instant::now() + Duration::from_secs(1)) {
            assert_eq!(
                stats.written, 4,
                "a late completed write must remain accounted for"
            );
        }
        assert!(
            task.handle.is_none(),
            "owned reader must be joined after the injected stall releases"
        );
    }
}
