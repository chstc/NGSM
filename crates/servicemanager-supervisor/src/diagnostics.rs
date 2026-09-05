//! Bounded, nonrecursive host diagnostics. The worker may block in the OS event
//! service; the supervision thread never waits for that I/O.

use std::io::{self, IsTerminal, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct Diagnostic {
    pub service: String,
    pub operation: String,
    pub message: String,
}

pub trait DiagnosticSink: Send + 'static {
    fn write(&mut self, record: &Diagnostic) -> io::Result<()>;
}

enum Message {
    Record(Diagnostic),
    Flush(mpsc::Sender<()>),
}

#[derive(Clone)]
pub struct Reporter {
    tx: SyncSender<Message>,
    dropped: Arc<AtomicU64>,
}

impl Reporter {
    pub fn new(mut sink: impl DiagnosticSink) -> Self {
        let (tx, rx) = mpsc::sync_channel(64);
        let dropped = Arc::new(AtomicU64::new(0));
        let failed = Arc::clone(&dropped);
        let worker = std::thread::Builder::new()
            .name("ngsm-diagnostics".into())
            .spawn(move || {
                while let Ok(message) = rx.recv() {
                    match message {
                        Message::Record(record) => {
                            if sink.write(&record).is_err() {
                                failed.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Message::Flush(done) => {
                            let _ = done.send(());
                        }
                    }
                }
            });
        if worker.is_err() {
            dropped.fetch_add(1, Ordering::Relaxed);
        }
        Self { tx, dropped }
    }

    pub fn report(&self, service: &str, operation: &str, message: &str) {
        let record = Diagnostic {
            service: bounded(service, 256),
            operation: bounded(operation, 128),
            message: bounded(message, 2048),
        };
        if self.tx.try_send(Message::Record(record)).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn flush(&self, timeout: Duration) -> bool {
        let (tx, rx) = mpsc::channel();
        self.tx.try_send(Message::Flush(tx)).is_ok() && rx.recv_timeout(timeout).is_ok()
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

fn bounded(value: &str, limit: usize) -> String {
    value.chars().take(limit).filter(|c| *c != '\0').collect()
}

pub fn reporter() -> &'static Reporter {
    static REPORTER: OnceLock<Reporter> = OnceLock::new();
    REPORTER.get_or_init(|| Reporter::new(SystemSink))
}

pub fn report(service: &str, operation: &str, message: impl std::fmt::Display) {
    reporter().report(service, operation, &message.to_string());
}

struct SystemSink;

impl DiagnosticSink for SystemSink {
    fn write(&mut self, record: &Diagnostic) -> io::Result<()> {
        if io::stderr().is_terminal() {
            let _ = writeln!(
                io::stderr().lock(),
                "[ngsm:{}:{}] {}",
                record.service,
                record.operation,
                record.message
            );
        }
        #[cfg(windows)]
        {
            use windows::core::{w, PCWSTR};
            use windows::Win32::System::EventLog::{
                DeregisterEventSource, RegisterEventSourceW, ReportEventW, EVENTLOG_ERROR_TYPE,
            };
            let text = format!(
                "Service: {}\r\nOperation: {}\r\n{}",
                record.service, record.operation, record.message
            );
            let text: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
            // SAFETY: the source name and server arguments are valid, terminated strings.
            let source =
                unsafe { RegisterEventSourceW(None, w!("NGSM")) }.map_err(io::Error::other)?;
            // SAFETY: source is live and text remains alive through ReportEventW.
            let result = unsafe {
                ReportEventW(
                    source,
                    EVENTLOG_ERROR_TYPE,
                    0,
                    1,
                    None,
                    0,
                    Some(&[PCWSTR(text.as_ptr())]),
                    None,
                )
            };
            // SAFETY: release the event source handle returned above, exactly once.
            unsafe {
                let _ = DeregisterEventSource(source);
            }
            result.map_err(io::Error::other)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Recording(Arc<Mutex<Vec<Diagnostic>>>);
    impl DiagnosticSink for Recording {
        fn write(&mut self, record: &Diagnostic) -> io::Result<()> {
            self.0.lock().unwrap().push(record.clone());
            Ok(())
        }
    }

    #[test]
    fn production_reporter_records_context_and_bounds_messages() {
        let records = Arc::new(Mutex::new(Vec::new()));
        let reporter = Reporter::new(Recording(Arc::clone(&records)));
        reporter.report("fixture", "hook Start/Post generation=1", &"x".repeat(4096));
        assert!(reporter.flush(Duration::from_secs(1)));
        let records = records.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].service, "fixture");
        assert_eq!(records[0].message.len(), 2048);
        assert!(records[0].operation.contains("generation=1"));
    }

    #[test]
    fn failing_sink_does_not_recurse_or_fail_the_producer() {
        struct Failing;
        impl DiagnosticSink for Failing {
            fn write(&mut self, _: &Diagnostic) -> io::Result<()> {
                Err(io::Error::other("injected diagnostic failure"))
            }
        }
        let reporter = Reporter::new(Failing);
        reporter.report("fixture", "spawn", "injected failure");
        assert!(reporter.flush(Duration::from_secs(1)));
        assert_eq!(reporter.dropped(), 1);
    }

    #[test]
    fn blocked_diagnostic_sink_has_bounded_queue_and_flush() {
        struct Blocked(mpsc::Receiver<()>);
        impl DiagnosticSink for Blocked {
            fn write(&mut self, _: &Diagnostic) -> io::Result<()> {
                let _ = self.0.recv();
                Ok(())
            }
        }
        let (release, wait) = mpsc::channel();
        let reporter = Reporter::new(Blocked(wait));
        for _ in 0..1000 {
            reporter.report("fixture", "I/O", "failure");
        }
        assert!(reporter.dropped() > 0);
        assert!(!reporter.flush(Duration::from_millis(10)));
        drop(release);
    }
}
