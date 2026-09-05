//! A retained identity for potentially blocking filesystem work. Cancellation
//! targets only this owned thread; an unresponsive task forbids another generation.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub(crate) struct IoTask<T> {
    handle: Option<JoinHandle<T>>,
    cancelled: Arc<AtomicBool>,
}

impl<T: Send + 'static> IoTask<T> {
    pub(crate) fn spawn(
        work: impl FnOnce(Arc<AtomicBool>) -> T + Send + 'static,
    ) -> io::Result<Self> {
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = Arc::clone(&cancelled);
        let handle = thread::Builder::new()
            .name("ngsm-file-io".into())
            .spawn(move || work(worker_cancelled))?;
        Ok(Self {
            handle: Some(handle),
            cancelled,
        })
    }

    pub(crate) fn wait(&mut self, budget: Duration, stopping: impl Fn() -> bool) -> io::Result<T> {
        let deadline = Instant::now() + budget;
        let mut cancel_deadline = None;
        loop {
            if self
                .handle
                .as_ref()
                .is_some_and(|handle| handle.is_finished())
            {
                return self
                    .handle
                    .take()
                    .unwrap()
                    .join()
                    .map_err(|_| io::Error::other("filesystem worker panicked"));
            }
            if self.handle.is_none() {
                return Err(io::Error::other("filesystem worker was already joined"));
            }
            if cancel_deadline.is_none() && (stopping() || Instant::now() >= deadline) {
                self.cancel();
                cancel_deadline = Some(Instant::now() + Duration::from_secs(2));
            }
            if cancel_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "filesystem I/O did not cancel; host exit is required before log reuse",
                ));
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
}

impl<T> IoTask<T> {
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        #[cfg(windows)]
        if let Some(handle) = &self.handle {
            use std::os::windows::io::AsRawHandle;
            use windows::Win32::Foundation::HANDLE;
            use windows::Win32::System::IO::CancelSynchronousIo;
            // SAFETY: the join handle pins the thread created by this task, never a foreign one.
            unsafe {
                let _ = CancelSynchronousIo(HANDLE(handle.as_raw_handle()));
            }
        }
    }
}

impl<T> Drop for IoTask<T> {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{mpsc, Condvar, Mutex};

    #[test]
    fn a_noncooperative_io_task_remains_owned_and_has_a_bounded_failure() {
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let worker_release = Arc::clone(&release);
        let (entered, waiting) = mpsc::channel();
        let mut task = IoTask::spawn(move |_| {
            entered.send(()).unwrap();
            let mut released = worker_release.0.lock().unwrap();
            while !*released {
                released = worker_release.1.wait(released).unwrap();
            }
            7
        })
        .unwrap();
        waiting.recv_timeout(Duration::from_secs(1)).unwrap();
        let started = Instant::now();
        let result = task.wait(Duration::from_millis(1), || true);
        *release.0.lock().unwrap() = true;
        release.1.notify_all();
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(
            task.handle.is_some(),
            "failed cancellation must retain the outstanding task identity"
        );
        assert_eq!(task.wait(Duration::from_secs(1), || false).unwrap(), 7);
        assert!(task.handle.is_none());
    }
}
