//! Safe wrapper around a Windows Job Object configured to terminate every
//! process in the job when the handle closes. The supervisor uses this to
//! ensure managed-child grandchildren do not survive a stop or a runner
//! crash.

use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, RawHandle};

use servicemanager_core::{Error, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, BOOL, HANDLE};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject, JOBOBJECT_BASIC_LIMIT_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

use crate::handles::win32_code;

pub struct JobObject(HANDLE);

// `HANDLE` is `Send + Sync` in windows-rs; the OS handle itself can be used
// from any thread.
unsafe impl Send for JobObject {}
unsafe impl Sync for JobObject {}

impl JobObject {
    /// Create an unnamed job whose `LimitFlags` include
    /// `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. The supervisor relies on the
    /// kill-on-close behavior as a safety net: even if the runner crashes,
    /// closing the job handle terminates the entire process tree.
    pub fn new_kill_on_close() -> Result<Self> {
        // SAFETY: `CreateJobObjectW` with null name and attributes creates an
        // unnamed job and returns an owned handle.
        let handle = unsafe { CreateJobObjectW(None, PCWSTR::null()) }
            .map_err(|e| Error::Scm(format!("CreateJobObject: {e} (code {})", win32_code(&e))))?;
        // Take RAII ownership of the handle immediately, so if the
        // configuration call below fails the handle is still closed by
        // `Drop` rather than leaked.
        let job = JobObject(handle);

        let info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
            BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION {
                LimitFlags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                ..Default::default()
            },
            ..Default::default()
        };
        // SAFETY: `info` is a fully-initialized structure of the type
        // `JobObjectExtendedLimitInformation` expects, and `size_of` gives
        // its exact byte length. `job.0` is the live handle created above.
        unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                &info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION as *const _,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        }
        .map_err(|e| Error::Scm(format!("SetInformationJobObject: {e}")))?;
        Ok(job)
    }

    /// Assign `child` to this job. Use [`std::process::Child::as_raw_handle`]
    /// from `std::os::windows::io::AsRawHandle` to obtain the handle.
    pub fn assign(&self, child_handle: RawHandle) -> Result<()> {
        // SAFETY: `self.0` is the live job handle owned by this type and
        // `child_handle` is a valid process handle supplied by the caller.
        unsafe {
            AssignProcessToJobObject(self.0, HANDLE(child_handle))
                .map_err(|e| Error::Scm(format!("AssignProcessToJobObject: {e}")))?;
        }
        Ok(())
    }

    /// Assign an arbitrary `Child` to this job in one call.
    pub fn assign_child(&self, child: &std::process::Child) -> Result<()> {
        self.assign(child.as_raw_handle())
    }

    /// Returns `true` only if the live process `pid` is currently a member
    /// of this job.
    ///
    /// The supervisor uses this to confirm a PID still refers to its managed
    /// child tree — and not an unrelated process that reused the PID after
    /// the child exited — immediately before issuing a PID-based control.
    /// Any failure (the process is gone, or cannot be opened) yields
    /// `false`, so callers fail safe and skip the control.
    pub fn contains(&self, pid: u32) -> bool {
        // SAFETY: `OpenProcess` returns an owned handle or an error.
        let handle = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
            Ok(h) => h,
            Err(_) => return false,
        };
        let mut in_job = BOOL(0);
        // SAFETY: `handle` is the live process handle just opened; `self.0`
        // is the live job handle owned by this type; `in_job` is a valid
        // out-pointer.
        let result = unsafe { IsProcessInJob(handle, self.0, &mut in_job) };
        // SAFETY: closing the process handle opened above, exactly once.
        unsafe {
            let _ = CloseHandle(handle);
        }
        result.is_ok() && in_job.as_bool()
    }

    /// Terminate every process in the job. After this returns the supervisor
    /// can `Child::wait` the original handle to reap it.
    pub fn terminate(&self, exit_code: u32) -> Result<()> {
        // SAFETY: `self.0` is the live job handle owned by this type.
        unsafe {
            TerminateJobObject(self.0, exit_code)
                .map_err(|e| Error::Scm(format!("TerminateJobObject: {e}")))?;
        }
        Ok(())
    }
}

impl Drop for JobObject {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: `self.0` is a handle this type exclusively owns and that
            // is still open (checked above). `KILL_ON_JOB_CLOSE` ensures
            // every member process is terminated when the last handle closes.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}
