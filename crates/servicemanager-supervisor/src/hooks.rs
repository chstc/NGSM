//! Hook lifecycle points and the machinery to find and run them.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant};

use servicemanager_core::HookConfig;

#[cfg(windows)]
use servicemanager_win32::JobObject;

use crate::diagnostics;

#[cfg(all(test, windows))]
#[path = "hook_tests.rs"]
mod tests;

/// Hook lifecycle points (`<event>/<action>` in NSSM terms).
#[derive(Debug, Clone, Copy)]
pub(crate) enum HookPoint {
    StartPre,
    StartPost,
    StopPre,
    ExitPost,
    RotatePre,
    RotatePost,
    PowerChange,
    PowerResume,
}

impl HookPoint {
    pub(crate) fn event(&self) -> &'static str {
        match self {
            HookPoint::StartPre | HookPoint::StartPost => "Start",
            HookPoint::StopPre => "Stop",
            HookPoint::ExitPost => "Exit",
            HookPoint::RotatePre | HookPoint::RotatePost => "Rotate",
            HookPoint::PowerChange | HookPoint::PowerResume => "Power",
        }
    }
    pub(crate) fn action(&self) -> &'static str {
        match self {
            HookPoint::StartPre | HookPoint::RotatePre | HookPoint::StopPre => "Pre",
            HookPoint::StartPost | HookPoint::RotatePost | HookPoint::ExitPost => "Post",
            HookPoint::PowerChange => "Change",
            HookPoint::PowerResume => "Resume",
        }
    }
}

// Subset of `PBT_*` we care about classifying as "resume" events.
const PBT_APMRESUMEAUTOMATIC: u32 = 18;
const PBT_APMRESUMECRITICAL: u32 = 6;
const PBT_APMRESUMESTANDBY: u32 = 8;
const PBT_APMRESUMESUSPEND: u32 = 7;

pub(crate) fn is_resume_event(event_type: u32) -> bool {
    matches!(
        event_type,
        PBT_APMRESUMEAUTOMATIC
            | PBT_APMRESUMECRITICAL
            | PBT_APMRESUMESTANDBY
            | PBT_APMRESUMESUSPEND
    )
}

/// Maximum time a hook is allowed to run before we kill it. Matches NSSM's
/// historical 30-second default; later we can make this configurable.
pub(crate) const HOOK_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) fn find_hook(hooks: &[HookConfig], point: HookPoint) -> Option<&HookConfig> {
    hooks.iter().find(|h| {
        h.event.eq_ignore_ascii_case(point.event()) && h.action.eq_ignore_ascii_case(point.action())
    })
}

/// Absolute path to the system `cmd.exe`, resolved from `%SystemRoot%`
/// rather than the ambient `PATH` / current-directory search.
fn system_cmd_exe() -> PathBuf {
    let root = std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("windir"))
        .unwrap_or_else(|| std::ffi::OsString::from("C:\\Windows"));
    Path::new(&root).join("System32").join("cmd.exe")
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HookOutcome {
    Empty,
    Completed(i32),
    Cancelled,
    TimedOut,
    Failed,
}

pub(crate) struct HookRuntime<'a> {
    pub service: &'a str,
    pub environment: &'a [(OsString, OsString)],
    pub directory: Option<&'a Path>,
    pub deadline: Instant,
    pub cancelled: &'a dyn Fn() -> bool,
    pub diagnostic: &'a diagnostics::Reporter,
    pub generation: u64,
}

pub(crate) fn run_hook(hook: &HookConfig, runtime: &HookRuntime<'_>) -> HookOutcome {
    let service_name = runtime.service;
    let environment = runtime.environment;
    let directory = runtime.directory;
    let cancelled = runtime.cancelled;
    if hook.command.trim().is_empty() {
        return HookOutcome::Empty;
    }
    if cancelled() {
        return HookOutcome::Cancelled;
    }
    let deadline = runtime.deadline.min(Instant::now() + HOOK_TIMEOUT);
    let label = format!(
        "hook {}/{} generation={}",
        hook.event, hook.action, runtime.generation
    );
    let mut cmd = Command::new(system_cmd_exe());
    cmd.args(["/d", "/s", "/c"]);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // cmd /s strips these outer quotes, not the configured inner quoting.
        cmd.raw_arg(format!("\"{}\"", hook.command));
        const CREATE_SUSPENDED: u32 = 0x0000_0004;
        cmd.creation_flags(CREATE_SUSPENDED);
    }
    #[cfg(not(windows))]
    {
        cmd.arg(&hook.command);
    }
    cmd.env_clear()
        .envs(environment.iter().map(|(name, value)| (name, value)));
    cmd.stdin(std::process::Stdio::null());
    if let Some(directory) = directory {
        cmd.current_dir(directory);
    }
    if cancelled() {
        return HookOutcome::Cancelled;
    }
    if Instant::now() >= deadline {
        runtime
            .diagnostic
            .report(service_name, &label, "timed out before spawn");
        return HookOutcome::TimedOut;
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            runtime
                .diagnostic
                .report(service_name, &label, &format!("spawn failed: {e}"));
            return HookOutcome::Failed;
        }
    };

    #[cfg(windows)]
    let hook_job: JobObject = match (|| -> servicemanager_core::Result<JobObject> {
        let job = JobObject::new_kill_on_close()?;
        job.assign_child(&child)?;
        if cancelled() {
            return Err(servicemanager_core::Error::other(
                "hook cancelled before resume",
            ));
        }
        if Instant::now() >= deadline {
            return Err(servicemanager_core::Error::other(
                "hook deadline expired before resume",
            ));
        }
        if !job.pin_child(&child)?.resume()? {
            return Err(servicemanager_core::Error::other(
                "hook exited before resume",
            ));
        }
        Ok(job)
    })() {
        Ok(job) => job,
        Err(e) => {
            kill_and_reap(&mut child);
            if cancelled() {
                return HookOutcome::Cancelled;
            }
            if Instant::now() >= deadline {
                runtime
                    .diagnostic
                    .report(service_name, &label, "timed out before resume");
                return HookOutcome::TimedOut;
            }
            runtime.diagnostic.report(
                service_name,
                &label,
                &format!("containment/resume failed: {e}"),
            );
            return HookOutcome::Failed;
        }
    };

    loop {
        let cancel = cancelled();
        if cancel || Instant::now() >= deadline {
            #[cfg(windows)]
            if let Err(e) = hook_job.terminate(1) {
                runtime.diagnostic.report(
                    service_name,
                    &label,
                    &format!("job termination failed: {e}"),
                );
            }
            kill_and_reap(&mut child);
            if cancel {
                return HookOutcome::Cancelled;
            }
            runtime.diagnostic.report(
                service_name,
                &label,
                "timed out; contained hook tree terminated",
            );
            return HookOutcome::TimedOut;
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                let code = status.code().unwrap_or(-1);
                if code != 0 {
                    runtime.diagnostic.report(
                        service_name,
                        &label,
                        &format!("exited with code {code}"),
                    );
                }
                return HookOutcome::Completed(code);
            }
            Ok(None) => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) => {
                runtime
                    .diagnostic
                    .report(service_name, &label, &format!("wait failed: {e}"));
                kill_and_reap(&mut child);
                return HookOutcome::Failed;
            }
        }
    }
}

fn kill_and_reap(child: &mut Child) {
    let _ = child.kill();
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            _ => return,
        }
    }
}
