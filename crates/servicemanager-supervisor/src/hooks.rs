//! Hook lifecycle points and the machinery to find and run them.

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant};

use servicemanager_core::HookConfig;

use crate::SupervisorError;

#[cfg(windows)]
use servicemanager_win32::{resume_process, JobObject};

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
const HOOK_TIMEOUT: Duration = Duration::from_secs(30);

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

/// Place a freshly-spawned (suspended) hook process into a kill-on-close job
/// and resume it. Returns an error — leaving the hook *still suspended and
/// not running* — if either job creation or assignment fails, so an
/// uncontained privileged hook is never resumed.
#[cfg(windows)]
fn contain_hook(child: &Child) -> Result<JobObject, SupervisorError> {
    let job = JobObject::new_kill_on_close()?;
    job.assign_child(child)?;
    // The hook was created suspended; resume it only now that the job
    // contains it (and will therefore catch every process it spawns).
    resume_process(child.id())?;
    Ok(job)
}

pub(crate) fn run_hook(
    service_name: &str,
    application: Option<&str>,
    hook: &HookConfig,
    child_pid: Option<u32>,
    exit_code: Option<i32>,
    power_event_type: Option<u32>,
) {
    if hook.command.trim().is_empty() {
        return;
    }
    // Resolve `cmd.exe` from `%SystemRoot%` explicitly. A privileged service
    // process must not resolve the interpreter through the ambient `PATH` or
    // current-directory search, which an attacker could influence.
    let mut cmd = Command::new(system_cmd_exe());
    cmd.arg("/c");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.raw_arg(&hook.command);
        // Create the hook suspended so it can be placed in a job object
        // before it executes — so every process the hook spawns is captured
        // by the job and cannot escape the hook timeout.
        const CREATE_SUSPENDED: u32 = 0x0000_0004;
        cmd.creation_flags(CREATE_SUSPENDED);
    }
    #[cfg(not(windows))]
    {
        cmd.arg(&hook.command);
    }
    cmd.env("NGSM_SERVICE_NAME", service_name);
    cmd.env("NGSM_EVENT", format!("{}/{}", hook.event, hook.action));
    if let Some(app) = application {
        cmd.env("NGSM_APPLICATION", app);
    }
    if let Some(pid) = child_pid {
        cmd.env("NGSM_APPLICATION_PID", pid.to_string());
    }
    if let Some(code) = exit_code {
        cmd.env("NGSM_EXIT_CODE", code.to_string());
    }
    if let Some(ev) = power_event_type {
        cmd.env("NGSM_POWER_EVENT_TYPE", ev.to_string());
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "[supervisor:{service_name}] hook {}/{} spawn failed: {e}",
                hook.event, hook.action
            );
            return;
        }
    };

    // Contain the hook's whole process tree in a kill-on-close job, so a
    // timed-out (or misbehaving) hook cannot leave privileged descendants
    // running after we report it killed. If containment cannot be
    // established, kill the still-suspended hook *without running it* —
    // resuming an uncontained privileged hook is not acceptable.
    #[cfg(windows)]
    let hook_job: JobObject = match contain_hook(&child) {
        Ok(job) => job,
        Err(e) => {
            eprintln!(
                "[supervisor:{service_name}] hook {}/{} containment failed: {e} — \
                 killing the suspended hook without running it",
                hook.event, hook.action
            );
            let _ = child.kill();
            let _ = child.wait();
            return;
        }
    };

    let deadline = Instant::now() + HOOK_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => return,
            Ok(None) => {
                if Instant::now() >= deadline {
                    eprintln!(
                        "[supervisor:{service_name}] hook {}/{} timed out — killing",
                        hook.event, hook.action
                    );
                    // Terminate the hook's entire process tree, not just the
                    // immediate cmd.exe child, so no descendant survives.
                    #[cfg(windows)]
                    if let Err(e) = hook_job.terminate(1) {
                        eprintln!(
                            "[supervisor:{service_name}] hook {}/{} job terminate failed: {e}",
                            hook.event, hook.action
                        );
                    }
                    let _ = child.kill();
                    let _ = child.wait();
                    return;
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                eprintln!(
                    "[supervisor:{service_name}] hook {}/{} wait failed: {e}",
                    hook.event, hook.action
                );
                return;
            }
        }
    }
}
