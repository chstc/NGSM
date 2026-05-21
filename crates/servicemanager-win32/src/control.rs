//! Install / remove / start / stop / control wrappers around the SCM.

use std::mem::size_of;
use std::path::Path;

use servicemanager_core::{
    quote_windows_arg, validate_service_name, Error, Result, ServiceRuntimeState,
};
use windows::core::PCWSTR;
use windows::Win32::System::Services::{
    ChangeServiceConfigW, ControlService, CreateServiceW, DeleteService, QueryServiceStatusEx,
    StartServiceW, ENUM_SERVICE_TYPE, SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE,
    SC_STATUS_PROCESS_INFO, SERVICE_ALL_ACCESS, SERVICE_AUTO_START, SERVICE_CHANGE_CONFIG,
    SERVICE_CONTROL_CONTINUE, SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_PAUSE,
    SERVICE_CONTROL_STOP, SERVICE_DEMAND_START, SERVICE_DISABLED, SERVICE_ERROR,
    SERVICE_ERROR_NORMAL, SERVICE_INTERROGATE, SERVICE_NO_CHANGE, SERVICE_PAUSE_CONTINUE,
    SERVICE_QUERY_STATUS, SERVICE_START, SERVICE_START_TYPE, SERVICE_STATUS,
    SERVICE_STATUS_PROCESS, SERVICE_STOP, SERVICE_USER_DEFINED_CONTROL, SERVICE_WIN32_OWN_PROCESS,
};

use crate::handles::{map_win_error, open_scm, open_service_handle, to_wide};
use crate::scm::classify_state_pub as classify_state;

/// Generic Windows `DELETE` access right (not exported from the Services
/// module of windows-rs 0.58 even though `DeleteService` requires it).
const DELETE_ACCESS: u32 = 0x0001_0000;

/// User-facing controls that map to SCM `ControlService` codes we support today.
#[derive(Debug, Clone, Copy)]
pub enum ServiceControlSignal {
    Stop,
    Pause,
    Continue,
    Interrogate,
    /// A user-defined control code in the range 128..=255.
    User(u32),
}

/// NSSM-compatible user control code that requests a log rotation.
pub const SERVICE_CONTROL_ROTATE: u32 = 174;

impl ServiceControlSignal {
    fn to_win32(self) -> u32 {
        match self {
            ServiceControlSignal::Stop => SERVICE_CONTROL_STOP,
            ServiceControlSignal::Pause => SERVICE_CONTROL_PAUSE,
            ServiceControlSignal::Continue => SERVICE_CONTROL_CONTINUE,
            ServiceControlSignal::Interrogate => SERVICE_CONTROL_INTERROGATE,
            ServiceControlSignal::User(code) => code,
        }
    }

    fn required_access(self) -> u32 {
        // We always include `SERVICE_QUERY_STATUS` because every control path
        // re-queries the post-control status to return it to the caller.
        let base = SERVICE_QUERY_STATUS;
        match self {
            ServiceControlSignal::Stop => base | SERVICE_STOP,
            ServiceControlSignal::Pause | ServiceControlSignal::Continue => {
                base | SERVICE_PAUSE_CONTINUE
            }
            // `Interrogate` is a standard control with its own access right;
            // it must not be grouped with the user-defined controls.
            ServiceControlSignal::Interrogate => base | SERVICE_INTERROGATE,
            ServiceControlSignal::User(_) => base | SERVICE_USER_DEFINED_CONTROL,
        }
    }
}

#[derive(Debug, Clone)]
pub struct InstallOptions {
    pub name: String,
    pub display_name: String,
    pub binary_path: String,
    pub start_type: InstallStartType,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum InstallStartType {
    #[default]
    Manual,
    Automatic,
    Disabled,
}

impl InstallStartType {
    fn to_win32(self) -> SERVICE_START_TYPE {
        match self {
            InstallStartType::Manual => SERVICE_DEMAND_START,
            InstallStartType::Automatic => SERVICE_AUTO_START,
            InstallStartType::Disabled => SERVICE_DISABLED,
        }
    }
}

/// Create a Windows service whose image path points at the supplied
/// `binary_path` (which should already include any args the service runner
/// needs, e.g. `\"C:\\…\\ngsm.exe\" run-service MyService`).
pub fn install_service(opts: &InstallOptions) -> Result<()> {
    validate_service_name(&opts.name)?;
    let scm = open_scm(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;
    let name = to_wide(&opts.name);
    let display = to_wide(&opts.display_name);
    let path = to_wide(&opts.binary_path);
    unsafe {
        let handle = CreateServiceW(
            scm.0,
            PCWSTR::from_raw(name.as_ptr()),
            PCWSTR::from_raw(display.as_ptr()),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            opts.start_type.to_win32(),
            SERVICE_ERROR_NORMAL,
            PCWSTR::from_raw(path.as_ptr()),
            PCWSTR::null(),
            None,
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
        )
        .map_err(|e| map_win_error(&format!("CreateService({})", opts.name), e))?;
        // Handle is closed by RAII when ScHandle is dropped; wrap and drop.
        drop(crate::handles::ScHandle(handle));
    }
    Ok(())
}

/// Build the SCM image-path command line for a managed service:
/// `"<ngsm.exe>" run-service "<name>"`. Every argument is quoted
/// with the standard Windows rules so a name containing spaces or quotes is
/// recovered intact by the service runner.
pub fn build_run_service_command(name: &str) -> Result<String> {
    validate_service_name(name)?;
    let exe = std::env::current_exe().map_err(|e| Error::other(format!("current_exe: {e}")))?;
    validate_runner_location(&exe)?;
    Ok(format!(
        "{} run-service {}",
        quote_windows_arg(&exe.to_string_lossy()),
        quote_windows_arg(name)
    ))
}

/// Refuse to install a service whose runner binary sits in a location a
/// non-administrator can replace. The SCM `ImagePath` is permanent, so a
/// runner kept under the user profile, a temp directory, or a network share
/// could later be swapped for an attacker-controlled binary that then runs
/// with the service account's privileges.
///
/// This is a location heuristic (profile / temp / network), not a full
/// effective-ACL check — it catches the realistic "installed straight from
/// Downloads" vector. The supported, trusted path is to place `ngsm.exe` in
/// an administrator-protected directory (e.g. under Program Files) and run
/// `install` from there.
fn validate_runner_location(exe: &Path) -> Result<()> {
    let canonical = std::fs::canonicalize(exe).map_err(|e| {
        Error::other(format!(
            "cannot resolve runner path '{}': {e}",
            exe.display()
        ))
    })?;
    let lower = canonical.to_string_lossy().to_ascii_lowercase();

    // A network / UNC location is outside this machine's administrative
    // control and is never a trusted install location. `canonicalize` emits
    // `\\?\UNC\...` for UNC paths and `\\?\C:\...` for local ones.
    let is_unc =
        lower.starts_with(r"\\?\unc\") || (lower.starts_with(r"\\") && !lower.starts_with(r"\\?\"));
    if is_unc {
        return Err(Error::other(format!(
            "refusing to install: the NGSM runner is on a network path ('{}'). Install \
             NGSM under a local, administrator-protected directory and run `install` \
             from there.",
            canonical.display()
        )));
    }
    // Strip the `\\?\` extended-length prefix so the comparison below lines
    // up with the (unprefixed) environment directory paths.
    let exe_path = lower.strip_prefix(r"\\?\").unwrap_or(&lower);

    // Reject the well-known per-user-writable roots — Downloads, Desktop,
    // Documents, AppData, and the temp directories all live under these.
    for var in [
        "USERPROFILE",
        "TEMP",
        "TMP",
        "PUBLIC",
        "LOCALAPPDATA",
        "APPDATA",
    ] {
        let Some(raw_dir) = std::env::var_os(var) else {
            continue;
        };
        let Ok(dir) = std::fs::canonicalize(&raw_dir) else {
            continue;
        };
        let dir_lower = dir.to_string_lossy().to_ascii_lowercase();
        let dir_path = dir_lower.strip_prefix(r"\\?\").unwrap_or(&dir_lower);
        if dir_path.is_empty() {
            continue;
        }
        let prefix = format!("{}\\", dir_path.trim_end_matches('\\'));
        if exe_path.starts_with(&prefix) {
            return Err(Error::other(format!(
                "refusing to install: the NGSM runner is under a user-writable location \
                 ('{}'). Copy NGSM into an administrator-protected directory (e.g. under \
                 Program Files) and run `install` from there.",
                canonical.display()
            )));
        }
    }
    Ok(())
}

/// Delete an existing service. Does not stop it; the caller should arrange
/// that separately if the service is running.
pub fn remove_service(name: &str) -> Result<()> {
    validate_service_name(name)?;
    let scm = open_scm(SC_MANAGER_CONNECT)?;
    let svc = open_service_handle(&scm, name, DELETE_ACCESS)?;
    unsafe {
        DeleteService(svc.0).map_err(|e| map_win_error(&format!("DeleteService({name})"), e))?;
    }
    Ok(())
}

/// Update select native (SCM-owned) fields on an existing service. Pass
/// `None` to leave a field untouched. Today this covers `DisplayName` and
/// `Start` — the most common GUI edit targets. Description is a separate
/// API (`ChangeServiceConfig2W` with `SERVICE_CONFIG_DESCRIPTION`) and is
/// not yet wired.
pub fn update_native_config(
    name: &str,
    display_name: Option<&str>,
    start_type: Option<InstallStartType>,
) -> Result<()> {
    validate_service_name(name)?;
    let scm = open_scm(SC_MANAGER_CONNECT)?;
    let svc = open_service_handle(&scm, name, SERVICE_CHANGE_CONFIG)?;

    let display_wide = display_name.map(to_wide);
    let display_pcwstr = match &display_wide {
        Some(w) => PCWSTR::from_raw(w.as_ptr()),
        None => PCWSTR::null(),
    };
    let start = match start_type {
        Some(s) => s.to_win32(),
        None => SERVICE_START_TYPE(SERVICE_NO_CHANGE),
    };

    unsafe {
        ChangeServiceConfigW(
            svc.0,
            ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),
            start,
            SERVICE_ERROR(SERVICE_NO_CHANGE),
            PCWSTR::null(), // binary path — unchanged
            PCWSTR::null(), // load order group — unchanged
            None,           // tag id — unchanged
            PCWSTR::null(), // dependencies — unchanged
            PCWSTR::null(), // service start name — unchanged
            PCWSTR::null(), // password — unchanged
            display_pcwstr,
        )
        .map_err(|e| map_win_error(&format!("ChangeServiceConfig({name})"), e))?;
    }
    Ok(())
}

/// Ask the SCM to start the service. Returns once SCM has accepted the
/// request; the service may still be in `start_pending`.
pub fn start_service(name: &str) -> Result<()> {
    validate_service_name(name)?;
    let scm = open_scm(SC_MANAGER_CONNECT)?;
    let svc = open_service_handle(&scm, name, SERVICE_START)?;
    unsafe {
        StartServiceW(svc.0, None)
            .map_err(|e| map_win_error(&format!("StartService({name})"), e))?;
    }
    Ok(())
}

/// Send a control code to a running service and return the resulting status
/// snapshot. The runtime block lacks `exit_code`, since `SERVICE_STATUS`
/// does not include the per-process exit code; callers can pull that
/// separately via [`crate::scm::query_service`].
pub fn control_service(name: &str, signal: ServiceControlSignal) -> Result<ServiceRuntimeState> {
    validate_service_name(name)?;
    let scm = open_scm(SC_MANAGER_CONNECT)?;
    let svc = open_service_handle(&scm, name, signal.required_access())?;
    let mut status = SERVICE_STATUS::default();
    unsafe {
        ControlService(svc.0, signal.to_win32(), &mut status as *mut SERVICE_STATUS)
            .map_err(|e| map_win_error(&format!("ControlService({name})"), e))?;
    }
    // Re-query for the richer process-aware status.
    let mut proc_status = SERVICE_STATUS_PROCESS::default();
    let mut written = 0u32;
    unsafe {
        QueryServiceStatusEx(
            svc.0,
            SC_STATUS_PROCESS_INFO,
            Some(std::slice::from_raw_parts_mut(
                (&mut proc_status as *mut SERVICE_STATUS_PROCESS) as *mut u8,
                size_of::<SERVICE_STATUS_PROCESS>(),
            )),
            &mut written,
        )
        .map_err(|e| map_win_error(&format!("QueryServiceStatusEx({name})"), e))?;
    }
    Ok(ServiceRuntimeState {
        state: classify_state(proc_status.dwCurrentState.0),
        pid: (proc_status.dwProcessId != 0).then_some(proc_status.dwProcessId),
        exit_code: None,
        checkpoint: Some(proc_status.dwCheckPoint),
        wait_hint_ms: Some(proc_status.dwWaitHint),
    })
}
