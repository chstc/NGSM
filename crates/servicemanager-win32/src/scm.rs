//! Service Control Manager wrappers.
//!
//! Enumerates services and queries the static config + live status. Output is
//! mapped onto [`servicemanager_core`] types so callers never see raw Win32.

use std::ffi::OsString;
use std::mem::size_of;
use std::os::windows::ffi::OsStringExt;
use std::ptr;
use std::slice;

use servicemanager_core::{
    validate_service_name, Error, NativeServiceConfig, Result, ServiceRuntimeState, ServiceState,
    ServiceType, StartupType,
};

use crate::handles::{map_win_error, open_scm, open_service_handle, win32_code, ScHandle};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA};
use windows::Win32::System::Services::{
    EnumServicesStatusExW, QueryServiceConfig2W, QueryServiceConfigW, QueryServiceStatusEx,
    ENUM_SERVICE_STATUS_PROCESSW, QUERY_SERVICE_CONFIGW, SC_ENUM_PROCESS_INFO, SC_MANAGER_CONNECT,
    SC_MANAGER_ENUMERATE_SERVICE, SC_STATUS_PROCESS_INFO, SERVICE_AUTO_START, SERVICE_BOOT_START,
    SERVICE_CONFIG_DELAYED_AUTO_START_INFO, SERVICE_CONFIG_DESCRIPTION,
    SERVICE_DELAYED_AUTO_START_INFO, SERVICE_DEMAND_START, SERVICE_DESCRIPTIONW, SERVICE_DISABLED,
    SERVICE_FILE_SYSTEM_DRIVER, SERVICE_KERNEL_DRIVER, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS,
    SERVICE_STATE_ALL, SERVICE_STATUS_PROCESS, SERVICE_SYSTEM_START, SERVICE_WIN32,
    SERVICE_WIN32_OWN_PROCESS, SERVICE_WIN32_SHARE_PROCESS,
};
use windows::Win32::System::SystemServices::SERVICE_INTERACTIVE_PROCESS;

/// A native Windows service as reported by the SCM.
#[derive(Debug, Clone)]
pub struct NativeService {
    pub config: NativeServiceConfig,
    pub runtime: Option<ServiceRuntimeState>,
    /// Set when the per-service SCM config query failed during enumeration:
    /// `config` then holds only partial data (empty image path, `Unknown`
    /// fields). Callers surface this as a warning so a broken managed
    /// service is not silently misclassified as native.
    pub query_error: Option<String>,
}

unsafe fn wide_to_string(ptr: *const u16) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    if len == 0 {
        return Some(String::new());
    }
    let slice = slice::from_raw_parts(ptr, len);
    Some(OsString::from_wide(slice).to_string_lossy().into_owned())
}

fn classify_startup(start_type: u32, delayed: bool) -> StartupType {
    match start_type {
        x if x == SERVICE_BOOT_START.0 => StartupType::Boot,
        x if x == SERVICE_SYSTEM_START.0 => StartupType::System,
        x if x == SERVICE_AUTO_START.0 => {
            if delayed {
                StartupType::AutomaticDelayed
            } else {
                StartupType::Automatic
            }
        }
        x if x == SERVICE_DEMAND_START.0 => StartupType::Manual,
        x if x == SERVICE_DISABLED.0 => StartupType::Disabled,
        _ => StartupType::Unknown,
    }
}

fn classify_type(service_type: u32) -> ServiceType {
    let interactive = service_type & SERVICE_INTERACTIVE_PROCESS != 0;
    let masked = service_type & !SERVICE_INTERACTIVE_PROCESS;
    if masked & SERVICE_KERNEL_DRIVER.0 != 0 {
        ServiceType::KernelDriver
    } else if masked & SERVICE_FILE_SYSTEM_DRIVER.0 != 0 {
        ServiceType::FileSystemDriver
    } else if masked & SERVICE_WIN32_OWN_PROCESS.0 != 0 {
        if interactive {
            ServiceType::InteractiveProcess
        } else {
            ServiceType::Win32OwnProcess
        }
    } else if masked & SERVICE_WIN32_SHARE_PROCESS.0 != 0 {
        ServiceType::Win32SharedProcess
    } else {
        ServiceType::Unknown
    }
}

/// Re-export of [`classify_state`] for sibling modules.
pub(crate) fn classify_state_pub(state: u32) -> ServiceState {
    classify_state(state)
}

fn classify_state(state: u32) -> ServiceState {
    use windows::Win32::System::Services::{
        SERVICE_CONTINUE_PENDING, SERVICE_PAUSED, SERVICE_PAUSE_PENDING, SERVICE_RUNNING,
        SERVICE_START_PENDING, SERVICE_STOPPED, SERVICE_STOP_PENDING,
    };
    match state {
        x if x == SERVICE_STOPPED.0 => ServiceState::Stopped,
        x if x == SERVICE_START_PENDING.0 => ServiceState::StartPending,
        x if x == SERVICE_STOP_PENDING.0 => ServiceState::StopPending,
        x if x == SERVICE_RUNNING.0 => ServiceState::Running,
        x if x == SERVICE_CONTINUE_PENDING.0 => ServiceState::ContinuePending,
        x if x == SERVICE_PAUSE_PENDING.0 => ServiceState::PausePending,
        x if x == SERVICE_PAUSED.0 => ServiceState::Paused,
        _ => ServiceState::Unknown,
    }
}

fn split_double_null(buf: &[u16]) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = 0usize;
    for (i, &c) in buf.iter().enumerate() {
        if c == 0 {
            if i == start {
                break;
            }
            out.push(String::from_utf16_lossy(&buf[start..i]));
            start = i + 1;
        }
    }
    out
}

fn collect_dependencies(ptr: *const u16) -> (Vec<String>, Vec<String>) {
    if ptr.is_null() {
        return (Vec::new(), Vec::new());
    }
    let mut len = 0usize;
    // SAFETY: `ptr` is non-null (checked above) and points to a
    // double-null-terminated wide string returned by `QueryServiceConfigW` and
    // stored inside a heap buffer that outlives this call. The 64 KiB limit
    // prevents unbounded reads if the data is malformed.
    unsafe {
        loop {
            if *ptr.add(len) == 0 && *ptr.add(len + 1) == 0 {
                break;
            }
            len += 1;
            if len > 64 * 1024 {
                break;
            }
        }
        let buf = slice::from_raw_parts(ptr, len + 1);
        let entries = split_double_null(buf);
        let mut services = Vec::new();
        let mut groups = Vec::new();
        for e in entries {
            if let Some(rest) = e.strip_prefix('+') {
                groups.push(rest.to_string());
            } else {
                services.push(e);
            }
        }
        (services, groups)
    }
}

/// Enumerate all services known to the SCM.
pub fn enumerate_services() -> Result<Vec<NativeService>> {
    // Enumeration needs both rights: CONNECT to obtain a usable SCM handle
    // and ENUMERATE_SERVICE for the enumeration call itself.
    let scm = open_scm(SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE)?;

    let mut buffer = vec![0u8; 256 * 1024];
    let mut bytes_needed = 0u32;
    let mut services_returned = 0u32;
    let mut resume = 0u32;
    let mut out = Vec::new();

    loop {
        // SAFETY: `scm.0` is a valid SCM handle opened with
        // `SC_MANAGER_ENUMERATE_SERVICE`; `buffer` is a heap-allocated byte
        // slice whose length is passed to the API; all other arguments are
        // by-reference or null.
        let ret = unsafe {
            EnumServicesStatusExW(
                scm.0,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                Some(&mut buffer),
                &mut bytes_needed,
                &mut services_returned,
                Some(&mut resume),
                PCWSTR::null(),
            )
        };

        let more = match ret {
            Ok(()) => false,
            Err(e) => {
                let code = win32_code(&e);
                if code == ERROR_MORE_DATA.0 {
                    true
                } else if code == ERROR_INSUFFICIENT_BUFFER.0 {
                    let new_size = (buffer.len() + bytes_needed as usize).max(buffer.len() * 2);
                    buffer.resize(new_size, 0);
                    continue;
                } else {
                    return Err(map_win_error("EnumServicesStatusEx", e));
                }
            }
        };

        if services_returned > 0 {
            let entry_size = size_of::<ENUM_SERVICE_STATUS_PROCESSW>();
            for i in 0..services_returned as usize {
                // SAFETY: `buffer` was written by `EnumServicesStatusExW` which
                // guarantees `services_returned` valid `ENUM_SERVICE_STATUS_PROCESSW`
                // entries at the start; `read_unaligned` handles any platform
                // alignment padding the API may impose.
                let raw = unsafe {
                    let p =
                        buffer.as_ptr().add(i * entry_size) as *const ENUM_SERVICE_STATUS_PROCESSW;
                    ptr::read_unaligned(p)
                };

                // SAFETY: `raw.lpServiceName` is a null-terminated wide-string
                // pointer written into `buffer` by `EnumServicesStatusExW`;
                // `buffer` outlives this block.
                let name = unsafe { wide_to_string(raw.lpServiceName.0).unwrap_or_default() };
                // SAFETY: same as above for `raw.lpDisplayName`.
                let display = unsafe { wide_to_string(raw.lpDisplayName.0).unwrap_or_default() };

                let runtime = ServiceRuntimeState {
                    state: classify_state(raw.ServiceStatusProcess.dwCurrentState.0),
                    pid: (raw.ServiceStatusProcess.dwProcessId != 0)
                        .then_some(raw.ServiceStatusProcess.dwProcessId),
                    exit_code: None,
                    checkpoint: Some(raw.ServiceStatusProcess.dwCheckPoint),
                    wait_hint_ms: Some(raw.ServiceStatusProcess.dwWaitHint),
                };

                let (config, query_error) = match query_service_inner(&scm, &name) {
                    Ok((mut config, _, inner_query_error)) => {
                        if config.display_name.is_empty() {
                            config.display_name = display;
                        }
                        (config, inner_query_error)
                    }
                    Err(e) => (
                        NativeServiceConfig {
                            name: name.clone(),
                            display_name: display,
                            description: None,
                            startup: StartupType::Unknown,
                            service_type: classify_type(raw.ServiceStatusProcess.dwServiceType.0),
                            image_path: String::new(),
                            account: None,
                            depend_on_services: Vec::new(),
                            depend_on_groups: Vec::new(),
                        },
                        Some(format!(
                            "{name}: SCM config query failed ({e}) — listed with partial data"
                        )),
                    ),
                };

                out.push(NativeService {
                    config,
                    runtime: Some(runtime),
                    query_error,
                });
            }
        }

        if !more {
            break;
        }
    }

    Ok(out)
}

/// Query a single service by name.
pub fn query_service(name: &str) -> Result<NativeService> {
    validate_service_name(name)?;
    // A single-service query only needs CONNECT; ENUMERATE_SERVICE would be
    // an unnecessary (and sometimes denied) extra right.
    let scm = open_scm(SC_MANAGER_CONNECT)?;
    let (config, runtime, query_error) = query_service_inner(&scm, name)?;
    Ok(NativeService {
        config,
        runtime: Some(runtime),
        query_error,
    })
}

fn query_service_inner(
    scm: &ScHandle,
    name: &str,
) -> Result<(NativeServiceConfig, ServiceRuntimeState, Option<String>)> {
    let svc = open_service_handle(scm, name, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS)?;
    let (config, query_error) = query_config(&svc, name)?;
    let runtime = query_status(&svc, name)?;
    Ok((config, runtime, query_error))
}

fn query_config(svc: &ScHandle, name: &str) -> Result<(NativeServiceConfig, Option<String>)> {
    let mut bytes_needed = 0u32;
    // SAFETY: passing `None`/0 is the documented probe pattern to get the
    // required buffer size; we ignore the error return from the probe.
    unsafe {
        let _ = QueryServiceConfigW(svc.0, None, 0, &mut bytes_needed);
    }
    if bytes_needed == 0 {
        return Err(Error::Scm(format!(
            "QueryServiceConfig({name}) returned 0 bytes"
        )));
    }
    let mut buffer = vec![0u8; bytes_needed as usize];
    let mut written = 0u32;
    // SAFETY: `svc.0` is a valid handle with `SERVICE_QUERY_CONFIG`; `buffer`
    // is a heap allocation of the exact size the probe reported; the cast to
    // `*mut QUERY_SERVICE_CONFIGW` is valid because the API writes the struct
    // plus string data into the contiguous buffer.
    unsafe {
        QueryServiceConfigW(
            svc.0,
            Some(buffer.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW),
            bytes_needed,
            &mut written,
        )
        .map_err(|e| map_win_error(&format!("QueryServiceConfig({name})"), e))?;
    }
    // SAFETY: the API just wrote a valid `QUERY_SERVICE_CONFIGW` at the start
    // of `buffer`; `read_unaligned` handles any alignment gap the Win32 layout
    // may impose.
    let cfg = unsafe { ptr::read_unaligned(buffer.as_ptr() as *const QUERY_SERVICE_CONFIGW) };

    // SAFETY: `cfg.lpDisplayName` points into `buffer` (still alive); the API
    // null-terminates it.
    let display_name = unsafe { wide_to_string(cfg.lpDisplayName.0).unwrap_or_default() };
    // SAFETY: same as above for `cfg.lpBinaryPathName`.
    let image_path = unsafe { wide_to_string(cfg.lpBinaryPathName.0).unwrap_or_default() };
    // SAFETY: same as above for `cfg.lpServiceStartName`.
    let account_raw = unsafe { wide_to_string(cfg.lpServiceStartName.0).unwrap_or_default() };
    let account = (!account_raw.is_empty()).then_some(account_raw);
    let (depend_on_services, depend_on_groups) = collect_dependencies(cfg.lpDependencies.0);

    let mut query_error: Option<String> = None;

    let delayed = match query_delayed_auto_start(svc) {
        Ok(v) => v,
        Err(e) => {
            query_error = Some(format!("delayed auto-start: {e}"));
            false
        }
    };
    let description = match query_description(svc) {
        Ok(Some(d)) => Some(d),
        Ok(None) => None,
        Err(e) => {
            query_error
                .get_or_insert_with(String::new)
                .push_str(&format!("; description: {e}"));
            None
        }
    };

    Ok((
        NativeServiceConfig {
            name: name.to_string(),
            display_name,
            description,
            startup: classify_startup(cfg.dwStartType.0, delayed),
            service_type: classify_type(cfg.dwServiceType.0),
            image_path,
            account,
            depend_on_services,
            depend_on_groups,
        },
        query_error,
    ))
}

fn query_delayed_auto_start(svc: &ScHandle) -> Result<bool> {
    let mut info = SERVICE_DELAYED_AUTO_START_INFO::default();
    let mut bytes_needed = 0u32;
    // SAFETY: `svc.0` is a valid handle with `SERVICE_QUERY_CONFIG`; the slice
    // covers exactly `size_of::<SERVICE_DELAYED_AUTO_START_INFO>()` bytes of
    // the local `info`, which is the correct buffer type for this info class.
    unsafe {
        QueryServiceConfig2W(
            svc.0,
            SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
            Some(slice::from_raw_parts_mut(
                (&mut info as *mut SERVICE_DELAYED_AUTO_START_INFO) as *mut u8,
                size_of::<SERVICE_DELAYED_AUTO_START_INFO>(),
            )),
            &mut bytes_needed,
        )
        .map_err(|e| map_win_error("QueryServiceConfig2(delayed)", e))?;
    }
    Ok(info.fDelayedAutostart.as_bool())
}

fn query_description(svc: &ScHandle) -> Result<Option<String>> {
    let mut bytes_needed = 0u32;
    // SAFETY: passing `None` is the documented probe pattern; we ignore the
    // error return — only `bytes_needed` matters at this point.
    unsafe {
        let _ = QueryServiceConfig2W(svc.0, SERVICE_CONFIG_DESCRIPTION, None, &mut bytes_needed);
    }
    if bytes_needed == 0 {
        return Ok(None);
    }
    let mut buffer = vec![0u8; bytes_needed as usize];
    let mut written = 0u32;
    // SAFETY: `svc.0` is a valid handle with `SERVICE_QUERY_CONFIG`; `buffer`
    // is a heap allocation sized to what the probe returned.
    unsafe {
        QueryServiceConfig2W(
            svc.0,
            SERVICE_CONFIG_DESCRIPTION,
            Some(&mut buffer),
            &mut written,
        )
        .map_err(|e| map_win_error("QueryServiceConfig2(description)", e))?;
    }
    // SAFETY: the API wrote a valid `SERVICE_DESCRIPTIONW` at the start of
    // `buffer`; `read_unaligned` handles any alignment gap.
    let desc = unsafe { ptr::read_unaligned(buffer.as_ptr() as *const SERVICE_DESCRIPTIONW) };
    // SAFETY: `desc.lpDescription` points into `buffer` which is still alive.
    let s = unsafe { wide_to_string(desc.lpDescription.0) };
    Ok(s.filter(|v| !v.is_empty()))
}

fn query_status(svc: &ScHandle, name: &str) -> Result<ServiceRuntimeState> {
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut written = 0u32;
    // SAFETY: `svc.0` is a valid handle with `SERVICE_QUERY_STATUS`; the slice
    // covers exactly `size_of::<SERVICE_STATUS_PROCESS>()` bytes of the local
    // `status`, satisfying the API buffer-size contract.
    unsafe {
        QueryServiceStatusEx(
            svc.0,
            SC_STATUS_PROCESS_INFO,
            Some(slice::from_raw_parts_mut(
                (&mut status as *mut SERVICE_STATUS_PROCESS) as *mut u8,
                size_of::<SERVICE_STATUS_PROCESS>(),
            )),
            &mut written,
        )
        .map_err(|e| map_win_error(&format!("QueryServiceStatusEx({name})"), e))?;
    }
    Ok(ServiceRuntimeState {
        state: classify_state(status.dwCurrentState.0),
        pid: (status.dwProcessId != 0).then_some(status.dwProcessId),
        exit_code: (status.dwWin32ExitCode != 0).then_some(status.dwWin32ExitCode),
        checkpoint: Some(status.dwCheckPoint),
        wait_hint_ms: Some(status.dwWaitHint),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::System::Services::SERVICE_RUNNING;

    #[test]
    fn startup_type_classification() {
        assert_eq!(
            classify_startup(SERVICE_AUTO_START.0, false),
            StartupType::Automatic
        );
        assert_eq!(
            classify_startup(SERVICE_AUTO_START.0, true),
            StartupType::AutomaticDelayed
        );
        assert_eq!(
            classify_startup(SERVICE_DISABLED.0, false),
            StartupType::Disabled
        );
        assert_eq!(classify_startup(0x9999, false), StartupType::Unknown);
    }

    #[test]
    fn service_state_classification() {
        assert_eq!(classify_state(SERVICE_RUNNING.0), ServiceState::Running);
        assert_eq!(classify_state(0x9999), ServiceState::Unknown);
    }

    #[test]
    fn service_type_classification() {
        assert_eq!(
            classify_type(SERVICE_WIN32_OWN_PROCESS.0),
            ServiceType::Win32OwnProcess
        );
        assert_eq!(
            classify_type(SERVICE_WIN32_OWN_PROCESS.0 | SERVICE_INTERACTIVE_PROCESS),
            ServiceType::InteractiveProcess
        );
    }
}
