//! Shared helpers for SCM and registry handle ownership and error mapping.

use servicemanager_core::{Error, Result};
use windows::core::{Error as WinError, PCWSTR};
use windows::Win32::Foundation::{ERROR_SERVICE_DOES_NOT_EXIST, WIN32_ERROR};
use windows::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, SC_HANDLE,
};

pub(crate) struct ScHandle(pub SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: `self.0` is a valid SCM handle obtained from `OpenSCManagerW`,
            // `OpenServiceW`, or `CreateServiceW`; the `is_invalid()` guard above
            // ensures we never call `CloseServiceHandle` on a null handle.
            unsafe {
                let _ = CloseServiceHandle(self.0);
            }
        }
    }
}

pub(crate) fn win32_code(err: &WinError) -> u32 {
    if let Some(code) = WIN32_ERROR::from_error(err) {
        return code.0;
    }
    err.code().0 as u32
}

pub(crate) fn map_win_error(context: &str, err: WinError) -> Error {
    if win32_code(&err) == ERROR_SERVICE_DOES_NOT_EXIST.0 {
        return Error::NotFound(context.to_string());
    }
    Error::Scm(format!("{context}: {err}"))
}

pub(crate) fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub(crate) fn open_scm(access: u32) -> Result<ScHandle> {
    // SAFETY: both PCWSTR arguments are null (meaning "use local machine / active
    // database"), which is the documented way to open the default SCM. The returned
    // handle is wrapped in ScHandle for RAII release.
    unsafe {
        match OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), access) {
            Ok(h) => Ok(ScHandle(h)),
            Err(e) => Err(map_win_error("OpenSCManager", e)),
        }
    }
}

pub(crate) fn open_service_handle(scm: &ScHandle, name: &str, access: u32) -> Result<ScHandle> {
    let wide = to_wide(name);
    // SAFETY: `scm.0` is a valid SCM handle (callers always pass an `ScHandle`
    // from `open_scm`); `wide` is a null-terminated UTF-16 string alive for the
    // duration of this call. The returned handle is wrapped in ScHandle.
    unsafe {
        match OpenServiceW(scm.0, PCWSTR::from_raw(wide.as_ptr()), access) {
            Ok(h) => Ok(ScHandle(h)),
            Err(e) => Err(map_win_error(&format!("OpenService({name})"), e)),
        }
    }
}
