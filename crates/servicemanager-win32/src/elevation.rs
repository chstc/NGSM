//! Is-this-process-elevated check.

use std::mem::size_of;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Return true if the current process token reports an elevated context
/// (i.e. the user accepted UAC for this process, or is running as Administrator).
pub fn is_elevated() -> bool {
    unsafe {
        let process: HANDLE = GetCurrentProcess();
        let mut token: HANDLE = HANDLE::default();
        if OpenProcessToken(process, TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut info = TOKEN_ELEVATION::default();
        let mut returned: u32 = 0;
        let result = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut info as *mut TOKEN_ELEVATION as *mut _),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        );
        let _ = CloseHandle(token);
        result.is_ok() && info.TokenIsElevated != 0
    }
}
