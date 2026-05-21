//! Process-elevation helpers used by the UI.
//!
//! The Windows implementation is gated so this module — and therefore the
//! GUI crate — type-checks on non-Windows hosts without depending on the
//! `windows` crate (which is itself a `cfg(windows)`-only dependency).

#[cfg(windows)]
mod imp {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStrExt;

    use windows::core::PCWSTR;
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    /// Re-launch the current executable with the `runas` verb (triggers UAC).
    /// On success the new process is detached; the caller should exit the
    /// current (unelevated) process.
    pub fn relaunch_as_admin() -> bool {
        let exe = match std::env::current_exe() {
            Ok(p) => p,
            Err(_) => return false,
        };
        // Re-issue the same subcommand: `gui` — the only way the UI is invoked.
        let verb = to_wide("runas");
        let file = to_wide(&exe.to_string_lossy());
        let args = to_wide("gui");
        // SAFETY: `verb`, `file`, and `args` are NUL-terminated UTF-16 buffers
        // that outlive the call; the other arguments are a null HWND and a
        // documented show-command constant.
        unsafe {
            let result = ShellExecuteW(
                None,
                PCWSTR::from_raw(verb.as_ptr()),
                PCWSTR::from_raw(file.as_ptr()),
                PCWSTR::from_raw(args.as_ptr()),
                PCWSTR::null(),
                SW_SHOWNORMAL,
            );
            // ShellExecuteW returns an HINSTANCE; values > 32 indicate success.
            (result.0 as usize) > 32
        }
    }

    fn to_wide(s: &str) -> Vec<u16> {
        OsString::from(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }
}

#[cfg(windows)]
pub use imp::relaunch_as_admin;

/// Non-Windows builds cannot elevate; the UI stays in its read-only mode.
#[cfg(not(windows))]
pub fn relaunch_as_admin() -> bool {
    false
}
