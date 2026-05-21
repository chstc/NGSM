//! Post `WM_CLOSE` to every top-level window owned by the target process.
//!
//! This is the NSSM-compatible middle step between CTRL+BREAK and
//! TerminateJobObject. Most well-behaved GUI apps respond to WM_CLOSE by
//! starting their normal shutdown sequence. Console processes have no
//! windows so this is a no-op for them.

use std::sync::Mutex;
use std::sync::OnceLock;

use servicemanager_core::{Error, Result};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND, LPARAM, WPARAM};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowThreadProcessId, PostMessageW, PostThreadMessageW, WM_CLOSE, WM_QUIT,
};

/// Post `WM_CLOSE` to every top-level window whose owning process is `pid`.
/// Returns the number of windows that were sent the message.
///
/// Concurrent callers serialize on a process-wide mutex because the
/// `EnumWindows` callback needs a global to communicate with us — running
/// two enumerations at once would cross their results.
pub fn post_wm_close_to_process(pid: u32) -> Result<usize> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let lock = LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock().unwrap();

    // Stash the target pid + count where the C callback can find them.
    let mut state = EnumState {
        target_pid: pid,
        posted: 0,
    };
    let state_ptr = &mut state as *mut EnumState;

    unsafe {
        EnumWindows(Some(enum_proc), LPARAM(state_ptr as isize))
            .map_err(|e| Error::other(format!("EnumWindows: {e}")))?;
    }
    Ok(state.posted)
}

struct EnumState {
    target_pid: u32,
    posted: usize,
}

/// Post `WM_QUIT` to every thread of the target process via
/// `PostThreadMessage`. The last graceful step NSSM tries before
/// `TerminateProcess` — covers UI threads whose message loops don't run
/// WindowProcs (so `WM_CLOSE` to a window handle wouldn't reach them) but
/// do pump thread messages. Returns the number of `WM_QUIT` posts that
/// succeeded.
pub fn post_wm_quit_to_process(pid: u32) -> Result<usize> {
    let snapshot = unsafe {
        CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
            .map_err(|e| Error::other(format!("CreateToolhelp32Snapshot(threads): {e}")))?
    };
    let _guard = HandleGuard(snapshot);

    let mut entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };

    let mut posted = 0usize;
    unsafe {
        if Thread32First(snapshot, &mut entry).is_err() {
            return Ok(0);
        }
        loop {
            if entry.th32OwnerProcessID == pid
                && PostThreadMessageW(entry.th32ThreadID, WM_QUIT, WPARAM(0), LPARAM(0)).is_ok()
            {
                posted += 1;
            }
            if Thread32Next(snapshot, &mut entry).is_err() {
                break;
            }
        }
    }
    Ok(posted)
}

struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

extern "system" fn enum_proc(hwnd: HWND, lparam: LPARAM) -> windows::Win32::Foundation::BOOL {
    let state = unsafe { &mut *(lparam.0 as *mut EnumState) };
    let mut owner_pid: u32 = 0;
    let _tid = unsafe { GetWindowThreadProcessId(hwnd, Some(&mut owner_pid)) };
    if owner_pid == state.target_pid {
        unsafe {
            // Best-effort: ignore failures (closed window, no message queue, etc.).
            let _ = PostMessageW(hwnd, WM_CLOSE, WPARAM(0), LPARAM(0));
        }
        state.posted += 1;
    }
    // Continue enumeration.
    windows::Win32::Foundation::BOOL(1)
}
