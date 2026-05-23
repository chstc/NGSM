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
    let _guard = lock.lock().unwrap_or_else(|p| p.into_inner());

    // Stash the target pid + count where the C callback can find them.
    let mut state = EnumState {
        target_pid: pid,
        posted: 0,
    };
    let state_ptr = &mut state as *mut EnumState;

    // SAFETY: `enum_proc` has the correct `WNDENUMPROC` signature; `state_ptr`
    // points to a local `EnumState` on this stack frame which outlives the
    // synchronous `EnumWindows` call (the callback is invoked before this
    // returns). The serialisation mutex above guarantees there is no concurrent
    // `EnumWindows` call that could alias `state_ptr`.
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
    // SAFETY: `TH32CS_SNAPTHREAD` with pid=0 is the documented way to snapshot
    // all threads system-wide. The returned handle is wrapped in HandleGuard.
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
    // SAFETY: `snapshot` is a valid toolhelp snapshot handle (or we returned
    // early); `entry` is initialised with the correct `dwSize`; `Thread32First`
    // and `Thread32Next` mutate `entry` in-place per the API contract.
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
            // SAFETY: `self.0` is a toolhelp snapshot handle obtained from
            // `CreateToolhelp32Snapshot`; `is_invalid()` guards against null.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

extern "system" fn enum_proc(hwnd: HWND, lparam: LPARAM) -> windows::Win32::Foundation::BOOL {
    // SAFETY: `lparam` was set to `state_ptr` (a `*mut EnumState` on the
    // caller's stack) in `post_wm_close_to_process`. The serialisation mutex
    // ensures no concurrent enumeration, so this is the only live mutable
    // reference to `state` during this callback.
    let state = unsafe { &mut *(lparam.0 as *mut EnumState) };
    let mut owner_pid: u32 = 0;
    // SAFETY: `hwnd` is supplied by the OS enumeration and is valid for the
    // duration of the callback; `owner_pid` is a local on the stack.
    let _tid = unsafe { GetWindowThreadProcessId(hwnd, Some(&mut owner_pid)) };
    if owner_pid == state.target_pid {
        // SAFETY: `hwnd` is a live window handle provided by `EnumWindows`.
        // `PostMessageW` is documented to be safe to call from any thread;
        // failures (e.g. closed window, no message queue) are handled below.
        unsafe {
            match PostMessageW(hwnd, WM_CLOSE, WPARAM(0), LPARAM(0)) {
                Ok(()) => state.posted += 1,
                Err(e) => {
                    eprintln!(
                        "[windows_close] PostMessageW(hwnd=0x{:x}) failed: {e}",
                        hwnd.0 as usize
                    );
                }
            }
        }
    }
    // Continue enumeration.
    windows::Win32::Foundation::BOOL(1)
}
