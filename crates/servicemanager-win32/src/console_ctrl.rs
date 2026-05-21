//! Console control signaling.
//!
//! Services start with no console attached. To deliver `CTRL+BREAK` to a
//! child we must own a console: we allocate one (silently), then send the
//! event to the child's process group. The child must have been created
//! with `CREATE_NEW_PROCESS_GROUP` so that the event is scoped to it.

use std::sync::OnceLock;

use servicemanager_core::{Error, Result};
use windows::Win32::System::Console::{AllocConsole, GenerateConsoleCtrlEvent, CTRL_BREAK_EVENT};

use crate::handles::win32_code;

static CONSOLE_READY: OnceLock<()> = OnceLock::new();

/// Ensure the current process is attached to a console (allocating one if
/// necessary) so it can dispatch console control events. Safe to call any
/// number of times; subsequent invocations are no-ops.
pub fn ensure_console() -> Result<()> {
    if CONSOLE_READY.get().is_some() {
        return Ok(());
    }
    unsafe {
        // If a console is already attached (e.g. when running from cmd) this
        // returns `ERROR_ACCESS_DENIED` (5), which we treat as success.
        match AllocConsole() {
            Ok(()) => {}
            Err(e) if win32_code(&e) == 5 => {}
            Err(e) => return Err(Error::Scm(format!("AllocConsole: {e}"))),
        }
    }
    let _ = CONSOLE_READY.set(());
    Ok(())
}

/// Send `CTRL+BREAK` to the process group with the given id. The target was
/// expected to be spawned with `CREATE_NEW_PROCESS_GROUP`; otherwise the
/// event reaches every process attached to our console (including us).
pub fn send_ctrl_break(process_group_id: u32) -> Result<()> {
    ensure_console()?;
    unsafe {
        GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, process_group_id)
            .map_err(|e| Error::Scm(format!("GenerateConsoleCtrlEvent: {e}")))?;
    }
    Ok(())
}
