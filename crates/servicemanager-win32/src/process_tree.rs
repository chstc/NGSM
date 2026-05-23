//! Process-tree enumeration + suspend/resume.
//!
//! - Enumeration walks parent-PID links via the Toolhelp32 snapshot. We
//!   start at the supervisor's direct child and recurse to descendants.
//!   A misbehaving service that re-parents will not be fully captured —
//!   the Job Object on the supervisor side is what makes the kill-tree
//!   semantics watertight; this walk is for *display*.
//! - Suspend/resume use the undocumented but stable `NtSuspendProcess` /
//!   `NtResumeProcess` from `ntdll.dll`, resolved lazily via
//!   `GetProcAddress`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::OnceLock;

use servicemanager_core::{Error, Result};
use windows::core::{s, PCSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Threading::{
    OpenProcess, TerminateProcess, PROCESS_SUSPEND_RESUME, PROCESS_TERMINATE,
};

/// One descendant of the service's root process.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub parent_pid: u32,
    pub image_name: String,
}

/// Walk descendants of `root_pid` (inclusive) using the Toolhelp32 process
/// snapshot. Order is breadth-first from the root.
pub fn enumerate_descendants(root_pid: u32) -> Result<Vec<ProcessInfo>> {
    let snapshot = unsafe {
        CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|e| Error::other(format!("CreateToolhelp32Snapshot: {e}")))?
    };
    let _guard = HandleGuard(snapshot);

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    let mut by_parent: HashMap<u32, Vec<ProcessInfo>> = HashMap::new();
    let mut by_pid: HashMap<u32, ProcessInfo> = HashMap::new();

    unsafe {
        if Process32FirstW(snapshot, &mut entry).is_err() {
            return Ok(Vec::new());
        }
        loop {
            let name_end = entry
                .szExeFile
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szExeFile.len());
            let image_name = String::from_utf16_lossy(&entry.szExeFile[..name_end]);
            let info = ProcessInfo {
                pid: entry.th32ProcessID,
                parent_pid: entry.th32ParentProcessID,
                image_name,
            };
            by_parent
                .entry(info.parent_pid)
                .or_default()
                .push(info.clone());
            by_pid.insert(info.pid, info);
            if Process32NextW(snapshot, &mut entry).is_err() {
                break;
            }
        }
    }

    let mut out = Vec::new();
    let mut seen: HashSet<u32> = HashSet::new();
    let mut queue: VecDeque<u32> = VecDeque::new();
    queue.push_back(root_pid);
    while let Some(pid) = queue.pop_front() {
        if !seen.insert(pid) {
            continue;
        }
        if let Some(info) = by_pid.get(&pid) {
            out.push(info.clone());
        }
        if let Some(children) = by_parent.get(&pid) {
            for c in children {
                queue.push_back(c.pid);
            }
        }
    }
    Ok(out)
}

/// Suspend every thread of `pid` by calling `NtSuspendProcess`.
pub fn suspend_process(pid: u32) -> Result<()> {
    let proc = open_for_suspend(pid)?;
    let f = nt_suspend_process()?;
    let status = unsafe { f(proc.0) };
    if status != 0 {
        return Err(Error::other(format!(
            "NtSuspendProcess: NTSTATUS {status:#x}"
        )));
    }
    Ok(())
}

/// Resume every thread of `pid` previously suspended by [`suspend_process`].
pub fn resume_process(pid: u32) -> Result<()> {
    let proc = open_for_suspend(pid)?;
    let f = nt_resume_process()?;
    let status = unsafe { f(proc.0) };
    if status != 0 {
        return Err(Error::other(format!(
            "NtResumeProcess: NTSTATUS {status:#x}"
        )));
    }
    Ok(())
}

fn open_for_suspend(pid: u32) -> Result<HandleGuard> {
    // SAFETY: `OpenProcess` returns an owned handle or an error; the handle
    // is wrapped in `HandleGuard` for RAII release.
    let handle = unsafe {
        OpenProcess(PROCESS_SUSPEND_RESUME, false, pid)
            .map_err(|e| Error::other(format!("OpenProcess({pid}): {e}")))?
    };
    Ok(HandleGuard(handle))
}

/// Forcibly terminate `pid`.
///
/// This is the supervisor's last-resort stop step: when the job-object kill
/// was skipped or failed, the immediate child is still owned (inside a
/// blocking `wait()`) by the exit-watcher thread, so `Child::kill` is not
/// available. Terminating by PID always works regardless of who holds the
/// `Child`.
pub fn terminate_process(pid: u32, exit_code: u32) -> Result<()> {
    // SAFETY: `OpenProcess` returns an owned handle or an error; the handle
    // is wrapped in `HandleGuard` for RAII release.
    let handle = unsafe {
        OpenProcess(PROCESS_TERMINATE, false, pid)
            .map_err(|e| Error::other(format!("OpenProcess({pid}) for terminate: {e}")))?
    };
    let guard = HandleGuard(handle);
    // SAFETY: `guard.0` is the live process handle just opened with
    // `PROCESS_TERMINATE`.
    unsafe {
        TerminateProcess(guard.0, exit_code)
            .map_err(|e| Error::other(format!("TerminateProcess({pid}): {e}")))?;
    }
    Ok(())
}

type NtProcessFn = unsafe extern "system" fn(HANDLE) -> i32;

static NT_SUSPEND: OnceLock<NtProcessFn> = OnceLock::new();
static NT_RESUME: OnceLock<NtProcessFn> = OnceLock::new();

fn nt_suspend_process() -> Result<NtProcessFn> {
    if let Some(f) = NT_SUSPEND.get() {
        return Ok(*f);
    }
    let f = load_ntdll_fn("NtSuspendProcess\0")?;
    let _ = NT_SUSPEND.set(f);
    Ok(f)
}

fn nt_resume_process() -> Result<NtProcessFn> {
    if let Some(f) = NT_RESUME.get() {
        return Ok(*f);
    }
    let f = load_ntdll_fn("NtResumeProcess\0")?;
    let _ = NT_RESUME.set(f);
    Ok(f)
}

fn load_ntdll_fn(name_with_nul: &str) -> Result<NtProcessFn> {
    unsafe {
        let module = GetModuleHandleA(s!("ntdll.dll"))
            .map_err(|e| Error::other(format!("GetModuleHandle(ntdll): {e}")))?;
        let proc =
            GetProcAddress(module, PCSTR::from_raw(name_with_nul.as_ptr())).ok_or_else(|| {
                Error::other(format!(
                    "GetProcAddress({})",
                    name_with_nul.trim_end_matches('\0')
                ))
            })?;
        // Retyping a function pointer via raw-pointer cast is the
        // documented idiom — direct transmute between two different
        // fn-pointer signatures is UB on calling conventions like
        // __stdcall (x86) where the callee cleans up the stack.
        let raw: *const () = proc as *const ();
        Ok(std::mem::transmute::<*const (), NtProcessFn>(raw))
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    fn spawn_long_lived_child() -> std::process::Child {
        Command::new("cmd.exe")
            .args(["/c", "ping", "127.0.0.1", "-n", "30", ">NUL"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(0x08000000)
            .spawn()
            .expect("spawn cmd.exe")
    }

    fn kill_and_wait(mut child: std::process::Child) {
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn enumerate_descendants_of_self_includes_a_spawned_child() {
        let child = spawn_long_lived_child();
        let child_pid = child.id();

        // Give Windows a moment to register the new process in the
        // toolhelp snapshot. The snapshot is updated immediately on
        // CreateProcess so this is usually instant, but a small wait
        // makes the test less flaky on a heavily-loaded machine.
        std::thread::sleep(Duration::from_millis(100));

        let self_pid = std::process::id();
        let descendants = enumerate_descendants(self_pid).expect("enumerate descendants");
        let found = descendants.iter().any(|p| p.pid == child_pid);
        assert!(
            found,
            "expected child pid {child_pid} in descendants of self ({self_pid}): {descendants:?}"
        );

        kill_and_wait(child);
    }

    #[test]
    fn enumerate_descendants_of_unknown_pid_returns_empty() {
        // An unreachable PID (Windows PIDs are multiples of 4; 0xFFFF_FFFC
        // is never a real process). The BFS finds no children of a PID that
        // does not appear in the snapshot, so the result must be empty.
        // The function returns Ok(vec![]) rather than Err in this case
        // because CreateToolhelp32Snapshot succeeds; the PID just has no
        // entry in the snapshot.
        let result = enumerate_descendants(0xFFFF_FFFC);
        match result {
            Ok(list) => assert!(
                list.is_empty(),
                "expected empty list for nonexistent pid, got {list:?}"
            ),
            Err(_) => { /* erroring is also acceptable */ }
        }
    }

    #[test]
    fn enumerate_descendants_has_no_duplicate_pids() {
        // The BFS seen-set should prevent any PID from appearing twice
        // even if the process tree has cycles in the parent-pid data.
        let self_pid = std::process::id();
        let descendants = enumerate_descendants(self_pid).expect("enumerate descendants");
        let mut seen: HashSet<u32> = HashSet::new();
        for p in &descendants {
            assert!(
                seen.insert(p.pid),
                "duplicate pid {} in descendant list",
                p.pid
            );
        }
    }
}
