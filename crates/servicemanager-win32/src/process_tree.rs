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
use std::os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::sync::OnceLock;

use servicemanager_core::{Error, Result};
use windows::core::{s, PCSTR};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_INVALID_PARAMETER, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Threading::{
    GetPriorityClass, GetProcessAffinityMask, GetProcessGroupAffinity, OpenProcess,
    SetPriorityClass, SetProcessAffinityMask, TerminateProcess, WaitForSingleObject,
    PROCESS_ACCESS_RIGHTS, PROCESS_CREATION_FLAGS, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SUSPEND_RESUME, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
};

/// Irreversibly terminate this host after lifecycle cleanup. Unlike a normal
/// ExitProcess path, this cannot deadlock in DLL detach behind a stalled worker.
pub fn terminate_current_process(exit_code: u32) -> ! {
    use windows::Win32::System::Threading::GetCurrentProcess;
    // SAFETY: the pseudo-handle names this process only; this is an explicit terminal boundary.
    unsafe {
        let _ = TerminateProcess(GetCurrentProcess(), exit_code);
    }
    // Terminating ourselves does not normally return. Keep a terminal fallback
    // rather than continuing a service that has already committed its outcome.
    std::process::exit(exit_code as i32)
}

/// An owned process identity. Controls use this handle, never reopen its PID.
pub struct PinnedProcess {
    handle: OwnedHandle,
    pid: u32,
}

impl PinnedProcess {
    pub(crate) fn open(pid: u32) -> Result<Option<Self>> {
        let access =
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SUSPEND_RESUME | PROCESS_SYNCHRONIZE;
        Self::open_with_access(pid, access)
    }

    fn open_with_access(pid: u32, access: PROCESS_ACCESS_RIGHTS) -> Result<Option<Self>> {
        // SAFETY: OpenProcess returns a new owned handle, or an error.
        let handle = match unsafe { OpenProcess(access, false, pid) } {
            Ok(handle) => handle,
            Err(e) if crate::handles::win32_code(&e) == ERROR_INVALID_PARAMETER.0 => {
                return Ok(None);
            }
            Err(e) => return Err(Error::other(format!("OpenProcess({pid}): {e}"))),
        };
        Ok(Some(Self {
            // SAFETY: ownership of the successful OpenProcess result is transferred once.
            handle: unsafe { OwnedHandle::from_raw_handle(handle.0) },
            pid,
        }))
    }

    pub(crate) fn from_child(child: &std::process::Child) -> Result<Self> {
        // SAFETY: Child owns this handle for the entire borrow; cloning pins the same object.
        let borrowed = unsafe { BorrowedHandle::borrow_raw(child.as_raw_handle()) };
        let handle = borrowed
            .try_clone_to_owned()
            .map_err(|e| Error::other(format!("duplicate child handle: {e}")))?;
        Ok(Self {
            handle,
            pid: child.id(),
        })
    }

    pub(crate) fn raw(&self) -> HANDLE {
        HANDLE(self.handle.as_raw_handle())
    }

    pub fn id(&self) -> u32 {
        self.pid
    }

    pub fn is_running(&self) -> Result<bool> {
        // SAFETY: the owned process handle has SYNCHRONIZE access.
        match unsafe { WaitForSingleObject(self.raw(), 0) } {
            WAIT_TIMEOUT => Ok(true),
            WAIT_OBJECT_0 => Ok(false),
            _ => Err(Error::other(format!(
                "query process {}: {}",
                self.pid,
                std::io::Error::last_os_error()
            ))),
        }
    }

    /// Returns false if the pinned process already exited.
    pub fn suspend(&self) -> Result<bool> {
        self.change_suspension(nt_suspend_process()?, "suspend")
    }

    /// Removes one suspension increment, not somebody else's additional increments.
    pub fn resume(&self) -> Result<bool> {
        self.change_suspension(nt_resume_process()?, "resume")
    }

    fn change_suspension(&self, operation: NtProcessFn, label: &str) -> Result<bool> {
        if !self.is_running()? {
            return Ok(false);
        }
        // SAFETY: operation has the Nt*Process signature and receives the retained handle.
        let status = unsafe { operation(self.raw()) };
        if status == 0 {
            Ok(true)
        } else if !self.is_running()? {
            Ok(false)
        } else {
            Err(Error::other(format!(
                "{label} process {}: NTSTATUS {status:#x}",
                self.pid
            )))
        }
    }

    /// Termination requires a handle retained from pin_child, rather than the
    /// smaller query/suspend capability used by member enumeration.
    pub fn terminate(&self, exit_code: u32) -> Result<()> {
        // SAFETY: this retained handle names the original process and has terminate access.
        match unsafe { TerminateProcess(self.raw(), exit_code) } {
            Ok(()) => Ok(()),
            Err(_) if !self.is_running()? => Ok(()),
            Err(e) => Err(Error::other(format!("terminate process {}: {e}", self.pid))),
        }
    }

    /// Apply launch settings before resuming a freshly created child.
    pub fn configure(&self, priority: Option<u32>, affinity: Option<&str>) -> Result<()> {
        if let Some(priority) = priority {
            if !matches!(priority, 0x20 | 0x40 | 0x80 | 0x100 | 0x4000 | 0x8000) {
                return Err(Error::InvalidConfig(
                    "AppPriority is not a supported priority class".into(),
                ));
            }
            // SAFETY: the pinned Child handle has PROCESS_SET_INFORMATION access.
            unsafe { SetPriorityClass(self.raw(), PROCESS_CREATION_FLAGS(priority)) }
                .map_err(|e| Error::other(format!("set child priority: {e}")))?;
            // Windows may silently downgrade REALTIME without the appropriate privilege.
            // SAFETY: the handle has query access.
            if unsafe { GetPriorityClass(self.raw()) } != priority {
                return Err(Error::other("the requested child priority was not granted"));
            }
        }
        if let Some(affinity) = affinity {
            let mut groups = [0u16; 64];
            let mut count = groups.len() as u16;
            // SAFETY: count describes the writable group buffer and the handle is valid.
            unsafe { GetProcessGroupAffinity(self.raw(), &mut count, groups.as_mut_ptr()) }
                .ok()
                .map_err(|e| Error::other(format!("query child processor groups: {e}")))?;
            if count != 1 || groups[0] != 0 {
                return Err(Error::InvalidConfig(
                    "AppAffinity currently supports only a child in processor group 0".into(),
                ));
            }
            let mut process_mask = 0usize;
            let mut system_mask = 0usize;
            // SAFETY: both output pointers are valid and the process handle has query access.
            unsafe { GetProcessAffinityMask(self.raw(), &mut process_mask, &mut system_mask) }
                .map_err(|e| Error::other(format!("query child affinity: {e}")))?;
            let mask = parse_affinity(affinity, system_mask)?;
            // SAFETY: the validated mask only contains available CPUs in the sole group.
            unsafe { SetProcessAffinityMask(self.raw(), mask) }
                .map_err(|e| Error::other(format!("set child affinity: {e}")))?;
        }
        Ok(())
    }
}

fn parse_affinity(value: &str, available: usize) -> Result<usize> {
    let invalid = || {
        Error::InvalidConfig(
            "AppAffinity must be CPU IDs/ranges (for example 0-2,4) available in processor group 0"
                .into(),
        )
    };
    let mut mask = 0usize;
    for part in value.split(',') {
        let (first, last) = match part.split_once('-') {
            Some((first, last)) => (first, last),
            None => (part, part),
        };
        if first.is_empty()
            || last.is_empty()
            || !first.bytes().all(|b| b.is_ascii_digit())
            || !last.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(invalid());
        }
        let first: u32 = first.parse().map_err(|_| invalid())?;
        let last: u32 = last.parse().map_err(|_| invalid())?;
        if first > last || last >= usize::BITS {
            return Err(invalid());
        }
        for cpu in first..=last {
            mask |= 1usize << cpu;
        }
    }
    if mask == 0 || mask & !available != 0 {
        return Err(invalid());
    }
    Ok(mask)
}

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
    // SAFETY: `TH32CS_SNAPPROCESS` with pid=0 is the documented way to snapshot
    // all running processes; the returned handle is wrapped in HandleGuard.
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

    // SAFETY: `snapshot` is a valid toolhelp snapshot handle (obtained above);
    // `entry` is initialised with the correct `dwSize`; `Process32FirstW` and
    // `Process32NextW` write into `entry` in-place per the API contract.
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
    // SAFETY: `f` is `NtSuspendProcess` resolved from `ntdll.dll` with the
    // correct function signature; `proc.0` is a live process handle opened
    // with `PROCESS_SUSPEND_RESUME` by `open_for_suspend`.
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
    // SAFETY: `f` is `NtResumeProcess` resolved from `ntdll.dll` with the
    // correct function signature; `proc.0` is a live process handle opened
    // with `PROCESS_SUSPEND_RESUME` by `open_for_suspend`.
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
    // SAFETY: `ntdll.dll` is always loaded in every Windows process; `s!` is a
    // null-terminated literal; `name_with_nul` is required by callers to end
    // with `\0`. The transmute converts the opaque `FARPROC` to the concrete
    // `NtProcessFn` type — both are function pointers with the `extern "system"`
    // calling convention and a single `HANDLE` argument, so the cast is sound.
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
            // SAFETY: `self.0` is a process handle obtained from `OpenProcess`;
            // `is_invalid()` guards against a null handle.
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

    #[test]
    #[ignore = "uniquely owned subprocess fixture for the irreversible host boundary"]
    fn terminates_self_fixture() {
        terminate_current_process(37);
    }

    #[test]
    fn deliberate_host_termination_preserves_the_nonzero_exit_code() {
        use crate::job::JobObject;
        let job = JobObject::new_kill_on_close().unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "process_tree::tests::terminates_self_fixture",
                "--ignored",
                "--nocapture",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(4)
            .spawn()
            .unwrap();
        job.assign_child(&child).unwrap();
        job.pin_child(&child).unwrap().resume().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert_eq!(status.code(), Some(37));
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "owned termination fixture must exit"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

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
    fn affinity_is_a_bounded_cpu_id_list_not_an_integer_mask() {
        assert_eq!(parse_affinity("0-2,4", 0b10111).unwrap(), 0b10111);
        assert_eq!(parse_affinity("1,1", 0b10111).unwrap(), 2);
        for invalid in ["", "-1", "2-1", "1,,2", "64", "3", "0x3", "all", " 1"] {
            assert!(parse_affinity(invalid, 0b10111).is_err(), "{invalid}");
        }
    }

    #[test]
    fn pinned_child_settings_apply_before_execution_and_do_not_reopen_cached_pid() {
        use crate::job::JobObject;
        let executable = std::path::PathBuf::from(
            std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into()),
        )
        .join("System32")
        .join("cmd.exe");
        let job = JobObject::new_kill_on_close().unwrap();
        let mut child = Command::new(&executable)
            .args(["/d", "/c", "exit", "0"])
            .creation_flags(4)
            .spawn()
            .unwrap();
        job.assign_child(&child).unwrap();
        let mut pinned = job.pin_child(&child).unwrap();
        pinned.configure(Some(0x4000), None).unwrap();
        // SAFETY: the retained child handle grants query access.
        assert_eq!(unsafe { GetPriorityClass(pinned.raw()) }, 0x4000);
        let mut group_count = 64u16;
        let mut groups = [0u16; 64];
        // SAFETY: the count and buffer describe writable storage.
        unsafe { GetProcessGroupAffinity(pinned.raw(), &mut group_count, groups.as_mut_ptr()) }
            .ok()
            .unwrap();
        if group_count == 1 && groups[0] == 0 {
            let mut process = 0usize;
            let mut available = 0usize;
            // SAFETY: both output pointers and the retained query handle are valid.
            unsafe { GetProcessAffinityMask(pinned.raw(), &mut process, &mut available) }.unwrap();
            let cpu = available.trailing_zeros();
            pinned.configure(None, Some(&cpu.to_string())).unwrap();
            // SAFETY: the output pointers remain valid.
            unsafe { GetProcessAffinityMask(pinned.raw(), &mut process, &mut available) }.unwrap();
            assert_eq!(process, 1usize << cpu);
        } else {
            assert!(pinned.configure(None, Some("0")).is_err());
        }
        assert!(pinned.configure(Some(123), None).is_err());
        let mut other = Command::new(&executable)
            .args(["/d", "/c", "exit", "0"])
            .creation_flags(4)
            .spawn()
            .unwrap();
        job.assign_child(&other).unwrap();
        // Fault-inject a changed PID mapping using a second, uniquely owned fixture.
        // The control must still use the original retained process object.
        pinned.pid = other.id();
        assert!(pinned.resume().unwrap());
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while child.try_wait().unwrap().is_none() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(!pinned.is_running().unwrap());
        assert!(!pinned.suspend().unwrap());
        assert!(
            other.try_wait().unwrap().is_none(),
            "the other suspended fixture must not be resumed"
        );
        job.terminate(1).unwrap();
        while other.try_wait().unwrap().is_none() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
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
