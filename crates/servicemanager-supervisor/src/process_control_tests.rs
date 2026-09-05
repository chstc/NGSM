use super::*;
use servicemanager_win32::{process_tree::PinnedProcess, JobObject};
use std::os::windows::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

#[path = "process_control_review_tests.rs"]
mod review;

struct Workers {
    job: Arc<JobObject>,
    children: Vec<Child>,
    processes: Vec<Arc<PinnedProcess>>,
}

impl Workers {
    fn new(count: usize) -> Self {
        let job = Arc::new(JobObject::new_kill_on_close().unwrap());
        let mut workers = Self {
            job,
            children: Vec::new(),
            processes: Vec::new(),
        };
        for _ in 0..count {
            let child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tests::fixture_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("NGSM_TEST_CHILD_MODE", "heartbeat")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags(4)
                .spawn()
                .unwrap();
            workers.job.assign_child(&child).unwrap();
            let process = Arc::new(workers.job.pin_child(&child).unwrap());
            process.resume().unwrap();
            workers.children.push(child);
            workers.processes.push(process);
        }
        std::thread::sleep(Duration::from_millis(40));
        workers
    }
}
impl Drop for Workers {
    fn drop(&mut self) {
        let _ = self.job.terminate(1);
        for child in &mut self.children {
            crate::kill_owned_child(child);
        }
    }
}

struct FaultMember {
    process: Arc<PinnedProcess>,
    fail_suspend: AtomicBool,
    fail_resume: AtomicBool,
    cancel_after_suspend: Option<Arc<AtomicBool>>,
    after_resume: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}
impl FaultMember {
    fn new(process: Arc<PinnedProcess>) -> Arc<Self> {
        Arc::new(Self {
            process,
            fail_suspend: AtomicBool::new(false),
            fail_resume: AtomicBool::new(false),
            cancel_after_suspend: None,
            after_resume: Mutex::new(None),
        })
    }
}
impl Member for FaultMember {
    fn id(&self) -> u32 {
        self.process.id()
    }
    fn running(&self) -> Result<bool, String> {
        self.process.is_running().map_err(|e| e.to_string())
    }
    fn suspend(&self) -> Result<bool, String> {
        if self.fail_suspend.swap(false, Ordering::AcqRel) {
            return Err("injected suspend failure".into());
        }
        let result = self.process.suspend().map_err(|e| e.to_string());
        if let Some(cancelled) = &self.cancel_after_suspend {
            cancelled.store(true, Ordering::Release);
        }
        result
    }
    fn resume(&self) -> Result<bool, String> {
        if self.fail_resume.swap(false, Ordering::AcqRel) {
            return Err("injected resume failure".into());
        }
        let result = self.process.resume().map_err(|e| e.to_string());
        if matches!(result, Ok(true)) {
            let after_resume = self.after_resume.lock().unwrap().take();
            if let Some(after_resume) = after_resume {
                after_resume();
            }
        }
        result
    }
}

fn members(processes: &[Arc<FaultMember>]) -> Vec<Arc<dyn Member>> {
    processes
        .iter()
        .map(|process| Arc::clone(process) as Arc<dyn Member>)
        .collect()
}

fn suspension_count(pid: u32) -> u32 {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows::Win32::System::Threading::{
        GetProcessIdOfThread, OpenThread, ResumeThread, SuspendThread,
        THREAD_QUERY_LIMITED_INFORMATION, THREAD_SUSPEND_RESUME,
    };
    // SAFETY: snapshot is a new owned handle; enumeration changes no processes.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) }.unwrap();
    // SAFETY: transfer that one owned snapshot handle to RAII storage.
    let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot.0) };
    let mut entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };
    // SAFETY: the snapshot and initialized output structure are valid.
    unsafe { Thread32First(HANDLE(snapshot.as_raw_handle()), &mut entry) }.unwrap();
    loop {
        if entry.th32OwnerProcessID == pid {
            // SAFETY: the new thread handle is verified against our pinned child before control.
            if let Ok(handle) = unsafe {
                OpenThread(
                    THREAD_QUERY_LIMITED_INFORMATION | THREAD_SUSPEND_RESUME,
                    false,
                    entry.th32ThreadID,
                )
            } {
                // SAFETY: transfer the returned owned thread handle exactly once.
                let handle = unsafe { OwnedHandle::from_raw_handle(handle.0) };
                let raw = HANDLE(handle.as_raw_handle());
                // SAFETY: GetProcessIdOfThread queries the retained thread object.
                if unsafe { GetProcessIdOfThread(raw) } == pid {
                    // SAFETY: probe only our owned child; undo precisely our extra increment.
                    let count = unsafe { SuspendThread(raw) };
                    if count != u32::MAX {
                        // SAFETY: undo the preceding successful SuspendThread.
                        assert_ne!(unsafe { ResumeThread(raw) }, u32::MAX);
                        return count;
                    }
                }
            }
        }
        // SAFETY: the snapshot and output structure remain valid.
        if unsafe { Thread32Next(HANDLE(snapshot.as_raw_handle()), &mut entry) }.is_err() {
            break;
        }
    }
    panic!("fixture has no inspectable live thread");
}

#[test]
fn partial_native_suspend_failure_rolls_back_and_duplicate_controls_are_idempotent() {
    let workers = Workers::new(2);
    let processes: Vec<_> = workers
        .processes
        .iter()
        .cloned()
        .map(FaultMember::new)
        .collect();
    let mut state = PauseState::default();
    processes[1].fail_suspend.store(true, Ordering::Release);
    assert!(matches!(
        state.change(true, || Ok(members(&processes)), || false),
        TransitionOutcome::Rejected(_)
    ));
    assert!(!state.paused);
    assert_eq!(suspension_count(processes[0].id()), 0);
    assert_eq!(
        state.change(true, || Ok(members(&processes)), || false),
        TransitionOutcome::Applied
    );
    assert_eq!(
        state.change(
            true,
            || panic!("duplicate pause must not enumerate"),
            || false
        ),
        TransitionOutcome::Applied
    );
    assert_eq!(suspension_count(processes[0].id()), 1);
    assert_eq!(
        state.change(false, || Ok(members(&processes)), || false),
        TransitionOutcome::Applied
    );
    assert_eq!(
        state.change(
            false,
            || panic!("duplicate continue must not enumerate"),
            || false
        ),
        TransitionOutcome::Applied
    );
    assert_eq!(suspension_count(processes[0].id()), 0);
}

#[test]
fn partial_native_resume_failure_restores_the_paused_state() {
    let workers = Workers::new(2);
    let processes: Vec<_> = workers
        .processes
        .iter()
        .cloned()
        .map(FaultMember::new)
        .collect();
    let mut state = PauseState::default();
    assert_eq!(
        state.change(true, || Ok(members(&processes)), || false),
        TransitionOutcome::Applied
    );
    processes[0].fail_resume.store(true, Ordering::Release);
    assert!(matches!(
        state.change(false, || Ok(members(&processes)), || false),
        TransitionOutcome::Rejected(_)
    ));
    assert!(state.paused);
    for process in &processes {
        assert_eq!(suspension_count(process.id()), 1);
    }
    assert_eq!(
        state.change(false, || Ok(members(&processes)), || false),
        TransitionOutcome::Applied
    );
    for process in &processes {
        assert_eq!(suspension_count(process.id()), 0);
    }
}

#[test]
fn cancellation_during_native_suspend_undoes_owned_increments() {
    let workers = Workers::new(1);
    let cancelled = Arc::new(AtomicBool::new(false));
    let process = Arc::new(FaultMember {
        process: Arc::clone(&workers.processes[0]),
        fail_suspend: AtomicBool::new(false),
        fail_resume: AtomicBool::new(false),
        cancel_after_suspend: Some(Arc::clone(&cancelled)),
        after_resume: Mutex::new(None),
    });
    let mut state = PauseState::default();
    assert_eq!(
        state.change(
            true,
            || Ok(members(&[Arc::clone(&process)])),
            || cancelled.load(Ordering::Acquire)
        ),
        TransitionOutcome::Cancelled
    );
    assert!(!state.paused);
    assert_eq!(suspension_count(process.id()), 0);
}

#[test]
fn membership_failure_rolls_back_but_failed_rollback_is_explicitly_degraded() {
    let workers = Workers::new(2);
    let processes: Vec<_> = workers
        .processes
        .iter()
        .cloned()
        .map(FaultMember::new)
        .collect();
    let mut state = PauseState::default();
    let mut pass = 0;
    assert!(matches!(
        state.change(
            true,
            || {
                pass += 1;
                if pass == 1 {
                    Ok(members(&processes[..1]))
                } else {
                    Err("injected membership failure".into())
                }
            },
            || false
        ),
        TransitionOutcome::Rejected(_)
    ));
    assert_eq!(suspension_count(processes[0].id()), 0);
    processes[1].fail_suspend.store(true, Ordering::Release);
    processes[0].fail_resume.store(true, Ordering::Release);
    assert!(matches!(
        state.change(true, || Ok(members(&processes)), || false),
        TransitionOutcome::Degraded(_)
    ));
    assert_eq!(suspension_count(processes[0].id()), 1);
}

#[test]
fn bounded_stable_passes_include_a_member_discovered_after_the_first_pass() {
    let workers = Workers::new(2);
    let processes: Vec<_> = workers
        .processes
        .iter()
        .cloned()
        .map(FaultMember::new)
        .collect();
    let mut state = PauseState::default();
    let mut pass = 0;
    assert_eq!(
        state.change(
            true,
            || {
                pass += 1;
                Ok(if pass == 1 {
                    members(&processes[..1])
                } else {
                    members(&processes)
                })
            },
            || false
        ),
        TransitionOutcome::Applied
    );
    assert!(pass >= 3);
    for process in &processes {
        assert_eq!(suspension_count(process.id()), 1);
    }
    assert_eq!(
        state.change(false, || Ok(members(&processes)), || false),
        TransitionOutcome::Applied
    );
}
