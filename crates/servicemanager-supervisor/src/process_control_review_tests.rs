use super::*;

struct BornMembers {
    job: Arc<JobObject>,
    children: Mutex<Vec<Child>>,
    processes: Mutex<Vec<Arc<FaultMember>>>,
}

impl BornMembers {
    fn new(job: &Arc<JobObject>) -> Arc<Self> {
        Arc::new(Self {
            job: Arc::clone(job),
            children: Mutex::new(Vec::new()),
            processes: Mutex::new(Vec::new()),
        })
    }

    fn spawn(&self) -> Arc<FaultMember> {
        let mut child = Command::new(std::env::current_exe().unwrap())
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
        if let Err(error) = self.job.assign_child(&child) {
            crate::kill_owned_child(&mut child);
            panic!("contain newborn fixture: {error}");
        }
        let process = Arc::new(self.job.pin_child(&child).unwrap());
        process.resume().unwrap();
        let process = FaultMember::new(process);
        self.children.lock().unwrap().push(child);
        self.processes.lock().unwrap().push(Arc::clone(&process));
        process
    }

    fn snapshot(&self, originals: &[Arc<FaultMember>]) -> Vec<Arc<dyn Member>> {
        let mut result = members(originals);
        result.extend(members(&self.processes.lock().unwrap()));
        result
    }
}

impl Drop for BornMembers {
    fn drop(&mut self) {
        for child in self
            .children
            .get_mut()
            .unwrap_or_else(|error| error.into_inner())
        {
            crate::kill_owned_child(child);
        }
    }
}

#[test]
fn failed_or_cancelled_resume_pauses_newborn_members_once_and_retains_them_for_continue() {
    for cancel in [false, true] {
        let workers = Workers::new(2);
        let originals: Vec<_> = workers
            .processes
            .iter()
            .cloned()
            .map(FaultMember::new)
            .collect();
        let born = BornMembers::new(&workers.job);
        let mut state = PauseState::default();
        assert_eq!(
            state.change(true, || Ok(members(&originals)), || false),
            TransitionOutcome::Applied
        );
        let cancelled = Arc::new(AtomicBool::new(false));
        let on_resume_born = Arc::clone(&born);
        let on_resume_cancelled = Arc::clone(&cancelled);
        *originals[1].after_resume.lock().unwrap() = Some(Box::new(move || {
            on_resume_born.spawn();
            if cancel {
                on_resume_cancelled.store(true, Ordering::Release);
            }
        }));
        originals[0].fail_resume.store(!cancel, Ordering::Release);
        let outcome = state.change(
            false,
            || Ok(born.snapshot(&originals)),
            || cancelled.load(Ordering::Acquire),
        );
        assert!(if cancel {
            outcome == TransitionOutcome::Cancelled
        } else {
            matches!(outcome, TransitionOutcome::Rejected(_))
        });
        assert!(state.paused);
        let all = born.snapshot(&originals);
        assert_eq!(
            all.len(),
            3,
            "an early real resume must create a new contained process"
        );
        for process in &all {
            assert_eq!(
                suspension_count(process.id()),
                1,
                "every live job member needs exactly one owned pause increment"
            );
        }
        assert_eq!(state.owned.len(), 3, "new handles must survive recovery");
        assert_eq!(
            state.change(false, || Ok(born.snapshot(&originals)), || false),
            TransitionOutcome::Applied
        );
        for process in &all {
            assert_eq!(
                suspension_count(process.id()),
                0,
                "a later Continue must resume both original and newborn members"
            );
        }
    }
}

#[test]
fn resume_recovery_enumeration_or_new_member_failure_is_degraded_even_after_cancellation() {
    for fail_enumeration in [true, false] {
        let workers = Workers::new(2);
        let originals: Vec<_> = workers
            .processes
            .iter()
            .cloned()
            .map(FaultMember::new)
            .collect();
        let born = BornMembers::new(&workers.job);
        let mut state = PauseState::default();
        assert_eq!(
            state.change(true, || Ok(members(&originals)), || false),
            TransitionOutcome::Applied
        );
        let cancelled = Arc::new(AtomicBool::new(false));
        let on_resume_born = Arc::clone(&born);
        let on_resume_cancelled = Arc::clone(&cancelled);
        *originals[1].after_resume.lock().unwrap() = Some(Box::new(move || {
            let process = on_resume_born.spawn();
            process
                .fail_suspend
                .store(!fail_enumeration, Ordering::Release);
            on_resume_cancelled.store(true, Ordering::Release);
        }));
        let result = state.change(
            false,
            || {
                if fail_enumeration {
                    Err("injected recovery enumeration failure".into())
                } else {
                    Ok(born.snapshot(&originals))
                }
            },
            || cancelled.load(Ordering::Acquire),
        );
        assert!(
            matches!(result, TransitionOutcome::Degraded(_)),
            "unconfirmed paused state must not be reported as Cancelled/Rejected: {result:?}"
        );
    }
}

#[test]
fn resume_recovery_that_never_stabilizes_has_a_bounded_degraded_outcome() {
    let workers = Workers::new(2);
    let originals: Vec<_> = workers
        .processes
        .iter()
        .cloned()
        .map(FaultMember::new)
        .collect();
    let born = BornMembers::new(&workers.job);
    let mut state = PauseState::default();
    assert_eq!(
        state.change(true, || Ok(members(&originals)), || false),
        TransitionOutcome::Applied
    );
    originals[0].fail_resume.store(true, Ordering::Release);
    let mut passes = 0;
    let started = Instant::now();
    let result = state.change(
        false,
        || {
            passes += 1;
            born.spawn();
            Ok(born.snapshot(&originals))
        },
        || false,
    );
    assert!(
        matches!(result, TransitionOutcome::Degraded(_)),
        "a perpetually changing job cannot be claimed paused: {result:?}"
    );
    assert!(
        passes > 0 && passes <= 16,
        "recovery membership passes must be bounded"
    );
    assert!(started.elapsed() < Duration::from_secs(5));
}
