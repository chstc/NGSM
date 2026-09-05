use super::*;
use std::cell::Cell;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{mpsc, Mutex};

#[derive(Clone, Copy)]
enum Script {
    None,
    StopWhilePending,
    CancelThenStop,
}

struct FakeContext {
    tx: mpsc::Sender<ServiceControl>,
    rx: mpsc::Receiver<ServiceControl>,
    statuses: Mutex<Vec<Status>>,
    terminal: AtomicU8,
    flood: bool,
    script: Script,
    clock: Cell<Instant>,
}

impl FakeContext {
    fn new(flood: bool, script: Script) -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            tx,
            rx,
            statuses: Mutex::new(Vec::new()),
            terminal: AtomicU8::new(0),
            flood,
            script,
            clock: Cell::new(Instant::now()),
        }
    }
    fn accept_stop(&self) {
        assert!(self
            .terminal
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok());
        self.tx.send(ServiceControl::Stop).unwrap();
    }
}

impl Context for FakeContext {
    fn try_recv(&self) -> std::result::Result<ServiceControl, TryRecvError> {
        match self.rx.try_recv() {
            Err(TryRecvError::Empty) if self.flood => Ok(ServiceControl::Interrogate),
            result => result,
        }
    }
    fn recv_timeout(
        &self,
        timeout: Duration,
    ) -> std::result::Result<ServiceControl, RecvTimeoutError> {
        // Advance the bridge's injected clock independently of Windows timer granularity.
        self.clock.set(self.clock.get() + timeout);
        if self.flood {
            return Ok(ServiceControl::Interrogate);
        }
        self.rx.recv_timeout(timeout)
    }
    fn report(&self, status: Status) -> Result<()> {
        let mut statuses = self.statuses.lock().unwrap();
        statuses.push(status);
        let running_count = statuses
            .iter()
            .filter(|&&status| status == Status::Running)
            .count();
        drop(statuses);
        match (self.script, status, running_count) {
            (Script::StopWhilePending | Script::CancelThenStop, Status::Running, 1) => {
                self.tx.send(ServiceControl::Pause).unwrap();
            }
            (Script::StopWhilePending, Status::PausePending, _) if !self.stop_requested() => {
                self.accept_stop()
            }
            (Script::CancelThenStop, Status::Running, 2) => self.accept_stop(),
            _ => {}
        }
        Ok(())
    }
    fn stop_requested(&self) -> bool {
        self.terminal.load(Ordering::Acquire) == 1
    }
    fn claim_terminal(&self) -> bool {
        match self
            .terminal
            .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => false,
            Err(1) => true,
            Err(_) => false,
        }
    }
    fn now(&self) -> Instant {
        self.clock.get()
    }
}

fn timing() -> Timing {
    Timing {
        poll: Duration::from_millis(1),
        checkpoint: Duration::from_millis(5),
        startup: Duration::from_millis(100),
        transition: Duration::from_millis(20),
        stop: Duration::from_secs(2),
    }
}

#[test]
fn continuous_controls_do_not_hide_a_finished_supervisor_before_startup() {
    let mut supervisor = Supervisor::new("RunnerFixture", Default::default());
    let signals = Signals::for_supervisor(&mut supervisor);
    let (startup_tx, startup) = mpsc::channel();
    drop(startup_tx);
    let handle = thread::spawn(|| Ok(ExitReason::Suicide { exit_code: 7 }));
    while !handle.is_finished() {
        thread::yield_now();
    }
    let context = FakeContext::new(true, Script::None);
    let started = Instant::now();
    let result = bridge(
        "RunnerFixture",
        &context,
        startup,
        handle,
        signals,
        timing(),
    );
    assert_eq!(result.terminal, Terminal::Crash(7));
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(!context.statuses.lock().unwrap().contains(&Status::Running));
}

#[test]
fn explicit_stop_overrides_suicide_even_when_completion_is_already_available() {
    let mut supervisor = Supervisor::new("StopRace", Default::default());
    let signals = Signals::for_supervisor(&mut supervisor);
    let (_startup_tx, startup) = mpsc::channel();
    let handle = thread::spawn(|| Ok(ExitReason::Suicide { exit_code: 7 }));
    while !handle.is_finished() {
        thread::yield_now();
    }
    let context = FakeContext::new(true, Script::None);
    context.accept_stop();
    let result = bridge("StopRace", &context, startup, handle, signals, timing());
    assert_eq!(result.terminal, Terminal::Stopped(0));
}

fn pending_fixture(script: Script) -> Vec<Status> {
    let mut supervisor = Supervisor::new("PendingFixture", Default::default());
    let signals = Signals::for_supervisor(&mut supervisor);
    let stop = signals.stop.clone();
    let (startup_tx, startup) = mpsc::channel();
    startup_tx.send(StartupStatus::Running).unwrap();
    let handle = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !stop.is_requested() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        assert!(stop.is_requested(), "runner must keep Stop responsive");
        Ok(ExitReason::Stopped)
    });
    let context = FakeContext::new(false, script);
    let result = bridge(
        "PendingFixture",
        &context,
        startup,
        handle,
        signals,
        timing(),
    );
    assert_eq!(result.terminal, Terminal::Stopped(0));
    context.statuses.into_inner().unwrap()
}

#[test]
fn stop_remains_responsive_while_a_pause_acknowledgement_is_pending() {
    let statuses = pending_fixture(Script::StopWhilePending);
    assert!(statuses.contains(&Status::PausePending));
    assert!(statuses.contains(&Status::StopPending));
    assert!(!statuses.contains(&Status::Paused));
}

#[test]
fn queued_timeout_refreshes_checkpoints_and_restores_only_after_confirmed_cancellation() {
    let statuses = pending_fixture(Script::CancelThenStop);
    assert!(
        statuses
            .iter()
            .filter(|&&status| status == Status::PausePending)
            .count()
            >= 2
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|&&status| status == Status::Running)
            .count(),
        2
    );
    assert!(!statuses.contains(&Status::Paused));
}

#[test]
fn final_terminal_claim_gives_an_already_accepted_stop_precedence() {
    let context = FakeContext::new(false, Script::None);
    context.accept_stop();
    finish(
        &context,
        "FinalRace",
        BridgeExit {
            terminal: Terminal::Crash(7),
            force_exit: false,
        },
    );
    assert_eq!(
        context.statuses.lock().unwrap().last(),
        Some(&Status::Stopped(0))
    );
}
