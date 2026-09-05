//! SCM bridge. Controls, generation completion and transition checkpoints are
//! polled independently; a pending control never guesses the previous state.

use servicemanager_core::{Error, Result};
use servicemanager_supervisor::ExitReason;

pub const SUICIDE_FALLBACK_EXIT_CODE: u32 = 1;
pub const SUPERVISOR_ERROR_EXIT_CODE: u32 = 2;

pub fn service_exit_code_for(reason: ExitReason) -> u32 {
    match reason {
        ExitReason::Stopped | ExitReason::ChildExited => 0,
        ExitReason::SpawnFailed => SUPERVISOR_ERROR_EXIT_CODE,
        ExitReason::Suicide { exit_code } if exit_code > 0 => exit_code as u32,
        ExitReason::Suicide { .. } => SUICIDE_FALLBACK_EXIT_CODE,
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Terminal {
    Stopped(u32),
    /// No SERVICE_STOPPED report: SCM recovery also works with failureflag=0.
    Crash(u32),
}

fn terminal_for(reason: std::result::Result<ExitReason, ()>, explicit_stop: bool) -> Terminal {
    if explicit_stop {
        return Terminal::Stopped(0);
    }
    match reason {
        Ok(reason @ ExitReason::Suicide { .. }) => Terminal::Crash(service_exit_code_for(reason)),
        Ok(reason) => Terminal::Stopped(service_exit_code_for(reason)),
        Err(()) => Terminal::Stopped(SUPERVISOR_ERROR_EXIT_CODE),
    }
}

#[cfg(windows)]
mod windows_runner {
    use super::*;
    use std::sync::mpsc::{Receiver, RecvTimeoutError, TryRecvError};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    use servicemanager_supervisor::{
        diagnostics, PauseContinueSignal, PowerEventSignal, RotateSignal, StartupStatus,
        StopSignal, Supervisor, SupervisorError, TerminalGate, Transition, TransitionOutcome,
    };
    use servicemanager_win32::{
        ensure_console, run_service_dispatcher, ServiceContext, ServiceControl,
    };

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Status {
        StartPending,
        Running,
        PausePending,
        Paused,
        ContinuePending,
        StopPending,
        Stopped(u32),
    }

    trait Context {
        fn recv_timeout(
            &self,
            timeout: Duration,
        ) -> std::result::Result<ServiceControl, RecvTimeoutError>;
        fn try_recv(&self) -> std::result::Result<ServiceControl, TryRecvError>;
        fn report(&self, status: Status) -> Result<()>;
        fn stop_requested(&self) -> bool {
            false
        }
        fn claim_terminal(&self) -> bool {
            self.stop_requested()
        }
        fn now(&self) -> Instant {
            Instant::now()
        }
    }

    impl Context for ServiceContext {
        fn stop_requested(&self) -> bool {
            ServiceContext::stop_requested(self)
        }
        fn claim_terminal(&self) -> bool {
            ServiceContext::claim_terminal(self)
        }
        fn recv_timeout(
            &self,
            timeout: Duration,
        ) -> std::result::Result<ServiceControl, RecvTimeoutError> {
            self.controls().recv_timeout(timeout)
        }
        fn try_recv(&self) -> std::result::Result<ServiceControl, TryRecvError> {
            self.controls().try_recv()
        }
        fn report(&self, status: Status) -> Result<()> {
            match status {
                Status::StartPending => self.report_start_pending(6_000),
                Status::Running => self.report_running(),
                Status::PausePending => self.report_pause_pending(20_000),
                Status::Paused => self.report_paused(),
                Status::ContinuePending => self.report_continue_pending(20_000),
                Status::StopPending => self.report_stop_pending(8_000),
                Status::Stopped(code) => self.report_stopped(code),
            }
        }
    }

    #[derive(Clone, Copy)]
    struct Timing {
        poll: Duration,
        checkpoint: Duration,
        startup: Duration,
        transition: Duration,
        stop: Duration,
    }
    impl Default for Timing {
        fn default() -> Self {
            Self {
                poll: Duration::from_millis(250),
                checkpoint: Duration::from_secs(2),
                startup: Duration::from_secs(60),
                transition: Duration::from_secs(15),
                stop: Duration::from_secs(120),
            }
        }
    }

    struct Signals {
        stop: StopSignal,
        rotate: RotateSignal,
        pause: PauseContinueSignal,
        power: PowerEventSignal,
        terminal: TerminalGate,
    }
    impl Signals {
        fn for_supervisor(supervisor: &mut Supervisor) -> Self {
            Self {
                stop: supervisor.stop_signal(),
                rotate: supervisor.rotate_signal(),
                pause: supervisor.pause_continue_signal(),
                power: supervisor.power_event_signal(),
                terminal: supervisor.terminal_gate(),
            }
        }
    }

    struct Pending {
        request: Transition,
        pause: bool,
        started: Instant,
    }

    struct BridgeExit {
        terminal: Terminal,
        force_exit: bool,
    }

    fn report(context: &impl Context, name: &str, status: Status) {
        if let Err(error) = context.report(status) {
            diagnostics::report(name, "SCM status", format!("{status:?}: {error}"));
        }
    }

    fn bridge(
        name: &str,
        context: &impl Context,
        startup: Receiver<StartupStatus>,
        handle: JoinHandle<std::result::Result<ExitReason, SupervisorError>>,
        signals: Signals,
        timing: Timing,
    ) -> BridgeExit {
        let started = context.now();
        let mut handle = Some(handle);
        let mut checkpoint = started;
        let mut running = false;
        let mut paused = false;
        let mut stopping = None;
        let mut explicit_stop = false;
        let mut failure_code = None;
        let mut pending: Option<Pending> = None;
        let mut deferred = None;
        let mut first_control = None;
        let mut terminal_claimed = false;
        report(context, name, Status::StartPending);

        loop {
            let mut controls = Vec::new();
            if let Some(control) = first_control.take() {
                controls.push(control);
            }
            for _ in 0..32 {
                match context.try_recv() {
                    Ok(control) => controls.push(control),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        explicit_stop = true;
                        break;
                    }
                }
            }
            explicit_stop |= context.stop_requested()
                || controls.iter().any(|control| {
                    matches!(control, ServiceControl::Stop | ServiceControl::Shutdown)
                });
            if !terminal_claimed && signals.terminal.is_ready() {
                explicit_stop |= context.claim_terminal();
                if explicit_stop {
                    signals.stop.stop();
                }
                // Publish Stop before release; the supervisor rechecks it before
                // returning and still owns its hook/environment context.
                signals.terminal.release();
                terminal_claimed = true;
                if let Some(pending) = pending.take() {
                    pending.request.cancel();
                }
                deferred = None;
                if stopping.is_none() {
                    stopping = Some(context.now());
                    report(context, name, Status::StopPending);
                    checkpoint = context.now();
                }
            }
            if explicit_stop && stopping.is_none() {
                stopping = Some(context.now());
                signals.stop.stop();
                if let Some(pending) = pending.take() {
                    pending.request.cancel();
                }
                deferred = None;
                report(context, name, Status::StopPending);
                checkpoint = context.now();
            }

            // Completion is not conditional on a quiet control channel.
            if handle.as_ref().is_some_and(|handle| handle.is_finished()) {
                let result = match handle.take().unwrap().join() {
                    Ok(Ok(reason)) => Ok(reason),
                    Ok(Err(error)) => {
                        diagnostics::report(name, "supervisor terminal failure", error);
                        Err(())
                    }
                    Err(_) => {
                        diagnostics::report(name, "supervisor terminal failure", "thread panicked");
                        Err(())
                    }
                };
                let accepted_stop = explicit_stop || context.stop_requested();
                let failed = result.is_err();
                let terminal = if accepted_stop {
                    Terminal::Stopped(0)
                } else if let Some(code) = failure_code {
                    Terminal::Stopped(code)
                } else {
                    terminal_for(result, false)
                };
                return BridgeExit {
                    terminal,
                    force_exit: failed,
                };
            }

            if !running && stopping.is_none() {
                if let Ok(status) = startup.try_recv() {
                    if status == StartupStatus::Quiesced {
                        diagnostics::report(
                            name,
                            "startup",
                            "initial Ignore policy: host is intentionally quiesced without a child",
                        );
                    }
                    running = true;
                    report(context, name, Status::Running);
                    checkpoint = context.now();
                } else if context.now().saturating_duration_since(started) >= timing.startup {
                    diagnostics::report(
                        name,
                        "startup",
                        "no confirmed live/quiesced startup before deadline",
                    );
                    failure_code = Some(3);
                    stopping = Some(context.now());
                    signals.stop.stop();
                    report(context, name, Status::StopPending);
                    checkpoint = context.now();
                }
            }

            if stopping.is_none() {
                for control in controls {
                    match control {
                        ServiceControl::Pause if running => deferred = Some(true),
                        ServiceControl::Continue if running => deferred = Some(false),
                        ServiceControl::PowerEvent(event) => signals.power.power_event(event),
                        ServiceControl::Other(code)
                            if code == servicemanager_win32::SERVICE_CONTROL_ROTATE =>
                        {
                            signals.rotate.rotate()
                        }
                        _ => {}
                    }
                }
                if let Some(transition) = &pending {
                    if context.now().saturating_duration_since(transition.started)
                        >= timing.transition
                    {
                        transition.request.cancel();
                    }
                    if let Some(outcome) = transition.request.outcome() {
                        match outcome {
                            TransitionOutcome::Applied => paused = transition.pause,
                            TransitionOutcome::Cancelled | TransitionOutcome::Rejected(_) => {
                                diagnostics::report(
                                    name,
                                    "pause/continue",
                                    format!("{outcome:?}; previous state restored"),
                                );
                            }
                            TransitionOutcome::Degraded(error) => {
                                diagnostics::report(
                                    name,
                                    "pause/continue",
                                    format!("fail-stop: {error}"),
                                );
                                failure_code = Some(SUPERVISOR_ERROR_EXIT_CODE);
                                stopping = Some(context.now());
                            }
                        }
                        pending = None;
                        if stopping.is_none() {
                            report(
                                context,
                                name,
                                if paused {
                                    Status::Paused
                                } else {
                                    Status::Running
                                },
                            );
                        } else {
                            report(context, name, Status::StopPending);
                        }
                        checkpoint = context.now();
                    } else if context.now().saturating_duration_since(transition.started)
                        >= timing.stop
                    {
                        diagnostics::report(
                            name,
                            "pause/continue",
                            "executing transition exceeded the hard deadline",
                        );
                        failure_code = Some(SUPERVISOR_ERROR_EXIT_CODE);
                        stopping = Some(context.now());
                        signals.stop.stop();
                        report(context, name, Status::StopPending);
                    }
                }
                if pending.is_none() && stopping.is_none() {
                    if let Some(pause) = deferred.take() {
                        let request = if pause {
                            signals.pause.request_pause()
                        } else {
                            signals.pause.request_resume()
                        };
                        pending = Some(Pending {
                            request,
                            pause,
                            started: context.now(),
                        });
                        report(
                            context,
                            name,
                            if pause {
                                Status::PausePending
                            } else {
                                Status::ContinuePending
                            },
                        );
                        checkpoint = context.now();
                    }
                }
            }

            if let Some(stopped_at) = stopping {
                if context.now().saturating_duration_since(stopped_at) >= timing.stop {
                    diagnostics::report(
                        name,
                        "stop",
                        "supervisor did not finish; terminating the service host",
                    );
                    return BridgeExit {
                        terminal: Terminal::Stopped(if explicit_stop || context.stop_requested() {
                            0
                        } else {
                            failure_code.unwrap_or(SUPERVISOR_ERROR_EXIT_CODE)
                        }),
                        force_exit: true,
                    };
                }
            }
            if context.now().saturating_duration_since(checkpoint) >= timing.checkpoint {
                let status = if stopping.is_some() {
                    Some(Status::StopPending)
                } else if let Some(transition) = &pending {
                    Some(if transition.pause {
                        Status::PausePending
                    } else {
                        Status::ContinuePending
                    })
                } else if !running {
                    Some(Status::StartPending)
                } else {
                    None
                };
                if let Some(status) = status {
                    report(context, name, status);
                }
                checkpoint = context.now();
            }
            match context.recv_timeout(timing.poll) {
                Ok(control) => first_control = Some(control),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => explicit_stop = true,
            }
        }
    }

    fn service_main(name: &str, context: &ServiceContext) -> Result<()> {
        if let Err(error) = ensure_console() {
            diagnostics::report(name, "console", format!("CTRL+BREAK unavailable: {error}"));
        }
        let config = servicemanager_registry::read_managed_config(name)?.ok_or_else(|| {
            Error::InvalidConfig(format!("no managed config for service '{name}'"))
        })?;
        let mut supervisor = Supervisor::new(name.to_string(), config);
        let startup = supervisor.startup_receiver();
        let signals = Signals::for_supervisor(&mut supervisor);
        let handle = thread::spawn(move || supervisor.run());
        let outcome = bridge(name, context, startup, handle, signals, Timing::default());
        finish(context, name, outcome);
        Ok(())
    }

    fn finish(context: &impl Context, name: &str, mut outcome: BridgeExit) {
        if context.claim_terminal() {
            outcome.terminal = Terminal::Stopped(0);
        }
        match outcome.terminal {
            Terminal::Stopped(code) => {
                report(context, name, Status::Stopped(code));
                if outcome.force_exit {
                    servicemanager_win32::process_tree::terminate_current_process(code);
                }
            }
            Terminal::Crash(code) => {
                diagnostics::report(
                    name,
                    "Suicide",
                    format!("deliberate crash-style host exit {code} after cleanup"),
                );
                diagnostics::reporter().flush(Duration::from_millis(250));
                // Do not report SERVICE_STOPPED: failureflag=0 recovery requires this path.
                servicemanager_win32::process_tree::terminate_current_process(code);
            }
        }
    }

    pub(super) fn run(service_name: &str) -> Result<()> {
        let name = service_name.to_owned();
        run_service_dispatcher(service_name, move |context: ServiceContext| {
            if let Err(error) = service_main(&name, &context) {
                diagnostics::report(&name, "startup failure", error);
                let code = if context.claim_terminal() {
                    0
                } else {
                    SUPERVISOR_ERROR_EXIT_CODE
                };
                report(&context, &name, Status::Stopped(code));
            }
        })
    }

    #[cfg(test)]
    #[path = "windows_tests.rs"]
    mod tests;
}

#[cfg(windows)]
pub fn run(service_name: &str) -> Result<()> {
    windows_runner::run(service_name)
}

#[cfg(not(windows))]
pub fn run(_service_name: &str) -> Result<()> {
    Err(Error::other("service runner requires Windows"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stopped_reason_maps_to_zero_service_exit_code() {
        assert_eq!(service_exit_code_for(ExitReason::Stopped), 0);
    }
    #[test]
    fn child_exited_reason_maps_to_zero_service_exit_code() {
        assert_eq!(service_exit_code_for(ExitReason::ChildExited), 0);
    }
    #[test]
    fn spawn_failed_reason_maps_to_nonzero_service_exit_code() {
        assert_eq!(
            service_exit_code_for(ExitReason::SpawnFailed),
            SUPERVISOR_ERROR_EXIT_CODE
        );
    }
    #[test]
    fn suicide_reason_maps_to_nonzero_service_exit_code() {
        for code in [-1, 0, 1, 42, 200] {
            assert_ne!(
                service_exit_code_for(ExitReason::Suicide { exit_code: code }),
                0
            );
        }
    }
    #[test]
    fn suicide_preserves_meaningful_child_exit_code() {
        assert_eq!(
            service_exit_code_for(ExitReason::Suicide { exit_code: 42 }),
            42
        );
        assert_eq!(
            service_exit_code_for(ExitReason::Suicide { exit_code: 1 }),
            1
        );
    }
    #[test]
    fn suicide_falls_back_when_child_exit_code_is_not_positive() {
        assert_eq!(
            service_exit_code_for(ExitReason::Suicide { exit_code: 0 }),
            1
        );
        assert_eq!(
            service_exit_code_for(ExitReason::Suicide { exit_code: -1 }),
            1
        );
    }
    #[test]
    fn suicide_is_crash_style_before_and_after_startup_but_explicit_stop_wins() {
        for code in [-1, 0, 7, 42] {
            assert!(matches!(
                terminal_for(Ok(ExitReason::Suicide { exit_code: code }), false),
                Terminal::Crash(_)
            ));
            assert_eq!(
                terminal_for(Ok(ExitReason::Suicide { exit_code: code }), true),
                Terminal::Stopped(0)
            );
        }
        assert_eq!(
            terminal_for(Ok(ExitReason::ChildExited), false),
            Terminal::Stopped(0)
        );
        assert_eq!(terminal_for(Err(()), true), Terminal::Stopped(0));
    }
}
