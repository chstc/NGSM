//! Windows service entrypoint that bridges SCM controls into the supervisor.
//!
//! Used by `ngsm.exe run-service <name>`: loads the managed config
//! from the registry, registers with the SCM, spawns the supervisor on a
//! background thread, and shuttles SCM `Stop` / `Shutdown` controls into the
//! supervisor's stop signal.

use std::sync::mpsc::RecvTimeoutError;
use std::thread;
use std::time::Duration;

use servicemanager_core::{Error, Result};

#[cfg(windows)]
use servicemanager_supervisor::{ExitReason, Supervisor, SupervisorError};
#[cfg(windows)]
use servicemanager_win32::{
    ensure_console, run_service_dispatcher, ServiceContext, ServiceControl,
};

/// How often the stop path re-checks the supervisor thread and refreshes the
/// SCM checkpoint while a stop is in progress.
#[cfg(windows)]
const STOP_POLL_INTERVAL: Duration = Duration::from_secs(3);
/// Wait hint reported to SCM during a stop. Must comfortably exceed
/// [`STOP_POLL_INTERVAL`] so SCM does not flag a hang between checkpoints.
#[cfg(windows)]
const STOP_WAIT_HINT_MS: u32 = 8_000;
/// Hard cap on how long the runner waits for the supervisor to finish a stop
/// before abandoning it (the process then exits, tearing everything down).
#[cfg(windows)]
const STOP_ESCALATION_TIMEOUT: Duration = Duration::from_secs(120);
/// How often the startup wait re-checks for the child and refreshes the SCM
/// `START_PENDING` checkpoint.
#[cfg(windows)]
const STARTUP_POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Cap on how long the runner waits for startup confirmation before it
/// declares the start a failure and reports `SERVICE_STOPPED` to SCM. The
/// runner never reports `RUNNING` without a confirmed child.
#[cfg(windows)]
const STARTUP_MAX_WAIT: Duration = Duration::from_secs(60);
/// Wait hint reported to SCM while startup is still pending.
#[cfg(windows)]
const START_WAIT_HINT_MS: u32 = 6_000;
/// Wait hint reported to SCM while a pause/continue is being carried out.
/// Comfortably exceeds the supervisor's pause/continue acknowledgement
/// timeout so SCM does not flag the transition as hung.
#[cfg(windows)]
const PAUSE_WAIT_HINT_MS: u32 = 20_000;

/// Outcome of waiting for the supervisor to bring up the managed child.
#[cfg(windows)]
enum StartupResult {
    /// The supervisor confirmed the first managed child has started.
    Running,
    /// The supervisor thread ended before confirming a child — safe to join.
    SupervisorExited,
    /// No confirmation arrived within [`STARTUP_MAX_WAIT`]. The supervisor
    /// may still be looping on a failing spawn, so its thread must not be
    /// joined (the join could block forever).
    TimedOut,
}

/// Wait for the supervisor to confirm the managed child has actually
/// started. The SCM `START_PENDING` checkpoint is advanced while waiting so
/// a slow (but legitimate) startup is not mistaken for a hang.
#[cfg(windows)]
fn await_startup(
    name: &str,
    startup_rx: &std::sync::mpsc::Receiver<()>,
    ctx: &ServiceContext,
) -> StartupResult {
    let started = std::time::Instant::now();
    loop {
        match startup_rx.recv_timeout(STARTUP_POLL_INTERVAL) {
            Ok(()) => return StartupResult::Running,
            // The supervisor thread ended (dropping the sender) without ever
            // signalling a started child.
            Err(RecvTimeoutError::Disconnected) => return StartupResult::SupervisorExited,
            Err(RecvTimeoutError::Timeout) => {
                if started.elapsed() >= STARTUP_MAX_WAIT {
                    return StartupResult::TimedOut;
                }
                report(
                    name,
                    "start-pending",
                    ctx.report_start_pending(START_WAIT_HINT_MS),
                );
            }
        }
    }
}

/// Run as a Windows service.
///
/// This call blocks until the service exits. It is intended to be invoked
/// from `main` when the process was launched by the SCM with the
/// `run-service <name>` arguments.
#[cfg(windows)]
pub fn run(service_name: &str) -> Result<()> {
    let name = service_name.to_string();
    run_service_dispatcher(service_name, move |ctx: ServiceContext| {
        if let Err(e) = service_main(&name, &ctx) {
            eprintln!("[runner:{name}] fatal: {e}");
            // `service_main` failed before it could report a terminal state
            // (e.g. missing managed config, before `report_running`). Report
            // STOPPED with a failure code so SCM does not leave the service
            // stuck in START_PENDING until the wait hint expires.
            report(&name, "stopped", ctx.report_stopped(2));
        }
    })
}

#[cfg(not(windows))]
pub fn run(_service_name: &str) -> Result<()> {
    Err(Error::other("service runner requires Windows"))
}

/// Log (but do not abort on) a failed SCM status report. A dropped status
/// update is worth a diagnostic even though the runner cannot do much else
/// about it.
#[cfg(windows)]
fn report(name: &str, what: &str, result: Result<()>) {
    if let Err(e) = result {
        eprintln!("[runner:{name}] failed to report '{what}' to SCM: {e}");
    }
}

#[cfg(windows)]
fn service_main(name: &str, ctx: &ServiceContext) -> Result<()> {
    // Allocate a console before spawning the supervised child so the child
    // inherits it and we can dispatch CTRL+BREAK on stop. Without this the
    // child gets no console and `GenerateConsoleCtrlEvent` cannot reach it.
    if let Err(e) = ensure_console() {
        eprintln!("[runner:{name}] ensure_console failed: {e} — graceful stop will not work");
    }

    let cfg = servicemanager_registry::read_managed_config(name)?
        .ok_or_else(|| Error::InvalidConfig(format!("no managed config for service '{name}'")))?;

    let mut supervisor = Supervisor::new(name.to_string(), cfg);
    let startup_rx = supervisor.startup_receiver();
    let stop_signal = supervisor.stop_signal();
    let rotate_signal = supervisor.rotate_signal();
    let pause_continue = supervisor.pause_continue_signal();
    let power_signal = supervisor.power_event_signal();

    let supervisor_handle = thread::spawn(move || supervisor.run());
    let mut handle = Some(supervisor_handle);

    // Report RUNNING only after the supervisor confirms the managed child is
    // actually up — SCM and dependent services must not see RUNNING while
    // the application is still starting (or about to fail).
    match await_startup(name, &startup_rx, ctx) {
        StartupResult::Running => report(name, "running", ctx.report_running()),
        StartupResult::SupervisorExited => {
            eprintln!("[runner:{name}] supervisor exited before the managed child started");
            if let Some(h) = handle.take() {
                match h.join() {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => eprintln!("[runner:{name}] supervisor error: {e}"),
                    Err(_) => eprintln!("[runner:{name}] supervisor thread panicked"),
                }
            }
            report(name, "stopped", ctx.report_stopped(2));
            return Ok(());
        }
        StartupResult::TimedOut => {
            eprintln!(
                "[runner:{name}] managed child not confirmed running within {} s — \
                 reporting startup failure to SCM",
                STARTUP_MAX_WAIT.as_secs()
            );
            // The supervisor may still be retrying a failing spawn, so its
            // thread must not be joined here. Signal it to stop and abandon
            // the handle — the process exit below tears down the job object
            // (and any suspended child) regardless.
            stop_signal.stop();
            let _ = handle.take();
            report(name, "stopped", ctx.report_stopped(3));
            return Ok(());
        }
    }

    // Forward SCM controls into the supervisor and poll for the supervisor
    // thread finishing on its own (e.g. spawn failure with `Exit` policy).
    let poll_interval = Duration::from_millis(250);
    let mut exit_code: u32 = 0;
    loop {
        match ctx.controls().recv_timeout(poll_interval) {
            Ok(ServiceControl::Stop) | Ok(ServiceControl::Shutdown) => {
                report(
                    name,
                    "stop-pending",
                    ctx.report_stop_pending(STOP_WAIT_HINT_MS),
                );
                stop_signal.stop();
                if let Some(h) = handle.take() {
                    exit_code = await_supervisor_stop(name, h, ctx);
                }
                break;
            }
            Ok(ServiceControl::Other(code))
                if code == servicemanager_win32::SERVICE_CONTROL_ROTATE =>
            {
                rotate_signal.rotate();
            }
            Ok(ServiceControl::Pause) => {
                // Announce the transition, then report the final state only
                // after the supervisor confirms the tree was actually
                // suspended — never report PAUSED on a best-effort guess.
                report(
                    name,
                    "pause-pending",
                    ctx.report_pause_pending(PAUSE_WAIT_HINT_MS),
                );
                match pause_continue.pause() {
                    Ok(()) => report(name, "paused", ctx.report_paused()),
                    Err(e) => {
                        eprintln!("[runner:{name}] pause failed: {e} — staying RUNNING");
                        report(name, "running", ctx.report_running());
                    }
                }
            }
            Ok(ServiceControl::Continue) => {
                report(
                    name,
                    "continue-pending",
                    ctx.report_continue_pending(PAUSE_WAIT_HINT_MS),
                );
                match pause_continue.resume() {
                    Ok(()) => report(name, "running", ctx.report_running()),
                    Err(e) => {
                        eprintln!("[runner:{name}] continue failed: {e} — staying PAUSED");
                        report(name, "paused", ctx.report_paused());
                    }
                }
            }
            Ok(ServiceControl::PowerEvent(ev)) => {
                power_signal.power_event(ev);
            }
            Ok(_) => { /* interrogate / other unknown — no-op */ }
            Err(RecvTimeoutError::Timeout) => {
                if handle.as_ref().is_some_and(|h| h.is_finished()) {
                    report(name, "stop-pending", ctx.report_stop_pending(2_000));
                    if let Some(h) = handle.take() {
                        match h.join() {
                            Ok(Ok(reason)) => {
                                if matches!(reason, ExitReason::SpawnFailed) {
                                    exit_code = 2;
                                }
                            }
                            Ok(Err(e)) => {
                                eprintln!("[runner:{name}] supervisor error: {e}");
                                exit_code = 2;
                            }
                            Err(_) => {
                                eprintln!("[runner:{name}] supervisor thread panicked");
                                exit_code = 2;
                            }
                        }
                    }
                    break;
                }
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }

    report(name, "stopped", ctx.report_stopped(exit_code));
    Ok(())
}

/// Wait for the supervisor thread to finish stopping. Stop hooks and the
/// graceful-shutdown grace periods can run well past a single SCM wait hint,
/// so the checkpoint is advanced on every poll — SCM only treats a stop as
/// hung when checkpoints stop moving. Returns the runner exit code.
#[cfg(windows)]
fn await_supervisor_stop(
    name: &str,
    handle: thread::JoinHandle<std::result::Result<ExitReason, SupervisorError>>,
    ctx: &ServiceContext,
) -> u32 {
    let started = std::time::Instant::now();
    loop {
        if handle.is_finished() {
            return match handle.join() {
                Ok(Ok(_)) => 0,
                Ok(Err(e)) => {
                    eprintln!("[runner:{name}] supervisor error: {e}");
                    1
                }
                Err(_) => {
                    eprintln!("[runner:{name}] supervisor thread panicked");
                    1
                }
            };
        }
        if started.elapsed() >= STOP_ESCALATION_TIMEOUT {
            eprintln!(
                "[runner:{name}] supervisor did not finish stopping within {} s — abandoning it",
                STOP_ESCALATION_TIMEOUT.as_secs()
            );
            return 1;
        }
        thread::sleep(STOP_POLL_INTERVAL);
        report(
            name,
            "stop-pending",
            ctx.report_stop_pending(STOP_WAIT_HINT_MS),
        );
    }
}
