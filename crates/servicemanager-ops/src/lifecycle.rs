use std::thread;
use std::time::{Duration, Instant};

use servicemanager_win32::{control_service, query_service, start_service, ServiceControlSignal};

use crate::error::{message_error, OpResult};
use crate::helpers::{ensure_enabled, ensure_ngsm_managed};

/// Request that a service be started.
///
/// Re-validates NGSM ownership and enabled state against current SCM/registry
/// state before issuing the start — the caller's snapshot may be stale.
pub fn start(name: &str) -> OpResult {
    ensure_ngsm_managed(name)?;
    ensure_enabled(name)?;
    start_service(name)?;
    Ok(format!("Start requested for '{name}'."))
}

/// Request that a service be stopped.
///
/// Re-validates NGSM ownership before issuing the stop control.
pub fn stop(name: &str) -> OpResult {
    ensure_ngsm_managed(name)?;
    control_service(name, ServiceControlSignal::Stop).map(|_| ())?;
    Ok(format!("Stop requested for '{name}'."))
}

/// Request that a service be paused.
///
/// Re-validates NGSM ownership before issuing the pause control.
pub fn pause(name: &str) -> OpResult {
    ensure_ngsm_managed(name)?;
    control_service(name, ServiceControlSignal::Pause).map(|_| ())?;
    Ok(format!("Pause requested for '{name}'."))
}

/// Request that a paused service be continued.
///
/// Re-validates NGSM ownership before issuing the continue control.
///
/// Named `continue_service` because `continue` is a Rust keyword.
pub fn continue_service(name: &str) -> OpResult {
    ensure_ngsm_managed(name)?;
    control_service(name, ServiceControlSignal::Continue).map(|_| ())?;
    Ok(format!("Continue requested for '{name}'."))
}

/// Stop and then start a service, waiting up to `stop_timeout_ms` milliseconds
/// for it to reach the `Stopped` state before re-starting.
///
/// Re-validates NGSM ownership and enabled state before acting. If the service
/// is already stopped, the stop step is skipped.
///
/// A 250 ms post-stop pause is applied before the start to give the SCM time
/// to accept a new Start on the same service.
pub fn restart(name: &str, stop_timeout_ms: u64) -> OpResult {
    use servicemanager_core::ServiceState;

    ensure_ngsm_managed(name)?;
    ensure_enabled(name)?;

    let snapshot = query_service(name)?;
    let initial = snapshot.runtime.as_ref().map(|r| r.state);
    let needs_stop = !matches!(initial, Some(ServiceState::Stopped) | None);

    if needs_stop {
        match control_service(name, ServiceControlSignal::Stop) {
            Ok(_) => {}
            Err(e) => {
                // Swallow "service not active" — another stopper may have
                // beaten us to it (race is harmless).
                if !is_service_not_active_error(&e) {
                    return Err(e);
                }
            }
        }
        let deadline = Instant::now() + Duration::from_millis(stop_timeout_ms);
        loop {
            let s = query_service(name)?;
            if matches!(
                s.runtime.as_ref().map(|r| r.state),
                Some(ServiceState::Stopped)
            ) {
                break;
            }
            if Instant::now() >= deadline {
                return Err(message_error(format!(
                    "'{name}' did not stop within {stop_timeout_ms} ms"
                )));
            }
            thread::sleep(Duration::from_millis(200));
        }
        // SCM occasionally needs a beat after STOPPED before it will accept
        // a new Start on the same service.
        thread::sleep(Duration::from_millis(250));
    }

    start_service(name)?;
    Ok(format!("Restarted '{name}'."))
}

fn is_service_not_active_error(error: &servicemanager_core::Error) -> bool {
    let msg = error.to_string();
    msg.contains("0x80070426") || msg.contains("has not been started")
}
