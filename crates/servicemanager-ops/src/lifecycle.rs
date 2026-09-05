use std::thread;
use std::time::{Duration, Instant};

use servicemanager_core::{ServiceState, StartupType};
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
    restart_with_options(name, stop_timeout_ms, false)
}

/// Restart with an explicit native-service override. The override bypasses
/// ownership only; a disabled service is never stopped for a doomed restart.
pub fn restart_with_options(name: &str, stop_timeout_ms: u64, force_native: bool) -> OpResult {
    restart_using(
        name,
        stop_timeout_ms,
        force_native,
        &mut ScmRestartBackend {
            name,
            clock: Instant::now(),
        },
    )
}

struct RestartSnapshot {
    startup: StartupType,
    state: Option<ServiceState>,
}

trait RestartBackend {
    fn ensure_managed(&mut self) -> servicemanager_core::Result<()>;
    fn query(&mut self) -> servicemanager_core::Result<RestartSnapshot>;
    fn stop(&mut self) -> servicemanager_core::Result<()>;
    fn start(&mut self) -> servicemanager_core::Result<()>;
    fn now(&self) -> Duration;
    fn sleep(&mut self, duration: Duration);
}

struct ScmRestartBackend<'a> {
    name: &'a str,
    clock: Instant,
}

impl RestartBackend for ScmRestartBackend<'_> {
    fn ensure_managed(&mut self) -> servicemanager_core::Result<()> {
        ensure_ngsm_managed(self.name)
    }

    fn query(&mut self) -> servicemanager_core::Result<RestartSnapshot> {
        let snapshot = query_service(self.name)?;
        Ok(RestartSnapshot {
            startup: snapshot.config.startup,
            state: snapshot.runtime.map(|r| r.state),
        })
    }

    fn stop(&mut self) -> servicemanager_core::Result<()> {
        control_service(self.name, ServiceControlSignal::Stop).map(|_| ())
    }

    fn start(&mut self) -> servicemanager_core::Result<()> {
        start_service(self.name)
    }

    fn now(&self) -> Duration {
        self.clock.elapsed()
    }

    fn sleep(&mut self, duration: Duration) {
        thread::sleep(duration);
    }
}

fn restart_using(
    name: &str,
    stop_timeout_ms: u64,
    force_native: bool,
    backend: &mut impl RestartBackend,
) -> OpResult {
    if !force_native {
        backend.ensure_managed()?;
    }
    let snapshot = backend.query()?;
    if snapshot.startup == StartupType::Disabled {
        return Err(message_error(format!(
            "'{name}' is disabled — enable it before restarting"
        )));
    }
    if !matches!(snapshot.state, Some(ServiceState::Stopped) | None) {
        if snapshot.state != Some(ServiceState::StopPending) {
            if let Err(e) = backend.stop() {
                if !is_service_not_active_error(&e) {
                    return Err(e);
                }
            }
        }
        let began = backend.now();
        let timeout = Duration::from_millis(stop_timeout_ms);
        loop {
            if backend.query()?.state == Some(ServiceState::Stopped) {
                break;
            }
            let elapsed = backend.now().saturating_sub(began);
            if elapsed >= timeout {
                return Err(message_error(format!(
                    "'{name}' did not stop within {stop_timeout_ms} ms"
                )));
            }
            backend.sleep(Duration::from_millis(200).min(timeout - elapsed));
        }
        backend.sleep(Duration::from_millis(250));
    }

    backend.start()?;
    Ok(format!("Restarted '{name}'."))
}

fn is_service_not_active_error(error: &servicemanager_core::Error) -> bool {
    let msg = error.to_string();
    msg.contains("0x80070426") || msg.contains("has not been started")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct RecordingBackend {
        startup: StartupType,
        states: VecDeque<ServiceState>,
        calls: Vec<&'static str>,
        clock: Duration,
        sleeps: Vec<Duration>,
        stop_error: Option<servicemanager_core::Error>,
        query_error: bool,
        start_error: bool,
    }

    impl RecordingBackend {
        fn new(startup: StartupType, states: &[ServiceState]) -> Self {
            Self {
                startup,
                states: states.iter().copied().collect(),
                calls: Vec::new(),
                clock: Duration::ZERO,
                sleeps: Vec::new(),
                stop_error: None,
                query_error: false,
                start_error: false,
            }
        }
    }

    impl RestartBackend for RecordingBackend {
        fn ensure_managed(&mut self) -> servicemanager_core::Result<()> {
            self.calls.push("ownership");
            Ok(())
        }

        fn query(&mut self) -> servicemanager_core::Result<RestartSnapshot> {
            self.calls.push("query");
            if self.query_error {
                return Err(message_error("query failed"));
            }
            let state = if self.states.len() > 1 {
                self.states.pop_front()
            } else {
                self.states.front().copied()
            };
            Ok(RestartSnapshot {
                startup: self.startup,
                state,
            })
        }

        fn stop(&mut self) -> servicemanager_core::Result<()> {
            self.calls.push("stop");
            match self.stop_error.take() {
                Some(e) => Err(e),
                None => Ok(()),
            }
        }

        fn start(&mut self) -> servicemanager_core::Result<()> {
            self.calls.push("start");
            if self.start_error {
                Err(message_error("start failed"))
            } else {
                Ok(())
            }
        }

        fn now(&self) -> Duration {
            self.clock
        }

        fn sleep(&mut self, duration: Duration) {
            self.sleeps.push(duration);
            self.clock += duration;
        }
    }

    #[test]
    fn disabled_restart_never_stops_or_starts_even_with_native_override() {
        for force_native in [false, true] {
            for state in [
                ServiceState::Running,
                ServiceState::Paused,
                ServiceState::Stopped,
            ] {
                let mut backend = RecordingBackend::new(StartupType::Disabled, &[state]);
                let error = restart_using("Svc", 30_000, force_native, &mut backend)
                    .unwrap_err()
                    .to_string();
                assert!(error.contains("disabled"), "{error}");
                assert!(!backend.calls.contains(&"stop"));
                assert!(!backend.calls.contains(&"start"));
                assert_eq!(backend.calls.contains(&"ownership"), !force_native);
            }
        }
    }

    #[test]
    fn enabled_restart_uses_the_same_stop_wait_start_flow_for_both_ownership_modes() {
        for force_native in [false, true] {
            let mut backend = RecordingBackend::new(
                StartupType::Manual,
                &[
                    ServiceState::Running,
                    ServiceState::StopPending,
                    ServiceState::Stopped,
                ],
            );
            restart_using("Svc", 30_000, force_native, &mut backend).unwrap();
            let controls: Vec<_> = backend
                .calls
                .iter()
                .copied()
                .filter(|call| *call == "stop" || *call == "start")
                .collect();
            assert_eq!(controls, ["stop", "start"]);
            assert_eq!(
                backend.sleeps,
                [Duration::from_millis(200), Duration::from_millis(250)]
            );
        }
    }

    #[test]
    fn already_stopped_and_already_stopping_do_not_get_duplicate_stop_controls() {
        let mut stopped = RecordingBackend::new(StartupType::Automatic, &[ServiceState::Stopped]);
        restart_using("Svc", 0, true, &mut stopped).unwrap();
        assert_eq!(stopped.calls, ["query", "start"]);
        assert!(stopped.sleeps.is_empty());

        let mut stopping = RecordingBackend::new(
            StartupType::Manual,
            &[ServiceState::StopPending, ServiceState::Stopped],
        );
        restart_using("Svc", 0, true, &mut stopping).unwrap();
        assert!(!stopping.calls.contains(&"stop"));
        assert!(stopping.calls.contains(&"start"));
    }

    #[test]
    fn configured_restart_timeouts_bound_waiting_and_never_start_after_timeout() {
        for timeout_ms in [0, 350, 30_000] {
            let mut backend = RecordingBackend::new(StartupType::Manual, &[ServiceState::Running]);
            let error = restart_using("Svc", timeout_ms, true, &mut backend)
                .unwrap_err()
                .to_string();
            assert!(error.contains(&format!("{timeout_ms} ms")), "{error}");
            assert_eq!(backend.clock, Duration::from_millis(timeout_ms));
            assert!(!backend.calls.contains(&"start"));
        }
    }

    #[test]
    fn control_and_query_failures_propagate_but_a_stopped_race_is_harmless() {
        let mut backend = RecordingBackend::new(StartupType::Manual, &[ServiceState::Running]);
        backend.stop_error = Some(message_error("stop denied"));
        assert!(restart_using("Svc", 30_000, true, &mut backend)
            .unwrap_err()
            .to_string()
            .contains("stop denied"));
        assert!(!backend.calls.contains(&"start"));

        let mut backend = RecordingBackend::new(StartupType::Manual, &[ServiceState::Running]);
        backend.query_error = true;
        assert!(restart_using("Svc", 30_000, true, &mut backend).is_err());
        assert_eq!(backend.calls, ["query"]);

        let mut backend = RecordingBackend::new(
            StartupType::Manual,
            &[ServiceState::Running, ServiceState::Stopped],
        );
        backend.stop_error = Some(message_error("0x80070426"));
        restart_using("Svc", 30_000, true, &mut backend).unwrap();
        assert!(backend.calls.contains(&"start"));

        let mut backend = RecordingBackend::new(StartupType::Manual, &[ServiceState::Stopped]);
        backend.start_error = true;
        assert!(restart_using("Svc", 30_000, true, &mut backend)
            .unwrap_err()
            .to_string()
            .contains("start failed"));
    }
}
