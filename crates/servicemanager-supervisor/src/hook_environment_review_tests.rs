use super::*;
use crate::{ExitReason, Supervisor};
use servicemanager_core::ManagedApplicationConfig;

#[test]
fn invalid_hook_environment_never_executes_terminal_commands_in_the_host_environment() {
    let directory = tempfile::tempdir().unwrap();
    let records = Arc::new(Mutex::new(Vec::new()));
    let reporter = diagnostics::Reporter::new(Recording(Arc::clone(&records)));
    for (index, point) in [HookPoint::StopPre, HookPoint::ExitPost]
        .into_iter()
        .enumerate()
    {
        for replacement in [true, false] {
            let marker = directory
                .path()
                .join(format!("executed-{index}-{replacement}.log"));
            let mut config = ManagedApplicationConfig::default();
            if replacement {
                config.environment.push("SECRET_INVALID_REPLACEMENT".into());
            } else {
                config
                    .environment_extra
                    .push("BAD\0NAME=SECRET_EXTRA_VALUE".into());
            }
            config.hooks.push(HookConfig {
                event: point.event().into(),
                action: point.action().into(),
                command: format!("echo executed>\"{}\"", marker.display()),
            });
            let mut supervisor = Supervisor::new("InvalidHookEnvironment", config);
            supervisor.diagnostic = reporter.clone();
            supervisor.stop_signal().stop();
            supervisor.fire_hook(point, None, Some(7), None);
            assert!(
                !marker.exists(),
                "invalid configured environment must not fall back to inherited variables"
            );
        }
    }
    assert!(reporter.flush(Duration::from_secs(1)));
    let records = records.lock().unwrap();
    assert_eq!(records.len(), 4);
    assert!(records
        .iter()
        .all(|record| record.operation.contains("hook environment")
            && record.message.contains("skipped")
            && !record.message.contains("SECRET")));
    assert!(records
        .iter()
        .any(|record| record.message.contains("Stop/Pre")));
    assert!(records
        .iter()
        .any(|record| record.message.contains("Exit/Post")));
}

#[test]
fn invalid_hook_environment_does_not_prevent_terminal_cleanup_and_stopped_bookkeeping() {
    let _guard = crate::TEST_PROGRAM_DATA_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let directory = tempfile::tempdir().unwrap();
    std::env::set_var("NGSM_PROGRAM_DATA_DIR", directory.path());
    let marker = directory.path().join("must-not-execute.log");
    let records = Arc::new(Mutex::new(Vec::new()));
    let reporter = diagnostics::Reporter::new(Recording(Arc::clone(&records)));
    let config = ManagedApplicationConfig {
        environment: vec!["SECRET_NOT_NAME_VALUE".into()],
        hooks: vec![HookConfig {
            event: "Stop".into(),
            action: "Pre".into(),
            command: format!("echo executed>\"{}\"", marker.display()),
        }],
        ..Default::default()
    };
    let mut supervisor = Supervisor::new("InvalidEnvironmentStop", config);
    supervisor.diagnostic = reporter.clone();
    supervisor.stop_signal().stop();
    assert_eq!(supervisor.run().unwrap(), ExitReason::Stopped);
    assert!(!marker.exists());
    let log = std::fs::read_to_string(servicemanager_core::paths::events_log().unwrap()).unwrap();
    assert_eq!(
        log.lines()
            .filter(|line| line.contains("\"event\":\"stopped\""))
            .count(),
        1
    );
    assert!(reporter.flush(Duration::from_secs(1)));
    assert!(records
        .lock()
        .unwrap()
        .iter()
        .any(|record| record.operation.contains("hook environment")
            && !record.message.contains("SECRET")));
}
