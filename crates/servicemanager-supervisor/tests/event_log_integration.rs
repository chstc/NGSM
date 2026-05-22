//! End-to-end test: run the supervisor against a child that exits
//! immediately, observe the events file gets the expected sequence.

#[cfg(windows)]
mod windows_only {
    use std::sync::Mutex;
    use std::time::Duration;

    use servicemanager_core::events::{EventKind, EventRecord};
    use servicemanager_core::paths;
    use servicemanager_core::{ExitAction, ManagedApplicationConfig, RestartPolicy};
    use servicemanager_supervisor::Supervisor;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn isolate() -> (std::sync::MutexGuard<'static, ()>, tempfile::TempDir) {
        let guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("NGSM_PROGRAM_DATA_DIR", dir.path());
        (guard, dir)
    }

    fn read_records() -> Vec<EventRecord> {
        let path = paths::events_log().unwrap();
        if !path.exists() {
            return Vec::new();
        }
        std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str::<EventRecord>(l).expect("line must parse"))
            .collect()
    }

    #[test]
    fn one_restart_cycle_produces_started_exited_throttled_restarted_stopped() {
        let (_g, _dir) = isolate();

        // `cmd /c exit 1` — exits immediately with code 1.
        let config = ManagedApplicationConfig {
            application: Some("C:\\Windows\\System32\\cmd.exe".to_string()),
            app_parameters: Some("/c exit 1".to_string()),
            restart: RestartPolicy {
                restart_delay_ms: Some(0),
                throttle_delay_ms: Some(200),
                default_action: Some(ExitAction::Restart),
            },
            ..Default::default()
        };

        let mut sup = Supervisor::new("TestSvc", config);
        let _startup = sup.startup_receiver();
        let stop = sup.stop_signal();

        let handle = std::thread::spawn(move || {
            // The supervisor returns ExitReason::Stopped when StopSignal fires.
            let _ = sup.run();
        });

        // Give the supervisor enough time to: spawn (fail-fast), see exit,
        // throttle, spawn again. Two cycles is plenty.
        std::thread::sleep(Duration::from_millis(900));
        stop.stop();
        handle.join().unwrap();

        let recs = read_records();
        let kinds: Vec<EventKind> = recs.iter().map(|r| r.event).collect();

        // The sequence we expect (at minimum): Started, ChildExited,
        // Throttled, Restarted (one or more iterations possible), then
        // either ChildExited+Throttled or Stopped at the end. We don't
        // pin the exact count — just the presence and ordering rules.
        assert!(
            kinds.contains(&EventKind::Started),
            "missing Started in {kinds:?}"
        );
        assert!(
            kinds.contains(&EventKind::ChildExited),
            "missing ChildExited in {kinds:?}"
        );
        assert!(
            kinds.contains(&EventKind::Throttled),
            "missing Throttled in {kinds:?}"
        );
        assert!(
            kinds.contains(&EventKind::Restarted) || kinds.contains(&EventKind::Stopped),
            "expected at least one Restarted or Stopped in {kinds:?}"
        );

        // Started precedes ChildExited.
        let started_idx = kinds.iter().position(|k| *k == EventKind::Started).unwrap();
        let exited_idx = kinds
            .iter()
            .position(|k| *k == EventKind::ChildExited)
            .unwrap();
        assert!(started_idx < exited_idx);
    }
}
