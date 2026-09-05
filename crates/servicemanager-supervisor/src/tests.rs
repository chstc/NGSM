use super::*;
use servicemanager_core::events::{EventKind, EventRecord};
use servicemanager_core::HookConfig;
use std::io::Write;

#[path = "expansion_runtime_tests.rs"]
mod expansion;

struct Discard;
impl diagnostics::DiagnosticSink for Discard {
    fn write(&mut self, _: &diagnostics::Diagnostic) -> io::Result<()> {
        Ok(())
    }
}

fn isolate_program_data() -> (std::sync::MutexGuard<'static, ()>, tempfile::TempDir) {
    let guard = TEST_PROGRAM_DATA_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("NGSM_PROGRAM_DATA_DIR", dir.path());
    (guard, dir)
}

fn seed_exit(supervisor: &mut Supervisor, code: i32) {
    supervisor.generation = Some(Generation {
        id: 1,
        pid: 0,
        started: Instant::now(),
        state: Arc::new(Mutex::new(ChildState {
            child: None,
            exit: Some(ObservedExit {
                code,
                observed: Instant::now(),
                timestamp: event_log::now_rfc3339(),
                error: None,
            }),
        })),
        watcher: None,
        recorded: false,
        #[cfg(windows)]
        root: None,
    });
}

#[test]
fn racing_stop_consumes_pending_exit_without_relocking_its_guard() {
    let (_guard, _dir) = isolate_program_data();
    let mut supervisor = Supervisor::new("PendingExitFixture", ManagedApplicationConfig::default());
    seed_exit(&mut supervisor, 42);
    let (finished_tx, finished_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        supervisor.stop_child_gracefully().unwrap();
        finished_tx.send(supervisor.last_exit_code()).unwrap();
    });
    assert_eq!(
        finished_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("a racing Stop must not deadlock on pending_exit"),
        Some(42)
    );
    worker.join().unwrap();
}

#[test]
fn zero_retry_delay_does_not_skip_a_queued_stop() {
    let (_guard, _dir) = isolate_program_data();
    for _ in 0..256 {
        let mut supervisor =
            Supervisor::new("ZeroDelayFixture", ManagedApplicationConfig::default());
        supervisor.stop_signal().stop();
        assert!(
            !supervisor.sleep_or_stop(Duration::ZERO).unwrap(),
            "an expired delay does not take precedence over an already queued Stop"
        );
    }
}

#[test]
fn copy_and_truncate_does_not_erase_an_unrotated_log_at_startup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("existing.log");
    std::fs::write(&path, b"previous generation\n").unwrap();
    let stream = IoStream {
        path: path.to_str().unwrap().to_string(),
        share_mode: None,
        creation_disposition: None,
        flags_and_attributes: None,
        copy_and_truncate: Some(true),
    };
    drop(open_log_file(&stream, &LogRotationConfig::default()).unwrap());
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"previous generation\n",
        "CopyAndTruncate is a rotation strategy, not an unconditional startup truncation"
    );
}

#[test]
fn resume_events_are_classified() {
    assert!(is_resume_event(18));
    assert!(is_resume_event(7));
    assert!(!is_resume_event(4));
}

#[test]
fn find_hook_matches_event_action_case_insensitively() {
    let hooks = vec![
        HookConfig {
            event: "start".into(),
            action: "PRE".into(),
            command: "warmup".into(),
        },
        HookConfig {
            event: "Stop".into(),
            action: "Pre".into(),
            command: "drain".into(),
        },
    ];
    assert_eq!(
        find_hook(&hooks, HookPoint::StartPre).map(|h| h.command.as_str()),
        Some("warmup")
    );
    assert!(find_hook(&hooks, HookPoint::ExitPost).is_none());
}

#[test]
fn rotated_name_keeps_stem_and_extension() {
    let rotated = rotation::build_rotated_name(Path::new("C:\\logs\\service.log"));
    let name = rotated.file_name().unwrap().to_string_lossy();
    assert!(name.starts_with("service."), "{name}");
    assert!(name.ends_with(".log"), "{name}");
}

#[test]
fn env_entry_parsing() {
    assert_eq!(parse_env_entry("FOO=bar").unwrap(), ("FOO", "bar"));
    assert_eq!(parse_env_entry("FOO=a=b").unwrap(), ("FOO", "a=b"));
    assert_eq!(parse_env_entry("EMPTY=").unwrap(), ("EMPTY", ""));
    assert!(parse_env_entry("noequals").is_err());
    assert!(parse_env_entry("=value").is_err());
    assert!(parse_env_entry("BAD\0NAME=x").is_err());
}

#[test]
fn exit_observation_is_recorded_once_without_clearing_identity_early() {
    let (_guard, _dir) = isolate_program_data();
    let mut supervisor = Supervisor::new("ExitOnce", ManagedApplicationConfig::default());
    seed_exit(&mut supervisor, 7);
    let writer = EventWriter::for_service("ExitOnce");
    supervisor.record_child_exit(&writer);
    supervisor.record_child_exit(&writer);
    assert_eq!(supervisor.last_exit_code(), Some(7));
    assert!(supervisor.generation.as_ref().unwrap().recorded);
    let records =
        std::fs::read_to_string(servicemanager_core::paths::events_log().unwrap()).unwrap();
    assert_eq!(records.lines().count(), 1);
}

#[test]
fn ignore_quiesce_returns_stopped_when_stop_message_arrives() {
    let (_guard, _dir) = isolate_program_data();
    let mut supervisor = Supervisor::new("IgnoreQuiesce", ManagedApplicationConfig::default());
    supervisor.stop_signal().stop();
    assert_eq!(
        supervisor.wait_for_stop_quiesced().unwrap(),
        ExitReason::Stopped
    );
}

#[test]
fn ignore_quiesce_drains_non_terminal_signals_until_stop() {
    let (_guard, _dir) = isolate_program_data();
    let mut supervisor = Supervisor::new("IgnoreDrain", ManagedApplicationConfig::default());
    supervisor.rotate_signal().rotate();
    supervisor.stop_signal().stop();
    assert_eq!(
        supervisor.wait_for_stop_quiesced().unwrap(),
        ExitReason::Stopped
    );
}

#[test]
fn ignore_quiesce_returns_stopped_when_channel_disconnects() {
    let (_guard, _dir) = isolate_program_data();
    let mut supervisor = Supervisor::new("IgnoreDisconnect", ManagedApplicationConfig::default());
    let (tx, rx) = mpsc::channel();
    drop(tx);
    supervisor.rx = rx;
    assert_eq!(
        supervisor.wait_for_stop_quiesced().unwrap(),
        ExitReason::Stopped
    );
}

#[test]
fn mandatory_restart_delay_and_actual_uptime_select_the_delay() {
    let mut config = ManagedApplicationConfig::default();
    config.restart.restart_delay_ms = Some(600_000);
    config.restart.throttle_delay_ms = Some(1500);
    assert_eq!(
        restart_delay(&config, Duration::from_millis(150)),
        Duration::from_secs(600)
    );
    config.restart.restart_delay_ms = Some(0);
    assert_eq!(
        restart_delay(&config, Duration::from_millis(10)),
        Duration::from_millis(1500)
    );
    assert_eq!(
        restart_delay(&config, Duration::from_secs(2)),
        Duration::ZERO
    );
}

#[test]
#[ignore = "isolated subprocess fixture, invoked only by the owning tests"]
fn fixture_child() {
    match std::env::var("NGSM_TEST_CHILD_MODE").as_deref() {
        Ok("exit") => std::process::exit(7),
        Ok("tail") => {
            let mut stdout = std::io::stdout().lock();
            for _ in 0..128 {
                stdout.write_all(&[b'x'; 1024]).unwrap();
            }
            stdout.write_all(b"\nFINAL_GENERATION_MARKER\n").unwrap();
            stdout.flush().unwrap();
        }
        Ok("arguments") => {
            println!("APP_ARGUMENTS={:?}", std::env::args().collect::<Vec<_>>());
            println!(
                "SERVICE_VALUE={}",
                std::env::var("NGSM_TEST_VALUE").unwrap()
            );
        }
        _ => loop {
            println!("HEARTBEAT");
            std::io::stdout().flush().unwrap();
            thread::sleep(Duration::from_millis(10));
        },
    }
}

#[test]
#[ignore = "isolated contained hook fixture"]
fn fixture_hook() {
    let path = std::env::var("NGSM_TEST_HOOK_LOG").unwrap();
    let event = std::env::var("NGSM_EVENT").unwrap();
    let pid = std::env::var("NGSM_APPLICATION_PID").unwrap_or_else(|_| "NONE".into());
    let expanded = std::env::var("NGSM_TEST_EXPANDED_PID").unwrap_or_else(|_| "NONE".into());
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
        .unwrap();
    writeln!(file, "begin {event} pid={pid} expanded={expanded}").unwrap();
    file.flush().unwrap();
    let sleep = std::env::var("NGSM_TEST_HOOK_SLEEP_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    thread::sleep(Duration::from_millis(sleep));
    writeln!(file, "end {event}").unwrap();
}

fn output_stream(path: &Path) -> IoStream {
    IoStream {
        path: path.to_string_lossy().into_owned(),
        share_mode: None,
        creation_disposition: None,
        flags_and_attributes: None,
        copy_and_truncate: None,
    }
}

fn fixture_config(mode: &str) -> ManagedApplicationConfig {
    let mut config = ManagedApplicationConfig {
        application: Some(
            std::env::current_exe()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
        ),
        app_parameters: Some("--exact tests::fixture_child --ignored --nocapture".into()),
        environment_extra: vec![format!("NGSM_TEST_CHILD_MODE={mode}")],
        ..Default::default()
    };
    config.restart.default_action = Some(ExitAction::Exit);
    config.shutdown.stop_method_skip = Some(7);
    config
}

fn hook_command(executable: &Path) -> String {
    format!(
        "\"{}\" \"--exact\" \"tests::fixture_hook\" --ignored --nocapture >nul 2>nul",
        executable.display()
    )
}

struct Running {
    stop: StopSignal,
    pause: PauseContinueSignal,
    power: PowerEventSignal,
    rotate: RotateSignal,
    startup: Receiver<StartupStatus>,
    done: Receiver<Result<ExitReason, SupervisorError>>,
    handle: Option<JoinHandle<()>>,
}

impl Running {
    fn new(name: &str, config: ManagedApplicationConfig) -> Self {
        let mut supervisor = Supervisor::new(name, config);
        supervisor.diagnostic = diagnostics::Reporter::new(Discard);
        let stop = supervisor.stop_signal();
        let pause = supervisor.pause_continue_signal();
        let power = supervisor.power_event_signal();
        let rotate = supervisor.rotate_signal();
        let startup = supervisor.startup_receiver();
        let (finished, done) = mpsc::channel();
        let handle = thread::spawn(move || {
            let _ = finished.send(supervisor.run());
        });
        Self {
            stop,
            pause,
            power,
            rotate,
            startup,
            done,
            handle: Some(handle),
        }
    }
    fn finish(mut self, stop: bool) -> Result<ExitReason, SupervisorError> {
        if stop {
            self.stop.stop();
        }
        let result = self
            .done
            .recv_timeout(Duration::from_secs(8))
            .expect("supervisor must finish within the test bound");
        self.handle.take().unwrap().join().unwrap();
        result
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.stop();
        if let Some(handle) = self.handle.take() {
            let deadline = Instant::now() + Duration::from_secs(3);
            while !handle.is_finished() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(5));
            }
            if handle.is_finished() {
                let _ = handle.join();
            }
        }
    }
}

fn records() -> Vec<EventRecord> {
    std::fs::read_to_string(servicemanager_core::paths::events_log().unwrap())
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

fn wait_until(mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !ready() {
        assert!(Instant::now() < deadline, "fixture observation timed out");
        thread::sleep(Duration::from_millis(5));
    }
}

fn wait_transition(request: &Transition) -> TransitionOutcome {
    wait_until(|| request.outcome().is_some());
    request.outcome().unwrap()
}

#[test]
fn real_zero_delay_spawn_failure_is_interruptible_and_records_one_stop() {
    let (_guard, dir) = isolate_program_data();
    let mut config = fixture_config("exit");
    config.application = Some(
        dir.path()
            .join("missing.exe")
            .to_string_lossy()
            .into_owned(),
    );
    config.restart.default_action = Some(ExitAction::Restart);
    config.restart.throttle_delay_ms = Some(0);
    let running = Running::new("ZeroFailure", config);
    thread::sleep(Duration::from_millis(30));
    let stopped_at = Instant::now();
    assert_eq!(running.finish(true).unwrap(), ExitReason::Stopped);
    assert!(stopped_at.elapsed() < Duration::from_secs(2));
    assert_eq!(
        records()
            .iter()
            .filter(|record| record.event == EventKind::Stopped)
            .count(),
        1
    );
    assert!(!records()
        .iter()
        .any(|record| record.event == EventKind::Started));
}

#[test]
fn pause_intent_survives_real_restart_backoff_and_zero_child_generations() {
    let (_guard, _dir) = isolate_program_data();
    let mut config = fixture_config("exit");
    config.restart.default_action = Some(ExitAction::Restart);
    config.restart.restart_delay_ms = Some(350);
    config.restart.throttle_delay_ms = Some(0);
    let running = Running::new("PauseBackoff", config);
    wait_until(|| {
        records()
            .iter()
            .any(|record| record.event == EventKind::Throttled)
    });
    assert_eq!(
        wait_transition(&running.pause.request_pause()),
        TransitionOutcome::Applied
    );
    assert_eq!(
        wait_transition(&running.pause.request_pause()),
        TransitionOutcome::Applied
    );
    thread::sleep(Duration::from_millis(450));
    assert_eq!(
        records()
            .iter()
            .filter(|record| matches!(record.event, EventKind::Started | EventKind::Restarted))
            .count(),
        1
    );
    assert_eq!(
        wait_transition(&running.pause.request_resume()),
        TransitionOutcome::Applied
    );
    wait_until(|| {
        records()
            .iter()
            .any(|record| record.event == EventKind::Restarted)
    });
    assert_eq!(running.finish(true).unwrap(), ExitReason::Stopped);
}

#[test]
fn stopped_during_backoff_fires_stop_pre_and_records_stopped_once() {
    let (_guard, dir) = isolate_program_data();
    let marker = dir.path().join("hooks.log");
    let mut config = fixture_config("exit");
    config.restart.default_action = Some(ExitAction::Restart);
    config.restart.restart_delay_ms = Some(600_000);
    config
        .environment_extra
        .push(format!("NGSM_TEST_HOOK_LOG={}", marker.display()));
    config.hooks.push(HookConfig {
        event: "Stop".into(),
        action: "Pre".into(),
        command: hook_command(&std::env::current_exe().unwrap()),
    });
    let running = Running::new("BackoffStop", config);
    wait_until(|| {
        records()
            .iter()
            .any(|record| record.event == EventKind::Throttled)
    });
    assert_eq!(
        records()
            .iter()
            .find(|record| record.event == EventKind::Throttled)
            .unwrap()
            .delay_ms,
        Some(600_000)
    );
    assert_eq!(running.finish(true).unwrap(), ExitReason::Stopped);
    let hooks = std::fs::read_to_string(marker).unwrap();
    assert_eq!(
        hooks
            .lines()
            .filter(|line| line.starts_with("begin Stop/Pre"))
            .count(),
        1
    );
    assert_eq!(
        records()
            .iter()
            .filter(|record| record.event == EventKind::Stopped)
            .count(),
        1
    );
}

#[test]
fn long_start_post_does_not_inflate_uptime_or_confirm_an_already_dead_child() {
    let (_guard, dir) = isolate_program_data();
    let marker = dir.path().join("hooks.log");
    let mut config = fixture_config("exit");
    config.environment_extra.extend([
        format!("NGSM_TEST_HOOK_LOG={}", marker.display()),
        "NGSM_TEST_HOOK_SLEEP_MS=1600".into(),
    ]);
    config.hooks.push(HookConfig {
        event: "Start".into(),
        action: "Post".into(),
        command: hook_command(&std::env::current_exe().unwrap()),
    });
    let running = Running::new("ObservedExit", config);
    wait_until(|| {
        std::fs::read_to_string(&marker)
            .unwrap_or_default()
            .contains("begin Start/Post")
    });
    assert!(running
        .startup
        .recv_timeout(Duration::from_millis(100))
        .is_err());
    assert_eq!(running.finish(false).unwrap(), ExitReason::ChildExited);
    let records = records();
    assert_eq!(records[0].event, EventKind::Started);
    assert_eq!(records[1].event, EventKind::ChildExited);
    assert!(records[1].lived_ms.unwrap() < 1500);
    assert!(records[0].ts <= records[1].ts);
}

#[test]
fn initial_ignore_has_explicit_quiesced_readiness_and_remains_stoppable() {
    let (_guard, dir) = isolate_program_data();
    let mut config = fixture_config("exit");
    config.restart.default_action = Some(ExitAction::Ignore);
    config.environment_extra.extend([
        format!(
            "NGSM_TEST_HOOK_LOG={}",
            dir.path().join("hook.log").display()
        ),
        "NGSM_TEST_HOOK_SLEEP_MS=200".into(),
    ]);
    config.hooks.push(HookConfig {
        event: "Start".into(),
        action: "Post".into(),
        command: hook_command(&std::env::current_exe().unwrap()),
    });
    let running = Running::new("InitialIgnore", config);
    assert_eq!(
        running
            .startup
            .recv_timeout(Duration::from_secs(3))
            .unwrap(),
        StartupStatus::Quiesced
    );
    assert_eq!(running.finish(true).unwrap(), ExitReason::Stopped);
}

#[test]
fn real_online_child_tail_is_drained_before_supervisor_completion() {
    let (_guard, dir) = isolate_program_data();
    let path = dir.path().join("output.log");
    let mut config = fixture_config("tail");
    config.io.stdout = Some(output_stream(&path));
    config.io.stderr = Some(output_stream(&path));
    config.rotation.enabled = Some(true);
    config.rotation.online = Some(1);
    let running = Running::new("TailFixture", config);
    assert_eq!(running.finish(false).unwrap(), ExitReason::ChildExited);
    let output = std::fs::read_to_string(path).unwrap();
    assert_eq!(output.matches("FINAL_GENERATION_MARKER").count(), 1);
    assert!(output.len() >= 128 * 1024);
}

#[test]
fn launch_expansion_uses_service_overrides_and_preserves_raw_percent_metadata() {
    let (_guard, dir) = isolate_program_data();
    let path = dir.path().join("arguments.log");
    let executable = std::env::current_exe()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let mut config = fixture_config("arguments");
    config.application = Some("%NGSM_TEST_EXE%".into());
    config.app_parameters =
        Some("--exact tests::fixture_child --ignored --nocapture --skip=%NGSM_TEST_ARG%".into());
    config.environment = vec![
        "NGSM_TEST_EXE=C:\\wrong.exe".into(),
        "NGSM_TEST_VALUE=base".into(),
        "NGSM_TEST_CHILD_MODE=arguments".into(),
        "NGSM_TEST_ARG=literal-service-value".into(),
    ];
    config.environment_extra = vec![
        format!("ngsm_test_exe={executable}"),
        "ngsm_test_value=extra".into(),
    ];
    config
        .expandable_strings
        .extend(["Application".into(), "AppParameters".into()]);
    config.io.stdout = Some(output_stream(&path));
    let raw = config.clone();
    let running = Running::new("ServiceExpansion", config);
    assert_eq!(running.finish(false).unwrap(), ExitReason::ChildExited);
    let output = std::fs::read_to_string(&path).unwrap();
    assert!(output.contains("--skip=literal-service-value"));
    assert!(output.contains("SERVICE_VALUE=extra"));
    assert_eq!(raw.application.as_deref(), Some("%NGSM_TEST_EXE%"));
    assert!(raw.is_expandable_string("Application"));

    let mut supervisor = Supervisor::new("LiteralParameters", raw.clone());
    supervisor.config.expandable_strings.remove("AppParameters");
    supervisor.prepare_launch().unwrap();
    assert!(supervisor
        .launch_config
        .as_ref()
        .unwrap()
        .app_parameters
        .as_deref()
        .unwrap()
        .contains("%NGSM_TEST_ARG%"));
    assert!(supervisor.config.is_expandable_string("Application"));
    supervisor.config.application = Some("%NGSM_UNDEFINED_ABSOLUTE_ROOT%\\missing.exe".into());
    assert!(
        supervisor.prepare_launch().is_err(),
        "unresolved non-absolute paths must not execute"
    );
}

#[test]
fn marked_hooks_expand_with_real_invocation_pid_not_stale_configured_values() {
    let (_guard, dir) = isolate_program_data();
    let marker = dir.path().join("hooks.log");
    let mut config = fixture_config("heartbeat");
    config.environment_extra.extend([
        "NGSM_APPLICATION_PID=stale".into(),
        format!("NGSM_TEST_HOOK_LOG={}", marker.display()),
    ]);
    let command = format!(
        "set \"NGSM_TEST_EXPANDED_PID=%NGSM_APPLICATION_PID%\" & {}",
        hook_command(&std::env::current_exe().unwrap())
    );
    for (event, action) in [("Start", "Pre"), ("Start", "Post")] {
        config.hooks.push(HookConfig {
            event: event.into(),
            action: action.into(),
            command: command.clone(),
        });
        config
            .expandable_strings
            .insert(ManagedApplicationConfig::hook_expansion_key(event, action));
    }

    let running = Running::new("HookExpansion", config);
    assert_eq!(
        running
            .startup
            .recv_timeout(Duration::from_secs(3))
            .unwrap(),
        StartupStatus::Running
    );
    assert_eq!(running.finish(true).unwrap(), ExitReason::Stopped);
    let hooks = std::fs::read_to_string(marker).unwrap();
    assert!(hooks.contains("begin Start/Pre pid=NONE"));
    let post = hooks
        .lines()
        .find(|line| line.starts_with("begin Start/Post"))
        .unwrap();
    assert!(!post.contains("stale"));
    let pid = post
        .split("pid=")
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap();
    assert_ne!(pid, "NONE");
    assert!(post.ends_with(&format!("expanded={pid}")));
}

#[test]
fn a_cancelled_queued_pause_does_not_suspend_after_a_slow_power_hook() {
    let (_guard, dir) = isolate_program_data();
    let marker = dir.path().join("power.log");
    let output = dir.path().join("heartbeat.log");
    let mut config = fixture_config("heartbeat");
    config.io.stdout = Some(output_stream(&output));
    config.environment_extra.extend([
        format!("NGSM_TEST_HOOK_LOG={}", marker.display()),
        "NGSM_TEST_HOOK_SLEEP_MS=250".into(),
    ]);
    config.hooks.push(HookConfig {
        event: "Power".into(),
        action: "Change".into(),
        command: hook_command(&std::env::current_exe().unwrap()),
    });
    let running = Running::new("LatePause", config);
    assert_eq!(
        running
            .startup
            .recv_timeout(Duration::from_secs(3))
            .unwrap(),
        StartupStatus::Running
    );
    running.power.power_event(4);
    wait_until(|| {
        std::fs::read_to_string(&marker)
            .unwrap_or_default()
            .contains("begin Power/Change")
    });
    let pause = running.pause.request_pause();
    assert_eq!(pause.cancel(), Some(TransitionOutcome::Cancelled));
    wait_until(|| {
        std::fs::read_to_string(&marker)
            .unwrap_or_default()
            .contains("end Power/Change")
    });
    let before = std::fs::metadata(&output).unwrap().len();
    wait_until(|| std::fs::metadata(&output).unwrap().len() > before);
    assert_eq!(pause.outcome(), Some(TransitionOutcome::Cancelled));
    assert_eq!(running.finish(true).unwrap(), ExitReason::Stopped);
}

#[test]
fn automatic_offline_and_online_rotations_run_one_hook_cycle_per_shared_destination() {
    let (_guard, dir) = isolate_program_data();
    for online in [false, true] {
        let marker = dir.path().join(format!("hooks-{online}.log"));
        let output = dir.path().join(format!("output-{online}.log"));
        if !online {
            std::fs::write(&output, b"ORIGINAL_LOG_DATA").unwrap();
        }
        let mut config = fixture_config(if online { "tail" } else { "exit" });
        config.io.stdout = Some(output_stream(&output));
        config.io.stderr = Some(output_stream(&output));
        config.rotation.enabled = Some(true);
        config.rotation.online = Some(u32::from(online));
        config.rotation.bytes = Some(if online { 4096 } else { 4 });
        config
            .environment_extra
            .push(format!("NGSM_TEST_HOOK_LOG={}", marker.display()));
        for action in ["Pre", "Post"] {
            config.hooks.push(HookConfig {
                event: "Rotate".into(),
                action: action.into(),
                command: hook_command(&std::env::current_exe().unwrap()),
            });
        }
        let running = Running::new("AutomaticHooks", config);
        assert_eq!(running.finish(false).unwrap(), ExitReason::ChildExited);
        let hooks = std::fs::read_to_string(marker).unwrap();
        let pre = hooks
            .lines()
            .filter(|line| line.starts_with("begin Rotate/Pre"))
            .count();
        let post = hooks
            .lines()
            .filter(|line| line.starts_with("begin Rotate/Post"))
            .count();
        assert!(pre >= 1);
        assert_eq!(pre, post);
        if !online {
            assert_eq!(
                pre, 1,
                "a shared stdout/stderr destination rotates only once at startup"
            );
        }
    }
}

#[test]
fn manual_rotation_runs_hooks_but_an_empty_destination_is_a_noop() {
    let (_guard, dir) = isolate_program_data();
    let marker = dir.path().join("manual-hooks.log");
    let output = dir.path().join("manual.log");
    let mut config = fixture_config("heartbeat");
    config.io.stdout = Some(output_stream(&output));
    config.rotation.enabled = Some(true);
    config.rotation.online = Some(1);
    config
        .environment_extra
        .push(format!("NGSM_TEST_HOOK_LOG={}", marker.display()));
    for action in ["Pre", "Post"] {
        config.hooks.push(HookConfig {
            event: "Rotate".into(),
            action: action.into(),
            command: hook_command(&std::env::current_exe().unwrap()),
        });
    }
    let mut empty = Supervisor::new("EmptyRotate", config.clone());
    empty.prepare_launch().unwrap();
    empty.sinks = dedup_sinks(config.io.stdout.as_ref(), None, &config.rotation)
        .unwrap()
        .2;
    empty.rotate_sinks(true, false).unwrap();
    assert!(
        !marker.exists(),
        "no actual rotation means no Pre or success Post"
    );
    drop(empty);
    let running = Running::new("ManualRotate", config);
    running
        .startup
        .recv_timeout(Duration::from_secs(3))
        .unwrap();
    wait_until(|| std::fs::metadata(&output).unwrap().len() > 0);
    running.rotate.rotate();
    wait_until(|| {
        std::fs::read_to_string(&marker)
            .unwrap_or_default()
            .contains("end Rotate/Post")
    });
    assert_eq!(running.finish(true).unwrap(), ExitReason::Stopped);
}

#[test]
fn nondefault_unimplemented_options_fail_explicitly_and_stdin_remains_unchanged() {
    let mut supervisor = Supervisor::new("UnsupportedTimestamp", fixture_config("exit"));
    supervisor.config.io.timestamp_log = Some(true);
    assert!(supervisor
        .prepare_launch()
        .unwrap_err()
        .to_string()
        .contains("AppTimestampLog"));
    supervisor.config.io.timestamp_log = Some(false);
    supervisor.config.rotation.delay_ms = Some(10);
    assert!(supervisor
        .prepare_launch()
        .unwrap_err()
        .to_string()
        .contains("AppRotateDelay"));
    supervisor.config.rotation.delay_ms = Some(0);
    supervisor.prepare_launch().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.txt");
    std::fs::write(&input, b"do not truncate").unwrap();
    let configured = output_stream(&input);
    drop(open_stdin_file(&configured).unwrap());
    assert_eq!(std::fs::read(input).unwrap(), b"do not truncate");
}

#[test]
fn production_spawn_failure_uses_an_injected_diagnostic_sink_without_environment_secrets() {
    struct Recording(Arc<Mutex<Vec<diagnostics::Diagnostic>>>);
    impl diagnostics::DiagnosticSink for Recording {
        fn write(&mut self, record: &diagnostics::Diagnostic) -> io::Result<()> {
            self.0.lock().unwrap().push(record.clone());
            Ok(())
        }
    }
    let (_guard, _dir) = isolate_program_data();
    let records = Arc::new(Mutex::new(Vec::new()));
    let reporter = diagnostics::Reporter::new(Recording(Arc::clone(&records)));
    let mut config = fixture_config("exit");
    config
        .environment_extra
        .push("SECRET_MALFORMED_ENVIRONMENT_VALUE".into());
    let mut supervisor = Supervisor::new("DiagnosticFixture", config);
    supervisor.diagnostic = reporter.clone();
    assert!(supervisor.run().is_err());
    assert!(reporter.flush(Duration::from_secs(1)));
    let records = records.lock().unwrap();
    assert!(records
        .iter()
        .any(|record| record.operation.starts_with("startup/spawn")
            && record.service == "DiagnosticFixture"));
    assert!(records
        .iter()
        .all(|record| !record.message.contains("SECRET")));
}
