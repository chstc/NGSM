use super::*;

#[test]
fn marked_directory_stdio_and_affinity_resolve_only_in_the_effective_launch_copy() {
    let (_guard, directory) = isolate_program_data();
    let output = directory.path().join("expanded-output.log");
    let mut config = fixture_config("arguments");
    config.app_directory = Some("%NGSM_TEST_DIRECTORY%".into());
    config.io.stdout = Some(output_stream(Path::new(
        "%NGSM_TEST_DIRECTORY%\\expanded-output.log",
    )));
    config.affinity = Some("%NGSM_TEST_CPUS%".into());
    config.environment_extra.extend([
        format!("NGSM_TEST_DIRECTORY={}", directory.path().display()),
        "NGSM_TEST_CPUS=0-2,4".into(),
        "NGSM_TEST_VALUE=resolved-stdio".into(),
    ]);
    config.expandable_strings.extend([
        "AppDirectory".into(),
        "AppStdout".into(),
        "AppAffinity".into(),
    ]);
    let mut supervisor = Supervisor::new("ExpandedFields", config.clone());
    supervisor.prepare_launch().unwrap();
    let effective = supervisor.launch_config.as_ref().unwrap();
    assert_eq!(effective.affinity.as_deref(), Some("0-2,4"));
    assert_eq!(
        effective.io.stdout.as_ref().unwrap().path,
        output.to_string_lossy()
    );
    assert_eq!(
        supervisor.config.affinity.as_deref(),
        Some("%NGSM_TEST_CPUS%")
    );
    assert!(supervisor.config.is_expandable_string("AppAffinity"));
    // Actual affinity application is covered by the native pre-resume tests; do
    // not assume this host has CPUs 0-2,4 available to a fixture.
    config.affinity = None;
    config.expandable_strings.remove("AppAffinity");
    assert_eq!(
        Running::new("ExpandedFields", config)
            .finish(false)
            .unwrap(),
        ExitReason::ChildExited
    );
    assert!(std::fs::read_to_string(output)
        .unwrap()
        .contains("SERVICE_VALUE=resolved-stdio"));
}

#[test]
fn plain_reg_sz_executable_and_parameters_keep_percent_text_literal() {
    let (_guard, directory) = isolate_program_data();
    let executable = directory.path().join("literal%NGSM_TEST_LITERAL%.exe");
    std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
    let output = directory.path().join("literal-output.log");
    let mut config = fixture_config("arguments");
    config.application = Some(executable.to_string_lossy().into_owned());
    config.app_parameters = Some(
        "--exact tests::fixture_child --ignored --nocapture --skip=%NGSM_TEST_LITERAL%".into(),
    );
    config.environment_extra.extend([
        "NGSM_TEST_LITERAL=must-not-substitute".into(),
        "NGSM_TEST_VALUE=literal-ok".into(),
    ]);
    config.io.stdout = Some(output_stream(&output));
    assert!(config.expandable_strings.is_empty());
    assert_eq!(
        Running::new("LiteralFields", config).finish(false).unwrap(),
        ExitReason::ChildExited
    );
    let output = std::fs::read_to_string(output).unwrap();
    assert!(output.contains("--skip=%NGSM_TEST_LITERAL%"));
    assert!(output.contains("SERVICE_VALUE=literal-ok"));
}

#[test]
fn conflicting_shared_open_options_are_rejected_before_any_truncation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("existing.log");
    std::fs::write(&path, b"retain previous generation").unwrap();
    let mut stdout = output_stream(&path);
    stdout.creation_disposition = Some(2);
    let stderr = output_stream(&path);
    assert!(dedup_sinks(Some(&stdout), Some(&stderr), &LogRotationConfig::default()).is_err());
    assert_eq!(std::fs::read(path).unwrap(), b"retain previous generation");
}

#[test]
fn a_fatal_spawn_under_suicide_is_deliberate_before_any_startup_confirmation() {
    let (_guard, directory) = isolate_program_data();
    let mut config = fixture_config("exit");
    config.application = Some(
        directory
            .path()
            .join("missing.exe")
            .to_string_lossy()
            .into_owned(),
    );
    config.restart.default_action = Some(ExitAction::Suicide);
    let running = Running::new("InitialSuicide", config);
    assert_eq!(
        running.finish(false).unwrap(),
        ExitReason::Suicide { exit_code: -1 }
    );
    assert!(!records()
        .iter()
        .any(|record| record.event == EventKind::Started));
}

#[test]
fn terminal_handoff_keeps_late_stop_hooks_alive_and_overrides_suicide() {
    let (_guard, directory) = isolate_program_data();
    let marker = directory.path().join("terminal-hooks.log");
    let mut config = fixture_config("exit");
    config.restart.default_action = Some(ExitAction::Suicide);
    config
        .environment_extra
        .push(format!("NGSM_TEST_HOOK_LOG={}", marker.display()));
    config.hooks.push(HookConfig {
        event: "Stop".into(),
        action: "Pre".into(),
        command: hook_command(&std::env::current_exe().unwrap()),
    });
    let mut supervisor = Supervisor::new("TerminalStop", config);
    supervisor.diagnostic = diagnostics::Reporter::new(Discard);
    let stop = supervisor.stop_signal();
    let gate = supervisor.terminal_gate();
    let worker = thread::spawn(move || supervisor.run());
    wait_until(|| gate.is_ready());
    assert!(
        !worker.is_finished(),
        "supervisor must retain late-stop context until the runner commits"
    );
    stop.stop();
    gate.release();
    wait_until(|| worker.is_finished());
    assert_eq!(worker.join().unwrap().unwrap(), ExitReason::Stopped);
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
