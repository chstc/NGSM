use super::*;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[path = "hook_environment_review_tests.rs"]
mod environment_review;

struct Recording(Arc<Mutex<Vec<diagnostics::Diagnostic>>>);
impl diagnostics::DiagnosticSink for Recording {
    fn write(&mut self, record: &diagnostics::Diagnostic) -> io::Result<()> {
        self.0.lock().unwrap().push(record.clone());
        Ok(())
    }
}

#[test]
fn quoted_existing_executable_and_arguments_run_in_the_real_contained_hook_path() {
    let directory = tempfile::tempdir().unwrap();
    let tools = directory.path().join("hook tools");
    std::fs::create_dir(&tools).unwrap();
    let executable = tools.join("fixture.exe");
    std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
    let marker = directory.path().join("hook.log");
    let hook = HookConfig {
        event: "Start".into(),
        action: "Post".into(),
        command: format!(
            "\"{}\" \"--exact\" \"tests::fixture_hook\" --ignored --nocapture >nul 2>nul",
            executable.display()
        ),
    };
    let mut environment: Vec<(OsString, OsString)> = std::env::vars_os().collect();
    environment.push(("NGSM_EVENT".into(), "Start/Post".into()));
    environment.push(("NGSM_TEST_HOOK_LOG".into(), marker.as_os_str().to_owned()));
    let records = Arc::new(Mutex::new(Vec::new()));
    let reporter = diagnostics::Reporter::new(Recording(records));
    let result = run_hook(
        &hook,
        &HookRuntime {
            service: "QuotedHook",
            environment: &environment,
            directory: None,
            deadline: Instant::now() + Duration::from_secs(3),
            cancelled: &|| false,
            diagnostic: &reporter,
            generation: 4,
        },
    );
    assert_eq!(result, HookOutcome::Completed(0));
    assert!(std::fs::read_to_string(marker)
        .unwrap()
        .contains("end Start/Post"));
}

#[test]
fn hook_failure_and_timeout_use_the_injected_nonrecursive_diagnostic_sink() {
    let records = Arc::new(Mutex::new(Vec::new()));
    let reporter = diagnostics::Reporter::new(Recording(Arc::clone(&records)));
    let environment: Vec<_> = std::env::vars_os().collect();
    let hook = HookConfig {
        event: "Start".into(),
        action: "Pre".into(),
        command: "exit /b 7 & rem SECRET_MUST_NOT_BE_DIAGNOSED".into(),
    };
    assert_eq!(
        run_hook(
            &hook,
            &HookRuntime {
                service: "FailureHook",
                environment: &environment,
                directory: None,
                deadline: Instant::now() + Duration::from_secs(2),
                cancelled: &|| false,
                diagnostic: &reporter,
                generation: 8,
            }
        ),
        HookOutcome::Completed(7)
    );
    let hook = HookConfig {
        command: "ping -n 30 127.0.0.1 >nul".into(),
        ..hook
    };
    assert_eq!(
        run_hook(
            &hook,
            &HookRuntime {
                service: "FailureHook",
                environment: &environment,
                directory: None,
                deadline: Instant::now() + Duration::from_millis(60),
                cancelled: &|| false,
                diagnostic: &reporter,
                generation: 9,
            }
        ),
        HookOutcome::TimedOut
    );
    assert!(reporter.flush(Duration::from_secs(1)));
    let records = records.lock().unwrap();
    assert!(records.iter().any(
        |record| record.operation.contains("generation=8") && record.message.contains("code 7")
    ));
    assert!(records
        .iter()
        .any(|record| record.operation.contains("generation=9")
            && record.message.contains("timed out")));
    assert!(records
        .iter()
        .all(|record| !record.message.contains("SECRET")));
}

#[test]
fn cancellation_terminates_the_actual_hook_tree_without_waiting_for_timeout() {
    let records = Arc::new(Mutex::new(Vec::new()));
    let reporter = diagnostics::Reporter::new(Recording(records));
    let cancelled = Arc::new(AtomicBool::new(false));
    let worker_cancelled = Arc::clone(&cancelled);
    let worker = thread::spawn(move || {
        let environment: Vec<_> = std::env::vars_os().collect();
        let hook = HookConfig {
            event: "Power".into(),
            action: "Change".into(),
            command: "ping -n 30 127.0.0.1 >nul".into(),
        };
        run_hook(
            &hook,
            &HookRuntime {
                service: "CancelledHook",
                environment: &environment,
                directory: None,
                deadline: Instant::now() + Duration::from_secs(30),
                cancelled: &|| worker_cancelled.load(Ordering::Acquire),
                diagnostic: &reporter,
                generation: 3,
            },
        )
    });
    thread::sleep(Duration::from_millis(50));
    let started = Instant::now();
    cancelled.store(true, Ordering::Release);
    let deadline = Instant::now() + Duration::from_secs(3);
    while !worker.is_finished() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        worker.is_finished(),
        "owned hook cancellation must be bounded"
    );
    assert_eq!(worker.join().unwrap(), HookOutcome::Cancelled);
    assert!(started.elapsed() < Duration::from_secs(3));
}
