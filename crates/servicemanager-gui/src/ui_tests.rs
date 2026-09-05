//! Hidden-window checks using the existing Slint backend and a non-executing
//! worker queue. No service, registry, settings, or native-picker callbacks run.

use super::*;
use crate::data::RecoverySpec;
use servicemanager_core::{
    Error, ExitAction, ManagedApplicationConfig, NativeServiceConfig, ServiceRuntimeState,
    ServiceState, ServiceType, StartupType,
};
use slint::Model;
use std::sync::mpsc::Sender;

fn definition(name: &str) -> ServiceDefinition {
    ServiceDefinition {
        native: NativeServiceConfig {
            name: name.into(),
            display_name: name.into(),
            description: None,
            startup: StartupType::Manual,
            service_type: ServiceType::Win32OwnProcess,
            image_path: format!("C:\\NGSM\\ngsm.exe run-service {name}"),
            account: Some("LocalSystem".into()),
            depend_on_services: vec![],
            depend_on_groups: vec![],
        },
        managed: Some(ManagedApplicationConfig {
            application: Some("C:\\app.exe".into()),
            ..Default::default()
        }),
        runtime: Some(ServiceRuntimeState {
            state: ServiceState::Running,
            pid: Some(123),
            exit_code: None,
            checkpoint: None,
            wait_hint_ms: None,
        }),
    }
}

fn fake_state(win: &MainWindow, capacity: usize) -> (Receiver<Job>, Sender<JobResult>) {
    let (job_tx, jobs) = crate::data::test_channel(capacity);
    let (results, result_rx) = channel();
    let mut state = AppState {
        window: win.as_weak(),
        job_tx,
        result_rx,
        defs: vec![definition("A"), definition("B")],
        startup_warning: None,
        warnings: vec![],
        managed_only: true,
        running_only: false,
        search: String::new(),
        search_debounce: slint::Timer::default(),
        sort_column: 0,
        sort_ascending: true,
        visible_names: vec![],
        log_stderr: false,
        logs: LogViewState::default(),
        event_records: vec![],
        metrics: Default::default(),
        events: vec![],
        edit_form: None,
        proc_rows: vec![],
        proc_sort_column: 0,
        proc_sort_ascending: true,
        recovery: RecoveryEditor::default(),
        config: config::Config::default(),
        timer: slint::Timer::default(),
        modal: ModalState::default(),
        action_ids: RequestSequence::default(),
        status: StatusState::default(),
        scan_error: None,
        refresh: RefreshState::default(),
    };
    win.set_elevated(true);
    win.set_view(1);
    replace_modal(&mut state, win, ModalKind::Closed, "");
    refresh_service_model(win, &mut state);
    STATE.with(|slot| *slot.borrow_mut() = Some(state));
    (jobs, results)
}

fn policy(name: &str, delay: u32) -> RecoverySpec {
    RecoverySpec {
        name: name.into(),
        restart_delay_ms: Some(delay),
        throttle_delay_ms: None,
        default_action: ExitAction::Restart,
        exit_actions: Default::default(),
    }
}

fn enter_recovery(win: &MainWindow) {
    win.set_view(3);
    win.invoke_view_changed(3);
    win.invoke_recovery_reload();
}

#[test]
fn hidden_window_layout_and_async_callbacks_preserve_current_context() {
    // MainWindow::new does not call build_ui: no live worker or preference I/O.
    let win = MainWindow::new().unwrap();
    wire_callbacks(&win);
    check_layout(&win);
    check_processes_and_modal_tokens(&win);
    check_busy_send_failure_and_mutation_outcome(&win);
    check_view_local_enqueue_failures(&win);
    check_log_labels(&win);
    check_recovery_results(&win);
    STATE.with(|slot| *slot.borrow_mut() = None);
}

fn check_layout(win: &MainWindow) {
    // Inspect the same generated layout metadata used by the native backend;
    // no graphics surface or visible window is needed.
    use slint::private_unstable_api::re_exports::{Orientation, VRc, WindowInner};
    for (width, height) in [(1040.0, 700.0), (1260.0, 820.0)] {
        win.window()
            .dispatch_event(slint::platform::WindowEvent::Resized {
                size: slint::LogicalSize::new(width, height),
            });
        for count in [0, 1, 30] {
            let rows = (0..count)
                .map(|i| RecoveryRow {
                    exit_code: i.to_string().into(),
                    action: 0,
                })
                .collect::<Vec<_>>();
            let events = (0..count.min(12))
                .map(|i| EventEntry {
                    label: format!("Service {i} restarted").into(),
                    time: "12:00:00".into(),
                    kind: 0,
                })
                .collect::<Vec<_>>();
            win.set_recovery_available(true);
            win.set_recovery_service("A".into());
            win.set_recovery_status("Long policy validation message. ".repeat(50).into());
            win.set_recovery_rows(slint::ModelRc::new(slint::VecModel::from(rows)));
            win.set_events(slint::ModelRc::new(slint::VecModel::from(events)));
            for view in [0, 3] {
                win.set_view(view);
                let component = WindowInner::from_pub(win.window()).component();
                let component = VRc::borrow_pin(&component);
                let horizontal = component.as_ref().layout_info(Orientation::Horizontal);
                let vertical = component.as_ref().layout_info(Orientation::Vertical);
                assert!(
                    horizontal.min <= width,
                    "view {view}, {count} rows: {horizontal:?}"
                );
                assert!(
                    vertical.min <= height,
                    "view {view}, {count} rows: {vertical:?}"
                );
            }
        }
    }
}

fn check_processes_and_modal_tokens(win: &MainWindow) {
    for success in [false, true] {
        let (jobs, results) = fake_state(win, 8);
        win.invoke_action("processes".into(), "A".into());
        let Job::Processes(request) = jobs.try_recv().unwrap() else {
            panic!("process request")
        };
        win.invoke_action("edit".into(), "B".into());
        win.set_modal_password("new B secret".into());
        results
            .send(JobResult::Processes {
                request,
                result: if success {
                    Ok(vec![])
                } else {
                    Err(Error::other("old A error"))
                },
            })
            .unwrap();
        drain_results();
        assert_eq!(win.get_active_modal(), ModalKind::Edit as i32);
        assert_eq!(win.get_modal_service_name(), "B");
        assert_eq!(win.get_modal_password(), "new B secret");
        assert_eq!(win.get_modal_error(), "");
    }
}

fn check_busy_send_failure_and_mutation_outcome(win: &MainWindow) {
    let (jobs, results) = fake_state(win, 1);
    win.invoke_install();
    win.set_modal_name("NewService".into());
    win.set_modal_application("C:\\app.exe".into());
    win.invoke_modal_install_submit();
    assert!(win.get_modal_busy());
    win.invoke_refresh(); // Full: the accepted Install still owns the modal.
    win.invoke_modal_cancel();
    win.invoke_modal_install_submit();
    assert!(win.get_modal_busy());
    assert_eq!(win.get_active_modal(), ModalKind::Install as i32);
    let Job::Install { request, .. } = jobs.try_recv().unwrap() else {
        panic!("install request")
    };
    assert!(jobs.try_recv().is_err(), "no duplicate mutation");
    results
        .send(JobResult::Installed {
            request: request.clone(),
            result: Ok("Installed NewService".into()),
        })
        .unwrap();
    drain_results();
    assert_eq!(win.get_active_modal(), ModalKind::Closed as i32);
    assert!(matches!(jobs.try_recv().unwrap(), Job::Refresh));
    assert!(win.get_status_text().contains("Installed NewService"));
    win.invoke_action("edit".into(), "B".into());
    win.set_modal_password("keep this new secret".into());
    results
        .send(JobResult::Installed {
            request,
            result: Err(Error::other("late NewService error")),
        })
        .unwrap();
    results
        .send(JobResult::Services {
            defs: vec![definition("A"), definition("B")],
            warnings: vec![],
            events: vec![],
            metrics: Default::default(),
        })
        .unwrap();
    drain_results();
    assert_eq!(win.get_modal_service_name(), "B");
    assert_eq!(win.get_modal_password(), "keep this new secret");
    assert_eq!(win.get_modal_error(), "");
    assert!(win.get_status_text().contains("late NewService error"));
    assert!(win.get_status_has_details());
}

fn check_log_labels(win: &MainWindow) {
    let (jobs, results) = fake_state(win, 8);
    win.set_selected_service(0);
    win.invoke_logs_reload();
    let Job::ReadLog(first) = jobs.try_recv().unwrap() else {
        panic!("log A")
    };
    results
        .send(JobResult::Log {
            request: first.clone(),
            status: "A stdout".into(),
            lines: vec!["old A".into()],
        })
        .unwrap();
    drain_results();
    assert_eq!(win.get_log_lines().row_count(), 1);
    win.set_selected_service(1);
    win.invoke_logs_reload();
    let Job::ReadLog(second) = jobs.try_recv().unwrap() else {
        panic!("log B")
    };
    assert_eq!(win.get_log_service_name(), "B");
    assert_eq!(win.get_log_lines().row_count(), 0);
    win.set_selected_service(0);
    win.invoke_logs_set_stderr(true);
    let Job::ReadLog(latest) = jobs.try_recv().unwrap() else {
        panic!("log A stderr")
    };
    for old in [first, second] {
        results
            .send(JobResult::Log {
                request: old,
                status: "stale".into(),
                lines: vec!["stale".into()],
            })
            .unwrap();
    }
    drain_results();
    assert_eq!(win.get_log_service_name(), "A");
    assert!(win.get_log_stderr());
    assert_eq!(win.get_log_lines().row_count(), 0);
    results
        .send(JobResult::Log {
            request: latest,
            status: "fresh stderr".into(),
            lines: vec!["new A stderr".into()],
        })
        .unwrap();
    drain_results();
    assert_eq!(win.get_log_lines().row_data(0).unwrap(), "new A stderr");
}

fn check_recovery_results(win: &MainWindow) {
    for success in [false, true] {
        let (jobs, results) = fake_state(win, 8);
        win.set_selected_service(0);
        enter_recovery(win);
        let Job::ReadRecovery(request) = jobs.try_recv().unwrap() else {
            panic!("read A")
        };
        results
            .send(JobResult::RecoveryLoaded {
                request,
                result: Ok(policy("A", 200)),
            })
            .unwrap();
        drain_results();
        assert_eq!(win.get_recovery_restart_delay(), "200");
        win.set_recovery_restart_delay("333".into());
        win.invoke_recovery_reload();
        let Job::ReadRecovery(request) = jobs.try_recv().unwrap() else {
            panic!("reload A")
        };
        results
            .send(JobResult::RecoveryLoaded {
                request,
                result: Err(Error::other("read unavailable")),
            })
            .unwrap();
        drain_results();
        assert_eq!(win.get_recovery_restart_delay(), "333");
        assert!(win.get_recovery_status().contains("Draft retained"));
        win.invoke_recovery_save();
        let Job::SaveRecovery {
            request: save,
            spec,
        } = jobs.try_recv().unwrap()
        else {
            panic!("save A")
        };
        assert_eq!(spec.restart_delay_ms, Some(333));
        let row_count = win.get_recovery_rows().row_count();
        win.invoke_recovery_add_row();
        assert_eq!(win.get_recovery_rows().row_count(), row_count);
        win.invoke_recovery_save();
        assert!(jobs.try_recv().is_err(), "save and editing are frozen");
        win.set_view(1);
        win.invoke_view_changed(1);
        win.set_selected_service(1);
        enter_recovery(win);
        let Job::ReadRecovery(request) = jobs.try_recv().unwrap() else {
            panic!("read B")
        };
        results
            .send(JobResult::RecoveryLoaded {
                request,
                result: Ok(policy("B", 400)),
            })
            .unwrap();
        drain_results();
        let before = win.get_recovery_status();
        results
            .send(JobResult::RecoverySaved {
                request: save,
                result: if success {
                    Ok("Saved recovery for A".into())
                } else {
                    Err(Error::other("A save failed"))
                },
            })
            .unwrap();
        drain_results();
        assert_eq!(win.get_recovery_service(), "B");
        assert_eq!(win.get_recovery_restart_delay(), "400");
        assert_eq!(win.get_recovery_status(), before);
        assert!(win.get_status_text().contains("A"));
        assert!(matches!(jobs.try_recv().unwrap(), Job::Refresh));
    }
}

fn check_view_local_enqueue_failures(win: &MainWindow) {
    let (_jobs, _results) = fake_state(win, 1);
    win.invoke_refresh();
    win.invoke_logs_reload();
    assert!(!win.get_log_status().contains("Loading"));
    assert!(win.get_log_status().contains("retry"));
    assert_eq!(win.get_log_lines().row_count(), 0);
    enter_recovery(win);
    assert!(!win.get_recovery_busy());
    assert!(win.get_recovery_status().contains("retry"));
    win.invoke_install();
    win.set_modal_name("Rejected".into());
    win.set_modal_application("C:\\app.exe".into());
    win.invoke_modal_install_submit();
    assert!(!win.get_modal_busy());
    assert!(win.get_modal_error().contains("retry"));
    win.invoke_modal_cancel();
    assert_eq!(win.get_active_modal(), 0);
}
