//! Slint application controller: window construction, the background-worker
//! bridge, and the UI callbacks.

use std::cell::RefCell;
use std::sync::mpsc::{channel, Receiver, Sender};

use servicemanager_core::ServiceDefinition;
use servicemanager_win32::InstallStartType;
use slint::ComponentHandle;

use crate::data::{spawn_worker, Job, JobResult};
use crate::{adapter, config, forms, recovery};
use crate::{MainWindow, ProcessRow, RecoveryRow, ServiceRow};

/// UI-thread-only controller state. It lives in a `thread_local` so the
/// worker's wake callback — which must be `Send` — can stay capture-free and
/// reach this only after hopping onto the UI thread.
struct AppState {
    window: slint::Weak<MainWindow>,
    job_tx: Sender<Job>,
    result_rx: Receiver<JobResult>,
    defs: Vec<ServiceDefinition>,
    /// Per-service warnings from the most recent scan (unreadable config, ...).
    warnings: Vec<String>,
    managed_only: bool,
    running_only: bool,
    search: String,
    /// Single-shot timer that coalesces rapid search keystrokes into one
    /// model rebuild.
    search_debounce: slint::Timer,
    sort_column: i32,
    sort_ascending: bool,
    /// Service names in current display order — maps the selected row index
    /// (used by the Logs view) back to a service.
    visible_names: Vec<String>,
    /// Whether the Logs view is showing stderr (vs stdout).
    log_stderr: bool,
    /// The (service, stderr) the Logs view currently wants — used to discard
    /// stale `ReadLog` results that arrive after the user moved on.
    log_request: Option<(String, bool)>,
    /// True while a `ReadEvents` job is queued/running — prevents piling up
    /// duplicate event-log reads.
    events_pending: bool,
    /// In-progress edit form — holds the originals so `to_spec` can diff.
    edit_form: Option<forms::EditForm>,
    /// Process-tree rows for the open Processes dialog.
    proc_rows: Vec<ProcessRow>,
    proc_sort_column: i32,
    proc_sort_ascending: bool,
    /// In-progress Recovery editor form for the selected managed service.
    recovery_form: Option<recovery::RecoveryForm>,
    /// Persisted user preferences.
    config: config::Config,
    /// Auto-refresh ticker; held so it keeps running and can be restarted.
    timer: slint::Timer,
}

thread_local! {
    static STATE: RefCell<Option<AppState>> = const { RefCell::new(None) };
}

/// The auto-refresh ticker body: enqueue a refresh while the toggle is on.
fn auto_refresh_tick() {
    STATE.with(|s| {
        if let Some(st) = s.borrow().as_ref() {
            if let Some(win) = st.window.upgrade() {
                if win.get_auto_refresh() {
                    let _ = st.job_tx.send(Job::Refresh);
                }
            }
        }
    });
}

/// Debounced search rebuild: runs once the user pauses typing.
fn apply_search() {
    STATE.with(|s| {
        let mut guard = s.borrow_mut();
        let Some(st) = guard.as_mut() else { return };
        if let Some(win) = st.window.upgrade() {
            refresh_service_model(&win, st);
        }
    });
}

/// Build the main window, spawn the worker, and kick off the first refresh.
pub fn build_ui() -> Result<MainWindow, slint::PlatformError> {
    let window = MainWindow::new()?;
    window.set_elevated(servicemanager_win32::is_elevated());
    window.set_sort_ascending(true);
    window.set_modal_sort_ascending(true);

    let (result_tx, result_rx) = channel::<JobResult>();
    // The worker calls this off-thread; it only re-enters the event loop, so
    // it captures nothing and is trivially `Send`.
    let job_tx = spawn_worker(
        result_tx,
        Box::new(|| {
            let _ = slint::invoke_from_event_loop(drain_results);
        }),
    );

    // Load persisted preferences and seed the window from them.
    let config = config::load();
    window.set_auto_refresh(config.auto_refresh);
    window.set_managed_only(config.managed_only);
    window.set_auto_refresh_secs(config.auto_refresh_secs as i32);

    // Auto-refresh: a repeating tick that re-enumerates while the toggle is
    // on. The interval comes from preferences and can be changed in Settings.
    let auto_timer = slint::Timer::default();
    auto_timer.start(
        slint::TimerMode::Repeated,
        std::time::Duration::from_secs(config.auto_refresh_secs.max(1) as u64),
        auto_refresh_tick,
    );

    STATE.with(|s| {
        *s.borrow_mut() = Some(AppState {
            window: window.as_weak(),
            job_tx: job_tx.clone(),
            result_rx,
            defs: Vec::new(),
            warnings: Vec::new(),
            managed_only: config.managed_only,
            running_only: false,
            search: String::new(),
            search_debounce: slint::Timer::default(),
            sort_column: 0,
            sort_ascending: true,
            visible_names: Vec::new(),
            log_stderr: false,
            log_request: None,
            events_pending: false,
            edit_form: None,
            proc_rows: Vec::new(),
            proc_sort_column: 0,
            proc_sort_ascending: true,
            recovery_form: None,
            config,
            timer: auto_timer,
        });
    });

    wire_callbacks(&window);

    window.set_status_text("Loading…".into());
    let _ = job_tx.send(Job::Refresh);

    Ok(window)
}

/// Register the UI callbacks. Each runs on the UI thread and reaches the
/// controller through the `STATE` thread-local.
fn wire_callbacks(window: &MainWindow) {
    window.on_refresh(|| {
        STATE.with(|s| {
            if let Some(st) = s.borrow().as_ref() {
                let _ = st.job_tx.send(Job::Refresh);
            }
        });
    });
    window.on_view_warnings(|| {
        STATE.with(|s| {
            if let Some(st) = s.borrow().as_ref() {
                if let Some(win) = st.window.upgrade() {
                    if !st.warnings.is_empty() {
                        win.set_active_modal(5);
                    }
                }
            }
        });
    });
    window.on_filter_changed(|managed_only| {
        STATE.with(|s| {
            let mut guard = s.borrow_mut();
            let Some(st) = guard.as_mut() else { return };
            st.config.managed_only = managed_only;
            st.managed_only = managed_only;
            if let Some(win) = st.window.upgrade() {
                refresh_service_model(&win, st);
                persist_config(st, &win);
            }
        });
    });
    window.on_running_changed(|running_only| {
        STATE.with(|s| {
            let mut guard = s.borrow_mut();
            let Some(st) = guard.as_mut() else { return };
            st.running_only = running_only;
            if let Some(win) = st.window.upgrade() {
                refresh_service_model(&win, st);
            }
        });
    });
    window.on_search_changed(|text| {
        STATE.with(|s| {
            let mut guard = s.borrow_mut();
            let Some(st) = guard.as_mut() else { return };
            st.search = text.to_string();
            // Coalesce rapid keystrokes: rebuild the model only after the user
            // pauses. Calling `start` again restarts the single-shot timer.
            st.search_debounce.start(
                slint::TimerMode::SingleShot,
                std::time::Duration::from_millis(180),
                apply_search,
            );
        });
    });
    window.on_sort_changed(|column| {
        STATE.with(|s| {
            let mut guard = s.borrow_mut();
            let Some(st) = guard.as_mut() else { return };
            if st.sort_column == column {
                st.sort_ascending = !st.sort_ascending;
            } else {
                st.sort_column = column;
                st.sort_ascending = true;
            }
            if let Some(win) = st.window.upgrade() {
                win.set_sort_column(st.sort_column);
                win.set_sort_ascending(st.sort_ascending);
                refresh_service_model(&win, st);
            }
        });
    });
    window.on_action(|verb, name| {
        STATE.with(|s| {
            let mut guard = s.borrow_mut();
            let Some(st) = guard.as_mut() else { return };
            let Some(win) = st.window.upgrade() else {
                return;
            };
            let name = name.to_string();
            match verb.as_str() {
                "start" => dispatch(
                    st,
                    &win,
                    Job::Start(name.clone()),
                    format!("Starting '{name}'…"),
                ),
                "stop" => dispatch(
                    st,
                    &win,
                    Job::Stop(name.clone()),
                    format!("Stopping '{name}'…"),
                ),
                "restart" => dispatch(
                    st,
                    &win,
                    Job::Restart(name.clone()),
                    format!("Restarting '{name}'…"),
                ),
                "pause" => dispatch(
                    st,
                    &win,
                    Job::Pause(name.clone()),
                    format!("Pausing '{name}'…"),
                ),
                "continue" => dispatch(
                    st,
                    &win,
                    Job::Continue(name.clone()),
                    format!("Resuming '{name}'…"),
                ),
                "rotate" => dispatch(
                    st,
                    &win,
                    Job::Rotate(name.clone()),
                    format!("Rotating logs for '{name}'…"),
                ),
                "processes" => dispatch(
                    st,
                    &win,
                    Job::Processes(name.clone()),
                    format!("Listing processes of '{name}'…"),
                ),
                "edit" => open_edit_modal(st, &win, &name),
                "remove" => {
                    win.set_modal_service_name(name.clone().into());
                    win.set_active_modal(3);
                }
                other => {
                    win.set_status_text(format!("Unknown action '{other}' — ignored.").into());
                }
            }
        });
    });
    window.on_relaunch_admin(|| {
        if crate::elevation::relaunch_as_admin() {
            std::process::exit(0);
        }
        STATE.with(|s| {
            if let Some(st) = s.borrow().as_ref() {
                if let Some(win) = st.window.upgrade() {
                    win.set_status_text("Relaunch declined or failed.".into());
                }
            }
        });
    });
    window.on_install(|| {
        STATE.with(|s| {
            if let Some(st) = s.borrow().as_ref() {
                if let Some(win) = st.window.upgrade() {
                    clear_modal_fields(&win);
                    win.set_modal_start_type(0);
                    win.set_modal_error("".into());
                    win.set_modal_busy(false);
                    win.set_active_modal(1);
                }
            }
        });
    });
    window.on_modal_cancel(|| {
        STATE.with(|s| {
            let mut guard = s.borrow_mut();
            let Some(st) = guard.as_mut() else { return };
            st.edit_form = None;
            if let Some(win) = st.window.upgrade() {
                win.set_active_modal(0);
                win.set_modal_busy(false);
            }
        });
    });
    window.on_modal_browse_app(|| {
        // The native picker runs its own modal loop; do this before borrowing
        // STATE so the borrow is not held across the blocking call.
        let picked = rfd::FileDialog::new()
            .add_filter("Executables", &["exe"])
            .add_filter("All files", &["*"])
            .pick_file();
        if let Some(path) = picked {
            STATE.with(|s| {
                if let Some(st) = s.borrow().as_ref() {
                    if let Some(win) = st.window.upgrade() {
                        win.set_modal_application(path.to_string_lossy().into_owned().into());
                    }
                }
            });
        }
    });
    window.on_modal_install_submit(|| {
        STATE.with(|s| {
            let guard = s.borrow();
            let Some(st) = guard.as_ref() else { return };
            let Some(win) = st.window.upgrade() else {
                return;
            };
            let form = forms::InstallForm {
                name: win.get_modal_name().to_string(),
                display_name: win.get_modal_display().to_string(),
                application: win.get_modal_application().to_string(),
                app_parameters: win.get_modal_arguments().to_string(),
                app_directory: win.get_modal_working_dir().to_string(),
                stdout: win.get_modal_stdout().to_string(),
                stderr: win.get_modal_stderr().to_string(),
                start_type: int_to_start_type(win.get_modal_start_type()),
            };
            match form.to_spec() {
                Ok(spec) => {
                    win.set_status_text(format!("Installing '{}'…", spec.name).into());
                    win.set_modal_error("".into());
                    win.set_modal_busy(true);
                    let _ = st.job_tx.send(Job::Install(spec));
                }
                Err(e) => win.set_modal_error(e.into()),
            }
        });
    });
    window.on_modal_edit_submit(|| {
        STATE.with(|s| {
            let mut guard = s.borrow_mut();
            let Some(st) = guard.as_mut() else { return };
            let Some(win) = st.window.upgrade() else {
                return;
            };
            let Some(form) = st.edit_form.as_mut() else {
                return;
            };
            form.display_name = win.get_modal_display().to_string();
            form.application = win.get_modal_application().to_string();
            form.app_parameters = win.get_modal_arguments().to_string();
            form.app_directory = win.get_modal_working_dir().to_string();
            form.stdout = win.get_modal_stdout().to_string();
            form.stderr = win.get_modal_stderr().to_string();
            form.start_type = int_to_start_type(win.get_modal_start_type());
            match form.to_spec() {
                Ok(spec) => {
                    win.set_status_text(format!("Editing '{}'…", spec.name).into());
                    win.set_modal_error("".into());
                    win.set_modal_busy(true);
                    let _ = st.job_tx.send(Job::Edit(spec));
                }
                Err(e) => win.set_modal_error(e.into()),
            }
        });
    });
    window.on_modal_remove_confirm(|| {
        STATE.with(|s| {
            let guard = s.borrow();
            let Some(st) = guard.as_ref() else { return };
            let Some(win) = st.window.upgrade() else {
                return;
            };
            let name = win.get_modal_service_name().to_string();
            win.set_status_text(format!("Removing '{name}'…").into());
            let _ = st.job_tx.send(Job::Remove(name));
            win.set_active_modal(0);
        });
    });
    window.on_modal_sort_changed(|column| {
        STATE.with(|s| {
            let mut guard = s.borrow_mut();
            let Some(st) = guard.as_mut() else { return };
            if st.proc_sort_column == column {
                st.proc_sort_ascending = !st.proc_sort_ascending;
            } else {
                st.proc_sort_column = column;
                st.proc_sort_ascending = true;
            }
            if let Some(win) = st.window.upgrade() {
                win.set_modal_sort_column(st.proc_sort_column);
                win.set_modal_sort_ascending(st.proc_sort_ascending);
                apply_process_model(&win, st);
            }
        });
    });
    window.on_logs_reload(|| {
        STATE.with(|s| {
            let mut guard = s.borrow_mut();
            let Some(st) = guard.as_mut() else { return };
            if let Some(win) = st.window.upgrade() {
                request_log(&win, st);
            }
        });
    });
    window.on_logs_set_stderr(|stderr| {
        STATE.with(|s| {
            let mut guard = s.borrow_mut();
            let Some(st) = guard.as_mut() else { return };
            st.log_stderr = stderr;
            if let Some(win) = st.window.upgrade() {
                win.set_log_stderr(stderr);
                request_log(&win, st);
            }
        });
    });
    window.on_recovery_reload(|| {
        STATE.with(|s| {
            let mut guard = s.borrow_mut();
            let Some(st) = guard.as_mut() else { return };
            if let Some(win) = st.window.upgrade() {
                reload_recovery(&win, st);
            }
        });
    });
    window.on_recovery_add_row(|| {
        STATE.with(|s| {
            let mut guard = s.borrow_mut();
            let Some(st) = guard.as_mut() else { return };
            let Some(form) = st.recovery_form.as_mut() else {
                return;
            };
            form.rows.push(recovery::RecoveryExitRow::default());
            if let Some(win) = st.window.upgrade() {
                push_recovery_rows(&win, form);
            }
        });
    });
    window.on_recovery_remove_row(|idx| {
        STATE.with(|s| {
            let mut guard = s.borrow_mut();
            let Some(st) = guard.as_mut() else { return };
            let Some(form) = st.recovery_form.as_mut() else {
                return;
            };
            let i = idx.max(0) as usize;
            if i < form.rows.len() {
                form.rows.remove(i);
            }
            if let Some(win) = st.window.upgrade() {
                push_recovery_rows(&win, form);
            }
        });
    });
    window.on_recovery_code_changed(|idx, text| {
        STATE.with(|s| {
            let mut guard = s.borrow_mut();
            let Some(st) = guard.as_mut() else { return };
            let Some(form) = st.recovery_form.as_mut() else {
                return;
            };
            if let Some(row) = form.rows.get_mut(idx.max(0) as usize) {
                row.exit_code = text.to_string();
            }
        });
    });
    window.on_recovery_action_changed(|idx, action| {
        STATE.with(|s| {
            let mut guard = s.borrow_mut();
            let Some(st) = guard.as_mut() else { return };
            let Some(form) = st.recovery_form.as_mut() else {
                return;
            };
            if let Some(row) = form.rows.get_mut(idx.max(0) as usize) {
                row.action = action;
            }
            if let Some(win) = st.window.upgrade() {
                push_recovery_rows(&win, form);
            }
        });
    });
    window.on_recovery_save(|| {
        STATE.with(|s| {
            let mut guard = s.borrow_mut();
            let Some(st) = guard.as_mut() else { return };
            let Some(win) = st.window.upgrade() else {
                return;
            };
            let Some(form) = st.recovery_form.as_mut() else {
                return;
            };
            // The exit-code rows are kept current by the row callbacks; pull
            // the delay / default-action fields from the bound properties.
            form.restart_delay = win.get_recovery_restart_delay().to_string();
            form.throttle = win.get_recovery_throttle().to_string();
            form.default_action = win.get_recovery_default_action();
            match form.to_spec() {
                Ok(spec) => {
                    win.set_recovery_status(format!("Saving '{}'…", spec.name).into());
                    let _ = st.job_tx.send(Job::SaveRecovery(spec));
                }
                Err(e) => win.set_recovery_status(e.into()),
            }
        });
    });
    window.on_settings_set_auto_refresh(|v| {
        STATE.with(|s| {
            let mut guard = s.borrow_mut();
            let Some(st) = guard.as_mut() else { return };
            st.config.auto_refresh = v;
            if let Some(win) = st.window.upgrade() {
                persist_config(st, &win);
            }
        });
    });
    window.on_settings_set_interval(|secs| {
        STATE.with(|s| {
            let mut guard = s.borrow_mut();
            let Some(st) = guard.as_mut() else { return };
            let secs_u = secs.max(1) as u32;
            st.config.auto_refresh_secs = secs_u;
            // Restart the ticker so the new interval takes effect at once.
            // Calling `start` on a running `slint::Timer` replaces its current
            // registration, so no explicit cancel/stop is needed first.
            st.timer.start(
                slint::TimerMode::Repeated,
                std::time::Duration::from_secs(secs_u as u64),
                auto_refresh_tick,
            );
            if let Some(win) = st.window.upgrade() {
                win.set_auto_refresh_secs(secs);
                persist_config(st, &win);
            }
        });
    });
    window.on_settings_set_managed_only(|v| {
        STATE.with(|s| {
            let mut guard = s.borrow_mut();
            let Some(st) = guard.as_mut() else { return };
            st.config.managed_only = v;
            st.managed_only = v;
            if let Some(win) = st.window.upgrade() {
                refresh_service_model(&win, st);
                persist_config(st, &win);
            }
        });
    });
}

/// Send a worker job and show a pending message in the status bar.
fn dispatch(st: &AppState, win: &MainWindow, job: Job, msg: String) {
    win.set_status_text(msg.into());
    let _ = st.job_tx.send(job);
}

/// Populate the shared modal fields from a service's config and open Edit.
fn open_edit_modal(st: &mut AppState, win: &MainWindow, name: &str) {
    let Some(def) = st.defs.iter().find(|d| d.native.name == name) else {
        win.set_status_text(format!("'{name}' is no longer present.").into());
        return;
    };
    let form = forms::EditForm::from_definition(def);
    win.set_modal_service_name(form.name.clone().into());
    win.set_modal_display(form.display_name.clone().into());
    win.set_modal_application(form.application.clone().into());
    win.set_modal_arguments(form.app_parameters.clone().into());
    win.set_modal_working_dir(form.app_directory.clone().into());
    win.set_modal_stdout(form.stdout.clone().into());
    win.set_modal_stderr(form.stderr.clone().into());
    win.set_modal_start_type(start_type_to_int(form.start_type));
    win.set_modal_error("".into());
    win.set_modal_busy(false);
    st.edit_form = Some(form);
    win.set_active_modal(2);
}

fn clear_modal_fields(win: &MainWindow) {
    win.set_modal_name("".into());
    win.set_modal_display("".into());
    win.set_modal_application("".into());
    win.set_modal_arguments("".into());
    win.set_modal_working_dir("".into());
    win.set_modal_stdout("".into());
    win.set_modal_stderr("".into());
}

fn int_to_start_type(v: i32) -> InstallStartType {
    match v {
        1 => InstallStartType::Automatic,
        2 => InstallStartType::Disabled,
        _ => InstallStartType::Manual,
    }
}

fn start_type_to_int(v: InstallStartType) -> i32 {
    match v {
        InstallStartType::Manual => 0,
        InstallStartType::Automatic => 1,
        InstallStartType::Disabled => 2,
    }
}

/// Drain every pending `JobResult` and apply it to the UI. Posted onto the UI
/// thread by the worker's wake callback.
fn drain_results() {
    STATE.with(|s| {
        let mut guard = s.borrow_mut();
        let Some(st) = guard.as_mut() else { return };
        let Some(win) = st.window.upgrade() else {
            return;
        };
        while let Ok(result) = st.result_rx.try_recv() {
            match result {
                JobResult::Services { defs, warnings } => {
                    st.defs = defs;
                    st.warnings = warnings;
                    let base = format!("{} services", st.defs.len());
                    win.set_status_text(
                        if st.warnings.is_empty() {
                            base
                        } else {
                            format!(
                                "{base}  —  {} with unreadable config (click for details)",
                                st.warnings.len()
                            )
                        }
                        .into(),
                    );
                    let shared: Vec<slint::SharedString> =
                        st.warnings.iter().map(|w| w.as_str().into()).collect();
                    win.set_warnings(slint::ModelRc::new(slint::VecModel::from(shared)));
                    apply_snapshot(&win, st);
                }
                JobResult::Acted(msg) => {
                    win.set_status_text(msg.into());
                    let _ = st.job_tx.send(Job::Refresh);
                }
                JobResult::Processes { service, processes } => {
                    st.proc_rows = processes
                        .iter()
                        .map(|p| ProcessRow {
                            pid: p.pid.to_string().into(),
                            ppid: p.parent_pid.to_string().into(),
                            image: p.image_name.clone().into(),
                        })
                        .collect();
                    win.set_status_text(format!("{} process(es)", processes.len()).into());
                    win.set_modal_service_name(service.into());
                    apply_process_model(&win, st);
                    win.set_active_modal(4);
                }
                JobResult::Log {
                    service,
                    stderr,
                    status,
                    lines,
                } => {
                    // Discard a result the user no longer wants — they may have
                    // changed selection or toggled stdout/stderr since the read
                    // was queued.
                    if st.log_request.as_ref() == Some(&(service.clone(), stderr)) {
                        win.set_log_service_name(service.into());
                        win.set_log_stderr(stderr);
                        win.set_log_status(status.into());
                        let shared: Vec<slint::SharedString> =
                            lines.into_iter().map(|l| l.into()).collect();
                        win.set_log_lines(slint::ModelRc::new(slint::VecModel::from(shared)));
                    }
                }
                JobResult::Events(events) => {
                    st.events_pending = false;
                    let entries = adapter::scm_events_to_entries(&events, &st.defs, 30);
                    win.set_events(slint::ModelRc::new(slint::VecModel::from(entries)));
                }
                JobResult::RecoverySaved(result) => match result {
                    Ok(msg) => {
                        win.set_recovery_status(msg.clone().into());
                        win.set_status_text(msg.into());
                        let _ = st.job_tx.send(Job::Refresh);
                    }
                    Err(e) => {
                        win.set_recovery_status(format!("Error: {e}").into());
                    }
                },
                JobResult::Installed(result) => match result {
                    Ok(msg) => {
                        win.set_modal_busy(false);
                        win.set_active_modal(0);
                        win.set_status_text(msg.into());
                        let _ = st.job_tx.send(Job::Refresh);
                    }
                    Err(e) => {
                        win.set_modal_busy(false);
                        win.set_modal_error(e.into());
                    }
                },
                JobResult::Edited(result) => match result {
                    Ok(msg) => {
                        win.set_modal_busy(false);
                        st.edit_form = None;
                        win.set_active_modal(0);
                        win.set_status_text(msg.into());
                        let _ = st.job_tx.send(Job::Refresh);
                    }
                    Err(e) => {
                        win.set_modal_busy(false);
                        win.set_modal_error(e.into());
                    }
                },
                JobResult::Error(e) => {
                    st.events_pending = false;
                    win.set_status_text(format!("Error: {e}").into());
                }
            }
        }
    });
}

/// Rebuild the service model and Dashboard stats from the cached defs, then
/// kick off an event-log read for the Recent Events panel.
fn apply_snapshot(win: &MainWindow, st: &mut AppState) {
    refresh_service_model(win, st);

    let stats = adapter::dashboard_stats(&st.defs);
    win.set_stat_total(stats.total.to_string().into());
    win.set_stat_running(stats.running.to_string().into());
    win.set_stat_stopped(stats.stopped.to_string().into());
    win.set_stat_attention(stats.attention.to_string().into());

    // Recent Events come from the OS event log. Only read them when the
    // Dashboard is actually visible, and never pile up a second read.
    if win.get_view() == 0 && !st.events_pending {
        st.events_pending = true;
        let _ = st.job_tx.send(Job::ReadEvents);
    }
}

/// Rebuild the `services` model from the cached defs + current filter/search,
/// preserving the user's selection by service name across the rebuild.
fn refresh_service_model(win: &MainWindow, st: &mut AppState) {
    let elevated = win.get_elevated();
    // Capture the selected service name before the model (and visible_names)
    // are replaced, so the selection can follow the service, not the index.
    let selected_name = {
        let idx = win.get_selected_service().max(0) as usize;
        st.visible_names.get(idx).cloned()
    };
    let mut rows: Vec<ServiceRow> = st
        .defs
        .iter()
        .filter(|d| adapter::matches_filter(d, st.managed_only, st.running_only, &st.search))
        .map(|d| adapter::to_service_row(d, elevated))
        .collect();
    adapter::sort_service_rows(&mut rows, st.sort_column, st.sort_ascending);
    st.visible_names = rows.iter().map(|r| r.name.to_string()).collect();
    let selected = adapter::remap_selection(selected_name.as_deref(), &st.visible_names);
    win.set_services(slint::ModelRc::new(slint::VecModel::from(rows)));
    win.set_selected_service(selected);
}

/// Re-read the currently-selected service's log into the Logs view.
fn request_log(win: &MainWindow, st: &mut AppState) {
    let idx = win.get_selected_service().max(0) as usize;
    match st.visible_names.get(idx).cloned() {
        Some(name) => {
            win.set_log_service_name(name.clone().into());
            win.set_log_status("Loading…".into());
            st.log_request = Some((name.clone(), st.log_stderr));
            let _ = st.job_tx.send(Job::ReadLog {
                service: name,
                stderr: st.log_stderr,
            });
        }
        None => {
            st.log_request = None;
            win.set_log_service_name("".into());
            win.set_log_status("Select a service in the Services view to view its log.".into());
            win.set_log_lines(slint::ModelRc::new(slint::VecModel::from(Vec::<
                slint::SharedString,
            >::new(
            ))));
        }
    }
}

/// Rebuild the Processes-dialog model from the cached rows + current sort.
fn apply_process_model(win: &MainWindow, st: &AppState) {
    let mut rows = st.proc_rows.clone();
    adapter::sort_process_rows(&mut rows, st.proc_sort_column, st.proc_sort_ascending);
    win.set_modal_processes(slint::ModelRc::new(slint::VecModel::from(rows)));
}

/// Rebuild the Recovery editor form for the currently-selected service, or
/// show an explanatory placeholder when it cannot be edited.
fn reload_recovery(win: &MainWindow, st: &mut AppState) {
    let placeholder = |win: &MainWindow, msg: &str| {
        win.set_recovery_available(false);
        win.set_recovery_placeholder(msg.into());
    };
    if !win.get_elevated() {
        st.recovery_form = None;
        placeholder(win, "Recovery editing needs an administrator session.");
        return;
    }
    let idx = win.get_selected_service().max(0) as usize;
    let Some(name) = st.visible_names.get(idx).cloned() else {
        st.recovery_form = None;
        placeholder(
            win,
            "Select a service in the Services view to edit its recovery policy.",
        );
        return;
    };
    let Some(def) = st.defs.iter().find(|d| d.native.name == name) else {
        st.recovery_form = None;
        placeholder(win, "The selected service is no longer present.");
        return;
    };
    let Some(managed) = def.managed.clone() else {
        st.recovery_form = None;
        placeholder(win, &format!("'{name}' is not an NGSM-managed service."));
        return;
    };
    let display = def.native.display_name.clone();
    let form = recovery::RecoveryForm::from_managed(&name, &managed);
    win.set_recovery_service(display.into());
    win.set_recovery_restart_delay(form.restart_delay.clone().into());
    win.set_recovery_throttle(form.throttle.clone().into());
    win.set_recovery_default_action(form.default_action);
    win.set_recovery_status("".into());
    push_recovery_rows(win, &form);
    win.set_recovery_available(true);
    st.recovery_form = Some(form);
}

/// Push the form's exit-code rows into the Slint `recovery-rows` model.
fn push_recovery_rows(win: &MainWindow, form: &recovery::RecoveryForm) {
    let rows: Vec<RecoveryRow> = form
        .rows
        .iter()
        .map(|r| RecoveryRow {
            exit_code: r.exit_code.clone().into(),
            action: r.action,
        })
        .collect();
    win.set_recovery_rows(slint::ModelRc::new(slint::VecModel::from(rows)));
}

/// Persist preferences; a failed save is surfaced in the status bar but is
/// non-fatal (the in-memory config still applies for the session).
fn persist_config(st: &AppState, win: &MainWindow) {
    if let Err(e) = config::save(&st.config) {
        win.set_status_text(format!("Settings not saved: {e}").into());
    }
}
