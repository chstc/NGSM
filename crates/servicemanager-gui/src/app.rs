//! Slint application controller: window construction, the background-worker
//! bridge, and the UI callbacks.

use std::cell::RefCell;
use std::sync::mpsc::{channel, Receiver};

use servicemanager_core::ServiceDefinition;
use servicemanager_win32::InstallStartType;
use slint::ComponentHandle;

use crate::data::{
    spawn_worker, ActionKind, ActionTarget, Job, JobResult, JobSendError, JobSender,
};
use crate::requests::{
    mutation_outcome, LogTarget, LogViewState, ModalKind, ModalState, MutationOutcome, OperationId,
    RecoveryEditor, RecoveryWork, RefreshState, RequestSequence, StatusState,
};
use crate::{adapter, config, forms, recovery};
use crate::{EventEntry, MainWindow, ProcessRow, RecoveryRow, ServiceRow};

/// UI-thread-only controller state. It lives in a `thread_local` so the
/// worker's wake callback — which must be `Send` — can stay capture-free and
/// reach this only after hopping onto the UI thread.
struct AppState {
    window: slint::Weak<MainWindow>,
    job_tx: JobSender,
    result_rx: Receiver<JobResult>,
    defs: Vec<ServiceDefinition>,
    /// Startup-time warning (e.g. corrupt config.json), shown persistently
    /// alongside per-scan warnings. `None` when config loaded cleanly.
    startup_warning: Option<String>,
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
    logs: LogViewState,
    /// Most-recent supervisor-recorded events from the last scan
    /// (newest first). The display `events: Vec<EventEntry>` is
    /// rebuilt from this every `apply_snapshot`.
    event_records: Vec<servicemanager_core::EventRecord>,
    /// Latest dashboard metrics computed by the worker.
    metrics: crate::metrics::DashboardMetrics,
    /// Display model for the Recent Events panel — rebuilt from `event_records`
    /// every `apply_snapshot`, newest first, capped at 12.
    events: Vec<EventEntry>,
    /// In-progress edit form — holds the originals so `to_spec` can diff.
    edit_form: Option<forms::EditForm>,
    /// Process-tree rows for the open Processes dialog.
    proc_rows: Vec<ProcessRow>,
    proc_sort_column: i32,
    proc_sort_ascending: bool,
    recovery: RecoveryEditor,
    /// Persisted user preferences.
    config: config::Config,
    /// Auto-refresh ticker; held so it keeps running and can be restarted.
    timer: slint::Timer,
    modal: ModalState,
    action_ids: RequestSequence,
    status: StatusState,
    scan_error: Option<String>,
    refresh: RefreshState,
}

thread_local! {
    static STATE: RefCell<Option<AppState>> = const { RefCell::new(None) };
}

/// The auto-refresh ticker body: enqueue a refresh while the toggle is on.
fn auto_refresh_tick() {
    STATE.with(|s| {
        if let Some(st) = s.borrow_mut().as_mut() {
            if let Some(win) = st.window.upgrade() {
                if win.get_auto_refresh() {
                    request_refresh(st, &win);
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
    let config_load = config::load();
    let config_startup_warning = config_load.warning;
    let config = config_load.config;
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
            startup_warning: config_startup_warning,
            warnings: Vec::new(),
            managed_only: config.managed_only,
            running_only: false,
            search: String::new(),
            search_debounce: slint::Timer::default(),
            sort_column: 0,
            sort_ascending: true,
            visible_names: Vec::new(),
            log_stderr: false,
            logs: LogViewState::default(),
            event_records: Vec::new(),
            metrics: Default::default(),
            events: Vec::new(),
            edit_form: None,
            proc_rows: Vec::new(),
            proc_sort_column: 0,
            proc_sort_ascending: true,
            recovery: RecoveryEditor::default(),
            config,
            timer: auto_timer,
            modal: ModalState::default(),
            action_ids: RequestSequence::default(),
            status: StatusState::default(),
            scan_error: None,
            refresh: RefreshState::default(),
        });
    });

    wire_callbacks(&window);

    STATE.with(|s| {
        if let Some(st) = s.borrow_mut().as_mut() {
            st.status.scan("Loading…".into());
            request_refresh(st, &window);
            render_status(st, &window);
        }
    });

    Ok(window)
}

/// Register the UI callbacks. Each runs on the UI thread and reaches the
/// controller through the `STATE` thread-local.
fn wire_callbacks(window: &MainWindow) {
    window.on_refresh(|| {
        STATE.with(|s| {
            if let Some(st) = s.borrow_mut().as_mut() {
                if let Some(win) = st.window.upgrade() {
                    request_refresh(st, &win);
                }
            }
        });
    });
    window.on_view_warnings(|| {
        STATE.with(|s| {
            if let Some(st) = s.borrow_mut().as_mut() {
                if let Some(win) = st.window.upgrade() {
                    // Open the warnings dialog when there is either a startup
                    // config warning OR per-scan service warnings. Previously
                    // only st.warnings was checked, so a startup_warning-only
                    // scenario left the dialog unreachable.
                    let has_any = st.startup_warning.is_some()
                        || !st.warnings.is_empty()
                        || st.scan_error.is_some()
                        || !st.status.details().is_empty();
                    if has_any {
                        replace_modal(st, &win, ModalKind::Warnings, "");
                    }
                }
            }
        });
    });
    window.on_view_changed(|view| {
        STATE.with(|s| {
            let mut guard = s.borrow_mut();
            let Some(st) = guard.as_mut() else { return };
            let Some(win) = st.window.upgrade() else {
                return;
            };
            if view != 3 {
                capture_recovery_fields(st, &win);
                st.recovery.leave();
                win.set_recovery_busy(false);
            }
            if view != 2 {
                st.logs.leave();
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
                    ActionKind::Start,
                    &name,
                    format!("Starting '{name}'…"),
                ),
                "stop" => dispatch(
                    st,
                    &win,
                    ActionKind::Stop,
                    &name,
                    format!("Stopping '{name}'…"),
                ),
                "restart" => dispatch(
                    st,
                    &win,
                    ActionKind::Restart,
                    &name,
                    format!("Restarting '{name}'…"),
                ),
                "pause" => dispatch(
                    st,
                    &win,
                    ActionKind::Pause,
                    &name,
                    format!("Pausing '{name}'…"),
                ),
                "continue" => dispatch(
                    st,
                    &win,
                    ActionKind::Continue,
                    &name,
                    format!("Resuming '{name}'…"),
                ),
                "rotate" => dispatch(
                    st,
                    &win,
                    ActionKind::Rotate,
                    &name,
                    format!("Rotating logs for '{name}'…"),
                ),
                "processes" => open_processes_modal(st, &win, &name),
                "edit" => open_edit_modal(st, &win, &name),
                "remove" => {
                    replace_modal(st, &win, ModalKind::Remove, &name);
                }
                other => {
                    operation_status(st, &win, format!("Unknown action '{other}' — ignored."));
                }
            }
        });
    });
    window.on_relaunch_admin(|| {
        if crate::elevation::relaunch_as_admin() {
            std::process::exit(0);
        }
        STATE.with(|s| {
            if let Some(st) = s.borrow_mut().as_mut() {
                if let Some(win) = st.window.upgrade() {
                    operation_status(st, &win, "Relaunch declined or failed.".into());
                }
            }
        });
    });
    window.on_install(|| {
        STATE.with(|s| {
            if let Some(st) = s.borrow_mut().as_mut() {
                if let Some(win) = st.window.upgrade() {
                    replace_modal(st, &win, ModalKind::Install, "");
                }
            }
        });
    });
    window.on_modal_cancel(|| {
        STATE.with(|s| {
            let mut guard = s.borrow_mut();
            let Some(st) = guard.as_mut() else { return };
            if let Some(win) = st.window.upgrade() {
                replace_modal(st, &win, ModalKind::Closed, "");
            }
        });
    });
    window.on_modal_browse_app(|| {
        let generation = STATE.with(|s| {
            s.borrow().as_ref().and_then(|st| {
                (!st.modal.busy() && matches!(st.modal.kind, ModalKind::Install | ModalKind::Edit))
                    .then_some(st.modal.generation)
            })
        });
        let Some(generation) = generation else { return };
        // The native picker runs its own modal loop; do this before borrowing
        // STATE so the borrow is not held across the blocking call.
        let picked = rfd::FileDialog::new()
            .add_filter("Executables", &["exe"])
            .add_filter("All files", &["*"])
            .pick_file();
        if let Some(path) = picked {
            STATE.with(|s| {
                if let Some(st) = s.borrow().as_ref() {
                    if let Some(win) = st
                        .window
                        .upgrade()
                        .filter(|_| st.modal.generation == generation && !st.modal.busy())
                    {
                        win.set_modal_application(path.to_string_lossy().into_owned().into());
                    }
                }
            });
        }
    });
    window.on_modal_install_submit(|| {
        STATE.with(|s| {
            let mut guard = s.borrow_mut();
            let Some(st) = guard.as_mut() else { return };
            let Some(win) = st.window.upgrade() else {
                return;
            };
            if st.modal.kind != ModalKind::Install || st.modal.busy() {
                return;
            }
            let form = forms::InstallForm {
                name: win.get_modal_name().to_string(),
                display_name: win.get_modal_display().to_string(),
                description: win.get_modal_description().to_string(),
                application: win.get_modal_application().to_string(),
                app_parameters: win.get_modal_arguments().to_string(),
                app_directory: win.get_modal_working_dir().to_string(),
                stdout: win.get_modal_stdout().to_string(),
                stderr: win.get_modal_stderr().to_string(),
                account: win.get_modal_account().to_string(),
                password: win.get_modal_password().to_string(),
                start_type: int_to_start_type(win.get_modal_start_type()),
            };
            let mut form = form;
            let spec = form.to_spec();
            form.clear_password();
            clear_modal_password(&win);
            match spec {
                Ok(spec) => {
                    let name = spec.name.clone();
                    let sender = st.job_tx.clone();
                    win.set_modal_error("".into());
                    match st.modal.submit(name.clone(), |request| {
                        try_send_job(&sender, Job::Install { spec, request })
                    }) {
                        Ok(request) => begin_operation(
                            st,
                            &win,
                            OperationId::Modal(request.id),
                            format!("Installing '{name}'…"),
                        ),
                        Err(e) => win.set_modal_error(e.to_string().into()),
                    }
                    win.set_modal_busy(st.modal.busy());
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
            if st.modal.kind != ModalKind::Edit || st.modal.busy() {
                return;
            }
            let Some(form) = st.edit_form.as_mut() else {
                return;
            };
            form.display_name = win.get_modal_display().to_string();
            form.description = win.get_modal_description().to_string();
            form.application = win.get_modal_application().to_string();
            form.app_parameters = win.get_modal_arguments().to_string();
            form.app_directory = win.get_modal_working_dir().to_string();
            form.stdout = win.get_modal_stdout().to_string();
            form.stderr = win.get_modal_stderr().to_string();
            form.account = win.get_modal_account().to_string();
            form.password = win.get_modal_password().to_string();
            form.start_type = int_to_start_type(win.get_modal_start_type());
            let spec = form.to_spec();
            form.clear_password();
            clear_modal_password(&win);
            match spec {
                Ok(spec) => {
                    let name = spec.name.clone();
                    let sender = st.job_tx.clone();
                    win.set_modal_error("".into());
                    match st.modal.submit(name.clone(), |request| {
                        try_send_job(&sender, Job::Edit { spec, request })
                    }) {
                        Ok(request) => begin_operation(
                            st,
                            &win,
                            OperationId::Modal(request.id),
                            format!("Editing '{name}'…"),
                        ),
                        Err(e) => win.set_modal_error(e.to_string().into()),
                    }
                    win.set_modal_busy(st.modal.busy());
                }
                Err(e) => win.set_modal_error(e.into()),
            }
        });
    });
    window.on_modal_remove_confirm(|| {
        STATE.with(|s| {
            let mut guard = s.borrow_mut();
            let Some(st) = guard.as_mut() else { return };
            let Some(win) = st.window.upgrade() else {
                return;
            };
            if st.modal.kind != ModalKind::Remove {
                return;
            }
            let name = win.get_modal_service_name().to_string();
            match queue_action(
                st,
                &win,
                ActionKind::Remove,
                &name,
                format!("Removing '{name}'…"),
            ) {
                Ok(()) => {
                    replace_modal(st, &win, ModalKind::Closed, "");
                }
                Err(e) => {
                    win.set_modal_error(format!("Removal not queued: {e}. Please retry.").into())
                }
            }
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
            if !st.recovery.active() || st.recovery.busy() {
                return;
            }
            let Some(form) = st.recovery.editable_draft() else {
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
            if !st.recovery.active() || st.recovery.busy() {
                return;
            }
            let Some(form) = st.recovery.editable_draft() else {
                return;
            };
            let Ok(i) = usize::try_from(idx) else { return };
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
            if !st.recovery.active() || st.recovery.busy() {
                return;
            }
            let Some(form) = st.recovery.editable_draft() else {
                return;
            };
            let Ok(idx) = usize::try_from(idx) else {
                return;
            };
            if let Some(row) = form.rows.get_mut(idx) {
                row.exit_code = text.to_string();
            }
        });
    });
    window.on_recovery_action_changed(|idx, action| {
        STATE.with(|s| {
            let mut guard = s.borrow_mut();
            let Some(st) = guard.as_mut() else { return };
            if !st.recovery.active() || st.recovery.busy() {
                return;
            }
            let Some(form) = st.recovery.editable_draft() else {
                return;
            };
            let Ok(idx) = usize::try_from(idx) else {
                return;
            };
            if let Some(row) = form.rows.get_mut(idx) {
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
            if !st.recovery.active() || st.recovery.busy() {
                return;
            }
            capture_recovery_fields(st, &win);
            let Some(form) = st.recovery.draft.as_ref() else {
                return;
            };
            match form.to_spec() {
                Ok(spec) => {
                    let name = spec.name.clone();
                    let sender = st.job_tx.clone();
                    match st.recovery.submit(RecoveryWork::Save, |request| {
                        try_send_job(&sender, Job::SaveRecovery { spec, request })
                    }) {
                        Ok(request) => {
                            win.set_recovery_status(format!("Saving '{name}'…").into());
                            begin_operation(
                                st,
                                &win,
                                OperationId::Recovery(request.id),
                                format!("Saving recovery for '{name}'…"),
                            );
                        }
                        Err(e) => win.set_recovery_status(e.to_string().into()),
                    }
                    win.set_recovery_busy(st.recovery.busy());
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
                win.set_auto_refresh(v);
                persist_config(st, &win);
            }
        });
    });
    window.on_settings_set_interval(|secs| {
        STATE.with(|s| {
            let mut guard = s.borrow_mut();
            let Some(st) = guard.as_mut() else { return };
            let secs_u = (secs.max(1) as u32)
                .clamp(config::AUTO_REFRESH_SECS_MIN, config::AUTO_REFRESH_SECS_MAX);
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
                win.set_auto_refresh_secs(secs_u as i32);
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
                win.set_managed_only(v);
                refresh_service_model(&win, st);
                persist_config(st, &win);
            }
        });
    });
}

fn try_send_job(sender: &JobSender, job: Job) -> Result<(), JobSendError> {
    sender.send(job)
}

fn render_status(st: &AppState, win: &MainWindow) {
    win.set_status_text(st.status.text().into());
    let details: Vec<slint::SharedString> = st
        .status
        .details()
        .into_iter()
        .chain(st.startup_warning.iter().cloned())
        .chain(st.warnings.iter().cloned())
        .chain(st.scan_error.iter().cloned())
        .map(Into::into)
        .collect();
    win.set_status_has_details(!details.is_empty());
    win.set_status_details(slint::ModelRc::new(slint::VecModel::from(details)));
}

fn operation_status(st: &mut AppState, win: &MainWindow, message: String) {
    st.status.operation(message);
    render_status(st, win);
}

fn begin_operation(st: &mut AppState, win: &MainWindow, id: OperationId, message: String) {
    st.status.begin(id, message);
    render_status(st, win);
}

fn update_scan_status(st: &mut AppState, win: &MainWindow) {
    let warnings: Vec<slint::SharedString> = st
        .startup_warning
        .iter()
        .chain(st.warnings.iter())
        .chain(st.scan_error.iter())
        .map(|warning| warning.as_str().into())
        .collect();
    let base = st
        .scan_error
        .clone()
        .unwrap_or_else(|| format!("{} services", st.defs.len()));
    st.status.scan(if warnings.is_empty() {
        base
    } else {
        format!("{base} — {} warning(s); click for details", warnings.len())
    });
    win.set_warnings(slint::ModelRc::new(slint::VecModel::from(warnings)));
    render_status(st, win);
}

fn request_refresh(st: &mut AppState, win: &MainWindow) {
    let sender = st.job_tx.clone();
    if let Err(e) = st.refresh.request(|| try_send_job(&sender, Job::Refresh)) {
        st.scan_error = Some(format!("Refresh not queued: {e}; retry pending"));
        update_scan_status(st, win);
    }
}

/// Send a worker job and show a pending message in the status bar.
fn dispatch(st: &mut AppState, win: &MainWindow, kind: ActionKind, service: &str, msg: String) {
    if let Err(e) = queue_action(st, win, kind, service, msg) {
        operation_status(
            st,
            win,
            format!("Action for '{service}' not queued: {e}. Please retry."),
        );
    }
}

fn queue_action(
    st: &mut AppState,
    win: &MainWindow,
    kind: ActionKind,
    service: &str,
    message: String,
) -> Result<(), JobSendError> {
    let request = st.action_ids.issue(ActionTarget {
        service: service.into(),
        kind,
    });
    let id = OperationId::Action(request.id);
    try_send_job(&st.job_tx, Job::Action(request))?;
    begin_operation(st, win, id, message);
    Ok(())
}

fn replace_modal(st: &mut AppState, win: &MainWindow, kind: ModalKind, service: &str) -> bool {
    if !st.modal.replace(kind) {
        return false;
    }
    st.edit_form = None;
    clear_modal_fields(win);
    win.set_modal_service_name(service.into());
    win.set_modal_error("".into());
    win.set_modal_busy(false);
    win.set_active_modal(kind as i32);
    true
}

fn open_processes_modal(st: &mut AppState, win: &MainWindow, name: &str) {
    if !replace_modal(st, win, ModalKind::Processes, name) {
        return;
    }
    st.proc_rows.clear();
    apply_process_model(win, st);
    let sender = st.job_tx.clone();
    if let Err(e) = st.modal.submit(name.into(), |request| {
        try_send_job(&sender, Job::Processes(request))
    }) {
        win.set_modal_error(e.to_string().into());
    }
    win.set_modal_busy(st.modal.busy());
}

/// Populate the shared modal fields from a service's config and open Edit.
fn open_edit_modal(st: &mut AppState, win: &MainWindow, name: &str) {
    let Some(def) = st.defs.iter().find(|d| d.native.name == name) else {
        operation_status(st, win, format!("'{name}' is no longer present."));
        return;
    };
    let form = forms::EditForm::from_definition(def);
    if !replace_modal(st, win, ModalKind::Edit, &form.name) {
        return;
    }
    win.set_modal_display(form.display_name.clone().into());
    win.set_modal_description(form.description.clone().into());
    win.set_modal_application(form.application.clone().into());
    win.set_modal_arguments(form.app_parameters.clone().into());
    win.set_modal_working_dir(form.app_directory.clone().into());
    win.set_modal_stdout(form.stdout.clone().into());
    win.set_modal_stderr(form.stderr.clone().into());
    win.set_modal_account(form.account.clone().into());
    win.set_modal_password("".into());
    win.set_modal_start_type(start_type_to_int(form.start_type));
    st.edit_form = Some(form);
}

fn clear_modal_fields(win: &MainWindow) {
    win.set_modal_name("".into());
    win.set_modal_display("".into());
    win.set_modal_description("".into());
    win.set_modal_application("".into());
    win.set_modal_arguments("".into());
    win.set_modal_working_dir("".into());
    win.set_modal_stdout("".into());
    win.set_modal_stderr("".into());
    win.set_modal_account("".into());
    win.set_modal_start_type(0);
    clear_modal_password(win);
}

fn clear_modal_password(win: &MainWindow) {
    win.set_modal_password("".into());
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
                JobResult::Services {
                    defs,
                    warnings,
                    events,
                    metrics,
                } => {
                    st.defs = defs;
                    st.warnings = warnings;
                    st.event_records = events;
                    st.metrics = metrics;
                    st.scan_error = None;
                    update_scan_status(st, &win);
                    apply_snapshot(&win, st);
                }
                JobResult::Acted { request, result } => {
                    let outcome = mutation_outcome(
                        false,
                        &format!("{:?} '{}'", request.target.kind, request.target.service),
                        result,
                    );
                    apply_mutation_outcome(st, &win, OperationId::Action(request.id), &outcome);
                }
                JobResult::Processes { request, result } => {
                    if st.modal.finish(&request) {
                        win.set_modal_busy(false);
                        match result {
                            Ok(processes) => {
                                st.proc_rows = processes
                                    .iter()
                                    .map(|p| ProcessRow {
                                        pid: p.pid.to_string().into(),
                                        ppid: p.parent_pid.to_string().into(),
                                        image: p.image_name.clone().into(),
                                    })
                                    .collect();
                                apply_process_model(&win, st);
                            }
                            Err(e) => {
                                win.set_modal_error(format!("Cannot read processes: {e}").into())
                            }
                        }
                    }
                }
                JobResult::Log {
                    request,
                    status,
                    lines,
                } => {
                    if st.logs.received(&request, status, lines) {
                        render_log(&win, st);
                    }
                }
                JobResult::RecoveryLoaded { request, result } => {
                    if let Some(result) = st.recovery.loaded(&request, result) {
                        win.set_recovery_busy(false);
                        match result {
                            Ok(()) => {
                                show_recovery_draft(&win, st);
                                win.set_recovery_status(
                                    "Policy reloaded from the service configuration.".into(),
                                );
                            }
                            Err(e) => {
                                let suffix = if st.recovery.draft.is_some() {
                                    " Draft retained."
                                } else {
                                    ""
                                };
                                let error = format!("Reload failed: {e}.{suffix} Please retry.");
                                win.set_recovery_status(error.clone().into());
                                win.set_recovery_placeholder(error.into());
                            }
                        }
                    }
                }
                JobResult::RecoverySaved { request, result } => {
                    let outcome = mutation_outcome(
                        st.recovery.finish(&request),
                        &format!("Save recovery for '{}'", request.target.service),
                        result,
                    );
                    if outcome.apply_local {
                        win.set_recovery_busy(false);
                        win.set_recovery_status(outcome.message.clone().into());
                    }
                    apply_mutation_outcome(st, &win, OperationId::Recovery(request.id), &outcome);
                }
                JobResult::Installed { request, result }
                | JobResult::Edited { request, result } => {
                    let outcome = mutation_outcome(
                        st.modal.finish(&request),
                        &format!("{:?} '{}'", request.target.kind, request.target.service),
                        result,
                    );
                    if outcome.apply_local {
                        win.set_modal_busy(false);
                        clear_modal_password(&win);
                        if let Some(error) = &outcome.error {
                            if let Some(form) = st.edit_form.as_mut() {
                                form.clear_password();
                            }
                            win.set_modal_error(error.as_str().into());
                        } else {
                            replace_modal(st, &win, ModalKind::Closed, "");
                        }
                    }
                    apply_mutation_outcome(st, &win, OperationId::Modal(request.id), &outcome);
                }
                JobResult::ScanError(e) => {
                    st.scan_error = Some(format!("Refresh failed: {e}"));
                    update_scan_status(st, &win);
                }
            }
        }
        if st.refresh.retry {
            request_refresh(st, &win);
        }
    });
}

fn apply_mutation_outcome(
    st: &mut AppState,
    win: &MainWindow,
    id: OperationId,
    outcome: &MutationOutcome,
) {
    st.status.finish(id, outcome.message.clone());
    render_status(st, win);
    if outcome.refresh {
        request_refresh(st, win);
    }
}

/// Rebuild the service model and Dashboard stats from the cached defs, then
/// render the Recent Events feed from the cached supervisor event records.
fn apply_snapshot(win: &MainWindow, st: &mut AppState) {
    refresh_service_model(win, st);

    // --- Dashboard tile bindings ---
    let m = &st.metrics;
    win.set_stat_total(m.total.to_string().into());
    win.set_stat_running(m.running.to_string().into());
    win.set_stat_stopped(m.stopped.to_string().into());
    win.set_stat_manual_start(m.manual_start.to_string().into());
    win.set_stat_failed(m.failed.to_string().into());
    win.set_stat_auto_recovering(m.auto_recovering.to_string().into());
    win.set_stat_availability_title(
        format!("Availability ({}d)", m.availability_window_days).into(),
    );
    let availability_text = if m.total == 0 || m.availability_unknown {
        "—".to_string()
    } else {
        format!("{:.1}%", m.availability_pct)
    };
    win.set_stat_availability_value(availability_text.into());
    // Hide the sparkline whenever the "—" text is shown — either there are
    // no managed services (`total == 0`) or the event-log read failed
    // (`availability_unknown`). Otherwise a flat 100% line under "—" would
    // mislead.
    let (line, area) = if m.total == 0 || m.availability_unknown {
        (String::new(), String::new())
    } else {
        let start = m
            .availability_daily
            .len()
            .saturating_sub(m.availability_window_days as usize);
        crate::metrics::sparkline_paths(&m.availability_daily[start..])
    };
    win.set_stat_availability_line(line.into());
    win.set_stat_availability_area(area.into());

    // Recent Events: render from the supervisor's persistent log.
    use servicemanager_core::events::{EventKind as Ek, EventRecord};
    let render = |rec: &EventRecord| {
        let (label, kind) = match rec.event {
            Ek::Started => (format!("{} — started", rec.service), 0),
            Ek::Stopped => (format!("{} — stopped", rec.service), 1),
            Ek::ChildExited => match rec.exit_code {
                Some(c) => (format!("{} — exited (code {c})", rec.service), 1),
                None => (format!("{} — exited", rec.service), 1),
            },
            Ek::Restarted => (format!("{} — restarted", rec.service), 2),
            Ek::Throttled => match rec.delay_ms {
                Some(ms) => (format!("{} — restart throttled ({ms}ms)", rec.service), 2),
                None => (format!("{} — restart throttled", rec.service), 2),
            },
        };
        EventEntry {
            label: label.into(),
            time: crate::event_log_reader::format_local_hms(&rec.ts).into(),
            kind,
        }
    };
    st.events = st.event_records.iter().take(12).map(render).collect();
    win.set_events(slint::ModelRc::new(slint::VecModel::from(
        st.events.clone(),
    )));
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
    // Clear the selected index BEFORE swapping the model so the Slint
    // detail-pane binding cannot observe an out-of-range index against
    // the just-replaced (possibly shorter) `services` model — even with
    // the slint-side bounds guard in place, narrowing the window of stale
    // state keeps behavior predictable across binding orderings.
    win.set_selected_service(-1);
    win.set_services(slint::ModelRc::new(slint::VecModel::from(rows)));
    win.set_selected_service(selected);
}

/// Re-read the currently-selected service's log into the Logs view.
fn request_log(win: &MainWindow, st: &mut AppState) {
    let idx = win.get_selected_service().max(0) as usize;
    let target = st.visible_names.get(idx).cloned().map(|service| LogTarget {
        service,
        stderr: st.log_stderr,
    });
    let sender = st.job_tx.clone();
    st.logs.request(target, |request| {
        try_send_job(&sender, Job::ReadLog(request))
    });
    render_log(win, st);
}

fn render_log(win: &MainWindow, st: &AppState) {
    let lines: Vec<slint::SharedString> = st
        .logs
        .lines
        .iter()
        .map(|line| line.as_str().into())
        .collect();
    win.set_log_lines(slint::ModelRc::new(slint::VecModel::from(lines)));
    win.set_log_service_name(
        st.logs
            .target
            .as_ref()
            .map_or("", |target| target.service.as_str())
            .into(),
    );
    win.set_log_stderr(
        st.logs
            .target
            .as_ref()
            .map_or(st.log_stderr, |target| target.stderr),
    );
    win.set_log_status(st.logs.status.as_str().into());
}

/// Rebuild the Processes-dialog model from the cached rows + current sort.
fn apply_process_model(win: &MainWindow, st: &AppState) {
    let mut rows = st.proc_rows.clone();
    adapter::sort_process_rows(&mut rows, st.proc_sort_column, st.proc_sort_ascending);
    win.set_modal_processes(slint::ModelRc::new(slint::VecModel::from(rows)));
}

/// Reload current backend policy, keeping an existing same-service draft until
/// a matching read succeeds. Read/save controls are frozen while pending.
fn reload_recovery(win: &MainWindow, st: &mut AppState) {
    if st.recovery.busy() {
        return;
    }
    capture_recovery_fields(st, win);
    let placeholder = |win: &MainWindow, msg: &str| {
        win.set_recovery_available(false);
        win.set_recovery_busy(false);
        win.set_recovery_placeholder(msg.into());
    };
    if !win.get_elevated() {
        st.recovery.leave();
        placeholder(win, "Recovery editing needs an administrator session.");
        return;
    }
    let idx = win.get_selected_service().max(0) as usize;
    let Some(name) = st.visible_names.get(idx).cloned() else {
        st.recovery.leave();
        placeholder(
            win,
            "Select a service in the Services view to edit its recovery policy.",
        );
        return;
    };
    st.recovery.activate(name.clone());
    win.set_recovery_service(name.clone().into());
    show_recovery_draft(win, st);
    let message = format!("Reloading recovery policy for '{name}'…");
    win.set_recovery_placeholder(message.clone().into());
    win.set_recovery_status(message.into());
    let sender = st.job_tx.clone();
    if let Err(e) = st.recovery.submit(RecoveryWork::Read, |request| {
        try_send_job(&sender, Job::ReadRecovery(request))
    }) {
        let suffix = if st.recovery.draft.is_some() {
            " Draft retained."
        } else {
            ""
        };
        let message = format!("{e}{suffix}");
        win.set_recovery_placeholder(message.clone().into());
        win.set_recovery_status(message.into());
    }
    win.set_recovery_busy(st.recovery.busy());
}

fn capture_recovery_fields(st: &mut AppState, win: &MainWindow) {
    if let Some(form) = st.recovery.editable_draft() {
        form.restart_delay = win.get_recovery_restart_delay().to_string();
        form.throttle = win.get_recovery_throttle().to_string();
        form.default_action = win.get_recovery_default_action();
    }
}

fn show_recovery_draft(win: &MainWindow, st: &AppState) {
    let Some(form) = st.recovery.draft.as_ref() else {
        win.set_recovery_available(false);
        return;
    };
    win.set_recovery_service(form.service.clone().into());
    win.set_recovery_restart_delay(form.restart_delay.clone().into());
    win.set_recovery_throttle(form.throttle.clone().into());
    win.set_recovery_default_action(form.default_action);
    push_recovery_rows(win, form);
    win.set_recovery_available(true);
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
fn persist_config(st: &mut AppState, win: &MainWindow) {
    let message = match config::save(&st.config) {
        Ok(()) => "Settings saved.".into(),
        Err(e) => format!("Settings not saved: {e}"),
    };
    operation_status(st, win, message);
}

#[cfg(test)]
#[path = "ui_tests.rs"]
mod ui_tests;

#[cfg(test)]
mod tests {
    use crate::event_log_reader::format_local_hms;
    use crate::requests::Pending;

    #[test]
    fn format_local_hms_round_trip_for_known_input() {
        // Only assert the shape — actual local hour depends on test
        // machine timezone.
        let s = format_local_hms("2026-05-22T14:15:32Z");
        assert_eq!(s.len(), 8);
        assert!(s.chars().nth(2) == Some(':'));
    }

    #[test]
    fn modal_result_with_matching_token_is_applied() {
        let mut pending = Pending::default();
        let request = pending.submit("A", |_| Ok::<_, ()>(())).unwrap();
        assert!(pending.finish(&request));
    }

    #[test]
    fn modal_result_with_stale_token_is_dropped() {
        // Active op moved on (or a different submit happened) — old
        // worker result must not affect the current modal.
        let mut pending = Pending::default();
        let old = pending.submit("A", |_| Ok::<_, ()>(())).unwrap();
        let current = pending.submit("B", |_| Ok::<_, ()>(())).unwrap();
        assert!(!pending.finish(&old));
        assert!(pending.finish(&current));
    }

    #[test]
    fn modal_result_with_no_active_op_is_dropped() {
        // The modal was cancelled or already resolved — any result
        // arriving now is stale by definition.
        let mut pending = Pending::default();
        let old = pending.submit("A", |_| Ok::<_, ()>(())).unwrap();
        pending.invalidate();
        assert!(!pending.finish(&old));
    }
}
