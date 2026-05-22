//! Slint application controller: window construction, the background-worker
//! bridge, and the UI callbacks.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::mpsc::{channel, Receiver, Sender};

use servicemanager_core::{ServiceDefinition, ServiceState};
use servicemanager_win32::InstallStartType;
use slint::ComponentHandle;

use crate::data::{spawn_worker, Job, JobResult};
use crate::{adapter, forms};
use crate::{EventEntry, MainWindow, ProcessRow, ServiceRow};

/// UI-thread-only controller state. It lives in a `thread_local` so the
/// worker's wake callback — which must be `Send` — can stay capture-free and
/// reach this only after hopping onto the UI thread.
struct AppState {
    window: slint::Weak<MainWindow>,
    job_tx: Sender<Job>,
    result_rx: Receiver<JobResult>,
    defs: Vec<ServiceDefinition>,
    prev_states: HashMap<String, ServiceState>,
    managed_only: bool,
    search: String,
    events: Vec<EventEntry>,
    /// In-progress edit form — holds the originals so `to_spec` can diff.
    edit_form: Option<forms::EditForm>,
    /// Auto-refresh ticker; held only to keep it running.
    _timer: slint::Timer,
}

thread_local! {
    static STATE: RefCell<Option<AppState>> = const { RefCell::new(None) };
}

/// Build the main window, spawn the worker, and kick off the first refresh.
pub fn build_ui() -> Result<MainWindow, slint::PlatformError> {
    let window = MainWindow::new()?;
    window.set_elevated(servicemanager_win32::is_elevated());

    let (result_tx, result_rx) = channel::<JobResult>();
    // The worker calls this off-thread; it only re-enters the event loop, so
    // it captures nothing and is trivially `Send`.
    let job_tx = spawn_worker(
        result_tx,
        Box::new(|| {
            let _ = slint::invoke_from_event_loop(drain_results);
        }),
    );

    // Auto-refresh: a repeating 5 s tick that re-enumerates while the toggle
    // is on. The toggle state lives in the `auto-refresh` window property.
    let auto_timer = slint::Timer::default();
    auto_timer.start(
        slint::TimerMode::Repeated,
        std::time::Duration::from_secs(5),
        || {
            STATE.with(|s| {
                if let Some(st) = s.borrow().as_ref() {
                    if let Some(win) = st.window.upgrade() {
                        if win.get_auto_refresh() {
                            let _ = st.job_tx.send(Job::Refresh);
                        }
                    }
                }
            });
        },
    );

    STATE.with(|s| {
        *s.borrow_mut() = Some(AppState {
            window: window.as_weak(),
            job_tx: job_tx.clone(),
            result_rx,
            defs: Vec::new(),
            prev_states: HashMap::new(),
            managed_only: true,
            search: String::new(),
            events: Vec::new(),
            edit_form: None,
            _timer: auto_timer,
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
    window.on_filter_changed(|managed_only| {
        STATE.with(|s| {
            let mut guard = s.borrow_mut();
            let Some(st) = guard.as_mut() else { return };
            st.managed_only = managed_only;
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
            if let Some(win) = st.window.upgrade() {
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
                _ => {}
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
                    let _ = st.job_tx.send(Job::Install(spec));
                    win.set_active_modal(0);
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
                    let _ = st.job_tx.send(Job::Edit(spec));
                    st.edit_form = None;
                    win.set_active_modal(0);
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
                    let base = format!("{} services", st.defs.len());
                    win.set_status_text(
                        if warnings.is_empty() {
                            base
                        } else {
                            format!("{base}  —  {} with unreadable config", warnings.len())
                        }
                        .into(),
                    );
                    apply_snapshot(&win, st);
                }
                JobResult::Acted(msg) => {
                    win.set_status_text(msg.into());
                    let _ = st.job_tx.send(Job::Refresh);
                }
                JobResult::Processes { service, processes } => {
                    let rows: Vec<ProcessRow> = processes
                        .iter()
                        .map(|p| ProcessRow {
                            pid: p.pid.to_string().into(),
                            ppid: p.parent_pid.to_string().into(),
                            image: p.image_name.clone().into(),
                        })
                        .collect();
                    win.set_status_text(format!("{} process(es)", processes.len()).into());
                    win.set_modal_service_name(service.into());
                    win.set_modal_processes(slint::ModelRc::new(slint::VecModel::from(rows)));
                    win.set_active_modal(4);
                }
                JobResult::Error(e) => {
                    win.set_status_text(format!("Error: {e}").into());
                }
            }
        }
    });
}

/// Rebuild the service model, Dashboard stats, and Recent Events feed from
/// the cached defs.
fn apply_snapshot(win: &MainWindow, st: &mut AppState) {
    refresh_service_model(win, st);

    let stats = adapter::dashboard_stats(&st.defs);
    win.set_stat_total(stats.total.to_string().into());
    win.set_stat_running(stats.running.to_string().into());
    win.set_stat_stopped(stats.stopped.to_string().into());
    win.set_stat_attention(stats.attention.to_string().into());

    // Recent Events: diff this scan against the previous one, newest first.
    let changes = adapter::diff_events(&st.prev_states, &st.defs);
    if !changes.is_empty() {
        let now = local_hms();
        for change in changes {
            let (verb, kind) = match change.kind {
                adapter::EventKind::Started => ("started", 0),
                adapter::EventKind::Stopped => ("stopped", 1),
            };
            st.events.insert(
                0,
                EventEntry {
                    label: format!("{} — {verb}", change.service).into(),
                    time: now.clone().into(),
                    kind,
                },
            );
        }
        st.events.truncate(12);
    }
    st.prev_states = adapter::state_snapshot(&st.defs);
    win.set_events(slint::ModelRc::new(slint::VecModel::from(
        st.events.clone(),
    )));
}

/// Current local time formatted `HH:MM:SS`, for event timestamps.
fn local_hms() -> String {
    use windows::Win32::System::SystemInformation::GetLocalTime;
    // SAFETY: `GetLocalTime` returns a fully-initialised `SYSTEMTIME`.
    let t = unsafe { GetLocalTime() };
    format!("{:02}:{:02}:{:02}", t.wHour, t.wMinute, t.wSecond)
}

/// Rebuild the `services` model from the cached defs + current filter/search.
fn refresh_service_model(win: &MainWindow, st: &AppState) {
    let elevated = win.get_elevated();
    let rows: Vec<ServiceRow> = st
        .defs
        .iter()
        .filter(|d| adapter::matches_filter(d, st.managed_only, &st.search))
        .map(|d| adapter::to_service_row(d, elevated))
        .collect();
    win.set_services(slint::ModelRc::new(slint::VecModel::from(rows)));
}
