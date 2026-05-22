//! Slint application controller: window construction, the background-worker
//! bridge, and the UI callbacks.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::mpsc::{channel, Receiver, Sender};

use servicemanager_core::{ServiceDefinition, ServiceState};
use slint::ComponentHandle;

use crate::adapter;
use crate::data::{spawn_worker, Job, JobResult};
use crate::{EventEntry, MainWindow, ServiceRow};

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
            let guard = s.borrow();
            let Some(st) = guard.as_ref() else { return };
            let Some(win) = st.window.upgrade() else { return };
            let name = name.to_string();
            let job = match verb.as_str() {
                "start" => Some((Job::Start(name.clone()), format!("Starting '{name}'…"))),
                "stop" => Some((Job::Stop(name.clone()), format!("Stopping '{name}'…"))),
                "restart" => {
                    Some((Job::Restart(name.clone()), format!("Restarting '{name}'…")))
                }
                "pause" => Some((Job::Pause(name.clone()), format!("Pausing '{name}'…"))),
                "continue" => {
                    Some((Job::Continue(name.clone()), format!("Resuming '{name}'…")))
                }
                "rotate" => {
                    Some((Job::Rotate(name.clone()), format!("Rotating logs for '{name}'…")))
                }
                "processes" => Some((
                    Job::Processes(name.clone()),
                    format!("Listing processes of '{name}'…"),
                )),
                // "edit" / "remove" open modal dialogs — wired in Task 16.
                _ => None,
            };
            if let Some((job, msg)) = job {
                win.set_status_text(msg.into());
                let _ = st.job_tx.send(job);
            }
        });
    });
}

/// Drain every pending `JobResult` and apply it to the UI. Posted onto the UI
/// thread by the worker's wake callback.
fn drain_results() {
    STATE.with(|s| {
        let mut guard = s.borrow_mut();
        let Some(st) = guard.as_mut() else { return };
        let Some(win) = st.window.upgrade() else { return };
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
                JobResult::Processes { .. } => {
                    // Wired in Task 16 (Processes modal).
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
    win.set_events(slint::ModelRc::new(slint::VecModel::from(st.events.clone())));
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
