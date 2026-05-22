//! Background worker for the UI thread.
//!
//! Win32 calls (SCM enumerate, registry read, install, etc.) can take
//! tens to hundreds of milliseconds; running them on the UI thread would
//! freeze the frame. We send `Job`s to a worker and post `JobResult`s
//! back, calling a `wake` callback after each so the UI drains them promptly.

use std::collections::BTreeMap;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use servicemanager_core::{
    ExitAction, ExitActionPolicy, IoRedirectionConfig, IoStream, ManagedApplicationConfig,
    ServiceDefinition,
};
use servicemanager_win32::{
    build_run_service_command, control_service, enumerate_descendants, enumerate_services,
    install_service, query_service, read_scm_events, remove_service, start_service,
    update_native_config, InstallOptions, InstallStartType, ProcessInfo, ScmEvent,
    ServiceControlSignal, SERVICE_CONTROL_ROTATE,
};

/// Wrap a log-file path in a plain [`IoStream`] (default share/disposition).
fn io_stream(path: String) -> IoStream {
    IoStream {
        path,
        share_mode: None,
        creation_disposition: None,
        flags_and_attributes: None,
        copy_and_truncate: None,
    }
}

/// A unit of work the UI hands to the worker thread.
pub enum Job {
    Refresh,
    Install(InstallSpec),
    Edit(EditSpec),
    Start(String),
    Stop(String),
    Restart(String),
    Pause(String),
    Continue(String),
    Rotate(String),
    Remove(String),
    Processes(String),
    ReadLog { service: String, stderr: bool },
    ReadEvents,
    SaveRecovery(RecoverySpec),
}

/// A result the worker posts back to the UI.
pub enum JobResult {
    Services {
        defs: Vec<ServiceDefinition>,
        /// Per-service managed-config read failures (access denied, corrupt
        /// values, ...). The rows are still shown; these are surfaced as a
        /// status-bar warning instead of being silently dropped.
        warnings: Vec<String>,
    },
    Processes {
        service: String,
        processes: Vec<ProcessInfo>,
    },
    /// A privileged action ran (e.g. `Install`). Stash the success message;
    /// the UI shows it in the status bar.
    Acted(String),
    /// A tail of a service's stdout/stderr log.
    Log {
        service: String,
        stderr: bool,
        status: String,
        lines: Vec<String>,
    },
    /// Recent Service Control Manager events for the Dashboard feed.
    Events(Vec<ScmEvent>),
    /// Outcome of a `SaveRecovery` job — routed to the Recovery view's own
    /// status line. `Ok` carries the success message, `Err` the failure.
    RecoverySaved(Result<String, String>),
    /// Outcome of an `Install` job — routed back to the Install dialog.
    Installed(Result<String, String>),
    /// Outcome of an `Edit` job — routed back to the Edit dialog.
    Edited(Result<String, String>),
    Error(String),
}

#[derive(Clone, Debug, Default)]
pub struct InstallSpec {
    pub name: String,
    pub display_name: Option<String>,
    pub application: String,
    pub app_parameters: Option<String>,
    pub app_directory: Option<String>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub start_type: InstallStartType,
}

/// A validated recovery-policy change for the worker to apply. The form layer
/// has already parsed and checked every field; the worker only re-reads the
/// current managed config and writes these values onto it.
#[derive(Clone, Debug)]
pub struct RecoverySpec {
    pub name: String,
    pub restart_delay_ms: Option<u32>,
    pub throttle_delay_ms: Option<u32>,
    pub default_action: ExitAction,
    pub exit_actions: BTreeMap<String, ExitAction>,
}

#[derive(Clone, Debug, Default)]
pub struct EditSpec {
    pub name: String,
    pub display_name: Option<String>,
    pub application: Option<String>,
    pub app_parameters: Option<String>,
    pub app_directory: Option<String>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub start_type: Option<InstallStartType>,
}

/// Spawn the worker thread. Returns the job sender; results land on
/// `result_tx`. The worker calls `wake` after each result so the UI thread
/// can drain and apply them.
pub fn spawn_worker(result_tx: Sender<JobResult>, wake: Box<dyn Fn() + Send>) -> Sender<Job> {
    let (job_tx, job_rx) = std::sync::mpsc::channel::<Job>();
    thread::spawn(move || worker_loop(job_rx, result_tx, wake));
    job_tx
}

fn worker_loop(rx: Receiver<Job>, tx: Sender<JobResult>, wake: Box<dyn Fn() + Send>) {
    while let Ok(job) = rx.recv() {
        let result = execute(job);
        let _ = tx.send(result);
        wake();
    }
}

fn execute(job: Job) -> JobResult {
    match job {
        Job::Refresh => match list_services() {
            Ok((defs, warnings)) => JobResult::Services { defs, warnings },
            Err(e) => JobResult::Error(format!("enumerate: {e}")),
        },
        Job::Install(spec) => JobResult::Installed(install(spec)),
        Job::Edit(spec) => JobResult::Edited(edit(spec)),
        Job::Start(n) => simple(&n, "Start requested", || {
            ensure_ngsm_managed(&n)?;
            ensure_enabled(&n)?;
            start_service(&n)
        }),
        Job::Stop(n) => simple_with(&n, "Stop requested", || {
            ensure_ngsm_managed(&n)?;
            control_service(&n, ServiceControlSignal::Stop).map(|_| ())
        }),
        Job::Pause(n) => simple_with(&n, "Pause requested", || {
            ensure_ngsm_managed(&n)?;
            control_service(&n, ServiceControlSignal::Pause).map(|_| ())
        }),
        Job::Continue(n) => simple_with(&n, "Continue requested", || {
            ensure_ngsm_managed(&n)?;
            control_service(&n, ServiceControlSignal::Continue).map(|_| ())
        }),
        Job::Rotate(n) => match rotate(&n) {
            Ok(msg) => JobResult::Acted(msg),
            Err(e) => JobResult::Error(e),
        },
        Job::Restart(n) => match restart(&n) {
            Ok(msg) => JobResult::Acted(msg),
            Err(e) => JobResult::Error(e),
        },
        Job::Remove(n) => match remove(&n) {
            Ok(msg) => JobResult::Acted(msg),
            Err(e) => JobResult::Error(e),
        },
        Job::Processes(n) => match processes(&n) {
            Ok(r) => r,
            Err(e) => JobResult::Error(e),
        },
        Job::ReadLog { service, stderr } => read_log(&service, stderr),
        Job::ReadEvents => read_events(),
        Job::SaveRecovery(spec) => JobResult::RecoverySaved(save_recovery(spec)),
    }
}

fn simple(
    name: &str,
    label: &str,
    f: impl FnOnce() -> servicemanager_core::Result<()>,
) -> JobResult {
    match f() {
        Ok(()) => JobResult::Acted(format!("{label} for '{name}'.")),
        Err(e) => JobResult::Error(format!("{name}: {e}")),
    }
}

fn simple_with(
    name: &str,
    label: &str,
    f: impl FnOnce() -> servicemanager_core::Result<()>,
) -> JobResult {
    simple(name, label, f)
}

#[allow(clippy::type_complexity)]
pub fn list_services() -> servicemanager_core::Result<(Vec<ServiceDefinition>, Vec<String>)> {
    let mut warnings: Vec<String> = Vec::new();
    let mut defs: Vec<ServiceDefinition> = enumerate_services()?
        .into_iter()
        .map(|s| {
            // A failed SCM config query during enumeration left this entry
            // with only partial data — surface it rather than silently
            // classifying the service from incomplete fields.
            if let Some(w) = s.query_error {
                warnings.push(w);
            }
            // A genuine managed-config read failure (access denied, corrupt
            // value) is kept as a warning rather than collapsed into "not
            // managed".
            let managed = match servicemanager_registry::read_managed_config(&s.config.name) {
                Ok(m) => m,
                Err(e) => {
                    warnings.push(format!(
                        "{}: managed config unreadable ({e})",
                        s.config.name
                    ));
                    None
                }
            };
            ServiceDefinition {
                native: s.config,
                managed,
                runtime: s.runtime,
            }
        })
        .collect();
    defs.sort_by(|a, b| {
        a.native
            .name
            .to_lowercase()
            .cmp(&b.native.name.to_lowercase())
    });
    Ok((defs, warnings))
}

fn install(spec: InstallSpec) -> Result<String, String> {
    if spec.application.trim().is_empty() {
        return Err("Application path is required.".into());
    }
    let binary_path = build_run_service_command(&spec.name).map_err(|e| e.to_string())?;

    // Build the managed config before creating the SCM service.
    let managed = ManagedApplicationConfig {
        application: Some(spec.application),
        app_parameters: spec.app_parameters,
        app_directory: spec.app_directory,
        io: IoRedirectionConfig {
            stdin: None,
            stdout: spec.stdout.map(io_stream),
            stderr: spec.stderr.map(io_stream),
            timestamp_log: None,
        },
        ..Default::default()
    };

    install_service(&InstallOptions {
        name: spec.name.clone(),
        display_name: spec
            .display_name
            .clone()
            .unwrap_or_else(|| spec.name.clone()),
        binary_path,
        start_type: spec.start_type,
    })
    .map_err(|e| e.to_string())?;

    // Roll the SCM service back if the managed config cannot be written.
    if let Err(e) = servicemanager_registry::create_managed_config(&spec.name, &managed) {
        return Err(match remove_service(&spec.name) {
            Ok(()) => format!("install failed, service rolled back: {e}"),
            Err(re) => format!("install failed ({e}); rollback also failed ({re})"),
        });
    }
    Ok(format!("Installed '{}'.", spec.name))
}

fn edit(spec: EditSpec) -> Result<String, String> {
    let touches_managed = spec.application.is_some()
        || spec.app_parameters.is_some()
        || spec.app_directory.is_some()
        || spec.stdout.is_some()
        || spec.stderr.is_some();

    // `edit` only mutates NGSM-managed services. Re-validate ownership
    // against current registry state — the UI button may be stale, and a
    // native-only edit must not slip through unchecked.
    let Some(mut managed) =
        servicemanager_registry::read_managed_config(&spec.name).map_err(|e| e.to_string())?
    else {
        return Err(format!(
            "'{}' is not an NGSM-managed service — refusing to edit it",
            spec.name
        ));
    };

    // Managed (NSSM-owned) changes go first: validate every managed value
    // and complete the registry write *before* touching native SCM state,
    // so a rejected value or a failed write cannot leave a half-applied
    // edit with the display name / start type already changed.
    if touches_managed {
        if let Some(v) = spec.application {
            // Defence in depth — the edit form already rejects an empty
            // application, but never write one even if that changes.
            if v.trim().is_empty() {
                return Err("Application path must not be empty.".into());
            }
            managed.application = Some(v);
        }
        if let Some(v) = spec.app_parameters {
            managed.app_parameters = Some(v);
        }
        if let Some(v) = spec.app_directory {
            managed.app_directory = Some(v);
        }
        if let Some(v) = spec.stdout {
            // An empty path clears the value; the registry reconcile drops it.
            managed.io.stdout = if v.is_empty() {
                None
            } else {
                Some(io_stream(v))
            };
        }
        if let Some(v) = spec.stderr {
            managed.io.stderr = if v.is_empty() {
                None
            } else {
                Some(io_stream(v))
            };
        }
        servicemanager_registry::write_managed_config(&spec.name, &managed)
            .map_err(|e| e.to_string())?;
    }

    if spec.display_name.is_some() || spec.start_type.is_some() {
        update_native_config(&spec.name, spec.display_name.as_deref(), spec.start_type)
            .map_err(|e| e.to_string())?;
    }
    Ok(format!("Edited '{}'.", spec.name))
}

/// Re-validate, against current SCM/registry state, that a service is
/// NGSM-managed before the worker issues a lifecycle control. The UI gates
/// the buttons too, but its snapshot can be stale — the worker must not
/// trust it for start/stop/restart of (potentially native) services.
fn ensure_ngsm_managed(name: &str) -> servicemanager_core::Result<()> {
    let native = query_service(name)?;
    let managed = servicemanager_registry::read_managed_config(name)
        .ok()
        .flatten();
    let def = ServiceDefinition {
        native: native.config,
        managed,
        runtime: native.runtime,
    };
    if def.is_managed() {
        Ok(())
    } else {
        Err(servicemanager_core::Error::other(format!(
            "'{name}' is not an NGSM-managed service — refusing the lifecycle operation"
        )))
    }
}

/// Re-check, against current SCM state, that a service is not Disabled before
/// the worker attempts to start it. The UI gates this too, but its snapshot
/// can be stale.
fn ensure_enabled(name: &str) -> servicemanager_core::Result<()> {
    use servicemanager_core::StartupType;
    let native = query_service(name)?;
    if native.config.startup == StartupType::Disabled {
        return Err(servicemanager_core::Error::other(format!(
            "'{name}' is disabled — enable it before starting"
        )));
    }
    Ok(())
}

/// Worker-side rotate: re-read managed config and require online rotation
/// before issuing `SERVICE_CONTROL_ROTATE`, matching the CLI/broker
/// preflight (the UI snapshot may be stale).
fn rotate(name: &str) -> Result<String, String> {
    match servicemanager_registry::read_managed_config(name).map_err(|e| e.to_string())? {
        Some(cfg) if cfg.has_online_rotation() => {}
        Some(_) => {
            return Err(format!(
                "'{name}' does not use online log rotation — its logs rotate on restart, \
                 not on demand"
            ))
        }
        None => return Err(format!("'{name}' is not an NGSM-managed service")),
    }
    control_service(name, ServiceControlSignal::User(SERVICE_CONTROL_ROTATE))
        .map_err(|e| e.to_string())?;
    Ok(format!("Rotate requested for '{name}'."))
}

fn restart(name: &str) -> Result<String, String> {
    use servicemanager_core::ServiceState;
    ensure_ngsm_managed(name).map_err(|e| e.to_string())?;
    ensure_enabled(name).map_err(|e| e.to_string())?;
    let snapshot = query_service(name).map_err(|e| e.to_string())?;
    let initial = snapshot.runtime.as_ref().map(|r| r.state);
    let needs_stop = !matches!(initial, Some(ServiceState::Stopped) | None);
    if needs_stop {
        match control_service(name, ServiceControlSignal::Stop) {
            Ok(_) => {}
            Err(e) => {
                let msg = e.to_string();
                if !(msg.contains("0x80070426") || msg.contains("has not been started")) {
                    return Err(msg);
                }
            }
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let s = query_service(name).map_err(|e| e.to_string())?;
            if matches!(
                s.runtime.as_ref().map(|r| r.state),
                Some(ServiceState::Stopped)
            ) {
                break;
            }
            if Instant::now() >= deadline {
                return Err(format!("'{name}' did not stop within 30 s"));
            }
            thread::sleep(Duration::from_millis(200));
        }
        thread::sleep(Duration::from_millis(250));
    }
    start_service(name).map_err(|e| e.to_string())?;
    Ok(format!("Restarted '{name}'."))
}

fn remove(name: &str) -> Result<String, String> {
    // Re-query and re-validate managed ownership against the *current*
    // SCM/registry state. The UI enabled the button from a possibly-stale
    // service list, so the worker must not trust that authorization.
    let native = query_service(name).map_err(|e| e.to_string())?;
    // Fail closed: an unreadable managed config means ownership cannot be
    // confirmed, so refuse rather than collapsing the error into "native".
    let managed = match servicemanager_registry::read_managed_config(name) {
        Ok(m) => m,
        Err(e) => {
            return Err(format!(
                "'{name}': managed ownership cannot be determined — its managed config \
                 is unreadable ({e}); refusing to remove it"
            ));
        }
    };
    let def = ServiceDefinition {
        native: native.config,
        managed,
        runtime: native.runtime,
    };
    if !def.is_managed() {
        return Err(format!(
            "'{name}' is not an NGSM-managed service — refusing to remove it"
        ));
    }
    // The UI gates Remove on the stopped state, but its snapshot can be stale —
    // refuse to delete a service that is still running/pending/paused.
    use servicemanager_core::ServiceState;
    let stopped = matches!(
        def.runtime.as_ref().map(|r| r.state),
        Some(ServiceState::Stopped) | None
    );
    if !stopped {
        return Err(format!(
            "'{name}' is not stopped — stop it before removing it"
        ));
    }
    // Remove the SCM service first, then scrub the registry; surface a
    // cleanup failure instead of silently dropping it.
    remove_service(name).map_err(|e| e.to_string())?;
    servicemanager_registry::delete_managed_config(name)
        .map_err(|e| format!("service removed, but managed config cleanup failed: {e}"))?;
    Ok(format!("Removed '{name}'."))
}

fn processes(name: &str) -> Result<JobResult, String> {
    let snap = query_service(name).map_err(|e| e.to_string())?;
    let pid = snap
        .runtime
        .as_ref()
        .and_then(|r| r.pid)
        .ok_or_else(|| format!("service '{name}' is not running"))?;
    let descendants = enumerate_descendants(pid).map_err(|e| e.to_string())?;
    Ok(JobResult::Processes {
        service: name.to_string(),
        processes: descendants,
    })
}

/// Read the tail of a managed service's stdout or stderr log file.
fn read_log(service: &str, stderr: bool) -> JobResult {
    let which = if stderr { "stderr" } else { "stdout" };
    let log = |status: String, lines: Vec<String>| JobResult::Log {
        service: service.to_string(),
        stderr,
        status,
        lines,
    };
    let cfg = match servicemanager_registry::read_managed_config(service) {
        Ok(Some(c)) => c,
        Ok(None) => {
            return log(
                format!("'{service}' is not an NGSM-managed service."),
                Vec::new(),
            )
        }
        Err(e) => return log(format!("Cannot read '{service}' config: {e}"), Vec::new()),
    };
    let path = if stderr {
        cfg.io.stderr.as_ref().map(|s| s.path.clone())
    } else {
        cfg.io.stdout.as_ref().map(|s| s.path.clone())
    };
    let Some(path) = path else {
        return log(
            format!("No {which} log is configured for '{service}'."),
            Vec::new(),
        );
    };
    match tail_file(&path) {
        Ok(lines) => log(
            format!("{which}  ·  {path}  ·  {} lines", lines.len()),
            lines,
        ),
        Err(e) => log(format!("Cannot read {which} log '{path}': {e}"), Vec::new()),
    }
}

/// Read recent Service Control Manager lifecycle records for the Recent Events
/// feed. 200 raw records is a generous upper bound — the GUI then keeps only
/// those for managed services and shows the newest ~30.
fn read_events() -> JobResult {
    match read_scm_events(200) {
        Ok(events) => JobResult::Events(events),
        Err(e) => JobResult::Error(format!("event log: {e}")),
    }
}

/// Worker-side recovery save: re-read the managed config from the registry
/// (never trusting the possibly-stale UI snapshot, exactly as `edit` does),
/// apply the restart-policy and exit-action fields, and write it all back.
fn save_recovery(spec: RecoverySpec) -> Result<String, String> {
    let Some(mut managed) =
        servicemanager_registry::read_managed_config(&spec.name).map_err(|e| e.to_string())?
    else {
        return Err(format!(
            "'{}' is not an NGSM-managed service — refusing to edit its recovery policy",
            spec.name
        ));
    };
    managed.restart.restart_delay_ms = spec.restart_delay_ms;
    managed.restart.throttle_delay_ms = spec.throttle_delay_ms;
    // The editor always writes an explicit default action; a service that
    // previously had no explicit default is promoted to one (semantically
    // equivalent at runtime, since the supervisor's implicit fallback is Restart).
    managed.restart.default_action = Some(spec.default_action);
    managed.exit_actions = spec
        .exit_actions
        .iter()
        .map(|(code, action)| (code.clone(), ExitActionPolicy { action: *action }))
        .collect();
    servicemanager_registry::write_managed_config(&spec.name, &managed)
        .map_err(|e| e.to_string())?;
    Ok(format!("Saved recovery policy for '{}'.", spec.name))
}

/// Read the last ~64 KiB of a file and return up to its last 400 lines.
fn tail_file(path: &str) -> std::io::Result<Vec<String>> {
    use std::io::{Read, Seek, SeekFrom};
    const TAIL: u64 = 64 * 1024;
    let mut f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    let partial = len > TAIL;
    if partial {
        f.seek(SeekFrom::Start(len - TAIL))?;
    }
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    let mut lines: Vec<String> = String::from_utf8_lossy(&buf)
        .lines()
        .map(|l| l.to_string())
        .collect();
    // A mid-file seek leaves the first line truncated — drop it.
    if partial && !lines.is_empty() {
        lines.remove(0);
    }
    let extra = lines.len().saturating_sub(400);
    if extra > 0 {
        lines.drain(0..extra);
    }
    Ok(lines)
}
