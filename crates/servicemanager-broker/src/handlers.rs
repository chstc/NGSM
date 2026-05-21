//! Broker request dispatch — thin wrappers that translate JSON args into
//! [`servicemanager-win32`] / [`servicemanager-registry`] calls. Each
//! handler returns a `serde_json::Value` (or an error message) so the
//! pipe-layer code stays generic.

use serde::Deserialize;
use serde_json::{json, Value};
use servicemanager_core::{
    IoRedirectionConfig, IoStream, ManagedApplicationConfig, ServiceDefinition,
};
use servicemanager_win32::{
    build_run_service_command, control_service, enumerate_descendants, enumerate_services,
    install_service, query_service, remove_service, start_service, update_native_config,
    InstallOptions, InstallStartType, ServiceControlSignal, SERVICE_CONTROL_ROTATE,
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

use crate::protocol::Request;

pub fn dispatch(req: &Request) -> Result<Value, String> {
    let result = match req.op.as_str() {
        "ping" => json!({ "pong": true }),
        "list" => op_list(&req.args)?,
        "dump" => op_dump(&req.args)?,
        "install" => op_install(&req.args)?,
        "remove" => op_remove(&req.args)?,
        "start" => op_start(&req.args)?,
        "stop" => op_stop(&req.args)?,
        "restart" => op_restart(&req.args)?,
        "edit" => op_edit(&req.args)?,
        "rotate" => op_rotate(&req.args)?,
        "processes" => op_processes(&req.args)?,
        "pause" => op_pause(&req.args)?,
        "continue" => op_continue(&req.args)?,
        other => return Err(format!("unknown op '{other}'")),
    };
    Ok(result)
}

#[derive(Deserialize)]
struct NameArg {
    name: String,
}

#[derive(Deserialize)]
struct RemoveArgs {
    name: String,
    /// Allow removing a service that is not NGSM/NSSM-managed.
    #[serde(default)]
    force_native: bool,
}

#[derive(Deserialize)]
struct LifecycleArgs {
    name: String,
    /// Allow a start/stop/restart/pause/continue control on a service that
    /// is not NGSM/NSSM-managed.
    #[serde(default)]
    force_native: bool,
}

#[derive(Deserialize)]
struct ListArgs {
    #[serde(default)]
    filter: ListFilterArg,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "lowercase")]
enum ListFilterArg {
    #[default]
    Managed,
    All,
}

#[derive(Deserialize)]
struct InstallArgs {
    name: String,
    application: String,
    #[serde(default)]
    app_parameters: Option<String>,
    #[serde(default)]
    app_directory: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default = "default_start_type")]
    start_type: String,
    #[serde(default)]
    stdout: Option<String>,
    #[serde(default)]
    stderr: Option<String>,
}

fn default_start_type() -> String {
    "manual".into()
}

#[derive(Deserialize)]
struct EditArgs {
    name: String,
    #[serde(default)]
    application: Option<String>,
    #[serde(default)]
    app_parameters: Option<String>,
    #[serde(default)]
    app_directory: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    start_type: Option<String>,
    #[serde(default)]
    stdout: Option<String>,
    #[serde(default)]
    stderr: Option<String>,
    /// Allow changing native SCM fields on a service that is not NGSM-managed.
    #[serde(default)]
    force_native: bool,
}

fn parse_args<T: for<'de> Deserialize<'de>>(args: &Value) -> Result<T, String> {
    serde_json::from_value::<T>(args.clone()).map_err(|e| format!("invalid args: {e}"))
}

fn parse_start_type(s: &str) -> Result<InstallStartType, String> {
    match s.to_ascii_lowercase().as_str() {
        "manual" => Ok(InstallStartType::Manual),
        "automatic" => Ok(InstallStartType::Automatic),
        "disabled" => Ok(InstallStartType::Disabled),
        other => Err(format!("unknown start_type '{other}'")),
    }
}

fn op_list(args: &Value) -> Result<Value, String> {
    let args: ListArgs = parse_args(args)?;
    let services = enumerate_services().map_err(|e| e.to_string())?;
    let mut warnings: Vec<String> = Vec::new();
    let mut definitions: Vec<ServiceDefinition> = services
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
            // managed" — the same behaviour the CLI and GUI list flows have.
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
        .filter(|d| match args.filter {
            // Use the shared classifier so the broker's managed filter
            // agrees with the CLI and GUI.
            ListFilterArg::Managed => d.is_managed(),
            ListFilterArg::All => true,
        })
        .collect();
    definitions.sort_by(|a, b| {
        a.native
            .name
            .to_lowercase()
            .cmp(&b.native.name.to_lowercase())
    });
    Ok(json!({ "services": definitions, "warnings": warnings }))
}

fn op_dump(args: &Value) -> Result<Value, String> {
    let a: NameArg = parse_args(args)?;
    let native = query_service(&a.name).map_err(|e| e.to_string())?;
    let managed =
        servicemanager_registry::read_managed_config(&a.name).map_err(|e| e.to_string())?;
    let def = ServiceDefinition {
        native: native.config,
        managed,
        runtime: native.runtime,
    };
    serde_json::to_value(def).map_err(|e| e.to_string())
}

fn op_install(args: &Value) -> Result<Value, String> {
    let a: InstallArgs = parse_args(args)?;
    if a.application.trim().is_empty() {
        return Err("application path is required".into());
    }
    // Validate and build everything that can fail *before* touching the SCM,
    // so a bad argument never leaves an orphaned service behind.
    let start_type = parse_start_type(&a.start_type)?;
    let binary_path = build_run_service_command(&a.name).map_err(|e| e.to_string())?;
    let display = a.display_name.clone().unwrap_or_else(|| a.name.clone());
    let managed = ManagedApplicationConfig {
        application: Some(a.application.clone()),
        app_parameters: a.app_parameters.clone(),
        app_directory: a.app_directory.clone(),
        io: IoRedirectionConfig {
            stdin: None,
            stdout: a.stdout.clone().map(io_stream),
            stderr: a.stderr.clone().map(io_stream),
            timestamp_log: None,
        },
        ..Default::default()
    };

    install_service(&InstallOptions {
        name: a.name.clone(),
        display_name: display,
        binary_path,
        start_type,
    })
    .map_err(|e| e.to_string())?;

    // If the managed config cannot be written, the SCM service we just
    // created has no usable config — roll it back so we do not leave a
    // broken service behind.
    if let Err(e) = servicemanager_registry::create_managed_config(&a.name, &managed) {
        return Err(match remove_service(&a.name) {
            Ok(()) => format!("install failed, service rolled back: {e}"),
            Err(re) => format!("install failed ({e}); rollback also failed ({re})"),
        });
    }
    Ok(json!({ "installed": a.name }))
}

fn op_remove(args: &Value) -> Result<Value, String> {
    let a: RemoveArgs = parse_args(args)?;
    // Refuse to delete a service that is not NGSM/NSSM-managed unless the
    // caller explicitly opts in — a `remove` request must not be able to
    // wipe an arbitrary native Windows service.
    if !a.force_native {
        let native = query_service(&a.name).map_err(|e| e.to_string())?;
        // Fail closed: if the managed config cannot be read we genuinely
        // cannot tell whether this service is ours, so refuse rather than
        // guess. `force_native` is the explicit override.
        let managed = match servicemanager_registry::read_managed_config(&a.name) {
            Ok(m) => m,
            Err(e) => {
                return Err(format!(
                    "'{}': managed ownership cannot be determined — its managed config is \
                     unreadable ({e}); set \"force_native\": true to remove it anyway",
                    a.name
                ))
            }
        };
        let def = ServiceDefinition {
            native: native.config,
            managed,
            runtime: native.runtime,
        };
        if !def.is_managed() {
            return Err(format!(
                "'{}' is not an NGSM-managed service; set \"force_native\": true to remove a native service",
                a.name
            ));
        }
    }
    // Remove the SCM service first: if that fails the service keeps its
    // managed config and the caller can retry. Only then scrub the registry,
    // and surface a cleanup failure instead of silently dropping it.
    remove_service(&a.name).map_err(|e| e.to_string())?;
    servicemanager_registry::delete_managed_config(&a.name)
        .map_err(|e| format!("service removed, but managed config cleanup failed: {e}"))?;
    Ok(json!({ "removed": a.name }))
}

/// Refuse a lifecycle control on a service that is not NGSM-managed unless
/// the caller passed `force_native`. Fails closed when the managed config
/// cannot be read. Shared by start/stop/restart/pause/continue.
fn require_managed_or_force(name: &str, force_native: bool) -> Result<(), String> {
    if force_native {
        return Ok(());
    }
    let native = query_service(name).map_err(|e| e.to_string())?;
    let managed = match servicemanager_registry::read_managed_config(name) {
        Ok(m) => m,
        Err(e) => {
            return Err(format!(
                "'{name}': managed ownership cannot be determined — its managed config is \
                 unreadable ({e}); set \"force_native\": true to act on it anyway"
            ))
        }
    };
    let def = ServiceDefinition {
        native: native.config,
        managed,
        runtime: native.runtime,
    };
    if def.is_managed() {
        Ok(())
    } else {
        Err(format!(
            "'{name}' is not an NGSM-managed service — set \"force_native\": true to \
             control a native Windows service"
        ))
    }
}

fn op_start(args: &Value) -> Result<Value, String> {
    let a: LifecycleArgs = parse_args(args)?;
    require_managed_or_force(&a.name, a.force_native)?;
    start_service(&a.name).map_err(|e| e.to_string())?;
    Ok(json!({ "started": a.name }))
}

fn op_stop(args: &Value) -> Result<Value, String> {
    let a: LifecycleArgs = parse_args(args)?;
    require_managed_or_force(&a.name, a.force_native)?;
    let state = control_service(&a.name, ServiceControlSignal::Stop).map_err(|e| e.to_string())?;
    Ok(json!({ "stopped": a.name, "state": format!("{:?}", state.state) }))
}

fn op_restart(args: &Value) -> Result<Value, String> {
    use servicemanager_core::ServiceState;
    use std::thread::sleep;
    use std::time::{Duration, Instant};

    let a: LifecycleArgs = parse_args(args)?;
    require_managed_or_force(&a.name, a.force_native)?;
    let snapshot = query_service(&a.name).map_err(|e| e.to_string())?;
    let initial = snapshot.runtime.as_ref().map(|r| r.state);
    let needs_stop = !matches!(initial, Some(ServiceState::Stopped) | None);
    if needs_stop {
        match control_service(&a.name, ServiceControlSignal::Stop) {
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
            let snap = query_service(&a.name).map_err(|e| e.to_string())?;
            if matches!(
                snap.runtime.as_ref().map(|r| r.state),
                Some(ServiceState::Stopped)
            ) {
                break;
            }
            if Instant::now() >= deadline {
                return Err(format!("'{}' did not stop within 30 s", a.name));
            }
            sleep(Duration::from_millis(200));
        }
        sleep(Duration::from_millis(250));
    }
    start_service(&a.name).map_err(|e| e.to_string())?;
    Ok(json!({ "restarted": a.name }))
}

fn op_edit(args: &Value) -> Result<Value, String> {
    let a: EditArgs = parse_args(args)?;
    let want_native = a.display_name.is_some() || a.start_type.is_some();
    let want_managed = a.application.is_some()
        || a.app_parameters.is_some()
        || a.app_directory.is_some()
        || a.stdout.is_some()
        || a.stderr.is_some();

    // Ownership preflight before any mutation. Managed-field edits require
    // an NGSM-managed service; a native-only edit also requires NGSM
    // ownership unless `force_native` — `edit` must not silently alter
    // arbitrary native Windows services.
    let managed_cfg =
        servicemanager_registry::read_managed_config(&a.name).map_err(|e| e.to_string())?;
    if want_managed && managed_cfg.is_none() {
        return Err(format!(
            "'{}' is not an NGSM-managed service; managed fields can only be edited on a \
             managed service",
            a.name
        ));
    }
    if want_native && !a.force_native {
        let owned = managed_cfg.is_some() || {
            let native = query_service(&a.name).map_err(|e| e.to_string())?;
            ServiceDefinition {
                native: native.config,
                managed: None,
                runtime: native.runtime,
            }
            .is_managed()
        };
        if !owned {
            return Err(format!(
                "'{}' is not an NGSM-managed service — set \"force_native\": true to \
                 change a native service's SCM config",
                a.name
            ));
        }
    }
    let managed_base = if want_managed { managed_cfg } else { None };

    // Parse (and so validate) the native start type up front, before any
    // mutation runs.
    let start = match a.start_type.as_deref() {
        Some(s) => Some(parse_start_type(s)?),
        None => None,
    };

    // Managed (NSSM-owned) changes go first: validate every managed value
    // and complete the registry write *before* touching native SCM state,
    // so a rejected value or a failed write cannot leave a half-applied
    // edit with the native display name / start type already changed.
    if let Some(mut managed) = managed_base {
        if let Some(v) = a.application {
            // An empty `Application` would make the service read back as
            // non-managed; reject it instead of corrupting the config.
            if v.trim().is_empty() {
                return Err("application path must not be empty".into());
            }
            managed.application = Some(v);
        }
        if let Some(v) = a.app_parameters {
            managed.app_parameters = Some(v);
        }
        if let Some(v) = a.app_directory {
            managed.app_directory = Some(v);
        }
        if let Some(v) = a.stdout {
            // An empty path means "clear"; the registry reconcile then drops
            // the value rather than writing a blank one.
            managed.io.stdout = if v.is_empty() {
                None
            } else {
                Some(io_stream(v))
            };
        }
        if let Some(v) = a.stderr {
            managed.io.stderr = if v.is_empty() {
                None
            } else {
                Some(io_stream(v))
            };
        }
        servicemanager_registry::write_managed_config(&a.name, &managed)
            .map_err(|e| e.to_string())?;
    }

    if want_native {
        update_native_config(&a.name, a.display_name.as_deref(), start)
            .map_err(|e| e.to_string())?;
    }
    Ok(json!({ "edited": a.name }))
}

fn op_rotate(args: &Value) -> Result<Value, String> {
    let a: NameArg = parse_args(args)?;
    // On-demand rotation only acts on online (pipe-backed) logs; offline
    // logs rotate on restart. Refuse rather than report a false success.
    match servicemanager_registry::read_managed_config(&a.name).map_err(|e| e.to_string())? {
        Some(cfg) if cfg.has_online_rotation() => {}
        Some(_) => {
            return Err(format!(
                "'{}' does not use online log rotation — its logs rotate on restart, \
                 not on demand",
                a.name
            ))
        }
        None => return Err(format!("'{}' is not an NGSM-managed service", a.name)),
    }
    let state = control_service(&a.name, ServiceControlSignal::User(SERVICE_CONTROL_ROTATE))
        .map_err(|e| e.to_string())?;
    Ok(json!({ "rotated": a.name, "state": format!("{:?}", state.state) }))
}

fn op_pause(args: &Value) -> Result<Value, String> {
    let a: LifecycleArgs = parse_args(args)?;
    require_managed_or_force(&a.name, a.force_native)?;
    let state = control_service(&a.name, ServiceControlSignal::Pause).map_err(|e| e.to_string())?;
    Ok(json!({ "paused": a.name, "state": format!("{:?}", state.state) }))
}

fn op_continue(args: &Value) -> Result<Value, String> {
    let a: LifecycleArgs = parse_args(args)?;
    require_managed_or_force(&a.name, a.force_native)?;
    let state =
        control_service(&a.name, ServiceControlSignal::Continue).map_err(|e| e.to_string())?;
    Ok(json!({ "continued": a.name, "state": format!("{:?}", state.state) }))
}

fn op_processes(args: &Value) -> Result<Value, String> {
    let a: NameArg = parse_args(args)?;
    let snap = query_service(&a.name).map_err(|e| e.to_string())?;
    let pid = snap
        .runtime
        .as_ref()
        .and_then(|r| r.pid)
        .ok_or_else(|| format!("service '{}' is not running (no PID reported)", a.name))?;
    let descendants = enumerate_descendants(pid).map_err(|e| e.to_string())?;
    Ok(json!({ "service": a.name, "root_pid": pid, "processes": descendants }))
}
