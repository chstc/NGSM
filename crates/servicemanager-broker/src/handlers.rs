//! Broker request dispatch — thin wrappers that translate JSON args into
//! [`servicemanager_ops`] calls. Each handler returns a `serde_json::Value`
//! (or an error message) so the pipe-layer code stays generic.

use serde::Deserialize;
use serde_json::{json, Value};
use servicemanager_core::ServiceDefinition;
use servicemanager_ops::{EditSpec, InstallSpec};
use servicemanager_win32::{
    control_service, enumerate_descendants, query_service, start_service, update_native_config,
    InstallStartType, ServiceControlSignal,
};

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
    let (all_defs, warnings) = servicemanager_ops::list_services().map_err(|e| e.to_string())?;
    let definitions: Vec<servicemanager_core::ServiceDefinition> = all_defs
        .into_iter()
        .filter(|d| match args.filter {
            ListFilterArg::Managed => d.is_managed(),
            ListFilterArg::All => true,
        })
        .collect();
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
    let start_type = parse_start_type(&a.start_type)?;
    let spec = InstallSpec {
        name: a.name.clone(),
        display_name: a.display_name,
        application: a.application,
        app_parameters: a.app_parameters,
        app_directory: a.app_directory,
        stdout: a.stdout,
        stderr: a.stderr,
        start_type,
    };
    servicemanager_ops::install(spec)?;
    Ok(json!({ "installed": a.name }))
}

fn op_remove(args: &Value) -> Result<Value, String> {
    let a: RemoveArgs = parse_args(args)?;
    // Delegate to ops — enforces NGSM-managed check and the M-03 stopped-state
    // check (the old broker remove lacked the stopped check; this is now added).
    servicemanager_ops::remove(&a.name, a.force_native, true)?;
    Ok(json!({ "removed": a.name }))
}

fn op_start(args: &Value) -> Result<Value, String> {
    let a: LifecycleArgs = parse_args(args)?;
    if a.force_native {
        // Bypass NGSM-managed check — call win32 directly.
        start_service(&a.name).map_err(|e| e.to_string())?;
    } else {
        servicemanager_ops::start(&a.name)?;
    }
    Ok(json!({ "started": a.name }))
}

fn op_stop(args: &Value) -> Result<Value, String> {
    let a: LifecycleArgs = parse_args(args)?;
    if a.force_native {
        // Bypass NGSM-managed check — call win32 directly and return state.
        let state =
            control_service(&a.name, ServiceControlSignal::Stop).map_err(|e| e.to_string())?;
        return Ok(json!({ "stopped": a.name, "state": format!("{:?}", state.state) }));
    }
    // ops::stop enforces the NGSM-managed check internally.
    servicemanager_ops::stop(&a.name)?;
    // Query post-op state to maintain the wire-level { "state": ... } field
    // that broker clients depend on.
    let state_str = query_service(&a.name)
        .ok()
        .and_then(|s| s.runtime)
        .map(|r| format!("{:?}", r.state))
        .unwrap_or_default();
    Ok(json!({ "stopped": a.name, "state": state_str }))
}

fn op_restart(args: &Value) -> Result<Value, String> {
    let a: LifecycleArgs = parse_args(args)?;
    if a.force_native {
        // Bypass NGSM-managed check — implement restart loop locally.
        op_restart_force_native(&a.name)?;
    } else {
        servicemanager_ops::restart(&a.name)?;
    }
    Ok(json!({ "restarted": a.name }))
}

/// Restart implementation for `force_native: true`: bypasses the NGSM-managed
/// check and uses a fixed 30-second stop-wait deadline.
fn op_restart_force_native(name: &str) -> Result<(), String> {
    use servicemanager_core::ServiceState;
    use std::thread::sleep;
    use std::time::{Duration, Instant};

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
            let snap = query_service(name).map_err(|e| e.to_string())?;
            if matches!(
                snap.runtime.as_ref().map(|r| r.state),
                Some(ServiceState::Stopped)
            ) {
                break;
            }
            if Instant::now() >= deadline {
                return Err(format!("'{name}' did not stop within 30 s"));
            }
            sleep(Duration::from_millis(200));
        }
        sleep(Duration::from_millis(250));
    }
    start_service(name).map_err(|e| e.to_string())
}

fn op_edit(args: &Value) -> Result<Value, String> {
    let a: EditArgs = parse_args(args)?;
    let want_native = a.display_name.is_some() || a.start_type.is_some();

    // When force_native is set for a native-only SCM edit, ops::edit cannot
    // be used (it enforces NGSM-managed ownership). Apply the native change
    // directly; reject any managed-field combination in the same call.
    if a.force_native && want_native {
        let want_managed = a.application.is_some()
            || a.app_parameters.is_some()
            || a.app_directory.is_some()
            || a.stdout.is_some()
            || a.stderr.is_some();
        if want_managed {
            let managed_cfg =
                servicemanager_registry::read_managed_config(&a.name).map_err(|e| e.to_string())?;
            if managed_cfg.is_none() {
                return Err(format!(
                    "'{}' is not an NGSM-managed service; managed fields can only be edited on a \
                     managed service",
                    a.name
                ));
            }
        }
        let start = match a.start_type.as_deref() {
            Some(s) => Some(parse_start_type(s)?),
            None => None,
        };
        update_native_config(&a.name, a.display_name.as_deref(), start)
            .map_err(|e| e.to_string())?;
        return Ok(json!({ "edited": a.name }));
    }

    // Delegate to ops — enforces NGSM-managed ownership internally.
    let start = match a.start_type.as_deref() {
        Some(s) => Some(parse_start_type(s)?),
        None => None,
    };
    let spec = EditSpec {
        name: a.name.clone(),
        display_name: a.display_name,
        application: a.application,
        app_parameters: a.app_parameters,
        app_directory: a.app_directory,
        stdout: a.stdout,
        stderr: a.stderr,
        start_type: start,
    };
    servicemanager_ops::edit(spec)?;
    Ok(json!({ "edited": a.name }))
}

fn op_rotate(args: &Value) -> Result<Value, String> {
    let a: NameArg = parse_args(args)?;
    // ops::rotate validates online-rotation preflight and issues the control
    // signal, but does not return post-op state. Query after the fact to
    // maintain the wire-level { "state": ... } field that clients depend on.
    servicemanager_ops::rotate(&a.name)?;
    let state_str = query_service(&a.name)
        .ok()
        .and_then(|s| s.runtime)
        .map(|r| format!("{:?}", r.state))
        .unwrap_or_default();
    Ok(json!({ "rotated": a.name, "state": state_str }))
}

fn op_pause(args: &Value) -> Result<Value, String> {
    let a: LifecycleArgs = parse_args(args)?;
    let state = if a.force_native {
        control_service(&a.name, ServiceControlSignal::Pause).map_err(|e| e.to_string())?
    } else {
        servicemanager_ops::pause(&a.name)?;
        return Ok(json!({
            "paused": a.name,
            "state": query_service(&a.name)
                .ok()
                .and_then(|s| s.runtime)
                .map(|r| format!("{:?}", r.state))
                .unwrap_or_default()
        }));
    };
    Ok(json!({ "paused": a.name, "state": format!("{:?}", state.state) }))
}

fn op_continue(args: &Value) -> Result<Value, String> {
    let a: LifecycleArgs = parse_args(args)?;
    let state = if a.force_native {
        control_service(&a.name, ServiceControlSignal::Continue).map_err(|e| e.to_string())?
    } else {
        servicemanager_ops::continue_service(&a.name)?;
        return Ok(json!({
            "continued": a.name,
            "state": query_service(&a.name)
                .ok()
                .and_then(|s| s.runtime)
                .map(|r| format!("{:?}", r.state))
                .unwrap_or_default()
        }));
    };
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
