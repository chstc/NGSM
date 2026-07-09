//! Broker request dispatch — thin wrappers that translate JSON args into
//! [`servicemanager_ops`] calls. Handlers keep structured core errors
//! internally; `dispatch` stringifies them at the broker wire boundary.

use serde::Deserialize;
use serde_json::{json, Value};
use servicemanager_core::{
    Error as CoreError, HookConfig, LogRotationConfig, Result as CoreResult, ServiceDefinition,
};
use servicemanager_ops::{EditSpec, InstallSpec};
use servicemanager_win32::{
    control_service, enumerate_descendants, query_service, start_service, update_native_config,
    InstallStartType, ServiceControlSignal, ServiceDependencies,
};

use crate::protocol::Request;

pub fn dispatch(req: &Request) -> Result<Value, String> {
    dispatch_inner(req).map_err(|e| e.to_string())
}

fn dispatch_inner(req: &Request) -> CoreResult<Value> {
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
        "repair_runner" => op_repair_runner(&req.args)?,
        "rotate" => op_rotate(&req.args)?,
        "processes" => op_processes(&req.args)?,
        "pause" => op_pause(&req.args)?,
        "continue" => op_continue(&req.args)?,
        "recovery_get" => op_recovery_get(&req.args)?,
        "recovery_set" => op_recovery_set(&req.args)?,
        other => return Err(CoreError::other(format!("unknown op '{other}'"))),
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
    #[serde(default)]
    description: Option<String>,
    #[serde(default = "default_start_type")]
    start_type: String,
    #[serde(default)]
    stdout: Option<String>,
    #[serde(default)]
    stderr: Option<String>,
    #[serde(default)]
    hooks: Vec<HookConfig>,
    #[serde(default)]
    rotation: LogRotationConfig,
    #[serde(default)]
    depend_on_services: Vec<String>,
    #[serde(default)]
    depend_on_groups: Vec<String>,
    #[serde(default)]
    account: Option<String>,
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
    description: Option<String>,
    #[serde(default)]
    start_type: Option<String>,
    #[serde(default)]
    stdout: Option<String>,
    #[serde(default)]
    stderr: Option<String>,
    #[serde(default)]
    depend_on_services: Vec<String>,
    #[serde(default)]
    depend_on_groups: Vec<String>,
    #[serde(default)]
    clear_dependencies: bool,
    #[serde(default)]
    account: Option<String>,
    /// Allow changing native SCM fields on a service that is not NGSM-managed.
    #[serde(default)]
    force_native: bool,
}

fn parse_args<T: for<'de> Deserialize<'de>>(args: &Value) -> CoreResult<T> {
    serde_json::from_value::<T>(args.clone())
        .map_err(|e| CoreError::other(format!("invalid args: {e}")))
}

fn reject_broker_password_fields(args: &Value) -> CoreResult<()> {
    if let Some(obj) = args.as_object() {
        if obj.contains_key("password") || obj.contains_key("password_stdin") {
            return Err(CoreError::InvalidConfig(
                "broker requests do not accept service account passwords; use the CLI with --password-stdin".into(),
            ));
        }
    }
    Ok(())
}

fn dependencies_from_args(
    services: Vec<String>,
    groups: Vec<String>,
) -> CoreResult<ServiceDependencies> {
    let dependencies = ServiceDependencies { services, groups };
    dependencies.validate()?;
    Ok(dependencies)
}

/// Result of a best-effort post-op `query_service` call. Distinguishing
/// "known state" from "could not verify state" matters: the broker reports
/// the control op succeeded, and a silently-empty `state` field would let a
/// caller misread "we don't know" as "state is empty/unknown". Encoded into
/// the response JSON by [`apply_post_op_state`].
enum PostOpState {
    /// `query_service` succeeded and returned a runtime state.
    Known(String),
    /// `query_service` succeeded but reported no runtime info
    /// (`runtime == None`) — the SCM has no state to report.
    NoRuntime,
    /// `query_service` itself failed; the resulting state is unknown.
    /// The caller must surface this in the response.
    QueryFailed(String),
}

/// Best-effort post-op query of a service's runtime state. The control op
/// itself has already succeeded by the time this is called; the only thing
/// being reported here is the *follow-up* query's outcome.
fn post_op_state(name: &str) -> PostOpState {
    match query_service(name) {
        Ok(snap) => match snap.runtime {
            Some(r) => PostOpState::Known(format!("{:?}", r.state)),
            None => PostOpState::NoRuntime,
        },
        Err(e) => PostOpState::QueryFailed(e.to_string()),
    }
}

/// Merge a [`PostOpState`] into a successful-op response body, preserving the
/// `state` field's existing wire shape (a string, or `null` when the post-op
/// query failed) and adding a `warning` field when the state could not be
/// verified. Without the warning, a caller cannot tell "post-op state is
/// unknown" apart from "state is currently empty/unknown" — the latter being
/// a legitimate value, the former being a broker-side failure that must be
/// surfaced.
fn apply_post_op_state(body: &mut Value, st: PostOpState) {
    let obj = body
        .as_object_mut()
        .expect("post-op response bodies are always JSON objects");
    match st {
        PostOpState::Known(s) => {
            obj.insert("state".into(), Value::String(s));
        }
        PostOpState::NoRuntime => {
            // `query_service` succeeded with no runtime info — historically
            // serialized as an empty string. Preserve that shape so callers
            // that already special-case `""` keep working.
            obj.insert("state".into(), Value::String(String::new()));
        }
        PostOpState::QueryFailed(err) => {
            obj.insert("state".into(), Value::Null);
            obj.insert(
                "warning".into(),
                Value::String(format!("post-op state query failed: {err}")),
            );
        }
    }
}

fn parse_start_type(s: &str) -> CoreResult<InstallStartType> {
    match s.to_ascii_lowercase().as_str() {
        "manual" => Ok(InstallStartType::Manual),
        "automatic" => Ok(InstallStartType::Automatic),
        "disabled" => Ok(InstallStartType::Disabled),
        other => Err(CoreError::other(format!("unknown start_type '{other}'"))),
    }
}

fn op_list(args: &Value) -> CoreResult<Value> {
    let args: ListArgs = parse_args(args)?;
    let (all_defs, warnings) = servicemanager_ops::list_services()?;
    let definitions: Vec<servicemanager_core::ServiceDefinition> = all_defs
        .into_iter()
        .filter(|d| match args.filter {
            ListFilterArg::Managed => d.is_managed(),
            ListFilterArg::All => true,
        })
        .collect();
    Ok(json!({ "services": definitions, "warnings": warnings }))
}

fn op_dump(args: &Value) -> CoreResult<Value> {
    let a: NameArg = parse_args(args)?;
    let native = query_service(&a.name)?;
    let managed = servicemanager_registry::read_managed_config(&a.name)?;
    let def = ServiceDefinition {
        native: native.config,
        managed,
        runtime: native.runtime,
    };
    serde_json::to_value(def).map_err(|e| CoreError::other(e.to_string()))
}

fn op_install(args: &Value) -> CoreResult<Value> {
    reject_broker_password_fields(args)?;
    let a: InstallArgs = parse_args(args)?;
    let start_type = parse_start_type(&a.start_type)?;
    let dependencies = dependencies_from_args(a.depend_on_services, a.depend_on_groups)?;
    let spec = InstallSpec {
        name: a.name.clone(),
        display_name: a.display_name,
        description: a.description,
        application: a.application,
        app_parameters: a.app_parameters,
        app_directory: a.app_directory,
        stdout: a.stdout,
        stderr: a.stderr,
        rotation: a.rotation,
        hooks: a.hooks,
        start_type,
        dependencies,
        account: a.account,
        password: None,
    };
    servicemanager_ops::install(spec)?;
    Ok(json!({ "installed": a.name }))
}

fn op_remove(args: &Value) -> CoreResult<Value> {
    let a: RemoveArgs = parse_args(args)?;
    // Delegate to ops — enforces NGSM-managed check and the M-03 stopped-state
    // check (the old broker remove lacked the stopped check; this is now added).
    servicemanager_ops::remove(&a.name, a.force_native, true)?;
    Ok(json!({ "removed": a.name }))
}

fn op_start(args: &Value) -> CoreResult<Value> {
    let a: LifecycleArgs = parse_args(args)?;
    if a.force_native {
        // Bypass NGSM-managed check — call win32 directly.
        start_service(&a.name)?;
    } else {
        servicemanager_ops::start(&a.name)?;
    }
    Ok(json!({ "started": a.name }))
}

fn op_stop(args: &Value) -> CoreResult<Value> {
    let a: LifecycleArgs = parse_args(args)?;
    if a.force_native {
        // Bypass NGSM-managed check — call win32 directly and return state.
        let state = control_service(&a.name, ServiceControlSignal::Stop)?;
        return Ok(json!({ "stopped": a.name, "state": format!("{:?}", state.state) }));
    }
    // ops::stop enforces the NGSM-managed check internally.
    servicemanager_ops::stop(&a.name)?;
    // Query post-op state to maintain the wire-level { "state": ... } field
    // that broker clients depend on. A query failure here is surfaced as
    // `state: null` + a `warning`, so the caller can tell "I don't know the
    // post-op state" apart from a legitimate empty/unknown state value.
    let mut body = json!({ "stopped": a.name });
    apply_post_op_state(&mut body, post_op_state(&a.name));
    Ok(body)
}

fn op_restart(args: &Value) -> CoreResult<Value> {
    let a: LifecycleArgs = parse_args(args)?;
    if a.force_native {
        // Bypass NGSM-managed check — implement restart loop locally.
        op_restart_force_native(&a.name)?;
    } else {
        servicemanager_ops::restart(&a.name, 30_000)?;
    }
    Ok(json!({ "restarted": a.name }))
}

/// Restart implementation for `force_native: true`: bypasses the NGSM-managed
/// check and uses a fixed 30-second stop-wait deadline.
fn op_restart_force_native(name: &str) -> CoreResult<()> {
    use servicemanager_core::ServiceState;
    use std::thread::sleep;
    use std::time::{Duration, Instant};

    let snapshot = query_service(name)?;
    let initial = snapshot.runtime.as_ref().map(|r| r.state);
    let needs_stop = !matches!(initial, Some(ServiceState::Stopped) | None);
    if needs_stop {
        match control_service(name, ServiceControlSignal::Stop) {
            Ok(_) => {}
            Err(e) => {
                let msg = e.to_string();
                if !(msg.contains("0x80070426") || msg.contains("has not been started")) {
                    return Err(e);
                }
            }
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let snap = query_service(name)?;
            if matches!(
                snap.runtime.as_ref().map(|r| r.state),
                Some(ServiceState::Stopped)
            ) {
                break;
            }
            if Instant::now() >= deadline {
                return Err(CoreError::other(format!(
                    "'{name}' did not stop within 30 s"
                )));
            }
            sleep(Duration::from_millis(200));
        }
        sleep(Duration::from_millis(250));
    }
    start_service(name)
}

fn op_edit(args: &Value) -> CoreResult<Value> {
    reject_broker_password_fields(args)?;
    let a: EditArgs = parse_args(args)?;
    if a.clear_dependencies && (!a.depend_on_services.is_empty() || !a.depend_on_groups.is_empty())
    {
        return Err(CoreError::InvalidConfig(
            "clear_dependencies cannot be combined with depend_on_services or depend_on_groups"
                .into(),
        ));
    }
    let dependencies = if a.clear_dependencies {
        Some(ServiceDependencies::default())
    } else if a.depend_on_services.is_empty() && a.depend_on_groups.is_empty() {
        None
    } else {
        Some(dependencies_from_args(
            a.depend_on_services,
            a.depend_on_groups,
        )?)
    };
    let want_native = a.display_name.is_some()
        || a.description.is_some()
        || a.start_type.is_some()
        || dependencies.is_some()
        || a.account.is_some();

    // Refuse to mix force_native (which targets only native SCM metadata)
    // with managed-field flags. A partial success that updates only the native
    // fields would silently swallow the managed-field changes.
    if a.force_native {
        let any_managed = a.application.is_some()
            || a.app_parameters.is_some()
            || a.app_directory.is_some()
            || a.stdout.is_some()
            || a.stderr.is_some();
        if any_managed {
            return Err(CoreError::other(
                "--force-native cannot be combined with managed-field flags \
                 (application, app_parameters, app_directory, stdout, stderr). \
                 Run two separate edit calls — one with force_native for \
                 native-only fields, and one without it for managed fields."
                    .to_string(),
            ));
        }
    }

    // When force_native is set for a native-only SCM edit, ops::edit cannot
    // be used (it enforces NGSM-managed ownership). Apply the native change
    // directly.
    if a.force_native && want_native {
        let start = match a.start_type.as_deref() {
            Some(s) => Some(parse_start_type(s)?),
            None => None,
        };
        update_native_config(
            &a.name,
            a.display_name.as_deref(),
            a.description.as_deref(),
            start,
            dependencies.as_ref(),
            a.account.as_deref(),
            None,
        )?;
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
        description: a.description,
        application: a.application,
        app_parameters: a.app_parameters,
        app_directory: a.app_directory,
        stdout: a.stdout,
        stderr: a.stderr,
        start_type: start,
        dependencies,
        account: a.account,
        password: None,
    };
    servicemanager_ops::edit(spec)?;
    Ok(json!({ "edited": a.name }))
}

fn op_repair_runner(args: &Value) -> CoreResult<Value> {
    let a: NameArg = parse_args(args)?;
    servicemanager_ops::repair_runner(&a.name)?;
    Ok(json!({ "repaired": a.name, "runner": true }))
}

fn op_rotate(args: &Value) -> CoreResult<Value> {
    let a: NameArg = parse_args(args)?;
    // ops::rotate validates online-rotation preflight and issues the control
    // signal, but does not return post-op state. Query after the fact to
    // maintain the wire-level { "state": ... } field that clients depend on.
    // A query failure here is surfaced rather than hidden — see
    // `apply_post_op_state` for the wire shape.
    servicemanager_ops::rotate(&a.name)?;
    let mut body = json!({ "rotated": a.name });
    apply_post_op_state(&mut body, post_op_state(&a.name));
    Ok(body)
}

fn op_pause(args: &Value) -> CoreResult<Value> {
    let a: LifecycleArgs = parse_args(args)?;
    let state = if a.force_native {
        control_service(&a.name, ServiceControlSignal::Pause)?
    } else {
        servicemanager_ops::pause(&a.name)?;
        // Surface a post-op query failure as `state: null` + a `warning`
        // rather than hiding it behind an empty state string.
        let mut body = json!({ "paused": a.name });
        apply_post_op_state(&mut body, post_op_state(&a.name));
        return Ok(body);
    };
    Ok(json!({ "paused": a.name, "state": format!("{:?}", state.state) }))
}

fn op_continue(args: &Value) -> CoreResult<Value> {
    let a: LifecycleArgs = parse_args(args)?;
    let state = if a.force_native {
        control_service(&a.name, ServiceControlSignal::Continue)?
    } else {
        servicemanager_ops::continue_service(&a.name)?;
        // Surface a post-op query failure as `state: null` + a `warning`
        // rather than hiding it behind an empty state string.
        let mut body = json!({ "continued": a.name });
        apply_post_op_state(&mut body, post_op_state(&a.name));
        return Ok(body);
    };
    Ok(json!({ "continued": a.name, "state": format!("{:?}", state.state) }))
}

fn op_processes(args: &Value) -> CoreResult<Value> {
    let a: NameArg = parse_args(args)?;
    let snap = query_service(&a.name)?;
    let pid = snap.runtime.as_ref().and_then(|r| r.pid).ok_or_else(|| {
        CoreError::other(format!(
            "service '{}' is not running (no PID reported)",
            a.name
        ))
    })?;
    let descendants = enumerate_descendants(pid)?;
    Ok(json!({ "service": a.name, "root_pid": pid, "processes": descendants }))
}

#[derive(Deserialize)]
struct OpRecoveryGetArgs {
    name: String,
}

fn op_recovery_get(args: &Value) -> CoreResult<Value> {
    let OpRecoveryGetArgs { name } = parse_args(args)?;
    let spec = servicemanager_ops::read_recovery(&name)?;
    // Use the same JSON shape the CLI uses.
    let exit_map: std::collections::BTreeMap<_, _> = spec
        .exit_actions
        .iter()
        .map(|(code, action)| (code.clone(), action))
        .collect();
    Ok(json!({
        "service": spec.name,
        "restart_delay_ms": spec.restart_delay_ms,
        "throttle_delay_ms": spec.throttle_delay_ms,
        "default_action": spec.default_action,
        "exit_actions": exit_map,
    }))
}

#[derive(Deserialize)]
struct OpRecoverySetArgs {
    name: String,
    #[serde(default)]
    restart_delay_ms: Option<u32>,
    #[serde(default)]
    throttle_delay_ms: Option<u32>,
    default_action: servicemanager_core::ExitAction,
    #[serde(default)]
    exit_actions: Option<std::collections::BTreeMap<String, servicemanager_core::ExitAction>>,
}

fn op_recovery_set(args: &Value) -> CoreResult<Value> {
    let OpRecoverySetArgs {
        name,
        restart_delay_ms,
        throttle_delay_ms,
        default_action,
        exit_actions,
    } = parse_args(args)?;
    let exit_actions = exit_actions.unwrap_or_default();
    // Reject malformed per-exit-code keys up front. `save_recovery` runs
    // the same check, but the broker validates here too so an out-of-spec
    // key produces a clear "exit-action code ..." error before any
    // registry read happens.
    for code in exit_actions.keys() {
        servicemanager_ops::validate_exit_action_key(code)
            .map_err(|e| CoreError::other(format!("exit-action code '{code}': {e}")))?;
    }
    let spec = servicemanager_ops::RecoverySpec {
        name: name.clone(),
        restart_delay_ms,
        throttle_delay_ms,
        default_action,
        exit_actions,
    };
    let msg = servicemanager_ops::save_recovery(spec)?;
    Ok(json!({ "saved": name, "message": msg }))
}

#[cfg(test)]
mod tests {
    //! Tests for the M-03 response-shaping helper. The full handler paths
    //! call `servicemanager_win32::query_service`, which requires a real SCM
    //! connection (and on many setups, admin) — so the tests here exercise
    //! `apply_post_op_state` directly. That helper is what guarantees a
    //! post-op `query_service` failure is surfaced rather than hidden, no
    //! matter which control op produced the response body.
    use super::*;

    #[test]
    fn op_stop_propagates_query_failure_as_warning() {
        // Simulate the shape `op_stop` builds before invoking the helper.
        let mut body = json!({ "stopped": "Spooler" });
        apply_post_op_state(
            &mut body,
            PostOpState::QueryFailed("SCM unreachable".into()),
        );
        // `state` must exist and be JSON null — distinguishable from a
        // legitimate empty/unknown state string.
        assert_eq!(body["state"], Value::Null);
        // A `warning` field carries the underlying error so the caller can
        // tell post-op verification failed rather than silently succeeding.
        let warning = body["warning"]
            .as_str()
            .expect("warning must be a JSON string");
        assert!(
            warning.contains("post-op state query failed"),
            "warning text should name the failure mode, got {warning:?}"
        );
        assert!(
            warning.contains("SCM unreachable"),
            "warning text should include the underlying error, got {warning:?}"
        );
        // The pre-existing op-success marker must be preserved.
        assert_eq!(body["stopped"], "Spooler");
    }

    #[test]
    fn op_pause_propagates_query_failure_as_warning() {
        // `op_pause` (and `op_continue`, `op_rotate`) all funnel through the
        // same helper; verifying one additional op covers the shape since
        // the only thing that differs is the success-marker key.
        let mut body = json!({ "paused": "Spooler" });
        apply_post_op_state(&mut body, PostOpState::QueryFailed("denied".into()));
        assert_eq!(body["state"], Value::Null);
        assert!(body["warning"]
            .as_str()
            .unwrap()
            .contains("post-op state query failed"));
        assert_eq!(body["paused"], "Spooler");
    }

    #[test]
    fn apply_post_op_state_inserts_known_state_without_warning() {
        // The successful path must not bolt on a warning field — that would
        // train callers to ignore warnings.
        let mut body = json!({ "stopped": "Spooler" });
        apply_post_op_state(&mut body, PostOpState::Known("Stopped".into()));
        assert_eq!(body["state"], "Stopped");
        assert!(
            body.get("warning").is_none(),
            "successful queries must not emit a warning"
        );
    }

    #[test]
    fn apply_post_op_state_preserves_empty_string_for_no_runtime() {
        // `query_service` succeeding with `runtime == None` is a real
        // observation, not a broker failure. Preserve the historical empty
        // string so callers that already special-case `""` keep working.
        let mut body = json!({ "stopped": "Spooler" });
        apply_post_op_state(&mut body, PostOpState::NoRuntime);
        assert_eq!(body["state"], "");
        assert!(body.get("warning").is_none());
    }

    #[test]
    fn install_args_defaults_hooks_and_rotation_for_backcompat() {
        let args: InstallArgs = parse_args(&json!({
            "name": "TestSvc",
            "application": "C:\\app\\svc.exe"
        }))
        .expect("minimal install args should still parse");

        assert!(args.hooks.is_empty());
        assert!(args.rotation.enabled.is_none());
        assert!(args.rotation.online.is_none());
        assert!(args.rotation.seconds.is_none());
        assert!(args.rotation.bytes.is_none());
        assert!(args.rotation.delay_ms.is_none());
        assert!(args.depend_on_services.is_empty());
        assert!(args.depend_on_groups.is_empty());
        assert!(args.account.is_none());
    }

    #[test]
    fn install_args_parse_hooks_and_rotation() {
        let args: InstallArgs = parse_args(&json!({
            "name": "TestSvc",
            "application": "C:\\app\\svc.exe",
            "stdout": "C:\\logs\\out.log",
            "hooks": [{
                "event": "Start",
                "action": "Pre",
                "command": "C:\\hooks\\warmup.cmd"
            }],
            "rotation": {
                "enabled": true,
                "online": 2,
                "seconds": 30,
                "bytes": 1024,
                "delay_ms": 250
            }
        }))
        .expect("install args with hooks/rotation should parse");

        assert_eq!(args.hooks.len(), 1);
        assert_eq!(args.hooks[0].event, "Start");
        assert_eq!(args.hooks[0].action, "Pre");
        assert_eq!(args.hooks[0].command, "C:\\hooks\\warmup.cmd");
        assert_eq!(args.rotation.enabled, Some(true));
        assert_eq!(args.rotation.online, Some(2));
        assert_eq!(args.rotation.seconds, Some(30));
        assert_eq!(args.rotation.bytes, Some(1024));
        assert_eq!(args.rotation.delay_ms, Some(250));
    }

    #[test]
    fn install_args_parse_dependencies_and_account_but_reject_password() {
        let args: InstallArgs = parse_args(&json!({
            "name": "TestSvc",
            "application": "C:\\app\\svc.exe",
            "depend_on_services": ["Tcpip"],
            "depend_on_groups": ["NetworkProvider"],
            "account": ".\\svc_user"
        }))
        .expect("install args with dependencies/account should parse");

        assert_eq!(args.depend_on_services, vec!["Tcpip"]);
        assert_eq!(args.depend_on_groups, vec!["NetworkProvider"]);
        assert_eq!(args.account.as_deref(), Some(".\\svc_user"));

        let err = reject_broker_password_fields(&json!({
            "name": "TestSvc",
            "application": "C:\\app\\svc.exe",
            "password": "argv-password-value"
        }))
        .expect_err("broker must reject password payloads")
        .to_string();
        assert!(err.contains("password"), "got: {err}");
        assert!(
            !err.contains("argv-password-value"),
            "must not echo password: {err}"
        );
    }

    #[test]
    fn edit_dependency_clear_conflict_is_rejected_by_helper_logic() {
        let err = op_edit(&json!({
            "name": "TestSvc",
            "clear_dependencies": true,
            "depend_on_services": ["Tcpip"]
        }))
        .expect_err("clear and explicit dependencies must conflict")
        .to_string();

        assert!(err.contains("clear_dependencies"), "got: {err}");
    }
}
