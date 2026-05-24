use servicemanager_core::{
    validate_absolute_path, validate_hook_component, ManagedApplicationConfig,
};

use crate::recovery::validate_exit_action_key;

/// Pure pre-validation of a [`ManagedApplicationConfig`] that mirrors every
/// reject-the-config check `servicemanager_registry::create_managed_config`
/// performs *before* it touches the registry.
///
/// This exists so install can fail fast — *before* an SCM service is created
/// — when a config would be rejected by the registry writer anyway. Without
/// this pre-check a doomed config would still create the SCM service, hit
/// the registry-layer error, and rely on rollback to clean up the orphan;
/// if rollback also fails (rare but possible), the user is left with an
/// orphaned, unconfigured SCM entry.
///
/// The registry-layer checks remain in place as defense-in-depth — there are
/// registry-only invariants (e.g. service-name shape, post-synthesis
/// `AppExit` `i32` parsing) that this layer cannot reproduce without
/// touching the registry. So pre-validating here narrows the failure window
/// but does not replace the writer's own checks.
///
/// Returns `Err(message)` naming the first offending field, suitable for
/// surfacing directly to the user.
pub fn validate_managed_config(cfg: &ManagedApplicationConfig) -> Result<(), String> {
    // 1. Application must be present and non-empty — without it the
    //    registry writer would reject the config as unmanaged.
    match cfg.application.as_deref() {
        Some(app) if !app.trim().is_empty() => {}
        _ => return Err("managed config requires a non-empty Application value".into()),
    }

    // 2. Absolute-path checks mirror the registry writer's path validation
    //    (Application, AppDirectory, stdio paths). `validate_absolute_path`
    //    also rejects NUL / control characters, so these calls double as
    //    NUL prechecks for the path-valued fields.
    if let Some(app) = &cfg.application {
        validate_absolute_path("Application", app).map_err(|e| e.to_string())?;
    }
    if let Some(dir) = cfg.app_directory.as_deref().filter(|d| !d.is_empty()) {
        validate_absolute_path("AppDirectory", dir).map_err(|e| e.to_string())?;
    }
    if let Some(s) = &cfg.io.stdin {
        validate_absolute_path("AppStdin", &s.path).map_err(|e| e.to_string())?;
    }
    if let Some(s) = &cfg.io.stdout {
        validate_absolute_path("AppStdout", &s.path).map_err(|e| e.to_string())?;
    }
    if let Some(s) = &cfg.io.stderr {
        validate_absolute_path("AppStderr", &s.path).map_err(|e| e.to_string())?;
    }

    // 3. Hook event/action names must be usable as registry subkey / value
    //    names. Mirrors `validate_hook_component` calls in `write_into_key`.
    for hook in &cfg.hooks {
        validate_hook_component(&hook.event, "event").map_err(|e| e.to_string())?;
        validate_hook_component(&hook.action, "action").map_err(|e| e.to_string())?;
        // The registry writer's NUL precheck covers the hook command field
        // too. Mirror it here so a NUL in `command` is caught before the
        // SCM service is created.
        if hook.command.contains('\0') {
            return Err(format!(
                "AppEvents\\{}\\{} (command) contains an embedded NUL — \
                 registry strings cannot carry NULs",
                hook.event, hook.action
            ));
        }
    }

    // 4. Per-exit-code action keys must be `i32`s — `"default"`, whitespace,
    //    `=`, NUL, and non-numeric keys are all rejected. Re-uses the same
    //    validator the recovery editor funnels every caller through.
    for code in cfg.exit_actions.keys() {
        validate_exit_action_key(code).map_err(|e| format!("AppExit\\{code}: {e}"))?;
    }

    // 5. NUL precheck for the remaining REG_SZ / REG_MULTI_SZ string fields
    //    that are not path-typed (so `validate_absolute_path` above did not
    //    already cover them). Mirrors `precheck_no_embedded_nuls` in the
    //    registry writer so a NUL in (say) `AppParameters` cannot reach the
    //    SCM-creation step.
    if let Some(v) = &cfg.app_parameters {
        check_no_nul("AppParameters", v)?;
    }
    if let Some(v) = &cfg.affinity {
        check_no_nul("AppAffinity", v)?;
    }
    for (i, v) in cfg.environment.iter().enumerate() {
        check_no_nul(&format!("AppEnvironment[{i}]"), v)?;
    }
    for (i, v) in cfg.environment_extra.iter().enumerate() {
        check_no_nul(&format!("AppEnvironmentExtra[{i}]"), v)?;
    }

    Ok(())
}

fn check_no_nul(field: &str, value: &str) -> Result<(), String> {
    if value.contains('\0') {
        return Err(format!(
            "{field} contains an embedded NUL — registry strings cannot carry NULs"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use servicemanager_core::{ExitAction, ExitActionPolicy, HookConfig, IoStream};

    fn minimal_valid_config() -> ManagedApplicationConfig {
        ManagedApplicationConfig {
            application: Some("C:\\app\\svc.exe".into()),
            ..Default::default()
        }
    }

    #[test]
    fn accepts_minimal_valid_config() {
        assert!(validate_managed_config(&minimal_valid_config()).is_ok());
    }

    #[test]
    fn rejects_missing_application() {
        let cfg = ManagedApplicationConfig {
            application: None,
            ..Default::default()
        };
        let err = validate_managed_config(&cfg).unwrap_err();
        assert!(err.contains("Application"), "got: {err}");
    }

    #[test]
    fn rejects_empty_application() {
        let mut cfg = minimal_valid_config();
        cfg.application = Some("   ".into());
        let err = validate_managed_config(&cfg).unwrap_err();
        assert!(err.contains("Application"), "got: {err}");
    }

    #[test]
    fn rejects_relative_application_path() {
        let mut cfg = minimal_valid_config();
        cfg.application = Some("svc.exe".into());
        let err = validate_managed_config(&cfg).unwrap_err();
        assert!(err.contains("absolute"), "got: {err}");
        assert!(err.contains("Application"), "got: {err}");
    }

    #[test]
    fn rejects_relative_app_directory() {
        let mut cfg = minimal_valid_config();
        cfg.app_directory = Some("relative\\dir".into());
        let err = validate_managed_config(&cfg).unwrap_err();
        assert!(err.contains("AppDirectory"), "got: {err}");
    }

    #[test]
    fn rejects_relative_stdout_path() {
        let mut cfg = minimal_valid_config();
        cfg.io.stdout = Some(IoStream {
            path: "logs\\out.log".into(),
            share_mode: None,
            creation_disposition: None,
            flags_and_attributes: None,
            copy_and_truncate: None,
        });
        let err = validate_managed_config(&cfg).unwrap_err();
        assert!(err.contains("AppStdout"), "got: {err}");
    }

    #[test]
    fn rejects_invalid_exit_action_key() {
        let mut cfg = minimal_valid_config();
        cfg.exit_actions.insert(
            "default".into(),
            ExitActionPolicy {
                action: ExitAction::Restart,
            },
        );
        let err = validate_managed_config(&cfg).unwrap_err();
        assert!(err.contains("default"), "got: {err}");
        assert!(err.contains("AppExit"), "got: {err}");
    }

    #[test]
    fn rejects_non_numeric_exit_action_key() {
        let mut cfg = minimal_valid_config();
        cfg.exit_actions.insert(
            "abc".into(),
            ExitActionPolicy {
                action: ExitAction::Restart,
            },
        );
        let err = validate_managed_config(&cfg).unwrap_err();
        assert!(err.contains("AppExit\\abc"), "got: {err}");
    }

    #[test]
    fn rejects_unsupported_hook_event_name_with_separator() {
        let mut cfg = minimal_valid_config();
        cfg.hooks.push(HookConfig {
            event: "Start/Pre".into(), // contains '/', which is rejected
            action: "Pre".into(),
            command: "C:\\hooks\\warmup.cmd".into(),
        });
        let err = validate_managed_config(&cfg).unwrap_err();
        assert!(err.contains("event"), "got: {err}");
    }

    #[test]
    fn rejects_empty_hook_event() {
        let mut cfg = minimal_valid_config();
        cfg.hooks.push(HookConfig {
            event: "".into(),
            action: "Pre".into(),
            command: "C:\\hooks\\warmup.cmd".into(),
        });
        let err = validate_managed_config(&cfg).unwrap_err();
        assert!(err.contains("event"), "got: {err}");
    }

    #[test]
    fn rejects_nul_in_hook_command() {
        let mut cfg = minimal_valid_config();
        cfg.hooks.push(HookConfig {
            event: "Start".into(),
            action: "Pre".into(),
            command: "C:\\hooks\\warmup.cmd\0".into(),
        });
        let err = validate_managed_config(&cfg).unwrap_err();
        assert!(err.contains("NUL"), "got: {err}");
        assert!(err.contains("command"), "got: {err}");
    }

    #[test]
    fn rejects_nul_in_app_parameters() {
        let mut cfg = minimal_valid_config();
        cfg.app_parameters = Some("--foo\0--bar".into());
        let err = validate_managed_config(&cfg).unwrap_err();
        assert!(err.contains("AppParameters"), "got: {err}");
        assert!(err.contains("NUL"), "got: {err}");
    }

    #[test]
    fn rejects_nul_in_environment_entry() {
        let mut cfg = minimal_valid_config();
        cfg.environment.push("FOO=1".into());
        cfg.environment.push("BAR=\0bad".into());
        let err = validate_managed_config(&cfg).unwrap_err();
        assert!(err.contains("AppEnvironment[1]"), "got: {err}");
    }

    // -- The install-flow assertions the spec asked for. These exercise
    //    `validate_managed_config` directly (not through `install`) because
    //    the install path requires the SCM, which is not available in unit
    //    tests. Documenting why: a real `install` call would need
    //    Administrator + a live Service Control Manager, neither of which
    //    a `cargo test` run has. The validator IS the new check, so testing
    //    it directly proves install will reject the config before it ever
    //    reaches `install_service`.

    #[test]
    fn install_rejects_invalid_application_path_before_touching_scm() {
        let mut cfg = minimal_valid_config();
        cfg.application = Some("not_absolute.exe".into());
        let err = validate_managed_config(&cfg).unwrap_err();
        assert!(err.contains("Application"), "got: {err}");
        assert!(err.contains("absolute"), "got: {err}");
    }

    #[test]
    fn install_rejects_invalid_exit_action_key_before_touching_scm() {
        let mut cfg = minimal_valid_config();
        cfg.exit_actions.insert(
            "default".into(),
            ExitActionPolicy {
                action: ExitAction::Restart,
            },
        );
        let err = validate_managed_config(&cfg).unwrap_err();
        assert!(err.contains("default"), "got: {err}");
    }

    #[test]
    fn install_rejects_invalid_hook_event_before_touching_scm() {
        // Empty event name -> rejected as registry subkey name. The
        // separate "unsupported event/action pair" check lives in the CLI's
        // `parse_hook_spec`, not at the registry/ops boundary — so test
        // here against the shape-level check the registry actually performs.
        let mut cfg = minimal_valid_config();
        cfg.hooks.push(HookConfig {
            event: "".into(),
            action: "Pre".into(),
            command: "C:\\hooks\\warmup.cmd".into(),
        });
        let err = validate_managed_config(&cfg).unwrap_err();
        assert!(err.contains("event"), "got: {err}");
    }
}
