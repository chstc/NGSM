use servicemanager_core::{IoRedirectionConfig, ManagedApplicationConfig};
use servicemanager_win32::{
    build_run_service_command, install_service, remove_service, InstallOptions,
};

use crate::error::{message_error, OpResult};
use crate::helpers::io_stream;
use crate::specs::InstallSpec;
use crate::validate::{validate_install_config, validate_managed_config};

/// Install a new NGSM-managed service.
///
/// The managed config is built and *fully validated* before creating the SCM
/// service entry. Validating up front matters: an SCM service is only created
/// once the config has passed every check the registry writer would apply, so
/// a doomed config cannot leave an orphaned SCM entry that has to be cleaned
/// up by rollback (and that would survive a rollback failure).
///
/// If writing the managed config still fails after the SCM service has been
/// created (registry-level errors the pre-check cannot reproduce — e.g. a
/// permission failure on the `Parameters` key), the SCM service is rolled
/// back so no orphaned, unconfigured service is left behind.
pub fn install(spec: InstallSpec) -> OpResult {
    if spec.application.trim().is_empty() {
        return Err(message_error("Application path is required."));
    }

    // Build the managed config before creating the SCM service.
    let managed = managed_config_from_spec(&spec);

    // Pre-validate every config check the registry writer would apply,
    // *before* the SCM service is created. Without this an invalid config
    // would create the SCM service, fail at registry-write time, and rely on
    // rollback — which itself can fail, leaving an orphan SCM entry.
    validate_managed_config(&managed)?;

    // Install-only semantic checks (hooks understood by the supervisor,
    // rotation tied to real stdout/stderr streams) also run before SCM
    // creation so invalid extended installs have no side effects.
    validate_install_config(&managed)?;

    let binary_path = build_run_service_command(&spec.name)?;

    install_service(&InstallOptions {
        name: spec.name.clone(),
        display_name: spec
            .display_name
            .clone()
            .unwrap_or_else(|| spec.name.clone()),
        description: spec.description.clone(),
        binary_path,
        start_type: spec.start_type,
        dependencies: spec.dependencies.clone(),
        account: spec.account.clone(),
        password: spec.password.clone(),
    })?;

    // Roll the SCM service back if the managed config cannot be written.
    if let Err(e) = servicemanager_registry::create_managed_config(&spec.name, &managed) {
        return Err(message_error(match remove_service(&spec.name) {
            Ok(()) => format!("install failed, service rolled back: {e}"),
            Err(re) => format!("install failed ({e}); rollback also failed ({re})"),
        }));
    }
    Ok(format!("Installed '{}'.", spec.name))
}

fn managed_config_from_spec(spec: &InstallSpec) -> ManagedApplicationConfig {
    ManagedApplicationConfig {
        application: Some(spec.application.clone()),
        app_parameters: spec.app_parameters.clone(),
        app_directory: spec.app_directory.clone(),
        io: IoRedirectionConfig {
            stdin: None,
            stdout: spec.stdout.clone().map(io_stream),
            stderr: spec.stderr.clone().map(io_stream),
            timestamp_log: None,
        },
        rotation: spec.rotation.clone(),
        hooks: spec.hooks.clone(),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use servicemanager_core::{HookConfig, LogRotationConfig};

    #[test]
    fn install_rejects_empty_application_path() {
        let spec = InstallSpec {
            name: "TestSvc".into(),
            application: "".into(),
            ..Default::default()
        };
        let result = install(spec);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Application path is required."
        );
    }

    #[test]
    fn install_rejects_whitespace_only_application_path() {
        let spec = InstallSpec {
            name: "TestSvc".into(),
            application: "   ".into(),
            ..Default::default()
        };
        let result = install(spec);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Application path is required."
        );
    }

    #[test]
    fn install_rejects_rotation_without_log_stream_before_scm() {
        let spec = InstallSpec {
            name: "TestSvc".into(),
            application: "C:\\app\\svc.exe".into(),
            rotation: LogRotationConfig {
                enabled: Some(true),
                online: Some(1),
                seconds: Some(60),
                bytes: None,
                delay_ms: None,
            },
            ..Default::default()
        };

        let err = install(spec).unwrap_err().to_string();
        assert!(err.contains("--stdout"), "got: {err}");
        assert!(err.contains("--stderr"), "got: {err}");
        assert!(err.contains("rotation"), "got: {err}");
    }

    #[test]
    fn managed_config_from_spec_carries_hooks_and_rotation() {
        let spec = InstallSpec {
            name: "TestSvc".into(),
            application: "C:\\app\\svc.exe".into(),
            stdout: Some("C:\\logs\\out.log".into()),
            stderr: Some("C:\\logs\\err.log".into()),
            rotation: LogRotationConfig {
                enabled: Some(true),
                online: Some(2),
                seconds: Some(30),
                bytes: Some(1_024),
                delay_ms: Some(250),
            },
            hooks: vec![HookConfig {
                event: "Start".into(),
                action: "Pre".into(),
                command: "C:\\hooks\\warmup.cmd".into(),
            }],
            ..Default::default()
        };

        let managed = managed_config_from_spec(&spec);
        assert_eq!(managed.rotation.enabled, Some(true));
        assert_eq!(managed.rotation.online, Some(2));
        assert_eq!(managed.rotation.seconds, Some(30));
        assert_eq!(managed.rotation.bytes, Some(1_024));
        assert_eq!(managed.rotation.delay_ms, Some(250));
        assert_eq!(
            managed.io.stdout.as_ref().expect("stdout stream").path,
            "C:\\logs\\out.log"
        );
        assert_eq!(
            managed.io.stderr.as_ref().expect("stderr stream").path,
            "C:\\logs\\err.log"
        );
        assert_eq!(managed.hooks.len(), 1);
        assert_eq!(managed.hooks[0].event, "Start");
        assert_eq!(managed.hooks[0].action, "Pre");
        assert_eq!(managed.hooks[0].command, "C:\\hooks\\warmup.cmd");
    }
}
