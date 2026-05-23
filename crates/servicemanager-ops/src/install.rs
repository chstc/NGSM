use servicemanager_core::{IoRedirectionConfig, ManagedApplicationConfig};
use servicemanager_win32::{
    build_run_service_command, install_service, remove_service, InstallOptions,
};

use crate::error::OpResult;
use crate::helpers::io_stream;
use crate::specs::InstallSpec;

/// Install a new NGSM-managed service.
///
/// The managed config is built and validated *before* creating the SCM
/// service entry. If writing the managed config fails after the SCM service
/// has been created, the SCM service is rolled back so no orphaned,
/// unconfigured service is left behind.
pub fn install(spec: InstallSpec) -> OpResult {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_rejects_empty_application_path() {
        let spec = InstallSpec {
            name: "TestSvc".into(),
            application: "".into(),
            ..Default::default()
        };
        let result = install(spec);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Application path is required.");
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
        assert_eq!(result.unwrap_err(), "Application path is required.");
    }
}
