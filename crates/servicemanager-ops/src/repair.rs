use servicemanager_core::{ServiceDefinition, ServiceState};
use servicemanager_win32::{query_service, repair_service_runner};

use crate::error::{message_error, OpResult};

/// Repair an NGSM/NSSM-managed service's SCM runner binding.
///
/// This intentionally avoids raw `ImagePath` / `ServiceType` editing. It only
/// rebinds the service to the currently running, ACL-validated `ngsm.exe`
/// runner command and restores the service type to `Win32OwnProcess`.
pub fn repair_runner(name: &str) -> OpResult {
    let native = query_service(name)?;
    let managed = servicemanager_registry::read_managed_config(name).map_err(|e| {
        message_error(format!(
            "'{name}': managed ownership cannot be determined — its managed config \
             is unreadable ({e}); refusing to repair runner binding"
        ))
    })?;
    let has_managed_config = managed.is_some();
    let def = ServiceDefinition {
        native: native.config,
        managed,
        runtime: native.runtime,
    };
    if !def.is_managed() || !has_managed_config {
        return Err(message_error(format!(
            "'{name}' is not an NGSM-managed service with managed configuration — \
             refusing to repair runner binding"
        )));
    }

    let stopped = matches!(
        def.runtime.as_ref().map(|r| r.state),
        Some(ServiceState::Stopped) | None
    );
    if !stopped {
        return Err(message_error(format!(
            "'{name}' is not stopped — stop it before repairing the runner binding"
        )));
    }

    repair_service_runner(name)?;
    Ok(format!("Repaired runner binding for '{name}'."))
}

#[cfg(test)]
mod tests {
    #[test]
    fn repair_message_does_not_suggest_raw_image_path_editing() {
        let msg = "Repaired runner binding for 'Demo'.";
        assert!(!msg.contains("ImagePath"));
        assert!(!msg.contains("ServiceType"));
    }
}
