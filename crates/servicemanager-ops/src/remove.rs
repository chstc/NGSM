use servicemanager_core::ServiceDefinition;
use servicemanager_win32::{query_service, remove_service};

use crate::error::OpResult;

/// Remove an NGSM-managed (or, with `force_native`, any) Windows service.
///
/// # Arguments
///
/// * `name` — service name (SCM key, not display name).
/// * `force_native` — if `true`, bypass the NGSM-ownership check. Use for
///   removing native Windows services that were never managed by NGSM.
/// * `purge_managed_config` — if `true`, also delete the NGSM registry config
///   after the SCM service is removed. Pass `false` only when the config
///   should survive (rare; normally you want `true`).
///
/// The stopped-state check (M-03) runs unconditionally regardless of
/// `force_native`: Windows SCM does not stop a service on `DeleteService` — it
/// marks the service for deletion and finalises it when the service next stops,
/// while our managed-config purge happens immediately. That race leaves the
/// operator with a marked-for-deletion service whose NGSM config is already gone.
///
/// Error message text is taken from the GUI's `data.rs::remove` (the most
/// user-visible path). The CLI adds `--force-native` / `ngsm stop <name>`
/// hints in its own error formatting layer on top.
pub fn remove(name: &str, force_native: bool, purge_managed_config: bool) -> OpResult {
    // Query once; we need both the SCM state (for the stopped check) and the
    // managed config (for the ownership check, when force_native is false).
    let native = query_service(name).map_err(|e| e.to_string())?;

    if !force_native {
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
            native: native.config.clone(),
            managed,
            runtime: native.runtime.clone(),
        };
        if !def.is_managed() {
            return Err(format!(
                "'{name}' is not an NGSM-managed service — refusing to remove it"
            ));
        }
    }

    // M-03: refuse to delete a running service. Windows SCM does not stop
    // the service on DeleteService — it sets a flag and finalizes when the
    // service next stops, while our managed-config purge happens
    // immediately. That leaves the operator with a marked-for-deletion
    // service whose NGSM config is already gone.
    use servicemanager_core::ServiceState;
    let stopped = matches!(
        native.runtime.as_ref().map(|r| r.state),
        Some(ServiceState::Stopped) | None
    );
    if !stopped {
        return Err(format!(
            "'{name}' is not stopped — stop it before removing it"
        ));
    }

    // Remove the SCM service first: if that fails the service keeps its
    // managed config and the caller can retry. Only then scrub the registry,
    // and surface a cleanup failure instead of silently dropping it.
    remove_service(name).map_err(|e| e.to_string())?;
    if purge_managed_config {
        servicemanager_registry::delete_managed_config(name)
            .map_err(|e| format!("service removed, but managed config cleanup failed: {e}"))?;
    }
    Ok(format!("Removed '{name}'."))
}
