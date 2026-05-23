use servicemanager_core::ExitActionPolicy;

use crate::error::OpResult;
use crate::specs::RecoverySpec;

/// Save a restart-policy and exit-action configuration for a managed service.
///
/// Re-reads the managed config from the registry (never trusting a
/// possibly-stale caller snapshot, exactly as `edit` does), applies the
/// restart-policy and exit-action fields, and writes it all back.
pub fn save_recovery(spec: RecoverySpec) -> OpResult {
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
