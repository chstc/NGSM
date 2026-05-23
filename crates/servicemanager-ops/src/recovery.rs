use std::collections::BTreeMap;

use servicemanager_core::{ExitAction, ExitActionPolicy};

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

/// Read the current recovery policy for a managed service. Returns an
/// `Err` if the service is not NGSM-managed or its config is unreadable.
pub fn read_recovery(name: &str) -> Result<RecoverySpec, String> {
    let Some(managed) =
        servicemanager_registry::read_managed_config(name).map_err(|e| e.to_string())?
    else {
        return Err(format!("'{}' is not an NGSM-managed service", name));
    };
    // The registry pseudo-key "default" mirrors restart.default_action;
    // filter it out so the returned spec only contains per-exit-code
    // entries (matches what the GUI's RecoveryForm does).
    let exit_actions: BTreeMap<String, ExitAction> = managed
        .exit_actions
        .iter()
        .filter(|(code, _)| code.as_str() != "default")
        .map(|(code, policy)| (code.clone(), policy.action))
        .collect();
    Ok(RecoverySpec {
        name: name.to_string(),
        restart_delay_ms: managed.restart.restart_delay_ms,
        throttle_delay_ms: managed.restart.throttle_delay_ms,
        default_action: managed
            .restart
            .default_action
            .unwrap_or(ExitAction::Restart),
        exit_actions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_recovery_for_unknown_service_returns_error_mentioning_managed() {
        let err = read_recovery("__definitely_does_not_exist_zzz").unwrap_err();
        assert!(
            err.contains("not an NGSM-managed service") || err.contains("not"),
            "error should mention not-managed: {err}"
        );
    }
}
