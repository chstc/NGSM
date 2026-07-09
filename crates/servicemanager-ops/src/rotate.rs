use servicemanager_win32::{control_service, ServiceControlSignal, SERVICE_CONTROL_ROTATE};

use crate::error::{message_error, OpResult};

/// Request an online log rotation for a managed service.
///
/// On-demand rotation only applies to services that have online (pipe-backed)
/// log rotation enabled. Offline logs rotate on restart — a `rotate` request
/// against such a service is meaningless and is refused rather than silently
/// reporting a false success.
///
/// Re-reads the managed config rather than trusting a potentially-stale caller
/// snapshot, matching the preflight logic in the GUI, CLI, and broker.
pub fn rotate(name: &str) -> OpResult {
    match servicemanager_registry::read_managed_config(name)? {
        Some(cfg) if cfg.has_online_rotation() => {}
        Some(_) => {
            return Err(message_error(format!(
                "'{name}' does not use online log rotation — its logs rotate on restart, \
                 not on demand"
            )))
        }
        None => {
            return Err(message_error(format!(
                "'{name}' is not an NGSM-managed service"
            )))
        }
    }
    control_service(name, ServiceControlSignal::User(SERVICE_CONTROL_ROTATE))?;
    Ok(format!("Rotate requested for '{name}'."))
}
