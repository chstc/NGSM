use servicemanager_core::ServiceDefinition;
use servicemanager_win32::{query_service, remove_service};

use crate::error::{message_error, OpResult};

/// Remove an NGSM-managed (or, with `force_native`, any) Windows service.
///
/// # Arguments
///
/// * `name` — service name (SCM key, not display name).
/// * `force_native` — if `true`, bypass the NGSM-ownership check. Use for
///   removing native Windows services that were never managed by NGSM.
/// * `purge_managed_config` — must be `true`. Preservation requests are
///   rejected: SCM deletion removes the service's whole registry subtree,
///   whether or not NGSM explicitly scrubs its managed values.
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
    if !purge_managed_config {
        return Err(servicemanager_core::Error::InvalidConfig(
            "cannot preserve managed config during removal: Windows SCM deletes the \
             service registry subtree, including Parameters. Export or back up the \
             configuration before removing the service; --no-purge-config is unsupported."
                .into(),
        ));
    }

    let _guard = servicemanager_registry::lock_service_config(name)?;
    // Query once; we need both the SCM state (for the stopped check) and the
    // managed config (for the ownership check, when force_native is false).
    let native = query_service(name)?;

    if !force_native {
        // Fail closed: an unreadable managed config means ownership cannot be
        // confirmed, so refuse rather than collapsing the error into "native".
        let managed = match servicemanager_registry::read_managed_config(name) {
            Ok(m) => m,
            Err(e) => {
                return Err(message_error(format!(
                    "'{name}': managed ownership cannot be determined — its managed config \
                     is unreadable ({e}); refusing to remove it"
                )));
            }
        };
        let def = ServiceDefinition {
            native: native.config.clone(),
            managed,
            runtime: native.runtime.clone(),
        };
        if !def.is_managed() {
            return Err(message_error(format!(
                "'{name}' is not an NGSM-managed service — refusing to remove it"
            )));
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
        return Err(message_error(format!(
            "'{name}' is not stopped — stop it before removing it"
        )));
    }

    // Remove the SCM service first: if that fails the service keeps its
    // managed config and the caller can retry. Only then scrub the registry,
    // and surface a cleanup failure instead of silently dropping it.
    remove_service(name)?;
    if purge_managed_config && is_managed_for_purge(name) {
        servicemanager_registry::delete_managed_config(name).map_err(|e| {
            message_error(format!(
                "service removed, but managed config cleanup failed: {e}"
            ))
        })?;
    }
    Ok(format!("Removed '{name}'."))
}

/// Gate the managed-config purge on a confirmed NGSM/NSSM marker.
///
/// `delete_managed_config` blindly scrubs every NGSM-owned value name
/// (Application, AppDirectory, AppExit, AppEvents, AppStdout, ...) under
/// the service's `Parameters` key. On the non-`force_native` path, the
/// caller has already proved managed ownership before we reach the purge,
/// so scrubbing is safe. With `--force-native` that ownership check is
/// skipped — a native Windows service that happens to use one of the
/// NSSM-shaped value names (e.g. its own `Application`) would lose its
/// own configuration if we still scrubbed unconditionally.
///
/// Re-read the managed config and only scrub when it confirms NGSM
/// ownership. An unreadable or absent managed config degrades silently —
/// the SCM record is already gone, and the operator can clean any
/// orphaned values up by hand (or via a future explicit cleanup
/// command); the alternative is corrupting an unrelated service's
/// registry state.
fn is_managed_for_purge(name: &str) -> bool {
    servicemanager_registry::read_managed_config(name)
        .map(|c| c.is_some())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preservation_requests_fail_before_any_service_lookup_or_deletion() {
        for force_native in [false, true] {
            let error = remove("invalid\\service\\name", force_native, false)
                .expect_err("preservation must be rejected before SCM access")
                .to_string();
            assert!(error.contains("SCM"), "{error}");
            assert!(error.contains("Parameters"), "{error}");
            assert!(error.contains("Export or back up"), "{error}");
            assert!(error.contains("--no-purge-config"), "{error}");
        }
    }

    /// `ops::remove` itself touches the live SCM and the per-service
    /// `Parameters` key under HKLM, which neither test runner has — but
    /// the purge gate is now a small pure function over
    /// `read_managed_config`, and that we *can* drive without elevation
    /// via the registry crate's HKCU test surface… except its HKCU
    /// helpers are private. So instead we cover the gate indirectly with
    /// the only test that's actually reliable here: a name guaranteed
    /// not to exist as a managed service must read back as "not managed"
    /// and therefore be skipped by the purge gate.
    ///
    /// This is the regression guard for finding #4: with the bug, the
    /// purge ran unconditionally; with the fix, an unmanaged (or
    /// unreadable) target must skip the scrub silently.
    #[test]
    fn purge_gate_skips_unmanaged_service() {
        // A name that cannot collide with any real installed service.
        // `read_managed_config` returns Ok(None) for it (no Parameters
        // key, no `Application` marker), and the gate must report false.
        let probe = "NgsmRemoveTestProbe_DoesNotExist_4f0a91";
        assert!(
            !is_managed_for_purge(probe),
            "purge gate must skip a service with no managed marker — \
             otherwise force-native remove would scrub an unrelated \
             service's registry state"
        );
    }
}
