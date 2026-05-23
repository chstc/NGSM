use servicemanager_core::ServiceDefinition;
use servicemanager_win32::enumerate_services;

/// Enumerate all Windows services and annotate each one with its NGSM managed
/// configuration (if present). Returns the sorted list and any per-service
/// warnings (e.g. access-denied on the managed-config registry key).
///
/// A warning does **not** suppress the row — the service is still included in
/// the result so it can be shown in the UI/CLI rather than silently dropped.
#[allow(clippy::type_complexity)]
pub fn list_services() -> servicemanager_core::Result<(Vec<ServiceDefinition>, Vec<String>)> {
    let mut warnings: Vec<String> = Vec::new();
    let mut defs: Vec<ServiceDefinition> = enumerate_services()?
        .into_iter()
        .map(|s| {
            // A failed SCM config query during enumeration left this entry
            // with only partial data — surface it rather than silently
            // classifying the service from incomplete fields. Prefix the
            // service name so the warning identifies the row at a glance
            // (matches the shape used by the managed-config warning below).
            if let Some(w) = s.query_error {
                warnings.push(format!("{}: {w}", s.config.name));
            }
            // A genuine managed-config read failure (access denied, corrupt
            // value) is kept as a warning rather than collapsed into "not
            // managed".
            let managed = match servicemanager_registry::read_managed_config(&s.config.name) {
                Ok(m) => m,
                Err(e) => {
                    warnings.push(format!(
                        "{}: managed config unreadable ({e})",
                        s.config.name
                    ));
                    None
                }
            };
            ServiceDefinition {
                native: s.config,
                managed,
                runtime: s.runtime,
            }
        })
        .collect();
    defs.sort_by(|a, b| {
        a.native
            .name
            .to_lowercase()
            .cmp(&b.native.name.to_lowercase())
    });
    Ok((defs, warnings))
}
