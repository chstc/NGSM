//! Pure view-model logic: filtering, dashboard stats, and event diffing.
//! No Slint or Win32 calls — every function here is unit-tested.

use servicemanager_core::{ServiceDefinition, ServiceState};

/// True if `def` should be shown given the managed-only toggle and search box.
/// Search matches the service name or display name, case-insensitively.
pub fn matches_filter(def: &ServiceDefinition, managed_only: bool, search: &str) -> bool {
    if managed_only && !def.is_managed() {
        return false;
    }
    let q = search.trim().to_lowercase();
    if q.is_empty() {
        return true;
    }
    def.native.name.to_lowercase().contains(&q)
        || def.native.display_name.to_lowercase().contains(&q)
}

#[cfg(test)]
mod tests {
    use super::*;
    use servicemanager_core::{
        NativeServiceConfig, ServiceDefinition, ServiceRuntimeState, ServiceState, ServiceType,
        StartupType,
    };

    /// Build a `ServiceDefinition` for tests. `image` decides managed-ness via
    /// the executable-basename rule in `ServiceDefinition::is_managed`.
    pub(super) fn def(
        name: &str,
        display: &str,
        image: &str,
        startup: StartupType,
        state: Option<ServiceState>,
    ) -> ServiceDefinition {
        ServiceDefinition {
            native: NativeServiceConfig {
                name: name.into(),
                display_name: display.into(),
                description: None,
                startup,
                service_type: ServiceType::Win32OwnProcess,
                image_path: image.into(),
                account: None,
                depend_on_services: Vec::new(),
                depend_on_groups: Vec::new(),
            },
            managed: None,
            runtime: state.map(|s| ServiceRuntimeState {
                state: s,
                pid: None,
                exit_code: None,
                checkpoint: None,
                wait_hint_ms: None,
            }),
        }
    }

    #[test]
    fn managed_only_excludes_native_services() {
        let native = def(
            "Spooler",
            "Print Spooler",
            "C:\\Windows\\spoolsv.exe",
            StartupType::Automatic,
            Some(ServiceState::Running),
        );
        let managed = def(
            "SmA",
            "Demo A",
            "C:\\NGSM\\ngsm.exe run-service SmA",
            StartupType::Manual,
            Some(ServiceState::Running),
        );
        assert!(!matches_filter(&native, true, ""));
        assert!(matches_filter(&managed, true, ""));
        assert!(matches_filter(&native, false, ""));
    }

    #[test]
    fn search_matches_name_and_display_case_insensitively() {
        let d = def(
            "SmIngestWorker",
            "Ingest worker",
            "C:\\NGSM\\ngsm.exe run-service SmIngestWorker",
            StartupType::Automatic,
            Some(ServiceState::Running),
        );
        assert!(matches_filter(&d, false, "ingest"));
        assert!(matches_filter(&d, false, "SMINGEST"));
        assert!(!matches_filter(&d, false, "spooler"));
    }

    #[test]
    fn blank_search_matches_everything() {
        let d = def("X", "X", "C:\\x.exe", StartupType::Manual, None);
        assert!(matches_filter(&d, false, "   "));
    }
}
