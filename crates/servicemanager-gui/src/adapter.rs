//! Pure view-model logic: filtering, dashboard stats, and event mapping.
//! No Slint or Win32 calls — every function here is unit-tested.

use servicemanager_core::{ServiceDefinition, ServiceState};

use crate::{ProcessRow, ServiceRow};

/// True if `def` should be shown given the managed-only / running-only
/// toggles and the search box. Search matches the service name or display
/// name, case-insensitively.
pub fn matches_filter(
    def: &ServiceDefinition,
    managed_only: bool,
    running_only: bool,
    search: &str,
) -> bool {
    if managed_only && !def.is_managed() {
        return false;
    }
    if running_only && def.runtime.as_ref().map(|r| r.state) != Some(ServiceState::Running) {
        return false;
    }
    let q = search.trim().to_lowercase();
    if q.is_empty() {
        return true;
    }
    def.native.name.to_lowercase().contains(&q)
        || def.native.display_name.to_lowercase().contains(&q)
}

/// Counts shown on the Dashboard stat cards. Only managed services count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DashboardStats {
    pub total: usize,
    pub running: usize,
    pub stopped: usize,
    /// Managed, Automatic-start, currently stopped — "needs attention".
    pub attention: usize,
}

/// Tally the Dashboard stat-card counts across the managed services.
pub fn dashboard_stats(defs: &[ServiceDefinition]) -> DashboardStats {
    let mut s = DashboardStats::default();
    for d in defs.iter().filter(|d| d.is_managed()) {
        s.total += 1;
        let state = d.runtime.as_ref().map(|r| r.state);
        match state {
            Some(ServiceState::Running) => s.running += 1,
            Some(ServiceState::Stopped) => {
                s.stopped += 1;
                if matches!(
                    d.native.startup,
                    servicemanager_core::StartupType::Automatic
                        | servicemanager_core::StartupType::AutomaticDelayed
                ) {
                    s.attention += 1;
                }
            }
            _ => {}
        }
    }
    s
}

/// Convert a core `ServiceDefinition` into the Slint table/detail row,
/// computing action-button gating from elevation and the runtime state.
pub fn to_service_row(d: &ServiceDefinition, elevated: bool) -> ServiceRow {
    use servicemanager_core::ManagementKind;
    let state = d.runtime.as_ref().map(|r| r.state);
    let owned = d.is_managed();
    let managed_cfg = d.managed.is_some();
    let enabled = d.native.startup != servicemanager_core::StartupType::Disabled;
    let can_start =
        elevated && owned && enabled && matches!(state, Some(ServiceState::Stopped) | None);
    let can_stop = elevated
        && owned
        && matches!(
            state,
            Some(ServiceState::Running | ServiceState::Paused | ServiceState::StartPending)
        );
    let m = d.managed.as_ref();
    ServiceRow {
        name: d.native.name.clone().into(),
        display: d.native.display_name.clone().into(),
        kind: match d.management_kind() {
            ManagementKind::Managed => "managed",
            ManagementKind::Native => "native",
        }
        .into(),
        state: state
            .map(|s| format!("{s:?}"))
            .unwrap_or_else(|| "Unknown".to_string())
            .into(),
        startup: format!("{:?}", d.native.startup).into(),
        running: matches!(state, Some(ServiceState::Running)),
        image_path: d.native.image_path.clone().into(),
        application: m
            .and_then(|m| m.application.clone())
            .unwrap_or_default()
            .into(),
        arguments: m
            .and_then(|m| m.app_parameters.clone())
            .unwrap_or_default()
            .into(),
        working_dir: m
            .and_then(|m| m.app_directory.clone())
            .unwrap_or_default()
            .into(),
        account: d.native.account.clone().unwrap_or_default().into(),
        pid: d
            .runtime
            .as_ref()
            .and_then(|r| r.pid)
            .map(|p| p.to_string())
            .unwrap_or_default()
            .into(),
        stdout_log: m
            .and_then(|m| m.io.stdout.as_ref().map(|s| s.path.clone()))
            .unwrap_or_default()
            .into(),
        can_start,
        can_stop,
        // Restart only makes sense when the service is currently running or
        // paused — i.e. when we could issue a Stop. A stopped service should
        // just use Start.
        can_restart: can_stop,
        can_pause: elevated && managed_cfg && matches!(state, Some(ServiceState::Running)),
        can_continue: elevated && managed_cfg && matches!(state, Some(ServiceState::Paused)),
        can_rotate: elevated
            && m.is_some_and(|m| m.has_online_rotation())
            && matches!(state, Some(ServiceState::Running | ServiceState::Paused)),
        can_edit: elevated && managed_cfg,
        can_remove: elevated && owned && matches!(state, Some(ServiceState::Stopped) | None),
        can_processes: matches!(
            state,
            Some(ServiceState::Running | ServiceState::Paused | ServiceState::StartPending)
        ),
    }
}

/// Sort the service table rows in place by column index, case-insensitively.
/// Columns: 0 name, 1 display, 2 kind, 3 state, 4 startup.
pub fn sort_service_rows(rows: &mut [ServiceRow], column: i32, ascending: bool) {
    let key = |r: &ServiceRow| -> String {
        match column {
            1 => r.display.to_lowercase(),
            2 => r.kind.to_lowercase(),
            3 => r.state.to_lowercase(),
            4 => r.startup.to_lowercase(),
            _ => r.name.to_lowercase(),
        }
    };
    rows.sort_by_cached_key(key);
    if !ascending {
        rows.reverse();
    }
}

/// Find the new row index for a previously-selected service after the model
/// was rebuilt. Returns the index of `selected` in `names`, or `0` when there
/// is no prior selection or the service is no longer present. The caller must
/// still guard against indexing an empty model.
pub fn remap_selection(selected: Option<&str>, names: &[String]) -> i32 {
    selected
        .and_then(|name| names.iter().position(|n| n == name))
        .unwrap_or(0) as i32
}

/// Sort the process-tree rows in place. Columns 0 (pid) and 1 (parent pid)
/// sort numerically; column 2 (image) sorts as text.
pub fn sort_process_rows(rows: &mut [ProcessRow], column: i32, ascending: bool) {
    fn pid_num(s: &str) -> u64 {
        s.parse().unwrap_or(0)
    }
    rows.sort_by(|a, b| {
        let ord = match column {
            2 => a.image.to_lowercase().cmp(&b.image.to_lowercase()),
            1 => pid_num(&a.ppid).cmp(&pid_num(&b.ppid)),
            _ => pid_num(&a.pid).cmp(&pid_num(&b.pid)),
        };
        if ascending {
            ord
        } else {
            ord.reverse()
        }
    });
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
        assert!(!matches_filter(&native, true, false, ""));
        assert!(matches_filter(&managed, true, false, ""));
        assert!(matches_filter(&native, false, false, ""));
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
        assert!(matches_filter(&d, false, false, "ingest"));
        assert!(matches_filter(&d, false, false, "SMINGEST"));
        assert!(!matches_filter(&d, false, false, "spooler"));
    }

    #[test]
    fn blank_search_matches_everything() {
        let d = def("X", "X", "C:\\x.exe", StartupType::Manual, None);
        assert!(matches_filter(&d, false, false, "   "));
    }

    #[test]
    fn running_only_excludes_non_running_services() {
        let running = def(
            "A",
            "A",
            "C:\\a.exe",
            StartupType::Manual,
            Some(ServiceState::Running),
        );
        let stopped = def(
            "B",
            "B",
            "C:\\b.exe",
            StartupType::Manual,
            Some(ServiceState::Stopped),
        );
        assert!(matches_filter(&running, false, true, ""));
        assert!(!matches_filter(&stopped, false, true, ""));
        assert!(matches_filter(&stopped, false, false, ""));
    }

    #[test]
    fn dashboard_stats_counts_only_managed_services() {
        let ngsm = |n: &str, st, state| {
            def(
                n,
                n,
                &format!("C:\\NGSM\\ngsm.exe run-service {n}"),
                st,
                state,
            )
        };
        let defs = vec![
            ngsm("A", StartupType::Manual, Some(ServiceState::Running)),
            ngsm("B", StartupType::Automatic, Some(ServiceState::Stopped)),
            ngsm("C", StartupType::Manual, Some(ServiceState::Stopped)),
            def(
                "Spooler",
                "Spooler",
                "C:\\Windows\\spoolsv.exe",
                StartupType::Automatic,
                Some(ServiceState::Stopped),
            ),
        ];
        let s = dashboard_stats(&defs);
        assert_eq!(s.total, 3); // native Spooler excluded
        assert_eq!(s.running, 1);
        assert_eq!(s.stopped, 2);
        assert_eq!(s.attention, 1); // only B: managed + Automatic + Stopped
    }

    #[test]
    fn sort_service_rows_orders_by_name_case_insensitively() {
        let row = |name: &str| ServiceRow {
            name: name.into(),
            ..Default::default()
        };
        let mut rows = vec![row("Charlie"), row("alpha"), row("Bravo")];
        sort_service_rows(&mut rows, 0, true);
        assert_eq!(
            rows.iter().map(|r| r.name.to_string()).collect::<Vec<_>>(),
            ["alpha", "Bravo", "Charlie"]
        );
        sort_service_rows(&mut rows, 0, false);
        assert_eq!(
            rows.iter().map(|r| r.name.to_string()).collect::<Vec<_>>(),
            ["Charlie", "Bravo", "alpha"]
        );
    }

    #[test]
    fn sort_process_rows_sorts_pid_numerically() {
        let row = |pid: &str| ProcessRow {
            pid: pid.into(),
            ppid: "0".into(),
            image: "x".into(),
        };
        let mut rows = vec![row("100"), row("9"), row("40")];
        sort_process_rows(&mut rows, 0, true);
        assert_eq!(
            rows.iter().map(|r| r.pid.to_string()).collect::<Vec<_>>(),
            ["9", "40", "100"]
        );
    }

    #[test]
    fn disabled_services_cannot_start_or_restart() {
        let disabled = def(
            "DisabledSvc",
            "Disabled Svc",
            "C:\\NGSM\\ngsm.exe run-service DisabledSvc",
            StartupType::Disabled,
            Some(ServiceState::Stopped),
        );
        let row = to_service_row(&disabled, true);
        assert!(!row.can_start, "disabled service must not be startable");
        assert!(!row.can_restart, "disabled service must not be restartable");

        let manual = def(
            "ManualSvc",
            "Manual Svc",
            "C:\\NGSM\\ngsm.exe run-service ManualSvc",
            StartupType::Manual,
            Some(ServiceState::Stopped),
        );
        let row = to_service_row(&manual, true);
        assert!(
            row.can_start,
            "a stopped manual managed service stays startable"
        );
    }

    #[test]
    fn restart_is_disabled_for_stopped_services() {
        let stopped = def(
            "StopSvc",
            "Stop Svc",
            "C:\\NGSM\\ngsm.exe run-service StopSvc",
            StartupType::Manual,
            Some(ServiceState::Stopped),
        );
        let row = to_service_row(&stopped, true);
        assert!(
            !row.can_restart,
            "stopped service should not be restartable"
        );
        assert!(row.can_start, "stopped service should be startable");
    }

    #[test]
    fn restart_is_enabled_for_running_services() {
        let running = def(
            "RunSvc",
            "Run Svc",
            "C:\\NGSM\\ngsm.exe run-service RunSvc",
            StartupType::Manual,
            Some(ServiceState::Running),
        );
        let row = to_service_row(&running, true);
        assert!(row.can_restart);
        assert!(row.can_stop);
        assert!(!row.can_start);
    }

    #[test]
    fn only_stopped_services_can_be_removed() {
        let running = def(
            "RunSvc",
            "Run Svc",
            "C:\\NGSM\\ngsm.exe run-service RunSvc",
            StartupType::Manual,
            Some(ServiceState::Running),
        );
        assert!(
            !to_service_row(&running, true).can_remove,
            "a running service must not be removable"
        );

        let stopped = def(
            "StopSvc",
            "Stop Svc",
            "C:\\NGSM\\ngsm.exe run-service StopSvc",
            StartupType::Manual,
            Some(ServiceState::Stopped),
        );
        assert!(
            to_service_row(&stopped, true).can_remove,
            "a stopped managed service stays removable"
        );
    }

    #[test]
    fn remap_selection_follows_the_name() {
        let names = vec![
            "alpha".to_string(),
            "bravo".to_string(),
            "charlie".to_string(),
        ];
        // The selected service moved to a new index.
        assert_eq!(remap_selection(Some("charlie"), &names), 2);
        assert_eq!(remap_selection(Some("alpha"), &names), 0);
        // The selected service is gone -> fall back to the first row.
        assert_eq!(remap_selection(Some("ghost"), &names), 0);
        // No prior selection -> first row.
        assert_eq!(remap_selection(None, &names), 0);
        // Empty list -> 0 (callers must guard indexing an empty model).
        assert_eq!(remap_selection(Some("alpha"), &[]), 0);
    }
}
