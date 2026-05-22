//! Pure view-model logic: filtering, dashboard stats, and event diffing.
//! No Slint or Win32 calls — every function here is unit-tested.

use std::collections::HashMap;

use servicemanager_core::{ServiceDefinition, ServiceState};

use crate::ServiceRow;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Started,
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventChange {
    pub service: String,
    pub kind: EventKind,
}

/// Compare the previous managed-service states to the current snapshot and
/// return the state transitions worth surfacing in the Recent Events panel.
/// Only managed services are considered. A service with no prior entry (first
/// scan) produces no event.
pub fn diff_events(
    prev: &HashMap<String, ServiceState>,
    now: &[ServiceDefinition],
) -> Vec<EventChange> {
    let mut out = Vec::new();
    for d in now.iter().filter(|d| d.is_managed()) {
        let Some(cur) = d.runtime.as_ref().map(|r| r.state) else {
            continue;
        };
        let Some(&old) = prev.get(&d.native.name) else {
            continue;
        };
        if old == cur {
            continue;
        }
        match cur {
            ServiceState::Running => out.push(EventChange {
                service: d.native.name.clone(),
                kind: EventKind::Started,
            }),
            ServiceState::Stopped => out.push(EventChange {
                service: d.native.name.clone(),
                kind: EventKind::Stopped,
            }),
            _ => {}
        }
    }
    out
}

/// Snapshot the current managed-service states for the next `diff_events`.
pub fn state_snapshot(defs: &[ServiceDefinition]) -> HashMap<String, ServiceState> {
    defs.iter()
        .filter(|d| d.is_managed())
        .filter_map(|d| d.runtime.as_ref().map(|r| (d.native.name.clone(), r.state)))
        .collect()
}

/// Convert a core `ServiceDefinition` into the Slint table/detail row,
/// computing action-button gating from elevation and the runtime state.
pub fn to_service_row(d: &ServiceDefinition, elevated: bool) -> ServiceRow {
    use servicemanager_core::ManagementKind;
    let state = d.runtime.as_ref().map(|r| r.state);
    let owned = d.is_managed();
    let managed_cfg = d.managed.is_some();
    let can_start = elevated && owned && matches!(state, Some(ServiceState::Stopped) | None);
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
        can_restart: can_start || can_stop,
        can_pause: elevated && managed_cfg && matches!(state, Some(ServiceState::Running)),
        can_continue: elevated && managed_cfg && matches!(state, Some(ServiceState::Paused)),
        can_rotate: elevated
            && m.is_some_and(|m| m.has_online_rotation())
            && matches!(state, Some(ServiceState::Running | ServiceState::Paused)),
        can_edit: elevated && managed_cfg,
        can_remove: elevated && owned,
        can_processes: matches!(
            state,
            Some(ServiceState::Running | ServiceState::Paused | ServiceState::StartPending)
        ),
    }
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
    fn diff_events_reports_start_and_stop_transitions() {
        let ngsm = |n: &str, state| {
            def(
                n,
                n,
                &format!("C:\\NGSM\\ngsm.exe run-service {n}"),
                StartupType::Manual,
                state,
            )
        };
        let prev: HashMap<String, ServiceState> = [
            ("A".to_string(), ServiceState::Stopped),
            ("B".to_string(), ServiceState::Running),
            ("C".to_string(), ServiceState::Running),
        ]
        .into_iter()
        .collect();
        let now = vec![
            ngsm("A", Some(ServiceState::Running)), // started
            ngsm("B", Some(ServiceState::Stopped)), // stopped
            ngsm("C", Some(ServiceState::Running)), // unchanged
        ];
        let events = diff_events(&prev, &now);
        assert_eq!(
            events,
            vec![
                EventChange {
                    service: "A".into(),
                    kind: EventKind::Started
                },
                EventChange {
                    service: "B".into(),
                    kind: EventKind::Stopped
                },
            ]
        );
    }

    #[test]
    fn diff_events_ignores_first_scan_and_native_services() {
        let now = vec![
            def(
                "A",
                "A",
                "C:\\NGSM\\ngsm.exe run-service A",
                StartupType::Manual,
                Some(ServiceState::Running),
            ),
            def(
                "Spooler",
                "Spooler",
                "C:\\Windows\\spoolsv.exe",
                StartupType::Automatic,
                Some(ServiceState::Running),
            ),
        ];
        assert!(diff_events(&HashMap::new(), &now).is_empty());
    }
}
