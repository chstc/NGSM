//! Pure dashboard-metrics computation: classification counts and 30-day
//! availability. No I/O — caller passes already-loaded services + events
//! and a `now`. Every function is unit-tested.

// No callers yet — Tasks 5/6 will wire this up.
#![allow(dead_code)]

use servicemanager_core::events::{EventKind, EventRecord};
use servicemanager_core::{ServiceDefinition, ServiceState, StartupType};
use std::collections::HashMap;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Numbers driving the four Dashboard stat tiles + the 30-day sparkline.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DashboardMetrics {
    pub total: usize,
    pub running: usize,
    pub stopped: usize,
    pub manual_start: usize,
    pub failed: usize,
    pub auto_recovering: usize,
    /// 0.0..=100.0. 100.0 when no service has any event history (the UI
    /// renders "—" instead of "100.0%" when `total == 0` OR
    /// `availability_unknown`).
    pub availability_pct: f32,
    pub availability_window_days: u32,
    /// 30 entries oldest→newest. Each is mean availability across services
    /// for that UTC calendar day in 0..=100. Days with no data carry
    /// forward from the previous day; the first day with no data uses 100.0.
    pub availability_daily: Vec<f32>,
    /// True when the availability metric is not trustworthy — set by the
    /// caller (worker) when `read_since` errored. `compute_metrics` itself
    /// never sets this. The UI must render "—" instead of the numeric
    /// percentage when this is true.
    pub availability_unknown: bool,
}

/// Top-level entry: deterministic given inputs. `events` MUST be ascending
/// by `ts` (as returned by `event_log_reader::read_since`).
pub fn compute_metrics(
    defs: &[ServiceDefinition],
    events: &[EventRecord],
    now: OffsetDateTime,
) -> DashboardMetrics {
    let counts = compute_counts(defs, events, now);
    // Availability fields filled in by later tasks; default for now so this
    // task ships a runnable build without breaking callers.
    DashboardMetrics {
        total: counts.total,
        running: counts.running,
        stopped: counts.stopped,
        manual_start: counts.manual_start,
        failed: counts.failed,
        auto_recovering: counts.auto_recovering,
        availability_pct: 100.0,
        availability_window_days: 30,
        availability_daily: vec![100.0; 30],
        availability_unknown: false,
    }
}

#[derive(Debug, Default, PartialEq)]
struct Counts {
    total: usize,
    running: usize,
    stopped: usize,
    manual_start: usize,
    failed: usize,
    auto_recovering: usize,
}

fn compute_counts(
    defs: &[ServiceDefinition],
    events: &[EventRecord],
    now: OffsetDateTime,
) -> Counts {
    // Index the most-recent event per service for O(1) lookups in the loop.
    let last_event = last_event_per_service(events);

    let mut c = Counts::default();
    for def in defs.iter().filter(|d| d.is_managed()) {
        c.total += 1;
        let state = def.runtime.as_ref().map(|r| r.state);
        match state {
            Some(ServiceState::Running) => c.running += 1,
            Some(ServiceState::Stopped) => {
                c.stopped += 1;
                if def.native.startup == StartupType::Manual {
                    c.manual_start += 1;
                }
            }
            _ => {}
        }
        let last = last_event.get(def.native.name.as_str());
        if classify_failed(state, last, now) {
            c.failed += 1;
        }
        if classify_auto_recovering(state, last, events, &def.native.name, now) {
            c.auto_recovering += 1;
        }
    }
    c
}

/// Build `service_name → most-recent EventRecord`. Walks events once.
fn last_event_per_service(events: &[EventRecord]) -> HashMap<&str, &EventRecord> {
    let mut map: HashMap<&str, &EventRecord> = HashMap::new();
    for ev in events {
        // events is ascending; later overwrites earlier — correct.
        map.insert(ev.service.as_str(), ev);
    }
    map
}

fn parse_ts(ts: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(ts, &Rfc3339).ok()
}

/// `failed` = state Stopped + last event is `child_exited` with non-zero
/// exit code + within the last 24 h. Future-dated events (ts > now)
/// excluded — a clock-skewed or malformed timestamp would otherwise
/// trivially satisfy the recency check (negative age).
fn classify_failed(
    state: Option<ServiceState>,
    last: Option<&&EventRecord>,
    now: OffsetDateTime,
) -> bool {
    if state != Some(ServiceState::Stopped) {
        return false;
    }
    let Some(rec) = last else { return false };
    if rec.event != EventKind::ChildExited {
        return false;
    }
    if matches!(rec.exit_code, None | Some(0)) {
        return false;
    }
    let Some(ts) = parse_ts(&rec.ts) else { return false };
    if ts > now {
        return false;
    }
    (now - ts) <= time::Duration::hours(24)
}

/// `auto_recovering` = state != Running + last event is either `throttled`,
/// or a `restarted` immediately following a `child_exited` with no
/// `stopped` between them — within the last 5 minutes. Future-dated
/// events excluded (see `classify_failed` rationale).
fn classify_auto_recovering(
    state: Option<ServiceState>,
    last: Option<&&EventRecord>,
    events: &[EventRecord],
    service: &str,
    now: OffsetDateTime,
) -> bool {
    if state == Some(ServiceState::Running) {
        return false;
    }
    let Some(rec) = last else { return false };
    let Some(ts) = parse_ts(&rec.ts) else { return false };
    if ts > now {
        return false;
    }
    if (now - ts) > time::Duration::minutes(5) {
        return false;
    }
    match rec.event {
        EventKind::Throttled => true,
        EventKind::Restarted => {
            // Look back: is the most-recent prior event for this service a
            // `child_exited`, with no `stopped` in between?
            for prior in events.iter().rev().filter(|e| e.service == service) {
                if std::ptr::eq(prior, *rec) {
                    continue;
                }
                match prior.event {
                    EventKind::Stopped => return false,
                    EventKind::ChildExited => return true,
                    _ => continue,
                }
            }
            false
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use servicemanager_core::{
        NativeServiceConfig, ServiceDefinition, ServiceRuntimeState, ServiceType,
    };
    use time::macros::datetime;

    fn def(name: &str, image: &str, startup: StartupType, state: Option<ServiceState>) -> ServiceDefinition {
        ServiceDefinition {
            native: NativeServiceConfig {
                name: name.into(),
                display_name: name.into(),
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

    fn ngsm(name: &str, startup: StartupType, state: Option<ServiceState>) -> ServiceDefinition {
        def(name, &format!("C:\\NGSM\\ngsm.exe run-service {name}"), startup, state)
    }

    fn ev(svc: &str, ts: OffsetDateTime, kind: EventKind, exit_code: Option<i32>) -> EventRecord {
        EventRecord {
            ts: ts.format(&Rfc3339).unwrap(),
            service: svc.into(),
            event: kind,
            pid: None,
            exit_code,
            lived_ms: None,
            delay_ms: None,
            reason: None,
        }
    }

    #[test]
    fn empty_inputs_yield_zero_counts() {
        let m = compute_metrics(&[], &[], datetime!(2026-05-23 12:00:00 UTC));
        assert_eq!(m.total, 0);
        assert_eq!(m.running, 0);
        assert_eq!(m.failed, 0);
    }

    #[test]
    fn running_and_stopped_tally_only_managed() {
        let defs = vec![
            ngsm("A", StartupType::Manual, Some(ServiceState::Running)),
            ngsm("B", StartupType::Automatic, Some(ServiceState::Stopped)),
            // Native service: must NOT count.
            def("Spooler", "C:\\Windows\\spoolsv.exe", StartupType::Automatic, Some(ServiceState::Running)),
        ];
        let m = compute_metrics(&defs, &[], datetime!(2026-05-23 12:00:00 UTC));
        assert_eq!(m.total, 2);
        assert_eq!(m.running, 1);
        assert_eq!(m.stopped, 1);
    }

    #[test]
    fn manual_start_counts_only_stopped_manual() {
        let defs = vec![
            ngsm("ManualStopped", StartupType::Manual, Some(ServiceState::Stopped)),
            ngsm("ManualRunning", StartupType::Manual, Some(ServiceState::Running)),
            ngsm("AutoStopped", StartupType::Automatic, Some(ServiceState::Stopped)),
        ];
        let m = compute_metrics(&defs, &[], datetime!(2026-05-23 12:00:00 UTC));
        assert_eq!(m.manual_start, 1);
    }

    #[test]
    fn failed_requires_stopped_plus_recent_nonzero_exit() {
        let now = datetime!(2026-05-23 12:00:00 UTC);
        let defs = vec![ngsm("A", StartupType::Automatic, Some(ServiceState::Stopped))];
        let events = vec![ev(
            "A",
            now - time::Duration::hours(1),
            EventKind::ChildExited,
            Some(1),
        )];
        let m = compute_metrics(&defs, &events, now);
        assert_eq!(m.failed, 1);
    }

    #[test]
    fn failed_excludes_clean_exit_zero() {
        let now = datetime!(2026-05-23 12:00:00 UTC);
        let defs = vec![ngsm("A", StartupType::Manual, Some(ServiceState::Stopped))];
        let events = vec![ev(
            "A",
            now - time::Duration::hours(1),
            EventKind::ChildExited,
            Some(0),
        )];
        assert_eq!(compute_metrics(&defs, &events, now).failed, 0);
    }

    #[test]
    fn failed_excludes_old_exit_beyond_24h() {
        let now = datetime!(2026-05-23 12:00:00 UTC);
        let defs = vec![ngsm("A", StartupType::Automatic, Some(ServiceState::Stopped))];
        let events = vec![ev(
            "A",
            now - time::Duration::hours(48),
            EventKind::ChildExited,
            Some(1),
        )];
        assert_eq!(compute_metrics(&defs, &events, now).failed, 0);
    }

    #[test]
    fn auto_recovering_for_recent_throttled() {
        let now = datetime!(2026-05-23 12:00:00 UTC);
        let defs = vec![ngsm("A", StartupType::Automatic, Some(ServiceState::Stopped))];
        let events = vec![ev(
            "A",
            now - time::Duration::minutes(2),
            EventKind::Throttled,
            None,
        )];
        assert_eq!(compute_metrics(&defs, &events, now).auto_recovering, 1);
    }

    #[test]
    fn auto_recovering_for_restarted_following_child_exited() {
        let now = datetime!(2026-05-23 12:00:00 UTC);
        let defs = vec![ngsm("A", StartupType::Automatic, Some(ServiceState::StartPending))];
        let events = vec![
            ev("A", now - time::Duration::minutes(3), EventKind::ChildExited, Some(1)),
            ev("A", now - time::Duration::minutes(2), EventKind::Restarted, None),
        ];
        assert_eq!(compute_metrics(&defs, &events, now).auto_recovering, 1);
    }

    #[test]
    fn auto_recovering_excluded_when_running_and_old() {
        let now = datetime!(2026-05-23 12:00:00 UTC);
        let defs = vec![ngsm("A", StartupType::Automatic, Some(ServiceState::Running))];
        let events = vec![ev(
            "A",
            now - time::Duration::minutes(2),
            EventKind::Throttled,
            None,
        )];
        assert_eq!(compute_metrics(&defs, &events, now).auto_recovering, 0);

        let stopped = vec![ngsm("A", StartupType::Automatic, Some(ServiceState::Stopped))];
        let old = vec![ev(
            "A",
            now - time::Duration::minutes(10),
            EventKind::Throttled,
            None,
        )];
        assert_eq!(compute_metrics(&stopped, &old, now).auto_recovering, 0);
    }

    #[test]
    fn future_dated_events_do_not_classify_failed_or_auto_recovering() {
        // D3 regression: an event with ts > now would have (now - ts)
        // be negative, which would trivially satisfy "within 24h" / "within
        // 5min". Both classifiers must guard against that.
        let now = datetime!(2026-05-23 12:00:00 UTC);
        let defs = vec![ngsm("Skew", StartupType::Automatic, Some(ServiceState::Stopped))];
        let future_exit = vec![ev(
            "Skew",
            now + time::Duration::minutes(10),
            EventKind::ChildExited,
            Some(1),
        )];
        let m = compute_metrics(&defs, &future_exit, now);
        assert_eq!(m.failed, 0, "future child_exited must not classify as failed");

        let future_throttle = vec![ev(
            "Skew",
            now + time::Duration::minutes(10),
            EventKind::Throttled,
            None,
        )];
        let m = compute_metrics(&defs, &future_throttle, now);
        assert_eq!(
            m.auto_recovering, 0,
            "future throttled must not classify as auto-recovering"
        );
    }
}
