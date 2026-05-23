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
    let window_start = now - time::Duration::days(30);
    let timelines = build_service_timelines(defs, events, window_start, now);
    let avail = compute_availability(&timelines, window_start, now);
    DashboardMetrics {
        total: counts.total,
        running: counts.running,
        stopped: counts.stopped,
        manual_start: counts.manual_start,
        failed: counts.failed,
        auto_recovering: counts.auto_recovering,
        availability_pct: avail.aggregate_pct,
        availability_window_days: avail.window_days,
        // Sparkline filled in by Task 6 (still uses aggregate as placeholder
        // so the build stays green; a real per-bucket vec lands in Task 6).
        availability_daily: vec![avail.aggregate_pct; 30],
        availability_unknown: false,
    }
}

/// One service's up/down history across the 30-day window. Intervals are
/// disjoint, ordered, and clipped to `[window_start, now]` so downstream
/// clippers (per-day, per-window) can be O(n_intervals) without re-parsing.
struct ServiceTimeline {
    /// Per-service window start = `max(first_event_ts, global_window_start)`.
    window_start: OffsetDateTime,
    /// Up-intervals, oldest first.
    intervals: Vec<(OffsetDateTime, OffsetDateTime)>,
}

struct AvailabilityResult {
    aggregate_pct: f32,
    window_days: u32,
}

fn build_service_timelines(
    defs: &[ServiceDefinition],
    events: &[EventRecord],
    window_start: OffsetDateTime,
    now: OffsetDateTime,
) -> Vec<ServiceTimeline> {
    let mut out = Vec::new();
    for def in defs.iter().filter(|d| d.is_managed()) {
        let svc = def.native.name.as_str();
        let svc_events: Vec<&EventRecord> =
            events.iter().filter(|e| e.service == svc).collect();
        if svc_events.is_empty() {
            continue;
        }
        let Some(first_ts) = parse_ts(&svc_events[0].ts) else {
            continue;
        };
        let svc_window_start = first_ts.max(window_start);
        let state = def.runtime.as_ref().map(|r| r.state);
        let intervals = build_up_intervals(&svc_events, svc_window_start, now, state);
        out.push(ServiceTimeline {
            window_start: svc_window_start,
            intervals,
        });
    }
    out
}

/// Build the list of up-intervals for one service across `[start, now]`.
/// `state` decides whether a still-open `up_since` at end-of-log extends
/// to `now`. Future timestamps are clamped to `now` (clock skew safety).
fn build_up_intervals(
    events: &[&EventRecord],
    start: OffsetDateTime,
    now: OffsetDateTime,
    state: Option<ServiceState>,
) -> Vec<(OffsetDateTime, OffsetDateTime)> {
    let mut intervals: Vec<(OffsetDateTime, OffsetDateTime)> = Vec::new();
    let mut up_since: Option<OffsetDateTime> = None;
    let mut last_event_kind: Option<EventKind> = None;
    for rec in events {
        let Some(ts) = parse_ts(&rec.ts) else { continue };
        let ts = ts.min(now); // Clamp future skew.
        if ts < start {
            continue;
        }
        match rec.event {
            EventKind::Started | EventKind::Restarted => {
                if up_since.is_none() {
                    up_since = Some(ts.max(start));
                }
            }
            EventKind::ChildExited
            | EventKind::Stopped
            | EventKind::Throttled => {
                if let Some(s) = up_since.take() {
                    if ts > s {
                        intervals.push((s, ts));
                    }
                }
            }
        }
        last_event_kind = Some(rec.event);
    }
    // Extend an open `up_since` to `now` only when (a) the SCM thinks the
    // service is Running AND (b) the last event was a start-like event.
    // A Throttled event would already have closed `up_since`; this is a
    // consistency safeguard for the SCM-state safeguard test.
    if let Some(s) = up_since {
        if state == Some(ServiceState::Running)
            && matches!(last_event_kind, Some(EventKind::Started | EventKind::Restarted))
            && now > s
        {
            intervals.push((s, now));
        }
    }
    intervals
}

/// Sum the milliseconds of `intervals` overlap with `[win_start, win_end]`.
/// Used both at window scale (availability) and at day scale (sparkline)
/// — the same intervals are clipped repeatedly.
fn up_ms_in_window(
    intervals: &[(OffsetDateTime, OffsetDateTime)],
    win_start: OffsetDateTime,
    win_end: OffsetDateTime,
) -> f32 {
    let mut total: f32 = 0.0;
    for (s, e) in intervals {
        let cs = (*s).max(win_start);
        let ce = (*e).min(win_end);
        if ce > cs {
            total += (ce - cs).whole_milliseconds().max(0) as f32;
        }
    }
    total
}

fn compute_availability(
    timelines: &[ServiceTimeline],
    window_start: OffsetDateTime,
    now: OffsetDateTime,
) -> AvailabilityResult {
    let mut ratios: Vec<f32> = Vec::new();
    let mut earliest: Option<OffsetDateTime> = None;
    for t in timelines {
        let window_len = (now - t.window_start).whole_milliseconds().max(1) as f32;
        let up_ms = up_ms_in_window(&t.intervals, t.window_start, now);
        let pct = (up_ms / window_len * 100.0).clamp(0.0, 100.0);
        ratios.push(pct);
        earliest = Some(earliest.map_or(t.window_start, |prev| prev.min(t.window_start)));
    }
    let aggregate_pct = if ratios.is_empty() {
        100.0
    } else {
        ratios.iter().sum::<f32>() / ratios.len() as f32
    };
    let window_days = match earliest {
        None => 30,
        Some(ts) => {
            let span = now - ts.max(window_start);
            let days = (span.whole_seconds() as f32 / 86_400.0).ceil() as i64;
            days.clamp(1, 30) as u32
        }
    };
    AvailabilityResult {
        aggregate_pct,
        window_days,
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

    #[test]
    fn auto_recovering_excludes_restarted_with_stopped_in_between() {
        // A `restarted` event whose nearest prior same-service event is
        // `stopped` (not `child_exited`) means the operator deliberately
        // stopped+started — NOT auto-recovery. Even if `child_exited`
        // appears earlier in the history, the `stopped` in between breaks
        // the chain.
        let now = datetime!(2026-05-23 12:00:00 UTC);
        let defs = vec![ngsm("A", StartupType::Automatic, Some(ServiceState::StartPending))];
        let events = vec![
            ev("A", now - time::Duration::minutes(10), EventKind::ChildExited, Some(1)),
            ev("A", now - time::Duration::minutes(8), EventKind::Stopped, None),
            ev("A", now - time::Duration::minutes(2), EventKind::Restarted, None),
        ];
        assert_eq!(
            compute_metrics(&defs, &events, now).auto_recovering,
            0,
            "restarted following stopped (even with earlier child_exited) is not auto-recovery"
        );
    }

    #[test]
    fn auto_recovering_isolated_per_service() {
        // A `stopped` or `child_exited` event for a DIFFERENT service must
        // not affect the classification of the target. The Restarted walk
        // filters by service name; this test pins that filter.
        let now = datetime!(2026-05-23 12:00:00 UTC);
        let defs = vec![
            ngsm("A", StartupType::Automatic, Some(ServiceState::StartPending)),
            ngsm("B", StartupType::Automatic, Some(ServiceState::Running)),
        ];
        // B's `stopped` is interleaved between A's `child_exited` and A's
        // `restarted`. A must still classify as auto_recovering because
        // B's event is unrelated.
        let events = vec![
            ev("A", now - time::Duration::minutes(3), EventKind::ChildExited, Some(1)),
            ev("B", now - time::Duration::minutes(2) - time::Duration::seconds(30), EventKind::Stopped, None),
            ev("A", now - time::Duration::minutes(2), EventKind::Restarted, None),
        ];
        let m = compute_metrics(&defs, &events, now);
        assert_eq!(
            m.auto_recovering, 1,
            "A's auto_recovering classification must ignore B's interleaved stopped event"
        );
    }

    #[test]
    fn availability_100_when_no_events() {
        let m = compute_metrics(&[], &[], datetime!(2026-05-23 12:00:00 UTC));
        assert!((m.availability_pct - 100.0).abs() < 0.01);
        assert_eq!(m.availability_window_days, 30);
    }

    #[test]
    fn availability_100_for_continuously_running_service() {
        let now = datetime!(2026-05-23 12:00:00 UTC);
        let defs = vec![ngsm("A", StartupType::Automatic, Some(ServiceState::Running))];
        let events = vec![ev("A", now - time::Duration::days(7), EventKind::Started, None)];
        let m = compute_metrics(&defs, &events, now);
        assert!(
            (m.availability_pct - 100.0).abs() < 0.1,
            "got {}",
            m.availability_pct
        );
    }

    #[test]
    fn availability_reflects_brief_outage() {
        // 24h window; 1h down → 23/24 = ~95.83%
        let now = datetime!(2026-05-23 12:00:00 UTC);
        let defs = vec![ngsm("A", StartupType::Automatic, Some(ServiceState::Running))];
        let events = vec![
            ev("A", now - time::Duration::hours(24), EventKind::Started, None),
            ev("A", now - time::Duration::hours(5), EventKind::ChildExited, Some(1)),
            ev("A", now - time::Duration::hours(4), EventKind::Restarted, None),
        ];
        let m = compute_metrics(&defs, &events, now);
        assert!(
            (m.availability_pct - 95.83).abs() < 0.5,
            "got {}",
            m.availability_pct
        );
    }

    #[test]
    fn availability_aggregate_is_unweighted_mean() {
        // Two services: A always up, B up half the time.
        let now = datetime!(2026-05-23 12:00:00 UTC);
        let defs = vec![
            ngsm("A", StartupType::Automatic, Some(ServiceState::Running)),
            ngsm("B", StartupType::Automatic, Some(ServiceState::Stopped)),
        ];
        let events = vec![
            ev("A", now - time::Duration::days(2), EventKind::Started, None),
            ev("B", now - time::Duration::days(2), EventKind::Started, None),
            ev("B", now - time::Duration::days(1), EventKind::ChildExited, Some(0)),
        ];
        let m = compute_metrics(&defs, &events, now);
        // A=100, B=50 → mean 75
        assert!(
            (m.availability_pct - 75.0).abs() < 1.0,
            "got {}",
            m.availability_pct
        );
    }

    #[test]
    fn window_days_clamps_to_actual_history() {
        let now = datetime!(2026-05-23 12:00:00 UTC);
        let defs = vec![ngsm("A", StartupType::Automatic, Some(ServiceState::Running))];
        // Only 7d of history.
        let events = vec![ev("A", now - time::Duration::days(7), EventKind::Started, None)];
        let m = compute_metrics(&defs, &events, now);
        assert!(m.availability_window_days >= 7 && m.availability_window_days <= 8);
    }

    #[test]
    fn availability_open_interval_not_extended_when_state_not_running() {
        // The open-interval extension in build_up_intervals requires BOTH
        // state==Running AND last event is Started/Restarted. If state is
        // Stopped (or None), the open up_since must be discarded — not
        // extended to `now`. Otherwise a stopped service whose stop event
        // didn't reach the log would report 100% availability.
        let now = datetime!(2026-05-23 12:00:00 UTC);
        // Service has a Started event 2h ago but no matching close event,
        // AND the SCM currently reports it as Stopped (perhaps the stop
        // event hasn't reached the log yet, or was lost).
        let defs = vec![ngsm("A", StartupType::Automatic, Some(ServiceState::Stopped))];
        let events = vec![ev(
            "A",
            now - time::Duration::hours(2),
            EventKind::Started,
            None,
        )];
        let m = compute_metrics(&defs, &events, now);
        // The open interval must NOT be extended to now. With per-service
        // window = 2h and no closed intervals, up_ms = 0 → 0% availability.
        assert!(
            m.availability_pct < 1.0,
            "open interval was extended despite state != Running (got {}%)",
            m.availability_pct
        );
    }
}
