//! Pure dashboard-metrics computation: classification counts and 30-day
//! availability. No I/O — caller passes already-loaded services + events
//! and a `now`. Every function is unit-tested.

use servicemanager_core::events::{EventKind, EventRecord};
use servicemanager_core::{ServiceDefinition, ServiceState, StartupType};
use std::collections::HashMap;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use windows::Win32::Globalization::{CompareStringOrdinal, CSTR_EQUAL};

type TimedEvent<'a> = (OffsetDateTime, &'a EventRecord);
type ServiceEvents<'a> = HashMap<&'a str, Vec<TimedEvent<'a>>>;

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
    /// 30 UTC-day buckets, oldest→newest, or empty for unknown coverage.
    /// Leading unobserved buckets are placeholders; the UI plots only the
    /// tail corresponding to `availability_window_days`.
    pub availability_daily: Vec<f32>,
    /// Conservative fleet coverage: every managed service needs a usable
    /// timeline and an unambiguous tail. I/O failure also makes it unknown.
    pub availability_unknown: bool,
}

/// Deterministic given inputs. Invalid and future records are excluded before
/// indexing or interval construction so they cannot shadow valid state.
pub fn compute_metrics(
    defs: &[ServiceDefinition],
    events: &[EventRecord],
    now: OffsetDateTime,
) -> DashboardMetrics {
    let mut events: Vec<_> = events
        .iter()
        .filter_map(|event| parse_ts(&event.ts).map(|ts| (ts, event)))
        .filter(|(ts, _)| *ts <= now)
        .collect();
    events.sort_by_key(|(ts, _)| *ts);
    let events = group_service_events(defs, &events, ordinal_name_eq);
    let counts = compute_counts(defs, &events, now);
    let window_start = now - time::Duration::days(30);
    let (timelines, unknown) = build_service_timelines(defs, &events, window_start, now);
    let avail = compute_availability(&timelines, window_start, now);
    let unknown = unknown || counts.total == 0;
    let daily = if unknown {
        Vec::new()
    } else {
        compute_daily_sparkline(&timelines, now)
    };
    DashboardMetrics {
        total: counts.total,
        running: counts.running,
        stopped: counts.stopped,
        manual_start: counts.manual_start,
        failed: counts.failed,
        auto_recovering: counts.auto_recovering,
        availability_pct: avail.aggregate_pct,
        availability_window_days: avail.window_days,
        availability_daily: daily,
        availability_unknown: unknown,
    }
}

fn ordinal_name_eq(left: &[u16], right: &[u16]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    // Both counted strings are bounded valid service names. Ordinal casing
    // follows Windows identity rules without linguistic multi-character folds.
    unsafe { CompareStringOrdinal(left, right, true) == CSTR_EQUAL }
}

fn group_service_events<'a>(
    defs: &'a [ServiceDefinition],
    events: &[TimedEvent<'a>],
    mut compare: impl FnMut(&[u16], &[u16]) -> bool,
) -> ServiceEvents<'a> {
    let names: Vec<_> = defs
        .iter()
        .filter(|def| def.is_managed())
        .map(|def| {
            (
                def.native.name.as_str(),
                def.native.name.encode_utf16().collect::<Vec<_>>(),
            )
        })
        .collect();
    let mut grouped = ServiceEvents::new();
    if names.is_empty() {
        return grouped;
    }
    let mut aliases: HashMap<&str, Option<&str>> =
        names.iter().map(|(name, _)| (*name, Some(*name))).collect();
    for &(ts, event) in events {
        let canonical = *aliases.entry(&event.service).or_insert_with(|| {
            let candidate: Vec<u16> = event.service.encode_utf16().take(257).collect();
            if candidate.is_empty() || candidate.len() > 256 {
                return None;
            }
            names
                .iter()
                .find(|(_, name)| compare(&candidate, name))
                .map(|(name, _)| *name)
        });
        if let Some(name) = canonical {
            grouped.entry(name).or_default().push((ts, event));
        }
    }
    grouped
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
    events: &ServiceEvents<'_>,
    window_start: OffsetDateTime,
    now: OffsetDateTime,
) -> (Vec<ServiceTimeline>, bool) {
    let mut out = Vec::new();
    let mut unknown = false;
    for def in defs.iter().filter(|d| d.is_managed()) {
        let svc = def.native.name.as_str();
        let Some(svc_events) = events.get(svc) else {
            unknown = true;
            continue;
        };
        let svc_window_start = svc_events[0].0.max(window_start);
        if svc_window_start >= now {
            unknown = true;
            continue;
        }
        let state = def.runtime.as_ref().map(|r| r.state);
        let (intervals, uncertain_tail) =
            build_up_intervals(svc_events, svc_window_start, now, state);
        unknown |= uncertain_tail;
        out.push(ServiceTimeline {
            window_start: svc_window_start,
            intervals,
        });
    }
    (out, unknown)
}

/// Build the list of up-intervals for one service across `[start, now]`.
/// A pre-window state seeds the boundary. Availability measures recorded child
/// lifetime, not whether a paused child is currently serving requests. Live-host
/// transitions therefore do not retroactively erase that lifetime. A stopped or
/// missing host with an unclosed start is ambiguous, not evidence of zero uptime.
fn build_up_intervals(
    events: &[(OffsetDateTime, &EventRecord)],
    start: OffsetDateTime,
    now: OffsetDateTime,
    state: Option<ServiceState>,
) -> (Vec<(OffsetDateTime, OffsetDateTime)>, bool) {
    let mut intervals: Vec<(OffsetDateTime, OffsetDateTime)> = Vec::new();
    let mut up_since: Option<OffsetDateTime> = None;
    for &(ts, rec) in events {
        let ts = ts.max(start);
        match rec.event {
            EventKind::Started | EventKind::Restarted => {
                if up_since.is_none() {
                    up_since = Some(ts.max(start));
                }
            }
            EventKind::ChildExited | EventKind::Stopped | EventKind::Throttled => {
                if let Some(s) = up_since.take() {
                    if ts > s {
                        intervals.push((s, ts));
                    }
                }
            }
        }
    }
    if let Some(s) = up_since {
        if matches!(
            state,
            Some(
                ServiceState::Running
                    | ServiceState::Paused
                    | ServiceState::PausePending
                    | ServiceState::ContinuePending
                    | ServiceState::StopPending
            )
        ) {
            if now > s {
                intervals.push((s, now));
            }
        } else {
            return (intervals, true);
        }
    }
    (intervals, false)
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

/// 30 daily availability buckets, oldest→newest, each 0..=100.
/// Reads from already-built `ServiceTimeline`s and clips each interval
/// into the day bucket — events in distant days still contribute to
/// today's bucket via the "up" interval they opened. Days with no
/// contributing service carry forward from the previous bucket. Leading
/// unobserved buckets are zero placeholders, excluded from the displayed chart.
fn compute_daily_sparkline(timelines: &[ServiceTimeline], now: OffsetDateTime) -> Vec<f32> {
    let mut out: Vec<f32> = Vec::with_capacity(30);
    // Day boundaries in UTC for stability. `today_start` = midnight UTC of
    // `now`'s date; today's bucket length is `now - today_start`.
    let today_start = now.replace_time(time::Time::MIDNIGHT);
    for i in (0..30).rev() {
        let day_start = today_start - time::Duration::days(i as i64);
        let day_end = (day_start + time::Duration::hours(24)).min(now);

        let mut ratios: Vec<f32> = Vec::new();
        for t in timelines {
            // A service only contributes to days its window covers.
            if t.window_start >= day_end {
                continue;
            }
            let effective_start = day_start.max(t.window_start);
            let bucket_len = (day_end - effective_start).whole_milliseconds().max(1) as f32;
            let up_ms = up_ms_in_window(&t.intervals, effective_start, day_end);
            ratios.push((up_ms / bucket_len * 100.0).clamp(0.0, 100.0));
        }

        let value = if ratios.is_empty() {
            *out.last().unwrap_or(&0.0)
        } else {
            ratios.iter().sum::<f32>() / ratios.len() as f32
        };
        out.push(value);
    }
    out
}

/// Build SVG path strings (`line`, `area`) for the 30-bucket sparkline,
/// rendered into a 100×28 viewBox to match the `StatCard.show-chart` mode.
/// Returns `("", "")` when `daily` is empty so the UI can hide the chart.
pub fn sparkline_paths(daily: &[f32]) -> (String, String) {
    if daily.is_empty() {
        return (String::new(), String::new());
    }
    let n = daily.len();
    let x = |i: usize| -> f32 {
        if n <= 1 {
            0.0
        } else {
            (i as f32) * (100.0 / (n - 1) as f32)
        }
    };
    let y = |v: f32| -> f32 { 28.0 - (v.clamp(0.0, 100.0) / 100.0) * 28.0 };

    let mut line = format!("M {:.2} {:.2}", x(0), y(daily[0]));
    for (i, v) in daily.iter().enumerate().skip(1) {
        line.push_str(&format!(" L {:.2} {:.2}", x(i), y(*v)));
    }
    let mut area = format!("M {:.2} 28 L {:.2} {:.2}", x(0), x(0), y(daily[0]));
    for (i, v) in daily.iter().enumerate().skip(1) {
        area.push_str(&format!(" L {:.2} {:.2}", x(i), y(*v)));
    }
    area.push_str(&format!(" L {:.2} 28 Z", x(n - 1)));
    (line, area)
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
    events: &ServiceEvents<'_>,
    now: OffsetDateTime,
) -> Counts {
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
        let last = events
            .get(def.native.name.as_str())
            .and_then(|events| events.last())
            .map(|(_, event)| event);
        if classify_failed(state, last, now) {
            c.failed += 1;
        }
        if classify_auto_recovering(state, last, now) {
            c.auto_recovering += 1;
        }
    }
    c
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
    let Some(ts) = parse_ts(&rec.ts) else {
        return false;
    };
    if ts > now {
        return false;
    }
    (now - ts) <= time::Duration::hours(24)
}

/// The supervisor stays SCM Running while waiting for a replacement child.
/// A recorded successful restart ends recovery. Permit a bounded scheduling
/// grace after a recorded delay, or five minutes for legacy records without it.
fn classify_auto_recovering(
    state: Option<ServiceState>,
    last: Option<&&EventRecord>,
    now: OffsetDateTime,
) -> bool {
    if !matches!(
        state,
        Some(ServiceState::Running | ServiceState::StartPending)
    ) {
        return false;
    }
    let Some(rec) = last else { return false };
    let Some(ts) = parse_ts(&rec.ts) else {
        return false;
    };
    if ts > now {
        return false;
    }
    let wait_ms = rec
        .delay_ms
        .map(|ms| ms.min(u32::MAX as u64).saturating_add(30_000))
        .unwrap_or(5 * 60 * 1000);
    rec.event == EventKind::Throttled && (now - ts).whole_milliseconds() <= i128::from(wait_ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use servicemanager_core::{
        NativeServiceConfig, ServiceDefinition, ServiceRuntimeState, ServiceType,
    };
    use time::macros::datetime;

    fn def(
        name: &str,
        image: &str,
        startup: StartupType,
        state: Option<ServiceState>,
    ) -> ServiceDefinition {
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
        def(
            name,
            &format!("C:\\NGSM\\ngsm.exe run-service {name}"),
            startup,
            state,
        )
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
    fn service_identity_case_aliases_share_recovery_and_uptime() {
        let now = datetime!(2026-05-23 12:00:00 UTC);
        let defs = [ngsm(
            "CaseSvc",
            StartupType::Manual,
            Some(ServiceState::Running),
        )];
        let mut throttle = ev(
            "CASESVC",
            now - time::Duration::minutes(5),
            EventKind::Throttled,
            None,
        );
        throttle.delay_ms = Some(600_000);
        let events = [
            ev(
                "CaseSvc",
                now - time::Duration::minutes(10),
                EventKind::Started,
                None,
            ),
            ev(
                "casesvc",
                now - time::Duration::minutes(5),
                EventKind::ChildExited,
                Some(7),
            ),
            throttle,
        ];
        let metrics = compute_metrics(&defs, &events, now);
        assert_eq!(metrics.auto_recovering, 1);
        assert!(!metrics.availability_unknown);
        assert!((metrics.availability_pct - 50.0).abs() < 0.001);
    }

    #[test]
    fn service_identity_non_ascii_aliases_keep_the_pre_window_seed() {
        let now = datetime!(2026-05-23 12:00:00 UTC);
        let defs = [ngsm(
            "\u{03a3}ervice",
            StartupType::Manual,
            Some(ServiceState::Stopped),
        )];
        let events = [
            ev(
                "\u{03c3}ervice",
                now - time::Duration::days(31),
                EventKind::Started,
                None,
            ),
            ev(
                "\u{03a3}ERVICE",
                now - time::Duration::days(1),
                EventKind::ChildExited,
                Some(7),
            ),
        ];
        let metrics = compute_metrics(&defs, &events, now);
        assert!(!metrics.availability_unknown);
        assert_eq!(metrics.failed, 1);
        assert!((metrics.availability_pct - 100.0 * 29.0 / 30.0).abs() < 0.001);
    }

    #[test]
    fn service_identity_does_not_merge_distinct_linguistic_spellings() {
        let now = datetime!(2026-05-23 12:00:00 UTC);
        let defs = [
            ngsm(
                "Stra\u{00df}e",
                StartupType::Manual,
                Some(ServiceState::Running),
            ),
            ngsm("STRASSE", StartupType::Manual, Some(ServiceState::Stopped)),
        ];
        let events = [
            ev(
                "STRA\u{00df}E",
                now - time::Duration::hours(1),
                EventKind::Started,
                None,
            ),
            ev(
                "strasse",
                now - time::Duration::hours(1),
                EventKind::ChildExited,
                Some(7),
            ),
        ];
        let metrics = compute_metrics(&defs, &events, now);
        assert_eq!(metrics.total, 2);
        assert_eq!(metrics.failed, 1);
        assert!(!metrics.availability_unknown);
        assert!((metrics.availability_pct - 50.0).abs() < 0.001);
    }

    #[test]
    fn service_identity_comparison_is_cached_per_distinct_event_spelling() {
        let now = datetime!(2026-05-23 12:00:00 UTC);
        let defs = [
            ngsm("CaseSvc", StartupType::Manual, Some(ServiceState::Running)),
            ngsm("OtherSvc", StartupType::Manual, Some(ServiceState::Stopped)),
        ];
        let events: Vec<_> = (0..200)
            .map(|index| {
                ev(
                    if index % 2 == 0 { "casesvc" } else { "unknown" },
                    now,
                    EventKind::Started,
                    None,
                )
            })
            .collect();
        let parsed: Vec<_> = events.iter().map(|event| (now, event)).collect();
        let mut comparisons = 0;
        let grouped = group_service_events(&defs, &parsed, |left, right| {
            comparisons += 1;
            ordinal_name_eq(left, right)
        });
        assert_eq!(grouped["CaseSvc"].len(), 100);
        assert!(!grouped.contains_key("OtherSvc"));
        assert_eq!(comparisons, 3);
        assert_eq!(events[0].service, "casesvc", "stored names stay unchanged");
    }

    #[test]
    fn availability_is_unknown_without_managed_service_history() {
        for state in [ServiceState::Running, ServiceState::Stopped] {
            let defs = [ngsm("A", StartupType::Manual, Some(state))];
            let metrics = compute_metrics(&defs, &[], datetime!(2026-05-23 12:00:00 UTC));
            assert!(
                metrics.availability_unknown,
                "missing history must not imply healthy availability for {state:?}"
            );
        }
    }

    #[test]
    fn running_supervisor_can_be_waiting_in_its_recorded_recovery_delay() {
        let now = datetime!(2026-05-23 12:00:00 UTC);
        let defs = [ngsm("A", StartupType::Manual, Some(ServiceState::Running))];
        for (age_ms, delay_ms) in [(500_i64, 1500_u64), (360_000, 600_000)] {
            let exited_at = now - time::Duration::milliseconds(age_ms);
            let mut throttle = ev("A", exited_at, EventKind::Throttled, None);
            throttle.delay_ms = Some(delay_ms);
            let events = [
                ev(
                    "A",
                    exited_at - time::Duration::seconds(2),
                    EventKind::Started,
                    None,
                ),
                ev("A", exited_at, EventKind::ChildExited, Some(7)),
                throttle,
            ];
            let metrics = compute_metrics(&defs, &events, now);
            assert_eq!(
                metrics.auto_recovering, 1,
                "SCM Running does not imply a live child during the {delay_ms}ms retry delay"
            );
        }
    }

    #[test]
    fn availability_retains_a_pre_window_start_as_state_evidence() {
        let now = datetime!(2026-05-23 12:00:00 UTC);
        let defs = [ngsm("A", StartupType::Manual, Some(ServiceState::Stopped))];
        let events = [
            ev(
                "A",
                now - time::Duration::days(31),
                EventKind::Started,
                None,
            ),
            ev("A", now - time::Duration::days(1), EventKind::Stopped, None),
        ];
        let metrics = compute_metrics(&defs, &events, now);
        let expected = 100.0 * 29.0 / 30.0;
        assert!(
            (metrics.availability_pct - expected).abs() < 0.001,
            "retained history should show 29 up days out of 30, got {}",
            metrics.availability_pct
        );
        assert_eq!(metrics.availability_window_days, 30);
    }

    #[test]
    fn paused_or_pending_snapshot_does_not_invent_historical_downtime() {
        let now = datetime!(2026-05-23 12:00:00 UTC);
        let events = [ev(
            "A",
            now - time::Duration::days(7),
            EventKind::Started,
            None,
        )];
        for state in [
            ServiceState::Paused,
            ServiceState::PausePending,
            ServiceState::ContinuePending,
            ServiceState::StopPending,
        ] {
            let defs = [ngsm("A", StartupType::Manual, Some(state))];
            let metrics = compute_metrics(&defs, &events, now);
            assert!(
                metrics.availability_unknown
                    || (metrics.availability_daily[27] - 100.0).abs() < 0.001,
                "{state:?} cannot retroactively erase observed uptime"
            );
        }
    }

    #[test]
    fn running_and_stopped_tally_only_managed() {
        let defs = vec![
            ngsm("A", StartupType::Manual, Some(ServiceState::Running)),
            ngsm("B", StartupType::Automatic, Some(ServiceState::Stopped)),
            // Native service: must NOT count.
            def(
                "Spooler",
                "C:\\Windows\\spoolsv.exe",
                StartupType::Automatic,
                Some(ServiceState::Running),
            ),
        ];
        let m = compute_metrics(&defs, &[], datetime!(2026-05-23 12:00:00 UTC));
        assert_eq!(m.total, 2);
        assert_eq!(m.running, 1);
        assert_eq!(m.stopped, 1);
    }

    #[test]
    fn manual_start_counts_only_stopped_manual() {
        let defs = vec![
            ngsm(
                "ManualStopped",
                StartupType::Manual,
                Some(ServiceState::Stopped),
            ),
            ngsm(
                "ManualRunning",
                StartupType::Manual,
                Some(ServiceState::Running),
            ),
            ngsm(
                "AutoStopped",
                StartupType::Automatic,
                Some(ServiceState::Stopped),
            ),
        ];
        let m = compute_metrics(&defs, &[], datetime!(2026-05-23 12:00:00 UTC));
        assert_eq!(m.manual_start, 1);
    }

    #[test]
    fn failed_requires_stopped_plus_recent_nonzero_exit() {
        let now = datetime!(2026-05-23 12:00:00 UTC);
        let defs = vec![ngsm(
            "A",
            StartupType::Automatic,
            Some(ServiceState::Stopped),
        )];
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
        let defs = vec![ngsm(
            "A",
            StartupType::Automatic,
            Some(ServiceState::Stopped),
        )];
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
        let defs = vec![ngsm(
            "A",
            StartupType::Automatic,
            Some(ServiceState::Running),
        )];
        let events = vec![ev(
            "A",
            now - time::Duration::minutes(2),
            EventKind::Throttled,
            None,
        )];
        assert_eq!(compute_metrics(&defs, &events, now).auto_recovering, 1);
    }

    #[test]
    fn successful_restart_clears_auto_recovery_after_child_exit() {
        let now = datetime!(2026-05-23 12:00:00 UTC);
        let defs = vec![ngsm(
            "A",
            StartupType::Automatic,
            Some(ServiceState::Running),
        )];
        let events = vec![
            ev(
                "A",
                now - time::Duration::minutes(3),
                EventKind::ChildExited,
                Some(1),
            ),
            ev(
                "A",
                now - time::Duration::minutes(2),
                EventKind::Restarted,
                None,
            ),
        ];
        assert_eq!(compute_metrics(&defs, &events, now).auto_recovering, 0);
    }

    #[test]
    fn auto_recovering_excluded_when_stopped_or_legacy_event_is_old() {
        let now = datetime!(2026-05-23 12:00:00 UTC);
        let defs = vec![ngsm(
            "A",
            StartupType::Automatic,
            Some(ServiceState::Stopped),
        )];
        let events = vec![ev(
            "A",
            now - time::Duration::minutes(2),
            EventKind::Throttled,
            None,
        )];
        assert_eq!(compute_metrics(&defs, &events, now).auto_recovering, 0);

        let running = vec![ngsm(
            "A",
            StartupType::Automatic,
            Some(ServiceState::Running),
        )];
        let old = vec![ev(
            "A",
            now - time::Duration::minutes(10),
            EventKind::Throttled,
            None,
        )];
        assert_eq!(compute_metrics(&running, &old, now).auto_recovering, 0);
    }

    #[test]
    fn future_dated_events_do_not_classify_failed_or_auto_recovering() {
        // D3 regression: an event with ts > now would have (now - ts)
        // be negative, which would trivially satisfy "within 24h" / "within
        // 5min". Both classifiers must guard against that.
        let now = datetime!(2026-05-23 12:00:00 UTC);
        let defs = vec![ngsm(
            "Skew",
            StartupType::Automatic,
            Some(ServiceState::Stopped),
        )];
        let future_exit = vec![ev(
            "Skew",
            now + time::Duration::minutes(10),
            EventKind::ChildExited,
            Some(1),
        )];
        let m = compute_metrics(&defs, &future_exit, now);
        assert_eq!(
            m.failed, 0,
            "future child_exited must not classify as failed"
        );

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
        let defs = vec![ngsm(
            "A",
            StartupType::Automatic,
            Some(ServiceState::StartPending),
        )];
        let events = vec![
            ev(
                "A",
                now - time::Duration::minutes(10),
                EventKind::ChildExited,
                Some(1),
            ),
            ev(
                "A",
                now - time::Duration::minutes(8),
                EventKind::Stopped,
                None,
            ),
            ev(
                "A",
                now - time::Duration::minutes(2),
                EventKind::Restarted,
                None,
            ),
        ];
        assert_eq!(
            compute_metrics(&defs, &events, now).auto_recovering,
            0,
            "restarted following stopped (even with earlier child_exited) is not auto-recovery"
        );
    }

    #[test]
    fn auto_recovering_isolated_per_service() {
        // Another service's stop must not clear A's outstanding retry delay.
        let now = datetime!(2026-05-23 12:00:00 UTC);
        let defs = vec![
            ngsm("A", StartupType::Automatic, Some(ServiceState::Running)),
            ngsm("B", StartupType::Automatic, Some(ServiceState::Running)),
        ];
        let events = vec![
            ev(
                "A",
                now - time::Duration::minutes(3),
                EventKind::ChildExited,
                Some(1),
            ),
            ev(
                "B",
                now - time::Duration::minutes(2) - time::Duration::seconds(30),
                EventKind::Stopped,
                None,
            ),
            ev(
                "A",
                now - time::Duration::minutes(2),
                EventKind::Throttled,
                None,
            ),
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
        let defs = vec![ngsm(
            "A",
            StartupType::Automatic,
            Some(ServiceState::Running),
        )];
        let events = vec![ev(
            "A",
            now - time::Duration::days(7),
            EventKind::Started,
            None,
        )];
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
        let defs = vec![ngsm(
            "A",
            StartupType::Automatic,
            Some(ServiceState::Running),
        )];
        let events = vec![
            ev(
                "A",
                now - time::Duration::hours(24),
                EventKind::Started,
                None,
            ),
            ev(
                "A",
                now - time::Duration::hours(5),
                EventKind::ChildExited,
                Some(1),
            ),
            ev(
                "A",
                now - time::Duration::hours(4),
                EventKind::Restarted,
                None,
            ),
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
            ev(
                "B",
                now - time::Duration::days(1),
                EventKind::ChildExited,
                Some(0),
            ),
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
        let defs = vec![ngsm(
            "A",
            StartupType::Automatic,
            Some(ServiceState::Running),
        )];
        // Only 7d of history.
        let events = vec![ev(
            "A",
            now - time::Duration::days(7),
            EventKind::Started,
            None,
        )];
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
        let defs = vec![ngsm(
            "A",
            StartupType::Automatic,
            Some(ServiceState::Stopped),
        )];
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

    #[test]
    fn daily_sparkline_has_30_entries() {
        let now = datetime!(2026-05-23 12:00:00 UTC);
        let defs = vec![ngsm(
            "A",
            StartupType::Automatic,
            Some(ServiceState::Running),
        )];
        let events = vec![ev(
            "A",
            now - time::Duration::days(30),
            EventKind::Started,
            None,
        )];
        let m = compute_metrics(&defs, &events, now);
        assert_eq!(m.availability_daily.len(), 30);
        for v in &m.availability_daily {
            assert!(*v >= 0.0 && *v <= 100.0);
        }
    }

    #[test]
    fn daily_sparkline_reflects_one_full_outage_day() {
        // A is up for the whole window EXCEPT all of day -3 (24h down).
        let now = datetime!(2026-05-23 12:00:00 UTC);
        let defs = vec![ngsm(
            "A",
            StartupType::Automatic,
            Some(ServiceState::Running),
        )];
        let events = vec![
            ev(
                "A",
                now - time::Duration::days(10),
                EventKind::Started,
                None,
            ),
            ev(
                "A",
                now - time::Duration::days(4),
                EventKind::ChildExited,
                Some(1),
            ),
            ev(
                "A",
                now - time::Duration::days(3),
                EventKind::Restarted,
                None,
            ),
        ];
        let m = compute_metrics(&defs, &events, now);
        // The dip day is somewhere in the middle of the sparkline; check that
        // *some* entry is well below 50% (proves a real outage drove a bucket
        // down, not the placeholder constant).
        let min = m
            .availability_daily
            .iter()
            .cloned()
            .fold(100.0f32, f32::min);
        // The 24h outage (noon-to-noon) straddles two midnight-UTC calendar-day
        // buckets, each showing ~50%.  50% is well below 100% (the flat
        // placeholder) and proves the real per-bucket computation is working.
        assert!(
            min <= 50.0,
            "sparkline did not record the outage; got {m:?}"
        );
    }

    #[test]
    fn daily_sparkline_carries_uptime_across_event_free_days() {
        // D1 regression: a service started 7 days ago and still running has
        // ZERO events in any of the intervening 6 day buckets. A naive
        // implementation that walks events PER bucket sees nothing and
        // returns 0% for those days. Correct implementation: build
        // intervals once and CLIP into each bucket — the 7-day-old "up"
        // interval covers all 7 buckets and should yield ~100% each.
        let now = datetime!(2026-05-23 12:00:00 UTC);
        let defs = vec![ngsm(
            "A",
            StartupType::Automatic,
            Some(ServiceState::Running),
        )];
        let events = vec![ev(
            "A",
            now - time::Duration::days(7),
            EventKind::Started,
            None,
        )];
        let m = compute_metrics(&defs, &events, now);
        // The last 7 buckets must all be ~100% (any one dropping to 0 means
        // the interval did not cross bucket boundaries — that's the D1 bug).
        let recent7 = &m.availability_daily[m.availability_daily.len() - 7..];
        for (i, v) in recent7.iter().enumerate() {
            assert!(
                *v > 95.0,
                "bucket -{} should be ~100% (continuously up), got {}",
                7 - i,
                v
            );
        }
    }

    #[test]
    fn sparkline_path_strings_are_well_formed() {
        let daily: Vec<f32> = (0..30).map(|i| (i as f32) * 3.0).collect();
        let (line, area) = sparkline_paths(&daily);
        assert!(line.starts_with("M "));
        assert!(area.starts_with("M "));
        assert!(area.ends_with(" Z"));
        // 30 points → 29 line segments plus the move; check the line is non-trivial.
        assert!(line.matches('L').count() >= 29);
    }

    #[test]
    fn sparkline_paths_handle_empty_input_gracefully() {
        let (line, area) = sparkline_paths(&[]);
        assert!(line.is_empty());
        assert!(area.is_empty());
    }

    #[test]
    fn coverage_is_unknown_for_invalid_future_only_or_partially_observed_fleets() {
        let now = datetime!(2026-05-23 12:00:00 UTC);
        let a = ngsm("A", StartupType::Manual, Some(ServiceState::Running));
        let mut invalid = ev("A", now, EventKind::Started, None);
        invalid.ts = "invalid".into();
        for events in [
            vec![invalid],
            vec![ev(
                "A",
                now + time::Duration::hours(1),
                EventKind::Started,
                None,
            )],
            vec![ev("A", now, EventKind::Started, None)],
        ] {
            let metrics = compute_metrics(std::slice::from_ref(&a), &events, now);
            assert!(metrics.availability_unknown);
            assert!(metrics.availability_daily.is_empty());
        }
        let events = [ev(
            "A",
            now - time::Duration::days(2),
            EventKind::Started,
            None,
        )];
        let metrics = compute_metrics(
            &[
                a,
                ngsm("B", StartupType::Manual, Some(ServiceState::Stopped)),
            ],
            &events,
            now,
        );
        assert!(metrics.availability_unknown);
        assert!(metrics.availability_daily.is_empty());
    }

    #[test]
    fn pre_window_down_state_and_exact_boundary_starts_have_full_window_coverage() {
        let now = datetime!(2026-05-23 12:00:00 UTC);
        let defs = [ngsm("A", StartupType::Manual, Some(ServiceState::Running))];
        let events = [
            ev(
                "A",
                now - time::Duration::days(35),
                EventKind::Stopped,
                None,
            ),
            ev(
                "A",
                now - time::Duration::days(15),
                EventKind::Restarted,
                None,
            ),
        ];
        let metrics = compute_metrics(&defs, &events, now);
        assert!(!metrics.availability_unknown);
        assert!((metrics.availability_pct - 50.0).abs() < 0.01);
        assert_eq!(metrics.availability_window_days, 30);
        for age in [30, 31] {
            let events = [ev(
                "A",
                now - time::Duration::days(age),
                EventKind::Started,
                None,
            )];
            let metrics = compute_metrics(&defs, &events, now);
            assert!(!metrics.availability_unknown);
            assert!((metrics.availability_pct - 100.0).abs() < 0.01);
            assert_eq!(metrics.availability_window_days, 30);
        }
    }

    #[test]
    fn future_events_cannot_shadow_current_failure_recovery_or_uptime() {
        let now = datetime!(2026-05-23 12:00:00 UTC);
        let running = [ngsm("A", StartupType::Manual, Some(ServiceState::Running))];
        let events = [
            ev("A", now - time::Duration::days(2), EventKind::Started, None),
            ev("A", now + time::Duration::days(1), EventKind::Stopped, None),
        ];
        assert_eq!(
            compute_metrics(&running, &events, now).availability_pct,
            100.0
        );
        let events = [
            ev(
                "A",
                now - time::Duration::seconds(1),
                EventKind::Throttled,
                None,
            ),
            ev(
                "A",
                now + time::Duration::days(1),
                EventKind::Restarted,
                None,
            ),
        ];
        assert_eq!(compute_metrics(&running, &events, now).auto_recovering, 1);
        let stopped = [ngsm("A", StartupType::Manual, Some(ServiceState::Stopped))];
        let events = [
            ev(
                "A",
                now - time::Duration::seconds(1),
                EventKind::ChildExited,
                Some(7),
            ),
            ev("A", now + time::Duration::days(1), EventKind::Started, None),
        ];
        assert_eq!(compute_metrics(&stopped, &events, now).failed, 1);
    }

    #[test]
    fn retry_delay_grace_is_bounded_and_ignore_or_restart_ends_recovery() {
        let now = datetime!(2026-05-23 12:00:00 UTC);
        let defs = [ngsm("A", StartupType::Manual, Some(ServiceState::Running))];
        for (age, expected) in [(10_000, 1), (40_001, 0)] {
            let mut throttle = ev(
                "A",
                now - time::Duration::milliseconds(age),
                EventKind::Throttled,
                None,
            );
            throttle.delay_ms = Some(10_000);
            assert_eq!(
                compute_metrics(&defs, &[throttle], now).auto_recovering,
                expected
            );
        }
        for event in [
            EventKind::ChildExited,
            EventKind::Restarted,
            EventKind::Started,
            EventKind::Stopped,
        ] {
            let events = [ev("A", now - time::Duration::seconds(1), event, Some(1))];
            assert_eq!(compute_metrics(&defs, &events, now).auto_recovering, 0);
        }
    }

    #[test]
    fn missing_close_is_unknown_instead_of_fabricated_history() {
        let now = datetime!(2026-05-23 12:00:00 UTC);
        for state in [Some(ServiceState::Stopped), None] {
            let defs = [ngsm("A", StartupType::Manual, state)];
            let events = [ev(
                "A",
                now - time::Duration::days(7),
                EventKind::Started,
                None,
            )];
            let metrics = compute_metrics(&defs, &events, now);
            assert!(metrics.availability_unknown);
            assert!(metrics.availability_daily.is_empty());
        }
    }
}
