//! Read recent supervisor-recorded events from
//! `%ProgramData%\NGSM\events.log` (+ rotated `events.log.1`).
//!
//! Records are returned **newest first**. Malformed lines are skipped
//! silently. The reader is best-effort: missing files, parse errors, and
//! I/O failures all collapse to "no events" — Recent Events MUST NOT
//! show error noise from a transient log problem.

use servicemanager_core::events::EventRecord;
use servicemanager_core::paths;

/// Read up to `max` most-recent records across both log files.
/// Reads only the trailing TAIL_BYTES from each file (rather than the
/// whole thing), so cost is bounded regardless of file size. Sorts by
/// the RFC 3339 ts field descending — newest first — to tolerate
/// out-of-order writes from clock skew between concurrent supervisors.
/// Caller is on the worker thread; this is allowed to do file I/O.
pub fn read_recent(max: usize) -> Vec<EventRecord> {
    let active = paths::events_log().ok();
    let backup = paths::events_log_backup().ok();
    let mut all: Vec<EventRecord> = Vec::new();
    if let Some(b) = backup {
        parse_tail_into(&b, &mut all);
    }
    if let Some(a) = active {
        parse_tail_into(&a, &mut all);
    }
    // ts is RFC 3339 UTC — lexicographic order matches time order.
    all.sort_by(|a, b| b.ts.cmp(&a.ts));
    all.truncate(max);
    all
}

/// Read the last TAIL_BYTES of `path`, drop the first (possibly partial)
/// line when the seek landed mid-file, and JSON-parse every remaining
/// non-empty line into `out`. Malformed lines are silently skipped.
fn parse_tail_into(path: &std::path::Path, out: &mut Vec<EventRecord>) {
    use std::io::{Read, Seek, SeekFrom};
    const TAIL_BYTES: u64 = 64 * 1024;
    let Ok(mut f) = std::fs::File::open(path) else {
        return;
    };
    let Ok(meta) = f.metadata() else { return };
    let len = meta.len();
    let partial = len > TAIL_BYTES;
    if partial && f.seek(SeekFrom::Start(len - TAIL_BYTES)).is_err() {
        return;
    }
    let mut buf = Vec::with_capacity(TAIL_BYTES as usize);
    if f.read_to_end(&mut buf).is_err() {
        return;
    }
    let text = String::from_utf8_lossy(&buf);
    let mut lines = text.lines();
    // A mid-file seek leaves the first line truncated — drop it.
    if partial {
        let _ = lines.next();
    }
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Ok(rec) = serde_json::from_str::<EventRecord>(line) {
            out.push(rec);
        }
    }
}

/// Convert an RFC 3339 UTC `ts` (as produced by the supervisor) into a
/// local `HH:MM:SS` string for display. Falls back to the first eight
/// characters of the input (or the empty string) on parse failure — the
/// timestamp display must never derail rendering.
pub fn format_local_hms(ts: &str) -> String {
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;
    let Ok(parsed) = OffsetDateTime::parse(ts, &Rfc3339) else {
        return ts.chars().take(8).collect();
    };
    let local = match time::UtcOffset::current_local_offset() {
        Ok(off) => parsed.to_offset(off),
        Err(_) => parsed,
    };
    format!(
        "{:02}:{:02}:{:02}",
        local.hour(),
        local.minute(),
        local.second()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use servicemanager_core::events::{EventKind, EventRecord, StopReason};
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn isolate() -> (std::sync::MutexGuard<'static, ()>, tempfile::TempDir) {
        let guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("NGSM_PROGRAM_DATA_DIR", dir.path());
        (guard, dir)
    }

    fn write_active(lines: &[&str]) {
        let path = paths::events_log().unwrap();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
    }

    fn write_backup(lines: &[&str]) {
        let path = paths::events_log_backup().unwrap();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
    }

    #[test]
    fn returns_empty_when_log_is_missing() {
        let (_g, _dir) = isolate();
        let out = read_recent(50);
        assert!(out.is_empty());
    }

    #[test]
    fn returns_newest_first_within_active_file() {
        let (_g, _dir) = isolate();
        write_active(&[
            r#"{"ts":"2026-05-22T14:15:00Z","service":"A","event":"started","pid":1}"#,
            r#"{"ts":"2026-05-22T14:15:01Z","service":"A","event":"stopped","reason":"scm_stop"}"#,
            r#"{"ts":"2026-05-22T14:15:02Z","service":"B","event":"started","pid":2}"#,
        ]);
        let out = read_recent(50);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].event, EventKind::Started);
        assert_eq!(out[0].service, "B");
        assert_eq!(out[2].service, "A");
    }

    #[test]
    fn merges_backup_then_active_newest_first() {
        let (_g, _dir) = isolate();
        write_backup(&[
            r#"{"ts":"2026-05-22T14:10:00Z","service":"Old","event":"started","pid":1}"#,
        ]);
        write_active(&[
            r#"{"ts":"2026-05-22T14:15:00Z","service":"New","event":"started","pid":2}"#,
        ]);
        let out = read_recent(50);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].service, "New"); // newer is first
        assert_eq!(out[1].service, "Old");
    }

    #[test]
    fn malformed_lines_are_skipped_silently() {
        let (_g, _dir) = isolate();
        write_active(&[
            r#"{"ts":"2026-05-22T14:15:00Z","service":"A","event":"started","pid":1}"#,
            r#"this is not json"#,
            r#"{"ts":"2026-05-22T14:15:02Z","service":"B","event":"started","pid":2}"#,
            r#""#,
        ]);
        let out = read_recent(50);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn max_cap_is_honored() {
        let (_g, _dir) = isolate();
        let lines: Vec<String> = (0..20)
            .map(|i| {
                let rec = EventRecord {
                    ts: format!("2026-05-22T14:15:{i:02}Z"),
                    service: format!("S{i}"),
                    event: EventKind::Started,
                    pid: Some(i as u32),
                    exit_code: None,
                    lived_ms: None,
                    delay_ms: None,
                    reason: None,
                };
                serde_json::to_string(&rec).unwrap()
            })
            .collect();
        let refs: Vec<&str> = lines.iter().map(|s| s.as_str()).collect();
        write_active(&refs);
        let out = read_recent(5);
        assert_eq!(out.len(), 5);
        assert_eq!(out[0].service, "S19");
        assert_eq!(out[4].service, "S15");
    }

    #[test]
    fn reads_a_stopped_record_with_reason() {
        let (_g, _dir) = isolate();
        write_active(&[
            r#"{"ts":"2026-05-22T14:15:00Z","service":"A","event":"stopped","reason":"scm_stop"}"#,
        ]);
        let out = read_recent(50);
        assert_eq!(out[0].event, EventKind::Stopped);
        assert_eq!(out[0].reason, Some(StopReason::ScmStop));
    }

    #[test]
    fn format_local_hms_falls_back_on_garbage() {
        assert_eq!(format_local_hms("not a date"), "not a da");
        assert_eq!(format_local_hms(""), "");
    }

    #[test]
    fn format_local_hms_produces_8_chars_for_valid_input() {
        let s = format_local_hms("2026-05-22T14:15:32Z");
        assert_eq!(s.len(), 8);
        assert_eq!(&s[2..3], ":");
        assert_eq!(&s[5..6], ":");
    }

    #[test]
    fn tail_reads_only_recent_records_from_large_active_file() {
        let (_g, _dir) = isolate();
        let path = paths::events_log().unwrap();
        // Write 10k records — far more than fit in 64 KiB.
        let mut all_text = String::new();
        for i in 0..10_000 {
            let rec = EventRecord {
                ts: format!("2026-05-22T14:{:02}:{:02}Z", (i / 60) % 60, i % 60),
                service: format!("S{i}"),
                event: EventKind::Started,
                pid: Some(i as u32),
                exit_code: None,
                lived_ms: None,
                delay_ms: None,
                reason: None,
            };
            all_text.push_str(&serde_json::to_string(&rec).unwrap());
            all_text.push('\n');
        }
        std::fs::write(&path, &all_text).unwrap();
        let out = read_recent(50);
        assert_eq!(out.len(), 50);
        // The newest records (highest ts) must come first.
        assert_eq!(out[0].service, "S9999");
        // The tail window must have captured the very last records, not
        // the head ones.
        assert!(out[49].service.starts_with('S'));
        let last_idx: u32 = out[49].service[1..].parse().unwrap();
        assert!(
            last_idx > 9000,
            "tail did not capture recent records: got S{last_idx}"
        );
    }

    #[test]
    fn sorts_out_of_order_records_newest_first() {
        let (_g, _dir) = isolate();
        write_active(&[
            // Deliberately out of order in the file
            r#"{"ts":"2026-05-22T14:15:02Z","service":"middle","event":"started","pid":1}"#,
            r#"{"ts":"2026-05-22T14:15:00Z","service":"oldest","event":"started","pid":2}"#,
            r#"{"ts":"2026-05-22T14:15:05Z","service":"newest","event":"started","pid":3}"#,
        ]);
        let out = read_recent(50);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].service, "newest");
        assert_eq!(out[1].service, "middle");
        assert_eq!(out[2].service, "oldest");
    }
}
