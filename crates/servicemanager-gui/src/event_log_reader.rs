//! Read recent supervisor-recorded events from
//! `%ProgramData%\NGSM\events.log` (+ rotated `events.log.N`).
//!
//! Records are returned **newest first**. Malformed lines are skipped
//! silently. The reader is best-effort: missing files, parse errors, and
//! I/O failures all collapse to "no events" — Recent Events MUST NOT
//! show error noise from a transient log problem.

use servicemanager_core::events::EventRecord;
use servicemanager_core::paths;

/// Build the full list of log paths to scan, oldest-first: rotated
/// backups `.N` down through `.1`, then the active log. Shared by
/// `read_recent` and `read_since` so a future change to the retention
/// scheme (or backup-naming) updates both readers at once and the panel
/// can never silently drop retained records again (see #13).
fn iter_log_paths() -> Vec<std::path::PathBuf> {
    (1..=paths::BACKUP_RETENTION_COUNT)
        .rev()
        .filter_map(|n| paths::events_log_backup_n(n).ok())
        .chain(paths::events_log().ok())
        .collect()
}

/// Read up to `max` most-recent records across every retained log file
/// (active + all rotated backups).
///
/// Reads only the trailing TAIL_BYTES from each file (rather than the
/// whole thing), so cost is bounded regardless of file size. Sorts by
/// parsed RFC 3339 instants descending — newest first — to tolerate
/// fractional seconds, non-Z offsets, and out-of-order writes from
/// clock skew between concurrent supervisors. Records with unparseable
/// timestamps are skipped, matching `read_since`.
/// Caller is on the worker thread; this is allowed to do file I/O.
pub fn read_recent(max: usize) -> Vec<EventRecord> {
    let mut all: Vec<EventRecord> = Vec::new();
    for path in iter_log_paths() {
        parse_tail_into(&path, &mut all);
    }
    let now = time::OffsetDateTime::now_utc();
    let mut parsed: Vec<(time::OffsetDateTime, EventRecord)> = all
        .into_iter()
        .filter_map(|rec| parse_rfc3339_ts(&rec.ts).ok().map(|ts| (ts, rec)))
        .filter(|(ts, _)| *ts <= now)
        .collect();
    parsed.sort_by(|(a, _), (b, _)| b.cmp(a));
    parsed.truncate(max);
    parsed.into_iter().map(|(_, rec)| rec).collect()
}

fn parse_rfc3339_ts(ts: &str) -> Result<time::OffsetDateTime, time::error::Parse> {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::parse(ts, &Rfc3339)
}

/// Read the last TAIL_BYTES of `path`, drop the first (possibly partial)
/// line when the seek landed mid-file, and JSON-parse every remaining
/// non-empty line into `out`. Malformed lines are silently skipped.
fn parse_tail_into(path: &std::path::Path, out: &mut Vec<EventRecord>) {
    const TAIL_BYTES: u64 = 64 * 1024;
    let Ok(mut f) = std::fs::File::open(path) else {
        return;
    };
    let Ok(meta) = f.metadata() else { return };
    let len = meta.len();
    if let Ok(records) = read_records(&mut f, len, TAIL_BYTES) {
        out.extend(records);
    }
}

fn read_records(
    reader: &mut (impl std::io::Read + std::io::Seek),
    len: u64,
    budget: u64,
) -> std::io::Result<Vec<EventRecord>> {
    let tail = crate::bounded_log::read_tail(reader, len, budget, false)?;
    Ok(tail
        .bytes
        .split(|b| *b == b'\n')
        .skip(usize::from(tail.partial))
        .filter_map(|line| serde_json::from_slice::<EventRecord>(line).ok())
        .collect())
}

/// Maximum bytes scanned per log file. 2× the supervisor's rotation
/// threshold — a file larger than this is either a manual paste or a
/// rotation race, and the GUI must not be forced into multi-MB scans
/// every refresh. Over-cap files are tail-read (lose oldest records),
/// not error.
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Read every record since `since`, plus the nearest older state record per
/// service to seed availability at the window boundary. Returns ascending
/// parsed `OffsetDateTime` order (NOT by
/// the raw `ts` string — fractional seconds and non-Z offsets can lex-
/// sort differently from their chronological order).
///
/// `Err` indicates a real I/O failure (open succeeded, read failed
/// mid-stream). Missing files are NOT errors — they yield `Ok(empty)`.
/// Malformed lines and records with unparseable `ts` are silently
/// skipped. Per-file size capped at `MAX_FILE_BYTES`; over that, the
/// file is tail-read and the first (partial) line dropped.
pub fn read_since(since: time::OffsetDateTime) -> std::io::Result<Vec<EventRecord>> {
    let mut records = Vec::new();

    // Scan oldest backup first (.N) through active. The final sort makes
    // file order irrelevant for correctness, but oldest-first keeps the
    // intermediate vector roughly time-ordered, which the sort handles
    // efficiently. Share the path list with `read_recent` so a retention
    // bump cannot regress one reader without the other (#13).
    let paths = iter_log_paths();

    for path in &paths {
        let mut file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        let len = file.metadata()?.len();
        records.extend(read_records(&mut file, len, MAX_FILE_BYTES)?);
    }
    Ok(history_window(
        records,
        since,
        time::OffsetDateTime::now_utc(),
    ))
}

fn history_window(
    records: Vec<EventRecord>,
    since: time::OffsetDateTime,
    now: time::OffsetDateTime,
) -> Vec<EventRecord> {
    let mut seeds =
        std::collections::HashMap::<String, (time::OffsetDateTime, usize, EventRecord)>::new();
    let mut parsed = Vec::new();
    for (order, rec) in records.into_iter().enumerate() {
        let Ok(ts) = parse_rfc3339_ts(&rec.ts) else {
            continue;
        };
        if ts > now {
            continue;
        }
        if ts >= since {
            parsed.push((ts, order, rec));
        } else if seeds
            .get(&rec.service)
            .is_none_or(|(previous, _, _)| ts >= *previous)
        {
            seeds.insert(rec.service.clone(), (ts, order, rec));
        }
    }
    parsed.extend(seeds.into_values());
    // Different spellings can identify the same Windows service. Preserve
    // source order on timestamp ties even when their seeds came from the map.
    parsed.sort_by_key(|(ts, order, _)| (*ts, *order));
    parsed.into_iter().map(|(_, _, rec)| rec).collect()
}

/// Convert an RFC 3339 UTC `ts` (as produced by the supervisor) into a
/// local `HH:MM:SS` string for display. Falls back to the first eight
/// characters of the input (or the empty string) on parse failure — the
/// timestamp display must never derail rendering.
pub fn format_local_hms(ts: &str) -> String {
    format_hms_with(ts, |instant| time::UtcOffset::local_offset_at(instant).ok())
}

fn format_hms_with(
    ts: &str,
    offset_at: impl FnOnce(time::OffsetDateTime) -> Option<time::UtcOffset>,
) -> String {
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;
    let Ok(parsed) = OffsetDateTime::parse(ts, &Rfc3339) else {
        return ts.chars().take(8).collect();
    };
    let local = parsed.to_offset(offset_at(parsed).unwrap_or(time::UtcOffset::UTC));
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

    #[test]
    fn history_seed_ties_keep_source_order_across_service_case_aliases() {
        let records: Vec<EventRecord> = [
            r#"{"ts":"2026-04-22T00:00:00Z","service":"CaseSvc","event":"started"}"#,
            r#"{"ts":"2026-04-22T00:00:00Z","service":"CASESVC","event":"stopped"}"#,
        ]
        .into_iter()
        .map(|json| serde_json::from_str(json).unwrap())
        .collect();
        let since = parse_rfc3339_ts("2026-04-23T00:00:00Z").unwrap();
        let now = parse_rfc3339_ts("2026-05-23T00:00:00Z").unwrap();
        for _ in 0..32 {
            let history = history_window(records.clone(), since, now);
            assert_eq!(history[0].event, EventKind::Started);
            assert_eq!(history[1].event, EventKind::Stopped);
        }
    }

    fn isolate() -> (std::sync::MutexGuard<'static, ()>, tempfile::TempDir) {
        let guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir_in(".").unwrap();
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

    #[test]
    fn read_recent_sorts_by_parsed_instant_not_string() {
        let (_g, _dir) = isolate();
        write_active(&[
            r#"{"ts":"2026-05-23T08:30:00Z","service":"base","event":"started","pid":1}"#,
            r#"{"ts":"2026-05-23T08:30:00.100Z","service":"fractional-newest","event":"started","pid":2}"#,
            r#"{"ts":"2026-05-23T09:00:00+01:00","service":"offset-oldest","event":"started","pid":3}"#,
        ]);
        let out = read_recent(50);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].service, "fractional-newest");
        assert_eq!(out[1].service, "base");
        assert_eq!(out[2].service, "offset-oldest");
    }

    #[test]
    fn read_recent_skips_records_with_unparseable_timestamps() {
        let (_g, _dir) = isolate();
        write_active(&[
            r#"{"ts":"NOT-A-DATE","service":"bad","event":"started","pid":1}"#,
            r#"{"ts":"2026-05-22T14:15:00Z","service":"good","event":"started","pid":2}"#,
        ]);
        let out = read_recent(50);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].service, "good");
    }

    use time::macros::datetime;

    fn write_backup_n(n: u8, lines: &[&str]) {
        let path = servicemanager_core::paths::events_log_backup_n(n).unwrap();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
    }

    #[test]
    fn read_since_returns_records_within_window_ascending() {
        let (_g, _dir) = isolate();
        write_active(&[
            r#"{"ts":"2026-05-22T14:15:02Z","service":"B","event":"started","pid":2}"#,
            r#"{"ts":"2026-05-22T14:15:00Z","service":"A","event":"started","pid":1}"#,
            r#"{"ts":"2026-05-22T14:15:05Z","service":"C","event":"started","pid":3}"#,
        ]);
        let since = datetime!(2026-05-22 14:15:00 UTC);
        let out = read_since(since).unwrap();
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].service, "A");
        assert_eq!(out[1].service, "B");
        assert_eq!(out[2].service, "C");
    }

    #[test]
    fn read_since_preserves_the_last_older_record_as_boundary_evidence() {
        let (_g, _dir) = isolate();
        write_active(&[
            r#"{"ts":"2026-04-01T00:00:00Z","service":"Old","event":"started","pid":1}"#,
            r#"{"ts":"2026-05-22T14:15:00Z","service":"New","event":"started","pid":2}"#,
        ]);
        let since = datetime!(2026-05-01 00:00:00 UTC);
        let out = read_since(since).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].service, "Old");
        assert_eq!(out[1].service, "New");
    }

    #[test]
    fn read_since_reads_all_four_backups_plus_active() {
        let (_g, _dir) = isolate();
        write_backup_n(
            4,
            &[r#"{"ts":"2026-05-20T00:00:00Z","service":"B4","event":"started","pid":1}"#],
        );
        write_backup_n(
            3,
            &[r#"{"ts":"2026-05-21T00:00:00Z","service":"B3","event":"started","pid":2}"#],
        );
        write_backup_n(
            2,
            &[r#"{"ts":"2026-05-22T00:00:00Z","service":"B2","event":"started","pid":3}"#],
        );
        write_backup_n(
            1,
            &[r#"{"ts":"2026-05-23T00:00:00Z","service":"B1","event":"started","pid":4}"#],
        );
        write_active(&[
            r#"{"ts":"2026-05-23T12:00:00Z","service":"Active","event":"started","pid":5}"#,
        ]);
        let since = datetime!(2026-05-19 00:00:00 UTC);
        let out = read_since(since).unwrap();
        assert_eq!(out.len(), 5);
        // Ascending by ts:
        assert_eq!(out[0].service, "B4");
        assert_eq!(out[1].service, "B3");
        assert_eq!(out[2].service, "B2");
        assert_eq!(out[3].service, "B1");
        assert_eq!(out[4].service, "Active");
    }

    #[test]
    fn read_since_skips_malformed_lines() {
        let (_g, _dir) = isolate();
        write_active(&[
            r#"{"ts":"2026-05-22T14:15:00Z","service":"A","event":"started","pid":1}"#,
            r#"GARBAGE"#,
            r#"{"ts":"NOT-A-DATE","service":"B","event":"started","pid":2}"#,
            r#"{"ts":"2026-05-22T14:15:05Z","service":"C","event":"started","pid":3}"#,
        ]);
        let since = datetime!(2026-01-01 00:00:00 UTC);
        let out = read_since(since).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].service, "A");
        assert_eq!(out[1].service, "C");
    }

    #[test]
    fn read_since_missing_files_yields_empty_ok() {
        let (_g, _dir) = isolate();
        let out = read_since(datetime!(2026-01-01 00:00:00 UTC)).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn read_since_sorts_by_parsed_instant_not_string() {
        // D2 regression: records with non-Z offsets parse correctly but
        // lex-sort differently from their chronological order.
        //   T1 = 2026-05-23T09:00:00+01:00  (08:00:00 UTC) — string lex-LARGER
        //   T2 = 2026-05-23T08:30:00Z      (08:30:00 UTC) — string lex-SMALLER
        // Instant order: T1 (08:00) < T2 (08:30). String order: T2 < T1.
        let (_g, _dir) = isolate();
        write_active(&[
            r#"{"ts":"2026-05-23T08:30:00Z","service":"second","event":"started","pid":1}"#,
            r#"{"ts":"2026-05-23T09:00:00+01:00","service":"first","event":"started","pid":2}"#,
        ]);
        let since = datetime!(2026-01-01 00:00:00 UTC);
        let out = read_since(since).unwrap();
        assert_eq!(out.len(), 2);
        // True instant order: first (08:00 UTC) before second (08:30 UTC).
        assert_eq!(out[0].service, "first");
        assert_eq!(out[1].service, "second");
    }

    #[test]
    fn read_recent_includes_records_from_backup_2() {
        // #13 regression: prior to the fix, `read_recent` only scanned
        // the active log + `.1`, so a record retained in `.2` (or
        // later) would silently vanish from the Recent Events panel.
        let (_g, _dir) = isolate();
        write_backup_n(
            2,
            &[r#"{"ts":"2026-05-20T00:00:00Z","service":"FromBackup2","event":"started","pid":1}"#],
        );
        // Active and `.1` deliberately left absent.
        let out = read_recent(50);
        assert!(
            out.iter().any(|r| r.service == "FromBackup2"),
            "read_recent must surface records retained in .2 (got {out:?})"
        );
    }

    #[test]
    fn read_recent_returns_newest_first_across_all_backups() {
        // Each retained backup contributes one record at a distinct
        // timestamp; `read_recent` must merge them and sort newest-first
        // across the full retention chain.
        let (_g, _dir) = isolate();
        write_backup_n(
            4,
            &[r#"{"ts":"2026-05-20T00:00:00Z","service":"B4","event":"started","pid":1}"#],
        );
        write_backup_n(
            3,
            &[r#"{"ts":"2026-05-21T00:00:00Z","service":"B3","event":"started","pid":2}"#],
        );
        write_backup_n(
            2,
            &[r#"{"ts":"2026-05-22T00:00:00Z","service":"B2","event":"started","pid":3}"#],
        );
        write_backup_n(
            1,
            &[r#"{"ts":"2026-05-23T00:00:00Z","service":"B1","event":"started","pid":4}"#],
        );
        write_active(&[
            r#"{"ts":"2026-05-23T12:00:00Z","service":"Active","event":"started","pid":5}"#,
        ]);
        let out = read_recent(50);
        assert_eq!(out.len(), 5);
        // Newest first across all five files:
        assert_eq!(out[0].service, "Active");
        assert_eq!(out[1].service, "B1");
        assert_eq!(out[2].service, "B2");
        assert_eq!(out[3].service, "B3");
        assert_eq!(out[4].service, "B4");
    }

    #[test]
    fn read_since_caps_file_size_with_tail_read() {
        // D7 regression: a file larger than MAX_FILE_BYTES must be
        // tail-read (oldest records silently lost), NOT errored.
        let (_g, _dir) = isolate();
        let path = servicemanager_core::paths::events_log().unwrap();
        let pad_line = "x".repeat(1024);
        let mut text = String::new();
        for _ in 0..(17 * 1024) {
            text.push_str(&pad_line);
            text.push('\n');
        }
        text.push_str(
            r#"{"ts":"2026-05-23T12:00:00Z","service":"tail","event":"started","pid":99}"#,
        );
        text.push('\n');
        std::fs::write(&path, text).unwrap();

        let out = read_since(datetime!(2026-01-01 00:00:00 UTC))
            .expect("over-cap file should tail-read, not error");
        // Pad lines are not valid JSON → skipped. The tail record survives.
        assert!(out.iter().any(|r| r.service == "tail"));
    }

    #[test]
    fn both_event_reader_budgets_stop_growing_unterminated_records() {
        for budget in [64 * 1024, MAX_FILE_BYTES] {
            for len in [10, budget * 2] {
                let mut reader = crate::bounded_log::tests::GrowingReader::default();
                assert!(read_records(&mut reader, len, budget).unwrap().is_empty());
                assert_eq!(reader.read, len.min(budget));
            }
        }
    }

    #[test]
    fn event_reader_handles_empty_truncated_and_partial_records() {
        use std::io::Cursor;
        let record = br#"{"ts":"2026-05-23T12:00:00Z","service":"A","event":"started"}"#;
        assert!(read_records(&mut Cursor::new(b""), 0, 64)
            .unwrap()
            .is_empty());
        let mut bytes = record.to_vec();
        bytes.extend_from_slice(b"\n{\"unfinished\":");
        let records = read_records(&mut Cursor::new(&bytes), 1000, 2000).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].service, "A");
        assert!(read_records(&mut Cursor::new(record), 1000, 64)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn history_keeps_only_nearest_seed_and_ignores_invalid_and_future_events() {
        let parse = |ts: &str, kind: &str| {
            serde_json::from_str::<EventRecord>(&format!(
                r#"{{"ts":"{ts}","service":"A","event":"{kind}"}}"#
            ))
            .unwrap()
        };
        let records = vec![
            parse("2026-04-01T00:00:00Z", "started"),
            parse("2026-04-20T00:00:00Z", "stopped"),
            parse("2026-05-10T00:00:00Z", "started"),
            parse("2026-06-01T00:00:00Z", "stopped"),
            parse("invalid", "stopped"),
        ];
        let out = history_window(
            records,
            datetime!(2026-05-01 0:00 UTC),
            datetime!(2026-05-23 0:00 UTC),
        );
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].event, EventKind::Stopped);
        assert_eq!(out[0].ts, "2026-04-20T00:00:00Z");
        assert_eq!(out[1].event, EventKind::Started);
    }

    #[test]
    fn local_time_uses_each_event_instant_and_falls_back_to_utc() {
        let offset = |instant: time::OffsetDateTime| {
            Some(
                time::UtcOffset::from_hms(
                    if instant.month() == time::Month::January {
                        -5
                    } else {
                        -4
                    },
                    0,
                    0,
                )
                .unwrap(),
            )
        };
        assert_eq!(format_hms_with("2026-01-10T12:00:00Z", offset), "07:00:00");
        assert_eq!(format_hms_with("2026-07-10T12:00:00Z", offset), "08:00:00");
        assert_eq!(
            format_hms_with("2026-07-10T12:00:00+01:00", |_| None),
            "11:00:00"
        );
        assert_eq!(
            format_hms_with("2026-07-10T12:00:00Z", |_| Some(time::UtcOffset::UTC)),
            "12:00:00"
        );
        assert_eq!(
            format_hms_with("garbage", |_| panic!("must not look up invalid date")),
            "garbage"
        );
    }
}
