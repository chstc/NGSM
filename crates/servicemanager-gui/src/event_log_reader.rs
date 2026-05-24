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
/// the RFC 3339 ts field descending — newest first — to tolerate
/// out-of-order writes from clock skew between concurrent supervisors.
/// Caller is on the worker thread; this is allowed to do file I/O.
pub fn read_recent(max: usize) -> Vec<EventRecord> {
    let mut all: Vec<EventRecord> = Vec::new();
    for path in iter_log_paths() {
        parse_tail_into(&path, &mut all);
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

/// Maximum bytes scanned per log file. 2× the supervisor's rotation
/// threshold — a file larger than this is either a manual paste or a
/// rotation race, and the GUI must not be forced into multi-MB scans
/// every refresh. Over-cap files are tail-read (lose oldest records),
/// not error.
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Read every record across all retained log files whose parsed `ts`
/// is `>= since`, returned ascending by parsed `OffsetDateTime` (NOT by
/// the raw `ts` string — fractional seconds and non-Z offsets can lex-
/// sort differently from their chronological order).
///
/// `Err` indicates a real I/O failure (open succeeded, read failed
/// mid-stream). Missing files are NOT errors — they yield `Ok(empty)`.
/// Malformed lines and records with unparseable `ts` are silently
/// skipped. Per-file size capped at `MAX_FILE_BYTES`; over that, the
/// file is tail-read and the first (partial) line dropped.
pub fn read_since(since: time::OffsetDateTime) -> std::io::Result<Vec<EventRecord>> {
    use std::io::{BufRead, BufReader, Seek, SeekFrom};
    use time::format_description::well_known::Rfc3339;

    let mut parsed: Vec<(time::OffsetDateTime, EventRecord)> = Vec::new();

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
        let mut partial = false;
        if len > MAX_FILE_BYTES {
            file.seek(SeekFrom::Start(len - MAX_FILE_BYTES))?;
            partial = true;
        }
        let reader = BufReader::new(file);
        let mut lines = reader.lines();
        if partial {
            // The seek landed mid-line; drop the truncated first record.
            let _ = lines.next();
        }
        for line_res in lines {
            let line = line_res?; // I/O failure mid-read → propagate.
            if line.is_empty() {
                continue;
            }
            let Ok(rec) = serde_json::from_str::<EventRecord>(&line) else {
                continue;
            };
            let Ok(ts) = time::OffsetDateTime::parse(&rec.ts, &Rfc3339) else {
                continue;
            };
            if ts >= since {
                parsed.push((ts, rec));
            }
        }
    }

    // Sort by parsed instant — NOT the raw ts string. RFC 3339 with
    // fractional seconds or non-Z offsets parses correctly but does not
    // lex-sort chronologically, and downstream interval math depends on
    // true chronological order.
    parsed.sort_by_key(|(ts, _)| *ts);
    Ok(parsed.into_iter().map(|(_, rec)| rec).collect())
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
    fn read_since_filters_older_records() {
        let (_g, _dir) = isolate();
        write_active(&[
            r#"{"ts":"2026-04-01T00:00:00Z","service":"Old","event":"started","pid":1}"#,
            r#"{"ts":"2026-05-22T14:15:00Z","service":"New","event":"started","pid":2}"#,
        ]);
        let since = datetime!(2026-05-01 00:00:00 UTC);
        let out = read_since(since).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].service, "New");
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
}
