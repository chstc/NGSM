//! Schema for NGSM's persistent supervisor event log.
//!
//! Each lifecycle event is one `EventRecord`. The on-disk encoding is
//! JSON Lines (one `serde_json::to_string(&record)` per line). The schema
//! is additive: optional fields skip serialization when `None`, so older
//! readers tolerate newer writers.

use serde::{Deserialize, Serialize};

/// Kind of lifecycle event recorded in `%ProgramData%\NGSM\events.log`.
///
/// **Schema evolution.** Variants of this enum are part of the persistent
/// on-disk schema. The on-disk records are physically retained no matter
/// what (they're plain JSON lines written by the supervisor), but the
/// derived `Deserialize` impl REJECTS any variant it does not know. So
/// when an older binary reads a log written by a newer one:
///
/// - Records carrying a known variant deserialize normally.
/// - Records carrying a new (unknown-to-this-binary) variant fail to
///   parse. The current reader layer (`event_log_reader::read_recent` /
///   `read_since`) catches that parse error and silently skips the
///   offending record — the line is still in the file, but no
///   reader-side code can interpret it until the binary is upgraded.
///
/// **Adding a variant.** Adding a new variant is a coordinated change:
/// writers and readers must both be aware of it, OR the enum must grow a
/// `#[serde(other)]` arm BEFORE the new variant is emitted in production,
/// so older readers can at least classify unknown variants as "other"
/// rather than dropping the whole record. We have deliberately not added
/// `#[serde(other)]` yet — the test below pins current behavior so
/// adding `#[serde(other)]` later is a deliberate, test-breaking change
/// rather than an accidental schema shift.
///
/// **RENAMING or REMOVING a variant is a breaking change** to the schema
/// — bump `EventRecord`-level versioning before doing so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Started,
    Stopped,
    ChildExited,
    Restarted,
    Throttled,
}

/// Reason the supervisor stopped. **Schema evolution rules match
/// [`EventKind`]** — unknown variants are rejected at deserialization
/// time and silently skipped by the GUI reader, the on-disk record
/// itself is preserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    ScmStop,
    // Additional variants (ScmShutdown, ScmPause) are intentionally
    // deferred — v1 always emits ScmStop. The enum exists now so the
    // schema is additive.
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRecord {
    /// RFC 3339 UTC, e.g. `"2026-05-22T14:15:32.103Z"`.
    pub ts: String,
    pub service: String,
    pub event: EventKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lived_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delay_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<StopReason>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_started_record_skips_none_fields() {
        let rec = EventRecord {
            ts: "2026-05-22T14:15:32Z".into(),
            service: "Rufus".into(),
            event: EventKind::Started,
            pid: Some(1234),
            exit_code: None,
            lived_ms: None,
            delay_ms: None,
            reason: None,
        };
        let line = serde_json::to_string(&rec).unwrap();
        assert_eq!(
            line,
            r#"{"ts":"2026-05-22T14:15:32Z","service":"Rufus","event":"started","pid":1234}"#
        );
        let parsed: EventRecord = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed, rec);
    }

    #[test]
    fn round_trip_child_exited_record() {
        let rec = EventRecord {
            ts: "2026-05-22T14:15:32Z".into(),
            service: "Rufus".into(),
            event: EventKind::ChildExited,
            pid: None,
            exit_code: Some(1),
            lived_ms: Some(800),
            delay_ms: None,
            reason: None,
        };
        let line = serde_json::to_string(&rec).unwrap();
        let parsed: EventRecord = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed, rec);
        assert!(line.contains(r#""event":"child_exited""#));
    }

    #[test]
    fn parses_stopped_with_reason() {
        let line = r#"{"ts":"2026-05-22T14:15:32Z","service":"Rufus","event":"stopped","reason":"scm_stop"}"#;
        let parsed: EventRecord = serde_json::from_str(line).unwrap();
        assert_eq!(parsed.event, EventKind::Stopped);
        assert_eq!(parsed.reason, Some(StopReason::ScmStop));
    }

    #[test]
    fn parses_record_with_unknown_extra_field() {
        // Older readers must tolerate newer writers. serde silently
        // ignores unknown fields by default; this test pins that.
        let line = r#"{"ts":"2026-05-22T14:15:32Z","service":"Rufus","event":"started","pid":1234,"future_field":"hi"}"#;
        let parsed: EventRecord = serde_json::from_str(line).unwrap();
        assert_eq!(parsed.event, EventKind::Started);
    }

    #[test]
    fn unknown_event_kind_record_fails_to_deserialize() {
        // Pins the current schema-evolution behavior documented on
        // `EventKind`: a record carrying a variant this binary does not
        // know fails to deserialize. The GUI's event log reader catches
        // this error and silently skips the offending line, so the file
        // retains the record but old readers cannot interpret it.
        //
        // If `#[serde(other)]` is later added to `EventKind`, this test
        // will start passing (the unknown variant will map to the
        // `Unknown` arm) — and that's the signal that the schema-evolution
        // policy has deliberately shifted from "skip" to "classify as
        // other".
        let line = r#"{"ts":"2026-05-23T12:00:00Z","service":"X","event":"future_variant"}"#;
        let parsed = serde_json::from_str::<EventRecord>(line);
        assert!(
            parsed.is_err(),
            "expected unknown EventKind to fail to deserialize, got {parsed:?}"
        );
    }

    #[test]
    fn unknown_stop_reason_record_fails_to_deserialize() {
        // Mirror of `unknown_event_kind_record_fails_to_deserialize` for
        // `StopReason`. Same evolution rules — same regression pin.
        let line = r#"{"ts":"2026-05-23T12:00:00Z","service":"X","event":"stopped","reason":"future_reason"}"#;
        let parsed = serde_json::from_str::<EventRecord>(line);
        assert!(
            parsed.is_err(),
            "expected unknown StopReason to fail to deserialize, got {parsed:?}"
        );
    }
}
