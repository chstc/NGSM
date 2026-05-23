//! Schema for NGSM's persistent supervisor event log.
//!
//! Each lifecycle event is one `EventRecord`. The on-disk encoding is
//! JSON Lines (one `serde_json::to_string(&record)` per line). The schema
//! is additive: optional fields skip serialization when `None`, so older
//! readers tolerate newer writers.

use serde::{Deserialize, Serialize};

/// Kind of lifecycle event recorded in `%ProgramData%\NGSM\events.log`.
///
/// **Append-only.** Variants of this enum are part of the persistent
/// on-disk schema. New variants may be ADDED at the end safely — older
/// readers will silently skip lines containing the unknown variant
/// (acceptable degradation), but the records are NOT lost from the file.
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

/// Reason the supervisor stopped. **Append-only** — see [`EventKind`].
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
}
