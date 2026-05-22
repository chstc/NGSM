//! Windows System event-log reader for Service Control Manager records.
//!
//! The Recent Events panel needs a feed of service lifecycle events that
//! survives restarts. The OS already records every service state change: the
//! Service Control Manager writes them to the **System** event log. This
//! module queries that log for the SCM provider's lifecycle records and parses
//! each into a typed [`ScmEvent`].

use std::ffi::c_void;

use servicemanager_core::{Error, Result};
use windows::core::PCWSTR;
use windows::Win32::System::EventLog::{
    EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection, EvtRender,
    EvtRenderEventXml, EVT_HANDLE,
};

use crate::handles::to_wide;

/// A Service Control Manager lifecycle record from the System event log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScmEvent {
    /// The service **display name** — SCM events carry the display name, not
    /// the service key name.
    pub service: String,
    pub kind: ScmEventKind,
    /// `YYYY-MM-DD HH:MM:SS`, UTC (the event log stores timestamps in UTC).
    /// Empty string when the event carries no usable `SystemTime` attribute —
    /// callers should treat an empty timestamp as "timestamp unavailable".
    pub timestamp: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScmEventKind {
    Started,
    Stopped,
    Terminated,
    StartFailed,
}

/// Parse one System-log event XML fragment (as produced by `EvtRender` with
/// `EvtRenderEventXml`) into an [`ScmEvent`]. Returns `None` when the event is
/// not a recognised SCM lifecycle record.
///
/// This is the riskiest code in R3 (see the design doc §11), so it is kept
/// pure and unit-tested rather than folded into the Win32 query loop.
pub fn parse_scm_event_xml(xml: &str) -> Option<ScmEvent> {
    let event_id: u32 = tag_text(xml, "EventID")?.parse().ok()?;
    // `<Data>` values in document order. For SCM lifecycle events param1 is
    // the service display name; for 7036, param2 is the state it entered.
    let params = extract_data_values(xml);
    let service = params.first()?.trim().to_string();
    if service.is_empty() {
        return None;
    }
    let kind = match event_id {
        7036 => match params.get(1).map(|s| s.trim().to_lowercase()).as_deref() {
            Some("running") => ScmEventKind::Started,
            Some("stopped") => ScmEventKind::Stopped,
            // paused / continued / other transitions are not surfaced.
            _ => return None,
        },
        7034 | 7031 => ScmEventKind::Terminated,
        7000 | 7009 | 7011 => ScmEventKind::StartFailed,
        _ => return None,
    };
    let timestamp = extract_attr(xml, "SystemTime")
        .map(format_iso_utc)
        .unwrap_or_default();
    Some(ScmEvent {
        service,
        kind,
        timestamp,
    })
}

/// Text content of the first `<tag ...>...</tag>` element.
///
/// NOTE: This relies on `EventID` appearing only in the `<System>` section of
/// OS-generated event XML — `<Data>` text content is XML-escaped, so it cannot
/// contain a literal `<EventID>`.
fn tag_text(xml: &str, tag: &str) -> Option<String> {
    let open = xml.find(&format!("<{tag}"))?;
    let content_start = xml[open..].find('>')? + open + 1;
    let close = xml[content_start..].find(&format!("</{tag}>"))? + content_start;
    Some(xml[content_start..close].trim().to_string())
}

/// Text content of every `<Data ...>...</Data>` element, in document order.
fn extract_data_values(xml: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(open) = rest.find("<Data") {
        let Some(gt_rel) = rest[open..].find('>') else {
            break;
        };
        let gt = open + gt_rel;
        // `<Data .../>` — self-closing, empty value.
        if rest[open..gt].ends_with('/') {
            out.push(String::new());
            rest = &rest[gt + 1..];
            continue;
        }
        let after = gt + 1;
        let Some(close_rel) = rest[after..].find("</Data>") else {
            break;
        };
        let close = after + close_rel;
        out.push(unescape_xml(rest[after..close].trim()));
        rest = &rest[close + "</Data>".len()..];
    }
    out
}

/// Value of the first `attr='...'` (or `attr="..."`) attribute.
fn extract_attr(xml: &str, attr: &str) -> Option<String> {
    let key = format!("{attr}=");
    let start = xml.find(&key)? + key.len();
    let quote = *xml.as_bytes().get(start)?;
    if quote != b'"' && quote != b'\'' {
        return None;
    }
    // The byte at `start` is `b'"'` or `b'\''` — single-byte ASCII — so `start + 1` is a valid char boundary.
    let value = &xml[start + 1..];
    let end = value.find(quote as char)?;
    Some(value[..end].to_string())
}

/// `2026-05-21T09:15:42.123Z` -> `2026-05-21 09:15:42`. The event log stores
/// UTC; this keeps the value honest and deterministic without timezone math.
fn format_iso_utc(iso: String) -> String {
    let core = iso.split('.').next().unwrap_or(&iso).trim_end_matches('Z');
    core.replacen('T', " ", 1)
}

/// Undo the five predefined XML entity escapes.
fn unescape_xml(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// RAII closer for an `EVT_HANDLE`. Only ever wraps handles returned by a
/// successful `Evt*` call, so the drop can close unconditionally.
struct EvtGuard(EVT_HANDLE);

impl Drop for EvtGuard {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from a successful Evt* call and is closed once.
        // Guard against an invalid handle for consistency with the other RAII
        // guards in this crate (`ScHandle`, `HandleGuard`).
        if !self.0.is_invalid() {
            unsafe {
                let _ = EvtClose(self.0);
            }
        }
    }
}

/// Read up to `max` recent Service Control Manager lifecycle records from the
/// Windows **System** event log, newest first. The query filters to the SCM
/// provider and the six lifecycle event IDs at the OS level, so the read stays
/// bounded and fast even though the System log is large.
pub fn read_scm_events(max: usize) -> Result<Vec<ScmEvent>> {
    if max == 0 {
        return Ok(Vec::new());
    }
    let query = "*[System[Provider[@Name='Service Control Manager'] and \
        (EventID=7036 or EventID=7034 or EventID=7031 or EventID=7000 or \
        EventID=7009 or EventID=7011)]]";
    let channel = to_wide("System");
    let query_w = to_wide(query);
    let flags = EvtQueryChannelPath.0 | EvtQueryReverseDirection.0;

    // SAFETY: a null session = the local machine; both PCWSTRs point at
    // NUL-terminated buffers that outlive the call.
    let results = unsafe {
        EvtQuery(
            EVT_HANDLE::default(),
            PCWSTR::from_raw(channel.as_ptr()),
            PCWSTR::from_raw(query_w.as_ptr()),
            flags,
        )
        .map_err(|e| Error::other(format!("EvtQuery(System): {e}")))?
    };
    let _results = EvtGuard(results);

    let mut out: Vec<ScmEvent> = Vec::new();
    // `EvtNext` (windows 0.58) writes the raw handle values into an `isize`
    // slice; each is wrapped in an `EVT_HANDLE` below before use.
    let mut batch: [isize; 16] = [0; 16];
    'outer: loop {
        let mut returned: u32 = 0;
        // SAFETY: `batch` is a valid array; `returned` is a valid out-pointer.
        let ok = unsafe { EvtNext(results, &mut batch, 0, 0, &mut returned).is_ok() };
        if !ok || returned == 0 {
            break; // ERROR_NO_MORE_ITEMS, or genuinely no records.
        }
        for &raw in batch.iter().take(returned as usize) {
            let evt = EVT_HANDLE(raw);
            // Guard every handle in the batch so none leaks, even past `max`.
            let _evt = EvtGuard(evt);
            if out.len() >= max {
                continue;
            }
            if let Some(xml) = render_event_xml(evt) {
                if let Some(parsed) = parse_scm_event_xml(&xml) {
                    out.push(parsed);
                }
            }
        }
        if out.len() >= max {
            break 'outer;
        }
    }
    Ok(out)
}

/// Render one event handle to its XML form. Returns `None` on any failure — a
/// single unreadable record must not abort the whole feed.
fn render_event_xml(event: EVT_HANDLE) -> Option<String> {
    let flags = EvtRenderEventXml.0;
    let mut used: u32 = 0;
    let mut props: u32 = 0;
    // Size probe: a null buffer makes EvtRender report the bytes needed. The
    // probe call returns an error (insufficient buffer); only `used` matters.
    // SAFETY: the documented size-probe form; `event` is a live handle.
    unsafe {
        let _ = EvtRender(
            EVT_HANDLE::default(),
            event,
            flags,
            0,
            None,
            &mut used,
            &mut props,
        );
    }
    if used == 0 {
        return None;
    }
    // `used` is a byte count; the XML is UTF-16, so allocate u16s.
    let mut buf: Vec<u16> = vec![0u16; (used as usize).div_ceil(2)];
    // SAFETY: `buf` spans `used` bytes, the size the probe requested.
    let ok = unsafe {
        EvtRender(
            EVT_HANDLE::default(),
            event,
            flags,
            used,
            Some(buf.as_mut_ptr() as *mut c_void),
            &mut used,
            &mut props,
        )
        .is_ok()
    };
    if !ok {
        return None;
    }
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Some(String::from_utf16_lossy(&buf[..end]))
}

#[cfg(test)]
mod tests {
    use super::*;

    const E_7036_RUNNING: &str = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Service Control Manager' Guid='{555908d1-a6d7-4695-8e1e-26931d2012f4}' EventSourceName='Service Control Manager'/><EventID Qualifiers='16384'>7036</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x8080000000000000</Keywords><TimeCreated SystemTime='2026-05-21T09:15:42.1234567Z'/><EventRecordID>900</EventRecordID><Correlation/><Execution ProcessID='800' ThreadID='1100'/><Channel>System</Channel><Computer>HOST</Computer><Security/></System><EventData><Data Name='param1'>Demo Worker A</Data><Data Name='param2'>running</Data><Binary>0102</Binary></EventData></Event>";

    const E_7036_STOPPED: &str = "<Event><System><Provider Name='Service Control Manager'/><EventID>7036</EventID><TimeCreated SystemTime='2026-05-21T10:00:00Z'/></System><EventData><Data Name='param1'>Demo Worker A</Data><Data Name='param2'>stopped</Data></EventData></Event>";

    const E_7034: &str = "<Event><System><Provider Name='Service Control Manager'/><EventID Qualifiers='49152'>7034</EventID><TimeCreated SystemTime='2026-05-21T11:30:05.5Z'/></System><EventData><Data Name='param1'>Demo Worker B</Data><Data Name='param2'>2</Data></EventData></Event>";

    const E_7000: &str = "<Event><System><Provider Name='Service Control Manager'/><EventID>7000</EventID><TimeCreated SystemTime='2026-05-21T08:00:00Z'/></System><EventData><Data Name='param1'>Demo Worker C</Data><Data Name='param2'>%%1058</Data></EventData></Event>";

    #[test]
    fn parse_7036_running_yields_started() {
        let e = parse_scm_event_xml(E_7036_RUNNING).expect("should parse");
        assert_eq!(e.service, "Demo Worker A");
        assert_eq!(e.kind, ScmEventKind::Started);
        assert_eq!(e.timestamp, "2026-05-21 09:15:42");
    }

    #[test]
    fn parse_7036_stopped_yields_stopped() {
        let e = parse_scm_event_xml(E_7036_STOPPED).expect("should parse");
        assert_eq!(e.service, "Demo Worker A");
        assert_eq!(e.kind, ScmEventKind::Stopped);
        assert_eq!(e.timestamp, "2026-05-21 10:00:00");
    }

    #[test]
    fn parse_7034_yields_terminated() {
        let e = parse_scm_event_xml(E_7034).expect("should parse");
        assert_eq!(e.service, "Demo Worker B");
        assert_eq!(e.kind, ScmEventKind::Terminated);
        assert_eq!(e.timestamp, "2026-05-21 11:30:05");
    }

    #[test]
    fn parse_7000_yields_start_failed() {
        let e = parse_scm_event_xml(E_7000).expect("should parse");
        assert_eq!(e.service, "Demo Worker C");
        assert_eq!(e.kind, ScmEventKind::StartFailed);
        assert_eq!(e.timestamp, "2026-05-21 08:00:00");
    }

    #[test]
    fn parse_unrelated_event_id_returns_none() {
        let xml = "<Event><System><EventID>1234</EventID></System><EventData><Data Name='param1'>X</Data></EventData></Event>";
        assert!(parse_scm_event_xml(xml).is_none());
    }

    #[test]
    fn parse_7036_paused_returns_none() {
        let xml = "<Event><System><EventID>7036</EventID><TimeCreated SystemTime='2026-05-21T10:00:00Z'/></System><EventData><Data Name='param1'>Demo Worker A</Data><Data Name='param2'>paused</Data></EventData></Event>";
        assert!(parse_scm_event_xml(xml).is_none());
    }

    #[test]
    fn parse_unescapes_xml_entities_in_service_name() {
        let xml = "<Event><System><EventID>7036</EventID><TimeCreated SystemTime='2026-05-21T10:00:00Z'/></System><EventData><Data Name='param1'>Ben &amp; Jerry Sync</Data><Data Name='param2'>running</Data></EventData></Event>";
        let e = parse_scm_event_xml(xml).expect("should parse");
        assert_eq!(e.service, "Ben & Jerry Sync");
    }

    #[test]
    fn parse_empty_service_name_returns_none() {
        let xml = "<Event><System><EventID>7036</EventID></System><EventData><Data Name='param1'></Data><Data Name='param2'>running</Data></EventData></Event>";
        assert!(parse_scm_event_xml(xml).is_none());
    }
}
