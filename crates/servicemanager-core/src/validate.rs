//! Validation and escaping for caller-supplied strings.
//!
//! Service names and arguments arrive from the CLI, the GUI, and the broker
//! IPC surface. They are interpolated into registry paths and Windows
//! command lines, so they must be checked once, centrally, before any
//! privileged call uses them.

use crate::{Error, Result};

/// Maximum length the Windows SCM accepts for a service name. SCM rejects
/// anything longer, and the matching `Services\<name>` registry key is bound
/// by the same limit.
pub const MAX_SERVICE_NAME_LEN: usize = 256;

/// Validate a Windows service name before it is used to build a registry
/// path or passed to an SCM call.
///
/// Rejects empty names, names longer than the SCM limit, path separators
/// (which would let a name escape its `Services\<name>` subtree or confuse
/// `RegCreateKeyEx`), and NUL or other control characters (which can
/// truncate or corrupt the name as it crosses the Rust/Win32 boundary).
///
/// The length check counts UTF-16 code units, not Rust `char`s, because the
/// SCM limit is enforced on the wide-string the Win32 API receives. A non-BMP
/// character (e.g. an emoji) is one `char` but two UTF-16 code units, so a
/// char-count check would accept names the SCM will reject.
pub fn validate_service_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::InvalidConfig(
            "service name must not be empty".into(),
        ));
    }
    let len = name.encode_utf16().count();
    if len > MAX_SERVICE_NAME_LEN {
        return Err(Error::InvalidConfig(format!(
            "service name is {len} UTF-16 code units; the limit is {MAX_SERVICE_NAME_LEN}"
        )));
    }
    for ch in name.chars() {
        if ch == '\\' || ch == '/' {
            return Err(Error::InvalidConfig(format!(
                "service name '{name}' must not contain '\\' or '/'"
            )));
        }
        if ch.is_control() {
            return Err(Error::InvalidConfig(format!(
                "service name '{name}' must not contain control characters"
            )));
        }
    }
    Ok(())
}

/// Validate a hook event or action name before it is used as a registry
/// subkey name (`event`) or value name (`action`). `kind` is `"event"` or
/// `"action"` and only shapes the error message.
///
/// Rejects empty names, path separators (which would nest or escape the
/// `AppEvents` subtree), NUL/control characters, and absurdly long names —
/// all of which would otherwise round-trip incorrectly or silently lose the
/// hook.
pub fn validate_hook_component(name: &str, kind: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::InvalidConfig(format!(
            "hook {kind} name must not be empty"
        )));
    }
    let len = name.encode_utf16().count();
    if len > 255 {
        return Err(Error::InvalidConfig(format!(
            "hook {kind} name '{name}' is {len} UTF-16 code units; the limit is 255"
        )));
    }
    for ch in name.chars() {
        if ch == '\\' || ch == '/' {
            return Err(Error::InvalidConfig(format!(
                "hook {kind} name '{name}' must not contain '\\' or '/'"
            )));
        }
        if ch.is_control() {
            return Err(Error::InvalidConfig(format!(
                "hook {kind} name '{name}' must not contain control characters"
            )));
        }
    }
    Ok(())
}

/// Validate that a configured filesystem path is unambiguously absolute on
/// Windows.
///
/// A managed service's executable, working directory, and stdio paths run
/// with the service account's privileges. A relative path would be resolved
/// through that account's `PATH` / current directory (search-path
/// confusion), and a relative log path is ambiguous — so every such path
/// must be absolute. `field` names the offending field for the error.
///
/// "Absolute" here is stricter than `Path::is_absolute()`. On Windows the
/// stdlib treats drive-relative `\foo` as absolute even though its meaning
/// depends on the current process's drive. We require one of:
///
/// - A drive-letter prefix: `X:\...` or `X:/...` (letter, colon, slash).
/// - A UNC prefix: `\\server\share\...` or `//server/share/...`.
///
/// Drive-relative (`\foo`), drive-with-no-separator (`C:foo`), and any
/// non-rooted path (`foo`, `..\foo`) are rejected.
pub fn validate_absolute_path(field: &str, value: &str) -> Result<()> {
    if value.chars().any(|c| c.is_control()) {
        return Err(Error::InvalidConfig(format!(
            "{field} contains a control character (e.g. NUL, tab, newline); \
             these characters can truncate or corrupt the path as it crosses \
             the registry / Win32 / process-spawn boundaries"
        )));
    }
    if !is_unambiguously_absolute_windows(value) {
        return Err(Error::InvalidConfig(format!(
            "{field} must be an absolute path (e.g. C:\\path or \\\\server\\share\\path), \
             got '{value}'"
        )));
    }
    Ok(())
}

/// True if `value` is unambiguously absolute on Windows — either a
/// drive-rooted path (`X:\...` / `X:/...`) or a UNC path (`\\...` / `//...`).
fn is_unambiguously_absolute_windows(value: &str) -> bool {
    let bytes = value.as_bytes();
    // UNC: starts with \\ or // followed by NON-EMPTY server, separator,
    // and NON-EMPTY share — e.g., \\server\share\... or //srv/sh/...
    if bytes.len() >= 2
        && (bytes[0] == b'\\' || bytes[0] == b'/')
        && (bytes[1] == b'\\' || bytes[1] == b'/')
    {
        let rest = &bytes[2..];
        // Find the next separator — that's the end of the server name.
        let Some(server_end) = rest.iter().position(|b| *b == b'\\' || *b == b'/') else {
            return false; // no separator after server
        };
        if server_end == 0 {
            return false; // empty server name
        }
        let after_server = &rest[server_end + 1..];
        // The share is everything up to the next separator (or end).
        // It must be non-empty.
        let share_end = after_server
            .iter()
            .position(|b| *b == b'\\' || *b == b'/')
            .unwrap_or(after_server.len());
        return share_end > 0;
    }
    // Drive-rooted: letter + ':' + slash. (unchanged)
    if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
    {
        return true;
    }
    false
}

/// Quote a single argument for a Windows command line so that
/// `CommandLineToArgvW` (and therefore the service runner's own argument
/// parsing) recovers exactly the original string.
///
/// Implements the standard MSVCRT/`CommandLineToArgvW` quoting rules:
/// backslashes are only special immediately before a quote.
pub fn quote_windows_arg(arg: &str) -> String {
    let needs_quotes = arg.is_empty()
        || arg
            .chars()
            .any(|c| matches!(c, ' ' | '\t' | '\n' | '\u{0b}' | '"'));
    if !needs_quotes {
        return arg.to_string();
    }

    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                // Escape every pending backslash, plus the quote itself.
                for _ in 0..(backslashes * 2 + 1) {
                    out.push('\\');
                }
                backslashes = 0;
                out.push('"');
            }
            _ => {
                for _ in 0..backslashes {
                    out.push('\\');
                }
                backslashes = 0;
                out.push(c);
            }
        }
    }
    // Trailing backslashes precede the closing quote, so double them.
    for _ in 0..(backslashes * 2) {
        out.push('\\');
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_names() {
        for name in ["MyService", "svc_01", "Web Service", "name.with.dots"] {
            assert!(validate_service_name(name).is_ok(), "{name}");
        }
    }

    #[test]
    fn rejects_empty() {
        assert!(validate_service_name("").is_err());
    }

    #[test]
    fn rejects_path_separators() {
        assert!(validate_service_name("evil\\..\\Parameters").is_err());
        assert!(validate_service_name("a/b").is_err());
    }

    #[test]
    fn rejects_control_characters() {
        assert!(validate_service_name("bad\0name").is_err());
        assert!(validate_service_name("tab\tname").is_err());
    }

    #[test]
    fn rejects_overlong_names() {
        let long = "x".repeat(MAX_SERVICE_NAME_LEN + 1);
        assert!(validate_service_name(&long).is_err());
        let ok = "x".repeat(MAX_SERVICE_NAME_LEN);
        assert!(validate_service_name(&ok).is_ok());
    }

    #[test]
    fn service_name_emoji_is_counted_as_two_utf16_units() {
        // A non-BMP emoji (U+1F600) is one Rust `char` but two UTF-16 code
        // units. Build a name that lands exactly at MAX_SERVICE_NAME_LEN
        // UTF-16 units using 127 emoji (= 254 UTF-16 units) plus 2 ASCII
        // characters: total = 256 UTF-16 units, accepted.
        let emoji = "\u{1F600}";
        let at_limit: String = emoji.repeat(127) + "xx";
        assert_eq!(at_limit.encode_utf16().count(), MAX_SERVICE_NAME_LEN);
        assert!(
            validate_service_name(&at_limit).is_ok(),
            "name with {} UTF-16 units must be accepted",
            MAX_SERVICE_NAME_LEN
        );

        // Add one more emoji: now 256 + 2 = 258 UTF-16 units, must be
        // rejected. A char-count check (the previous buggy behaviour) would
        // see only 130 chars and incorrectly accept this.
        let over_limit: String = emoji.repeat(128) + "xx";
        assert_eq!(over_limit.encode_utf16().count(), MAX_SERVICE_NAME_LEN + 2);
        assert!(
            over_limit.chars().count() <= MAX_SERVICE_NAME_LEN,
            "test premise: char-count must be under the limit so we know we \
             caught a bug a char-count check would have missed"
        );
        let err = validate_service_name(&over_limit).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("UTF-16"),
            "error message should mention UTF-16 code units, got {msg:?}"
        );
    }

    #[test]
    fn hook_component_emoji_is_counted_as_two_utf16_units() {
        // hook component limit is 255 UTF-16 code units. 126 emoji
        // (= 252 units) + 3 ASCII = 255 units: accepted.
        let emoji = "\u{1F600}";
        let at_limit: String = emoji.repeat(126) + "xxx";
        assert_eq!(at_limit.encode_utf16().count(), 255);
        assert!(validate_hook_component(&at_limit, "event").is_ok());

        // One more emoji => 257 UTF-16 units: rejected, with a clear message.
        let over_limit: String = emoji.repeat(127) + "xxx";
        assert_eq!(over_limit.encode_utf16().count(), 257);
        assert!(
            over_limit.chars().count() <= 255,
            "test premise: char-count is under 255 so a char-count check \
             would have wrongly accepted this name"
        );
        let err = validate_hook_component(&over_limit, "event").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("UTF-16"),
            "error should mention UTF-16 code units, got {msg:?}"
        );
        assert!(
            msg.contains("255"),
            "error should mention the 255 limit, got {msg:?}"
        );
    }

    #[test]
    fn absolute_path_validation() {
        assert!(validate_absolute_path("Application", "C:\\app\\svc.exe").is_ok());
        assert!(validate_absolute_path("Application", "\\\\server\\share\\svc.exe").is_ok());
        assert!(validate_absolute_path("Application", "svc.exe").is_err());
        assert!(validate_absolute_path("Application", "bin\\svc.exe").is_err());
    }

    #[test]
    fn validate_absolute_path_accepts_drive_rooted_and_unc() {
        assert!(validate_absolute_path("p", r"C:\foo").is_ok());
        assert!(validate_absolute_path("p", "C:/foo").is_ok());
        assert!(validate_absolute_path("p", r"D:\path with spaces\file.exe").is_ok());
        assert!(validate_absolute_path("p", r"\\server\share\file").is_ok());
        assert!(validate_absolute_path("p", "//server/share/file").is_ok());
    }

    #[test]
    fn validate_absolute_path_rejects_drive_relative_and_relative() {
        // Drive-relative: depends on per-process CWD.
        assert!(validate_absolute_path("p", r"\foo").is_err());
        assert!(validate_absolute_path("p", "/foo").is_err());
        // Drive with no separator: relative to the per-drive CWD.
        assert!(validate_absolute_path("p", "C:foo").is_err());
        // Plain relative.
        assert!(validate_absolute_path("p", "foo").is_err());
        assert!(validate_absolute_path("p", r"..\foo").is_err());
        assert!(validate_absolute_path("p", "").is_err());
        // Single-char paths that look almost absolute.
        assert!(validate_absolute_path("p", "C").is_err());
        assert!(validate_absolute_path("p", "C:").is_err());
    }

    #[test]
    fn validate_absolute_path_rejects_malformed_unc() {
        // Just the double-backslash with no server.
        assert!(validate_absolute_path("p", r"\\").is_err());
        assert!(validate_absolute_path("p", "//").is_err());
        // Server but no separator after it.
        assert!(validate_absolute_path("p", r"\\server").is_err());
        assert!(validate_absolute_path("p", "//server").is_err());
        // Server + separator but no share.
        assert!(validate_absolute_path("p", r"\\server\").is_err());
        assert!(validate_absolute_path("p", "//server/").is_err());
    }

    #[test]
    fn validate_absolute_path_accepts_unc_with_share() {
        assert!(validate_absolute_path("p", r"\\server\share").is_ok());
        assert!(validate_absolute_path("p", r"\\server\share\sub\file.exe").is_ok());
        assert!(validate_absolute_path("p", "//server/share/file").is_ok());
    }

    #[test]
    fn validate_absolute_path_error_message_mentions_expected_shape() {
        let err = validate_absolute_path("Application", r"\foo").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Application"), "missing field name in {msg:?}");
        assert!(msg.contains("absolute"), "missing 'absolute' in {msg:?}");
        assert!(
            msg.contains(r"\foo") || msg.contains("\\foo"),
            "missing the offending value in {msg:?}"
        );
    }

    #[test]
    fn validate_absolute_path_rejects_embedded_nul() {
        let err = validate_absolute_path("Application", "C:\\app\\\0svc.exe").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("control character"),
            "expected control-character message, got {msg:?}"
        );
        assert!(
            msg.contains("Application"),
            "expected field name in {msg:?}"
        );
    }

    #[test]
    fn validate_absolute_path_rejects_tab_and_newline() {
        assert!(validate_absolute_path("Application", "C:\\app\\foo\tbar.exe").is_err());
        assert!(validate_absolute_path("Application", "C:\\app\\foo\nbar.exe").is_err());
        assert!(validate_absolute_path("Application", "C:\\app\\foo\rbar.exe").is_err());
    }

    #[test]
    fn validate_absolute_path_accepts_valid_drive_and_unc() {
        assert!(validate_absolute_path("Application", "C:\\app.exe").is_ok());
        assert!(validate_absolute_path("Application", "\\\\server\\share\\app.exe").is_ok());
    }

    #[test]
    fn quote_leaves_simple_args_untouched() {
        assert_eq!(quote_windows_arg("plain"), "plain");
        assert_eq!(quote_windows_arg("C:\\path\\file"), "C:\\path\\file");
    }

    #[test]
    fn quote_wraps_spaces() {
        assert_eq!(quote_windows_arg("has space"), "\"has space\"");
        assert_eq!(quote_windows_arg(""), "\"\"");
    }

    #[test]
    fn quote_escapes_quotes_and_backslashes() {
        assert_eq!(quote_windows_arg("a\"b"), "\"a\\\"b\"");
        // A path with a trailing backslash inside a quoted arg must double it.
        assert_eq!(
            quote_windows_arg("C:\\Program Files\\"),
            "\"C:\\Program Files\\\\\""
        );
    }
}
