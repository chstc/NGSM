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
pub fn validate_service_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::InvalidConfig(
            "service name must not be empty".into(),
        ));
    }
    let len = name.chars().count();
    if len > MAX_SERVICE_NAME_LEN {
        return Err(Error::InvalidConfig(format!(
            "service name is {len} characters; the limit is {MAX_SERVICE_NAME_LEN}"
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
    if name.chars().count() > 255 {
        return Err(Error::InvalidConfig(format!(
            "hook {kind} name '{name}' exceeds 255 characters"
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
    // UNC: starts with \\ or //.
    if bytes.len() >= 2
        && (bytes[0] == b'\\' || bytes[0] == b'/')
        && (bytes[1] == b'\\' || bytes[1] == b'/')
    {
        return true;
    }
    // Drive-rooted: letter + ':' + slash.
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
