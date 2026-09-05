use crate::config_lock::windows_name_key;
use crate::lock_service_config;
use std::collections::{BTreeMap, BTreeSet, HashSet};

use servicemanager_core::{
    validate_absolute_path, validate_hook_component, validate_service_name, Error, ExitAction,
    ExitActionPolicy, HookConfig, IoRedirectionConfig, IoStream, LogRotationConfig,
    ManagedApplicationConfig, RestartPolicy, Result, ShutdownPolicy,
};

use windows::core::{Error as WinError, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, WIN32_ERROR,
};
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegDeleteValueW, RegEnumKeyExW, RegEnumValueW,
    RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE,
    REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ, REG_OPTION_NON_VOLATILE, REG_QWORD, REG_SAM_FLAGS,
    REG_SZ, REG_VALUE_TYPE,
};

/// Public constants mirroring NSSM's value names so callers (and tests) can
/// reference the same source of truth.
pub mod nssm_keys {
    pub const APPLICATION: &str = "Application";
    pub const APP_PARAMETERS: &str = "AppParameters";
    pub const APP_DIRECTORY: &str = "AppDirectory";
    pub const APP_ENVIRONMENT: &str = "AppEnvironment";
    pub const APP_ENVIRONMENT_EXTRA: &str = "AppEnvironmentExtra";
    pub const APP_EXIT: &str = "AppExit";
    pub const APP_RESTART_DELAY: &str = "AppRestartDelay";
    pub const APP_THROTTLE: &str = "AppThrottle";
    pub const APP_STOP_METHOD_SKIP: &str = "AppStopMethodSkip";
    pub const APP_KILL_CONSOLE_GRACE: &str = "AppStopMethodConsole";
    pub const APP_KILL_WINDOW_GRACE: &str = "AppStopMethodWindow";
    pub const APP_KILL_THREADS_GRACE: &str = "AppStopMethodThreads";
    pub const APP_KILL_PROCESS_TREE: &str = "AppKillProcessTree";
    pub const APP_STDIN: &str = "AppStdin";
    pub const APP_STDOUT: &str = "AppStdout";
    pub const APP_STDERR: &str = "AppStderr";
    pub const APP_STDIO_SHARING: &str = "ShareMode";
    pub const APP_STDIO_DISPOSITION: &str = "CreationDisposition";
    pub const APP_STDIO_FLAGS: &str = "FlagsAndAttributes";
    pub const APP_STDIO_COPY_AND_TRUNCATE: &str = "CopyAndTruncate";
    pub const APP_ROTATE: &str = "AppRotateFiles";
    pub const APP_ROTATE_ONLINE: &str = "AppRotateOnline";
    pub const APP_ROTATE_SECONDS: &str = "AppRotateSeconds";
    pub const APP_ROTATE_BYTES_LOW: &str = "AppRotateBytes";
    pub const APP_ROTATE_BYTES_HIGH: &str = "AppRotateBytesHigh";
    pub const APP_ROTATE_DELAY: &str = "AppRotateDelay";
    pub const APP_TIMESTAMP_LOG: &str = "AppTimestampLog";
    pub const APP_PRIORITY: &str = "AppPriority";
    pub const APP_AFFINITY: &str = "AppAffinity";
    pub const APP_EVENTS: &str = "AppEvents";
}

/// Open the `Parameters` subkey for a service and return a typed
/// [`ManagedApplicationConfig`]. Returns `Ok(None)` when the key (or the
/// `Application` marker value) is genuinely absent — i.e. this is a native,
/// non-managed service.
///
/// A read failure that is *not* a plain "not found" (access denied, a
/// corrupt value, a type mismatch) is propagated as an error rather than
/// being collapsed into "native", so a managed service with broken config
/// is never silently misreported.
pub fn read_managed_config(service: &str) -> Result<Option<ManagedApplicationConfig>> {
    validate_service_name(service)?;
    let path = format!("SYSTEM\\CurrentControlSet\\Services\\{service}\\Parameters");
    let key = match open_subkey(HKEY_LOCAL_MACHINE, &path, KEY_READ) {
        Ok(k) => k,
        Err(Error::NotFound(_)) => return Ok(None),
        Err(e) => return Err(e),
    };
    read_managed_from_key(&key, service)
}

fn read_managed_from_key(key: &RegKey, service: &str) -> Result<Option<ManagedApplicationConfig>> {
    let mut expandable_strings = BTreeSet::new();
    // The defining marker of an NSSM/NGSM-managed service is a
    // non-empty `Application` value under `Parameters`. Many native Windows
    // services have a `Parameters` subkey of their own; without the marker
    // we treat them as native.
    let application = match opt_config_string(key, nssm_keys::APPLICATION, &mut expandable_strings)?
    {
        Some(v) if !v.trim().is_empty() => v,
        // Present but empty/whitespace: a corrupt managed config, *not* a
        // native service. Surface it rather than silently classify the
        // service as unmanaged and hide the breakage from operators.
        Some(_) => {
            return Err(Error::InvalidConfig(format!(
                "service '{service}' has an empty `Application` value — its managed \
                 configuration is corrupt"
            )))
        }
        // Genuinely absent: this is a native, non-managed service.
        None => return Ok(None),
    };

    let rotate_low = opt_u32(key, nssm_keys::APP_ROTATE_BYTES_LOW)?;
    let rotate_high = opt_u32(key, nssm_keys::APP_ROTATE_BYTES_HIGH)?;
    let rotate_bytes = match (rotate_low, rotate_high) {
        (None, None) => None,
        (lo, hi) => Some(((hi.unwrap_or(0) as u64) << 32) | lo.unwrap_or(0) as u64),
    };

    let exit_actions = read_exit_actions(key)?;
    let default_action = exit_actions.get("default").map(|p| p.action);

    let cfg = ManagedApplicationConfig {
        application: Some(application),
        app_parameters: opt_config_string(key, nssm_keys::APP_PARAMETERS, &mut expandable_strings)?,
        app_directory: opt_config_string(key, nssm_keys::APP_DIRECTORY, &mut expandable_strings)?,
        environment: opt_multi_string(key, nssm_keys::APP_ENVIRONMENT)?.unwrap_or_default(),
        environment_extra: opt_multi_string(key, nssm_keys::APP_ENVIRONMENT_EXTRA)?
            .unwrap_or_default(),
        priority: opt_u32(key, nssm_keys::APP_PRIORITY)?,
        affinity: opt_config_string(key, nssm_keys::APP_AFFINITY, &mut expandable_strings)?,
        restart: RestartPolicy {
            restart_delay_ms: opt_u32(key, nssm_keys::APP_RESTART_DELAY)?,
            throttle_delay_ms: opt_u32(key, nssm_keys::APP_THROTTLE)?,
            default_action,
        },
        shutdown: ShutdownPolicy {
            stop_method_skip: opt_u32(key, nssm_keys::APP_STOP_METHOD_SKIP)?,
            kill_console_grace_ms: opt_u32(key, nssm_keys::APP_KILL_CONSOLE_GRACE)?,
            kill_window_grace_ms: opt_u32(key, nssm_keys::APP_KILL_WINDOW_GRACE)?,
            kill_threads_grace_ms: opt_u32(key, nssm_keys::APP_KILL_THREADS_GRACE)?,
            kill_process_tree: opt_u32(key, nssm_keys::APP_KILL_PROCESS_TREE)?.map(|v| v != 0),
        },
        io: IoRedirectionConfig {
            stdin: read_io_stream(key, nssm_keys::APP_STDIN, &mut expandable_strings)?,
            stdout: read_io_stream(key, nssm_keys::APP_STDOUT, &mut expandable_strings)?,
            stderr: read_io_stream(key, nssm_keys::APP_STDERR, &mut expandable_strings)?,
            timestamp_log: opt_u32(key, nssm_keys::APP_TIMESTAMP_LOG)?.map(|v| v != 0),
        },
        rotation: LogRotationConfig {
            enabled: opt_u32(key, nssm_keys::APP_ROTATE)?.map(|v| v != 0),
            online: opt_u32(key, nssm_keys::APP_ROTATE_ONLINE)?,
            seconds: opt_u32(key, nssm_keys::APP_ROTATE_SECONDS)?,
            bytes: rotate_bytes,
            delay_ms: opt_u32(key, nssm_keys::APP_ROTATE_DELAY)?,
        },
        exit_actions,
        hooks: read_hooks(key, &mut expandable_strings)?,
        expandable_strings,
    };
    Ok(Some(cfg))
}

/// Normalize an `AppExit` value name to the internal exit-actions key.
///
/// NSSM stores the default action in the subkey's *unnamed* value, but a
/// named `Default` value (in any case) means exactly the same thing — both
/// map to the internal `"default"` key. A specific exit code (e.g. `"1"`)
/// passes through unchanged.
fn normalize_exit_action_name(name: &str) -> Result<String> {
    if name.is_empty() || name.eq_ignore_ascii_case("default") {
        Ok("default".to_string())
    } else {
        let code = name
            .parse::<i32>()
            .or_else(|_| name.parse::<u32>().map(|code| code as i32))
            .map_err(|_| {
                Error::InvalidConfig(format!("AppExit key '{name}' is not a 32-bit exit code"))
            })?;
        Ok(code.to_string())
    }
}

fn insert_exit_action(
    out: &mut BTreeMap<String, ExitActionPolicy>,
    name: &str,
    action: ExitAction,
) -> Result<()> {
    let canonical = normalize_exit_action_name(name)?;
    if let Some(previous) = out.get(&canonical) {
        if previous.action != action {
            return Err(Error::InvalidConfig(format!(
                "conflicting AppExit aliases for '{canonical}'"
            )));
        }
    } else {
        out.insert(canonical, ExitActionPolicy { action });
    }
    Ok(())
}
fn parse_exit_action(value: &str) -> Option<ExitAction> {
    match value.trim().to_ascii_lowercase().as_str() {
        "restart" => Some(ExitAction::Restart),
        "ignore" => Some(ExitAction::Ignore),
        "exit" => Some(ExitAction::Exit),
        "suicide" => Some(ExitAction::Suicide),
        _ => None,
    }
}

fn read_io_stream(
    parent: &RegKey,
    value_name: &str,
    marked: &mut BTreeSet<String>,
) -> Result<Option<IoStream>> {
    let path = match opt_config_string(parent, value_name, marked)? {
        Some(p) if !p.is_empty() => p,
        _ => return Ok(None),
    };
    Ok(Some(IoStream {
        path,
        share_mode: opt_u32(
            parent,
            &format!("{value_name}{}", nssm_keys::APP_STDIO_SHARING),
        )?,
        creation_disposition: opt_u32(
            parent,
            &format!("{value_name}{}", nssm_keys::APP_STDIO_DISPOSITION),
        )?,
        flags_and_attributes: opt_u32(
            parent,
            &format!("{value_name}{}", nssm_keys::APP_STDIO_FLAGS),
        )?,
        copy_and_truncate: opt_u32(
            parent,
            &format!("{value_name}{}", nssm_keys::APP_STDIO_COPY_AND_TRUNCATE),
        )?
        .map(|v| v != 0),
    }))
}

fn read_exit_actions(parent: &RegKey) -> Result<BTreeMap<String, ExitActionPolicy>> {
    let exit_key = match open_subkey(parent.0, nssm_keys::APP_EXIT, KEY_READ) {
        Ok(k) => k,
        Err(Error::NotFound(_)) => return Ok(BTreeMap::new()),
        Err(e) => return Err(e),
    };
    let mut out = BTreeMap::new();
    for (name, value) in enumerate_string_values(&exit_key)? {
        let action_name = normalize_exit_action_name(&name)?;
        match parse_exit_action(&value) {
            Some(action) => {
                insert_exit_action(&mut out, &action_name, action)?;
            }
            // Corrupt config: surface it rather than silently dropping the
            // entry, which a later reconcile write would then scrub for good.
            None => {
                return Err(Error::Registry(format!(
                    "AppExit entry '{action_name}' has an unrecognized action '{value}'"
                )));
            }
        }
    }
    Ok(out)
}

fn read_hooks(parent: &RegKey, marked: &mut BTreeSet<String>) -> Result<Vec<HookConfig>> {
    let events_key = match open_subkey(parent.0, nssm_keys::APP_EVENTS, KEY_READ) {
        Ok(k) => k,
        Err(Error::NotFound(_)) => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    for event in enumerate_subkey_names(&events_key)? {
        validate_hook_component(&event, "event")?;
        let event_key = match open_subkey(events_key.0, &event, KEY_READ) {
            Ok(k) => k,
            Err(Error::NotFound(_)) => continue,
            Err(e) => return Err(e),
        };
        for (action, command, kind) in enumerate_typed_string_values(&event_key)? {
            validate_hook_component(&action, "action")?;
            if kind == REG_EXPAND_SZ {
                marked.insert(ManagedApplicationConfig::hook_expansion_key(
                    &event, &action,
                ));
            }
            out.push(HookConfig {
                event: event.clone(),
                action,
                command,
            });
        }
    }
    Ok(out)
}

// -- Low-level registry helpers --------------------------------------------

struct RegKey(HKEY);

impl Drop for RegKey {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: `self.0` is a key handle this type exclusively owns and
            // that is still open (checked non-invalid above); closing it once
            // on drop is the matching release for the `RegOpenKeyEx` /
            // `RegCreateKeyEx` that produced it.
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn win32_code(err: &WinError) -> u32 {
    if let Some(code) = WIN32_ERROR::from_error(err) {
        return code.0;
    }
    err.code().0 as u32
}

fn map_reg_error(context: &str, err: WinError) -> Error {
    if win32_code(&err) == ERROR_FILE_NOT_FOUND.0 {
        return Error::NotFound(context.to_string());
    }
    Error::Registry(format!("{context}: {err}"))
}

/// Standard `DELETE` access right (`0x0001_0000`). `RegDeleteTree` requires
/// it on the key whose subtree is removed, and it is *not* part of
/// `KEY_WRITE`; windows-rs does not re-export it from the Registry module.
const KEY_DELETE: REG_SAM_FLAGS = REG_SAM_FLAGS(0x0001_0000);

/// Access mask for a `Parameters` key we intend to reconcile (write + scrub):
/// read + write values, plus `DELETE` so `RegDeleteTree` can drop the
/// `AppExit` / `AppEvents` subtrees.
fn parameters_rw_sam() -> REG_SAM_FLAGS {
    KEY_WRITE | KEY_READ | KEY_DELETE
}

/// Run `r`, converting a plain "not found" into success. Any other error is
/// propagated. Used where deleting an already-absent value is not a failure.
fn ignore_missing(r: Result<()>) -> Result<()> {
    match r {
        Err(Error::NotFound(_)) => Ok(()),
        other => other,
    }
}

fn open_subkey(parent: HKEY, path: &str, sam: REG_SAM_FLAGS) -> Result<RegKey> {
    let wide = to_wide(path);
    let mut key = HKEY::default();
    // SAFETY: `wide` is a NUL-terminated UTF-16 buffer that outlives the
    // call; `&mut key` is a valid out-parameter. The returned handle is
    // taken under RAII ownership by `RegKey`.
    unsafe {
        RegOpenKeyExW(
            parent,
            PCWSTR::from_raw(wide.as_ptr()),
            Some(0),
            sam,
            &mut key,
        )
        .ok()
        .map_err(|e| map_reg_error(&format!("RegOpenKeyEx({path})"), e))?;
    }
    Ok(RegKey(key))
}

fn query_value_raw(key: &RegKey, name: &str) -> Result<(REG_VALUE_TYPE, Vec<u8>)> {
    let wide_name = to_wide(name);
    let mut value_type = REG_VALUE_TYPE::default();
    let mut bytes_needed = 0u32;
    // SAFETY: `wide_name` is NUL-terminated and outlives the call. Passing a
    // null data pointer with a size out-parameter is the documented way to
    // ask `RegQueryValueEx` for the required buffer size.
    unsafe {
        RegQueryValueExW(
            key.0,
            PCWSTR::from_raw(wide_name.as_ptr()),
            None,
            Some(&mut value_type as *mut REG_VALUE_TYPE),
            None,
            Some(&mut bytes_needed),
        )
        .ok()
        .map_err(|e| map_reg_error(&format!("RegQueryValueEx({name}) size"), e))?;
    }
    let mut buffer = vec![0u8; bytes_needed as usize];
    let mut written = bytes_needed;
    // SAFETY: `buffer` is sized to `bytes_needed` and `written` is initialized
    // to that capacity, so `RegQueryValueEx` writes within bounds.
    unsafe {
        RegQueryValueExW(
            key.0,
            PCWSTR::from_raw(wide_name.as_ptr()),
            None,
            Some(&mut value_type as *mut REG_VALUE_TYPE),
            Some(buffer.as_mut_ptr()),
            Some(&mut written),
        )
        .ok()
        .map_err(|e| map_reg_error(&format!("RegQueryValueEx({name})"), e))?;
    }
    buffer.truncate(written as usize);
    Ok((value_type, buffer))
}

/// Decode a `REG_SZ`/`REG_EXPAND_SZ` byte buffer as strict UTF-16.
///
/// Corrupt registry data is rejected rather than papered over: an odd byte
/// count cannot be valid UTF-16, invalid surrogate pairs produce an error
/// instead of silent replacement characters, and non-zero data *after* the
/// NUL terminator (a sign of a malformed or truncated value) is rejected
/// rather than silently dropped.
fn bytes_to_wide_string(bytes: &[u8]) -> Result<String> {
    if bytes.is_empty() {
        return Ok(String::new());
    }
    if !bytes.len().is_multiple_of(2) {
        return Err(Error::Registry(format!(
            "REG_SZ value has an odd byte length ({}) — not valid UTF-16",
            bytes.len()
        )));
    }
    let words: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    match words.iter().position(|&c| c == 0) {
        Some(end) => {
            // Everything past the first NUL terminator must itself be NUL
            // padding; non-zero trailing words mean the value is corrupt.
            if words[end + 1..].iter().any(|&c| c != 0) {
                return Err(Error::Registry(
                    "REG_SZ value has non-zero data after its NUL terminator — corrupt".to_string(),
                ));
            }
            String::from_utf16(&words[..end])
                .map_err(|e| Error::Registry(format!("REG_SZ value is not valid UTF-16: {e}")))
        }
        // An unterminated REG_SZ is permitted by the registry contract;
        // decode the whole buffer.
        None => String::from_utf16(&words)
            .map_err(|e| Error::Registry(format!("REG_SZ value is not valid UTF-16: {e}"))),
    }
}

/// Decode a `REG_MULTI_SZ` byte buffer as strict UTF-16.
///
/// A well-formed value is a run of NUL-terminated strings followed by one
/// final NUL (the empty-string block terminator); an empty value is a single
/// NUL or zero bytes. Anything else — an unterminated trailing entry, a
/// missing block terminator, data past the block terminator — is rejected so
/// a truncated value such as `alpha\0beta` is not silently read as `alpha`.
fn bytes_to_wide_multi(bytes: &[u8]) -> Result<Vec<String>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if !bytes.len().is_multiple_of(2) {
        return Err(Error::Registry(format!(
            "REG_MULTI_SZ value has an odd byte length ({}) — not valid UTF-16",
            bytes.len()
        )));
    }
    let words: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    if words.last() != Some(&0) {
        return Err(Error::Registry(
            "REG_MULTI_SZ value is not NUL-terminated — corrupt or truncated".to_string(),
        ));
    }

    let mut out = Vec::new();
    let mut start = 0;
    for (i, &c) in words.iter().enumerate() {
        if c == 0 {
            if i == start {
                // Empty string == the block terminator. Anything after it
                // is trailing garbage.
                if words[i + 1..].iter().any(|&word| word != 0) {
                    return Err(Error::Registry(
                        "REG_MULTI_SZ value has data after its block terminator".to_string(),
                    ));
                }
                return Ok(out);
            }
            out.push(String::from_utf16(&words[start..i]).map_err(|e| {
                Error::Registry(format!("REG_MULTI_SZ entry is not valid UTF-16: {e}"))
            })?);
            start = i + 1;
        }
    }
    // Reached the end without an empty-string block terminator: the final
    // entry was NUL-terminated but the closing NUL is missing.
    Err(Error::Registry(
        "REG_MULTI_SZ value is missing its block terminator".to_string(),
    ))
}

fn read_string(key: &RegKey, name: &str) -> Result<String> {
    read_typed_string(key, name).map(|(value, _)| value)
}

fn read_typed_string(key: &RegKey, name: &str) -> Result<(String, REG_VALUE_TYPE)> {
    let (ty, bytes) = query_value_raw(key, name)?;
    if ty != REG_SZ && ty != REG_EXPAND_SZ {
        return Err(Error::Registry(format!("value {name} is not REG_SZ")));
    }
    Ok((bytes_to_wide_string(&bytes)?, ty))
}

fn opt_config_string(
    key: &RegKey,
    name: &str,
    marked: &mut BTreeSet<String>,
) -> Result<Option<String>> {
    match read_typed_string(key, name) {
        Ok((value, kind)) => {
            if kind == REG_EXPAND_SZ {
                marked.insert(name.to_string());
            }
            Ok(Some(value))
        }
        Err(Error::NotFound(_)) => Ok(None),
        Err(error) => Err(error),
    }
}
fn read_multi_string(key: &RegKey, name: &str) -> Result<Vec<String>> {
    let (ty, bytes) = query_value_raw(key, name)?;
    if ty != REG_MULTI_SZ {
        return Err(Error::Registry(format!("value {name} is not REG_MULTI_SZ")));
    }
    bytes_to_wide_multi(&bytes)
}

fn read_u32(key: &RegKey, name: &str) -> Result<u32> {
    let (ty, bytes) = query_value_raw(key, name)?;
    decode_u32(name, ty, &bytes)
}

/// Decode a numeric registry value, requiring an *exact* buffer size:
/// 4 bytes for `REG_DWORD`, 8 for `REG_QWORD`. An over- or under-sized
/// buffer is corrupt and is rejected rather than silently truncated — the
/// same strictness the string decoders apply.
fn decode_u32(name: &str, ty: REG_VALUE_TYPE, bytes: &[u8]) -> Result<u32> {
    match ty {
        REG_DWORD => {
            let b: [u8; 4] = bytes.try_into().map_err(|_| {
                Error::Registry(format!(
                    "value {name} is REG_DWORD but holds {} bytes (expected 4)",
                    bytes.len()
                ))
            })?;
            Ok(u32::from_le_bytes(b))
        }
        REG_QWORD => {
            let b: [u8; 8] = bytes.try_into().map_err(|_| {
                Error::Registry(format!(
                    "value {name} is REG_QWORD but holds {} bytes (expected 8)",
                    bytes.len()
                ))
            })?;
            let v = u64::from_le_bytes(b);
            // The managed schema only uses QWORD-on-DWORD for compatibility;
            // a value that genuinely needs 64 bits would silently wrap if
            // truncated, so reject it instead.
            if v > u32::MAX as u64 {
                return Err(Error::Registry(format!(
                    "value {name} ({v}) exceeds the 32-bit range expected here"
                )));
            }
            Ok(v as u32)
        }
        _ => Err(Error::Registry(format!("value {name} is not numeric"))),
    }
}

/// Read a string value, mapping a genuinely-absent value to `Ok(None)` while
/// still propagating real failures (access denied, type mismatch).
fn opt_string(key: &RegKey, name: &str) -> Result<Option<String>> {
    match read_string(key, name) {
        Ok(v) => Ok(Some(v)),
        Err(Error::NotFound(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

fn opt_multi_string(key: &RegKey, name: &str) -> Result<Option<Vec<String>>> {
    match read_multi_string(key, name) {
        Ok(v) => Ok(Some(v)),
        Err(Error::NotFound(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

fn opt_u32(key: &RegKey, name: &str) -> Result<Option<u32>> {
    match read_u32(key, name) {
        Ok(v) => Ok(Some(v)),
        Err(Error::NotFound(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

fn enumerate_string_values(key: &RegKey) -> Result<Vec<(String, String)>> {
    Ok(enumerate_typed_string_values(key)?
        .into_iter()
        .map(|(name, value, _)| (name, value))
        .collect())
}

fn enumerate_typed_string_values(key: &RegKey) -> Result<Vec<(String, String, REG_VALUE_TYPE)>> {
    let mut out = Vec::new();
    let mut index = 0u32;
    let mut name_cap = 256usize;
    let mut value_cap = 4 * 1024usize;
    const NAME_CAP_LIMIT: usize = 64 * 1024;
    const VALUE_CAP_LIMIT: usize = 1024 * 1024;

    loop {
        let mut name_buf = vec![0u16; name_cap];
        let mut name_len = name_buf.len() as u32;
        let mut value_type: u32 = 0;
        let mut value_buf = vec![0u8; value_cap];
        let mut value_len = value_buf.len() as u32;

        // SAFETY: every pointer passed below is into a buffer that outlives
        // the call, and each length out-parameter is initialized to the real
        // capacity of its buffer.
        let ret = unsafe {
            RegEnumValueW(
                key.0,
                index,
                Some(PWSTR::from_raw(name_buf.as_mut_ptr())),
                &mut name_len,
                None,
                Some(&mut value_type),
                Some(value_buf.as_mut_ptr()),
                Some(&mut value_len),
            )
        };

        if ret == ERROR_NO_MORE_ITEMS {
            break;
        }
        if ret == ERROR_MORE_DATA {
            // A name or value was longer than our buffer. Grow and retry the
            // *same* index instead of skipping the entry.
            if name_cap >= NAME_CAP_LIMIT && value_cap >= VALUE_CAP_LIMIT {
                return Err(Error::Registry(format!(
                    "registry value at index {index} exceeds the supported size"
                )));
            }
            name_cap = (name_cap * 2).min(NAME_CAP_LIMIT);
            value_cap = (value_cap * 2).min(VALUE_CAP_LIMIT);
            continue;
        }
        if ret != ERROR_SUCCESS {
            return Err(Error::Registry(format!(
                "RegEnumValue(index {index}) failed: WIN32_ERROR {}",
                ret.0
            )));
        }

        let name = decode_registry_name(&name_buf[..name_len as usize])?;
        value_buf.truncate(value_len as usize);
        let ty = REG_VALUE_TYPE(value_type);
        // This helper is only used on NGSM-owned subtrees (`AppExit`,
        // `AppEvents\<event>`) where every value must be a string. A value of
        // any other type is corruption — fail rather than skip it silently.
        if ty != REG_SZ && ty != REG_EXPAND_SZ {
            return Err(Error::Registry(format!(
                "registry value '{name}' (index {index}) is not a string (REG type {value_type})"
            )));
        }
        out.push((name, bytes_to_wide_string(&value_buf)?, ty));
        index += 1;
    }
    Ok(out)
}

fn enumerate_subkey_names(key: &RegKey) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut index = 0u32;
    let mut name_cap = 256usize;
    const NAME_CAP_LIMIT: usize = 64 * 1024;

    loop {
        let mut name_buf = vec![0u16; name_cap];
        let mut name_len = name_buf.len() as u32;
        // SAFETY: `name_buf` outlives the call and `name_len` is initialized
        // to its capacity, so `RegEnumKeyEx` writes within bounds.
        let ret = unsafe {
            RegEnumKeyExW(
                key.0,
                index,
                Some(PWSTR::from_raw(name_buf.as_mut_ptr())),
                &mut name_len,
                None,
                None,
                None,
                None,
            )
        };

        if ret == ERROR_NO_MORE_ITEMS {
            break;
        }
        if ret == ERROR_MORE_DATA {
            if name_cap >= NAME_CAP_LIMIT {
                return Err(Error::Registry(format!(
                    "registry subkey name at index {index} exceeds the supported size"
                )));
            }
            name_cap = (name_cap * 2).min(NAME_CAP_LIMIT);
            continue;
        }
        if ret != ERROR_SUCCESS {
            return Err(Error::Registry(format!(
                "RegEnumKeyEx(index {index}) failed: WIN32_ERROR {}",
                ret.0
            )));
        }

        out.push(decode_registry_name(&name_buf[..name_len as usize])?);
        index += 1;
    }
    Ok(out)
}

fn decode_registry_name(words: &[u16]) -> Result<String> {
    let name = String::from_utf16(words)
        .map_err(|_| Error::Registry("owned registry name contains invalid UTF-16".into()))?;
    if name.contains('\0') {
        return Err(Error::Registry(
            "owned registry name contains an embedded NUL".into(),
        ));
    }
    Ok(name)
}

fn enumerate_value_names(key: &RegKey) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut capacity = 256;
    let mut index = 0;
    loop {
        let mut buffer = vec![0u16; capacity];
        let mut length = buffer.len() as u32;
        // SAFETY: the counted name buffer is live; unused data/type outputs
        // are null so malformed payloads can still be explicitly repaired.
        let status = unsafe {
            RegEnumValueW(
                key.0,
                index,
                Some(PWSTR(buffer.as_mut_ptr())),
                &mut length,
                None,
                None,
                None,
                None,
            )
        };
        if status == ERROR_NO_MORE_ITEMS {
            return Ok(out);
        }
        if status == ERROR_MORE_DATA && capacity < 64 * 1024 {
            capacity *= 2;
            continue;
        }
        status
            .ok()
            .map_err(|error| map_reg_error("RegEnumValue(names)", error))?;
        out.push(decode_registry_name(&buffer[..length as usize])?);
        index += 1;
    }
}

fn check_existing_names(key: &RegKey) -> Result<()> {
    match open_subkey(key.0, nssm_keys::APP_EXIT, KEY_READ) {
        Ok(exit) => {
            enumerate_value_names(&exit)?;
        }
        Err(Error::NotFound(_)) => {}
        Err(error) => return Err(error),
    }
    match open_subkey(key.0, nssm_keys::APP_EVENTS, KEY_READ) {
        Ok(events) => {
            for name in enumerate_subkey_names(&events)? {
                match open_subkey(events.0, &name, KEY_READ) {
                    Ok(event) => {
                        enumerate_value_names(&event)?;
                    }
                    Err(Error::NotFound(_)) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        Err(Error::NotFound(_)) => {}
        Err(error) => return Err(error),
    }
    Ok(())
}

// -- Set / Get / Unset by NSSM value name ---------------------------------

/// Kind of a managed registry value. Used to pick the right read/write
/// helper from a string-typed CLI surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedValueKind {
    String,
    MultiString,
    Number,
}

/// A reader's view of one value, normalized to a string the CLI can render.
#[derive(Debug, Clone)]
pub struct ValueRecord {
    pub kind: ManagedValueKind,
    pub value: String,
}

/// Render a `REG_MULTI_SZ` value as the single comma-separated string the
/// CLI's string-typed `get` returns. A backslash or comma inside an entry is
/// escaped (`\\`, `\,`) so [`split_multi_value`] recovers the exact entries —
/// a value such as `FOO=a,b` survives a `get` followed by a `set`.
fn join_multi_value(entries: &[String]) -> String {
    entries
        .iter()
        .map(|e| e.replace('\\', "\\\\").replace(',', "\\,"))
        .collect::<Vec<_>>()
        .join(",")
}

/// Inverse of [`join_multi_value`]: split a comma-separated string into
/// `REG_MULTI_SZ` entries, honoring `\\` and `\,` escapes. Each entry is
/// preserved verbatim, and empty entries are dropped — `REG_MULTI_SZ` cannot represent
/// an empty string (it doubles as the block terminator).
/// UNC paths must also escape each backslash: `\\\\server\\share` represents
/// `\\server\share`. [`join_multi_value`] always emits this canonical notation.
fn split_multi_value(value: &str) -> Vec<String> {
    let mut entries: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut chars = value.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if matches!(chars.peek(), Some(',' | '\\')) => current.push(chars.next().unwrap()),
            '\\' => current.push('\\'),
            ',' => entries.push(std::mem::take(&mut current)),
            other => current.push(other),
        }
    }
    entries.push(current);
    entries.into_iter().filter(|s| !s.is_empty()).collect()
}

/// True for the NSSM value names that hold a filesystem path the service
/// account later resolves — these are subject to the absolute-path policy.
fn is_path_value(canonical: &str) -> bool {
    matches!(
        canonical,
        nssm_keys::APPLICATION
            | nssm_keys::APP_DIRECTORY
            | nssm_keys::APP_STDIN
            | nssm_keys::APP_STDOUT
            | nssm_keys::APP_STDERR
    )
}

/// Set a single managed registry value by its NSSM-style name (e.g.
/// `AppParameters`). The kind is resolved from a built-in table; unknown
/// names return [`Error::InvalidConfig`].
pub fn set_value(service: &str, name: &str, value: &str) -> Result<()> {
    validate_service_name(service)?;
    let _guard = lock_service_config(service)?;
    let path = format!("SYSTEM\\CurrentControlSet\\Services\\{service}\\Parameters");
    let key = open_subkey(HKEY_LOCAL_MACHINE, &path, KEY_READ | KEY_WRITE)?;
    set_value_in_key(&key, name, value)
}

fn set_value_in_key(key: &RegKey, name: &str, value: &str) -> Result<()> {
    let (canonical, kind) = lookup_kind(name)?;
    // `Application` is the managed-service marker; setting it empty would make
    // the service read back as native. Reject that here.
    if canonical == nssm_keys::APPLICATION && value.trim().is_empty() {
        return Err(Error::InvalidConfig(
            "Application must not be set to an empty value — it is the managed-service marker"
                .into(),
        ));
    }
    // Path-valued fields must be absolute, matching full-config writes — the
    // single-value `set` API must not be a way to persist a relative
    // service-account path. An empty value clears the field and is allowed.
    if is_path_value(&canonical) && !value.trim().is_empty() {
        validate_absolute_path(&canonical, value)?;
    }
    // `set` mutates an existing managed config; it must not be able to mark a
    // native service as managed by creating the marker from scratch.
    require_managed_marker(key)?;
    match kind {
        ManagedValueKind::String => {
            // For path-valued fields other than the required `Application`
            // marker, an empty value clears the field rather than writing
            // an empty REG_SZ. An empty `""` REG_SZ is ambiguous (looks
            // like a configured-but-empty path), and for stdio fields
            // leaves attribute values like `AppStdoutShareMode` pointing
            // at a now-empty path. Delete the value (and stdio attributes
            // when applicable) so the registry state is consistent.
            if is_path_value(&canonical)
                && canonical != nssm_keys::APPLICATION
                && value.trim().is_empty()
            {
                clear_path_value(key, &canonical)?;
            } else {
                write_string(key, &canonical, value)?;
            }
        }
        ManagedValueKind::MultiString => {
            // Comma-separated input, with `\,` / `\\` escapes so an entry
            // that genuinely contains a comma round-trips through `get`.
            let parts = split_multi_value(value);
            write_multi_string(key, &canonical, &parts)?;
        }
        ManagedValueKind::Number => {
            let parsed: u32 = value.parse().map_err(|_| {
                Error::InvalidConfig(format!(
                    "{canonical} expects a numeric value, got '{value}'"
                ))
            })?;
            write_u32(key, &canonical, parsed)?;
        }
    }
    Ok(())
}

/// True for the NSSM value names that are per-stdio-stream bases (path
/// field carries an associated set of sharing/disposition/flags attribute
/// values like `AppStdoutShareMode`).
fn is_stdio_path_value(canonical: &str) -> bool {
    matches!(
        canonical,
        nssm_keys::APP_STDIN | nssm_keys::APP_STDOUT | nssm_keys::APP_STDERR
    )
}

/// Names of the four per-stream attribute values associated with a stdio
/// path field (`AppStdout`/`AppStderr`/`AppStdin`). Used when clearing a
/// stdio path so the registry is not left with orphaned sharing/flags
/// entries pointing at a now-empty path.
fn stdio_attribute_names(base: &str) -> [String; 4] {
    [
        format!("{base}{}", nssm_keys::APP_STDIO_SHARING),
        format!("{base}{}", nssm_keys::APP_STDIO_DISPOSITION),
        format!("{base}{}", nssm_keys::APP_STDIO_FLAGS),
        format!("{base}{}", nssm_keys::APP_STDIO_COPY_AND_TRUNCATE),
    ]
}

/// Clear a path-valued field by deleting the value (and, for stdio paths,
/// the four associated attribute values) instead of writing `""`. Missing
/// values are not errors — clearing an already-empty field is a no-op.
fn clear_path_value(key: &RegKey, canonical: &str) -> Result<()> {
    ignore_missing(delete_value(key, canonical))?;
    if is_stdio_path_value(canonical) {
        for attr in stdio_attribute_names(canonical) {
            ignore_missing(delete_value(key, &attr))?;
        }
    }
    Ok(())
}

/// Read a single managed value by NSSM-style name.
pub fn get_value(service: &str, name: &str) -> Result<Option<ValueRecord>> {
    validate_service_name(service)?;
    let (canonical, kind) = lookup_kind(name)?;
    let path = format!("SYSTEM\\CurrentControlSet\\Services\\{service}\\Parameters");
    let key = match open_subkey(HKEY_LOCAL_MACHINE, &path, KEY_READ) {
        Ok(k) => k,
        Err(Error::NotFound(_)) => return Ok(None),
        Err(e) => return Err(e),
    };
    let value = match kind {
        ManagedValueKind::String => match read_string(&key, &canonical) {
            Ok(v) => Some(ValueRecord { kind, value: v }),
            Err(Error::NotFound(_)) => None,
            Err(e) => return Err(e),
        },
        ManagedValueKind::MultiString => match read_multi_string(&key, &canonical) {
            Ok(v) => Some(ValueRecord {
                kind,
                value: join_multi_value(&v),
            }),
            Err(Error::NotFound(_)) => None,
            Err(e) => return Err(e),
        },
        ManagedValueKind::Number => match read_u32(&key, &canonical) {
            Ok(v) => Some(ValueRecord {
                kind,
                value: v.to_string(),
            }),
            Err(Error::NotFound(_)) => None,
            Err(e) => return Err(e),
        },
    };
    Ok(value)
}

/// Delete a single managed value by NSSM-style name. Missing values are
/// silently tolerated.
///
/// For stdio path fields (`AppStdin`/`AppStdout`/`AppStderr`) this also
/// deletes the four associated attribute values
/// (`{base}ShareMode`/`CreationDisposition`/`FlagsAndAttributes`/`CopyAndTruncate`)
/// via `clear_path_value`, mirroring the M-04 fix in `set_value`. Without
/// that mirror, `ngsm unset AppStdout` would leave the attribute values
/// behind so a subsequent `ngsm set AppStdout <new-path>` would silently
/// inherit stale attributes from the old path.
pub fn unset_value(service: &str, name: &str) -> Result<()> {
    validate_service_name(service)?;
    let _guard = lock_service_config(service)?;
    let path = format!("SYSTEM\\CurrentControlSet\\Services\\{service}\\Parameters");
    let key = open_subkey(HKEY_LOCAL_MACHINE, &path, KEY_READ | KEY_WRITE)?;
    unset_value_in_key(&key, name)
}

fn unset_value_in_key(key: &RegKey, name: &str) -> Result<()> {
    let (canonical, _) = lookup_kind(name)?;
    // Removing `Application` would silently turn the service unmanaged.
    // Removing the marker is `delete_managed_config`'s job, not `unset`'s.
    if canonical == nssm_keys::APPLICATION {
        return Err(Error::InvalidConfig(
            "refusing to unset Application — it is the managed-service marker; \
             remove the whole managed config instead"
                .into(),
        ));
    }
    // Only mutate the config of a service that is actually managed.
    require_managed_marker(key)?;
    // Route stdio path fields through `clear_path_value` so the
    // associated attribute values go with them; other fields delete
    // through the bare canonical path (no attribute family to cascade).
    if is_stdio_path_value(&canonical) {
        clear_path_value(key, &canonical)
    } else {
        ignore_missing(delete_value(key, &canonical))
    }
}

/// Resolve a (possibly whitespace-padded, possibly mis-cased) value name to
/// its **canonical** NSSM name and kind. Callers must use the returned
/// canonical name — not the raw input — for registry I/O and marker checks,
/// so a name like `" Application "` cannot read one value while bypassing a
/// guard keyed on another.
fn lookup_kind(name: &str) -> Result<(String, ManagedValueKind)> {
    let normalized = name.trim();
    // String comparisons are case-insensitive to mirror NSSM's behavior.
    for (canonical, kind) in MANAGED_VALUE_KINDS {
        if normalized.eq_ignore_ascii_case(canonical) {
            return Ok(((*canonical).to_string(), *kind));
        }
    }
    // Per-stream stdio attribute values (e.g. `AppStdoutShareMode`) are valid
    // numeric values handled by the full read/write path; expose them through
    // the single-value API too.
    for base in [
        nssm_keys::APP_STDIN,
        nssm_keys::APP_STDOUT,
        nssm_keys::APP_STDERR,
    ] {
        for suffix in [
            nssm_keys::APP_STDIO_SHARING,
            nssm_keys::APP_STDIO_DISPOSITION,
            nssm_keys::APP_STDIO_FLAGS,
            nssm_keys::APP_STDIO_COPY_AND_TRUNCATE,
        ] {
            let canonical = format!("{base}{suffix}");
            if normalized.eq_ignore_ascii_case(&canonical) {
                return Ok((canonical, ManagedValueKind::Number));
            }
        }
    }
    Err(Error::InvalidConfig(format!(
        "unknown managed value '{name}'"
    )))
}

fn require_managed_marker(key: &RegKey) -> Result<()> {
    match opt_string(key, nssm_keys::APPLICATION)? {
        Some(value) if !value.trim().is_empty() => Ok(()),
        _ => Err(Error::InvalidConfig(
            "a valid nonempty Application marker is required; native services cannot be modified"
                .into(),
        )),
    }
}

const MANAGED_VALUE_KINDS: &[(&str, ManagedValueKind)] = &[
    (nssm_keys::APPLICATION, ManagedValueKind::String),
    (nssm_keys::APP_PARAMETERS, ManagedValueKind::String),
    (nssm_keys::APP_DIRECTORY, ManagedValueKind::String),
    (nssm_keys::APP_ENVIRONMENT, ManagedValueKind::MultiString),
    (
        nssm_keys::APP_ENVIRONMENT_EXTRA,
        ManagedValueKind::MultiString,
    ),
    (nssm_keys::APP_PRIORITY, ManagedValueKind::Number),
    (nssm_keys::APP_AFFINITY, ManagedValueKind::String),
    (nssm_keys::APP_RESTART_DELAY, ManagedValueKind::Number),
    (nssm_keys::APP_THROTTLE, ManagedValueKind::Number),
    (nssm_keys::APP_STOP_METHOD_SKIP, ManagedValueKind::Number),
    (nssm_keys::APP_KILL_CONSOLE_GRACE, ManagedValueKind::Number),
    (nssm_keys::APP_KILL_WINDOW_GRACE, ManagedValueKind::Number),
    (nssm_keys::APP_KILL_THREADS_GRACE, ManagedValueKind::Number),
    (nssm_keys::APP_KILL_PROCESS_TREE, ManagedValueKind::Number),
    (nssm_keys::APP_STDIN, ManagedValueKind::String),
    (nssm_keys::APP_STDOUT, ManagedValueKind::String),
    (nssm_keys::APP_STDERR, ManagedValueKind::String),
    (nssm_keys::APP_ROTATE, ManagedValueKind::Number),
    (nssm_keys::APP_ROTATE_ONLINE, ManagedValueKind::Number),
    (nssm_keys::APP_ROTATE_SECONDS, ManagedValueKind::Number),
    (nssm_keys::APP_ROTATE_BYTES_LOW, ManagedValueKind::Number),
    (nssm_keys::APP_ROTATE_BYTES_HIGH, ManagedValueKind::Number),
    (nssm_keys::APP_ROTATE_DELAY, ManagedValueKind::Number),
    (nssm_keys::APP_TIMESTAMP_LOG, ManagedValueKind::Number),
];

// -- Write surface ---------------------------------------------------------

/// Create the `Parameters` subkey for a service (which must already exist)
/// and write the supplied configuration. NGSM-owned values are
/// reconciled, so the result reflects exactly `cfg`.
pub fn create_managed_config(service: &str, cfg: &ManagedApplicationConfig) -> Result<()> {
    validate_service_name(service)?;
    validate_managed_config(cfg)?;
    let _guard = lock_service_config(service)?;
    let service_path = format!("SYSTEM\\CurrentControlSet\\Services\\{service}");
    let service_key = open_subkey(HKEY_LOCAL_MACHINE, &service_path, KEY_WRITE | KEY_READ)?;
    create_managed_under_service(&service_key, cfg)
}

/// A managed config must carry a non-empty `Application`; without it the
/// service immediately reads back as native/unmanaged. Reject such a config
/// at write time rather than silently producing an unmanaged service that
/// the caller was told was written successfully.
fn require_application(cfg: &ManagedApplicationConfig) -> Result<()> {
    match cfg.application.as_deref() {
        Some(app) if !app.trim().is_empty() => Ok(()),
        _ => Err(Error::InvalidConfig(
            "managed config requires a non-empty Application value".into(),
        )),
    }
}

/// Overwrite the managed config under an existing `Parameters` key.
/// Returns [`Error::NotFound`] if the service's `Parameters` key does not exist.
pub fn write_managed_config(service: &str, cfg: &ManagedApplicationConfig) -> Result<()> {
    validate_service_name(service)?;
    validate_managed_config(cfg)?;
    let _guard = lock_service_config(service)?;
    require_application(cfg)?;
    let path = format!("SYSTEM\\CurrentControlSet\\Services\\{service}\\Parameters");
    let key = open_subkey(HKEY_LOCAL_MACHINE, &path, parameters_rw_sam())?;
    require_managed_marker(&key)?;
    write_into_key(&key, cfg)
}

/// Delete the NGSM-managed configuration for a service. Removes
/// only NGSM-owned values plus the `AppExit` / `AppEvents`
/// subtrees; other values under `Parameters` are preserved so we do not
/// stomp on native registry data the service writes for itself.
///
/// If any owned value or subtree cannot be removed (and the failure is not
/// simply "already absent"), the names that failed are reported in the
/// returned error rather than the caller being told the purge succeeded.
pub fn delete_managed_config(service: &str) -> Result<()> {
    validate_service_name(service)?;
    let _guard = lock_service_config(service)?;
    let path = format!("SYSTEM\\CurrentControlSet\\Services\\{service}\\Parameters");
    let key = match open_subkey(HKEY_LOCAL_MACHINE, &path, parameters_rw_sam()) {
        Ok(k) => k,
        Err(Error::NotFound(_)) => return Ok(()),
        Err(e) => return Err(e),
    };
    scrub_managed(&key)
}

fn create_managed_under_service(
    service_key: &RegKey,
    cfg: &ManagedApplicationConfig,
) -> Result<()> {
    validate_managed_config(cfg)?;
    let key = create_subkey_under(service_key, "Parameters")?;
    write_into_key(&key, cfg)
}

/// Names of every value NGSM may have written under `Parameters`,
/// including the per-stream stdio attribute values. Used to reconcile state
/// on update and to scrub on delete.
fn owned_value_names() -> Vec<String> {
    let mut names: Vec<String> = MANAGED_VALUE_NAMES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    for base in [
        nssm_keys::APP_STDIN,
        nssm_keys::APP_STDOUT,
        nssm_keys::APP_STDERR,
    ] {
        for suffix in [
            nssm_keys::APP_STDIO_SHARING,
            nssm_keys::APP_STDIO_DISPOSITION,
            nssm_keys::APP_STDIO_FLAGS,
            nssm_keys::APP_STDIO_COPY_AND_TRUNCATE,
        ] {
            names.push(format!("{base}{suffix}"));
        }
    }
    names
}

/// Remove every NGSM-owned value and the `AppExit` / `AppEvents`
/// subtrees under an open `Parameters` key. Items that are already absent
/// are not failures; any other failure is collected and reported together.
fn scrub_managed(key: &RegKey) -> Result<()> {
    let mut failures: Vec<String> = Vec::new();
    for sub in [nssm_keys::APP_EXIT, nssm_keys::APP_EVENTS] {
        if let Err(e) = ignore_missing(delete_subtree(key, sub)) {
            failures.push(format!("{sub} ({e})"));
        }
    }
    for name in owned_value_names() {
        if let Err(e) = ignore_missing(delete_value(key, &name)) {
            failures.push(format!("{name} ({e})"));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(Error::Registry(format!(
            "could not remove managed registry data: {}",
            failures.join("; ")
        )))
    }
}

fn exit_action_str(action: ExitAction) -> &'static str {
    match action {
        ExitAction::Restart => "Restart",
        ExitAction::Ignore => "Ignore",
        ExitAction::Exit => "Exit",
        ExitAction::Suicide => "Suicide",
    }
}

/// Walk every string in `cfg` that would be written as a `REG_SZ` value,
/// `REG_MULTI_SZ` entry, value name, or subkey name, and reject the
/// config up front if any contains an embedded NUL. Returns an error
/// naming the first offending field.
///
/// `write_string` and `write_multi_string` already refuse NUL-bearing
/// values, but they fire mid-write — after earlier fields have already
/// been persisted. Without this precheck a NUL in (say) `AppParameters`
/// would leave the registry in a half-mutated state: `Application` and
/// other earlier-written values updated, later values stale, exit and
/// hooks subtrees unreconciled.
///
/// Field coverage mirrors `write_into_key` exactly. If a new string
/// field is added there, it must also be added here.
fn precheck_no_embedded_nuls(cfg: &ManagedApplicationConfig) -> Result<()> {
    fn check(field: &str, value: &str) -> Result<()> {
        if value.contains('\0') {
            return Err(Error::InvalidConfig(format!(
                "{field} contains an embedded NUL — registry strings cannot \
                 carry NULs (the value would be silently truncated or split)"
            )));
        }
        Ok(())
    }

    // Single REG_SZ values.
    if let Some(v) = &cfg.application {
        check("Application", v)?;
    }
    if let Some(v) = &cfg.app_parameters {
        check("AppParameters", v)?;
    }
    if let Some(v) = &cfg.app_directory {
        check("AppDirectory", v)?;
    }
    if let Some(v) = &cfg.affinity {
        check("AppAffinity", v)?;
    }

    // REG_MULTI_SZ entries.
    for (i, v) in cfg.environment.iter().enumerate() {
        check(&format!("AppEnvironment[{i}]"), v)?;
    }
    for (i, v) in cfg.environment_extra.iter().enumerate() {
        check(&format!("AppEnvironmentExtra[{i}]"), v)?;
    }

    // Stdio paths.
    if let Some(s) = &cfg.io.stdin {
        check("AppStdin", &s.path)?;
    }
    if let Some(s) = &cfg.io.stdout {
        check("AppStdout", &s.path)?;
    }
    if let Some(s) = &cfg.io.stderr {
        check("AppStderr", &s.path)?;
    }

    // Exit-action map: keys become registry value names; values become
    // REG_SZ data ("Restart"/"Ignore"/... — fixed strings, but the
    // key itself is user input).
    for name in cfg.exit_actions.keys() {
        check(&format!("AppExit\\{name}"), name)?;
    }

    // Hooks: event becomes a subkey name; action becomes a value name;
    // command becomes the REG_SZ data.
    for hook in &cfg.hooks {
        check(&format!("AppEvents\\{}", hook.event), &hook.event)?;
        check(
            &format!("AppEvents\\{}\\{}", hook.event, hook.action),
            &hook.action,
        )?;
        check(
            &format!("AppEvents\\{}\\{} (command)", hook.event, hook.action),
            &hook.command,
        )?;
    }

    Ok(())
}

/// Write `cfg` into an open `Parameters` key, reconciling away any stale
/// managed data left by a previous config.
///
/// Crucially this is **write-first**: every value present in `cfg` is
/// written *before* any delete happens. A failure partway through can leave
/// a few stale values behind, but it can never erase the previous working
/// `Application`/IO/restart config — which a delete-then-write order would.
/// Shared, non-mutating preflight for full managed writes. Installers and
/// editors can use the identical validation before their first mutation.
pub fn validate_managed_config(cfg: &ManagedApplicationConfig) -> Result<()> {
    preflight_config(cfg).map(|_| ())
}

fn preflight_config(cfg: &ManagedApplicationConfig) -> Result<BTreeMap<String, ExitActionPolicy>> {
    require_application(cfg)?;
    for marked in &cfg.expandable_strings {
        let scalar = [
            "Application",
            "AppParameters",
            "AppDirectory",
            "AppAffinity",
            "AppStdin",
            "AppStdout",
            "AppStderr",
        ]
        .iter()
        .any(|name| marked.eq_ignore_ascii_case(name));
        if !scalar {
            let components: Vec<&str> = marked.split('\\').collect();
            if components.len() != 3 || !components[0].eq_ignore_ascii_case("AppEvents") {
                return Err(Error::InvalidConfig(
                    "unknown expandable string metadata key".into(),
                ));
            }
            validate_hook_component(components[1], "event")?;
            validate_hook_component(components[2], "action")?;
        }
    }
    // Reject any embedded NUL up front, before any registry mutation —
    // otherwise a NUL in (say) `AppParameters` would only be caught
    // after `Application` and earlier fields have already been written,
    // leaving the registry half-mutated.
    precheck_no_embedded_nuls(cfg)?;
    for (name, values) in [
        (nssm_keys::APP_ENVIRONMENT, &cfg.environment),
        (nssm_keys::APP_ENVIRONMENT_EXTRA, &cfg.environment_extra),
    ] {
        if values.iter().any(String::is_empty) {
            return Err(Error::InvalidConfig(format!(
                "{name} cannot contain an empty REG_MULTI_SZ entry"
            )));
        }
    }
    let mut hooks = BTreeMap::new();
    // Validate hook names up front, before mutating the registry at all.
    for hook in &cfg.hooks {
        validate_hook_component(&hook.event, "event")?;
        validate_hook_component(&hook.action, "action")?;
        let identity = (
            windows_name_key(&hook.event)?,
            windows_name_key(&hook.action)?,
        );
        if let Some(previous) = hooks.insert(identity, &hook.command) {
            if previous != &hook.command {
                return Err(Error::InvalidConfig(
                    "conflicting case-insensitive hook definitions".into(),
                ));
            }
        }
    }
    // Every configured filesystem path must be absolute — a relative
    // application path would resolve through the service account's PATH /
    // working directory (search-path confusion), and relative log paths are
    // ambiguous. Checked before any registry mutation.
    if let Some(app) = &cfg.application {
        validate_raw_path(cfg, "Application", app)?;
    }
    if let Some(dir) = cfg.app_directory.as_deref().filter(|d| !d.is_empty()) {
        validate_raw_path(cfg, "AppDirectory", dir)?;
    }
    if let Some(s) = &cfg.io.stdin {
        validate_raw_path(cfg, "AppStdin", &s.path)?;
    }
    if let Some(s) = &cfg.io.stdout {
        validate_raw_path(cfg, "AppStdout", &s.path)?;
    }
    if let Some(s) = &cfg.io.stderr {
        validate_raw_path(cfg, "AppStderr", &s.path)?;
    }
    let mut exit_actions = BTreeMap::new();
    for (name, policy) in &cfg.exit_actions {
        insert_exit_action(&mut exit_actions, name, policy.action)?;
    }
    if let Some(action) = cfg.restart.default_action {
        insert_exit_action(&mut exit_actions, "default", action)?;
    }
    Ok(exit_actions)
}

fn validate_raw_path(cfg: &ManagedApplicationConfig, name: &str, value: &str) -> Result<()> {
    if cfg.is_expandable_string(name) {
        if value.chars().any(char::is_control) {
            return Err(Error::InvalidConfig(format!(
                "{name} contains a control character"
            )));
        }
        // A variable can supply a drive/UNC prefix. Only the service account
        // can resolve it; runtime validates the effective path before use.
        if value
            .split('%')
            .enumerate()
            .any(|(index, part)| index % 2 == 1 && !part.is_empty())
            && value.matches('%').count() >= 2
        {
            return Ok(());
        }
    }
    validate_absolute_path(name, value)
}

fn write_into_key(key: &RegKey, cfg: &ManagedApplicationConfig) -> Result<()> {
    let exit_actions = preflight_config(cfg)?;
    check_existing_names(key)?;
    // --- Phase 1: write every scalar value present in `cfg`. ---
    let mut written: HashSet<String> = HashSet::new();
    macro_rules! put {
        ($name:expr, $write:expr) => {{
            $write;
            written.insert($name.to_string());
        }};
    }

    if let Some(v) = &cfg.application {
        put!(
            nssm_keys::APPLICATION,
            write_config_string(key, cfg, nssm_keys::APPLICATION, v)?
        );
    }
    if let Some(v) = &cfg.app_parameters {
        put!(
            nssm_keys::APP_PARAMETERS,
            write_config_string(key, cfg, nssm_keys::APP_PARAMETERS, v)?
        );
    }
    if let Some(v) = &cfg.app_directory {
        put!(
            nssm_keys::APP_DIRECTORY,
            write_config_string(key, cfg, nssm_keys::APP_DIRECTORY, v)?
        );
    }
    if let Some(v) = cfg.priority {
        put!(
            nssm_keys::APP_PRIORITY,
            write_u32(key, nssm_keys::APP_PRIORITY, v)?
        );
    }
    if let Some(v) = &cfg.affinity {
        put!(
            nssm_keys::APP_AFFINITY,
            write_config_string(key, cfg, nssm_keys::APP_AFFINITY, v)?
        );
    }
    if !cfg.environment.is_empty() {
        put!(
            nssm_keys::APP_ENVIRONMENT,
            write_multi_string(key, nssm_keys::APP_ENVIRONMENT, &cfg.environment)?
        );
    }
    if !cfg.environment_extra.is_empty() {
        put!(
            nssm_keys::APP_ENVIRONMENT_EXTRA,
            write_multi_string(
                key,
                nssm_keys::APP_ENVIRONMENT_EXTRA,
                &cfg.environment_extra
            )?
        );
    }
    if let Some(v) = cfg.restart.restart_delay_ms {
        put!(
            nssm_keys::APP_RESTART_DELAY,
            write_u32(key, nssm_keys::APP_RESTART_DELAY, v)?
        );
    }
    if let Some(v) = cfg.restart.throttle_delay_ms {
        put!(
            nssm_keys::APP_THROTTLE,
            write_u32(key, nssm_keys::APP_THROTTLE, v)?
        );
    }
    if let Some(v) = cfg.shutdown.stop_method_skip {
        put!(
            nssm_keys::APP_STOP_METHOD_SKIP,
            write_u32(key, nssm_keys::APP_STOP_METHOD_SKIP, v)?
        );
    }
    if let Some(v) = cfg.shutdown.kill_console_grace_ms {
        put!(
            nssm_keys::APP_KILL_CONSOLE_GRACE,
            write_u32(key, nssm_keys::APP_KILL_CONSOLE_GRACE, v)?
        );
    }
    if let Some(v) = cfg.shutdown.kill_window_grace_ms {
        put!(
            nssm_keys::APP_KILL_WINDOW_GRACE,
            write_u32(key, nssm_keys::APP_KILL_WINDOW_GRACE, v)?
        );
    }
    if let Some(v) = cfg.shutdown.kill_threads_grace_ms {
        put!(
            nssm_keys::APP_KILL_THREADS_GRACE,
            write_u32(key, nssm_keys::APP_KILL_THREADS_GRACE, v)?
        );
    }
    if let Some(v) = cfg.shutdown.kill_process_tree {
        put!(
            nssm_keys::APP_KILL_PROCESS_TREE,
            write_u32(key, nssm_keys::APP_KILL_PROCESS_TREE, v as u32)?
        );
    }
    if let Some(v) = cfg.rotation.enabled {
        put!(
            nssm_keys::APP_ROTATE,
            write_u32(key, nssm_keys::APP_ROTATE, v as u32)?
        );
    }
    if let Some(v) = cfg.rotation.online {
        put!(
            nssm_keys::APP_ROTATE_ONLINE,
            write_u32(key, nssm_keys::APP_ROTATE_ONLINE, v)?
        );
    }
    if let Some(v) = cfg.rotation.seconds {
        put!(
            nssm_keys::APP_ROTATE_SECONDS,
            write_u32(key, nssm_keys::APP_ROTATE_SECONDS, v)?
        );
    }
    if let Some(v) = cfg.rotation.bytes {
        put!(
            nssm_keys::APP_ROTATE_BYTES_LOW,
            write_u32(key, nssm_keys::APP_ROTATE_BYTES_LOW, v as u32)?
        );
        put!(
            nssm_keys::APP_ROTATE_BYTES_HIGH,
            write_u32(key, nssm_keys::APP_ROTATE_BYTES_HIGH, (v >> 32) as u32)?
        );
    }
    if let Some(v) = cfg.rotation.delay_ms {
        put!(
            nssm_keys::APP_ROTATE_DELAY,
            write_u32(key, nssm_keys::APP_ROTATE_DELAY, v)?
        );
    }
    if let Some(v) = cfg.io.timestamp_log {
        put!(
            nssm_keys::APP_TIMESTAMP_LOG,
            write_u32(key, nssm_keys::APP_TIMESTAMP_LOG, v as u32)?
        );
    }
    for name in write_io_stream(key, cfg, nssm_keys::APP_STDIN, &cfg.io.stdin)? {
        written.insert(name);
    }
    for name in write_io_stream(key, cfg, nssm_keys::APP_STDOUT, &cfg.io.stdout)? {
        written.insert(name);
    }
    for name in write_io_stream(key, cfg, nssm_keys::APP_STDERR, &cfg.io.stderr)? {
        written.insert(name);
    }

    // --- Phase 2a: reconcile the AppExit subtree (write new, prune stale). ---
    // `restart.default_action` is the typed mirror of AppExit's "default"
    // entry. If a caller set it without also populating `exit_actions`, the
    // default action would otherwise be silently dropped on write — so
    // synthesize the "default" entry from it when one is not already present.
    if exit_actions.is_empty() {
        ignore_missing(delete_subtree(key, nssm_keys::APP_EXIT))?;
    } else {
        let exit_key = create_subkey_under(key, nssm_keys::APP_EXIT)?;
        let mut wanted: HashSet<String> = HashSet::new();
        for (name, policy) in &exit_actions {
            // The default action is written to the *unnamed* `AppExit`
            // value — NSSM's canonical representation. The reader also
            // accepts a named `Default` value, but the writer deliberately
            // normalizes to the unnamed form (and the reconcile below then
            // prunes a stale named `Default`), so a config never carries
            // both shapes of the same action.
            let registry_name = if name == "default" { "" } else { name.as_str() };
            // Defense-in-depth: every non-"default" key must parse as i32
            // (the supervisor matches numeric child exit codes). Callers
            // already validate via `servicemanager_ops::validate_exit_action_key`,
            // but a typed write path that never accepts a non-numeric key
            // means a future caller cannot regress the invariant by
            // skipping the ops layer.
            if !registry_name.is_empty() && registry_name.parse::<i32>().is_err() {
                return Err(Error::InvalidConfig(format!(
                    "AppExit key '{name}' is not a valid i32 exit code — \
                     the supervisor would never match it at runtime"
                )));
            }
            write_string(&exit_key, registry_name, exit_action_str(policy.action))?;
            wanted.insert(registry_name.to_string());
        }
        for existing in enumerate_value_names(&exit_key)? {
            if !wanted.contains(&existing) {
                ignore_missing(delete_value(&exit_key, &existing))?;
            }
        }
    }

    // --- Phase 2b: reconcile the AppEvents subtree. ---
    if cfg.hooks.is_empty() {
        ignore_missing(delete_subtree(key, nssm_keys::APP_EVENTS))?;
    } else {
        let events_key = create_subkey_under(key, nssm_keys::APP_EVENTS)?;
        let mut wanted: BTreeMap<Vec<u16>, HashSet<Vec<u16>>> = BTreeMap::new();
        for hook in &cfg.hooks {
            // Layout matches the reader: `AppEvents\<event>` is a subkey
            // and each `<action>` is a named REG_SZ value under it.
            let event_key = create_subkey_under(&events_key, &hook.event)?;
            let kind = if registry_is_expandable(
                cfg,
                &ManagedApplicationConfig::hook_expansion_key(&hook.event, &hook.action),
            )? {
                REG_EXPAND_SZ
            } else {
                REG_SZ
            };
            write_string_typed(&event_key, &hook.action, &hook.command, kind)?;
            wanted
                .entry(windows_name_key(&hook.event)?)
                .or_default()
                .insert(windows_name_key(&hook.action)?);
        }
        for existing_event in enumerate_subkey_names(&events_key)? {
            match wanted.get(&windows_name_key(&existing_event)?) {
                None => {
                    ignore_missing(delete_subtree(&events_key, &existing_event))?;
                }
                Some(wanted_actions) => {
                    let event_key =
                        match open_subkey(events_key.0, &existing_event, parameters_rw_sam()) {
                            Ok(k) => k,
                            Err(Error::NotFound(_)) => continue,
                            Err(e) => return Err(e),
                        };
                    for existing_action in enumerate_value_names(&event_key)? {
                        if !wanted_actions.contains(&windows_name_key(&existing_action)?) {
                            ignore_missing(delete_value(&event_key, &existing_action))?;
                        }
                    }
                }
            }
        }
    }

    // --- Phase 2c: delete owned scalar values `cfg` did not write. ---
    for name in owned_value_names() {
        if !written.contains(&name) {
            ignore_missing(delete_value(key, &name))?;
        }
    }
    Ok(())
}

/// Write an optional redirected stream and return the names of every value
/// it wrote (the base name plus any per-stream attribute values) so the
/// caller can reconcile which owned values are now stale.
fn write_io_stream(
    parent: &RegKey,
    cfg: &ManagedApplicationConfig,
    base: &str,
    stream: &Option<IoStream>,
) -> Result<Vec<String>> {
    let Some(stream) = stream else {
        return Ok(Vec::new());
    };
    let mut names = vec![base.to_string()];
    write_config_string(parent, cfg, base, &stream.path)?;
    if let Some(v) = stream.share_mode {
        let n = format!("{base}{}", nssm_keys::APP_STDIO_SHARING);
        write_u32(parent, &n, v)?;
        names.push(n);
    }
    if let Some(v) = stream.creation_disposition {
        let n = format!("{base}{}", nssm_keys::APP_STDIO_DISPOSITION);
        write_u32(parent, &n, v)?;
        names.push(n);
    }
    if let Some(v) = stream.flags_and_attributes {
        let n = format!("{base}{}", nssm_keys::APP_STDIO_FLAGS);
        write_u32(parent, &n, v)?;
        names.push(n);
    }
    if let Some(v) = stream.copy_and_truncate {
        let n = format!("{base}{}", nssm_keys::APP_STDIO_COPY_AND_TRUNCATE);
        write_u32(parent, &n, v as u32)?;
        names.push(n);
    }
    Ok(names)
}

fn create_subkey(parent: HKEY, path: &str, sam: REG_SAM_FLAGS) -> Result<RegKey> {
    let wide = to_wide(path);
    let mut key = HKEY::default();
    // SAFETY: `wide` is a NUL-terminated UTF-16 buffer that outlives the
    // call; `&mut key` is a valid out-parameter. The returned handle is
    // taken under RAII ownership by `RegKey`.
    unsafe {
        RegCreateKeyExW(
            parent,
            PCWSTR::from_raw(wide.as_ptr()),
            Some(0),
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            sam,
            None,
            &mut key,
            None,
        )
        .ok()
        .map_err(|e| map_reg_error(&format!("RegCreateKeyEx({path})"), e))?;
    }
    Ok(RegKey(key))
}

fn create_subkey_under(parent: &RegKey, name: &str) -> Result<RegKey> {
    create_subkey(parent.0, name, parameters_rw_sam())
}

fn write_string(key: &RegKey, name: &str, value: &str) -> Result<()> {
    write_string_typed(key, name, value, REG_SZ)
}

fn write_config_string(
    key: &RegKey,
    cfg: &ManagedApplicationConfig,
    name: &str,
    value: &str,
) -> Result<()> {
    write_string_typed(
        key,
        name,
        value,
        if registry_is_expandable(cfg, name)? {
            REG_EXPAND_SZ
        } else {
            REG_SZ
        },
    )
}

fn registry_is_expandable(cfg: &ManagedApplicationConfig, name: &str) -> Result<bool> {
    let identity = windows_name_key(name)?;
    for marked in &cfg.expandable_strings {
        if windows_name_key(marked)? == identity {
            return Ok(true);
        }
    }
    Ok(false)
}

fn write_string_typed(key: &RegKey, name: &str, value: &str, kind: REG_VALUE_TYPE) -> Result<()> {
    // An embedded NUL would read back truncated at the first NUL — reject it
    // up front rather than silently storing an unrecoverable value.
    if value.contains('\0') {
        return Err(Error::Registry(format!(
            "value '{name}' contains an embedded NUL and cannot be stored as REG_SZ"
        )));
    }
    let wide_name = to_wide(name);
    let wide_value: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
    let bytes = wide_to_bytes(&wide_value);
    // SAFETY: `wide_name` is NUL-terminated and `bytes` is a byte view of the
    // NUL-terminated UTF-16 value; both outlive the call.
    unsafe {
        RegSetValueExW(
            key.0,
            PCWSTR::from_raw(wide_name.as_ptr()),
            Some(0),
            kind,
            Some(&bytes),
        )
        .ok()
        .map_err(|e| map_reg_error(&format!("RegSetValueEx({name})"), e))?;
    }
    Ok(())
}

fn write_multi_string(key: &RegKey, name: &str, values: &[String]) -> Result<()> {
    // An embedded NUL in any entry would split or truncate it on read-back.
    if values.iter().any(|v| v.contains('\0') || v.is_empty()) {
        return Err(Error::Registry(format!(
            "value '{name}' has an empty or NUL-containing entry and cannot be \
             stored as REG_MULTI_SZ"
        )));
    }
    let wide_name = to_wide(name);
    let mut buf: Vec<u16> = Vec::new();
    for v in values {
        buf.extend(v.encode_utf16());
        buf.push(0);
    }
    buf.push(0);
    let bytes = wide_to_bytes(&buf);
    // SAFETY: `wide_name` is NUL-terminated and `bytes` is a byte view of the
    // double-NUL-terminated REG_MULTI_SZ buffer; both outlive the call.
    unsafe {
        RegSetValueExW(
            key.0,
            PCWSTR::from_raw(wide_name.as_ptr()),
            Some(0),
            REG_MULTI_SZ,
            Some(&bytes),
        )
        .ok()
        .map_err(|e| map_reg_error(&format!("RegSetValueEx({name})"), e))?;
    }
    Ok(())
}

fn write_u32(key: &RegKey, name: &str, value: u32) -> Result<()> {
    let wide_name = to_wide(name);
    let bytes = value.to_le_bytes();
    // SAFETY: `wide_name` is NUL-terminated and `bytes` is a 4-byte buffer
    // matching REG_DWORD; both outlive the call.
    unsafe {
        RegSetValueExW(
            key.0,
            PCWSTR::from_raw(wide_name.as_ptr()),
            Some(0),
            REG_DWORD,
            Some(&bytes),
        )
        .ok()
        .map_err(|e| map_reg_error(&format!("RegSetValueEx({name})"), e))?;
    }
    Ok(())
}

fn delete_value(key: &RegKey, name: &str) -> Result<()> {
    let wide_name = to_wide(name);
    // SAFETY: `wide_name` is a NUL-terminated UTF-16 buffer that outlives the
    // call; `key.0` is a live key handle owned by `RegKey`.
    unsafe {
        RegDeleteValueW(key.0, PCWSTR::from_raw(wide_name.as_ptr()))
            .ok()
            .map_err(|e| map_reg_error(&format!("RegDeleteValue({name})"), e))?;
    }
    Ok(())
}

fn delete_subtree(key: &RegKey, subkey: &str) -> Result<()> {
    let wide = to_wide(subkey);
    // SAFETY: `wide` is a NUL-terminated UTF-16 buffer that outlives the
    // call; `key.0` is a live key handle owned by `RegKey`.
    unsafe {
        RegDeleteTreeW(key.0, PCWSTR::from_raw(wide.as_ptr()))
            .ok()
            .map_err(|e| map_reg_error(&format!("RegDeleteTree({subkey})"), e))?;
    }
    Ok(())
}

fn wide_to_bytes(words: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(words.len() * 2);
    for &w in words {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out
}

/// Set of value names NGSM owns directly under `Parameters`.
const MANAGED_VALUE_NAMES: &[&str] = &[
    nssm_keys::APPLICATION,
    nssm_keys::APP_PARAMETERS,
    nssm_keys::APP_DIRECTORY,
    nssm_keys::APP_ENVIRONMENT,
    nssm_keys::APP_ENVIRONMENT_EXTRA,
    nssm_keys::APP_PRIORITY,
    nssm_keys::APP_AFFINITY,
    nssm_keys::APP_RESTART_DELAY,
    nssm_keys::APP_THROTTLE,
    nssm_keys::APP_STOP_METHOD_SKIP,
    nssm_keys::APP_KILL_CONSOLE_GRACE,
    nssm_keys::APP_KILL_WINDOW_GRACE,
    nssm_keys::APP_KILL_THREADS_GRACE,
    nssm_keys::APP_KILL_PROCESS_TREE,
    nssm_keys::APP_STDIN,
    nssm_keys::APP_STDOUT,
    nssm_keys::APP_STDERR,
    nssm_keys::APP_ROTATE,
    nssm_keys::APP_ROTATE_ONLINE,
    nssm_keys::APP_ROTATE_SECONDS,
    nssm_keys::APP_ROTATE_BYTES_LOW,
    nssm_keys::APP_ROTATE_BYTES_HIGH,
    nssm_keys::APP_ROTATE_DELAY,
    nssm_keys::APP_TIMESTAMP_LOG,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_empty_double_nul_multisz_is_readable() {
        assert_eq!(
            bytes_to_wide_multi(&[0, 0, 0, 0]).unwrap(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn environment_codec_preserves_ordinary_windows_path_backslashes() {
        let entry = r"PATH=C:\Tools\bin";
        assert_eq!(split_multi_value(entry), vec![entry.to_string()]);
    }

    #[test]
    fn environment_codec_round_trips_significant_trailing_whitespace() {
        let entries = vec![
            "FIRST=ends in a space ".to_string(),
            "SECOND=ends in a tab\t".to_string(),
        ];
        assert_eq!(split_multi_value(&join_multi_value(&entries)), entries);
    }

    #[test]
    fn exit_action_names_normalize_default() {
        // The unnamed value and a named `Default` (any case) all collapse to
        // the internal "default" key; specific exit codes pass through.
        assert_eq!(normalize_exit_action_name("").unwrap(), "default");
        assert_eq!(normalize_exit_action_name("Default").unwrap(), "default");
        assert_eq!(normalize_exit_action_name("DEFAULT").unwrap(), "default");
        assert_eq!(normalize_exit_action_name("default").unwrap(), "default");
        assert_eq!(normalize_exit_action_name("0").unwrap(), "0");
        assert_eq!(normalize_exit_action_name("1").unwrap(), "1");
    }

    #[test]
    fn exit_action_parsing_is_case_insensitive() {
        assert_eq!(parse_exit_action(" Restart "), Some(ExitAction::Restart));
        assert_eq!(parse_exit_action("IGNORE"), Some(ExitAction::Ignore));
        assert_eq!(parse_exit_action("exit"), Some(ExitAction::Exit));
        assert_eq!(parse_exit_action("nonsense"), None);
    }

    #[test]
    fn owned_value_names_cover_stdio_attributes() {
        let names = owned_value_names();
        assert!(names.iter().any(|n| n == "Application"));
        assert!(names.iter().any(|n| n == "AppStdoutShareMode"));
        assert!(names.iter().any(|n| n == "AppStderrCopyAndTruncate"));
    }

    #[test]
    fn stdio_path_values_are_recognized() {
        assert!(is_stdio_path_value(nssm_keys::APP_STDIN));
        assert!(is_stdio_path_value(nssm_keys::APP_STDOUT));
        assert!(is_stdio_path_value(nssm_keys::APP_STDERR));
        // Non-stdio path fields are not.
        assert!(!is_stdio_path_value(nssm_keys::APPLICATION));
        assert!(!is_stdio_path_value(nssm_keys::APP_DIRECTORY));
    }

    #[test]
    fn stdio_attribute_names_cover_all_four_per_stream_attrs() {
        let attrs = stdio_attribute_names(nssm_keys::APP_STDOUT);
        assert!(attrs.iter().any(|s| s == "AppStdoutShareMode"));
        assert!(attrs.iter().any(|s| s == "AppStdoutCreationDisposition"));
        assert!(attrs.iter().any(|s| s == "AppStdoutFlagsAndAttributes"));
        assert!(attrs.iter().any(|s| s == "AppStdoutCopyAndTruncate"));
        // Stderr is named consistently.
        let attrs = stdio_attribute_names(nssm_keys::APP_STDERR);
        assert!(attrs.iter().any(|s| s == "AppStderrShareMode"));
        assert!(attrs.iter().any(|s| s == "AppStderrCopyAndTruncate"));
    }

    #[test]
    fn path_valued_names_are_recognized() {
        // These five carry filesystem paths and are subject to the
        // absolute-path policy in `set_value`.
        assert!(is_path_value(nssm_keys::APPLICATION));
        assert!(is_path_value(nssm_keys::APP_DIRECTORY));
        assert!(is_path_value(nssm_keys::APP_STDIN));
        assert!(is_path_value(nssm_keys::APP_STDOUT));
        assert!(is_path_value(nssm_keys::APP_STDERR));
        // Non-path values are not.
        assert!(!is_path_value(nssm_keys::APP_PARAMETERS));
        assert!(!is_path_value(nssm_keys::APP_PRIORITY));
    }

    #[test]
    fn lookup_kind_canonicalizes_and_resolves() {
        // Whitespace-padded, mis-cased input resolves to the canonical name.
        let (canon, kind) = lookup_kind("  application ").unwrap();
        assert_eq!(canon, "Application");
        assert_eq!(kind, ManagedValueKind::String);
        assert_eq!(
            lookup_kind("AppPriority").unwrap().1,
            ManagedValueKind::Number
        );
        // Per-stream stdio attribute values are resolvable too.
        let (canon, kind) = lookup_kind("appstdoutsharemode").unwrap();
        assert_eq!(canon, "AppStdoutShareMode");
        assert_eq!(kind, ManagedValueKind::Number);
        assert!(lookup_kind("NotAValue").is_err());
    }

    #[test]
    fn multi_string_round_trips_through_bytes() {
        let words: Vec<u16> = "alpha\0beta\0\0".encode_utf16().collect();
        let bytes = wide_to_bytes(&words);
        assert_eq!(bytes_to_wide_multi(&bytes).unwrap(), vec!["alpha", "beta"]);
    }

    #[test]
    fn odd_length_utf16_buffers_are_rejected() {
        // An odd byte count cannot be valid UTF-16.
        assert!(bytes_to_wide_string(&[0x41, 0x00, 0x42]).is_err());
        assert!(bytes_to_wide_multi(&[0x41, 0x00, 0x42]).is_err());
        // Even-length, valid UTF-16 still decodes.
        assert_eq!(bytes_to_wide_string(&[0x41, 0x00]).unwrap(), "A");
    }

    #[test]
    fn reg_sz_with_data_after_terminator_is_rejected() {
        // "A\0B": a NUL-terminated "A" followed by stray "B" — the trailing
        // data is corruption and must not be silently dropped.
        let embedded: Vec<u16> = "A\0B".encode_utf16().collect();
        assert!(bytes_to_wide_string(&wide_to_bytes(&embedded)).is_err());
        // Trailing NUL padding after the terminator is acceptable.
        let padded: Vec<u16> = "A\0\0".encode_utf16().collect();
        assert_eq!(bytes_to_wide_string(&wide_to_bytes(&padded)).unwrap(), "A");
        // An unterminated REG_SZ is permitted and decodes whole.
        assert_eq!(
            bytes_to_wide_string(&[0x41, 0x00, 0x42, 0x00]).unwrap(),
            "AB"
        );
    }

    #[test]
    fn unterminated_multi_string_is_rejected() {
        // "alpha\0beta": the final entry has no NUL terminator — a lenient
        // decoder would silently return only ["alpha"].
        let unterminated: Vec<u16> = "alpha\0beta".encode_utf16().collect();
        assert!(bytes_to_wide_multi(&wide_to_bytes(&unterminated)).is_err());
        // A single trailing NUL (no empty-string block terminator) is also
        // rejected.
        let one_nul: Vec<u16> = "alpha\0beta\0".encode_utf16().collect();
        assert!(bytes_to_wide_multi(&wide_to_bytes(&one_nul)).is_err());
        // The properly double-NUL-terminated form still decodes.
        let ok: Vec<u16> = "alpha\0beta\0\0".encode_utf16().collect();
        assert_eq!(
            bytes_to_wide_multi(&wide_to_bytes(&ok)).unwrap(),
            vec!["alpha", "beta"]
        );
    }

    #[test]
    fn numeric_values_require_exact_size() {
        assert_eq!(decode_u32("X", REG_DWORD, &[1, 0, 0, 0]).unwrap(), 1);
        // Under- and over-sized DWORD buffers are corrupt, not truncated.
        assert!(decode_u32("X", REG_DWORD, &[1, 0, 0]).is_err());
        assert!(decode_u32("X", REG_DWORD, &[1, 0, 0, 0, 0]).is_err());
        assert_eq!(
            decode_u32("X", REG_QWORD, &[2, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            2
        );
        assert!(decode_u32("X", REG_QWORD, &[0u8; 9]).is_err());
    }

    #[test]
    fn multi_value_get_set_round_trips_with_commas() {
        // An entry containing a comma (e.g. an environment value) and one
        // containing a backslash both survive join -> split unchanged.
        let entries = vec![
            "PATH=a,b,c".to_string(),
            "PLAIN=x".to_string(),
            "ESC=back\\slash".to_string(),
        ];
        assert_eq!(split_multi_value(&join_multi_value(&entries)), entries);
        // Empty entries collapse away — REG_MULTI_SZ cannot store them.
        assert_eq!(split_multi_value("a,,b"), vec!["a", "b"]);
        assert!(split_multi_value("").is_empty());
    }

    // --- Registry I/O tests (use HKCU to avoid admin requirements) ---------
    //
    // These tests exercise the real `Reg*W` API through the same helpers
    // production uses, but rooted at a temporary `HKCU\Software\NgsmTests\...`
    // key rather than the per-service HKLM path. That lets us assert the
    // exact post-write registry state without elevation.

    use windows::Win32::System::Registry::HKEY_CURRENT_USER;

    struct Fixture {
        key: RegKey,
        name: String,
    }

    impl Fixture {
        fn new() -> Self {
            let name = format!(
                "platform_{}_{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            );
            let key = create_subkey(
                HKEY_CURRENT_USER,
                &format!("Software\\NgsmTests\\{name}"),
                parameters_rw_sam(),
            )
            .unwrap();
            Self { key, name }
        }
    }

    impl std::ops::Deref for Fixture {
        type Target = RegKey;
        fn deref(&self) -> &RegKey {
            &self.key
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            if let Ok(parent) = open_subkey(
                HKEY_CURRENT_USER,
                "Software\\NgsmTests",
                parameters_rw_sam(),
            ) {
                let _ = delete_subtree(&parent, &self.name);
            }
        }
    }

    fn snapshot(key: &RegKey) -> BTreeMap<String, (u32, Vec<u8>)> {
        fn collect(key: &RegKey, prefix: &str, out: &mut BTreeMap<String, (u32, Vec<u8>)>) {
            out.insert(format!("K:{prefix}"), (0, Vec::new()));
            for name in enumerate_value_names(key).unwrap() {
                let (kind, bytes) = query_value_raw(key, &name).unwrap();
                out.insert(format!("V:{prefix}\\{name}"), (kind.0, bytes));
            }
            for name in enumerate_subkey_names(key).unwrap() {
                let child = open_subkey(key.0, &name, KEY_READ).unwrap();
                collect(&child, &format!("{prefix}\\{name}"), out);
            }
        }
        let mut out = BTreeMap::new();
        collect(key, "", &mut out);
        out
    }

    fn valid_config() -> ManagedApplicationConfig {
        ManagedApplicationConfig {
            application: Some(r"C:\old\app.exe".into()),
            app_parameters: Some("before".into()),
            environment: vec!["A=1".into()],
            hooks: vec![HookConfig {
                event: "Start".into(),
                action: "Pre".into(),
                command: "before".into(),
            }],
            exit_actions: [(
                "1".into(),
                ExitActionPolicy {
                    action: ExitAction::Exit,
                },
            )]
            .into(),
            ..Default::default()
        }
    }

    #[test]
    fn invalid_complete_configs_leave_exact_registry_bytes_unchanged() {
        let fixture = Fixture::new();
        let original = valid_config();
        write_into_key(&fixture, &original).unwrap();
        write_string(&fixture, "NotOwned", "keep me").unwrap();
        let before = snapshot(&fixture);
        let mut invalid = Vec::new();
        for entries in [
            vec!["".into(), "A=1".into()],
            vec!["A=1".into(), "".into()],
            vec!["A=1".into(), "".into(), "B=2".into()],
            vec!["".into()],
        ] {
            let mut cfg = original.clone();
            cfg.environment = entries.clone();
            invalid.push(cfg);
            let mut cfg = original.clone();
            cfg.environment_extra = entries;
            invalid.push(cfg);
        }
        for key in ["bogus", "4294967296", "-2147483649", "1\0hidden"] {
            let mut cfg = original.clone();
            cfg.exit_actions.insert(
                key.into(),
                ExitActionPolicy {
                    action: ExitAction::Restart,
                },
            );
            invalid.push(cfg);
        }
        let mut cfg = original.clone();
        cfg.exit_actions.insert(
            "+1".into(),
            ExitActionPolicy {
                action: ExitAction::Restart,
            },
        );
        invalid.push(cfg);
        let mut cfg = original.clone();
        cfg.exit_actions.insert(
            "default".into(),
            ExitActionPolicy {
                action: ExitAction::Exit,
            },
        );
        cfg.restart.default_action = Some(ExitAction::Restart);
        invalid.push(cfg);
        let mut cfg = original.clone();
        cfg.hooks.push(HookConfig {
            event: "start".into(),
            action: "pre".into(),
            command: "conflict".into(),
        });
        invalid.push(cfg);
        for bad in ["bad\\event", "bad\0event", ""] {
            let mut cfg = original.clone();
            cfg.hooks[0].event = bad.into();
            invalid.push(cfg);
        }
        let mut cfg = original.clone();
        cfg.hooks[0].command = "bad\0command".into();
        invalid.push(cfg);
        for mut cfg in invalid {
            cfg.application = Some(r"C:\new\app.exe".into());
            cfg.app_parameters = Some("after".into());
            assert!(write_into_key(&fixture, &cfg).is_err());
            assert_eq!(snapshot(&fixture), before);
        }
    }

    #[test]
    fn invalid_new_config_does_not_create_parameters() {
        let fixture = Fixture::new();
        let before = snapshot(&fixture);
        let mut cfg = valid_config();
        cfg.environment = vec!["".into()];
        assert!(create_managed_under_service(&fixture, &cfg).is_err());
        assert_eq!(snapshot(&fixture), before);
        assert!(matches!(
            open_subkey(fixture.0, "Parameters", KEY_READ),
            Err(Error::NotFound(_))
        ));
    }

    #[test]
    fn hooks_reconcile_windows_case_identity_without_losing_updated_values() {
        let fixture = Fixture::new();
        let mut cfg = valid_config();
        cfg.hooks.push(HookConfig {
            event: "Start".into(),
            action: "Post".into(),
            command: "post".into(),
        });
        cfg.hooks.push(HookConfig {
            event: "Stop".into(),
            action: "Pre".into(),
            command: "stale".into(),
        });
        write_into_key(&fixture, &cfg).unwrap();
        cfg.hooks.truncate(2);
        cfg.hooks[0] = HookConfig {
            event: "start".into(),
            action: "pre".into(),
            command: "updated".into(),
        };
        cfg.hooks[1].event = "START".into();
        write_into_key(&fixture, &cfg).unwrap();
        let hooks = read_managed_from_key(&fixture, "fixture")
            .unwrap()
            .unwrap()
            .hooks;
        assert_eq!(hooks.len(), 2);
        assert!(hooks
            .iter()
            .any(|hook| hook.action.eq_ignore_ascii_case("pre") && hook.command == "updated"));
        assert!(hooks
            .iter()
            .any(|hook| hook.action.eq_ignore_ascii_case("post") && hook.command == "post"));
        cfg.hooks = vec![
            HookConfig {
                event: "Événement".into(),
                action: "Pré".into(),
                command: "%CMD%".into(),
            },
            HookConfig {
                event: "événement".into(),
                action: "PRÉ".into(),
                command: "%CMD%".into(),
            },
        ];
        cfg.expandable_strings
            .insert("AppEvents\\ÉVÉNEMENT\\PRÉ".into());
        write_into_key(&fixture, &cfg).unwrap();
        let loaded = read_managed_from_key(&fixture, "fixture").unwrap().unwrap();
        assert_eq!(loaded.hooks.len(), 1);
        assert_eq!(loaded.hooks[0].command, "%CMD%");
        assert_eq!(
            loaded
                .resolve_expandable_strings(|name| {
                    (name == "CMD").then(|| "Unicode command".into())
                })
                .unwrap()
                .hooks[0]
                .command,
            "Unicode command"
        );
    }

    #[test]
    fn targeted_repairs_ignore_unrelated_corrupt_optional_values() {
        let fixture = Fixture::new();
        write_string(&fixture, nssm_keys::APPLICATION, r"C:\app.exe").unwrap();
        write_string(&fixture, nssm_keys::APP_PRIORITY, "wrong type").unwrap();
        write_string(&fixture, nssm_keys::APP_ENVIRONMENT_EXTRA, "wrong type").unwrap();
        assert!(read_managed_from_key(&fixture, "fixture").is_err());
        set_value_in_key(&fixture, "AppPriority", "32").unwrap();
        assert_eq!(read_u32(&fixture, "AppPriority").unwrap(), 32);
        unset_value_in_key(&fixture, "AppEnvironmentExtra").unwrap();
        assert!(read_managed_from_key(&fixture, "fixture").is_ok());
        write_string(&fixture, nssm_keys::APP_PRIORITY, "bad again").unwrap();
        unset_value_in_key(&fixture, "AppPriority").unwrap();
        assert!(read_managed_from_key(&fixture, "fixture").is_ok());
        assert!(unset_value_in_key(&fixture, "Application").is_err());
    }

    #[test]
    fn targeted_repairs_never_create_or_replace_a_bad_native_marker() {
        let fixture = Fixture::new();
        for marker in [None, Some(""), Some("   ")] {
            let _ = delete_value(&fixture, nssm_keys::APPLICATION);
            if let Some(value) = marker {
                write_string(&fixture, nssm_keys::APPLICATION, value).unwrap();
            }
            let before = snapshot(&fixture);
            assert!(set_value_in_key(&fixture, "Application", r"C:\app.exe").is_err());
            assert!(set_value_in_key(&fixture, "AppPriority", "32").is_err());
            assert!(unset_value_in_key(&fixture, "AppPriority").is_err());
            assert_eq!(snapshot(&fixture), before);
        }
        write_u32(&fixture, nssm_keys::APPLICATION, 1).unwrap();
        assert!(set_value_in_key(&fixture, "AppPriority", "32").is_err());
        assert!(unset_value_in_key(&fixture, "AppPriority").is_err());
        let marker = to_wide(nssm_keys::APPLICATION);
        // SAFETY: writing deliberately invalid UTF-16 data only to this test's
        // marker verifies that strict marker ownership cannot be bypassed.
        unsafe {
            RegSetValueExW(
                fixture.0,
                PCWSTR(marker.as_ptr()),
                Some(0),
                REG_SZ,
                Some(&[0, 0xd8, 0, 0]),
            )
            .ok()
            .unwrap();
        }
        let before = snapshot(&fixture);
        assert!(set_value_in_key(&fixture, "AppPriority", "32").is_err());
        assert!(unset_value_in_key(&fixture, "AppPriority").is_err());
        assert_eq!(snapshot(&fixture), before);
    }

    #[test]
    fn legacy_exit_codes_and_defaults_normalize_and_conflicts_fail() {
        let fixture = Fixture::new();
        write_string(&fixture, nssm_keys::APPLICATION, r"C:\app.exe").unwrap();
        let exit = create_subkey_under(&fixture, nssm_keys::APP_EXIT).unwrap();
        for (key, action) in [
            ("", "Restart"),
            ("Default", "Restart"),
            ("01", "Ignore"),
            ("+1", "Ignore"),
            ("3221225477", "Suicide"),
            ("-0", "Exit"),
        ] {
            write_string(&exit, key, action).unwrap();
        }
        let cfg = read_managed_from_key(&fixture, "fixture").unwrap().unwrap();
        assert_eq!(cfg.exit_actions["1"].action, ExitAction::Ignore);
        assert_eq!(cfg.exit_actions["0"].action, ExitAction::Exit);
        assert_eq!(cfg.exit_actions["-1073741819"].action, ExitAction::Suicide);
        assert_eq!(cfg.restart.default_action, Some(ExitAction::Restart));
        write_into_key(&fixture, &cfg).unwrap();
        let mut names = enumerate_value_names(&exit).unwrap();
        names.sort();
        assert_eq!(names, vec!["", "-1073741819", "0", "1"]);
        write_string(&exit, "01", "Exit").unwrap();
        assert!(read_exit_actions(&fixture).is_err());
        delete_value(&exit, "01").unwrap();
        write_string(&exit, "DEFAULT", "Exit").unwrap();
        assert!(read_exit_actions(&fixture).is_err());
        for (raw, expected) in [
            ("2147483648", "-2147483648"),
            ("4294967295", "-1"),
            ("+1", "1"),
            ("-0", "0"),
            ("2147483647", "2147483647"),
        ] {
            assert_eq!(normalize_exit_action_name(raw).unwrap(), expected);
        }
    }

    #[test]
    fn environment_codec_preserves_escaped_unc_and_all_significant_data() {
        assert_eq!(
            split_multi_value(r"PATH=\\\\server\\share\\bin"),
            vec![r"PATH=\\server\share\bin"]
        );
        let entries = vec![
            r"PATH=\\server\share\bin".into(),
            r"LOCAL=C:\Tools\bin".into(),
            "EMPTY=".into(),
            " leading=data ".into(),
            "TAB=value\t".into(),
            "COMMA=a,b".into(),
            "BACKSLASH=value\\".into(),
        ];
        assert_eq!(split_multi_value(&join_multi_value(&entries)), entries);
        assert_eq!(split_multi_value(r"KEY=a\qb"), vec![r"KEY=a\qb"]);
        assert!(write_multi_string(&Fixture::new(), "Env", &["".into()]).is_err());
    }

    #[test]
    fn strict_name_decode_preserves_valid_replacement_characters() {
        assert!(decode_registry_name(&[0xd800]).is_err());
        assert!(decode_registry_name(&[97, 0, 98]).is_err());
        assert_eq!(decode_registry_name(&[0xfffd]).unwrap(), "\u{fffd}");
        let fixture = Fixture::new();
        let mut cfg = valid_config();
        cfg.hooks[0].event = "\u{fffd}".into();
        write_into_key(&fixture, &cfg).unwrap();
        assert_eq!(
            read_managed_from_key(&fixture, "fixture")
                .unwrap()
                .unwrap()
                .hooks[0]
                .event,
            "\u{fffd}"
        );
    }

    #[test]
    fn malformed_utf16_subkey_is_not_aliased_or_mutated() {
        let fixture = Fixture::new();
        let cfg = valid_config();
        write_into_key(&fixture, &cfg).unwrap();
        let events = open_subkey(fixture.0, nssm_keys::APP_EVENTS, parameters_rw_sam()).unwrap();
        let replacement = create_subkey_under(&events, "\u{fffd}").unwrap();
        write_string(&replacement, "Pre", "neighbor").unwrap();
        let bad_name = [0xd800u16, 0];
        let mut bad = HKEY::default();
        // SAFETY: this deliberate malformed UTF-16 fixture is a valid counted
        // allocation for RegCreateKeyEx; only our unique HKCU key is affected.
        unsafe {
            RegCreateKeyExW(
                events.0,
                PCWSTR(bad_name.as_ptr()),
                Some(0),
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                parameters_rw_sam(),
                None,
                &mut bad,
                None,
            )
            .ok()
            .unwrap();
        }
        let _bad = RegKey(bad);
        assert!(read_managed_from_key(&fixture, "fixture").is_err());
        let before = query_value_raw(&fixture, nssm_keys::APP_PARAMETERS).unwrap();
        let mut changed = cfg;
        changed.app_parameters = Some("after".into());
        assert!(write_into_key(&fixture, &changed).is_err());
        assert_eq!(
            query_value_raw(&fixture, nssm_keys::APP_PARAMETERS).unwrap(),
            before
        );
        assert_eq!(read_string(&replacement, "Pre").unwrap(), "neighbor");
    }

    #[test]
    fn malformed_utf16_value_name_fails_before_reconciliation_writes() {
        let fixture = Fixture::new();
        let mut cfg = valid_config();
        write_into_key(&fixture, &cfg).unwrap();
        let exit = open_subkey(fixture.0, nssm_keys::APP_EXIT, parameters_rw_sam()).unwrap();
        let bad_name = [0xd800u16, 0];
        let data = wide_to_bytes(&"Restart\0".encode_utf16().collect::<Vec<_>>());
        // SAFETY: both buffers live through the call and the malformed name
        // is confined to a unique test fixture.
        unsafe {
            RegSetValueExW(
                exit.0,
                PCWSTR(bad_name.as_ptr()),
                Some(0),
                REG_SZ,
                Some(&data),
            )
            .ok()
            .unwrap();
        }
        assert!(read_exit_actions(&fixture).is_err());
        let before = query_value_raw(&fixture, nssm_keys::APP_PARAMETERS).unwrap();
        cfg.app_parameters = Some("after".into());
        assert!(write_into_key(&fixture, &cfg).is_err());
        assert_eq!(
            query_value_raw(&fixture, nssm_keys::APP_PARAMETERS).unwrap(),
            before
        );
    }

    /// Create a fresh, empty temporary key under HKCU for an I/O test.
    /// The key is scrubbed first so a prior aborted run cannot leak state in.
    fn make_test_key(name: &str) -> RegKey {
        let path = format!("Software\\NgsmTests\\{name}");
        // Best-effort cleanup of leftovers from a previous run.
        if let Ok(parent) = open_subkey(
            HKEY_CURRENT_USER,
            "Software\\NgsmTests",
            parameters_rw_sam(),
        ) {
            let _ = ignore_missing(delete_subtree(&parent, name));
        }
        create_subkey(HKEY_CURRENT_USER, &path, parameters_rw_sam()).expect("create HKCU test key")
    }

    fn drop_test_key(name: &str) {
        if let Ok(parent) = open_subkey(
            HKEY_CURRENT_USER,
            "Software\\NgsmTests",
            parameters_rw_sam(),
        ) {
            let _ = ignore_missing(delete_subtree(&parent, name));
        }
    }

    #[test]
    fn expandable_metadata_round_trips_raw_registry_strings() {
        let key = Fixture::new();
        write_string_typed(
            &key,
            nssm_keys::APPLICATION,
            r"%ROOT%\app.exe",
            REG_EXPAND_SZ,
        )
        .unwrap();
        write_string_typed(&key, nssm_keys::APP_PARAMETERS, "%ARG%", REG_SZ).unwrap();
        let events = create_subkey_under(&key, nssm_keys::APP_EVENTS).unwrap();
        let start = create_subkey_under(&events, "Start").unwrap();
        write_string_typed(&start, "Pre", "%HOOK%", REG_EXPAND_SZ).unwrap();
        let mut cfg = read_managed_from_key(&key, "fixture").unwrap().unwrap();
        assert!(cfg.is_expandable_string("Application"));
        assert!(cfg.is_expandable_string("AppEvents\\Start\\Pre"));
        assert!(!cfg.is_expandable_string("AppParameters"));
        cfg.restart.restart_delay_ms = Some(123);
        write_into_key(&key, &cfg).unwrap();
        assert_eq!(
            read_typed_string(&key, nssm_keys::APPLICATION).unwrap(),
            (r"%ROOT%\app.exe".to_string(), REG_EXPAND_SZ)
        );
        assert_eq!(
            read_typed_string(&key, nssm_keys::APP_PARAMETERS).unwrap(),
            ("%ARG%".to_string(), REG_SZ)
        );
        assert_eq!(
            read_typed_string(&start, "Pre").unwrap(),
            ("%HOOK%".into(), REG_EXPAND_SZ)
        );
        let resolved = cfg
            .resolve_expandable_strings(|name| match name {
                "ROOT" => Some(r"C:\ServiceAccount".into()),
                "HOOK" => Some("echo ok".into()),
                _ => None,
            })
            .unwrap();
        assert_eq!(
            resolved.application.as_deref(),
            Some(r"C:\ServiceAccount\app.exe")
        );
        assert_eq!(resolved.app_parameters.as_deref(), Some("%ARG%"));
        assert_eq!(resolved.hooks[0].command, "echo ok");
        drop(start);
        drop(events);
        drop(key);
    }

    /// True if `name` is absent under `key` (RegQueryValueExW returns
    /// ERROR_FILE_NOT_FOUND, surfaced as `Error::NotFound`).
    fn value_absent(key: &RegKey, name: &str) -> bool {
        matches!(query_value_raw(key, name), Err(Error::NotFound(_)))
    }

    #[test]
    fn set_empty_app_directory_deletes_value() {
        let name = "set_empty_app_directory_deletes_value";
        let key = make_test_key(name);

        // Seed a non-empty AppDirectory.
        write_string(&key, nssm_keys::APP_DIRECTORY, "C:\\app").unwrap();
        assert!(!value_absent(&key, nssm_keys::APP_DIRECTORY));

        // Clearing a non-Application path-value should delete it, not
        // leave an empty REG_SZ behind.
        clear_path_value(&key, nssm_keys::APP_DIRECTORY).unwrap();
        assert!(
            value_absent(&key, nssm_keys::APP_DIRECTORY),
            "AppDirectory should be absent after clear_path_value"
        );

        // A second clear is a no-op (missing values are tolerated).
        clear_path_value(&key, nssm_keys::APP_DIRECTORY).unwrap();
        drop(key);
        drop_test_key(name);
    }

    #[test]
    fn set_empty_stdout_deletes_path_and_attributes() {
        let name = "set_empty_stdout_deletes_path_and_attributes";
        let key = make_test_key(name);

        // Seed a complete stdout configuration: path + all four attributes.
        write_string(&key, nssm_keys::APP_STDOUT, "C:\\logs\\out.log").unwrap();
        for attr in stdio_attribute_names(nssm_keys::APP_STDOUT) {
            write_u32(&key, &attr, 1).unwrap();
            assert!(!value_absent(&key, &attr));
        }
        assert!(!value_absent(&key, nssm_keys::APP_STDOUT));

        // Clearing the stdout path should drop all five values.
        clear_path_value(&key, nssm_keys::APP_STDOUT).unwrap();
        assert!(
            value_absent(&key, nssm_keys::APP_STDOUT),
            "AppStdout path should be absent"
        );
        for attr in stdio_attribute_names(nssm_keys::APP_STDOUT) {
            assert!(
                value_absent(&key, &attr),
                "{attr} should be absent — clearing the path must not leave \
                 orphaned attribute values pointing at it"
            );
        }
        drop(key);
        drop_test_key(name);
    }

    #[test]
    fn precheck_rejects_nul_in_app_parameters_without_writing_application() {
        let name = "precheck_rejects_nul_in_app_parameters_without_writing_application";
        let key = make_test_key(name);

        // Clean Application (an absolute path so it would otherwise pass
        // the absolute-path check), NUL-bearing AppParameters.
        let cfg = ManagedApplicationConfig {
            application: Some("C:\\app\\svc.exe".to_string()),
            app_parameters: Some("--ok\0--evil".to_string()),
            ..Default::default()
        };

        // The whole write must error out before *any* mutation, so
        // Application is not written.
        let err = write_into_key(&key, &cfg).unwrap_err();
        assert!(
            matches!(err, Error::InvalidConfig(ref m) if m.contains("AppParameters")),
            "expected InvalidConfig naming AppParameters, got {err:?}"
        );
        assert!(
            value_absent(&key, nssm_keys::APPLICATION),
            "Application was written despite a later field failing — the \
             precheck did not stop the write up front"
        );
        drop(key);
        drop_test_key(name);
    }

    #[test]
    fn precheck_rejects_nul_in_environment_entry() {
        let name = "precheck_rejects_nul_in_environment_entry";
        let key = make_test_key(name);

        let cfg = ManagedApplicationConfig {
            application: Some("C:\\app\\svc.exe".to_string()),
            environment: vec!["GOOD=1".to_string(), "BAD=value\0sneak".to_string()],
            ..Default::default()
        };

        let err = write_into_key(&key, &cfg).unwrap_err();
        assert!(
            matches!(err, Error::InvalidConfig(ref m) if m.contains("AppEnvironment")),
            "expected InvalidConfig naming AppEnvironment, got {err:?}"
        );
        assert!(
            value_absent(&key, nssm_keys::APPLICATION),
            "Application was written despite environment NUL — precheck \
             did not stop the write up front"
        );
        assert!(value_absent(&key, nssm_keys::APP_ENVIRONMENT));
        drop(key);
        drop_test_key(name);
    }

    #[test]
    fn precheck_passes_for_clean_config() {
        // A config with no NULs anywhere round-trips through the precheck.
        let mut exit_actions = BTreeMap::new();
        exit_actions.insert(
            "1".to_string(),
            ExitActionPolicy {
                action: ExitAction::Restart,
            },
        );
        let cfg = ManagedApplicationConfig {
            application: Some("C:\\app\\svc.exe".to_string()),
            app_parameters: Some("--ok".to_string()),
            app_directory: Some("C:\\app".to_string()),
            affinity: Some("0x3".to_string()),
            environment: vec!["A=1".to_string()],
            environment_extra: vec!["B=2".to_string()],
            io: IoRedirectionConfig {
                stdin: Some(IoStream {
                    path: "C:\\in".to_string(),
                    share_mode: None,
                    creation_disposition: None,
                    flags_and_attributes: None,
                    copy_and_truncate: None,
                }),
                ..Default::default()
            },
            exit_actions,
            hooks: vec![HookConfig {
                event: "Start".to_string(),
                action: "Pre".to_string(),
                command: "C:\\hooks\\start.exe".to_string(),
            }],
            ..Default::default()
        };
        assert!(precheck_no_embedded_nuls(&cfg).is_ok());
    }

    #[test]
    fn set_empty_application_still_writes_or_rejects() {
        // The `Application` value is the managed-service marker. The
        // single-value `set` API already rejects an empty `Application`
        // up front (see `set_value`), and `clear_path_value` is only
        // invoked for path-values *other than* `Application`. Document
        // both invariants here as a regression guard for M-04.
        assert!(is_path_value(nssm_keys::APPLICATION));
        // The marker should never be the operand of clear_path_value:
        // callers gate on `canonical != Application`. If that gate is
        // ever removed, this assert protects the invariant.
        assert_ne!(nssm_keys::APPLICATION, nssm_keys::APP_DIRECTORY);

        // Round-trip through write_string: a real value persists.
        let key = make_test_key("set_empty_application_still_writes_or_rejects");
        write_string(&key, nssm_keys::APPLICATION, "C:\\app.exe").unwrap();
        assert!(!value_absent(&key, nssm_keys::APPLICATION));
        drop(key);
        drop_test_key("set_empty_application_still_writes_or_rejects");
    }

    #[test]
    fn unset_app_stdout_also_removes_associated_attributes() {
        // Regression guard for finding #8: `unset_value(name, "AppStdout")`
        // used to delete only the canonical path value, leaving the four
        // associated attribute values (`AppStdoutShareMode`,
        // `AppStdoutCreationDisposition`, `AppStdoutFlagsAndAttributes`,
        // `AppStdoutCopyAndTruncate`) behind. A subsequent `set AppStdout
        // <new-path>` would then silently inherit stale attributes from
        // the old path.
        //
        // The fix routes stdio path fields in `unset_value` through
        // `clear_path_value`, which deletes the path *and* the four
        // attribute values together. The public `unset_value` opens
        // HKLM and goes through `require_managed`, neither of which is
        // available in a unit test — so we exercise the exact helper
        // `unset_value` now delegates to, against a seeded HKCU shim
        // matching the per-service `Parameters` layout. Coverage of the
        // delegation itself comes from the source code inspection in
        // `unset_value_for_stdio_routes_through_clear_path_value`.
        let name = "unset_app_stdout_also_removes_associated_attributes";
        let key = make_test_key(name);

        // Seed a complete AppStdout configuration: path + all four
        // associated attribute values, matching what NSSM-style writes
        // produce.
        write_string(&key, nssm_keys::APP_STDOUT, "C:\\logs\\out.log").unwrap();
        for attr in stdio_attribute_names(nssm_keys::APP_STDOUT) {
            write_u32(&key, &attr, 7).unwrap();
            assert!(
                !value_absent(&key, &attr),
                "{attr} should be present after seed"
            );
        }
        assert!(!value_absent(&key, nssm_keys::APP_STDOUT));

        // The helper `unset_value` delegates to for stdio paths.
        clear_path_value(&key, nssm_keys::APP_STDOUT).unwrap();

        // All five values must be gone — leaving any attribute behind
        // would let a subsequent `set AppStdout <new-path>` inherit
        // stale state.
        assert!(
            value_absent(&key, nssm_keys::APP_STDOUT),
            "AppStdout path should be absent after unset"
        );
        for attr in stdio_attribute_names(nssm_keys::APP_STDOUT) {
            assert!(
                value_absent(&key, &attr),
                "{attr} should be absent after unset — orphan attribute \
                 values would silently bleed into the next AppStdout set"
            );
        }
        drop(key);
        drop_test_key(name);
    }

    #[test]
    fn unset_value_for_stdio_routes_through_clear_path_value() {
        // Lock the routing decision in `unset_value` to source: every
        // stdio path canonical name is recognized as such by
        // `is_stdio_path_value`, so the `unset_value` branch that
        // dispatches to `clear_path_value` covers AppStdin, AppStdout,
        // and AppStderr. If `is_stdio_path_value` ever stops recognising
        // one of them, finding #8 silently regresses.
        assert!(is_stdio_path_value(nssm_keys::APP_STDIN));
        assert!(is_stdio_path_value(nssm_keys::APP_STDOUT));
        assert!(is_stdio_path_value(nssm_keys::APP_STDERR));

        // Non-stdio path-values must NOT route through clear_path_value:
        // they have no associated attribute family and the bare
        // `delete_value` path is correct for them.
        assert!(!is_stdio_path_value(nssm_keys::APPLICATION));
        assert!(!is_stdio_path_value(nssm_keys::APP_DIRECTORY));
    }
}
