use std::collections::{BTreeMap, HashSet};
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

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

    // The defining marker of an NSSM/NGSM-managed service is a
    // non-empty `Application` value under `Parameters`. Many native Windows
    // services have a `Parameters` subkey of their own; without the marker
    // we treat them as native.
    let application = match opt_string(&key, nssm_keys::APPLICATION)? {
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

    let rotate_low = opt_u32(&key, nssm_keys::APP_ROTATE_BYTES_LOW)?;
    let rotate_high = opt_u32(&key, nssm_keys::APP_ROTATE_BYTES_HIGH)?;
    let rotate_bytes = match (rotate_low, rotate_high) {
        (None, None) => None,
        (lo, hi) => Some(((hi.unwrap_or(0) as u64) << 32) | lo.unwrap_or(0) as u64),
    };

    let exit_actions = read_exit_actions(&key)?;
    let default_action = exit_actions.get("default").map(|p| p.action);

    let cfg = ManagedApplicationConfig {
        application: Some(application),
        app_parameters: opt_string(&key, nssm_keys::APP_PARAMETERS)?,
        app_directory: opt_string(&key, nssm_keys::APP_DIRECTORY)?,
        environment: opt_multi_string(&key, nssm_keys::APP_ENVIRONMENT)?.unwrap_or_default(),
        environment_extra: opt_multi_string(&key, nssm_keys::APP_ENVIRONMENT_EXTRA)?
            .unwrap_or_default(),
        priority: opt_u32(&key, nssm_keys::APP_PRIORITY)?,
        affinity: opt_string(&key, nssm_keys::APP_AFFINITY)?,
        restart: RestartPolicy {
            restart_delay_ms: opt_u32(&key, nssm_keys::APP_RESTART_DELAY)?,
            throttle_delay_ms: opt_u32(&key, nssm_keys::APP_THROTTLE)?,
            default_action,
        },
        shutdown: ShutdownPolicy {
            stop_method_skip: opt_u32(&key, nssm_keys::APP_STOP_METHOD_SKIP)?,
            kill_console_grace_ms: opt_u32(&key, nssm_keys::APP_KILL_CONSOLE_GRACE)?,
            kill_window_grace_ms: opt_u32(&key, nssm_keys::APP_KILL_WINDOW_GRACE)?,
            kill_threads_grace_ms: opt_u32(&key, nssm_keys::APP_KILL_THREADS_GRACE)?,
            kill_process_tree: opt_u32(&key, nssm_keys::APP_KILL_PROCESS_TREE)?.map(|v| v != 0),
        },
        io: IoRedirectionConfig {
            stdin: read_io_stream(&key, nssm_keys::APP_STDIN)?,
            stdout: read_io_stream(&key, nssm_keys::APP_STDOUT)?,
            stderr: read_io_stream(&key, nssm_keys::APP_STDERR)?,
            timestamp_log: opt_u32(&key, nssm_keys::APP_TIMESTAMP_LOG)?.map(|v| v != 0),
        },
        rotation: LogRotationConfig {
            enabled: opt_u32(&key, nssm_keys::APP_ROTATE)?.map(|v| v != 0),
            online: opt_u32(&key, nssm_keys::APP_ROTATE_ONLINE)?,
            seconds: opt_u32(&key, nssm_keys::APP_ROTATE_SECONDS)?,
            bytes: rotate_bytes,
            delay_ms: opt_u32(&key, nssm_keys::APP_ROTATE_DELAY)?,
        },
        exit_actions,
        hooks: read_hooks(&key)?,
    };
    Ok(Some(cfg))
}

/// Normalize an `AppExit` value name to the internal exit-actions key.
///
/// NSSM stores the default action in the subkey's *unnamed* value, but a
/// named `Default` value (in any case) means exactly the same thing — both
/// map to the internal `"default"` key. A specific exit code (e.g. `"1"`)
/// passes through unchanged.
fn normalize_exit_action_name(name: &str) -> String {
    if name.is_empty() || name.eq_ignore_ascii_case("default") {
        "default".to_string()
    } else {
        name.to_string()
    }
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

fn read_io_stream(parent: &RegKey, value_name: &str) -> Result<Option<IoStream>> {
    let path = match opt_string(parent, value_name)? {
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
        let action_name = normalize_exit_action_name(&name);
        match parse_exit_action(&value) {
            Some(action) => {
                out.insert(action_name, ExitActionPolicy { action });
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

fn read_hooks(parent: &RegKey) -> Result<Vec<HookConfig>> {
    let events_key = match open_subkey(parent.0, nssm_keys::APP_EVENTS, KEY_READ) {
        Ok(k) => k,
        Err(Error::NotFound(_)) => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    for event in enumerate_subkey_names(&events_key)? {
        let event_key = match open_subkey(events_key.0, &event, KEY_READ) {
            Ok(k) => k,
            Err(Error::NotFound(_)) => continue,
            Err(e) => return Err(e),
        };
        for (action, command) in enumerate_string_values(&event_key)? {
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
        RegOpenKeyExW(parent, PCWSTR::from_raw(wide.as_ptr()), 0, sam, &mut key)
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
                if i + 1 != words.len() {
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
    let (ty, bytes) = query_value_raw(key, name)?;
    if ty != REG_SZ && ty != REG_EXPAND_SZ {
        return Err(Error::Registry(format!("value {name} is not REG_SZ")));
    }
    bytes_to_wide_string(&bytes)
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
                PWSTR::from_raw(name_buf.as_mut_ptr()),
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

        let name = OsString::from_wide(&name_buf[..name_len as usize])
            .to_string_lossy()
            .into_owned();
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
        out.push((name, bytes_to_wide_string(&value_buf)?));
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
                PWSTR::from_raw(name_buf.as_mut_ptr()),
                &mut name_len,
                None,
                PWSTR::null(),
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

        out.push(
            OsString::from_wide(&name_buf[..name_len as usize])
                .to_string_lossy()
                .into_owned(),
        );
        index += 1;
    }
    Ok(out)
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
/// trimmed, and empty entries are dropped — `REG_MULTI_SZ` cannot represent
/// an empty string (it doubles as the block terminator).
fn split_multi_value(value: &str) -> Vec<String> {
    let mut entries: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        match c {
            // `\` escapes the next character; a trailing lone `\` is literal.
            '\\' => match chars.next() {
                Some(next) => current.push(next),
                None => current.push('\\'),
            },
            ',' => entries.push(std::mem::take(&mut current)),
            other => current.push(other),
        }
    }
    entries.push(current);
    entries
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
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
    require_managed(service)?;
    let key = create_parameters_key(service)?;
    match kind {
        ManagedValueKind::String => write_string(&key, &canonical, value)?,
        ManagedValueKind::MultiString => {
            // Comma-separated input, with `\,` / `\\` escapes so an entry
            // that genuinely contains a comma round-trips through `get`.
            let parts = split_multi_value(value);
            write_multi_string(&key, &canonical, &parts)?;
        }
        ManagedValueKind::Number => {
            let parsed: u32 = value.parse().map_err(|_| {
                Error::InvalidConfig(format!(
                    "{canonical} expects a numeric value, got '{value}'"
                ))
            })?;
            write_u32(&key, &canonical, parsed)?;
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
pub fn unset_value(service: &str, name: &str) -> Result<()> {
    validate_service_name(service)?;
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
    require_managed(service)?;
    let path = format!("SYSTEM\\CurrentControlSet\\Services\\{service}\\Parameters");
    let key = match open_subkey(HKEY_LOCAL_MACHINE, &path, KEY_WRITE) {
        Ok(k) => k,
        Err(Error::NotFound(_)) => return Ok(()),
        Err(e) => return Err(e),
    };
    ignore_missing(delete_value(&key, &canonical))
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

/// Require that `service` already has managed configuration. `set`/`unset`
/// only *mutate* an existing managed config — they must not be able to
/// create the managed-service marker on an arbitrary native service.
fn require_managed(service: &str) -> Result<()> {
    if read_managed_config(service)?.is_none() {
        return Err(Error::InvalidConfig(format!(
            "'{service}' has no managed configuration; create one with `install` first"
        )));
    }
    Ok(())
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
    require_application(cfg)?;
    let key = create_parameters_key(service)?;
    write_into_key(&key, cfg)
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
    require_application(cfg)?;
    let path = format!("SYSTEM\\CurrentControlSet\\Services\\{service}\\Parameters");
    let key = open_subkey(HKEY_LOCAL_MACHINE, &path, parameters_rw_sam())?;
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
    let path = format!("SYSTEM\\CurrentControlSet\\Services\\{service}\\Parameters");
    let key = match open_subkey(HKEY_LOCAL_MACHINE, &path, parameters_rw_sam()) {
        Ok(k) => k,
        Err(Error::NotFound(_)) => return Ok(()),
        Err(e) => return Err(e),
    };
    scrub_managed(&key)
}

/// Open the service's key (which must exist) and create `Parameters` under
/// it. Refusing to create the service key itself is what prevents
/// orphan service-like keys appearing from typos or bad input.
fn create_parameters_key(service: &str) -> Result<RegKey> {
    let service_path = format!("SYSTEM\\CurrentControlSet\\Services\\{service}");
    let service_key = open_subkey(HKEY_LOCAL_MACHINE, &service_path, KEY_WRITE | KEY_READ)?;
    create_subkey_under(&service_key, "Parameters")
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

/// Write `cfg` into an open `Parameters` key, reconciling away any stale
/// managed data left by a previous config.
///
/// Crucially this is **write-first**: every value present in `cfg` is
/// written *before* any delete happens. A failure partway through can leave
/// a few stale values behind, but it can never erase the previous working
/// `Application`/IO/restart config — which a delete-then-write order would.
fn write_into_key(key: &RegKey, cfg: &ManagedApplicationConfig) -> Result<()> {
    // Validate hook names up front, before mutating the registry at all.
    for hook in &cfg.hooks {
        validate_hook_component(&hook.event, "event")?;
        validate_hook_component(&hook.action, "action")?;
    }
    // Every configured filesystem path must be absolute — a relative
    // application path would resolve through the service account's PATH /
    // working directory (search-path confusion), and relative log paths are
    // ambiguous. Checked before any registry mutation.
    if let Some(app) = &cfg.application {
        validate_absolute_path("Application", app)?;
    }
    if let Some(dir) = cfg.app_directory.as_deref().filter(|d| !d.is_empty()) {
        validate_absolute_path("AppDirectory", dir)?;
    }
    if let Some(s) = &cfg.io.stdin {
        validate_absolute_path("AppStdin", &s.path)?;
    }
    if let Some(s) = &cfg.io.stdout {
        validate_absolute_path("AppStdout", &s.path)?;
    }
    if let Some(s) = &cfg.io.stderr {
        validate_absolute_path("AppStderr", &s.path)?;
    }

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
            write_string(key, nssm_keys::APPLICATION, v)?
        );
    }
    if let Some(v) = &cfg.app_parameters {
        put!(
            nssm_keys::APP_PARAMETERS,
            write_string(key, nssm_keys::APP_PARAMETERS, v)?
        );
    }
    if let Some(v) = &cfg.app_directory {
        put!(
            nssm_keys::APP_DIRECTORY,
            write_string(key, nssm_keys::APP_DIRECTORY, v)?
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
            write_string(key, nssm_keys::APP_AFFINITY, v)?
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
    for name in write_io_stream(key, nssm_keys::APP_STDIN, &cfg.io.stdin)? {
        written.insert(name);
    }
    for name in write_io_stream(key, nssm_keys::APP_STDOUT, &cfg.io.stdout)? {
        written.insert(name);
    }
    for name in write_io_stream(key, nssm_keys::APP_STDERR, &cfg.io.stderr)? {
        written.insert(name);
    }

    // --- Phase 2a: reconcile the AppExit subtree (write new, prune stale). ---
    // `restart.default_action` is the typed mirror of AppExit's "default"
    // entry. If a caller set it without also populating `exit_actions`, the
    // default action would otherwise be silently dropped on write — so
    // synthesize the "default" entry from it when one is not already present.
    let mut exit_actions = cfg.exit_actions.clone();
    if let Some(action) = cfg.restart.default_action {
        exit_actions
            .entry("default".to_string())
            .or_insert(ExitActionPolicy { action });
    }
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
            write_string(&exit_key, registry_name, exit_action_str(policy.action))?;
            wanted.insert(registry_name.to_string());
        }
        for (existing, _) in enumerate_string_values(&exit_key)? {
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
        let mut wanted: BTreeMap<String, HashSet<String>> = BTreeMap::new();
        for hook in &cfg.hooks {
            // Layout matches the reader: `AppEvents\<event>` is a subkey
            // and each `<action>` is a named REG_SZ value under it.
            let event_key = create_subkey_under(&events_key, &hook.event)?;
            write_string(&event_key, &hook.action, &hook.command)?;
            wanted
                .entry(hook.event.clone())
                .or_default()
                .insert(hook.action.clone());
        }
        for existing_event in enumerate_subkey_names(&events_key)? {
            match wanted.get(&existing_event) {
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
                    for (existing_action, _) in enumerate_string_values(&event_key)? {
                        if !wanted_actions.contains(&existing_action) {
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
fn write_io_stream(parent: &RegKey, base: &str, stream: &Option<IoStream>) -> Result<Vec<String>> {
    let Some(stream) = stream else {
        return Ok(Vec::new());
    };
    let mut names = vec![base.to_string()];
    write_string(parent, base, &stream.path)?;
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
            0,
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
            0,
            REG_SZ,
            Some(&bytes),
        )
        .ok()
        .map_err(|e| map_reg_error(&format!("RegSetValueEx({name})"), e))?;
    }
    Ok(())
}

fn write_multi_string(key: &RegKey, name: &str, values: &[String]) -> Result<()> {
    // An embedded NUL in any entry would split or truncate it on read-back.
    if values.iter().any(|v| v.contains('\0')) {
        return Err(Error::Registry(format!(
            "value '{name}' has an entry containing an embedded NUL and cannot be \
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
            0,
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
            0,
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
    fn exit_action_names_normalize_default() {
        // The unnamed value and a named `Default` (any case) all collapse to
        // the internal "default" key; specific exit codes pass through.
        assert_eq!(normalize_exit_action_name(""), "default");
        assert_eq!(normalize_exit_action_name("Default"), "default");
        assert_eq!(normalize_exit_action_name("DEFAULT"), "default");
        assert_eq!(normalize_exit_action_name("default"), "default");
        assert_eq!(normalize_exit_action_name("0"), "0");
        assert_eq!(normalize_exit_action_name("1"), "1");
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
}
