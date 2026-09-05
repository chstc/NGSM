//! Install / remove / start / stop / control wrappers around the SCM.

use std::ffi::c_void;
use std::fmt;
use std::mem::size_of;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{compiler_fence, Ordering};

use servicemanager_core::{
    quote_windows_arg, validate_service_name, Error, Result, ServiceRuntimeState,
};
use windows::core::{BOOL, PCWSTR, PWSTR};
use windows::Win32::Foundation::{LocalFree, ERROR_SUCCESS, GENERIC_ALL, GENERIC_WRITE, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertStringSidToSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    EqualSid, GetAce, GetLengthSid, GetSecurityDescriptorDacl, IsValidAcl, IsValidSid,
    IsWellKnownSid, WinAuthenticatedUserSid, WinBuiltinAdministratorsSid, WinBuiltinUsersSid,
    WinInteractiveSid, WinLocalSystemSid, WinWorldSid, ACE_HEADER,
    ACE_INHERITED_OBJECT_TYPE_PRESENT, ACE_OBJECT_TYPE_PRESENT, ACL, DACL_SECURITY_INFORMATION,
    INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
};
use windows::Win32::Storage::FileSystem::{
    DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_APPEND_DATA, FILE_DELETE_CHILD,
    FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, WRITE_DAC, WRITE_OWNER,
};
use windows::Win32::System::Services::{
    ChangeServiceConfig2W, ChangeServiceConfigW, ControlService, CreateServiceW, DeleteService,
    QueryServiceStatusEx, StartServiceW, ENUM_SERVICE_TYPE, SC_MANAGER_CONNECT,
    SC_MANAGER_CREATE_SERVICE, SC_STATUS_PROCESS_INFO, SERVICE_AUTO_START, SERVICE_CHANGE_CONFIG,
    SERVICE_CONFIG_DESCRIPTION, SERVICE_CONTROL_CONTINUE, SERVICE_CONTROL_INTERROGATE,
    SERVICE_CONTROL_PAUSE, SERVICE_CONTROL_STOP, SERVICE_DEMAND_START, SERVICE_DESCRIPTIONW,
    SERVICE_DISABLED, SERVICE_ERROR, SERVICE_ERROR_NORMAL, SERVICE_INTERROGATE, SERVICE_NO_CHANGE,
    SERVICE_PAUSE_CONTINUE, SERVICE_QUERY_STATUS, SERVICE_START, SERVICE_START_TYPE,
    SERVICE_STATUS, SERVICE_STATUS_PROCESS, SERVICE_STOP, SERVICE_USER_DEFINED_CONTROL,
    SERVICE_WIN32_OWN_PROCESS,
};
use windows::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_ALLOWED_COMPOUND_ACE_TYPE,
    ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, ACCESS_DENIED_CALLBACK_ACE_TYPE,
    ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_DENIED_OBJECT_ACE_TYPE,
};

use crate::handles::{map_win_error, open_scm, open_service_handle, to_wide};
use crate::scm::classify_state_pub as classify_state;

/// Generic Windows `DELETE` access right (not exported from the Services
/// module of windows-rs 0.58 even though `DeleteService` requires it).
const DELETE_ACCESS: u32 = 0x0001_0000;
const TRUSTED_INSTALLER_SID: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

const FILE_DANGEROUS_ACCESS: u32 = GENERIC_ALL.0
    | GENERIC_WRITE.0
    | DELETE.0
    | WRITE_DAC.0
    | WRITE_OWNER.0
    | FILE_WRITE_DATA.0
    | FILE_APPEND_DATA.0
    | FILE_WRITE_EA.0
    | FILE_WRITE_ATTRIBUTES.0;
const DIRECTORY_DANGEROUS_ACCESS: u32 =
    FILE_DANGEROUS_ACCESS | FILE_ADD_FILE.0 | FILE_ADD_SUBDIRECTORY.0 | FILE_DELETE_CHILD.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AclObjectKind {
    File,
    Directory,
    VolumeRoot,
}

impl AclObjectKind {
    fn label(self) -> &'static str {
        match self {
            AclObjectKind::File => "file",
            AclObjectKind::Directory => "directory",
            AclObjectKind::VolumeRoot => "volume root",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AclPrincipal {
    Trusted(&'static str),
    KnownUntrusted(&'static str),
    Unknown,
}

impl AclPrincipal {
    fn is_trusted(self) -> bool {
        matches!(self, AclPrincipal::Trusted(_))
    }

    fn label(self) -> &'static str {
        match self {
            AclPrincipal::Trusted(name) | AclPrincipal::KnownUntrusted(name) => name,
            AclPrincipal::Unknown => "an unknown SID",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AclAllowedGrant {
    principal: AclPrincipal,
    mask: u32,
    inherit_only: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AclDecisionError {
    UntrustedOwner {
        principal: AclPrincipal,
    },
    DangerousGrant {
        principal: AclPrincipal,
        mask: u32,
        dangerous_mask: u32,
        object_kind: AclObjectKind,
    },
}

/// User-facing controls that map to SCM `ControlService` codes we support today.
#[derive(Debug, Clone, Copy)]
pub enum ServiceControlSignal {
    Stop,
    Pause,
    Continue,
    Interrogate,
    /// A user-defined control code in the range 128..=255.
    User(u32),
}

/// NSSM-compatible user control code that requests a log rotation.
pub const SERVICE_CONTROL_ROTATE: u32 = 174;

impl ServiceControlSignal {
    fn to_win32(self) -> u32 {
        match self {
            ServiceControlSignal::Stop => SERVICE_CONTROL_STOP,
            ServiceControlSignal::Pause => SERVICE_CONTROL_PAUSE,
            ServiceControlSignal::Continue => SERVICE_CONTROL_CONTINUE,
            ServiceControlSignal::Interrogate => SERVICE_CONTROL_INTERROGATE,
            ServiceControlSignal::User(code) => code,
        }
    }

    fn required_access(self) -> u32 {
        // We always include `SERVICE_QUERY_STATUS` because every control path
        // re-queries the post-control status to return it to the caller.
        let base = SERVICE_QUERY_STATUS;
        match self {
            ServiceControlSignal::Stop => base | SERVICE_STOP,
            ServiceControlSignal::Pause | ServiceControlSignal::Continue => {
                base | SERVICE_PAUSE_CONTINUE
            }
            // `Interrogate` is a standard control with its own access right;
            // it must not be grouped with the user-defined controls.
            ServiceControlSignal::Interrogate => base | SERVICE_INTERROGATE,
            ServiceControlSignal::User(_) => base | SERVICE_USER_DEFINED_CONTROL,
        }
    }
}

#[derive(Clone)]
pub struct InstallOptions {
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub binary_path: String,
    pub start_type: InstallStartType,
    pub dependencies: ServiceDependencies,
    pub account: Option<String>,
    pub password: Option<String>,
}

impl fmt::Debug for InstallOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InstallOptions")
            .field("name", &self.name)
            .field("display_name", &self.display_name)
            .field("description", &self.description)
            .field("binary_path", &self.binary_path)
            .field("start_type", &self.start_type)
            .field("dependencies", &self.dependencies)
            .field("account", &self.account)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceDependencies {
    pub services: Vec<String>,
    pub groups: Vec<String>,
}

impl ServiceDependencies {
    pub fn is_empty(&self) -> bool {
        self.services.is_empty() && self.groups.is_empty()
    }

    pub fn validate(&self) -> Result<()> {
        for service in &self.services {
            validate_service_dependency_name(service)?;
        }
        for group in &self.groups {
            validate_group_dependency_name(group)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum InstallStartType {
    #[default]
    Manual,
    Automatic,
    Disabled,
}

impl InstallStartType {
    fn to_win32(self) -> SERVICE_START_TYPE {
        match self {
            InstallStartType::Manual => SERVICE_DEMAND_START,
            InstallStartType::Automatic => SERVICE_AUTO_START,
            InstallStartType::Disabled => SERVICE_DISABLED,
        }
    }
}

fn validate_service_dependency_name(value: &str) -> Result<()> {
    if value.starts_with('+') {
        return Err(Error::InvalidConfig(
            "service dependency must not begin with '+'; use a group dependency instead".into(),
        ));
    }
    validate_service_name(value).map_err(|_| {
        Error::InvalidConfig(
            "service dependency entry must be a valid service name (non-empty, \
             at most 256 UTF-16 code units, and no path separators or control characters)"
                .into(),
        )
    })
}

fn validate_group_dependency_name(value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(Error::InvalidConfig(
            "group dependency entry must not be empty".into(),
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(Error::InvalidConfig(
            "group dependency entry must not contain NUL or control characters".into(),
        ));
    }
    if value == "." || value == ".." || value.chars().any(is_group_dependency_path_char) {
        return Err(Error::InvalidConfig(
            "group dependency entry must not contain path separators or path-like characters"
                .into(),
        ));
    }
    Ok(())
}

fn is_group_dependency_path_char(ch: char) -> bool {
    matches!(ch, '\\' | '/' | ':')
}

fn encode_dependencies(dependencies: &ServiceDependencies) -> Result<Vec<u16>> {
    dependencies.validate()?;
    if dependencies.is_empty() {
        return Ok(vec![0, 0]);
    }

    let mut wide = Vec::new();
    for service in &dependencies.services {
        wide.extend(service.encode_utf16());
        wide.push(0);
    }
    for group in &dependencies.groups {
        wide.push('+' as u16);
        wide.extend(group.encode_utf16());
        wide.push(0);
    }
    wide.push(0);
    Ok(wide)
}

fn validate_account(account: &str) -> Result<()> {
    if account.chars().any(char::is_control) {
        return Err(Error::InvalidConfig(
            "service account must not contain NUL or control characters".into(),
        ));
    }
    Ok(())
}

fn validate_password(password: &str) -> Result<()> {
    if password.contains('\0') {
        return Err(Error::InvalidConfig(
            "password contains an embedded NUL, which cannot be passed to the SCM".into(),
        ));
    }
    Ok(())
}

fn validate_native_string(field: &str, value: &str) -> Result<()> {
    if value.contains('\0') {
        return Err(Error::InvalidConfig(format!(
            "{field} must not contain an embedded NUL"
        )));
    }
    Ok(())
}

/// Pure preflight for native edits. Call before any managed or SCM mutation.
pub fn validate_native_update(
    name: &str,
    display_name: Option<&str>,
    description: Option<&str>,
    dependencies: Option<&ServiceDependencies>,
    account: Option<&str>,
    password: Option<&str>,
) -> Result<()> {
    validate_service_name(name)?;
    if let Some(display) = display_name {
        validate_native_string("display name", display)?;
        if display.encode_utf16().count() > 256 {
            return Err(Error::InvalidConfig(
                "display name exceeds 256 UTF-16 code units".into(),
            ));
        }
    }
    if let Some(description) = description {
        validate_native_string("description", description)?;
    }
    if let Some(dependencies) = dependencies {
        dependencies.validate()?;
    }
    if let Some(account) = account {
        validate_account(account)?;
    }
    if let Some(password) = password {
        validate_password(password)?;
        if account.is_none() {
            return Err(Error::InvalidConfig(
                "--password-stdin requires --account so the SCM can apply the password".into(),
            ));
        }
    }
    Ok(())
}

fn zeroize_wide_buffer(buf: &mut [u16]) {
    for unit in buf {
        // SAFETY: `unit` is a valid mutable reference. Volatile writes prevent
        // the compiler from eliding the secret wipe as dead stores.
        unsafe {
            std::ptr::write_volatile(unit, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

/// Create a Windows service whose image path points at the supplied
/// `binary_path` (which should already include any args the service runner
/// needs, e.g. `\"C:\\…\\ngsm.exe\" run-service MyService`).
pub fn install_service(opts: &InstallOptions) -> Result<()> {
    validate_install_options(opts)?;
    install_validated_service(opts)
}

fn validate_install_options(opts: &InstallOptions) -> Result<()> {
    validate_native_update(
        &opts.name,
        Some(&opts.display_name),
        opts.description.as_deref(),
        Some(&opts.dependencies),
        opts.account.as_deref(),
        opts.password.as_deref(),
    )?;
    validate_native_string("binary path", &opts.binary_path)
}

fn install_validated_service(opts: &InstallOptions) -> Result<()> {
    let scm = open_scm(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;
    let name = to_wide(&opts.name);
    let display = to_wide(&opts.display_name);
    let path = to_wide(&opts.binary_path);
    let dependencies_wide = if opts.dependencies.is_empty() {
        None
    } else {
        Some(encode_dependencies(&opts.dependencies)?)
    };
    if let Some(account) = opts.account.as_deref() {
        validate_account(account)?;
    }
    if opts.password.is_some() && opts.account.is_none() {
        return Err(Error::InvalidConfig(
            "--password-stdin requires --account so the SCM can apply the password".into(),
        ));
    }
    let account_wide = opts.account.as_deref().map(to_wide);
    if let Some(password) = opts.password.as_deref() {
        validate_password(password)?;
    }
    let mut password_wide = opts.password.as_deref().map(to_wide);
    let dependencies_pcwstr = dependencies_wide
        .as_ref()
        .map_or(PCWSTR::null(), |w| PCWSTR::from_raw(w.as_ptr()));
    let account_pcwstr = account_wide
        .as_ref()
        .map_or(PCWSTR::null(), |w| PCWSTR::from_raw(w.as_ptr()));
    let password_pcwstr = password_wide
        .as_ref()
        .map_or(PCWSTR::null(), |w| PCWSTR::from_raw(w.as_ptr()));
    // SAFETY: `scm.0` is a valid SCM handle opened with `SC_MANAGER_CREATE_SERVICE`;
    // `name`, `display`, `path`, and optional dependency/account/password buffers
    // are null-terminated UTF-16 vecs that outlive the call. The returned service
    // handle is wrapped in ScHandle for RAII close.
    let handle_result = unsafe {
        CreateServiceW(
            scm.0,
            PCWSTR::from_raw(name.as_ptr()),
            PCWSTR::from_raw(display.as_ptr()),
            SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG | DELETE_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            opts.start_type.to_win32(),
            SERVICE_ERROR_NORMAL,
            PCWSTR::from_raw(path.as_ptr()),
            PCWSTR::null(),
            None,
            dependencies_pcwstr,
            account_pcwstr,
            password_pcwstr,
        )
    };
    if let Some(password) = &mut password_wide {
        zeroize_wide_buffer(password);
    }
    complete_install(
        handle_result
            .map(crate::handles::ScHandle)
            .map_err(|e| map_win_error(&format!("CreateService({})", opts.name), e)),
        |svc| match opts.description.as_deref() {
            Some(description) => change_service_description(svc, &opts.name, description),
            None => Ok(()),
        },
        |svc| {
            // SAFETY: only the just-created service reaches this closure, and
            // its still-owned handle explicitly includes DELETE access.
            unsafe { DeleteService(svc.0) }
                .map_err(|e| map_win_error("DeleteService(install rollback)", e))
        },
    )
}

fn complete_install<T>(
    created: Result<T>,
    configure: impl FnOnce(&T) -> Result<()>,
    rollback: impl FnOnce(&T) -> Result<()>,
) -> Result<()> {
    let service = created?;
    if let Err(primary) = configure(&service) {
        return Err(Error::Scm(match rollback(&service) {
            Ok(()) => format!("service installation failed and was rolled back: {primary}"),
            Err(cleanup) => {
                format!("service installation failed ({primary}); rollback also failed ({cleanup})")
            }
        }));
    }
    Ok(())
}

/// Build the SCM image-path command line for a managed service:
/// `"<ngsm.exe>" run-service "<name>"`. Every argument is quoted
/// with the standard Windows rules so a name containing spaces or quotes is
/// recovered intact by the service runner.
pub fn build_run_service_command(name: &str) -> Result<String> {
    validate_service_name(name)?;
    let exe = std::env::current_exe().map_err(|e| Error::other(format!("current_exe: {e}")))?;
    command_for_validated_runner(name, &exe, validate_runner_location)
}

fn command_for_validated_runner(
    name: &str,
    original: &Path,
    validate: impl FnOnce(&Path) -> Result<PathBuf>,
) -> Result<String> {
    let canonical = validate(original)?;
    let exe_str = canonical.to_str().ok_or_else(|| {
        Error::other("runner path contains invalid Unicode and cannot be stored losslessly")
    })?;
    Ok(format!(
        "{} run-service {}",
        quote_windows_arg(exe_str),
        quote_windows_arg(name)
    ))
}

/// Refuse to install a service whose runner binary sits in a location a
/// non-administrator can replace. The SCM `ImagePath` is permanent, so a
/// runner kept under the user profile, a temp directory, a network share, or
/// a permissive ACL could later be swapped for an attacker-controlled binary
/// that then runs with the service account's privileges.
fn validate_runner_location(exe: &Path) -> Result<PathBuf> {
    let canonical = canonicalize_runner_path(exe)?;
    validate_runner_location_heuristics(&canonical)?;
    validate_runner_acl_chain(&canonical)?;
    Ok(canonical)
}

fn canonicalize_runner_path(exe: &Path) -> Result<PathBuf> {
    let canonical = std::fs::canonicalize(exe).map_err(|e| {
        Error::other(format!(
            "cannot resolve runner path '{}': {e}",
            exe.display()
        ))
    })?;
    if canonical.to_str().is_none() {
        return Err(Error::other(format!(
            "cannot validate runner location: path contains non-UTF-8 characters: {}",
            canonical.display()
        )));
    }
    Ok(canonical)
}

fn validate_runner_location_heuristics(canonical: &Path) -> Result<()> {
    let canonical_text = canonical.to_str().ok_or_else(|| {
        Error::other("cannot validate runner location: path contains invalid Unicode")
    })?;
    let lower = canonical_text.to_ascii_lowercase();

    // A network / UNC location is outside this machine's administrative
    // control and is never a trusted install location. `canonicalize` emits
    // `\\?\UNC\...` for UNC paths and `\\?\C:\...` for local ones.
    let is_unc =
        lower.starts_with(r"\\?\unc\") || (lower.starts_with(r"\\") && !lower.starts_with(r"\\?\"));
    if is_unc {
        return Err(Error::other(format!(
            "refusing to install: the NGSM runner is on a network path ('{}'). Install \
             NGSM under a local, administrator-protected directory and run `install` \
             from there.",
            canonical.display()
        )));
    }
    // Strip the `\\?\` extended-length prefix so the comparison below lines
    // up with the (unprefixed) environment directory paths.
    let exe_path = lower.strip_prefix(r"\\?\").unwrap_or(&lower);

    // Reject the well-known per-user-writable roots — Downloads, Desktop,
    // Documents, AppData, and the temp directories all live under these.
    for var in [
        "USERPROFILE",
        "TEMP",
        "TMP",
        "PUBLIC",
        "LOCALAPPDATA",
        "APPDATA",
    ] {
        let Some(raw_dir) = std::env::var_os(var) else {
            continue;
        };
        let Ok(dir) = std::fs::canonicalize(&raw_dir) else {
            continue;
        };
        let Some(dir_text) = dir.to_str() else {
            continue;
        };
        let dir_lower = dir_text.to_ascii_lowercase();
        let dir_path = dir_lower.strip_prefix(r"\\?\").unwrap_or(&dir_lower);
        if dir_path.is_empty() {
            continue;
        }
        let prefix = format!("{}\\", dir_path.trim_end_matches('\\'));
        if exe_path.starts_with(&prefix) {
            return Err(Error::other(format!(
                "refusing to install: the NGSM runner is under a user-writable location \
                 ('{}'). Copy NGSM into an administrator-protected directory (e.g. under \
                 Program Files) and run `install` from there.",
                canonical.display()
            )));
        }
    }
    Ok(())
}

/// Validate that the runner binary and every parent directory in its path are
/// owned/writable only by administrator-controlled principals.
pub fn validate_runner_acl_chain(canonical: &Path) -> Result<()> {
    for (path, object_kind) in runner_acl_targets(canonical) {
        validate_path_acl(&path, object_kind).map_err(|msg| {
            Error::other(format!(
                "refusing to install: the NGSM runner location is not \
                 administrator-protected: {msg}. Copy NGSM into a directory \
                 writable only by SYSTEM, BUILTIN\\Administrators, or TrustedInstaller."
            ))
        })?;
    }
    Ok(())
}

fn runner_acl_targets(canonical: &Path) -> Vec<(PathBuf, AclObjectKind)> {
    let mut targets = vec![(canonical.to_path_buf(), AclObjectKind::File)];
    let mut parent = canonical.parent();
    while let Some(dir) = parent {
        let is_root = !dir
            .components()
            .any(|component| matches!(component, Component::Normal(_)));
        targets.push((
            dir.to_path_buf(),
            if is_root {
                AclObjectKind::VolumeRoot
            } else {
                AclObjectKind::Directory
            },
        ));
        if is_root {
            break;
        }
        parent = dir.parent();
    }
    targets
}

fn validate_path_acl(path: &Path, object_kind: AclObjectKind) -> std::result::Result<(), String> {
    let path_text = path.to_str().ok_or_else(|| {
        format!(
            "cannot validate ACL for {}: path contains invalid Unicode",
            object_kind.label()
        )
    })?;
    let wide_path = to_wide(path_text);

    let mut owner = PSID::default();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `wide_path` is NUL-terminated and lives for the duration of the
    // call; the returned owner pointer is owned by the returned security
    // descriptor, which is freed by `LocalSecurityDescriptor`.
    let status = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR::from_raw(wide_path.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            &mut sd,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(format!(
            "cannot read security descriptor for {} '{}': Win32 error {}",
            object_kind.label(),
            path.display(),
            status.0
        ));
    }
    let _sd = LocalSecurityDescriptor(sd);

    if owner.is_invalid() {
        return Err(format!(
            "security descriptor for {} '{}' has no owner",
            object_kind.label(),
            path.display()
        ));
    }
    // SAFETY: `owner` points into the security descriptor returned above and is
    // valid until `_sd` is dropped at the end of this function.
    let owner_principal = unsafe { classify_acl_sid(owner)? };

    let mut dacl_present = BOOL(0);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut dacl_defaulted = BOOL(0);
    // SAFETY: `sd` is a valid security descriptor returned by
    // `GetNamedSecurityInfoW`; the output pointers are local variables.
    unsafe {
        GetSecurityDescriptorDacl(sd, &mut dacl_present, &mut dacl, &mut dacl_defaulted).map_err(
            |e| {
                format!(
                    "cannot inspect DACL for {} '{}': {e}",
                    object_kind.label(),
                    path.display()
                )
            },
        )?;
    }
    if !dacl_present.as_bool() {
        return Err(format!(
            "security descriptor for {} '{}' has no DACL",
            object_kind.label(),
            path.display()
        ));
    }
    if dacl.is_null() {
        return Err(format!(
            "security descriptor for {} '{}' has a null DACL",
            object_kind.label(),
            path.display()
        ));
    }
    // SAFETY: `dacl` came from the validated security descriptor above.
    if !unsafe { IsValidAcl(dacl) }.as_bool() {
        return Err(format!(
            "security descriptor for {} '{}' has an invalid DACL",
            object_kind.label(),
            path.display()
        ));
    }

    // SAFETY: `dacl` came from a present, non-null, valid DACL in the security
    // descriptor above, so reading its header fields is valid for this scope.
    let ace_count = unsafe { (*dacl).AceCount as u32 };
    let mut grants = Vec::with_capacity(ace_count as usize);
    for index in 0..ace_count {
        let mut ace: *mut c_void = std::ptr::null_mut();
        // SAFETY: `dacl` is valid and `index` is bounded by `AceCount`.
        unsafe {
            GetAce(dacl, index, &mut ace).map_err(|e| {
                format!(
                    "cannot read ACE {index} for {} '{}': {e}",
                    object_kind.label(),
                    path.display()
                )
            })?;
            if let Some(grant) = allowed_grant_from_ace(ace)? {
                grants.push(grant);
            }
        }
    }

    evaluate_acl_decision(owner_principal, &grants, object_kind).map_err(|err| {
        format!(
            "unsafe ACL on {} '{}': {}",
            object_kind.label(),
            path.display(),
            describe_acl_decision_error(err)
        )
    })
}

fn evaluate_acl_decision(
    owner: AclPrincipal,
    grants: &[AclAllowedGrant],
    object_kind: AclObjectKind,
) -> std::result::Result<(), AclDecisionError> {
    if !owner.is_trusted() {
        return Err(AclDecisionError::UntrustedOwner { principal: owner });
    }

    let dangerous_mask = dangerous_access_mask(object_kind);
    for grant in grants {
        if grant.inherit_only || grant.principal.is_trusted() {
            continue;
        }
        let dangerous_bits = grant.mask & dangerous_mask;
        if dangerous_bits != 0 {
            return Err(AclDecisionError::DangerousGrant {
                principal: grant.principal,
                mask: grant.mask,
                dangerous_mask: dangerous_bits,
                object_kind,
            });
        }
    }
    Ok(())
}

fn dangerous_access_mask(object_kind: AclObjectKind) -> u32 {
    match object_kind {
        AclObjectKind::File => FILE_DANGEROUS_ACCESS,
        AclObjectKind::Directory => DIRECTORY_DANGEROUS_ACCESS,
        // Creating siblings under a volume root cannot replace this existing
        // protected path. Deleting children or taking over the root can.
        AclObjectKind::VolumeRoot => {
            GENERIC_ALL.0 | WRITE_DAC.0 | WRITE_OWNER.0 | FILE_DELETE_CHILD.0
        }
    }
}

fn describe_acl_decision_error(err: AclDecisionError) -> String {
    match err {
        AclDecisionError::UntrustedOwner { principal } => format!(
            "{} owns the object and can take over its DACL",
            principal.label()
        ),
        AclDecisionError::DangerousGrant {
            principal,
            mask,
            dangerous_mask,
            object_kind,
        } => format!(
            "{} has write/delete/takeover rights on the {} (ACE mask 0x{mask:08x}, \
             dangerous bits 0x{dangerous_mask:08x})",
            principal.label(),
            object_kind.label()
        ),
    }
}

unsafe fn allowed_grant_from_ace(
    ace: *mut c_void,
) -> std::result::Result<Option<AclAllowedGrant>, String> {
    if ace.is_null() {
        return Err("DACL contains a null ACE pointer".to_string());
    }
    let header = &*(ace as *const ACE_HEADER);
    let ace_type = header.AceType as u32;
    let inherit_only = (header.AceFlags as u32 & INHERIT_ONLY_ACE.0) != 0;
    let ace_size = header.AceSize as usize;
    if ace_size < size_of::<ACE_HEADER>() {
        return Err(format!("DACL contains an ACE with invalid size {ace_size}"));
    }

    match ace_type {
        ACCESS_ALLOWED_ACE_TYPE
        | ACCESS_ALLOWED_CALLBACK_ACE_TYPE
        | ACCESS_ALLOWED_OBJECT_ACE_TYPE
        | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE => {
            let base = ace as *const u8;
            let mask = read_ace_u32(base, ace_size, size_of::<ACE_HEADER>())?;
            let sid_offset = allowed_ace_sid_offset(base, ace_size, ace_type)?;
            if sid_offset >= ace_size {
                return Err(format!(
                    "DACL contains an ACE whose SID offset {sid_offset} exceeds ACE size {ace_size}"
                ));
            }
            let sid = PSID(base.add(sid_offset) as *mut c_void);
            if !IsValidSid(sid).as_bool() {
                return Err("DACL contains an access-allowed ACE with an invalid SID".to_string());
            }
            let sid_len = GetLengthSid(sid) as usize;
            if sid_len == 0 || sid_offset.saturating_add(sid_len) > ace_size {
                return Err("DACL contains an access-allowed ACE with a truncated SID".to_string());
            }
            Ok(Some(AclAllowedGrant {
                principal: classify_acl_sid(sid)?,
                mask,
                inherit_only,
            }))
        }
        ACCESS_ALLOWED_COMPOUND_ACE_TYPE => {
            Err("DACL contains an unsupported compound allow ACE".to_string())
        }
        ACCESS_DENIED_ACE_TYPE
        | ACCESS_DENIED_CALLBACK_ACE_TYPE
        | ACCESS_DENIED_OBJECT_ACE_TYPE
        | ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE => Ok(None),
        _ => Err(format!("DACL contains unsupported ACE type {ace_type}")),
    }
}

unsafe fn allowed_ace_sid_offset(
    ace: *const u8,
    ace_size: usize,
    ace_type: u32,
) -> std::result::Result<usize, String> {
    match ace_type {
        ACCESS_ALLOWED_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_ACE_TYPE => {
            Ok(size_of::<ACE_HEADER>() + size_of::<u32>())
        }
        ACCESS_ALLOWED_OBJECT_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE => {
            let flags_offset = size_of::<ACE_HEADER>() + size_of::<u32>();
            let flags = read_ace_u32(ace, ace_size, flags_offset)?;
            let mut sid_offset = flags_offset + size_of::<u32>();
            if flags & ACE_OBJECT_TYPE_PRESENT.0 != 0 {
                sid_offset += size_of::<windows::core::GUID>();
            }
            if flags & ACE_INHERITED_OBJECT_TYPE_PRESENT.0 != 0 {
                sid_offset += size_of::<windows::core::GUID>();
            }
            Ok(sid_offset)
        }
        _ => Err(format!("unsupported allow ACE type {ace_type}")),
    }
}

unsafe fn read_ace_u32(
    ace: *const u8,
    ace_size: usize,
    offset: usize,
) -> std::result::Result<u32, String> {
    if offset.saturating_add(size_of::<u32>()) > ace_size {
        return Err(format!(
            "DACL contains an ACE too small to read a u32 at offset {offset}"
        ));
    }
    Ok(std::ptr::read_unaligned(ace.add(offset) as *const u32))
}

unsafe fn classify_acl_sid(sid: PSID) -> std::result::Result<AclPrincipal, String> {
    if !IsValidSid(sid).as_bool() {
        return Err("security descriptor contains an invalid SID".to_string());
    }
    if IsWellKnownSid(sid, WinLocalSystemSid).as_bool() {
        return Ok(AclPrincipal::Trusted("SYSTEM"));
    }
    if IsWellKnownSid(sid, WinBuiltinAdministratorsSid).as_bool() {
        return Ok(AclPrincipal::Trusted("BUILTIN\\Administrators"));
    }
    if is_trusted_installer_sid(sid)? {
        return Ok(AclPrincipal::Trusted("TrustedInstaller"));
    }
    if IsWellKnownSid(sid, WinWorldSid).as_bool() {
        return Ok(AclPrincipal::KnownUntrusted("Everyone"));
    }
    if IsWellKnownSid(sid, WinBuiltinUsersSid).as_bool() {
        return Ok(AclPrincipal::KnownUntrusted("BUILTIN\\Users"));
    }
    if IsWellKnownSid(sid, WinAuthenticatedUserSid).as_bool() {
        return Ok(AclPrincipal::KnownUntrusted("Authenticated Users"));
    }
    if IsWellKnownSid(sid, WinInteractiveSid).as_bool() {
        return Ok(AclPrincipal::KnownUntrusted("Interactive"));
    }
    Ok(AclPrincipal::Unknown)
}

unsafe fn is_trusted_installer_sid(sid: PSID) -> std::result::Result<bool, String> {
    let trusted_installer_wide = to_wide(TRUSTED_INSTALLER_SID);
    let mut trusted_installer = PSID::default();
    ConvertStringSidToSidW(
        PCWSTR::from_raw(trusted_installer_wide.as_ptr()),
        &mut trusted_installer,
    )
    .map_err(|e| format!("cannot construct TrustedInstaller SID: {e}"))?;
    let is_equal = EqualSid(sid, trusted_installer).is_ok();
    if !trusted_installer.is_invalid() {
        let _ = LocalFree(Some(HLOCAL(trusted_installer.0)));
    }
    Ok(is_equal)
}

struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        let ptr = (self.0).0;
        if !ptr.is_null() {
            // SAFETY: this descriptor was allocated by `GetNamedSecurityInfoW`
            // and is freed exactly once by this guard.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(ptr)));
            }
        }
    }
}

/// Delete an existing service. Does not stop it; the caller should arrange
/// that separately if the service is running.
pub fn remove_service(name: &str) -> Result<()> {
    validate_service_name(name)?;
    let scm = open_scm(SC_MANAGER_CONNECT)?;
    let svc = open_service_handle(&scm, name, DELETE_ACCESS)?;
    // SAFETY: `svc.0` is a valid service handle opened with `DELETE_ACCESS`.
    unsafe {
        DeleteService(svc.0).map_err(|e| map_win_error(&format!("DeleteService({name})"), e))?;
    }
    Ok(())
}

/// Update select native (SCM-owned) fields on an existing service. Pass
/// `None` to leave a field untouched. Passing `Some("")` for `description`
/// clears the SCM description.
pub fn update_native_config(
    name: &str,
    display_name: Option<&str>,
    description: Option<&str>,
    start_type: Option<InstallStartType>,
    dependencies: Option<&ServiceDependencies>,
    account: Option<&str>,
    password: Option<&str>,
) -> Result<()> {
    validate_native_update(
        name,
        display_name,
        description,
        dependencies,
        account,
        password,
    )?;
    let scm = open_scm(SC_MANAGER_CONNECT)?;
    let svc = open_service_handle(&scm, name, SERVICE_CHANGE_CONFIG)?;

    let display_wide = display_name.map(to_wide);
    let display_pcwstr = match &display_wide {
        Some(w) => PCWSTR::from_raw(w.as_ptr()),
        None => PCWSTR::null(),
    };
    let start = match start_type {
        Some(s) => s.to_win32(),
        None => SERVICE_START_TYPE(SERVICE_NO_CHANGE),
    };
    let dependencies_wide = dependencies.map(encode_dependencies).transpose()?;
    if let Some(account) = account {
        validate_account(account)?;
    }
    if password.is_some() && account.is_none() {
        return Err(Error::InvalidConfig(
            "--password-stdin requires --account so the SCM can apply the password".into(),
        ));
    }
    let account_wide = account.map(to_wide);
    if let Some(password) = password {
        validate_password(password)?;
    }
    let mut password_wide = password.map(to_wide);
    let dependencies_pcwstr = dependencies_wide
        .as_ref()
        .map_or(PCWSTR::null(), |w| PCWSTR::from_raw(w.as_ptr()));
    let account_pcwstr = account_wide
        .as_ref()
        .map_or(PCWSTR::null(), |w| PCWSTR::from_raw(w.as_ptr()));
    let password_pcwstr = password_wide
        .as_ref()
        .map_or(PCWSTR::null(), |w| PCWSTR::from_raw(w.as_ptr()));

    if display_name.is_some()
        || start_type.is_some()
        || dependencies.is_some()
        || account.is_some()
        || password.is_some()
    {
        // SAFETY: `svc.0` is a valid service handle opened with
        // `SERVICE_CHANGE_CONFIG`; optional display/dependency/account/password
        // buffers outlive the call; null PCWSTR args are the documented way to
        // leave the corresponding fields unchanged.
        unsafe {
            let result = ChangeServiceConfigW(
                svc.0,
                ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),
                start,
                SERVICE_ERROR(SERVICE_NO_CHANGE),
                PCWSTR::null(), // binary path — unchanged
                PCWSTR::null(), // load order group — unchanged
                None,           // tag id — unchanged
                dependencies_pcwstr,
                account_pcwstr,
                password_pcwstr,
                display_pcwstr,
            );
            if let Some(password) = &mut password_wide {
                zeroize_wide_buffer(password);
            }
            result.map_err(|e| map_win_error(&format!("ChangeServiceConfig({name})"), e))?;
        }
    }

    if let Some(description) = description {
        if let Err(error) = change_service_description(&svc, name, description) {
            if display_name.is_some()
                || start_type.is_some()
                || dependencies.is_some()
                || account.is_some()
                || password.is_some()
            {
                return Err(Error::Scm(format!(
                    "native fields were changed, but description update failed: {error}; \
                     no automatic rollback was attempted (prior account passwords are unreadable)"
                )));
            }
            return Err(error);
        }
    }
    Ok(())
}

/// Repair a managed service's SCM runner binding.
///
/// This deliberately does **not** expose raw `ImagePath` or service-type
/// editing. Instead it recomputes NGSM's canonical, validated
/// `"<ngsm.exe>" run-service "<name>"` command and restores the service type
/// to `SERVICE_WIN32_OWN_PROCESS`, preserving all other native fields.
pub fn repair_service_runner(name: &str) -> Result<()> {
    validate_service_name(name)?;
    let binary_path = build_run_service_command(name)?;
    let scm = open_scm(SC_MANAGER_CONNECT)?;
    let svc = open_service_handle(&scm, name, SERVICE_CHANGE_CONFIG)?;
    let path = to_wide(&binary_path);

    // SAFETY: `svc.0` is a valid service handle opened with
    // `SERVICE_CHANGE_CONFIG`; `path` is a NUL-terminated UTF-16 buffer that
    // outlives the call; null PCWSTR args leave unrelated fields unchanged.
    unsafe {
        ChangeServiceConfigW(
            svc.0,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_START_TYPE(SERVICE_NO_CHANGE),
            SERVICE_ERROR(SERVICE_NO_CHANGE),
            PCWSTR::from_raw(path.as_ptr()),
            PCWSTR::null(), // load order group — unchanged
            None,           // tag id — unchanged
            PCWSTR::null(), // dependencies — unchanged
            PCWSTR::null(), // service start name — unchanged
            PCWSTR::null(), // password — unchanged
            PCWSTR::null(), // display name — unchanged
        )
        .map_err(|e| map_win_error(&format!("ChangeServiceConfig(repair-runner:{name})"), e))?;
    }
    Ok(())
}

fn change_service_description(
    svc: &crate::handles::ScHandle,
    name: &str,
    value: &str,
) -> Result<()> {
    validate_native_string("description", value)?;
    let mut description_wide = to_wide(value);
    let description = SERVICE_DESCRIPTIONW {
        lpDescription: PWSTR(description_wide.as_mut_ptr()),
    };
    // SAFETY: `svc.0` is a valid service handle opened with
    // `SERVICE_CHANGE_CONFIG`; `description` and its UTF-16 backing buffer
    // outlive the call; the buffer is null-terminated by `to_wide`.
    unsafe {
        ChangeServiceConfig2W(
            svc.0,
            SERVICE_CONFIG_DESCRIPTION,
            Some((&description as *const SERVICE_DESCRIPTIONW).cast()),
        )
        .map_err(|e| map_win_error(&format!("ChangeServiceConfig2(description:{name})"), e))?;
    }
    Ok(())
}

/// Ask the SCM to start the service. Returns once SCM has accepted the
/// request; the service may still be in `start_pending`.
pub fn start_service(name: &str) -> Result<()> {
    validate_service_name(name)?;
    let scm = open_scm(SC_MANAGER_CONNECT)?;
    let svc = open_service_handle(&scm, name, SERVICE_START)?;
    // SAFETY: `svc.0` is a valid service handle opened with `SERVICE_START`;
    // passing `None` for the arguments array is the documented way to start
    // with no arguments.
    unsafe {
        StartServiceW(svc.0, None)
            .map_err(|e| map_win_error(&format!("StartService({name})"), e))?;
    }
    Ok(())
}

/// Send a control code to a running service and return the resulting status
/// snapshot. The runtime block lacks `exit_code`, since `SERVICE_STATUS`
/// does not include the per-process exit code; callers can pull that
/// separately via [`crate::scm::query_service`].
pub fn control_service(name: &str, signal: ServiceControlSignal) -> Result<ServiceRuntimeState> {
    if let ServiceControlSignal::User(code) = signal {
        if !(128..=255).contains(&code) {
            return Err(Error::other(format!(
                "user-defined service control code {code} is out of range; SCM reserves \
                 128..=255 for user controls"
            )));
        }
    }
    validate_service_name(name)?;
    let scm = open_scm(SC_MANAGER_CONNECT)?;
    let svc = open_service_handle(&scm, name, signal.required_access())?;
    let mut status = SERVICE_STATUS::default();
    // SAFETY: `svc.0` is a valid service handle opened with the access rights
    // required by the signal; `status` is a local struct whose pointer is only
    // used for the duration of this call.
    unsafe {
        ControlService(svc.0, signal.to_win32(), &mut status as *mut SERVICE_STATUS)
            .map_err(|e| map_win_error(&format!("ControlService({name})"), e))?;
    }
    // Re-query for the richer process-aware status.
    let mut proc_status = SERVICE_STATUS_PROCESS::default();
    let mut written = 0u32;
    // SAFETY: `svc.0` is still valid (the handle is alive for the scope of
    // `svc`); the slice covers exactly `size_of::<SERVICE_STATUS_PROCESS>()`
    // bytes of the local `proc_status`, satisfying the API buffer contract.
    unsafe {
        QueryServiceStatusEx(
            svc.0,
            SC_STATUS_PROCESS_INFO,
            Some(std::slice::from_raw_parts_mut(
                (&mut proc_status as *mut SERVICE_STATUS_PROCESS) as *mut u8,
                size_of::<SERVICE_STATUS_PROCESS>(),
            )),
            &mut written,
        )
        .map_err(|e| map_win_error(&format!("QueryServiceStatusEx({name})"), e))?;
    }
    Ok(ServiceRuntimeState {
        state: classify_state(proc_status.dwCurrentState.0),
        pid: (proc_status.dwProcessId != 0).then_some(proc_status.dwProcessId),
        exit_code: None,
        checkpoint: Some(proc_status.dwCheckPoint),
        wait_hint_ms: Some(proc_status.dwWaitHint),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_install_preflight_rejects_a_nul_binary_command_without_scm() {
        let options = InstallOptions {
            name: "NeverCreated".into(),
            display_name: "NeverCreated".into(),
            description: None,
            binary_path: "C:\\ngsm.exe\0hidden".into(),
            start_type: InstallStartType::Manual,
            dependencies: ServiceDependencies::default(),
            account: None,
            password: None,
        };
        let error = validate_install_options(&options).unwrap_err();
        assert!(matches!(error, Error::InvalidConfig(_)));
        assert!(error.to_string().contains("binary path"));
    }
    #[test]
    fn install_transaction_rolls_back_only_successfully_created_services() {
        use std::cell::Cell;
        let rollback_count = Cell::new(0);
        let result = complete_install::<()>(
            Err(Error::Scm("already exists".into())),
            |_| panic!("configure must not run after failed creation"),
            |_| {
                rollback_count.set(rollback_count.get() + 1);
                Ok(())
            },
        );
        assert!(result.unwrap_err().to_string().contains("already exists"));
        assert_eq!(rollback_count.get(), 0);
        let result = complete_install(
            Ok(()),
            |_| Err(Error::Scm("description failed".into())),
            |_| {
                rollback_count.set(rollback_count.get() + 1);
                Ok(())
            },
        );
        let message = result.unwrap_err().to_string();
        assert!(message.contains("description failed") && message.contains("rolled back"));
        assert_eq!(rollback_count.get(), 1);
        let message = complete_install(
            Ok(()),
            |_| Err(Error::Scm("primary".into())),
            |_| Err(Error::Scm("cleanup".into())),
        )
        .unwrap_err()
        .to_string();
        assert!(message.contains("primary") && message.contains("cleanup"));
        assert!(complete_install(Ok(()), |_| Ok(()), |_| panic!("no rollback on success")).is_ok());
    }

    #[test]
    fn install_transaction_releases_owned_handles_on_all_outcomes() {
        use std::cell::Cell;
        struct Owned<'a>(&'a Cell<u32>);
        impl Drop for Owned<'_> {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }
        let closed = Cell::new(0);
        assert!(complete_install(Ok(Owned(&closed)), |_| Ok(()), |_| Ok(())).is_ok());
        assert_eq!(closed.get(), 1);
        assert!(complete_install(
            Ok(Owned(&closed)),
            |_| Err(Error::other("failure")),
            |_| Err(Error::other("rollback"))
        )
        .is_err());
        assert_eq!(closed.get(), 2);
    }

    #[test]
    fn runner_command_persists_only_the_validated_canonical_target() {
        let original = Path::new(r"C:\ReplaceableAlias\ngsm.exe");
        let target = PathBuf::from(r"\\?\C:\Program Files\NGSM\ngsm.exe");
        let command = command_for_validated_runner("Name With Spaces", original, |path| {
            assert_eq!(path, original);
            Ok(target.clone())
        })
        .unwrap();
        assert_eq!(
            command,
            format!(
                "{} run-service \"Name With Spaces\"",
                quote_windows_arg(target.to_str().unwrap())
            )
        );
        assert!(!command.contains("ReplaceableAlias"));
    }

    #[test]
    fn runner_command_preserves_literal_replacement_character_but_rejects_bad_utf16() {
        use std::os::windows::ffi::OsStringExt;
        let valid = PathBuf::from("C:\\\u{fffd}\\ngsm.exe");
        assert!(
            command_for_validated_runner("Svc", &valid, |path| Ok(path.into()))
                .unwrap()
                .contains('\u{fffd}')
        );
        let invalid = PathBuf::from(std::ffi::OsString::from_wide(&[67, 58, 92, 0xd800]));
        assert!(command_for_validated_runner("Svc", &invalid, |path| Ok(path.into())).is_err());
    }

    #[test]
    fn root_acl_allows_new_siblings_but_not_replacement_or_takeover() {
        let principal = AclPrincipal::KnownUntrusted("Authenticated Users");
        evaluate_acl_decision(
            trusted_owner(),
            &[grant(principal, FILE_ADD_SUBDIRECTORY.0 | FILE_ADD_FILE.0)],
            AclObjectKind::VolumeRoot,
        )
        .unwrap();
        for mask in [
            FILE_DELETE_CHILD.0,
            WRITE_DAC.0,
            WRITE_OWNER.0,
            GENERIC_ALL.0,
        ] {
            assert!(evaluate_acl_decision(
                trusted_owner(),
                &[grant(principal, mask)],
                AclObjectKind::VolumeRoot
            )
            .is_err());
        }
        assert!(
            evaluate_acl_decision(AclPrincipal::Unknown, &[], AclObjectKind::VolumeRoot).is_err()
        );
    }

    #[test]
    fn native_update_preflight_rejects_nuls_and_keeps_secrets_private() {
        assert!(validate_native_update("Svc", Some("a\0b"), None, None, None, None).is_err());
        assert!(validate_native_update("Svc", None, Some("a\0b"), None, None, None).is_err());
        assert!(validate_native_update("Svc", None, None, None, Some("a\0b"), None).is_err());
        let error = validate_native_update(
            "Svc",
            None,
            None,
            None,
            Some(".\\account"),
            Some("secret\0secret"),
        )
        .unwrap_err()
        .to_string();
        assert!(!error.contains("secret"));
        assert!(validate_native_update("Svc", None, None, None, None, Some("secret")).is_err());
    }

    #[test]
    fn native_update_preflight_preserves_supported_empty_and_unicode_values() {
        assert!(validate_native_update(
            "服务",
            Some("Display \u{fffd}"),
            Some("one\ntwo"),
            None,
            None,
            None,
        )
        .is_ok());
        assert!(validate_native_update("Svc", None, Some(""), None, None, None).is_ok());
        assert!(
            validate_native_update("Svc", Some(&"x".repeat(257)), None, None, None, None).is_err()
        );
    }

    #[test]
    fn service_dependencies_do_not_reinterpret_plus_names_as_groups() {
        for name in ["+", "+Worker"] {
            let dependencies = ServiceDependencies {
                services: vec![name.to_string()],
                groups: Vec::new(),
            };
            assert!(
                dependencies.validate().is_err(),
                "{name} cannot be encoded as a service dependency"
            );
            assert!(encode_dependencies(&dependencies).is_err());
        }
    }

    #[test]
    fn runner_acl_chain_includes_the_volume_root() {
        for (runner, root) in [
            (r"C:\NGSM\ngsm.exe", r"C:\"),
            (r"C:\ngsm.exe", r"C:\"),
            (r"\\?\C:\NGSM\ngsm.exe", r"\\?\C:\"),
        ] {
            assert!(
                runner_acl_targets(std::path::Path::new(runner))
                    .iter()
                    .any(|(path, _)| path == std::path::Path::new(root)),
                "replacement-safety proof omitted the root of {runner}"
            );
        }
    }
    use std::sync::Mutex;

    /// The six env vars that `validate_runner_location_heuristics` inspects.
    const USER_VARS: &[&str] = &[
        "USERPROFILE",
        "TEMP",
        "TMP",
        "PUBLIC",
        "LOCALAPPDATA",
        "APPDATA",
    ];

    /// Serializes tests that mutate process-wide env vars. Cargo runs each
    /// crate's tests in one binary, multithreaded, so concurrent env mutations
    /// would race without this lock.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// RAII guard that acquires `ENV_LOCK` and restores every entry in
    /// `USER_VARS` to its original value when dropped.  Callers must keep
    /// this guard alive until env vars and any temp directories are no longer
    /// needed.
    struct EnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (var, val) in &self.saved {
                match val {
                    Some(v) => std::env::set_var(var, v),
                    None => std::env::remove_var(var),
                }
            }
        }
    }

    /// Acquires the env lock and snapshots all `USER_VARS` so they are
    /// restored when the returned guard is dropped.  Call this BEFORE any
    /// `tempfile::tempdir()` so that `%TEMP%` cannot change underneath us.
    fn isolate() -> EnvGuard {
        let lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let saved = USER_VARS
            .iter()
            .map(|&v| (v, std::env::var_os(v)))
            .collect();
        EnvGuard { _lock: lock, saved }
    }

    /// Drop a zero-byte file with a `.exe` extension into `dir` and return its path.
    fn make_stub_exe(dir: &std::path::Path) -> std::path::PathBuf {
        let exe = dir.join("stub.exe");
        std::fs::write(&exe, b"").unwrap();
        exe
    }

    // -----------------------------------------------------------------------
    // validate_runner_location_heuristics — happy path
    // -----------------------------------------------------------------------

    #[test]
    fn validate_runner_location_heuristics_accepts_path_not_under_user_roots() {
        // Acquire the lock (and snapshot env) FIRST so that %TEMP% cannot be
        // changed by a concurrent test between our tempdir() calls and the
        // env-var sets below.  The guard restores everything on drop.
        let _g = isolate();

        // Create two independent temp dirs. We keep the stub exe in `safe` and
        // point all six user-writable env vars at `elsewhere`, so `safe` is not
        // considered user-writable by the validator.
        let safe = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let exe = make_stub_exe(safe.path());

        std::env::set_var("USERPROFILE", elsewhere.path());
        std::env::set_var("TEMP", elsewhere.path());
        std::env::set_var("TMP", elsewhere.path());
        std::env::set_var("PUBLIC", elsewhere.path());
        std::env::set_var("LOCALAPPDATA", elsewhere.path());
        std::env::set_var("APPDATA", elsewhere.path());

        // Defensive: if the OS happened to allocate both temp dirs under the
        // same canonical root they'd collide. Skip rather than false-fail.
        if let (Ok(cs), Ok(ce)) = (
            std::fs::canonicalize(safe.path()),
            std::fs::canonicalize(elsewhere.path()),
        ) {
            if cs.starts_with(&ce) {
                eprintln!("skipping validate_runner_location_heuristics_accepts_path_not_under_user_roots: temp dirs collide");
                return;
            }
        }

        let canonical = canonicalize_runner_path(&exe).unwrap();
        validate_runner_location_heuristics(&canonical)
            .expect("heuristics should accept an exe outside all user-writable env-var roots");
    }

    // -----------------------------------------------------------------------
    // validate_runner_location_heuristics — rejection cases (one per sensitive env var)
    // -----------------------------------------------------------------------

    /// Inner helper so each per-var rejection test avoids duplication.
    fn assert_rejects_under_var(var: &str) {
        // Acquire the lock (and snapshot env) FIRST so that %TEMP% cannot be
        // changed by a concurrent test between our tempdir() calls and the
        // env-var sets below.  The guard restores everything on drop.
        let _g = isolate();

        let user_dir = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let exe = make_stub_exe(user_dir.path());

        // Set `var` → the dir containing the exe; all others → `elsewhere`
        // so they can't match first and mask the real assertion.
        for v in USER_VARS {
            if *v == var {
                std::env::set_var(v, user_dir.path());
            } else {
                std::env::set_var(v, elsewhere.path());
            }
        }

        let canonical = canonicalize_runner_path(&exe).unwrap();
        let err = validate_runner_location_heuristics(&canonical)
            .expect_err(&format!("should reject exe under {var}"));
        let msg = err.to_string();
        assert!(
            msg.to_lowercase().contains("user") || msg.to_lowercase().contains("administrator"),
            "error message should mention user-writable / administrator concern for {var}: {msg}"
        );
    }

    #[test]
    fn validate_runner_location_rejects_path_under_userprofile() {
        assert_rejects_under_var("USERPROFILE");
    }

    #[test]
    fn validate_runner_location_rejects_path_under_temp() {
        assert_rejects_under_var("TEMP");
    }

    #[test]
    fn validate_runner_location_rejects_path_under_localappdata() {
        assert_rejects_under_var("LOCALAPPDATA");
    }

    #[test]
    fn validate_runner_location_rejects_path_under_appdata() {
        assert_rejects_under_var("APPDATA");
    }

    #[test]
    fn validate_runner_location_rejects_path_under_public() {
        assert_rejects_under_var("PUBLIC");
    }

    #[test]
    fn validate_runner_location_rejects_path_under_tmp() {
        assert_rejects_under_var("TMP");
    }

    // -----------------------------------------------------------------------
    // validate_runner_location — UNC paths
    // -----------------------------------------------------------------------

    // UNC path rejection cannot be exercised hermetically without a real
    // (or virtual) SMB share because `std::fs::canonicalize` must succeed for
    // the path to reach the UNC check. Spinning up a network share in a unit
    // test is not feasible on a standard CI runner, so this case is verified
    // only by manual / integration testing. The code path is covered by
    // inspection: `canonicalize` emits `\\?\UNC\...` for any UNC path and
    // `starts_with(r"\\?\unc\")` (lowercased) catches that; the second arm
    // (`starts_with(r"\\")` without `\\?\`) is the belt-and-suspenders check
    // for unresolved UNC inputs that somehow bypass the `\\?\` normalization.

    // -----------------------------------------------------------------------
    // ACL evaluator — pure decision logic
    // -----------------------------------------------------------------------

    fn trusted_owner() -> AclPrincipal {
        AclPrincipal::Trusted("SYSTEM")
    }

    fn grant(principal: AclPrincipal, mask: u32) -> AclAllowedGrant {
        AclAllowedGrant {
            principal,
            mask,
            inherit_only: false,
        }
    }

    #[test]
    fn acl_evaluator_accepts_trusted_writer_grants() {
        for principal in [
            AclPrincipal::Trusted("SYSTEM"),
            AclPrincipal::Trusted("BUILTIN\\Administrators"),
            AclPrincipal::Trusted("TrustedInstaller"),
        ] {
            evaluate_acl_decision(
                trusted_owner(),
                &[grant(principal, FILE_DANGEROUS_ACCESS)],
                AclObjectKind::File,
            )
            .expect("trusted writers may hold dangerous rights");
        }
    }

    #[test]
    fn acl_evaluator_rejects_known_untrusted_dangerous_grants() {
        for principal in [
            AclPrincipal::KnownUntrusted("Everyone"),
            AclPrincipal::KnownUntrusted("BUILTIN\\Users"),
            AclPrincipal::KnownUntrusted("Authenticated Users"),
            AclPrincipal::KnownUntrusted("Interactive"),
        ] {
            let err = evaluate_acl_decision(
                trusted_owner(),
                &[grant(principal, FILE_WRITE_DATA.0)],
                AclObjectKind::File,
            )
            .expect_err("known untrusted write grants must be rejected");
            assert!(matches!(
                err,
                AclDecisionError::DangerousGrant { principal: got, .. } if got == principal
            ));
        }
    }

    #[test]
    fn acl_evaluator_rejects_unknown_dangerous_grants() {
        let err = evaluate_acl_decision(
            trusted_owner(),
            &[grant(AclPrincipal::Unknown, WRITE_DAC.0)],
            AclObjectKind::File,
        )
        .expect_err("unknown takeover grants must be rejected");
        assert!(matches!(
            err,
            AclDecisionError::DangerousGrant {
                principal: AclPrincipal::Unknown,
                ..
            }
        ));
    }

    #[test]
    fn acl_evaluator_rejects_untrusted_owner() {
        let err = evaluate_acl_decision(
            AclPrincipal::KnownUntrusted("BUILTIN\\Users"),
            &[],
            AclObjectKind::File,
        )
        .expect_err("untrusted owners can rewrite the DACL and must be rejected");
        assert!(matches!(
            err,
            AclDecisionError::UntrustedOwner {
                principal: AclPrincipal::KnownUntrusted("BUILTIN\\Users")
            }
        ));
    }

    #[test]
    fn acl_evaluator_allows_read_only_untrusted_grants() {
        evaluate_acl_decision(
            trusted_owner(),
            &[grant(AclPrincipal::KnownUntrusted("Everyone"), 0x0000_0001)],
            AclObjectKind::File,
        )
        .expect("read-only grants do not make the runner replaceable");
    }

    #[test]
    fn acl_evaluator_ignores_inherit_only_grants_for_current_object() {
        let inherit_only = AclAllowedGrant {
            principal: AclPrincipal::KnownUntrusted("Everyone"),
            mask: FILE_DANGEROUS_ACCESS,
            inherit_only: true,
        };
        evaluate_acl_decision(trusted_owner(), &[inherit_only], AclObjectKind::Directory)
            .expect("inherit-only ACEs do not grant rights on the current object");
    }

    #[test]
    fn acl_evaluator_rejects_directory_child_delete_grants() {
        let err = evaluate_acl_decision(
            trusted_owner(),
            &[grant(
                AclPrincipal::KnownUntrusted("Authenticated Users"),
                FILE_DELETE_CHILD.0,
            )],
            AclObjectKind::Directory,
        )
        .expect_err("directory delete-child grants can replace existing children");
        assert!(matches!(
            err,
            AclDecisionError::DangerousGrant {
                principal: AclPrincipal::KnownUntrusted("Authenticated Users"),
                object_kind: AclObjectKind::Directory,
                ..
            }
        ));
    }

    // -----------------------------------------------------------------------
    // dependency encoding / validation
    // -----------------------------------------------------------------------

    #[test]
    fn dependency_encoder_uses_service_names_and_prefixed_group_names() {
        let encoded = encode_dependencies(&ServiceDependencies {
            services: vec!["Tcpip".into(), "EventLog".into()],
            groups: vec!["NetworkProvider".into()],
        })
        .expect("valid dependencies encode");

        let expected: Vec<u16> = "Tcpip\0EventLog\0+NetworkProvider\0\0"
            .encode_utf16()
            .collect();
        assert_eq!(encoded, expected);
    }

    #[test]
    fn dependency_encoder_encodes_empty_list_as_double_nul_for_clear() {
        assert_eq!(
            encode_dependencies(&ServiceDependencies::default()).unwrap(),
            vec![0, 0]
        );
    }

    #[test]
    fn dependency_encoder_rejects_empty_entries() {
        let err = encode_dependencies(&ServiceDependencies {
            services: vec!["".into()],
            groups: Vec::new(),
        })
        .expect_err("empty service dependency must fail")
        .to_string();
        assert!(err.contains("empty"), "got: {err}");

        let err = encode_dependencies(&ServiceDependencies {
            services: Vec::new(),
            groups: vec!["".into()],
        })
        .expect_err("empty group dependency must fail")
        .to_string();
        assert!(err.contains("empty"), "got: {err}");
    }

    #[test]
    fn dependency_encoder_rejects_control_characters() {
        let err = encode_dependencies(&ServiceDependencies {
            services: vec!["Tcpip\n".into()],
            groups: Vec::new(),
        })
        .expect_err("control chars must fail")
        .to_string();
        assert!(err.contains("control"), "got: {err}");
        assert!(
            !err.contains("Tcpip"),
            "dependency value should not be echoed: {err}"
        );

        let err = encode_dependencies(&ServiceDependencies {
            services: Vec::new(),
            groups: vec!["Group\nName".into()],
        })
        .expect_err("control chars in group dependencies must fail")
        .to_string();
        assert!(err.contains("control"), "got: {err}");
        assert!(
            !err.contains("Group"),
            "dependency value should not be echoed: {err}"
        );
    }

    #[test]
    fn dependency_encoder_rejects_service_names_with_separators() {
        let err = encode_dependencies(&ServiceDependencies {
            services: vec!["Bad\\..\\Parameters".into()],
            groups: Vec::new(),
        })
        .expect_err("service dependency names must use service-name validation")
        .to_string();
        assert!(err.contains("valid service name"), "got: {err}");
        assert!(
            !err.contains("Bad") && !err.contains("Parameters"),
            "dependency value should not be echoed: {err}"
        );
    }

    #[test]
    fn dependency_encoder_rejects_group_path_like_entries() {
        for group in ["Bad\\Group", "Bad/Group", "C:Group", ".", ".."] {
            let err = encode_dependencies(&ServiceDependencies {
                services: Vec::new(),
                groups: vec![group.into()],
            })
            .expect_err("path-like group dependency must fail")
            .to_string();
            assert!(err.contains("group"), "got: {err}");
            assert!(err.contains("path"), "got: {err}");
            assert!(
                !err.contains("Bad") && !err.contains("C:"),
                "dependency value should not be echoed: {err}"
            );
        }
    }

    #[test]
    fn install_options_debug_redacts_password() {
        let opts = InstallOptions {
            name: "TestSvc".into(),
            display_name: "Test Service".into(),
            description: None,
            binary_path: "C:\\Program Files\\NGSM\\ngsm.exe run-service TestSvc".into(),
            start_type: InstallStartType::Manual,
            dependencies: ServiceDependencies::default(),
            account: Some(".\\svc_user".into()),
            password: Some("super-secret".into()),
        };
        let debug = format!("{opts:?}");
        assert!(!debug.contains("super-secret"));
        assert!(debug.contains("<redacted>"));
    }

    // -----------------------------------------------------------------------
    // build_run_service_command — validation-rejection cases
    // -----------------------------------------------------------------------

    #[test]
    fn build_run_service_command_rejects_empty_name() {
        assert!(
            build_run_service_command("").is_err(),
            "empty service name must be rejected"
        );
    }

    #[test]
    fn build_run_service_command_rejects_name_with_nul() {
        // NUL is a control character — validate_service_name rejects it before
        // current_exe() or validate_runner_location() are ever called.
        assert!(
            build_run_service_command("has\0nul").is_err(),
            "name containing NUL must be rejected"
        );
    }

    #[test]
    fn build_run_service_command_rejects_name_with_newline() {
        assert!(
            build_run_service_command("has\nnewline").is_err(),
            "name containing newline (control char) must be rejected"
        );
    }

    #[test]
    fn build_run_service_command_rejects_name_with_tab() {
        assert!(
            build_run_service_command("has\ttab").is_err(),
            "name containing tab (control char) must be rejected"
        );
    }

    #[test]
    fn build_run_service_command_rejects_overlong_name() {
        use servicemanager_core::MAX_SERVICE_NAME_LEN;
        let long = "x".repeat(MAX_SERVICE_NAME_LEN + 1);
        assert!(
            build_run_service_command(&long).is_err(),
            "name exceeding {MAX_SERVICE_NAME_LEN} chars must be rejected"
        );
    }

    #[test]
    fn build_run_service_command_rejects_name_with_backslash() {
        assert!(
            build_run_service_command("evil\\path").is_err(),
            "name containing backslash must be rejected"
        );
    }

    #[test]
    fn build_run_service_command_rejects_name_with_forward_slash() {
        assert!(
            build_run_service_command("evil/path").is_err(),
            "name containing forward slash must be rejected"
        );
    }

    // Happy-path (name valid + runner location accepted + correct quoting) is
    // not exercised here because `current_exe()` on a test runner resolves to
    // something under `target/debug/deps/...`, which on a developer machine
    // typically lives under USERPROFILE — causing validate_runner_location to
    // reject it. The formatting logic itself (`quote_windows_arg`) is tested
    // in servicemanager-core; end-to-end formatting is covered by integration
    // testing during the install flow.

    // -----------------------------------------------------------------------
    // control_service — user control code range validation
    // -----------------------------------------------------------------------

    #[test]
    fn control_service_rejects_user_code_below_128() {
        let err = control_service("AnyName", ServiceControlSignal::User(5))
            .expect_err("code 5 is in SCM-reserved range, not user range");
        let msg = err.to_string();
        assert!(
            msg.contains("out of range"),
            "error should mention out of range: {msg}"
        );
        assert!(
            msg.contains("128..=255") || (msg.contains("128") && msg.contains("255")),
            "error should mention the valid range: {msg}"
        );
    }

    #[test]
    fn control_service_rejects_user_code_above_255() {
        let err = control_service("AnyName", ServiceControlSignal::User(256))
            .expect_err("code 256 is out of user range");
        assert!(err.to_string().contains("out of range"));
    }

    #[test]
    fn control_service_accepts_user_code_174() {
        // SERVICE_CONTROL_ROTATE is 174, the NGSM rotate signal.
        // This test verifies the guard passes for 174 — the call will
        // then fail because "AnyName" doesn't exist, but the failure
        // must NOT be the out-of-range error. It must be an SCM error
        // (or similar) about the service not existing.
        let err = control_service(
            "DoesNotExistService_xyz123",
            ServiceControlSignal::User(174),
        )
        .expect_err("service doesn't exist, so the call fails — but not for range reasons");
        let msg = err.to_string();
        assert!(
            !msg.contains("out of range"),
            "code 174 must pass range validation: got {msg}"
        );
    }
}
