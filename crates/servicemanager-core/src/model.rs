use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// A fully-resolved managed service definition.
///
/// `native` describes what the Windows Service Control Manager knows about
/// the service. `managed` is populated when NGSM (or legacy NSSM)
/// configuration is detected under the service's `Parameters` registry key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDefinition {
    pub native: NativeServiceConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed: Option<ManagedApplicationConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<ServiceRuntimeState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeServiceConfig {
    pub name: String,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub startup: StartupType,
    pub service_type: ServiceType,
    pub image_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depend_on_services: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depend_on_groups: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StartupType {
    Boot,
    System,
    Automatic,
    AutomaticDelayed,
    Manual,
    Disabled,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServiceType {
    KernelDriver,
    FileSystemDriver,
    Win32OwnProcess,
    Win32SharedProcess,
    InteractiveProcess,
    Unknown,
}

/// Application configuration owned by NGSM (compatible with NSSM
/// `Parameters` keys). All fields are optional because a non-managed Windows
/// service will not have any of them set.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ManagedApplicationConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_parameters: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_directory: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub environment: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub environment_extra: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affinity: Option<String>,
    #[serde(default)]
    pub restart: RestartPolicy,
    #[serde(default)]
    pub shutdown: ShutdownPolicy,
    #[serde(default)]
    pub io: IoRedirectionConfig,
    #[serde(default)]
    pub rotation: LogRotationConfig,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub exit_actions: BTreeMap<String, ExitActionPolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hooks: Vec<HookConfig>,
    /// NSSM value names stored as REG_EXPAND_SZ, including
    /// `AppEvents\<event>\<action>` for hook commands. Text remains unexpanded
    /// until the service resolves an effective copy using its own environment.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub expandable_strings: BTreeSet<String>,
}

impl ManagedApplicationConfig {
    /// True when this service has on-demand (online) log rotation the
    /// supervisor can actually act on: rotation enabled, in online mode, and
    /// with at least one redirected stdout/stderr stream. Offline rotation
    /// only happens on (re)start, so a "rotate now" request against it is a
    /// silent no-op — callers gate the rotate command on this.
    pub fn has_online_rotation(&self) -> bool {
        self.rotation.enabled == Some(true)
            && matches!(self.rotation.online, Some(v) if v != 0)
            && (self.io.stdout.is_some() || self.io.stderr.is_some())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RestartPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart_delay_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub throttle_delay_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_action: Option<ExitAction>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExitAction {
    Restart,
    Ignore,
    Exit,
    Suicide,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitActionPolicy {
    pub action: ExitAction,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ShutdownPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_method_skip: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kill_console_grace_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kill_window_grace_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kill_threads_grace_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kill_process_tree: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IoRedirectionConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdin: Option<IoStream>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdout: Option<IoStream>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stderr: Option<IoStream>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_log: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoStream {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub share_mode: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creation_disposition: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flags_and_attributes: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copy_and_truncate: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogRotationConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub online: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delay_ms: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookConfig {
    pub event: String,
    pub action: String,
    pub command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRuntimeState {
    pub state: ServiceState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_hint_ms: Option<u32>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServiceState {
    Stopped,
    StartPending,
    StopPending,
    Running,
    ContinuePending,
    PausePending,
    Paused,
    Unknown,
}

/// High-level classification of a service: one NGSM owns versus a native
/// Windows service. This is the label shown in list views, and it is defined
/// to agree exactly with [`ServiceDefinition::is_managed`] so a service can
/// never be filtered as managed yet labeled native (or vice versa).
///
/// To decide whether *managed configuration fields* are available to display
/// or edit, check `ServiceDefinition::managed.is_some()` directly — a service
/// can be `Managed` here (via its image path) while still having no managed
/// configuration to show.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagementKind {
    /// Image path looks like NGSM or NSSM, or NSSM parameters are present.
    Managed,
    /// A normal Windows service we do not own.
    Native,
}

impl ServiceDefinition {
    /// Display/authorization classification. Delegates to [`Self::is_managed`]
    /// so list filters (which use `is_managed`) and labels (which use this)
    /// can never disagree.
    pub fn management_kind(&self) -> ManagementKind {
        if self.is_managed() {
            ManagementKind::Managed
        } else {
            ManagementKind::Native
        }
    }

    /// True if this service is NGSM/NSSM-managed.
    ///
    /// A service counts as managed when it has managed configuration *or*
    /// its SCM image path's *executable* is the NGSM or NSSM binary. The
    /// image-path fallback covers orphaned or partially-installed services
    /// whose `Parameters\Application` marker is missing — those still need to
    /// be recognized so they can be cleaned up rather than mistaken for
    /// native Windows services.
    ///
    /// The match is on the executable's exact basename, not a substring of
    /// the raw image path: a native service whose directory, arguments, or
    /// some unrelated path component merely *contains* `ngsm.exe`/`nssm.exe`
    /// must not be classified as managed (and so become deletable).
    pub fn is_managed(&self) -> bool {
        if self.managed.is_some() {
            return true;
        }
        if let Some(exe) = image_path_exe_name(&self.native.image_path) {
            if exe.eq_ignore_ascii_case("ngsm.exe") || exe.eq_ignore_ascii_case("nssm.exe") {
                return true;
            }
        }
        false
    }
}

/// Extract the executable's file name from an SCM image path.
///
/// An image path is a command line — a possibly-quoted executable followed
/// by arguments — so we isolate just the executable token and return its
/// basename (the part after the last `\` or `/`).
fn image_path_exe_name(image_path: &str) -> Option<&str> {
    let trimmed = image_path.trim_start();
    let exe = if let Some(rest) = trimmed.strip_prefix('"') {
        rest.split_once('"')?.0
    } else {
        // CreateProcess can probe progressively longer unquoted prefixes;
        // CommandLineToArgvW does not. Never scan beyond the first .exe
        // boundary, which could already identify an unrelated native binary.
        let end = trimmed
            .char_indices()
            .filter_map(|(index, ch)| ch.is_whitespace().then_some(index))
            .chain(std::iter::once(trimmed.len()))
            .find(|&end| trimmed[..end].to_ascii_lowercase().ends_with(".exe"))?;
        let candidate = &trimmed[..end];
        if candidate.chars().any(char::is_whitespace) {
            // The conventional Program Files prefix is the one supported
            // legacy ambiguity. Extra whitespace later could separate a
            // native command from a runner-looking argument; fail closed.
            let normalized = candidate.replace('/', "\\").to_ascii_lowercase();
            let rooted = normalized
                .as_bytes()
                .get(0..3)
                .is_some_and(|prefix| prefix[0].is_ascii_alphabetic() && prefix[1..] == *b":\\");
            if !rooted {
                return None;
            }
            let tail = normalized[3..]
                .strip_prefix("program files\\")
                .or_else(|| normalized[3..].strip_prefix("program files (x86)\\"))?;
            if tail.chars().any(char::is_whitespace) {
                return None;
            }
        }
        let remainder = trimmed[end..].trim_start();
        // For legacy unquoted runners accept only an empty argument list or
        // NGSM's known binding shape. Other suffixes might be path fragments.
        if !remainder.is_empty()
            && !remainder
                .strip_prefix("run-service")
                .is_some_and(|rest| rest.starts_with(char::is_whitespace))
        {
            return None;
        }
        candidate
    };
    let name = exe.rsplit(['\\', '/']).next()?;
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_config_deserializes_with_policy_sections_omitted() {
        // Only `application` is present; every nested policy section is
        // omitted. With `#[serde(default)]` on those fields this must still
        // deserialize (older / minimal configs in the wild look like this).
        let json = r#"{ "application": "C:\\app.exe" }"#;
        let cfg: ManagedApplicationConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.application.as_deref(), Some("C:\\app.exe"));
        assert!(cfg.restart.restart_delay_ms.is_none());
        assert!(cfg.shutdown.stop_method_skip.is_none());
        assert!(cfg.io.stdout.is_none());
        assert!(cfg.rotation.enabled.is_none());
    }

    fn def_with_image(image: &str) -> ServiceDefinition {
        ServiceDefinition {
            native: NativeServiceConfig {
                name: "S".into(),
                display_name: "S".into(),
                description: None,
                startup: StartupType::Manual,
                service_type: ServiceType::Win32OwnProcess,
                image_path: image.into(),
                account: None,
                depend_on_services: Vec::new(),
                depend_on_groups: Vec::new(),
            },
            managed: None,
            runtime: None,
        }
    }

    #[test]
    fn is_managed_matches_executable_basename_not_substring() {
        // Genuine NGSM/NSSM services — quoted and unquoted image paths.
        assert!(
            def_with_image("\"C:\\Program Files\\NGSM\\ngsm.exe\" run-service Foo").is_managed()
        );
        assert!(def_with_image("C:\\tools\\nssm.exe").is_managed());
        assert!(def_with_image("C:\\tools\\NGSM.EXE run-service Bar").is_managed());

        // Native services whose image path merely *contains* the substring
        // must NOT be classified as managed.
        assert!(!def_with_image("C:\\nssm.exe-backup\\realservice.exe").is_managed());
        assert!(!def_with_image("C:\\app\\runner.exe --label ngsm.exe").is_managed());
        assert!(!def_with_image("C:\\Windows\\System32\\svchost.exe -k netsvcs").is_managed());
        assert!(!def_with_image("").is_managed());
    }

    #[test]
    fn native_runner_arguments_and_directory_fragments_do_not_grant_ownership() {
        for image in [
            r"C:\app\worker.exe --runner C:\tools\ngsm.exe",
            r#""C:\Program Files\Vendor\worker.exe" --runner C:\tools\NSSM.EXE"#,
            r#""C:\tools\ngsm.exe data\worker.exe""#,
            r"C:\native.com --runner C:\tools\ngsm.exe",
            r"C:\native --runner C:\tools\ngsm.exe",
            r"C:\Program Files\Vendor\native --runner C:\tools\ngsm.exe",
            r"C:\Program Files\Vendor\native arguments\ngsm.exe",
            r"C:\tools\ngsm.exe data\worker.exe",
        ] {
            let definition = def_with_image(image);
            assert!(
                !definition.is_managed(),
                "native executable misclassified: {image}"
            );
            assert_eq!(definition.management_kind(), ManagementKind::Native);
        }
    }

    #[test]
    fn is_managed_for_unquoted_program_files_ngsm() {
        // The classic unquoted-with-spaces case. Win32 itself resolves this
        // by probing the filesystem; we use a token-boundary fallback.
        assert!(def_with_image("C:\\Program Files\\NGSM\\ngsm.exe run-service Foo").is_managed());
        // Trailing executable with no args still classifies as managed.
        assert!(def_with_image("C:\\Program Files\\NGSM\\ngsm.exe").is_managed());
        // Forward slashes work too.
        assert!(def_with_image("C:/Program Files/NGSM/ngsm.exe run-service Foo").is_managed());
        // Case-insensitive match.
        assert!(def_with_image("C:\\Program Files\\NGSM\\NGSM.EXE run-service Foo").is_managed());
    }

    #[test]
    fn is_managed_for_unquoted_program_files_nssm() {
        assert!(def_with_image("C:\\Program Files\\NSSM\\nssm.exe run-service Foo").is_managed());
        assert!(def_with_image("C:\\Program Files\\NSSM\\nssm.exe").is_managed());
        assert!(def_with_image("C:\\Program Files\\NSSM\\NSSM.EXE run-service Foo").is_managed());
    }

    #[test]
    fn is_managed_still_rejects_substring_in_dir_name() {
        // Existing negative case must still hold: `nssm.exe` followed by `-`
        // (not whitespace / end-of-string) is not a token boundary.
        assert!(!def_with_image("C:\\nssm.exe-backup\\realservice.exe").is_managed());
        // And followed by another path segment.
        assert!(!def_with_image("C:\\ngsm.exe.dir\\real.exe").is_managed());
    }

    #[test]
    fn is_managed_still_rejects_substring_in_args() {
        // `ngsm.exe` appears in args, not preceded by `\` or `/`, so the
        // token-boundary check rejects it (and the primary basename check
        // already rejected `app.exe`).
        assert!(!def_with_image("C:\\app.exe --label ngsm.exe").is_managed());
        // Same shape with nssm.exe as a bare arg value.
        assert!(!def_with_image("C:\\app.exe --runner nssm.exe").is_managed());
    }

    #[test]
    fn management_kind_agrees_with_is_managed_for_image_path_orphans() {
        // An NGSM image path but no managed registry config (an orphaned /
        // partially-installed service). It must classify as Managed so it is
        // not mistaken for a native service in either filters or labels.
        let orphan = def_with_image("C:\\tools\\ngsm.exe run-service Orphan");
        assert!(orphan.managed.is_none());
        assert!(orphan.is_managed());
        assert_eq!(orphan.management_kind(), ManagementKind::Managed);

        let native = def_with_image("C:\\Windows\\System32\\svchost.exe -k netsvcs");
        assert!(!native.is_managed());
        assert_eq!(native.management_kind(), ManagementKind::Native);
    }

    #[test]
    fn service_definition_deserializes_without_runtime() {
        let json = r#"{
            "native": {
                "name": "Svc",
                "display_name": "Svc",
                "startup": "manual",
                "service_type": "win32_own_process",
                "image_path": "C:\\svc.exe"
            }
        }"#;
        let def: ServiceDefinition = serde_json::from_str(json).unwrap();
        assert!(def.runtime.is_none());
        assert!(def.managed.is_none());
        assert_eq!(def.management_kind(), ManagementKind::Native);
    }
}
