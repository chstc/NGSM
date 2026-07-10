use std::collections::BTreeMap;
use std::fmt;

use servicemanager_core::{ExitAction, HookConfig, LogRotationConfig};
use servicemanager_win32::{InstallStartType, ServiceDependencies};

/// Parameters for installing a new NGSM-managed service.
///
/// Lifted verbatim from `servicemanager-gui/src/data.rs`; the GUI, CLI, and
/// broker all construct equivalent structures before calling into the SCM.
#[derive(Clone, Default)]
pub struct InstallSpec {
    pub name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub application: String,
    pub app_parameters: Option<String>,
    pub app_directory: Option<String>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub rotation: LogRotationConfig,
    pub hooks: Vec<HookConfig>,
    pub start_type: InstallStartType,
    pub dependencies: ServiceDependencies,
    pub account: Option<String>,
    pub password: Option<String>,
}

impl fmt::Debug for InstallSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InstallSpec")
            .field("name", &self.name)
            .field("display_name", &self.display_name)
            .field("description", &self.description)
            .field("application", &self.application)
            .field("app_parameters", &self.app_parameters)
            .field("app_directory", &self.app_directory)
            .field("stdout", &self.stdout)
            .field("stderr", &self.stderr)
            .field("rotation", &self.rotation)
            .field("hooks", &self.hooks)
            .field("start_type", &self.start_type)
            .field("dependencies", &self.dependencies)
            .field("account", &self.account)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Parameters for editing an existing NGSM-managed service.
///
/// Every field is `Option` — only the `Some` fields are written back.
#[derive(Clone, Default)]
pub struct EditSpec {
    pub name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub application: Option<String>,
    pub app_parameters: Option<String>,
    pub app_directory: Option<String>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub start_type: Option<InstallStartType>,
    /// `None` leaves dependencies unchanged; `Some(empty)` clears them.
    pub dependencies: Option<ServiceDependencies>,
    pub account: Option<String>,
    pub password: Option<String>,
}

impl fmt::Debug for EditSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EditSpec")
            .field("name", &self.name)
            .field("display_name", &self.display_name)
            .field("description", &self.description)
            .field("application", &self.application)
            .field("app_parameters", &self.app_parameters)
            .field("app_directory", &self.app_directory)
            .field("stdout", &self.stdout)
            .field("stderr", &self.stderr)
            .field("start_type", &self.start_type)
            .field("dependencies", &self.dependencies)
            .field("account", &self.account)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl EditSpec {
    pub fn has_changes(&self) -> bool {
        self.display_name.is_some()
            || self.description.is_some()
            || self.application.is_some()
            || self.app_parameters.is_some()
            || self.app_directory.is_some()
            || self.stdout.is_some()
            || self.stderr.is_some()
            || self.start_type.is_some()
            || self.dependencies.is_some()
            || self.account.is_some()
            || self.password.is_some()
    }
}

/// A validated recovery-policy change to apply. The form/CLI layer has
/// already parsed and validated every field; this struct is written back
/// onto the current managed config in the registry.
#[derive(Clone, Debug)]
pub struct RecoverySpec {
    pub name: String,
    pub restart_delay_ms: Option<u32>,
    pub throttle_delay_ms: Option<u32>,
    pub default_action: ExitAction,
    pub exit_actions: BTreeMap<String, ExitAction>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_spec_default_has_empty_name_and_application() {
        let s = InstallSpec::default();
        assert!(s.name.is_empty());
        assert!(s.application.is_empty());
        assert!(s.display_name.is_none());
        assert!(s.description.is_none());
        assert!(s.app_parameters.is_none());
        assert!(s.app_directory.is_none());
        assert!(s.stdout.is_none());
        assert!(s.stderr.is_none());
        assert!(s.rotation.enabled.is_none());
        assert!(s.rotation.online.is_none());
        assert!(s.rotation.seconds.is_none());
        assert!(s.rotation.bytes.is_none());
        assert!(s.rotation.delay_ms.is_none());
        assert!(s.hooks.is_empty());
        assert_eq!(s.start_type, InstallStartType::Manual);
        assert!(s.dependencies.is_empty());
        assert!(s.account.is_none());
        assert!(s.password.is_none());
    }

    #[test]
    fn edit_spec_default_all_none() {
        let s = EditSpec::default();
        assert!(s.name.is_empty());
        assert!(s.description.is_none());
        assert!(s.application.is_none());
        assert!(s.app_parameters.is_none());
        assert!(s.app_directory.is_none());
        assert!(s.stdout.is_none());
        assert!(s.stderr.is_none());
        assert!(s.display_name.is_none());
        assert!(s.start_type.is_none());
        assert!(s.dependencies.is_none());
        assert!(s.account.is_none());
        assert!(s.password.is_none());
        assert!(!s.has_changes());
    }

    #[test]
    fn install_spec_round_trip_fields() {
        let s = InstallSpec {
            name: "MySvc".into(),
            display_name: Some("My Service".into()),
            description: Some("Runs the important app".into()),
            application: "C:\\tools\\app.exe".into(),
            app_parameters: Some("--flag".into()),
            app_directory: Some("C:\\tools".into()),
            stdout: Some("C:\\logs\\out.log".into()),
            stderr: Some("C:\\logs\\err.log".into()),
            rotation: LogRotationConfig {
                enabled: Some(true),
                online: Some(1),
                seconds: Some(3600),
                bytes: Some(1_048_576),
                delay_ms: Some(250),
            },
            hooks: vec![HookConfig {
                event: "Start".into(),
                action: "Pre".into(),
                command: "C:\\hooks\\warmup.cmd".into(),
            }],
            start_type: InstallStartType::Automatic,
            dependencies: ServiceDependencies {
                services: vec!["Tcpip".into()],
                groups: vec!["NetworkProvider".into()],
            },
            account: Some(".\\svc_user".into()),
            password: Some("dummy-password".into()),
        };
        assert_eq!(s.name, "MySvc");
        assert_eq!(s.display_name.as_deref(), Some("My Service"));
        assert_eq!(s.description.as_deref(), Some("Runs the important app"));
        assert_eq!(s.application, "C:\\tools\\app.exe");
        assert_eq!(s.app_parameters.as_deref(), Some("--flag"));
        assert_eq!(s.app_directory.as_deref(), Some("C:\\tools"));
        assert_eq!(s.stdout.as_deref(), Some("C:\\logs\\out.log"));
        assert_eq!(s.stderr.as_deref(), Some("C:\\logs\\err.log"));
        assert_eq!(s.rotation.enabled, Some(true));
        assert_eq!(s.rotation.online, Some(1));
        assert_eq!(s.rotation.seconds, Some(3600));
        assert_eq!(s.rotation.bytes, Some(1_048_576));
        assert_eq!(s.rotation.delay_ms, Some(250));
        assert_eq!(s.hooks.len(), 1);
        assert_eq!(s.hooks[0].event, "Start");
        assert_eq!(s.hooks[0].action, "Pre");
        assert_eq!(s.hooks[0].command, "C:\\hooks\\warmup.cmd");
        assert_eq!(s.start_type, InstallStartType::Automatic);
        assert_eq!(s.dependencies.services, vec!["Tcpip"]);
        assert_eq!(s.dependencies.groups, vec!["NetworkProvider"]);
        assert_eq!(s.account.as_deref(), Some(".\\svc_user"));
        assert_eq!(s.password.as_deref(), Some("dummy-password"));
    }

    #[test]
    fn edit_spec_round_trip_fields() {
        let s = EditSpec {
            name: "MySvc".into(),
            display_name: Some("New Display".into()),
            description: Some("New description".into()),
            application: Some("C:\\new\\app.exe".into()),
            app_parameters: Some("--new".into()),
            app_directory: Some("C:\\new".into()),
            stdout: Some("C:\\logs\\out.log".into()),
            stderr: None,
            start_type: Some(InstallStartType::Disabled),
            dependencies: Some(ServiceDependencies {
                services: vec!["Tcpip".into()],
                groups: Vec::new(),
            }),
            account: Some(".\\svc_user".into()),
            password: Some("dummy-password".into()),
        };
        assert_eq!(s.name, "MySvc");
        assert_eq!(s.description.as_deref(), Some("New description"));
        assert_eq!(s.application.as_deref(), Some("C:\\new\\app.exe"));
        assert!(s.stderr.is_none());
        assert_eq!(s.start_type, Some(InstallStartType::Disabled));
        assert_eq!(
            s.dependencies.as_ref().expect("dependencies set").services,
            vec!["Tcpip"]
        );
        assert_eq!(s.account.as_deref(), Some(".\\svc_user"));
        assert_eq!(s.password.as_deref(), Some("dummy-password"));
        assert!(s.has_changes());
    }

    #[test]
    fn edit_spec_has_changes_counts_every_edit_field() {
        let cases = [
            EditSpec {
                display_name: Some("Display".into()),
                ..Default::default()
            },
            EditSpec {
                description: Some(String::new()),
                ..Default::default()
            },
            EditSpec {
                application: Some("C:\\app.exe".into()),
                ..Default::default()
            },
            EditSpec {
                app_parameters: Some("--flag".into()),
                ..Default::default()
            },
            EditSpec {
                app_directory: Some("C:\\app".into()),
                ..Default::default()
            },
            EditSpec {
                stdout: Some("C:\\logs\\out.log".into()),
                ..Default::default()
            },
            EditSpec {
                stderr: Some(String::new()),
                ..Default::default()
            },
            EditSpec {
                start_type: Some(InstallStartType::Automatic),
                ..Default::default()
            },
            EditSpec {
                dependencies: Some(ServiceDependencies::default()),
                ..Default::default()
            },
            EditSpec {
                account: Some(".\\svc_user".into()),
                ..Default::default()
            },
            EditSpec {
                password: Some("dummy-password".into()),
                ..Default::default()
            },
        ];

        for spec in cases {
            assert!(spec.has_changes(), "{spec:?}");
        }
    }

    #[test]
    fn debug_redacts_passwords() {
        let install = InstallSpec {
            password: Some("super-secret".into()),
            ..Default::default()
        };
        let edit = EditSpec {
            password: Some("super-secret".into()),
            ..Default::default()
        };
        let install_debug = format!("{install:?}");
        let edit_debug = format!("{edit:?}");
        assert!(!install_debug.contains("super-secret"));
        assert!(!edit_debug.contains("super-secret"));
        assert!(install_debug.contains("<redacted>"));
        assert!(edit_debug.contains("<redacted>"));
    }
}
