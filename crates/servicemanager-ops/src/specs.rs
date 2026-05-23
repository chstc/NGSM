use std::collections::BTreeMap;

use servicemanager_core::ExitAction;
use servicemanager_win32::InstallStartType;

/// Parameters for installing a new NGSM-managed service.
///
/// Lifted verbatim from `servicemanager-gui/src/data.rs`; the GUI, CLI, and
/// broker all construct equivalent structures before calling into the SCM.
#[derive(Clone, Debug, Default)]
pub struct InstallSpec {
    pub name: String,
    pub display_name: Option<String>,
    pub application: String,
    pub app_parameters: Option<String>,
    pub app_directory: Option<String>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub start_type: InstallStartType,
}

/// Parameters for editing an existing NGSM-managed service.
///
/// Every field is `Option` — only the `Some` fields are written back.
#[derive(Clone, Debug, Default)]
pub struct EditSpec {
    pub name: String,
    pub display_name: Option<String>,
    pub application: Option<String>,
    pub app_parameters: Option<String>,
    pub app_directory: Option<String>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub start_type: Option<InstallStartType>,
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
        assert!(s.app_parameters.is_none());
        assert!(s.app_directory.is_none());
        assert!(s.stdout.is_none());
        assert!(s.stderr.is_none());
        assert_eq!(s.start_type, InstallStartType::Manual);
    }

    #[test]
    fn edit_spec_default_all_none() {
        let s = EditSpec::default();
        assert!(s.name.is_empty());
        assert!(s.application.is_none());
        assert!(s.app_parameters.is_none());
        assert!(s.app_directory.is_none());
        assert!(s.stdout.is_none());
        assert!(s.stderr.is_none());
        assert!(s.display_name.is_none());
        assert!(s.start_type.is_none());
    }

    #[test]
    fn install_spec_round_trip_fields() {
        let s = InstallSpec {
            name: "MySvc".into(),
            display_name: Some("My Service".into()),
            application: "C:\\tools\\app.exe".into(),
            app_parameters: Some("--flag".into()),
            app_directory: Some("C:\\tools".into()),
            stdout: Some("C:\\logs\\out.log".into()),
            stderr: Some("C:\\logs\\err.log".into()),
            start_type: InstallStartType::Automatic,
        };
        assert_eq!(s.name, "MySvc");
        assert_eq!(s.display_name.as_deref(), Some("My Service"));
        assert_eq!(s.application, "C:\\tools\\app.exe");
        assert_eq!(s.app_parameters.as_deref(), Some("--flag"));
        assert_eq!(s.app_directory.as_deref(), Some("C:\\tools"));
        assert_eq!(s.stdout.as_deref(), Some("C:\\logs\\out.log"));
        assert_eq!(s.stderr.as_deref(), Some("C:\\logs\\err.log"));
        assert_eq!(s.start_type, InstallStartType::Automatic);
    }

    #[test]
    fn edit_spec_round_trip_fields() {
        let s = EditSpec {
            name: "MySvc".into(),
            display_name: Some("New Display".into()),
            application: Some("C:\\new\\app.exe".into()),
            app_parameters: Some("--new".into()),
            app_directory: Some("C:\\new".into()),
            stdout: Some("C:\\logs\\out.log".into()),
            stderr: None,
            start_type: Some(InstallStartType::Disabled),
        };
        assert_eq!(s.name, "MySvc");
        assert_eq!(s.application.as_deref(), Some("C:\\new\\app.exe"));
        assert!(s.stderr.is_none());
        assert_eq!(s.start_type, Some(InstallStartType::Disabled));
    }
}
