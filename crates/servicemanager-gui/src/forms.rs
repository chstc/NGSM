//! Install / edit dialog form models.
//!
//! These structs hold in-progress text-field state and translate it into the
//! `InstallSpec` / `EditSpec` jobs the worker executes. They contain no UI
//! framework code, so they are unit-tested directly.

use servicemanager_core::ServiceDefinition;
use servicemanager_win32::InstallStartType;

use crate::data::{EditSpec, InstallSpec};

#[derive(Default)]
pub struct InstallForm {
    pub name: String,
    pub display_name: String,
    pub application: String,
    pub app_parameters: String,
    pub app_directory: String,
    pub stdout: String,
    pub stderr: String,
    pub start_type: InstallStartType,
}

impl InstallForm {
    pub fn to_spec(&self) -> Result<InstallSpec, String> {
        if self.name.trim().is_empty() {
            return Err("Service name is required".into());
        }
        if self.application.trim().is_empty() {
            return Err("Application path is required".into());
        }
        Ok(InstallSpec {
            name: self.name.trim().into(),
            display_name: empty_to_none(&self.display_name),
            application: self.application.trim().into(),
            app_parameters: empty_to_none(&self.app_parameters),
            app_directory: empty_to_none(&self.app_directory),
            stdout: empty_to_none(&self.stdout),
            stderr: empty_to_none(&self.stderr),
            start_type: self.start_type,
        })
    }
}

#[derive(Default)]
pub struct EditForm {
    pub name: String,
    pub display_name: String,
    pub application: String,
    pub app_parameters: String,
    pub app_directory: String,
    pub stdout: String,
    pub stderr: String,
    pub start_type: InstallStartType,

    // Originals (so we can diff and only send changed fields).
    pub orig_display_name: String,
    pub orig_application: String,
    pub orig_app_parameters: String,
    pub orig_app_directory: String,
    pub orig_stdout: String,
    pub orig_stderr: String,
    pub orig_start_type: InstallStartType,
}

impl EditForm {
    pub fn from_definition(def: &ServiceDefinition) -> Self {
        let display = def.native.display_name.clone();
        let start_type = match def.native.startup {
            servicemanager_core::StartupType::Automatic
            | servicemanager_core::StartupType::AutomaticDelayed => InstallStartType::Automatic,
            servicemanager_core::StartupType::Disabled => InstallStartType::Disabled,
            _ => InstallStartType::Manual,
        };
        let app = def
            .managed
            .as_ref()
            .and_then(|m| m.application.clone())
            .unwrap_or_default();
        let params = def
            .managed
            .as_ref()
            .and_then(|m| m.app_parameters.clone())
            .unwrap_or_default();
        let dir = def
            .managed
            .as_ref()
            .and_then(|m| m.app_directory.clone())
            .unwrap_or_default();
        let stdout = def
            .managed
            .as_ref()
            .and_then(|m| m.io.stdout.as_ref().map(|s| s.path.clone()))
            .unwrap_or_default();
        let stderr = def
            .managed
            .as_ref()
            .and_then(|m| m.io.stderr.as_ref().map(|s| s.path.clone()))
            .unwrap_or_default();
        Self {
            name: def.native.name.clone(),
            display_name: display.clone(),
            application: app.clone(),
            app_parameters: params.clone(),
            app_directory: dir.clone(),
            stdout: stdout.clone(),
            stderr: stderr.clone(),
            start_type,

            orig_display_name: display,
            orig_application: app,
            orig_app_parameters: params,
            orig_app_directory: dir,
            orig_stdout: stdout,
            orig_stderr: stderr,
            orig_start_type: start_type,
        }
    }

    /// Diff the form against the originals, sending only changed fields.
    /// Edit is only offered for managed services, so a cleared `Application`
    /// would make the service unreadable — that is rejected here. An empty
    /// log path *is* allowed: it means "clear this redirection".
    pub fn to_spec(&self) -> Result<EditSpec, String> {
        if self.application.trim().is_empty() {
            return Err("Application path must not be empty.".into());
        }
        let diff = |new: &str, orig: &str| (new != orig).then(|| new.to_string());
        Ok(EditSpec {
            name: self.name.clone(),
            display_name: diff(&self.display_name, &self.orig_display_name),
            application: diff(&self.application, &self.orig_application),
            app_parameters: diff(&self.app_parameters, &self.orig_app_parameters),
            app_directory: diff(&self.app_directory, &self.orig_app_directory),
            stdout: diff(&self.stdout, &self.orig_stdout),
            stderr: diff(&self.stderr, &self.orig_stderr),
            start_type: (self.start_type != self.orig_start_type).then_some(self.start_type),
        })
    }
}

fn empty_to_none(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;

    #[test]
    fn install_form_requires_name_and_application() {
        let mut f = InstallForm::default();
        assert!(f.to_spec().is_err());
        f.name = "SmA".into();
        assert!(f.to_spec().is_err());
        f.application = "C:\\app.exe".into();
        let spec = f.to_spec().unwrap();
        assert_eq!(spec.name, "SmA");
        assert_eq!(spec.application, "C:\\app.exe");
        assert!(spec.display_name.is_none());
    }

    #[test]
    fn install_form_trims_and_blanks_to_none() {
        let mut f = InstallForm::default();
        f.name = "  SmA  ".into();
        f.application = " C:\\app.exe ".into();
        f.app_parameters = "   ".into();
        let spec = f.to_spec().unwrap();
        assert_eq!(spec.name, "SmA");
        assert_eq!(spec.application, "C:\\app.exe");
        assert!(spec.app_parameters.is_none());
    }

    #[test]
    fn edit_form_rejects_cleared_application() {
        let mut f = EditForm::default();
        f.name = "SmA".into();
        f.application = "".into();
        assert!(f.to_spec().is_err());
    }

    #[test]
    fn edit_form_sends_only_changed_fields() {
        let mut f = EditForm::default();
        f.name = "SmA".into();
        f.application = "C:\\app.exe".into();
        f.orig_application = "C:\\app.exe".into();
        f.display_name = "New name".into();
        f.orig_display_name = "Old name".into();
        let spec = f.to_spec().unwrap();
        assert_eq!(spec.display_name.as_deref(), Some("New name"));
        assert!(spec.application.is_none()); // unchanged
    }
}
