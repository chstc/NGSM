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
    pub description: String,
    pub application: String,
    pub app_parameters: String,
    pub app_directory: String,
    pub stdout: String,
    pub stderr: String,
    pub account: String,
    pub password: String,
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
        let account = empty_to_none(&self.account);
        let password = password_to_none(&self.password);
        if password.is_some() && account.is_none() {
            return Err("Password requires a service account.".into());
        }
        Ok(InstallSpec {
            name: self.name.trim().into(),
            display_name: empty_to_none(&self.display_name),
            description: empty_to_none(&self.description),
            application: self.application.trim().into(),
            app_parameters: empty_to_none(&self.app_parameters),
            app_directory: empty_to_none(&self.app_directory),
            stdout: empty_to_none(&self.stdout),
            stderr: empty_to_none(&self.stderr),
            rotation: Default::default(),
            hooks: Vec::new(),
            start_type: self.start_type,
            dependencies: Default::default(),
            account,
            password,
        })
    }

    pub fn clear_password(&mut self) {
        self.password.clear();
    }
}

#[derive(Default)]
pub struct EditForm {
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub application: String,
    pub app_parameters: String,
    pub app_directory: String,
    pub stdout: String,
    pub stderr: String,
    pub account: String,
    pub password: String,
    pub start_type: InstallStartType,

    // Originals (so we can diff and only send changed fields).
    pub orig_display_name: String,
    pub orig_description: String,
    pub orig_application: String,
    pub orig_app_parameters: String,
    pub orig_app_directory: String,
    pub orig_stdout: String,
    pub orig_stderr: String,
    pub orig_account: String,
    pub orig_start_type: InstallStartType,
}

impl EditForm {
    pub fn from_definition(def: &ServiceDefinition) -> Self {
        let display = def.native.display_name.clone();
        let description = def.native.description.clone().unwrap_or_default();
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
        let account = def.native.account.clone().unwrap_or_default();
        Self {
            name: def.native.name.clone(),
            display_name: display.clone(),
            description: description.clone(),
            application: app.clone(),
            app_parameters: params.clone(),
            app_directory: dir.clone(),
            stdout: stdout.clone(),
            stderr: stderr.clone(),
            account: account.clone(),
            password: String::new(),
            start_type,

            orig_display_name: display,
            orig_description: description,
            orig_application: app,
            orig_app_parameters: params,
            orig_app_directory: dir,
            orig_stdout: stdout,
            orig_stderr: stderr,
            orig_account: account,
            orig_start_type: start_type,
        }
    }

    /// Diff the form against the originals, sending only changed fields.
    /// Edit is only offered for managed services, so a cleared `Application`
    /// would make the service unreadable — that is rejected here. An empty
    /// log path *is* allowed: it means "clear this redirection".
    ///
    /// Path-like fields (`application`, `app_directory`, `stdout`, `stderr`)
    /// are trimmed before diffing so accidental leading/trailing whitespace
    /// from focus-loss or copy/paste doesn't silently break service startup or
    /// log handling. `app_parameters` is left as-is because it carries
    /// command-line arguments where spacing may be intentional.
    pub fn to_spec(&self) -> Result<EditSpec, String> {
        if self.application.trim().is_empty() {
            return Err("Application path must not be empty.".into());
        }
        let diff = |new: &str, orig: &str| (new != orig).then(|| new.to_string());
        let diff_trim = |new: &str, orig: &str| {
            let t = new.trim();
            (t != orig).then(|| t.to_string())
        };
        let account_trimmed = self.account.trim();
        let password = password_to_none(&self.password);
        if password.is_some() && account_trimmed.is_empty() {
            return Err("Password requires a service account.".into());
        }
        let account = if password.is_some() {
            Some(account_trimmed.to_string())
        } else if account_trimmed.is_empty() {
            None
        } else {
            (account_trimmed != self.orig_account).then(|| account_trimmed.to_string())
        };
        Ok(EditSpec {
            name: self.name.clone(),
            display_name: diff(&self.display_name, &self.orig_display_name),
            description: diff(&self.description, &self.orig_description),
            application: diff_trim(&self.application, &self.orig_application),
            app_parameters: diff(&self.app_parameters, &self.orig_app_parameters),
            app_directory: diff_trim(&self.app_directory, &self.orig_app_directory),
            stdout: diff_trim(&self.stdout, &self.orig_stdout),
            stderr: diff_trim(&self.stderr, &self.orig_stderr),
            start_type: (self.start_type != self.orig_start_type).then_some(self.start_type),
            dependencies: None,
            account,
            password,
        })
    }

    pub fn clear_password(&mut self) {
        self.password.clear();
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

fn password_to_none(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
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
        f.description = "  My service  ".into();
        f.application = " C:\\app.exe ".into();
        f.app_parameters = "   ".into();
        let spec = f.to_spec().unwrap();
        assert_eq!(spec.name, "SmA");
        assert_eq!(spec.description.as_deref(), Some("My service"));
        assert_eq!(spec.application, "C:\\app.exe");
        assert!(spec.app_parameters.is_none());
    }

    #[test]
    fn install_form_accepts_account_without_password() {
        let mut f = InstallForm::default();
        f.name = "SmA".into();
        f.application = "C:\\app.exe".into();
        f.account = "  .\\svc_user  ".into();
        let spec = f.to_spec().unwrap();
        assert_eq!(spec.account.as_deref(), Some(".\\svc_user"));
        assert!(spec.password.is_none());
    }

    #[test]
    fn install_form_requires_account_for_password() {
        let mut f = InstallForm::default();
        f.name = "SmA".into();
        f.application = "C:\\app.exe".into();
        let password = "x".repeat(12);
        f.password = password.clone();
        let err = f.to_spec().unwrap_err();
        assert!(err.contains("account"), "got: {err}");
        assert!(!err.contains(&password), "error must not echo password");
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
        f.description = "New description".into();
        f.orig_description = "Old description".into();
        let spec = f.to_spec().unwrap();
        assert_eq!(spec.display_name.as_deref(), Some("New name"));
        assert_eq!(spec.description.as_deref(), Some("New description"));
        assert!(spec.application.is_none()); // unchanged
    }

    #[test]
    fn edit_form_trims_path_like_fields_before_diff() {
        let mut f = EditForm::default();
        f.name = "SmA".into();
        // Same logical value as the original, just with stray whitespace.
        f.application = "  C:\\app.exe  ".into();
        f.orig_application = "C:\\app.exe".into();
        // display_name unchanged from original so we don't drag it into the diff.
        f.display_name = "svc".into();
        f.orig_display_name = "svc".into();
        let spec = f.to_spec().unwrap();
        // Whitespace-only "change" must be a no-op — application is not in diff.
        assert!(
            spec.application.is_none(),
            "trimmed application equals original; should not be in diff (got {:?})",
            spec.application
        );

        // And when application *does* differ, the value in the diff is trimmed.
        let mut f2 = EditForm::default();
        f2.name = "SmA".into();
        f2.application = "  C:\\new.exe  ".into();
        f2.orig_application = "C:\\app.exe".into();
        f2.display_name = "svc".into();
        f2.orig_display_name = "svc".into();
        let spec2 = f2.to_spec().unwrap();
        assert_eq!(spec2.application.as_deref(), Some("C:\\new.exe"));
    }

    #[test]
    fn edit_form_preserves_app_parameters_whitespace() {
        let mut f = EditForm::default();
        f.name = "SmA".into();
        f.application = "C:\\app.exe".into();
        f.orig_application = "C:\\app.exe".into();
        f.app_parameters = "  --flag value  ".into();
        f.orig_app_parameters = "".into();
        let spec = f.to_spec().unwrap();
        assert_eq!(
            spec.app_parameters.as_deref(),
            Some("  --flag value  "),
            "app_parameters whitespace must be sent verbatim"
        );
    }

    #[test]
    fn edit_form_sends_changed_account_without_password() {
        let mut f = EditForm::default();
        f.name = "SmA".into();
        f.application = "C:\\app.exe".into();
        f.orig_application = "C:\\app.exe".into();
        f.account = "  .\\svc_user  ".into();
        f.orig_account = "LocalSystem".into();
        let spec = f.to_spec().unwrap();
        assert_eq!(spec.account.as_deref(), Some(".\\svc_user"));
        assert!(spec.password.is_none());
    }

    #[test]
    fn edit_form_sends_account_with_password_even_when_account_unchanged() {
        let mut f = EditForm::default();
        f.name = "SmA".into();
        f.application = "C:\\app.exe".into();
        f.orig_application = "C:\\app.exe".into();
        f.account = ".\\svc_user".into();
        f.orig_account = ".\\svc_user".into();
        let password = "x".repeat(12);
        f.password = password.clone();
        let spec = f.to_spec().unwrap();
        assert_eq!(spec.account.as_deref(), Some(".\\svc_user"));
        assert!(matches!(
            spec.password.as_deref(),
            Some(value) if value == password.as_str()
        ));
    }

    #[test]
    fn edit_form_clear_password_drops_form_secret_state() {
        let mut f = EditForm {
            password: "x".repeat(12),
            ..Default::default()
        };
        f.clear_password();
        assert!(f.password.is_empty());
    }

    #[test]
    fn edit_form_requires_account_for_password_without_echoing_it() {
        let mut f = EditForm::default();
        f.name = "SmA".into();
        f.application = "C:\\app.exe".into();
        let password = "x".repeat(12);
        f.password = password.clone();
        let err = f.to_spec().unwrap_err();
        assert!(err.contains("account"), "got: {err}");
        assert!(!err.contains(&password), "error must not echo password");
    }
}
