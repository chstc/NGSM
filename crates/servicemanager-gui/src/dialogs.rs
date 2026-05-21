//! Modal dialog state machines.
//!
//! egui doesn't have a built-in modal concept — we model dialogs as an
//! enum on `App` and render them inside a windowed `egui::Modal` block.

use eframe::egui;
use servicemanager_core::ServiceDefinition;
use servicemanager_win32::{InstallStartType, ProcessInfo};

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
    pub error: Option<String>,
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

    pub error: Option<String>,
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

            error: None,
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

/// Render the install dialog. Returns `Some(spec)` on Install click, `None`
/// otherwise. The caller is responsible for closing the modal on success.
pub fn show_install_dialog(ui: &mut egui::Ui, form: &mut InstallForm) -> InstallDialogResult {
    let mut result = InstallDialogResult::Idle;

    ui.heading("Install service");
    ui.add_space(8.0);
    egui::Grid::new("install-grid")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            ui.label("Service name *");
            ui.add(egui::TextEdit::singleline(&mut form.name).desired_width(360.0));
            ui.end_row();

            ui.label("Display name");
            ui.add(egui::TextEdit::singleline(&mut form.display_name).desired_width(360.0));
            ui.end_row();

            ui.label("Application *");
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut form.application).desired_width(280.0));
                if ui.button("Browse…").clicked() {
                    if let Some(p) = rfd::FileDialog::new()
                        .add_filter("Executables", &["exe"])
                        .add_filter("All files", &["*"])
                        .pick_file()
                    {
                        form.application = p.to_string_lossy().into_owned();
                    }
                }
            });
            ui.end_row();

            ui.label("Arguments");
            ui.add(egui::TextEdit::singleline(&mut form.app_parameters).desired_width(360.0));
            ui.end_row();

            ui.label("Working dir");
            ui.add(egui::TextEdit::singleline(&mut form.app_directory).desired_width(360.0));
            ui.end_row();

            ui.label("Stdout log");
            ui.add(egui::TextEdit::singleline(&mut form.stdout).desired_width(360.0));
            ui.end_row();

            ui.label("Stderr log");
            ui.add(egui::TextEdit::singleline(&mut form.stderr).desired_width(360.0));
            ui.end_row();

            ui.label("Startup");
            start_combo(ui, "install-start", &mut form.start_type);
            ui.end_row();
        });

    if let Some(err) = &form.error {
        ui.colored_label(egui::Color32::from_rgb(180, 50, 50), err);
    }

    ui.add_space(12.0);
    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
        if ui.button("Install").clicked() {
            match form.to_spec() {
                Ok(spec) => {
                    result = InstallDialogResult::Submit(spec);
                }
                Err(msg) => form.error = Some(msg),
            }
        }
        if ui.button("Cancel").clicked() {
            result = InstallDialogResult::Cancel;
        }
    });

    result
}

pub fn show_edit_dialog(ui: &mut egui::Ui, form: &mut EditForm) -> EditDialogResult {
    let mut result = EditDialogResult::Idle;
    ui.heading(format!("Edit service — {}", form.name));
    ui.add_space(8.0);
    egui::Grid::new("edit-grid")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            ui.label("Display name");
            ui.add(egui::TextEdit::singleline(&mut form.display_name).desired_width(360.0));
            ui.end_row();

            ui.label("Application");
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut form.application).desired_width(280.0));
                if ui.button("Browse…").clicked() {
                    if let Some(p) = rfd::FileDialog::new()
                        .add_filter("Executables", &["exe"])
                        .add_filter("All files", &["*"])
                        .pick_file()
                    {
                        form.application = p.to_string_lossy().into_owned();
                    }
                }
            });
            ui.end_row();

            ui.label("Arguments");
            ui.add(egui::TextEdit::singleline(&mut form.app_parameters).desired_width(360.0));
            ui.end_row();

            ui.label("Working dir");
            ui.add(egui::TextEdit::singleline(&mut form.app_directory).desired_width(360.0));
            ui.end_row();

            ui.label("Stdout log");
            ui.add(egui::TextEdit::singleline(&mut form.stdout).desired_width(360.0));
            ui.end_row();

            ui.label("Stderr log");
            ui.add(egui::TextEdit::singleline(&mut form.stderr).desired_width(360.0));
            ui.end_row();

            ui.label("Startup");
            start_combo(ui, "edit-start", &mut form.start_type);
            ui.end_row();
        });

    ui.add_space(8.0);
    ui.label(
        egui::RichText::new("Only fields you change are written.")
            .italics()
            .color(egui::Color32::GRAY),
    );

    if let Some(err) = &form.error {
        ui.colored_label(egui::Color32::from_rgb(180, 50, 50), err);
    }

    ui.add_space(12.0);
    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
        if ui.button("Save").clicked() {
            match form.to_spec() {
                Ok(spec) => result = EditDialogResult::Submit(spec),
                Err(msg) => form.error = Some(msg),
            }
        }
        if ui.button("Cancel").clicked() {
            result = EditDialogResult::Cancel;
        }
    });
    result
}

pub fn show_processes_dialog(ui: &mut egui::Ui, service_name: &str, rows: &[ProcessInfo]) -> bool {
    ui.heading(format!("Processes for '{}' ({})", service_name, rows.len()));
    ui.add_space(6.0);
    egui_extras::TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .column(egui_extras::Column::initial(80.0).at_least(60.0))
        .column(egui_extras::Column::initial(80.0).at_least(60.0))
        .column(egui_extras::Column::remainder())
        .header(22.0, |mut h| {
            h.col(|ui| {
                ui.strong("PID");
            });
            h.col(|ui| {
                ui.strong("PPID");
            });
            h.col(|ui| {
                ui.strong("Image");
            });
        })
        .body(|mut body| {
            for p in rows {
                body.row(20.0, |mut row| {
                    row.col(|ui| {
                        ui.label(p.pid.to_string());
                    });
                    row.col(|ui| {
                        ui.label(p.parent_pid.to_string());
                    });
                    row.col(|ui| {
                        ui.label(&p.image_name);
                    });
                });
            }
        });

    ui.add_space(12.0);
    let mut close = false;
    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
        if ui.button("Close").clicked() {
            close = true;
        }
    });
    close
}

pub enum InstallDialogResult {
    Idle,
    Submit(InstallSpec),
    Cancel,
}

pub enum EditDialogResult {
    Idle,
    Submit(EditSpec),
    Cancel,
}

fn start_combo(ui: &mut egui::Ui, id: &str, value: &mut InstallStartType) {
    let current = match value {
        InstallStartType::Manual => "Manual",
        InstallStartType::Automatic => "Automatic",
        InstallStartType::Disabled => "Disabled",
    };
    egui::ComboBox::from_id_salt(id)
        .selected_text(current)
        .show_ui(ui, |ui| {
            ui.selectable_value(value, InstallStartType::Manual, "Manual");
            ui.selectable_value(value, InstallStartType::Automatic, "Automatic");
            ui.selectable_value(value, InstallStartType::Disabled, "Disabled");
        });
}

fn empty_to_none(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}
