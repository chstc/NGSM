use std::sync::mpsc::{Receiver, Sender};
use std::time::{Duration, Instant};

use eframe::egui;
use servicemanager_core::{ManagementKind, ServiceDefinition, ServiceState};
use servicemanager_win32::ProcessInfo;

use crate::data::{spawn_worker, EditSpec, InstallSpec, Job, JobResult};
use crate::dialogs::{
    show_edit_dialog, show_install_dialog, show_processes_dialog, EditDialogResult, EditForm,
    InstallDialogResult, InstallForm,
};

pub struct App {
    services: Vec<ServiceDefinition>,
    selected: Option<String>,
    filter_managed_only: bool,
    search: String,
    auto_refresh: bool,
    last_refresh_at: Instant,
    job_tx: Sender<Job>,
    result_rx: Receiver<JobResult>,
    busy: bool,
    status: String,
    /// True when this process is elevated; controls action-button enabling.
    elevated: bool,

    // Modal state
    install_form: Option<InstallForm>,
    edit_form: Option<EditForm>,
    confirm_remove: Option<String>,
    processes_view: Option<ProcessesView>,
}

/// How often the auto-refresh tick fires when enabled.
const AUTO_REFRESH_INTERVAL: Duration = Duration::from_secs(5);

struct ProcessesView {
    service: String,
    root_pid: u32,
    rows: Vec<ProcessInfo>,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let (result_tx, result_rx) = std::sync::mpsc::channel::<JobResult>();
        let job_tx = spawn_worker(result_tx, cc.egui_ctx.clone());
        // Kick off the first refresh immediately.
        let _ = job_tx.send(Job::Refresh);
        Self {
            services: Vec::new(),
            selected: None,
            filter_managed_only: true,
            search: String::new(),
            auto_refresh: false,
            last_refresh_at: Instant::now(),
            job_tx,
            result_rx,
            busy: true,
            status: "Loading…".into(),
            elevated: servicemanager_win32::is_elevated(),
            install_form: None,
            edit_form: None,
            confirm_remove: None,
            processes_view: None,
        }
    }

    fn drain_results(&mut self) {
        while let Ok(r) = self.result_rx.try_recv() {
            self.busy = false;
            match r {
                JobResult::Services { defs, warnings } => {
                    self.services = defs;
                    self.last_refresh_at = Instant::now();
                    // Restore selection if the service still exists.
                    if let Some(sel) = &self.selected {
                        if !self.services.iter().any(|s| &s.native.name == sel) {
                            self.selected = None;
                        }
                    }
                    // The refreshed list may have changed the selected
                    // service's managed status — drop it if now filtered out.
                    self.invalidate_selection_if_hidden();
                    let base = format!(
                        "{} services ({})",
                        self.filtered_count(),
                        if self.filter_managed_only {
                            "managed"
                        } else {
                            "all"
                        }
                    );
                    // Surface, rather than hide, services whose managed
                    // config could not be read.
                    self.status = if warnings.is_empty() {
                        base
                    } else {
                        format!(
                            "{base}  ⚠ {} with unreadable config: {}",
                            warnings.len(),
                            warnings.join("; ")
                        )
                    };
                }
                JobResult::Acted(msg) => {
                    self.status = msg;
                    // Most actions change state; refresh.
                    let _ = self.job_tx.send(Job::Refresh);
                    self.busy = true;
                }
                JobResult::Processes {
                    service,
                    root_pid,
                    processes,
                } => {
                    self.status =
                        format!("Listed {} process(es) for '{service}'.", processes.len());
                    self.processes_view = Some(ProcessesView {
                        service,
                        root_pid,
                        rows: processes,
                    });
                }
                JobResult::Error(e) => {
                    self.status = format!("Error: {e}");
                }
            }
        }
    }

    fn matches_filters(&self, d: &ServiceDefinition) -> bool {
        if self.filter_managed_only && !d.is_managed() {
            return false;
        }
        if self.search.is_empty() {
            return true;
        }
        let q = self.search.to_lowercase();
        d.native.name.to_lowercase().contains(&q)
            || d.native.display_name.to_lowercase().contains(&q)
    }

    fn filtered_count(&self) -> usize {
        self.services
            .iter()
            .filter(|d| self.matches_filters(d))
            .count()
    }

    fn submit_job(&mut self, job: Job, busy_label: &str) {
        // If the worker thread has gone away the job will never run, so do
        // not flip into a `busy` state we can never clear — surface the
        // failure instead.
        match self.job_tx.send(job) {
            Ok(()) => {
                self.busy = true;
                self.status = busy_label.to_string();
            }
            Err(_) => {
                self.busy = false;
                self.status = "Background worker is unavailable — restart NGSM.".to_string();
            }
        }
    }

    fn current(&self) -> Option<&ServiceDefinition> {
        self.selected
            .as_ref()
            .and_then(|n| self.services.iter().find(|s| &s.native.name == n))
    }

    fn current_state(&self) -> Option<ServiceState> {
        self.current()
            .and_then(|d| d.runtime.as_ref().map(|r| r.state))
    }

    fn current_managed(&self) -> bool {
        self.current().map(|d| d.managed.is_some()).unwrap_or(false)
    }

    /// Drop the current selection if the selected service no longer matches
    /// the active filter/search. Without this the detail pane and action
    /// buttons stay bound to a row the user can no longer see in the table.
    fn invalidate_selection_if_hidden(&mut self) {
        let hidden = match self.current() {
            Some(d) => !self.matches_filters(d),
            None => false,
        };
        if hidden {
            self.selected = None;
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_results();

        // === Toolbar ===
        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!self.busy, egui::Button::new("Refresh"))
                    .clicked()
                {
                    self.submit_job(Job::Refresh, "Refreshing…");
                }
                if ui
                    .checkbox(&mut self.auto_refresh, "Auto")
                    .on_hover_text(format!(
                        "Refresh every {} seconds",
                        AUTO_REFRESH_INTERVAL.as_secs()
                    ))
                    .changed()
                {
                    self.last_refresh_at = Instant::now();
                }
                ui.separator();
                if ui
                    .add_enabled(self.elevated && !self.busy, egui::Button::new("Install…"))
                    .clicked()
                {
                    self.install_form = Some(InstallForm::default());
                }
                ui.separator();
                ui.label("Show:");
                let prior = self.filter_managed_only;
                egui::ComboBox::from_id_salt("filter")
                    .selected_text(if self.filter_managed_only {
                        "Managed only"
                    } else {
                        "All services"
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.filter_managed_only, true, "Managed only");
                        ui.selectable_value(&mut self.filter_managed_only, false, "All services");
                    });
                if prior != self.filter_managed_only {
                    // A selected service may now be filtered out of the table.
                    self.invalidate_selection_if_hidden();
                    self.status = format!(
                        "{} services ({})",
                        self.filtered_count(),
                        if self.filter_managed_only {
                            "managed"
                        } else {
                            "all"
                        }
                    );
                }
                ui.separator();
                ui.label("Search:");
                let search_changed = ui
                    .add(
                        egui::TextEdit::singleline(&mut self.search)
                            .hint_text("name or display")
                            .desired_width(180.0),
                    )
                    .changed();
                let mut search_cleared = false;
                if !self.search.is_empty() && ui.small_button("×").on_hover_text("Clear").clicked()
                {
                    self.search.clear();
                    search_cleared = true;
                }
                if search_changed || search_cleared {
                    // A selected service may no longer match the search.
                    self.invalidate_selection_if_hidden();
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if self.busy {
                        ui.spinner();
                    }
                });
            });
            ui.add_space(2.0);
        });

        // Auto-refresh tick: if enabled and idle for AUTO_REFRESH_INTERVAL,
        // fire a Refresh job. Request a repaint at the next deadline so we
        // don't have to wait for user input to wake up.
        if self.auto_refresh && !self.busy {
            if self.last_refresh_at.elapsed() >= AUTO_REFRESH_INTERVAL {
                self.last_refresh_at = Instant::now();
                self.submit_job(Job::Refresh, "Auto-refreshing…");
            } else {
                let remaining = AUTO_REFRESH_INTERVAL - self.last_refresh_at.elapsed();
                ctx.request_repaint_after(remaining);
            }
        }

        // === Elevation banner (only when not elevated) ===
        if !self.elevated {
            egui::TopBottomPanel::top("elevation-banner").show(ctx, |ui| {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.colored_label(
                        egui::Color32::from_rgb(200, 130, 50),
                        "⚠ Read-only — start an elevated session to manage services.",
                    );
                    if ui.button("Relaunch as Administrator").clicked() {
                        if crate::elevation::relaunch_as_admin() {
                            std::process::exit(0);
                        } else {
                            self.status = "Relaunch declined or failed.".into();
                        }
                    }
                });
                ui.add_space(4.0);
            });
        }

        // === Status bar ===
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(&self.status);
            });
        });

        // === Detail / action pane (right) ===
        egui::SidePanel::right("detail")
            .default_width(420.0)
            .min_width(280.0)
            .show(ctx, |ui| {
                self.render_detail(ui);
            });

        // === Service list (centre) ===
        egui::CentralPanel::default().show(ctx, |ui| {
            self.render_table(ui);
        });

        // === Modals ===
        self.render_install_modal(ctx);
        self.render_edit_modal(ctx);
        self.render_remove_modal(ctx);
        self.render_processes_modal(ctx);

        // While a job is in flight, repaint at ~10 Hz so the spinner moves.
        if self.busy {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
}

impl App {
    fn render_table(&mut self, ui: &mut egui::Ui) {
        use egui_extras::{Column, TableBuilder};
        let mut clicked: Option<String> = None;

        let rows: Vec<&ServiceDefinition> = self
            .services
            .iter()
            .filter(|d| self.matches_filters(d))
            .collect();

        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::initial(180.0).at_least(80.0))
            .column(Column::initial(260.0).at_least(120.0))
            .column(Column::initial(80.0))
            .column(Column::initial(110.0))
            .column(Column::remainder().at_least(80.0))
            .header(22.0, |mut h| {
                h.col(|ui| {
                    ui.strong("Name");
                });
                h.col(|ui| {
                    ui.strong("Display name");
                });
                h.col(|ui| {
                    ui.strong("Kind");
                });
                h.col(|ui| {
                    ui.strong("State");
                });
                h.col(|ui| {
                    ui.strong("Startup");
                });
            })
            .body(|mut body| {
                for d in &rows {
                    body.row(22.0, |mut row| {
                        let name = &d.native.name;
                        let is_sel = self.selected.as_deref() == Some(name.as_str());
                        row.set_selected(is_sel);
                        let kind = match d.management_kind() {
                            ManagementKind::Managed => "managed",
                            ManagementKind::Native => "native",
                        };
                        let state = d
                            .runtime
                            .as_ref()
                            .map(|r| format!("{:?}", r.state))
                            .unwrap_or_else(|| "-".into());
                        let startup = format!("{:?}", d.native.startup);

                        let click = |r: &egui::Response| {
                            if r.clicked() {
                                Some(name.clone())
                            } else {
                                None
                            }
                        };
                        row.col(|ui| {
                            if let Some(n) = click(&ui.label(name)) {
                                clicked = Some(n);
                            }
                        });
                        row.col(|ui| {
                            if let Some(n) = click(&ui.label(&d.native.display_name)) {
                                clicked = Some(n);
                            }
                        });
                        row.col(|ui| {
                            if let Some(n) = click(&ui.label(kind)) {
                                clicked = Some(n);
                            }
                        });
                        row.col(|ui| {
                            if let Some(n) = click(&ui.label(&state)) {
                                clicked = Some(n);
                            }
                        });
                        row.col(|ui| {
                            if let Some(n) = click(&ui.label(&startup)) {
                                clicked = Some(n);
                            }
                        });
                    });
                }
            });

        if let Some(n) = clicked {
            self.selected = Some(n);
        }
    }

    fn render_detail(&mut self, ui: &mut egui::Ui) {
        let Some(def) = self.current().cloned() else {
            ui.add_space(20.0);
            ui.colored_label(egui::Color32::GRAY, "Select a service to view details");
            return;
        };

        ui.heading(&def.native.display_name);
        ui.add_space(6.0);
        let labelled = |ui: &mut egui::Ui, k: &str, v: &str| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(format!("{k}: ")).color(egui::Color32::GRAY));
                ui.label(v);
            });
        };
        labelled(ui, "Name", &def.native.name);
        if let Some(d) = &def.native.description {
            ui.label(
                egui::RichText::new(d)
                    .color(egui::Color32::DARK_GRAY)
                    .italics(),
            );
        }
        labelled(ui, "Startup", &format!("{:?}", def.native.startup));
        labelled(ui, "Type", &format!("{:?}", def.native.service_type));
        labelled(ui, "Image", &def.native.image_path);
        if let Some(account) = &def.native.account {
            labelled(ui, "Account", account);
        }
        if let Some(rt) = &def.runtime {
            let pid = rt.pid.map(|p| p.to_string()).unwrap_or_else(|| "—".into());
            labelled(ui, "State", &format!("{:?} (pid {pid})", rt.state));
        }
        if !def.native.depend_on_services.is_empty() {
            labelled(ui, "Depends on", &def.native.depend_on_services.join(", "));
        }

        if let Some(m) = &def.managed {
            ui.add_space(8.0);
            ui.separator();
            ui.label(
                egui::RichText::new("Managed (NSSM-compatible)")
                    .strong()
                    .color(egui::Color32::from_rgb(60, 120, 180)),
            );
            if let Some(a) = &m.application {
                labelled(ui, "Application", a);
            }
            if let Some(a) = &m.app_parameters {
                labelled(ui, "Arguments", a);
            }
            if let Some(a) = &m.app_directory {
                labelled(ui, "Working dir", a);
            }
            if let Some(io) = m.io.stdout.as_ref() {
                labelled(ui, "Stdout", &io.path);
            }
            if let Some(io) = m.io.stderr.as_ref() {
                labelled(ui, "Stderr", &io.path);
            }
        }

        // === Actions ===
        ui.add_space(12.0);
        ui.separator();
        ui.add_space(4.0);
        let state = self.current_state();
        let managed = self.current_managed();
        let elevated = self.elevated && !self.busy;
        // Lifecycle controls are gated to NGSM-managed services. NGSM is not
        // a general-purpose services.msc; stopping or restarting a critical
        // native Windows service from this elevated view would be an easy
        // and damaging mistake.
        let owned = def.is_managed();
        let can_start = elevated && owned && matches!(state, Some(ServiceState::Stopped) | None);
        let can_stop = elevated
            && owned
            && matches!(
                state,
                Some(ServiceState::Running)
                    | Some(ServiceState::Paused)
                    | Some(ServiceState::StartPending)
            );
        // Restart works from any actionable state: it skips the stop step
        // when the service is already stopped, so a stopped service can be
        // restarted (which simply starts it).
        let can_restart = can_start || can_stop;
        let can_pause = elevated && managed && matches!(state, Some(ServiceState::Running));
        let can_continue = elevated && managed && matches!(state, Some(ServiceState::Paused));
        // Rotate is only meaningful for services with online log rotation;
        // for offline logs an on-demand rotate is a no-op.
        let has_online_rotation = def
            .managed
            .as_ref()
            .is_some_and(|m| m.has_online_rotation());
        let can_rotate = elevated
            && has_online_rotation
            && matches!(
                state,
                Some(ServiceState::Running) | Some(ServiceState::Paused)
            );
        let can_processes = !self.busy
            && matches!(
                state,
                Some(ServiceState::Running)
                    | Some(ServiceState::Paused)
                    | Some(ServiceState::StartPending)
            );
        // Edit needs readable managed config; Remove only needs the service
        // to *be* NGSM/NSSM-managed (image-path match counts), so an orphaned
        // service whose `Application` marker is missing can still be cleaned up.
        let can_edit = elevated && managed;
        let can_remove = elevated && def.is_managed();

        let name = def.native.name.clone();
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(can_start, egui::Button::new("Start"))
                .clicked()
            {
                self.submit_job(Job::Start(name.clone()), &format!("Starting '{name}'…"));
            }
            if ui
                .add_enabled(can_stop, egui::Button::new("Stop"))
                .clicked()
            {
                self.submit_job(Job::Stop(name.clone()), &format!("Stopping '{name}'…"));
            }
            if ui
                .add_enabled(can_restart, egui::Button::new("Restart"))
                .clicked()
            {
                self.submit_job(Job::Restart(name.clone()), &format!("Restarting '{name}'…"));
            }
            if ui
                .add_enabled(can_pause, egui::Button::new("Pause"))
                .clicked()
            {
                self.submit_job(Job::Pause(name.clone()), &format!("Pausing '{name}'…"));
            }
            if ui
                .add_enabled(can_continue, egui::Button::new("Continue"))
                .clicked()
            {
                self.submit_job(Job::Continue(name.clone()), &format!("Resuming '{name}'…"));
            }
            if ui
                .add_enabled(can_rotate, egui::Button::new("Rotate logs"))
                .clicked()
            {
                self.submit_job(Job::Rotate(name.clone()), &format!("Rotating '{name}'…"));
            }
            if ui
                .add_enabled(can_processes, egui::Button::new("Processes…"))
                .clicked()
            {
                self.submit_job(
                    Job::Processes(name.clone()),
                    &format!("Listing processes of '{name}'…"),
                );
            }
            if ui
                .add_enabled(can_edit, egui::Button::new("Edit…"))
                .clicked()
            {
                self.edit_form = Some(EditForm::from_definition(&def));
            }
            if ui
                .add_enabled(
                    can_remove,
                    egui::Button::new(
                        egui::RichText::new("Remove").color(egui::Color32::from_rgb(160, 30, 30)),
                    ),
                )
                .clicked()
            {
                self.confirm_remove = Some(name.clone());
            }
        });
    }

    fn render_install_modal(&mut self, ctx: &egui::Context) {
        let Some(form) = self.install_form.as_mut() else {
            return;
        };
        let mut should_close = false;
        let mut submitted: Option<InstallSpec> = None;
        egui::Window::new("Install service")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .show(ctx, |ui| match show_install_dialog(ui, form) {
                InstallDialogResult::Idle => {}
                InstallDialogResult::Cancel => should_close = true,
                InstallDialogResult::Submit(spec) => {
                    submitted = Some(spec);
                    should_close = true;
                }
            });
        if let Some(spec) = submitted {
            let label = format!("Installing '{}'…", spec.name);
            self.submit_job(Job::Install(spec), &label);
        }
        if should_close {
            self.install_form = None;
        }
    }

    fn render_edit_modal(&mut self, ctx: &egui::Context) {
        let Some(form) = self.edit_form.as_mut() else {
            return;
        };
        let mut should_close = false;
        let mut submitted: Option<EditSpec> = None;
        egui::Window::new("Edit service")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .show(ctx, |ui| match show_edit_dialog(ui, form) {
                EditDialogResult::Idle => {}
                EditDialogResult::Cancel => should_close = true,
                EditDialogResult::Submit(spec) => {
                    submitted = Some(spec);
                    should_close = true;
                }
            });
        if let Some(spec) = submitted {
            let label = format!("Editing '{}'…", spec.name);
            self.submit_job(Job::Edit(spec), &label);
        }
        if should_close {
            self.edit_form = None;
        }
    }

    fn render_remove_modal(&mut self, ctx: &egui::Context) {
        let Some(name) = self.confirm_remove.clone() else {
            return;
        };
        let mut confirmed = false;
        let mut cancelled = false;
        egui::Window::new("Remove service")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .show(ctx, |ui| {
                ui.label(format!(
                    "Remove the service '{name}'?\n\nThis deletes the SCM registration and the managed configuration."
                ));
                ui.add_space(12.0);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Remove").clicked() {
                        confirmed = true;
                    }
                    if ui.button("Cancel").clicked() {
                        cancelled = true;
                    }
                });
            });
        if confirmed {
            let label = format!("Removing '{name}'…");
            self.submit_job(Job::Remove(name.clone()), &label);
        }
        if confirmed || cancelled {
            self.confirm_remove = None;
        }
    }

    fn render_processes_modal(&mut self, ctx: &egui::Context) {
        let Some(view) = self.processes_view.as_ref() else {
            return;
        };
        let mut should_close = false;
        let service = view.service.clone();
        let root_pid = view.root_pid;
        let rows = view.rows.clone();
        egui::Window::new("Processes")
            .collapsible(false)
            .resizable(true)
            .default_width(540.0)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .show(ctx, |ui| {
                ui.colored_label(egui::Color32::GRAY, format!("Root PID: {root_pid}"));
                if show_processes_dialog(ui, &service, &rows) {
                    should_close = true;
                }
            });
        if should_close {
            self.processes_view = None;
        }
    }
}
