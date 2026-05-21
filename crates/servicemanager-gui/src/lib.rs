//! egui-based desktop UI for NGSM.
//!
//! Runs in-process with the rest of the Rust workspace — there is no IPC
//! across an elevation boundary anymore, so privileged operations call
//! straight into `servicemanager-win32` / `servicemanager-registry`. When
//! the process isn't elevated, write actions are still attempted; SCM
//! returns access-denied and the GUI surfaces that with a re-launch banner.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// The desktop UI drives the Windows SCM/registry through `servicemanager-win32`
// and is Windows-only by design — fail fast and clearly on other targets.
#[cfg(not(windows))]
compile_error!("servicemanager-gui builds only for Windows targets.");

mod app;
mod data;
mod dialogs;
mod elevation;

pub fn run() -> Result<(), eframe::Error> {
    let icon = load_icon();
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 640.0])
            .with_min_inner_size([720.0, 420.0])
            .with_title("NGSM")
            .with_icon(icon),
        ..Default::default()
    };
    eframe::run_native(
        "NGSM",
        options,
        Box::new(|cc| Ok(Box::new(app::App::new(cc)))),
    )
}

fn load_icon() -> std::sync::Arc<eframe::egui::IconData> {
    let bytes = include_bytes!("../assets/logo.png");
    match image::load_from_memory(bytes) {
        Ok(img) => {
            let rgba = img.to_rgba8();
            let (w, h) = rgba.dimensions();
            std::sync::Arc::new(eframe::egui::IconData {
                rgba: rgba.into_raw(),
                width: w,
                height: h,
            })
        }
        Err(_) => std::sync::Arc::new(eframe::egui::IconData::default()),
    }
}
