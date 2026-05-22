//! Slint-based desktop UI for NGSM.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// The desktop UI drives the Windows SCM/registry through `servicemanager-win32`
// and is Windows-only by design — fail fast and clearly on other targets.
#[cfg(not(windows))]
compile_error!("servicemanager-gui builds only for Windows targets.");

mod adapter;
mod app;
mod config;
mod data;
mod elevation;
mod forms;
mod recovery;

slint::include_modules!();

pub fn run() -> Result<(), slint::PlatformError> {
    let window = app::build_ui()?;
    window.run()
}
