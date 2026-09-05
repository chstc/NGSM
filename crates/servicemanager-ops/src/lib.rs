//! Shared service-management operations extracted from the CLI, GUI worker,
//! and broker to eliminate verbatim duplication (M-02).
//!
//! Every public function returns [`OpResult`] — `Ok(message)` is a
//! human-readable success status; `Err(error)` is a structured core error.
//! Callers convert errors to display strings at their own UI or wire boundary
//! (CLI stderr/stdout, GUI status bar, broker JSON value).
//!
//! # Crate layout
//!
//! | Module | Contents |
//! |---|---|
//! | `error` | [`OpResult`] type alias |
//! | `specs` | [`InstallSpec`], [`EditSpec`], [`RecoverySpec`] |
//! | `helpers` | `io_stream`, `ensure_ngsm_managed`, `ensure_enabled` (crate-private) |
//! | `list` | [`list_services`] |
//! | `install` | [`install`] + rollback |
//! | `edit` | [`edit`] |
//! | `remove` | [`remove`] (with stopped check + `force_native` option) |
//! | `repair` | [`repair_runner`] (safe NGSM runner ImagePath/type rebind) |
//! | `lifecycle` | [`start`], [`stop`], [`pause`], [`continue_service`], [`restart`] |
//! | `rotate` | [`rotate`] (with online-rotation preflight) |
//! | `recovery` | [`read_recovery`], [`save_recovery`] |

mod error;
mod helpers;

#[cfg(all(test, windows))]
mod config_test_support;

pub mod edit;
pub mod install;
pub mod lifecycle;
pub mod list;
pub mod recovery;
pub mod remove;
pub mod repair;
pub mod rotate;
pub mod specs;
pub mod validate;

// Flat re-exports so callers can write `servicemanager_ops::install(spec)`.
pub use error::OpResult;
pub use specs::{EditSpec, InstallSpec, RecoverySpec};

pub use edit::edit;
pub use install::install;
pub use lifecycle::{continue_service, pause, restart, restart_with_options, start, stop};
pub use list::list_services;
pub use recovery::{read_recovery, save_recovery, update_recovery, validate_exit_action_key};
pub use remove::remove;
pub use repair::repair_runner;
pub use rotate::rotate;
pub use validate::validate_managed_config;
