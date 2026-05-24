//! Shared service-management operations extracted from the CLI, GUI worker,
//! and broker to eliminate verbatim duplication (M-02).
//!
//! Every public function returns [`OpResult`] — `Ok(message)` is a
//! human-readable success status; `Err(message)` is a failure message.
//! Callers format these strings for their own UI (CLI stdout, GUI status bar,
//! broker JSON value).
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
//! | `lifecycle` | [`start`], [`stop`], [`pause`], [`continue_service`], [`restart`] |
//! | `rotate` | [`rotate`] (with online-rotation preflight) |
//! | `recovery` | [`read_recovery`], [`save_recovery`] |

mod error;
mod helpers;

pub mod edit;
pub mod install;
pub mod lifecycle;
pub mod list;
pub mod recovery;
pub mod remove;
pub mod rotate;
pub mod specs;

// Flat re-exports so callers can write `servicemanager_ops::install(spec)`.
pub use error::OpResult;
pub use specs::{EditSpec, InstallSpec, RecoverySpec};

pub use edit::edit;
pub use install::install;
pub use lifecycle::{continue_service, pause, restart, start, stop};
pub use list::list_services;
pub use recovery::{read_recovery, save_recovery, validate_exit_action_key};
pub use remove::remove;
pub use rotate::rotate;
