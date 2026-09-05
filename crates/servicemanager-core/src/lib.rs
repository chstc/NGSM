//! Domain models for NGSM.
//!
//! This crate is intentionally free of Windows API calls. Types here are the
//! canonical representation of a managed service. Adapters live in
//! `servicemanager-win32` (SCM) and `servicemanager-registry` (NSSM keys).

pub mod error;
pub mod events;
mod expansion;
pub mod model;
pub mod paths;
pub mod validate;

pub use error::{Error, Result};
pub use events::{EventKind, EventRecord, StopReason};
pub use model::*;
pub use validate::{
    quote_windows_arg, validate_absolute_path, validate_hook_component, validate_service_name,
    MAX_SERVICE_NAME_LEN,
};
