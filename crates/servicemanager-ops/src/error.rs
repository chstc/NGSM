/// Result of a service-management operation. `Ok(message)` is the
/// human-readable success status; `Err(error)` carries the structured core
/// error. Callers convert errors to display strings at their UI or wire
/// boundary.
pub type OpResult = servicemanager_core::Result<String>;

pub(crate) type Result<T> = servicemanager_core::Result<T>;

pub(crate) fn message_error(message: impl Into<String>) -> servicemanager_core::Error {
    servicemanager_core::Error::other(message)
}
