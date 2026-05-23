/// Result of a service-management operation. `Ok(message)` is the
/// human-readable success status; `Err(message)` is the failure message.
/// Callers format these strings for their own UI (CLI stdout, GUI status
/// bar, broker JSON value).
pub type OpResult = Result<String, String>;
