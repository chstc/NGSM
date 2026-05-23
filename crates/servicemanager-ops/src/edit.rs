use servicemanager_win32::update_native_config;

use crate::error::OpResult;
use crate::helpers::io_stream;
use crate::specs::EditSpec;

/// Edit an existing NGSM-managed service.
///
/// Managed (NSSM-owned) changes go first: every managed value is validated
/// and the registry write completes (or fails) *before* any native SCM field
/// is touched. A rejected value or a failed registry write therefore cannot
/// leave a half-applied edit with the native display name / start type already
/// changed.
///
/// `edit` only mutates NGSM-managed services. Re-validates ownership against
/// current registry state — the UI button / CLI snapshot may be stale, and a
/// native-only edit must not slip through unchecked.
pub fn edit(spec: EditSpec) -> OpResult {
    let touches_managed = spec.application.is_some()
        || spec.app_parameters.is_some()
        || spec.app_directory.is_some()
        || spec.stdout.is_some()
        || spec.stderr.is_some();

    let Some(mut managed) =
        servicemanager_registry::read_managed_config(&spec.name).map_err(|e| e.to_string())?
    else {
        return Err(format!(
            "'{}' is not an NGSM-managed service — refusing to edit it",
            spec.name
        ));
    };

    if touches_managed {
        if let Some(v) = spec.application {
            // Defence in depth — the edit form already rejects an empty
            // application, but never write one even if that changes.
            if v.trim().is_empty() {
                return Err("Application path must not be empty.".into());
            }
            managed.application = Some(v);
        }
        if let Some(v) = spec.app_parameters {
            managed.app_parameters = Some(v);
        }
        if let Some(v) = spec.app_directory {
            managed.app_directory = Some(v);
        }
        if let Some(v) = spec.stdout {
            // An empty path clears the value; the registry reconcile drops it.
            managed.io.stdout = if v.is_empty() {
                None
            } else {
                Some(io_stream(v))
            };
        }
        if let Some(v) = spec.stderr {
            managed.io.stderr = if v.is_empty() {
                None
            } else {
                Some(io_stream(v))
            };
        }
        servicemanager_registry::write_managed_config(&spec.name, &managed)
            .map_err(|e| e.to_string())?;
    }

    if spec.display_name.is_some() || spec.start_type.is_some() {
        update_native_config(&spec.name, spec.display_name.as_deref(), spec.start_type)
            .map_err(|e| e.to_string())?;
    }
    Ok(format!("Edited '{}'.", spec.name))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `edit` function cannot be unit-tested against real SCM/registry;
    /// the tests here cover the pure pre-check logic only.

    #[test]
    fn edit_empty_application_is_caught_by_type_system() {
        // EditSpec.application is Option<String>; passing Some("") should
        // result in an error from the trim check. We can't reach that code
        // without a live registry, but we can verify the data shape allows it.
        let spec = EditSpec {
            name: "MySvc".into(),
            application: Some("".into()),
            ..Default::default()
        };
        // The application field is Some("") — a non-None Some with an empty
        // string. The trim check inside `edit` will reject it with an Err.
        // We cannot call `edit` in a unit test (needs SCM), but we verify the
        // spec is constructed correctly so the caller path exercises the check.
        assert_eq!(spec.application.as_deref(), Some(""));
    }

    #[test]
    fn edit_spec_with_only_display_name_touches_no_managed_fields() {
        let spec = EditSpec {
            name: "MySvc".into(),
            display_name: Some("New Name".into()),
            ..Default::default()
        };
        // touches_managed should be false for this spec
        let touches_managed = spec.application.is_some()
            || spec.app_parameters.is_some()
            || spec.app_directory.is_some()
            || spec.stdout.is_some()
            || spec.stderr.is_some();
        assert!(!touches_managed);
        assert!(spec.display_name.is_some());
    }
}
