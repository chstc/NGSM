use servicemanager_core::{IoStream, ManagedApplicationConfig, ServiceDefinition};
use servicemanager_win32::query_service;

use crate::specs::EditSpec;

pub(crate) trait ConfigBackend {
    fn read_managed(
        &mut self,
        name: &str,
    ) -> servicemanager_core::Result<Option<ManagedApplicationConfig>>;
    fn write_managed(
        &mut self,
        name: &str,
        config: &ManagedApplicationConfig,
    ) -> servicemanager_core::Result<()>;
    fn update_native(&mut self, spec: &EditSpec) -> servicemanager_core::Result<()>;
}

pub(crate) struct RegistryConfigBackend;

impl ConfigBackend for RegistryConfigBackend {
    fn read_managed(
        &mut self,
        name: &str,
    ) -> servicemanager_core::Result<Option<ManagedApplicationConfig>> {
        servicemanager_registry::read_managed_config(name)
    }

    fn write_managed(
        &mut self,
        name: &str,
        config: &ManagedApplicationConfig,
    ) -> servicemanager_core::Result<()> {
        servicemanager_registry::write_managed_config(name, config)
    }

    fn update_native(&mut self, spec: &EditSpec) -> servicemanager_core::Result<()> {
        servicemanager_win32::update_native_config(
            &spec.name,
            spec.display_name.as_deref(),
            spec.description.as_deref(),
            spec.start_type,
            spec.dependencies.as_ref(),
            spec.account.as_deref(),
            spec.password.as_deref(),
        )
    }
}

/// Wrap a log-file path in a plain [`IoStream`] with all optional fields
/// left at their defaults (share mode, creation disposition, flags, and
/// copy-and-truncate are each `None`, which lets the supervisor apply its
/// own defaults at runtime).
pub(crate) fn io_stream(path: String) -> IoStream {
    IoStream {
        path,
        share_mode: None,
        creation_disposition: None,
        flags_and_attributes: None,
        copy_and_truncate: None,
    }
}

/// Re-validate, against current SCM/registry state, that a service is
/// NGSM-managed before issuing a lifecycle control. The UI/CLI snapshot can
/// be stale — the caller must not trust it for lifecycle operations on
/// (potentially native) services. Fails closed when the managed config
/// cannot be read.
pub(crate) fn ensure_ngsm_managed(name: &str) -> servicemanager_core::Result<()> {
    let native = query_service(name)?;
    let managed = servicemanager_registry::read_managed_config(name).map_err(|e| {
        servicemanager_core::Error::other(format!(
            "'{name}': managed ownership cannot be determined — its managed config \
             is unreadable ({e})"
        ))
    })?;
    let def = ServiceDefinition {
        native: native.config,
        managed,
        runtime: native.runtime,
    };
    if def.is_managed() {
        Ok(())
    } else {
        Err(servicemanager_core::Error::other(format!(
            "'{name}' is not an NGSM-managed service — refusing the lifecycle operation"
        )))
    }
}

/// Re-check, against current SCM state, that a service is not Disabled before
/// attempting to start it. The UI/CLI gates this too, but its snapshot can be
/// stale.
pub(crate) fn ensure_enabled(name: &str) -> servicemanager_core::Result<()> {
    use servicemanager_core::StartupType;
    let native = query_service(name)?;
    if native.config.startup == StartupType::Disabled {
        return Err(servicemanager_core::Error::other(format!(
            "'{name}' is disabled — enable it before starting"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_stream_has_all_optional_fields_none() {
        let s = io_stream("C:\\logs\\out.log".into());
        assert_eq!(s.path, "C:\\logs\\out.log");
        assert!(s.share_mode.is_none());
        assert!(s.creation_disposition.is_none());
        assert!(s.flags_and_attributes.is_none());
        assert!(s.copy_and_truncate.is_none());
    }

    #[test]
    fn io_stream_preserves_path() {
        let path = "D:\\my logs\\service stderr.log".to_string();
        let s = io_stream(path.clone());
        assert_eq!(s.path, path);
    }
}
