//! NSSM-compatible registry layout adapter.
//!
//! Reads and writes the `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters`
//! keys that legacy NSSM (and the new NGSM) use, mapping them to
//! the typed [`ManagedApplicationConfig`].
//!
//! NGSM as a whole is Windows-only (the `ngsm` binary and GUI fail to build
//! elsewhere by design). This crate, however, exposes its non-Windows
//! surface as stubs that return an explicit unsupported-platform error, so
//! the library layers (`core`/`registry`/`win32`/`supervisor`) still
//! type-check on a non-Windows host for faster local iteration.

#![cfg_attr(not(windows), allow(dead_code, unused_imports))]

#[cfg(windows)]
mod config_lock;
#[cfg(windows)]
mod imp;
#[cfg(windows)]
pub use config_lock::{lock_service_config, ServiceConfigGuard};

#[cfg(windows)]
pub use imp::{
    create_managed_config, delete_managed_config, get_value, nssm_keys, read_managed_config,
    set_value, unset_value, validate_managed_config, write_managed_config, ManagedValueKind,
    ValueRecord,
};

#[cfg(not(windows))]
mod stub {
    use servicemanager_core::{Error, ManagedApplicationConfig, Result};

    fn unsupported(op: &str) -> Error {
        Error::other(format!("registry operation '{op}' requires Windows"))
    }

    pub struct ServiceConfigGuard(std::marker::PhantomData<std::rc::Rc<()>>);

    impl ServiceConfigGuard {
        pub fn was_abandoned(&self) -> bool {
            false
        }
    }

    pub fn lock_service_config(_name: &str) -> Result<ServiceConfigGuard> {
        Err(unsupported("lock_service_config"))
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ManagedValueKind {
        String,
        MultiString,
        Number,
    }

    #[derive(Debug, Clone)]
    pub struct ValueRecord {
        pub kind: ManagedValueKind,
        pub value: String,
    }

    pub fn read_managed_config(_service: &str) -> Result<Option<ManagedApplicationConfig>> {
        // Return an explicit unsupported-platform error rather than `Ok(None)`:
        // a caller must not mistake "this host has no registry" for "this
        // service is native / has no managed config".
        Err(unsupported("read_managed_config"))
    }

    pub fn create_managed_config(_service: &str, _cfg: &ManagedApplicationConfig) -> Result<()> {
        Err(unsupported("create_managed_config"))
    }

    pub fn write_managed_config(_service: &str, _cfg: &ManagedApplicationConfig) -> Result<()> {
        Err(unsupported("write_managed_config"))
    }

    pub fn validate_managed_config(_cfg: &ManagedApplicationConfig) -> Result<()> {
        Err(unsupported("validate_managed_config"))
    }

    pub fn delete_managed_config(_service: &str) -> Result<()> {
        Err(unsupported("delete_managed_config"))
    }

    pub fn get_value(_service: &str, _name: &str) -> Result<Option<ValueRecord>> {
        Err(unsupported("get_value"))
    }

    pub fn set_value(_service: &str, _name: &str, _value: &str) -> Result<()> {
        Err(unsupported("set_value"))
    }

    pub fn unset_value(_service: &str, _name: &str) -> Result<()> {
        Err(unsupported("unset_value"))
    }

    /// Mirrors the Windows `nssm_keys` constant surface exactly, so code that
    /// references these names compiles identically on every platform.
    pub mod nssm_keys {
        pub const APPLICATION: &str = "Application";
        pub const APP_PARAMETERS: &str = "AppParameters";
        pub const APP_DIRECTORY: &str = "AppDirectory";
        pub const APP_ENVIRONMENT: &str = "AppEnvironment";
        pub const APP_ENVIRONMENT_EXTRA: &str = "AppEnvironmentExtra";
        pub const APP_EXIT: &str = "AppExit";
        pub const APP_RESTART_DELAY: &str = "AppRestartDelay";
        pub const APP_THROTTLE: &str = "AppThrottle";
        pub const APP_STOP_METHOD_SKIP: &str = "AppStopMethodSkip";
        pub const APP_KILL_CONSOLE_GRACE: &str = "AppStopMethodConsole";
        pub const APP_KILL_WINDOW_GRACE: &str = "AppStopMethodWindow";
        pub const APP_KILL_THREADS_GRACE: &str = "AppStopMethodThreads";
        pub const APP_KILL_PROCESS_TREE: &str = "AppKillProcessTree";
        pub const APP_STDIN: &str = "AppStdin";
        pub const APP_STDOUT: &str = "AppStdout";
        pub const APP_STDERR: &str = "AppStderr";
        pub const APP_STDIO_SHARING: &str = "ShareMode";
        pub const APP_STDIO_DISPOSITION: &str = "CreationDisposition";
        pub const APP_STDIO_FLAGS: &str = "FlagsAndAttributes";
        pub const APP_STDIO_COPY_AND_TRUNCATE: &str = "CopyAndTruncate";
        pub const APP_ROTATE: &str = "AppRotateFiles";
        pub const APP_ROTATE_ONLINE: &str = "AppRotateOnline";
        pub const APP_ROTATE_SECONDS: &str = "AppRotateSeconds";
        pub const APP_ROTATE_BYTES_LOW: &str = "AppRotateBytes";
        pub const APP_ROTATE_BYTES_HIGH: &str = "AppRotateBytesHigh";
        pub const APP_ROTATE_DELAY: &str = "AppRotateDelay";
        pub const APP_TIMESTAMP_LOG: &str = "AppTimestampLog";
        pub const APP_PRIORITY: &str = "AppPriority";
        pub const APP_AFFINITY: &str = "AppAffinity";
        pub const APP_EVENTS: &str = "AppEvents";
    }
}

#[cfg(not(windows))]
pub use stub::{
    create_managed_config, delete_managed_config, get_value, lock_service_config, nssm_keys,
    read_managed_config, set_value, unset_value, validate_managed_config, write_managed_config,
    ManagedValueKind, ServiceConfigGuard, ValueRecord,
};
