//! Windows API wrappers used by NGSM.
//!
//! Unsafe code is concentrated here. Public APIs return
//! [`servicemanager_core::Result`] and never expose raw handles.

#![cfg_attr(not(windows), allow(dead_code, unused_imports))]
#![warn(clippy::undocumented_unsafe_blocks)]

#[cfg(windows)]
pub mod console_ctrl;
#[cfg(windows)]
pub mod control;
#[cfg(windows)]
mod handles;
#[cfg(windows)]
pub mod job;
#[cfg(windows)]
pub mod process_tree;
#[cfg(windows)]
pub mod runtime;
#[cfg(windows)]
pub mod scm;
#[cfg(windows)]
pub mod windows_close;

#[cfg(windows)]
pub use console_ctrl::{ensure_console, send_ctrl_break};
#[cfg(windows)]
pub use control::{
    build_run_service_command, control_service, install_service, remove_service,
    repair_service_runner, start_service, update_native_config, validate_runner_acl_chain,
    InstallOptions, InstallStartType, ServiceControlSignal, ServiceDependencies,
    SERVICE_CONTROL_ROTATE,
};
#[cfg(windows)]
pub use elevation::is_elevated;
#[cfg(windows)]
pub use job::JobObject;
#[cfg(windows)]
pub use process_tree::{
    enumerate_descendants, resume_process, suspend_process, terminate_process, ProcessInfo,
};
#[cfg(windows)]
pub use runtime::{run_service_dispatcher, ServiceContext, ServiceControl, ServiceLifecycle};
#[cfg(windows)]
pub use scm::{enumerate_services, query_service, NativeService};
#[cfg(windows)]
pub use windows_close::{post_wm_close_to_process, post_wm_quit_to_process};
#[cfg(windows)]
pub mod elevation;

#[cfg(not(windows))]
pub mod scm {
    use servicemanager_core::{Error, NativeServiceConfig, Result, ServiceRuntimeState};

    #[derive(Debug, Clone)]
    pub struct NativeService {
        pub config: NativeServiceConfig,
        pub runtime: Option<ServiceRuntimeState>,
        pub query_error: Option<String>,
    }

    pub fn enumerate_services() -> Result<Vec<NativeService>> {
        Err(Error::other("SCM enumeration requires Windows"))
    }

    pub fn query_service(_name: &str) -> Result<NativeService> {
        Err(Error::other("SCM query requires Windows"))
    }
}

#[cfg(not(windows))]
pub use scm::NativeService;
