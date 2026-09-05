use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use servicemanager_core::{
    ExitAction, ExitActionPolicy, IoStream, ManagedApplicationConfig, Result,
};

use crate::error::message_error;
use crate::helpers::ConfigBackend;
use crate::EditSpec;

pub(crate) fn service_name() -> String {
    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);
    format!(
        "NgsmOpsFixture_{}_{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

pub(crate) fn configured_stream(path: &str) -> IoStream {
    IoStream {
        path: path.into(),
        share_mode: Some(3),
        creation_disposition: Some(4),
        flags_and_attributes: Some(128),
        copy_and_truncate: Some(true),
    }
}

pub(crate) fn config() -> ManagedApplicationConfig {
    let mut config = ManagedApplicationConfig {
        application: Some("C:\\fixture\\app.exe".into()),
        app_parameters: Some("--original".into()),
        app_directory: Some("C:\\fixture".into()),
        environment: vec!["FIRST=1".into(), "LAST=2".into()],
        ..Default::default()
    };
    config.io.stdout = Some(configured_stream("C:\\logs\\out.log"));
    config.io.stderr = Some(configured_stream("C:\\logs\\err.log"));
    config.restart.restart_delay_ms = Some(1000);
    config.restart.throttle_delay_ms = Some(2000);
    config.restart.default_action = Some(ExitAction::Exit);
    config.exit_actions.insert(
        "default".into(),
        ExitActionPolicy {
            action: ExitAction::Exit,
        },
    );
    config.exit_actions.insert(
        "0".into(),
        ExitActionPolicy {
            action: ExitAction::Ignore,
        },
    );
    config
}

pub(crate) fn assert_config_eq(
    actual: &ManagedApplicationConfig,
    expected: &ManagedApplicationConfig,
) {
    // The model has no PartialEq; derived Debug includes the complete snapshot.
    assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
}

pub(crate) struct RecordingConfigBackend {
    pub config: Arc<Mutex<ManagedApplicationConfig>>,
    pub calls: Vec<&'static str>,
    pub snapshots: Vec<ManagedApplicationConfig>,
    pub read_error: Option<&'static str>,
    pub managed: bool,
    pub after_read: Option<Box<dyn FnOnce() + Send>>,
    pub before_native: Option<Box<dyn FnOnce() + Send>>,
    pub native_error: Option<&'static str>,
    pub write_errors: VecDeque<Option<&'static str>>,
}

impl RecordingConfigBackend {
    pub fn new(config: ManagedApplicationConfig) -> Self {
        Self::sharing(Arc::new(Mutex::new(config)))
    }

    pub fn sharing(config: Arc<Mutex<ManagedApplicationConfig>>) -> Self {
        Self {
            config,
            calls: Vec::new(),
            snapshots: Vec::new(),
            read_error: None,
            managed: true,
            after_read: None,
            before_native: None,
            native_error: None,
            write_errors: VecDeque::new(),
        }
    }
}

impl ConfigBackend for RecordingConfigBackend {
    fn read_managed(&mut self, _name: &str) -> Result<Option<ManagedApplicationConfig>> {
        self.calls.push("read");
        if let Some(error) = self.read_error {
            return Err(message_error(error));
        }
        let config = self.managed.then(|| self.config.lock().unwrap().clone());
        if let Some(after_read) = self.after_read.take() {
            after_read();
        }
        Ok(config)
    }

    fn write_managed(&mut self, name: &str, config: &ManagedApplicationConfig) -> Result<()> {
        // Model the adapter's inner writer guard using the actual reentrant
        // cross-process primitive, not a substitute process-local lock.
        let _guard = servicemanager_registry::lock_service_config(name)?;
        self.calls.push("write");
        self.snapshots.push(config.clone());
        if let Some(error) = self.write_errors.pop_front().flatten() {
            return Err(message_error(error));
        }
        *self.config.lock().unwrap() = config.clone();
        Ok(())
    }

    fn update_native(&mut self, _spec: &EditSpec) -> Result<()> {
        self.calls.push("native");
        if let Some(before_native) = self.before_native.take() {
            before_native();
        }
        match self.native_error {
            Some(error) => Err(message_error(error)),
            None => Ok(()),
        }
    }
}
