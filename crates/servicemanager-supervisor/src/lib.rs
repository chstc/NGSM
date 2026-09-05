//! Managed-process generations, cancelable lifecycle controls, contained hooks,
//! and loss-aware output drainage. SCM stays RUNNING during ordinary backoff.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[cfg(test)]
use servicemanager_core::LogRotationConfig;
use servicemanager_core::{ExitAction, IoStream, ManagedApplicationConfig};

#[cfg(windows)]
use servicemanager_win32::process_tree::PinnedProcess;
#[cfg(windows)]
use servicemanager_win32::{
    post_wm_close_to_process, post_wm_quit_to_process, send_ctrl_break, JobObject,
};

pub mod diagnostics;
pub mod event_log;
pub mod hooks;
mod io_task;
mod output;
mod process_control;
pub mod rotation;
mod transition;

use event_log::EventWriter;
use hooks::{find_hook, is_resume_event, run_hook, HookPoint, HookRuntime};
use io_task::IoTask;
use output::ReaderTask;
use process_control::{Member, PauseState};
use rotation::{dedup_sinks, RotationSink};
pub use transition::{Transition, TransitionOutcome};

#[cfg(test)]
pub(crate) static TEST_PROGRAM_DATA_LOCK: Mutex<()> = Mutex::new(());

pub const DEFAULT_RESTART_DELAY_MS: u32 = 0;
pub const DEFAULT_THROTTLE_DELAY_MS: u32 = 1500;
pub const THROTTLE_THRESHOLD_MS: u128 = 1500;
pub const DEFAULT_CONSOLE_GRACE_MS: u32 = 1500;
pub const DEFAULT_WINDOW_GRACE_MS: u32 = 1500;
pub const DEFAULT_THREADS_GRACE_MS: u32 = 1500;
pub const STOP_METHOD_SKIP_CONSOLE: u32 = 0x1;
pub const STOP_METHOD_SKIP_WINDOW: u32 = 0x2;
pub const STOP_METHOD_SKIP_THREADS: u32 = 0x4;
pub const STOP_METHOD_SKIP_TERMINATE: u32 = 0x8;
const CONTROL_POLL: Duration = Duration::from_millis(25);
const DRAIN_BUDGET: Duration = Duration::from_secs(5);
const SHUTDOWN_BUDGET: Duration = Duration::from_secs(90);
const PAUSE_CONTINUE_ACK_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, thiserror::Error)]
pub enum SupervisorError {
    #[error("application path is not configured")]
    MissingApplication,
    #[error("spawn {0:?}: {1}")]
    Spawn(PathBuf, #[source] io::Error),
    #[error("open log file {0:?}: {1}")]
    OpenLog(PathBuf, #[source] io::Error),
    #[error("open stdin file {0:?}: {1}")]
    OpenStdin(PathBuf, #[source] io::Error),
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("core: {0}")]
    Core(#[from] servicemanager_core::Error),
    #[error("process state degraded: {0}")]
    Degraded(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
    Stopped,
    ChildExited,
    SpawnFailed,
    /// The host must exit without SERVICE_STOPPED, after generation cleanup.
    Suicide {
        exit_code: i32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupStatus {
    Running,
    /// Initial Ignore policy intentionally keeps the host alive without a child.
    Quiesced,
}

#[derive(Default)]
struct TerminalState {
    ready: AtomicBool,
    released: AtomicBool,
}

/// The runner commits its SCM terminal decision while the supervisor still
/// exists to perform a concurrently accepted Stop's final hooks/bookkeeping.
pub struct TerminalGate {
    state: Arc<TerminalState>,
}

impl TerminalGate {
    pub fn is_ready(&self) -> bool {
        self.state.ready.load(Ordering::Acquire)
    }
    pub fn release(&self) {
        self.state.released.store(true, Ordering::Release);
    }
}

impl Drop for TerminalGate {
    fn drop(&mut self) {
        self.release();
    }
}

#[derive(Clone)]
pub struct StopSignal {
    tx: Sender<SupervisorMessage>,
    requested: Arc<AtomicBool>,
}

impl StopSignal {
    pub fn stop(&self) {
        // Cancellation is out-of-band: queued hooks/rotations cannot overtake Stop.
        self.requested.store(true, Ordering::Release);
        let _ = self.tx.send(SupervisorMessage::Stop);
    }

    pub fn is_requested(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }
}

enum SupervisorMessage {
    Stop,
    Rotate,
    Pause(Transition),
    Continue(Transition),
    PowerEvent(u32),
    ChildExited(u64),
    AutoRotate(u64),
    ReaderFailed(u64),
}

#[derive(Clone)]
pub struct RotateSignal {
    tx: Sender<SupervisorMessage>,
}
impl RotateSignal {
    pub fn rotate(&self) {
        let _ = self.tx.send(SupervisorMessage::Rotate);
    }
}

#[derive(Clone)]
pub struct PowerEventSignal {
    tx: Sender<SupervisorMessage>,
}
impl PowerEventSignal {
    pub fn power_event(&self, event_type: u32) {
        let _ = self.tx.send(SupervisorMessage::PowerEvent(event_type));
    }
}

#[derive(Clone)]
pub struct PauseContinueSignal {
    tx: Sender<SupervisorMessage>,
}
impl PauseContinueSignal {
    pub fn request_pause(&self) -> Transition {
        self.request(true)
    }
    pub fn request_resume(&self) -> Transition {
        self.request(false)
    }

    fn request(&self, pause: bool) -> Transition {
        let request = Transition::new();
        let message = if pause {
            SupervisorMessage::Pause(request.clone())
        } else {
            SupervisorMessage::Continue(request.clone())
        };
        if self.tx.send(message).is_err() {
            request.reject("supervisor is no longer running");
        }
        request
    }

    pub fn pause(&self) -> Result<(), String> {
        self.request_pause().wait(PAUSE_CONTINUE_ACK_TIMEOUT)
    }
    pub fn resume(&self) -> Result<(), String> {
        self.request_resume().wait(PAUSE_CONTINUE_ACK_TIMEOUT)
    }
}

#[derive(Clone)]
struct ObservedExit {
    code: i32,
    observed: Instant,
    timestamp: String,
    error: Option<String>,
}

#[derive(Default)]
struct ChildState {
    child: Option<Child>,
    exit: Option<ObservedExit>,
}

struct Generation {
    id: u64,
    pid: u32,
    started: Instant,
    state: Arc<Mutex<ChildState>>,
    watcher: Option<JoinHandle<()>>,
    recorded: bool,
    #[cfg(windows)]
    root: Option<PinnedProcess>,
}

impl Generation {
    fn exit(&self) -> Option<ObservedExit> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .exit
            .clone()
    }

    fn alive(&self) -> bool {
        if self.exit().is_some() {
            return false;
        }
        #[cfg(windows)]
        {
            self.root
                .as_ref()
                .is_some_and(|root| root.is_running().unwrap_or(false))
        }
        #[cfg(not(windows))]
        {
            true
        }
    }
}

pub struct Supervisor {
    name: String,
    config: ManagedApplicationConfig,
    launch_config: Option<ManagedApplicationConfig>,
    environment: Vec<(OsString, OsString)>,
    rx: Receiver<SupervisorMessage>,
    tx: Sender<SupervisorMessage>,
    stop_requested: Arc<AtomicBool>,
    pause: Mutex<PauseState>,
    generation: Option<Generation>,
    next_generation: u64,
    last_exit_code: Option<i32>,
    sinks: Vec<Arc<RotationSink>>,
    readers: Vec<ReaderTask>,
    open_task: Option<IoTask<Result<rotation::DedupSinks, SupervisorError>>>,
    rotation_task: Option<IoTask<io::Result<Option<PathBuf>>>>,
    startup_tx: Sender<StartupStatus>,
    startup_rx: Option<Receiver<StartupStatus>>,
    startup_reported: bool,
    terminal: Option<Arc<TerminalState>>,
    stop_hook_fired: bool,
    stopped_recorded: bool,
    shutdown_deadline: Option<Instant>,
    diagnostic: diagnostics::Reporter,
    #[cfg(windows)]
    job: Option<Arc<JobObject>>,
}

impl Supervisor {
    pub fn new(name: impl Into<String>, config: ManagedApplicationConfig) -> Self {
        let (tx, rx) = mpsc::channel();
        let (startup_tx, startup_rx) = mpsc::channel();
        Self {
            name: name.into(),
            config,
            launch_config: None,
            environment: Vec::new(),
            tx,
            rx,
            stop_requested: Arc::new(AtomicBool::new(false)),
            pause: Mutex::new(PauseState::default()),
            generation: None,
            next_generation: 0,
            last_exit_code: None,
            sinks: Vec::new(),
            readers: Vec::new(),
            open_task: None,
            rotation_task: None,
            startup_tx,
            startup_rx: Some(startup_rx),
            startup_reported: false,
            terminal: None,
            stop_hook_fired: false,
            stopped_recorded: false,
            shutdown_deadline: None,
            diagnostic: diagnostics::reporter().clone(),
            #[cfg(windows)]
            job: None,
        }
    }

    pub fn startup_receiver(&mut self) -> Receiver<StartupStatus> {
        self.startup_rx
            .take()
            .expect("startup_receiver must be called exactly once")
    }
    pub fn stop_signal(&self) -> StopSignal {
        StopSignal {
            tx: self.tx.clone(),
            requested: Arc::clone(&self.stop_requested),
        }
    }
    pub fn rotate_signal(&self) -> RotateSignal {
        RotateSignal {
            tx: self.tx.clone(),
        }
    }
    pub fn pause_continue_signal(&self) -> PauseContinueSignal {
        PauseContinueSignal {
            tx: self.tx.clone(),
        }
    }
    pub fn power_event_signal(&self) -> PowerEventSignal {
        PowerEventSignal {
            tx: self.tx.clone(),
        }
    }
    pub fn last_exit_code(&self) -> Option<i32> {
        self.last_exit_code
    }

    pub fn terminal_gate(&mut self) -> TerminalGate {
        assert!(
            self.terminal.is_none(),
            "terminal_gate must be taken only once"
        );
        let state = Arc::new(TerminalState::default());
        self.terminal = Some(Arc::clone(&state));
        TerminalGate { state }
    }

    fn stopping(&self) -> bool {
        self.stop_requested.load(Ordering::Acquire)
    }
    fn paused(&self) -> bool {
        self.pause.lock().unwrap_or_else(|e| e.into_inner()).paused
    }
    fn report(&self, operation: &str, message: impl std::fmt::Display) {
        let context = format!("{operation} generation={}", self.next_generation);
        self.diagnostic
            .report(&self.name, &context, &message.to_string());
    }

    pub fn run(mut self) -> Result<ExitReason, SupervisorError> {
        let writer = EventWriter::with_diagnostics(self.name.clone(), self.diagnostic.clone());
        let mut result = self.run_generations(&writer);
        if self.stopping() {
            result = self.finish_stop(&writer);
        } else if let Err(error) = self.cleanup_generation(&writer) {
            result = Err(error);
        }
        if self.stopping() && !self.stopped_recorded {
            result = self.finish_stop(&writer);
        }
        if let Some(terminal) = self.terminal.clone() {
            terminal.ready.store(true, Ordering::Release);
            let deadline = Instant::now() + Duration::from_secs(5);
            while !terminal.released.load(Ordering::Acquire) && Instant::now() < deadline {
                thread::sleep(CONTROL_POLL);
            }
            if !terminal.released.load(Ordering::Acquire) {
                self.report(
                    "terminal handoff",
                    "runner did not commit within the bounded handoff deadline",
                );
            }
            if self.stopping() && !self.stopped_recorded {
                result = self.finish_stop(&writer);
            }
        }
        // Pending request owners must receive a definitive result when the supervisor ends.
        for _ in 0..1024 {
            let Ok(message) = self.rx.try_recv() else {
                break;
            };
            if let SupervisorMessage::Pause(request) | SupervisorMessage::Continue(request) =
                message
            {
                request.reject("supervisor has stopped");
            }
        }
        if let Err(error) = &result {
            self.report("terminal failure", error);
        }
        result
    }

    fn run_generations(&mut self, writer: &EventWriter) -> Result<ExitReason, SupervisorError> {
        let default_action = self
            .config
            .restart
            .default_action
            .unwrap_or(ExitAction::Restart);
        let retry_delay = Duration::from_millis(
            self.config
                .restart
                .throttle_delay_ms
                .unwrap_or(DEFAULT_THROTTLE_DELAY_MS) as u64,
        );
        let mut first = true;
        let mut last_delay = Duration::ZERO;
        loop {
            if !self.sleep_or_stop(Duration::ZERO)? {
                return Ok(ExitReason::Stopped);
            }
            self.next_generation = self.next_generation.wrapping_add(1);
            match self.start_generation(writer, first, last_delay) {
                Ok(false) => return Ok(ExitReason::Stopped),
                Ok(true) => first = false,
                Err(error) => {
                    self.report("startup/spawn", &error);
                    self.cleanup_generation(writer)?;
                    if self.stopping() {
                        return Ok(ExitReason::Stopped);
                    }
                    if default_action == ExitAction::Suicide {
                        return Ok(ExitReason::Suicide { exit_code: -1 });
                    }
                    if default_action == ExitAction::Exit {
                        return Err(error);
                    }
                    if !self.sleep_or_stop(retry_delay)? {
                        return Ok(ExitReason::Stopped);
                    }
                    continue;
                }
            }
            loop {
                if self.stopping() {
                    return Ok(ExitReason::Stopped);
                }
                if self
                    .generation
                    .as_ref()
                    .and_then(Generation::exit)
                    .is_some()
                {
                    break;
                }
                self.receive_control(CONTROL_POLL)?;
            }
            let generation = self.generation.as_ref().unwrap();
            let exit = generation.exit().unwrap();
            let lived = exit.observed.saturating_duration_since(generation.started);
            let action = self
                .config
                .exit_actions
                .get(&exit.code.to_string())
                .map(|policy| policy.action)
                .unwrap_or(default_action);
            self.cleanup_generation(writer)?;
            if self.stopping() {
                return Ok(ExitReason::Stopped);
            }
            match action {
                ExitAction::Restart => {
                    last_delay = restart_delay(&self.config, lived);
                    if !last_delay.is_zero() {
                        writer.throttled(last_delay.as_millis() as u64);
                    }
                    if !self.sleep_or_stop(last_delay)? {
                        return Ok(ExitReason::Stopped);
                    }
                }
                ExitAction::Ignore => {
                    self.confirm_startup(StartupStatus::Quiesced);
                    return self.wait_for_stop_quiesced();
                }
                ExitAction::Exit => return Ok(ExitReason::ChildExited),
                ExitAction::Suicide => {
                    return Ok(ExitReason::Suicide {
                        exit_code: exit.code,
                    })
                }
            }
        }
    }

    fn prepare_launch(&mut self) -> Result<(), SupervisorError> {
        self.environment = effective_environment(&self.config)?;
        // Hook expansion belongs to its invocation, after dynamic NGSM_* values
        // replace any stale user values. Only launch fields are resolved here.
        let mut launch = self.config.clone();
        launch.expandable_strings.retain(|name| {
            !name
                .get(..10)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("AppEvents\\"))
        });
        let config = launch
            .resolve_expandable_strings(|name| lookup_environment(&self.environment, name))?;
        if config.io.timestamp_log == Some(true) {
            return Err(invalid(
                "AppTimestampLog is unsupported; the application must timestamp its output",
            ));
        }
        if config.rotation.delay_ms.is_some_and(|delay| delay != 0) {
            return Err(invalid(
                "nonzero AppRotateDelay is unsupported; rotation does not add an artificial delay",
            ));
        }
        let application = config
            .application
            .as_deref()
            .ok_or(SupervisorError::MissingApplication)?;
        servicemanager_core::validate_absolute_path("application", application)?;
        if let Some(directory) = config.app_directory.as_deref().filter(|d| !d.is_empty()) {
            servicemanager_core::validate_absolute_path("app_directory", directory)?;
        }
        for (label, stream) in [
            ("stdin", &config.io.stdin),
            ("stdout", &config.io.stdout),
            ("stderr", &config.io.stderr),
        ] {
            if let Some(stream) = stream {
                servicemanager_core::validate_absolute_path(label, &stream.path)?;
                if label == "stdin" {
                    rotation::validate_input(stream)?;
                } else {
                    rotation::validate_output(stream, &config.rotation)?;
                }
            }
        }
        self.launch_config = Some(config);
        Ok(())
    }

    fn start_generation(
        &mut self,
        writer: &EventWriter,
        first: bool,
        last_delay: Duration,
    ) -> Result<bool, SupervisorError> {
        if self.stopping() {
            return Ok(false);
        }
        self.prepare_launch()?;
        self.fire_hook(HookPoint::StartPre, None, None, None);
        if self.stopping() {
            return Ok(false);
        }
        #[cfg(windows)]
        {
            self.job = Some(Arc::new(JobObject::new_kill_on_close()?));
        }

        let config = self.launch_config.as_ref().unwrap().clone();
        let stdout_config = config.io.stdout.clone();
        let stderr_config = config.io.stderr.clone();
        let rotation_config = config.rotation.clone();
        self.open_task = Some(IoTask::spawn(move |cancelled| {
            if cancelled.load(Ordering::Acquire) {
                return Err(io::Error::from(io::ErrorKind::Interrupted).into());
            }
            dedup_sinks(
                stdout_config.as_ref(),
                stderr_config.as_ref(),
                &rotation_config,
            )
        })?);
        let stopping = Arc::clone(&self.stop_requested);
        let opened = self
            .open_task
            .as_mut()
            .unwrap()
            .wait(Duration::from_secs(30), || stopping.load(Ordering::Acquire))
            .map_err(|error| SupervisorError::Degraded(error.to_string()))?;
        self.open_task = None;
        let (out, err, sinks) = opened?;
        self.sinks = sinks;
        self.rotate_sinks(false, true)?;
        if self.stopping() {
            return Ok(false);
        }

        let application = config.application.as_ref().unwrap();
        let mut command = Command::new(application);
        if let Some(arguments) = &config.app_parameters {
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                command.raw_arg(arguments);
            }
            #[cfg(not(windows))]
            command.arg(arguments);
        }
        if let Some(directory) = config.app_directory.as_deref().filter(|d| !d.is_empty()) {
            command.current_dir(directory);
        }
        command
            .env_clear()
            .envs(self.environment.iter().map(|(name, value)| (name, value)));
        let online = config.rotation.enabled == Some(true)
            && config.rotation.online.is_some_and(|mode| mode != 0);
        if let Some(sink) = out {
            command.stdout(if online {
                self.attach_pipe_sink("stdout", sink)?
            } else {
                sink.child_stdio()?
            });
        }
        if let Some(sink) = err {
            command.stderr(if online {
                self.attach_pipe_sink("stderr", sink)?
            } else {
                sink.child_stdio()?
            });
        }
        if let Some(stream) = &config.io.stdin {
            command.stdin(open_stdin_file(stream)?);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            let console =
                config.shutdown.stop_method_skip.unwrap_or(0) & STOP_METHOD_SKIP_CONSOLE == 0;
            command.creation_flags(0x4 | if console { 0x200 } else { 0 });
        }
        if self.stopping() {
            return Ok(false);
        }
        let mut child = command
            .spawn()
            .map_err(|e| SupervisorError::Spawn(PathBuf::from(application), e))?;
        drop(command);
        let pid = child.id();
        #[cfg(windows)]
        let root = match (|| -> Result<PinnedProcess, SupervisorError> {
            let job = self.job.as_ref().unwrap();
            job.assign_child(&child)?;
            let root = job.pin_child(&child)?;
            root.configure(config.priority, config.affinity.as_deref())?;
            Ok(root)
        })() {
            Ok(root) => root,
            Err(error) => {
                kill_owned_child(&mut child);
                return Err(error);
            }
        };
        if self.stopping() {
            kill_owned_child(&mut child);
            return Ok(false);
        }
        let started = Instant::now();
        let timestamp = event_log::now_rfc3339();
        #[cfg(windows)]
        match root.resume() {
            Ok(true) => {}
            Ok(false) => {
                kill_owned_child(&mut child);
                return Err(invalid("child exited before its initial resume"));
            }
            Err(error) => {
                kill_owned_child(&mut child);
                return Err(error.into());
            }
        }
        let state = Arc::new(Mutex::new(ChildState {
            child: Some(child),
            exit: None,
        }));
        self.generation = Some(Generation {
            id: self.next_generation,
            pid,
            started,
            state: Arc::clone(&state),
            watcher: None,
            recorded: false,
            #[cfg(windows)]
            root: Some(root),
        });
        let tx = self.tx.clone();
        let id = self.next_generation;
        let watcher = thread::Builder::new()
            .name("ngsm-exit".into())
            .spawn(move || {
                let child = state.lock().unwrap_or_else(|e| e.into_inner()).child.take();
                let Some(mut child) = child else {
                    return;
                };
                let result = child.wait();
                let exit = observed_exit(&result);
                {
                    let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
                    state.child = Some(child);
                    state.exit = Some(exit);
                }
                let _ = tx.send(SupervisorMessage::ChildExited(id));
            });
        // Start is recorded before any Exit record, but both carry occurrence
        // timestamps, not the time a slow hook lets the main loop process them.
        if first {
            writer.started_at(pid, timestamp);
        } else {
            writer.restarted_at(pid, last_delay.as_millis() as u64, timestamp);
        }
        self.generation.as_mut().unwrap().watcher = Some(watcher?);
        if self.stopping() {
            return Ok(false);
        }
        self.fire_hook(HookPoint::StartPost, Some(pid), None, None);
        if self.stopping() {
            return Ok(false);
        }
        if self.generation.as_ref().is_some_and(Generation::alive) {
            self.confirm_startup(StartupStatus::Running);
        }
        Ok(true)
    }

    fn confirm_startup(&mut self, status: StartupStatus) {
        if !self.startup_reported && !self.stopping() {
            let _ = self.startup_tx.send(status);
            self.startup_reported = true;
        }
    }

    fn attach_pipe_sink(
        &mut self,
        label: &str,
        sink: Arc<RotationSink>,
    ) -> Result<Stdio, SupervisorError> {
        let (reader, writer) = os_pipe::pipe()?;
        self.readers.push(ReaderTask::spawn(
            self.name.clone(),
            label.into(),
            reader,
            sink,
            self.tx.clone(),
            self.next_generation,
            self.diagnostic.clone(),
        )?);
        Ok(Stdio::from(writer))
    }

    fn receive_control(&mut self, delay: Duration) -> Result<(), SupervisorError> {
        if self.stopping() {
            return Ok(());
        }
        match self.rx.recv_timeout(delay) {
            Ok(message) => self.handle_control(message),
            Err(RecvTimeoutError::Timeout) => Ok(()),
            Err(RecvTimeoutError::Disconnected) => {
                self.stop_requested.store(true, Ordering::Release);
                Ok(())
            }
        }
    }

    fn handle_control(&mut self, message: SupervisorMessage) -> Result<(), SupervisorError> {
        if self.stopping() {
            if let SupervisorMessage::Pause(request) | SupervisorMessage::Continue(request) =
                message
            {
                request.cancel();
            }
            return Ok(());
        }
        match message {
            SupervisorMessage::Stop => self.stop_requested.store(true, Ordering::Release),
            SupervisorMessage::Pause(request) => self.change_pause(true, request)?,
            SupervisorMessage::Continue(request) => self.change_pause(false, request)?,
            SupervisorMessage::Rotate => {
                if self.config.has_online_rotation() {
                    self.rotate_sinks(true, false)?;
                } else {
                    self.report(
                        "rotate",
                        "no online log sinks; offline rotation occurs at startup",
                    );
                }
            }
            SupervisorMessage::AutoRotate(id) => {
                if self
                    .generation
                    .as_ref()
                    .is_some_and(|generation| generation.id == id)
                {
                    self.rotate_sinks(false, false)?;
                }
            }
            SupervisorMessage::ReaderFailed(id) => {
                if self
                    .generation
                    .as_ref()
                    .is_some_and(|generation| generation.id == id)
                {
                    return Err(SupervisorError::Io(io::Error::other(
                        "generation output reader failed",
                    )));
                }
            }
            SupervisorMessage::PowerEvent(event) => {
                let point = if is_resume_event(event) {
                    HookPoint::PowerResume
                } else {
                    HookPoint::PowerChange
                };
                self.fire_hook(point, self.current_pid(), None, Some(event));
            }
            SupervisorMessage::ChildExited(id) => {
                let _ = self
                    .generation
                    .as_ref()
                    .is_some_and(|generation| generation.id == id);
            }
        }
        Ok(())
    }

    fn change_pause(&mut self, pause: bool, request: Transition) -> Result<(), SupervisorError> {
        let result = request.execute(|cancelled| {
            self.pause.lock().unwrap_or_else(|e| e.into_inner()).change(
                pause,
                || self.members(),
                || self.stopping() || cancelled.load(Ordering::Acquire),
            )
        });
        if let TransitionOutcome::Degraded(error) = result {
            return Err(SupervisorError::Degraded(error));
        }
        Ok(())
    }

    fn members(&self) -> Result<Vec<Arc<dyn Member>>, String> {
        #[cfg(windows)]
        {
            match &self.job {
                Some(job) => job
                    .members()
                    .map(|members| {
                        members
                            .into_iter()
                            .map(|member| Arc::new(member) as Arc<dyn Member>)
                            .collect()
                    })
                    .map_err(|e| e.to_string()),
                None => Ok(Vec::new()),
            }
        }
        #[cfg(not(windows))]
        {
            Ok(Vec::new())
        }
    }

    fn sleep_or_stop(&mut self, delay: Duration) -> Result<bool, SupervisorError> {
        let deadline = Instant::now() + delay;
        loop {
            if self.stopping() {
                return Ok(false);
            }
            for _ in 0..32 {
                match self.rx.try_recv() {
                    Ok(message) => self.handle_control(message)?,
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        self.stop_requested.store(true, Ordering::Release);
                        return Ok(false);
                    }
                }
                if self.stopping() {
                    return Ok(false);
                }
            }
            if !self.paused() && Instant::now() >= deadline {
                return Ok(true);
            }
            let remaining = if self.paused() {
                CONTROL_POLL
            } else {
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(CONTROL_POLL)
            };
            self.receive_control(remaining)?;
        }
    }

    fn wait_for_stop_quiesced(&mut self) -> Result<ExitReason, SupervisorError> {
        while !self.stopping() {
            self.receive_control(CONTROL_POLL)?;
        }
        Ok(ExitReason::Stopped)
    }

    fn current_pid(&self) -> Option<u32> {
        self.generation
            .as_ref()
            .filter(|generation| generation.alive())
            .map(|generation| generation.pid)
    }

    fn finish_stop(&mut self, writer: &EventWriter) -> Result<ExitReason, SupervisorError> {
        self.shutdown_deadline
            .get_or_insert_with(|| Instant::now() + SHUTDOWN_BUDGET);
        if !self.stop_hook_fired {
            self.stop_hook_fired = true;
            self.fire_hook(HookPoint::StopPre, self.current_pid(), None, None);
        }
        let graceful = self.stop_child_gracefully();
        let cleanup = self.cleanup_generation(writer);
        if !self.stopped_recorded {
            self.stopped_recorded = true;
            writer.stopped(servicemanager_core::events::StopReason::ScmStop);
        }
        graceful?;
        cleanup?;
        Ok(ExitReason::Stopped)
    }

    fn stop_child_gracefully(&mut self) -> Result<(), SupervisorError> {
        // Exit and child identity are published together. Copy the observation
        // out of the lock before recording it or running any callback.
        if let Some(exit) = self.generation.as_ref().and_then(Generation::exit) {
            self.last_exit_code = Some(exit.code);
            return Ok(());
        }
        let Some(generation) = &self.generation else {
            return Ok(());
        };
        let pid = generation.pid;
        let resume = self.pause.lock().unwrap_or_else(|e| e.into_inner()).change(
            false,
            || self.members(),
            || false,
        );
        if matches!(
            resume,
            TransitionOutcome::Degraded(_) | TransitionOutcome::Rejected(_)
        ) {
            self.report(
                "stop",
                "could not restore the suspended tree; forcing contained cleanup",
            );
            return Ok(());
        }
        let policy = self.config.shutdown.clone();
        let skip = policy.stop_method_skip.unwrap_or(0);
        #[cfg(windows)]
        {
            if skip & STOP_METHOD_SKIP_CONSOLE == 0
                && self.generation.as_ref().is_some_and(Generation::alive)
            {
                if let Err(error) = send_ctrl_break(pid) {
                    self.report("CTRL+BREAK", error);
                } else if self.wait_for_exit(Duration::from_millis(
                    policy
                        .kill_console_grace_ms
                        .unwrap_or(DEFAULT_CONSOLE_GRACE_MS) as u64,
                )) {
                    return Ok(());
                }
            }
            for (skip_bit, grace, close) in [
                (
                    STOP_METHOD_SKIP_WINDOW,
                    policy
                        .kill_window_grace_ms
                        .unwrap_or(DEFAULT_WINDOW_GRACE_MS),
                    true,
                ),
                (
                    STOP_METHOD_SKIP_THREADS,
                    policy
                        .kill_threads_grace_ms
                        .unwrap_or(DEFAULT_THREADS_GRACE_MS),
                    false,
                ),
            ] {
                if skip & skip_bit != 0 {
                    continue;
                }
                let members = self.job.as_ref().map(|job| job.members()).transpose()?;
                for process in members.unwrap_or_default() {
                    // Keep the pinned identity alive across the PID-only message helper.
                    let result = if close {
                        post_wm_close_to_process(process.id()).map(|_| ())
                    } else {
                        post_wm_quit_to_process(process.id()).map(|_| ())
                    };
                    if let Err(error) = result {
                        self.report("graceful window/thread control", error);
                    }
                }
                if self.wait_for_exit(Duration::from_millis(grace as u64)) {
                    return Ok(());
                }
            }
            if skip & STOP_METHOD_SKIP_TERMINATE == 0 {
                if policy.kill_process_tree.unwrap_or(true) {
                    if let Some(job) = &self.job {
                        job.terminate(1)?;
                    }
                } else if let Some(root) = self
                    .generation
                    .as_ref()
                    .and_then(|generation| generation.root.as_ref())
                {
                    root.terminate(1)?;
                }
            }
        }
        #[cfg(not(windows))]
        let _ = (pid, policy, skip);
        self.wait_for_exit(Duration::from_secs(2));
        Ok(())
    }

    fn wait_for_exit(&mut self, duration: Duration) -> bool {
        let mut deadline = Instant::now() + duration;
        if let Some(stop_deadline) = self.shutdown_deadline {
            // Reserve time for contained termination, reader drainage and Exit/Post.
            deadline = deadline.min(
                stop_deadline
                    .checked_sub(Duration::from_secs(40))
                    .unwrap_or(stop_deadline),
            );
        }
        self.wait_for_exit_until(deadline)
    }

    fn wait_for_exit_until(&mut self, deadline: Instant) -> bool {
        while Instant::now() < deadline {
            self.observe_unwatched_child();
            if self.exit_observed_and_tree_empty() {
                return true;
            }
            thread::sleep(CONTROL_POLL.min(deadline.saturating_duration_since(Instant::now())));
        }
        self.exit_observed_and_tree_empty()
    }

    fn exit_observed_and_tree_empty(&self) -> bool {
        let exited = self
            .generation
            .as_ref()
            .and_then(Generation::exit)
            .is_some();
        #[cfg(windows)]
        {
            exited
                && self
                    .job
                    .as_ref()
                    .is_none_or(|job| job.is_empty().unwrap_or(false))
        }
        #[cfg(not(windows))]
        {
            exited
        }
    }

    fn observe_unwatched_child(&mut self) {
        let Some(generation) = &self.generation else {
            return;
        };
        if generation.watcher.is_some() {
            return;
        }
        let mut state = generation.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.exit.is_some() {
            return;
        }
        if let Some(child) = state.child.as_mut() {
            match child.try_wait() {
                Ok(Some(status)) => state.exit = Some(observed_exit(&Ok(status))),
                Err(error) => state.exit = Some(observed_exit(&Err(error))),
                Ok(None) => {}
            }
        }
    }

    fn record_child_exit(&mut self, writer: &EventWriter) {
        let Some(generation) = &mut self.generation else {
            return;
        };
        if generation.recorded {
            return;
        }
        let Some(exit) = generation.exit() else {
            return;
        };
        generation.recorded = true;
        let lived = exit.observed.saturating_duration_since(generation.started);
        let pid = generation.pid;
        self.last_exit_code = Some(exit.code);
        writer.child_exited_at(exit.code, lived.as_millis() as u64, exit.timestamp);
        if let Some(error) = exit.error {
            self.report("child wait", error);
        }
        self.fire_hook(HookPoint::ExitPost, Some(pid), Some(exit.code), None);
    }

    fn cleanup_generation(&mut self, writer: &EventWriter) -> Result<(), SupervisorError> {
        #[cfg(windows)]
        if let Some(job) = self.job.take() {
            let terminated = job
                .terminate(1)
                .and_then(|()| job.wait_empty(Duration::from_secs(2)));
            drop(job);
            if let Err(error) = terminated {
                self.report("generation tree cleanup", &error);
                return Err(SupervisorError::Degraded(error.to_string()));
            }
        }
        #[cfg(not(windows))]
        if let Some(generation) = &self.generation {
            if let Some(child) = generation
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .child
                .as_mut()
            {
                let _ = child.kill();
            }
        }
        self.finish_filesystem_tasks()?;
        if self.generation.is_some()
            && !self.wait_for_exit_until(Instant::now() + Duration::from_secs(2))
        {
            return Err(SupervisorError::Degraded(
                "contained child did not finish before cleanup deadline".into(),
            ));
        }
        if let Some(watcher) = self
            .generation
            .as_mut()
            .and_then(|generation| generation.watcher.take())
        {
            let deadline = Instant::now() + Duration::from_secs(1);
            while !watcher.is_finished() && Instant::now() < deadline {
                thread::sleep(CONTROL_POLL);
            }
            if !watcher.is_finished() {
                return Err(SupervisorError::Degraded(
                    "exit watcher did not finish after publishing exit".into(),
                ));
            }
            watcher
                .join()
                .map_err(|_| SupervisorError::Degraded("exit watcher panicked".into()))?;
        }
        let deadline = Instant::now() + DRAIN_BUDGET;
        let mut failure = None;
        for reader in &mut self.readers {
            if let Err(error) = reader.finish(deadline) {
                failure = Some(error);
            }
        }
        if failure.is_none() && !self.stopping() && self.config.has_online_rotation() {
            self.rotate_sinks(false, false)?;
        }
        self.record_child_exit(writer);
        if let Some(error) = failure {
            self.report("output drain", &error);
            return Err(error.into());
        }
        self.readers.clear();
        self.generation = None;
        self.sinks.clear();
        self.pause
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear_generation();
        Ok(())
    }

    /// Each actual destination is one hook cycle: Pre -> rotation -> Post.
    /// No Post is emitted for a no-op, cancellation, or failed rotation.
    fn rotate_sinks(&mut self, force: bool, offline: bool) -> Result<(), SupervisorError> {
        for sink in self.sinks.clone() {
            if self.stopping() {
                break;
            }
            let due = if force {
                sink.has_data()?
            } else {
                sink.due(offline)?
            };
            if !due {
                sink.rotation_handled();
                continue;
            }
            self.fire_hook(HookPoint::RotatePre, self.current_pid(), None, None);
            if self.stopping() {
                break;
            }
            let worker_sink = Arc::clone(&sink);
            let stopping = Arc::clone(&self.stop_requested);
            self.rotation_task = Some(IoTask::spawn(move |cancelled| {
                worker_sink.rotate(&|| {
                    cancelled.load(Ordering::Acquire) || stopping.load(Ordering::Acquire)
                })
            })?);
            let stopping = Arc::clone(&self.stop_requested);
            let rotated = self
                .rotation_task
                .as_mut()
                .unwrap()
                .wait(Duration::from_secs(30), || stopping.load(Ordering::Acquire))
                .map_err(|error| SupervisorError::Degraded(error.to_string()))?;
            self.rotation_task = None;
            match rotated {
                Ok(Some(_)) => {
                    self.fire_hook(HookPoint::RotatePost, self.current_pid(), None, None)
                }
                Ok(None) => {}
                Err(error) => self.report("log rotation", error),
            }
            sink.rotation_handled();
        }
        Ok(())
    }

    fn finish_filesystem_tasks(&mut self) -> Result<(), SupervisorError> {
        if let Some(task) = &mut self.open_task {
            let _ = task
                .wait(Duration::ZERO, || true)
                .map_err(|error| SupervisorError::Degraded(error.to_string()))?;
            self.open_task = None;
        }
        if let Some(task) = &mut self.rotation_task {
            let _ = task
                .wait(Duration::ZERO, || true)
                .map_err(|error| SupervisorError::Degraded(error.to_string()))?;
            self.rotation_task = None;
        }
        Ok(())
    }

    fn fire_hook(&self, point: HookPoint, pid: Option<u32>, exit: Option<i32>, power: Option<u32>) {
        // Terminal hooks are part of cleanup itself, not queued nonterminal work.
        let shutdown = matches!(point, HookPoint::StopPre | HookPoint::ExitPost);
        if self.stopping() && !shutdown {
            return;
        }
        let Some(hook) = find_hook(&self.config.hooks, point) else {
            return;
        };
        let mut environment = if self.environment.is_empty() {
            match effective_environment(&self.config) {
                Ok(environment) => environment,
                Err(error) => {
                    self.report(
                        "hook environment",
                        format!("{}/{} skipped: {error}", point.event(), point.action()),
                    );
                    return;
                }
            }
        } else {
            self.environment.clone()
        };
        for key in [
            "NGSM_SERVICE_NAME",
            "NGSM_EVENT",
            "NGSM_APPLICATION",
            "NGSM_APPLICATION_PID",
            "NGSM_EXIT_CODE",
            "NGSM_POWER_EVENT_TYPE",
        ] {
            environment.retain(|(name, _)| !env_name_eq(name, std::ffi::OsStr::new(key)));
        }
        set_environment(&mut environment, "NGSM_SERVICE_NAME", &self.name);
        set_environment(
            &mut environment,
            "NGSM_EVENT",
            &format!("{}/{}", point.event(), point.action()),
        );
        let config = self.launch_config.as_ref().unwrap_or(&self.config);
        if let Some(application) = &config.application {
            set_environment(&mut environment, "NGSM_APPLICATION", application);
        }
        if let Some(pid) = pid {
            set_environment(&mut environment, "NGSM_APPLICATION_PID", &pid.to_string());
        }
        if let Some(exit) = exit {
            set_environment(&mut environment, "NGSM_EXIT_CODE", &exit.to_string());
        }
        if let Some(power) = power {
            set_environment(
                &mut environment,
                "NGSM_POWER_EVENT_TYPE",
                &power.to_string(),
            );
        }
        let deadline = self
            .shutdown_deadline
            .unwrap_or_else(|| Instant::now() + hooks::HOOK_TIMEOUT);
        let mut invocation = ManagedApplicationConfig {
            hooks: vec![hook.clone()],
            ..Default::default()
        };
        let key = ManagedApplicationConfig::hook_expansion_key(&hook.event, &hook.action);
        if self.config.is_expandable_string(&key) {
            invocation.expandable_strings.insert(key);
        }
        let invocation = match invocation
            .resolve_expandable_strings(|name| lookup_environment(&environment, name))
        {
            Ok(invocation) => invocation,
            Err(error) => {
                self.report("hook expansion", error);
                return;
            }
        };
        run_hook(
            &invocation.hooks[0],
            &HookRuntime {
                service: &self.name,
                environment: &environment,
                directory: config
                    .app_directory
                    .as_deref()
                    .filter(|dir| !dir.is_empty())
                    .map(Path::new),
                deadline,
                cancelled: &|| self.stopping() && !shutdown,
                diagnostic: &self.diagnostic,
                generation: self.next_generation,
            },
        );
    }
}

fn restart_delay(config: &ManagedApplicationConfig, lived: Duration) -> Duration {
    let mandatory = config
        .restart
        .restart_delay_ms
        .unwrap_or(DEFAULT_RESTART_DELAY_MS);
    let throttle = if lived.as_millis() < THROTTLE_THRESHOLD_MS {
        config
            .restart
            .throttle_delay_ms
            .unwrap_or(DEFAULT_THROTTLE_DELAY_MS)
    } else {
        0
    };
    Duration::from_millis(u64::from(mandatory.max(throttle)))
}

fn observed_exit(result: &io::Result<std::process::ExitStatus>) -> ObservedExit {
    ObservedExit {
        code: result
            .as_ref()
            .ok()
            .and_then(|status| status.code())
            .unwrap_or(-1),
        observed: Instant::now(),
        timestamp: event_log::now_rfc3339(),
        error: result.as_ref().err().map(ToString::to_string),
    }
}

fn kill_owned_child(child: &mut Child) {
    let _ = child.kill();
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(None) => thread::sleep(CONTROL_POLL),
            _ => return,
        }
    }
}

fn invalid(message: &str) -> SupervisorError {
    servicemanager_core::Error::InvalidConfig(message.into()).into()
}

fn parse_env_entry(entry: &str) -> Result<(&str, &str), SupervisorError> {
    let (name, value) = entry
        .split_once('=')
        .ok_or_else(|| invalid("environment entry must be NAME=VALUE"))?;
    if name.is_empty() || name.contains('\0') || value.contains('\0') {
        return Err(invalid(
            "environment entry has an empty name or embedded NUL",
        ));
    }
    Ok((name, value))
}

fn env_name_eq(left: &std::ffi::OsStr, right: &std::ffi::OsStr) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows::Win32::Globalization::{CompareStringOrdinal, CSTR_EQUAL};
        let left: Vec<u16> = left.encode_wide().collect();
        let right: Vec<u16> = right.encode_wide().collect();
        // SAFETY: both counted slices remain alive for this ordinal comparison.
        (unsafe { CompareStringOrdinal(&left, &right, true) }) == CSTR_EQUAL
    }
    #[cfg(not(windows))]
    {
        left == right
    }
}

fn set_environment(environment: &mut Vec<(OsString, OsString)>, name: &str, value: &str) {
    environment.retain(|(key, _)| !env_name_eq(key, std::ffi::OsStr::new(name)));
    environment.push((name.into(), value.into()));
}

fn lookup_environment(environment: &[(OsString, OsString)], name: &str) -> Option<String> {
    environment
        .iter()
        .find(|(key, _)| env_name_eq(key, std::ffi::OsStr::new(name)))
        .and_then(|(_, value)| value.to_str().map(str::to_owned))
}

fn effective_environment(
    config: &ManagedApplicationConfig,
) -> Result<Vec<(OsString, OsString)>, SupervisorError> {
    let mut environment = if config.environment.is_empty() {
        std::env::vars_os().collect()
    } else {
        Vec::new()
    };
    for entry in config
        .environment
        .iter()
        .chain(config.environment_extra.iter())
    {
        let (name, value) = parse_env_entry(entry)?;
        set_environment(&mut environment, name, value);
    }
    Ok(environment)
}

#[cfg(test)]
fn open_log_file(
    stream: &IoStream,
    _rotation: &LogRotationConfig,
) -> Result<Stdio, SupervisorError> {
    Ok(Stdio::from(rotation::open_output(stream)?))
}

fn open_stdin_file(stream: &IoStream) -> Result<Stdio, SupervisorError> {
    Ok(Stdio::from(rotation::open_input(stream).map_err(
        |error| SupervisorError::OpenStdin(PathBuf::from(&stream.path), error),
    )?))
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
